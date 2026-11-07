//! The hosts connected right now, what they said about themselves, which of
//! them a queued job should wake, and which of their targets the
//! reconciliation sweep covers.
//!
//! Stage 3: a version-3 host whose target the sweep covers is in **launch
//! mode** for that target's pool profiles. A queued pool job does not wake it;
//! [`crate::placement`] sends it a `launch` instead, to exactly one such host.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use runner_manager_coordinator_protocol::{
    CLOSE_REPLACED, HELLO_ACK_VERSION, Heartbeat, Hello, HelloAck, LAUNCH_VERSION, ServerMessage,
    Target, TargetRef, TargetScope, Wake, WakeReason,
};
use runner_manager_domain::model::Label;
use runner_manager_domain::policy::is_pool_label;
use tokio::sync::mpsc;

use crate::webhook::{profile_covers, required_labels};

/// How many messages may wait for one host before further ones are dropped.
pub const OUTBOUND_QUEUE: usize = 64;

/// What the server task of one connection is asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    Send(ServerMessage),
    Close(u16, &'static str),
}

#[derive(Debug)]
struct Connected {
    connection: u64,
    /// The protocol version this connection negotiated.
    version: u32,
    sender: mpsc::Sender<Outbound>,
    hello: Option<Hello>,
    heartbeat: Option<Heartbeat>,
    /// The last `hello_ack` sent, so an unchanged one is not sent again.
    acked: Option<HelloAck>,
}

/// What the reconciliation sweep reads: repositories by name, and the
/// accounts whose every repository it reads (an installation with
/// `repository_selection: all`). Names are lower-cased.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Coverage {
    /// `None` when no sweep runs (no GitHub App configured).
    pub interval: Option<Duration>,
    pub repositories: BTreeSet<String>,
    pub accounts: BTreeSet<String>,
}

impl Coverage {
    /// Whether the sweep reads everything `target` serves.
    #[must_use]
    pub fn covers(&self, target: &TargetRef) -> bool {
        self.interval.is_some()
            && match target.scope {
                TargetScope::Repo => self
                    .repositories
                    .contains(&target.name.to_ascii_lowercase()),
                TargetScope::Org => self.accounts.contains(&target.name.to_ascii_lowercase()),
            }
    }

    /// The `hello_ack` for a host that advertised `targets`.
    #[must_use]
    pub fn ack(&self, targets: &[Target]) -> HelloAck {
        HelloAck {
            reconcile_interval_secs: self
                .interval
                .map(|interval| u32::try_from(interval.as_secs()).unwrap_or(u32::MAX)),
            covered: targets
                .iter()
                .map(Target::reference)
                .filter(|target| self.covers(target))
                .collect(),
        }
    }
}

/// Every authenticated connection, by host id. At most one per host: a new
/// connection replaces the old one, which is told so and closed.
#[derive(Debug, Default)]
pub struct Registry {
    hosts: Mutex<HashMap<String, Connected>>,
    next: AtomicU64,
    coverage: Mutex<Coverage>,
    /// Every wake sent, by the webhook or the sweep, so the sweep does not
    /// repeat one.
    wakes: WakeLog,
}

/// When a wake was last sent for a repository and a set of required labels,
/// by the webhook or by the sweep.
///
/// A job is identified by what decides which hosts it wakes: its repository
/// and its required labels. Two queued jobs with the same labels in the same
/// repository wake the same hosts, and one poll answers both.
#[derive(Debug, Default)]
pub struct WakeLog {
    sent: Mutex<HashMap<(String, BTreeSet<Label>), Instant>>,
}

/// Wake log entries kept at most this long, once the log is pruned.
const WAKE_MEMORY: Duration = Duration::from_secs(60 * 60);

/// Entries at which the log is pruned.
const WAKE_PRUNE_AT: usize = 1024;

impl WakeLog {
    fn key(repository: &str, required: &[Label]) -> (String, BTreeSet<Label>) {
        (
            repository.to_ascii_lowercase(),
            required.iter().cloned().collect(),
        )
    }

    /// Records a wake sent now.
    pub fn record(&self, repository: &str, required: &[Label], now: Instant) {
        let mut sent = self
            .sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Pruned only once the map has grown, not on every wake.
        if sent.len() >= WAKE_PRUNE_AT {
            sent.retain(|_, at| now.saturating_duration_since(*at) < WAKE_MEMORY);
        }
        sent.insert(Self::key(repository, required), now);
    }

    /// Whether a wake was sent within `within` of `now`.
    #[must_use]
    pub fn recent(
        &self,
        repository: &str,
        required: &[Label],
        within: Duration,
        now: Instant,
    ) -> bool {
        self.sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&Self::key(repository, required))
            .is_some_and(|at| now.saturating_duration_since(*at) < within)
    }
}

/// A host that may be sent a `launch` for one queued pool job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub host_id: String,
    /// The host's target that serves the job's repository.
    pub target: TargetRef,
    /// The pool profile that would start the runner.
    pub profile: String,
    /// The profile keeps a persistent workspace there.
    pub warm: bool,
    pub heartbeat: Heartbeat,
}

/// Whether a job requiring `required` asks for a shared pool.
#[must_use]
pub fn is_pool_job(required: &[Label]) -> bool {
    required.iter().any(|label| is_pool_label(label.as_str()))
}

/// A connected host, as `hosts list` would describe it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectedHost {
    pub host_id: String,
    pub hello: Option<Hello>,
    pub heartbeat: Option<Heartbeat>,
}

impl Registry {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Connected>> {
        self.hosts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Registers a connection for `host_id` at protocol `version`,
    /// returning its token.
    pub fn register(&self, host_id: &str, version: u32, sender: mpsc::Sender<Outbound>) -> u64 {
        let connection = self.next.fetch_add(1, Ordering::Relaxed);
        let previous = self.lock().insert(
            host_id.to_string(),
            Connected {
                connection,
                version,
                sender,
                hello: None,
                heartbeat: None,
                acked: None,
            },
        );
        if let Some(previous) = previous {
            let _ = previous
                .sender
                .try_send(Outbound::Close(CLOSE_REPLACED, "replaced"));
        }
        connection
    }

    /// Forgets `connection`, unless a newer one has already replaced it;
    /// `true` when it was forgotten.
    pub fn unregister(&self, host_id: &str, connection: u64) -> bool {
        let mut hosts = self.lock();
        if hosts
            .get(host_id)
            .is_some_and(|current| current.connection == connection)
        {
            hosts.remove(host_id);
            return true;
        }
        false
    }

    /// Queues `message` for `host_id`'s connection; `false` when it is not
    /// connected or its queue is full.
    pub fn send(&self, host_id: &str, message: ServerMessage) -> bool {
        self.lock()
            .get(host_id)
            .is_some_and(|connected| connected.sender.try_send(Outbound::Send(message)).is_ok())
    }

    /// Asks `host_id`'s connection to close with `code`; `true` when it was
    /// connected.
    pub fn close(&self, host_id: &str, code: u16, reason: &'static str) -> bool {
        self.lock().get(host_id).is_some_and(|connected| {
            // A full queue still ends the connection: the server task sees the
            // closed channel once this sender is dropped below.
            connected
                .sender
                .try_send(Outbound::Close(code, reason))
                .is_ok()
        })
    }

    /// The ids of every connected host.
    #[must_use]
    pub fn host_ids(&self) -> Vec<String> {
        self.lock().keys().cloned().collect()
    }

    /// Every connected host in launch mode for `repository` with an enabled
    /// pool profile whose labels cover `required`, and its last heartbeat. A
    /// host that has not sent a heartbeat yet is not a candidate.
    #[must_use]
    pub fn launch_candidates(&self, repository: &str, required: &[Label]) -> Vec<Candidate> {
        let coverage = self.coverage();
        let hosts = self.lock();
        let mut candidates = Vec::new();
        for (host_id, connected) in hosts.iter() {
            if connected.version < LAUNCH_VERSION {
                continue;
            }
            let (Some(hello), Some(heartbeat)) = (&connected.hello, &connected.heartbeat) else {
                continue;
            };
            for target in &hello.targets {
                let reference = target.reference();
                if !reference.covers(repository) || !coverage.covers(&reference) {
                    continue;
                }
                if let Some(profile) = target.profiles.iter().find(|profile| {
                    profile.enabled
                        && profile.labels.iter().any(|label| is_pool_label(label))
                        && profile_covers(&profile.labels, required)
                }) {
                    candidates.push(Candidate {
                        host_id: host_id.clone(),
                        target: reference,
                        profile: profile.name.clone(),
                        warm: profile.warm,
                        heartbeat: heartbeat.clone(),
                    });
                    break;
                }
            }
        }
        candidates
    }

    /// Records what a host said about itself and, to a version-2 host,
    /// answers with its coverage.
    pub fn set_hello(&self, host_id: &str, connection: u64, hello: Hello) {
        let mut hosts = self.lock();
        // Read under the hosts lock: a `set_coverage` that lands after this
        // read reaches this host in its own pass, which waits for the lock.
        let coverage = self.coverage();
        if let Some(current) = hosts.get_mut(host_id)
            && current.connection == connection
        {
            current.hello = Some(hello);
            // Always answered, even when unchanged: the host may have
            // reconnected and forgotten it.
            current.acked = None;
            acknowledge(host_id, current, &coverage);
        }
    }

    /// What the sweep covers now.
    #[must_use]
    pub fn coverage(&self) -> Coverage {
        self.coverage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The wakes sent recently.
    #[must_use]
    pub const fn wakes(&self) -> &WakeLog {
        &self.wakes
    }

    /// Replaces the sweep's coverage and tells every version-2 host whose
    /// answer differs from the last one it was sent.
    ///
    /// Every host is visited even when the coverage is unchanged: an answer
    /// that met a full outbound queue last time is retried here, and one
    /// already delivered is not sent again.
    pub fn set_coverage(&self, coverage: Coverage) {
        self.coverage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone_from(&coverage);
        for (host_id, connected) in self.lock().iter_mut() {
            acknowledge(host_id, connected, &coverage);
        }
    }

    /// Every target some connected host advertised, once each.
    #[must_use]
    pub fn advertised(&self) -> Vec<TargetRef> {
        let mut seen = BTreeSet::new();
        self.lock()
            .values()
            .flat_map(|connected| connected.hello.iter().flat_map(|hello| &hello.targets))
            .map(Target::reference)
            .filter(|target| seen.insert((target.scope, target.name.to_ascii_lowercase())))
            .collect()
    }

    pub fn set_heartbeat(&self, host_id: &str, connection: u64, heartbeat: Heartbeat) {
        if let Some(current) = self.lock().get_mut(host_id)
            && current.connection == connection
        {
            current.heartbeat = Some(heartbeat);
        }
    }

    /// Every connected host.
    #[must_use]
    pub fn connected(&self) -> Vec<ConnectedHost> {
        let mut hosts: Vec<ConnectedHost> = self
            .lock()
            .iter()
            .map(|(host_id, connected)| ConnectedHost {
                host_id: host_id.clone(),
                hello: connected.hello.clone(),
                heartbeat: connected.heartbeat.clone(),
            })
            .collect();
        hosts.sort_by(|a, b| a.host_id.cmp(&b.host_id));
        hosts
    }

    /// Wakes every connected host that advertised a target covering
    /// `repository` with an enabled profile whose labels cover `labels`.
    /// Returns how many were woken.
    pub fn wake_for_job(&self, repository: &str, labels: &[String], delivery_id: &str) -> usize {
        required_labels(labels).map_or(0, |required| {
            self.wake_for(repository, &required, WakeReason::JobQueued, delivery_id)
        })
    }

    /// [`Self::wake_for_job`] for a job whose required labels are resolved.
    /// A wake that reached a host is recorded in [`Self::wakes`].
    pub fn wake_for(
        &self,
        repository: &str,
        required: &[Label],
        reason: WakeReason,
        delivery_id: &str,
    ) -> usize {
        let pool = is_pool_job(required);
        let coverage = self.coverage();
        let hosts = self.lock();
        let mut woken = 0;
        for (host_id, connected) in hosts.iter() {
            let Some(target) = connected
                .hello
                .as_ref()
                .and_then(|hello| matching_target(hello, repository, required))
            else {
                continue;
            };
            // A pool job reaches a host in launch mode as a `launch` to one
            // of them (see `crate::placement`), never as a wake to all.
            if pool && connected.version >= LAUNCH_VERSION && coverage.covers(&target) {
                continue;
            }
            let wake = Wake {
                target,
                repository: repository.to_string(),
                reason,
                delivery_id: delivery_id.to_string(),
            };
            match connected
                .sender
                .try_send(Outbound::Send(ServerMessage::Wake(wake)))
            {
                Ok(()) => woken += 1,
                Err(_) => {
                    tracing::warn!(%host_id, "a host's outbound queue is full; its wake was dropped");
                }
            }
        }
        drop(hosts);
        if woken > 0 {
            self.wakes.record(repository, required, Instant::now());
        }
        woken
    }
}

/// Sends `connected` its `hello_ack` when it speaks version 2, has said
/// hello, and the answer differs from the last one sent.
fn acknowledge(host_id: &str, connected: &mut Connected, coverage: &Coverage) {
    if connected.version < HELLO_ACK_VERSION {
        return;
    }
    let Some(hello) = &connected.hello else {
        return;
    };
    let ack = coverage.ack(&hello.targets);
    if connected.acked.as_ref() == Some(&ack) {
        return;
    }
    match connected
        .sender
        .try_send(Outbound::Send(ServerMessage::HelloAck(ack.clone())))
    {
        Ok(()) => connected.acked = Some(ack),
        Err(_) => {
            tracing::warn!(%host_id, "a host's outbound queue is full; its coverage update waits");
        }
    }
}

/// The first of `hello`'s targets that covers `repository` and has an enabled
/// profile able to take a job requiring `required`.
#[must_use]
pub fn matching_target(hello: &Hello, repository: &str, required: &[Label]) -> Option<TargetRef> {
    hello
        .targets
        .iter()
        .find(|target| {
            target.reference().covers(repository)
                && target
                    .profiles
                    .iter()
                    .any(|profile| profile.enabled && profile_covers(&profile.labels, required))
        })
        .map(Target::reference)
}

#[cfg(test)]
mod tests {
    use runner_manager_coordinator_protocol::{MIN_PROTOCOL_VERSION, PROTOCOL_VERSION, Profile};

    use super::*;

    fn required(values: &[&str]) -> Vec<Label> {
        required_labels(&labels(values)).expect("resolvable")
    }

    fn hello(scope: TargetScope, name: &str, labels: &[&str], enabled: bool) -> Hello {
        Hello {
            protocol_version: PROTOCOL_VERSION,
            host_id: "h".into(),
            os: "linux".into(),
            arch: "x64".into(),
            cores: 4,
            ram_bytes: None,
            disk_free_bytes: None,
            targets: vec![Target {
                scope,
                name: name.into(),
                profiles: vec![Profile {
                    name: "default".into(),
                    labels: labels.iter().map(ToString::to_string).collect(),
                    enabled,
                    warm: false,
                }],
            }],
        }
    }

    fn labels(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn only_a_host_with_a_covering_enabled_profile_matches() {
        let linux = hello(TargetScope::Org, "Octo", &["self-hosted", "linux"], true);
        assert_eq!(
            matching_target(&linux, "octo/app", &required(&["self-hosted", "Linux"])),
            Some(TargetRef {
                scope: TargetScope::Org,
                name: "Octo".into()
            })
        );
        assert_eq!(
            matching_target(&linux, "octo/app", &required(&["windows"])),
            None
        );
        assert_eq!(
            matching_target(&linux, "other/app", &required(&["linux"])),
            None
        );
        let disabled = hello(TargetScope::Repo, "octo/app", &["linux"], false);
        assert_eq!(
            matching_target(&disabled, "octo/app", &required(&["linux"])),
            None
        );
    }

    #[tokio::test]
    async fn a_job_wakes_matching_hosts_and_a_new_connection_replaces_the_old() {
        let registry = Registry::default();
        let (linux_tx, mut linux_rx) = mpsc::channel(4);
        let (mac_tx, mut mac_rx) = mpsc::channel(4);
        let linux = registry.register("linux", MIN_PROTOCOL_VERSION, linux_tx);
        let mac = registry.register("mac", MIN_PROTOCOL_VERSION, mac_tx);
        registry.set_hello(
            "linux",
            linux,
            hello(TargetScope::Repo, "octo/app", &["linux"], true),
        );
        registry.set_hello(
            "mac",
            mac,
            hello(TargetScope::Repo, "octo/app", &["macos"], true),
        );

        assert_eq!(
            registry.wake_for_job("octo/app", &labels(&["linux"]), "d1"),
            1
        );
        assert!(matches!(
            linux_rx.try_recv(),
            Ok(Outbound::Send(ServerMessage::Wake(Wake { delivery_id, .. }))) if delivery_id == "d1"
        ));
        assert!(mac_rx.try_recv().is_err());

        let (again_tx, _again_rx) = mpsc::channel(4);
        let again = registry.register("linux", MIN_PROTOCOL_VERSION, again_tx);
        assert_eq!(
            linux_rx.try_recv(),
            Ok(Outbound::Close(CLOSE_REPLACED, "replaced"))
        );
        // The old connection's late cleanup must not remove the new one.
        registry.unregister("linux", linux);
        assert_eq!(registry.connected().len(), 2);
        registry.unregister("linux", again);
        assert_eq!(registry.connected().len(), 1);
    }

    #[tokio::test]
    async fn only_a_version_two_host_is_told_its_coverage_and_only_when_it_changes() {
        let registry = Registry::default();
        let (new_tx, mut new_rx) = mpsc::channel(8);
        let (old_tx, mut old_rx) = mpsc::channel(8);
        let new = registry.register("new", PROTOCOL_VERSION, new_tx);
        let old = registry.register("old", MIN_PROTOCOL_VERSION, old_tx);
        registry.set_hello(
            "new",
            new,
            hello(TargetScope::Repo, "Octo/App", &["linux"], true),
        );
        registry.set_hello(
            "old",
            old,
            hello(TargetScope::Repo, "octo/app", &["linux"], true),
        );
        // No sweep yet: the answer says so, and covers nothing.
        assert_eq!(
            new_rx.try_recv(),
            Ok(Outbound::Send(ServerMessage::HelloAck(HelloAck::default())))
        );
        assert!(old_rx.try_recv().is_err(), "a version-1 host gets none");

        let covering = Coverage {
            interval: Some(Duration::from_secs(120)),
            repositories: BTreeSet::from(["octo/app".to_string()]),
            accounts: BTreeSet::new(),
        };
        registry.set_coverage(covering.clone());
        let Ok(Outbound::Send(ServerMessage::HelloAck(ack))) = new_rx.try_recv() else {
            panic!("the new coverage was sent");
        };
        assert_eq!(ack.reconcile_interval_secs, Some(120));
        assert_eq!(ack.covered.len(), 1);
        assert_eq!(
            ack.covered[0].name, "Octo/App",
            "named as the host named it"
        );
        registry.set_coverage(covering.clone());
        assert!(new_rx.try_recv().is_err(), "unchanged: not sent again");

        // An answer that met a full queue is retried by the next sweep's
        // unchanged coverage.
        let (full_tx, mut full_rx) = mpsc::channel(1);
        let full = registry.register("full", PROTOCOL_VERSION, full_tx);
        registry.set_hello(
            "full",
            full,
            hello(TargetScope::Repo, "octo/app", &["linux"], true),
        );
        assert!(matches!(
            full_rx.try_recv(),
            Ok(Outbound::Send(ServerMessage::HelloAck(ack))) if ack.covered.len() == 1
        ));
        // This answer fills the queue, so the next one is dropped.
        registry.set_coverage(Coverage::default());
        registry.set_coverage(covering.clone());
        assert!(matches!(
            full_rx.try_recv(),
            Ok(Outbound::Send(ServerMessage::HelloAck(ack))) if ack.covered.is_empty()
        ));
        registry.set_coverage(covering.clone());
        assert!(matches!(
            full_rx.try_recv(),
            Ok(Outbound::Send(ServerMessage::HelloAck(ack))) if ack.covered.len() == 1
        ));
        assert!(old_rx.try_recv().is_err());
        assert_eq!(registry.advertised().len(), 1, "the same target once");
    }
}
