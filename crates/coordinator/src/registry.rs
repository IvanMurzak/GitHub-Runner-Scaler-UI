//! The hosts connected right now, what they said about themselves, and which
//! of them a queued job should wake.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use runner_manager_coordinator_protocol::{
    CLOSE_REPLACED, Heartbeat, Hello, ServerMessage, TargetRef, Wake, WakeReason,
};
use tokio::sync::mpsc;

use crate::webhook::labels_cover;

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
    sender: mpsc::Sender<Outbound>,
    hello: Option<Hello>,
    heartbeat: Option<Heartbeat>,
}

/// Every authenticated connection, by host id. At most one per host: a new
/// connection replaces the old one, which is told so and closed.
#[derive(Debug, Default)]
pub struct Registry {
    hosts: Mutex<HashMap<String, Connected>>,
    next: AtomicU64,
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

    /// Registers a connection for `host_id`, returning its token.
    pub fn register(&self, host_id: &str, sender: mpsc::Sender<Outbound>) -> u64 {
        let connection = self.next.fetch_add(1, Ordering::Relaxed);
        let previous = self.lock().insert(
            host_id.to_string(),
            Connected {
                connection,
                sender,
                hello: None,
                heartbeat: None,
            },
        );
        if let Some(previous) = previous {
            let _ = previous
                .sender
                .try_send(Outbound::Close(CLOSE_REPLACED, "replaced"));
        }
        connection
    }

    /// Forgets `connection`, unless a newer one has already replaced it.
    pub fn unregister(&self, host_id: &str, connection: u64) {
        let mut hosts = self.lock();
        if hosts
            .get(host_id)
            .is_some_and(|current| current.connection == connection)
        {
            hosts.remove(host_id);
        }
    }

    pub fn set_hello(&self, host_id: &str, connection: u64, hello: Hello) {
        if let Some(current) = self.lock().get_mut(host_id)
            && current.connection == connection
        {
            current.hello = Some(hello);
        }
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
        let hosts = self.lock();
        let mut woken = 0;
        for (host_id, connected) in hosts.iter() {
            let Some(target) = connected
                .hello
                .as_ref()
                .and_then(|hello| matching_target(hello, repository, labels))
            else {
                continue;
            };
            let wake = Wake {
                target,
                repository: repository.to_string(),
                reason: WakeReason::JobQueued,
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
        woken
    }
}

/// The first of `hello`'s targets that covers `repository` and has an enabled
/// profile able to take a job labelled `labels`.
#[must_use]
pub fn matching_target(hello: &Hello, repository: &str, labels: &[String]) -> Option<TargetRef> {
    hello
        .targets
        .iter()
        .find(|target| {
            target.reference().covers(repository)
                && target
                    .profiles
                    .iter()
                    .any(|profile| profile.enabled && labels_cover(&profile.labels, labels))
        })
        .map(runner_manager_coordinator_protocol::Target::reference)
}

#[cfg(test)]
mod tests {
    use runner_manager_coordinator_protocol::{PROTOCOL_VERSION, Profile, Target, TargetScope};

    use super::*;

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
            matching_target(&linux, "octo/app", &labels(&["self-hosted", "Linux"])),
            Some(TargetRef {
                scope: TargetScope::Org,
                name: "Octo".into()
            })
        );
        assert_eq!(
            matching_target(&linux, "octo/app", &labels(&["windows"])),
            None
        );
        assert_eq!(
            matching_target(&linux, "other/app", &labels(&["linux"])),
            None
        );
        let disabled = hello(TargetScope::Repo, "octo/app", &["linux"], false);
        assert_eq!(
            matching_target(&disabled, "octo/app", &labels(&["linux"])),
            None
        );
    }

    #[tokio::test]
    async fn a_job_wakes_matching_hosts_and_a_new_connection_replaces_the_old() {
        let registry = Registry::default();
        let (linux_tx, mut linux_rx) = mpsc::channel(4);
        let (mac_tx, mut mac_rx) = mpsc::channel(4);
        let linux = registry.register("linux", linux_tx);
        let mac = registry.register("mac", mac_tx);
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
        let again = registry.register("linux", again_tx);
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
}
