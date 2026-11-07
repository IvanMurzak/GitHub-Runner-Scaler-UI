//! Coordinated placement (stage 3): exactly one host starts a runner for a
//! queued job that asks for a shared pool label (`runs-on: rm-pool-linux`).
//!
//! # What is tracked
//!
//! A runner registered with GitHub takes *any* queued job its labels cover,
//! not the one it was started for (design 4.4). So placement counts, per
//! repository and required label set (a [`JobKey`]):
//!
//! * the **queued** jobs: the ones `workflow_job` webhooks announced and no
//!   later event took away, plus any more the reconciliation sweep counted;
//! * the **leases**: launches sent to a host and not yet closed.
//!
//! and keeps `leases <= queued`. While fewer leases than queued jobs exist it
//! places one more; while more exist it cancels the newest (`cancel_launch`),
//! which a host honours only while that runner has not started.
//!
//! A lease closes when its runner takes a job (the host's `attempt_started`),
//! when its attempt ends (`attempt_finished`), when its host disconnects, or
//! when it expires ([`LEASE_TTL`]); the job, if still queued, is then placed
//! again. A webhook `in_progress` or `completed` takes the job out of the
//! queue; the caller rebalances after [`CLAIM_GRACE`], by when the host whose
//! runner took it has normally closed that very lease, so a surplus lease
//! cancelled is one whose runner took nothing.
//!
//! # Choosing the host (design 4.5, steps 1-5, without statistics)
//!
//! Candidates: connected version-3 hosts whose target serving the repository
//! is covered by the sweep (launch mode), with an enabled pool profile whose
//! labels cover the job, not unfit, not draining, and with a free slot by
//! their last heartbeat once the leases already sent to them are counted.
//! Ranked by a warm workspace for the repository, then the most free RAM,
//! then the fewest busy slots. The first is sent a `launch`; a refusal or no
//! answer within [`ACK_TIMEOUT`] moves on to the next.
//!
//! # Logging
//!
//! Lease ids, host ids, job ids and counts only: never a repository name, a
//! label or a runner name, which came off the wire.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use runner_manager_coordinator_protocol::{
    AttemptFinished, AttemptStarted, CancelLaunch, Launch, LaunchAck, ServerMessage,
};
use runner_manager_domain::model::Label;
use tokio::sync::oneshot;

use crate::registry::{Candidate, Registry, is_pool_job};

/// How long a host has to answer a `launch`.
pub const ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a lease counts once accepted: long enough for a cold runner
/// (including an isolated one) to register and take a job.
pub const LEASE_TTL: Duration = Duration::from_secs(5 * 60);

/// How long after a job leaves the queue its key is rebalanced: time for the
/// host whose runner took it to report `attempt_started`, so the lease
/// cancelled as surplus is not that one.
pub const CLAIM_GRACE: Duration = Duration::from_secs(3);

/// How often leases expire and unplaced jobs are retried.
pub const TICK: Duration = Duration::from_secs(5);

/// A job announced by a webhook and never taken away is forgotten after this.
const JOB_MEMORY: Duration = Duration::from_secs(6 * 60 * 60);

/// Queued jobs remembered at most, across every key.
const MAX_JOBS: usize = 10_000;

/// What decides which runners can take a job: its repository and its
/// required labels.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct JobKey {
    /// `owner/name`, lower-cased.
    pub repository: String,
    pub labels: BTreeSet<Label>,
}

impl JobKey {
    #[must_use]
    pub fn new(repository: &str, required: &[Label]) -> Self {
        Self {
            repository: repository.to_ascii_lowercase(),
            labels: required.iter().cloned().collect(),
        }
    }

    fn required(&self) -> Vec<Label> {
        self.labels.iter().cloned().collect()
    }
}

#[derive(Debug, Default)]
struct Queue {
    /// Job ids a webhook announced, and when.
    jobs: BTreeMap<u64, Instant>,
    /// Queued jobs the sweep counted beyond `jobs`.
    unnamed: u32,
}

impl Queue {
    fn len(&self) -> usize {
        self.jobs.len() + self.unnamed as usize
    }

    /// One job left the queue: the named one if known, else an unnamed one.
    fn take(&mut self, job_id: u64) {
        if self.jobs.remove(&job_id).is_none() {
            self.unnamed = self.unnamed.saturating_sub(1);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeaseState {
    /// Sent; no answer yet.
    Offered,
    Accepted,
}

#[derive(Debug, Clone)]
struct Lease {
    key: JobKey,
    host_id: String,
    state: LeaseState,
    sent_at: Instant,
    expires: Instant,
}

#[derive(Debug, Default)]
struct State {
    queues: HashMap<JobKey, Queue>,
    leases: HashMap<String, Lease>,
}

impl State {
    fn leases_for(&self, key: &JobKey) -> usize {
        self.leases
            .values()
            .filter(|lease| &lease.key == key)
            .count()
    }

    fn leases_on(&self, host_id: &str) -> u32 {
        u32::try_from(
            self.leases
                .values()
                .filter(|lease| lease.host_id == host_id)
                .count(),
        )
        .unwrap_or(u32::MAX)
    }
}

/// What one [`Placement::rebalance`] did, for tests and logs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rebalanced {
    /// Launches a host accepted.
    pub accepted: u32,
    /// Launches refused, unanswered or undeliverable.
    pub refused: u32,
    /// Leases cancelled because fewer jobs are queued than leases exist.
    pub cancelled: u32,
}

/// The placement state and the hosts it places on.
#[derive(Debug)]
pub struct Placement {
    registry: Arc<Registry>,
    state: Mutex<State>,
    waiting: Mutex<HashMap<String, (String, oneshot::Sender<LaunchAck>)>>,
    ack_timeout: Duration,
    lease_ttl: Duration,
}

impl Placement {
    #[must_use]
    pub fn new(registry: Arc<Registry>) -> Self {
        Self::with_timings(registry, ACK_TIMEOUT, LEASE_TTL)
    }

    /// [`Self::new`] with other timings, for tests.
    #[must_use]
    pub fn with_timings(
        registry: Arc<Registry>,
        ack_timeout: Duration,
        lease_ttl: Duration,
    ) -> Self {
        Self {
            registry,
            state: Mutex::new(State::default()),
            waiting: Mutex::new(HashMap::new()),
            ack_timeout,
            lease_ttl,
        }
    }

    #[must_use]
    pub const fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn waiting(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<String, (String, oneshot::Sender<LaunchAck>)>> {
        self.waiting
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// How many jobs of `key` are queued and how many leases are open.
    #[must_use]
    pub fn counts(&self, key: &JobKey) -> (usize, usize) {
        let state = self.state();
        (
            state.queues.get(key).map_or(0, Queue::len),
            state.leases_for(key),
        )
    }

    // -- Events --------------------------------------------------------------

    /// A webhook announced a queued job. `false` (nothing recorded) for a job
    /// that asks for no pool.
    pub fn queued(&self, repository: &str, required: &[Label], job_id: u64) -> Option<JobKey> {
        if !is_pool_job(required) {
            return None;
        }
        let key = JobKey::new(repository, required);
        let mut state = self.state();
        let total: usize = state.queues.values().map(|queue| queue.jobs.len()).sum();
        if total >= MAX_JOBS {
            tracing::warn!("too many queued pool jobs are remembered; this one is not placed");
            return None;
        }
        state
            .queues
            .entry(key.clone())
            .or_default()
            .jobs
            .insert(job_id, Instant::now());
        Some(key)
    }

    /// A webhook said a job left the queue: a runner took it
    /// (`in_progress`) or it ended (`completed`).
    pub fn dequeued(&self, repository: &str, required: &[Label], job_id: u64) -> Option<JobKey> {
        if !is_pool_job(required) {
            return None;
        }
        let key = JobKey::new(repository, required);
        let mut state = self.state();
        if let Some(queue) = state.queues.get_mut(&key) {
            queue.take(job_id);
            if queue.len() == 0 {
                state.queues.remove(&key);
            }
        }
        Some(key)
    }

    /// The sweep counted `counts` queued pool jobs per required label set in
    /// `repository`, which it read in full. Returns the keys that changed.
    pub fn swept(&self, repository: &str, counts: &HashMap<BTreeSet<Label>, u32>) -> Vec<JobKey> {
        let repository = repository.to_ascii_lowercase();
        let mut state = self.state();
        let mut keys: BTreeSet<JobKey> = state
            .queues
            .keys()
            .filter(|key| key.repository == repository)
            .cloned()
            .collect();
        keys.extend(counts.keys().map(|labels| JobKey {
            repository: repository.clone(),
            labels: labels.clone(),
        }));
        let mut changed = Vec::new();
        for key in keys {
            let swept = counts.get(&key.labels).copied().unwrap_or(0);
            let queue = state.queues.entry(key.clone()).or_default();
            let before = queue.len();
            let named = u32::try_from(queue.jobs.len()).unwrap_or(u32::MAX);
            if swept >= named {
                queue.unnamed = swept - named;
            } else {
                // Some announced jobs left without a webhook saying so: the
                // oldest are the ones most likely gone.
                queue.unnamed = 0;
                let surplus = (named - swept) as usize;
                let oldest: Vec<u64> = {
                    let mut by_age: Vec<(u64, Instant)> =
                        queue.jobs.iter().map(|(id, at)| (*id, *at)).collect();
                    by_age.sort_by_key(|(_, at)| *at);
                    by_age.into_iter().take(surplus).map(|(id, _)| id).collect()
                };
                for id in oldest {
                    queue.jobs.remove(&id);
                }
            }
            if queue.len() != before {
                changed.push(key.clone());
            }
            if queue.len() == 0 {
                state.queues.remove(&key);
            }
        }
        changed
    }

    /// A host answered a launch. Ignored unless that host was sent it.
    pub fn acknowledged(&self, host_id: &str, ack: LaunchAck) {
        let waiter = self.waiting().remove(&ack.lease_id);
        match waiter {
            Some((expected, sender)) if expected == host_id => {
                let _ = sender.send(ack);
            }
            Some(other) => {
                // Not this host's lease: put it back for its real host.
                self.waiting().insert(ack.lease_id, other);
            }
            None => {}
        }
    }

    /// A host's runner took a job. Closes its lease.
    pub fn attempt_started(&self, host_id: &str, started: &AttemptStarted) {
        if let Some(lease_id) = &started.lease_id {
            let mut state = self.state();
            if state
                .leases
                .get(lease_id)
                .is_some_and(|lease| lease.host_id == host_id)
            {
                state.leases.remove(lease_id);
            }
        }
    }

    /// A host's attempt ended. Closes its lease, if it still had one.
    pub fn attempt_finished(&self, host_id: &str, finished: &AttemptFinished) {
        if let Some(lease_id) = &finished.lease_id {
            let mut state = self.state();
            if state
                .leases
                .get(lease_id)
                .is_some_and(|lease| lease.host_id == host_id)
            {
                state.leases.remove(lease_id);
            }
        }
    }

    /// A host disconnected: its leases close, and a launch it was answering
    /// is refused at once.
    pub fn host_gone(&self, host_id: &str) {
        self.state()
            .leases
            .retain(|_, lease| lease.host_id != host_id);
        self.waiting().retain(|_, (host, _)| host != host_id);
    }

    // -- Placement -----------------------------------------------------------

    /// Expires leases and forgets stale jobs; returns every key with fewer
    /// leases than queued jobs.
    pub fn expire(&self, now: Instant) -> Vec<JobKey> {
        let mut state = self.state();
        let before = state.leases.len();
        state.leases.retain(|_, lease| lease.expires > now);
        let expired = before - state.leases.len();
        if expired > 0 {
            tracing::info!(expired, "placement leases expired");
        }
        for queue in state.queues.values_mut() {
            queue
                .jobs
                .retain(|_, at| now.saturating_duration_since(*at) < JOB_MEMORY);
        }
        state.queues.retain(|_, queue| queue.len() > 0);
        let deficit: Vec<JobKey> = state
            .queues
            .iter()
            .filter(|(key, queue)| queue.len() > state.leases_for(key))
            .map(|(key, _)| key.clone())
            .collect();
        deficit
    }

    /// Expires and retries every [`TICK`], forever.
    pub async fn run(self: Arc<Self>) {
        let mut ticks = tokio::time::interval(TICK);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticks.tick().await;
            for key in self.expire(Instant::now()) {
                self.rebalance(&key).await;
            }
        }
    }

    /// Brings `key`'s leases to its queued count: places one launch per
    /// missing lease, host by host, and cancels the newest surplus leases.
    pub async fn rebalance(&self, key: &JobKey) -> Rebalanced {
        let mut report = Rebalanced::default();
        let mut tried: HashSet<String> = HashSet::new();
        loop {
            let Some((lease_id, host_id, launch)) = self.offer(key, &tried, &mut report) else {
                return report;
            };
            let (sender, receiver) = oneshot::channel();
            self.waiting()
                .insert(lease_id.clone(), (host_id.clone(), sender));
            // `Ok(Err)`: undeliverable, or the host went away meanwhile.
            let answer = if self.registry.send(&host_id, ServerMessage::Launch(launch)) {
                tokio::time::timeout(self.ack_timeout, receiver)
                    .await
                    .map(|answer| answer.map_err(|_| ()))
            } else {
                Ok(Err(()))
            };
            self.waiting().remove(&lease_id);
            match answer {
                Ok(Ok(ack)) if ack.accepted => {
                    if let Some(lease) = self.state().leases.get_mut(&lease_id) {
                        lease.state = LeaseState::Accepted;
                    }
                    report.accepted += 1;
                    tracing::info!(%lease_id, %host_id, "a host accepted a launch");
                    continue;
                }
                Ok(Ok(ack)) => {
                    tracing::info!(
                        %lease_id,
                        %host_id,
                        reason = ack.reason.map_or("unspecified", |reason| reason.as_str()),
                        "a host refused a launch; trying the next"
                    );
                }
                Ok(Err(_)) => {
                    tracing::info!(%lease_id, %host_id, "a launch could not be delivered; trying the next host");
                }
                Err(_) => {
                    tracing::warn!(%lease_id, %host_id, "a host did not answer a launch in time; trying the next");
                    // It may still accept late: tell it not to.
                    self.registry.send(
                        &host_id,
                        ServerMessage::CancelLaunch(CancelLaunch {
                            lease_id: lease_id.clone(),
                        }),
                    );
                }
            }
            self.state().leases.remove(&lease_id);
            report.refused += 1;
            tried.insert(host_id);
        }
    }

    /// Under the lock: cancels surplus leases, then picks the next host and
    /// records an offered lease for it, so a concurrent rebalance counts it.
    fn offer(
        &self,
        key: &JobKey,
        tried: &HashSet<String>,
        report: &mut Rebalanced,
    ) -> Option<(String, String, Launch)> {
        let required = key.required();
        // Read before the placement lock: the registry has its own.
        let candidates = self.registry.launch_candidates(&key.repository, &required);
        let mut state = self.state();
        let queued = state.queues.get(key).map_or(0, Queue::len);
        let open = state.leases_for(key);
        if open > queued {
            self.cancel_surplus(&mut state, key, open - queued, report);
            return None;
        }
        if open == queued {
            return None;
        }
        let chosen = rank(
            candidates
                .into_iter()
                .filter(|candidate| !tried.contains(&candidate.host_id))
                .filter(|candidate| !candidate.heartbeat.unfit && !candidate.heartbeat.draining)
                .filter(|candidate| {
                    candidate.heartbeat.free_slots > state.leases_on(&candidate.host_id)
                })
                .collect(),
        )
        .into_iter()
        .next()?;
        let lease_id = uuid::Uuid::new_v4().simple().to_string();
        let now = Instant::now();
        let ttl = self.lease_ttl;
        state.leases.insert(
            lease_id.clone(),
            Lease {
                key: key.clone(),
                host_id: chosen.host_id.clone(),
                state: LeaseState::Offered,
                sent_at: now,
                expires: now + ttl + self.ack_timeout,
            },
        );
        let job_key = state
            .queues
            .get(key)
            .and_then(|queue| queue.jobs.keys().next())
            .map_or_else(
                || key.repository.clone(),
                |job| format!("{}#{job}", key.repository),
            );
        let ttl_secs = u32::try_from(ttl.as_secs()).unwrap_or(u32::MAX);
        let launch = Launch {
            target: chosen.target,
            profile: chosen.profile,
            job_key,
            lease_id: lease_id.clone(),
            expires_at: chrono::Utc::now().timestamp() + i64::from(ttl_secs),
            ttl_secs,
        };
        Some((lease_id, chosen.host_id, launch))
    }

    fn cancel_surplus(
        &self,
        state: &mut State,
        key: &JobKey,
        surplus: usize,
        report: &mut Rebalanced,
    ) {
        // Newest first: the oldest lease's runner is the likeliest to be about
        // to take a job. An offered lease is left to its pending answer.
        let mut accepted: Vec<(String, Instant)> = state
            .leases
            .iter()
            .filter(|(_, lease)| &lease.key == key && lease.state == LeaseState::Accepted)
            .map(|(id, lease)| (id.clone(), lease.sent_at))
            .collect();
        accepted.sort_by_key(|(_, at)| std::cmp::Reverse(*at));
        for (lease_id, _) in accepted.into_iter().take(surplus) {
            if let Some(lease) = state.leases.remove(&lease_id) {
                self.registry.send(
                    &lease.host_id,
                    ServerMessage::CancelLaunch(CancelLaunch {
                        lease_id: lease_id.clone(),
                    }),
                );
                report.cancelled += 1;
                tracing::info!(%lease_id, host_id = %lease.host_id, "a launch was cancelled: its job is no longer queued");
            }
        }
    }
}

/// Best first: a warm workspace, then the most free RAM, then the fewest busy
/// slots, then the host id so the order is stable.
fn rank(mut candidates: Vec<Candidate>) -> Vec<Candidate> {
    candidates.sort_by(|a, b| {
        b.warm
            .cmp(&a.warm)
            .then_with(|| {
                b.heartbeat
                    .free_ram_bytes
                    .unwrap_or(0)
                    .cmp(&a.heartbeat.free_ram_bytes.unwrap_or(0))
            })
            .then_with(|| a.heartbeat.busy_slots.cmp(&b.heartbeat.busy_slots))
            .then_with(|| a.host_id.cmp(&b.host_id))
    });
    candidates
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use runner_manager_coordinator_protocol::{
        Heartbeat, Hello, LAUNCH_VERSION, Profile, RefusalReason, Target, TargetRef, TargetScope,
    };
    use tokio::sync::mpsc;

    use super::*;
    use crate::registry::{Coverage, Outbound};
    use crate::webhook::required_labels;

    const POOL: &[&str] = &["rm-pool-linux"];

    fn required(labels: &[&str]) -> Vec<Label> {
        required_labels(&labels.iter().map(ToString::to_string).collect::<Vec<_>>())
            .expect("resolvable")
    }

    fn covering() -> Coverage {
        Coverage {
            interval: Some(Duration::from_secs(120)),
            repositories: BTreeSet::from(["octo/app".to_string()]),
            accounts: BTreeSet::new(),
        }
    }

    /// How a fake host answers a launch.
    #[derive(Clone, Copy)]
    enum Answer {
        Accept,
        Refuse,
        Silent,
    }

    struct FakeHost {
        rx: mpsc::Receiver<Outbound>,
    }

    /// Connects `id` at `version` with a pool profile (or not), `free` free
    /// slots and `ram` free RAM.
    fn connect(
        registry: &Registry,
        id: &str,
        version: u32,
        labels: &[&str],
        free: u32,
        ram: u64,
    ) -> FakeHost {
        let (tx, rx) = mpsc::channel(64);
        let connection = registry.register(id, version, tx);
        registry.set_hello(
            id,
            connection,
            Hello {
                protocol_version: version,
                host_id: id.into(),
                os: "linux".into(),
                arch: "x64".into(),
                cores: 8,
                ram_bytes: None,
                disk_free_bytes: None,
                targets: vec![Target {
                    scope: TargetScope::Repo,
                    name: "octo/app".into(),
                    profiles: vec![Profile {
                        name: "pool".into(),
                        labels: labels.iter().map(ToString::to_string).collect(),
                        enabled: true,
                        warm: false,
                    }],
                }],
            },
        );
        registry.set_heartbeat(
            id,
            connection,
            Heartbeat {
                free_slots: free,
                busy_slots: 0,
                free_ram_bytes: Some(ram),
                ..Heartbeat::default()
            },
        );
        FakeHost { rx }
    }

    /// Answers every launch `host` receives, forever; returns what it saw.
    fn answer(
        placement: &Arc<Placement>,
        id: &'static str,
        mut host: FakeHost,
        how: Answer,
    ) -> tokio::task::JoinHandle<Vec<ServerMessage>> {
        let placement = Arc::clone(placement);
        tokio::spawn(async move {
            let mut seen = Vec::new();
            while let Ok(Some(Outbound::Send(message))) =
                tokio::time::timeout(Duration::from_millis(400), host.rx.recv()).await
            {
                if let ServerMessage::Launch(launch) = &message {
                    match how {
                        Answer::Accept => {
                            placement.acknowledged(id, LaunchAck::accepted(&launch.lease_id));
                        }
                        Answer::Refuse => placement.acknowledged(
                            id,
                            LaunchAck::refused(&launch.lease_id, RefusalReason::HostCapacity),
                        ),
                        Answer::Silent => {}
                    }
                }
                seen.push(message);
            }
            seen
        })
    }

    fn launches(seen: &[ServerMessage]) -> usize {
        seen.iter()
            .filter(|message| matches!(message, ServerMessage::Launch(_)))
            .count()
    }

    fn setup() -> (Arc<Registry>, Arc<Placement>) {
        let registry = Arc::new(Registry::default());
        registry.set_coverage(covering());
        let placement = Arc::new(Placement::with_timings(
            Arc::clone(&registry),
            Duration::from_millis(150),
            Duration::from_secs(300),
        ));
        (registry, placement)
    }

    #[tokio::test]
    async fn exactly_one_of_several_eligible_hosts_is_sent_a_launch() {
        let (registry, placement) = setup();
        let a = connect(&registry, "a", LAUNCH_VERSION, POOL, 2, 8 << 30);
        let b = connect(&registry, "b", LAUNCH_VERSION, POOL, 2, 64 << 30);
        let c = connect(&registry, "c", LAUNCH_VERSION, POOL, 2, 16 << 30);
        let hosts = [
            answer(&placement, "a", a, Answer::Accept),
            answer(&placement, "b", b, Answer::Accept),
            answer(&placement, "c", c, Answer::Accept),
        ];

        // The webhook's wake skips every host in launch mode.
        assert_eq!(
            registry.wake_for_job("octo/app", &["rm-pool-linux".into()], "d"),
            0
        );
        let key = placement
            .queued("Octo/App", &required(POOL), 7)
            .expect("a pool job");
        let report = placement.rebalance(&key).await;
        assert_eq!(
            report,
            Rebalanced {
                accepted: 1,
                ..Rebalanced::default()
            }
        );
        assert_eq!(placement.counts(&key), (1, 1));
        // Placed again: nothing more to do.
        assert_eq!(placement.rebalance(&key).await, Rebalanced::default());

        let mut seen = Vec::new();
        for host in hosts {
            seen.push(launches(&host.await.expect("host")));
        }
        assert_eq!(seen, vec![0, 1, 0], "the host with the most free RAM, once");
    }

    #[tokio::test]
    async fn a_refusal_or_silence_moves_on_to_the_next_host() {
        let (registry, placement) = setup();
        let refuses = connect(&registry, "refuses", LAUNCH_VERSION, POOL, 1, 64 << 30);
        let silent = connect(&registry, "silent", LAUNCH_VERSION, POOL, 1, 32 << 30);
        let accepts = connect(&registry, "accepts", LAUNCH_VERSION, POOL, 1, 8 << 30);
        let refuses = answer(&placement, "refuses", refuses, Answer::Refuse);
        let silent = answer(&placement, "silent", silent, Answer::Silent);
        let accepts = answer(&placement, "accepts", accepts, Answer::Accept);

        let key = placement
            .queued("octo/app", &required(POOL), 1)
            .expect("pool");
        let report = placement.rebalance(&key).await;
        assert_eq!(report.accepted, 1);
        assert_eq!(report.refused, 2);
        assert_eq!(placement.counts(&key), (1, 1));
        assert_eq!(launches(&refuses.await.expect("host")), 1);
        let silent = silent.await.expect("host");
        assert_eq!(launches(&silent), 1);
        assert!(
            silent
                .iter()
                .any(|message| matches!(message, ServerMessage::CancelLaunch(_))),
            "a host that did not answer in time is told to drop it"
        );
        assert_eq!(launches(&accepts.await.expect("host")), 1);
    }

    #[tokio::test]
    async fn queued_jobs_never_get_more_leases_than_jobs_or_slots() {
        let (registry, placement) = setup();
        // Two jobs, five hosts with room: exactly two launches.
        let mut hosts = Vec::new();
        for id in ["h1", "h2", "h3", "h4", "h5"] {
            let host = connect(&registry, id, LAUNCH_VERSION, POOL, 1, 8 << 30);
            hosts.push(answer(&placement, id, host, Answer::Accept));
        }
        let pool = required(POOL);
        let key = placement.queued("octo/app", &pool, 1).expect("pool");
        placement.queued("octo/app", &pool, 2);
        // Two rebalances racing for the same key.
        let (one, two) = tokio::join!(placement.rebalance(&key), placement.rebalance(&key));
        assert_eq!(one.accepted + two.accepted, 2);
        assert_eq!(placement.counts(&key), (2, 2));
        let mut total = 0;
        for host in hosts {
            let launched = launches(&host.await.expect("host"));
            assert!(launched <= 1, "one slot each");
            total += launched;
        }
        assert_eq!(total, 2);

        // Five jobs, two hosts with one slot each: two leases, and a second
        // pass sends nothing more until a slot frees.
        let (registry, placement) = setup();
        let one = connect(&registry, "one", LAUNCH_VERSION, POOL, 1, 8 << 30);
        let two = connect(&registry, "two", LAUNCH_VERSION, POOL, 1, 8 << 30);
        let one = answer(&placement, "one", one, Answer::Accept);
        let two = answer(&placement, "two", two, Answer::Accept);
        for job in 1..=5 {
            placement.queued("octo/app", &pool, job);
        }
        assert_eq!(placement.rebalance(&key).await.accepted, 2);
        assert_eq!(placement.rebalance(&key).await, Rebalanced::default());
        assert_eq!(placement.counts(&key), (5, 2));
        assert_eq!(launches(&one.await.expect("host")), 1);
        assert_eq!(launches(&two.await.expect("host")), 1);
    }

    #[tokio::test]
    async fn a_lease_expires_and_its_job_is_placed_again() {
        let registry = Arc::new(Registry::default());
        registry.set_coverage(covering());
        let placement = Arc::new(Placement::with_timings(
            Arc::clone(&registry),
            Duration::from_millis(150),
            Duration::from_millis(50),
        ));
        let host = connect(&registry, "h", LAUNCH_VERSION, POOL, 4, 8 << 30);
        let host = answer(&placement, "h", host, Answer::Accept);
        let key = placement
            .queued("octo/app", &required(POOL), 1)
            .expect("pool");
        assert_eq!(placement.rebalance(&key).await.accepted, 1);
        assert!(placement.expire(Instant::now()).is_empty(), "not yet");
        let later = Instant::now() + Duration::from_secs(1);
        assert_eq!(placement.expire(later), vec![key.clone()]);
        assert_eq!(placement.counts(&key), (1, 0));
        assert_eq!(placement.rebalance(&key).await.accepted, 1);
        assert_eq!(launches(&host.await.expect("host")), 2);
    }

    #[tokio::test]
    async fn a_job_that_left_the_queue_cancels_its_surplus_lease_and_a_claim_closes_one() {
        let (registry, placement) = setup();
        let host = connect(&registry, "h", LAUNCH_VERSION, POOL, 4, 8 << 30);
        let host = answer(&placement, "h", host, Answer::Accept);
        let pool = required(POOL);
        let key = placement.queued("octo/app", &pool, 1).expect("pool");
        placement.queued("octo/app", &pool, 2);
        assert_eq!(placement.rebalance(&key).await.accepted, 2);

        // Job 1 was cancelled while queued: one lease too many.
        placement.dequeued("octo/app", &pool, 1);
        assert_eq!(placement.rebalance(&key).await.cancelled, 1);
        assert_eq!(placement.counts(&key), (1, 1));

        // The remaining lease's runner takes job 2: the host says so.
        let seen_lease = {
            let state = placement.state();
            state.leases.keys().next().cloned().expect("a lease")
        };
        placement.attempt_started(
            "h",
            &AttemptStarted {
                lease_id: Some(seen_lease),
                runner_name: "runner-manager-x".into(),
                target: TargetRef {
                    scope: TargetScope::Repo,
                    name: "octo/app".into(),
                },
                profile: "pool".into(),
            },
        );
        placement.dequeued("octo/app", &pool, 2);
        assert_eq!(placement.counts(&key), (0, 0));
        assert_eq!(placement.rebalance(&key).await, Rebalanced::default());
        let seen = host.await.expect("host");
        assert_eq!(launches(&seen), 2);
        assert_eq!(
            seen.iter()
                .filter(|message| matches!(message, ServerMessage::CancelLaunch(_)))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn older_uncovered_unfit_or_full_hosts_are_not_candidates_and_are_woken_instead() {
        let (registry, placement) = setup();
        // A version-2 host serving the pool label: woken, never launched.
        let mut old = connect(&registry, "old", 2, POOL, 4, 64 << 30);
        // A host with no free slot.
        let full = connect(&registry, "full", LAUNCH_VERSION, POOL, 0, 64 << 30);
        // A host without the pool label.
        let plain = connect(&registry, "plain", LAUNCH_VERSION, &["linux"], 4, 64 << 30);
        let full = answer(&placement, "full", full, Answer::Accept);
        let plain = answer(&placement, "plain", plain, Answer::Accept);
        // Only the full host qualifies by version, coverage and labels; its
        // slots rule it out at placement.
        let candidates: Vec<String> = placement
            .registry()
            .launch_candidates("octo/app", &required(POOL))
            .into_iter()
            .map(|candidate| candidate.host_id)
            .collect();
        assert_eq!(candidates, vec!["full".to_string()]);
        let key = placement
            .queued("octo/app", &required(POOL), 1)
            .expect("pool");
        assert_eq!(placement.rebalance(&key).await, Rebalanced::default());
        assert_eq!(placement.counts(&key), (1, 0), "waits for a host");

        // The version-2 host still gets the wake it always got.
        while old.rx.try_recv().is_ok() {}
        assert_eq!(
            registry.wake_for_job("octo/app", &["rm-pool-linux".into()], "d"),
            1
        );
        assert!(matches!(
            old.rx.try_recv(),
            Ok(Outbound::Send(ServerMessage::Wake(_)))
        ));
        assert_eq!(launches(&full.await.expect("host")), 0);
        assert_eq!(launches(&plain.await.expect("host")), 0);
        // Not a pool job: placement does not track it.
        assert!(
            placement
                .queued("octo/app", &required(&["linux"]), 9)
                .is_none()
        );
    }

    #[tokio::test]
    async fn the_sweep_count_adds_unnamed_jobs_and_drops_stale_ones() {
        let (registry, placement) = setup();
        let host = connect(&registry, "h", LAUNCH_VERSION, POOL, 8, 8 << 30);
        let host = answer(&placement, "h", host, Answer::Accept);
        let pool = required(POOL);
        let labels: BTreeSet<Label> = pool.iter().cloned().collect();
        let key = placement.queued("octo/app", &pool, 1).expect("pool");
        // Three queued by the sweep's count, one of them announced.
        let changed = placement.swept("Octo/App", &HashMap::from([(labels.clone(), 3)]));
        assert_eq!(changed, vec![key.clone()]);
        assert_eq!(placement.counts(&key).0, 3);
        assert_eq!(placement.rebalance(&key).await.accepted, 3);
        // The next sweep sees none: the queue empties and the leases are
        // cancelled.
        placement.swept("octo/app", &HashMap::new());
        assert_eq!(placement.counts(&key).0, 0);
        assert_eq!(placement.rebalance(&key).await.cancelled, 3);
        drop(host);
    }

    #[tokio::test]
    async fn a_disconnected_host_loses_its_leases_and_answers_only_count_from_their_host() {
        let (registry, placement) = setup();
        let host = connect(&registry, "h", LAUNCH_VERSION, POOL, 2, 8 << 30);
        let mut host = host;
        let key = placement
            .queued("octo/app", &required(POOL), 1)
            .expect("pool");
        let rebalance = {
            let placement = Arc::clone(&placement);
            let key = key.clone();
            tokio::spawn(async move { placement.rebalance(&key).await })
        };
        let launch = loop {
            match host.rx.recv().await {
                Some(Outbound::Send(ServerMessage::Launch(launch))) => break launch,
                Some(_) => {}
                None => panic!("a launch"),
            }
        };
        // Another host cannot answer for it.
        placement.acknowledged("intruder", LaunchAck::accepted(&launch.lease_id));
        placement.host_gone("h");
        let report = rebalance.await.expect("rebalance");
        assert_eq!(report.accepted, 0);
        assert_eq!(placement.counts(&key), (1, 0));
    }
}
