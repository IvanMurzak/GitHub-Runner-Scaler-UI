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
//! A lease closes, and its job (if still queued) is placed again, when:
//!
//! * its runner takes a job (the host's `attempt_started`) or its attempt
//!   ends (`attempt_finished`);
//! * its host disconnects or connects again;
//! * its host's heartbeat no longer lists it (the host dropped it);
//! * another runner of the same host takes a job of its queue: a runner takes
//!   *any* job of its labels, so the lease's runner would find nothing left;
//! * it expires ([`LEASE_TTL`], `COORDINATOR_LEASE_TTL`).
//!
//! A webhook `in_progress` or `completed` takes the job out of the
//! queue; the caller rebalances after [`CLAIM_GRACE`], by when the host whose
//! runner took it has normally closed that very lease, so a surplus lease
//! cancelled is one whose runner took nothing.
//!
//! # Choosing the host (design 4.5)
//!
//! Candidates: connected version-3 hosts whose target serving the repository
//! is covered by the sweep (launch mode), with an enabled pool profile whose
//! labels cover the job, not unfit, not draining, and with a free slot by
//! their last heartbeat once the leases already sent to them are counted.
//!
//! Stage 4: with [`crate::stats::Statistics`] attached, the queue's demand is
//! its heaviest queued job's p90 peak memory; a host that cannot hold it
//! (less the estimates of its launches whose runner took no job yet) is
//! passed over, and the rest are ranked by [`crate::stats::score`]. Each
//! decision is logged with host ids and scores and kept for `stats`. With no
//! statistics for the queue, the order is stage 3's: a warm workspace for
//! the repository, then the most free RAM, then the fewest busy slots.
//!
//! The first is sent a `launch`; a refusal or no answer within
//! [`ACK_TIMEOUT`] moves on to the next. A queue left short is given a reason
//! ([`Unplaced`]), logged at most once a minute and shown by `stats`.
//!
//! # Logging
//!
//! Lease ids, host ids, job ids and counts only: never a repository name, a
//! label or a runner name, which came off the wire.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use runner_manager_domain::coordinator_protocol::{
    AttemptFinished, AttemptStarted, CancelLaunch, Launch, LaunchAck, OpenLease, PendingQueue,
    PlacementDecision, RefusalReason, ServerMessage, is_managed_runner_name,
};
use runner_manager_domain::model::Label;
use tokio::sync::oneshot;

use crate::registry::{Candidate, Registry, is_pool_job};
use crate::stats::{Aggregates, Contender, Demand, Statistics, score};

/// How long a host has to answer a `launch`.
pub const ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a lease counts once accepted by default
/// (`COORDINATOR_LEASE_TTL`): long enough for a cold runner to register and
/// take a job. A lease whose runner is not coming is normally closed long
/// before by the host's heartbeat or by another of its runners taking the job.
pub const LEASE_TTL: Duration = Duration::from_secs(2 * 60);

/// The shortest lease lifetime accepted.
pub const MIN_LEASE_TTL: Duration = Duration::from_secs(30);

/// A queue that stays unplaced for the same reason is logged at most this
/// often.
const UNPLACED_LOG_EVERY: Duration = Duration::from_secs(60);

/// How long a host's runner is remembered from its `attempt_started`, and a
/// runner that took a job before its host said so, for closing a lease when
/// another runner of the same host takes its queue's job.
const RUNNER_MEMORY: Duration = Duration::from_secs(10 * 60);

/// Runners remembered at most, each way.
const MAX_RUNNERS: usize = 10_000;

/// Pending queues and open leases `stats` shows at most.
const REPORT_PENDING: usize = 20;
const REPORT_LEASES: usize = 50;

/// How long after a job leaves the queue its key is rebalanced: time for the
/// host whose runner took it to report `attempt_started`, so the lease
/// cancelled as surplus is not that one.
pub const CLAIM_GRACE: Duration = Duration::from_secs(3);

/// How long a lease whose runner took a job (`attempt_started`) still counts,
/// waiting for the webhook that takes that job out of the queue; and how long
/// a job that left the queue waits for the claim of the runner that took it.
pub const CLAIM_HOLD: Duration = Duration::from_secs(30);

/// How long the memory a job was expected to need stays reserved on its host
/// after its runner took it: a build reaches its peak minutes in, and until
/// then the host's heartbeat still shows that memory free.
pub const RAMP_HOLD: Duration = Duration::from_secs(2 * 60);

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

    /// Its labels, comma-separated, as `stats` shows them.
    #[must_use]
    pub fn labels_csv(&self) -> String {
        self.labels
            .iter()
            .map(Label::as_str)
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[derive(Debug, Default)]
struct Queue {
    /// Job ids a webhook announced, when, and their statistics key
    /// (`owner/repo/workflow/job`) when the webhook named it.
    jobs: BTreeMap<u64, (Instant, Option<String>)>,
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
    /// Its runner took a job; held until the webhook takes that job out of
    /// the queue, so the job is not placed a second time meanwhile.
    Claimed(Instant),
}

impl LeaseState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Accepted => "accepted",
            Self::Claimed(_) => "claimed",
        }
    }
}

#[derive(Debug, Clone)]
struct Lease {
    key: JobKey,
    host_id: String,
    state: LeaseState,
    sent: Instant,
    expires: Instant,
    /// The memory its queue was expected to need when it was placed.
    estimate: u64,
}

/// Why a pool queue has fewer runners on their way than jobs queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unplaced {
    /// No connected launch-mode host serves it with an enabled pool profile.
    NoCandidate,
    /// Every candidate is unfit or draining.
    UnfitOrDraining,
    /// Every candidate is full by its last heartbeat and open leases.
    NoFreeSlot,
    /// No candidate's free memory holds the queue's measured estimate.
    NoMemoryFit,
    /// The last candidate tried refused, for this reason.
    Refused(RefusalReason),
    /// The last candidate tried did not answer, or could not be reached.
    Unanswered,
}

impl Unplaced {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoCandidate => "no_candidate",
            Self::UnfitOrDraining => "unfit_or_draining",
            Self::NoFreeSlot => "no_free_slot",
            Self::NoMemoryFit => "no_memory_fit",
            Self::Refused(_) => "refused",
            Self::Unanswered => "unanswered",
        }
    }

    const fn refusal(self) -> Option<RefusalReason> {
        match self {
            Self::Refused(reason) => Some(reason),
            _ => None,
        }
    }
}

/// A runner a host said took a job, or a job taken by a runner its host had
/// not said yet.
#[derive(Debug, Clone)]
struct Runner {
    host_id: String,
    /// The queue of the lease it was started for, if any.
    queue: Option<JobKey>,
    at: Instant,
}

#[derive(Debug, Default)]
struct State {
    queues: HashMap<JobKey, Queue>,
    /// Why each queue short of leases was not placed, and when it was last
    /// logged.
    unplaced: HashMap<JobKey, (Unplaced, Option<Instant>)>,
    /// Runners whose `attempt_started` came in, by lower-cased name.
    runners: HashMap<String, Runner>,
    /// Jobs a webhook said a runner took before its host reported that
    /// runner, by lower-cased runner name.
    taken: HashMap<String, (JobKey, Instant)>,
    leases: HashMap<String, Lease>,
    /// When a webhook last changed a key's queue, so a sweep that read
    /// GitHub before that does not overwrite it.
    touched: HashMap<JobKey, Instant>,
    /// Jobs that left the queue before the runner that took them was
    /// reported: the next claim on that key closes its lease outright.
    credits: HashMap<JobKey, VecDeque<Instant>>,
    /// Stage 4: the estimates of leases whose runner took its job, per host,
    /// held for [`RAMP_HOLD`] from the claim.
    ramping: Vec<(String, u64, Instant)>,
}

impl State {
    fn leases_for(&self, key: &JobKey) -> usize {
        self.leases
            .values()
            .filter(|lease| &lease.key == key)
            .count()
    }

    /// The estimates of `host_id`'s leases whose runner took no job yet:
    /// memory its heartbeat still shows free.
    fn reserved_on(&self, host_id: &str) -> u64 {
        let now = Instant::now();
        let leased = self
            .leases
            .values()
            .filter(|lease| lease.host_id == host_id)
            .filter(|lease| match lease.state {
                LeaseState::Claimed(at) => now.saturating_duration_since(at) < RAMP_HOLD,
                _ => true,
            })
            .fold(0u64, |sum, lease| sum.saturating_add(lease.estimate));
        self.ramping
            .iter()
            .filter(|(host, _, until)| host == host_id && *until > now)
            .fold(leased, |sum, (_, estimate, _)| {
                sum.saturating_add(*estimate)
            })
    }

    /// Removes a lease whose runner took its job; its estimate stays
    /// reserved on its host until [`RAMP_HOLD`] after the claim.
    fn release_claimed(&mut self, lease_id: &str, claimed_at: Instant) {
        if let Some(lease) = self.leases.remove(lease_id)
            && lease.estimate > 0
        {
            self.ramping
                .push((lease.host_id, lease.estimate, claimed_at + RAMP_HOLD));
        }
    }

    fn job_keys(&self, key: &JobKey) -> (Vec<String>, bool) {
        self.queues.get(key).map_or((Vec::new(), true), |queue| {
            (
                queue
                    .jobs
                    .values()
                    .filter_map(|(_, job_key)| job_key.clone())
                    .collect(),
                queue.unnamed > 0 || queue.jobs.values().any(|(_, job_key)| job_key.is_none()),
            )
        })
    }

    /// Closes the oldest accepted lease `host_id` holds for `key`: another of
    /// its runners took that queue's job. The host is told to drop it.
    fn close_oldest_accepted(&mut self, registry: &Registry, host_id: &str, key: &JobKey) {
        let oldest = self
            .leases
            .iter()
            .filter(|(_, lease)| {
                lease.host_id == host_id && &lease.key == key && lease.state == LeaseState::Accepted
            })
            .min_by_key(|(_, lease)| lease.sent)
            .map(|(id, _)| id.clone());
        if let Some(lease_id) = oldest
            && self.cancel_lease(registry, &lease_id)
        {
            tracing::info!(%lease_id, %host_id, "a lease was closed: another runner of its host took its queue's job");
        }
    }

    /// Removes `lease_id` and tells its host to drop the launch; `false`
    /// when there was no such lease.
    fn cancel_lease(&mut self, registry: &Registry, lease_id: &str) -> bool {
        let Some(lease) = self.leases.remove(lease_id) else {
            return false;
        };
        registry.send(
            &lease.host_id,
            ServerMessage::CancelLaunch(CancelLaunch {
                lease_id: lease_id.to_string(),
            }),
        );
        true
    }

    /// Records why `key` is short of runners; logs it when that changed or a
    /// minute passed.
    fn note_unplaced(&mut self, key: &JobKey, reason: Unplaced) {
        let now = Instant::now();
        let entry = self.unplaced.entry(key.clone()).or_insert((reason, None));
        let due = entry.0 != reason
            || entry
                .1
                .is_none_or(|at| now.saturating_duration_since(at) >= UNPLACED_LOG_EVERY);
        entry.0 = reason;
        if due {
            entry.1 = Some(now);
            let queue = self.queues.get(key);
            let queued = queue.map_or(0, Queue::len);
            let oldest_job = queue
                .and_then(|queue| queue.jobs.iter().min_by_key(|(_, (at, _))| *at))
                .map(|(id, _)| *id);
            let leases = self.leases_for(key);
            tracing::info!(
                reason = reason.as_str(),
                refusal = reason.refusal().map_or("", RefusalReason::as_str),
                queued,
                leases,
                oldest_job = oldest_job.unwrap_or_default(),
                "a pool queue is not placed"
            );
        }
    }

    /// Launches on `host_id` its heartbeat at `heartbeat_at` cannot have
    /// counted yet: sent after it, and not claimed.
    fn unreported_on(&self, host_id: &str, heartbeat_at: Instant) -> u32 {
        u32::try_from(
            self.leases
                .values()
                .filter(|lease| lease.host_id == host_id && lease.sent > heartbeat_at)
                .filter(|lease| !matches!(lease.state, LeaseState::Claimed(_)))
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
    /// Stage 4: weighs placement by what jobs used; `None` places as stage 3.
    stats: Option<Arc<Statistics>>,
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
            stats: None,
        }
    }

    /// Weighs placement with `stats` (stage 4).
    #[must_use]
    pub fn with_statistics(mut self, stats: Arc<Statistics>) -> Self {
        self.stats = Some(stats);
        self
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

    /// A webhook announced a queued job; its key, or `None` (nothing
    /// recorded) for a job that asks for no pool.
    pub fn queued(&self, repository: &str, required: &[Label], job_id: u64) -> Option<JobKey> {
        self.queued_job(repository, required, job_id, None)
    }

    /// [`Self::queued`] for a job the webhook named: `job_key` is its
    /// statistics key, which tells placement how heavy it is.
    pub fn queued_job(
        &self,
        repository: &str,
        required: &[Label],
        job_id: u64,
        job_key: Option<String>,
    ) -> Option<JobKey> {
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
        let now = Instant::now();
        state.touched.insert(key.clone(), now);
        let queue = state.queues.entry(key.clone()).or_default();
        if queue.jobs.insert(job_id, (now, job_key)).is_none() && queue.unnamed > 0 {
            // A late webhook for a job the sweep already counted.
            queue.unnamed -= 1;
        }
        Some(key)
    }

    /// A webhook said a job left the queue: a runner took it
    /// (`in_progress`) or it ended (`completed`).
    pub fn dequeued(&self, repository: &str, required: &[Label], job_id: u64) -> Option<JobKey> {
        self.dequeued_by(repository, required, job_id, None)
    }

    /// [`Self::dequeued`], naming the runner that took the job (`in_progress`).
    /// A runner of this tool whose host started it for no lease of this
    /// queue closes that host's oldest accepted lease for the queue: the
    /// runner that lease was waiting for would find the job gone.
    pub fn dequeued_by(
        &self,
        repository: &str,
        required: &[Label],
        job_id: u64,
        runner: Option<&str>,
    ) -> Option<JobKey> {
        if !is_pool_job(required) {
            return None;
        }
        let key = JobKey::new(repository, required);
        let now = Instant::now();
        let mut state = self.state();
        state.touched.insert(key.clone(), now);
        if let Some(queue) = state.queues.get_mut(&key) {
            queue.take(job_id);
            if queue.len() == 0 {
                state.queues.remove(&key);
            }
        }
        let runner = runner
            .filter(|name| is_managed_runner_name(name))
            .map(str::to_ascii_lowercase);
        if let Some(name) = runner {
            match state.runners.get(&name).cloned() {
                // Started for no lease, or for another queue's.
                Some(known) if known.queue.as_ref() != Some(&key) => {
                    state.close_oldest_accepted(&self.registry, &known.host_id, &key);
                    return Some(key);
                }
                Some(_) => {}
                // Its host has not said yet: its `attempt_started` decides.
                None => {
                    if state.taken.len() < MAX_RUNNERS {
                        state.taken.insert(name, (key.clone(), now));
                    }
                }
            }
        }
        // The runner that took it closes its lease; if it already said so,
        // that lease goes now, else its claim will.
        let claimed = state
            .leases
            .iter()
            .filter(|(_, lease)| lease.key == key)
            .filter_map(|(id, lease)| match lease.state {
                LeaseState::Claimed(at) => Some((id.clone(), at)),
                _ => None,
            })
            .min_by_key(|(_, at)| *at);
        match claimed {
            Some((id, at)) => state.release_claimed(&id, at),
            None => state.credits.entry(key.clone()).or_default().push_back(now),
        }
        Some(key)
    }

    /// The sweep counted `counts` queued pool jobs per required label set in
    /// `repository`, reading it from `read_at` on. `floor`: the listing was
    /// truncated, so a count is a minimum and nothing is taken away. A key a
    /// webhook changed after `read_at` is left alone: the webhook is newer.
    /// Returns the keys that changed.
    pub fn swept(
        &self,
        repository: &str,
        counts: &HashMap<BTreeSet<Label>, u32>,
        read_at: Instant,
        floor: bool,
    ) -> Vec<JobKey> {
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
            if state.touched.get(&key).is_some_and(|at| *at >= read_at) {
                continue;
            }
            let swept = counts.get(&key.labels).copied().unwrap_or(0);
            let queue = state.queues.entry(key.clone()).or_default();
            let before = queue.len();
            let named = u32::try_from(queue.jobs.len()).unwrap_or(u32::MAX);
            if swept >= named {
                queue.unnamed = if floor {
                    queue.unnamed.max(swept - named)
                } else {
                    swept - named
                };
            } else if floor {
                // A minimum below what is known says nothing.
            } else {
                // Some announced jobs left without a webhook saying so: the
                // oldest are the ones most likely gone.
                queue.unnamed = 0;
                let surplus = (named - swept) as usize;
                let oldest: Vec<u64> = {
                    let mut by_age: Vec<(u64, Instant)> =
                        queue.jobs.iter().map(|(id, (at, _))| (*id, *at)).collect();
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

    /// A host's runner took a job. Its lease closes if the job already left
    /// the queue; otherwise it is held as claimed until the webhook says so.
    pub fn attempt_started(&self, host_id: &str, started: &AttemptStarted) {
        let mut state = self.state();
        let name = started.runner_name.to_ascii_lowercase();
        let taken = state.taken.remove(&name);
        if is_managed_runner_name(&name) && state.runners.len() < MAX_RUNNERS {
            let queue = started
                .lease_id
                .as_ref()
                .and_then(|lease| state.leases.get(lease))
                .filter(|lease| lease.host_id == host_id)
                .map(|lease| lease.key.clone());
            state.runners.insert(
                name,
                Runner {
                    host_id: host_id.to_string(),
                    queue,
                    at: Instant::now(),
                },
            );
        }
        let Some(lease_id) = started.lease_id.as_deref() else {
            // A runner of no lease took a job a webhook already named: that
            // job's credit is its, and the host's oldest lease for that queue
            // is not coming to anything.
            if let Some((key, _)) = taken {
                if let Some(credits) = state.credits.get_mut(&key) {
                    credits.pop_front();
                }
                state.close_oldest_accepted(&self.registry, host_id, &key);
            }
            return;
        };
        let Some(key) = state
            .leases
            .get(lease_id)
            .filter(|lease| lease.host_id == host_id)
            .map(|lease| lease.key.clone())
        else {
            return;
        };
        let credited = state
            .credits
            .get_mut(&key)
            .and_then(VecDeque::pop_front)
            .is_some();
        if credited {
            state.release_claimed(lease_id, Instant::now());
        } else if let Some(lease) = state.leases.get_mut(lease_id) {
            lease.state = LeaseState::Claimed(Instant::now());
        }
    }

    /// A host's attempt ended. Closes its lease, if it still had one.
    pub fn attempt_finished(&self, host_id: &str, finished: &AttemptFinished) {
        self.close(host_id, finished.lease_id.as_deref());
    }

    /// Closes `lease_id` if `host_id` holds it.
    fn close(&self, host_id: &str, lease_id: Option<&str>) {
        let Some(lease_id) = lease_id else {
            return;
        };
        let mut state = self.state();
        if state
            .leases
            .get(lease_id)
            .is_some_and(|lease| lease.host_id == host_id)
        {
            state.leases.remove(lease_id);
        }
    }

    /// A host's heartbeat listed the launches it still holds open (`held`):
    /// every accepted lease of that host it does not list is closed, and the
    /// number closed returned. A lease still being offered, or whose runner
    /// took a job, is left alone: the host reports those another way.
    ///
    /// Sound because one connection is ordered: a lease is accepted here only
    /// after its `launch_ack`, so a heartbeat read after that was sent after
    /// it, when the host already held the launch.
    pub fn reconcile_leases(&self, host_id: &str, held: &[String]) -> usize {
        let held: HashSet<&str> = held.iter().map(String::as_str).collect();
        let mut state = self.state();
        let stale: Vec<String> = state
            .leases
            .iter()
            .filter(|(id, lease)| {
                lease.host_id == host_id
                    && lease.state == LeaseState::Accepted
                    && !held.contains(id.as_str())
            })
            .map(|(id, _)| id.clone())
            .collect();
        for lease_id in &stale {
            state.leases.remove(lease_id);
            tracing::info!(%lease_id, %host_id, "a lease was closed: its host no longer holds it");
        }
        stale.len()
    }

    /// A host disconnected, or connected again (its new link starts with no
    /// launch, whatever an old half-open one held): its leases close, and a
    /// launch it was answering is refused at once.
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
        let held: Vec<(String, Instant)> = state
            .leases
            .iter()
            .filter_map(|(id, lease)| match lease.state {
                LeaseState::Claimed(at) if now.saturating_duration_since(at) >= CLAIM_HOLD => {
                    Some((id.clone(), at))
                }
                _ => None,
            })
            .collect();
        for (id, at) in held {
            state.release_claimed(&id, at);
        }
        state.leases.retain(|_, lease| lease.expires > now);
        state.ramping.retain(|(_, _, until)| *until > now);
        for credits in state.credits.values_mut() {
            credits.retain(|at| now.saturating_duration_since(*at) < CLAIM_HOLD);
        }
        state.credits.retain(|_, credits| !credits.is_empty());
        state
            .touched
            .retain(|_, at| now.saturating_duration_since(*at) < JOB_MEMORY);
        state
            .runners
            .retain(|_, runner| now.saturating_duration_since(runner.at) < RUNNER_MEMORY);
        state
            .taken
            .retain(|_, (_, at)| now.saturating_duration_since(*at) < RUNNER_MEMORY);
        let expired = before - state.leases.len();
        if expired > 0 {
            tracing::info!(expired, "placement leases expired");
        }
        for queue in state.queues.values_mut() {
            queue
                .jobs
                .retain(|_, (at, _)| now.saturating_duration_since(*at) < JOB_MEMORY);
        }
        state.queues.retain(|_, queue| queue.len() > 0);
        let short: Vec<JobKey> = state
            .queues
            .iter()
            .filter(|(key, queue)| queue.len() > state.leases_for(key))
            .map(|(key, _)| key.clone())
            .collect();
        state.unplaced.retain(|key, _| short.contains(key));
        short
    }

    /// The queues short of runners and the open leases, for `stats`.
    #[must_use]
    pub fn snapshot(&self) -> (Vec<PendingQueue>, Vec<OpenLease>) {
        let now = Instant::now();
        let state = self.state();
        let mut open: HashMap<&JobKey, usize> = HashMap::new();
        for lease in state.leases.values() {
            *open.entry(&lease.key).or_default() += 1;
        }
        let leases_for = |key: &JobKey| open.get(key).copied().unwrap_or(0);
        let mut pending: Vec<(Option<Instant>, PendingQueue)> = state
            .queues
            .iter()
            .filter(|(key, queue)| queue.len() > leases_for(key))
            .map(|(key, queue)| {
                let oldest = queue.jobs.values().map(|(at, _)| *at).min();
                let reason = state.unplaced.get(key).map(|(reason, _)| *reason);
                (
                    oldest,
                    PendingQueue {
                        repository: key.repository.clone(),
                        labels: key.labels_csv(),
                        queued: u32::try_from(queue.len()).unwrap_or(u32::MAX),
                        leases: u32::try_from(leases_for(key)).unwrap_or(u32::MAX),
                        oldest_wait_secs: oldest
                            .map(|at| now.saturating_duration_since(at).as_secs()),
                        reason: reason.map(|reason| reason.as_str().to_string()),
                        refusal: reason
                            .and_then(Unplaced::refusal)
                            .map(|refusal| refusal.as_str().to_string()),
                    },
                )
            })
            .collect();
        // The longest waiting first; queues only the sweep counted last.
        pending.sort_by_key(|(oldest, _)| oldest.map_or((1, now), |at| (0, at)));
        let mut leases: Vec<(Instant, OpenLease)> = state
            .leases
            .iter()
            .map(|(id, lease)| {
                (
                    lease.sent,
                    OpenLease {
                        host_id: lease.host_id.clone(),
                        lease_id: id.clone(),
                        state: lease.state.as_str().to_string(),
                        age_secs: now.saturating_duration_since(lease.sent).as_secs(),
                        repository: lease.key.repository.clone(),
                    },
                )
            })
            .collect();
        leases.sort_by(|(a_at, a), (b_at, b)| a.host_id.cmp(&b.host_id).then(a_at.cmp(b_at)));
        (
            pending
                .into_iter()
                .take(REPORT_PENDING)
                .map(|(_, queue)| queue)
                .collect(),
            leases
                .into_iter()
                .take(REPORT_LEASES)
                .map(|(_, lease)| lease)
                .collect(),
        )
    }

    /// Expires leases, then places every job still short of one.
    pub async fn retry_all(&self) {
        for key in self.expire(Instant::now()) {
            self.rebalance(&key).await;
        }
    }

    /// [`Self::rebalance`] after `delay`, off the caller's task.
    pub fn spawn_rebalance(self: &Arc<Self>, key: JobKey, delay: Duration) {
        let placement = Arc::clone(self);
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            placement.rebalance(&key).await;
        });
    }

    /// [`Self::retry_all`], off the caller's task: a slot was freed somewhere.
    pub fn spawn_retry_all(self: &Arc<Self>) {
        let placement = Arc::clone(self);
        tokio::spawn(async move { placement.retry_all().await });
    }

    /// Expires and retries every `tick` ([`TICK`] in service), forever.
    pub async fn run(self: Arc<Self>, tick: Duration) {
        let mut ticks = tokio::time::interval(tick);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticks.tick().await;
            self.retry_all().await;
        }
    }

    /// Brings `key`'s leases to its queued count: places one launch per
    /// missing lease, host by host, and cancels the newest surplus leases.
    pub async fn rebalance(&self, key: &JobKey) -> Rebalanced {
        let mut report = Rebalanced::default();
        let mut tried: HashSet<String> = HashSet::new();
        let mut last_failure = None;
        loop {
            let mut decision = None;
            let offered = self.offer(key, &tried, last_failure, &mut report, &mut decision);
            if let (Some(stats), Some(decision)) = (&self.stats, decision) {
                stats.decided(&decision);
            }
            let Some((lease_id, host_id, launch)) = offered else {
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
                    if let Some(stats) = &self.stats {
                        stats.count_launch();
                    }
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
                    last_failure = Some(Unplaced::Refused(
                        ack.reason.unwrap_or(RefusalReason::Other),
                    ));
                }
                Ok(Err(_)) => {
                    tracing::info!(%lease_id, %host_id, "a launch could not be delivered; trying the next host");
                    last_failure = Some(Unplaced::Unanswered);
                }
                Err(_) => {
                    last_failure = Some(Unplaced::Unanswered);
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
        last_failure: Option<Unplaced>,
        report: &mut Rebalanced,
        decision: &mut Option<PlacementDecision>,
    ) -> Option<(String, String, Launch)> {
        let required: Vec<Label> = key.labels.iter().cloned().collect();
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
            state.unplaced.remove(key);
            return None;
        }
        let untried = |candidate: &Candidate| !tried.contains(&candidate.host_id);
        let fit =
            |candidate: &Candidate| !candidate.heartbeat.unfit && !candidate.heartbeat.draining;
        let free = |candidate: &Candidate| {
            candidate.heartbeat.free_slots
                > state.unreported_on(&candidate.host_id, candidate.heartbeat_at)
        };
        // When nothing is left, the first filter that emptied the field says
        // why; a host tried this round says it best.
        if !candidates.iter().any(|c| untried(c) && fit(c) && free(c)) {
            let reason = if !tried.is_empty() {
                last_failure.unwrap_or(Unplaced::Unanswered)
            } else if candidates.is_empty() {
                Unplaced::NoCandidate
            } else if !candidates.iter().any(fit) {
                Unplaced::UnfitOrDraining
            } else {
                Unplaced::NoFreeSlot
            };
            state.note_unplaced(key, reason);
            return None;
        }
        let eligible: Vec<Candidate> = candidates
            .into_iter()
            .filter(|c| untried(c) && fit(c) && free(c))
            .collect();
        let chosen = match &self.stats {
            Some(stats) => Self::weigh(stats, &state, key, eligible, decision),
            None => rank(eligible).into_iter().next().map(|chosen| (chosen, 0)),
        };
        let Some((chosen, estimate)) = chosen else {
            state.note_unplaced(key, Unplaced::NoMemoryFit);
            return None;
        };
        let lease_id = uuid::Uuid::new_v4().simple().to_string();
        let now = Instant::now();
        let ttl = self.lease_ttl;
        state.leases.insert(
            lease_id.clone(),
            Lease {
                key: key.clone(),
                host_id: chosen.host_id.clone(),
                state: LeaseState::Offered,
                sent: now,
                expires: now + ttl + self.ack_timeout,
                estimate,
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

    /// Stage 4: the queue's demand, every candidate's score, the decision
    /// logged and handed back in `decision` (recorded once the placement
    /// lock is released); the best candidate that fits and the estimate its
    /// lease reserves, or `None` when none fits.
    fn weigh(
        stats: &Statistics,
        state: &State,
        key: &JobKey,
        eligible: Vec<Candidate>,
        decision: &mut Option<PlacementDecision>,
    ) -> Option<(Candidate, u64)> {
        if eligible.is_empty() {
            return None;
        }
        stats.with_aggregates(|aggregates| {
            let config = stats.config();
            let demand_of = |key: &JobKey, aggregates: &Aggregates| -> Demand {
                let (job_keys, unnamed) = state.job_keys(key);
                aggregates.demand(&key.repository, &job_keys, unnamed, config.default_job_ram)
            };
            let demand = demand_of(key, aggregates);
            // The heaviest measured demand of every other queue still short of
            // runners: a host only it fits is spared for it.
            let heavier = state
                .queues
                .iter()
                .filter(|(other, queue)| *other != key && queue.len() > state.leases_for(other))
                .map(|(other, _)| demand_of(other, aggregates))
                .filter(|other| other.source != crate::stats::EstimateSource::Default)
                .map(|other| other.estimate)
                .max();
            let contenders: Vec<Contender> = eligible
                .iter()
                .map(|candidate| Contender {
                    host_id: candidate.host_id.clone(),
                    warm: candidate.warm,
                    free_ram: candidate.heartbeat.free_ram_bytes,
                    total_ram: candidate.ram_bytes,
                    busy_slots: candidate.heartbeat.busy_slots,
                    reserved: state.reserved_on(&candidate.host_id),
                })
                .collect();
            let scored = score(&contenders, &demand, heavier, config, aggregates);
            let chosen = scored
                .first()
                .filter(|(_, best)| best.fits)
                .map(|(contender, _)| contender.host_id.clone());
            let method = if demand.measured {
                "weighted"
            } else {
                "stage3"
            };
            tracing::info!(
                host_id = chosen.as_deref().unwrap_or("none"),
                estimate_bytes = demand.estimate,
                estimate = demand.source.as_str(),
                method,
                candidates = scored.len(),
                fitting = scored.iter().filter(|(_, score)| score.fits).count(),
                "a pool queue was weighed"
            );
            for (_, host) in &scored {
                tracing::debug!(
                    host_id = %host.host_id,
                    fits = host.fits,
                    cache = host.cache,
                    headroom = host.headroom,
                    speed = host.speed,
                    bigfit = host.bigfit,
                    total = host.total,
                    "placement score"
                );
            }
            *decision = Some(PlacementDecision {
                at: chrono::Utc::now().timestamp(),
                repository: key.repository.clone(),
                labels: key.labels_csv(),
                estimate_bytes: demand.estimate,
                estimate_source: demand.source.as_str().to_string(),
                method: method.to_string(),
                chosen: chosen.clone(),
                scores: scored.iter().map(|(_, score)| score.clone()).collect(),
            });
            let chosen = chosen?;
            eligible
                .into_iter()
                .find(|candidate| candidate.host_id == chosen)
                .map(|candidate| (candidate, demand.estimate))
        })
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
            .map(|(id, lease)| (id.clone(), lease.sent))
            .collect();
        accepted.sort_by_key(|(_, at)| std::cmp::Reverse(*at));
        for (lease_id, _) in accepted.into_iter().take(surplus) {
            if state.cancel_lease(&self.registry, &lease_id) {
                report.cancelled += 1;
                tracing::info!(%lease_id, "a launch was cancelled: its job is no longer queued");
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

    use runner_manager_domain::coordinator_protocol::{
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
        setup_with_ttl(Duration::from_secs(300))
    }

    fn setup_with_ttl(lease_ttl: Duration) -> (Arc<Registry>, Arc<Placement>) {
        let registry = Arc::new(Registry::default());
        registry.set_coverage(covering());
        let placement = Arc::new(Placement::with_timings(
            Arc::clone(&registry),
            Duration::from_millis(150),
            lease_ttl,
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
        let (registry, placement) = setup_with_ttl(Duration::from_millis(50));
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
        let read_at = Instant::now();
        // Three queued by the sweep's count, one of them announced.
        let three = HashMap::from([(labels.clone(), 3)]);
        assert_eq!(
            placement.swept("Octo/App", &three, read_at, false),
            vec![key.clone()]
        );
        assert_eq!(placement.counts(&key).0, 3);
        assert_eq!(placement.rebalance(&key).await.accepted, 3);
        // A late webhook for one the sweep already counted is not a fourth.
        placement.queued("octo/app", &pool, 2);
        assert_eq!(placement.counts(&key).0, 3);
        // A sweep that read before that webhook does not overwrite it.
        assert!(
            placement
                .swept("octo/app", &HashMap::new(), read_at, false)
                .is_empty()
        );
        assert_eq!(placement.counts(&key).0, 3);
        // A truncated listing is a minimum: it never takes jobs away.
        let later = Instant::now();
        let one = HashMap::from([(labels.clone(), 1)]);
        assert!(placement.swept("octo/app", &one, later, true).is_empty());
        assert_eq!(placement.counts(&key).0, 3);
        // The next full sweep sees none: the queue empties and the leases are
        // cancelled.
        placement.swept("octo/app", &HashMap::new(), later, false);
        assert_eq!(placement.counts(&key).0, 0);
        assert_eq!(placement.rebalance(&key).await.cancelled, 3);
        drop(host);
    }

    #[tokio::test]
    async fn a_claimed_lease_holds_its_job_until_the_webhook_and_either_order_closes_it() {
        let (registry, placement) = setup();
        let host = connect(&registry, "h", LAUNCH_VERSION, POOL, 8, 8 << 30);
        let host = answer(&placement, "h", host, Answer::Accept);
        let pool = required(POOL);
        let key = placement.queued("octo/app", &pool, 1).expect("pool");
        placement.queued("octo/app", &pool, 2);
        assert_eq!(placement.rebalance(&key).await.accepted, 2);
        let leases: Vec<String> = placement.state().leases.keys().cloned().collect();
        let started = |lease: &str| AttemptStarted {
            lease_id: Some(lease.to_string()),
            runner_name: "runner-manager-x".into(),
            target: TargetRef {
                scope: TargetScope::Repo,
                name: "octo/app".into(),
            },
            profile: "pool".into(),
        };

        // Claim first: the lease still counts, so nothing is placed twice.
        placement.attempt_started("h", &started(&leases[0]));
        assert_eq!(placement.counts(&key), (2, 2));
        assert_eq!(placement.rebalance(&key).await, Rebalanced::default());
        placement.dequeued("octo/app", &pool, 1);
        assert_eq!(placement.counts(&key), (1, 1));

        // Webhook first: the other lease is not cancelled as surplus once
        // its claim arrives.
        placement.dequeued("octo/app", &pool, 2);
        placement.attempt_started("h", &started(&leases[1]));
        assert_eq!(placement.counts(&key), (0, 0));
        assert_eq!(placement.rebalance(&key).await, Rebalanced::default());
        assert_eq!(launches(&host.await.expect("host")), 2);
    }

    fn started_by(runner: &str, lease: Option<&str>) -> AttemptStarted {
        AttemptStarted {
            lease_id: lease.map(ToString::to_string),
            runner_name: runner.into(),
            target: TargetRef {
                scope: TargetScope::Repo,
                name: "octo/app".into(),
            },
            profile: "pool".into(),
        }
    }

    fn cancels(seen: &[ServerMessage]) -> Vec<String> {
        seen.iter()
            .filter_map(|message| match message {
                ServerMessage::CancelLaunch(cancel) => Some(cancel.lease_id.clone()),
                _ => None,
            })
            .collect()
    }

    /// The host's heartbeat lists the launches it still holds: an accepted
    /// lease it no longer lists is closed and its job placed again at once;
    /// an older host's heartbeat (no list) changes nothing.
    #[tokio::test]
    async fn a_lease_its_host_no_longer_holds_is_closed_by_its_heartbeat() {
        let (registry, placement) = setup();
        let host = connect(&registry, "h", LAUNCH_VERSION, POOL, 8, 8 << 30);
        let host = answer(&placement, "h", host, Answer::Accept);
        let pool = required(POOL);
        let key = placement.queued("octo/app", &pool, 1).expect("pool");
        placement.queued("octo/app", &pool, 2);
        placement.queued("octo/app", &pool, 3);
        assert_eq!(placement.rebalance(&key).await.accepted, 3);
        let mut leases: Vec<(String, Instant)> = placement
            .state()
            .leases
            .iter()
            .map(|(id, lease)| (id.clone(), lease.sent))
            .collect();
        leases.sort_by_key(|(_, at)| *at);
        let ids: Vec<String> = leases.into_iter().map(|(id, _)| id).collect();
        // One claimed: held whatever the list says.
        placement.attempt_started("h", &started_by("runner-manager-c", Some(&ids[2])));
        assert_eq!(
            placement.reconcile_leases("h", std::slice::from_ref(&ids[0])),
            1,
            "only the accepted lease the host dropped"
        );
        assert_eq!(placement.counts(&key), (3, 2));
        assert!(!placement.state().leases.contains_key(&ids[1]));
        // Another host's list says nothing about these.
        assert_eq!(placement.reconcile_leases("other", &[]), 0);
        // Placed again.
        assert_eq!(placement.rebalance(&key).await.accepted, 1);
        assert_eq!(placement.counts(&key), (3, 3));
        assert_eq!(launches(&host.await.expect("host")), 4);
    }

    /// A runner of a host takes a job of a queue it holds no lease for (an
    /// idle runner, or one started for a dropped launch): the host's oldest
    /// accepted lease for that queue is closed, and the host told, whether
    /// the host's report or the webhook comes first.
    #[tokio::test]
    async fn another_runner_of_the_host_taking_the_job_closes_its_oldest_lease() {
        let (registry, placement) = setup();
        let host = connect(&registry, "h", LAUNCH_VERSION, POOL, 8, 8 << 30);
        let host = answer(&placement, "h", host, Answer::Accept);
        let pool = required(POOL);
        let key = placement.queued("octo/app", &pool, 1).expect("pool");
        placement.queued("octo/app", &pool, 2);
        placement.queued("octo/app", &pool, 3);
        assert_eq!(placement.rebalance(&key).await.accepted, 3);
        let oldest = |placement: &Placement| {
            placement
                .state()
                .leases
                .iter()
                .min_by_key(|(_, lease)| lease.sent)
                .map(|(id, _)| id.clone())
                .expect("a lease")
        };

        // The host's report first, then the webhook naming that runner.
        let first = oldest(&placement);
        placement.attempt_started("h", &started_by("runner-manager-idle1", None));
        assert_eq!(
            placement.counts(&key),
            (3, 3),
            "a lease-less claim alone closes nothing"
        );
        placement.dequeued_by("octo/app", &pool, 1, Some("Runner-Manager-Idle1"));
        assert_eq!(placement.counts(&key), (2, 2));
        assert!(!placement.state().leases.contains_key(&first));

        // The webhook first: its runner's report decides.
        let second = oldest(&placement);
        placement.dequeued_by("octo/app", &pool, 2, Some("runner-manager-idle2"));
        assert_eq!(placement.counts(&key), (1, 2), "not yet known whose runner");
        placement.attempt_started("h", &started_by("runner-manager-idle2", None));
        assert_eq!(placement.counts(&key), (1, 1));
        assert!(!placement.state().leases.contains_key(&second));
        assert!(
            placement
                .state()
                .credits
                .get(&key)
                .is_none_or(VecDeque::is_empty)
        );

        // A runner started for this very queue's lease is the ordinary claim.
        let third = oldest(&placement);
        placement.attempt_started("h", &started_by("runner-manager-own", Some(&third)));
        placement.dequeued_by("octo/app", &pool, 3, Some("runner-manager-own"));
        assert_eq!(placement.counts(&key), (0, 0));

        let seen = host.await.expect("host");
        assert_eq!(
            cancels(&seen),
            vec![first, second],
            "the host drops them too"
        );
    }

    /// A queue left short says why, and `stats` lists it with the open
    /// leases.
    #[tokio::test]
    async fn an_unplaced_queue_says_why_and_the_snapshot_lists_queues_and_leases() {
        let (registry, placement) = setup();
        let pool = required(POOL);
        let key = placement.queued("octo/app", &pool, 1).expect("pool");
        placement.rebalance(&key).await;
        let reason = |placement: &Placement| {
            let (pending, _) = placement.snapshot();
            pending
                .first()
                .map(|queue| (queue.reason.clone(), queue.refusal.clone()))
        };
        assert_eq!(
            reason(&placement),
            Some((Some("no_candidate".into()), None))
        );
        let _full = connect(&registry, "full", LAUNCH_VERSION, POOL, 0, 8 << 30);
        placement.rebalance(&key).await;
        assert_eq!(
            reason(&placement),
            Some((Some("no_free_slot".into()), None))
        );
        let refuses = connect(&registry, "refuses", LAUNCH_VERSION, POOL, 1, 8 << 30);
        let refuses = answer(&placement, "refuses", refuses, Answer::Refuse);
        placement.rebalance(&key).await;
        assert_eq!(
            reason(&placement),
            Some((Some("refused".into()), Some("host_capacity".into())))
        );
        let (pending, leases) = placement.snapshot();
        assert_eq!(pending[0].repository, "octo/app");
        assert_eq!(pending[0].labels, "rm-pool-linux");
        assert_eq!((pending[0].queued, pending[0].leases), (1, 0));
        assert!(pending[0].oldest_wait_secs.is_some());
        assert!(leases.is_empty());
        refuses.await.expect("host");

        let accepts = connect(&registry, "accepts", LAUNCH_VERSION, POOL, 1, 8 << 30);
        let accepts = answer(&placement, "accepts", accepts, Answer::Accept);
        assert_eq!(placement.rebalance(&key).await.accepted, 1);
        let (pending, leases) = placement.snapshot();
        assert!(pending.is_empty(), "placed: nothing waits");
        assert_eq!(leases.len(), 1);
        assert_eq!(
            (leases[0].host_id.as_str(), leases[0].state.as_str()),
            ("accepts", "accepted")
        );
        accepts.await.expect("host");
    }

    #[tokio::test]
    async fn a_launch_already_counted_by_the_last_heartbeat_does_not_take_a_second_slot() {
        let (registry, placement) = setup();
        let (tx, mut rx) = mpsc::channel(64);
        let connection = registry.register("h", LAUNCH_VERSION, tx);
        drop(connect(&registry, "other", 2, POOL, 0, 0));
        registry.set_hello(
            "h",
            connection,
            Hello {
                protocol_version: LAUNCH_VERSION,
                host_id: "h".into(),
                os: "linux".into(),
                arch: "x64".into(),
                cores: 2,
                ram_bytes: None,
                disk_free_bytes: None,
                targets: vec![Target {
                    scope: TargetScope::Repo,
                    name: "octo/app".into(),
                    profiles: vec![Profile {
                        name: "pool".into(),
                        labels: vec!["rm-pool-linux".into()],
                        enabled: true,
                        warm: false,
                    }],
                }],
            },
        );
        let beat = |free| Heartbeat {
            free_slots: free,
            ..Heartbeat::default()
        };
        registry.set_heartbeat("h", connection, beat(2));
        let placing = {
            let placement = Arc::clone(&placement);
            tokio::spawn(async move {
                while let Some(message) = rx.recv().await {
                    if let Outbound::Send(ServerMessage::Launch(launch)) = message {
                        placement.acknowledged("h", LaunchAck::accepted(&launch.lease_id));
                    }
                }
            })
        };
        let pool = required(POOL);
        let key = placement.queued("octo/app", &pool, 1).expect("pool");
        assert_eq!(placement.rebalance(&key).await.accepted, 1);
        // The heartbeat after it counts its runner: one slot left, and the
        // second job still fits.
        registry.set_heartbeat("h", connection, beat(1));
        placement.queued("octo/app", &pool, 2);
        assert_eq!(placement.rebalance(&key).await.accepted, 1);
        // Full by its heartbeat and one unreported launch: a third waits.
        placement.queued("octo/app", &pool, 3);
        assert_eq!(placement.rebalance(&key).await, Rebalanced::default());
        placing.abort();
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

    fn measured(
        placement: Placement,
        store: crate::store::Store,
    ) -> (Arc<Placement>, Arc<Statistics>) {
        let stats = Arc::new(Statistics::load(
            Arc::new(Mutex::new(store)),
            crate::stats::StatsConfig::default(),
        ));
        (
            Arc::new(placement.with_statistics(Arc::clone(&stats))),
            stats,
        )
    }

    #[tokio::test]
    async fn a_measured_heavy_queue_goes_to_the_host_it_fits_and_the_decision_is_kept() {
        use runner_manager_domain::coordinator_protocol::{AttemptOutcomeKind, AttemptUsage};

        let registry = Arc::new(Registry::default());
        registry.set_coverage(covering());
        let (placement, stats) = measured(
            Placement::with_timings(
                Arc::clone(&registry),
                Duration::from_millis(150),
                Duration::from_secs(300),
            ),
            crate::store::Store::open_in_memory().expect("store"),
        );
        // `build` once peaked at 12 GiB.
        let identity =
            crate::stats::JobIdentity::new("octo/app", Some("ci"), Some("build")).expect("named");
        stats.job_identified(
            "runner-manager-x",
            identity.clone(),
            crate::stats::JobTimes::parse(None, None, Some("2026-11-07T10:10:00Z")),
        );
        stats.attempt_finished(
            "elsewhere",
            &AttemptFinished {
                lease_id: None,
                runner_name: "runner-manager-x".into(),
                outcome: AttemptOutcomeKind::CompletedJob,
                duration_secs: Some(600),
                usage: Some(AttemptUsage {
                    peak_rss_bytes: 12 << 30,
                    samples: 10,
                    ..AttemptUsage::default()
                }),
            },
            None,
        );
        // The roomiest by free memory now cannot hold it with the margin
        // once the lease it already holds is counted; stage 3 would pick it.
        let small = connect(&registry, "small", LAUNCH_VERSION, POOL, 2, 8 << 30);
        let big = connect(&registry, "big", LAUNCH_VERSION, POOL, 2, 20 << 30);
        let small = answer(&placement, "small", small, Answer::Accept);
        let big = answer(&placement, "big", big, Answer::Accept);
        let pool = required(POOL);
        let key = placement
            .queued_job("octo/app", &pool, 1, Some(identity.key()))
            .expect("pool");
        assert_eq!(placement.rebalance(&key).await.accepted, 1);
        // A second build: `big` has 20 GiB free by its heartbeat, but 12 are
        // spoken for by the first lease, so nothing fits and it waits.
        placement.queued_job("octo/app", &pool, 2, Some(identity.key()));
        assert_eq!(placement.rebalance(&key).await, Rebalanced::default());
        assert_eq!(placement.counts(&key), (2, 1));
        // Its runner takes job 1: the lease closes, but the memory it will
        // need stays reserved while the build ramps up.
        let lease = placement
            .state()
            .leases
            .keys()
            .next()
            .cloned()
            .expect("a lease");
        placement.attempt_started(
            "big",
            &AttemptStarted {
                lease_id: Some(lease),
                runner_name: "runner-manager-y".into(),
                target: TargetRef {
                    scope: TargetScope::Repo,
                    name: "octo/app".into(),
                },
                profile: "pool".into(),
            },
        );
        placement.dequeued("octo/app", &pool, 1);
        assert_eq!(placement.counts(&key), (1, 0));
        assert_eq!(placement.state().reserved_on("big"), 12 << 30);
        assert_eq!(placement.rebalance(&key).await, Rebalanced::default());
        assert_eq!(placement.state().reserved_on("small"), 0);
        assert_eq!(launches(&big.await.expect("host")), 1);
        assert_eq!(launches(&small.await.expect("host")), 0);

        let report = stats.report(chrono::Utc::now()).expect("report");
        let placed = report
            .decisions
            .iter()
            .find(|decision| decision.chosen.is_some())
            .expect("the placement was kept");
        assert_eq!(placed.chosen.as_deref(), Some("big"));
        assert_eq!(
            (placed.estimate_bytes, placed.estimate_source.as_str()),
            (12 << 30, "job")
        );
        assert_eq!(placed.method, "weighted");
        assert!(
            placed
                .scores
                .iter()
                .any(|score| score.host_id == "small" && !score.fits)
        );
        assert!(
            report
                .decisions
                .iter()
                .any(|decision| decision.chosen.is_none()),
            "the queue nothing fits is shown too"
        );
        assert_eq!(report.launches, 1);
    }

    #[tokio::test]
    async fn with_statistics_but_no_data_the_choice_is_stage_threes() {
        let (registry, plain) = setup();
        let a = connect(&registry, "a", LAUNCH_VERSION, POOL, 2, 1 << 30);
        let b = connect(&registry, "b", LAUNCH_VERSION, POOL, 2, 3 << 30);
        drop((a, b));
        let candidates = registry.launch_candidates("octo/app", &required(POOL));
        let stage_three: Vec<String> = rank(candidates)
            .into_iter()
            .map(|candidate| candidate.host_id)
            .collect();
        drop(plain);
        let (placement, _stats) = measured(
            Placement::with_timings(
                Arc::clone(&registry),
                Duration::from_millis(150),
                Duration::from_secs(300),
            ),
            crate::store::Store::open_in_memory().expect("store"),
        );
        let key = placement
            .queued_job(
                "octo/app",
                &required(POOL),
                1,
                Some("octo/app/ci/new".into()),
            )
            .expect("pool");
        let mut decision = None;
        let offered = placement.offer(
            &key,
            &HashSet::new(),
            None,
            &mut Rebalanced::default(),
            &mut decision,
        );
        let (_, host, _) = offered.expect("placed though 1 GiB free is under the default 2 GiB");
        assert_eq!(host, stage_three[0]);
        let decision = decision.expect("recorded");
        assert_eq!(decision.method, "stage3");
        assert_eq!(decision.estimate_source, "default");
        assert!(decision.scores.iter().all(|score| score.fits));
    }
}
