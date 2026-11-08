// owner: coordinator-stage3

//! The coordinator's launches on this host (`.taskflow/2026-11-07-coordinator-server`,
//! stage 3): which pool profiles start runners only when the coordinator
//! places one here, the launches this host accepted, and the attempt reports
//! it sends back.
//!
//! # When a profile is directed
//!
//! A profile is **directed** while it carries this host's shared pool label
//! (`rm-pool-linux`, ...) and its target is in `coordinated` mode on a link
//! that speaks protocol version 3. Its demand is then the number of open
//! launches ([`Launches::directed_demand`]), never its own reading of the
//! queue, which every host in the pool sees the same way. In `fallback` and
//! `standalone`, or on a version-2 link, it is an ordinary profile: its own
//! demand, and a surplus runner when two hosts answer one job.
//!
//! # What the coordinator can and cannot make this host do
//!
//! A `launch` is accepted only for an enabled pool profile of this host, in
//! coordinated mode, and only when [`HostAllocator`] — over this host's
//! attempts, its capacity, the profile's `max_capacity` — grants one more
//! runner than the open launches already take; not while unfit or draining.
//! The runner is then started by the ordinary reconciliation pass, through
//! the same allocator and lock. So a coordinator can at worst fill this host
//! up to the ceilings its owner set — exactly what a queue of jobs could.
//!
//! # A launch's life
//!
//! Accepted → its runner is started (the pass reports it through
//! [`DemandDirector::launched`]) → it closes when that runner leaves the
//! unassigned states (takes a job, or ends), when the coordinator cancels it,
//! or when it expires (`ttl_secs`, measured on this host's clock).

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use runner_manager_agent::reconcile::DemandDirector;
use runner_manager_domain::attempt::{AttemptOutcome, AttemptState, RunnerAttempt};
use runner_manager_domain::capacity::{HostAllocator, LimitingFactor};
use runner_manager_domain::coordinator_protocol::{
    AttemptFinished, AttemptOutcomeKind, AttemptStarted, Launch, LaunchAck, MAX_OPEN_LEASES,
    RefusalReason,
};
use runner_manager_domain::model::{AttemptId, Host, PolicyId};
use runner_manager_domain::policy::{ScalePolicy, pool_label};
use runner_manager_domain::store::Store;
use tokio::sync::watch;
use tokio::time::Instant;

use super::coordinator::{LinkView, same_target, target_ref};
use super::meters::AttemptMeters;

/// Lease ids remembered so a repeat is refused.
const SEEN_MEMORY: usize = 1024;

/// Attempts whose lease is remembered for the attempt reports.
const LEASED_MEMORY: usize = 1024;

/// How long an accepted launch may go without a runner, whatever the reason,
/// before it is dropped and its job placed again: well inside a lease's
/// lifetime, with room for a retry.
const START_LIMIT: Duration = Duration::from_secs(45);

/// One accepted launch.
#[derive(Debug, Clone)]
struct Open {
    policy: PolicyId,
    expires: Instant,
    accepted_at: Instant,
    /// The runner started for it, once the pass started one.
    attempt: Option<AttemptId>,
}

#[derive(Debug, Default)]
struct Book {
    open: BTreeMap<String, Open>,
    seen: VecDeque<String>,
    seen_set: HashSet<String>,
    /// Which lease each runner was started for, for the attempt reports.
    leased: HashMap<AttemptId, String>,
    leased_order: VecDeque<AttemptId>,
    /// A launch was dropped since the link last asked: say so at once.
    dropped: bool,
}

impl Book {
    fn remember(&mut self, lease_id: &str) {
        if self.seen_set.insert(lease_id.to_string()) {
            self.seen.push_back(lease_id.to_string());
            if self.seen.len() > SEEN_MEMORY
                && let Some(oldest) = self.seen.pop_front()
            {
                self.seen_set.remove(&oldest);
            }
        }
    }

    /// Whatever kept it from starting, a launch with no runner for
    /// [`START_LIMIT`] goes, well before its lease would run out.
    fn drop_late(&mut self, now: Instant) {
        let before = self.open.len();
        self.open.retain(|lease, open| {
            let late = open.attempt.is_none()
                && now.saturating_duration_since(open.accepted_at) >= START_LIMIT;
            if late {
                tracing::warn!(%lease, "no runner could be started for a launch in time; it was dropped");
            }
            !late
        });
        self.dropped |= self.open.len() != before;
    }

    /// A launch whose runner exited idle waits again, with a fresh start
    /// limit; one whose runner took a job, failed or vanished is closed.
    fn release_ended(
        &mut self,
        attempts: &[RunnerAttempt],
        cleaned: &[RunnerAttempt],
        now: Instant,
    ) {
        let mut released = Vec::new();
        for open in self.open.values_mut() {
            let Some(attempt) = open.attempt else {
                continue;
            };
            let runner = attempts
                .iter()
                .chain(cleaned)
                .find(|runner| runner.id == attempt);
            match runner {
                Some(runner) if runner.state().is_unassigned() => {}
                Some(runner)
                    if matches!(
                        runner.outcome(),
                        Some(AttemptOutcome::ExitedIdleWithoutWork)
                    ) =>
                {
                    open.attempt = None;
                    open.accepted_at = now;
                    released.push(attempt);
                }
                // Not read yet (bound since those reads): looked at next time.
                None => {}
                _ => open.expires = now,
            }
        }
        self.open.retain(|_, open| open.expires > now);
        for attempt in released {
            self.leased.remove(&attempt);
        }
    }

    /// Gives a launch without a runner a waiting runner of its profile that no
    /// launch holds: that runner serves it, so no other is started.
    fn bind_free(&mut self, attempts: &[RunnerAttempt]) {
        let held: HashSet<AttemptId> = self.open.values().filter_map(|open| open.attempt).collect();
        let mut free: HashMap<PolicyId, Vec<AttemptId>> = HashMap::new();
        for attempt in attempts {
            if attempt.state().is_unassigned() && !held.contains(&attempt.id) {
                free.entry(attempt.policy_id).or_default().push(attempt.id);
            }
        }
        let mut bound = Vec::new();
        for (lease_id, open) in &mut self.open {
            if open.attempt.is_none()
                && let Some(attempt) = free.get_mut(&open.policy).and_then(Vec::pop)
            {
                open.attempt = Some(attempt);
                bound.push((attempt, lease_id.clone()));
            }
        }
        for (attempt, lease_id) in bound {
            self.lease_runner(attempt, &lease_id);
        }
    }

    /// Drops the launches with no runner beyond what this host can start: the
    /// slots are the host's, its oldest launch's profile first, and each
    /// profile's oldest launches keep theirs.
    fn drop_unstartable(
        &mut self,
        own: &HashMap<PolicyId, ScalePolicy>,
        directed: &HashSet<PolicyId>,
        host: &Host,
        attempts: &[RunnerAttempt],
    ) {
        let mut by_age: Vec<(Instant, PolicyId)> = own
            .keys()
            .filter_map(|policy| {
                let oldest = self
                    .open
                    .values()
                    .filter(|open| open.policy == *policy)
                    .map(|open| open.accepted_at)
                    .min()?;
                Some((oldest, *policy))
            })
            .collect();
        by_age.sort();
        let mut allocator = HostAllocator::from_attempts(host, attempts);
        for (_, policy) in by_age {
            let mut waiting: Vec<(Instant, String)> = self
                .open
                .iter()
                .filter(|(_, open)| open.policy == policy && open.attempt.is_none())
                .map(|(id, open)| (open.accepted_at, id.clone()))
                .collect();
            waiting.sort();
            let demand = self
                .open
                .values()
                .filter(|open| open.policy == policy)
                .count();
            let startable = if directed.contains(&policy) {
                allocator
                    .allocate(&own[&policy], u32::try_from(demand).unwrap_or(u32::MAX))
                    .to_start
            } else {
                0
            };
            for (_, lease) in waiting.iter().skip(usize::from(startable)) {
                self.open.remove(lease);
                self.dropped = true;
                tracing::info!(%lease, "a launch this host cannot start was dropped");
            }
        }
    }

    fn lease_runner(&mut self, attempt: AttemptId, lease_id: &str) {
        self.leased.insert(attempt, lease_id.to_string());
        self.leased_order.push_back(attempt);
        if self.leased_order.len() > LEASED_MEMORY
            && let Some(oldest) = self.leased_order.pop_front()
        {
            self.leased.remove(&oldest);
        }
    }
}

/// The host's launches, shared by the link (which accepts and cancels them)
/// and every target loop (whose passes start their runners).
#[derive(Debug)]
pub struct Launches {
    store: Arc<dyn Store>,
    host: Host,
    view: watch::Receiver<LinkView>,
    book: Mutex<Book>,
}

impl Launches {
    #[must_use]
    pub fn new(store: Arc<dyn Store>, host: Host, view: watch::Receiver<LinkView>) -> Self {
        Self {
            store,
            host,
            view,
            book: Mutex::new(Book::default()),
        }
    }

    fn book(&self) -> std::sync::MutexGuard<'_, Book> {
        self.book
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether `policy` is directed right now: a pool profile of this host
    /// whose target is coordinated on a version-3 link.
    #[must_use]
    pub fn is_directed(&self, policy: &ScalePolicy) -> bool {
        self.is_own_pool_profile(policy)
            && self
                .view
                .borrow()
                .launch_mode(&policy.target, Instant::now())
    }

    /// A profile of this host answering this host's own pool label. A
    /// stored label for another OS's pool (written before it was refused)
    /// never makes a profile a pool profile here.
    fn is_own_pool_profile(&self, policy: &ScalePolicy) -> bool {
        policy.is_owned_by(self.host.id) && policy.pool_label() == Some(&pool_label(self.host.os))
    }

    /// Drops every open launch: the link ended, and the coordinator forgets
    /// a disconnected host's leases and places their jobs elsewhere. A runner
    /// already started for one stays, as an idle runner of its profile.
    pub fn clear(&self) {
        self.book().open.clear();
    }

    /// How many launches are open for `policy`.
    #[must_use]
    pub fn open_for(&self, policy: PolicyId) -> u32 {
        let count = self
            .book()
            .open
            .values()
            .filter(|open| open.policy == policy)
            .count();
        u32::try_from(count).unwrap_or(u32::MAX)
    }

    /// Keeps every open launch's promise: a launch has a runner still able to
    /// take a job, or one this host can start, or it is dropped, so the next
    /// heartbeat closes its lease and the coordinator places the job again.
    ///
    /// * Expired, or its profile gone: dropped.
    /// * Its runner took a job: closed, the job is served. A runner that
    ///   failed or was orphaned closes it too: its `attempt_finished` closes
    ///   the lease, and the coordinator places the job on any host.
    /// * Its runner exited idle: it took nothing, so the launch is free again,
    ///   and no longer reported as that runner's.
    /// * A launch without a runner is given a waiting runner of its profile
    ///   that no launch holds (one left idle, or kept by `min_capacity`): that
    ///   runner serves it, so the allocator must not start another.
    /// * Still without one, and more than this host can start, oldest first
    ///   across its profiles: dropped. Slots are the host's, and may have gone
    ///   to another profile's runner since it was accepted. Nothing would ever
    ///   start it: the loop waiting for it hears of no slot freed elsewhere.
    fn settle(&self, now: Instant) {
        let policies: HashSet<PolicyId> =
            self.book().open.values().map(|open| open.policy).collect();
        if policies.is_empty() {
            return;
        }
        // Read without holding the book: the link and the passes use it.
        // `Err` (unreadable) decides nothing.
        let mut own: HashMap<PolicyId, ScalePolicy> = HashMap::new();
        let mut gone: HashSet<PolicyId> = HashSet::new();
        for policy in policies {
            match self.store.policy(policy) {
                Ok(Some(found)) if self.is_own_pool_profile(&found) => {
                    own.insert(policy, found);
                }
                Ok(_) => {
                    gone.insert(policy);
                }
                Err(_) => {}
            }
        }
        let attempts = self.store.uncleaned_attempts().ok();
        let host = self.current_host();
        let directed: HashSet<PolicyId> = own
            .values()
            .filter(|policy| self.is_directed(policy))
            .map(|policy| policy.id)
            .collect();
        // A runner already cleaned is not among those, and how it ended counts.
        let held: Vec<AttemptId> = self
            .book()
            .open
            .values()
            .filter_map(|open| open.attempt)
            .collect();
        let cleaned: Vec<RunnerAttempt> = attempts.as_ref().map_or_else(Vec::new, |attempts| {
            held.into_iter()
                .filter(|id| !attempts.iter().any(|attempt| attempt.id == *id))
                .filter_map(|id| self.store.attempt(id).ok().flatten())
                .collect()
        });

        let mut book = self.book();
        book.open
            .retain(|_, open| open.expires > now && !gone.contains(&open.policy));
        book.drop_late(now);
        let Some(attempts) = attempts else {
            return;
        };
        book.release_ended(&attempts, &cleaned, now);
        book.bind_free(&attempts);
        book.drop_unstartable(&own, &directed, &host, &attempts);
    }

    /// This host, at the capacity its operator last set.
    pub fn current_host(&self) -> Host {
        let mut host = self.host.clone();
        if let Ok(Some(current)) = self.store.host(self.host.id) {
            host.host_capacity = current.host_capacity;
        }
        host
    }

    /// The coordinator's `launch`: accepted or refused, and on acceptance
    /// opened, so the target's next pass starts its runner.
    pub fn decide(&self, launch: &Launch, unfit: bool, draining: bool) -> LaunchAck {
        let refuse = |reason| LaunchAck::refused(&launch.lease_id, reason);
        let now = Instant::now();
        self.settle(now);
        {
            let mut book = self.book();
            if book.seen_set.contains(&launch.lease_id) || launch.ttl_secs == 0 {
                return refuse(RefusalReason::Stale);
            }
            book.remember(&launch.lease_id);
        }
        if draining {
            return refuse(RefusalReason::Draining);
        }
        if unfit {
            return refuse(RefusalReason::Unfit);
        }
        let policies = match self.store.policies() {
            Ok(policies) => policies,
            Err(_) => return refuse(RefusalReason::Other),
        };
        let Some(policy) = policies.iter().find(|policy| {
            same_target(&policy.target, &launch.target)
                && policy.profile_name().as_str() == launch.profile
                && self.is_own_pool_profile(policy)
        }) else {
            return refuse(RefusalReason::UnknownProfile);
        };
        if !policy.may_start_runners() {
            return refuse(RefusalReason::Disabled);
        }
        if !self.is_directed(policy) {
            return refuse(RefusalReason::NotCoordinated);
        }
        let host = self.current_host();
        // Host-wide, as the allocator of the pass counts them: the runners of
        // a repository removed while they finish still hold their slots.
        let Ok(attempts) = self.store.uncleaned_attempts() else {
            return refuse(RefusalReason::Other);
        };
        // Slots are the host's: every other profile's open launches take
        // theirs first, or two profiles together accept more than it can run.
        let mut allocator = HostAllocator::from_attempts(&host, &attempts);
        for other in policies.iter().filter(|other| other.id != policy.id) {
            let open = self.open_for(other.id);
            if open > 0 {
                allocator.allocate(other, open);
            }
        }
        let open = self.open_for(policy.id);
        let without = allocator.clone().allocate(policy, open);
        let with = allocator.clone().allocate(policy, open.saturating_add(1));
        // One more runner than the open launches already take, or an idle
        // runner of this profile that can take the job: accepted. A ceiling
        // that stops it: refused, and the coordinator tries another host.
        if with.to_start <= without.to_start {
            match with.limiting_factor {
                LimitingFactor::MaxCapacity => return refuse(RefusalReason::MaxCapacity),
                LimitingFactor::HostCapacity => return refuse(RefusalReason::HostCapacity),
                LimitingFactor::MonitorOnly
                | LimitingFactor::NotReconciling
                | LimitingFactor::ForeignHost => return refuse(RefusalReason::Disabled),
                LimitingFactor::Demand | LimitingFactor::MinCapacity => {}
            }
        }
        let ttl = Duration::from_secs(u64::from(launch.ttl_secs));
        self.book().open.insert(
            launch.lease_id.clone(),
            Open {
                policy: policy.id,
                expires: now + ttl,
                accepted_at: now,
                attempt: None,
            },
        );
        LaunchAck::accepted(&launch.lease_id)
    }

    /// The coordinator's `cancel_launch`: the job is no longer queued. A
    /// runner already started for it stays (it may take another job, or
    /// exits idle); none is started for it any more.
    pub fn cancel(&self, lease_id: &str) -> bool {
        let mut book = self.book();
        book.remember(lease_id);
        book.open.remove(lease_id).is_some()
    }

    /// The launches still open, for the heartbeat: the coordinator closes
    /// any accepted lease of this host not among them. Settled here: a target
    /// with nothing running may not run a pass for minutes, and what this
    /// lists is what the coordinator believes is coming.
    #[must_use]
    pub fn open_leases(&self) -> Vec<String> {
        self.settle(Instant::now());
        self.book()
            .open
            .keys()
            .take(MAX_OPEN_LEASES)
            .cloned()
            .collect()
    }

    /// Whether a launch was dropped since the last call.
    pub fn take_dropped(&self) -> bool {
        std::mem::take(&mut self.book().dropped)
    }

    /// How many open launches have no runner yet, across this host: slots
    /// that are spoken for though no attempt counts them.
    #[must_use]
    pub fn unstarted(&self) -> u16 {
        let count = self
            .book()
            .open
            .values()
            .filter(|open| open.attempt.is_none())
            .count();
        u16::try_from(count).unwrap_or(u16::MAX)
    }

    /// Whether a launch of `policies` is open with no runner yet: its target's
    /// loop must not sleep on the coordinator's long interval.
    #[must_use]
    pub fn holds_unstarted(&self, policies: &[ScalePolicy]) -> bool {
        self.book().open.values().any(|open| {
            open.attempt.is_none() && policies.iter().any(|policy| policy.id == open.policy)
        })
    }

    /// The lease `attempt`'s runner was started for, if any.
    #[must_use]
    pub fn lease_of(&self, attempt: AttemptId) -> Option<String> {
        self.book().leased.get(&attempt).cloned()
    }
}

impl DemandDirector for Launches {
    fn directed_demand(&self, policy: &ScalePolicy) -> Option<u32> {
        if !self.is_directed(policy) {
            return None;
        }
        self.settle(Instant::now());
        Some(self.open_for(policy.id))
    }

    fn launched(&self, policy: &ScalePolicy, attempt: AttemptId) {
        let mut book = self.book();
        // `settle` may have bound it already: an attempt exists, and waits,
        // while it is still being started. One runner serves one launch.
        if book.open.values().any(|open| open.attempt == Some(attempt)) {
            return;
        }
        // The oldest launch still waiting for a runner gets this one.
        let lease = book
            .open
            .iter()
            .filter(|(_, open)| open.policy == policy.id && open.attempt.is_none())
            .min_by_key(|(_, open)| open.accepted_at)
            .map(|(id, _)| id.clone());
        if let Some(lease_id) = lease {
            if let Some(open) = book.open.get_mut(&lease_id) {
                open.attempt = Some(attempt);
            }
            book.lease_runner(attempt, &lease_id);
        }
    }
}

/// What the attempt reports need to remember between two looks.
#[derive(Debug, Clone, Copy)]
struct Watched {
    policy: PolicyId,
    started: bool,
    finished: bool,
}

/// Turns this host's attempt states into `attempt_started` (a runner took a
/// job: `busy`) and `attempt_finished` (it reached a terminal state) reports,
/// each at most once per attempt. Attempts that had already ended when the
/// link came up are not reported, unless a launch of this host started them.
#[derive(Debug, Default)]
pub struct AttemptReports {
    watched: HashMap<AttemptId, Watched>,
    /// An attempt ended or was cleaned since [`Self::take_released`]: a slot
    /// may have freed. An isolated attempt frees its slot only when cleaned,
    /// after its `attempt_finished`.
    released: bool,
}

/// One report to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptReport {
    Started(AttemptStarted),
    Finished(AttemptFinished),
}

fn outcome_kind(outcome: Option<&AttemptOutcome>) -> AttemptOutcomeKind {
    match outcome {
        Some(AttemptOutcome::CompletedJob) => AttemptOutcomeKind::CompletedJob,
        Some(AttemptOutcome::ExitedIdleWithoutWork) => AttemptOutcomeKind::IdleExit,
        Some(AttemptOutcome::Failed { .. }) => AttemptOutcomeKind::Failed,
        Some(AttemptOutcome::Orphaned) => AttemptOutcomeKind::Orphaned,
        None => AttemptOutcomeKind::Other,
    }
}

impl AttemptReports {
    /// What changed since the last look at `policies`' attempts.
    pub fn poll(
        &mut self,
        store: &dyn Store,
        policies: &[ScalePolicy],
        launches: &Launches,
        meters: &AttemptMeters,
    ) -> Vec<AttemptReport> {
        let mut reports = Vec::new();
        let mut present = HashSet::new();
        for policy in policies {
            let Ok(attempts) = store.uncleaned_attempts_for_policy(policy.id) else {
                continue;
            };
            for attempt in attempts {
                present.insert(attempt.id);
                // Terminal, not just concluded: an isolated attempt passes
                // through `destroying` and `cleanup_deferred` after it ended.
                let ended = attempt.state().is_terminal();
                let watched = self.watched.entry(attempt.id).or_insert(Watched {
                    policy: policy.id,
                    started: ended,
                    // Ended before this link saw it: news only when a launch
                    // started it, so its lease closes.
                    finished: ended && launches.lease_of(attempt.id).is_none(),
                });
                if !watched.started && attempt.state() == AttemptState::Busy {
                    watched.started = true;
                    reports.push(AttemptReport::Started(AttemptStarted {
                        lease_id: launches.lease_of(attempt.id),
                        runner_name: runner_manager_agent::lifecycle::runner_name(attempt.id),
                        target: target_ref(&policy.target),
                        profile: policy.profile_name().to_string(),
                    }));
                }
                if ended && !watched.finished {
                    watched.finished = true;
                    self.released = true;
                    reports.push(finished(&attempt, launches, meters));
                }
            }
        }
        // Cleaned between two looks: read once more for its outcome.
        let gone: Vec<AttemptId> = self
            .watched
            .keys()
            .filter(|id| !present.contains(id))
            .copied()
            .collect();
        self.released |= !gone.is_empty();
        for id in gone {
            let unreported = self.watched.remove(&id).is_some_and(|watched| {
                !watched.finished && policies.iter().any(|policy| policy.id == watched.policy)
            });
            if let (true, Ok(Some(attempt))) = (unreported, store.attempt(id)) {
                reports.push(finished(&attempt, launches, meters));
            }
        }
        reports
    }

    /// Whether a slot may have freed since the last call.
    pub fn take_released(&mut self) -> bool {
        std::mem::take(&mut self.released)
    }
}

fn finished(attempt: &RunnerAttempt, launches: &Launches, meters: &AttemptMeters) -> AttemptReport {
    let ended = attempt
        .terminal_at()
        .unwrap_or_else(|| attempt.last_state_change_at());
    AttemptReport::Finished(AttemptFinished {
        lease_id: launches.lease_of(attempt.id),
        runner_name: runner_manager_agent::lifecycle::runner_name(attempt.id),
        outcome: outcome_kind(attempt.outcome()),
        duration_secs: ended
            .signed_duration_since(attempt.created_at())
            .to_std()
            .ok()
            .map(|duration| duration.as_secs()),
        usage: meters.take(attempt.id),
    })
}

#[cfg(test)]
mod tests {
    use runner_manager_domain::coordinator_protocol::{HelloAck, LAUNCH_VERSION};
    use runner_manager_domain::store::SqliteStore;
    use runner_manager_testkit::fixtures;

    use super::*;

    fn directed_view(policy: &ScalePolicy, version: u32) -> watch::Receiver<LinkView> {
        let (_sender, receiver) = watch::channel(LinkView {
            configured: true,
            connected: true,
            down_since: None,
            ack: Some(HelloAck {
                reconcile_interval_secs: Some(120),
                covered: vec![target_ref(&policy.target)],
            }),
            version: Some(version),
        });
        // A dropped sender leaves the last value readable.
        receiver
    }

    fn setup(version: u32) -> (Arc<SqliteStore>, ScalePolicy, Launches) {
        let host = fixtures::host().build();
        let mut policy = fixtures::policy()
            .repository("octo/app")
            .host(host.id)
            .autoscale("home", 2)
            .active()
            .build();
        policy
            .add_routing_label(pool_label(host.os))
            .expect("pool label");
        let store = Arc::new(SqliteStore::open_in_memory().expect("store"));
        store.put_host(&host).expect("host");
        store.insert_policy(&policy).expect("policy");
        let launches = Launches::new(
            Arc::clone(&store) as Arc<dyn Store>,
            host,
            directed_view(&policy, version),
        );
        (store, policy, launches)
    }

    fn launch(policy: &ScalePolicy, lease: &str) -> Launch {
        Launch {
            target: target_ref(&policy.target),
            profile: policy.profile_name().to_string(),
            job_key: "octo/app#1".into(),
            lease_id: lease.into(),
            expires_at: 0,
            ttl_secs: 300,
        }
    }

    #[test]
    fn a_version_two_link_or_a_plain_profile_is_never_directed() {
        let (_store, policy, launches) = setup(2);
        assert!(!launches.is_directed(&policy));
        assert_eq!(launches.directed_demand(&policy), None);
        assert_eq!(
            launches.decide(&launch(&policy, "l"), false, false).reason,
            Some(RefusalReason::NotCoordinated)
        );

        let (store, mut policy, launches) = setup(LAUNCH_VERSION);
        let pool = policy.pool_label().cloned().expect("pool");
        policy.remove_routing_label(&pool).expect("removed");
        store
            .update_policy(&policy, policy.revision() - 1)
            .expect("stored");
        assert!(!launches.is_directed(&policy));
        assert_eq!(
            launches.decide(&launch(&policy, "l2"), false, false).reason,
            Some(RefusalReason::UnknownProfile)
        );
        assert_eq!(
            launches.decide(&launch(&policy, "l3"), true, false).reason,
            Some(RefusalReason::Unfit)
        );
    }

    /// A second profile on one host, recorded, sharing the first's slots.
    fn second_profile(store: &SqliteStore, policy: &ScalePolicy, max: u16) -> ScalePolicy {
        let mut other = fixtures::policy()
            .id(PolicyId::new_random())
            .repository("octo/other")
            .host(policy.host_id)
            .autoscale("home", max)
            .active()
            .build();
        other
            .add_routing_label(pool_label(fixtures::host().build().os))
            .expect("pool label");
        store.insert_policy(&other).expect("policy");
        other
    }

    /// Live experiment E4b, reproduced: two repositories' pool profiles on one
    /// host, each with room of its own. Each counted only its own launches, so
    /// together they accepted more than the host's slots; the surplus never
    /// started and stayed listed until its lease's lifetime ran out.
    #[test]
    fn two_profiles_together_never_accept_more_than_the_hosts_slots() {
        let (store, policy, _) = setup(LAUNCH_VERSION);
        let other = second_profile(&store, &policy, 6);
        let host = store.hosts().expect("hosts").remove(0);
        // Both targets coordinated.
        let (_sender, view) = watch::channel(LinkView {
            configured: true,
            connected: true,
            down_since: None,
            ack: Some(HelloAck {
                reconcile_interval_secs: Some(120),
                covered: vec![target_ref(&policy.target), target_ref(&other.target)],
            }),
            version: Some(LAUNCH_VERSION),
        });
        let launches = Launches::new(Arc::clone(&store) as Arc<dyn Store>, host, view);
        // The fixture host has two slots.
        assert!(
            launches
                .decide(&launch(&policy, "a"), false, false)
                .accepted
        );
        assert!(launches.decide(&launch(&other, "b"), false, false).accepted);
        assert_eq!(
            launches.decide(&launch(&other, "c"), false, false).reason,
            Some(RefusalReason::HostCapacity)
        );
        assert_eq!(
            launches.decide(&launch(&policy, "d"), false, false).reason,
            Some(RefusalReason::HostCapacity)
        );
    }

    /// The invariant: a launch has a runner able to take a job, or one this
    /// host can start, or it is dropped. A slot taken since it was accepted
    /// (a runner of another profile) leaves it with none of those: the newest
    /// goes, and the heartbeat's list says so without waiting for a pass.
    #[test]
    fn a_launch_this_host_can_no_longer_start_is_dropped_oldest_kept() {
        let (store, policy, launches) = setup(LAUNCH_VERSION);
        let other = second_profile(&store, &policy, 6);
        assert!(
            launches
                .decide(&launch(&policy, "old"), false, false)
                .accepted
        );
        std::thread::sleep(Duration::from_millis(2));
        assert!(
            launches
                .decide(&launch(&policy, "new"), false, false)
                .accepted
        );
        assert_eq!(launches.open_leases().len(), 2, "both can start");
        store
            .record_attempt(
                &fixtures::attempt()
                    .id(AttemptId::new_random())
                    .policy_id(other.id)
                    .state(AttemptState::Busy)
                    .build(),
            )
            .expect("recorded");
        assert_eq!(launches.open_leases(), vec!["old".to_string()]);
        assert!(launches.holds_unstarted(std::slice::from_ref(&policy)));
    }

    /// An attempt is visible and waiting while it is still being started, so
    /// `settle` can give it to a launch before the pass reports it. It serves
    /// one launch, not two: the other still gets a runner of its own.
    #[test]
    fn a_runner_being_started_serves_one_launch_not_two() {
        let (store, policy, launches) = setup(LAUNCH_VERSION);
        assert!(
            launches
                .decide(&launch(&policy, "a"), false, false)
                .accepted
        );
        assert!(
            launches
                .decide(&launch(&policy, "b"), false, false)
                .accepted
        );
        let runner = AttemptId::new_random();
        store
            .record_attempt(
                &fixtures::attempt()
                    .id(runner)
                    .policy_id(policy.id)
                    .state(AttemptState::Starting)
                    .build(),
            )
            .expect("recorded");
        assert_eq!(launches.open_leases().len(), 2, "settled while it starts");
        launches.launched(&policy, runner);
        assert_eq!(launches.unstarted(), 1, "the other still needs a runner");
        assert_eq!(launches.directed_demand(&policy), Some(2));
    }

    /// Whatever keeps a launch from starting, it does not hold its lease to
    /// the end: it is dropped well inside the lease's lifetime.
    #[test]
    fn a_launch_with_no_runner_for_too_long_is_dropped() {
        let (_store, policy, launches) = setup(LAUNCH_VERSION);
        let before = Instant::now();
        assert!(
            launches
                .decide(&launch(&policy, "a"), false, false)
                .accepted
        );
        launches.settle(before + START_LIMIT - Duration::from_secs(1));
        assert_eq!(launches.open_for(policy.id), 1);
        assert!(!launches.take_dropped());
        launches.settle(Instant::now() + START_LIMIT);
        assert_eq!(launches.open_for(policy.id), 0);
        assert!(launches.take_dropped(), "the link says so at once");
        assert!(!launches.take_dropped());
    }

    /// A launch's runner took a job: served, closed, without any pass. Its
    /// runner exited idle: it took nothing, so the launch goes back to waiting
    /// and is not reported as that runner's, or its report would close a lease
    /// this host still means to serve.
    #[test]
    fn a_launch_whose_runner_exited_idle_is_served_again_and_one_that_took_a_job_closes() {
        let (store, policy, launches) = setup(LAUNCH_VERSION);
        let in_state = |id, state| {
            fixtures::attempt()
                .id(id)
                .policy_id(policy.id)
                .state(state)
                .build()
        };
        assert!(
            launches
                .decide(&launch(&policy, "a"), false, false)
                .accepted
        );
        let runner = AttemptId::new_random();
        store
            .record_attempt(&in_state(runner, AttemptState::Idle))
            .expect("recorded");
        launches.launched(&policy, runner);
        assert_eq!(launches.lease_of(runner).as_deref(), Some("a"));
        assert!(!launches.holds_unstarted(std::slice::from_ref(&policy)));

        store
            .record_attempt(
                &fixtures::attempt()
                    .id(runner)
                    .policy_id(policy.id)
                    .state(AttemptState::Finished)
                    .outcome(AttemptOutcome::ExitedIdleWithoutWork)
                    .build(),
            )
            .expect("recorded");
        // However long it idled first: the start limit counts from now.
        launches.settle(Instant::now() + START_LIMIT + Duration::from_secs(1));
        assert_eq!(launches.open_leases(), vec!["a".to_string()], "still open");
        assert_eq!(launches.lease_of(runner), None);
        assert!(launches.holds_unstarted(std::slice::from_ref(&policy)));
        assert_eq!(
            launches.directed_demand(&policy),
            Some(1),
            "a new runner is due"
        );

        // Another waiting runner takes it over at once.
        let second = AttemptId::new_random();
        store
            .record_attempt(&in_state(second, AttemptState::Idle))
            .expect("recorded");
        assert_eq!(launches.open_leases(), vec!["a".to_string()]);
        assert_eq!(launches.lease_of(second).as_deref(), Some("a"));
        // It takes a job: served.
        store
            .record_attempt(&in_state(second, AttemptState::Busy))
            .expect("recorded");
        assert!(launches.open_leases().is_empty());
    }

    /// The heartbeat lists the launches still open: accepted ones until
    /// cancelled; a policy change keeps them while their profile exists,
    /// and drops them once it is gone.
    #[test]
    fn the_open_launches_survive_a_policy_change_but_not_their_profile() {
        let (store, policy, launches) = setup(LAUNCH_VERSION);
        for lease in ["a", "b"] {
            assert!(
                launches
                    .decide(&launch(&policy, lease), false, false)
                    .accepted
            );
        }
        assert_eq!(
            launches.open_leases(),
            vec!["a".to_string(), "b".to_string()]
        );
        assert!(launches.cancel("a"));
        assert_eq!(launches.open_leases(), vec!["b".to_string()]);
        // Another repository added: the launch stays.
        let other = fixtures::policy()
            .id(PolicyId::new_random())
            .repository("octo/other")
            .host(policy.host_id)
            .autoscale("home", 1)
            .active()
            .build();
        store.insert_policy(&other).expect("added");
        let _ = launches.directed_demand(&policy);
        assert_eq!(launches.open_leases(), vec!["b".to_string()]);
        // Its own profile removed: nothing to start it with, from the next
        // pass on.
        store
            .remove_policy(policy.id, policy.revision())
            .expect("removed");
        let _ = launches.directed_demand(&policy);
        assert!(launches.open_leases().is_empty());
        assert_eq!(launches.open_for(policy.id), 0);
    }

    /// A slot may free when an attempt ends and again when it is cleaned
    /// (an isolated runner holds its slot until then): both are signalled,
    /// each once.
    #[test]
    fn an_ended_and_a_cleaned_attempt_each_signal_a_released_slot() {
        let (store, policy, launches) = setup(LAUNCH_VERSION);
        let policies = vec![policy.clone()];
        let meters = AttemptMeters::default();
        let mut reports = AttemptReports::default();
        let id = AttemptId::new_random();
        let in_state = |state| {
            fixtures::attempt()
                .id(id)
                .policy_id(policy.id)
                .state(state)
                .build()
        };
        store
            .record_attempt(&in_state(AttemptState::Busy))
            .expect("busy");
        reports.poll(store.as_ref(), &policies, &launches, &meters);
        assert!(!reports.take_released(), "a busy runner frees nothing");
        store
            .record_attempt(&in_state(AttemptState::Finished))
            .expect("finished");
        reports.poll(store.as_ref(), &policies, &launches, &meters);
        assert!(reports.take_released());
        assert!(!reports.take_released(), "said once");
        store
            .record_attempt(&in_state(AttemptState::Cleaned))
            .expect("cleaned");
        reports.poll(store.as_ref(), &policies, &launches, &meters);
        assert!(reports.take_released(), "cleaned: its slot is free now");
    }

    #[test]
    fn a_launch_becomes_one_runner_and_its_attempt_is_reported_with_its_lease() {
        let (store, policy, launches) = setup(LAUNCH_VERSION);
        let mut reports = AttemptReports::default();
        // An attempt that ended before the link saw it is not news.
        let old = fixtures::attempt()
            .id(AttemptId::new_random())
            .policy_id(policy.id)
            .state(AttemptState::Finished)
            .outcome(AttemptOutcome::ExitedIdleWithoutWork)
            .build();
        store.record_attempt(&old).expect("recorded");
        let policies = vec![policy.clone()];
        assert!(
            reports
                .poll(
                    store.as_ref(),
                    &policies,
                    &launches,
                    &AttemptMeters::default()
                )
                .is_empty()
        );

        assert!(
            launches
                .decide(&launch(&policy, "lease-1"), false, false)
                .accepted
        );
        assert_eq!(launches.directed_demand(&policy), Some(1));
        let id = AttemptId::new_random();
        let starting = fixtures::attempt()
            .id(id)
            .policy_id(policy.id)
            .state(AttemptState::Starting)
            .build();
        store.record_attempt(&starting).expect("recorded");
        launches.launched(&policy, id);
        assert!(
            reports
                .poll(
                    store.as_ref(),
                    &policies,
                    &launches,
                    &AttemptMeters::default()
                )
                .is_empty()
        );
        // Still waiting for a job: the launch stays open, and its runner
        // covers it in the allocator.
        assert_eq!(launches.directed_demand(&policy), Some(1));

        let busy = fixtures::attempt()
            .id(id)
            .policy_id(policy.id)
            .state(AttemptState::Busy)
            .build();
        store.record_attempt(&busy).expect("recorded");
        let started = reports.poll(
            store.as_ref(),
            &policies,
            &launches,
            &AttemptMeters::default(),
        );
        assert_eq!(started.len(), 1);
        let AttemptReport::Started(started) = &started[0] else {
            panic!("started");
        };
        assert_eq!(started.lease_id.as_deref(), Some("lease-1"));
        assert_eq!(
            started.runner_name,
            runner_manager_agent::lifecycle::runner_name(id)
        );
        // The runner took a job: the launch is closed.
        assert_eq!(launches.directed_demand(&policy), Some(0));

        let done = fixtures::attempt()
            .id(id)
            .policy_id(policy.id)
            .state(AttemptState::Finished)
            .outcome(AttemptOutcome::CompletedJob)
            .build();
        store.record_attempt(&done).expect("recorded");
        let finished = reports.poll(
            store.as_ref(),
            &policies,
            &launches,
            &AttemptMeters::default(),
        );
        assert!(matches!(
            finished.as_slice(),
            [AttemptReport::Finished(AttemptFinished {
                lease_id: Some(lease),
                outcome: AttemptOutcomeKind::CompletedJob,
                ..
            })] if lease == "lease-1"
        ));
        assert!(
            reports
                .poll(
                    store.as_ref(),
                    &policies,
                    &launches,
                    &AttemptMeters::default()
                )
                .is_empty()
        );
    }

    #[test]
    fn a_cancelled_or_expired_launch_no_longer_counts() {
        let (_store, policy, launches) = setup(LAUNCH_VERSION);
        assert!(
            launches
                .decide(&launch(&policy, "a"), false, false)
                .accepted
        );
        assert!(launches.cancel("a"));
        assert_eq!(launches.directed_demand(&policy), Some(0));
        // A cancelled lease cannot be launched afterwards.
        assert_eq!(
            launches.decide(&launch(&policy, "a"), false, false).reason,
            Some(RefusalReason::Stale)
        );
        let mut short = launch(&policy, "b");
        short.ttl_secs = 0;
        assert_eq!(
            launches.decide(&short, false, false).reason,
            Some(RefusalReason::Stale)
        );
        assert!(
            launches
                .decide(&launch(&policy, "c"), false, false)
                .accepted
        );
        launches.settle(Instant::now() + Duration::from_secs(301));
        assert_eq!(launches.open_for(policy.id), 0);
    }

    fn attempt_in(policy: &ScalePolicy, id: AttemptId, state: AttemptState) -> RunnerAttempt {
        let builder = fixtures::attempt().id(id).policy_id(policy.id).state(state);
        match state {
            AttemptState::Finished => builder.outcome(AttemptOutcome::CompletedJob).build(),
            _ => builder.build(),
        }
    }

    #[test]
    fn an_idle_runner_of_the_profile_serves_a_launch_instead_of_a_new_one() {
        let (store, policy, launches) = setup(LAUNCH_VERSION);
        let idle = AttemptId::new_random();
        store
            .record_attempt(&attempt_in(&policy, idle, AttemptState::Idle))
            .expect("recorded");
        assert!(
            launches
                .decide(&launch(&policy, "l"), false, false)
                .accepted
        );
        // Bound to the idle runner: still one launch, served by it.
        assert_eq!(launches.directed_demand(&policy), Some(1));
        assert_eq!(launches.lease_of(idle).as_deref(), Some("l"));
        // It takes the job: the launch closes and nothing new is owed.
        store
            .record_attempt(&attempt_in(&policy, idle, AttemptState::Busy))
            .expect("recorded");
        assert_eq!(launches.directed_demand(&policy), Some(0));
    }

    #[test]
    fn a_lost_link_drops_every_open_launch() {
        let (_store, policy, launches) = setup(LAUNCH_VERSION);
        assert!(
            launches
                .decide(&launch(&policy, "l"), false, false)
                .accepted
        );
        launches.clear();
        assert_eq!(launches.open_for(policy.id), 0);
    }

    #[test]
    fn each_attempt_is_reported_started_and_finished_once_whatever_its_cleanup() {
        let (store, policy, launches) = setup(LAUNCH_VERSION);
        let policies = vec![policy.clone()];
        let mut reports = AttemptReports::default();
        let id = AttemptId::new_random();
        store
            .record_attempt(&attempt_in(&policy, id, AttemptState::Busy))
            .expect("recorded");
        assert_eq!(
            reports
                .poll(
                    store.as_ref(),
                    &policies,
                    &launches,
                    &AttemptMeters::default()
                )
                .len(),
            1
        );
        store
            .record_attempt(&attempt_in(&policy, id, AttemptState::Finished))
            .expect("recorded");
        assert_eq!(
            reports
                .poll(
                    store.as_ref(),
                    &policies,
                    &launches,
                    &AttemptMeters::default()
                )
                .len(),
            1
        );
        assert!(
            reports
                .poll(
                    store.as_ref(),
                    &policies,
                    &launches,
                    &AttemptMeters::default()
                )
                .is_empty()
        );
        // An isolated attempt still being destroyed when the link comes up
        // ended long ago: not a start, not news.
        let destroying = AttemptId::new_random();
        store
            .record_attempt(&attempt_in(&policy, destroying, AttemptState::Destroying))
            .expect("recorded");
        assert!(
            reports
                .poll(
                    store.as_ref(),
                    &policies,
                    &launches,
                    &AttemptMeters::default()
                )
                .is_empty()
        );

        // A launched runner that failed between two looks is still reported,
        // so its lease closes.
        assert!(
            launches
                .decide(&launch(&policy, "short"), false, false)
                .accepted
        );
        let short = AttemptId::new_random();
        launches.launched(&policy, short);
        let failed = fixtures::attempt()
            .id(short)
            .policy_id(policy.id)
            .state(AttemptState::Failed)
            .build();
        store.record_attempt(&failed).expect("recorded");
        let reported = reports.poll(
            store.as_ref(),
            &policies,
            &launches,
            &AttemptMeters::default(),
        );
        assert!(matches!(
            reported.as_slice(),
            [AttemptReport::Finished(AttemptFinished { lease_id: Some(lease), .. })] if lease == "short"
        ));
        assert!(
            reports
                .poll(
                    store.as_ref(),
                    &policies,
                    &launches,
                    &AttemptMeters::default()
                )
                .is_empty()
        );
    }

    #[test]
    fn a_finished_attempt_carries_what_its_meter_measured_once() {
        let (store, policy, launches) = setup(LAUNCH_VERSION);
        let policies = vec![policy.clone()];
        let mut reports = AttemptReports::default();
        let meters = AttemptMeters::default();
        let id = AttemptId::new_random();
        store
            .record_attempt(&attempt_in(&policy, id, AttemptState::Busy))
            .expect("recorded");
        assert_eq!(
            reports
                .poll(store.as_ref(), &policies, &launches, &meters)
                .len(),
            1
        );
        meters.record(
            id,
            tokio::time::Instant::now(),
            runner_manager_platform::resource_usage::TreeUsage {
                rss_bytes: 7 << 20,
                cpu_time: Duration::from_secs(1),
                processes: 3,
            },
        );
        store
            .record_attempt(&attempt_in(&policy, id, AttemptState::Finished))
            .expect("recorded");
        let reported = reports.poll(store.as_ref(), &policies, &launches, &meters);
        assert!(
            matches!(
                reported.as_slice(),
                [AttemptReport::Finished(AttemptFinished {
                    usage: Some(usage),
                    ..
                })] if usage.peak_rss_bytes == 7 << 20 && usage.samples == 1
            ),
            "{reported:?}"
        );
        assert_eq!(meters.take(id), None, "taken by the report");
    }
}
