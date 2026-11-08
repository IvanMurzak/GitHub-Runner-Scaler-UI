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

    /// Closes every open launch that expired, whose profile is gone, and
    /// whose runner is no longer waiting for a job. A launch without a runner of its own is
    /// first given a waiting runner of its profile that no launch holds (one
    /// left idle, or kept by `min_capacity`): that runner is what serves it,
    /// so the allocator must not start another, and its claim closes it.
    fn settle(&self, now: Instant) {
        let policies: HashSet<PolicyId> =
            self.book().open.values().map(|open| open.policy).collect();
        // A launch whose profile was removed, or stopped being this host's
        // pool profile, starts nothing any more; every other one survives a
        // policy change. `Err` (unreadable) keeps them all.
        let gone: HashSet<PolicyId> = policies
            .iter()
            .copied()
            .filter(|policy| {
                self.store
                    .policy(*policy)
                    .is_ok_and(|found| found.is_none_or(|found| !self.is_own_pool_profile(&found)))
            })
            .collect();
        // Read without holding the book: the link and the passes use it.
        let waiting: HashMap<PolicyId, Vec<AttemptId>> = policies
            .into_iter()
            .map(|policy| {
                let attempts = self
                    .store
                    .uncleaned_attempts_for_policy(policy)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|attempt| attempt.state().is_unassigned())
                    .map(|attempt| attempt.id)
                    .collect();
                (policy, attempts)
            })
            .collect();
        let mut book = self.book();
        book.open
            .retain(|_, open| open.expires > now && !gone.contains(&open.policy));
        let held: HashSet<AttemptId> = book.open.values().filter_map(|open| open.attempt).collect();
        let mut free: HashMap<PolicyId, Vec<AttemptId>> = waiting
            .iter()
            .map(|(policy, attempts)| {
                let attempts = attempts
                    .iter()
                    .filter(|attempt| !held.contains(attempt))
                    .copied()
                    .collect();
                (*policy, attempts)
            })
            .collect();
        let mut bound = Vec::new();
        for (lease_id, open) in &mut book.open {
            match open.attempt {
                // Its runner took a job or ended.
                Some(attempt)
                    if !waiting
                        .get(&open.policy)
                        .is_some_and(|attempts| attempts.contains(&attempt)) =>
                {
                    open.expires = now;
                }
                Some(_) => {}
                None => {
                    if let Some(attempt) = free.get_mut(&open.policy).and_then(Vec::pop) {
                        open.attempt = Some(attempt);
                        bound.push((attempt, lease_id.clone()));
                    }
                }
            }
        }
        book.open.retain(|_, open| open.expires > now);
        for (attempt, lease_id) in bound {
            book.lease_runner(attempt, &lease_id);
        }
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
        let mut host = self.host.clone();
        if let Ok(Some(current)) = self.store.host(self.host.id) {
            host.host_capacity = current.host_capacity;
        }
        let attempts: Vec<RunnerAttempt> = policies
            .iter()
            .filter(|policy| policy.is_owned_by(self.host.id))
            .filter_map(|policy| self.store.uncleaned_attempts_for_policy(policy.id).ok())
            .flatten()
            .collect();
        let open = self.open_for(policy.id);
        let allocator = HostAllocator::from_attempts(&host, &attempts);
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
    /// any accepted lease of this host not among them.
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
        assert_eq!(launches.open_leases(), vec!["b".to_string()]);
        // Its own profile removed: nothing to start it with.
        store
            .remove_policy(policy.id, policy.revision())
            .expect("removed");
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
