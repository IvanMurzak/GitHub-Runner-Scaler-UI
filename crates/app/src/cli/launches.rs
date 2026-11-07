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
use runner_manager_coordinator_protocol::{
    AttemptFinished, AttemptOutcomeKind, AttemptStarted, Launch, LaunchAck, RefusalReason,
};
use runner_manager_domain::attempt::{AttemptOutcome, RunnerAttempt};
use runner_manager_domain::capacity::{HostAllocator, LimitingFactor};
use runner_manager_domain::model::{AttemptId, Host, PolicyId};
use runner_manager_domain::policy::ScalePolicy;
use runner_manager_domain::store::Store;
use tokio::sync::watch;
use tokio::time::Instant;

use super::coordinator::{LinkView, same_target, target_ref};

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
        policy.is_owned_by(self.host.id)
            && policy.pool_label().is_some()
            && self
                .view
                .borrow()
                .launch_mode(&policy.target, Instant::now())
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

    /// Closes every open launch that expired, and every one whose runner is
    /// no longer waiting for a job.
    fn settle(&self, now: Instant) {
        let started: Vec<(String, AttemptId)> = self
            .book()
            .open
            .iter()
            .filter_map(|(id, open)| open.attempt.map(|attempt| (id.clone(), attempt)))
            .collect();
        // Read without holding the book: the link and the passes use it.
        let done: Vec<String> = started
            .into_iter()
            .filter(|(_, attempt)| {
                !self
                    .store
                    .attempt(*attempt)
                    .ok()
                    .flatten()
                    .is_some_and(|attempt| attempt.state().is_unassigned())
            })
            .map(|(lease_id, _)| lease_id)
            .collect();
        let mut book = self.book();
        for lease_id in done {
            book.open.remove(&lease_id);
        }
        book.open.retain(|_, open| open.expires > now);
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
                && policy.is_owned_by(self.host.id)
                && policy.pool_label().is_some()
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
}

/// Turns this host's attempt states into `attempt_started` (a runner took a
/// job) and `attempt_finished` reports. Attempts that had already ended when
/// the link came up are not reported.
#[derive(Debug, Default)]
pub struct AttemptReports {
    watched: HashMap<AttemptId, Watched>,
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
    ) -> Vec<AttemptReport> {
        let mut reports = Vec::new();
        let mut present = HashSet::new();
        for policy in policies {
            let Ok(attempts) = store.uncleaned_attempts_for_policy(policy.id) else {
                continue;
            };
            for attempt in attempts {
                present.insert(attempt.id);
                let concluded = attempt.state().is_concluded();
                let watched = match self.watched.get_mut(&attempt.id) {
                    Some(watched) => watched,
                    // Ended before this link saw it: not news.
                    None if concluded => continue,
                    None => self.watched.entry(attempt.id).or_insert(Watched {
                        policy: policy.id,
                        started: false,
                    }),
                };
                if !watched.started && !attempt.state().is_unassigned() && !concluded {
                    watched.started = true;
                    reports.push(AttemptReport::Started(AttemptStarted {
                        lease_id: launches.lease_of(attempt.id),
                        runner_name: runner_manager_agent::lifecycle::runner_name(attempt.id),
                        target: target_ref(&policy.target),
                        profile: policy.profile_name().to_string(),
                    }));
                }
                if concluded {
                    self.watched.remove(&attempt.id);
                    reports.push(finished(&attempt, launches));
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
        for id in gone {
            let watched = self.watched.remove(&id);
            let still_served = watched
                .is_some_and(|watched| policies.iter().any(|policy| policy.id == watched.policy));
            if let (true, Ok(Some(attempt))) = (still_served, store.attempt(id)) {
                reports.push(finished(&attempt, launches));
            }
        }
        reports
    }
}

fn finished(attempt: &RunnerAttempt, launches: &Launches) -> AttemptReport {
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
    })
}

#[cfg(test)]
mod tests {
    use runner_manager_coordinator_protocol::{HelloAck, LAUNCH_VERSION};
    use runner_manager_domain::attempt::AttemptState;
    use runner_manager_domain::policy::pool_label;
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
                .poll(store.as_ref(), &policies, &launches)
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
                .poll(store.as_ref(), &policies, &launches)
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
        let started = reports.poll(store.as_ref(), &policies, &launches);
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
        let finished = reports.poll(store.as_ref(), &policies, &launches);
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
                .poll(store.as_ref(), &policies, &launches)
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
}
