// owner: b1-domain-core

//! The two-level capacity ceiling (D7, D9), expressed as an allocator.
//!
//! ```text
//! demand        = queued jobs whose required labels match this policy's routing labels
//! desired       = clamp(demand, min_capacity, max_capacity)
//! host_headroom = host_capacity - active_owned_runners_all_policies
//! to_start      = max(0, min(desired - active_owned_runners, host_headroom))
//! ```
//!
//! **Why this is a type and not a function.** `b1`'s Scope requires the host
//! ceiling to be "a first-class allocator over all policies, not a check a caller
//! may forget". A per-policy `to_start(policy, demand)` free function cannot
//! enforce D9 at all: the host ceiling is a property of the *set* of policies, so
//! N policies each individually under their own `max_capacity` still
//! oversubscribe one machine. [`HostAllocator`] owns the running total, deducts
//! from it on every grant, and is the only way to obtain a `to_start`, so there
//! is no call shape in which the ceiling is skipped.
//!
//! **Why `- active_owned_runners` is load-bearing.** Under scale sets, demand was
//! a count of *assigned* jobs. Over REST it is a count of *queued* jobs, and a
//! job stays queued across consecutive polls while its runner is starting. A
//! formula that ignored attempts already in flight would start a fresh runner on
//! every poll until the job was finally picked up — runaway runners, with no
//! error anywhere. `e1`'s Definition of Done tests three consecutive polls;
//! [`tests::the_same_queued_job_on_two_polls_yields_one_attempt_not_two`] tests
//! the arithmetic underneath it.
//!
//! **There is no reservation here.** Nothing in this module claims, leases, or
//! acknowledges a job. The surplus runner that results is an accepted, bounded
//! cost (`02-target-architecture.md`), and the two ceilings computed here are two
//! of the three controls that bound it.

use std::fmt;
use std::num::NonZeroU16;

use crate::attempt::RunnerAttempt;
use crate::model::{Host, HostId, PolicyId};
use crate::policy::ScalePolicy;

/// Why `to_start` came out the size it did.
///
/// Reported rather than inferred, because "we started fewer runners than demand"
/// has five quite different causes and an operator staring at a queue needs to
/// know which one applies. `g2` renders it; `e1` emits it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitingFactor {
    /// Demand was fully served.
    Demand,
    /// `min_capacity` raised the target above demand. Unreachable in v1, where
    /// D7 fixes `min_capacity` at 0, but the clamp has two ends and this is the
    /// other one.
    MinCapacity,
    /// The per-policy ceiling bound first.
    MaxCapacity,
    /// The host ceiling bound first. D9's whole reason for existing.
    HostCapacity,
    /// The policy is monitor-only and owns nothing (D19).
    MonitorOnly,
    /// The policy is not `active`, not enabled, or both — a `pending`,
    /// `draining`, `disabled`, `repair_required`, or `authentication_failed`
    /// policy starts nothing.
    NotReconciling,
    /// The policy belongs to another host. Ownership rule 2.
    ForeignHost,
}

impl fmt::Display for LimitingFactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            LimitingFactor::Demand => "demand",
            LimitingFactor::MinCapacity => "min_capacity",
            LimitingFactor::MaxCapacity => "max_capacity",
            LimitingFactor::HostCapacity => "host_capacity",
            LimitingFactor::MonitorOnly => "monitor_only",
            LimitingFactor::NotReconciling => "not_reconciling",
            LimitingFactor::ForeignHost => "foreign_host",
        })
    }
}

/// One policy's share of one reconciliation pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    pub policy_id: PolicyId,
    /// Queued jobs matching this policy's routing labels.
    pub demand: u32,
    /// `clamp(demand, min_capacity, max_capacity)`.
    pub desired: u16,
    /// Attempts already in flight for this policy.
    pub active_owned: u16,
    /// Host headroom before this allocation was granted.
    pub headroom_before: u16,
    /// How many runners to start now. Never more than the headroom.
    pub to_start: u16,
    pub limiting_factor: LimitingFactor,
}

impl Allocation {
    #[must_use]
    pub const fn starts_nothing(&self) -> bool {
        self.to_start == 0
    }
}

/// The host-wide allocator. One per reconciliation pass.
///
/// Construct it from the host and every attempt currently on the machine, then
/// call [`HostAllocator::allocate`] once per policy. Each grant reduces the
/// remaining headroom, so the sum of `to_start` across all policies in one pass
/// can never exceed `host_capacity - active_total`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAllocator {
    host_id: HostId,
    host_capacity: NonZeroU16,
    active_total: u16,
}

impl HostAllocator {
    /// Build from an explicit active total.
    ///
    /// The total is **not** clamped to `host_capacity` — [`Self::active_total`]
    /// reports the raw count, over-subscription included, because an operator
    /// looking at a machine holding more attempts than its ceiling needs to see
    /// that. What saturates is [`Self::headroom`], which floors at zero: an
    /// over-subscribed machine has no headroom, rather than negative headroom
    /// that wraps into a large positive one.
    #[must_use]
    pub fn new(host: &Host, active_total: u16) -> Self {
        Self {
            host_id: host.id,
            host_capacity: host.host_capacity,
            active_total,
        }
    }

    /// Build by counting the attempts the machine actually holds.
    ///
    /// Prefer this. Passing every attempt across every policy is what makes the
    /// host ceiling a fact about the machine rather than a number a caller
    /// remembered to compute.
    #[must_use]
    pub fn from_attempts<'a>(
        host: &Host,
        attempts: impl IntoIterator<Item = &'a RunnerAttempt>,
    ) -> Self {
        Self::new(host, crate::attempt::active_count(attempts))
    }

    #[must_use]
    pub fn host_capacity(&self) -> u16 {
        self.host_capacity.get()
    }

    /// Attempts currently occupying a slot, across every policy.
    #[must_use]
    pub const fn active_total(&self) -> u16 {
        self.active_total
    }

    /// `host_capacity - active_owned_runners_all_policies`, floored at zero.
    #[must_use]
    pub fn headroom(&self) -> u16 {
        self.host_capacity.get().saturating_sub(self.active_total)
    }

    /// Decide how many runners to start for one policy, and spend the headroom.
    ///
    /// Pass every attempt on the machine — the same set given to
    /// [`Self::from_attempts`]. This method selects the ones belonging to
    /// `policy` and still occupying a slot, and that count is `active_owned`:
    /// the term that stops a job still sitting in the queue from being served
    /// twice. It is derived from the same host-wide total because the two are
    /// different quantities over the same set — the total is host-wide (D9),
    /// this one is per-policy (D7), and `to_start` is bound by both.
    ///
    /// **Why this is a slice and not a `u16`.** It used to be a `u16`, and the
    /// argument the module documentation makes about the *host* ceiling —
    /// "an allocator, not a check a caller may forget" — applies with equal
    /// force one level down. `active_owned` is the term whose omission is
    /// silent: a caller passing a literal `0` compiled, ran, and started a
    /// fresh runner on every poll for a job that was already being served, with
    /// no error anywhere. There is no longer a way to write that call. If a
    /// caller genuinely holds a pre-computed count, it can still reach
    /// [`crate::attempt::active_count_for`] directly and see what it is asking
    /// for by name.
    pub fn allocate<'a>(
        &mut self,
        policy: &ScalePolicy,
        demand: u32,
        attempts: impl IntoIterator<Item = &'a RunnerAttempt>,
    ) -> Allocation {
        let active_owned = crate::attempt::active_count_for(policy.id, attempts);
        let headroom_before = self.headroom();

        let refuse = |limiting_factor| Allocation {
            policy_id: policy.id,
            demand,
            desired: 0,
            active_owned,
            headroom_before,
            to_start: 0,
            limiting_factor,
        };

        // Ownership rule 2, checked before anything is spent: an agent may act
        // only on policies under its own host.
        if !policy.is_owned_by(self.host_id) {
            return refuse(LimitingFactor::ForeignHost);
        }
        // D19: a monitor-only policy is skipped entirely by reconciliation, and
        // this is asserted on the mode rather than deduced from `max_capacity`
        // being absent.
        if !policy.owns_runners() {
            return refuse(LimitingFactor::MonitorOnly);
        }
        // Precedence rule 4: a user-requested disable beats demand.
        if !policy.may_start_runners() {
            return refuse(LimitingFactor::NotReconciling);
        }

        let min = policy.min_capacity();
        let max = policy
            .max_capacity()
            .expect("an Autoscale policy always has a max_capacity (D19)")
            .get();

        // `min <= max` was validated when the policy was built
        // (`policy::AutoscaleConfig::new`), which is what keeps this `clamp`
        // total -- Rust's `clamp` panics on an inverted range.
        debug_assert!(min <= max, "PolicyMode invariant");
        let desired = demand.clamp(u32::from(min), u32::from(max)) as u16;

        let limiting_factor = if demand > u32::from(max) {
            LimitingFactor::MaxCapacity
        } else if demand < u32::from(min) {
            LimitingFactor::MinCapacity
        } else {
            LimitingFactor::Demand
        };

        let wanted = desired.saturating_sub(active_owned);
        let to_start = wanted.min(headroom_before);
        let limiting_factor = if to_start < wanted {
            // The host ceiling bound before the per-policy one did.
            LimitingFactor::HostCapacity
        } else {
            limiting_factor
        };

        self.active_total = self.active_total.saturating_add(to_start);

        Allocation {
            policy_id: policy.id,
            demand,
            desired,
            active_owned,
            headroom_before,
            to_start,
            limiting_factor,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attempt::{
        AttemptOutcome, AttemptState, FailureReason, PersistedAttempt, RunnerAttempt,
    };
    use crate::model::{
        Arch, AttemptId, CachePolicy, HostLabel, Os, PolicyId, ScaleTarget, Timestamp,
    };
    use crate::policy::{PolicyMode, RoutingLabels, RunsOn, ScalePolicy};

    fn ts(secs: i64) -> Timestamp {
        chrono::DateTime::from_timestamp(secs, 0).expect("valid timestamp")
    }

    fn nz(v: u16) -> NonZeroU16 {
        NonZeroU16::new(v).expect("non-zero")
    }

    const HOST: HostId = HostId::from_u128(7);

    fn host(capacity: u16) -> Host {
        Host::new(HOST, "home-pc", Os::Windows, Arch::X64, nz(capacity), ts(0)).expect("valid host")
    }

    fn labels(name: &str) -> RoutingLabels {
        RoutingLabels::derive(&HostLabel::new(name).unwrap(), Os::Windows, Arch::X64)
    }

    /// An `active`, enabled autoscale policy — the only kind that ever starts a
    /// runner.
    fn active_policy(id: u128, host_label: &str, max: u16) -> ScalePolicy {
        let mut policy = ScalePolicy::new(
            PolicyId::from_u128(id),
            ScaleTarget::repository("o/r").unwrap(),
            1,
            HOST,
            PolicyMode::autoscale(labels(host_label), 0, nz(max)).unwrap(),
            CachePolicy::default(),
        );
        policy.activate().expect("pending -> active");
        policy
    }

    /// A journal row in `state`. A terminal state needs a matching outcome, so
    /// one is supplied rather than letting the fixture build a row the domain
    /// would refuse to load.
    fn attempt_in(state: AttemptState, id: u128, policy: u128) -> RunnerAttempt {
        let outcome = state.is_terminal().then(|| match state {
            AttemptState::Failed => {
                AttemptOutcome::failed(FailureReason::ProcessExitedUnexpectedly)
            }
            AttemptState::Orphaned => AttemptOutcome::Orphaned,
            _ => AttemptOutcome::CompletedJob,
        });
        RunnerAttempt::from_persisted(PersistedAttempt {
            id: AttemptId::from_u128(id),
            policy_id: PolicyId::from_u128(policy),
            github_runner_id: None,
            state,
            outcome,
            process_id: None,
            runtime_path: "runtime/p/a".into(),
            created_at: ts(0),
            terminal_at: state.is_terminal().then(|| ts(0)),
            last_state_change_at: ts(0),
        })
        .expect("a state/outcome pair the domain accepts")
    }

    // =======================================================================
    // The clamp, both ends
    // =======================================================================

    #[test]
    fn desired_clamps_above_and_below() {
        let host = host(100);
        let policy = active_policy(1, "home", 3);

        // Above the ceiling.
        let mut alloc = HostAllocator::new(&host, 0);
        let above = alloc.allocate(&policy, 10, &[]);
        assert_eq!(above.desired, 3, "max_capacity beats reported demand");
        assert_eq!(above.to_start, 3);
        assert_eq!(above.limiting_factor, LimitingFactor::MaxCapacity);

        // Inside the range.
        let mut alloc = HostAllocator::new(&host, 0);
        let inside = alloc.allocate(&policy, 2, &[]);
        assert_eq!(inside.desired, 2);
        assert_eq!(inside.to_start, 2);
        assert_eq!(inside.limiting_factor, LimitingFactor::Demand);

        // At the floor. D7 fixes min_capacity at 0 in v1, so no demand means no
        // runners -- the "no idle runners when unused" requirement.
        let mut alloc = HostAllocator::new(&host, 0);
        let none = alloc.allocate(&policy, 0, &[]);
        assert_eq!(none.desired, 0);
        assert_eq!(none.to_start, 0);
        assert!(none.starts_nothing());
    }

    #[test]
    fn a_non_zero_min_capacity_raises_desired_above_demand() {
        // The other end of the clamp. Not reachable in v1 (D7 fixes min at 0),
        // but the formula has two ends and a later warm-minimum feature would
        // arrive through this path.
        let host = host(10);
        let mut policy = ScalePolicy::new(
            PolicyId::from_u128(1),
            ScaleTarget::organization("acme").unwrap(),
            1,
            HOST,
            PolicyMode::autoscale(labels("home"), 2, nz(5)).unwrap(),
            CachePolicy::default(),
        );
        policy.activate().unwrap();

        let mut alloc = HostAllocator::new(&host, 0);
        let got = alloc.allocate(&policy, 0, &[]);
        assert_eq!(got.desired, 2);
        assert_eq!(got.to_start, 2);
        assert_eq!(got.limiting_factor, LimitingFactor::MinCapacity);
    }

    // =======================================================================
    // The in-flight term
    // =======================================================================

    #[test]
    fn the_same_queued_job_on_two_polls_yields_one_attempt_not_two() {
        // `b1`: "the same queued job present on two consecutive polls yielding
        // one attempt, not two". This is the single most likely way `e1` goes
        // wrong, and it is silent when it does: the operator sees runaway
        // runners, not an error.
        //
        // The job stays `queued` at GitHub for the whole time its runner is
        // starting, because there is no `AcquireJobs` to take it out of the
        // queue. So demand reads 1 on every poll.
        let host = host(4);
        let policy = active_policy(1, "home", 4);
        let queued = vec![RunsOn::Single("rm-home-win-x64".into())];

        // Poll 1: nothing in flight.
        let demand = policy.tally(&queued).demand();
        assert_eq!(demand, 1);
        let mut alloc = HostAllocator::new(&host, 0);
        let first = alloc.allocate(&policy, demand, &[]);
        assert_eq!(first.to_start, 1);

        // The runner is allocated and starting. The job is *still queued*.
        let attempts = vec![attempt_in(AttemptState::Starting, 1, 1)];

        // Poll 2, and poll 3: same job, same demand, one attempt in flight.
        for poll in 2..=3 {
            let demand = policy.tally(&queued).demand();
            assert_eq!(demand, 1, "poll {poll}: the job has not left the queue");

            let mut alloc = HostAllocator::from_attempts(&host, &attempts);
            let again = alloc.allocate(&policy, demand, &attempts);
            assert_eq!(
                again.to_start, 0,
                "poll {poll} started another runner for a job already being \
                 served; the `- active_owned_runners` term was dropped from the \
                 formula"
            );
            assert_eq!(again.desired, 1);
            assert_eq!(again.active_owned, 1);
        }
    }

    #[test]
    fn an_attempt_stops_counting_once_it_is_terminal() {
        let host = host(4);
        let policy = active_policy(1, "home", 4);

        let in_flight = vec![
            attempt_in(AttemptState::Allocated, 1, 1),
            attempt_in(AttemptState::Starting, 2, 1),
            attempt_in(AttemptState::Busy, 3, 1),
        ];
        let mut alloc = HostAllocator::from_attempts(&host, &in_flight);
        assert_eq!(alloc.active_total(), 3);
        assert_eq!(alloc.headroom(), 1);
        assert_eq!(alloc.allocate(&policy, 4, &in_flight).to_start, 1);

        // The same three, all concluded: their slots are back.
        let done = vec![
            attempt_in(AttemptState::Finished, 1, 1),
            attempt_in(AttemptState::Failed, 2, 1),
            attempt_in(AttemptState::Cleaned, 3, 1),
        ];
        let mut alloc = HostAllocator::from_attempts(&host, &done);
        assert_eq!(alloc.active_total(), 0);
        assert_eq!(alloc.headroom(), 4);
        assert_eq!(alloc.allocate(&policy, 4, &[]).to_start, 4);
    }

    // =======================================================================
    // The host ceiling (D9)
    // =======================================================================

    #[test]
    fn the_host_ceiling_binds_across_two_policies_whose_max_capacities_sum_higher() {
        // D9's reason for existing: "A single per-policy limit cannot stop N
        // policies from jointly oversubscribing one machine."
        let host = host(3);
        let a = active_policy(1, "home", 3);
        let b = active_policy(2, "home", 3);

        let mut alloc = HostAllocator::new(&host, 0);
        let first = alloc.allocate(&a, 10, &[]);
        let second = alloc.allocate(&b, 10, &[]);

        assert_eq!(first.to_start, 3, "the first policy takes the whole host");
        assert_eq!(
            second.to_start, 0,
            "the second gets nothing; each policy is individually within its own \
             max_capacity of 3, and 3 + 3 > host_capacity of 3"
        );
        assert_eq!(second.limiting_factor, LimitingFactor::HostCapacity);
        assert_eq!(
            first.to_start + second.to_start,
            3,
            "the sum across policies must never exceed host_capacity"
        );
        assert_eq!(alloc.headroom(), 0);
    }

    #[test]
    fn the_host_ceiling_splits_headroom_between_policies_in_call_order() {
        let host = host(5);
        let a = active_policy(1, "home", 4);
        let b = active_policy(2, "home", 4);
        let c = active_policy(3, "home", 4);

        let mut alloc = HostAllocator::new(&host, 0);
        let first = alloc.allocate(&a, 4, &[]);
        let second = alloc.allocate(&b, 4, &[]);
        let third = alloc.allocate(&c, 4, &[]);

        assert_eq!(first.to_start, 4);
        assert_eq!(second.to_start, 1, "one slot of headroom left");
        assert_eq!(second.limiting_factor, LimitingFactor::HostCapacity);
        assert_eq!(third.to_start, 0);
        assert_eq!(
            first.to_start + second.to_start + third.to_start,
            5,
            "12 requested across three policies, 5 granted, which is host_capacity"
        );
    }

    #[test]
    fn zero_headroom_starts_nothing_even_at_maximum_demand() {
        let host = host(2);
        let policy = active_policy(1, "home", 2);

        let full = vec![
            attempt_in(AttemptState::Busy, 1, 1),
            attempt_in(AttemptState::Busy, 2, 1),
        ];
        let mut alloc = HostAllocator::from_attempts(&host, &full);
        assert_eq!(alloc.headroom(), 0);

        let got = alloc.allocate(&policy, u32::from(u16::MAX), &full);
        assert_eq!(got.to_start, 0);
        assert_eq!(got.headroom_before, 0);
        assert_eq!(got.limiting_factor, LimitingFactor::MaxCapacity);
    }

    #[test]
    fn headroom_smaller_than_the_per_policy_allowance_wins() {
        // `b1`: "headroom smaller than the per-policy allowance". A policy
        // allowed 5 on a host with 2 free slots gets 2.
        let host = host(6);
        let policy = active_policy(1, "home", 5);

        let others = vec![
            attempt_in(AttemptState::Busy, 1, 99),
            attempt_in(AttemptState::Busy, 2, 99),
            attempt_in(AttemptState::Idle, 3, 99),
            attempt_in(AttemptState::Starting, 4, 99),
        ];
        let mut alloc = HostAllocator::from_attempts(&host, &others);
        assert_eq!(alloc.headroom(), 2, "four slots are held by another policy");

        let got = alloc.allocate(&policy, 5, &[]);
        assert_eq!(got.desired, 5, "the policy's own ceiling would allow five");
        assert_eq!(got.to_start, 2, "but the host has only two slots free");
        assert_eq!(got.limiting_factor, LimitingFactor::HostCapacity);
        assert_eq!(alloc.headroom(), 0);
    }

    #[test]
    fn an_over_subscribed_host_reports_zero_headroom_rather_than_wrapping() {
        // If some caller ever hands in more active attempts than the ceiling,
        // `host_capacity - active_total` must not wrap to 65535 and authorise a
        // storm of runners.
        let host = host(2);
        let policy = active_policy(1, "home", 10);
        let mut alloc = HostAllocator::new(&host, 9);
        assert_eq!(alloc.headroom(), 0);
        assert_eq!(alloc.allocate(&policy, 10, &[]).to_start, 0);
    }

    // =======================================================================
    // Precedence: who is allowed to ask at all
    // =======================================================================

    #[test]
    fn a_monitor_only_policy_under_maximum_demand_starts_nothing() {
        // D19. `e1` must "assert this rather than relying on its `max_capacity`
        // being absent", so the refusal is reported as `MonitorOnly` and not as a
        // capacity outcome.
        let host = host(10);
        let mut policy = ScalePolicy::new(
            PolicyId::from_u128(1),
            ScaleTarget::organization("acme").unwrap(),
            1,
            HOST,
            PolicyMode::monitor_only(),
            CachePolicy::default(),
        );
        policy.activate().unwrap();

        let mut alloc = HostAllocator::new(&host, 0);
        let got = alloc.allocate(&policy, 1_000, &[]);
        assert_eq!(got.to_start, 0);
        assert_eq!(got.limiting_factor, LimitingFactor::MonitorOnly);
        assert_eq!(
            alloc.headroom(),
            10,
            "and it consumes no headroom, so an autoscale policy on the same host \
             is unaffected"
        );
    }

    #[test]
    fn a_policy_that_is_not_active_and_enabled_starts_nothing() {
        let host = host(10);

        // Pending: D20 says `add` never arms a host.
        let pending = ScalePolicy::new(
            PolicyId::from_u128(1),
            ScaleTarget::repository("o/r").unwrap(),
            1,
            HOST,
            PolicyMode::autoscale(labels("home"), 0, nz(5)).unwrap(),
            CachePolicy::default(),
        );
        let mut alloc = HostAllocator::new(&host, 0);
        let got = alloc.allocate(&pending, 5, &[]);
        assert_eq!(got.to_start, 0);
        assert_eq!(got.limiting_factor, LimitingFactor::NotReconciling);

        // Draining: precedence rule 4, a user-requested disable beats demand.
        let mut draining = active_policy(2, "home", 5);
        draining.request_disable().unwrap();
        let mut alloc = HostAllocator::new(&host, 0);
        let got = alloc.allocate(&draining, 5, &[]);
        assert_eq!(got.to_start, 0);
        assert_eq!(got.limiting_factor, LimitingFactor::NotReconciling);
        assert_eq!(alloc.headroom(), 10);
    }

    #[test]
    fn a_policy_belonging_to_another_host_is_refused_before_any_headroom_is_spent() {
        let host = host(4);
        let mut theirs = ScalePolicy::new(
            PolicyId::from_u128(1),
            ScaleTarget::repository("o/r").unwrap(),
            1,
            HostId::from_u128(8),
            PolicyMode::autoscale(labels("office"), 0, nz(4)).unwrap(),
            CachePolicy::default(),
        );
        theirs.activate().unwrap();

        let mut alloc = HostAllocator::new(&host, 0);
        let got = alloc.allocate(&theirs, 4, &[]);
        assert_eq!(got.to_start, 0);
        assert_eq!(got.limiting_factor, LimitingFactor::ForeignHost);
        assert_eq!(alloc.headroom(), 4);
    }

    // =======================================================================
    // The precedence chain, end to end
    // =======================================================================

    #[test]
    fn max_capacity_beats_demand_and_host_capacity_beats_max_capacity() {
        // Precedence rule 5, as one assertion chain.
        let host = host(2);
        let policy = active_policy(1, "home", 4);

        let mut alloc = HostAllocator::new(&host, 0);
        let got = alloc.allocate(&policy, 9, &[]);

        assert_eq!(got.demand, 9);
        assert_eq!(got.desired, 4, "max_capacity beats reported demand");
        assert_eq!(got.to_start, 2, "host_capacity beats max_capacity");
        assert_eq!(got.limiting_factor, LimitingFactor::HostCapacity);
    }

    #[test]
    fn an_idle_host_with_no_demand_starts_no_runners() {
        // "No idle runners when unused" (`02-target-architecture.md`,
        // traceability table). The whole allocator must return zero.
        let host = host(8);
        let policies = [active_policy(1, "home", 4), active_policy(2, "home", 4)];
        let mut alloc = HostAllocator::new(&host, 0);
        for policy in &policies {
            let got = alloc.allocate(policy, 0, &[]);
            assert_eq!(got.to_start, 0);
            assert_eq!(got.desired, 0);
        }
        assert_eq!(alloc.active_total(), 0);
        assert_eq!(alloc.headroom(), 8);
    }
}
