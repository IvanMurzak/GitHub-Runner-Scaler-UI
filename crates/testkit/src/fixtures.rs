// owner: b1-domain-core

//! Deterministic builders for hosts, policies, attempts, and queued jobs.
//!
//! Groups C, E, F, and G all need the same three or four objects, and they need
//! them to be *the same* three or four objects: a capacity test in `e1` and a
//! snapshot test in `g2` that disagree about what a default policy looks like
//! will disagree about what a bug looks like too.
//!
//! Two properties are deliberate:
//!
//! * **Every identifier is fixed, not random.** [`uuid::Uuid::new_v4`] would make
//!   a snapshot test (`g2`) unrepeatable and a failure message unreadable. The
//!   ids here come from small constants.
//! * **Every timestamp is fixed.** `created_at` comes from
//!   [`crate::clock::DEFAULT_EPOCH_SECS`], not from the system clock, so a
//!   fixture built today and one built next year are equal.
//!
//! The builders return real domain types built through the real constructors, so
//! a fixture cannot express a state the domain forbids. That is the point: a
//! fixture that could build an autoscale policy with no ceiling would let a
//! downstream test pass against a value production can never see.

use std::num::NonZeroU16;

use runner_manager_domain::attempt::{
    AttemptOutcome, AttemptState, FailureReason, PersistedAttempt, RunnerAttempt,
};
use runner_manager_domain::model::{
    Arch, AttemptId, CachePolicy, Host, HostId, HostLabel, Label, Os, PolicyId, RefreshInterval,
    ScaleTarget, StartMode, Timestamp,
};
use runner_manager_domain::policy::{PolicyMode, RoutingLabels, RunsOn, ScalePolicy};
use runner_manager_domain::workspace::AttemptWorkspace;

use crate::clock::{DEFAULT_EPOCH_SECS, timestamp};

/// The host every fixture belongs to unless told otherwise.
pub const HOST_ID: HostId = HostId::from_u128(0x0000_0001);
/// A second host, for the ownership-rejection and two-host contention tests.
pub const OTHER_HOST_ID: HostId = HostId::from_u128(0x0000_0002);
/// The default policy id.
pub const POLICY_ID: PolicyId = PolicyId::from_u128(0x0000_0010);
/// A second policy id, for the host-ceiling tests that need two policies.
pub const OTHER_POLICY_ID: PolicyId = PolicyId::from_u128(0x0000_0011);
/// The default attempt id.
pub const ATTEMPT_ID: AttemptId = AttemptId::from_u128(0x0000_0100);

/// The instant every fixture is created at.
#[must_use]
pub fn created_at() -> Timestamp {
    timestamp(DEFAULT_EPOCH_SECS)
}

// ---------------------------------------------------------------------------
// Host
// ---------------------------------------------------------------------------

/// Builds a [`Host`]. Defaults to `home-pc`, Windows x64, capacity 2.
#[derive(Debug, Clone)]
pub struct HostBuilder {
    id: HostId,
    display_name: String,
    os: Os,
    architecture: Arch,
    host_capacity: u16,
    service_start_mode: StartMode,
    refresh_interval: RefreshInterval,
    created_at: Timestamp,
}

impl Default for HostBuilder {
    fn default() -> Self {
        Self {
            id: HOST_ID,
            display_name: "home-pc".to_string(),
            os: Os::Windows,
            architecture: Arch::X64,
            host_capacity: 2,
            service_start_mode: StartMode::Boot,
            refresh_interval: RefreshInterval::default(),
            created_at: created_at(),
        }
    }
}

/// A [`HostBuilder`] with the defaults.
#[must_use]
pub fn host() -> HostBuilder {
    HostBuilder::default()
}

impl HostBuilder {
    #[must_use]
    pub fn id(mut self, id: HostId) -> Self {
        self.id = id;
        self
    }

    #[must_use]
    pub fn display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = name.into();
        self
    }

    #[must_use]
    pub fn os(mut self, os: Os) -> Self {
        self.os = os;
        self
    }

    #[must_use]
    pub fn architecture(mut self, architecture: Arch) -> Self {
        self.architecture = architecture;
        self
    }

    /// # Panics
    /// On zero, which [`Host`] cannot represent.
    #[must_use]
    pub fn capacity(mut self, capacity: u16) -> Self {
        assert!(
            capacity > 0,
            "host_capacity is NonZeroU16; use a disabled policy to express 'no runners'"
        );
        self.host_capacity = capacity;
        self
    }

    #[must_use]
    pub fn start_mode(mut self, mode: StartMode) -> Self {
        self.service_start_mode = mode;
        self
    }

    /// # Panics
    /// Below the documented 30-second floor.
    #[must_use]
    pub fn refresh_secs(mut self, secs: u16) -> Self {
        self.refresh_interval =
            RefreshInterval::from_secs(secs).expect("fixture refresh interval below the floor");
        self
    }

    #[must_use]
    pub fn created_at(mut self, at: Timestamp) -> Self {
        self.created_at = at;
        self
    }

    /// # Panics
    /// On a blank display name.
    #[must_use]
    pub fn build(self) -> Host {
        let mut host = Host::new(
            self.id,
            &self.display_name,
            self.os,
            self.architecture,
            NonZeroU16::new(self.host_capacity).expect("checked in `capacity`"),
            self.created_at,
        )
        .expect("fixture host is valid");
        host.service_start_mode = self.service_start_mode;
        host.refresh_interval = self.refresh_interval;
        host
    }
}

// ---------------------------------------------------------------------------
// Routing labels
// ---------------------------------------------------------------------------

/// The derived routing label set for a host label on Windows x64:
/// `rm-<host>-win-x64`.
///
/// # Panics
/// On a host label the domain rejects.
#[must_use]
pub fn routing_labels(host_label: &str) -> RoutingLabels {
    RoutingLabels::derive(
        &HostLabel::new(host_label).expect("fixture host label is valid"),
        Os::Windows,
        Arch::X64,
    )
}

/// A [`Label`].
///
/// # Panics
/// On a label the domain rejects.
#[must_use]
pub fn label(raw: &str) -> Label {
    Label::new(raw).expect("fixture label is valid")
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// Builds a [`ScalePolicy`].
///
/// Defaults to an autoscale repository policy for `o/r` on [`HOST_ID`], routing
/// label `rm-home-win-x64`, `max_capacity` 2, left `pending` and not enabled —
/// which is what `repo add` actually produces (D20). Call
/// [`PolicyBuilder::active`] for a policy that reconciliation will act on.
#[derive(Debug, Clone)]
pub struct PolicyBuilder {
    id: PolicyId,
    target: ScaleTarget,
    installation_id: u64,
    host_id: HostId,
    mode: PolicyMode,
    cache_policy: CachePolicy,
    activate: bool,
}

impl Default for PolicyBuilder {
    fn default() -> Self {
        Self {
            id: POLICY_ID,
            target: ScaleTarget::repository("o/r").expect("fixture target is valid"),
            installation_id: 1,
            host_id: HOST_ID,
            mode: PolicyMode::autoscale(
                routing_labels("home"),
                0,
                NonZeroU16::new(2).expect("non-zero"),
            )
            .expect("fixture mode is valid"),
            cache_policy: CachePolicy::default(),
            activate: false,
        }
    }
}

/// A [`PolicyBuilder`] with the defaults.
#[must_use]
pub fn policy() -> PolicyBuilder {
    PolicyBuilder::default()
}

/// An `active`, enabled autoscale policy — the shape most `e1` tests want.
#[must_use]
pub fn active_policy() -> ScalePolicy {
    policy().active().build()
}

/// A monitor-only policy (D19): no routing label, no ceiling, starts nothing.
#[must_use]
pub fn monitor_only_policy() -> ScalePolicy {
    policy().monitor_only().active().build()
}

impl PolicyBuilder {
    #[must_use]
    pub fn id(mut self, id: PolicyId) -> Self {
        self.id = id;
        self
    }

    /// # Panics
    /// On a malformed `OWNER/REPO`.
    #[must_use]
    pub fn repository(mut self, owner_repo: &str) -> Self {
        self.target = ScaleTarget::repository(owner_repo).expect("fixture repository is valid");
        self
    }

    /// # Panics
    /// On a malformed organization login.
    #[must_use]
    pub fn organization(mut self, org: &str) -> Self {
        self.target = ScaleTarget::organization(org).expect("fixture organization is valid");
        self
    }

    #[must_use]
    pub fn target(mut self, target: ScaleTarget) -> Self {
        self.target = target;
        self
    }

    #[must_use]
    pub fn installation_id(mut self, id: u64) -> Self {
        self.installation_id = id;
        self
    }

    #[must_use]
    pub fn host(mut self, host_id: HostId) -> Self {
        self.host_id = host_id;
        self
    }

    #[must_use]
    pub fn monitor_only(mut self) -> Self {
        self.mode = PolicyMode::monitor_only();
        self
    }

    /// An autoscale mode with a derived label for `host_label` and this ceiling.
    ///
    /// # Panics
    /// On a zero ceiling or an invalid host label.
    #[must_use]
    pub fn autoscale(mut self, host_label: &str, max_capacity: u16) -> Self {
        self.mode = PolicyMode::autoscale(
            routing_labels(host_label),
            0,
            NonZeroU16::new(max_capacity).expect("max_capacity is NonZeroU16"),
        )
        .expect("fixture mode is valid");
        self
    }

    /// Change only the ceiling, keeping the current routing labels.
    ///
    /// # Panics
    /// On a zero ceiling, or on a monitor-only policy, which has no ceiling.
    #[must_use]
    pub fn max_capacity(mut self, max_capacity: u16) -> Self {
        let labels = self
            .mode
            .routing_labels()
            .expect("max_capacity on a monitor-only policy; call `autoscale` first")
            .clone();
        self.mode = PolicyMode::autoscale(
            labels,
            self.mode.min_capacity(),
            NonZeroU16::new(max_capacity).expect("max_capacity is NonZeroU16"),
        )
        .expect("fixture mode is valid");
        self
    }

    /// Set the routing labels outright, for a test that needs an unusual set.
    ///
    /// # Panics
    /// On a monitor-only policy, which owns none.
    #[must_use]
    pub fn routing_labels(mut self, labels: RoutingLabels) -> Self {
        let max = self
            .mode
            .max_capacity()
            .expect("routing_labels on a monitor-only policy; call `autoscale` first");
        self.mode = PolicyMode::autoscale(labels, self.mode.min_capacity(), max)
            .expect("fixture mode is valid");
        self
    }

    #[must_use]
    pub fn cache_policy(mut self, cache_policy: CachePolicy) -> Self {
        self.cache_policy = cache_policy;
        self
    }

    /// Move the built policy to `active` and set `enabled`, as `set-scale
    /// --enabled true` does.
    #[must_use]
    pub fn active(mut self) -> Self {
        self.activate = true;
        self
    }

    /// # Panics
    /// If activation is impossible, which cannot happen for a freshly built
    /// `pending` policy.
    #[must_use]
    pub fn build(self) -> ScalePolicy {
        let mut policy = ScalePolicy::new(
            self.id,
            self.target,
            self.installation_id,
            self.host_id,
            self.mode,
            self.cache_policy,
        );
        if self.activate {
            policy.activate().expect("a new policy is pending");
        }
        policy
    }
}

// ---------------------------------------------------------------------------
// Attempt
// ---------------------------------------------------------------------------

/// Builds a [`RunnerAttempt`] in any state, with a consistent outcome.
///
/// A terminal state needs an outcome and a non-terminal one must not have any;
/// [`AttemptBuilder::build`] supplies a matching default rather than letting a
/// caller construct a row the domain would reject on load.
#[derive(Debug, Clone)]
pub struct AttemptBuilder {
    id: AttemptId,
    policy_id: PolicyId,
    github_runner_id: Option<u64>,
    state: AttemptState,
    outcome: Option<AttemptOutcome>,
    process_id: Option<u32>,
    runtime_path: String,
    workspace: AttemptWorkspace,
    created_at: Timestamp,
    entered_state_at: Option<Timestamp>,
}

impl Default for AttemptBuilder {
    fn default() -> Self {
        Self {
            id: ATTEMPT_ID,
            policy_id: POLICY_ID,
            github_runner_id: None,
            state: AttemptState::Allocated,
            outcome: None,
            process_id: None,
            runtime_path: "runtime/00000000-0000-0000-0000-000000000010/\
                           00000000-0000-0000-0000-000000000100"
                .to_string(),
            // D3: the fixture default is the product default. A test about a
            // persistent slot has to say so with `persistent_slot`.
            workspace: AttemptWorkspace::Ephemeral,
            created_at: created_at(),
            entered_state_at: None,
        }
    }
}

/// An [`AttemptBuilder`] with the defaults.
#[must_use]
pub fn attempt() -> AttemptBuilder {
    AttemptBuilder::default()
}

/// The surplus case: a runner that registered, got no job, and exited on its
/// idle timeout (`03-control-flows.md`, flow 2.7). Terminal, cleaned like any
/// other, and **not** a failure.
#[must_use]
pub fn idle_exit_attempt() -> RunnerAttempt {
    attempt()
        .state(AttemptState::Finished)
        .outcome(AttemptOutcome::ExitedIdleWithoutWork)
        .build()
}

/// A failed attempt, for the fixture where `g2` must render the two apart.
#[must_use]
pub fn failed_attempt() -> RunnerAttempt {
    attempt()
        .state(AttemptState::Failed)
        .outcome(AttemptOutcome::failed(FailureReason::ProcessStartFailed))
        .build()
}

/// An attempt executing its one job.
#[must_use]
pub fn busy_attempt() -> RunnerAttempt {
    attempt()
        .state(AttemptState::Busy)
        .github_runner_id(73)
        .process_id(4242)
        .build()
}

impl AttemptBuilder {
    #[must_use]
    pub fn id(mut self, id: AttemptId) -> Self {
        self.id = id;
        self
    }

    #[must_use]
    pub fn policy_id(mut self, policy_id: PolicyId) -> Self {
        self.policy_id = policy_id;
        self
    }

    #[must_use]
    pub fn state(mut self, state: AttemptState) -> Self {
        self.state = state;
        self
    }

    #[must_use]
    pub fn outcome(mut self, outcome: AttemptOutcome) -> Self {
        self.outcome = Some(outcome);
        self
    }

    #[must_use]
    pub fn github_runner_id(mut self, id: u64) -> Self {
        self.github_runner_id = Some(id);
        self
    }

    #[must_use]
    pub fn process_id(mut self, pid: u32) -> Self {
        self.process_id = Some(pid);
        self
    }

    #[must_use]
    pub fn runtime_path(mut self, path: impl Into<String>) -> Self {
        self.runtime_path = path.into();
        self
    }

    /// Lease persistent slot `slot`, as `c2`'s allocator does.
    ///
    /// # Panics
    /// If `slot` is zero; there is no `s0`, and a fixture that could name one
    /// would be building state the domain refuses.
    #[must_use]
    pub fn persistent_slot(mut self, slot: u16) -> Self {
        self.workspace = AttemptWorkspace::persistent_slot(
            NonZeroU16::new(slot).expect("a persistent slot is positive"),
        );
        self
    }

    #[must_use]
    pub fn created_at(mut self, at: Timestamp) -> Self {
        self.created_at = at;
        self
    }

    /// When the attempt entered its current state — the instant every recovery
    /// timeout is measured from.
    #[must_use]
    pub fn entered_state_at(mut self, at: Timestamp) -> Self {
        self.entered_state_at = Some(at);
        self
    }

    /// # Panics
    /// If an explicitly supplied outcome contradicts the state, which is the
    /// fixture equivalent of a corrupted journal row.
    #[must_use]
    pub fn build(self) -> RunnerAttempt {
        let outcome = match (self.outcome, self.state.is_terminal()) {
            (given @ Some(_), _) => given,
            (None, true) => Some(default_outcome_for(self.state)),
            (None, false) => None,
        };
        let entered_state_at = self.entered_state_at.unwrap_or(self.created_at);
        let terminal_at = self.state.is_terminal().then_some(entered_state_at);

        RunnerAttempt::from_persisted(PersistedAttempt {
            id: self.id,
            policy_id: self.policy_id,
            github_runner_id: self.github_runner_id,
            state: self.state,
            outcome,
            process_id: self.process_id,
            runtime_path: self.runtime_path.into(),
            workspace_kind: self.workspace.kind(),
            workspace_slot: self.workspace.slot_number(),
            created_at: self.created_at,
            terminal_at,
            last_state_change_at: entered_state_at,
        })
        .expect("fixture attempt is a state/outcome pair the domain accepts")
    }
}

fn default_outcome_for(state: AttemptState) -> AttemptOutcome {
    match state {
        AttemptState::Failed => AttemptOutcome::failed(FailureReason::ProcessExitedUnexpectedly),
        AttemptState::Orphaned => AttemptOutcome::Orphaned,
        // `finished` and `cleaned`. `CompletedJob` is the unremarkable default;
        // a test about the surplus path should say so with `idle_exit_attempt`.
        _ => AttemptOutcome::CompletedJob,
    }
}

// ---------------------------------------------------------------------------
// Queued jobs
// ---------------------------------------------------------------------------

/// One queued job's `runs-on`, in the array form the jobs API returns.
#[must_use]
pub fn queued_job(labels: &[&str]) -> RunsOn {
    RunsOn::from_job_labels(labels.iter().copied())
}

/// `n` copies of one queued job — a demand signal of `n` for a policy carrying
/// those labels.
#[must_use]
pub fn queued_jobs(labels: &[&str], n: usize) -> Vec<RunsOn> {
    vec![queued_job(labels); n]
}

/// A `runs-on` this process cannot resolve, for the case that must be reported
/// rather than counted or dropped.
#[must_use]
pub fn unresolvable_job() -> RunsOn {
    RunsOn::Single("${{ matrix.runner }}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures_are_deterministic_across_calls() {
        // A snapshot test in `g2` depends on this exactly.
        assert_eq!(host().build(), host().build());
        assert_eq!(active_policy(), active_policy());
        assert_eq!(attempt().build(), attempt().build());
        assert_eq!(created_at(), created_at());
    }

    #[test]
    fn the_default_policy_is_what_repo_add_actually_produces() {
        // D20: `add` creates the policy in `pending` and never enables scaling.
        let policy = policy().build();
        assert!(!policy.enabled());
        assert_eq!(
            policy.routing_labels().unwrap().host_label().as_str(),
            "rm-home-win-x64"
        );
        assert_eq!(policy.max_capacity().unwrap().get(), 2);

        // And `active()` is the explicit `set-scale`.
        assert!(active_policy().may_start_runners());
    }

    #[test]
    fn a_monitor_only_fixture_owns_nothing() {
        let policy = monitor_only_policy();
        assert!(policy.routing_labels().is_none());
        assert!(policy.max_capacity().is_none());
        assert!(!policy.may_start_runners());
    }

    #[test]
    fn attempt_fixtures_carry_an_outcome_consistent_with_their_state() {
        for state in AttemptState::ALL {
            let built = attempt().state(state).build();
            assert_eq!(built.state(), state);
            assert_eq!(
                built.outcome().is_some(),
                state.is_terminal(),
                "{state}: a terminal attempt must carry an outcome and a \
                 non-terminal one must not"
            );
        }
    }

    #[test]
    fn the_idle_exit_and_failed_fixtures_are_distinguishable() {
        // `g2` needs a fixture containing both, and needs them to differ in the
        // journal rather than only on screen.
        let idle = idle_exit_attempt();
        let failed = failed_attempt();

        assert!(idle.outcome().unwrap().is_idle_exit());
        assert!(!idle.outcome().unwrap().is_failure());
        assert!(failed.outcome().unwrap().is_failure());
        assert_ne!(idle.outcome(), failed.outcome());
    }

    #[test]
    fn queued_job_fixtures_produce_the_demand_a_policy_expects() {
        let policy = active_policy();
        let jobs = queued_jobs(&["rm-home-win-x64"], 3);
        assert_eq!(policy.tally(&jobs).demand(), 3);

        let mixed = vec![
            queued_job(&["rm-home-win-x64"]),
            queued_job(&["ubuntu-latest"]),
            unresolvable_job(),
        ];
        let tally = policy.tally(&mixed);
        assert_eq!(tally.demand(), 1);
        assert_eq!(tally.not_matched, 1);
        assert_eq!(tally.unresolvable.len(), 1);
    }
}
