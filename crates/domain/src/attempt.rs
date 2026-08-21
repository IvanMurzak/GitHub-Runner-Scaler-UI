// owner: b1-domain-core

//! One runner attempt: its lifecycle, its outcome, who may act on it, and what
//! to do about it after a restart.
//!
//! Two things here are easy to get subtly wrong, so they are stated before the
//! code:
//!
//! **The idle exit is a normal outcome, not a failure.** Because there is no
//! `AcquireJobs` equivalent on the REST path, nothing reserves a queued job for
//! this host. A runner may start, find that another host took the work, and exit
//! on its idle timeout (`03-control-flows.md`, flow 2.7). That attempt is
//! terminal and is cleaned like any other, but [`AttemptOutcome`] records *which*
//! terminal thing happened, because `g2` must render it distinctly from a
//! failure and can only do so if the domain wrote the distinction down. Showing a
//! normal surplus exit as an error sends an operator hunting a fault that does
//! not exist.
//!
//! **A `busy` attempt is never cleaned to free capacity.** Scale-down reclaims a
//! slot when an attempt reaches a terminal state and at no other time
//! (`04-subsystem-contracts.md`: "`busy` cannot transition to cleanup due to a
//! scale-down request"). [`RunnerAttempt::clean`] refuses it by name rather than
//! by a generic transition error, so the refusal is legible in a log.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::model::{AttemptId, Clock, Elapsed, HostId, PolicyId, Timestamp};
use crate::policy::ScalePolicy;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttemptError {
    #[error("{to} is not a legal transition from {from}")]
    IllegalTransition {
        from: AttemptState,
        to: AttemptState,
    },

    #[error(
        "a busy attempt must not be cleaned; capacity is reclaimed only when an \
         attempt reaches a terminal state, never by stopping a runner that is \
         executing a job"
    )]
    BusyCannotBeCleaned,

    #[error("the outcome {outcome:?} cannot be reached from {from}")]
    OutcomeUnreachable {
        from: AttemptState,
        outcome: AttemptOutcome,
    },

    #[error("{state} is a terminal state and requires an outcome, but none was recorded")]
    TerminalWithoutOutcome { state: AttemptState },

    #[error("{state} is not terminal, so it must not carry the outcome {outcome:?}")]
    NonTerminalWithOutcome {
        state: AttemptState,
        outcome: AttemptOutcome,
    },

    #[error("the recorded outcome {outcome:?} does not belong to the recorded state {state}")]
    OutcomeStateMismatch {
        state: AttemptState,
        outcome: AttemptOutcome,
    },

    #[error("{state} is a terminal state and requires a terminal_at, but none was recorded")]
    TerminalWithoutTimestamp { state: AttemptState },

    #[error("{state} is not terminal, so it must not carry a terminal_at")]
    NonTerminalWithTimestamp { state: AttemptState },

    #[error(
        "{state} carries {field} at {found}, which is before its created_at of \
         {created_at}; an attempt cannot have changed state or concluded before \
         it was allocated"
    )]
    TimestampsOutOfOrder {
        state: AttemptState,
        /// Which of the two orderable timestamps is out of order.
        field: &'static str,
        created_at: Timestamp,
        found: Timestamp,
    },
}

/// Ownership rule 2: "A host agent may act only on attempts persisted under its
/// `host_id`."
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OwnershipError {
    #[error(
        "attempt {attempt} belongs to policy {attempt_policy}, but was checked \
         against policy {policy}"
    )]
    PolicyMismatch {
        attempt: AttemptId,
        attempt_policy: PolicyId,
        policy: PolicyId,
    },

    #[error(
        "policy {policy} belongs to host {owner}; this agent runs on host \
         {agent} and must not act on its attempts"
    )]
    ForeignHost {
        policy: PolicyId,
        owner: HostId,
        agent: HostId,
    },
}

// ---------------------------------------------------------------------------
// AttemptState
// ---------------------------------------------------------------------------

/// The runner-attempt lifecycle, exactly as `04-subsystem-contracts.md` draws
/// it after its 2026-08-21 amendment:
///
/// ```text
/// allocated -> jit_received -> starting -> idle | busy
/// idle -> busy
/// allocated | jit_received | starting -> failed | orphaned
/// idle | busy -> finished | failed | orphaned
/// finished | failed | orphaned -> cleaned
/// ```
///
/// `idle` means the runner process is registered and awaiting its single job
/// assignment. It is short-lived and is **not** an idle persistent runner — this
/// product has none, by D7.
///
/// **Every transition outside that diagram is rejected**, which `b1`'s
/// Definition of Done requires. `cleaned` is absorbing, which is correct and
/// intended.
///
/// **The last two edge sets were added by amendment, and the reasons matter to
/// anyone reading this state machine.** `b1` first implemented the original
/// diagram faithfully and surfaced its gaps as an explicit
/// `NoLegalTransition` decision rather than inventing edges; the amendment
/// closed them at the design level, and that decision value is gone with them:
///
/// * **`idle -> busy`.** `e3`'s Scope step 4 moves an attempt through
///   `jit_received`, `starting`, `idle`, `busy` *in sequence*, and the
///   definition of `idle` above describes a state that by construction precedes
///   a job. Without this edge a runner observed idle and then assigned a job had
///   nowhere legal to go.
/// * **Terminal edges out of the three pre-registration states.** An attempt
///   counts against host capacity for exactly as long as it is non-terminal
///   ([`Self::counts_against_capacity`]), so an attempt that could not reach a
///   terminal state **held a host capacity slot permanently**: two failed JIT
///   requests on a `host_capacity: 2` host wedged that host into starting zero
///   runners, with no error state and no cleanup path. `orphaned` is included
///   for the restart case, where a pre-registration attempt is found after the
///   agent restarts.
///
/// Those edges are also what make six of the eight [`FailureReason`] variants
/// reachable at all — `JitRequestFailed`, `JitExpired`,
/// `RunnerPackageUnverified`, `RunnerVersionRejected`, `ProcessStartFailed` and
/// `RegistrationTimedOut` each occur at a pre-registration state.
/// `03-control-flows.md` flow 2 names the first five as conditions the agent
/// must record; `RegistrationTimedOut` is named by no document and is this
/// crate's own, added because [`recovery_decision`] needs to say "alive, past
/// its deadline, still unregistered" without calling it a crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptState {
    Allocated,
    JitReceived,
    Starting,
    Idle,
    Busy,
    Finished,
    Failed,
    Orphaned,
    Cleaned,
}

impl AttemptState {
    pub const ALL: [AttemptState; 9] = [
        AttemptState::Allocated,
        AttemptState::JitReceived,
        AttemptState::Starting,
        AttemptState::Idle,
        AttemptState::Busy,
        AttemptState::Finished,
        AttemptState::Failed,
        AttemptState::Orphaned,
        AttemptState::Cleaned,
    ];

    /// The complete legal transition list. A self-transition is not in it.
    pub const LEGAL: &'static [(AttemptState, AttemptState)] = &[
        // `allocated -> jit_received -> starting -> idle | busy`.
        (AttemptState::Allocated, AttemptState::JitReceived),
        (AttemptState::JitReceived, AttemptState::Starting),
        (AttemptState::Starting, AttemptState::Idle),
        (AttemptState::Starting, AttemptState::Busy),
        // `idle -> busy`.
        (AttemptState::Idle, AttemptState::Busy),
        // `allocated | jit_received | starting -> failed | orphaned`.
        (AttemptState::Allocated, AttemptState::Failed),
        (AttemptState::Allocated, AttemptState::Orphaned),
        (AttemptState::JitReceived, AttemptState::Failed),
        (AttemptState::JitReceived, AttemptState::Orphaned),
        (AttemptState::Starting, AttemptState::Failed),
        (AttemptState::Starting, AttemptState::Orphaned),
        // `idle | busy -> finished | failed | orphaned`.
        (AttemptState::Idle, AttemptState::Finished),
        (AttemptState::Idle, AttemptState::Failed),
        (AttemptState::Idle, AttemptState::Orphaned),
        (AttemptState::Busy, AttemptState::Finished),
        (AttemptState::Busy, AttemptState::Failed),
        (AttemptState::Busy, AttemptState::Orphaned),
        // `finished | failed | orphaned -> cleaned`.
        (AttemptState::Finished, AttemptState::Cleaned),
        (AttemptState::Failed, AttemptState::Cleaned),
        (AttemptState::Orphaned, AttemptState::Cleaned),
    ];

    /// The five states an attempt can still be concluded from: every
    /// non-terminal state. After the amendment this is exactly
    /// "not [`Self::is_terminal`]", which is what closed the permanently-held
    /// capacity slot — but it is written out rather than derived, because the
    /// two are only equal while the diagram gives every live state a terminal
    /// edge, and that equality is a property worth failing loudly on.
    pub const CONCLUDABLE_FROM: &'static [AttemptState] = &[
        AttemptState::Allocated,
        AttemptState::JitReceived,
        AttemptState::Starting,
        AttemptState::Idle,
        AttemptState::Busy,
    ];

    #[must_use]
    pub fn can_transition_to(self, next: AttemptState) -> bool {
        Self::LEGAL.contains(&(self, next))
    }

    /// Terminal states, at which capacity is reclaimed.
    ///
    /// `e1`: "capacity is reclaimed only when an attempt reaches a terminal
    /// state." `cleaned` is included because it follows a terminal state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            AttemptState::Finished
                | AttemptState::Failed
                | AttemptState::Orphaned
                | AttemptState::Cleaned
        )
    }

    /// Whether this attempt still occupies one of the host's capacity slots.
    ///
    /// This is the term the reconciliation formula subtracts, and getting it
    /// wrong is silent: counting a terminal attempt starves the host, and failing
    /// to count a `starting` one starts a second runner for a job already being
    /// served.
    #[must_use]
    pub const fn counts_against_capacity(self) -> bool {
        !self.is_terminal()
    }

    /// The three terminal states that require an outcome before `cleaned`.
    #[must_use]
    pub const fn is_concluded(self) -> bool {
        matches!(
            self,
            AttemptState::Finished | AttemptState::Failed | AttemptState::Orphaned
        )
    }
}

impl fmt::Display for AttemptState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AttemptState::Allocated => "allocated",
            AttemptState::JitReceived => "jit_received",
            AttemptState::Starting => "starting",
            AttemptState::Idle => "idle",
            AttemptState::Busy => "busy",
            AttemptState::Finished => "finished",
            AttemptState::Failed => "failed",
            AttemptState::Orphaned => "orphaned",
            AttemptState::Cleaned => "cleaned",
        })
    }
}

// ---------------------------------------------------------------------------
// Outcome
// ---------------------------------------------------------------------------

/// Why an attempt failed.
///
/// `Other` exists so `e3` is not blocked by a reason this task did not
/// anticipate; `crates/domain/src/attempt.rs` belongs to `b1` and `e3` cannot
/// extend this enum itself.
///
/// **Nothing that reaches this type may contain a credential.** It is written to
/// the journal by `b2` and rendered by `g2`, and `07-security.md`'s log scan runs
/// over both. A JIT blob, an `Authorization` header, or a token in an `Other`
/// string would defeat that gate from inside the domain, where the redacting log
/// sink (`d1`) never gets a chance to see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    /// `generate-jitconfig` did not return a configuration.
    JitRequestFailed,
    /// The configuration was never claimed and expired (flow 4.4).
    JitExpired,
    /// The runner package's published checksum was absent or did not match
    /// (`05-infrastructure.md`: the agent fails closed).
    RunnerPackageUnverified,
    /// GitHub rejects runners more than 30 days behind the latest release
    /// (`01-current-architecture.md`, edge case 7). Terminal and
    /// operator-actionable, never retried.
    RunnerVersionRejected,
    /// The child process could not be spawned.
    ProcessStartFailed,
    /// The child process exited before it could do its one job.
    ///
    /// **Only for a process that is actually gone.** A runner still running past
    /// its startup deadline is [`Self::RegistrationTimedOut`], not this: `g2`
    /// renders these strings to an operator, and telling one that a process
    /// "exited unexpectedly" while it is visible in Task Manager spends the
    /// credibility of every other message this product prints.
    ProcessExitedUnexpectedly,
    /// The runner process is up but never registered with GitHub inside its
    /// startup window.
    ///
    /// Split from [`Self::ProcessExitedUnexpectedly`] because it is accurate and
    /// because it points an operator somewhere else entirely. A process that
    /// exited is a crash to investigate — logs, exit code, a corrupt runner
    /// package. A process that is alive and unregistered has almost always
    /// failed to *reach* GitHub: a proxy, a firewall, a DNS answer, an expired
    /// or wrong-scoped configuration. Those are configuration and networking
    /// fixes, and an operator sent to the wrong one of the two loses the time
    /// this distinction exists to save.
    RegistrationTimedOut,
    /// Anything else. Must carry no credential.
    Other(String),
}

impl FailureReason {
    /// One value of every variant, the counterpart of [`AttemptState::ALL`].
    ///
    /// `Other`'s detail is empty because what a caller enumerates is the
    /// *variant*; no consumer should read the string out of this constant.
    ///
    /// **This list is hand-written and can go stale on its own.** What stops it
    /// is not the array length — a length written as `8` next to eight elements
    /// asserts nothing — but the exhaustive, wildcard-free `match` in
    /// `tests::all_failure_reasons_are_reachable_from_the_state_that_produces_them`,
    /// which stops compiling the moment a variant is added and so puts the
    /// author who adds one in front of this constant.
    pub const ALL: [FailureReason; 8] = [
        FailureReason::JitRequestFailed,
        FailureReason::JitExpired,
        FailureReason::RunnerPackageUnverified,
        FailureReason::RunnerVersionRejected,
        FailureReason::ProcessStartFailed,
        FailureReason::ProcessExitedUnexpectedly,
        FailureReason::RegistrationTimedOut,
        FailureReason::Other(String::new()),
    ];
}

impl fmt::Display for FailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FailureReason::JitRequestFailed => f.write_str("the JIT configuration request failed"),
            FailureReason::JitExpired => f.write_str("the JIT configuration expired unclaimed"),
            FailureReason::RunnerPackageUnverified => {
                f.write_str("the runner package could not be verified")
            }
            FailureReason::RunnerVersionRejected => {
                f.write_str("GitHub rejected the runner version")
            }
            FailureReason::ProcessStartFailed => f.write_str("the runner process failed to start"),
            FailureReason::ProcessExitedUnexpectedly => {
                f.write_str("the runner process exited unexpectedly")
            }
            FailureReason::RegistrationTimedOut => f.write_str(
                "the runner process is running but did not register with GitHub \
                 before its startup deadline",
            ),
            FailureReason::Other(detail) => write!(f, "{detail}"),
        }
    }
}

/// What terminally happened to an attempt.
///
/// The state and the outcome are not two independent fields that a caller has to
/// keep consistent: [`AttemptOutcome::terminal_state`] derives the state from the
/// outcome, and [`RunnerAttempt::conclude`] is the only way to set either. A
/// `failed` attempt whose outcome says it ran a job is therefore not a bug this
/// code can have.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum AttemptOutcome {
    /// The runner accepted its one job and the job ended. This says the *runner*
    /// finished, never that the workflow succeeded — GitHub remains the source of
    /// truth for workflow outcome (`03-control-flows.md`, flow 2, Failure).
    CompletedJob,
    /// The surplus case. The runner registered, no job arrived, and it exited on
    /// its idle timeout (flow 2.7). Normal, bounded, and **not** a failure.
    ExitedIdleWithoutWork,
    /// The attempt failed.
    Failed { reason: FailureReason },
    /// Supervision was lost: the process is gone and the attempt could not be
    /// reconciled with GitHub (`e3`, restart recovery).
    Orphaned,
}

impl AttemptOutcome {
    #[must_use]
    pub fn failed(reason: FailureReason) -> Self {
        Self::Failed { reason }
    }

    /// The one terminal state this outcome corresponds to.
    #[must_use]
    pub const fn terminal_state(&self) -> AttemptState {
        match self {
            AttemptOutcome::CompletedJob | AttemptOutcome::ExitedIdleWithoutWork => {
                AttemptState::Finished
            }
            AttemptOutcome::Failed { .. } => AttemptState::Failed,
            AttemptOutcome::Orphaned => AttemptState::Orphaned,
        }
    }

    /// True for the outcomes an operator should be told to look at.
    ///
    /// `g2` renders this differently from [`Self::is_idle_exit`], and `e1`'s
    /// Definition of Done requires that a surplus attempt "is not reported as a
    /// failure".
    #[must_use]
    pub const fn is_failure(&self) -> bool {
        matches!(
            self,
            AttemptOutcome::Failed { .. } | AttemptOutcome::Orphaned
        )
    }

    /// True only for the surplus case.
    #[must_use]
    pub const fn is_idle_exit(&self) -> bool {
        matches!(self, AttemptOutcome::ExitedIdleWithoutWork)
    }

    /// True only when this runner actually took a job.
    #[must_use]
    pub const fn ran_a_job(&self) -> bool {
        matches!(self, AttemptOutcome::CompletedJob)
    }

    /// The states an attempt must be in for this outcome to be reachable.
    ///
    /// Two of the four outcomes are narrower than the diagram's terminal edges,
    /// and deliberately so: `finished` is reachable from both `idle` and `busy`,
    /// but only one of them can have produced each of the two outcomes that lead
    /// there. Failure and orphaning are as wide as the diagram — every live
    /// state has a `-> failed | orphaned` edge since the amendment, and
    /// narrowing them per [`FailureReason`] here would invent product rules no
    /// document states.
    const fn required_from(&self) -> &'static [AttemptState] {
        match self {
            // Only a runner that was assigned a job can have run one.
            AttemptOutcome::CompletedJob => &[AttemptState::Busy],
            // Only a runner that was registered and waiting can have exited idle.
            AttemptOutcome::ExitedIdleWithoutWork => &[AttemptState::Idle],
            AttemptOutcome::Failed { .. } | AttemptOutcome::Orphaned => {
                AttemptState::CONCLUDABLE_FROM
            }
        }
    }
}

impl fmt::Display for AttemptOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttemptOutcome::CompletedJob => f.write_str("ran a job"),
            AttemptOutcome::ExitedIdleWithoutWork => f.write_str("exited idle without work"),
            AttemptOutcome::Failed { reason } => write!(f, "failed: {reason}"),
            AttemptOutcome::Orphaned => f.write_str("orphaned"),
        }
    }
}

// ---------------------------------------------------------------------------
// RunnerAttempt
// ---------------------------------------------------------------------------

/// One ephemeral runner, from directory allocation to cleanup.
///
/// The fields `04-subsystem-contracts.md` names are all here. Two are not in that
/// list and are added deliberately:
///
/// * `outcome`, because `b1`'s Scope requires the attempt to "carry an outcome
///   distinguishing 'ran a job' from 'exited idle without work'".
/// * `last_state_change_at`, because recovery decisions measure elapsed time in
///   the *current* state — an idle timeout runs from entering `idle`, not from
///   `created_at` — and `b1`'s Definition of Done requires those decisions to be
///   testable against a fake clock.
///
/// `b2` persists both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerAttempt {
    pub id: AttemptId,
    pub policy_id: PolicyId,
    github_runner_id: Option<u64>,
    state: AttemptState,
    outcome: Option<AttemptOutcome>,
    process_id: Option<u32>,
    runtime_path: PathBuf,
    pub created_at: Timestamp,
    terminal_at: Option<Timestamp>,
    last_state_change_at: Timestamp,
}

/// Every stored column of one attempt, named rather than positional.
///
/// **Why this is a struct.** [`RunnerAttempt::from_persisted`] took ten
/// positional arguments, and two of them — `created_at` and
/// `last_state_change_at` — are both `Timestamp`. Transposing them type-checked,
/// compiled, and silently reverted `last_state_change_at` to `created_at`, which
/// is precisely the bug that field exists to prevent: every recovery timeout
/// would then have measured from allocation rather than from the current state,
/// so a long-running `busy` attempt would be read as a stuck one. `terminal_at`
/// is a third `Option<Timestamp>` in the same list.
///
/// `b2` maps database columns onto this type. With a struct that mapping is
/// checked by name at compile time; positionally it was checked by nothing.
///
/// **That guarantee covers the Rust side of the mapping and no more.** It is
/// the *field* names that the compiler checks, not the column names they are
/// read from: `PersistedAttempt { created_at: row.get("last_state_change_at")?,
/// … }` compiles exactly as happily as the correct version, and reintroduces the
/// very transposition described above. `b2` still owes a test that loads a row
/// whose columns hold distinguishable values and asserts each landed in the
/// field of the same name; this type does not supply one.
///
/// Construct it with a struct literal so every field is written down at the call
/// site — that is the whole point, and a builder or a `Default` would give the
/// omission back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedAttempt {
    pub id: AttemptId,
    pub policy_id: PolicyId,
    pub github_runner_id: Option<u64>,
    pub state: AttemptState,
    pub outcome: Option<AttemptOutcome>,
    pub process_id: Option<u32>,
    pub runtime_path: PathBuf,
    /// When the runtime directory was allocated. Never moves.
    pub created_at: Timestamp,
    /// Set when, and only when, the attempt concluded.
    pub terminal_at: Option<Timestamp>,
    /// When the attempt entered its **current** state. Recovery timeouts run
    /// from here, not from `created_at`.
    pub last_state_change_at: Timestamp,
}

impl RunnerAttempt {
    /// Every stored column of this attempt, for `b2` to write back.
    ///
    /// The exact inverse of [`Self::from_persisted`], so a round trip through
    /// the journal is expressible without reaching for a field accessor per
    /// column and without this type exposing its private fields for writing.
    #[must_use]
    pub fn to_persisted(&self) -> PersistedAttempt {
        PersistedAttempt {
            id: self.id,
            policy_id: self.policy_id,
            github_runner_id: self.github_runner_id,
            state: self.state,
            outcome: self.outcome.clone(),
            process_id: self.process_id,
            runtime_path: self.runtime_path.clone(),
            created_at: self.created_at,
            terminal_at: self.terminal_at,
            last_state_change_at: self.last_state_change_at,
        }
    }

    /// The first step of `e3`'s per-attempt flow: a runtime directory is
    /// allocated and journalled **before** anything remote happens, so a crash
    /// leaves a recoverable trace rather than an invisible one.
    #[must_use]
    pub fn allocate(
        id: AttemptId,
        policy_id: PolicyId,
        runtime_path: impl Into<PathBuf>,
        now: Timestamp,
    ) -> Self {
        Self {
            id,
            policy_id,
            github_runner_id: None,
            state: AttemptState::Allocated,
            outcome: None,
            process_id: None,
            runtime_path: runtime_path.into(),
            created_at: now,
            terminal_at: None,
            last_state_change_at: now,
        }
    }

    /// Rebuild a journalled attempt.
    ///
    /// # Errors
    /// Any state/outcome/timestamp combination that this crate's own transitions
    /// cannot produce, so a hand-edited journal cannot inject a `failed` attempt
    /// that claims to have run a job, or a `finished` one that never reached a
    /// terminal state.
    pub fn from_persisted(fields: PersistedAttempt) -> Result<Self, AttemptError> {
        let PersistedAttempt {
            id,
            policy_id,
            github_runner_id,
            state,
            outcome,
            process_id,
            runtime_path,
            created_at,
            terminal_at,
            last_state_change_at,
        } = fields;

        match (&outcome, state.is_terminal()) {
            (None, true) => return Err(AttemptError::TerminalWithoutOutcome { state }),
            (Some(outcome), false) => {
                return Err(AttemptError::NonTerminalWithOutcome {
                    state,
                    outcome: outcome.clone(),
                });
            }
            (Some(outcome), true) => {
                let expected = outcome.terminal_state();
                if state != expected && state != AttemptState::Cleaned {
                    return Err(AttemptError::OutcomeStateMismatch {
                        state,
                        outcome: outcome.clone(),
                    });
                }
            }
            (None, false) => {}
        }

        // `terminal_at` is validated on exactly the same footing as `outcome`,
        // and for the same stated reason. `conclude` is the only writer of both
        // and sets them together, so `state.is_terminal()` and
        // `terminal_at.is_some()` are equivalent in anything this crate
        // produced; a row where they disagree was edited by hand. Without this,
        // a `finished` attempt with no `terminal_at` loaded cleanly and every
        // consumer of `terminal_at()` -- retention, reporting, `g2`'s ordering
        // -- silently saw an attempt that had never concluded.
        match (terminal_at, state.is_terminal()) {
            (None, true) => return Err(AttemptError::TerminalWithoutTimestamp { state }),
            (Some(_), false) => return Err(AttemptError::NonTerminalWithTimestamp { state }),
            _ => {}
        }

        // Presence was checked above; *ordering* is checked here, and it is a
        // separate hazard. `created_at` never moves and every other timestamp is
        // written by a transition that happens after it, so a row where either
        // precedes it is one this crate cannot have produced. Without this, a
        // `finished` row with `created_at: ts(100), terminal_at: Some(ts(0))`
        // loaded cleanly -- an attempt that concluded a hundred seconds before
        // it was created -- and every duration computed from the pair came out
        // negative or wrapped. The hand-edited-journal threat model that
        // motivates the presence gate covers this equally.
        if last_state_change_at < created_at {
            return Err(AttemptError::TimestampsOutOfOrder {
                state,
                field: "last_state_change_at",
                created_at,
                found: last_state_change_at,
            });
        }
        if let Some(terminal_at) = terminal_at
            && terminal_at < created_at
        {
            return Err(AttemptError::TimestampsOutOfOrder {
                state,
                field: "terminal_at",
                created_at,
                found: terminal_at,
            });
        }

        Ok(Self {
            id,
            policy_id,
            github_runner_id,
            state,
            outcome,
            process_id,
            runtime_path,
            created_at,
            terminal_at,
            last_state_change_at,
        })
    }

    #[must_use]
    pub const fn state(&self) -> AttemptState {
        self.state
    }

    #[must_use]
    pub const fn outcome(&self) -> Option<&AttemptOutcome> {
        self.outcome.as_ref()
    }

    #[must_use]
    pub const fn github_runner_id(&self) -> Option<u64> {
        self.github_runner_id
    }

    #[must_use]
    pub const fn process_id(&self) -> Option<u32> {
        self.process_id
    }

    #[must_use]
    pub fn runtime_path(&self) -> &Path {
        &self.runtime_path
    }

    #[must_use]
    pub const fn terminal_at(&self) -> Option<Timestamp> {
        self.terminal_at
    }

    /// When the attempt entered its current state. Recovery timeouts run from
    /// here.
    #[must_use]
    pub const fn last_state_change_at(&self) -> Timestamp {
        self.last_state_change_at
    }

    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Whether this attempt still holds one of the host's capacity slots.
    #[must_use]
    pub const fn counts_against_capacity(&self) -> bool {
        self.state.counts_against_capacity()
    }

    fn move_to(&mut self, next: AttemptState, now: Timestamp) -> Result<(), AttemptError> {
        if !self.state.can_transition_to(next) {
            return Err(AttemptError::IllegalTransition {
                from: self.state,
                to: next,
            });
        }
        self.state = next;
        self.last_state_change_at = now;
        Ok(())
    }

    /// `allocated -> jit_received`.
    ///
    /// # Errors
    /// [`AttemptError::IllegalTransition`] from any other state.
    pub fn jit_received(&mut self, now: Timestamp) -> Result<(), AttemptError> {
        self.move_to(AttemptState::JitReceived, now)
    }

    /// `jit_received -> starting`, recording the child process identity.
    ///
    /// # Errors
    /// [`AttemptError::IllegalTransition`] from any other state.
    pub fn started(&mut self, process_id: u32, now: Timestamp) -> Result<(), AttemptError> {
        self.move_to(AttemptState::Starting, now)?;
        self.process_id = Some(process_id);
        Ok(())
    }

    /// `starting -> idle`: the runner registered and is awaiting its one
    /// assignment.
    ///
    /// # Errors
    /// [`AttemptError::IllegalTransition`] from any other state.
    pub fn registered_idle(
        &mut self,
        github_runner_id: u64,
        now: Timestamp,
    ) -> Result<(), AttemptError> {
        self.move_to(AttemptState::Idle, now)?;
        self.github_runner_id = Some(github_runner_id);
        Ok(())
    }

    /// `starting | idle -> busy`: the runner was assigned its one job.
    ///
    /// Both sources are real. A runner may be observed taking a job directly out
    /// of `starting`, or it may be seen `idle` first and pick the job up on a
    /// later pass — `e3`'s Scope step 4 walks the second sequence explicitly.
    ///
    /// # Errors
    /// [`AttemptError::IllegalTransition`] from any other state.
    pub fn assigned_job(
        &mut self,
        github_runner_id: u64,
        now: Timestamp,
    ) -> Result<(), AttemptError> {
        self.move_to(AttemptState::Busy, now)?;
        self.github_runner_id = Some(github_runner_id);
        Ok(())
    }

    /// Record the terminal outcome, moving to the state it implies.
    ///
    /// # Errors
    /// [`AttemptError::OutcomeUnreachable`] when the outcome does not belong to
    /// the current state — `CompletedJob` from anything but `busy`, or
    /// `ExitedIdleWithoutWork` from anything but `idle` — and
    /// [`AttemptError::IllegalTransition`] otherwise.
    pub fn conclude(
        &mut self,
        outcome: AttemptOutcome,
        now: Timestamp,
    ) -> Result<(), AttemptError> {
        if !outcome.required_from().contains(&self.state) {
            return Err(AttemptError::OutcomeUnreachable {
                from: self.state,
                outcome,
            });
        }
        self.move_to(outcome.terminal_state(), now)?;
        self.terminal_at = Some(now);
        self.outcome = Some(outcome);
        Ok(())
    }

    /// `finished | failed | orphaned -> cleaned`.
    ///
    /// # Errors
    /// [`AttemptError::BusyCannotBeCleaned`] for a `busy` attempt — the
    /// scale-down case `04-subsystem-contracts.md` forbids — and
    /// [`AttemptError::IllegalTransition`] for any other non-terminal state or
    /// for an already-cleaned attempt.
    pub fn clean(&mut self, now: Timestamp) -> Result<(), AttemptError> {
        if self.state == AttemptState::Busy {
            return Err(AttemptError::BusyCannotBeCleaned);
        }
        self.move_to(AttemptState::Cleaned, now)
    }
}

// ---------------------------------------------------------------------------
// Ownership
// ---------------------------------------------------------------------------

/// Ownership rules 1 and 2 (`04-subsystem-contracts.md`).
///
/// An attempt records its `policy_id`, and the policy records its `host_id`, so
/// authorising an attempt is a two-link check and both links matter. `e3`'s
/// restart recovery runs this before it touches a process it found on the
/// machine: adopting, terminating, or cleaning another host's attempt is the
/// failure this rule exists to prevent.
///
/// # Errors
/// [`OwnershipError::PolicyMismatch`] when the attempt does not belong to the
/// policy, and [`OwnershipError::ForeignHost`] when the policy does not belong to
/// this agent's host.
pub fn authorize(
    agent_host: HostId,
    policy: &ScalePolicy,
    attempt: &RunnerAttempt,
) -> Result<(), OwnershipError> {
    if attempt.policy_id != policy.id {
        return Err(OwnershipError::PolicyMismatch {
            attempt: attempt.id,
            attempt_policy: attempt.policy_id,
            policy: policy.id,
        });
    }
    if !policy.is_owned_by(agent_host) {
        return Err(OwnershipError::ForeignHost {
            policy: policy.id,
            owner: policy.host_id,
            agent: agent_host,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

/// How long an attempt may sit in each pre-terminal state before recovery treats
/// it as stuck.
///
/// **No document in this taskflow states these durations.** `03-control-flows.md`
/// flow 2.7 says a surplus runner "exits on its idle timeout" without giving one,
/// and flow 4.4 says an expired JIT configuration is discarded without saying
/// when it expires. [`RecoveryTimeouts::provisional`] therefore returns values
/// chosen here, named so that a caller cannot mistake them for a product
/// decision, and there is deliberately no `Default` impl — `e1` and `e3` should
/// have to write the numbers down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryTimeouts {
    /// How long `allocated` or `jit_received` may last before the JIT
    /// configuration is assumed lost.
    pub jit_handoff: Elapsed,
    /// How long `starting` may last before the runner is assumed not to be
    /// coming up.
    pub startup: Elapsed,
    /// How long `idle` may last before an exit is read as the surplus case
    /// rather than a crash.
    pub idle: Elapsed,
}

impl RecoveryTimeouts {
    #[must_use]
    pub const fn new(jit_handoff: Elapsed, startup: Elapsed, idle: Elapsed) -> Self {
        Self {
            jit_handoff,
            startup,
            idle,
        }
    }

    /// Placeholder values. Not a product decision — see the type documentation.
    #[must_use]
    pub fn provisional() -> Self {
        Self {
            jit_handoff: Elapsed::seconds(120),
            startup: Elapsed::seconds(300),
            idle: Elapsed::seconds(300),
        }
    }
}

/// What GitHub says about this attempt's runner.
///
/// Precedence rule 3: "GitHub runner status is authoritative for remote job
/// status; local process state is authoritative only for a child process owned by
/// this agent." Both halves are inputs here, and neither is allowed to stand in
/// for the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GithubRunnerObservation {
    /// GitHub could not be reached this cycle. Flow 3.3: start nothing, retain
    /// what is running, back off. It is emphatically **not** the same as
    /// `NotRegistered`, and conflating the two would delete live runners during
    /// an outage.
    Unreachable,
    /// GitHub knows no runner for this attempt.
    NotRegistered,
    /// GitHub knows the runner.
    Registered { busy: bool },
}

/// One attempt's observed reality at recovery time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryObservation {
    /// Whether the child process this agent recorded is still alive. `d1` supplies
    /// a process identity that survives a reboot, because a bare PID is reused.
    pub process_alive: bool,
    pub github: GithubRunnerObservation,
}

/// What to do about one attempt found in the journal at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryDecision {
    /// Already cleaned; there is nothing left to do.
    Nothing,
    /// Terminal but not yet cleaned: remove the runtime directory and mark it
    /// `cleaned`.
    Clean,
    /// The process is alive and this attempt is still ours. `e3`: "an attempt
    /// whose process still runs is adopted, not duplicated."
    Adopt,
    /// Nothing is decidable yet; look again next cycle.
    Wait,
    /// GitHub is unreachable. Decide nothing destructive during an outage
    /// (flow 3.3).
    Defer,
    /// Move the attempt to this state to match what was observed.
    ///
    /// **Where the observed state is live, the caller must adopt supervision of
    /// the process independently of this decision.** `RecoveryDecision` has no
    /// way to express "adopt *and* observe" — the two are separate variants —
    /// so `Starting` with `process_alive` and `Registered { busy: false }`
    /// returns `Observe(Idle)` and never [`Self::Adopt`], because GitHub is
    /// authoritative for the remote status while the local process is
    /// authoritative for supervision, and both facts are true at once.
    /// `Idle` with `process_alive` and `Registered { busy: true }` returns
    /// `Observe(Busy)` for exactly the same reason; it did not always, and the
    /// arm's own comment records what that cost.
    ///
    /// **An `Observe` decision must be applied *and persisted*, or it repeats
    /// forever.** The decision is a pure function of the journalled state and
    /// the observation, so a caller that moves the in-memory attempt without
    /// writing the new state back will read the same stale state on the next
    /// pass and be handed the same decision, indefinitely.
    Observe(AttemptState),
    /// Conclude the attempt with this outcome.
    ///
    /// **Terminal, and therefore a capacity release.** An attempt is only
    /// concluded where the thing it was supervising is already gone; see
    /// [`Self::Terminate`] for the case where it is not.
    Conclude(AttemptOutcome),
    /// The process is still alive but the attempt cannot go on: **stop the
    /// process, and only once it is gone record this outcome.**
    ///
    /// **Why this is not a [`Self::Conclude`].** `Conclude` moves the attempt to
    /// a terminal state, and a terminal attempt no longer
    /// [counts against capacity](AttemptState::counts_against_capacity) — so
    /// concluding one whose process is still running hands the host back a slot
    /// it is still using. The agent then starts a replacement runner beside a
    /// live, unregistered one that may yet register and take a job, for an
    /// attempt the journal already calls `failed`. There is no
    /// `RecoveryDecision` that would have expressed the fix: [`Self::Adopt`]
    /// means take over supervision and [`Self::Clean`] means delete a runtime
    /// directory, and neither stops anything.
    ///
    /// **What happens to the capacity slot.** Nothing, until the process is
    /// actually gone. The attempt stays in its current, non-terminal state and
    /// keeps holding its slot for as long as the runner it started is running,
    /// which is the honest answer — the resources are genuinely occupied. The
    /// slot comes back at the moment the caller applies the payload through
    /// [`RunnerAttempt::conclude`], which it does only after the process has
    /// exited.
    ///
    /// **It is safe to re-derive.** The decision is a pure function of the
    /// journalled state and the observation, so an agent that dies between
    /// deciding and terminating is handed the same decision on the next pass. A
    /// caller that terminates but crashes before writing the outcome observes
    /// `process_alive: false` next time and reaches the ordinary
    /// [`Self::Conclude`] arm instead; that arm names the process as gone, which
    /// by then it is.
    ///
    /// **The one thing this does not bound** is a process that refuses to die.
    /// The slot is held until it does. That is a worse outcome than concluding
    /// early only if the runner was never going to register, and a better one in
    /// every case where it was — and unlike the early conclusion it cannot
    /// oversubscribe the host.
    Terminate(AttemptOutcome),
}

/// Decide what to do about one journalled attempt after a restart, or on any
/// reconciliation pass.
///
/// Time enters only through `clock`, and only as `now - attempt.
/// last_state_change_at()`, so the whole function is exercised by advancing a
/// [`crate::model::Clock`] the test controls.
#[must_use]
pub fn recovery_decision(
    attempt: &RunnerAttempt,
    observation: RecoveryObservation,
    timeouts: RecoveryTimeouts,
    clock: &dyn Clock,
) -> RecoveryDecision {
    use AttemptState as S;
    use GithubRunnerObservation as G;

    let state = attempt.state();

    if state == S::Cleaned {
        return RecoveryDecision::Nothing;
    }
    if state.is_terminal() {
        return RecoveryDecision::Clean;
    }
    if observation.github == G::Unreachable {
        return RecoveryDecision::Defer;
    }

    let elapsed = clock.now() - attempt.last_state_change_at();

    match state {
        S::Allocated | S::JitReceived => {
            if observation.process_alive {
                // Precedence rule 3's other half: local process state is
                // authoritative for a child process this agent owns. `e3`: an
                // attempt whose process still runs is adopted, not duplicated.
                RecoveryDecision::Adopt
            } else {
                match observation.github {
                    // The crash window `e3` exists for. A runner cannot register
                    // without having received its JIT configuration and started,
                    // so a registration is proof the attempt got further than
                    // the journal records: the `starting` write was lost, not
                    // the attempt. This branch used to consult only
                    // `process_alive` and the clock, which abandoned a live
                    // runner as `failed` and left its registration at GitHub
                    // unreconciled and unremoved.
                    //
                    // Each state takes the one *forward* edge out of itself, so
                    // recovery walks the diagram rather than jumping across it:
                    // `allocated -> jit_received` (the registration proves the
                    // JIT configuration arrived) and `jit_received -> starting`.
                    // `busy` is deliberately not consulted here -- neither state
                    // has an edge to it, and the next pass, from `starting`, is
                    // where that distinction becomes legal and is drawn.
                    //
                    // This is a genuine recovery path and not a workaround for a
                    // missing edge: GitHub really is reporting a live runner,
                    // and each step really did happen. It survived the diagram
                    // amendment unchanged.
                    G::Registered { .. } => RecoveryDecision::Observe(if state == S::Allocated {
                        S::JitReceived
                    } else {
                        S::Starting
                    }),
                    // Past the handoff deadline with nothing at GitHub and no
                    // process: the attempt died before registering, and since
                    // the amendment it can say so directly. It previously had to
                    // report `NoLegalTransition` and hold its host capacity slot
                    // for ever.
                    //
                    // The two states get different reasons because they know
                    // different things. At `allocated` no configuration was ever
                    // recorded as arriving, so the request itself did not
                    // complete; at `jit_received` one arrived and was never
                    // claimed, which is flow 4.4's expiry.
                    G::NotRegistered => {
                        if elapsed >= timeouts.jit_handoff {
                            RecoveryDecision::Conclude(AttemptOutcome::failed(
                                if state == S::Allocated {
                                    FailureReason::JitRequestFailed
                                } else {
                                    FailureReason::JitExpired
                                },
                            ))
                        } else {
                            RecoveryDecision::Wait
                        }
                    }
                    G::Unreachable => unreachable!("handled above"),
                }
            }
        }

        S::Starting => match observation.github {
            // GitHub is authoritative for remote job status, and both of these
            // are legal edges out of `starting`.
            G::Registered { busy: true } => RecoveryDecision::Observe(S::Busy),
            G::Registered { busy: false } => RecoveryDecision::Observe(S::Idle),
            // Three cases, not two, and the third is the one that matters.
            //
            // A live process inside its startup window is adopted, the same as
            // in every other pre-terminal state: `e3` must take over supervision
            // rather than start a second runner for the same work.
            //
            // A process that is *gone* is flow 2's "runner exit before job
            // acceptance". Since the amendment that is recordable, so the
            // attempt concludes and gives its slot back.
            //
            // A process that is alive and past its deadline is neither, and
            // collapsing it into the second was a real defect: `Conclude` makes
            // the attempt terminal, a terminal attempt stops counting against
            // capacity, and the host therefore got its slot back while the
            // runner was still running -- free to register late and take a job
            // for an attempt the journal already called `failed`, beside the
            // replacement the freed slot let the agent start. It also read
            // `ProcessExitedUnexpectedly` to an operator looking at the process
            // in a task manager. `Terminate` says the true thing and keeps the
            // slot until the process is actually gone.
            G::NotRegistered => {
                if !observation.process_alive {
                    RecoveryDecision::Conclude(AttemptOutcome::failed(
                        FailureReason::ProcessExitedUnexpectedly,
                    ))
                } else if elapsed < timeouts.startup {
                    RecoveryDecision::Adopt
                } else {
                    RecoveryDecision::Terminate(AttemptOutcome::failed(
                        FailureReason::RegistrationTimedOut,
                    ))
                }
            }
            G::Unreachable => unreachable!("handled above"),
        },

        // GitHub is consulted **first**, exactly as at `starting` above, and the
        // symmetry is load-bearing rather than tidy. This arm used to
        // short-circuit on `process_alive` before looking at GitHub, so the same
        // conflict -- a live process that GitHub reports as `busy` -- resolved
        // one way here and the opposite way one state earlier. What that cost
        // was not an inconsistency but a wrong outcome: `Adopt` left the journal
        // saying `idle`, so `last_state_change_at` went on pointing at the idle
        // entry, and a runner that later crashed *during its job* had its idle
        // timeout elapse and was concluded `ExitedIdleWithoutWork` -- the benign
        // surplus exit, recorded for a mid-job crash, inverting the one
        // distinction this module exists to keep. Nothing downstream could
        // catch it either: `required_from` for that outcome is `&[Idle]`, and
        // the attempt really was `idle`.
        //
        // `Observe(Busy)` is returned whether or not the process is alive: the
        // caller adopts supervision independently of this decision, which is
        // what [`RecoveryDecision::Observe`] already instructs and what
        // `starting` has always relied on.
        S::Idle => match observation.github {
            // GitHub says this runner took a job, and GitHub is authoritative
            // for remote job status (precedence rule 3). `idle -> busy` was
            // added by the amendment *for this observation*; before this change
            // the only arm that could reach it was the one where the process is
            // already dead.
            G::Registered { busy: true } => RecoveryDecision::Observe(S::Busy),
            // GitHub agrees with the journal, so there is no state to move to.
            // A live process is adopted; a dead one means supervision is lost
            // while the remote registration outlived it and needs removing.
            G::Registered { busy: false } => {
                if observation.process_alive {
                    RecoveryDecision::Adopt
                } else {
                    RecoveryDecision::Conclude(AttemptOutcome::Orphaned)
                }
            }
            // Nothing at GitHub. A live process is still ours to supervise.
            // Otherwise the surplus case and the crash case, separated by the
            // clock: a runner that sat out its whole idle timeout and then
            // exited with no registration left behind did what flow 2.7
            // describes. One that vanished early did not.
            G::NotRegistered => {
                if observation.process_alive {
                    RecoveryDecision::Adopt
                } else if elapsed >= timeouts.idle {
                    RecoveryDecision::Conclude(AttemptOutcome::ExitedIdleWithoutWork)
                } else {
                    RecoveryDecision::Conclude(AttemptOutcome::failed(
                        FailureReason::ProcessExitedUnexpectedly,
                    ))
                }
            }
            G::Unreachable => unreachable!("handled above"),
        },

        S::Busy => {
            if observation.process_alive {
                RecoveryDecision::Adopt
            } else {
                // `e3`: "an attempt whose process is gone and whose runner is
                // unknown to GitHub is `orphaned` and cleaned". The agent never
                // reports a job as complete, so a lost supervision is recorded as
                // exactly that and not guessed into a success.
                RecoveryDecision::Conclude(AttemptOutcome::Orphaned)
            }
        }

        S::Finished | S::Failed | S::Orphaned | S::Cleaned => {
            unreachable!("terminal states are handled above")
        }
    }
}

/// How many of these attempts still occupy a host capacity slot.
///
/// Saturating rather than wrapping: a host cannot hold more than `u16::MAX`
/// attempts, and if some caller ever produced that many, reporting the ceiling is
/// safe where wrapping to zero would let the allocator start `u16::MAX` more.
#[must_use]
pub fn active_count<'a>(attempts: impl IntoIterator<Item = &'a RunnerAttempt>) -> u16 {
    attempts
        .into_iter()
        .filter(|a| a.counts_against_capacity())
        .fold(0u16, |acc, _| acc.saturating_add(1))
}

/// How many of these attempts still occupy a slot **and belong to one policy**.
///
/// The per-policy counterpart of [`active_count`], and the term
/// [`crate::capacity::HostAllocator::allocate`] subtracts. The two are not
/// interchangeable: [`active_count`] is the host-wide total that bounds D9's
/// ceiling, this one is the per-policy figure that bounds D7's, and substituting
/// either for the other is silent — the host-wide count in a per-policy slot
/// starves every policy but the first, and a zero in place of this one starts a
/// duplicate runner on every poll.
#[must_use]
pub fn active_count_for<'a>(
    policy_id: PolicyId,
    attempts: impl IntoIterator<Item = &'a RunnerAttempt>,
) -> u16 {
    attempts
        .into_iter()
        .filter(|a| a.policy_id == policy_id && a.counts_against_capacity())
        .fold(0u16, |acc, _| acc.saturating_add(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Arch, CachePolicy, HostLabel, Os, ScaleTarget};
    use crate::policy::{PolicyMode, RoutingLabels};
    use std::num::NonZeroU16;

    #[derive(Debug)]
    struct StubClock(std::sync::Mutex<Timestamp>);

    impl StubClock {
        fn at(secs: i64) -> Self {
            Self(std::sync::Mutex::new(ts(secs)))
        }
        fn set(&self, secs: i64) {
            *self.0.lock().unwrap() = ts(secs);
        }
    }

    impl Clock for StubClock {
        fn now(&self) -> Timestamp {
            *self.0.lock().unwrap()
        }
    }

    fn ts(secs: i64) -> Timestamp {
        chrono::DateTime::from_timestamp(secs, 0).expect("valid timestamp")
    }

    fn attempt_in(state: AttemptState, entered_at: i64) -> RunnerAttempt {
        let mut attempt = RunnerAttempt::allocate(
            AttemptId::from_u128(1),
            PolicyId::from_u128(1),
            "runtime/p/a",
            ts(0),
        );
        // Set the state directly: only possible from inside the module, which is
        // exactly why the state-machine tests live here.
        attempt.state = state;
        attempt.last_state_change_at = ts(entered_at);
        attempt
    }

    /// The same, under a nominated policy, for the per-policy count.
    fn attempt_for(policy_id: PolicyId, state: AttemptState, entered_at: i64) -> RunnerAttempt {
        let mut attempt = attempt_in(state, entered_at);
        attempt.policy_id = policy_id;
        attempt
    }

    fn a_policy(host: HostId, policy_id: PolicyId) -> ScalePolicy {
        ScalePolicy::new(
            policy_id,
            ScaleTarget::repository("o/r").unwrap(),
            1,
            host,
            PolicyMode::autoscale(
                RoutingLabels::derive(&HostLabel::new("home").unwrap(), Os::Windows, Arch::X64),
                0,
                NonZeroU16::new(1).unwrap(),
            )
            .unwrap(),
            CachePolicy::default(),
        )
    }

    // =======================================================================
    // The state machine, both directions
    // =======================================================================

    /// The diagram from `04-subsystem-contracts.md`, transcribed by hand.
    ///
    /// **Deliberately a second copy of [`AttemptState::LEGAL`]**, for the reason
    /// given on `policy::tests::diagram_edges`: a test whose expectation is read
    /// out of the constant under test asserts only that the constant equals
    /// itself, and would accept any edge someone added to it.
    ///
    /// ```text
    /// allocated -> jit_received -> starting -> idle | busy
    /// idle -> busy
    /// allocated | jit_received | starting -> failed | orphaned
    /// idle | busy -> finished | failed | orphaned
    /// finished | failed | orphaned -> cleaned
    /// ```
    fn diagram_edges() -> Vec<(AttemptState, AttemptState)> {
        use AttemptState::*;
        // Line 1.
        let mut edges = vec![
            (Allocated, JitReceived),
            (JitReceived, Starting),
            (Starting, Idle),
            (Starting, Busy),
        ];
        // Line 2, added by the 2026-08-21 amendment.
        edges.push((Idle, Busy));
        // Line 3, added by the same amendment.
        for from in [Allocated, JitReceived, Starting] {
            for to in [Failed, Orphaned] {
                edges.push((from, to));
            }
        }
        // Line 4.
        for from in [Idle, Busy] {
            for to in [Finished, Failed, Orphaned] {
                edges.push((from, to));
            }
        }
        // Line 5.
        for from in [Finished, Failed, Orphaned] {
            edges.push((from, Cleaned));
        }
        edges
    }

    #[test]
    fn every_attempt_state_transition_is_legal_exactly_where_the_diagram_says() {
        let expected = diagram_edges();
        assert_eq!(
            expected.len(),
            20,
            "the transcription itself changed; check it against the diagram"
        );

        let mut legal_seen = 0usize;
        let mut illegal_seen = 0usize;

        for from in AttemptState::ALL {
            for to in AttemptState::ALL {
                let expected_legal = expected.contains(&(from, to));
                let mut attempt = attempt_in(from, 0);
                let result = attempt.move_to(to, ts(10));

                if expected_legal {
                    legal_seen += 1;
                    assert!(
                        result.is_ok(),
                        "{from} -> {to} is in the diagram and must be accepted"
                    );
                    assert_eq!(attempt.state(), to);
                    assert_eq!(attempt.last_state_change_at(), ts(10));
                } else {
                    illegal_seen += 1;
                    assert!(
                        matches!(result, Err(AttemptError::IllegalTransition { .. })),
                        "{from} -> {to} is not in the diagram and must be rejected"
                    );
                    assert_eq!(
                        attempt.state(),
                        from,
                        "a refused transition changes nothing"
                    );
                    assert_eq!(attempt.last_state_change_at(), ts(0));
                }
            }
        }

        assert_eq!(legal_seen, 20);
        assert_eq!(illegal_seen, 81 - 20);

        // And the published constant matches the transcription.
        let mut published = AttemptState::LEGAL.to_vec();
        let mut transcribed = expected;
        published.sort_unstable();
        transcribed.sort_unstable();
        assert_eq!(published, transcribed);
    }

    #[test]
    fn every_live_state_has_a_terminal_edge_so_no_attempt_can_hold_a_slot_forever() {
        // The operational half of the amendment, asserted as the property it is
        // rather than as a list of edges. An attempt occupies a host capacity
        // slot for exactly as long as it is non-terminal, so a live state with
        // no terminal edge is a state an attempt can be stranded in -- which is
        // how two failed JIT requests wedged a `host_capacity: 2` host into
        // starting zero runners, with no error and no cleanup path.
        for state in AttemptState::ALL {
            if state.is_terminal() {
                continue;
            }
            // Read through `active_count`, which is the function the
            // reconciliation formula actually calls, rather than through
            // `state.counts_against_capacity()`. The latter is defined as
            // `!self.is_terminal()`, so asserting it one line under
            // `if state.is_terminal() { continue; }` is `assert!(true)` and
            // catches nothing; this asserts the same property against a second
            // reader that can regress on its own -- an inverted or mistyped
            // filter predicate in `active_count` fails here and nowhere else in
            // this test.
            assert_eq!(
                active_count([&attempt_in(state, 0)]),
                1,
                "{state} is non-terminal, so the reconciliation formula must \
                 still be subtracting it"
            );
            assert!(
                state.can_transition_to(AttemptState::Failed)
                    || state.can_transition_to(AttemptState::Finished),
                "{state} has no way to conclude, so an attempt in it holds a host \
                 capacity slot permanently"
            );
            assert!(
                state.can_transition_to(AttemptState::Orphaned),
                "{state} has no orphan edge, so an attempt found in it after a \
                 restart cannot be recorded"
            );
            assert!(
                AttemptState::CONCLUDABLE_FROM.contains(&state),
                "{state} is live but missing from CONCLUDABLE_FROM"
            );
        }
        assert_eq!(
            AttemptState::CONCLUDABLE_FROM.len(),
            AttemptState::ALL
                .iter()
                .filter(|s| !s.is_terminal())
                .count(),
            "CONCLUDABLE_FROM must list every non-terminal state and nothing else"
        );
    }

    #[test]
    fn an_attempt_state_cannot_transition_to_itself() {
        for state in AttemptState::ALL {
            assert!(
                !state.can_transition_to(state),
                "{state} -> {state} is not an edge in the diagram"
            );
        }
    }

    #[test]
    fn cleaned_is_absorbing() {
        for to in AttemptState::ALL {
            assert!(
                !AttemptState::Cleaned.can_transition_to(to),
                "cleaned -> {to} must not exist; a cleaned runtime directory is gone"
            );
        }
    }

    #[test]
    fn the_documented_happy_path_walks_allocated_to_cleaned() {
        // `e3`: "A full attempt runs allocated -> jit_received -> starting ->
        // busy -> finished -> cleaned".
        let mut attempt = RunnerAttempt::allocate(
            AttemptId::from_u128(1),
            PolicyId::from_u128(1),
            "runtime/p/a",
            ts(0),
        );
        assert_eq!(attempt.state(), AttemptState::Allocated);
        assert!(attempt.counts_against_capacity());

        attempt.jit_received(ts(1)).unwrap();
        attempt.started(4242, ts(2)).unwrap();
        assert_eq!(attempt.process_id(), Some(4242));

        attempt.assigned_job(73, ts(3)).unwrap();
        assert_eq!(attempt.state(), AttemptState::Busy);
        assert_eq!(attempt.github_runner_id(), Some(73));

        attempt
            .conclude(AttemptOutcome::CompletedJob, ts(9))
            .unwrap();
        assert_eq!(attempt.state(), AttemptState::Finished);
        assert_eq!(attempt.terminal_at(), Some(ts(9)));
        assert!(!attempt.counts_against_capacity());

        attempt.clean(ts(10)).unwrap();
        assert_eq!(attempt.state(), AttemptState::Cleaned);
    }

    // =======================================================================
    // Outcome: the surplus attempt
    // =======================================================================

    #[test]
    fn an_attempt_that_exits_idle_without_work_is_terminal_and_not_a_failure() {
        // `b1`: "An attempt that exits idle without work reaches a terminal state
        // carrying an outcome distinguishable from a failure."
        let mut surplus = RunnerAttempt::allocate(
            AttemptId::from_u128(1),
            PolicyId::from_u128(1),
            "runtime/p/a",
            ts(0),
        );
        surplus.jit_received(ts(1)).unwrap();
        surplus.started(1, ts(2)).unwrap();
        surplus.registered_idle(73, ts(3)).unwrap();
        surplus
            .conclude(AttemptOutcome::ExitedIdleWithoutWork, ts(300))
            .unwrap();

        assert!(surplus.is_terminal());
        assert_eq!(surplus.state(), AttemptState::Finished);

        let outcome = surplus.outcome().expect("a terminal attempt carries one");
        assert!(outcome.is_idle_exit());
        assert!(
            !outcome.is_failure(),
            "the surplus runner is an accepted, bounded cost of having no job \
             reservation -- presenting it as a fault sends an operator hunting \
             something that did not happen"
        );
        assert!(!outcome.ran_a_job());

        // And it is cleaned like any other terminal attempt.
        surplus.clean(ts(301)).unwrap();
        assert_eq!(surplus.state(), AttemptState::Cleaned);
    }

    #[test]
    fn an_idle_exit_is_distinguishable_from_a_failure_and_from_a_completed_job() {
        // The three outcomes `g2` must render apart.
        let idle = AttemptOutcome::ExitedIdleWithoutWork;
        let failed = AttemptOutcome::failed(FailureReason::ProcessStartFailed);
        let done = AttemptOutcome::CompletedJob;

        assert_ne!(idle, failed);
        assert_ne!(idle, done);
        assert_ne!(failed, done);

        assert_eq!(idle.terminal_state(), AttemptState::Finished);
        assert_eq!(done.terminal_state(), AttemptState::Finished);
        assert_eq!(failed.terminal_state(), AttemptState::Failed);
        assert_eq!(
            AttemptOutcome::Orphaned.terminal_state(),
            AttemptState::Orphaned
        );

        // `finished` alone does not say which happened; the outcome does. This is
        // the assertion that would fail if someone dropped the outcome field and
        // let `g2` infer from the state.
        assert_eq!(idle.terminal_state(), done.terminal_state());
        assert_ne!(idle, done);

        assert!(!idle.is_failure());
        assert!(failed.is_failure());
        assert!(AttemptOutcome::Orphaned.is_failure());
    }

    #[test]
    fn an_outcome_cannot_be_recorded_from_a_state_that_could_not_produce_it() {
        // A runner that never got a job cannot have run one.
        let mut idle = attempt_in(AttemptState::Idle, 0);
        assert!(matches!(
            idle.conclude(AttemptOutcome::CompletedJob, ts(1)),
            Err(AttemptError::OutcomeUnreachable {
                from: AttemptState::Idle,
                ..
            })
        ));
        assert_eq!(idle.state(), AttemptState::Idle);
        assert!(idle.outcome().is_none());

        // And a runner that was executing a job did not exit idle without work.
        let mut busy = attempt_in(AttemptState::Busy, 0);
        assert!(matches!(
            busy.conclude(AttemptOutcome::ExitedIdleWithoutWork, ts(1)),
            Err(AttemptError::OutcomeUnreachable {
                from: AttemptState::Busy,
                ..
            })
        ));

        // Failure and orphaning are reachable from every live state, including
        // the three pre-registration ones the amendment gave terminal edges.
        for state in AttemptState::CONCLUDABLE_FROM {
            attempt_in(*state, 0)
                .conclude(AttemptOutcome::failed(FailureReason::JitExpired), ts(1))
                .unwrap_or_else(|e| panic!("{state} must be able to fail: {e}"));
            attempt_in(*state, 0)
                .conclude(AttemptOutcome::Orphaned, ts(1))
                .unwrap_or_else(|e| panic!("{state} must be able to orphan: {e}"));
        }

        // And from a terminal state nothing can be concluded at all -- a second
        // conclusion would overwrite the first.
        for state in AttemptState::ALL.iter().filter(|s| s.is_terminal()) {
            assert!(
                attempt_in(*state, 0)
                    .conclude(AttemptOutcome::Orphaned, ts(1))
                    .is_err(),
                "{state} has already concluded"
            );
        }
    }

    /// The earliest state at which the agent learns each fact, from flow 2's own
    /// step order.
    ///
    /// **This match is exhaustive and carries no wildcard, and that is the whole
    /// mechanism.** The assertion it replaced read
    /// `assert_eq!(cases.len(), 7, "FailureReason has seven variants; ...")`,
    /// and `cases.len()` on a `[_; 7]` is the compile-time constant `7`: the
    /// assertion was `7 == 7` and could not fail. Measured on the code as it
    /// stood, adding an eighth variant produced exactly one error — `E0004` from
    /// `Display`'s match — and once that arm was written the suite was green
    /// with the new variant unreachable and untested. Here, a ninth variant
    /// stops this file compiling until somebody says which state produces it,
    /// and `all_failure_reasons_are_reachable_from_the_state_that_produces_them`
    /// then proves the answer.
    fn earliest_state_producing(reason: &FailureReason) -> AttemptState {
        match reason {
            // Step 5: the package is verified before the JIT request is made.
            FailureReason::RunnerPackageUnverified => AttemptState::Allocated,
            // Step 5: `generate-jitconfig` did not return a configuration.
            FailureReason::JitRequestFailed => AttemptState::Allocated,
            // Flow 4.4: a configuration arrived and was never claimed.
            FailureReason::JitExpired => AttemptState::JitReceived,
            // Step 6: the child process could not be spawned.
            FailureReason::ProcessStartFailed => AttemptState::JitReceived,
            // Edge case 7: GitHub refuses the registration on version grounds.
            FailureReason::RunnerVersionRejected => AttemptState::Starting,
            // Flow 2's "runner exit before job acceptance".
            FailureReason::ProcessExitedUnexpectedly => AttemptState::Starting,
            // The live-but-unregistered process past its startup deadline; see
            // the `S::Starting` / `G::NotRegistered` arm of `recovery_decision`.
            FailureReason::RegistrationTimedOut => AttemptState::Starting,
            FailureReason::Other(_) => AttemptState::Busy,
        }
    }

    #[test]
    fn all_failure_reasons_are_reachable_from_the_state_that_produces_them() {
        // `03-control-flows.md` flow 2 names most of these by name as conditions
        // the agent must record. Before the diagram amendment five were
        // unreachable: each occurs at a pre-registration state, and `allocated`,
        // `jit_received` and `starting` had no terminal edge, so `conclude`
        // answered `OutcomeUnreachable` from every state that could actually
        // have produced them. A `FailureReason` variant that nothing can reach
        // is a variant `g2` renders a match arm for and no test can cover.
        //
        // The table is written out rather than derived so each pairing carries
        // its reason; `earliest_state_producing` above is what makes a new
        // variant a compile error, and the two are cross-checked below.
        let cases: [(FailureReason, AttemptState); 8] = [
            // Step 5: the package is verified before the JIT request is made.
            (
                FailureReason::RunnerPackageUnverified,
                AttemptState::Allocated,
            ),
            // Step 5: `generate-jitconfig` did not return a configuration.
            (FailureReason::JitRequestFailed, AttemptState::Allocated),
            // Flow 4.4: a configuration arrived and was never claimed.
            (FailureReason::JitExpired, AttemptState::JitReceived),
            // Step 6: the child process could not be spawned.
            (FailureReason::ProcessStartFailed, AttemptState::JitReceived),
            // Edge case 7: GitHub refuses the registration on version grounds.
            (FailureReason::RunnerVersionRejected, AttemptState::Starting),
            // Flow 2's "runner exit before job acceptance".
            (
                FailureReason::ProcessExitedUnexpectedly,
                AttemptState::Starting,
            ),
            // A live runner that never reached GitHub inside its startup window.
            (FailureReason::RegistrationTimedOut, AttemptState::Starting),
            (
                FailureReason::Other("a reason b1 did not anticipate".into()),
                AttemptState::Busy,
            ),
        ];

        // Every variant is covered exactly once. Three separate things have to
        // hold, and none of them is a length compared against itself:
        //
        //  * `FailureReason::ALL` and this table are the same size, so a variant
        //    added to one and not the other is caught;
        //  * every variant in `ALL` appears here -- by discriminant, because
        //    `Other`'s payload differs between the two lists;
        //  * each pairing agrees with `earliest_state_producing`, whose
        //    wildcard-free match is what stops this file compiling when a
        //    variant is added at all.
        assert_eq!(
            cases.len(),
            FailureReason::ALL.len(),
            "every FailureReason variant needs a state it is reachable from"
        );
        for listed in FailureReason::ALL {
            assert!(
                cases.iter().any(|(reason, _)| {
                    std::mem::discriminant(reason) == std::mem::discriminant(&listed)
                }),
                "{listed:?} is in FailureReason::ALL but has no case here"
            );
        }
        for (reason, from) in &cases {
            assert_eq!(
                earliest_state_producing(reason),
                *from,
                "{reason:?}: the table and the exhaustive match disagree"
            );
        }

        for (reason, from) in cases {
            let mut attempt = attempt_in(from, 0);
            attempt
                .conclude(AttemptOutcome::failed(reason.clone()), ts(5))
                .unwrap_or_else(|e| panic!("{reason:?} must be recordable from {from}, got {e}"));

            assert_eq!(attempt.state(), AttemptState::Failed);
            assert_eq!(attempt.terminal_at(), Some(ts(5)));
            assert_eq!(
                attempt.outcome(),
                Some(&AttemptOutcome::failed(reason.clone()))
            );
            assert!(
                !attempt.counts_against_capacity(),
                "{reason:?} from {from} must give the host capacity slot back; \
                 that is what the amendment was for"
            );

            // And it survives the persistence gate, so the row `b2` writes for
            // it can be read back.
            let restored = RunnerAttempt::from_persisted(attempt.to_persisted())
                .unwrap_or_else(|e| panic!("{reason:?} from {from} must reload: {e}"));
            assert_eq!(restored, attempt);
        }
    }

    // =======================================================================
    // Busy protection
    // =======================================================================

    #[test]
    fn a_busy_attempt_cannot_be_cleaned() {
        // `04-subsystem-contracts.md`: "`busy` cannot transition to cleanup due
        // to a scale-down request."
        let mut busy = attempt_in(AttemptState::Busy, 0);
        let err = busy.clean(ts(1)).unwrap_err();
        assert_eq!(
            err,
            AttemptError::BusyCannotBeCleaned,
            "the refusal must be named, not a generic transition error, so that a \
             scale-down that tried it is legible in a log"
        );
        assert_eq!(busy.state(), AttemptState::Busy);
        assert!(busy.counts_against_capacity());
    }

    #[test]
    fn only_a_terminal_attempt_can_be_cleaned() {
        for state in AttemptState::ALL {
            let mut attempt = attempt_in(state, 0);
            let result = attempt.clean(ts(1));
            if state.is_concluded() {
                assert!(result.is_ok(), "{state} is terminal and must be cleanable");
                assert_eq!(attempt.state(), AttemptState::Cleaned);
            } else {
                assert!(
                    result.is_err(),
                    "{state} is not terminal and must not be cleanable"
                );
                assert_eq!(attempt.state(), state);
            }
        }
    }

    #[test]
    fn capacity_is_reclaimed_exactly_at_the_terminal_states() {
        for state in AttemptState::ALL {
            assert_eq!(
                attempt_in(state, 0).counts_against_capacity(),
                !state.is_terminal(),
                "{state}"
            );
        }

        let attempts = vec![
            attempt_in(AttemptState::Allocated, 0),
            attempt_in(AttemptState::Starting, 0),
            attempt_in(AttemptState::Busy, 0),
            attempt_in(AttemptState::Finished, 0),
            attempt_in(AttemptState::Cleaned, 0),
        ];
        assert_eq!(active_count(&attempts), 3);
    }

    #[test]
    fn the_per_policy_active_count_is_not_the_host_wide_one() {
        // Substituting either for the other is silent, so the difference is
        // pinned rather than left to the reader of two similar names.
        let mine = PolicyId::from_u128(1);
        let theirs = PolicyId::from_u128(2);

        let mut attempts = vec![
            attempt_for(mine, AttemptState::Starting, 0),
            attempt_for(mine, AttemptState::Busy, 0),
            attempt_for(theirs, AttemptState::Busy, 0),
            attempt_for(theirs, AttemptState::Idle, 0),
            attempt_for(theirs, AttemptState::Allocated, 0),
        ];

        assert_eq!(active_count(&attempts), 5, "the host-wide total, for D9");
        assert_eq!(active_count_for(mine, &attempts), 2, "this policy, for D7");
        assert_eq!(active_count_for(theirs, &attempts), 3);
        assert_eq!(
            active_count_for(PolicyId::from_u128(3), &attempts),
            0,
            "a policy with nothing in flight"
        );

        // Terminal attempts drop out of the per-policy count on the same rule as
        // the host-wide one.
        attempts.push(attempt_for(mine, AttemptState::Finished, 0));
        attempts.push(attempt_for(mine, AttemptState::Cleaned, 0));
        assert_eq!(active_count_for(mine, &attempts), 2);
    }

    // =======================================================================
    // Persistence gate
    // =======================================================================

    /// A journal row the domain accepts, for a test to spoil one field of.
    fn row(state: AttemptState, outcome: Option<AttemptOutcome>) -> PersistedAttempt {
        PersistedAttempt {
            id: AttemptId::from_u128(1),
            policy_id: PolicyId::from_u128(1),
            github_runner_id: Some(73),
            state,
            outcome,
            process_id: Some(9),
            runtime_path: "runtime/p/a".into(),
            created_at: ts(0),
            terminal_at: state.is_terminal().then(|| ts(9)),
            last_state_change_at: ts(9),
        }
    }

    #[test]
    fn a_hand_edited_journal_row_with_an_impossible_outcome_is_rejected() {
        assert!(
            RunnerAttempt::from_persisted(row(
                AttemptState::Finished,
                Some(AttemptOutcome::ExitedIdleWithoutWork)
            ))
            .is_ok()
        );

        // Terminal with no outcome.
        assert!(matches!(
            RunnerAttempt::from_persisted(row(AttemptState::Failed, None)),
            Err(AttemptError::TerminalWithoutOutcome { .. })
        ));

        // Non-terminal carrying one.
        assert!(matches!(
            RunnerAttempt::from_persisted(row(
                AttemptState::Busy,
                Some(AttemptOutcome::CompletedJob)
            )),
            Err(AttemptError::NonTerminalWithOutcome { .. })
        ));

        // A `failed` row that claims to have run a job.
        assert!(matches!(
            RunnerAttempt::from_persisted(row(
                AttemptState::Failed,
                Some(AttemptOutcome::CompletedJob)
            )),
            Err(AttemptError::OutcomeStateMismatch { .. })
        ));

        // `cleaned` keeps whichever outcome preceded it.
        assert!(
            RunnerAttempt::from_persisted(row(
                AttemptState::Cleaned,
                Some(AttemptOutcome::Orphaned)
            ))
            .is_ok()
        );
    }

    #[test]
    fn a_hand_edited_journal_row_with_an_impossible_terminal_at_is_rejected() {
        // `terminal_at` is on the same footing as `outcome`: `conclude` is the
        // only writer of either and sets them together, so a row where
        // `state.is_terminal()` and `terminal_at.is_some()` disagree is one this
        // crate cannot have produced. Before this gate existed, a `finished` row
        // with `terminal_at: None` loaded cleanly and every reader of
        // `terminal_at()` saw an attempt that had never concluded.
        let mut terminal_without = row(AttemptState::Finished, Some(AttemptOutcome::CompletedJob));
        terminal_without.terminal_at = None;
        assert!(
            matches!(
                RunnerAttempt::from_persisted(terminal_without),
                Err(AttemptError::TerminalWithoutTimestamp {
                    state: AttemptState::Finished
                })
            ),
            "a terminal row with no terminal_at must be refused, exactly as a \
             terminal row with no outcome is"
        );

        // The other direction: a live attempt that claims to have concluded.
        let mut live_with = row(AttemptState::Busy, None);
        live_with.terminal_at = Some(ts(9));
        assert!(matches!(
            RunnerAttempt::from_persisted(live_with),
            Err(AttemptError::NonTerminalWithTimestamp {
                state: AttemptState::Busy
            })
        ));

        // `cleaned` follows a concluded state, so it keeps that state's
        // timestamp and is not a special case.
        let mut cleaned = row(AttemptState::Cleaned, Some(AttemptOutcome::Orphaned));
        cleaned.terminal_at = Some(ts(4));
        assert!(RunnerAttempt::from_persisted(cleaned).is_ok());
    }

    #[test]
    fn a_hand_edited_journal_row_whose_timestamps_run_backwards_is_rejected() {
        // Presence was already gated; ordering was not, so a row saying an
        // attempt concluded a hundred seconds before it was created loaded
        // cleanly and every duration derived from the pair came out negative.
        // The same hand-edited-journal threat model that motivates the presence
        // gate covers this, and `b2` is the task that will meet it.
        let mut concluded_before_created =
            row(AttemptState::Finished, Some(AttemptOutcome::CompletedJob));
        concluded_before_created.created_at = ts(100);
        concluded_before_created.last_state_change_at = ts(100);
        concluded_before_created.terminal_at = Some(ts(0));
        assert_eq!(
            RunnerAttempt::from_persisted(concluded_before_created),
            Err(AttemptError::TimestampsOutOfOrder {
                state: AttemptState::Finished,
                field: "terminal_at",
                created_at: ts(100),
                found: ts(0),
            })
        );

        // The same for the timestamp every recovery timeout is measured from. A
        // `last_state_change_at` before `created_at` makes `now - it` larger
        // than the attempt's whole life, so every timeout reads as expired.
        let mut changed_before_created = row(AttemptState::Busy, None);
        changed_before_created.created_at = ts(100);
        changed_before_created.last_state_change_at = ts(0);
        assert_eq!(
            RunnerAttempt::from_persisted(changed_before_created),
            Err(AttemptError::TimestampsOutOfOrder {
                state: AttemptState::Busy,
                field: "last_state_change_at",
                created_at: ts(100),
                found: ts(0),
            })
        );

        // Equal is not out of order: `allocate` writes the same instant to both,
        // so the very first row of every attempt has `created_at ==
        // last_state_change_at`, and an attempt concluded in the same second it
        // was allocated has all three equal.
        let mut same_instant = row(AttemptState::Failed, Some(AttemptOutcome::Orphaned));
        same_instant.outcome = Some(AttemptOutcome::failed(FailureReason::JitRequestFailed));
        same_instant.created_at = ts(7);
        same_instant.last_state_change_at = ts(7);
        same_instant.terminal_at = Some(ts(7));
        assert!(RunnerAttempt::from_persisted(same_instant).is_ok());

        // And a well-ordered row is untouched by the new arm.
        assert!(
            RunnerAttempt::from_persisted(row(
                AttemptState::Finished,
                Some(AttemptOutcome::CompletedJob)
            ))
            .is_ok()
        );
    }

    #[test]
    fn an_attempt_round_trips_through_its_persisted_form() {
        let mut attempt = RunnerAttempt::allocate(
            AttemptId::from_u128(3),
            PolicyId::from_u128(4),
            "runtime/p/a",
            ts(0),
        );
        attempt.jit_received(ts(1)).unwrap();
        attempt.started(7, ts(2)).unwrap();
        attempt.registered_idle(7, ts(3)).unwrap();
        attempt
            .conclude(AttemptOutcome::ExitedIdleWithoutWork, ts(4))
            .unwrap();

        let restored = RunnerAttempt::from_persisted(attempt.to_persisted())
            .expect("a row this crate produced must load");
        assert_eq!(restored, attempt);
        assert_eq!(restored.terminal_at(), Some(ts(4)));
        assert_ne!(
            restored.last_state_change_at(),
            restored.created_at,
            "the two timestamps must not collapse onto each other; that \
             transposition is what PersistedAttempt exists to prevent"
        );
    }

    #[test]
    fn an_attempt_round_trips_through_serde() {
        let mut attempt = RunnerAttempt::allocate(
            AttemptId::from_u128(3),
            PolicyId::from_u128(4),
            "runtime/p/a",
            ts(0),
        );
        attempt.jit_received(ts(1)).unwrap();
        attempt.started(7, ts(2)).unwrap();
        attempt.registered_idle(73, ts(3)).unwrap();
        attempt
            .conclude(
                AttemptOutcome::failed(FailureReason::Other("no detail".into())),
                ts(4),
            )
            .unwrap();

        let json = serde_json::to_string(&attempt).unwrap();
        let back: RunnerAttempt = serde_json::from_str(&json).unwrap();
        assert_eq!(attempt, back);
    }

    // =======================================================================
    // Ownership
    // =======================================================================

    #[test]
    fn an_attempt_belonging_to_another_host_is_rejected() {
        // Ownership rule 2: "A host agent may act only on attempts persisted
        // under its `host_id`."
        let mine = HostId::from_u128(7);
        let theirs = HostId::from_u128(8);
        let policy_id = PolicyId::from_u128(11);

        let their_policy = a_policy(theirs, policy_id);
        let attempt =
            RunnerAttempt::allocate(AttemptId::from_u128(1), policy_id, "runtime/p/a", ts(0));

        let err = authorize(mine, &their_policy, &attempt).unwrap_err();
        assert!(
            matches!(
                err,
                OwnershipError::ForeignHost {
                    owner,
                    agent,
                    ..
                } if owner == theirs && agent == mine
            ),
            "got {err:?}"
        );

        // The same attempt under our own policy is fine.
        let my_policy = a_policy(mine, policy_id);
        assert!(authorize(mine, &my_policy, &attempt).is_ok());
    }

    #[test]
    fn an_attempt_checked_against_the_wrong_policy_is_rejected() {
        let host = HostId::from_u128(7);
        let policy = a_policy(host, PolicyId::from_u128(11));
        let attempt = RunnerAttempt::allocate(
            AttemptId::from_u128(1),
            PolicyId::from_u128(12),
            "runtime/p/a",
            ts(0),
        );
        assert!(matches!(
            authorize(host, &policy, &attempt),
            Err(OwnershipError::PolicyMismatch { .. })
        ));
    }

    // =======================================================================
    // Recovery, against a controlled clock
    // =======================================================================

    #[test]
    fn recovery_never_reads_the_system_clock() {
        // The whole decision surface moves when the fake clock moves, and by
        // nothing else. If any branch called `Utc::now()` the two decisions below
        // would be identical.
        let timeouts = RecoveryTimeouts::new(
            Elapsed::seconds(60),
            Elapsed::seconds(120),
            Elapsed::seconds(300),
        );
        let attempt = attempt_in(AttemptState::Idle, 1_000);
        let observation = RecoveryObservation {
            process_alive: false,
            github: GithubRunnerObservation::NotRegistered,
        };

        let clock = StubClock::at(1_000 + 299);
        assert_eq!(
            recovery_decision(&attempt, observation, timeouts, &clock),
            RecoveryDecision::Conclude(AttemptOutcome::failed(
                FailureReason::ProcessExitedUnexpectedly
            )),
            "one second before its idle timeout, a vanished runner crashed"
        );

        clock.set(1_000 + 300);
        assert_eq!(
            recovery_decision(&attempt, observation, timeouts, &clock),
            RecoveryDecision::Conclude(AttemptOutcome::ExitedIdleWithoutWork),
            "at its idle timeout, the same runner is the surplus case from flow 2.7"
        );
    }

    #[test]
    fn a_live_process_is_adopted_rather_than_duplicated() {
        // `e3`: "an attempt whose process still runs is adopted, not duplicated."
        let timeouts = RecoveryTimeouts::provisional();
        let clock = StubClock::at(1_000_000);
        for state in [
            AttemptState::Allocated,
            AttemptState::JitReceived,
            AttemptState::Starting,
            AttemptState::Idle,
            AttemptState::Busy,
        ] {
            // `entered_at` is the clock's own instant, so every state is inside
            // its window and the only thing being asserted is the live-process
            // rule.
            let attempt = attempt_in(state, 1_000_000);
            assert_eq!(
                recovery_decision(
                    &attempt,
                    RecoveryObservation {
                        process_alive: true,
                        github: GithubRunnerObservation::NotRegistered,
                    },
                    timeouts,
                    &clock,
                ),
                RecoveryDecision::Adopt,
                "{state} with a live process"
            );
        }
    }

    #[test]
    fn a_dead_busy_attempt_is_orphaned_rather_than_guessed_into_a_success() {
        // The agent never reports a job as complete; GitHub remains the source of
        // truth for workflow outcome (flow 2, Failure).
        let clock = StubClock::at(1_000_000);
        for github in [
            GithubRunnerObservation::NotRegistered,
            GithubRunnerObservation::Registered { busy: true },
            GithubRunnerObservation::Registered { busy: false },
        ] {
            assert_eq!(
                recovery_decision(
                    &attempt_in(AttemptState::Busy, 0),
                    RecoveryObservation {
                        process_alive: false,
                        github,
                    },
                    RecoveryTimeouts::provisional(),
                    &clock,
                ),
                RecoveryDecision::Conclude(AttemptOutcome::Orphaned),
                "{github:?}"
            );
        }
    }

    #[test]
    fn an_unreachable_github_defers_every_decision() {
        // Flow 3.3: while offline, start nothing and retain what is running. An
        // agent that treated "unreachable" as "not registered" would conclude and
        // clean every live attempt during a network outage.
        let clock = StubClock::at(1_000_000);
        for state in [
            AttemptState::Allocated,
            AttemptState::JitReceived,
            AttemptState::Starting,
            AttemptState::Idle,
            AttemptState::Busy,
        ] {
            assert_eq!(
                recovery_decision(
                    &attempt_in(state, 0),
                    RecoveryObservation {
                        process_alive: false,
                        github: GithubRunnerObservation::Unreachable,
                    },
                    RecoveryTimeouts::provisional(),
                    &clock,
                ),
                RecoveryDecision::Defer,
                "{state} while GitHub is unreachable"
            );
        }
    }

    #[test]
    fn a_starting_attempt_follows_what_github_reports() {
        // Precedence rule 3: GitHub runner status is authoritative for remote job
        // status. Both edges are in the diagram.
        let clock = StubClock::at(1_000);
        let attempt = attempt_in(AttemptState::Starting, 0);

        assert_eq!(
            recovery_decision(
                &attempt,
                RecoveryObservation {
                    process_alive: true,
                    github: GithubRunnerObservation::Registered { busy: true },
                },
                RecoveryTimeouts::provisional(),
                &clock,
            ),
            RecoveryDecision::Observe(AttemptState::Busy)
        );
        assert_eq!(
            recovery_decision(
                &attempt,
                RecoveryObservation {
                    process_alive: true,
                    github: GithubRunnerObservation::Registered { busy: false },
                },
                RecoveryTimeouts::provisional(),
                &clock,
            ),
            RecoveryDecision::Observe(AttemptState::Idle)
        );
    }

    #[test]
    fn a_pre_registration_attempt_believes_github_over_its_own_stale_journal() {
        // The crash window `e3` exists for: the process started and registered
        // at GitHub, but the write recording it was lost. GitHub is telling the
        // agent the runner is alive.
        //
        // This branch used to consult only `process_alive` and the clock, so the
        // observation below produced
        // `NoLegalTransition { from: JitReceived, wanted: Failed }` -- the
        // attempt was abandoned as failed while its registration stayed at
        // GitHub, never reconciled and never removed. Nothing in the suite
        // noticed, because nothing asked.
        let timeouts = RecoveryTimeouts::new(
            Elapsed::seconds(60),
            Elapsed::seconds(120),
            Elapsed::seconds(300),
        );
        // Well past the JIT handoff deadline, so the old code's timeout arm is
        // the one being displaced.
        let clock = StubClock::at(10_000);

        for busy in [true, false] {
            assert_eq!(
                recovery_decision(
                    &attempt_in(AttemptState::JitReceived, 0),
                    RecoveryObservation {
                        process_alive: false,
                        github: GithubRunnerObservation::Registered { busy },
                    },
                    timeouts,
                    &clock,
                ),
                RecoveryDecision::Observe(AttemptState::Starting),
                "jit_received + Registered{{busy:{busy}}}: the runner cannot have \
                 registered without starting, and `jit_received -> starting` is \
                 an edge the diagram already has"
            );

            // `allocated` has no `-> starting` edge, so it takes the one legal
            // step it does have. The registration proves the JIT configuration
            // arrived, which is exactly what that edge records; the next pass
            // continues from `jit_received`.
            assert_eq!(
                recovery_decision(
                    &attempt_in(AttemptState::Allocated, 0),
                    RecoveryObservation {
                        process_alive: false,
                        github: GithubRunnerObservation::Registered { busy },
                    },
                    timeouts,
                    &clock,
                ),
                RecoveryDecision::Observe(AttemptState::JitReceived),
                "allocated + Registered{{busy:{busy}}}"
            );
        }

        // Unchanged where GitHub knows nothing: the timeout still decides, and a
        // live process is still adopted rather than duplicated. What changed at
        // the amendment is only what the timeout produces -- a conclusion
        // instead of a report that none was expressible.
        assert_eq!(
            recovery_decision(
                &attempt_in(AttemptState::JitReceived, 0),
                RecoveryObservation {
                    process_alive: false,
                    github: GithubRunnerObservation::NotRegistered,
                },
                timeouts,
                &clock,
            ),
            RecoveryDecision::Conclude(AttemptOutcome::failed(FailureReason::JitExpired))
        );
        assert_eq!(
            recovery_decision(
                &attempt_in(AttemptState::JitReceived, 0),
                RecoveryObservation {
                    process_alive: true,
                    github: GithubRunnerObservation::Registered { busy: false },
                },
                timeouts,
                &clock,
            ),
            RecoveryDecision::Adopt,
            "precedence rule 3's other half: local process state is \
             authoritative for a child process this agent owns"
        );
    }

    #[test]
    fn a_terminal_attempt_is_cleaned_and_a_cleaned_one_is_left_alone() {
        let clock = StubClock::at(1_000_000);
        let observation = RecoveryObservation {
            process_alive: false,
            github: GithubRunnerObservation::NotRegistered,
        };
        for state in [
            AttemptState::Finished,
            AttemptState::Failed,
            AttemptState::Orphaned,
        ] {
            assert_eq!(
                recovery_decision(
                    &attempt_in(state, 0),
                    observation,
                    RecoveryTimeouts::provisional(),
                    &clock
                ),
                RecoveryDecision::Clean,
                "{state}"
            );
        }
        assert_eq!(
            recovery_decision(
                &attempt_in(AttemptState::Cleaned, 0),
                observation,
                RecoveryTimeouts::provisional(),
                &clock
            ),
            RecoveryDecision::Nothing
        );
    }

    #[test]
    fn a_pre_registration_attempt_waits_until_its_deadline_then_concludes() {
        // This test used to document a gap in the state diagram: `allocated`,
        // `jit_received` and `starting` had no edge to `failed` or `orphaned`,
        // so a dead attempt that never registered could not be concluded at all
        // and the decision reported the missing edge instead of inventing one.
        // The 2026-08-21 amendment added those edges, and the whole point of
        // adding them was that this attempt now gives its capacity slot back.
        let timeouts = RecoveryTimeouts::new(
            Elapsed::seconds(60),
            Elapsed::seconds(120),
            Elapsed::seconds(300),
        );
        let clock = StubClock::at(1_059);
        let observation = RecoveryObservation {
            process_alive: false,
            github: GithubRunnerObservation::NotRegistered,
        };

        // The two pre-JIT states conclude with different reasons, because they
        // know different things: at `allocated` no configuration was ever
        // recorded as arriving, at `jit_received` one arrived and was never
        // claimed.
        for (state, reason) in [
            (AttemptState::Allocated, FailureReason::JitRequestFailed),
            (AttemptState::JitReceived, FailureReason::JitExpired),
        ] {
            let attempt = attempt_in(state, 1_000);
            assert_eq!(
                recovery_decision(&attempt, observation, timeouts, &clock),
                RecoveryDecision::Wait,
                "{state} inside its handoff window"
            );
            clock.set(1_060);
            assert_eq!(
                recovery_decision(&attempt, observation, timeouts, &clock),
                RecoveryDecision::Conclude(AttemptOutcome::failed(reason)),
                "{state} past its handoff window concludes rather than stranding \
                 the attempt"
            );
            clock.set(1_059);
        }

        // `starting` past its own, longer deadline: flow 2's "runner exit before
        // job acceptance".
        clock.set(1_121);
        assert_eq!(
            recovery_decision(
                &attempt_in(AttemptState::Starting, 1_000),
                observation,
                timeouts,
                &clock
            ),
            RecoveryDecision::Conclude(AttemptOutcome::failed(
                FailureReason::ProcessExitedUnexpectedly
            ))
        );

        // Every one of those decisions must be applicable to the attempt it was
        // made about; a decision the state machine then refuses would strand the
        // attempt just as the missing edges did.
        for (state, decision) in [
            (
                AttemptState::Allocated,
                AttemptOutcome::failed(FailureReason::JitRequestFailed),
            ),
            (
                AttemptState::JitReceived,
                AttemptOutcome::failed(FailureReason::JitExpired),
            ),
            (
                AttemptState::Starting,
                AttemptOutcome::failed(FailureReason::ProcessExitedUnexpectedly),
            ),
        ] {
            let mut attempt = attempt_in(state, 1_000);
            attempt
                .conclude(decision, ts(1_200))
                .unwrap_or_else(|e| panic!("recovery decided {state} concludes, but: {e}"));
            assert!(!attempt.counts_against_capacity());
        }
    }

    #[test]
    fn an_idle_runner_that_github_reports_as_busy_is_recorded_as_busy() {
        // The `idle -> busy` half of the amendment, at the point it bites in
        // recovery. GitHub is authoritative for remote job status (precedence
        // rule 3), and before the amendment this observation was not
        // representable at all: the decision reported that no legal transition
        // existed and the attempt stayed `idle` for ever while a job ran on it.
        let timeouts = RecoveryTimeouts::provisional();
        let clock = StubClock::at(1_121);
        assert_eq!(
            recovery_decision(
                &attempt_in(AttemptState::Idle, 1_000),
                RecoveryObservation {
                    process_alive: false,
                    github: GithubRunnerObservation::Registered { busy: true },
                },
                timeouts,
                &clock,
            ),
            RecoveryDecision::Observe(AttemptState::Busy)
        );

        // And the decision is applicable: `idle -> busy` is an edge, so the
        // caller can actually carry it out.
        let mut attempt = attempt_in(AttemptState::Idle, 1_000);
        attempt.assigned_job(73, ts(1_200)).unwrap();
        assert_eq!(attempt.state(), AttemptState::Busy);
        assert_eq!(attempt.github_runner_id(), Some(73));

        // And a live process does not change the answer. GitHub is authoritative
        // for remote job status; the caller adopts supervision independently of
        // the decision, which is what `Observe`'s own documentation says and
        // what `starting` has always relied on.
        assert_eq!(
            recovery_decision(
                &attempt_in(AttemptState::Idle, 1_000),
                RecoveryObservation {
                    process_alive: true,
                    github: GithubRunnerObservation::Registered { busy: true },
                },
                timeouts,
                &clock,
            ),
            RecoveryDecision::Observe(AttemptState::Busy),
            "a live process must not hide a job GitHub is reporting"
        );
    }

    #[test]
    fn a_restart_during_a_job_is_recorded_as_busy_and_not_left_reading_idle() {
        // A1. The same conflict -- a live process that GitHub reports as `busy`
        // -- must resolve the same way at `idle` as at `starting`, and this test
        // is written as the damage rather than as the symmetry, because the
        // symmetry is not what it costs to get wrong.
        //
        // Before the fix, `idle` short-circuited on `process_alive` and answered
        // `Adopt`. `Adopt` writes nothing, so the journal stayed `idle` and
        // `last_state_change_at` stayed pointed at the idle entry. Ten minutes
        // later the runner crashed mid-job, GitHub reaped its registration, and
        // the idle timeout had long since elapsed -- so the crash was concluded
        // `ExitedIdleWithoutWork`: the benign surplus exit, which `g2` renders
        // as a normal end and never alarms an operator about. Nothing
        // downstream could refuse it, because `required_from` for that outcome
        // is `&[Idle]` and the attempt genuinely was `idle`.
        let timeouts = RecoveryTimeouts::new(
            Elapsed::seconds(60),
            Elapsed::seconds(120),
            Elapsed::seconds(300),
        );
        let clock = StubClock::at(1_000);

        // The two arms answer alike, which is the property. `starting` was
        // already right; `idle` was not.
        let mid_job = RecoveryObservation {
            process_alive: true,
            github: GithubRunnerObservation::Registered { busy: true },
        };
        assert_eq!(
            recovery_decision(
                &attempt_in(AttemptState::Idle, 1_000),
                mid_job,
                timeouts,
                &clock
            ),
            recovery_decision(
                &attempt_in(AttemptState::Starting, 1_000),
                mid_job,
                timeouts,
                &clock
            ),
            "the same observation must not resolve one way at idle and the \
             opposite way one state earlier"
        );
        assert_eq!(
            recovery_decision(
                &attempt_in(AttemptState::Idle, 1_000),
                mid_job,
                timeouts,
                &clock
            ),
            RecoveryDecision::Observe(AttemptState::Busy)
        );

        // And now the consequence, walked end to end. The caller applies the
        // decision -- which `Observe` requires, on pain of repeating for ever --
        // and the attempt is `busy` with `last_state_change_at` moved to the
        // moment the job was observed.
        let mut attempt = attempt_in(AttemptState::Idle, 1_000);
        attempt.assigned_job(73, ts(1_000)).expect("idle -> busy");
        assert_eq!(attempt.last_state_change_at(), ts(1_000));

        // Ten minutes on, the process is gone and GitHub has reaped the runner.
        // Well past the idle timeout, and irrelevant: a crash from `busy` is
        // `Orphaned`, and `ExitedIdleWithoutWork` is not reachable from `busy`
        // at all.
        clock.set(1_600);
        let crashed = RecoveryObservation {
            process_alive: false,
            github: GithubRunnerObservation::NotRegistered,
        };
        let decision = recovery_decision(&attempt, crashed, timeouts, &clock);
        assert_eq!(
            decision,
            RecoveryDecision::Conclude(AttemptOutcome::Orphaned),
            "a crash during a job is a lost supervision, never the surplus exit"
        );
        let RecoveryDecision::Conclude(outcome) = decision else {
            unreachable!("asserted just above")
        };
        assert!(
            outcome.is_failure() && !outcome.is_idle_exit(),
            "`g2` reads these two flags to decide whether to alarm an operator, \
             and a mid-job crash must alarm one"
        );

        // The old behaviour, spelled out so the regression is unmistakable: had
        // the attempt been left at `idle`, this is what the same crash would
        // have produced.
        assert_eq!(
            recovery_decision(
                &attempt_in(AttemptState::Idle, 1_000),
                crashed,
                timeouts,
                &clock
            ),
            RecoveryDecision::Conclude(AttemptOutcome::ExitedIdleWithoutWork),
            "which is exactly why the journal must not be left saying `idle`"
        );
    }

    #[test]
    fn a_live_unregistered_runner_past_its_deadline_is_stopped_before_its_slot_returns() {
        // A2. Three cases at `starting` with nothing at GitHub, and the middle
        // one used to be folded into the last.
        let timeouts = RecoveryTimeouts::new(
            Elapsed::seconds(60),
            Elapsed::seconds(120),
            Elapsed::seconds(300),
        );
        let clock = StubClock::at(1_000);
        let attempt = attempt_in(AttemptState::Starting, 1_000);
        let unregistered = |alive| RecoveryObservation {
            process_alive: alive,
            github: GithubRunnerObservation::NotRegistered,
        };

        // Inside the window, alive: adopted.
        clock.set(1_119);
        assert_eq!(
            recovery_decision(&attempt, unregistered(true), timeouts, &clock),
            RecoveryDecision::Adopt
        );

        // Gone: an accurate `ProcessExitedUnexpectedly`, and terminal, because
        // there is nothing left running to hold the slot.
        assert_eq!(
            recovery_decision(&attempt, unregistered(false), timeouts, &clock),
            RecoveryDecision::Conclude(AttemptOutcome::failed(
                FailureReason::ProcessExitedUnexpectedly
            )),
            "the one case that really is flow 2's runner exit"
        );

        // Alive and past the deadline: neither of the above.
        clock.set(1_120);
        let decision = recovery_decision(&attempt, unregistered(true), timeouts, &clock);
        assert_eq!(
            decision,
            RecoveryDecision::Terminate(AttemptOutcome::failed(
                FailureReason::RegistrationTimedOut
            ))
        );
        assert_ne!(
            decision,
            RecoveryDecision::Conclude(AttemptOutcome::failed(
                FailureReason::ProcessExitedUnexpectedly
            )),
            "a process visible in a task manager did not exit unexpectedly, and \
             an operator told that it did stops believing the next message too"
        );

        // The substance: the slot is not returned while the process runs. The
        // decision itself moves nothing, so the attempt is still `starting` and
        // still counted -- which is what stops the agent starting a replacement
        // beside a runner that could still register and take a job.
        let mut attempt = attempt;
        assert!(attempt.counts_against_capacity());
        assert_eq!(active_count([&attempt]), 1);

        // The slot comes back at the moment the caller applies the payload,
        // which it does only after the process is gone.
        let RecoveryDecision::Terminate(outcome) = decision else {
            unreachable!("asserted above")
        };
        attempt
            .conclude(outcome, ts(1_130))
            .expect("the payload must be applicable to the attempt it was made about");
        assert_eq!(attempt.state(), AttemptState::Failed);
        assert!(!attempt.counts_against_capacity());
        assert_eq!(active_count([&attempt]), 0);

        // And the decision is re-derivable: an agent that died between deciding
        // and terminating is handed the same answer next pass, while one that
        // terminated but crashed before writing sees a dead process and reaches
        // the ordinary conclusion, whose wording is by then true.
        let pending = attempt_in(AttemptState::Starting, 1_000);
        assert_eq!(
            recovery_decision(&pending, unregistered(true), timeouts, &clock),
            RecoveryDecision::Terminate(AttemptOutcome::failed(
                FailureReason::RegistrationTimedOut
            ))
        );
        assert_eq!(
            recovery_decision(&pending, unregistered(false), timeouts, &clock),
            RecoveryDecision::Conclude(AttemptOutcome::failed(
                FailureReason::ProcessExitedUnexpectedly
            ))
        );
    }

    #[test]
    fn the_two_starting_failures_read_differently_to_an_operator() {
        // `g2` renders `FailureReason` directly, and these two send an operator
        // in different directions: one to a crash investigation, the other to a
        // networking or configuration fix. Reaching for `Other` here instead of
        // a named variant would have put a free-form string on the same path.
        let exited = FailureReason::ProcessExitedUnexpectedly.to_string();
        let timed_out = FailureReason::RegistrationTimedOut.to_string();
        assert_ne!(exited, timed_out);
        assert!(
            timed_out.contains("running") && timed_out.contains("register"),
            "the message must say the process is up and unregistered: {timed_out}"
        );
        assert!(
            !timed_out.contains("exited"),
            "the whole point is that nothing exited: {timed_out}"
        );
        assert!(
            !matches!(FailureReason::RegistrationTimedOut, FailureReason::Other(_)),
            "a known, named condition must not travel through the escape hatch"
        );
    }

    #[test]
    fn a_dead_idle_runner_still_registered_at_github_is_orphaned() {
        let clock = StubClock::at(1_000_000);
        assert_eq!(
            recovery_decision(
                &attempt_in(AttemptState::Idle, 0),
                RecoveryObservation {
                    process_alive: false,
                    github: GithubRunnerObservation::Registered { busy: false },
                },
                RecoveryTimeouts::provisional(),
                &clock,
            ),
            RecoveryDecision::Conclude(AttemptOutcome::Orphaned),
            "the remote registration outlived our process and needs removing"
        );
    }
}
