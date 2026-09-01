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
use crate::workspace::{AttemptWorkspace, WorkspaceError, WorkspaceKind};

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

    /// A stored workspace kind and slot that cannot describe one allocation, so
    /// the legal cleanup algorithm for the journalled path is undecidable.
    #[error(transparent)]
    Workspace(#[from] WorkspaceError),

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
/// Those edges are also what make seven of the nine [`FailureReason`] variants
/// reachable at all — `JitRequestFailed`, `JitExpired`,
/// `RunnerPackageUnverified`, `RunnerVersionRejected`, `ProcessStartFailed`,
/// `RegistrationTimedOut` and `TerminatedAfterRegistrationTimeout` each occur at
/// a pre-registration state. `03-control-flows.md` flow 2 names the first five
/// as conditions the agent must record; the last two are named by no document
/// and are this crate's own, added because [`recovery_decision`] needs to say
/// "alive, past its deadline, still unregistered" without calling it a crash,
/// and because `e3` then needs to say what became of that runner without
/// calling a process it stopped itself either a crash or still running.
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
    /// The agent stopped a runner process that had not registered inside its
    /// startup window.
    ///
    /// **The dead-process counterpart of [`Self::RegistrationTimedOut`], and it
    /// exists because that one cannot be reused here.** By the time this reason
    /// is recorded the process is gone — the agent signalled it — so rendering
    /// "the runner process is running but did not register" would tell an
    /// operator a process is up that they can see is not. That is the same false
    /// liveness claim [`Self::ProcessExitedUnexpectedly`]'s documentation says
    /// spends the credibility of every other message this product prints, and
    /// `tests::no_decision_calls_a_dead_process_live` is what holds the line.
    ///
    /// **It points where [`Self::RegistrationTimedOut`] points, not where
    /// [`Self::ProcessExitedUnexpectedly`] points.** The runner never reached
    /// GitHub — a proxy, a firewall, a DNS answer, an expired or wrong-scoped
    /// configuration — and the exit is the agent's own doing rather than
    /// evidence of a crash. An operator sent to logs and exit codes for this is
    /// investigating the wrong machine.
    ///
    /// **Who records it.** `e3`, and only `e3`. [`recovery_decision`] cannot
    /// derive it: a process this agent killed and a process that crashed on its
    /// own present the *same* [`RecoveryObservation`], so the distinguishing
    /// fact has to be journalled as terminate-intent before the signal is sent
    /// and read back afterwards. See [`RecoveryDecision::Terminate`] for the
    /// window that obligation closes.
    TerminatedAfterRegistrationTimeout,
    /// Anything else. Must carry no credential.
    Other(String),
}

impl FailureReason {
    /// One value of every variant, the counterpart of [`AttemptState::ALL`].
    ///
    /// `Other`'s detail is empty because what a caller enumerates is the
    /// *variant*; no consumer should read the string out of this constant.
    ///
    /// **This list is hand-written, and what keeps it honest is not its own
    /// length.** A length written as `9` next to nine elements asserts
    /// nothing — that was the defect in the assertion this constant replaced.
    /// What catches a new variant is the exhaustive, wildcard-free `match` in
    /// `tests::earliest_state_producing`, which stops the test target compiling
    /// the moment one is added and so puts the author in front of this list.
    ///
    /// **The residual gap, measured rather than assumed.** An author who adds a
    /// variant, writes its `Display` arm and its `earliest_state_producing` arm,
    /// and then adds it to *neither* this constant nor the test's `cases` table,
    /// gets a green suite with the variant untested. Adding it to exactly one of
    /// the two fails the length check; adding it to neither does not.
    ///
    /// Re-measured when `TerminatedAfterRegistrationTimeout` was added, because
    /// a gap described once and never re-run is a gap nobody knows still exists.
    /// With the variant declared and both match arms written but neither list
    /// touched, `cargo test -p runner-manager-domain` was green — its lib target
    /// reported `128 passed; 0 failed` — with the ninth variant unreachable and
    /// untested. Adding it to this constant alone then failed the length check
    /// with `left: 8 / right: 9`.
    ///
    /// **And the compiler never points at this constant.** A `const` array is
    /// unaffected by a new variant, so nothing here errors. What stops the
    /// author is `Display::fmt`'s match (`E0004`) and then
    /// `tests::earliest_state_producing`'s, and neither of those mentions this
    /// list — which is why a note pointing back here sits at each of those two
    /// match sites, where the author is actually standing.
    ///
    /// **This is closable in stable Rust, and is hand-written anyway.** A local
    /// `macro_rules!` that declares the enum and emits `ALL` from the same
    /// variant list needs no dependency and no unstable feature
    /// (`std::mem::variant_count` is unstable, but a declarative macro is not
    /// the same thing). It is not used here because every variant of this enum
    /// carries several paragraphs of its own documentation explaining what an
    /// operator should do about it, and variants declared inside a macro
    /// invocation are markedly worse to read and to `rustdoc`. That is a
    /// legibility trade, deliberately taken — not an impossibility. If the
    /// documentation ever thins out, the macro is the better answer.
    pub const ALL: [FailureReason; 9] = [
        FailureReason::JitRequestFailed,
        FailureReason::JitExpired,
        FailureReason::RunnerPackageUnverified,
        FailureReason::RunnerVersionRejected,
        FailureReason::ProcessStartFailed,
        FailureReason::ProcessExitedUnexpectedly,
        FailureReason::RegistrationTimedOut,
        FailureReason::TerminatedAfterRegistrationTimeout,
        FailureReason::Other(String::new()),
    ];
}

impl fmt::Display for FailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Adding a variant? This `E0004` is where the compiler stops you, and it
        // is the *only* place it does for `FailureReason::ALL`, which is a const
        // array and errors nowhere. Add the variant to `ALL` and to the `cases`
        // table in `tests::all_failure_reasons_are_reachable_from_the_state_that
        // _produces_them` as well, or it ships untested and unreachable.
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
            // Past tense, and no claim that anything is still running: by the
            // time this is recorded the agent has signalled the process and the
            // operator can see it is gone. `tests::a_terminated_runner_is_never
            // _described_as_running` pins that.
            FailureReason::TerminatedAfterRegistrationTimeout => f.write_str(
                "the agent stopped the runner process after it failed to \
                 register with GitHub before its startup deadline",
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
    /// Which cleanup algorithm this attempt's directory is entitled to, and the
    /// slot it leases if any.
    ///
    /// Immutable after allocation, by `02-target-architecture.md`: "The
    /// workspace kind and slot number tell recovery which cleanup algorithm is
    /// legal. Neither may change after allocation." Private with no setter is
    /// how that is enforced — a mutable kind would let a running attempt convert
    /// a disposable directory into a retained one, which is exactly the
    /// two-job contamination path `04-security-recovery.md` measures.
    workspace: AttemptWorkspace,
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
    /// `ephemeral` or `persistent`, stored beside the slot below.
    pub workspace_kind: WorkspaceKind,
    /// The leased slot: `Some` exactly when `workspace_kind` is `persistent`,
    /// and positive. It is a raw `u16` here rather than a `NonZeroU16` so that
    /// the `0` a hand-edited row can hold is refused by
    /// [`AttemptWorkspace::from_persisted`] instead of being unrepresentable at
    /// the column boundary and panicking somewhere else.
    pub workspace_slot: Option<u16>,
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
            workspace_kind: self.workspace.kind(),
            workspace_slot: self.workspace.slot_number(),
            created_at: self.created_at,
            terminal_at: self.terminal_at,
            last_state_change_at: self.last_state_change_at,
        }
    }

    /// The first step of `e3`'s per-attempt flow: a runtime directory is
    /// allocated and journalled **before** anything remote happens, so a crash
    /// leaves a recoverable trace rather than an invisible one.
    /// D3 keeps this the disposable path: an attempt allocated through it is
    /// [`AttemptWorkspace::Ephemeral`], so every existing caller and test goes on
    /// producing the behaviour it produced before persistent slots existed.
    /// [`Self::allocate_in`] is the one that leases a slot.
    #[must_use]
    pub fn allocate(
        id: AttemptId,
        policy_id: PolicyId,
        runtime_path: impl Into<PathBuf>,
        now: Timestamp,
    ) -> Self {
        Self::allocate_in(
            id,
            policy_id,
            runtime_path,
            AttemptWorkspace::Ephemeral,
            now,
        )
    }

    /// The same first step, recording which workspace the directory came from.
    ///
    /// `c2` calls this with [`AttemptWorkspace::PersistentSlot`] while holding
    /// the host allocation lock, so the slot lease is journalled "before package
    /// or GitHub effects" and a crash between the two leaves a recoverable trace
    /// rather than an orphaned slot.
    #[must_use]
    pub fn allocate_in(
        id: AttemptId,
        policy_id: PolicyId,
        runtime_path: impl Into<PathBuf>,
        workspace: AttemptWorkspace,
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
            workspace,
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
            workspace_kind,
            workspace_slot,
            created_at,
            terminal_at,
            last_state_change_at,
        } = fields;

        // The workspace pair is checked first because it decides which cleanup
        // algorithm recovery is allowed to run on `runtime_path`. A row that
        // claims `persistent` with no slot, or `ephemeral` with one, names a
        // directory whose safe cleanup is undecidable, and
        // `04-security-recovery.md` requires that to fail closed rather than to
        // fall back to the destructive branch.
        let workspace = AttemptWorkspace::from_persisted(workspace_kind, workspace_slot)?;

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
            workspace,
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

    /// The immutable allocation fact: disposable, or the persistent slot leased.
    ///
    /// There is no setter. Cleanup and recovery dispatch on this
    /// (`02-target-architecture.md`, "Cleanup and recovery"), so a value that
    /// could be changed after allocation would let the algorithm chosen for a
    /// directory disagree with the one it was created under.
    #[must_use]
    pub const fn workspace(&self) -> AttemptWorkspace {
        self.workspace
    }

    /// Whether this attempt holds a persistent slot lease.
    ///
    /// Every uncleaned persistent attempt is a lease, including a terminal one
    /// whose cleanup failed — which is why this asks about the workspace and not
    /// about the state.
    #[must_use]
    pub const fn holds_slot_lease(&self) -> bool {
        self.workspace.is_persistent() && !matches!(self.state, AttemptState::Cleaned)
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
    /// How long `idle` may last, in both directions it is read.
    ///
    /// For an attempt whose process is already gone it separates the two
    /// readings of that exit: past this, the surplus case; before it, a crash.
    ///
    /// For one whose process is still alive and still registered it is a
    /// deadline rather than a reading — the point at which the agent stops the
    /// runner itself. Nothing else does: `Runner.Listener run` long-polls for
    /// an assignment indefinitely, so this value, and only this value, bounds
    /// how long a runner that never gets a job holds its capacity slot and its
    /// entry in the target's runner settings.
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

    /// Placeholder values, with one exception — see the type documentation.
    ///
    /// `idle` is no longer a placeholder. It stopped being one when it became
    /// the only thing that bounds a live runner: five minutes is long enough
    /// that a runner GitHub is about to assign is not stopped out from under
    /// the assignment, and short enough that a machine does not carry an
    /// unusable slot, and a repository an unusable runner row, for hours. The
    /// other two still only separate readings of an event that already
    /// happened, and nothing here has had to decide what they should be.
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
    /// **Two producers, and the payload is what separates them.** `starting`
    /// past its registration timeout carries
    /// [`FailureReason::RegistrationTimedOut`]; `idle` past its idle timeout,
    /// with GitHub still reporting the runner registered and unassigned,
    /// carries [`AttemptOutcome::ExitedIdleWithoutWork`] — flow 2.7's surplus
    /// runner, which is a normal outcome and not a failure at all. The two
    /// share this variant because they need the identical *sequence* — signal,
    /// confirm the process is gone, then record — and differ only in what is
    /// recorded at the end. A caller that hardcodes either reason will
    /// mislabel the other, so the payload is the caller's instruction, not
    /// decoration.
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
    /// **It is safe to re-derive in one direction, and owes a debt in the
    /// other.** The decision is a pure function of the journalled state and the
    /// observation, so an agent that dies *before* terminating sees a live
    /// process and a larger `elapsed` on the next pass and is handed this same
    /// decision again. That half costs nothing and needs nothing.
    ///
    /// **The other half is a known defect, and it is not harmless.** An agent
    /// that terminates the process and then dies *before* writing the outcome
    /// observes `process_alive: false` next time and reaches the ordinary
    /// [`Self::Conclude`] arm, which records
    /// [`FailureReason::ProcessExitedUnexpectedly`]. The process did not exit
    /// unexpectedly; this agent killed it. That is precisely the diagnosis
    /// [`FailureReason::RegistrationTimedOut`] was split out to prevent — the
    /// two reasons send an operator to different places, and this window sends
    /// them to a crash investigation (logs, exit code, a corrupt package) for
    /// what was a registration failure.
    ///
    /// **It cannot be fixed here, and the alternative was weighed rather than
    /// waved off.** This function's inputs are the journalled state and a
    /// [`RecoveryObservation`], and neither carries the fact that separates the
    /// two cases: a process this agent killed and a process that crashed on its
    /// own present the *same observation*. Using `RegistrationTimedOut` in the
    /// dead-process arm once `elapsed >= startup` would close this window at the
    /// price of a wider one — every genuine early crash first observed after a
    /// restart longer than the startup window would then be reported as a runner
    /// that "is running but did not register", to an operator who can see that
    /// it is not running. That trades a rare wrong reason for a common false
    /// claim about liveness, in the one direction
    /// [`FailureReason::ProcessExitedUnexpectedly`]'s own documentation says
    /// spends the credibility of every other message this product prints.
    /// `tests::no_decision_calls_a_dead_process_live` is what stops that trade
    /// being made by accident later.
    ///
    /// **So the obligation is `e3`'s, and it is a persistence one.** The
    /// distinguishing fact exists only at the moment terminate-intent is formed,
    /// and the only way to carry it across a crash is to write it down. `e3`
    /// journals the intent *before* it signals the process, and on a later pass
    /// concludes an attempt it finds so marked with
    /// [`FailureReason::TerminatedAfterRegistrationTimeout`] rather than with
    /// whatever this function derived from an observation that could not know.
    /// Until `e3` does that, the window stands.
    ///
    /// **Why that closure needs a reason of its own, and not
    /// `RegistrationTimedOut`.** On the pass where `e3` reads the mark back, the
    /// process is dead — `e3` killed it, which is the whole reason the mark is
    /// there. `RegistrationTimedOut` renders as "the runner process is running
    /// but did not register", so concluding with it would print exactly the
    /// false liveness claim the paragraph above rejects option A for: the same
    /// sentence, about a process an operator can see is gone, moved one pass
    /// later. Rewording that string instead is not open either —
    /// `tests::the_two_starting_failures_read_differently_to_an_operator` pins
    /// it on "running", which is correct for the live case it names.
    ///
    /// [`FailureReason::TerminatedAfterRegistrationTimeout`] is that reason.
    /// It is true of a dead process, it says who stopped it and why, and it
    /// sends an operator to the networking and configuration fix rather than to
    /// a crash investigation — which is the whole distinction
    /// [`FailureReason::RegistrationTimedOut`] was split out to draw. Nothing in
    /// this function derives it, and nothing should: it is a claim about an
    /// action this agent took, not about anything a [`RecoveryObservation`]
    /// reports. `tests::no_decision_calls_a_dead_process_live` covers it
    /// alongside the other two liveness-claiming reasons, so the day something
    /// here does start deriving it — which it legitimately might, once the mark
    /// is journalled where this function can read it — it may only do so beside
    /// a process the observation says is gone.
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
            //
            // The dead-process arm below carries a residual this arm cannot
            // close: an agent that terminated the process and died before
            // writing the outcome lands there and records
            // `ProcessExitedUnexpectedly` for a process it killed itself. The
            // fact that would separate the two is not in this function's
            // inputs -- a killed process and a crashed one are the same
            // observation -- so the fix is `e3` journalling terminate-intent
            // before signalling and concluding the marked attempt with
            // `FailureReason::TerminatedAfterRegistrationTimeout`, not a
            // rearrangement here. That reason exists precisely because the
            // process is gone by then, so the closure cannot reuse
            // `RegistrationTimedOut` without printing the same false liveness
            // claim one pass later. See `RecoveryDecision::Terminate`, which
            // names the trade and the owner, and
            // `tests::no_decision_calls_a_dead_process_live`, which reds if
            // somebody closes it here instead.
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
            // A dead process means supervision is lost while the remote
            // registration outlived it and needs removing.
            //
            // A *live* one is adopted only while it is still inside the idle
            // timeout. Past it, this is flow 2.7's surplus runner and the agent
            // has to end it, because nothing else will: the runner is spawned as
            // a bare `Runner.Listener run`, and that process has no idle timeout
            // of its own -- it long-polls for an assignment until something
            // stops it. This arm used to answer `Adopt` for every elapsed time,
            // which is why it never was stopped. A registered, unassigned runner
            // then holds its capacity slot and its entry in the target's runner
            // settings for as long as the host stays up; one observed in the
            // field sat here for 27 hours across two restarts of nothing.
            //
            // `Terminate`, not `Conclude`: the process is alive, so the slot may
            // not be returned until it is gone. The caller signals it, re-reads
            // liveness, and only then applies the payload -- the same sequence
            // `starting` above relies on, and the reason that decision carries
            // its outcome rather than the caller deriving one.
            G::Registered { busy: false } => {
                if !observation.process_alive {
                    RecoveryDecision::Conclude(AttemptOutcome::Orphaned)
                } else if elapsed >= timeouts.idle {
                    RecoveryDecision::Terminate(AttemptOutcome::ExitedIdleWithoutWork)
                } else {
                    RecoveryDecision::Adopt
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
    /// with the new variant unreachable and untested. Here, a tenth variant
    /// stops this file compiling until somebody says which state produces it,
    /// and `all_failure_reasons_are_reachable_from_the_state_that_produces_them`
    /// then proves the answer.
    ///
    /// Re-measured on the ninth. Declaring
    /// `TerminatedAfterRegistrationTimeout` and changing nothing else produced
    /// exactly one error, `E0004` at `Display`'s match; writing that arm
    /// produced exactly one more, `E0004` here; writing this one left
    /// `cargo check --all-targets --workspace` clean. Two stops, in that order,
    /// and no third — which is what the note above each of them promises.
    fn earliest_state_producing(reason: &FailureReason) -> AttemptState {
        // The second place a new variant stops the compiler, and the last one.
        // `FailureReason::ALL` is a const array, so it errors nowhere at all:
        // add the variant to `ALL` and to the `cases` table below too, or the
        // suite goes green with it untested.
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
            // The same attempt one step later: still `starting`, because the
            // agent acts on the `Terminate` payload without moving the state
            // first, and the process it signalled is the one that never
            // registered.
            FailureReason::TerminatedAfterRegistrationTimeout => AttemptState::Starting,
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
        let cases: [(FailureReason, AttemptState); 9] = [
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
            // The same runner after `e3` acted on the `Terminate` payload: the
            // attempt never left `starting`, so this is where it concludes from.
            (
                FailureReason::TerminatedAfterRegistrationTimeout,
                AttemptState::Starting,
            ),
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
    // Workspace allocation (D3, D5, D6)
    // =======================================================================

    fn slot(n: u16) -> AttemptWorkspace {
        AttemptWorkspace::persistent_slot(std::num::NonZeroU16::new(n).expect("a positive slot"))
    }

    /// The unremarkable outcome for a terminal state, so a fixture does not have
    /// to restate the state/outcome pairing the loader enforces.
    fn terminal_outcome(state: AttemptState) -> AttemptOutcome {
        match state {
            AttemptState::Failed => {
                AttemptOutcome::failed(FailureReason::ProcessExitedUnexpectedly)
            }
            AttemptState::Orphaned => AttemptOutcome::Orphaned,
            _ => AttemptOutcome::CompletedJob,
        }
    }

    #[test]
    fn the_ordinary_constructor_still_allocates_a_disposable_workspace() {
        // D3: disposable mode remains the default, so every existing caller of
        // `allocate` keeps the cleanup behaviour it had.
        let attempt = RunnerAttempt::allocate(
            AttemptId::from_u128(1),
            PolicyId::from_u128(1),
            "runtime/p/a",
            ts(0),
        );
        assert_eq!(attempt.workspace(), AttemptWorkspace::Ephemeral);
        assert_eq!(attempt.workspace().slot(), None);
        assert!(!attempt.holds_slot_lease());
        assert_eq!(
            attempt.to_persisted().workspace_kind,
            WorkspaceKind::Ephemeral
        );
        assert_eq!(attempt.to_persisted().workspace_slot, None);
    }

    #[test]
    fn a_persistent_attempt_journals_the_slot_it_leased() {
        let attempt = RunnerAttempt::allocate_in(
            AttemptId::from_u128(1),
            PolicyId::from_u128(1),
            "/srv/rman/acme/s2",
            slot(2),
            ts(0),
        );
        assert_eq!(attempt.workspace(), slot(2));
        assert_eq!(attempt.workspace().slot_number(), Some(2));
        assert_eq!(
            attempt.workspace().slot_directory_name().as_deref(),
            Some("s2")
        );
        assert_eq!(attempt.runtime_path(), Path::new("/srv/rman/acme/s2"));
        assert!(attempt.holds_slot_lease());
    }

    #[test]
    fn the_workspace_kind_and_slot_do_not_change_after_allocation() {
        // `02-target-architecture.md`: "Neither may change after allocation."
        // There is no setter, so the property is proved by driving the whole
        // lifecycle and reading the value back at every step.
        let mut attempt = RunnerAttempt::allocate_in(
            AttemptId::from_u128(1),
            PolicyId::from_u128(1),
            "/srv/rman/acme/s1",
            slot(1),
            ts(0),
        );
        attempt
            .jit_received(ts(1))
            .expect("allocated -> jit_received");
        assert_eq!(attempt.workspace(), slot(1));
        attempt
            .started(4242, ts(2))
            .expect("jit_received -> starting");
        assert_eq!(attempt.workspace(), slot(1));
        attempt
            .registered_idle(73, ts(3))
            .expect("starting -> idle");
        assert_eq!(attempt.workspace(), slot(1));
        attempt.assigned_job(73, ts(4)).expect("idle -> busy");
        assert_eq!(attempt.workspace(), slot(1));
        attempt
            .conclude(AttemptOutcome::CompletedJob, ts(5))
            .expect("busy -> finished");
        assert_eq!(attempt.workspace(), slot(1));
        assert!(
            attempt.holds_slot_lease(),
            "a terminal attempt still holds its slot until cleanup succeeds"
        );

        attempt.clean(ts(6)).expect("finished -> cleaned");
        assert_eq!(attempt.workspace(), slot(1));
        assert!(
            !attempt.holds_slot_lease(),
            "a cleaned attempt releases the slot for reuse"
        );
    }

    #[test]
    fn an_uncleaned_terminal_attempt_keeps_its_lease() {
        // `04-security-recovery.md`: "Attempt remains not-cleaned and continues
        // to hold the slot through the unique lease index".
        for state in [
            AttemptState::Finished,
            AttemptState::Failed,
            AttemptState::Orphaned,
        ] {
            let mut fields = row(state, Some(terminal_outcome(state)));
            fields.workspace_kind = WorkspaceKind::Persistent;
            fields.workspace_slot = Some(3);
            let attempt = RunnerAttempt::from_persisted(fields).expect("a row the domain accepts");
            assert!(attempt.holds_slot_lease(), "state {state}");
        }
    }

    #[test]
    fn a_workspace_allocation_round_trips_through_the_journal() {
        for workspace in [AttemptWorkspace::Ephemeral, slot(1), slot(u16::MAX)] {
            let attempt = RunnerAttempt::allocate_in(
                AttemptId::from_u128(1),
                PolicyId::from_u128(1),
                "runtime/p/a",
                workspace,
                ts(0),
            );
            let restored = RunnerAttempt::from_persisted(attempt.to_persisted())
                .expect("a row this crate wrote must load");
            assert_eq!(restored, attempt);
            assert_eq!(restored.workspace(), workspace);
        }
    }

    #[test]
    fn a_journal_row_whose_workspace_columns_disagree_is_rejected() {
        // The kind decides which cleanup algorithm is legal, so an undecidable
        // pair must fail closed rather than fall back to the destructive branch.
        let mut persistent_without_slot = row(AttemptState::Allocated, None);
        persistent_without_slot.workspace_kind = WorkspaceKind::Persistent;
        assert_eq!(
            RunnerAttempt::from_persisted(persistent_without_slot),
            Err(AttemptError::Workspace(
                WorkspaceError::PersistentWithoutSlot
            ))
        );

        let mut zero_slot = row(AttemptState::Allocated, None);
        zero_slot.workspace_kind = WorkspaceKind::Persistent;
        zero_slot.workspace_slot = Some(0);
        assert_eq!(
            RunnerAttempt::from_persisted(zero_slot),
            Err(AttemptError::Workspace(WorkspaceError::SlotNotPositive))
        );

        let mut ephemeral_with_slot = row(AttemptState::Allocated, None);
        ephemeral_with_slot.workspace_slot = Some(1);
        assert_eq!(
            RunnerAttempt::from_persisted(ephemeral_with_slot),
            Err(AttemptError::Workspace(WorkspaceError::EphemeralWithSlot {
                slot: 1
            }))
        );
    }

    #[test]
    fn an_attempt_serialises_its_workspace_without_credentials() {
        let attempt = RunnerAttempt::allocate_in(
            AttemptId::from_u128(1),
            PolicyId::from_u128(1),
            "/srv/rman/acme/s2",
            slot(2),
            ts(0),
        );
        let encoded = serde_json::to_string(&attempt).expect("serialisable");
        let decoded: RunnerAttempt = serde_json::from_str(&encoded).expect("deserialisable");
        assert_eq!(decoded, attempt);
        for needle in ["token", "secret", "jitconfig", "password"] {
            assert!(
                !encoded.to_ascii_lowercase().contains(needle),
                "an attempt leaked {needle:?}: {encoded}"
            );
        }
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
            workspace_kind: WorkspaceKind::Ephemeral,
            workspace_slot: None,
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
    fn a_registered_runner_that_never_gets_a_job_is_stopped_at_its_idle_timeout() {
        // The surplus case of flow 2.7, in the shape it actually occurs in:
        // GitHub still lists the runner, it is not busy, and the process is
        // very much alive -- `Runner.Listener run` long-polls for an assignment
        // and has no idle timeout of its own, so it never leaves on its own.
        // This arm answered `Adopt` at every elapsed time, which is why a runner
        // observed in the field held its slot and its row in the target's runner
        // settings for 27 hours.
        let timeouts = RecoveryTimeouts::new(
            Elapsed::seconds(60),
            Elapsed::seconds(120),
            Elapsed::seconds(300),
        );
        let clock = StubClock::at(1_000);
        let attempt = attempt_in(AttemptState::Idle, 1_000);
        let idle_registered = |alive| RecoveryObservation {
            process_alive: alive,
            github: GithubRunnerObservation::Registered { busy: false },
        };

        // Inside the window the runner is still plausibly about to be assigned,
        // so it is adopted and nothing is disturbed.
        clock.set(1_299);
        assert_eq!(
            recovery_decision(&attempt, idle_registered(true), timeouts, &clock),
            RecoveryDecision::Adopt,
            "a runner one second inside its idle timeout may still be given a job"
        );

        // At the deadline it is surplus, and the agent has to end it.
        clock.set(1_300);
        let decision = recovery_decision(&attempt, idle_registered(true), timeouts, &clock);
        assert_eq!(
            decision,
            RecoveryDecision::Terminate(AttemptOutcome::ExitedIdleWithoutWork),
            "past the idle timeout a registered, unassigned runner is flow 2.7's surplus case"
        );

        // `Terminate`, not `Conclude`, and the difference is the capacity slot:
        // the process is alive, so the slot may not come back until it is gone.
        let mut attempt = attempt;
        assert!(attempt.counts_against_capacity());
        let RecoveryDecision::Terminate(outcome) = decision else {
            unreachable!("asserted above")
        };
        assert!(
            outcome.is_idle_exit(),
            "the surplus exit is a normal outcome, and `g2` renders it as one -- an operator \
             sent to hunt a fault here would find nothing"
        );
        attempt
            .conclude(outcome, ts(1_310))
            .expect("the payload must be applicable to the attempt it was made about");
        assert!(!attempt.counts_against_capacity());

        // A dead process is the pre-existing reading and is left alone: the
        // registration outlived supervision, which is what `Orphaned` names.
        clock.set(1_400);
        assert_eq!(
            recovery_decision(
                &attempt_in(AttemptState::Idle, 1_000),
                idle_registered(false),
                timeouts,
                &clock
            ),
            RecoveryDecision::Conclude(AttemptOutcome::Orphaned),
            "the idle deadline governs a live runner; a dead one is orphaned however long it sat"
        );

        // And a runner GitHub reports busy is never stopped, at any elapsed
        // time. This is the assertion that stops the deadline above from ever
        // being applied to a runner in the middle of a job.
        for offset in [0, 299, 300, 100_000] {
            clock.set(1_000 + offset);
            assert_eq!(
                recovery_decision(
                    &attempt_in(AttemptState::Idle, 1_000),
                    RecoveryObservation {
                        process_alive: true,
                        github: GithubRunnerObservation::Registered { busy: true },
                    },
                    timeouts,
                    &clock
                ),
                RecoveryDecision::Observe(AttemptState::Busy),
                "at +{offset}s a runner that took a job was stopped by an idle deadline"
            );
        }
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

        // Half the re-derivation is free: an agent that died between deciding
        // and terminating still sees a live process, and is handed the same
        // answer next pass.
        let pending = attempt_in(AttemptState::Starting, 1_000);
        assert_eq!(
            recovery_decision(&pending, unregistered(true), timeouts, &clock),
            RecoveryDecision::Terminate(AttemptOutcome::failed(
                FailureReason::RegistrationTimedOut
            ))
        );

        // The other half is not, and this is the assertion that says so rather
        // than blessing it. An agent that terminated the process and died
        // before writing the outcome is, on the next pass, indistinguishable
        // from one whose runner crashed on its own: both present exactly the
        // same `RecoveryObservation`. The decision below is therefore the same
        // for both, and for the terminate-then-crash case the reason it carries
        // is wrong -- nothing exited unexpectedly, this agent killed it.
        let crashed_on_its_own = unregistered(false);
        let killed_by_us_then_lost = unregistered(false);
        assert_eq!(
            crashed_on_its_own, killed_by_us_then_lost,
            "this equality *is* the defect: the fact that separates the two \
             cases is not an input to `recovery_decision`, which is why it \
             cannot be repaired inside it"
        );
        assert_eq!(
            recovery_decision(&pending, killed_by_us_then_lost, timeouts, &clock),
            RecoveryDecision::Conclude(AttemptOutcome::failed(
                FailureReason::ProcessExitedUnexpectedly
            )),
            "pinned as the current behaviour of a known-wrong window, not as a \
             correct answer: `e3` closes it by journalling terminate-intent \
             before signalling and concluding the marked attempt with \
             `TerminatedAfterRegistrationTimeout`, which is true of the dead \
             process this pass is looking at. `RecoveryDecision::Terminate` \
             names the trade and the owner"
        );
    }

    #[test]
    fn no_decision_calls_a_dead_process_live() {
        // `RegistrationTimedOut` renders as "the runner process is running but
        // did not register", `ProcessExitedUnexpectedly` is documented "only for
        // a process that is actually gone", and
        // `TerminatedAfterRegistrationTimeout` says the agent stopped the
        // process. All three are claims about liveness, and
        // `RecoveryObservation::process_alive` is the only source of truth for
        // it, so each reason may only ever appear beside the observation that
        // supports it.
        //
        // This is also the guard on the `Terminate` window's residual. The
        // rejected fix for that window -- reach for `RegistrationTimedOut` in
        // the dead-process arm at `starting` once `elapsed >= startup` --
        // compiles, and reds three tests. Measured by applying it:
        //
        //  * here, at `starting at +120s with NotRegistered and a process the
        //    observation says is gone was reported as still running`;
        //  * `a_live_unregistered_runner_past_its_deadline_is_stopped_before_
        //    its_slot_returns`, at the assertion that pins the known-wrong
        //    window as current behaviour;
        //  * `a_pre_registration_attempt_waits_until_its_deadline_then_
        //    concludes`, with `left: Conclude(Failed { reason:
        //    RegistrationTimedOut })` against `right: Conclude(Failed { reason:
        //    ProcessExitedUnexpectedly })`.
        //
        // The third is the strongest of the three and is worth naming ahead of
        // this one. It is not a guard written to catch this mistake: it is a
        // real scenario already in the suite -- flow 2's "runner exit before job
        // acceptance", process dead, elapsed 121s against a 120s startup window
        // -- which the rejected fix relabels `RegistrationTimedOut`. So the
        // objection is not only that a synthetic sweep dislikes the change; an
        // ordinary early crash, observed after a restart longer than the startup
        // window, gets reported as a runner that is still running. This test
        // remains the argument's *general* form, because it holds the claim at
        // every state, every observation and both sides of every deadline rather
        // than at one scenario.
        let timeouts = RecoveryTimeouts::new(
            Elapsed::seconds(60),
            Elapsed::seconds(120),
            Elapsed::seconds(300),
        );
        let entered_at = 1_000i64;
        // Both sides of each deadline, the deadlines themselves, and one
        // instant far past all three.
        let offsets = [0, 59, 60, 61, 119, 120, 121, 299, 300, 301, 100_000];
        let observations = [
            GithubRunnerObservation::NotRegistered,
            GithubRunnerObservation::Registered { busy: false },
            GithubRunnerObservation::Registered { busy: true },
            GithubRunnerObservation::Unreachable,
        ];

        // Set by the third arm below, and asserted `false` after the sweep. It
        // is what keeps that arm from being a vacuous assertion nobody notices
        // has stopped meaning anything: today the arm is unreached, and this
        // says so out loud rather than leaving it to be assumed.
        let mut agent_termination_derived_here = false;

        for state in AttemptState::ALL {
            for github in observations {
                for process_alive in [true, false] {
                    for offset in offsets {
                        let clock = StubClock::at(entered_at + offset);
                        let observation = RecoveryObservation {
                            process_alive,
                            github,
                        };
                        let decision = recovery_decision(
                            &attempt_in(state, entered_at),
                            observation,
                            timeouts,
                            &clock,
                        );
                        let reason = match &decision {
                            RecoveryDecision::Conclude(AttemptOutcome::Failed { reason })
                            | RecoveryDecision::Terminate(AttemptOutcome::Failed { reason }) => {
                                Some(reason)
                            }
                            _ => None,
                        };
                        match reason {
                            Some(FailureReason::RegistrationTimedOut) => assert!(
                                process_alive,
                                "{state} at +{offset}s with {github:?} and a process the \
                                 observation says is gone was reported as still running"
                            ),
                            Some(FailureReason::ProcessExitedUnexpectedly) => assert!(
                                !process_alive,
                                "{state} at +{offset}s with {github:?} reported an \
                                 unexpected exit for a process that is alive"
                            ),
                            // Nothing here derives this one today -- it is
                            // `e3`'s, recorded after reading its own journalled
                            // terminate-intent back, which is why the flag above
                            // records that the arm was reached at all. It is not
                            // idle cover: once the mark is journalled somewhere
                            // `recovery_decision` can read it, deriving the
                            // reason here becomes legitimate, and this is what
                            // stops that derivation landing beside a process the
                            // observation reports as still running.
                            Some(FailureReason::TerminatedAfterRegistrationTimeout) => {
                                agent_termination_derived_here = true;
                                assert!(
                                    !process_alive,
                                    "{state} at +{offset}s with {github:?} said the agent had \
                                     stopped a process the observation reports as alive"
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // The division of labour, asserted rather than described. The reason
        // that names an agent-initiated stop is not derivable from an
        // observation -- a process this agent killed and one that crashed on its
        // own look identical to `recovery_decision` -- so it must not appear
        // anywhere in the sweep above. If it ever does, the fact that separates
        // the two cases has become an input, and `RecoveryDecision::Terminate`'s
        // deferred obligation is either discharged or wrong; either way somebody
        // should be reading that doc rather than passing this test by accident.
        assert!(
            !agent_termination_derived_here,
            "`recovery_decision` derived `TerminatedAfterRegistrationTimeout`, \
             which is `e3`'s to record from journalled terminate-intent and not \
             this function's to infer from an observation that cannot know"
        );
    }

    #[test]
    fn a_terminated_runner_is_never_described_as_running() {
        // The `Display` half of the same argument. `e3` concludes the window in
        // `RecoveryDecision::Terminate`'s doc with this reason, on a pass where
        // the process is already dead, so its rendering may not claim otherwise.
        // Reusing `RegistrationTimedOut` there -- the closure this file used to
        // promise -- would have printed "the runner process is running but did
        // not register" about a process the operator can see is gone: the same
        // false liveness claim option A is rejected for, one pass later.
        let terminated = FailureReason::TerminatedAfterRegistrationTimeout.to_string();
        assert!(
            !terminated.contains("running"),
            "this reason is only ever recorded about a process the agent has \
             already stopped: {terminated}"
        );
        assert!(
            !terminated.contains("exited unexpectedly"),
            "and nothing exited unexpectedly either -- the agent stopped it on \
             purpose: {terminated}"
        );
        assert!(
            terminated.contains("stopped") && terminated.contains("register"),
            "it has to say both what happened to the process and why, or it \
             sends an operator to a crash investigation: {terminated}"
        );

        // Distinct from both neighbours, in the variant and in the string. A
        // reason that renders identically to another is a reason `g2` cannot
        // use to send an operator anywhere different.
        assert_ne!(
            terminated,
            FailureReason::RegistrationTimedOut.to_string(),
            "the live and the stopped case must read differently"
        );
        assert_ne!(
            terminated,
            FailureReason::ProcessExitedUnexpectedly.to_string()
        );
        assert!(
            !matches!(
                FailureReason::TerminatedAfterRegistrationTimeout,
                FailureReason::Other(_)
            ),
            "a known, named condition must not travel through the escape hatch"
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
