// owner: d1-workspace-cli-read-models

//! The shared workspace surface: one read model and one mutation per setting,
//! for `host set-runtime-root`, `host reset-runtime-root`,
//! `repo set-workspace`, `host show`, `repo list`, `status` and — when `e1`
//! arrives — the TUI.
//!
//! # Why this is a module and not four command bodies
//!
//! `02-target-architecture.md`'s eighth invariant is *"CLI and TUI use the same
//! domain mutations, path validation, active-attempt checks, and messages"*, and
//! `d1`'s scope says the handlers must be *"reusable by TUI, backed by the atomic
//! store mutations and operational preflight rather than CLI-only logic"*. A
//! second implementation in `crates/app/src/tui` would be a second set of
//! refusals, a second overlap set, and a second answer to "what is the effective
//! root" — and the two would disagree on the day one of them was fixed. So the
//! decisions live here, the commands render them, and `e1` calls the same three
//! entry points:
//!
//! * [`host_root`] and [`repository_workspace`] — the read models.
//! * [`set_host_runner_root`] and [`set_repository_workspace`] — the mutations.
//! * [`PERSISTENT_TRUST_WARNING`] — the words, once.
//!
//! # The order of operations is `03-migration-rollout.md`'s, exactly
//!
//! *"Configuration changes"* fixes it, and every step is load-bearing:
//!
//! 1. resolve the host or policy and the value the caller read;
//! 2. count affected attempts whose state is not `cleaned`;
//! 3. refuse if the count is non-zero — **separately** for active and for
//!    cleanup-blocked, because the operator's next action differs;
//! 4. validate the new path and the overlap set **without** mutating anything;
//! 5. create the leaf if it is needed;
//! 6. persist atomically, behind the store's own fence;
//! 7. print the effective new path;
//! 8. say plainly that the previous directory was neither moved nor removed.
//!
//! Steps 4 and 5 are in that order and not the other one: `d1` requires a
//! "validated leaf only after all non-mutating checks pass", so a refused
//! mutation leaves no directory behind at all. When step 6 then loses its
//! optimistic race the leaf *has* been created, and the refusal
//! ([`leftover_note`]) names it rather than deleting it —
//! `03-migration-rollout.md`: "It must never delete a directory it did not prove
//! it created empty in this invocation."

use std::fmt;
use std::io::Write;
use std::path::PathBuf;

use runner_manager_domain::attempt::RunnerAttempt;
use runner_manager_domain::model::{Host, ScaleTarget, StartMode, TargetScope};
use runner_manager_domain::path::LocalAbsolutePath;
use runner_manager_domain::policy::ScalePolicy;
use runner_manager_domain::store::{Store, StoreError};
use runner_manager_domain::workspace::{WorkspaceKind, WorkspacePolicy};
use runner_manager_platform::paths::AppPaths;
use runner_manager_platform::runner_root::{
    RootOwner, RootPreflight, default_runner_root, is_on_privacy_gated_volume,
};
use runner_manager_platform::service::{InstallRecord, ServiceError};

use super::{CliError, Context, Failure, Styling, write_failed};

// ---------------------------------------------------------------------------
// The trust warning
// ---------------------------------------------------------------------------

/// The five things `04-security-recovery.md` requires to be said before
/// persistent mode is saved.
///
/// Stated once, as data, because the same five lines have to appear in CLI
/// success output, in the TUI's mutation preview and settings detail, and in the
/// README — and a paraphrase in one of those places is a security control that
/// quietly stopped matching the others. The list is the section
/// "Operator-visible warnings", bullet for bullet.
pub const PERSISTENT_TRUST_WARNING: &[&str] = &[
    "warning: a persistent workspace is a trusted-workflow optimization, not isolation.",
    "  - files under _work are an input to later jobs on the same slot;",
    "  - executable and generated content can cross branch and job boundaries;",
    "  - do not enable it for untrusted fork or pull-request workflows;",
    "  - changing or disabling persistence does not delete old directories;",
    "  - `actions/checkout` still cleans the workspace, including Git-ignored files,",
    "    unless the workflow sets `clean: false`.",
];

/// Writes [`PERSISTENT_TRUST_WARNING`], one line per entry.
///
/// # Errors
/// [`Failure::Unclassified`] when `out` gives way.
pub fn write_trust_warning(out: &mut dyn Write) -> Result<(), CliError> {
    let failed = write_failed("this workspace trust warning");
    for line in PERSISTENT_TRUST_WARNING {
        writeln!(out, "{line}").map_err(&failed)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Where a root came from
// ---------------------------------------------------------------------------

/// Whether the effective host runner root is the operator's or the platform's.
///
/// `05-user-workflows.md`'s second UX principle — *"name whether a value is
/// default, configured, or repository-specific"* — and Journey 1's
/// `runner root source  platform-default` row. Two variants and no third: a
/// repository's persistent root is a different setting on a different type, not
/// a third source of this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootSource {
    /// No override is stored; `b1` resolves the root for this platform.
    PlatformDefault,
    /// `host set-runtime-root` put a value in the host row.
    Configured,
}

impl RootSource {
    /// The badge a human reads.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            RootSource::PlatformDefault => "platform-default",
            RootSource::Configured => "configured",
        }
    }

    /// The token `status --json` emits.
    ///
    /// Deliberately not [`Self::as_str`]: every other enumerated value in that
    /// document is `snake_case` (`monitor_only`, `not_authenticated`), and a
    /// lone hyphenated one would be the field a consumer gets wrong.
    #[must_use]
    pub const fn as_token(self) -> &'static str {
        match self {
            RootSource::PlatformDefault => "platform_default",
            RootSource::Configured => "configured",
        }
    }
}

impl fmt::Display for RootSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The effective host runner root, its source, and the value that was stored.
///
/// # `effective` is an `Option`, and that is not defensive
///
/// The platform default is *resolved*, not stored: on Windows from the system
/// directory the operating system reports, elsewhere from
/// [`AppPaths::runtime_dir`]. Both can fail — a machine with no reportable
/// system volume, a `--data-dir` that is not an absolute path — and `host show`
/// is precisely the command an operator runs when the tool is behaving oddly.
/// Failing it would take away the capacity, budget and secret-store rows for a
/// row that is one of eight. So the reason is carried in [`Self::unavailable`]
/// and printed beside the row; the operator is told the effective root is
/// unknown and which command sets one, instead of being told nothing at all.
///
/// A *configured* root never takes that path: it is a stored
/// [`LocalAbsolutePath`], so `effective` is `Some` whenever `configured` is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRoot {
    /// `Host.runner_root_override`: `None` means the platform default.
    pub configured: Option<LocalAbsolutePath>,
    /// The path attempts are actually created under.
    pub effective: Option<LocalAbsolutePath>,
    /// Why the platform default could not be resolved, when it could not be.
    pub unavailable: Option<String>,
}

impl HostRoot {
    #[must_use]
    pub const fn source(&self) -> RootSource {
        if self.configured.is_some() {
            RootSource::Configured
        } else {
            RootSource::PlatformDefault
        }
    }

    /// The effective path as text, for a display row or a JSON field.
    #[must_use]
    pub fn effective_text(&self) -> Option<&str> {
        self.effective.as_ref().map(LocalAbsolutePath::as_str)
    }

    /// The effective path, with the reason it is missing when it is.
    #[must_use]
    pub fn rendered(&self) -> String {
        match (&self.effective, &self.unavailable) {
            (Some(root), _) => root.as_str().to_string(),
            (None, Some(reason)) => format!("unavailable ({reason})"),
            (None, None) => "unavailable".to_string(),
        }
    }
}

/// Resolves the effective host runner root without touching the filesystem's
/// contents.
///
/// `host` is passed in rather than read here because every caller already holds
/// it — `host show` prints eight other things from the same row, and reading it
/// twice is two answers where the operator sees one.
#[must_use]
pub fn host_root(app_paths: &AppPaths, host: Option<&Host>) -> HostRoot {
    if let Some(configured) = host.and_then(|host| host.runner_root_override.clone()) {
        return HostRoot {
            effective: Some(configured.clone()),
            configured: Some(configured),
            unavailable: None,
        };
    }
    match default_runner_root(app_paths) {
        Ok(root) => HostRoot {
            configured: None,
            effective: Some(root),
            unavailable: None,
        },
        Err(source) => HostRoot {
            configured: None,
            effective: None,
            unavailable: Some(source.to_string()),
        },
    }
}

// ---------------------------------------------------------------------------
// Affected attempts
// ---------------------------------------------------------------------------

/// The two counts a path mutation is refused behind.
///
/// They are separate because the operator's next action is different, and
/// `d1`'s scope requires it: *"refuse active and cleanup-blocked affected
/// attempts with separate counts"*. An **active** attempt is running a job and
/// will finish on its own; a **cleanup-blocked** one has concluded, holds no
/// host capacity, and will not clear without recovery or remediation. Reporting
/// one total would send an operator who has a quarantined slot away to wait for
/// a job that is not running.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AffectedAttempts {
    /// Non-terminal: still occupying host capacity.
    pub active: u16,
    /// Terminal and not yet `cleaned`: still owning its directory, and its slot
    /// lease if it has one.
    pub cleanup_blocked: u16,
}

impl AffectedAttempts {
    /// The number the store's fence is given, which is the whole uncleaned set.
    #[must_use]
    pub const fn total(&self) -> u16 {
        self.active.saturating_add(self.cleanup_blocked)
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total() == 0
    }

    /// Splits an uncleaned set into the two counts.
    #[must_use]
    pub fn of<'a>(attempts: impl IntoIterator<Item = &'a RunnerAttempt>) -> Self {
        let mut counts = Self::default();
        for attempt in attempts {
            if attempt.counts_against_capacity() {
                counts.active = counts.active.saturating_add(1);
            } else {
                counts.cleanup_blocked = counts.cleanup_blocked.saturating_add(1);
            }
        }
        counts
    }

    /// The refusal sentence, naming both counts even when one is zero.
    ///
    /// Both are always printed: "0 awaiting cleanup" is the answer to a question
    /// the operator is about to ask, and omitting the zero makes the two
    /// refusals look like two different failures.
    #[must_use]
    pub fn refusal(&self, subject: &str) -> String {
        format!(
            "{subject} cannot change while attempts still own it: {} active and {} awaiting \
             cleanup. Nothing was changed.",
            self.active, self.cleanup_blocked
        )
    }
}

/// The uncleaned **ephemeral** attempts on this host, split into the two counts.
///
/// # Errors
/// [`Failure::LocalState`] when the journal cannot be read.
pub fn host_affected_attempts(store: &dyn Store) -> Result<AffectedAttempts, CliError> {
    Ok(AffectedAttempts::of(
        store
            .uncleaned_ephemeral_attempts()
            .map_err(read_failure)?
            .iter(),
    ))
}

/// The uncleaned attempts of one policy, split into the two counts.
///
/// # Errors
/// [`Failure::LocalState`] when the journal cannot be read.
pub fn policy_affected_attempts(
    store: &dyn Store,
    policy: &ScalePolicy,
) -> Result<AffectedAttempts, CliError> {
    Ok(AffectedAttempts::of(
        store
            .uncleaned_attempts_for_policy(policy.id)
            .map_err(read_failure)?
            .iter(),
    ))
}

// ---------------------------------------------------------------------------
// Slot leases
// ---------------------------------------------------------------------------

/// One durable slot lease, for a status document or a settings screen.
///
/// The path is **not** here and no directory is listed: `d1` requires the
/// surfaces to identify a workspace "without enumerating workspace files", and
/// `02-target-architecture.md`'s sixth invariant forbids inferring anything from
/// the filesystem. The slot number and the journal row are the whole truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotLease {
    pub slot: u16,
    pub attempt: String,
    pub state: String,
    /// The attempt is terminal and has not been cleaned, so this slot is
    /// quarantined rather than merely busy.
    pub cleanup_blocked: bool,
}

/// Every slot one policy still leases, oldest first.
///
/// # Errors
/// [`Failure::LocalState`] when the journal cannot be read.
pub fn slot_leases(store: &dyn Store, policy: &ScalePolicy) -> Result<Vec<SlotLease>, CliError> {
    Ok(store
        .slot_leases_for_policy(policy.id)
        .map_err(read_failure)?
        .iter()
        .filter_map(|attempt| {
            Some(SlotLease {
                slot: attempt.workspace().slot_number()?,
                attempt: attempt.id.to_string(),
                state: attempt.state().to_string(),
                cleanup_blocked: attempt.is_terminal(),
            })
        })
        .collect())
}

// ---------------------------------------------------------------------------
// The repository read model
// ---------------------------------------------------------------------------

/// One repository's workspace settings, as every surface shows them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryWorkspace {
    pub target: ScaleTarget,
    pub policy: WorkspacePolicy,
    /// The host root this repository's *ephemeral* attempts fall back to.
    pub host_root: HostRoot,
    pub attempts: AffectedAttempts,
    pub leases: Vec<SlotLease>,
}

impl RepositoryWorkspace {
    #[must_use]
    pub const fn kind(&self) -> WorkspaceKind {
        self.policy.kind()
    }

    /// The directory this policy's next attempt is created under.
    ///
    /// A persistent policy answers with its own root; an ephemeral one answers
    /// with the effective host root, which is the value Journey 4 requires to be
    /// printed when a repository returns to disposable mode. `None` only when
    /// this policy is ephemeral *and* the platform default could not be
    /// resolved — see [`HostRoot`].
    #[must_use]
    pub fn effective_root(&self) -> Option<&str> {
        self.policy
            .root()
            .map(LocalAbsolutePath::as_str)
            .or_else(|| self.host_root.effective_text())
    }

    /// Which of the three settings decided [`Self::effective_root`], as the
    /// token `status --json` emits.
    ///
    /// `d1`: the surfaces must "identify platform-default, configured, and
    /// repository-specific sources". Two of those are [`RootSource`]'s and the
    /// third is this type's, so the answer is assembled here rather than
    /// inferred by each consumer from "is `workspace_root` null".
    #[must_use]
    pub fn root_source(&self) -> &'static str {
        if self.policy.is_persistent() {
            "repository"
        } else {
            self.host_root.source().as_token()
        }
    }

    /// The same fact as the badge a human reads.
    #[must_use]
    pub fn root_source_badge(&self) -> &'static str {
        if self.policy.is_persistent() {
            "repository-specific"
        } else {
            self.host_root.source().as_str()
        }
    }
}

/// Assembles the read model for one policy.
///
/// The host root is *passed in* rather than resolved here, and that is the same
/// rule [`host_root`] states one paragraph up: a caller rendering a table asks
/// once and hands the answer to every row, so two rows of one table cannot
/// describe two different hosts. Resolving it per policy would also re-ask the
/// operating system for the system directory once per repository, for a value
/// that cannot legitimately change inside one command.
///
/// # Errors
/// [`Failure::LocalState`] when the journal cannot be read.
pub fn repository_workspace(
    store: &dyn Store,
    host_root: &HostRoot,
    policy: &ScalePolicy,
) -> Result<RepositoryWorkspace, CliError> {
    Ok(RepositoryWorkspace {
        target: policy.target.clone(),
        policy: policy.workspace_policy().clone(),
        host_root: host_root.clone(),
        attempts: policy_affected_attempts(store, policy)?,
        leases: slot_leases(store, policy)?,
    })
}

// ---------------------------------------------------------------------------
// The overlap set
// ---------------------------------------------------------------------------

/// A preflight that knows about every *other* configured root on this host.
///
/// `02-target-architecture.md`'s path validation requires "no equality,
/// ancestor, or descendant overlap between the effective host runner root and
/// any repository persistent root" and the same between two repositories. `b1`
/// enforces it and this is where the set is assembled — once, from the store, so
/// a caller cannot forget a repository.
///
/// The candidate's own owner is registered too and [`RootPreflight::against`]
/// skips it, which is what lets `repo set-workspace` re-save the path a
/// repository already has without being told it overlaps itself.
fn preflight_against_everything<'a>(
    app_paths: &'a AppPaths,
    host: &HostRoot,
    policies: &[ScalePolicy],
) -> RootPreflight<'a> {
    let mut preflight = RootPreflight::new(app_paths);
    if let Some(root) = host.effective.clone() {
        preflight = preflight.against(RootOwner::Host, root);
    }
    for policy in policies {
        if let Some(root) = policy.workspace_policy().root() {
            preflight =
                preflight.against(RootOwner::Repository(policy.target.slug()), root.clone());
        }
    }
    preflight
}

/// Steps 4 and 5, for either owner: validate the candidate against every other
/// configured root, then create the one leaf it needs, if it needs one.
///
/// The two are one function because their order is the invariant, not a detail
/// of either mutation: `d1` requires a "validated leaf only after all
/// non-mutating checks pass", so a refused change must leave no directory
/// behind. Splitting them would let a future caller do them the other way
/// around.
///
/// # Errors
/// [`Failure::InvalidArgument`] for a path this host cannot hold, and
/// [`Failure::LocalState`] when the leaf cannot be created.
fn validated_leaf(
    app_paths: &AppPaths,
    host_root: &HostRoot,
    policies: &[ScalePolicy],
    owner: &RootOwner,
    root: &LocalAbsolutePath,
) -> Result<Option<PathBuf>, CliError> {
    let checked = preflight_against_everything(app_paths, host_root, policies)
        .check(owner, root)
        .map_err(|source| unusable(source, owner))?;
    let Some(leaf) = checked.leaf_to_create() else {
        return Ok(None);
    };
    std::fs::create_dir(leaf).map_err(|source| {
        CliError::with_remedy(
            Failure::LocalState,
            format!("cannot create {}: {source}", leaf.display()),
            owner.remediation(),
        )
    })?;
    Ok(Some(leaf.to_path_buf()))
}

/// The refusal an ephemeral workspace answers a path with, stated once.
///
/// `02-target-architecture.md`: "`ephemeral` rejects `--path` so an ignored
/// argument cannot mislead". Both the command boundary — which refuses before
/// the store is opened at all — and [`set_repository_workspace`], which is what
/// `e1` saves through, raise *this* error rather than two paraphrases of it.
#[must_use]
pub fn ephemeral_rejects_a_path(target: &ScaleTarget) -> CliError {
    CliError::with_remedy(
        Failure::InvalidArgument,
        "--path names where persistent slots live, and an ephemeral workspace has none; \
         nothing was changed",
        format!("runner-manager repo set-workspace {target} --mode ephemeral"),
    )
}

/// Parses an operator's `--path` into the type the store and the preflight both
/// speak.
///
/// # Errors
/// [`Failure::InvalidArgument`], with the command that fixes it.
pub fn parse_root(raw: &str, owner: &RootOwner) -> Result<LocalAbsolutePath, CliError> {
    LocalAbsolutePath::new(raw).map_err(|source| {
        CliError::with_remedy(
            Failure::InvalidArgument,
            format!("{raw:?} cannot be used as {owner}: {source}"),
            owner.remediation(),
        )
    })
}

/// The non-mutating half of a path change: everything
/// [`set_host_runner_root`] and [`set_repository_workspace`] decide before they
/// create or write anything.
///
/// `e1`'s Host and Repository Settings screens answer "is this draft usable?"
/// while the operator is still typing, and `05-user-workflows.md` allows exactly
/// that — *"TUI preview may run this check"* — provided it is **this** check and
/// not a second one. Nothing is created here, so previewing a path that is never
/// saved leaves no directory behind, and the message a screen shows inline is
/// the message the command would have printed.
///
/// # Errors
/// [`Failure::InvalidArgument`] for a path this host cannot hold, and
/// [`Failure::LocalState`] when the host row or the policy set cannot be read.
pub fn check_root(
    context: &Context,
    store: &dyn Store,
    owner: &RootOwner,
    raw: &str,
) -> Result<LocalAbsolutePath, CliError> {
    let root = parse_root(raw, owner)?;
    let host = super::host::local_host(store)?;
    let current = host_root(context.paths(), host.as_ref());
    let policies = store.policies().map_err(read_failure)?;
    preflight_against_everything(context.paths(), &current, &policies)
        .check(owner, &root)
        .map_err(|source| unusable(source, owner))?;
    Ok(root)
}

// ---------------------------------------------------------------------------
// The mutations
// ---------------------------------------------------------------------------

/// What one accepted path change did, for the caller to render.
///
/// `d1`: *"Show previous configured value, new value, effective source, retained
/// old directories, and persistent trust warning."* Every one of those is a
/// field here rather than a sentence assembled at the call site, so the CLI and
/// the TUI report the same five facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootChange {
    pub previous: HostRoot,
    pub current: HostRoot,
    /// The one directory this invocation created, if it created one.
    pub created: Option<PathBuf>,
    /// The previous directory, which was neither moved nor deleted.
    pub retained: Option<LocalAbsolutePath>,
    /// What the *service* will not be able to reach, though the caller can.
    pub service_access: Option<ServiceAccessWarning>,
}

/// A root this account can use and the service account cannot.
///
/// The gap this closes: every check `host set-runtime-root` runs, it runs as the
/// operator typing the command. A boot-mode service on macOS runs as `root`
/// under `launchd`, which the privacy layer treats as a different subject
/// entirely -- it is denied any volume other than the startup disk until the
/// program is granted Full Disk Access, and being a daemon it cannot raise the
/// consent prompt that would say so. The command therefore used to accept the
/// path, print "Runner root configured.", and leave the daemon refusing every
/// launch once per poll with nothing on screen to connect the two.
///
/// Deliberately a warning and not a refusal. The path is legitimate, the consent
/// is grantable, and an operator who is about to grant it -- or who is about to
/// switch the service to login mode -- must not be blocked from configuring the
/// root first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAccessWarning {
    /// The binary to grant access to: the copy the service manager actually
    /// runs, and not whichever `runner-manager` is on `PATH`.
    ///
    /// `None` when a registration exists but this account may not read the
    /// record that names it -- the ordinary state for a boot-mode service, whose
    /// record is written by the account that installed it. The warning is still
    /// worth printing then; it just has to say how to find the path instead of
    /// naming it, because naming the wrong one is worse than naming none.
    pub program: Option<PathBuf>,
}

/// Whether a service started this way may be denied a root on this volume.
///
/// Both conditions have to hold, and the policy is separated from the probes so
/// that it can be stated exhaustively in a test: which volume a directory is on
/// is a question only the running machine can answer, and the suite cannot mount
/// one to ask it.
///
/// A **login-mode** service runs as the operator in their own session, where the
/// consent they have already granted applies and a prompt can still appear if it
/// has not; only a boot-mode daemon is mute. A root on the startup disk is not
/// gated at all.
const fn service_may_be_denied(start_mode: StartMode, on_gated_volume: bool) -> bool {
    matches!(start_mode, StartMode::Boot) && on_gated_volume
}

/// What the install record says about the service this warning is about.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RegisteredService {
    /// No registration: nothing to warn about.
    None,
    /// A registration whose record was read.
    Known {
        start_mode: StartMode,
        binary: PathBuf,
    },
    /// A registration exists and this account may not read its record.
    Unreadable,
}

/// Reads the install record, which is the only authority on what is registered.
///
/// Deliberately not a scan of `<state>/bin`. That directory is not the record:
/// `service uninstall` removes the registration and the record but leaves the
/// copy behind by design, so a scan reports a daemon that no longer exists; the
/// copy is named after the *source* file it was installed from, so
/// `runner-manager-0.3.0` and `runner-manager` can both be there; and a single
/// Finder visit adds `.DS_Store`, which has no extension and sorts first. Every
/// one of those names a path the operator would grant access to for nothing.
fn registered_service(paths: &AppPaths) -> RegisteredService {
    match InstallRecord::read(paths) {
        Ok(Some(record)) => RegisteredService::Known {
            start_mode: record.start_mode,
            binary: record.binary,
        },
        Ok(None) => RegisteredService::None,
        // The record is there and unreadable, which is the ordinary state for a
        // boot-mode registration: it is written by the account that installed
        // it, usually through `sudo`. Told apart from "no record" because the
        // two mean opposite things here.
        Err(ServiceError::RecordNotPermitted { .. }) => RegisteredService::Unreadable,
        // Any other read failure is not evidence that a service exists, and a
        // warning is not the place to report a corrupt record.
        Err(_) => RegisteredService::None,
    }
}

/// Whether the service will be able to reach `root`, and what to say if not.
///
/// `host` is consulted only when the record cannot be read: `Host` carries the
/// start mode this host *believes*, and `StartMode::default()` is `Boot`, so a
/// row that never saw an install claims boot mode. The record's own start mode
/// is preferred wherever it is available.
fn service_access_warning(
    paths: &AppPaths,
    host: &Host,
    root: &LocalAbsolutePath,
) -> Option<ServiceAccessWarning> {
    // The volume question first: it is the same answer whatever is installed,
    // and it is what keeps this off every root on the startup disk.
    if !is_on_privacy_gated_volume(root.as_path()) {
        return None;
    }
    let (start_mode, program) = match registered_service(paths) {
        RegisteredService::None => return None,
        RegisteredService::Known { start_mode, binary } => (start_mode, Some(binary)),
        RegisteredService::Unreadable => (host.service_start_mode, None),
    };
    if !service_may_be_denied(start_mode, true) {
        return None;
    }
    Some(ServiceAccessWarning { program })
}

/// `host set-runtime-root --path` and `host reset-runtime-root`.
///
/// `requested` is the value to store: `Some` configures a root, `None` returns
/// to the platform default. Resetting deliberately does **not** preflight the
/// default it falls back to. The default's usability is the daemon's gate —
/// `03-migration-rollout.md` gives it to startup, which "preflights
/// `%SystemDrive%\rman` before accepting new work" — and a reset that failed
/// because the default is not writable would take away the one command that
/// undoes a bad override.
///
/// # Errors
/// [`Failure::InvalidArgument`] for a path this host cannot hold,
/// [`Failure::Conflict`] for affected attempts or a lost optimistic race, and
/// [`Failure::LocalState`] for a journal or filesystem failure.
pub fn set_host_runner_root(
    context: &Context,
    store: &dyn Store,
    requested: Option<LocalAbsolutePath>,
) -> Result<RootChange, CliError> {
    let host = super::host::local_host_or_create(context, store)?;
    let previous = host_root(context.paths(), Some(&host));

    // Step 2 and 3: both counts, before anything is validated, so the operator
    // is told about running work rather than about a typo in a path they cannot
    // apply yet.
    let affected = host_affected_attempts(store)?;
    if !affected.is_empty() {
        return Err(CliError::with_remedy(
            Failure::Conflict,
            affected.refusal("the host runner root"),
            "runner-manager status",
        ));
    }

    // Steps 4 and 5: validate everything, then create at most one leaf.
    let created = match &requested {
        Some(root) => {
            let policies = store.policies().map_err(read_failure)?;
            validated_leaf(
                context.paths(),
                &previous,
                &policies,
                &RootOwner::Host,
                root,
            )?
        }
        None => None,
    };

    // Step 6: the targeted, fenced write. Never `put_host`, which would roll a
    // concurrent `host set-capacity` back.
    store
        .set_runner_root_override(
            host.id,
            previous.configured.as_ref(),
            requested.as_ref(),
            affected.total(),
        )
        .map_err(|source| write_failure(source, created.as_deref()))?;

    // Before the `Host` below takes ownership of `requested`.
    let service_access = requested
        .as_ref()
        .and_then(|root| service_access_warning(context.paths(), &host, root));
    let current = host_root(
        context.paths(),
        Some(&Host {
            runner_root_override: requested,
            ..host
        }),
    );
    Ok(RootChange {
        retained: retained_between(&previous, &current),
        previous,
        current,
        created,
        service_access,
    })
}

/// What one accepted `repo set-workspace` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceChange {
    pub target: ScaleTarget,
    pub previous: WorkspacePolicy,
    pub current: WorkspacePolicy,
    /// Where this repository's ephemeral attempts go, for Journey 4's
    /// "it also prints the effective host runner root".
    pub host_root: HostRoot,
    pub created: Option<PathBuf>,
    /// The previous persistent root, which still holds every old slot.
    pub retained: Option<LocalAbsolutePath>,
}

impl WorkspaceChange {
    /// The directory the next attempt will be created under.
    #[must_use]
    pub fn effective_root(&self) -> String {
        self.current.root().map_or_else(
            || self.host_root.rendered(),
            |root| root.as_str().to_string(),
        )
    }
}

/// `repo set-workspace --mode ephemeral|persistent [--path]`.
///
/// The organization half of D7 is not a check here: `org` declares no
/// `set-workspace` command, `ScaleTarget::Organization` cannot reach this
/// function through the CLI, and
/// [`ScalePolicy::set_workspace_policy`](runner_manager_domain::policy::ScalePolicy::set_workspace_policy)
/// refuses it anyway. Three layers, and the domain's is the one that also covers
/// a hand-edited row.
///
/// # Errors
/// As [`set_host_runner_root`], plus [`Failure::NotFound`] when no policy for
/// `target` exists.
pub fn set_repository_workspace(
    context: &Context,
    store: &dyn Store,
    target: &ScaleTarget,
    kind: WorkspaceKind,
    path: Option<LocalAbsolutePath>,
) -> Result<WorkspaceChange, CliError> {
    let policies = store.policies().map_err(read_failure)?;
    let mut policy = policies
        .iter()
        .find(|policy| &policy.target == target)
        .cloned()
        .ok_or_else(|| {
            CliError::with_remedy(
                Failure::NotFound,
                format!("no policy for {target} exists"),
                "runner-manager repo list",
            )
        })?;
    let previous = policy.workspace_policy().clone();
    let expected_revision = policy.revision();
    let host = super::host::local_host(store)?;
    let host_root = host_root(context.paths(), host.as_ref());

    let affected = policy_affected_attempts(store, &policy)?;
    if !affected.is_empty() {
        return Err(CliError::with_remedy(
            Failure::Conflict,
            affected.refusal(&format!("the workspace setting for {target}")),
            "runner-manager status",
        ));
    }

    let owner = RootOwner::Repository(target.slug());
    let requested = match (kind, path) {
        (WorkspaceKind::Ephemeral, None) => WorkspacePolicy::Ephemeral,
        // The mirror of the `Persistent, None` arm below, and refused for the
        // same reason. `repo set-workspace` already refuses it at the command
        // boundary, but this function is the handler `e1` saves through, and a
        // screen that passed a path alongside `ephemeral` would otherwise have
        // it silently dropped — the one outcome
        // `02-target-architecture.md` rules out.
        (WorkspaceKind::Ephemeral, Some(_)) => {
            return Err(ephemeral_rejects_a_path(target));
        }
        (WorkspaceKind::Persistent, Some(root)) => {
            WorkspacePolicy::persistent(root, target.scope()).map_err(|source| {
                CliError::with_remedy(
                    Failure::InvalidArgument,
                    source.to_string(),
                    "runner-manager repo set-workspace OWNER/REPO --mode ephemeral",
                )
            })?
        }
        // Unreachable through clap, which makes `--path` required for
        // `persistent`. Stated rather than `unwrap`ed because this function is
        // `pub` and `e1` will call it from a screen clap never parsed.
        (WorkspaceKind::Persistent, None) => {
            return Err(CliError::with_remedy(
                Failure::InvalidArgument,
                "a persistent workspace needs the directory its slots live in",
                "runner-manager repo set-workspace OWNER/REPO --mode persistent --path <PATH>",
            ));
        }
    };

    let created = match requested.root() {
        Some(root) => validated_leaf(context.paths(), &host_root, &policies, &owner, root)?,
        None => None,
    };

    policy
        .set_workspace_policy(requested.clone())
        .map_err(|source| CliError::new(Failure::InvalidArgument, source.to_string()))?;
    if policy.revision() != expected_revision {
        store
            .update_policy_confirming_uncleaned_count(&policy, expected_revision, affected.total())
            .map_err(|source| write_failure(source, created.as_deref()))?;
    }

    Ok(WorkspaceChange {
        target: target.clone(),
        retained: retained_root(&previous, &requested),
        previous,
        current: requested,
        host_root,
        created,
    })
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Journey 2's success block, and step 8's non-deletion sentence.
///
/// # Errors
/// [`Failure::Unclassified`] when `out` gives way.
pub fn write_root_change(out: &mut dyn Write, change: &RootChange) -> Result<(), CliError> {
    let failed = write_failed("this runner root result");
    writeln!(
        out,
        "Runner root {}.",
        if change.current.configured.is_some() {
            "configured"
        } else {
            "reset to the platform default"
        }
    )
    .map_err(&failed)?;
    writeln!(
        out,
        "Previous: {} ({})",
        change.previous.rendered(),
        change.previous.source()
    )
    .map_err(&failed)?;
    writeln!(
        out,
        "Current:  {} ({})",
        change.current.rendered(),
        change.current.source()
    )
    .map_err(&failed)?;
    if let Some(created) = &change.created {
        writeln!(out, "Created:  {}", created.display()).map_err(&failed)?;
    }
    writeln!(
        out,
        "New ephemeral attempts will use this path. No existing directory was moved or deleted."
    )
    .map_err(&failed)?;
    if let Some(retained) = &change.retained {
        writeln!(
            out,
            "Retained: {retained} still holds whatever was left there."
        )
        .map_err(&failed)?;
    }
    Ok(())
}

/// The bright block that follows a root the service will not be able to reach.
///
/// Printed after the ordinary result rather than instead of it: the root *was*
/// configured, and the operator needs to see what it was set to as well as what
/// is still in their way.
///
/// # Errors
/// [`Failure::LocalState`] when the output stream cannot be written.
pub fn write_service_access_warning(
    out: &mut dyn Write,
    styling: Styling,
    warning: &ServiceAccessWarning,
    settings_opened: bool,
) -> Result<(), CliError> {
    let failed = write_failed("this runner root warning");
    // One `writeln!` per rendered line, deliberately. A wrapped paragraph built
    // from `\`-continuations puts the source's own indentation into the output,
    // and the block is read on a terminal where that shows.
    let mut line = |text: &str| writeln!(out, "{text}").map_err(&failed);

    line("")?;
    line(&styling.caution("The service cannot use this path yet."))?;
    // The path itself is deliberately not repeated here: `Current:` above
    // already names it, and inlining it made this line as long as the path.
    line("This root is on a separate volume, and this host starts the agent at boot as")?;
    line("`root`. macOS withholds such volumes from a background service until the")?;
    line("program is granted Full Disk Access, and a service cannot ask for it: the")?;
    line("refusal is silent, and every launch fails with nothing on screen to say why.")?;
    line("")?;
    line(&styling.step("To fix it now:"))?;
    // Never claims a window appeared unless one did: `open_in_browser` declines
    // whenever stdout is not a terminal, and a redirected run that promised an
    // open window would send the operator looking for it.
    if settings_opened {
        line("  1. In the window that just opened -- System Settings > Privacy &")?;
        line("     Security > Full Disk Access -- select `+` and add this exact program:")?;
    } else {
        line("  1. Open System Settings > Privacy & Security > Full Disk Access, then")?;
        line("     select `+` and add this exact program:")?;
    }
    match &warning.program {
        Some(program) => {
            line(&format!(
                "     {}",
                styling.code(&program.display().to_string())
            ))?;
            line("     It is the copy the service runs, not the one on your PATH.")?;
        }
        // Never a guessed path: granting access to the wrong file looks like it
        // worked and changes nothing.
        None => {
            line("     the binary this host's service is registered to run, which")?;
            line(&format!(
                "     {} prints as `binary`. It is not the one on your PATH.",
                styling.code("sudo runner-manager service status")
            ))?;
        }
    }
    line("  2. Restart the service so it picks the grant up:")?;
    line(&format!(
        "     {}",
        styling
            .code("sudo runner-manager service uninstall && sudo runner-manager service install")
    ))?;
    line("")?;
    line("Or avoid the grant entirely by running the agent as you, in your own session:")?;
    line(&format!(
        "  {}",
        styling.code("runner-manager service install --start-at login")
    ))?;
    Ok(())
}

/// Journey 3's and Journey 4's success blocks.
///
/// # Errors
/// [`Failure::Unclassified`] when `out` gives way.
pub fn write_workspace_change(
    out: &mut dyn Write,
    change: &WorkspaceChange,
) -> Result<(), CliError> {
    let failed = write_failed("this workspace result");
    writeln!(out, "Workspace mode: {}", change.current.kind()).map_err(&failed)?;
    writeln!(out, "Workspace root: {}", change.effective_root()).map_err(&failed)?;
    if change.current.is_persistent() {
        if let Some(created) = &change.created {
            writeln!(out, "Created: {}", created.display()).map_err(&failed)?;
        }
        writeln!(out, "Slots: created on demand as s1, s2, ...").map_err(&failed)?;
        writeln!(out, "Retained: each slot's _work directory").map_err(&failed)?;
        writeln!(
            out,
            "Disposable: runner binaries, JIT handoff, and lifecycle files"
        )
        .map_err(&failed)?;
    } else {
        writeln!(
            out,
            "Root source: {} ({})",
            change.host_root.rendered(),
            change.host_root.source()
        )
        .map_err(&failed)?;
    }
    if let Some(retained) = &change.retained {
        // Deliberately not a second `Retained:` line. The one above names what
        // *this* setting keeps between jobs; this one names a directory the
        // setting no longer points at, and reading the two as the same kind of
        // statement is how an operator concludes the old slots are still in use.
        writeln!(
            out,
            "Left in place: every slot under {retained} remains on disk, including its _work \
             directory."
        )
        .map_err(&failed)?;
    }
    writeln!(out, "No existing directory was moved or deleted.").map_err(&failed)?;
    if change.current.is_persistent() {
        write_trust_warning(out)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared failure mapping
// ---------------------------------------------------------------------------

/// The previous directory a *host* root change left behind, if it moved.
fn retained_between(previous: &HostRoot, current: &HostRoot) -> Option<LocalAbsolutePath> {
    let old = previous.effective.clone()?;
    match &current.effective {
        Some(new) if new == &old => None,
        _ => Some(old),
    }
}

/// The previous persistent root a *repository* change left behind, if it moved.
fn retained_root(
    previous: &WorkspacePolicy,
    current: &WorkspacePolicy,
) -> Option<LocalAbsolutePath> {
    let old = previous.root()?.clone();
    match current.root() {
        Some(new) if new == &old => None,
        _ => Some(old),
    }
}

fn read_failure(source: StoreError) -> CliError {
    CliError::with_remedy(
        Failure::LocalState,
        format!("cannot read this host's local database: {source}"),
        "runner-manager host show",
    )
}

/// A refused write, plus the leaf this invocation created before it was refused.
///
/// The directory is **named and left**: `03-migration-rollout.md` allows the
/// deletion only of a directory this invocation proved it created empty, and
/// between `create_dir` and the failed write another process may have put
/// something in it. Reporting costs an operator one `rmdir`; guessing costs them
/// whatever was inside.
fn write_failure(source: StoreError, created: Option<&std::path::Path>) -> CliError {
    let class = if source.is_conflict() {
        Failure::Conflict
    } else {
        Failure::LocalState
    };
    let message = format!("{source}{}", leftover_note(created));
    CliError::with_remedy(class, message, "runner-manager status, then retry")
}

/// The sentence [`write_failure`] appends, empty when nothing was created.
fn leftover_note(created: Option<&std::path::Path>) -> String {
    created.map_or_else(String::new, |leaf| {
        format!(
            " The empty directory {} was created before the write was refused and has been \
             left in place; remove it yourself if you do not want it.",
            leaf.display()
        )
    })
}

fn unusable(
    source: runner_manager_platform::runner_root::RunnerRootError,
    owner: &RootOwner,
) -> CliError {
    CliError::with_remedy(
        Failure::InvalidArgument,
        source.to_string(),
        owner.remediation(),
    )
}

/// The word `status --json` and `repo list` use for a target's scope.
#[must_use]
pub const fn scope_token(scope: TargetScope) -> &'static str {
    match scope {
        TargetScope::Repository => "repository",
        TargetScope::Organization => "organization",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use runner_manager_domain::attempt::{AttemptOutcome, FailureReason, RunnerAttempt};
    use runner_manager_domain::model::{AttemptId, PolicyId};

    /// The configuration-time half of the outage this pair exists for.
    ///
    /// Every check `host set-runtime-root` runs, it runs as the operator typing
    /// it -- who can reach an external volume perfectly well. The boot-mode
    /// daemon that will actually use the root cannot, and says so nowhere a
    /// person looks. The command used to accept such a path, print "Runner root
    /// configured.", and leave the service refusing every launch.
    #[test]
    fn a_boot_service_pointed_off_the_startup_volume_is_warned_about() {
        assert!(
            service_may_be_denied(StartMode::Boot, true),
            "a boot-mode daemon is the one identity that cannot ask for consent"
        );
    }

    /// A `<state>/bin` copy is not a registration, and an earlier version of
    /// this warning treated it as one.
    ///
    /// `service uninstall` removes the registration and the record and leaves
    /// the binary copy behind on purpose, so an operator who uninstalled and
    /// then configured a root on an external volume was warned about a daemon
    /// that does not exist, told to grant Full Disk Access to a binary nothing
    /// runs, and told to restart a service that is not installed.
    #[test]
    fn no_install_record_means_no_registered_service() {
        let data_dir = tempfile::tempdir().expect("a temporary directory");
        let paths = AppPaths::rooted_at(data_dir.path());
        // The copy the uninstall left behind, which must not be mistaken for a
        // registration.
        let bin = paths.state_dir().join("bin");
        std::fs::create_dir_all(&bin).expect("the service binary directory");
        std::fs::write(bin.join("runner-manager"), b"leftover").expect("the leftover copy");

        assert_eq!(
            registered_service(&paths),
            RegisteredService::None,
            "only the install record says a service is registered"
        );
    }

    // The `Known` arm has no test of its own deliberately: it reads
    // `record.binary` and `record.start_mode` straight off the deserialised
    // record, so there is no logic left to get wrong. The logic that *was*
    // wrong -- picking a file out of `<state>/bin` by name and sort order -- is
    // gone, and the test above is what keeps it gone.

    /// The block must never invent a path when the record cannot be read, which
    /// is the ordinary state for a boot-mode service installed under `sudo`.
    #[test]
    fn an_unknown_program_is_described_rather_than_guessed() {
        let mut out = Vec::new();
        write_service_access_warning(
            &mut out,
            Styling::plain(),
            &ServiceAccessWarning { program: None },
            false,
        )
        .expect("the block is written");
        let text = String::from_utf8(out).expect("utf-8");

        assert!(
            text.contains("service status"),
            "an unknown path must be described, not omitted: {text}"
        );
        assert!(
            !text.contains("bin/runner-manager"),
            "a guessed path is worse than none -- granting it changes nothing: {text}"
        );
        assert!(
            !text.contains("window that just opened"),
            "nothing opened, so nothing may claim it did: {text}"
        );
    }

    /// The three cases that must stay quiet, so the warning keeps its meaning.
    #[test]
    fn every_other_combination_is_left_alone() {
        assert!(
            !service_may_be_denied(StartMode::Boot, false),
            "the startup disk is not gated at all"
        );
        assert!(
            !service_may_be_denied(StartMode::Login, true),
            "a login-mode agent runs as the operator, in a session that can still prompt"
        );
        assert!(
            !service_may_be_denied(StartMode::Login, false),
            "nothing to warn about"
        );
    }

    fn ts(secs: i64) -> runner_manager_domain::model::Timestamp {
        chrono::DateTime::from_timestamp(secs, 0).expect("a valid timestamp")
    }

    fn an_attempt(terminal: bool) -> RunnerAttempt {
        let mut attempt = RunnerAttempt::allocate(
            AttemptId::new_random(),
            PolicyId::new_random(),
            std::path::PathBuf::from(a_root(&root_text("rman")).as_path()),
            ts(0),
        );
        if terminal {
            // Any terminal state does: the split under test is
            // `counts_against_capacity`, not the transition table `a1` proves.
            attempt
                .conclude(
                    AttemptOutcome::failed(FailureReason::ProcessStartFailed),
                    ts(1),
                )
                .expect("allocated -> failed is a legal conclusion");
        }
        attempt
    }

    /// The split is the domain's own capacity predicate, not a second opinion
    /// about which states are running.
    #[test]
    fn the_two_counts_follow_the_domains_own_terminal_predicate() {
        let attempts = [an_attempt(false), an_attempt(false), an_attempt(true)];
        let counts = AffectedAttempts::of(attempts.iter());
        assert_eq!(counts.active, 2);
        assert_eq!(counts.cleanup_blocked, 1);
        assert_eq!(
            counts.total(),
            3,
            "the total is what the store's fence is given, so it must be the whole uncleaned \
             set and not just the active half"
        );
        assert!(!counts.is_empty());
        assert!(AffectedAttempts::default().is_empty());
    }

    /// Both numbers are printed even when one is zero: a refusal that mentioned
    /// only the non-zero half would read as though the other case could not
    /// happen.
    #[test]
    fn the_refusal_names_both_counts_separately() {
        let only_active = AffectedAttempts {
            active: 1,
            cleanup_blocked: 0,
        };
        let text = only_active.refusal("the host runner root");
        assert!(text.contains("1 active"), "{text}");
        assert!(text.contains("0 awaiting cleanup"), "{text}");
        assert!(text.contains("Nothing was changed."), "{text}");

        let only_blocked = AffectedAttempts {
            active: 0,
            cleanup_blocked: 2,
        };
        let text = only_blocked.refusal("the workspace setting for octo/repo");
        assert!(text.contains("0 active"), "{text}");
        assert!(text.contains("2 awaiting cleanup"), "{text}");
        assert!(text.contains("octo/repo"), "{text}");
    }

    /// The badge a human reads and the token a script reads are different
    /// spellings on purpose, and neither may drift onto the other.
    #[test]
    fn the_source_has_one_spelling_for_people_and_one_for_scripts() {
        assert_eq!(RootSource::PlatformDefault.as_str(), "platform-default");
        assert_eq!(RootSource::PlatformDefault.as_token(), "platform_default");
        assert_eq!(RootSource::Configured.as_str(), "configured");
        assert_eq!(RootSource::Configured.as_token(), "configured");
        assert_eq!(RootSource::Configured.to_string(), "configured");
        for source in [RootSource::PlatformDefault, RootSource::Configured] {
            assert!(
                !source.as_token().contains('-'),
                "every other enumerated value in status --json is snake_case: {}",
                source.as_token()
            );
        }
    }

    fn a_root(text: &str) -> LocalAbsolutePath {
        LocalAbsolutePath::new(text).expect("a valid fixture path")
    }

    fn root_text(leaf: &str) -> String {
        if cfg!(windows) {
            format!(r"C:\{leaf}")
        } else {
            format!("/srv/{leaf}")
        }
    }

    #[test]
    fn a_configured_root_is_its_own_effective_value_and_says_so() {
        let configured = a_root(&root_text("elsewhere"));
        let root = HostRoot {
            configured: Some(configured.clone()),
            effective: Some(configured.clone()),
            unavailable: None,
        };
        assert_eq!(root.source(), RootSource::Configured);
        assert_eq!(root.effective_text(), Some(configured.as_str()));
        assert_eq!(root.rendered(), configured.as_str());
    }

    /// An unresolvable platform default is reported, not fatal — see
    /// [`HostRoot`].
    #[test]
    fn an_unresolvable_default_renders_its_reason_instead_of_a_path() {
        let root = HostRoot {
            configured: None,
            effective: None,
            unavailable: Some("the system directory is unreadable".to_string()),
        };
        assert_eq!(root.source(), RootSource::PlatformDefault);
        assert_eq!(root.effective_text(), None);
        assert!(
            root.rendered().contains("unavailable"),
            "{}",
            root.rendered()
        );
        assert!(
            root.rendered()
                .contains("the system directory is unreadable"),
            "the reason has to travel with the row, or the operator learns nothing: {}",
            root.rendered()
        );
    }

    /// A root that did not move leaves nothing behind, and one that did is
    /// reported rather than removed.
    #[test]
    fn only_a_root_that_actually_moved_is_reported_as_retained() {
        let old = a_root(&root_text("rman"));
        let new = a_root(&root_text("elsewhere"));
        let at = |root: &LocalAbsolutePath| HostRoot {
            configured: Some(root.clone()),
            effective: Some(root.clone()),
            unavailable: None,
        };
        assert_eq!(retained_between(&at(&old), &at(&old)), None);
        assert_eq!(retained_between(&at(&old), &at(&new)), Some(old.clone()));

        let ephemeral = WorkspacePolicy::Ephemeral;
        let persistent = WorkspacePolicy::persistent(
            old.clone(),
            runner_manager_domain::model::TargetScope::Repository,
        )
        .expect("a repository may hold a persistent workspace");
        assert_eq!(retained_root(&ephemeral, &persistent), None);
        assert_eq!(retained_root(&persistent, &persistent), None);
        assert_eq!(
            retained_root(&persistent, &ephemeral),
            Some(old),
            "returning to ephemeral leaves every slot on disk, and the operator is told so"
        );
    }

    /// The leftover note fires only when a directory was really created, and
    /// names it when it was.
    #[test]
    fn a_lost_race_names_the_directory_it_left_behind() {
        assert_eq!(leftover_note(None), "");
        let note = leftover_note(Some(std::path::Path::new("/srv/ws")));
        assert!(note.contains("/srv/ws"), "{note}");
        assert!(note.contains("left in place"), "{note}");
        assert!(
            !note.contains("removed it") && !note.contains("deleted"),
            "the note must not claim a deletion this command is forbidden to perform: {note}"
        );
    }

    /// The five warnings `04-security-recovery.md` lists are all present, and
    /// the checkout caveat does not claim `clean: false` creates persistence.
    #[test]
    fn the_trust_warning_states_every_required_clause() {
        let text = PERSISTENT_TRUST_WARNING.join("\n");
        for clause in [
            "_work",
            "branch and job boundaries",
            "untrusted fork or pull-request",
            "does not delete old directories",
            "clean: false",
        ] {
            assert!(text.contains(clause), "missing {clause:?} from:\n{text}");
        }
        let mut buffer = Vec::new();
        write_trust_warning(&mut buffer).expect("writing to a Vec");
        assert_eq!(
            String::from_utf8(buffer).expect("utf-8"),
            format!("{text}\n"),
            "the rendered warning must be the constant, so a screen and a command cannot \
             paraphrase it differently"
        );
    }

    #[test]
    fn the_scope_token_is_the_one_the_status_document_already_emits() {
        assert_eq!(scope_token(TargetScope::Repository), "repository");
        assert_eq!(scope_token(TargetScope::Organization), "organization");
    }

    // -- output snapshots ----------------------------------------------------
    //
    // The two success blocks, whole. Assertions over fragments prove a phrase is
    // present; a snapshot proves the block an operator *reads* has not drifted —
    // which is what `04-security-recovery.md`'s "Snapshot and command-output
    // tests assert the warning" asks for, and the only way a silently reordered
    // or half-deleted warning fails a test.
    //
    // Paths are substituted for placeholders before comparison, because a
    // `LocalAbsolutePath` is native to the platform it was parsed on and a
    // snapshot holding `C:\...` would be a snapshot only Windows could run.

    /// Renders a block with every path replaced by a stable placeholder.
    fn snapshot_of(
        render: impl Fn(&mut Vec<u8>) -> Result<(), CliError>,
        paths: &[(&str, &str)],
    ) -> String {
        let mut buffer = Vec::new();
        render(&mut buffer).expect("writing to a Vec");
        let mut text = String::from_utf8(buffer).expect("utf-8");
        for (actual, placeholder) in paths {
            text = text.replace(actual, placeholder);
        }
        text
    }

    #[test]
    fn the_host_root_success_block_is_journey_2s() {
        let previous = a_root(&root_text("rman"));
        let current = a_root(&root_text("runners"));
        let change = RootChange {
            service_access: None,
            previous: HostRoot {
                configured: None,
                effective: Some(previous.clone()),
                unavailable: None,
            },
            current: HostRoot {
                configured: Some(current.clone()),
                effective: Some(current.clone()),
                unavailable: None,
            },
            created: Some(current.as_path().to_path_buf()),
            retained: Some(previous.clone()),
        };
        insta::assert_snapshot!(
            snapshot_of(
                |out| write_root_change(out, &change),
                &[
                    (current.as_str(), "<NEW>"),
                    (previous.as_str(), "<OLD>"),
                ],
            ),
            @r###"
        Runner root configured.
        Previous: <OLD> (platform-default)
        Current:  <NEW> (configured)
        Created:  <NEW>
        New ephemeral attempts will use this path. No existing directory was moved or deleted.
        Retained: <OLD> still holds whatever was left there.
        "###
        );
    }

    #[test]
    fn the_persistent_success_block_is_journey_3s_and_carries_the_whole_warning() {
        let old = a_root(&root_text("old-cache"));
        let new = a_root(&root_text("ci-cache"));
        let change = WorkspaceChange {
            target: ScaleTarget::repository("octo/repo").expect("a valid slug"),
            previous: WorkspacePolicy::persistent(old.clone(), TargetScope::Repository)
                .expect("a repository may hold one"),
            current: WorkspacePolicy::persistent(new.clone(), TargetScope::Repository)
                .expect("a repository may hold one"),
            host_root: HostRoot {
                configured: None,
                effective: Some(a_root(&root_text("rman"))),
                unavailable: None,
            },
            created: Some(new.as_path().to_path_buf()),
            retained: Some(old.clone()),
        };
        insta::assert_snapshot!(
            snapshot_of(
                |out| write_workspace_change(out, &change),
                &[(new.as_str(), "<NEW>"), (old.as_str(), "<OLD>")],
            ),
            @r###"
        Workspace mode: persistent
        Workspace root: <NEW>
        Created: <NEW>
        Slots: created on demand as s1, s2, ...
        Retained: each slot's _work directory
        Disposable: runner binaries, JIT handoff, and lifecycle files
        Left in place: every slot under <OLD> remains on disk, including its _work directory.
        No existing directory was moved or deleted.
        warning: a persistent workspace is a trusted-workflow optimization, not isolation.
          - files under _work are an input to later jobs on the same slot;
          - executable and generated content can cross branch and job boundaries;
          - do not enable it for untrusted fork or pull-request workflows;
          - changing or disabling persistence does not delete old directories;
          - `actions/checkout` still cleans the workspace, including Git-ignored files,
            unless the workflow sets `clean: false`.
        "###
        );
    }

    /// Journey 4: returning to disposable mode names the retained root and the
    /// host root future attempts will use, and prints no trust warning — there
    /// is no longer a trust boundary to warn about.
    #[test]
    fn the_ephemeral_success_block_is_journey_4s() {
        let old = a_root(&root_text("ci-cache"));
        let host = a_root(&root_text("rman"));
        let change = WorkspaceChange {
            target: ScaleTarget::repository("octo/repo").expect("a valid slug"),
            previous: WorkspacePolicy::persistent(old.clone(), TargetScope::Repository)
                .expect("a repository may hold one"),
            current: WorkspacePolicy::Ephemeral,
            host_root: HostRoot {
                configured: None,
                effective: Some(host.clone()),
                unavailable: None,
            },
            created: None,
            retained: Some(old.clone()),
        };
        insta::assert_snapshot!(
            snapshot_of(
                |out| write_workspace_change(out, &change),
                &[(old.as_str(), "<OLD>"), (host.as_str(), "<HOST>")],
            ),
            @r###"
        Workspace mode: ephemeral
        Workspace root: <HOST>
        Root source: <HOST> (platform-default)
        Left in place: every slot under <OLD> remains on disk, including its _work directory.
        No existing directory was moved or deleted.
        "###
        );
    }
}

// ---------------------------------------------------------------------------
// The race
// ---------------------------------------------------------------------------
//
// `d1`'s Definition of Done: "Mutations are non-destructive and race tests prove
// no stale host or policy write and no active or cleanup-blocked path change."
// The first two clauses cannot be measured from the command line, because the
// window they are about opens *inside* one invocation: between the read a
// handler takes and the write it makes. Two processes racing at the shell can
// only produce that interleaving by luck, which is not a test.
//
// So the concurrent write is injected into the window, by a `Store` that
// forwards to a real `SqliteStore` and performs one extra write on its way
// through the call the handler makes between its read and its write. That is a
// genuine interleaving, deterministically, every run.
//
// `a2` already proves the *fences* refuse a stale write
// (`crates/domain/tests/store_journal.rs`). What is proved here is that these
// handlers go through them: `put_host` is counted and must stay at zero, because
// a whole-record host upsert built from a read taken seconds earlier is exactly
// how a concurrent `host set-capacity` gets silently rolled back.
#[cfg(test)]
mod race {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use runner_manager_domain::attempt::RunnerAttempt;
    use runner_manager_domain::model::{AttemptId, HostId, PolicyId, ScaleTarget};
    use runner_manager_domain::policy::ScalePolicy;
    use runner_manager_domain::store::{SqliteStore, Store, StoreError};
    use runner_manager_domain::workspace::{WorkspaceKind, WorkspacePolicy};
    use runner_manager_testkit::fixtures;

    use super::{Failure, LocalAbsolutePath, set_host_runner_root, set_repository_workspace};
    use crate::cli::Context;

    /// Where the interleaved write is performed.
    ///
    /// Each is the last read a handler takes before its write, so a write
    /// performed here lands squarely in the window the optimistic fence exists
    /// to close.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum At {
        /// `set_host_runner_root`'s uncleaned-ephemeral count.
        HostCount,
        /// `set_repository_workspace`'s uncleaned per-policy count.
        PolicyCount,
    }

    /// The other operator's write, taken once.
    type ConcurrentWrite = Box<dyn FnOnce(&SqliteStore) + Send>;

    /// A real store that performs one extra write inside the handler's window.
    struct Interleaved {
        inner: SqliteStore,
        at: At,
        concurrent: Mutex<Option<ConcurrentWrite>>,
        put_hosts: AtomicUsize,
    }

    impl std::fmt::Debug for Interleaved {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Interleaved").field("at", &self.at).finish()
        }
    }

    impl Interleaved {
        fn new(
            inner: SqliteStore,
            at: At,
            concurrent: impl FnOnce(&SqliteStore) + Send + 'static,
        ) -> Self {
            Self {
                inner,
                at,
                concurrent: Mutex::new(Some(Box::new(concurrent))),
                put_hosts: AtomicUsize::new(0),
            }
        }

        /// Fires once, the first time the handler reaches the chosen point.
        fn interleave(&self, at: At) {
            if at != self.at {
                return;
            }
            let taken = self
                .concurrent
                .lock()
                .expect("no test panics while holding this")
                .take();
            if let Some(concurrent) = taken {
                concurrent(&self.inner);
            }
        }
    }

    // Forwarding, method by method. Verbose and mechanical on purpose: a
    // `Store` double that *implemented* anything would be measuring itself, and
    // the whole value of this fixture is that every predicate below is SQLite's
    // own.
    impl Store for Interleaved {
        fn put_host(&self, host: &runner_manager_domain::model::Host) -> Result<(), StoreError> {
            self.put_hosts.fetch_add(1, Ordering::Relaxed);
            self.inner.put_host(host)
        }
        fn host(
            &self,
            id: HostId,
        ) -> Result<Option<runner_manager_domain::model::Host>, StoreError> {
            self.inner.host(id)
        }
        fn hosts(&self) -> Result<Vec<runner_manager_domain::model::Host>, StoreError> {
            self.inner.hosts()
        }
        fn set_runner_root_override(
            &self,
            id: HostId,
            expected: Option<&LocalAbsolutePath>,
            new_root: Option<&LocalAbsolutePath>,
            expected_uncleaned: u16,
        ) -> Result<(), StoreError> {
            self.inner
                .set_runner_root_override(id, expected, new_root, expected_uncleaned)
        }
        fn insert_policy(&self, policy: &ScalePolicy) -> Result<(), StoreError> {
            self.inner.insert_policy(policy)
        }
        fn update_policy(
            &self,
            policy: &ScalePolicy,
            expected_revision: u64,
        ) -> Result<(), StoreError> {
            self.inner.update_policy(policy, expected_revision)
        }
        fn update_policy_confirming_active_count(
            &self,
            policy: &ScalePolicy,
            expected_revision: u64,
            expected_active: u16,
        ) -> Result<(), StoreError> {
            self.inner.update_policy_confirming_active_count(
                policy,
                expected_revision,
                expected_active,
            )
        }
        fn update_policy_confirming_uncleaned_count(
            &self,
            policy: &ScalePolicy,
            expected_revision: u64,
            expected_uncleaned: u16,
        ) -> Result<(), StoreError> {
            self.inner.update_policy_confirming_uncleaned_count(
                policy,
                expected_revision,
                expected_uncleaned,
            )
        }
        fn remove_policy(&self, id: PolicyId, expected_revision: u64) -> Result<(), StoreError> {
            self.inner.remove_policy(id, expected_revision)
        }
        fn policy(&self, id: PolicyId) -> Result<Option<ScalePolicy>, StoreError> {
            self.inner.policy(id)
        }
        fn policies(&self) -> Result<Vec<ScalePolicy>, StoreError> {
            self.inner.policies()
        }
        fn record_attempt(&self, attempt: &RunnerAttempt) -> Result<(), StoreError> {
            self.inner.record_attempt(attempt)
        }
        fn attempt(&self, id: AttemptId) -> Result<Option<RunnerAttempt>, StoreError> {
            self.inner.attempt(id)
        }
        fn attempts(&self) -> Result<Vec<RunnerAttempt>, StoreError> {
            self.inner.attempts()
        }
        fn attempts_for_policy(
            &self,
            policy_id: PolicyId,
        ) -> Result<Vec<RunnerAttempt>, StoreError> {
            self.inner.attempts_for_policy(policy_id)
        }
        fn active_attempts_for_policy(
            &self,
            policy_id: PolicyId,
        ) -> Result<Vec<RunnerAttempt>, StoreError> {
            self.inner.active_attempts_for_policy(policy_id)
        }
        fn uncleaned_attempts_for_policy(
            &self,
            policy_id: PolicyId,
        ) -> Result<Vec<RunnerAttempt>, StoreError> {
            let answer = self.inner.uncleaned_attempts_for_policy(policy_id);
            self.interleave(At::PolicyCount);
            answer
        }
        fn slot_leases_for_policy(
            &self,
            policy_id: PolicyId,
        ) -> Result<Vec<RunnerAttempt>, StoreError> {
            self.inner.slot_leases_for_policy(policy_id)
        }
        fn uncleaned_ephemeral_attempts(&self) -> Result<Vec<RunnerAttempt>, StoreError> {
            let answer = self.inner.uncleaned_ephemeral_attempts();
            self.interleave(At::HostCount);
            answer
        }
        fn remove_attempt(&self, id: AttemptId) -> Result<bool, StoreError> {
            self.inner.remove_attempt(id)
        }
    }

    /// A composition root over a disposable data directory.
    fn a_context(data_dir: &std::path::Path) -> Context {
        Context::resolve(Some(data_dir), &mut std::io::sink())
            .expect("a temporary data directory must resolve")
    }

    fn a_host() -> runner_manager_domain::model::Host {
        fixtures::host().capacity(1).build()
    }

    fn a_policy(host: HostId) -> ScalePolicy {
        fixtures::policy()
            .host(host)
            .repository("octo/repo")
            .autoscale("home-win", 1)
            .build()
    }

    fn a_root(parent: &tempfile::TempDir, leaf: &str) -> LocalAbsolutePath {
        LocalAbsolutePath::new(
            parent
                .path()
                .join(leaf)
                .to_str()
                .expect("a temporary path must be UTF-8"),
        )
        .expect("a temporary path is absolute and local")
    }

    /// A capacity change that lands inside the window is kept, not rolled back.
    ///
    /// This is the whole reason `Store::set_runner_root_override` exists rather
    /// than a `put_host` with one field changed: `hosts` carries no revision
    /// column, so a whole-record upsert built from the read this handler took at
    /// its start would write `host_capacity: 1` over the `9` that landed while
    /// it was working — and nothing would report it.
    #[test]
    fn a_host_root_change_does_not_roll_back_a_concurrent_capacity_change() {
        let data_dir = tempfile::tempdir().expect("a temporary directory");
        let roots = tempfile::tempdir().expect("a temporary directory");
        let context = a_context(data_dir.path());
        let inner = SqliteStore::open_in_memory().expect("an in-memory database");
        let host = a_host();
        inner.put_host(&host).expect("a fresh host");

        let id = host.id;
        let store = Interleaved::new(inner, At::HostCount, move |inner| {
            let mut concurrent = inner
                .host(id)
                .expect("readable")
                .expect("the host is there");
            concurrent.host_capacity = std::num::NonZeroU16::new(9).expect("non-zero");
            inner.put_host(&concurrent).expect("the concurrent write");
        });

        let root = a_root(&roots, "runners");
        let change = set_host_runner_root(&context, &store, Some(root.clone()))
            .expect("the override did not move, so the fenced write is accepted");
        assert_eq!(change.current.configured, Some(root));

        let after = store.host(id).expect("readable").expect("still there");
        assert_eq!(
            after.host_capacity.get(),
            9,
            "the capacity that landed inside the window must survive: a whole-record write \
             would have restored the 1 this handler read"
        );
        // The concurrent writer holds the inner store directly, so this counter
        // sees only what the handler itself did — and a workspace mutation must
        // never write a whole host record.
        assert_eq!(
            store.put_hosts.load(Ordering::Relaxed),
            0,
            "the handler must reach `set_runner_root_override` and never `put_host`, which \
             is the only shape that cannot roll a concurrent column back"
        );
    }

    /// A root that moved inside the window is a refusal, and nothing is written.
    #[test]
    fn a_host_root_change_refuses_when_the_override_moved_under_it() {
        let data_dir = tempfile::tempdir().expect("a temporary directory");
        let roots = tempfile::tempdir().expect("a temporary directory");
        let context = a_context(data_dir.path());
        let inner = SqliteStore::open_in_memory().expect("an in-memory database");
        let host = a_host();
        inner.put_host(&host).expect("a fresh host");

        let id = host.id;
        let theirs = a_root(&roots, "theirs");
        let stolen = theirs.clone();
        let store = Interleaved::new(inner, At::HostCount, move |inner| {
            inner
                .set_runner_root_override(id, None, Some(&stolen), 0)
                .expect("the concurrent operator got there first");
        });

        let mine = a_root(&roots, "mine");
        let refused = set_host_runner_root(&context, &store, Some(mine.clone()))
            .expect_err("the stored override is no longer the one that was read");
        assert_eq!(refused.class(), Failure::Conflict);
        assert!(
            refused
                .message()
                .contains("another process changed it first"),
            "the refusal must say a race was lost rather than look like an I/O failure: {}",
            refused.message()
        );
        assert!(
            refused.message().contains("left in place"),
            "and it must name the empty directory it created before the write was refused, \
             which `03-migration-rollout.md` forbids it to delete: {}",
            refused.message()
        );
        assert!(
            mine.as_path().is_dir(),
            "named, and left: the handler may not remove a directory it did not prove it \
             created empty in this invocation"
        );

        let after = store.host(id).expect("readable").expect("still there");
        assert_eq!(
            after.runner_root_override,
            Some(theirs),
            "the concurrent value stands; the refused one was never written"
        );
    }

    /// A policy revision that moved inside the window is a refusal too.
    #[test]
    fn a_workspace_change_refuses_when_the_policy_moved_under_it() {
        let data_dir = tempfile::tempdir().expect("a temporary directory");
        let roots = tempfile::tempdir().expect("a temporary directory");
        let context = a_context(data_dir.path());
        let inner = SqliteStore::open_in_memory().expect("an in-memory database");
        let host = a_host();
        inner.put_host(&host).expect("a fresh host");
        let policy = a_policy(host.id);
        inner.insert_policy(&policy).expect("a fresh policy");

        let id = policy.id;
        let store = Interleaved::new(inner, At::PolicyCount, move |inner| {
            let mut concurrent = inner
                .policy(id)
                .expect("readable")
                .expect("the policy is there");
            let revision = concurrent.revision();
            concurrent
                .set_max_capacity(std::num::NonZeroU16::new(4).expect("non-zero"))
                .expect("a legal ceiling change");
            inner
                .update_policy(&concurrent, revision)
                .expect("the concurrent write");
        });

        let target = ScaleTarget::repository("octo/repo").expect("a valid slug");
        let root = a_root(&roots, "ci-cache");
        let refused = set_repository_workspace(
            &context,
            &store,
            &target,
            WorkspaceKind::Persistent,
            Some(root.clone()),
        )
        .expect_err("the revision this write was built from no longer exists");
        assert_eq!(refused.class(), Failure::Conflict);
        assert!(
            refused.message().contains("left in place"),
            "the created leaf is reported: {}",
            refused.message()
        );

        let after = store
            .policy(id)
            .expect("readable")
            .expect("still there")
            .clone();
        assert_eq!(
            after.workspace_policy(),
            &WorkspacePolicy::Ephemeral,
            "nothing was written, so the repository is still disposable"
        );
        assert_eq!(
            after.max_capacity().map(std::num::NonZeroU16::get),
            Some(4),
            "and the concurrent ceiling change was not rolled back either"
        );
    }

    /// The `ephemeral` mode refuses a path *in the shared handler*, not only at
    /// the command boundary.
    ///
    /// It lives beside the race tests because they are what already builds a
    /// `Context` over a real store, which is the whole fixture this needs.
    /// `repo set-workspace` refuses the combination before it ever gets here,
    /// so a caller that is not clap — the settings screen, which saves through
    /// this same function — is the only one that can reach the arm. Dropping
    /// the path silently is the outcome `02-target-architecture.md` rules out:
    /// "`ephemeral` rejects `--path` so an ignored argument cannot mislead".
    #[test]
    fn the_shared_handler_refuses_a_path_for_an_ephemeral_workspace() {
        let data_dir = tempfile::tempdir().expect("a temporary directory");
        let roots = tempfile::tempdir().expect("a temporary directory");
        let context = a_context(data_dir.path());
        let store = SqliteStore::open_in_memory().expect("an in-memory database");
        let host = a_host();
        store.put_host(&host).expect("a fresh host");
        let policy = a_policy(host.id);
        store.insert_policy(&policy).expect("a fresh policy");

        let target = ScaleTarget::repository("octo/repo").expect("a valid slug");
        let root = a_root(&roots, "ci-cache");
        let refused = set_repository_workspace(
            &context,
            &store,
            &target,
            WorkspaceKind::Ephemeral,
            Some(root.clone()),
        )
        .expect_err("an ephemeral workspace has no slots to place");
        assert_eq!(refused.class(), Failure::InvalidArgument);
        assert!(
            refused.message().contains("nothing was changed"),
            "the refusal must say the setting is untouched: {}",
            refused.message()
        );
        assert!(
            !root.as_path().exists(),
            "and a refused mutation creates no directory"
        );
        assert_eq!(
            store
                .policy(policy.id)
                .expect("readable")
                .expect("still there")
                .workspace_policy(),
            &WorkspacePolicy::Ephemeral,
        );
    }
}
