// owner: b1-local-model-corpus
//
//! The pure transition function, `(model, action) -> (exit class, expected
//! observation, next model)`, and the self-check that keeps it honest.
//!
//! # The three rules of `03-coverage-model.md`, and where each is enforced
//!
//! * *"On a refusal, `next model` equals `model`."* [`check`] refuses a
//!   refusal that carries any delta, unless the transition names a
//!   [`Deviation`] — a product behaviour, recorded here on purpose, where a
//!   refused command does leave something behind. There are three; each is a
//!   finding for a human, not a licence.
//! * *"On success, only the fields owned by the action may change."* Every
//!   change is a [`Delta`], [`Delta::kind`] names the field family it touches,
//!   and [`owned`] lists the families each command leaf may touch. [`check`]
//!   replays the deltas onto the previous model and requires the result to be
//!   *exactly* the expected next model, so an unlisted change and a listed
//!   change that did not happen both fail.
//! * *"Reads never change model state."* A read with any delta fails [`check`].
//!
//! The model is computed before the real command runs, and nothing here reads
//! production state. The order of the checks inside each function mirrors the
//! order the product performs them in, because that order decides which
//! refusal a doubly-wrong command reports.

use std::collections::BTreeSet;

use super::action::{
    Action, ActionKind, AddArgs, AttemptKind, Labels, Seed, Target, TargetKey, WorkspaceSetting,
};
use super::model::{
    BUDGET_ALLOWANCE_PER_HOUR, DEFAULT_HOST_CAPACITY, HostModel, Installation, Mode, Model, Policy,
    PolicyState, Tally,
};
use super::values::{Capacity, LabelValue, OrgName, PathValue, Relation, RepoName, Scope};

// ---------------------------------------------------------------------------
// Exit classes
// ---------------------------------------------------------------------------

/// The failure classes a local chain can meet, with the product's published
/// exit codes restated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Failure {
    NotAuthenticated,
    InvalidArgument,
    NotFound,
    Conflict,
    BudgetRefused,
}

impl Failure {
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Failure::NotAuthenticated => 3,
            Failure::InvalidArgument => 9,
            Failure::NotFound => 10,
            Failure::Conflict => 11,
            Failure::BudgetRefused => 12,
        }
    }

    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Failure::NotAuthenticated => "not_authenticated",
            Failure::InvalidArgument => "invalid_argument",
            Failure::NotFound => "not_found",
            Failure::Conflict => "conflict",
            Failure::BudgetRefused => "budget_refused",
        }
    }
}

/// The expected exit class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Exit {
    Success,
    Refused(Failure),
}

impl Exit {
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Exit::Success => 0,
            Exit::Refused(failure) => failure.code(),
        }
    }

    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Exit::Success)
    }

    #[must_use]
    pub fn describe(self) -> String {
        match self {
            Exit::Success => "ok(0)".to_string(),
            Exit::Refused(failure) => format!("{}({})", failure.token(), failure.code()),
        }
    }
}

/// Why a command is refused: the semantic refusal class, finer than the exit
/// code (several distinct refusals share `invalid_argument`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reason {
    InvalidTarget,
    InvalidHostLabel,
    InvalidLabel,
    ZeroHostCapacity,
    ZeroMaxCapacity,
    LabelsNeedAutoscale,
    LabelsOnMonitorOnly,
    NotAuthenticated,
    AppNotInstalled,
    TargetNotInstalled,
    DuplicateTarget,
    BudgetExceeded,
    EnableMonitorOnly,
    IllegalStateTransition,
    DisableNeedsConfirmation,
    MissingPolicy,
    DerivedLabelNotRemovable,
    PurgeWithActiveAttempts,
    RelativePath,
    OverlapsApplicationData,
    OverlapsHostRoot,
    OverlapsRepositoryRoot,
    ExistingFile,
    MissingParents,
    AttemptsOwnHostRoot,
    AttemptsOwnWorkspace,
    EphemeralRejectsPath,
}

impl Reason {
    pub const ALL: [Reason; 27] = [
        Reason::InvalidTarget,
        Reason::InvalidHostLabel,
        Reason::InvalidLabel,
        Reason::ZeroHostCapacity,
        Reason::ZeroMaxCapacity,
        Reason::LabelsNeedAutoscale,
        Reason::LabelsOnMonitorOnly,
        Reason::NotAuthenticated,
        Reason::AppNotInstalled,
        Reason::TargetNotInstalled,
        Reason::DuplicateTarget,
        Reason::BudgetExceeded,
        Reason::EnableMonitorOnly,
        Reason::IllegalStateTransition,
        Reason::DisableNeedsConfirmation,
        Reason::MissingPolicy,
        Reason::DerivedLabelNotRemovable,
        Reason::PurgeWithActiveAttempts,
        Reason::RelativePath,
        Reason::OverlapsApplicationData,
        Reason::OverlapsHostRoot,
        Reason::OverlapsRepositoryRoot,
        Reason::ExistingFile,
        Reason::MissingParents,
        Reason::AttemptsOwnHostRoot,
        Reason::AttemptsOwnWorkspace,
        Reason::EphemeralRejectsPath,
    ];

    #[must_use]
    pub const fn failure(self) -> Failure {
        match self {
            Reason::NotAuthenticated => Failure::NotAuthenticated,
            Reason::AppNotInstalled | Reason::TargetNotInstalled | Reason::MissingPolicy => {
                Failure::NotFound
            }
            Reason::DuplicateTarget
            | Reason::DisableNeedsConfirmation
            | Reason::PurgeWithActiveAttempts
            | Reason::AttemptsOwnHostRoot
            | Reason::AttemptsOwnWorkspace => Failure::Conflict,
            Reason::BudgetExceeded => Failure::BudgetRefused,
            _ => Failure::InvalidArgument,
        }
    }

    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Reason::InvalidTarget => "invalid-target",
            Reason::InvalidHostLabel => "invalid-host-label",
            Reason::InvalidLabel => "invalid-label",
            Reason::ZeroHostCapacity => "zero-host-capacity",
            Reason::ZeroMaxCapacity => "zero-max-capacity",
            Reason::LabelsNeedAutoscale => "labels-need-autoscale",
            Reason::LabelsOnMonitorOnly => "labels-on-monitor-only",
            Reason::NotAuthenticated => "not-authenticated",
            Reason::AppNotInstalled => "app-not-installed",
            Reason::TargetNotInstalled => "target-not-installed",
            Reason::DuplicateTarget => "duplicate-target",
            Reason::BudgetExceeded => "budget-exceeded",
            Reason::EnableMonitorOnly => "enable-monitor-only",
            Reason::IllegalStateTransition => "illegal-state-transition",
            Reason::DisableNeedsConfirmation => "disable-needs-confirmation",
            Reason::MissingPolicy => "missing-policy",
            Reason::DerivedLabelNotRemovable => "derived-label-not-removable",
            Reason::PurgeWithActiveAttempts => "purge-with-active-attempts",
            Reason::RelativePath => "relative-path",
            Reason::OverlapsApplicationData => "overlaps-application-data",
            Reason::OverlapsHostRoot => "overlaps-host-root",
            Reason::OverlapsRepositoryRoot => "overlaps-repository-root",
            Reason::ExistingFile => "existing-file",
            Reason::MissingParents => "missing-parents",
            Reason::AttemptsOwnHostRoot => "attempts-own-host-root",
            Reason::AttemptsOwnWorkspace => "attempts-own-workspace",
            Reason::EphemeralRejectsPath => "ephemeral-rejects-path",
        }
    }
}

/// A product behaviour the model predicts faithfully although it bends one of
/// `03-coverage-model.md`'s rules. Each is reported to a human; none may be
/// added to make a failing case pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Deviation {
    /// `host set-runtime-root` / `reset-runtime-root` create this machine's
    /// host record before validating, so a refused change on a fresh data root
    /// still leaves a host record behind.
    HostMaterializedByRefusal,
    /// `add --enable` without `--max-capacity` stores the monitor-only policy
    /// and then exits `invalid_argument` because it cannot be armed.
    PartialCommitOnEnable,
    /// A persistent root's owner is compared by the typed spelling, so a
    /// case-variant repository argument meets its own root as "another" one.
    OwnerComparedCaseSensitively,
}

impl Deviation {
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Deviation::HostMaterializedByRefusal => "host-materialized-by-refusal",
            Deviation::PartialCommitOnEnable => "partial-commit-on-enable",
            Deviation::OwnerComparedCaseSensitively => "owner-compared-case-sensitively",
        }
    }

    /// The only delta kinds a refusal carrying this deviation may hold.
    #[must_use]
    pub const fn permitted(self) -> &'static [DeltaKind] {
        match self {
            Deviation::HostMaterializedByRefusal => &[DeltaKind::HostMaterialized],
            Deviation::PartialCommitOnEnable => {
                &[DeltaKind::HostMaterialized, DeltaKind::PolicyAdded]
            }
            Deviation::OwnerComparedCaseSensitively => &[],
        }
    }
}

// ---------------------------------------------------------------------------
// The fake GitHub's request history
// ---------------------------------------------------------------------------

/// One request the loopback fake GitHub is expected to answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Request {
    DeviceCode,
    AccessToken,
    ListInstallations,
    ListRepositories(u64),
}

impl Request {
    /// `METHOD /path`, as the fixture records it.
    #[must_use]
    pub fn render(self) -> String {
        match self {
            Request::DeviceCode => "POST /login/device/code".to_string(),
            Request::AccessToken => "POST /login/oauth/access_token".to_string(),
            Request::ListInstallations => "GET /user/installations".to_string(),
            Request::ListRepositories(id) => format!("GET /user/installations/{id}/repositories"),
        }
    }

    /// Whether this request can change anything on GitHub's side. Only the two
    /// device-flow exchanges are POSTs, and both only create a sign-in.
    #[must_use]
    pub const fn is_read(self) -> bool {
        matches!(
            self,
            Request::ListInstallations | Request::ListRepositories(_)
        )
    }
}

/// The read-only discovery a valid credential triggers.
#[must_use]
pub fn discovery(installation: Installation) -> Vec<Request> {
    let mut requests = vec![Request::ListInstallations];
    requests.extend(
        installation
            .specs()
            .iter()
            .map(|spec| Request::ListRepositories(spec.id)),
    );
    requests
}

// ---------------------------------------------------------------------------
// Deltas
// ---------------------------------------------------------------------------

/// One owned change. Replaying a transition's deltas onto its previous model
/// must produce its next model exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delta {
    CredentialStored,
    CredentialRemoved,
    HostMaterialized,
    HostCapacity {
        from: u16,
        to: u16,
    },
    HostRunnerRoot {
        from: Option<PathValue>,
        to: Option<PathValue>,
    },
    DirectoryCreated(PathValue),
    PolicyAdded {
        key: TargetKey,
        policy: Policy,
    },
    PolicyRemoved {
        key: TargetKey,
        policy: Policy,
    },
    /// `from: None` is the D19 promotion from monitor-only.
    PolicyMaxCapacity {
        key: TargetKey,
        from: Option<u16>,
        to: u16,
    },
    PolicyLabels {
        key: TargetKey,
        added: Vec<String>,
        removed: Vec<String>,
    },
    PolicyScale {
        key: TargetKey,
        from: (bool, PolicyState),
        to: (bool, PolicyState),
    },
    PolicyWorkspace {
        key: TargetKey,
        from: Option<PathValue>,
        to: Option<PathValue>,
    },
    /// A removed policy's attempts stay in the journal as diagnostics.
    AttemptsRetained {
        key: TargetKey,
        tally: Tally,
    },
    PackageCachePurged,
}

/// The field family a delta touches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeltaKind {
    CredentialStored,
    CredentialRemoved,
    HostMaterialized,
    HostCapacity,
    HostRunnerRoot,
    DirectoryCreated,
    PolicyAdded,
    PolicyRemoved,
    PolicyMaxCapacity,
    PolicyLabels,
    PolicyScale,
    PolicyWorkspace,
    AttemptsRetained,
    PackageCachePurged,
}

impl Delta {
    #[must_use]
    pub const fn kind(&self) -> DeltaKind {
        match self {
            Delta::CredentialStored => DeltaKind::CredentialStored,
            Delta::CredentialRemoved => DeltaKind::CredentialRemoved,
            Delta::HostMaterialized => DeltaKind::HostMaterialized,
            Delta::HostCapacity { .. } => DeltaKind::HostCapacity,
            Delta::HostRunnerRoot { .. } => DeltaKind::HostRunnerRoot,
            Delta::DirectoryCreated(_) => DeltaKind::DirectoryCreated,
            Delta::PolicyAdded { .. } => DeltaKind::PolicyAdded,
            Delta::PolicyRemoved { .. } => DeltaKind::PolicyRemoved,
            Delta::PolicyMaxCapacity { .. } => DeltaKind::PolicyMaxCapacity,
            Delta::PolicyLabels { .. } => DeltaKind::PolicyLabels,
            Delta::PolicyScale { .. } => DeltaKind::PolicyScale,
            Delta::PolicyWorkspace { .. } => DeltaKind::PolicyWorkspace,
            Delta::AttemptsRetained { .. } => DeltaKind::AttemptsRetained,
            Delta::PackageCachePurged => DeltaKind::PackageCachePurged,
        }
    }

    /// The policy this delta belongs to, if it belongs to one.
    #[must_use]
    pub fn key(&self) -> Option<&TargetKey> {
        match self {
            Delta::PolicyAdded { key, .. }
            | Delta::PolicyRemoved { key, .. }
            | Delta::PolicyMaxCapacity { key, .. }
            | Delta::PolicyLabels { key, .. }
            | Delta::PolicyScale { key, .. }
            | Delta::PolicyWorkspace { key, .. }
            | Delta::AttemptsRetained { key, .. } => Some(key),
            _ => None,
        }
    }
}

/// The field families each leaf owns.
#[must_use]
pub fn owned(kind: ActionKind) -> &'static [DeltaKind] {
    match kind {
        ActionKind::AuthLogin => &[DeltaKind::CredentialStored],
        ActionKind::AuthLogout => &[DeltaKind::CredentialRemoved],
        ActionKind::HostSetCapacity => &[DeltaKind::HostMaterialized, DeltaKind::HostCapacity],
        ActionKind::HostSetRuntimeRoot => &[
            DeltaKind::HostMaterialized,
            DeltaKind::HostRunnerRoot,
            DeltaKind::DirectoryCreated,
        ],
        ActionKind::HostResetRuntimeRoot => {
            &[DeltaKind::HostMaterialized, DeltaKind::HostRunnerRoot]
        }
        ActionKind::RepoAdd | ActionKind::OrgAdd => &[
            DeltaKind::HostMaterialized,
            DeltaKind::PolicyAdded,
            DeltaKind::PolicyScale,
        ],
        ActionKind::RepoSetCapacity | ActionKind::OrgSetCapacity => &[DeltaKind::PolicyMaxCapacity],
        ActionKind::RepoSetScale | ActionKind::OrgSetScale => &[DeltaKind::PolicyScale],
        ActionKind::RepoAddLabel
        | ActionKind::OrgAddLabel
        | ActionKind::RepoRemoveLabel
        | ActionKind::OrgRemoveLabel => &[DeltaKind::PolicyLabels],
        ActionKind::RepoSetWorkspace => &[DeltaKind::PolicyWorkspace, DeltaKind::DirectoryCreated],
        ActionKind::RepoRemove | ActionKind::OrgRemove => &[
            DeltaKind::PolicyRemoved,
            DeltaKind::AttemptsRetained,
            DeltaKind::PackageCachePurged,
        ],
        ActionKind::HostShow
        | ActionKind::RepoList
        | ActionKind::OrgList
        | ActionKind::StatusJson => &[],
    }
}

/// Applies one delta.
///
/// # Errors
/// When the delta does not describe `model` — its `from` side disagrees, or it
/// adds what exists or removes what does not.
pub fn replay_one(model: &mut Model, delta: &Delta) -> Result<(), String> {
    match delta {
        Delta::CredentialStored => {
            if model.credential {
                return Err("CredentialStored over a stored credential".to_string());
            }
            model.credential = true;
        }
        Delta::CredentialRemoved => {
            if !model.credential {
                return Err("CredentialRemoved with none stored".to_string());
            }
            model.credential = false;
        }
        Delta::HostMaterialized => {
            if model.host.is_some() {
                return Err("HostMaterialized over an existing host record".to_string());
            }
            model.host = Some(HostModel {
                capacity: DEFAULT_HOST_CAPACITY,
                runner_root: None,
            });
        }
        Delta::HostCapacity { from, to } => {
            let host = model
                .host
                .as_mut()
                .ok_or("HostCapacity with no host record")?;
            if host.capacity != *from || from == to {
                return Err(format!(
                    "HostCapacity {from}->{to} does not describe capacity {}",
                    host.capacity
                ));
            }
            host.capacity = *to;
        }
        Delta::HostRunnerRoot { from, to } => {
            let host = model
                .host
                .as_mut()
                .ok_or("HostRunnerRoot with no host record")?;
            if host.runner_root != *from || from == to {
                return Err(format!(
                    "HostRunnerRoot {from:?}->{to:?} does not describe {:?}",
                    host.runner_root
                ));
            }
            host.runner_root = *to;
        }
        Delta::DirectoryCreated(path) => {
            if !model.directories.insert(*path) {
                return Err(format!("DirectoryCreated({path:?}) already exists"));
            }
        }
        Delta::PolicyAdded { key, policy } => {
            if model.policies.insert(key.clone(), policy.clone()).is_some() {
                return Err(format!("PolicyAdded over the existing {key}"));
            }
        }
        Delta::PolicyRemoved { key, policy } => match model.policies.remove(key) {
            Some(existing) if existing == *policy => {}
            Some(existing) => {
                return Err(format!(
                    "PolicyRemoved({key}) names {policy:?}, found {existing:?}"
                ));
            }
            None => return Err(format!("PolicyRemoved({key}) with no policy")),
        },
        Delta::PolicyMaxCapacity { key, from, to } => {
            let policy = model
                .policies
                .get_mut(key)
                .ok_or_else(|| format!("PolicyMaxCapacity names {key}, which has no policy"))?;
            if policy.max_capacity() != *from || *from == Some(*to) || *to == 0 {
                return Err(format!(
                    "PolicyMaxCapacity {from:?}->{to} does not describe {:?}",
                    policy.max_capacity()
                ));
            }
            match &mut policy.mode {
                Mode::MonitorOnly => {
                    policy.mode = Mode::Autoscale {
                        max_capacity: *to,
                        extra_labels: BTreeSet::new(),
                    };
                }
                Mode::Autoscale { max_capacity, .. } => *max_capacity = *to,
            }
        }
        Delta::PolicyLabels {
            key,
            added,
            removed,
        } => {
            let policy = model
                .policies
                .get_mut(key)
                .ok_or_else(|| format!("PolicyLabels names {key}, which has no policy"))?;
            let Mode::Autoscale { extra_labels, .. } = &mut policy.mode else {
                return Err(format!("PolicyLabels on the monitor-only {key}"));
            };
            if added.is_empty() && removed.is_empty() {
                return Err("an empty PolicyLabels is not a change".to_string());
            }
            for label in removed {
                if !extra_labels.remove(label) {
                    return Err(format!("PolicyLabels removes {label}, which {key} lacks"));
                }
            }
            for label in added {
                if !extra_labels.insert(label.clone()) {
                    return Err(format!("PolicyLabels adds {label}, which {key} has"));
                }
            }
        }
        Delta::PolicyScale { key, from, to } => {
            let policy = model
                .policies
                .get_mut(key)
                .ok_or_else(|| format!("PolicyScale names {key}, which has no policy"))?;
            if (policy.enabled, policy.state) != *from || from == to {
                return Err(format!(
                    "PolicyScale {from:?}->{to:?} does not describe {:?}",
                    (policy.enabled, policy.state)
                ));
            }
            (policy.enabled, policy.state) = *to;
        }
        Delta::PolicyWorkspace { key, from, to } => {
            let policy = model
                .policies
                .get_mut(key)
                .ok_or_else(|| format!("PolicyWorkspace names {key}, which has no policy"))?;
            if policy.workspace != *from || from == to {
                return Err(format!(
                    "PolicyWorkspace {from:?}->{to:?} does not describe {:?}",
                    policy.workspace
                ));
            }
            policy.workspace = *to;
        }
        Delta::AttemptsRetained { key, tally } => {
            if tally.is_empty() {
                return Err("an empty AttemptsRetained is not a change".to_string());
            }
            let entry = model.retained.entry(key.clone()).or_default();
            *entry = entry.plus(*tally);
        }
        Delta::PackageCachePurged => {
            if !model.package_cache {
                return Err("PackageCachePurged with no cache".to_string());
            }
            model.package_cache = false;
        }
    }
    Ok(())
}

/// Replays every delta, in order.
///
/// # Errors
/// The first delta that does not describe the model it is applied to.
pub fn replay(model: &Model, deltas: &[Delta]) -> Result<Model, String> {
    let mut next = model.clone();
    for delta in deltas {
        replay_one(&mut next, delta)?;
    }
    Ok(next)
}

// ---------------------------------------------------------------------------
// Transitions
// ---------------------------------------------------------------------------

/// Everything the model predicts about one action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub exit: Exit,
    /// The refusal class; `Some` exactly when `exit` is a refusal.
    pub reason: Option<Reason>,
    pub deviation: Option<Deviation>,
    /// Fragments stdout must contain.
    pub stdout: Vec<String>,
    /// Fragments stderr must contain.
    pub stderr: Vec<String>,
    /// The exact requests the fake GitHub must see for this action, in order.
    pub requests: Vec<Request>,
    pub deltas: Vec<Delta>,
    pub next: Model,
    /// Coverage facts this transition witnesses (boundary, cross-scope,
    /// invariant), besides its refusal class.
    pub tags: Vec<String>,
}

/// A transition under construction.
struct Draft<'a> {
    before: &'a Model,
    next: Model,
    deltas: Vec<Delta>,
    stdout: Vec<String>,
    stderr: Vec<String>,
    requests: Vec<Request>,
    tags: Vec<String>,
}

impl<'a> Draft<'a> {
    fn new(before: &'a Model) -> Self {
        Self {
            before,
            next: before.clone(),
            deltas: Vec::new(),
            stdout: Vec::new(),
            stderr: Vec::new(),
            requests: Vec::new(),
            tags: Vec::new(),
        }
    }

    fn change(&mut self, delta: Delta) {
        replay_one(&mut self.next, &delta).unwrap_or_else(|problem| {
            panic!("the model produced an inconsistent delta: {problem}")
        });
        self.deltas.push(delta);
    }

    fn out(&mut self, fragment: impl Into<String>) {
        self.stdout.push(fragment.into());
    }

    fn tag(&mut self, tag: impl Into<String>) {
        self.tags.push(tag.into());
    }

    fn materialize_host(&mut self) {
        if self.next.host.is_none() {
            self.change(Delta::HostMaterialized);
        }
    }

    fn finish(
        self,
        exit: Exit,
        reason: Option<Reason>,
        deviation: Option<Deviation>,
    ) -> Transition {
        let mut tags = self.tags;
        tags.sort();
        tags.dedup();
        Transition {
            exit,
            reason,
            deviation,
            stdout: self.stdout,
            stderr: self.stderr,
            requests: self.requests,
            deltas: self.deltas,
            next: self.next,
            tags,
        }
    }

    fn succeed(self) -> Transition {
        self.finish(Exit::Success, None, None)
    }

    /// A refusal. Every change drafted so far is discarded unless it is one
    /// the product really leaves behind, which is named as a deviation.
    fn refuse(mut self, reason: Reason, fragment: impl Into<String>) -> Transition {
        self.stderr.push("error: ".to_string());
        self.stderr.push(fragment.into());
        let deviation = if self.deltas.is_empty() {
            None
        } else if self
            .deltas
            .iter()
            .all(|delta| delta.kind() == DeltaKind::HostMaterialized)
        {
            Some(Deviation::HostMaterializedByRefusal)
        } else {
            Some(Deviation::PartialCommitOnEnable)
        };
        if let Some(deviation) = deviation {
            self.tags.push(format!("deviation:{}", deviation.slug()));
        }
        self.finish(Exit::Refused(reason.failure()), Some(reason), deviation)
    }
}

/// The model's prediction for one action. Pure: `model` is not modified.
#[must_use]
pub fn apply(model: &Model, action: &Action) -> Transition {
    let draft = Draft::new(model);
    match action {
        Action::AuthLogin => login(draft),
        Action::AuthLogout => logout(draft),
        Action::HostSetCapacity(capacity) => host_set_capacity(draft, *capacity),
        Action::HostSetRuntimeRoot(path) => host_runtime_root(draft, Some(*path)),
        Action::HostResetRuntimeRoot => host_runtime_root(draft, None),
        Action::HostShow => host_show(draft),
        Action::Add(args) => add(draft, args),
        Action::List(scope) => list(draft, *scope),
        Action::SetCapacity {
            target,
            max_capacity,
        } => set_capacity(draft, *target, *max_capacity),
        Action::SetScale { target, enabled } => set_scale(draft, *target, *enabled),
        Action::AddLabel { target, labels } => mutate_labels(draft, *target, labels, true),
        Action::RemoveLabel { target, labels } => mutate_labels(draft, *target, labels, false),
        Action::SetWorkspace { repo, setting } => set_workspace(draft, *repo, *setting),
        Action::Remove { target, purge } => remove(draft, *target, *purge),
        Action::StatusJson => status(draft),
    }
}

fn login(mut draft: Draft<'_>) -> Transition {
    if draft.before.credential {
        draft.requests = discovery(draft.before.installation);
        draft.out("Already signed in, so no new code is needed.");
        draft.tag("invariant:login-resumes-without-a-new-code");
    } else {
        draft.requests = vec![Request::DeviceCode, Request::AccessToken];
        draft.requests.extend(discovery(draft.before.installation));
        draft.change(Delta::CredentialStored);
        draft.out("Signed in.");
    }
    draft.succeed()
}

fn logout(mut draft: Draft<'_>) -> Transition {
    if draft.before.credential {
        draft.change(Delta::CredentialRemoved);
        draft.out("Removed the stored credential");
    } else {
        draft.out("There was no stored credential");
        draft.tag("invariant:logout-without-a-credential-is-a-no-op");
    }
    if !draft.before.policies.is_empty() {
        draft.tag("invariant:logout-leaves-policies");
    }
    draft.succeed()
}

fn host_set_capacity(mut draft: Draft<'_>, capacity: Capacity) -> Transition {
    let to = capacity.value();
    if to == 0 {
        return draft.refuse(
            Reason::ZeroHostCapacity,
            "a host capacity of 0 is not a configured host",
        );
    }
    draft.materialize_host();
    let from = draft.next.host_capacity();
    if from != to {
        draft.change(Delta::HostCapacity { from, to });
    } else {
        draft.tag("invariant:host-capacity-rewrite-is-idempotent");
    }
    let in_use = draft.before.in_use();
    draft.out(format!("host_capacity: {from} -> {to}"));
    draft.out(format!("(in use right now: {in_use})"));
    if in_use > to {
        draft.out("Nothing was terminated");
        draft.tag("boundary:host-capacity-below-in-use");
    }
    match capacity {
        Capacity::Max => draft.tag("boundary:host-capacity-u16-max"),
        Capacity::One => draft.tag("boundary:host-capacity-product-default"),
        _ => {}
    }
    draft.succeed()
}

/// Why a candidate root is refused, checked in the product's order: the
/// application data tree, then every other root (the host's first), then what
/// is on disk.
fn root_refusal(
    model: &Model,
    candidate: PathValue,
    others: &[(RootOwner, PathValue)],
) -> Option<(Reason, String, Option<RootOwner>)> {
    if candidate == PathValue::InsideAppState {
        return Some((
            Reason::OverlapsApplicationData,
            "application data must survive".to_string(),
            None,
        ));
    }
    for (owner, root) in others {
        if candidate.relation(*root) != Relation::Disjoint {
            return Some(match owner {
                RootOwner::Host => (
                    Reason::OverlapsHostRoot,
                    "the host runner root".to_string(),
                    Some(owner.clone()),
                ),
                RootOwner::Repository(display) => (
                    Reason::OverlapsRepositoryRoot,
                    format!("the persistent workspace root for {display}"),
                    Some(owner.clone()),
                ),
            });
        }
    }
    match candidate {
        PathValue::OccupiedFile => Some((
            Reason::ExistingFile,
            "already exists and is not a directory".to_string(),
            None,
        )),
        PathValue::DeepMissing => Some((
            Reason::MissingParents,
            "more than its last component is missing".to_string(),
            None,
        )),
        _ => match candidate.creatable_parent() {
            Some(parent) if !model.directory_exists(parent) => Some((
                Reason::MissingParents,
                "more than its last component is missing".to_string(),
                None,
            )),
            _ => None,
        },
    }
}

/// Who a root in the overlap set belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RootOwner {
    Host,
    /// By the spelling the product compares: the target as stored.
    Repository(String),
}

fn repository_roots(model: &Model, skip_display: Option<&str>) -> Vec<(RootOwner, PathValue)> {
    model
        .policies
        .values()
        .filter_map(|policy| policy.workspace.map(|root| (policy.display.clone(), root)))
        .filter(|(display, _)| Some(display.as_str()) != skip_display)
        .map(|(display, root)| (RootOwner::Repository(display), root))
        .collect()
}

fn host_runtime_root(mut draft: Draft<'_>, requested: Option<PathValue>) -> Transition {
    if requested == Some(PathValue::Relative) {
        return draft.refuse(
            Reason::RelativePath,
            "cannot be used as the host runner root",
        );
    }
    draft.materialize_host();
    let journal = draft.before.journal();
    if journal.uncleaned() > 0 {
        if draft.before.retained_total().uncleaned() > 0 {
            draft.tag("cross:retained-attempts-block-the-host-root");
        }
        let fragment = format!(
            "{} active and {} awaiting cleanup",
            journal.active, journal.awaiting_cleanup
        );
        return draft.refuse(Reason::AttemptsOwnHostRoot, fragment);
    }
    let from = draft.next.runner_root();
    if let Some(path) = requested {
        let others = repository_roots(draft.before, None);
        if let Some((reason, fragment, owner)) = root_refusal(draft.before, path, &others) {
            if owner.is_some() {
                draft.tag("cross:host-root-overlaps-a-repository-root");
            }
            if path.is_creatable_leaf() {
                draft.tag("invariant:refused-path-creates-nothing");
            }
            return draft.refuse(reason, fragment);
        }
        if path.is_creatable_leaf() && !draft.before.directory_exists(path) {
            draft.change(Delta::DirectoryCreated(path));
            draft.out("Created:");
        }
        draft.out("Runner root configured.");
    } else {
        draft.out("Runner root reset to the platform default.");
    }
    if from != requested {
        draft.change(Delta::HostRunnerRoot {
            from,
            to: requested,
        });
        draft.out("Retained:");
        if from.is_some() {
            draft.tag("invariant:host-root-change-leaves-the-old-directory");
        }
    } else {
        draft.tag("invariant:host-root-rewrite-is-idempotent");
    }
    draft.out("No existing directory was moved or deleted.");
    draft.succeed()
}

fn host_show(mut draft: Draft<'_>) -> Transition {
    if draft.before.host.is_some() {
        draft.out("Host: ");
    } else {
        draft.out("no host record yet");
    }
    draft.out("host_capacity");
    draft.succeed()
}

fn status(mut draft: Draft<'_>) -> Transition {
    draft.out("\"schema_version\"");
    draft.out("\"github_contacted\": false");
    draft.succeed()
}

fn invalid_target(draft: Draft<'_>, target: Target) -> Transition {
    let fragment = match target {
        Target::Repo(RepoName::Malformed) => "OWNER/REPO",
        Target::Repo(_) => "a repository name",
        Target::Org(OrgName::TrailingDash) | Target::Org(_) => "an organization login",
    };
    draft.refuse(Reason::InvalidTarget, fragment)
}

fn missing_policy(draft: Draft<'_>, target: Target) -> Transition {
    let fragment = format!("no policy for {} exists", target.token());
    draft.refuse(Reason::MissingPolicy, fragment)
}

/// The account a target belongs to: the owner of a repository, or the
/// organization itself.
fn account_of(key: &TargetKey) -> &str {
    match key.scope {
        Scope::Repository => key.slug.split('/').next().unwrap_or_default(),
        Scope::Organization => &key.slug,
    }
}

fn add(mut draft: Draft<'_>, args: &AddArgs) -> Transition {
    let Some(key) = args.target.key() else {
        return invalid_target(draft, args.target);
    };
    let Some(host_label) = args.host_label.canonical() else {
        return draft.refuse(Reason::InvalidHostLabel, "a host label");
    };
    let mut labels = Vec::new();
    for label in &args.labels {
        match label.canonical() {
            Some(folded) => labels.push(folded),
            None => return draft.refuse(Reason::InvalidLabel, "a label"),
        }
    }
    if args.max_capacity == Some(Capacity::Zero) {
        return draft.refuse(Reason::ZeroMaxCapacity, "max capacity must be at least 1");
    }
    if args.max_capacity.is_none() && !labels.is_empty() {
        return draft.refuse(
            Reason::LabelsNeedAutoscale,
            "--label needs a policy that starts runners",
        );
    }
    let typed = args.target.token();
    if !draft.before.credential {
        return draft.refuse(Reason::NotAuthenticated, format!("cannot validate {typed}"));
    }
    draft.requests = discovery(draft.before.installation);
    if draft.before.installation == Installation::None {
        return draft.refuse(
            Reason::AppNotInstalled,
            format!("the GitHub App is not installed for {typed}"),
        );
    }
    if !draft.before.installation.reaches(&key) {
        return draft.refuse(
            Reason::TargetNotInstalled,
            format!("the GitHub App is installed, but not on {typed}"),
        );
    }
    draft.materialize_host();
    if draft.before.policies.contains_key(&key) {
        draft.tag("invariant:duplicate-add-keeps-the-existing-policy");
        return draft.refuse(
            Reason::DuplicateTarget,
            format!("a policy for {typed} already exists"),
        );
    }
    let cost = draft.before.admission_cost(&key);
    let projected = draft.before.admitted_cost() + cost;
    if projected > BUDGET_ALLOWANCE_PER_HOUR {
        draft.tag("boundary:budget-ceiling");
        let other = match key.scope {
            Scope::Repository => Scope::Organization,
            Scope::Organization => Scope::Repository,
        };
        if draft.before.has_scope(other) {
            draft.tag("cross:budget-counts-the-other-scope");
        }
        return draft.refuse(Reason::BudgetExceeded, "No policy was stored.");
    }
    if BUDGET_ALLOWANCE_PER_HOUR - projected < super::model::repository_admission_cost() {
        draft.tag("boundary:budget-filled");
    }

    let derived = super::values::derived_symbol(&host_label);
    if labels.contains(&derived) {
        draft.tag("invariant:derived-label-is-never-duplicated");
    }
    let mode = match args.max_capacity {
        Some(maximum) => Mode::Autoscale {
            max_capacity: maximum.value(),
            extra_labels: labels
                .into_iter()
                .filter(|label| *label != derived)
                .collect(),
        },
        None => Mode::MonitorOnly,
    };
    let monitor_only = mode == Mode::MonitorOnly;
    let policy = Policy {
        display: typed.clone(),
        host_label,
        mode,
        enabled: false,
        state: PolicyState::Pending,
        workspace: None,
        attempts: Tally::default(),
    };
    if draft.before.retained.contains_key(&key) {
        draft.tag("invariant:re-added-target-starts-fresh");
    }
    let account = account_of(&key).to_string();
    if draft
        .before
        .policies
        .keys()
        .any(|other| other.scope != key.scope && account_of(other) == account)
    {
        draft.tag("cross:repository-and-organization-policies-coexist");
    }
    match args.host_label.class() {
        "boundary-64" => draft.tag("boundary:host-label-64"),
        "case-variant" => draft.tag("invariant:host-label-folds-case"),
        _ => {}
    }
    if args.labels.contains(&LabelValue::Max256) {
        draft.tag("boundary:label-256");
    }
    if args.max_capacity == Some(Capacity::Max) {
        draft.tag("boundary:policy-capacity-u16-max");
    }
    draft.change(Delta::PolicyAdded {
        key: key.clone(),
        policy,
    });
    draft.out(format!(
        "Added {} policy for {typed} in pending; scaling is disabled.",
        key.scope.word()
    ));
    if monitor_only {
        draft.out("Monitor-only");
    } else {
        draft.out("Routing labels: ");
    }
    if args.enable {
        if monitor_only {
            return draft.refuse(
                Reason::EnableMonitorOnly,
                "monitor-only policies cannot be enabled",
            );
        }
        draft.change(Delta::PolicyScale {
            key,
            from: (false, PolicyState::Pending),
            to: (true, PolicyState::Active),
        });
        draft.out(format!("Scaling enabled for {typed}."));
    }
    draft.succeed()
}

fn list(mut draft: Draft<'_>, scope: Scope) -> Transition {
    let lines = draft.before.list_lines(scope);
    if lines.is_empty() {
        draft.out(format!("No {} policies.", scope.word()));
    }
    for line in lines {
        draft.out(line);
    }
    let repairs: Vec<String> = draft
        .before
        .policies
        .iter()
        .filter(|(key, policy)| key.scope == scope && policy.state == PolicyState::RepairRequired)
        .map(|(_, policy)| {
            format!(
                "repair: runner-manager {} remove {} --purge",
                scope.word(),
                policy.display
            )
        })
        .collect();
    for repair in repairs {
        draft.out(repair);
    }
    if scope == Scope::Organization && draft.before.has_scope(Scope::Organization) {
        draft.out("persistent workspaces require repository scope");
    }
    draft.succeed()
}

fn set_capacity(mut draft: Draft<'_>, target: Target, capacity: Capacity) -> Transition {
    let Some(key) = target.key() else {
        return invalid_target(draft, target);
    };
    let Some(policy) = draft.before.policies.get(&key).cloned() else {
        if capacity == Capacity::Zero {
            draft.tag("invariant:missing-target-is-reported-before-a-zero-capacity");
        }
        return missing_policy(draft, target);
    };
    if capacity == Capacity::Zero {
        return draft.refuse(Reason::ZeroMaxCapacity, "max capacity must be at least 1");
    }
    let to = capacity.value();
    let from = policy.max_capacity();
    if from.is_none() {
        draft.tag("boundary:monitor-only-promoted");
    }
    if from != Some(to) {
        draft.change(Delta::PolicyMaxCapacity { key, from, to });
    } else {
        draft.tag("invariant:capacity-rewrite-is-idempotent");
    }
    match capacity {
        Capacity::Max => draft.tag("boundary:policy-capacity-u16-max"),
        Capacity::One => draft.tag("boundary:policy-capacity-one"),
        _ => {}
    }
    draft.out(format!(
        "{} max capacity is now {to}; scaling remains {}.",
        target.token(),
        if policy.enabled {
            "enabled"
        } else {
            "disabled"
        }
    ));
    draft.out("Routing labels: ");
    draft.succeed()
}

fn set_scale(mut draft: Draft<'_>, target: Target, enabled: bool) -> Transition {
    let Some(key) = target.key() else {
        return invalid_target(draft, target);
    };
    let Some(policy) = draft.before.policies.get(&key).cloned() else {
        return missing_policy(draft, target);
    };
    let active = policy.attempts.active;
    if !enabled && active > 0 {
        // The runner supplies no stdin, so the drain confirmation reads end of
        // input, which is "no".
        draft.out("Continue? [y/N]");
        return draft.refuse(
            Reason::DisableNeedsConfirmation,
            "disable cancelled; the policy was not changed",
        );
    }
    let from = (policy.enabled, policy.state);
    if enabled {
        if policy.mode == Mode::MonitorOnly {
            return draft.refuse(
                Reason::EnableMonitorOnly,
                "monitor-only policies cannot be enabled",
            );
        }
        if policy.enabled {
            draft.tag("invariant:repeat-enable-is-idempotent");
        } else {
            let entry = if policy.state == PolicyState::Disabled {
                draft.tag("invariant:disabled-policy-can-be-re-armed");
                PolicyState::Pending
            } else {
                policy.state
            };
            if entry != PolicyState::Pending {
                return draft.refuse(
                    Reason::IllegalStateTransition,
                    "is not a legal transition from",
                );
            }
            draft.change(Delta::PolicyScale {
                key,
                from,
                to: (true, PolicyState::Active),
            });
        }
        draft.out(format!("Scaling enabled for {}.", policy.display));
    } else {
        let to = if policy.enabled || policy.state == PolicyState::Draining {
            if policy.state == PolicyState::Draining {
                draft.tag("invariant:repeated-disable-completes-a-drain");
            }
            (false, PolicyState::Disabled)
        } else {
            draft.tag("invariant:disabling-an-unarmed-policy-is-a-no-op");
            from
        };
        if to != from {
            draft.change(Delta::PolicyScale { key, from, to });
        }
        draft.out(format!(
            "{} is disabled with 0 active runner(s)",
            policy.display
        ));
    }
    draft.succeed()
}

fn mutate_labels(
    mut draft: Draft<'_>,
    target: Target,
    labels: &Labels,
    adding: bool,
) -> Transition {
    let Some(key) = target.key() else {
        return invalid_target(draft, target);
    };
    let mut folded = Vec::new();
    for label in labels.values() {
        match label.canonical() {
            Some(value) => folded.push(value),
            None => return draft.refuse(Reason::InvalidLabel, "a label"),
        }
    }
    let Some(policy) = draft.before.policies.get(&key).cloned() else {
        return missing_policy(draft, target);
    };
    let typed = target.token();
    let Mode::Autoscale { extra_labels, .. } = &policy.mode else {
        return draft.refuse(
            Reason::LabelsOnMonitorOnly,
            format!("{typed} is monitor-only, so it has no routing labels to change"),
        );
    };
    let derived = policy.derived_label();
    let mut extras = extra_labels.clone();
    let mut changed: Vec<String> = Vec::new();
    for label in folded {
        if adding {
            if label == derived {
                draft.tag("invariant:derived-label-is-never-duplicated");
            } else if extras.insert(label.clone()) {
                changed.push(label);
            }
        } else if label == derived {
            if !changed.is_empty() {
                draft.tag("invariant:multi-label-refusal-is-atomic");
            }
            return draft.refuse(Reason::DerivedLabelNotRemovable, "cannot be removed");
        } else if extras.remove(&label) {
            changed.push(label);
        }
    }
    if labels.values().contains(&LabelValue::Max256) && adding {
        draft.tag("boundary:label-256");
    }
    if labels
        .values()
        .iter()
        .any(|value| matches!(value, LabelValue::GpuCase | LabelValue::DerivedCase(_)))
    {
        draft.tag("invariant:labels-fold-case");
    }
    if changed.is_empty() {
        draft.tag("invariant:label-change-is-idempotent");
        draft.out(format!(
            "No label changed; {typed} already had them that way."
        ));
    } else {
        draft.out(format!(
            "{typed} {}: {}",
            if adding {
                "now answers"
            } else {
                "no longer answers"
            },
            changed.join(", ")
        ));
        let (added, removed) = if adding {
            (changed, Vec::new())
        } else {
            (Vec::new(), changed)
        };
        draft.change(Delta::PolicyLabels {
            key,
            added,
            removed,
        });
    }
    draft.out("Routing labels: ");
    if !extras.is_empty() {
        draft.out("warning: a label another runner also answers");
    }
    draft.succeed()
}

fn set_workspace(mut draft: Draft<'_>, repo: RepoName, setting: WorkspaceSetting) -> Transition {
    let target = Target::Repo(repo);
    let Some(key) = target.key() else {
        return invalid_target(draft, target);
    };
    let typed = repo.token();
    let requested = match setting {
        WorkspaceSetting::EphemeralWithPath(_) => {
            return draft.refuse(
                Reason::EphemeralRejectsPath,
                "an ephemeral workspace has none; nothing was changed",
            );
        }
        WorkspaceSetting::Persistent(PathValue::Relative) => {
            return draft.refuse(
                Reason::RelativePath,
                format!("cannot be used as the persistent workspace root for {typed}"),
            );
        }
        WorkspaceSetting::Persistent(path) => Some(path),
        WorkspaceSetting::Ephemeral => None,
    };
    let Some(policy) = draft.before.policies.get(&key).cloned() else {
        return missing_policy(draft, target);
    };
    if policy.attempts.uncleaned() > 0 {
        let fragment = format!(
            "{} active and {} awaiting cleanup",
            policy.attempts.active, policy.attempts.awaiting_cleanup
        );
        return draft.refuse(Reason::AttemptsOwnWorkspace, fragment);
    }
    if let Some(path) = requested {
        let mut others: Vec<(RootOwner, PathValue)> = Vec::new();
        if let Some(host_root) = draft.before.runner_root() {
            others.push((RootOwner::Host, host_root));
        }
        // The owner is compared by the typed spelling against the stored one.
        others.extend(repository_roots(draft.before, Some(typed.as_str())));
        if let Some((reason, fragment, owner)) = root_refusal(draft.before, path, &others) {
            match &owner {
                Some(RootOwner::Host) => draft.tag("cross:repository-root-overlaps-the-host-root"),
                Some(RootOwner::Repository(display)) => {
                    if *display == policy.display {
                        let mut refused = draft.refuse(reason, fragment);
                        refused.deviation = Some(Deviation::OwnerComparedCaseSensitively);
                        refused.tags.push(format!(
                            "deviation:{}",
                            Deviation::OwnerComparedCaseSensitively.slug()
                        ));
                        refused.tags.sort();
                        return refused;
                    }
                    draft.tag("invariant:repository-roots-never-overlap");
                }
                None => {}
            }
            if path.is_creatable_leaf() {
                draft.tag("invariant:refused-path-creates-nothing");
            }
            return draft.refuse(reason, fragment);
        }
        if path.is_creatable_leaf() && !draft.before.directory_exists(path) {
            draft.change(Delta::DirectoryCreated(path));
            draft.out("Created:");
        }
    }
    let from = policy.workspace;
    if from != requested {
        draft.change(Delta::PolicyWorkspace {
            key,
            from,
            to: requested,
        });
        if from.is_some() {
            draft.out("Left in place:");
            draft.tag("invariant:workspace-change-leaves-the-old-root");
        }
    } else {
        draft.tag("invariant:workspace-rewrite-is-idempotent");
    }
    draft.out(format!(
        "Workspace mode: {}",
        if requested.is_some() {
            "persistent"
        } else {
            "ephemeral"
        }
    ));
    if requested.is_some() {
        draft.out(
            "warning: a persistent workspace is a trusted-workflow optimization, not isolation.",
        );
    }
    draft.out("No existing directory was moved or deleted.");
    draft.succeed()
}

fn remove(mut draft: Draft<'_>, target: Target, purge: bool) -> Transition {
    let Some(key) = target.key() else {
        return invalid_target(draft, target);
    };
    let Some(policy) = draft.before.policies.get(&key).cloned() else {
        return missing_policy(draft, target);
    };
    let typed = target.token();
    if purge && policy.attempts.active > 0 {
        let fragment = format!(
            "cannot purge {typed} while {} active runner(s) exist",
            policy.attempts.active
        );
        return draft.refuse(Reason::PurgeWithActiveAttempts, fragment);
    }
    let attempts = policy.attempts;
    draft.change(Delta::PolicyRemoved {
        key: key.clone(),
        policy,
    });
    let account = account_of(&key).to_string();
    if draft
        .next
        .policies
        .keys()
        .any(|other| other.scope != key.scope && account_of(other) == account)
    {
        draft.tag("cross:removal-leaves-the-other-scope-policy");
    }
    if purge {
        if draft.next.policies.is_empty() {
            if draft.next.package_cache {
                draft.change(Delta::PackageCachePurged);
            }
            draft.out("purged because no policy still uses it");
        } else {
            draft.out("preserved because another policy still uses it");
            if draft.before.package_cache {
                let other_scope_only = draft
                    .next
                    .policies
                    .keys()
                    .all(|other| other.scope != key.scope);
                draft.tag(if other_scope_only {
                    "cross:purge-keeps-the-cache-for-the-other-scope"
                } else {
                    "invariant:purge-keeps-a-shared-cache-in-use"
                });
            }
        }
        draft.out(format!(
            "Removed {typed} and purged its historical diagnostics."
        ));
    } else {
        if !attempts.is_empty() {
            draft.change(Delta::AttemptsRetained {
                key: key.clone(),
                tally: attempts,
            });
            draft.tag("invariant:non-purge-removal-retains-diagnostics");
            if attempts.active > 0 {
                draft.tag("cross:removed-policy-attempts-still-count-host-wide");
            }
        }
        draft.out(format!(
            "Removed {typed}; cache and historical diagnostics were preserved."
        ));
    }
    draft.succeed()
}

// ---------------------------------------------------------------------------
// Seeds
// ---------------------------------------------------------------------------

/// Applies a seeded fact.
///
/// # Errors
/// When the seed's precondition does not hold in `model`: a seed describes a
/// state the daemon or another process could have produced from *this* one,
/// not an arbitrary edit.
pub fn seed(model: &Model, seed: &Seed) -> Result<Model, String> {
    let mut next = model.clone();
    let policy_of = |next: &mut Model, target: &Target| -> Result<TargetKey, String> {
        let key = target
            .key()
            .ok_or_else(|| format!("{} is not a valid target", target.token()))?;
        if next.policies.contains_key(&key) {
            Ok(key)
        } else {
            Err(format!("no policy for {key} to seed"))
        }
    };
    match seed {
        Seed::Credential => {
            if next.credential {
                return Err("a credential is already stored".to_string());
            }
            next.credential = true;
        }
        Seed::Attempt { target, kind } => {
            let key = policy_of(&mut next, target)?;
            let attempts = &mut next.policies.get_mut(&key).expect("checked").attempts;
            match kind {
                AttemptKind::Active => attempts.active += 1,
                AttemptKind::AwaitingCleanup => attempts.awaiting_cleanup += 1,
                AttemptKind::Cleaned => attempts.cleaned += 1,
            }
        }
        Seed::RepairRequired(target) => {
            let key = policy_of(&mut next, target)?;
            let policy = next.policies.get_mut(&key).expect("checked");
            if policy.state != PolicyState::Pending {
                return Err(format!(
                    "only a pending policy can become repair_required, not {}",
                    policy.state.token()
                ));
            }
            policy.state = PolicyState::RepairRequired;
        }
        Seed::Drain(target) => {
            let key = policy_of(&mut next, target)?;
            let policy = next.policies.get_mut(&key).expect("checked");
            if policy.state != PolicyState::Active {
                return Err(format!(
                    "only an active policy can drain, not {}",
                    policy.state.token()
                ));
            }
            policy.state = PolicyState::Draining;
            policy.enabled = false;
        }
        Seed::PackageCache => {
            if next.package_cache {
                return Err("the package cache already exists".to_string());
            }
            next.package_cache = true;
        }
    }
    Ok(next)
}

// ---------------------------------------------------------------------------
// The self-check
// ---------------------------------------------------------------------------

/// Checks a transition against the model's contract without re-running the
/// transition function, so a corrupted expectation is judged by rules rather
/// than by the code that produced it.
///
/// # Errors
/// The first broken rule.
pub fn check(before: &Model, action: &Action, transition: &Transition) -> Result<(), String> {
    let kind = action.kind();
    match (transition.exit, transition.reason) {
        (Exit::Success, None) => {}
        (Exit::Refused(failure), Some(reason)) if reason.failure() == failure => {}
        (exit, reason) => {
            return Err(format!(
                "exit {exit:?} does not agree with reason {reason:?}"
            ));
        }
    }
    let replayed = replay(before, &transition.deltas)?;
    if replayed != transition.next {
        return Err(format!(
            "the deltas do not produce the expected next model:\n  replayed: {replayed:?}\n  expected: {:?}",
            transition.next
        ));
    }
    transition.next.validate()?;
    for delta in &transition.deltas {
        if !owned(kind).contains(&delta.kind()) {
            return Err(format!("{kind} does not own {:?}", delta.kind()));
        }
        if let (Some(key), Some(target)) = (delta.key(), action.target())
            && Some(key) != target.key().as_ref()
        {
            return Err(format!("{kind} on {} changed {key}", target.token()));
        }
    }
    if kind.is_read() && (!transition.deltas.is_empty() || !transition.exit.is_success()) {
        return Err(format!("the read {kind} must succeed and change nothing"));
    }
    if !transition.exit.is_success() {
        match transition.deviation {
            None if !transition.deltas.is_empty() => {
                return Err(format!(
                    "a refusal must leave the model unchanged, but {kind} carries {:?}",
                    transition.deltas
                ));
            }
            Some(deviation) => {
                if let Some(delta) = transition
                    .deltas
                    .iter()
                    .find(|delta| !deviation.permitted().contains(&delta.kind()))
                {
                    return Err(format!("{deviation:?} does not permit {delta:?}"));
                }
            }
            None => {}
        }
    } else if transition.deviation.is_some() {
        return Err("only a refusal can carry a deviation".to_string());
    }
    // GitHub is only ever read, except by the two device-flow exchanges of a
    // sign-in that had no credential to resume.
    let posts = transition
        .requests
        .iter()
        .filter(|request| !request.is_read())
        .count();
    let signing_in = kind == ActionKind::AuthLogin && !before.credential;
    if posts != if signing_in { 2 } else { 0 } {
        return Err(format!(
            "{kind} makes {posts} non-read request(s): {:?}",
            transition.requests
        ));
    }
    let discovers = matches!(
        kind,
        ActionKind::AuthLogin | ActionKind::RepoAdd | ActionKind::OrgAdd
    );
    if !discovers && !transition.requests.is_empty() {
        return Err(format!("{kind} must not contact GitHub"));
    }
    if transition.requests.len() > 2 + discovery(before.installation).len() {
        return Err(format!("{kind} exceeds its request bound"));
    }
    if matches!(kind, ActionKind::RepoAdd | ActionKind::OrgAdd)
        && !before.credential
        && !transition.requests.is_empty()
    {
        return Err("an add with no credential must not contact GitHub".to_string());
    }
    Ok(())
}
