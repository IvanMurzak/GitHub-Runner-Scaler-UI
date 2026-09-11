// owner: b1-local-model-corpus
//
//! The typed action grammar: the allowlist, and the only road to an argument
//! vector.
//!
//! # The allowlist is an enum, and that is the security property
//!
//! `02-target-architecture.md`: "The action grammar is an enum, not arbitrary
//! strings." [`Action`] has one variant per allowlisted command leaf, each field
//! is one of the closed value sets in [`super::values`], and [`Action::argv`] is
//! a `match` that spells each variant out literally. There is no parser in the
//! other direction: the checked-in inventory is *rendered from* typed cases and
//! compared, never read back into a command. `daemon run`, `service`, `update`,
//! `tui`, `wsl` and every hidden command are unreachable by construction, and
//! `only_allowlisted_commands_are_generated` in `cli_chains_model.rs` checks
//! the rendered vectors anyway.
//!
//! # CLI syntax is enforced here; domain validity is not
//!
//! `03-coverage-model.md`: "The action constructor enforces CLI syntax;
//! domain-invalid values remain available so refusal paths are covered." So a
//! label command cannot be built with no label (the parser requires one), a
//! persistent workspace cannot be built without a path (a usage error), and a
//! capacity is a `u16` — while a zero capacity, a malformed repository, or an
//! ephemeral workspace *with* a path are all constructible, because the product
//! refuses those itself and that refusal is what the corpus exists to observe.

use std::fmt;

use super::values::{
    Capacity, HostLabelValue, LabelValue, OrgName, PathValue, RepoName, Resolver, Scope,
};

/// The subject of a policy command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Target {
    Repo(RepoName),
    Org(OrgName),
}

impl Target {
    #[must_use]
    pub const fn scope(self) -> Scope {
        match self {
            Target::Repo(_) => Scope::Repository,
            Target::Org(_) => Scope::Organization,
        }
    }

    /// The literal argument, exactly as typed.
    #[must_use]
    pub fn token(self) -> String {
        match self {
            Target::Repo(repo) => repo.token(),
            Target::Org(org) => org.token(),
        }
    }

    /// The case-folded identity, or `None` for a spelling the product refuses.
    #[must_use]
    pub fn key(self) -> Option<TargetKey> {
        let canonical = match self {
            Target::Repo(repo) => repo.canonical(),
            Target::Org(org) => org.canonical(),
        }?;
        Some(TargetKey {
            scope: self.scope(),
            slug: canonical,
        })
    }

    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Target::Repo(repo) => repo.class(),
            Target::Org(org) => org.class(),
        }
    }
}

/// A target's identity: scope plus case-folded slug.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TargetKey {
    pub scope: Scope,
    pub slug: String,
}

impl fmt::Display for TargetKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.scope.word(), self.slug)
    }
}

/// One or more `--label` values. Empty is unrepresentable because the parser
/// requires at least one for `add-label` and `remove-label`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Labels(Vec<LabelValue>);

impl Labels {
    /// # Panics
    /// On an empty list: that is a usage error, not a corpus value.
    #[must_use]
    pub fn of(values: &[LabelValue]) -> Self {
        assert!(
            !values.is_empty(),
            "a label command needs at least one --label"
        );
        Self(values.to_vec())
    }

    #[must_use]
    pub fn values(&self) -> &[LabelValue] {
        &self.0
    }
}

/// `repo set-workspace --mode … [--path …]`.
///
/// `--mode persistent` with no path is a usage error and has no variant;
/// `--mode ephemeral --path …` is a domain refusal and does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WorkspaceSetting {
    Ephemeral,
    EphemeralWithPath(PathValue),
    Persistent(PathValue),
}

/// `repo add` / `org add`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AddArgs {
    pub target: Target,
    pub host_label: HostLabelValue,
    pub max_capacity: Option<Capacity>,
    pub labels: Vec<LabelValue>,
    pub enable: bool,
}

/// Every allowlisted local action.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    /// `auth login` against the loopback fake GitHub.
    AuthLogin,
    /// `auth logout`.
    AuthLogout,
    HostSetCapacity(Capacity),
    HostSetRuntimeRoot(PathValue),
    HostResetRuntimeRoot,
    HostShow,
    Add(AddArgs),
    List(Scope),
    SetCapacity {
        target: Target,
        max_capacity: Capacity,
    },
    SetScale {
        target: Target,
        enabled: bool,
    },
    AddLabel {
        target: Target,
        labels: Labels,
    },
    RemoveLabel {
        target: Target,
        labels: Labels,
    },
    /// Repository scope only: `org` has no `set-workspace` leaf.
    SetWorkspace {
        repo: RepoName,
        setting: WorkspaceSetting,
    },
    Remove {
        target: Target,
        purge: bool,
    },
    StatusJson,
}

/// An action's command leaf, without its arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ActionKind {
    AuthLogin,
    AuthLogout,
    HostSetCapacity,
    HostSetRuntimeRoot,
    HostResetRuntimeRoot,
    HostShow,
    RepoAdd,
    RepoList,
    RepoSetCapacity,
    RepoSetScale,
    RepoAddLabel,
    RepoRemoveLabel,
    RepoSetWorkspace,
    RepoRemove,
    OrgAdd,
    OrgList,
    OrgSetCapacity,
    OrgSetScale,
    OrgAddLabel,
    OrgRemoveLabel,
    OrgRemove,
    StatusJson,
}

impl ActionKind {
    /// Every leaf the local model drives, in a fixed order.
    pub const ALL: [ActionKind; 22] = [
        ActionKind::AuthLogin,
        ActionKind::AuthLogout,
        ActionKind::HostSetCapacity,
        ActionKind::HostSetRuntimeRoot,
        ActionKind::HostResetRuntimeRoot,
        ActionKind::HostShow,
        ActionKind::RepoAdd,
        ActionKind::RepoList,
        ActionKind::RepoSetCapacity,
        ActionKind::RepoSetScale,
        ActionKind::RepoAddLabel,
        ActionKind::RepoRemoveLabel,
        ActionKind::RepoSetWorkspace,
        ActionKind::RepoRemove,
        ActionKind::OrgAdd,
        ActionKind::OrgList,
        ActionKind::OrgSetCapacity,
        ActionKind::OrgSetScale,
        ActionKind::OrgAddLabel,
        ActionKind::OrgRemoveLabel,
        ActionKind::OrgRemove,
        ActionKind::StatusJson,
    ];

    /// The stable dotted name used in coverage units and the inventory.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            ActionKind::AuthLogin => "auth.login",
            ActionKind::AuthLogout => "auth.logout",
            ActionKind::HostSetCapacity => "host.set-capacity",
            ActionKind::HostSetRuntimeRoot => "host.set-runtime-root",
            ActionKind::HostResetRuntimeRoot => "host.reset-runtime-root",
            ActionKind::HostShow => "host.show",
            ActionKind::RepoAdd => "repo.add",
            ActionKind::RepoList => "repo.list",
            ActionKind::RepoSetCapacity => "repo.set-capacity",
            ActionKind::RepoSetScale => "repo.set-scale",
            ActionKind::RepoAddLabel => "repo.add-label",
            ActionKind::RepoRemoveLabel => "repo.remove-label",
            ActionKind::RepoSetWorkspace => "repo.set-workspace",
            ActionKind::RepoRemove => "repo.remove",
            ActionKind::OrgAdd => "org.add",
            ActionKind::OrgList => "org.list",
            ActionKind::OrgSetCapacity => "org.set-capacity",
            ActionKind::OrgSetScale => "org.set-scale",
            ActionKind::OrgAddLabel => "org.add-label",
            ActionKind::OrgRemoveLabel => "org.remove-label",
            ActionKind::OrgRemove => "org.remove",
            ActionKind::StatusJson => "status.json",
        }
    }

    /// Reads never change state; everything else may.
    #[must_use]
    pub const fn is_read(self) -> bool {
        matches!(
            self,
            ActionKind::HostShow
                | ActionKind::RepoList
                | ActionKind::OrgList
                | ActionKind::StatusJson
        )
    }

    #[must_use]
    pub const fn is_mutating(self) -> bool {
        !self.is_read()
    }

    /// The mutating leaves, in [`ActionKind::ALL`] order.
    #[must_use]
    pub fn mutating() -> Vec<ActionKind> {
        Self::ALL.into_iter().filter(|k| k.is_mutating()).collect()
    }

    /// The read leaves, in [`ActionKind::ALL`] order.
    #[must_use]
    pub fn reads() -> Vec<ActionKind> {
        Self::ALL.into_iter().filter(|k| k.is_read()).collect()
    }

    /// The two leading argument-vector words of this leaf.
    #[must_use]
    pub const fn command_path(self) -> [&'static str; 2] {
        match self {
            ActionKind::AuthLogin => ["auth", "login"],
            ActionKind::AuthLogout => ["auth", "logout"],
            ActionKind::HostSetCapacity => ["host", "set-capacity"],
            ActionKind::HostSetRuntimeRoot => ["host", "set-runtime-root"],
            ActionKind::HostResetRuntimeRoot => ["host", "reset-runtime-root"],
            ActionKind::HostShow => ["host", "show"],
            ActionKind::RepoAdd => ["repo", "add"],
            ActionKind::RepoList => ["repo", "list"],
            ActionKind::RepoSetCapacity => ["repo", "set-capacity"],
            ActionKind::RepoSetScale => ["repo", "set-scale"],
            ActionKind::RepoAddLabel => ["repo", "add-label"],
            ActionKind::RepoRemoveLabel => ["repo", "remove-label"],
            ActionKind::RepoSetWorkspace => ["repo", "set-workspace"],
            ActionKind::RepoRemove => ["repo", "remove"],
            ActionKind::OrgAdd => ["org", "add"],
            ActionKind::OrgList => ["org", "list"],
            ActionKind::OrgSetCapacity => ["org", "set-capacity"],
            ActionKind::OrgSetScale => ["org", "set-scale"],
            ActionKind::OrgAddLabel => ["org", "add-label"],
            ActionKind::OrgRemoveLabel => ["org", "remove-label"],
            ActionKind::OrgRemove => ["org", "remove"],
            ActionKind::StatusJson => ["status", "--json"],
        }
    }
}

impl fmt::Display for ActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

fn scoped(scope: Scope, repo: ActionKind, org: ActionKind) -> ActionKind {
    match scope {
        Scope::Repository => repo,
        Scope::Organization => org,
    }
}

impl Action {
    #[must_use]
    pub fn kind(&self) -> ActionKind {
        match self {
            Action::AuthLogin => ActionKind::AuthLogin,
            Action::AuthLogout => ActionKind::AuthLogout,
            Action::HostSetCapacity(_) => ActionKind::HostSetCapacity,
            Action::HostSetRuntimeRoot(_) => ActionKind::HostSetRuntimeRoot,
            Action::HostResetRuntimeRoot => ActionKind::HostResetRuntimeRoot,
            Action::HostShow => ActionKind::HostShow,
            Action::Add(args) => {
                scoped(args.target.scope(), ActionKind::RepoAdd, ActionKind::OrgAdd)
            }
            Action::List(scope) => scoped(*scope, ActionKind::RepoList, ActionKind::OrgList),
            Action::SetCapacity { target, .. } => scoped(
                target.scope(),
                ActionKind::RepoSetCapacity,
                ActionKind::OrgSetCapacity,
            ),
            Action::SetScale { target, .. } => scoped(
                target.scope(),
                ActionKind::RepoSetScale,
                ActionKind::OrgSetScale,
            ),
            Action::AddLabel { target, .. } => scoped(
                target.scope(),
                ActionKind::RepoAddLabel,
                ActionKind::OrgAddLabel,
            ),
            Action::RemoveLabel { target, .. } => scoped(
                target.scope(),
                ActionKind::RepoRemoveLabel,
                ActionKind::OrgRemoveLabel,
            ),
            Action::SetWorkspace { .. } => ActionKind::RepoSetWorkspace,
            Action::Remove { target, .. } => scoped(
                target.scope(),
                ActionKind::RepoRemove,
                ActionKind::OrgRemove,
            ),
            Action::StatusJson => ActionKind::StatusJson,
        }
    }

    /// The policy target this action addresses, if any.
    #[must_use]
    pub fn target(&self) -> Option<Target> {
        match self {
            Action::Add(args) => Some(args.target),
            Action::SetCapacity { target, .. }
            | Action::SetScale { target, .. }
            | Action::AddLabel { target, .. }
            | Action::RemoveLabel { target, .. }
            | Action::Remove { target, .. } => Some(*target),
            Action::SetWorkspace { repo, .. } => Some(Target::Repo(*repo)),
            _ => None,
        }
    }

    /// The literal argument vector, without the binary and without the
    /// scenario's `--data-dir`, which the runner prepends.
    ///
    /// Options whose value could begin with `-` are spelled `--flag=value` so a
    /// value is never mistaken for an option.
    #[must_use]
    pub fn argv(&self, resolver: &dyn Resolver) -> Vec<String> {
        let mut argv: Vec<String> = self
            .kind()
            .command_path()
            .iter()
            .map(|word| (*word).to_string())
            .collect();
        match self {
            Action::AuthLogin
            | Action::AuthLogout
            | Action::HostResetRuntimeRoot
            | Action::HostShow
            | Action::List(_)
            | Action::StatusJson => {}
            Action::HostSetCapacity(capacity) => argv.push(capacity.value().to_string()),
            Action::HostSetRuntimeRoot(path) => {
                argv.push(format!("--path={}", resolver.path(*path)));
            }
            Action::Add(args) => {
                argv.push(args.target.token());
                argv.push(format!("--host-label={}", args.host_label.token()));
                if let Some(maximum) = args.max_capacity {
                    argv.push(format!("--max-capacity={}", maximum.value()));
                }
                for label in &args.labels {
                    argv.push(format!("--label={}", label.token(resolver)));
                }
                if args.enable {
                    argv.push("--enable".to_string());
                }
            }
            Action::SetCapacity {
                target,
                max_capacity,
            } => {
                argv.push(target.token());
                argv.push(format!("--max-capacity={}", max_capacity.value()));
            }
            Action::SetScale { target, enabled } => {
                argv.push(target.token());
                argv.push(format!("--enabled={enabled}"));
            }
            Action::AddLabel { target, labels } | Action::RemoveLabel { target, labels } => {
                argv.push(target.token());
                for label in labels.values() {
                    argv.push(format!("--label={}", label.token(resolver)));
                }
            }
            Action::SetWorkspace { repo, setting } => {
                argv.push(repo.token());
                match setting {
                    WorkspaceSetting::Ephemeral => argv.push("--mode=ephemeral".to_string()),
                    WorkspaceSetting::EphemeralWithPath(path) => {
                        argv.push("--mode=ephemeral".to_string());
                        argv.push(format!("--path={}", resolver.path(*path)));
                    }
                    WorkspaceSetting::Persistent(path) => {
                        argv.push("--mode=persistent".to_string());
                        argv.push(format!("--path={}", resolver.path(*path)));
                    }
                }
            }
            Action::Remove { target, purge } => {
                argv.push(target.token());
                if *purge {
                    argv.push("--purge".to_string());
                }
            }
        }
        argv
    }

    /// The equivalence classes this action's arguments exercise, as coverage
    /// units (`value:<leaf>:<parameter>=<class>`).
    #[must_use]
    pub fn value_units(&self) -> Vec<String> {
        let kind = self.kind().name();
        let unit = |parameter: &str, class: &str| format!("value:{kind}:{parameter}={class}");
        let mut units = Vec::new();
        match self {
            Action::AuthLogin
            | Action::AuthLogout
            | Action::HostResetRuntimeRoot
            | Action::HostShow
            | Action::List(_)
            | Action::StatusJson => {}
            Action::HostSetCapacity(capacity) => units.push(unit("capacity", capacity.class())),
            Action::HostSetRuntimeRoot(path) => units.push(unit("path", path.class())),
            Action::Add(args) => {
                units.push(unit("target", args.target.class()));
                units.push(unit("host-label", args.host_label.class()));
                units.push(unit(
                    "max-capacity",
                    args.max_capacity
                        .map_or("absent-monitor-only", Capacity::class),
                ));
                if args.labels.is_empty() {
                    units.push(unit("label", "none"));
                }
                for label in &args.labels {
                    units.push(unit("label", label.class()));
                }
                units.push(unit("enable", if args.enable { "true" } else { "false" }));
            }
            Action::SetCapacity {
                target,
                max_capacity,
            } => {
                units.push(unit("target", target.class()));
                units.push(unit("max-capacity", max_capacity.class()));
            }
            Action::SetScale { target, enabled } => {
                units.push(unit("target", target.class()));
                units.push(unit("enabled", if *enabled { "true" } else { "false" }));
            }
            Action::AddLabel { target, labels } | Action::RemoveLabel { target, labels } => {
                units.push(unit("target", target.class()));
                for label in labels.values() {
                    units.push(unit("label", label.class()));
                }
                if labels.values().len() > 1 {
                    units.push(unit("label-count", "several"));
                }
            }
            Action::SetWorkspace { repo, setting } => {
                units.push(unit("target", repo.class()));
                match setting {
                    WorkspaceSetting::Ephemeral => units.push(unit("mode", "ephemeral")),
                    WorkspaceSetting::EphemeralWithPath(path) => {
                        units.push(unit("mode", "ephemeral-with-path"));
                        units.push(unit("path", path.class()));
                    }
                    WorkspaceSetting::Persistent(path) => {
                        units.push(unit("mode", "persistent"));
                        units.push(unit("path", path.class()));
                    }
                }
            }
            Action::Remove { target, purge } => {
                units.push(unit("target", target.class()));
                units.push(unit("purge", if *purge { "true" } else { "false" }));
            }
        }
        units.sort();
        units.dedup();
        units
    }
}

/// A store-level setup step the runner applies through the public `Store` or
/// secret-store interface, never through a command.
///
/// Some states are real and reachable only by the daemon or by another
/// process: a runner attempt, a `repair_required` policy after an interrupted
/// add, a policy left `draining` by a confirmed disable. The local suite does
/// not run the daemon, so a case that needs one of those states seeds it. A
/// seed is part of a case's named initial state and is reported as such.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Seed {
    /// Store a fake credential for the recorded start mode, as a completed
    /// `auth login` would. Cheaper than the device flow, which waits out the
    /// polling interval on every sign-in.
    Credential,
    /// Journal one runner attempt against the target's policy. Every seeded
    /// attempt uses an ephemeral workspace.
    Attempt { target: Target, kind: AttemptKind },
    /// Move a `pending` policy to `repair_required`.
    RepairRequired(Target),
    /// Move an `active` policy to `draining` (`enabled` becomes false).
    Drain(Target),
    /// Create the shared runner package cache, `<data>/state/packages`.
    PackageCache,
}

/// What a seeded attempt counts as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AttemptKind {
    /// Non-terminal (for example `busy`): occupies host capacity.
    Active,
    /// Terminal and not yet `cleaned`: holds no capacity, still owns its
    /// directory.
    AwaitingCleanup,
    /// `cleaned`: historical diagnostics only.
    Cleaned,
}

impl AttemptKind {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            AttemptKind::Active => "active",
            AttemptKind::AwaitingCleanup => "awaiting-cleanup",
            AttemptKind::Cleaned => "cleaned",
        }
    }
}

impl Seed {
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Seed::Credential => "seed credential".to_string(),
            Seed::Attempt { target, kind } => format!(
                "seed {} attempt for {} {}",
                kind.name(),
                target.scope().word(),
                target.token()
            ),
            Seed::RepairRequired(target) => format!(
                "seed repair_required for {} {}",
                target.scope().word(),
                target.token()
            ),
            Seed::Drain(target) => format!(
                "seed draining for {} {}",
                target.scope().word(),
                target.token()
            ),
            Seed::PackageCache => "seed package cache".to_string(),
        }
    }
}

/// One step of a case: a real command, or a seeded fact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Step {
    Run(Action),
    Seed(Seed),
}

impl Step {
    /// The step as the inventory prints it.
    ///
    /// Display only: an argument holding whitespace is quoted and a long run of
    /// one character is abbreviated, so the text is reviewable. It is never
    /// parsed back into a command.
    #[must_use]
    pub fn describe(&self, resolver: &dyn Resolver) -> String {
        match self {
            Step::Run(action) => action
                .argv(resolver)
                .iter()
                .map(|argument| display_argument(argument))
                .collect::<Vec<_>>()
                .join(" "),
            Step::Seed(seed) => seed.describe(),
        }
    }
}

/// One argument, quoted when it holds whitespace and with any run of more than
/// sixteen identical characters written as `<c*N>`.
fn display_argument(argument: &str) -> String {
    let mut text = String::new();
    let characters: Vec<char> = argument.chars().collect();
    let mut index = 0;
    while index < characters.len() {
        let current = characters[index];
        let mut run = 1;
        while index + run < characters.len() && characters[index + run] == current {
            run += 1;
        }
        if run > 16 {
            text.push_str(&format!("<{current}*{run}>"));
        } else {
            text.extend(std::iter::repeat_n(current, run));
        }
        index += run;
    }
    if text.chars().any(char::is_whitespace) {
        format!("'{text}'")
    } else {
        text
    }
}
