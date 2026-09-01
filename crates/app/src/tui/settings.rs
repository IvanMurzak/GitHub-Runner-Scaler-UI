// owner: g3-tui-settings-parity
//
// `e1-workspace-tui` extends both screens with the workspace half of
// `02-target-architecture.md` ("TUI"): the host runner root and one
// repository's disposable/persistent workspace. It adds no rule of its own —
// every value it writes goes through the handler the CLI command calls, and
// every path it refuses is refused by the shared preflight.

//! Editable TUI settings and the CLI-parity dispatch boundary.
//!
//! Forms are presentation data and never own a store. Host capacity and policy
//! capacity/scale changes are translated into the exact command values used by
//! the CLI, so validation and persistence cannot drift.
//!
//! # Two tasks per screen
//!
//! Each screen now completes two independent tasks, and `08-user-workflows.md`'s
//! release gate — "at most 5 focused form actions per settings screen" — is
//! counted and asserted **per task**, which is what the gate's own sentence
//! means by "completes its task":
//!
//! | Screen | Task | Actions |
//! |---|---|---|
//! | Host | capacity / start mode / refresh | 4 |
//! | Host | runner root: edit, reset, save | 3 |
//! | Repository | scale, capacity, cache, confirm | 4 |
//! | Repository | workspace: mode, path, save | 3 |
//!
//! The two tasks on a screen have separate save actions because they are
//! separate store mutations behind separate fences: a workspace change is
//! refused while an attempt still owns its directory, and folding it into
//! "Save host settings" would make a capacity change fail for a reason that has
//! nothing to do with capacity.

use std::io::Write;

use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};
use runner_manager_domain::attempt::active_count_for;
use runner_manager_domain::capacity::HostAllocator;
use runner_manager_domain::model::{
    CachePolicy, RefreshInterval, ScaleTarget, StartMode, TargetScope,
};
use runner_manager_domain::path::LocalAbsolutePath;
use runner_manager_domain::policy::{PolicyMode, ScalePolicy};
use runner_manager_domain::store::{Store, StoreError};
use runner_manager_domain::workspace::WorkspaceKind;
use runner_manager_platform::runner_root::RootOwner;
use runner_manager_platform::service::ServiceError;

use super::path_field::PathField;
use crate::cli::workspace::{AffectedAttempts, HostRoot, RepositoryWorkspace};
use crate::cli::{
    self, CliError, Context, Failure, HostSetCapacityArgs, RepoSetWorkspaceArgs, WorkspaceMode,
};
#[cfg(test)]
use crate::cli::{
    OrgCommand, OrgSetCapacityArgs, OrgSetScaleArgs, RepoCommand, RepoSetCapacityArgs,
    RepoSetScaleArgs,
};

pub const MAX_FOCUSED_FORM_ACTIONS: u8 = 5;
pub const FORK_TRUST_WARNING: &str = "warning: fork and untrusted pull-request workflows must not run on a personal host until you explicitly accept that trust boundary.";

/// What Organization Settings says instead of offering a mode control.
///
/// `02-target-architecture.md`: "Organization Settings renders workspace mode as
/// `ephemeral` and explains that persistence requires repository scope", and
/// `05-user-workflows.md` adds the reason it is a sentence rather than a greyed
/// control: the screen "explains why persistent mode is unavailable instead of
/// showing a disabled unexplained control".
pub const ORGANIZATION_WORKSPACE_MODE: &str =
    "Workspace mode: ephemeral, and it cannot be changed for an organization.";

/// The D7 reason, stated where the operator asks the question.
pub const ORGANIZATION_WORKSPACE_EXPLANATION: &str = "An organization runner can accept jobs from more than one repository, so a retained _work \
     directory would cross a repository boundary. Persistent workspaces are repository-scoped.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSettings {
    pub current_capacity: u16,
    pub current_in_use: u16,
    pub current_start_mode: StartMode,
    pub current_refresh_interval: RefreshInterval,
    pub projected_requests_per_hour: u32,
    pub maximum_repository_targets: u32,
    pub projection_is_floor: bool,
    /// Journey 1's three rows: the effective path, whether it is the platform's
    /// or the operator's, and — through [`HostRoot::configured`] — what a reset
    /// would clear.
    pub runner_root: HostRoot,
    /// The two counts a runner-root change is refused behind, so the screen can
    /// preview the refusal before the operator types a path.
    pub affected: AffectedAttempts,
    targets: Vec<ScaleTarget>,
}

impl HostSettings {
    pub fn load(context: &Context) -> Result<Self, CliError> {
        let store = context.store()?;
        let host = cli::host::local_host_or_create(context, &store)?;
        let attempts = store.attempts().map_err(store_failure)?;
        let current_in_use = HostAllocator::from_attempts(&host, attempts.iter()).active_total();
        let targets = store
            .policies()
            .map_err(store_failure)?
            .into_iter()
            .map(|policy| policy.target)
            .collect::<Vec<_>>();
        let budget = cli::host::HostBudget::of(host.refresh_interval, &targets);
        Ok(Self {
            current_capacity: host.host_capacity(),
            current_in_use,
            current_start_mode: host.service_start_mode,
            current_refresh_interval: host.refresh_interval,
            projected_requests_per_hour: budget.requests_per_hour(),
            maximum_repository_targets: budget.max_repository_targets(),
            projection_is_floor: budget.is_floor(),
            runner_root: cli::workspace::host_root(context.paths(), Some(&host)),
            affected: cli::workspace::host_affected_attempts(&store)?,
            targets,
        })
    }

    /// The stored override as text, empty when the platform default is in use.
    ///
    /// The *editable* value is the override and not the effective path: seeding
    /// the field with a resolved platform default and saving it would silently
    /// turn "whatever this platform decides" into a pinned literal path, which
    /// is the one thing `02-target-architecture.md` stores `None` to avoid —
    /// "storing only the override allows a future platform-default correction
    /// without rewriting every database".
    #[must_use]
    pub fn configured_root_text(&self) -> String {
        self.runner_root
            .configured
            .as_ref()
            .map_or_else(String::new, |root| root.as_str().to_owned())
    }

    /// `host set-runtime-root --path` (`Some`) and `host reset-runtime-root`
    /// (`None`), dispatched through the command handler itself.
    ///
    /// Not a re-implementation with the same steps: literally
    /// [`cli::host::runtime_root`], given the raw text the operator typed. That
    /// is what makes "TUI and CLI save byte-identical stored values and render
    /// the same refusal reason" a property of the code rather than of two
    /// functions that currently agree.
    ///
    /// # Errors
    /// [`Failure::InvalidArgument`] for a path this host cannot hold,
    /// [`Failure::Conflict`] for affected attempts or a lost race, and
    /// [`Failure::LocalState`] for a journal or filesystem failure.
    pub fn save_runner_root(
        context: &Context,
        raw: Option<&str>,
        out: &mut dyn Write,
    ) -> Result<(), CliError> {
        cli::host::runtime_root(context, raw, out)
    }

    /// Edit, reset, save — the three focused actions the runner-root task costs.
    #[must_use]
    pub const fn workspace_action_count() -> u8 {
        3
    }

    pub fn preview_interval(&self, seconds: u16) -> Result<HostIntervalPreview, CliError> {
        let interval = RefreshInterval::from_secs(seconds).map_err(invalid)?;
        let budget = cli::host::HostBudget::of(interval, &self.targets);
        Ok(HostIntervalPreview {
            interval,
            projected_requests_per_hour: budget.requests_per_hour(),
            maximum_repository_targets: budget.max_repository_targets(),
            projection_is_floor: budget.is_floor(),
            over_budget: budget.exceeds_allowance(),
        })
    }

    /// Dispatches the same handler as `host set-capacity`.
    pub fn set_capacity(
        context: &Context,
        capacity: u16,
        out: &mut dyn Write,
    ) -> Result<(), CliError> {
        cli::host::set_capacity(context, &HostSetCapacityArgs { capacity }, out)
    }

    pub fn set_refresh_interval(
        &self,
        context: &Context,
        seconds: u16,
    ) -> Result<HostIntervalPreview, CliError> {
        let preview = self.accepted_interval_preview(seconds)?;
        let store = context.store()?;
        let mut host = cli::host::local_host_or_create(context, &store)?;
        host.refresh_interval = preview.interval;
        store.put_host(&host).map_err(store_failure)?;
        Ok(preview)
    }

    fn accepted_interval_preview(&self, seconds: u16) -> Result<HostIntervalPreview, CliError> {
        let preview = self.preview_interval(seconds)?;
        if preview.over_budget {
            return Err(CliError::with_remedy(
                Failure::BudgetRefused,
                format!(
                    "a {}-second refresh projects {} requests/hour for the configured targets; nothing was changed",
                    preview.interval.as_secs(),
                    preview.projected_requests_per_hour
                ),
                "choose a longer refresh interval or remove a target",
            ));
        }
        Ok(preview)
    }

    /// Switches the existing service registration in place, without reinstalling.
    pub fn set_start_mode(context: &Context, mode: StartMode) -> Result<(), CliError> {
        Self::set_start_mode_with(context, mode, |mode| {
            // Through `cli::service::operations` rather than
            // `ServiceOperations::on_this_host`, so the screen switches the
            // start mode of the registration `service status` reports on. Built
            // here the other way, this was the one code path that *wrote* to
            // the service manager while still resolving the product's constant
            // name -- which under the test harness means a suite that changed
            // the developer's own installed service.
            cli::service::operations(context)
                .set_start_mode(mode)
                .map(|_| ())
                .map_err(service_failure)
        })
    }

    fn set_start_mode_with(
        context: &Context,
        mode: StartMode,
        switch: impl FnOnce(StartMode) -> Result<(), CliError>,
    ) -> Result<(), CliError> {
        switch(mode)?;
        let store = context.store()?;
        let mut host = cli::host::local_host_or_create(context, &store)?;
        host.service_start_mode = mode;
        store.put_host(&host).map_err(store_failure)
    }

    #[must_use]
    pub const fn focused_action_count(&self) -> u8 {
        4
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostIntervalPreview {
    pub interval: RefreshInterval,
    pub projected_requests_per_hour: u32,
    pub maximum_repository_targets: u32,
    pub projection_is_floor: bool,
    pub over_budget: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySettings {
    pub target: ScaleTarget,
    pub host_identity: String,
    pub mode: SettingsPolicyMode,
    pub enabled: bool,
    pub current_max_capacity: Option<u16>,
    pub routing_labels: Vec<String>,
    pub copyable_runs_on: Option<String>,
    pub cache_policy: CachePolicy,
    pub active_runners: u16,
    /// `d1`'s repository read model, unmodified: mode, effective root, the two
    /// refusal counts, and the slot leases — with no path inside a workspace
    /// and no directory listing anywhere.
    pub workspace: RepositoryWorkspace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsPolicyMode {
    Autoscale,
    MonitorOnly,
}

impl PolicySettings {
    pub fn load(context: &Context, target: &ScaleTarget) -> Result<Self, CliError> {
        let store = context.store()?;
        let policy = find_policy(&store, target)?;
        let host = store
            .host(policy.host_id)
            .map_err(store_failure)?
            .ok_or_else(|| {
                CliError::new(
                    Failure::LocalState,
                    "the policy refers to a missing local host",
                )
            })?;
        let attempts = store
            .attempts_for_policy(policy.id)
            .map_err(store_failure)?;
        let active_runners = active_count_for(policy.id, attempts.iter());
        let routing_labels = policy.routing_labels().map_or_else(Vec::new, |labels| {
            labels.iter().map(ToString::to_string).collect()
        });
        let copyable_runs_on = policy.routing_labels().map(|labels| {
            labels
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        });
        // Resolved once from the host this policy belongs to, and handed to the
        // read model rather than resolved inside it -- `d1`'s rule, so two rows
        // of one screen cannot describe two different hosts.
        let workspace = cli::workspace::repository_workspace(
            &store,
            &cli::workspace::host_root(context.paths(), Some(&host)),
            &policy,
        )?;
        Ok(Self {
            target: policy.target.clone(),
            host_identity: host.display_name,
            mode: match policy.mode() {
                PolicyMode::Autoscale(_) => SettingsPolicyMode::Autoscale,
                PolicyMode::MonitorOnly => SettingsPolicyMode::MonitorOnly,
            },
            enabled: policy.enabled(),
            current_max_capacity: policy.max_capacity().map(std::num::NonZeroU16::get),
            routing_labels,
            copyable_runs_on,
            cache_policy: policy.cache_policy,
            active_runners,
            workspace,
        })
    }

    /// The stored persistent root as text, empty in ephemeral mode.
    #[must_use]
    pub fn configured_root_text(&self) -> String {
        self.workspace
            .policy
            .root()
            .map_or_else(String::new, |root| root.as_str().to_owned())
    }

    /// D7: an organization policy has no persistent-workspace control at all.
    #[must_use]
    pub fn is_organization(&self) -> bool {
        self.target.scope() == TargetScope::Organization
    }

    /// `repo set-workspace OWNER/REPO --mode ... [--path ...]`, dispatched
    /// through the command handler itself.
    ///
    /// The arguments are the strings a shell would have parsed, so the TUI and
    /// the command reach [`cli::workspace::set_repository_workspace`] having
    /// made exactly the same decisions on the way — including the refusal of a
    /// path alongside `--mode ephemeral`.
    ///
    /// # Errors
    /// [`Failure::InvalidArgument`] for a path this host cannot hold or a mode
    /// that forbids one, [`Failure::Conflict`] for affected attempts or a lost
    /// race, and [`Failure::LocalState`] for a journal or filesystem failure.
    pub fn save_workspace(
        &self,
        context: &Context,
        kind: WorkspaceKind,
        raw_path: Option<&str>,
        out: &mut dyn Write,
    ) -> Result<(), CliError> {
        cli::policy::set_workspace(
            context,
            &RepoSetWorkspaceArgs {
                repository: self.target.to_string(),
                mode: match kind {
                    WorkspaceKind::Ephemeral => WorkspaceMode::Ephemeral,
                    WorkspaceKind::Persistent => WorkspaceMode::Persistent,
                },
                path: raw_path.map(ToOwned::to_owned),
            },
            out,
        )
    }

    /// Mode, path, save — and no path control at all in ephemeral mode, which is
    /// why the count depends on the *draft* rather than on what is stored.
    #[must_use]
    pub fn workspace_action_count(&self, draft: WorkspaceKind) -> u8 {
        if self.is_organization() {
            0
        } else if draft.is_persistent() {
            3
        } else {
            2
        }
    }

    #[must_use]
    pub fn preview(&self, draft: &PolicyDraft) -> PolicyPreview {
        let enabling = !self.enabled && draft.enabled == Some(true);
        let disabling = self.enabled && draft.enabled == Some(false);
        PolicyPreview {
            target: self.target.to_string(),
            from_capacity: self.current_max_capacity,
            to_capacity: draft.max_capacity.or(self.current_max_capacity),
            from_enabled: self.enabled,
            to_enabled: draft.enabled.unwrap_or(self.enabled),
            cache_policy: draft.cache_policy.unwrap_or(self.cache_policy),
            promotion: self.mode == SettingsPolicyMode::MonitorOnly && draft.max_capacity.is_some(),
            drain_confirmation_required: disabling && self.active_runners > 0,
            active_runners: self.active_runners,
            state_after_disable: disabling.then_some(if self.active_runners == 0 {
                "disabled"
            } else {
                "draining"
            }),
            trust_warning: enabling.then_some(FORK_TRUST_WARNING),
        }
    }

    pub fn apply(
        &self,
        context: &Context,
        draft: &PolicyDraft,
        drain_confirmation: Option<cli::policy::ScaleObservation>,
        out: &mut dyn Write,
    ) -> Result<(), CliError> {
        cli::policy::apply_policy_mutation(
            context,
            &self.target,
            cli::policy::PolicyMutation {
                max_capacity: draft.max_capacity,
                enabled: draft.enabled,
                cache_policy: draft.cache_policy,
            },
            drain_confirmation,
            out,
        )
    }

    #[must_use]
    pub const fn exposes_scale_toggle(&self) -> bool {
        matches!(self.mode, SettingsPolicyMode::Autoscale)
    }

    #[must_use]
    pub const fn focused_action_count(&self) -> u8 {
        match self.mode {
            SettingsPolicyMode::Autoscale => 4,
            SettingsPolicyMode::MonitorOnly => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PolicyDraft {
    pub enabled: Option<bool>,
    pub max_capacity: Option<u16>,
    pub cache_policy: Option<CachePolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPreview {
    pub target: String,
    pub from_capacity: Option<u16>,
    pub to_capacity: Option<u16>,
    pub from_enabled: bool,
    pub to_enabled: bool,
    pub cache_policy: CachePolicy,
    pub promotion: bool,
    pub drain_confirmation_required: bool,
    pub active_runners: u16,
    pub state_after_disable: Option<&'static str>,
    pub trust_warning: Option<&'static str>,
}

// ---------------------------------------------------------------------------
// The controls
// ---------------------------------------------------------------------------

/// One focusable control on a settings screen.
///
/// Named rather than numbered because `e1` puts a **second** task on each of the
/// two screens — where runner workspaces live, next to how many of them there
/// may be — and the previous model was a bare `usize` decoded by three separate
/// `match self.focus` ladders plus a fourth table of hard-coded mouse rows. Four
/// places that had to agree about what "3" meant, and inserting a control in the
/// middle silently moved a click from *Save* to *Reset*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    HostCapacity,
    HostStartMode,
    HostInterval,
    HostSave,
    /// The host runner-root override text field.
    HostRunnerRoot,
    HostRootReset,
    HostRootSave,
    PolicyScale,
    PolicyCapacity,
    PolicyCache,
    PolicySave,
    /// `ephemeral` / `persistent` for one repository.
    WorkspaceMode,
    /// The repository persistent-root text field; present only in persistent
    /// mode, because `02-target-architecture.md` requires the path control to be
    /// "visible only in persistent mode".
    WorkspacePath,
    WorkspaceSave,
}

impl Control {
    /// Whether activating it *changes a value* rather than running a command.
    /// Steppers and toggles adjust; fields and actions activate.
    const fn is_adjustable(self) -> bool {
        matches!(
            self,
            Control::HostCapacity
                | Control::HostStartMode
                | Control::HostInterval
                | Control::PolicyScale
                | Control::PolicyCapacity
                | Control::PolicyCache
                | Control::WorkspaceMode
        )
    }
}

/// One physical row of a settings form, one terminal line tall.
///
/// Rows are wrapped here rather than by `Paragraph`'s own `Wrap`, and that is
/// not a style choice: a mouse click arrives as a row number, so a widget that
/// re-flows text *after* the row map is built puts every control below a long
/// path one row away from where it was clicked. Wrapping in the same pass that
/// assigns the control makes the two impossible to disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FormLine {
    text: String,
    /// The control this row focuses, as an index into [`SettingsUi::controls`].
    control: Option<usize>,
    /// Text this row yields to a click when it is not a control.
    copy: Option<String>,
    /// `e1`: "Keep current value, validation error, and save action visible in
    /// constrained layouts". A compact terminal keeps these rows plus the
    /// focused control, and drops the explanation around them.
    essential: bool,
}

impl FormLine {
    fn text(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            control: None,
            copy: None,
            essential: false,
        }
    }

    fn keep(text: impl Into<String>) -> Self {
        Self {
            essential: true,
            ..Self::text(text)
        }
    }

    const fn at(mut self, control: usize) -> Self {
        self.control = Some(control);
        self
    }

    fn copyable(mut self, text: impl Into<String>) -> Self {
        self.copy = Some(text.into());
        self
    }
}

/// Production state for the two editable screens. It contains no credential
/// and every mutation is represented by a [`SettingsCommand`] executed by the
/// shell's effect boundary.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SettingsUi {
    pub view: SettingsView,
    pub focus: usize,
    pub host_capacity: u16,
    pub host_mode: StartMode,
    pub host_interval_secs: u16,
    pub policy_draft: PolicyDraft,
    pub awaiting_drain_confirmation: bool,
    pub drain_observation: Option<cli::policy::ScaleObservation>,
    pub message: Option<String>,
    /// The host runner-root **override** being edited. Empty means "no
    /// override", which is how the platform default is stored; the *effective*
    /// path is shown on its own row above it.
    pub host_root: PathField,
    /// Inline validation and refusal preview for [`Self::host_root`].
    pub host_root_notice: Option<String>,
    /// The repository workspace mode being edited.
    pub workspace_mode: WorkspaceKind,
    /// The repository persistent root being edited.
    pub workspace_path: PathField,
    /// Inline validation and refusal preview for [`Self::workspace_path`].
    pub workspace_notice: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SettingsView {
    /// Nothing loaded yet, and something IS on its way.
    #[default]
    Empty,
    /// Nothing to load, and the screen says why.
    ///
    /// Distinct from [`SettingsView::Empty`] because the two mean opposite
    /// things to the person reading the screen: one is "wait", the other is
    /// "this is all there is until you do something". Rendering the second as
    /// the first is what left a host with no policies sitting on
    /// "Loading settings..." indefinitely.
    Notice(String),
    Host(HostSettings),
    Policy(PolicySettings),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsCommand {
    LoadHost,
    LoadPolicy(String),
    ApplyHost,
    ApplyPolicy,
    Copy(String),
    /// Preview one runner-root draft through the shared preflight.
    CheckHostRoot,
    /// `host reset-runtime-root`.
    ResetHostRoot,
    /// `host set-runtime-root --path <draft>`.
    SaveHostRoot,
    /// Preview one repository-root draft through the shared preflight.
    CheckWorkspaceRoot,
    /// `repo set-workspace OWNER/REPO --mode <draft> [--path <draft>]`.
    SaveWorkspace,
}

impl SettingsUi {
    /// Shows an explanation instead of a form, and clears any pending message.
    pub fn show_notice(&mut self, notice: impl Into<String>) {
        self.view = SettingsView::Notice(notice.into());
        self.message = None;
        self.focus = 0;
    }

    /// True while a path control owns the keyboard.
    ///
    /// The shell asks before it interprets a key: while a path is being typed
    /// there are no single-letter screen shortcuts, or `h` would jump to Host
    /// Settings in the middle of `C:\home\runners`.
    #[must_use]
    pub const fn is_editing(&self) -> bool {
        self.host_root.is_editing() || self.workspace_path.is_editing()
    }

    /// Bracketed paste into whichever path control is being edited.
    pub fn paste(&mut self, text: &str) {
        if self.host_root.is_editing() {
            self.host_root.paste(text);
        } else if self.workspace_path.is_editing() {
            self.workspace_path.paste(text);
        }
    }

    /// The text `c` copies on this screen, when the focused control has one.
    #[must_use]
    pub fn copy_text(&self) -> Option<String> {
        match self.focused()? {
            Control::HostRunnerRoot => match &self.view {
                SettingsView::Host(form) => Some(if self.host_root.is_blank() {
                    form.runner_root.rendered()
                } else {
                    self.host_root.text()
                }),
                _ => None,
            },
            Control::WorkspacePath => Some(self.workspace_path.text()),
            _ => None,
        }
    }

    pub fn execute(&mut self, context: &Context, command: SettingsCommand) -> Option<String> {
        if matches!(
            &command,
            SettingsCommand::LoadHost | SettingsCommand::LoadPolicy(_)
        ) {
            self.view = SettingsView::Empty;
            self.message = None;
        }
        let result = match command {
            SettingsCommand::LoadHost => self.load_host(context).map(|()| {
                self.focus = 0;
                self.message = None;
            }),
            SettingsCommand::LoadPolicy(raw) => ScaleTarget::repository(&raw)
                .or_else(|_| ScaleTarget::organization(&raw))
                .map_err(invalid)
                .and_then(|target| self.load_policy(context, &target))
                .map(|()| {
                    self.focus = 0;
                    self.message = None;
                }),
            SettingsCommand::ApplyHost => self.apply_host(context),
            SettingsCommand::ApplyPolicy => self.apply_policy(context),
            SettingsCommand::Copy(text) => return Some(text),
            SettingsCommand::CheckHostRoot => self.check_host_root(context),
            SettingsCommand::ResetHostRoot => self.save_host_root(context, None),
            SettingsCommand::SaveHostRoot => {
                let draft = self.host_root.text();
                self.save_host_root(context, Some(draft))
            }
            SettingsCommand::CheckWorkspaceRoot => self.check_workspace_root(context),
            SettingsCommand::SaveWorkspace => self.save_workspace(context),
        };
        if let Err(error) = result {
            self.message = Some(format!("error: {error}"));
        }
        None
    }

    fn load_host(&mut self, context: &Context) -> Result<(), CliError> {
        let form = HostSettings::load(context)?;
        self.host_capacity = form.current_capacity;
        self.host_mode = form.current_start_mode;
        self.host_interval_secs = form.current_refresh_interval.as_secs();
        self.host_root.reset_to(&form.configured_root_text());
        self.host_root_notice = None;
        self.view = SettingsView::Host(form);
        Ok(())
    }

    fn load_policy(&mut self, context: &Context, target: &ScaleTarget) -> Result<(), CliError> {
        let form = PolicySettings::load(context, target)?;
        self.policy_draft = PolicyDraft::default();
        self.workspace_mode = form.workspace.kind();
        self.workspace_path.reset_to(&form.configured_root_text());
        self.workspace_notice = None;
        self.awaiting_drain_confirmation = false;
        self.drain_observation = None;
        self.view = SettingsView::Policy(form);
        Ok(())
    }

    fn apply_host(&mut self, context: &Context) -> Result<(), CliError> {
        let SettingsView::Host(form) = &self.view else {
            return Ok(());
        };
        if self.host_capacity == 0 {
            return Err(CliError::new(
                Failure::InvalidArgument,
                "host capacity must be at least 1; nothing was changed",
            ));
        }
        form.accepted_interval_preview(self.host_interval_secs)?;
        let mut output = Vec::new();
        if self.host_mode != form.current_start_mode {
            HostSettings::set_start_mode(context, self.host_mode)?;
        }
        if self.host_capacity != form.current_capacity {
            HostSettings::set_capacity(context, self.host_capacity, &mut output)?;
        }
        if self.host_interval_secs != form.current_refresh_interval.as_secs() {
            form.set_refresh_interval(context, self.host_interval_secs)?;
        }
        self.message = Some(if output.is_empty() {
            "Host settings saved.".to_owned()
        } else {
            String::from_utf8_lossy(&output).trim().to_owned()
        });
        self.load_host(context)
    }

    /// Journey 2, step 4: the inline answer, before anything is saved.
    ///
    /// The answer comes from [`cli::workspace::check_root`] — the same preflight
    /// `host set-runtime-root` runs — and the refusal preview comes from the
    /// counts the form already loaded, so a screen cannot report a path as
    /// usable that the command would refuse, or the other way round.
    fn check_host_root(&mut self, context: &Context) -> Result<(), CliError> {
        let SettingsView::Host(form) = &self.view else {
            return Ok(());
        };
        let affected = form.affected;
        let draft = self.host_root.text();
        self.host_root_notice = Some(if draft.trim().is_empty() {
            "no override typed: saving is refused, and `Reset to platform default` is what \
             clears an existing one."
                .to_owned()
        } else {
            let store = context.store()?;
            notice_for(
                cli::workspace::check_root(context, &store, &RootOwner::Host, &draft),
                affected,
                "the host runner root",
                "new ephemeral attempts would be created under",
            )
        });
        Ok(())
    }

    /// `host set-runtime-root --path` and `host reset-runtime-root`, through the
    /// command handler itself rather than a second copy of it.
    fn save_host_root(&mut self, context: &Context, draft: Option<String>) -> Result<(), CliError> {
        if let Some(draft) = &draft
            && draft.trim().is_empty()
        {
            return Err(CliError::with_remedy(
                Failure::InvalidArgument,
                "type an absolute path before saving a runner root; nothing was changed",
                "focus `Reset to platform default` to clear the override instead",
            ));
        }
        let mut output = Vec::new();
        let result = HostSettings::save_runner_root(context, draft.as_deref(), &mut output);
        // The form is reloaded either way, because a refusal leaves the stored
        // value exactly where it was and the *effective* row has to keep showing
        // it. The draft is put back afterwards on refusal: Journey 6 requires
        // the screen to preserve "the operator's draft for correction", and
        // clearing the field they must now fix is the opposite of that.
        let draft = (self.host_root.clone(), self.host_root_notice.clone());
        let reloaded = self.load_host(context);
        if result.is_err() {
            (self.host_root, self.host_root_notice) = draft;
        }
        result?;
        reloaded?;
        self.host_root_notice = None;
        self.message = Some(String::from_utf8_lossy(&output).trim().to_owned());
        Ok(())
    }

    fn check_workspace_root(&mut self, context: &Context) -> Result<(), CliError> {
        let SettingsView::Policy(form) = &self.view else {
            return Ok(());
        };
        let affected = form.workspace.attempts;
        let owner = RootOwner::Repository(form.target.slug());
        let subject = format!("the workspace setting for {}", form.target);
        let draft = self.workspace_path.text();
        self.workspace_notice = Some(if draft.trim().is_empty() {
            "a persistent workspace needs the directory its slots live in".to_owned()
        } else {
            let store = context.store()?;
            notice_for(
                cli::workspace::check_root(context, &store, &owner, &draft),
                affected,
                &subject,
                "slots s1, s2, ... would be created under",
            )
        });
        Ok(())
    }

    /// `repo set-workspace`, through the command handler itself.
    fn save_workspace(&mut self, context: &Context) -> Result<(), CliError> {
        let SettingsView::Policy(form) = &self.view else {
            return Ok(());
        };
        let form = form.clone();
        // An ephemeral workspace has no path, and passing one is the refusal
        // `02-target-architecture.md` requires rather than a silently ignored
        // argument -- so the draft is simply not sent when the mode is
        // ephemeral, exactly as `repo set-workspace --mode ephemeral` omits it.
        let path = self
            .workspace_mode
            .is_persistent()
            .then(|| self.workspace_path.text());
        let mut output = Vec::new();
        let result =
            form.save_workspace(context, self.workspace_mode, path.as_deref(), &mut output);
        // As above: the stored value is re-read, and the refused draft — mode
        // and path together — is put back so the operator can correct it.
        let draft = (
            self.workspace_mode,
            self.workspace_path.clone(),
            self.workspace_notice.clone(),
        );
        let reloaded = self.load_policy(context, &form.target);
        if result.is_err() {
            (
                self.workspace_mode,
                self.workspace_path,
                self.workspace_notice,
            ) = draft;
        }
        result?;
        reloaded?;
        self.workspace_notice = None;
        self.message = Some(String::from_utf8_lossy(&output).trim().to_owned());
        Ok(())
    }

    fn apply_policy(&mut self, context: &Context) -> Result<(), CliError> {
        let SettingsView::Policy(form) = &self.view else {
            return Ok(());
        };
        let form = form.clone();
        if self.policy_draft.enabled == Some(false) && self.drain_observation.is_none() {
            let observed = cli::policy::observe_scale(context, &form.target)?;
            if observed.active > 0 {
                self.awaiting_drain_confirmation = true;
                self.drain_observation = Some(observed);
                self.message = Some(format!(
                    "Confirm drain: {} active runner(s) will be left to finish. Press Enter again.",
                    observed.active
                ));
                return Ok(());
            }
            self.drain_observation = Some(observed);
        }
        let target = form.target.clone();
        let mut output = Vec::new();
        let result = form.apply(
            context,
            &self.policy_draft,
            self.drain_observation,
            &mut output,
        );
        if let Err(error) = result {
            self.awaiting_drain_confirmation = false;
            self.drain_observation = None;
            self.view = SettingsView::Policy(PolicySettings::load(context, &target)?);
            return Err(error);
        }
        self.message = Some(String::from_utf8_lossy(&output).trim().to_owned());
        self.load_policy(context, &target)
    }

    #[must_use]
    pub fn key(&mut self, code: KeyCode) -> Option<SettingsCommand> {
        if self.is_editing() {
            return self.edit_key(code);
        }
        let controls = self.control_count();
        match code {
            KeyCode::Up | KeyCode::BackTab => {
                self.focus = self.focus.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Tab => {
                self.focus = (self.focus + 1).min(controls.saturating_sub(1));
            }
            KeyCode::Left | KeyCode::Char('-') => self.adjust(false),
            KeyCode::Right | KeyCode::Char('+') | KeyCode::Char(' ') => self.adjust(true),
            KeyCode::Enter => return self.activate(),
            _ => return None,
        }
        // Toggling a repository back to ephemeral removes the path control, so
        // a focus that was on it would otherwise point past the end.
        self.focus = self.focus.min(self.control_count().saturating_sub(1));
        None
    }

    /// Every key belongs to the path control while one is being edited.
    ///
    /// `05-user-workflows.md`: "Keyboard typing, Backspace, Delete, Home, End,
    /// arrows, paste, Escape cancel, and Enter accept work in path controls."
    fn edit_key(&mut self, code: KeyCode) -> Option<SettingsCommand> {
        let host = self.host_root.is_editing();
        let field = if host {
            &mut self.host_root
        } else {
            &mut self.workspace_path
        };
        match code {
            KeyCode::Char(character) => field.insert(character),
            KeyCode::Backspace => field.backspace(),
            KeyCode::Delete => field.delete(),
            KeyCode::Left => field.left(),
            KeyCode::Right => field.right(),
            KeyCode::Home => field.home(),
            KeyCode::End => field.end(),
            KeyCode::Esc => {
                field.cancel();
                if host {
                    self.host_root_notice = None;
                } else {
                    self.workspace_notice = None;
                }
            }
            // Accepting revalidates immediately, so the operator reads the
            // refusal beside the field instead of discovering it on save.
            KeyCode::Enter | KeyCode::Tab | KeyCode::BackTab => {
                field.accept();
                return Some(if host {
                    SettingsCommand::CheckHostRoot
                } else {
                    SettingsCommand::CheckWorkspaceRoot
                });
            }
            _ => {}
        }
        None
    }

    /// A left click on a rendered row, given the same width and compact flag the
    /// frame was drawn with.
    #[must_use]
    pub fn click(
        &mut self,
        content_row: u16,
        width: usize,
        compact: bool,
    ) -> Option<SettingsCommand> {
        let row = self
            .rows(width, compact)
            .get(usize::from(content_row))?
            .clone();
        if let Some(control) = row.control {
            self.focus = control;
            return if self.focused().is_some_and(Control::is_adjustable) {
                self.adjust(true);
                self.focus = self.focus.min(self.control_count().saturating_sub(1));
                None
            } else {
                self.activate()
            };
        }
        row.copy.map(SettingsCommand::Copy)
    }

    /// Every focusable control on the current view, in render order.
    #[must_use]
    pub fn controls(&self) -> Vec<Control> {
        match &self.view {
            SettingsView::Host(_) => vec![
                Control::HostCapacity,
                Control::HostStartMode,
                Control::HostInterval,
                Control::HostSave,
                Control::HostRunnerRoot,
                Control::HostRootReset,
                Control::HostRootSave,
            ],
            SettingsView::Policy(form) => {
                let mut controls = Vec::with_capacity(7);
                if form.exposes_scale_toggle() {
                    controls.push(Control::PolicyScale);
                }
                controls.push(Control::PolicyCapacity);
                controls.push(Control::PolicyCache);
                controls.push(Control::PolicySave);
                // D7: an organization policy is shown its mode and told why it
                // cannot be changed, rather than given a control that refuses.
                if !form.is_organization() {
                    controls.push(Control::WorkspaceMode);
                    if self.workspace_mode.is_persistent() {
                        controls.push(Control::WorkspacePath);
                    }
                    controls.push(Control::WorkspaceSave);
                }
                controls
            }
            // A notice is a screenful of text: nothing to focus, nothing to
            // adjust, nothing to apply.
            SettingsView::Empty | SettingsView::Notice(_) => Vec::new(),
        }
    }

    #[must_use]
    pub fn focused(&self) -> Option<Control> {
        self.controls().get(self.focus).copied()
    }

    /// The control each drawn row activates, for the shell's own mouse test.
    ///
    /// The shell has to be able to ask "which control did the frame put on row
    /// N?" without knowing how a form is built, or its click test degenerates
    /// into the table of hard-coded row numbers this model replaced.
    #[cfg(test)]
    #[must_use]
    pub fn control_rows(&self, width: usize, compact: bool) -> Vec<Option<usize>> {
        self.rows(width, compact)
            .into_iter()
            .map(|row| row.control)
            .collect()
    }

    fn control_count(&self) -> usize {
        self.controls().len()
    }

    fn adjust(&mut self, increase: bool) {
        let Some(control) = self.focused() else {
            return;
        };
        let form = match &self.view {
            SettingsView::Policy(form) => Some(form.clone()),
            _ => None,
        };
        match control {
            Control::HostCapacity => {
                self.host_capacity = if increase {
                    self.host_capacity.saturating_add(1)
                } else {
                    self.host_capacity.saturating_sub(1)
                };
            }
            Control::HostStartMode => {
                self.host_mode = if self.host_mode == StartMode::Boot {
                    StartMode::Login
                } else {
                    StartMode::Boot
                };
            }
            Control::HostInterval => {
                self.host_interval_secs = if increase {
                    self.host_interval_secs.saturating_add(30)
                } else {
                    self.host_interval_secs
                        .saturating_sub(30)
                        .max(RefreshInterval::MIN_SECS)
                };
            }
            Control::PolicyScale => {
                if let Some(form) = &form {
                    self.policy_draft.enabled =
                        Some(!self.policy_draft.enabled.unwrap_or(form.enabled));
                }
            }
            Control::PolicyCapacity => {
                if let Some(form) = &form {
                    let current = self
                        .policy_draft
                        .max_capacity
                        .or(form.current_max_capacity)
                        .unwrap_or(1);
                    self.policy_draft.max_capacity = Some(if increase {
                        current.saturating_add(1)
                    } else {
                        current.saturating_sub(1)
                    });
                }
            }
            Control::PolicyCache => {
                if let Some(form) = &form {
                    let current = self.policy_draft.cache_policy.unwrap_or(form.cache_policy);
                    self.policy_draft.cache_policy = Some(match current {
                        CachePolicy::RetainRunnerPackage => CachePolicy::DiscardRunnerPackage,
                        CachePolicy::DiscardRunnerPackage => CachePolicy::RetainRunnerPackage,
                    });
                }
            }
            Control::WorkspaceMode => {
                self.workspace_mode = match self.workspace_mode {
                    WorkspaceKind::Ephemeral => WorkspaceKind::Persistent,
                    WorkspaceKind::Persistent => WorkspaceKind::Ephemeral,
                };
                // The draft the operator already typed is kept, so toggling to
                // compare the two modes does not throw the path away.
                self.workspace_notice = None;
            }
            Control::HostSave
            | Control::HostRunnerRoot
            | Control::HostRootReset
            | Control::HostRootSave
            | Control::PolicySave
            | Control::WorkspacePath
            | Control::WorkspaceSave => {}
        }
    }

    fn activate(&mut self) -> Option<SettingsCommand> {
        match self.focused()? {
            Control::HostSave => Some(SettingsCommand::ApplyHost),
            Control::HostRunnerRoot => {
                self.host_root.begin();
                None
            }
            Control::HostRootReset => Some(SettingsCommand::ResetHostRoot),
            Control::HostRootSave => Some(SettingsCommand::SaveHostRoot),
            Control::PolicySave => Some(SettingsCommand::ApplyPolicy),
            Control::WorkspacePath => {
                self.workspace_path.begin();
                None
            }
            Control::WorkspaceSave => Some(SettingsCommand::SaveWorkspace),
            Control::HostCapacity
            | Control::HostStartMode
            | Control::HostInterval
            | Control::PolicyScale
            | Control::PolicyCapacity
            | Control::PolicyCache
            | Control::WorkspaceMode => None,
        }
    }

    /// The rows one frame draws, already wrapped and already filtered for a
    /// constrained terminal.
    fn rows(&self, width: usize, compact: bool) -> Vec<FormLine> {
        let mut logical = self.form_lines(width);
        if compact {
            logical.retain(|line| {
                line.essential || (line.control.is_some() && line.control == Some(self.focus))
            });
        }
        let mut physical = Vec::with_capacity(logical.len());
        for line in logical {
            for (index, text) in wrap(&line.text, width).into_iter().enumerate() {
                physical.push(FormLine {
                    text,
                    // Only the first row of a wrapped line is the control, so a
                    // click on its continuation does nothing rather than
                    // something adjacent.
                    control: if index == 0 { line.control } else { None },
                    copy: if index == 0 { line.copy.clone() } else { None },
                    essential: line.essential,
                });
            }
        }
        physical
    }

    fn form_lines(&self, width: usize) -> Vec<FormLine> {
        match &self.view {
            SettingsView::Empty => vec![FormLine::keep("Loading settings...")],
            SettingsView::Notice(notice) => notice.lines().map(FormLine::text).collect(),
            SettingsView::Host(form) => self.host_lines(form, width),
            SettingsView::Policy(form) => self.policy_lines(form, width),
        }
    }

    fn host_lines(&self, form: &HostSettings, width: usize) -> Vec<FormLine> {
        let preview = form.preview_interval(self.host_interval_secs).ok();
        let mut lines = vec![
            FormLine::text("Host settings"),
            FormLine::keep(format!("Current capacity: {}", form.current_capacity)),
            FormLine::text(format!("Currently in use: {}", form.current_in_use)),
            FormLine::keep(format!("Capacity: {}  [-/+ or click]", self.host_capacity)).at(0),
            FormLine::text(format!("Service start: {}  [toggle]", self.host_mode)).at(1),
            FormLine::text(format!(
                "Refresh interval: {}s  [-/+ 30s]",
                self.host_interval_secs
            ))
            .at(2),
            FormLine::text(format!(
                "Projected requests/hour: {}{}",
                preview.map_or(form.projected_requests_per_hour, |p| p
                    .projected_requests_per_hour),
                if preview.map_or(form.projection_is_floor, |p| p.projection_is_floor) {
                    " (a floor: organization targets present)"
                } else {
                    ""
                }
            )),
            FormLine::text(format!(
                "Maximum repository targets: about {}",
                preview.map_or(form.maximum_repository_targets, |p| p
                    .maximum_repository_targets)
            )),
            FormLine::text("30-second floor; over-budget changes are refused."),
            FormLine::keep("Save host settings [Enter/click]").at(3),
            FormLine::text(""),
            // -- where disposable attempts are created (Journeys 1 and 2) ---
            FormLine::keep(format!(
                "Runner root: {}  ({})",
                form.runner_root.rendered(),
                form.runner_root.source()
            )),
            FormLine::text(format!(
                "Affected attempts: {} active, {} awaiting cleanup",
                form.affected.active, form.affected.cleanup_blocked
            )),
            FormLine::keep(self.field_row("Override", &self.host_root, width))
                .at(4)
                .copyable(if self.host_root.is_blank() {
                    form.runner_root.rendered()
                } else {
                    self.host_root.text()
                }),
        ];
        if let Some(notice) = &self.host_root_notice {
            lines.push(FormLine::keep(notice.clone()));
        }
        lines.push(FormLine::text("Reset to platform default [Enter/click]").at(5));
        lines.push(FormLine::keep("Save runner root [Enter/click]").at(6));
        lines.push(FormLine::text(format!(
            "Focused form actions: {}/{} capacity, {}/{} runner root",
            form.focused_action_count(),
            MAX_FOCUSED_FORM_ACTIONS,
            HostSettings::workspace_action_count(),
            MAX_FOCUSED_FORM_ACTIONS
        )));
        lines
    }

    fn policy_lines(&self, form: &PolicySettings, width: usize) -> Vec<FormLine> {
        let preview = form.preview(&self.policy_draft);
        let mut lines = vec![
            FormLine::keep(format!("Target: {}", form.target)),
            FormLine::text(format!("Mode: {:?}", form.mode)),
            FormLine::text(format!("Local host: {}", form.host_identity)),
            FormLine::text(format!(
                "Current max_capacity: {}",
                form.current_max_capacity
                    .map_or_else(|| "monitor-only".into(), |v| v.to_string())
            )),
            FormLine::text(format!(
                "runs-on: {}  [click to copy]",
                form.copyable_runs_on
                    .as_deref()
                    .unwrap_or("not reserved until promotion")
            ))
            .copyable(
                form.copyable_runs_on
                    .clone()
                    .unwrap_or_else(|| "not reserved until promotion".to_owned()),
            ),
        ];
        let mut next = 0;
        if form.exposes_scale_toggle() {
            lines.push(
                FormLine::text(format!("Scaling enabled: {}  [toggle]", preview.to_enabled))
                    .at(next),
            );
            next += 1;
        }
        lines.push(
            FormLine::keep(format!(
                "max_capacity: {}  [-/+; setting promotes monitor-only]",
                preview
                    .to_capacity
                    .map_or_else(|| "unset".into(), |v| v.to_string())
            ))
            .at(next),
        );
        next += 1;
        lines.push(
            FormLine::text(format!(
                "Cache policy: {:?}  [toggle]",
                preview.cache_policy
            ))
            .at(next),
        );
        next += 1;
        if let Some(warning) = preview.trust_warning {
            lines.push(FormLine::text(warning));
        } else if preview.drain_confirmation_required {
            lines.push(FormLine::text(format!(
                "Disabling means draining {} active runner(s); none will be terminated.",
                preview.active_runners
            )));
        } else {
            lines.push(FormLine::text(
                "Preview: no runner is terminated immediately.",
            ));
        }
        lines.push(FormLine::keep("Confirm policy [Enter/click]").at(next));
        next += 1;
        lines.push(FormLine::text(""));
        lines.extend(self.workspace_lines(form, width, next));
        lines.push(FormLine::text(format!(
            "Focused form actions: {}/{} scaling, {}/{} workspace",
            form.focused_action_count(),
            MAX_FOCUSED_FORM_ACTIONS,
            form.workspace_action_count(self.workspace_mode),
            MAX_FOCUSED_FORM_ACTIONS
        )));
        lines
    }

    /// The workspace half of Repository Settings (`02-target-architecture.md`,
    /// "TUI"), and the organization explanation that replaces it.
    fn workspace_lines(
        &self,
        form: &PolicySettings,
        width: usize,
        first_control: usize,
    ) -> Vec<FormLine> {
        let mut lines = vec![
            FormLine::keep(format!(
                "Workspace: {}  ({})",
                form.workspace.kind(),
                form.workspace.root_source_badge()
            )),
            FormLine::keep(format!(
                "Workspace root: {}",
                form.workspace.effective_root().unwrap_or("unavailable")
            )),
            FormLine::text(lease_summary(&form.workspace.leases)),
            FormLine::text(format!(
                "Affected attempts: {} active, {} awaiting cleanup",
                form.workspace.attempts.active, form.workspace.attempts.cleanup_blocked
            )),
        ];
        if form.is_organization() {
            lines.push(FormLine::keep(ORGANIZATION_WORKSPACE_MODE));
            lines.push(FormLine::text(ORGANIZATION_WORKSPACE_EXPLANATION));
            lines.push(FormLine::text(format!(
                "Configure it per repository instead: {}",
                RootOwner::Repository("OWNER/REPO".to_owned()).remediation()
            )));
            return lines;
        }
        let mut control = first_control;
        lines.push(
            FormLine::keep(format!("Workspace mode: {}  [toggle]", self.workspace_mode))
                .at(control),
        );
        control += 1;
        if self.workspace_mode.is_persistent() {
            lines.push(
                FormLine::keep(self.field_row("Persistent root", &self.workspace_path, width))
                    .at(control)
                    .copyable(self.workspace_path.text()),
            );
            control += 1;
        }
        if let Some(notice) = &self.workspace_notice {
            lines.push(FormLine::keep(notice.clone()));
        }
        if self.workspace_mode.is_persistent() {
            // `04-security-recovery.md`: the warnings are stated "before
            // persistent mode is saved", so the preview carries them verbatim
            // from the one place they are written. The headline survives a
            // compact terminal; the whole list is in the save output either way.
            for (index, line) in cli::workspace::PERSISTENT_TRUST_WARNING.iter().enumerate() {
                lines.push(if index == 0 {
                    FormLine::keep(*line)
                } else {
                    FormLine::text(*line)
                });
            }
        }
        if let Some(retained) = self.retained_notice(form) {
            lines.push(FormLine::keep(retained));
        }
        lines.push(FormLine::keep("Save workspace [Enter/click]").at(control));
        lines
    }

    /// The non-destructive notice: `02-target-architecture.md` requires "a
    /// non-destructive notice when changing mode or path leaves old
    /// directories", and Journey 4 requires the same on the way back to
    /// disposable mode.
    fn retained_notice(&self, form: &PolicySettings) -> Option<String> {
        let current = form.workspace.policy.root()?;
        let moving_away = !self.workspace_mode.is_persistent()
            || self.workspace_path.text().trim() != current.as_str();
        moving_away.then(|| {
            format!(
                "Left in place: every slot under {current} remains on disk, including its _work \
                 directory. Nothing is moved or deleted."
            )
        })
    }

    /// One path control's row: label, the visible window of the value, and the
    /// keys that apply right now.
    fn field_row(&self, label: &str, field: &PathField, width: usize) -> String {
        let hint = if field.is_editing() {
            "  [Esc cancel | Enter accept]"
        } else {
            "  [Enter to edit]"
        };
        let budget = width
            .saturating_sub(label.chars().count() + 2 + hint.chars().count() + 2)
            .max(8);
        let view = field.view(budget);
        let rendered = view.rendered();
        let shown = if rendered.is_empty() {
            "(none - platform default)".to_owned()
        } else {
            rendered
        };
        format!("{label}: {shown}{hint}")
    }
}

/// The inline answer for one previewed path.
///
/// A refusal the operator cannot act on yet — running work — is reported only
/// once the path itself is known to be usable, so a typo is never hidden behind
/// "wait for the job to finish".
fn notice_for(
    checked: Result<LocalAbsolutePath, CliError>,
    affected: AffectedAttempts,
    subject: &str,
    accepted_prefix: &str,
) -> String {
    match checked {
        Err(error) => error.remedy().map_or_else(
            || format!("error: {error}"),
            |remedy| format!("error: {error} ({remedy})"),
        ),
        Ok(_) if !affected.is_empty() => format!("refused: {}", affected.refusal(subject)),
        Ok(root) => format!("ready: {accepted_prefix} {root}."),
    }
}

/// The slot leases one policy still holds, by number and state only.
///
/// `d1`'s read model deliberately carries no path, and `e1`'s scope repeats it:
/// settings screens "never enumerate workspace file names".
fn lease_summary(leases: &[cli::workspace::SlotLease]) -> String {
    if leases.is_empty() {
        return "Slot leases: none".to_owned();
    }
    let rendered = leases
        .iter()
        .map(|lease| {
            format!(
                "s{} {}",
                lease.slot,
                if lease.cleanup_blocked {
                    "cleanup-blocked"
                } else {
                    "active"
                }
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("Slot leases: {rendered}")
}

/// Greedy wrap to `width` columns, hard-splitting a token no row can hold.
///
/// A configured root is exactly such a token, and a path silently cut off at the
/// edge of the frame is the one thing a screen whose job is to show a path must
/// not do.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    if text.chars().count() <= width {
        return vec![text.to_owned()];
    }
    let mut rows: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut used = 0usize;
    for word in text.split(' ') {
        let length = word.chars().count();
        if used > 0 && used + 1 + length > width {
            rows.push(std::mem::take(&mut current));
            used = 0;
        }
        if length > width {
            if used > 0 {
                rows.push(std::mem::take(&mut current));
            }
            let characters: Vec<char> = word.chars().collect();
            for chunk in characters.chunks(width) {
                rows.push(chunk.iter().collect());
            }
            current = rows.pop().unwrap_or_default();
            used = current.chars().count();
            continue;
        }
        if used > 0 {
            current.push(' ');
            used += 1;
        }
        current.push_str(word);
        used += length;
    }
    rows.push(current);
    rows
}

pub fn render(frame: &mut Frame<'_>, area: Rect, ui: &SettingsUi, compact: bool) {
    let width = content_width(area.width);
    let mut lines: Vec<Line<'_>> = ui
        .rows(width, compact)
        .into_iter()
        .map(|row| {
            let focused = row.control.is_some() && row.control == Some(ui.focus);
            focus_line(focused, row.text)
        })
        .collect();
    if let Some(message) = &ui.message {
        lines.extend(wrap(message, width).into_iter().map(Line::from));
    }
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().title("Settings").borders(Borders::ALL)),
        area,
    );
}

/// The columns a settings row may use inside the bordered block.
///
/// `render` and the shell's click handler have to agree on it exactly, or a
/// click lands on the row the frame did not draw there.
#[must_use]
pub fn content_width(area_width: u16) -> usize {
    usize::from(area_width.saturating_sub(2)).max(1)
}

fn focus_line<'a>(focused: bool, text: impl Into<String>) -> Line<'a> {
    let style = if focused {
        Style::default().add_modifier(Modifier::REVERSED)
    } else {
        Style::default()
    };
    Line::from(Span::styled(text.into(), style))
}

#[cfg(test)]
fn dispatch_capacity(
    context: &Context,
    target: &ScaleTarget,
    maximum: u16,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    match target.scope() {
        TargetScope::Repository => cli::policy::dispatch_repo(
            context,
            &RepoCommand::SetCapacity(RepoSetCapacityArgs {
                repository: target.to_string(),
                max_capacity: maximum,
            }),
            out,
        ),
        TargetScope::Organization => cli::policy::dispatch_org(
            context,
            &OrgCommand::SetCapacity(OrgSetCapacityArgs {
                organization: target.to_string(),
                max_capacity: maximum,
            }),
            out,
        ),
    }
}

#[cfg(test)]
fn dispatch_scale(
    context: &Context,
    target: &ScaleTarget,
    enabled: bool,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    match target.scope() {
        TargetScope::Repository => cli::policy::dispatch_repo(
            context,
            &RepoCommand::SetScale(RepoSetScaleArgs {
                repository: target.to_string(),
                enabled,
            }),
            out,
        ),
        TargetScope::Organization => cli::policy::dispatch_org(
            context,
            &OrgCommand::SetScale(OrgSetScaleArgs {
                organization: target.to_string(),
                enabled,
            }),
            out,
        ),
    }
}

fn find_policy(store: &dyn Store, target: &ScaleTarget) -> Result<ScalePolicy, CliError> {
    store
        .policies()
        .map_err(store_failure)?
        .into_iter()
        .find(|policy| &policy.target == target)
        .ok_or_else(|| CliError::new(Failure::NotFound, format!("no policy for {target} exists")))
}

fn invalid(source: impl std::fmt::Display) -> CliError {
    CliError::new(Failure::InvalidArgument, source.to_string())
}

fn store_failure(source: StoreError) -> CliError {
    if source.is_conflict() {
        CliError::with_remedy(
            Failure::Conflict,
            source.to_string(),
            "re-open settings, then retry",
        )
    } else {
        CliError::new(Failure::LocalState, source.to_string())
    }
}

fn service_failure(source: ServiceError) -> CliError {
    CliError::with_remedy(
        Failure::LocalState,
        source.to_string(),
        "runner-manager service status",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::num::NonZeroU16;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use runner_manager_domain::attempt::RunnerAttempt;
    use runner_manager_domain::model::{Arch, AttemptId, Host, HostId, HostLabel, Os, PolicyId};
    use runner_manager_domain::policy::{PolicyState, RoutingLabels};
    use tempfile::TempDir;

    fn nz(value: u16) -> NonZeroU16 {
        NonZeroU16::new(value).unwrap()
    }

    fn fixture(monitor_only: bool) -> (TempDir, Context, ScaleTarget) {
        let dir = TempDir::new().unwrap();
        let context = Context::resolve(Some(dir.path()), &mut Vec::new()).unwrap();
        let store = context.store().unwrap();
        let host = Host::new(
            HostId::from_u128(1),
            "local-home",
            Os::Linux,
            Arch::X64,
            nz(4),
            chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        )
        .unwrap();
        store.put_host(&host).unwrap();
        let target = ScaleTarget::repository("octo/repo").unwrap();
        let mode = if monitor_only {
            PolicyMode::MonitorOnly
        } else {
            PolicyMode::autoscale(
                RoutingLabels::derive(&HostLabel::new("home").unwrap(), Os::Linux, Arch::X64),
                0,
                nz(2),
            )
            .unwrap()
        };
        let policy = ScalePolicy::new_for_host_label(
            PolicyId::from_u128(2),
            target.clone(),
            7,
            host.id,
            HostLabel::new("home").unwrap(),
            mode,
            CachePolicy::default(),
        );
        store.insert_policy(&policy).unwrap();
        drop(store);
        (dir, context, target)
    }

    #[test]
    fn forms_stay_inside_the_five_action_budget_and_monitor_only_has_no_noop_toggle() {
        let (_dir, context, target) = fixture(false);
        let autoscale = PolicySettings::load(&context, &target).unwrap();
        assert!(autoscale.focused_action_count() <= MAX_FOCUSED_FORM_ACTIONS);
        assert!(autoscale.exposes_scale_toggle());
        let (_dir, context, target) = fixture(true);
        let monitor = PolicySettings::load(&context, &target).unwrap();
        assert!(monitor.focused_action_count() <= MAX_FOCUSED_FORM_ACTIONS);
        assert!(!monitor.exposes_scale_toggle());
        assert_eq!(monitor.current_max_capacity, None);
    }

    #[test]
    fn views_show_current_values_identity_and_copy_safe_labels() {
        let (_dir, context, target) = fixture(false);
        let policy = PolicySettings::load(&context, &target).unwrap();
        assert_eq!(policy.current_max_capacity, Some(2));
        assert_eq!(policy.host_identity, "local-home");
        assert_eq!(policy.routing_labels, ["rm-home-linux-x64"]);
        assert_eq!(
            policy.copyable_runs_on.as_deref(),
            Some("rm-home-linux-x64")
        );
        let host = HostSettings::load(&context).unwrap();
        assert_eq!((host.current_capacity, host.current_in_use), (4, 0));
        assert!(host.focused_action_count() <= MAX_FOCUSED_FORM_ACTIONS);
    }

    #[test]
    fn interval_preview_enforces_floor_and_updates_both_budget_numbers() {
        let (_dir, context, _) = fixture(false);
        let form = HostSettings::load(&context).unwrap();
        assert_eq!(
            form.preview_interval(29).unwrap_err().class(),
            Failure::InvalidArgument
        );
        let faster = form.preview_interval(30).unwrap();
        let slower = form.preview_interval(120).unwrap();
        assert!(faster.projected_requests_per_hour > slower.projected_requests_per_hour);
        assert!(faster.maximum_repository_targets < slower.maximum_repository_targets);
    }

    #[test]
    fn tui_host_capacity_is_the_cli_handler() {
        let (_dir, context, _) = fixture(false);
        HostSettings::set_capacity(&context, 7, &mut Vec::new()).unwrap();
        assert_eq!(
            cli::host::local_host(&context.store().unwrap())
                .unwrap()
                .unwrap()
                .host_capacity(),
            7
        );
        assert_eq!(
            HostSettings::set_capacity(&context, 0, &mut Vec::new())
                .unwrap_err()
                .class(),
            Failure::InvalidArgument
        );
    }

    #[test]
    fn cli_and_tui_persist_byte_equivalent_host_policy_enable_disable_and_promotion_state() {
        let (_a, tui, target) = fixture(false);
        let (_b, cli_context, cli_target) = fixture(false);

        HostSettings::set_capacity(&tui, 7, &mut Vec::new()).unwrap();
        cli::host::set_capacity(
            &cli_context,
            &HostSetCapacityArgs { capacity: 7 },
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(
            cli::host::local_host(&tui.store().unwrap()).unwrap(),
            cli::host::local_host(&cli_context.store().unwrap()).unwrap()
        );

        let form = PolicySettings::load(&tui, &target).unwrap();
        form.apply(
            &tui,
            &PolicyDraft {
                max_capacity: Some(5),
                enabled: Some(true),
                cache_policy: None,
            },
            None,
            &mut Vec::new(),
        )
        .unwrap();
        dispatch_capacity(&cli_context, &cli_target, 5, &mut Vec::new()).unwrap();
        dispatch_scale(&cli_context, &cli_target, true, &mut Vec::new()).unwrap();
        assert_eq!(
            find_policy(&tui.store().unwrap(), &target).unwrap(),
            find_policy(&cli_context.store().unwrap(), &cli_target).unwrap()
        );

        let form = PolicySettings::load(&tui, &target).unwrap();
        form.apply(
            &tui,
            &PolicyDraft {
                enabled: Some(false),
                ..PolicyDraft::default()
            },
            None,
            &mut Vec::new(),
        )
        .unwrap();
        dispatch_scale(&cli_context, &cli_target, false, &mut Vec::new()).unwrap();
        assert_eq!(
            find_policy(&tui.store().unwrap(), &target).unwrap(),
            find_policy(&cli_context.store().unwrap(), &cli_target).unwrap()
        );

        let (_a, tui, target) = fixture(true);
        let (_b, cli_context, cli_target) = fixture(true);
        PolicySettings::load(&tui, &target)
            .unwrap()
            .apply(
                &tui,
                &PolicyDraft {
                    max_capacity: Some(3),
                    ..PolicyDraft::default()
                },
                None,
                &mut Vec::new(),
            )
            .unwrap();
        dispatch_capacity(&cli_context, &cli_target, 3, &mut Vec::new()).unwrap();
        assert_eq!(
            find_policy(&tui.store().unwrap(), &target).unwrap(),
            find_policy(&cli_context.store().unwrap(), &cli_target).unwrap()
        );
    }

    #[test]
    fn policy_capacity_and_monitor_promotion_use_the_cli_handler() {
        for monitor_only in [false, true] {
            let (_dir, context, target) = fixture(monitor_only);
            let form = PolicySettings::load(&context, &target).unwrap();
            form.apply(
                &context,
                &PolicyDraft {
                    max_capacity: Some(5),
                    ..PolicyDraft::default()
                },
                None,
                &mut Vec::new(),
            )
            .unwrap();
            let stored = find_policy(&context.store().unwrap(), &target).unwrap();
            assert_eq!(stored.max_capacity().map(NonZeroU16::get), Some(5));
            assert_eq!(stored.state(), PolicyState::Pending);
            assert!(!stored.enabled());
        }
    }

    #[test]
    fn enablement_previews_warning_and_dispatches_cli_output() {
        let (_dir, context, target) = fixture(false);
        let form = PolicySettings::load(&context, &target).unwrap();
        let draft = PolicyDraft {
            enabled: Some(true),
            ..PolicyDraft::default()
        };
        assert_eq!(form.preview(&draft).trust_warning, Some(FORK_TRUST_WARNING));
        let mut output = Vec::new();
        form.apply(&context, &draft, None, &mut output).unwrap();
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains(FORK_TRUST_WARNING)
        );
        assert!(
            find_policy(&context.store().unwrap(), &target)
                .unwrap()
                .enabled()
        );
    }

    #[test]
    fn disable_preview_is_honest_and_never_promises_termination() {
        let (_dir, context, target) = fixture(false);
        dispatch_scale(&context, &target, true, &mut Vec::new()).unwrap();
        let form = PolicySettings::load(&context, &target).unwrap();
        let draft = PolicyDraft {
            enabled: Some(false),
            ..PolicyDraft::default()
        };
        assert_eq!(form.preview(&draft).state_after_disable, Some("disabled"));
        form.apply(&context, &draft, None, &mut Vec::new()).unwrap();
        assert_eq!(
            find_policy(&context.store().unwrap(), &target)
                .unwrap()
                .state(),
            PolicyState::Disabled
        );
    }

    #[test]
    fn active_disable_uses_only_the_drain_confirmation_and_keeps_work_alive() {
        let (_dir, context, target) = fixture(false);
        dispatch_scale(&context, &target, true, &mut Vec::new()).unwrap();
        let store = context.store().unwrap();
        let policy = find_policy(&store, &target).unwrap();
        let attempt = RunnerAttempt::allocate(
            AttemptId::from_u128(3),
            policy.id,
            "active-runtime",
            chrono::DateTime::from_timestamp(1_700_000_001, 0).unwrap(),
        );
        store.record_attempt(&attempt).unwrap();
        drop(store);

        let form = PolicySettings::load(&context, &target).unwrap();
        let draft = PolicyDraft {
            enabled: Some(false),
            ..PolicyDraft::default()
        };
        let preview = form.preview(&draft);
        assert_eq!(preview.active_runners, 1);
        assert_eq!(preview.state_after_disable, Some("draining"));
        assert!(preview.drain_confirmation_required);
        assert_eq!(
            form.apply(&context, &draft, None, &mut Vec::new())
                .unwrap_err()
                .class(),
            Failure::Conflict
        );
        let mut output = Vec::new();
        let observation = cli::policy::observe_scale(&context, &target).unwrap();
        form.apply(&context, &draft, Some(observation), &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(
            output.contains("draining with 1 active runner(s)"),
            "{output}"
        );
        assert!(output.contains("not terminated"), "{output}");
        let store = context.store().unwrap();
        assert_eq!(
            find_policy(&store, &target).unwrap().state(),
            PolicyState::Draining
        );
        assert!(store.attempt(AttemptId::from_u128(3)).unwrap().is_some());
    }

    #[test]
    fn rejected_capacity_does_not_change_persisted_state_across_reload() {
        let (_dir, context, target) = fixture(false);
        let form = PolicySettings::load(&context, &target).unwrap();
        let error = form
            .apply(
                &context,
                &PolicyDraft {
                    max_capacity: Some(0),
                    ..PolicyDraft::default()
                },
                None,
                &mut Vec::new(),
            )
            .unwrap_err();
        assert_eq!(error.class(), Failure::InvalidArgument);
        assert_eq!(
            PolicySettings::load(&context, &target)
                .unwrap()
                .current_max_capacity,
            Some(2)
        );
    }

    #[test]
    fn invalid_combined_draft_persists_none_of_its_fields() {
        let (_dir, context, target) = fixture(false);
        let before = find_policy(&context.store().unwrap(), &target).unwrap();
        let form = PolicySettings::load(&context, &target).unwrap();
        let error = form
            .apply(
                &context,
                &PolicyDraft {
                    max_capacity: Some(0),
                    enabled: Some(true),
                    cache_policy: Some(CachePolicy::DiscardRunnerPackage),
                },
                None,
                &mut Vec::new(),
            )
            .unwrap_err();
        assert_eq!(error.class(), Failure::InvalidArgument);
        assert_eq!(
            find_policy(&context.store().unwrap(), &target).unwrap(),
            before
        );
    }

    #[test]
    fn monitor_precondition_failure_persists_no_cache_or_scale_change() {
        let (_dir, context, target) = fixture(true);
        let before = find_policy(&context.store().unwrap(), &target).unwrap();
        let form = PolicySettings::load(&context, &target).unwrap();
        let error = form
            .apply(
                &context,
                &PolicyDraft {
                    max_capacity: None,
                    enabled: Some(true),
                    cache_policy: Some(CachePolicy::DiscardRunnerPackage),
                },
                None,
                &mut Vec::new(),
            )
            .unwrap_err();
        assert_eq!(error.class(), Failure::InvalidArgument);
        assert_eq!(
            find_policy(&context.store().unwrap(), &target).unwrap(),
            before
        );
    }

    #[test]
    fn stale_combined_draft_persists_none_of_its_fields() {
        let (_dir, context, target) = fixture(false);
        let confirmation = cli::policy::observe_scale(&context, &target).unwrap();
        cli::policy::apply_policy_mutation(
            &context,
            &target,
            cli::policy::PolicyMutation {
                max_capacity: Some(3),
                ..cli::policy::PolicyMutation::default()
            },
            None,
            &mut Vec::new(),
        )
        .unwrap();
        let before = find_policy(&context.store().unwrap(), &target).unwrap();
        let form = PolicySettings::load(&context, &target).unwrap();
        let error = form
            .apply(
                &context,
                &PolicyDraft {
                    max_capacity: Some(4),
                    enabled: Some(false),
                    cache_policy: Some(CachePolicy::DiscardRunnerPackage),
                },
                Some(confirmation),
                &mut Vec::new(),
            )
            .unwrap_err();
        assert_eq!(error.class(), Failure::Conflict);
        assert_eq!(
            find_policy(&context.store().unwrap(), &target).unwrap(),
            before
        );
    }

    #[test]
    fn organization_projection_floor_survives_load_and_live_preview() {
        let (_dir, context, _) = fixture(false);
        let store = context.store().unwrap();
        let host = cli::host::local_host(&store).unwrap().unwrap();
        let org = ScalePolicy::new_for_host_label(
            PolicyId::from_u128(30),
            ScaleTarget::organization("octo-org").unwrap(),
            8,
            host.id,
            HostLabel::new("home").unwrap(),
            PolicyMode::MonitorOnly,
            CachePolicy::default(),
        );
        store.insert_policy(&org).unwrap();
        drop(store);
        let form = HostSettings::load(&context).unwrap();
        assert!(form.projection_is_floor);
        assert!(form.preview_interval(90).unwrap().projection_is_floor);
    }

    #[test]
    fn over_budget_interval_is_refused_without_mutating_the_host() {
        let (_dir, context, _) = fixture(false);
        let store = context.store().unwrap();
        let host = cli::host::local_host(&store).unwrap().unwrap();
        for id in 40..70 {
            let policy = ScalePolicy::new_for_host_label(
                PolicyId::from_u128(id),
                ScaleTarget::repository(format!("octo/repo-{id}")).unwrap(),
                id as u64,
                host.id,
                HostLabel::new("home").unwrap(),
                PolicyMode::MonitorOnly,
                CachePolicy::default(),
            );
            store.insert_policy(&policy).unwrap();
        }
        drop(store);
        let form = HostSettings::load(&context).unwrap();
        let before = form.current_refresh_interval;
        let error = form.set_refresh_interval(&context, 30).unwrap_err();
        assert_eq!(error.class(), Failure::BudgetRefused);
        assert_eq!(
            HostSettings::load(&context)
                .unwrap()
                .current_refresh_interval,
            before
        );
    }

    #[test]
    fn inverted_min_max_is_rejected_through_the_production_policy_command() {
        let (_dir, context, target) = fixture(false);
        let store = context.store().unwrap();
        let old = find_policy(&store, &target).unwrap();
        store.remove_policy(old.id, old.revision()).unwrap();
        let replacement = ScalePolicy::new_for_host_label(
            old.id,
            target.clone(),
            7,
            old.host_id,
            old.requested_host_label,
            PolicyMode::autoscale(
                RoutingLabels::derive(&HostLabel::new("home").unwrap(), Os::Linux, Arch::X64),
                5,
                nz(6),
            )
            .unwrap(),
            CachePolicy::default(),
        );
        store.insert_policy(&replacement).unwrap();
        drop(store);
        let form = PolicySettings::load(&context, &target).unwrap();
        let error = form
            .apply(
                &context,
                &PolicyDraft {
                    max_capacity: Some(4),
                    ..PolicyDraft::default()
                },
                None,
                &mut Vec::new(),
            )
            .unwrap_err();
        assert_eq!(error.class(), Failure::InvalidArgument);
        assert_eq!(
            PolicySettings::load(&context, &target)
                .unwrap()
                .current_max_capacity,
            Some(6)
        );
    }

    #[test]
    fn service_mode_switch_persists_and_host_show_reads_the_same_mode() {
        #[derive(Default)]
        struct RecordingService {
            requested_modes: RefCell<Vec<StartMode>>,
        }

        impl RecordingService {
            fn switch(&self, mode: StartMode) -> Result<(), CliError> {
                self.requested_modes.borrow_mut().push(mode);
                Ok(())
            }
        }

        let (_dir, context, _) = fixture(false);
        let service = RecordingService::default();
        HostSettings::set_start_mode_with(&context, StartMode::Login, |mode| service.switch(mode))
            .unwrap();
        // The injected production seam accepts only an in-place mode switch;
        // it has no install request or reinstall callback to invoke.
        assert_eq!(*service.requested_modes.borrow(), [StartMode::Login]);
        let mut shown = Vec::new();
        cli::host::show(&context, &mut shown).unwrap();
        let shown = String::from_utf8(shown).unwrap();
        assert!(shown.contains("service start mode        login"), "{shown}");
        assert_eq!(
            HostSettings::load(&context).unwrap().current_start_mode,
            StartMode::Login
        );
    }

    #[test]
    fn cache_policy_survives_a_fresh_context_and_settings_errors_render() {
        let (dir, context, target) = fixture(false);
        PolicySettings::load(&context, &target)
            .unwrap()
            .apply(
                &context,
                &PolicyDraft {
                    cache_policy: Some(CachePolicy::DiscardRunnerPackage),
                    ..PolicyDraft::default()
                },
                None,
                &mut Vec::new(),
            )
            .unwrap();
        drop(context);
        let restarted = Context::resolve(Some(dir.path()), &mut Vec::new()).unwrap();
        assert_eq!(
            PolicySettings::load(&restarted, &target)
                .unwrap()
                .cache_policy,
            CachePolicy::DiscardRunnerPackage
        );

        let mut ui = SettingsUi::default();
        ui.execute(&restarted, SettingsCommand::LoadPolicy(String::new()));
        let mut terminal = Terminal::new(TestBackend::new(100, 20)).unwrap();
        terminal
            .draw(|frame| render(frame, frame.area(), &ui, false))
            .unwrap();
        let text = super::super::buffer_text(terminal.backend().buffer());
        assert!(text.contains("error:"), "{text}");
    }

    // -----------------------------------------------------------------------
    // e1-workspace-tui
    // -----------------------------------------------------------------------
    //
    // Everything below measures the workspace half of the two screens against
    // `02-target-architecture.md` ("TUI"), `04-security-recovery.md`
    // ("Operator-visible warnings") and `05-user-workflows.md` (Journeys 1-4,
    // Journey 6, and "TUI interaction requirements").

    use runner_manager_domain::attempt::{AttemptOutcome, FailureReason};
    use runner_manager_domain::workspace::AttemptWorkspace;

    use crate::cli::{HostCommand, HostSetRuntimeRootArgs};

    /// A host, one repository policy, and a **second** temporary directory to
    /// put workspace roots in.
    ///
    /// The second directory is not tidiness. `b1`'s preflight refuses a root
    /// that overlaps `config/`, `state/` or `logs/`, and all three live under
    /// the data directory, so a root inside it would be refused for a reason
    /// that has nothing to do with the case under test.
    struct Workspaces {
        _data: TempDir,
        roots: TempDir,
        context: Context,
        target: ScaleTarget,
    }

    impl Workspaces {
        fn new() -> Self {
            Self::sharing(TempDir::new().expect("a temporary directory"))
        }

        /// The same fixture, with the workspace roots handed in.
        ///
        /// The parity test needs two independent stores that were given one
        /// path, because "byte-identical stored values" is not a claim two
        /// different paths can settle.
        fn sharing(roots: TempDir) -> Self {
            let (data, context, target) = fixture(false);
            Self {
                _data: data,
                roots,
                context,
                target,
            }
        }

        /// A candidate root that does not exist yet: the preflight accepts a
        /// creatable leaf below a writable parent, which is the ordinary case.
        fn root(&self, leaf: &str) -> String {
            self.roots
                .path()
                .join(leaf)
                .to_str()
                .expect("a temporary path must be UTF-8")
                .to_owned()
        }

        fn host_screen(&self) -> SettingsUi {
            let mut ui = SettingsUi::default();
            ui.execute(&self.context, SettingsCommand::LoadHost);
            assert!(matches!(ui.view, SettingsView::Host(_)), "{:?}", ui.message);
            ui
        }

        fn policy_screen(&self) -> SettingsUi {
            let mut ui = SettingsUi::default();
            ui.execute(
                &self.context,
                SettingsCommand::LoadPolicy(self.target.to_string()),
            );
            assert!(
                matches!(ui.view, SettingsView::Policy(_)),
                "{:?}",
                ui.message
            );
            ui
        }

        fn stored_policy(&self) -> ScalePolicy {
            find_policy(&self.context.store().unwrap(), &self.target).expect("the seeded policy")
        }

        fn stored_host(&self) -> runner_manager_domain::model::Host {
            cli::host::local_host(&self.context.store().unwrap())
                .unwrap()
                .expect("the seeded host")
        }

        /// Adds one attempt to this policy, terminal or not.
        ///
        /// Terminal-but-uncleaned is the "cleanup-blocked" half of the two
        /// counts a path change is refused behind; allocated is the "active"
        /// half.
        fn attempt(&self, id: u128, terminal: bool) {
            self.attempt_in(id, terminal, AttemptWorkspace::Ephemeral);
        }

        /// The same, in a named persistent slot, so the screen has a lease to
        /// report.
        fn attempt_in(&self, id: u128, terminal: bool, workspace: AttemptWorkspace) {
            let store = self.context.store().unwrap();
            let policy = find_policy(&store, &self.target).unwrap();
            let mut attempt = RunnerAttempt::allocate_in(
                AttemptId::from_u128(id),
                policy.id,
                "runtime",
                workspace,
                chrono::DateTime::from_timestamp(1_700_000_100, 0).unwrap(),
            );
            if terminal {
                attempt
                    .conclude(
                        AttemptOutcome::failed(FailureReason::ProcessStartFailed),
                        chrono::DateTime::from_timestamp(1_700_000_200, 0).unwrap(),
                    )
                    .expect("allocated -> failed is a legal conclusion");
            }
            store.record_attempt(&attempt).unwrap();
        }
    }

    /// Moves the focus with the key an operator presses.
    ///
    /// Deliberately not `ui.focus = n`: a control that cannot be reached with
    /// Tab or Down is an accessibility defect, and setting the index directly
    /// would hide it. `05-user-workflows.md`: "Mouse selects and focuses path
    /// controls but is not required for completion."
    fn focus_by_keyboard(ui: &mut SettingsUi, control: Control) {
        ui.focus = 0;
        for _ in 0..=ui.controls().len() {
            if ui.focused() == Some(control) {
                return;
            }
            let _ = ui.key(KeyCode::Down);
        }
        panic!("{control:?} is not reachable with Down from the first control");
    }

    /// Types a value into the focused path control exactly as a keyboard does.
    fn type_path(ui: &mut SettingsUi, text: &str) {
        for character in text.chars() {
            assert!(
                ui.key(KeyCode::Char(character)).is_none(),
                "typing must not dispatch a command"
            );
        }
    }

    /// Focus the field, open it, replace its value, accept, and run the inline
    /// check.
    ///
    /// The old value is cleared with End and Backspace rather than by assigning
    /// the field, because that is the only way an operator has of replacing a
    /// configured root — and a helper that assigned it would have hidden the
    /// first draft of this control appending to the stored value instead of
    /// replacing it.
    fn edit_path(ui: &mut SettingsUi, context: &Context, control: Control, text: &str) {
        focus_by_keyboard(ui, control);
        assert!(ui.key(KeyCode::Enter).is_none(), "Enter opens the editor");
        assert!(ui.is_editing());
        let _ = ui.key(KeyCode::End);
        for _ in 0..field_of(ui, control).text().chars().count() {
            let _ = ui.key(KeyCode::Backspace);
        }
        assert!(field_of(ui, control).text().is_empty());
        type_path(ui, text);
        let command = ui
            .key(KeyCode::Enter)
            .expect("Enter accepts and revalidates");
        assert!(!ui.is_editing());
        ui.execute(context, command);
    }

    fn field_of(ui: &SettingsUi, control: Control) -> &PathField {
        match control {
            Control::HostRunnerRoot => &ui.host_root,
            Control::WorkspacePath => &ui.workspace_path,
            other => panic!("{other:?} is not a path control"),
        }
    }

    /// Focus a control and press Enter, running whatever it dispatches.
    fn activate(ui: &mut SettingsUi, context: &Context, control: Control) {
        focus_by_keyboard(ui, control);
        let Some(command) = ui.key(KeyCode::Enter) else {
            panic!("{control:?} must dispatch a command");
        };
        ui.execute(context, command);
    }

    /// The drawn rows as one paragraph.
    ///
    /// A sentence a frame wrapped is still that sentence, and an assertion that
    /// broke because a column got narrower would be measuring the wrap rather
    /// than the words.
    fn rows_paragraph(ui: &SettingsUi, width: usize, compact: bool) -> String {
        rows_text(ui, width, compact).replace('\n', " ")
    }

    /// The rows one frame draws, as text.
    fn rows_text(ui: &SettingsUi, width: usize, compact: bool) -> String {
        ui.rows(width, compact)
            .into_iter()
            .map(|row| row.text)
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn every_screen_task_stays_inside_the_five_action_budget() {
        let fixture = Workspaces::new();
        assert!(HostSettings::workspace_action_count() <= MAX_FOCUSED_FORM_ACTIONS);

        let form = PolicySettings::load(&fixture.context, &fixture.target).unwrap();
        assert_eq!(form.workspace_action_count(WorkspaceKind::Ephemeral), 2);
        assert_eq!(form.workspace_action_count(WorkspaceKind::Persistent), 3);
        assert!(form.workspace_action_count(WorkspaceKind::Persistent) <= MAX_FOCUSED_FORM_ACTIONS);
        assert!(!form.is_organization());

        // The host screen exposes exactly the seven controls its two tasks add
        // up to, and the repository screen's path control appears only in the
        // mode that has a path.
        assert_eq!(fixture.host_screen().controls().len(), 7);
        let mut policy = fixture.policy_screen();
        assert!(!policy.controls().contains(&Control::WorkspacePath));
        focus_by_keyboard(&mut policy, Control::WorkspaceMode);
        let _ = policy.key(KeyCode::Right);
        assert_eq!(policy.workspace_mode, WorkspaceKind::Persistent);
        assert!(policy.controls().contains(&Control::WorkspacePath));
    }

    /// The layout invariant the mouse map depends on: the controls a frame
    /// draws are the controls the keyboard walks, once each and in that order.
    #[test]
    fn drawn_rows_and_focusable_controls_agree_on_every_view() {
        let fixture = Workspaces::new();
        let mut persistent = fixture.policy_screen();
        focus_by_keyboard(&mut persistent, Control::WorkspaceMode);
        let _ = persistent.key(KeyCode::Right);
        let screens = vec![
            SettingsUi::default(),
            fixture.host_screen(),
            fixture.policy_screen(),
            persistent,
        ];

        for ui in &screens {
            for compact in [false, true] {
                for width in [40usize, 118] {
                    let drawn: Vec<usize> = ui
                        .rows(width, compact)
                        .into_iter()
                        .filter_map(|row| row.control)
                        .collect();
                    assert!(
                        drawn.iter().all(|index| *index < ui.controls().len()),
                        "compact={compact} width={width}: a drawn row points past the end of \
                         the control list"
                    );
                    assert!(
                        drawn.windows(2).all(|pair| pair[0] < pair[1]),
                        "compact={compact} width={width}: each control is drawn once, in focus \
                         order, or Tab and the mouse disagree"
                    );
                    if !compact {
                        assert_eq!(
                            drawn,
                            (0..ui.controls().len()).collect::<Vec<_>>(),
                            "width={width}: every focusable control must be on screen"
                        );
                    }
                }
            }
        }
    }

    /// Journey 1: the effective path and its source are readable without
    /// entering edit mode, and the editable value is the *override*.
    #[test]
    fn host_settings_show_the_effective_root_its_source_and_the_override_separately() {
        let fixture = Workspaces::new();
        let ui = fixture.host_screen();
        let SettingsView::Host(form) = &ui.view else {
            unreachable!()
        };
        assert_eq!(
            form.runner_root.source(),
            cli::workspace::RootSource::PlatformDefault
        );
        assert!(form.configured_root_text().is_empty());
        assert!(ui.host_root.is_blank(), "nothing to edit until one is set");

        let text = rows_text(&ui, 118, false);
        assert!(text.contains("Runner root:"), "{text}");
        assert!(text.contains("(platform-default)"), "{text}");
        assert!(text.contains("(none - platform default)"), "{text}");
        assert!(
            text.contains("Affected attempts: 0 active, 0 awaiting cleanup"),
            "{text}"
        );
    }

    /// The Definition of Done's first clause, measured rather than asserted:
    /// the screen and the command write the same bytes and print the same
    /// words, for a configured root, a reset, and both repository modes.
    ///
    /// Both surfaces are given the *same* directories, and those directories
    /// exist before either runs, so neither creates a leaf the other did not
    /// and the two success blocks are comparable character for character.
    #[test]
    fn tui_and_cli_store_byte_identical_workspace_values_and_render_one_message() {
        let roots = TempDir::new().unwrap();
        let host_root = roots.path().join("shared-root");
        let slots = roots.path().join("slots");
        std::fs::create_dir_all(&host_root).unwrap();
        std::fs::create_dir_all(&slots).unwrap();
        let host_root = host_root.to_str().unwrap().to_owned();
        let slots = slots.to_str().unwrap().to_owned();

        let through_tui = Workspaces::sharing(TempDir::new().unwrap());
        let through_cli = Workspaces::sharing(TempDir::new().unwrap());

        // -- host: configure ------------------------------------------------
        let mut ui = through_tui.host_screen();
        edit_path(
            &mut ui,
            &through_tui.context,
            Control::HostRunnerRoot,
            &host_root,
        );
        activate(&mut ui, &through_tui.context, Control::HostRootSave);
        let mut cli_out = Vec::new();
        cli::host::dispatch(
            &through_cli.context,
            &HostCommand::SetRuntimeRoot(HostSetRuntimeRootArgs {
                path: host_root.clone(),
            }),
            &mut cli_out,
        )
        .unwrap();
        assert_eq!(
            through_tui.stored_host().runner_root_override,
            through_cli.stored_host().runner_root_override,
        );
        assert_eq!(
            ui.message.as_deref().unwrap(),
            String::from_utf8(cli_out).unwrap().trim(),
        );

        // -- host: reset ----------------------------------------------------
        activate(&mut ui, &through_tui.context, Control::HostRootReset);
        let mut cli_out = Vec::new();
        cli::host::dispatch(
            &through_cli.context,
            &HostCommand::ResetRuntimeRoot,
            &mut cli_out,
        )
        .unwrap();
        assert_eq!(through_tui.stored_host().runner_root_override, None);
        assert_eq!(through_cli.stored_host().runner_root_override, None);
        assert_eq!(
            ui.message.as_deref().unwrap(),
            String::from_utf8(cli_out).unwrap().trim(),
        );

        // -- repository: persistent -----------------------------------------
        let mut ui = through_tui.policy_screen();
        focus_by_keyboard(&mut ui, Control::WorkspaceMode);
        let _ = ui.key(KeyCode::Right);
        edit_path(
            &mut ui,
            &through_tui.context,
            Control::WorkspacePath,
            &slots,
        );
        activate(&mut ui, &through_tui.context, Control::WorkspaceSave);
        let mut cli_out = Vec::new();
        cli::policy::dispatch_repo(
            &through_cli.context,
            &RepoCommand::SetWorkspace(RepoSetWorkspaceArgs {
                repository: through_cli.target.to_string(),
                mode: WorkspaceMode::Persistent,
                path: Some(slots.clone()),
            }),
            &mut cli_out,
        )
        .unwrap();
        assert_eq!(
            through_tui.stored_policy(),
            through_cli.stored_policy(),
            "one mutation from two surfaces must persist one policy, revision included"
        );
        assert_eq!(
            ui.message.as_deref().unwrap(),
            String::from_utf8(cli_out).unwrap().trim(),
        );

        // -- repository: back to ephemeral ----------------------------------
        focus_by_keyboard(&mut ui, Control::WorkspaceMode);
        let _ = ui.key(KeyCode::Right);
        activate(&mut ui, &through_tui.context, Control::WorkspaceSave);
        let mut cli_out = Vec::new();
        cli::policy::dispatch_repo(
            &through_cli.context,
            &RepoCommand::SetWorkspace(RepoSetWorkspaceArgs {
                repository: through_cli.target.to_string(),
                mode: WorkspaceMode::Ephemeral,
                path: None,
            }),
            &mut cli_out,
        )
        .unwrap();
        assert_eq!(through_tui.stored_policy(), through_cli.stored_policy());
        assert_eq!(
            ui.message.as_deref().unwrap(),
            String::from_utf8(cli_out).unwrap().trim(),
        );
    }

    /// Journey 6's table, from both surfaces: one refusal, one wording.
    #[test]
    fn every_validation_fixture_is_refused_with_the_same_reason_from_both_surfaces() {
        let fixture = Workspaces::new();
        let existing_file = fixture.roots.path().join("a-file");
        std::fs::write(&existing_file, b"not a directory").unwrap();

        let candidates = [
            // Relative.
            "build/runners".to_owned(),
            // A filesystem root is too broad.
            if cfg!(windows) {
                "C:\\".to_owned()
            } else {
                "/".to_owned()
            },
            // Overlaps protected application data.
            fixture
                .context
                .paths()
                .config_dir()
                .to_str()
                .unwrap()
                .to_owned(),
            // An existing file is not a directory.
            existing_file.to_str().unwrap().to_owned(),
        ];

        for candidate in candidates {
            let mut ui = fixture.host_screen();
            edit_path(
                &mut ui,
                &fixture.context,
                Control::HostRunnerRoot,
                &candidate,
            );
            let inline = ui.host_root_notice.clone().expect("an inline answer");
            activate(&mut ui, &fixture.context, Control::HostRootSave);
            let saved = ui.message.clone().unwrap_or_default();

            let refused = cli::host::dispatch(
                &fixture.context,
                &HostCommand::SetRuntimeRoot(HostSetRuntimeRootArgs {
                    path: candidate.clone(),
                }),
                &mut Vec::new(),
            )
            .expect_err("every fixture in this table is refused");

            assert!(
                inline.contains(&refused.to_string()),
                "{candidate:?}: the inline answer {inline:?} does not carry the command's \
                 reason {refused}"
            );
            assert_eq!(saved, format!("error: {refused}"), "{candidate:?}");
            assert_eq!(
                fixture.stored_host().runner_root_override,
                None,
                "{candidate:?} must persist nothing"
            );
            assert_eq!(
                ui.host_root.text(),
                candidate,
                "the draft stays on screen for correction"
            );
        }
    }

    /// Journey 3's warning is on the screen *before* the mutation, and Journey
    /// 4's non-destructive notice is on it before the way back.
    #[test]
    fn persistent_mode_previews_the_whole_trust_warning_and_the_retained_directories() {
        let fixture = Workspaces::new();
        let mut ui = fixture.policy_screen();
        focus_by_keyboard(&mut ui, Control::WorkspaceMode);
        let _ = ui.key(KeyCode::Right);
        let previewed = rows_paragraph(&ui, 118, false);
        for line in cli::workspace::PERSISTENT_TRUST_WARNING {
            assert!(previewed.contains(line.trim()), "missing {line:?}");
        }

        edit_path(
            &mut ui,
            &fixture.context,
            Control::WorkspacePath,
            &fixture.root("slots"),
        );
        activate(&mut ui, &fixture.context, Control::WorkspaceSave);
        assert_eq!(
            fixture.stored_policy().workspace_policy().kind(),
            WorkspaceKind::Persistent
        );

        // Journey 4: back to disposable, with the old slots named and kept.
        let sentinel = std::path::Path::new(&fixture.root("slots")).join("s1");
        std::fs::create_dir_all(&sentinel).unwrap();
        focus_by_keyboard(&mut ui, Control::WorkspaceMode);
        let _ = ui.key(KeyCode::Right);
        assert_eq!(ui.workspace_mode, WorkspaceKind::Ephemeral);
        let leaving = rows_paragraph(&ui, 118, false);
        assert!(leaving.contains("Left in place"), "{leaving}");
        assert!(
            leaving.contains("Nothing is moved or deleted."),
            "{leaving}"
        );

        activate(&mut ui, &fixture.context, Control::WorkspaceSave);
        assert_eq!(
            fixture.stored_policy().workspace_policy().kind(),
            WorkspaceKind::Ephemeral
        );
        assert!(
            sentinel.is_dir(),
            "returning to ephemeral must leave every old slot directory on disk"
        );
        let saved = ui.message.as_deref().unwrap_or_default();
        assert!(saved.contains("remains on disk"), "{saved}");
        assert!(
            saved.contains("No existing directory was moved or deleted."),
            "{saved}"
        );
    }

    /// Journey 2's reset, and the clause "Reset clears only the host override".
    #[test]
    fn reset_clears_the_override_and_nothing_else_on_the_host_row() {
        let fixture = Workspaces::new();
        let mut ui = fixture.host_screen();
        edit_path(
            &mut ui,
            &fixture.context,
            Control::HostRunnerRoot,
            &fixture.root("configured"),
        );
        activate(&mut ui, &fixture.context, Control::HostRootSave);

        // Change capacity through the screen's other task first, so a reset
        // that wrote a whole `Host` row would be caught here.
        focus_by_keyboard(&mut ui, Control::HostCapacity);
        let _ = ui.key(KeyCode::Right);
        activate(&mut ui, &fixture.context, Control::HostSave);
        let before = fixture.stored_host();
        assert!(before.runner_root_override.is_some());

        activate(&mut ui, &fixture.context, Control::HostRootReset);
        let after = fixture.stored_host();
        assert_eq!(after.runner_root_override, None);
        assert_eq!(after.host_capacity(), before.host_capacity());
        assert_eq!(after.service_start_mode, before.service_start_mode);
        assert_eq!(after.refresh_interval, before.refresh_interval);
        assert!(
            std::path::Path::new(&fixture.root("configured")).is_dir(),
            "a reset must not remove the directory the override named"
        );
        assert!(
            ui.host_root.is_blank(),
            "the field follows the stored value"
        );
    }

    /// Journey 6, in the TUI: the same refusal the command prints, inline, with
    /// the operator's draft preserved for correction.
    #[test]
    fn a_blank_draft_points_at_reset_rather_than_at_a_path_parser() {
        let fixture = Workspaces::new();
        let mut ui = fixture.host_screen();
        focus_by_keyboard(&mut ui, Control::HostRunnerRoot);
        let _ = ui.key(KeyCode::Enter);
        let command = ui.key(KeyCode::Enter).expect("accepting revalidates");
        ui.execute(&fixture.context, command);
        let blank = ui.host_root_notice.clone().unwrap();
        assert!(blank.contains("Reset to platform default"), "{blank}");

        activate(&mut ui, &fixture.context, Control::HostRootSave);
        assert_eq!(fixture.stored_host().runner_root_override, None);
        let message = ui.message.clone().unwrap_or_default();
        assert!(message.contains("type an absolute path"), "{message}");
    }

    /// A path change is refused while attempts still own the directory, and the
    /// screen previews *both* counts before the operator tries.
    #[test]
    fn active_and_cleanup_blocked_attempts_are_previewed_and_refuse_the_save() {
        for (terminal, expected) in [
            (false, "1 active and 0 awaiting"),
            (true, "0 active and 1 awaiting"),
        ] {
            let fixture = Workspaces::new();
            fixture.attempt(0x51, terminal);
            let mut ui = fixture.policy_screen();
            focus_by_keyboard(&mut ui, Control::WorkspaceMode);
            let _ = ui.key(KeyCode::Right);
            edit_path(
                &mut ui,
                &fixture.context,
                Control::WorkspacePath,
                &fixture.root("slots"),
            );
            let notice = ui.workspace_notice.clone().expect("a refusal preview");
            assert!(notice.starts_with("refused:"), "{notice}");
            assert!(notice.contains(expected), "{notice}");

            activate(&mut ui, &fixture.context, Control::WorkspaceSave);
            assert_eq!(
                fixture.stored_policy().workspace_policy().kind(),
                WorkspaceKind::Ephemeral,
                "a refused change must persist nothing"
            );
            let message = ui.message.clone().unwrap_or_default();
            assert!(message.contains(expected), "{message}");
        }
    }

    /// The host half of the same rule, with the counts drawn on the screen.
    #[test]
    fn an_uncleaned_ephemeral_attempt_blocks_and_is_shown_on_the_host_screen() {
        let fixture = Workspaces::new();
        fixture.attempt(0x61, false);
        let mut ui = fixture.host_screen();
        let text = rows_paragraph(&ui, 118, false);
        assert!(
            text.contains("Affected attempts: 1 active, 0 awaiting cleanup"),
            "{text}"
        );
        edit_path(
            &mut ui,
            &fixture.context,
            Control::HostRunnerRoot,
            &fixture.root("elsewhere"),
        );
        assert!(
            ui.host_root_notice
                .as_deref()
                .unwrap_or_default()
                .starts_with("refused:"),
            "{:?}",
            ui.host_root_notice
        );
        activate(&mut ui, &fixture.context, Control::HostRootSave);
        assert_eq!(fixture.stored_host().runner_root_override, None);
        assert!(
            !std::path::Path::new(&fixture.root("elsewhere")).exists(),
            "a refusal that never reached the preflight must create nothing"
        );
    }

    /// The Definition of Done's third clause, control by control.
    #[test]
    fn a_path_control_types_moves_deletes_pastes_cancels_accepts_and_scrolls() {
        let fixture = Workspaces::new();
        let mut ui = fixture.host_screen();
        focus_by_keyboard(&mut ui, Control::HostRunnerRoot);
        assert!(ui.key(KeyCode::Enter).is_none());

        type_path(&mut ui, "C:/rman");
        assert_eq!(ui.host_root.text(), "C:/rman");
        let _ = ui.key(KeyCode::Backspace);
        assert_eq!(ui.host_root.text(), "C:/rma");
        let _ = ui.key(KeyCode::Home);
        let _ = ui.key(KeyCode::Delete);
        assert_eq!(ui.host_root.text(), ":/rma");
        let _ = ui.key(KeyCode::Right);
        type_path(&mut ui, "!");
        assert_eq!(ui.host_root.text(), ":!/rma");
        let _ = ui.key(KeyCode::Left);
        let _ = ui.key(KeyCode::Delete);
        assert_eq!(ui.host_root.text(), ":/rma");
        let _ = ui.key(KeyCode::End);
        ui.paste("\"D:/pasted\"\r\nsecond line");
        assert_eq!(ui.host_root.text(), ":/rmaD:/pasted");

        // Escape restores what the operator started from.
        let _ = ui.key(KeyCode::Esc);
        assert!(!ui.is_editing());
        assert!(ui.host_root.is_blank());
        assert!(ui.host_root_notice.is_none());

        // Horizontal scrolling: the tail is visible while typing at the end,
        // and Home brings the head back.
        let long = format!("{}/{}", fixture.root("deep"), "segment".repeat(20));
        focus_by_keyboard(&mut ui, Control::HostRunnerRoot);
        let _ = ui.key(KeyCode::Enter);
        type_path(&mut ui, &long);
        let tail = ui.host_root.view(30);
        assert!(tail.clipped_left && !tail.clipped_right, "{tail:?}");
        assert!(tail.text.ends_with("segment|"), "{tail:?}");
        let _ = ui.key(KeyCode::Home);
        let head = ui.host_root.view(30);
        assert!(!head.clipped_left && head.clipped_right, "{head:?}");
        assert!(head.text.starts_with('|'), "{head:?}");

        // And no row a frame draws ever exceeds the width it was given.
        for width in [24usize, 40, 80, 118] {
            for row in ui.rows(width, false) {
                assert!(
                    row.text.chars().count() <= width,
                    "width={width} row={:?}",
                    row.text
                );
            }
        }
    }

    /// `c` copies the path an operator is looking at, and the copy is the value
    /// rather than the decorated row.
    #[test]
    fn the_focused_path_control_is_the_one_that_is_copied() {
        let fixture = Workspaces::new();
        let mut ui = fixture.host_screen();
        focus_by_keyboard(&mut ui, Control::HostRunnerRoot);
        let effective = match &ui.view {
            SettingsView::Host(form) => form.runner_root.rendered(),
            _ => unreachable!(),
        };
        assert_eq!(
            ui.copy_text(),
            Some(effective),
            "with no override the copyable value is the effective root"
        );
        edit_path(
            &mut ui,
            &fixture.context,
            Control::HostRunnerRoot,
            &fixture.root("copied"),
        );
        focus_by_keyboard(&mut ui, Control::HostRunnerRoot);
        assert_eq!(ui.copy_text(), Some(fixture.root("copied")));
        focus_by_keyboard(&mut ui, Control::HostSave);
        assert_eq!(ui.copy_text(), None, "a save action has nothing to copy");
    }

    /// The Definition of Done's second clause: nothing here lives in memory.
    #[test]
    fn saved_values_survive_a_recreated_context_and_a_reloaded_screen() {
        let data = TempDir::new().unwrap();
        let roots = TempDir::new().unwrap();
        let slots = roots.path().join("slots").to_str().unwrap().to_owned();
        let host_root = roots.path().join("host").to_str().unwrap().to_owned();
        let target = ScaleTarget::repository("octo/repo").unwrap();
        {
            let context = Context::resolve(Some(data.path()), &mut Vec::new()).unwrap();
            let store = context.store().unwrap();
            let host = Host::new(
                HostId::from_u128(1),
                "local-home",
                Os::Linux,
                Arch::X64,
                nz(4),
                chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            )
            .unwrap();
            store.put_host(&host).unwrap();
            store
                .insert_policy(&ScalePolicy::new_for_host_label(
                    PolicyId::from_u128(2),
                    target.clone(),
                    7,
                    host.id,
                    HostLabel::new("home").unwrap(),
                    PolicyMode::autoscale(
                        RoutingLabels::derive(
                            &HostLabel::new("home").unwrap(),
                            Os::Linux,
                            Arch::X64,
                        ),
                        0,
                        nz(2),
                    )
                    .unwrap(),
                    CachePolicy::default(),
                ))
                .unwrap();
            drop(store);

            let mut ui = SettingsUi::default();
            ui.execute(&context, SettingsCommand::LoadHost);
            edit_path(&mut ui, &context, Control::HostRunnerRoot, &host_root);
            activate(&mut ui, &context, Control::HostRootSave);

            ui.execute(&context, SettingsCommand::LoadPolicy(target.to_string()));
            focus_by_keyboard(&mut ui, Control::WorkspaceMode);
            let _ = ui.key(KeyCode::Right);
            edit_path(&mut ui, &context, Control::WorkspacePath, &slots);
            activate(&mut ui, &context, Control::WorkspaceSave);
        }

        // A new process, a new context, a freshly opened screen.
        let restarted = Context::resolve(Some(data.path()), &mut Vec::new()).unwrap();
        let mut ui = SettingsUi::default();
        ui.execute(&restarted, SettingsCommand::LoadHost);
        assert_eq!(ui.host_root.text(), host_root);
        let SettingsView::Host(form) = &ui.view else {
            unreachable!()
        };
        assert_eq!(form.runner_root.effective_text(), Some(host_root.as_str()));
        assert_eq!(
            form.runner_root.source(),
            cli::workspace::RootSource::Configured
        );

        ui.execute(&restarted, SettingsCommand::LoadPolicy(target.to_string()));
        assert_eq!(ui.workspace_mode, WorkspaceKind::Persistent);
        assert_eq!(ui.workspace_path.text(), slots);
        let SettingsView::Policy(form) = &ui.view else {
            unreachable!()
        };
        assert_eq!(form.workspace.effective_root(), Some(slots.as_str()));
        assert_eq!(form.workspace.root_source_badge(), "repository-specific");
    }

    /// D7 in the TUI: an explanation, not a disabled control.
    #[test]
    fn organization_settings_render_ephemeral_and_say_why_it_cannot_change() {
        let fixture = Workspaces::new();
        let store = fixture.context.store().unwrap();
        let host = cli::host::local_host(&store).unwrap().unwrap();
        let organization = ScaleTarget::organization("octo-org").unwrap();
        store
            .insert_policy(&ScalePolicy::new_for_host_label(
                PolicyId::from_u128(90),
                organization.clone(),
                9,
                host.id,
                HostLabel::new("home").unwrap(),
                PolicyMode::MonitorOnly,
                CachePolicy::default(),
            ))
            .unwrap();
        drop(store);

        let mut ui = SettingsUi::default();
        ui.execute(
            &fixture.context,
            SettingsCommand::LoadPolicy(organization.to_string()),
        );
        let SettingsView::Policy(form) = &ui.view else {
            panic!("{:?}", ui.message)
        };
        assert!(form.is_organization());
        assert_eq!(form.workspace.kind(), WorkspaceKind::Ephemeral);
        assert_eq!(form.workspace_action_count(WorkspaceKind::Persistent), 0);

        for control in [
            Control::WorkspaceMode,
            Control::WorkspacePath,
            Control::WorkspaceSave,
        ] {
            assert!(
                !ui.controls().contains(&control),
                "{control:?} must not exist for an organization"
            );
        }
        let text = rows_paragraph(&ui, 118, false);
        assert!(text.contains(ORGANIZATION_WORKSPACE_MODE), "{text}");
        assert!(text.contains("cross a repository boundary"), "{text}");
        assert!(text.contains("repo set-workspace OWNER/REPO"), "{text}");
        for line in cli::workspace::PERSISTENT_TRUST_WARNING {
            assert!(
                !text.contains(line.trim()),
                "an organization is never offered persistence, so it is never warned about it"
            );
        }
    }

    /// `e1`: "Keep current value, validation error, and save action visible in
    /// constrained layouts".
    #[test]
    fn a_constrained_terminal_keeps_the_value_the_error_and_the_save_action() {
        let fixture = Workspaces::new();
        let mut ui = fixture.host_screen();
        edit_path(
            &mut ui,
            &fixture.context,
            Control::HostRunnerRoot,
            "build/runners",
        );
        let compact = rows_text(&ui, 56, true);
        assert!(compact.contains("Runner root:"), "{compact}");
        assert!(compact.contains("Override:"), "{compact}");
        assert!(compact.contains("error:"), "{compact}");
        assert!(compact.contains("Save runner root"), "{compact}");
        assert!(compact.contains("Save host settings"), "{compact}");
        assert!(
            !compact.contains("30-second floor"),
            "secondary explanation is what a compact frame drops: {compact}"
        );

        let mut ui = fixture.policy_screen();
        focus_by_keyboard(&mut ui, Control::WorkspaceMode);
        let _ = ui.key(KeyCode::Right);
        let compact = rows_paragraph(&ui, 56, true);
        assert!(compact.contains("Workspace mode:"), "{compact}");
        assert!(compact.contains("Persistent root:"), "{compact}");
        assert!(compact.contains("Save workspace"), "{compact}");
        assert!(
            compact.contains(cli::workspace::PERSISTENT_TRUST_WARNING[0].trim()),
            "the headline warning survives a compact frame: {compact}"
        );
    }

    /// `e1`: settings screens "never enumerate workspace file names".
    #[test]
    fn no_settings_row_names_anything_inside_a_workspace() {
        let fixture = Workspaces::new();
        let mut ui = fixture.policy_screen();
        focus_by_keyboard(&mut ui, Control::WorkspaceMode);
        let _ = ui.key(KeyCode::Right);
        edit_path(
            &mut ui,
            &fixture.context,
            Control::WorkspacePath,
            &fixture.root("slots"),
        );
        activate(&mut ui, &fixture.context, Control::WorkspaceSave);

        // A real slot with real contents, none of which may reach a row.
        let slot = std::path::Path::new(&fixture.root("slots")).join("s1");
        std::fs::create_dir_all(slot.join("_work")).unwrap();
        std::fs::write(slot.join("_work").join("checkout-secret.txt"), b"x").unwrap();
        std::fs::write(slot.join("build-output-42"), b"x").unwrap();
        fixture.attempt(0x71, false);

        let text = rows_paragraph(&fixture.policy_screen(), 118, false);
        for name in ["checkout-secret.txt", "build-output-42"] {
            assert!(!text.contains(name), "{name} was enumerated: {text}");
        }
        // The lease list is the journal's, not the filesystem's: an ephemeral
        // attempt holds no slot, and a directory on disk never invents one.
        assert!(text.contains("Slot leases: none"), "{text}");
    }

    /// A frame is drawn from memory and carries no credential, including one
    /// pasted into a path control by mistake.
    #[test]
    fn no_secret_reaches_a_settings_frame() {
        let fixture = Workspaces::new();
        let mut ui = fixture.host_screen();
        focus_by_keyboard(&mut ui, Control::HostRunnerRoot);
        let _ = ui.key(KeyCode::Enter);
        ui.paste("ghu_this_must_not_escape");
        let command = ui.key(KeyCode::Enter).unwrap();
        ui.execute(&fixture.context, command);

        // Redaction is the shell's job and is asserted there; what matters here
        // is that the value is refused as a path and never becomes a stored
        // root, and that the frame names no credential material of its own.
        activate(&mut ui, &fixture.context, Control::HostRootSave);
        assert_eq!(fixture.stored_host().runner_root_override, None);

        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal
            .draw(|frame| render(frame, frame.area(), &ui, false))
            .unwrap();
        let drawn = super::super::buffer_text(terminal.backend().buffer());
        assert!(drawn.contains("Runner root:"), "{drawn}");
        assert!(!drawn.contains("Authorization"), "{drawn}");
        assert!(!drawn.contains("jitconfig"), "{drawn}");
        assert!(!drawn.contains("token"), "{drawn}");
    }

    /// Every state `e1`'s Definition of Done names, as the rows a frame draws.
    ///
    /// Paths are substituted for placeholders first: a `LocalAbsolutePath` is
    /// native to the platform it was parsed on, and a snapshot holding a real
    /// temporary directory would be a snapshot that passes exactly once.
    #[test]
    fn snapshot_every_required_settings_state() {
        insta::assert_snapshot!(settings_matrix(), @r###"
        --- host/default ---
        Host settings
        Current capacity: 4
        Currently in use: 0
        Capacity: 4  [-/+ or click]
        Service start: boot  [toggle]
        Refresh interval: 60s  [-/+ 30s]
        Projected requests/hour: 180
        Maximum repository targets: about 13
        30-second floor; over-budget changes are refused.
        Save host settings [Enter/click]

        Runner root: <DEFAULT>  (platform-default)
        Affected attempts: 0 active, 0 awaiting cleanup
        Override: (none - platform default)  [Enter to edit]
        Reset to platform default [Enter/click]
        Save runner root [Enter/click]
        Focused form actions: 4/5 capacity, 3/5 runner root
        --- host/configured ---
        Host settings
        Current capacity: 4
        Currently in use: 0
        Capacity: 4  [-/+ or click]
        Service start: boot  [toggle]
        Refresh interval: 60s  [-/+ 30s]
        Projected requests/hour: 180
        Maximum repository targets: about 13
        30-second floor; over-budget changes are refused.
        Save host settings [Enter/click]

        Runner root: <CONFIGURED>  (configured)
        Affected attempts: 0 active, 0 awaiting cleanup
        Override: <CONFIGURED>  [Enter to edit]
        Reset to platform default [Enter/click]
        Save runner root [Enter/click]
        Focused form actions: 4/5 capacity, 3/5 runner root
        --- host/invalid ---
        Host settings
        Current capacity: 4
        Currently in use: 0
        Capacity: 4  [-/+ or click]
        Service start: boot  [toggle]
        Refresh interval: 60s  [-/+ 30s]
        Projected requests/hour: 180
        Maximum repository targets: about 13
        30-second floor; over-budget changes are refused.
        Save host settings [Enter/click]

        Runner root: <DEFAULT>  (platform-default)
        Affected attempts: 0 active, 0 awaiting cleanup
        Override: build/runners  [Enter to edit]
        error: "build/runners" cannot be used as the host runner root: a configured path must be absolute;
        "build/runners" is relative, and what it resolves to depends on the process working directory
        (runner-manager host set-runtime-root --path <PATH>)
        Reset to platform default [Enter/click]
        Save runner root [Enter/click]
        Focused form actions: 4/5 capacity, 3/5 runner root
        --- host/active-refusal ---
        Host settings
        Current capacity: 4
        Currently in use: 1
        Capacity: 4  [-/+ or click]
        Service start: boot  [toggle]
        Refresh interval: 60s  [-/+ 30s]
        Projected requests/hour: 180
        Maximum repository targets: about 13
        30-second floor; over-budget changes are refused.
        Save host settings [Enter/click]

        Runner root: <DEFAULT>  (platform-default)
        Affected attempts: 1 active, 0 awaiting cleanup
        Override: <CONFIGURED>  [Enter to edit]
        refused: the host runner root cannot change while attempts still own it: 1 active and 0 awaiting
        cleanup. Nothing was changed.
        Reset to platform default [Enter/click]
        Save runner root [Enter/click]
        Focused form actions: 4/5 capacity, 3/5 runner root
        --- host/compact ---
        Current capacity: 4
        Capacity: 4  [-/+ or click]
        Save host settings [Enter/click]
        Runner root: <DEFAULT>  (platform-default)
        Override: build/runners  [Enter to edit]
        error: "build/runners" cannot be used as the host runner
        root: a configured path must be absolute;
        "build/runners" is relative, and what it resolves to
        depends on the process working directory (runner-manager
        host set-runtime-root --path <PATH>)
        Save runner root [Enter/click]
        --- repository/ephemeral ---
        Target: octo/repo
        Mode: Autoscale
        Local host: local-home
        Current max_capacity: 2
        runs-on: rm-home-linux-x64  [click to copy]
        Scaling enabled: false  [toggle]
        max_capacity: 2  [-/+; setting promotes monitor-only]
        Cache policy: RetainRunnerPackage  [toggle]
        Preview: no runner is terminated immediately.
        Confirm policy [Enter/click]

        Workspace: ephemeral  (platform-default)
        Workspace root: <DEFAULT>
        Slot leases: none
        Affected attempts: 0 active, 0 awaiting cleanup
        Workspace mode: ephemeral  [toggle]
        Save workspace [Enter/click]
        Focused form actions: 4/5 scaling, 2/5 workspace
        --- repository/persistent-warning ---
        Target: octo/repo
        Mode: Autoscale
        Local host: local-home
        Current max_capacity: 2
        runs-on: rm-home-linux-x64  [click to copy]
        Scaling enabled: false  [toggle]
        max_capacity: 2  [-/+; setting promotes monitor-only]
        Cache policy: RetainRunnerPackage  [toggle]
        Preview: no runner is terminated immediately.
        Confirm policy [Enter/click]

        Workspace: ephemeral  (platform-default)
        Workspace root: <DEFAULT>
        Slot leases: none
        Affected attempts: 0 active, 0 awaiting cleanup
        Workspace mode: persistent  [toggle]
        Persistent root: <SLOTS>  [Enter to edit]
        ready: slots s1, s2, ... would be created under <SLOTS>.
        warning: a persistent workspace is a trusted-workflow optimization, not isolation.
          - files under _work are an input to later jobs on the same slot;
          - executable and generated content can cross branch and job boundaries;
          - do not enable it for untrusted fork or pull-request workflows;
          - changing or disabling persistence does not delete old directories;
          - `actions/checkout` still cleans the workspace, including Git-ignored files,
            unless the workflow sets `clean: false`.
        Save workspace [Enter/click]
        Focused form actions: 4/5 scaling, 3/5 workspace
        --- repository/cleanup-blocked ---
        Target: octo/repo
        Mode: Autoscale
        Local host: local-home
        Current max_capacity: 2
        runs-on: rm-home-linux-x64  [click to copy]
        Scaling enabled: false  [toggle]
        max_capacity: 2  [-/+; setting promotes monitor-only]
        Cache policy: RetainRunnerPackage  [toggle]
        Preview: no runner is terminated immediately.
        Confirm policy [Enter/click]

        Workspace: persistent  (repository-specific)
        Workspace root: <SLOTS>
        Slot leases: s1 cleanup-blocked
        Affected attempts: 0 active, 1 awaiting cleanup
        Workspace mode: persistent  [toggle]
        Persistent root: <ELSEWHERE>  [Enter to edit]
        refused: the workspace setting for octo/repo cannot change while attempts still own it: 0 active and
        1 awaiting cleanup. Nothing was changed.
        warning: a persistent workspace is a trusted-workflow optimization, not isolation.
          - files under _work are an input to later jobs on the same slot;
          - executable and generated content can cross branch and job boundaries;
          - do not enable it for untrusted fork or pull-request workflows;
          - changing or disabling persistence does not delete old directories;
          - `actions/checkout` still cleans the workspace, including Git-ignored files,
            unless the workflow sets `clean: false`.
        Left in place: every slot under <SLOTS> remains on disk,
        including its _work directory. Nothing is moved or deleted.
        Save workspace [Enter/click]
        Focused form actions: 4/5 scaling, 3/5 workspace
        "###);
    }

    fn settings_matrix() -> String {
        let mut sections: Vec<(&str, String)> = Vec::new();

        let default = Workspaces::new();
        let effective = match &default.host_screen().view {
            SettingsView::Host(form) => form.runner_root.rendered(),
            _ => unreachable!(),
        };
        let stable = |text: String, fixture: &Workspaces| {
            text.replace(&fixture.root("slots"), "<SLOTS>")
                .replace(&fixture.root("configured"), "<CONFIGURED>")
                .replace(&effective, "<DEFAULT>")
        };

        sections.push((
            "host/default",
            stable(rows_text(&default.host_screen(), 100, false), &default),
        ));

        let configured = Workspaces::new();
        let mut ui = configured.host_screen();
        edit_path(
            &mut ui,
            &configured.context,
            Control::HostRunnerRoot,
            &configured.root("configured"),
        );
        activate(&mut ui, &configured.context, Control::HostRootSave);
        sections.push((
            "host/configured",
            stable(
                rows_text(&configured.host_screen(), 100, false),
                &configured,
            ),
        ));

        let invalid = Workspaces::new();
        let mut ui = invalid.host_screen();
        edit_path(
            &mut ui,
            &invalid.context,
            Control::HostRunnerRoot,
            "build/runners",
        );
        sections.push(("host/invalid", stable(rows_text(&ui, 100, false), &invalid)));

        let active = Workspaces::new();
        active.attempt(0x81, false);
        let mut ui = active.host_screen();
        edit_path(
            &mut ui,
            &active.context,
            Control::HostRunnerRoot,
            &active.root("configured"),
        );
        sections.push((
            "host/active-refusal",
            stable(rows_text(&ui, 100, false), &active),
        ));

        // The compact section reuses the *invalid* draft rather than a
        // temporary path: at 56 columns a path control scrolls horizontally,
        // and a snapshot of half a temporary directory name would pass exactly
        // once. The state it has to prove is the same either way -- current
        // value, validation error, save action.
        let mut ui = invalid.host_screen();
        edit_path(
            &mut ui,
            &invalid.context,
            Control::HostRunnerRoot,
            "build/runners",
        );
        sections.push(("host/compact", stable(rows_text(&ui, 56, true), &invalid)));

        let repository = Workspaces::new();
        sections.push((
            "repository/ephemeral",
            stable(
                rows_text(&repository.policy_screen(), 100, false),
                &repository,
            ),
        ));

        let mut ui = repository.policy_screen();
        focus_by_keyboard(&mut ui, Control::WorkspaceMode);
        let _ = ui.key(KeyCode::Right);
        edit_path(
            &mut ui,
            &repository.context,
            Control::WorkspacePath,
            &repository.root("slots"),
        );
        sections.push((
            "repository/persistent-warning",
            stable(rows_text(&ui, 100, false), &repository),
        ));

        let blocked = Workspaces::new();
        let mut ui = blocked.policy_screen();
        focus_by_keyboard(&mut ui, Control::WorkspaceMode);
        let _ = ui.key(KeyCode::Right);
        edit_path(
            &mut ui,
            &blocked.context,
            Control::WorkspacePath,
            &blocked.root("slots"),
        );
        activate(&mut ui, &blocked.context, Control::WorkspaceSave);
        blocked.attempt_in(0x91, true, AttemptWorkspace::persistent_slot(nz(1)));
        let mut ui = blocked.policy_screen();
        edit_path(
            &mut ui,
            &blocked.context,
            Control::WorkspacePath,
            &blocked.root("elsewhere"),
        );
        sections.push((
            "repository/cleanup-blocked",
            stable(rows_text(&ui, 100, false), &blocked)
                .replace(&blocked.root("elsewhere"), "<ELSEWHERE>"),
        ));

        sections
            .into_iter()
            .map(|(name, body)| format!("--- {name} ---\n{body}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}
