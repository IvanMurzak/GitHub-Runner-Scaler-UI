// owner: g3-tui-settings-parity

//! Editable TUI settings and the CLI-parity dispatch boundary.
//!
//! Forms are presentation data and never own a store. Host capacity and policy
//! capacity/scale changes are translated into the exact command values used by
//! the CLI, so validation and persistence cannot drift.

use std::io::Write;

use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use runner_manager_domain::attempt::active_count_for;
use runner_manager_domain::capacity::HostAllocator;
#[cfg(test)]
use runner_manager_domain::model::TargetScope;
use runner_manager_domain::model::{CachePolicy, RefreshInterval, ScaleTarget, StartMode};
use runner_manager_domain::policy::{PolicyMode, ScalePolicy};
use runner_manager_domain::store::{Store, StoreError};
use runner_manager_platform::service::{ServiceError, ServiceOperations};

use crate::cli::{self, CliError, Context, Failure, HostSetCapacityArgs};
#[cfg(test)]
use crate::cli::{
    OrgCommand, OrgSetCapacityArgs, OrgSetScaleArgs, RepoCommand, RepoSetCapacityArgs,
    RepoSetScaleArgs,
};

pub const MAX_FOCUSED_FORM_ACTIONS: u8 = 5;
pub const FORK_TRUST_WARNING: &str = "warning: fork and untrusted pull-request workflows must not run on a personal host until you explicitly accept that trust boundary.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSettings {
    pub current_capacity: u16,
    pub current_in_use: u16,
    pub current_start_mode: StartMode,
    pub current_refresh_interval: RefreshInterval,
    pub projected_requests_per_hour: u32,
    pub maximum_repository_targets: u32,
    pub projection_is_floor: bool,
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
            targets,
        })
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
            ServiceOperations::on_this_host(context.paths().clone())
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
        })
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
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SettingsView {
    #[default]
    Empty,
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
}

impl SettingsUi {
    pub fn execute(&mut self, context: &Context, command: SettingsCommand) -> Option<String> {
        if matches!(
            &command,
            SettingsCommand::LoadHost | SettingsCommand::LoadPolicy(_)
        ) {
            self.view = SettingsView::Empty;
            self.message = None;
        }
        let result = match command {
            SettingsCommand::LoadHost => HostSettings::load(context).map(|form| {
                self.host_capacity = form.current_capacity;
                self.host_mode = form.current_start_mode;
                self.host_interval_secs = form.current_refresh_interval.as_secs();
                self.view = SettingsView::Host(form);
                self.focus = 0;
                self.message = None;
            }),
            SettingsCommand::LoadPolicy(raw) => ScaleTarget::repository(&raw)
                .or_else(|_| ScaleTarget::organization(&raw))
                .map_err(invalid)
                .and_then(|target| PolicySettings::load(context, &target))
                .map(|form| {
                    self.policy_draft = PolicyDraft::default();
                    self.view = SettingsView::Policy(form);
                    self.focus = 0;
                    self.awaiting_drain_confirmation = false;
                    self.drain_observation = None;
                    self.message = None;
                }),
            SettingsCommand::ApplyHost => self.apply_host(context),
            SettingsCommand::ApplyPolicy => self.apply_policy(context),
            SettingsCommand::Copy(text) => return Some(text),
        };
        if let Err(error) = result {
            self.message = Some(format!("error: {error}"));
        }
        None
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
        let refreshed = HostSettings::load(context)?;
        self.host_capacity = refreshed.current_capacity;
        self.host_mode = refreshed.current_start_mode;
        self.host_interval_secs = refreshed.current_refresh_interval.as_secs();
        self.view = SettingsView::Host(refreshed);
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
        self.policy_draft = PolicyDraft::default();
        self.awaiting_drain_confirmation = false;
        self.drain_observation = None;
        self.view = SettingsView::Policy(PolicySettings::load(context, &target)?);
        Ok(())
    }

    #[must_use]
    pub fn key(&mut self, code: KeyCode) -> Option<SettingsCommand> {
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
        None
    }

    #[must_use]
    pub fn click(&mut self, content_row: u16) -> Option<SettingsCommand> {
        let row = usize::from(content_row);
        match &self.view {
            SettingsView::Host(_) => match row {
                3 => {
                    self.focus = 0;
                    self.adjust(true);
                    None
                }
                4 => {
                    self.focus = 1;
                    self.adjust(true);
                    None
                }
                5 => {
                    self.focus = 2;
                    self.adjust(true);
                    None
                }
                9 => {
                    self.focus = 3;
                    Some(SettingsCommand::ApplyHost)
                }
                _ => None,
            },
            SettingsView::Policy(form) => {
                let enabled_row = 5;
                let maximum_row = if form.exposes_scale_toggle() { 6 } else { 5 };
                let cache_row = maximum_row + 1;
                let confirm_row = cache_row + 2;
                if row == 4 {
                    return form.copyable_runs_on.clone().map(SettingsCommand::Copy);
                }
                if form.exposes_scale_toggle() && row == enabled_row {
                    self.focus = 0;
                    self.adjust(true);
                } else if row == maximum_row {
                    self.focus = usize::from(form.exposes_scale_toggle());
                    self.adjust(true);
                } else if row == cache_row {
                    self.focus = usize::from(form.exposes_scale_toggle()) + 1;
                    self.adjust(true);
                } else if row == confirm_row {
                    self.focus = self.control_count().saturating_sub(1);
                    return Some(SettingsCommand::ApplyPolicy);
                }
                None
            }
            SettingsView::Empty => None,
        }
    }

    fn control_count(&self) -> usize {
        match &self.view {
            SettingsView::Host(_) => 4,
            SettingsView::Policy(form) => usize::from(form.exposes_scale_toggle()) + 3,
            SettingsView::Empty => 0,
        }
    }

    fn adjust(&mut self, increase: bool) {
        match &self.view {
            SettingsView::Host(_) => match self.focus {
                0 => {
                    self.host_capacity = if increase {
                        self.host_capacity.saturating_add(1)
                    } else {
                        self.host_capacity.saturating_sub(1)
                    }
                }
                1 => {
                    self.host_mode = if self.host_mode == StartMode::Boot {
                        StartMode::Login
                    } else {
                        StartMode::Boot
                    }
                }
                2 => {
                    self.host_interval_secs = if increase {
                        self.host_interval_secs.saturating_add(30)
                    } else {
                        self.host_interval_secs
                            .saturating_sub(30)
                            .max(RefreshInterval::MIN_SECS)
                    }
                }
                _ => {}
            },
            SettingsView::Policy(form) => {
                let mut index = self.focus;
                if form.exposes_scale_toggle() {
                    if index == 0 {
                        self.policy_draft.enabled =
                            Some(!self.policy_draft.enabled.unwrap_or(form.enabled));
                        return;
                    }
                    index -= 1;
                }
                match index {
                    0 => {
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
                    1 => {
                        let current = self.policy_draft.cache_policy.unwrap_or(form.cache_policy);
                        self.policy_draft.cache_policy = Some(match current {
                            CachePolicy::RetainRunnerPackage => CachePolicy::DiscardRunnerPackage,
                            CachePolicy::DiscardRunnerPackage => CachePolicy::RetainRunnerPackage,
                        });
                    }
                    _ => {}
                }
            }
            SettingsView::Empty => {}
        }
    }

    fn activate(&self) -> Option<SettingsCommand> {
        match &self.view {
            SettingsView::Host(_) if self.focus == 3 => Some(SettingsCommand::ApplyHost),
            SettingsView::Policy(form) if self.focus + 1 == self.control_count() => {
                Some(SettingsCommand::ApplyPolicy)
            }
            SettingsView::Policy(form) => form
                .copyable_runs_on
                .clone()
                .filter(|_| self.focus == self.control_count())
                .map(SettingsCommand::Copy),
            SettingsView::Empty | SettingsView::Host(_) => None,
        }
    }
}

pub fn render(frame: &mut Frame<'_>, area: Rect, ui: &SettingsUi, compact: bool) {
    let lines = match &ui.view {
        SettingsView::Empty => vec![Line::from("Loading settings...")],
        SettingsView::Host(form) => {
            let preview = form.preview_interval(ui.host_interval_secs).ok();
            vec![
                Line::from("Host settings"),
                Line::from(format!("Current capacity: {}", form.current_capacity)),
                Line::from(format!("Currently in use: {}", form.current_in_use)),
                focus_line(
                    ui.focus == 0,
                    format!("Capacity: {}  [-/+ or click]", ui.host_capacity),
                ),
                focus_line(
                    ui.focus == 1,
                    format!("Service start: {}  [toggle]", ui.host_mode),
                ),
                focus_line(
                    ui.focus == 2,
                    format!("Refresh interval: {}s  [-/+ 30s]", ui.host_interval_secs),
                ),
                Line::from(format!(
                    "Projected requests/hour: {}{}",
                    preview.map_or(form.projected_requests_per_hour, |p| p
                        .projected_requests_per_hour),
                    if preview.map_or(form.projection_is_floor, |p| p.projection_is_floor) {
                        " (a floor: organization targets present)"
                    } else {
                        ""
                    }
                )),
                Line::from(format!(
                    "Maximum repository targets: about {}",
                    preview.map_or(form.maximum_repository_targets, |p| p
                        .maximum_repository_targets)
                )),
                Line::from("30-second floor; over-budget changes are refused."),
                focus_line(ui.focus == 3, "Save host settings [Enter/click]"),
                Line::from(format!(
                    "Focused form actions: {}/{}",
                    form.focused_action_count(),
                    MAX_FOCUSED_FORM_ACTIONS
                )),
            ]
        }
        SettingsView::Policy(form) => {
            let preview = form.preview(&ui.policy_draft);
            let mut lines = vec![
                Line::from(format!("Target: {}", form.target)),
                Line::from(format!("Mode: {:?}", form.mode)),
                Line::from(format!("Local host: {}", form.host_identity)),
                Line::from(format!(
                    "Current max_capacity: {}",
                    form.current_max_capacity
                        .map_or_else(|| "monitor-only".into(), |v| v.to_string())
                )),
                Line::from(format!(
                    "runs-on: {}  [click to copy]",
                    form.copyable_runs_on
                        .as_deref()
                        .unwrap_or("not reserved until promotion")
                )),
            ];
            let mut focus = 0;
            if form.exposes_scale_toggle() {
                lines.push(focus_line(
                    ui.focus == focus,
                    format!("Scaling enabled: {}  [toggle]", preview.to_enabled),
                ));
                focus += 1;
            }
            lines.push(focus_line(
                ui.focus == focus,
                format!(
                    "max_capacity: {}  [-/+; setting promotes monitor-only]",
                    preview
                        .to_capacity
                        .map_or_else(|| "unset".into(), |v| v.to_string())
                ),
            ));
            focus += 1;
            lines.push(focus_line(
                ui.focus == focus,
                format!("Cache policy: {:?}  [toggle]", preview.cache_policy),
            ));
            if let Some(warning) = preview.trust_warning {
                lines.push(Line::from(warning));
            } else if preview.drain_confirmation_required {
                lines.push(Line::from(format!(
                    "Disabling means draining {} active runner(s); none will be terminated.",
                    preview.active_runners
                )));
            } else {
                lines.push(Line::from("Preview: no runner is terminated immediately."));
            }
            lines.push(focus_line(
                ui.focus + 1 == ui.control_count(),
                "Confirm policy [Enter/click]",
            ));
            lines.push(Line::from(format!(
                "Focused form actions: {}/{}",
                form.focused_action_count(),
                MAX_FOCUSED_FORM_ACTIONS
            )));
            lines
        }
    };
    let mut lines = if compact {
        lines.into_iter().take(7).collect::<Vec<_>>()
    } else {
        lines
    };
    if let Some(message) = &ui.message {
        lines.push(Line::from(message.clone()));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title("Settings").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        area,
    );
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
        let text = (0..20)
            .map(|y| {
                (0..100)
                    .map(|x| terminal.backend().buffer()[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("error:"), "{text}");
    }
}
