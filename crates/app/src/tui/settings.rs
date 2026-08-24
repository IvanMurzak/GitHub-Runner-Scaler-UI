// owner: g3-tui-settings-parity

//! Editable TUI settings and the CLI-parity dispatch boundary.
//!
//! Forms are presentation data and never own a store. Host capacity and policy
//! capacity/scale changes are translated into the exact command values used by
//! the CLI, so validation and persistence cannot drift.

#![allow(
    dead_code,
    reason = "the shell integration constructs these forms when an editable screen is active"
)]

use std::io::Write;

use runner_manager_domain::attempt::active_count_for;
use runner_manager_domain::capacity::HostAllocator;
use runner_manager_domain::model::{
    CachePolicy, RefreshInterval, ScaleTarget, StartMode, TargetScope,
};
use runner_manager_domain::policy::{PolicyMode, ScalePolicy};
use runner_manager_domain::store::{Store, StoreError};
use runner_manager_platform::service::{ServiceError, ServiceOperations};

use crate::cli::{
    self, CliError, Context, Failure, HostSetCapacityArgs, OrgCommand, OrgSetCapacityArgs,
    OrgSetScaleArgs, RepoCommand, RepoSetCapacityArgs, RepoSetScaleArgs,
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
        let store = context.store()?;
        let mut host = cli::host::local_host_or_create(context, &store)?;
        host.refresh_interval = preview.interval;
        store.put_host(&host).map_err(store_failure)?;
        Ok(preview)
    }

    /// Switches the existing service registration in place, without reinstalling.
    pub fn set_start_mode(context: &Context, mode: StartMode) -> Result<(), CliError> {
        ServiceOperations::on_this_host(context.paths().clone())
            .set_start_mode(mode)
            .map_err(service_failure)?;
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
        drain_confirmed: bool,
        out: &mut dyn Write,
    ) -> Result<(), CliError> {
        if self.preview(draft).drain_confirmation_required && !drain_confirmed {
            return Err(CliError::new(
                Failure::Conflict,
                format!(
                    "disable cancelled; {} active runner(s) must be left to finish while the policy drains",
                    self.active_runners
                ),
            ));
        }
        if let Some(maximum) = draft.max_capacity {
            dispatch_capacity(context, &self.target, maximum, out)?;
        }
        if let Some(enabled) = draft.enabled {
            if !enabled && self.active_runners > 0 {
                apply_confirmed_disable(context, &self.target, out)?;
            } else {
                dispatch_scale(context, &self.target, enabled, out)?;
            }
        }
        if let Some(cache_policy) = draft.cache_policy {
            set_cache_policy(context, &self.target, cache_policy)?;
        }
        Ok(())
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

/// The TUI has already collected the second (drain) confirmation, so this is
/// the same domain transition as `f2` without asking stdin a third time.
fn apply_confirmed_disable(
    context: &Context,
    target: &ScaleTarget,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let store = context.store()?;
    let mut policy = find_policy(&store, target)?;
    let attempts = store
        .attempts_for_policy(policy.id)
        .map_err(store_failure)?;
    let active = active_count_for(policy.id, attempts.iter());
    let expected = policy.revision();
    if policy.enabled() {
        policy.request_disable().map_err(invalid)?;
        if active == 0 {
            policy.drain_completed(0).map_err(invalid)?;
        }
        store
            .update_policy(&policy, expected)
            .map_err(store_failure)?;
    }
    writeln!(out, "{} is {} with {active} active runner(s); busy runners were not terminated. Cache and historical diagnostics were preserved.", policy.target, if active == 0 { "disabled" } else { "draining" })
        .map_err(|source| CliError::new(Failure::Unclassified, format!("cannot write this scale result: {source}")))
}

fn set_cache_policy(
    context: &Context,
    target: &ScaleTarget,
    cache_policy: CachePolicy,
) -> Result<(), CliError> {
    let store = context.store()?;
    let policy = find_policy(&store, target)?;
    let expected = policy.revision();
    if policy.cache_policy != cache_policy {
        // CachePolicy has no mutator because it is self-validating, but the
        // optimistic-concurrency revision must still advance. Rebuilding via
        // the domain's checked persistence constructor preserves the complete
        // PolicyMode shape invariant while making that advancement explicit.
        let mut fields = policy.to_persisted();
        fields.cache_policy = cache_policy;
        fields.revision = fields.revision.saturating_add(1);
        let policy = ScalePolicy::from_persisted(fields).map_err(invalid)?;
        store
            .update_policy(&policy, expected)
            .map_err(store_failure)?;
    }
    Ok(())
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
    use std::num::NonZeroU16;

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
            false,
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
            false,
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
                false,
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
                false,
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
        form.apply(&context, &draft, false, &mut output).unwrap();
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
        form.apply(&context, &draft, false, &mut Vec::new())
            .unwrap();
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
            form.apply(&context, &draft, false, &mut Vec::new())
                .unwrap_err()
                .class(),
            Failure::Conflict
        );
        let mut output = Vec::new();
        form.apply(&context, &draft, true, &mut output).unwrap();
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
                false,
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
}
