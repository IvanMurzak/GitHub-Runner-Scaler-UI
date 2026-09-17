//! Named repository profile commands. Every mutation resolves one PolicyId.

use std::io::{self, Write};

use runner_manager_agent::lifecycle::{ExecutionProvider, MacOsVmProcesses, ProviderCapability};
use runner_manager_domain::execution::{Backend, ExecutionPolicy, ImageReference, ResourceLimits};
use runner_manager_domain::model::{HostLabel, ProfileName, ScaleTarget};
use runner_manager_domain::store::{Store, StoreError};
use runner_manager_domain::workspace::WorkspaceKind;
use runner_manager_platform::runner_root::RootOwner;

use super::policy::{self, LabelChange, PolicyMutation};
use super::{
    BackendMode, CliError, Context, ExecutionMode, Failure, IsolationArgs, RepoProfileCommand,
    RepoProfileSelectArgs, write_failed,
};

fn target(raw: &str) -> Result<ScaleTarget, CliError> {
    ScaleTarget::repository(raw)
        .map_err(|error| CliError::new(Failure::InvalidArgument, error.to_string()))
}

fn store_error(error: StoreError) -> CliError {
    CliError::new(
        if error.is_conflict() {
            Failure::Conflict
        } else {
            Failure::LocalState
        },
        error.to_string(),
    )
}

fn selected(args: &RepoProfileSelectArgs) -> Result<(ScaleTarget, Option<&str>), CliError> {
    Ok((target(&args.repository)?, args.profile.as_deref()))
}

fn execution(mode: ExecutionMode, args: &IsolationArgs) -> Result<ExecutionPolicy, CliError> {
    match mode {
        ExecutionMode::Native => {
            if args.backend.is_some()
                || args.image.is_some()
                || args.cpu.is_some()
                || args.memory.is_some()
                || args.disk.is_some()
            {
                return Err(CliError::new(
                    Failure::InvalidArgument,
                    "native execution does not take backend, image or resource flags",
                ));
            }
            Ok(ExecutionPolicy::Native)
        }
        ExecutionMode::Isolated => {
            let image = args.image.as_deref().ok_or_else(|| {
                CliError::with_remedy(
                    Failure::InvalidArgument,
                    "isolated execution needs a pinned image",
                    "--mode isolated --backend auto --image <PINNED-REFERENCE>",
                )
            })?;
            let image = ImageReference::new(image)
                .map_err(|error| CliError::new(Failure::InvalidArgument, error.to_string()))?;
            let backend = match args.backend.unwrap_or(BackendMode::Auto) {
                BackendMode::Auto => Backend::Auto,
                BackendMode::Oci => Backend::Oci,
                BackendMode::WindowsHyperVContainer => Backend::WindowsHyperVContainer,
                BackendMode::VirtualMachine => Backend::VirtualMachine,
            };
            let policy = ExecutionPolicy::Isolated {
                backend,
                image,
                resources: ResourceLimits {
                    cpu_millis: args.cpu.unwrap_or(1000),
                    memory_mib: args.memory.unwrap_or(1024),
                    disk_mib: args.disk.unwrap_or(4096),
                },
            };
            policy
                .validate(
                    runner_manager_domain::model::TargetScope::Repository,
                    &runner_manager_domain::workspace::WorkspacePolicy::Ephemeral,
                )
                .map_err(|error| CliError::new(Failure::InvalidArgument, error.to_string()))?;
            Ok(policy)
        }
    }
}

/// # Errors
/// Invalid profile fields, absent targets, or store/confirmation failures.
pub fn dispatch(
    context: &Context,
    command: &RepoProfileCommand,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    match command {
        RepoProfileCommand::Add(args) => {
            let target = target(&args.repository)?;
            let name = ProfileName::new(&args.name)
                .map_err(|error| CliError::new(Failure::InvalidArgument, error.to_string()))?;
            let execution = execution(args.execution, &args.isolation)?;
            let host_label = match args.host_label.as_deref() {
                Some(label) => HostLabel::new(label)
                    .map_err(|error| CliError::new(Failure::InvalidArgument, error.to_string()))?,
                None => {
                    let store = context.store()?;
                    let sibling = store
                        .policies()
                        .map_err(store_error)?
                        .into_iter()
                        .find(|policy| policy.target == target);
                    sibling.map_or_else(
                        || HostLabel::new("local").expect("valid default"),
                        |policy| policy.requested_host_label,
                    )
                }
            };
            policy::add_named(
                context,
                target,
                host_label.as_str(),
                args.max_capacity,
                &args.labels,
                args.enable,
                name,
                execution,
                out,
            )
        }
        RepoProfileCommand::List(args) => list(context, &target(&args.repository)?, out),
        RepoProfileCommand::Show(args) => {
            let (target, profile) = selected(args)?;
            show(context, &target, profile, out)
        }
        RepoProfileCommand::SetCapacity(args) => {
            let (target, profile) = selected(&args.selection)?;
            policy::apply_policy_mutation_selected(
                context,
                &target,
                profile,
                PolicyMutation {
                    max_capacity: Some(args.max_capacity),
                    ..PolicyMutation::default()
                },
                None,
                out,
            )
        }
        RepoProfileCommand::SetScale(args) => {
            let (target, profile) = selected(&args.selection)?;
            set_scale_selected(context, &target, profile, args.enabled, out)
        }
        RepoProfileCommand::AddLabel(args) | RepoProfileCommand::RemoveLabel(args) => {
            let (target, profile) = selected(&args.selection)?;
            let change = if matches!(command, RepoProfileCommand::AddLabel(_)) {
                LabelChange::Add
            } else {
                LabelChange::Remove
            };
            policy::mutate_labels_selected(context, &target, profile, &args.labels, change, out)
        }
        RepoProfileCommand::SetWorkspace(args) => {
            let (target, profile) = selected(&args.selection)?;
            let kind = WorkspaceKind::from(args.mode);
            let path = match args.path.as_deref() {
                Some(_) if kind == WorkspaceKind::Ephemeral => {
                    return Err(super::workspace::ephemeral_rejects_a_path(&target));
                }
                Some(raw) => Some(super::workspace::parse_root(
                    raw,
                    &RootOwner::Repository(target.slug()),
                )?),
                None => None,
            };
            let store = context.store()?;
            let change = super::workspace::set_repository_workspace_selected(
                context, &store, &target, profile, kind, path,
            )?;
            super::workspace::write_workspace_change(out, &change)
        }
        RepoProfileCommand::SetExecution(args) => {
            let (target, profile) = selected(&args.selection)?;
            let execution = execution(args.mode, &args.isolation)?;
            let store = context.store()?;
            let mut policy = policy::find_policy_selected(&store, &target, profile)?;
            let expected = policy.revision();
            let uncleaned = store
                .uncleaned_attempts_for_policy(policy.id)
                .map_err(store_error)?
                .len();
            if uncleaned != 0 {
                return Err(CliError::with_remedy(
                    Failure::Conflict,
                    format!(
                        "profile {} has {uncleaned} uncleaned attempt(s); execution was not changed",
                        policy.profile_name()
                    ),
                    "runner-manager status",
                ));
            }
            policy
                .set_execution_policy(execution)
                .map_err(|error| CliError::new(Failure::InvalidArgument, error.to_string()))?;
            if policy.enabled() && !policy.execution_policy().is_native() {
                let provider = MacOsVmProcesses::new(policy.host_id);
                let capability = provider.probe(&policy);
                if capability != ProviderCapability::Ready {
                    return Err(CliError::with_remedy(
                        Failure::Conflict,
                        format!(
                            "profile {} is enabled and the selected isolation provider is not ready; execution was not changed",
                            policy.profile_name()
                        ),
                        format!(
                            "{}; or disable the profile first with runner-manager repo profile set-scale {target} --profile {} --enabled false",
                            MacOsVmProcesses::policy_remedy(&policy, capability),
                            policy.profile_name()
                        ),
                    ));
                }
            }
            if policy.revision() != expected {
                store
                    .update_policy_confirming_uncleaned_count(&policy, expected, 0)
                    .map_err(store_error)?;
            }
            show_policy(&policy, out)
        }
        RepoProfileCommand::Remove(args) => {
            let (target, profile) = selected(&args.selection)?;
            policy::remove_selected(context, target, profile, args.purge, out)
        }
    }
}

pub fn set_scale_selected(
    context: &Context,
    target: &ScaleTarget,
    profile: Option<&str>,
    enabled: bool,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let observation = policy::observe_scale_selected(context, target, profile)?;
    let confirmation = if !enabled && observation.active > 0 {
        write!(
            out,
            "{} active runner(s) will finish while this profile drains. Continue? [y/N] ",
            observation.active
        )
        .map_err(write_failed("this profile confirmation"))?;
        out.flush()
            .map_err(write_failed("this profile confirmation"))?;
        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .map_err(|error| CliError::new(Failure::Unclassified, error.to_string()))?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            return Err(CliError::new(
                Failure::Conflict,
                "disable cancelled; the policy was not changed",
            ));
        }
        Some(observation)
    } else {
        None
    };
    policy::apply_policy_mutation_selected(
        context,
        target,
        profile,
        PolicyMutation {
            enabled: Some(enabled),
            ..PolicyMutation::default()
        },
        confirmation,
        out,
    )
}

fn list(context: &Context, target: &ScaleTarget, out: &mut dyn Write) -> Result<(), CliError> {
    let store = context.store()?;
    let policies = store.policies().map_err(store_error)?;
    let mut count = 0;
    for policy in policies.iter().filter(|policy| &policy.target == target) {
        count += 1;
        show_policy(policy, out)?;
    }
    if count == 0 {
        return Err(CliError::with_remedy(
            Failure::NotFound,
            format!("no profiles for {target}"),
            format!("runner-manager repo add {target}"),
        ));
    }
    Ok(())
}

fn show(
    context: &Context,
    target: &ScaleTarget,
    profile: Option<&str>,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let store = context.store()?;
    let policy = policy::find_policy_selected(&store, target, profile)?;
    show_policy(&policy, out)
}

fn show_policy(
    policy: &runner_manager_domain::policy::ScalePolicy,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let selector = policy
        .routing_labels()
        .map(|labels| labels.host_label().as_str());
    let labels = policy.routing_labels().map_or_else(
        || "-".to_string(),
        |labels| {
            labels
                .iter()
                .map(|label| label.as_str())
                .collect::<Vec<_>>()
                .join(",")
        },
    );
    let workspace_path = policy
        .workspace_policy()
        .root()
        .map_or("-", |root| root.as_str());
    writeln!(
        out,
        "{} profile={} host_label={} selector={} labels={} enabled={} state={} min={} max={} workspace={} workspace_path={} execution={}",
        policy.target,
        policy.profile_name(),
        policy.requested_host_label,
        selector.unwrap_or("monitor-only"),
        labels,
        policy.enabled(),
        policy.state(),
        policy.min_capacity(),
        policy
            .max_capacity()
            .map_or_else(|| "-".to_string(), |maximum| maximum.to_string()),
        policy.workspace_policy().kind(),
        workspace_path,
        if policy.execution_policy().is_native() {
            "native"
        } else {
            "isolated"
        }
    )
    .map_err(write_failed("this profile status"))?;
    if let Some(selector) = selector {
        writeln!(out, "Copy runs-on: {selector}\nwarning: automatic scaling needs this static selector; matrix runs-on expressions are not resolved.")
            .map_err(write_failed("this profile status"))?;
    }
    writeln!(
        out,
        "execution details: {}",
        serde_json::to_string(policy.execution_policy())
            .map_err(|error| CliError::new(Failure::LocalState, error.to_string()))?
    )
    .map_err(write_failed("this profile status"))?;
    Ok(())
}
