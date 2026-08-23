// owner: f2-cli-policy-commands

//! Repository and organization policy commands. Both families share one path.

use std::io::{self, BufRead, Write};
use std::num::NonZeroU16;

use runner_manager_domain::attempt::active_count_for;
use runner_manager_domain::model::{
    CachePolicy, Host, HostLabel, PolicyId, RefreshInterval, ScaleTarget, TargetScope,
};
use runner_manager_domain::policy::{PolicyMode, PolicyState, RoutingLabels, ScalePolicy};
use runner_manager_domain::store::{Store, StoreError};
use runner_manager_github::InstallationAccount;
use runner_manager_github::rest::{Admission, BudgetProjection, TargetCost};

use super::auth::CredentialState;
use super::{CliError, Context, Failure, OrgCommand, RepoCommand, write_failed};

const PERMISSION_DISCLOSURE: &str =
    "The GitHub App grant includes Administration: Read and write for self-hosted runners.";
const TRUST_WARNING: &str = "warning: fork and untrusted pull-request workflows must not run on a personal host until you explicitly accept that trust boundary.";

pub fn dispatch_repo(
    context: &Context,
    command: &RepoCommand,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    match command {
        RepoCommand::Add(a) => add(
            context,
            ScaleTarget::repository(&a.repository).map_err(invalid)?,
            &a.host_label,
            a.max_capacity,
            out,
        ),
        RepoCommand::List => list(context, TargetScope::Repository, out),
        RepoCommand::SetCapacity(a) => set_capacity(
            context,
            ScaleTarget::repository(&a.repository).map_err(invalid)?,
            a.max_capacity,
            out,
        ),
        RepoCommand::SetScale(a) => set_scale(
            context,
            ScaleTarget::repository(&a.repository).map_err(invalid)?,
            a.enabled,
            out,
        ),
        RepoCommand::Remove(a) => remove(
            context,
            ScaleTarget::repository(&a.repository).map_err(invalid)?,
            a.purge,
            out,
        ),
    }
}

pub fn dispatch_org(
    context: &Context,
    command: &OrgCommand,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    match command {
        OrgCommand::Add(a) => add(
            context,
            ScaleTarget::organization(&a.organization).map_err(invalid)?,
            &a.host_label,
            a.max_capacity,
            out,
        ),
        OrgCommand::List => list(context, TargetScope::Organization, out),
        OrgCommand::SetCapacity(a) => set_capacity(
            context,
            ScaleTarget::organization(&a.organization).map_err(invalid)?,
            a.max_capacity,
            out,
        ),
        OrgCommand::SetScale(a) => set_scale(
            context,
            ScaleTarget::organization(&a.organization).map_err(invalid)?,
            a.enabled,
            out,
        ),
        OrgCommand::Remove(a) => remove(
            context,
            ScaleTarget::organization(&a.organization).map_err(invalid)?,
            a.purge,
            out,
        ),
    }
}

fn add(
    context: &Context,
    target: ScaleTarget,
    raw_host_label: &str,
    max_capacity: Option<u16>,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let host_label = HostLabel::new(raw_host_label).map_err(invalid)?;
    let maximum = max_capacity.map(non_zero_capacity).transpose()?;
    let store = context.store()?;
    let secrets = context.secret_store(context.recorded_start_mode(&store)?)?;
    let discovery = match super::auth::credential_state(context, &secrets)? {
        CredentialState::Authenticated(discovery) => discovery,
        state => {
            return Err(CliError::with_remedy(
                state.failure().unwrap_or(Failure::NotAuthenticated),
                format!(
                    "cannot validate {target}: credential state is {}. No policy was stored.",
                    state.as_str()
                ),
                state.remedy(),
            ));
        }
    };
    let reachable = discovery.targets().ok_or_else(|| {
        CliError::with_remedy(
            Failure::NotFound,
            format!("the GitHub App is not installed for {target}. No policy was stored."),
            "runner-manager auth status",
        )
    })?;
    let (installation_id, installed_repositories) = installation_for(&target, reachable)?;

    let host = super::host::local_host_or_create(context, &store)?;
    let candidate = match target.scope() {
        TargetScope::Repository => TargetCost::repository(),
        TargetScope::Organization => TargetCost::organization(installed_repositories),
    };
    let costs = store
        .policies()
        .map_err(store_failure)?
        .iter()
        .map(|policy| cost_for(&policy.target, reachable))
        .collect();
    record_policy(
        &store,
        &host,
        target,
        host_label,
        maximum,
        installation_id,
        candidate,
        costs,
        out,
    )
}

#[allow(clippy::too_many_arguments)]
fn record_policy(
    store: &dyn Store,
    host: &Host,
    target: ScaleTarget,
    host_label: HostLabel,
    maximum: Option<NonZeroU16>,
    installation_id: u64,
    candidate: TargetCost,
    existing_costs: Vec<TargetCost>,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    record_policy_with_id(
        store,
        host,
        target,
        host_label,
        maximum,
        installation_id,
        candidate,
        existing_costs,
        PolicyId::new_random(),
        out,
    )
}

#[allow(clippy::too_many_arguments)]
fn record_policy_with_id(
    store: &dyn Store,
    host: &Host,
    target: ScaleTarget,
    host_label: HostLabel,
    maximum: Option<NonZeroU16>,
    installation_id: u64,
    candidate: TargetCost,
    existing_costs: Vec<TargetCost>,
    policy_id: PolicyId,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    if store
        .policies()
        .map_err(store_failure)?
        .iter()
        .any(|policy| policy.target == target)
    {
        return Err(CliError::with_remedy(
            Failure::Conflict,
            format!("a policy for {target} already exists. Nothing was changed."),
            format!("runner-manager {} list", scope_word(target.scope())),
        ));
    }
    let projection = BudgetProjection::new(RefreshInterval::default(), existing_costs);
    if let refusal @ Admission::Refused { .. } = projection.admit(candidate) {
        return Err(CliError::with_remedy(
            Failure::BudgetRefused,
            format!("{refusal}. No policy was stored."),
            "runner-manager host show",
        ));
    }
    let mode = match maximum {
        Some(maximum) => PolicyMode::autoscale(
            RoutingLabels::derive(&host_label, host.os, host.architecture),
            0,
            maximum,
        )
        .map_err(invalid)?,
        None => PolicyMode::monitor_only(),
    };
    if let Some(labels) = mode.routing_labels()
        && store
            .policies()
            .map_err(store_failure)?
            .iter()
            .any(|existing| {
                existing.host_id != host.id
                    && existing
                        .routing_labels()
                        .is_some_and(|other| other.host_label() == labels.host_label())
            })
    {
        let failed = write_failed("this routing warning");
        writeln!(out, "warning: routing label {} is already recorded for another host. Both hosts may start for the same queued job; the surplus runner exits after wasting a slot.", labels.host_label()).map_err(failed)?;
    }
    let policy = ScalePolicy::new_for_host_label(
        policy_id,
        target,
        installation_id,
        host.id,
        host_label,
        mode,
        CachePolicy::default(),
    );
    store.insert_policy(&policy).map_err(store_failure)?;
    write_add_result(out, &policy, host)
}

fn installation_for(
    target: &ScaleTarget,
    reachable: &runner_manager_github::ReachableTargets,
) -> Result<(u64, u32), CliError> {
    reachable.installations().iter().find(|installation| match target {
        ScaleTarget::Repository(repository) => installation.repositories.contains(repository),
        ScaleTarget::Organization(org) => matches!(&installation.account, InstallationAccount::Organization(installed) if installed == org),
    }).map(|installation| (installation.id, u32::try_from(installation.repositories.len()).unwrap_or(u32::MAX))).ok_or_else(|| CliError::with_remedy(
        Failure::NotFound,
        format!("the GitHub App is not installed for {target}. No policy was stored."),
        "runner-manager auth status",
    ))
}

fn write_add_result(
    out: &mut dyn Write,
    policy: &ScalePolicy,
    host: &Host,
) -> Result<(), CliError> {
    let failed = write_failed("this policy result");
    writeln!(
        out,
        "Added {} policy for {} in pending; scaling is disabled.",
        scope_word(policy.target.scope()),
        policy.target
    )
    .map_err(failed)?;
    match policy.routing_labels() {
        Some(labels) => {
            writeln!(out, "Routing label: {}", labels.host_label()).map_err(failed)?;
            writeln!(
                out,
                "Next: runner-manager {} set-scale {} --enabled true",
                scope_word(policy.target.scope()),
                policy.target
            )
            .map_err(failed)?;
        }
        None => {
            writeln!(out, "Monitor-only: no routing label is reserved and no runner will ever be started for this policy.").map_err(failed)?;
            writeln!(out, "{PERMISSION_DISCLOSURE}").map_err(failed)?;
            writeln!(
                out,
                "Promote it with: runner-manager {} set-capacity {} --max-capacity N",
                scope_word(policy.target.scope()),
                policy.target
            )
            .map_err(failed)?;
        }
    }
    if host.architecture.to_string() == "arm64" {
        writeln!(out, "warning: ARM64 runner support is public preview.").map_err(failed)?;
    }
    if host.os.to_string() != "linux" {
        writeln!(
            out,
            "warning: container actions and service containers require a Linux host."
        )
        .map_err(failed)?;
    }
    if policy.target.scope() == TargetScope::Organization {
        writeln!(out, "Organization scope uses the narrower Organization -> Self-hosted runners grant and is the safer choice where both scopes work.").map_err(failed)?;
    }
    Ok(())
}

fn list(context: &Context, scope: TargetScope, out: &mut dyn Write) -> Result<(), CliError> {
    let failed = write_failed("this policy list");
    let store = context.store()?;
    let mut count = 0;
    for policy in store.policies().map_err(store_failure)? {
        if policy.target.scope() != scope {
            continue;
        }
        count += 1;
        let mode = if policy.routing_labels().is_some() {
            "autoscale"
        } else {
            "monitor_only"
        };
        let maximum = policy
            .max_capacity()
            .map_or("-".to_string(), |n| n.to_string());
        writeln!(
            out,
            "{}\t{}\t{}\tenabled={}\tmax={}",
            policy.target,
            mode,
            policy.state(),
            policy.enabled(),
            maximum
        )
        .map_err(failed)?;
        if policy.state() == PolicyState::RepairRequired {
            writeln!(
                out,
                "repair: runner-manager {} remove {} --purge",
                scope_word(policy.target.scope()),
                policy.target
            )
            .map_err(failed)?;
        }
    }
    if count == 0 {
        writeln!(out, "No {} policies.", scope_word(scope)).map_err(failed)?;
    }
    Ok(())
}

fn set_capacity(
    context: &Context,
    target: ScaleTarget,
    raw_maximum: u16,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let maximum = non_zero_capacity(raw_maximum)?;
    let store = context.store()?;
    let mut policy = find_policy(&store, &target)?;
    let expected = policy.revision();
    if policy.routing_labels().is_none() {
        let host = store
            .host(policy.host_id)
            .map_err(store_failure)?
            .ok_or_else(|| {
                CliError::new(
                    Failure::LocalState,
                    format!("policy {target} refers to a missing local host"),
                )
            })?;
        policy
            .promote_to_autoscale(
                RoutingLabels::derive(&policy.requested_host_label, host.os, host.architecture),
                0,
                maximum,
            )
            .map_err(invalid)?;
    } else {
        policy.set_max_capacity(maximum).map_err(invalid)?;
    }
    store
        .update_policy(&policy, expected)
        .map_err(store_failure)?;
    let failed = write_failed("this capacity result");
    writeln!(
        out,
        "{} max capacity is now {maximum}; scaling remains {}.",
        target,
        if policy.enabled() {
            "enabled"
        } else {
            "disabled"
        }
    )
    .map_err(failed)?;
    if let Some(labels) = policy.routing_labels() {
        writeln!(out, "Routing label: {}", labels.host_label()).map_err(failed)?;
    }
    Ok(())
}

fn set_scale(
    context: &Context,
    target: ScaleTarget,
    enabled: bool,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let store = context.store()?;
    let policy = find_policy(&store, &target)?;
    let attempts = store
        .attempts_for_policy(policy.id)
        .map_err(store_failure)?;
    let active = active_count_for(policy.id, attempts.iter());
    if !enabled && active > 0 {
        let stdin = io::stdin();
        if !confirm_disable(active, out, &mut stdin.lock())? {
            return Err(CliError::new(
                Failure::Conflict,
                "disable cancelled; the policy was not changed",
            ));
        }
    }
    apply_scale(&store, policy, enabled, active, out)
}

fn confirm_disable(
    active: u16,
    out: &mut dyn Write,
    input: &mut dyn BufRead,
) -> Result<bool, CliError> {
    let failed = write_failed("this confirmation prompt");
    write!(
        out,
        "{active} active runner(s) will be left to finish while the policy drains. Continue? [y/N] "
    )
    .map_err(failed)?;
    out.flush().map_err(failed)?;
    let mut answer = String::new();
    input.read_line(&mut answer).map_err(|source| {
        CliError::new(
            Failure::Unclassified,
            format!("cannot read confirmation: {source}"),
        )
    })?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn apply_scale(
    store: &dyn Store,
    mut policy: ScalePolicy,
    enabled: bool,
    active: u16,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let expected = policy.revision();
    if enabled {
        if policy.routing_labels().is_none() {
            return Err(CliError::with_remedy(
                Failure::InvalidArgument,
                "monitor-only policies cannot be enabled; no routing label or capacity is reserved",
                format!(
                    "runner-manager {} set-capacity {} --max-capacity N",
                    scope_word(policy.target.scope()),
                    policy.target
                ),
            ));
        }
        if !policy.enabled() {
            if policy.state() == PolicyState::Disabled {
                policy
                    .transition_to(PolicyState::Pending)
                    .map_err(invalid)?;
            }
            policy.activate().map_err(invalid)?;
            store
                .update_policy(&policy, expected)
                .map_err(store_failure)?;
        }
        let failed = write_failed("this scale result");
        writeln!(out, "Scaling enabled for {}.", policy.target).map_err(failed)?;
        writeln!(out, "{TRUST_WARNING}").map_err(failed)?;
    } else {
        if policy.enabled() {
            policy.request_disable().map_err(invalid)?;
            if active == 0 {
                policy.drain_completed(0).map_err(invalid)?;
            }
            store
                .update_policy(&policy, expected)
                .map_err(store_failure)?;
        }
        let failed = write_failed("this scale result");
        writeln!(out, "{} is {} with {active} active runner(s); busy runners were not terminated. Cache and historical diagnostics were preserved.", policy.target, if active == 0 { "disabled" } else { "draining" }).map_err(failed)?;
    }
    Ok(())
}

fn remove(
    context: &Context,
    target: ScaleTarget,
    purge: bool,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let store = context.store()?;
    let policy = find_policy(&store, &target)?;
    let attempts = store
        .attempts_for_policy(policy.id)
        .map_err(store_failure)?;
    let active = active_count_for(policy.id, attempts.iter());
    if purge && active > 0 {
        return Err(CliError::with_remedy(
            Failure::Conflict,
            format!(
                "cannot purge {target} while {active} active runner(s) exist; no policy, cache, or diagnostics were removed"
            ),
            format!(
                "runner-manager {} set-scale {} --enabled false",
                scope_word(target.scope()),
                target
            ),
        ));
    }
    store
        .remove_policy(policy.id, policy.revision())
        .map_err(store_failure)?;
    if purge {
        for attempt in attempts {
            store.remove_attempt(attempt.id).map_err(store_failure)?;
        }
    }
    let mut cache_purged = false;
    if purge && store.policies().map_err(store_failure)?.is_empty() {
        let cache = context.paths().state_dir().join("packages");
        if cache.exists() {
            std::fs::remove_dir_all(&cache).map_err(|source| CliError::new(Failure::LocalState, format!("the policy was removed, but its shared package cache at {} could not be purged: {source}", cache.display())))?;
        }
        cache_purged = true;
    }
    let failed = write_failed("this removal result");
    if purge {
        writeln!(out, "Removed {target} and purged its historical diagnostics. Shared runner package cache {}.", if cache_purged { "purged because no policy still uses it" } else { "preserved because another policy still uses it" }).map_err(failed)?;
    } else {
        writeln!(
            out,
            "Removed {target}; cache and historical diagnostics were preserved."
        )
        .map_err(failed)?;
    }
    Ok(())
}

fn find_policy(store: &dyn Store, target: &ScaleTarget) -> Result<ScalePolicy, CliError> {
    store
        .policies()
        .map_err(store_failure)?
        .into_iter()
        .find(|policy| &policy.target == target)
        .ok_or_else(|| {
            CliError::with_remedy(
                Failure::NotFound,
                format!("no policy for {target} exists"),
                format!("runner-manager {} list", scope_word(target.scope())),
            )
        })
}

fn cost_for(
    target: &ScaleTarget,
    reachable: &runner_manager_github::ReachableTargets,
) -> TargetCost {
    match target {
        ScaleTarget::Repository(_) => TargetCost::repository(),
        ScaleTarget::Organization(org) => {
            let count = reachable
                .installations()
                .iter()
                .find_map(|installation| match &installation.account {
                    InstallationAccount::Organization(installed) if installed == org => {
                        Some(installation.repositories.len())
                    }
                    _ => None,
                })
                .unwrap_or(0);
            TargetCost::organization(u32::try_from(count).unwrap_or(u32::MAX))
        }
    }
}

fn non_zero_capacity(value: u16) -> Result<NonZeroU16, CliError> {
    NonZeroU16::new(value).ok_or_else(|| {
        CliError::new(
            Failure::InvalidArgument,
            "max capacity must be at least 1; nothing was changed",
        )
    })
}
fn scope_word(scope: TargetScope) -> &'static str {
    match scope {
        TargetScope::Repository => "repo",
        TargetScope::Organization => "org",
    }
}
fn invalid(source: impl std::fmt::Display) -> CliError {
    CliError::new(Failure::InvalidArgument, source.to_string())
}
fn store_failure(source: StoreError) -> CliError {
    if source.is_conflict() {
        CliError::with_remedy(
            Failure::Conflict,
            source.to_string(),
            "re-read with runner-manager status, then retry",
        )
    } else {
        CliError::new(Failure::LocalState, source.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runner_manager_domain::model::{Arch, HostId, Org, Os, OwnerRepo};
    use runner_manager_domain::store::SqliteStore;

    fn nz(value: u16) -> NonZeroU16 {
        NonZeroU16::new(value).unwrap()
    }

    fn host(label: &str) -> Host {
        Host::new(
            HostId::new_random(),
            label,
            Os::Linux,
            Arch::X64,
            nz(4),
            chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        )
        .unwrap()
    }

    fn targets() -> [ScaleTarget; 2] {
        [
            ScaleTarget::Repository(OwnerRepo::parse("octo/repo").unwrap()),
            ScaleTarget::Organization(Org::new("octo-org").unwrap()),
        ]
    }

    /// One body proves D18 target equivalence. `record_policy` has no gateway
    /// argument, which also makes a state-changing GitHub request impossible on
    /// the local write path.
    #[test]
    fn repository_and_organization_add_share_pending_non_arming_behavior() {
        for target in targets() {
            let store = SqliteStore::open_in_memory().unwrap();
            let local = host("machine");
            let mut output = Vec::new();
            record_policy(
                &store,
                &local,
                target.clone(),
                HostLabel::new("home").unwrap(),
                Some(nz(2)),
                77,
                match target.scope() {
                    TargetScope::Repository => TargetCost::repository(),
                    TargetScope::Organization => TargetCost::organization(1),
                },
                Vec::new(),
                &mut output,
            )
            .unwrap();

            let policies = store.policies().unwrap();
            assert_eq!(policies.len(), 1);
            assert_eq!(policies[0].target, target);
            assert_eq!(policies[0].state(), PolicyState::Pending);
            assert!(!policies[0].enabled());
            assert!(!policies[0].may_start_runners());
            assert_eq!(
                policies[0].routing_labels().unwrap().host_label().as_str(),
                "rm-home-linux-x64"
            );
            let text = String::from_utf8(output).unwrap();
            assert!(text.contains("pending; scaling is disabled"), "{text}");
            assert!(text.contains("Routing label: rm-home-linux-x64"), "{text}");
        }
    }

    #[test]
    fn host_identity_changes_the_printed_routing_label() {
        let labels: Vec<String> = ["home", "office"]
            .into_iter()
            .map(|label| {
                RoutingLabels::derive(&HostLabel::new(label).unwrap(), Os::Linux, Arch::X64)
                    .host_label()
                    .to_string()
            })
            .collect();
        assert_eq!(labels, ["rm-home-linux-x64", "rm-office-linux-x64"]);
        assert_ne!(labels[0], labels[1]);
    }

    #[test]
    fn monitor_only_reserves_nothing_and_promotes_with_the_recorded_host_identity() {
        let store = SqliteStore::open_in_memory().unwrap();
        let local = host("machine");
        store.put_host(&local).unwrap();
        let target = targets()[0].clone();
        let mut output = Vec::new();
        record_policy(
            &store,
            &local,
            target,
            HostLabel::new("home").unwrap(),
            None,
            77,
            TargetCost::repository(),
            Vec::new(),
            &mut output,
        )
        .unwrap();
        let mut policy = store.policies().unwrap().remove(0);
        assert_eq!(policy.mode(), &PolicyMode::MonitorOnly);
        assert!(policy.routing_labels().is_none());
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("no runner will ever be started"), "{text}");
        assert!(text.contains("Administration: Read and write"), "{text}");

        let persisted_host = store.host(policy.host_id).unwrap().unwrap();
        policy
            .promote_to_autoscale(
                RoutingLabels::derive(
                    &policy.requested_host_label,
                    persisted_host.os,
                    persisted_host.architecture,
                ),
                0,
                nz(3),
            )
            .unwrap();
        assert_eq!(
            policy.routing_labels().unwrap().host_label().as_str(),
            "rm-home-linux-x64"
        );
        assert!(!policy.enabled());
        assert_eq!(policy.state(), PolicyState::Pending);
    }

    #[test]
    fn monitor_policy_keeps_its_own_label_when_another_policy_is_added_before_promotion() {
        let store = SqliteStore::open_in_memory().unwrap();
        let local = host("machine");
        store.put_host(&local).unwrap();
        for (target, label) in targets().into_iter().zip(["home", "office"]) {
            record_policy(
                &store,
                &local,
                target,
                HostLabel::new(label).unwrap(),
                None,
                77,
                TargetCost::repository(),
                Vec::new(),
                &mut Vec::new(),
            )
            .unwrap();
        }

        let mut policies = store.policies().unwrap();
        let mut first = policies
            .drain(..)
            .find(|policy| policy.target == targets()[0])
            .unwrap();
        first
            .promote_to_autoscale(
                RoutingLabels::derive(&first.requested_host_label, local.os, local.architecture),
                0,
                nz(2),
            )
            .unwrap();
        assert_eq!(
            first.routing_labels().unwrap().host_label().as_str(),
            "rm-home-linux-x64"
        );
    }

    #[test]
    fn failed_policy_insert_cannot_mutate_the_committed_host() {
        let store = SqliteStore::open_in_memory().unwrap();
        let local = host("machine");
        store.put_host(&local).unwrap();
        let duplicate_id = PolicyId::new_random();
        let existing = ScalePolicy::new_for_host_label(
            duplicate_id,
            targets()[0].clone(),
            77,
            local.id,
            HostLabel::new("home").unwrap(),
            PolicyMode::monitor_only(),
            CachePolicy::default(),
        );
        store.insert_policy(&existing).unwrap();

        let error = record_policy_with_id(
            &store,
            &local,
            targets()[1].clone(),
            HostLabel::new("office").unwrap(),
            None,
            78,
            TargetCost::organization(1),
            vec![TargetCost::repository()],
            duplicate_id,
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(error.class(), Failure::LocalState);
        assert_eq!(
            store.host(local.id).unwrap().unwrap().display_name,
            "machine"
        );
        let policies = store.policies().unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].requested_host_label.as_str(), "home");
    }

    #[test]
    fn refusal_prints_the_ceiling_admission_actually_used() {
        let interval = RefreshInterval::default();
        let candidate = TargetCost::repository();
        let maximum = BudgetProjection::max_repository_targets(interval, candidate);
        let projection = BudgetProjection::new(interval, vec![candidate; maximum as usize]);
        let refusal = projection.admit(candidate);
        let Admission::Refused {
            max_repository_targets,
            ..
        } = refusal.clone()
        else {
            panic!("the next target must be refused")
        };
        assert_eq!(max_repository_targets, maximum);
        assert!(
            refusal
                .to_string()
                .contains(&format!("about {maximum} repository"))
        );
    }

    #[test]
    fn repository_and_large_organization_budget_refusals_store_nothing_and_show_their_inputs() {
        for (target, candidate, existing, expected) in [
            (
                targets()[0].clone(),
                TargetCost::repository(),
                vec![TargetCost::repository(); 10],
                "about 10 repository",
            ),
            (
                targets()[1].clone(),
                TargetCost::organization(14),
                Vec::new(),
                "installed on 14 of its repositories",
            ),
        ] {
            let store = SqliteStore::open_in_memory().unwrap();
            let local = host("machine");
            let error = record_policy(
                &store,
                &local,
                target,
                HostLabel::new("home").unwrap(),
                Some(nz(2)),
                77,
                candidate,
                existing,
                &mut Vec::new(),
            )
            .unwrap_err();
            assert_eq!(error.class(), Failure::BudgetRefused);
            assert!(error.message().contains(expected), "{error}");
            assert!(error.message().contains("2500"), "{error}");
            assert!(store.policies().unwrap().is_empty());
        }
    }

    #[test]
    fn duplicate_and_zero_capacity_fail_before_an_active_policy_can_exist() {
        assert_eq!(
            non_zero_capacity(0).unwrap_err().class(),
            Failure::InvalidArgument
        );
        let store = SqliteStore::open_in_memory().unwrap();
        let local = host("machine");
        let target = targets()[0].clone();
        for attempt in 0..2 {
            let result = record_policy(
                &store,
                &local,
                target.clone(),
                HostLabel::new("home").unwrap(),
                Some(nz(2)),
                77,
                TargetCost::repository(),
                Vec::new(),
                &mut Vec::new(),
            );
            if attempt == 0 {
                result.unwrap();
            } else {
                assert_eq!(result.unwrap_err().class(), Failure::Conflict);
            }
        }
        let policies = store.policies().unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].state(), PolicyState::Pending);
        assert!(!policies[0].enabled());
    }

    #[test]
    fn disabling_with_work_in_flight_drains_without_terminating_it() {
        let store = SqliteStore::open_in_memory().unwrap();
        let local = host("home");
        store.put_host(&local).unwrap();
        let mut policy = ScalePolicy::new(
            PolicyId::new_random(),
            targets()[0].clone(),
            77,
            local.id,
            PolicyMode::autoscale(
                RoutingLabels::derive(
                    &HostLabel::new("home").unwrap(),
                    local.os,
                    local.architecture,
                ),
                0,
                nz(2),
            )
            .unwrap(),
            CachePolicy::default(),
        );
        policy.activate().unwrap();
        store.insert_policy(&policy).unwrap();
        let mut output = Vec::new();
        apply_scale(&store, policy, false, 2, &mut output).unwrap();
        let stored = store.policies().unwrap().remove(0);
        assert_eq!(stored.state(), PolicyState::Draining);
        assert!(!stored.enabled());
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("draining with 2 active runner(s)"), "{text}");
        assert!(text.contains("busy runners were not terminated"), "{text}");
    }

    #[test]
    fn active_runner_confirmation_defaults_to_no_and_names_the_count() {
        let mut output = Vec::new();
        assert!(!confirm_disable(3, &mut output, &mut io::Cursor::new(b"\n")).unwrap());
        let prompt = String::from_utf8(output).unwrap();
        assert!(prompt.contains("3 active runner(s)"), "{prompt}");
        assert!(prompt.contains("left to finish"), "{prompt}");
        assert!(confirm_disable(3, &mut Vec::new(), &mut io::Cursor::new(b"yes\n")).unwrap());
    }
}
