// owner: f2-cli-policy-commands

//! Repository and organization policy commands. Both families share one path.

use std::io::{self, BufRead, Write};
use std::num::NonZeroU16;

use runner_manager_domain::attempt::active_count_for;
use runner_manager_domain::model::{
    CachePolicy, Host, HostLabel, Label, PolicyId, RefreshInterval, ScaleTarget, TargetScope,
};
use runner_manager_domain::policy::{PolicyMode, PolicyState, RoutingLabels, ScalePolicy};
use runner_manager_domain::store::{Store, StoreError};
use runner_manager_domain::workspace::WorkspaceKind;
use runner_manager_github::InstallationAccount;
use runner_manager_github::rest::{Admission, BudgetProjection, TargetCost};
use runner_manager_platform::runner_root::RootOwner;

use super::auth::CredentialState;
use super::workspace;
use super::{
    CliError, Context, Failure, OrgCommand, RepoCommand, RepoSetWorkspaceArgs, write_failed,
};

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
            &a.labels,
            a.enable,
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
        RepoCommand::AddLabel(a) => mutate_labels(
            context,
            &ScaleTarget::repository(&a.repository).map_err(invalid)?,
            &a.labels,
            LabelChange::Add,
            out,
        ),
        RepoCommand::RemoveLabel(a) => mutate_labels(
            context,
            &ScaleTarget::repository(&a.repository).map_err(invalid)?,
            &a.labels,
            LabelChange::Remove,
            out,
        ),
        RepoCommand::SetWorkspace(a) => set_workspace(context, a, out),
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
            &a.labels,
            a.enable,
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
        OrgCommand::AddLabel(a) => mutate_labels(
            context,
            &ScaleTarget::organization(&a.organization).map_err(invalid)?,
            &a.labels,
            LabelChange::Add,
            out,
        ),
        OrgCommand::RemoveLabel(a) => mutate_labels(
            context,
            &ScaleTarget::organization(&a.organization).map_err(invalid)?,
            &a.labels,
            LabelChange::Remove,
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

// ---------------------------------------------------------------------------
// repo set-workspace
// ---------------------------------------------------------------------------

/// `repo set-workspace OWNER/REPO --mode ephemeral|persistent [--path PATH]`.
///
/// # The two `--path` refusals, and why they are different classes
///
/// `--mode persistent` without `--path` is `required_if_eq` and never reaches
/// here: clap refuses it with exit 2, which
/// [`the taxonomy`](super::Failure) reserves for usage errors. `--mode
/// ephemeral` **with** `--path` is a rule clap has no spelling for, so it is
/// refused here as [`Failure::InvalidArgument`] — literally "an argument that
/// was well-formed for clap and wrong for the domain". Silently ignoring the
/// path is the one option `02-target-architecture.md` rules out: "`ephemeral`
/// rejects `--path` so an ignored argument cannot mislead".
fn set_workspace(
    context: &Context,
    args: &RepoSetWorkspaceArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let target = ScaleTarget::repository(&args.repository).map_err(invalid)?;
    let kind = WorkspaceKind::from(args.mode);
    let owner = RootOwner::Repository(target.slug());
    let path = match (kind, args.path.as_deref()) {
        (WorkspaceKind::Ephemeral, Some(_)) => {
            return Err(workspace::ephemeral_rejects_a_path(&target));
        }
        (WorkspaceKind::Ephemeral, None) => None,
        (WorkspaceKind::Persistent, Some(raw)) => Some(workspace::parse_root(raw, &owner)?),
        // clap's `required_if_eq` covers this; `e1` reaches the same refusal
        // through `workspace::set_repository_workspace`.
        (WorkspaceKind::Persistent, None) => None,
    };

    let store = context.store()?;
    let change = workspace::set_repository_workspace(context, &store, &target, kind, path)?;
    workspace::write_workspace_change(out, &change)
}

fn add(
    context: &Context,
    target: ScaleTarget,
    raw_host_label: &str,
    max_capacity: Option<u16>,
    raw_labels: &[String],
    enable: bool,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let host_label = HostLabel::new(raw_host_label).map_err(invalid)?;
    let extra = parse_labels(raw_labels)?;
    let maximum = max_capacity.map(non_zero_capacity).transpose()?;
    // Refused rather than silently dropped: a monitor-only policy has no
    // routing labels at all, so `--label` on one asks for something the stored
    // shape cannot hold, and accepting it would report success for a setting
    // that never existed.
    if maximum.is_none() && !extra.is_empty() {
        return Err(CliError::with_remedy(
            Failure::InvalidArgument,
            "--label needs a policy that starts runners, and a monitor-only policy never \n             does. No policy was stored.",
            format!(
                "runner-manager {} add {target} --host-label {raw_host_label} --max-capacity N --label ...",
                scope_word(target.scope())
            ),
        ));
    }
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
    let reachable = match discovery.targets() {
        Some(reachable) => reachable,
        None => {
            // ----------------------------------------------------------------
            // AUTHORIZED IS NOT INSTALLED, AND THIS IS WHERE THAT BITES.
            // ----------------------------------------------------------------
            // `auth login` proves who the operator is. Installing the App is
            // what grants it access to a repository, and they are two separate
            // consents on GitHub's side — which is why `auth login` counts the
            // install as its third action. Somebody who signed in and went
            // straight to `repo add` has done the first and not the second.
            //
            // The page that fixes it is opened here rather than only named,
            // because this failure has exactly one remedy and it is a URL. The
            // launcher is skipped when stderr is not a terminal, so a script
            // gets the message and no browser.
            let install_url = discovery.install_url().map_or_else(
                || "your GitHub App's installations page".to_string(),
                ToString::to_string,
            );
            let opened = super::open_in_browser(&install_url, super::Styling::for_stderr());
            let how = if opened {
                format!("Its installation page is open in your browser ({install_url})")
            } else {
                format!("Install it at {install_url}")
            };
            return Err(CliError::with_remedy(
                Failure::NotFound,
                format!(
                    "the GitHub App is not installed for {target}, so this host cannot register \
                     a runner there. Signing in authorized the App; installing it is the \
                     separate step that grants access. {how} — choose {target}, then run this \
                     command again. No policy was stored."
                ),
                "runner-manager auth status",
            ));
        }
    };
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
    let armed = target.clone();
    record_policy(
        &store,
        &host,
        target,
        host_label,
        extra,
        maximum,
        installation_id,
        candidate,
        costs,
        out,
    )?;
    // Arming is still a separate decision; `--enable` is the operator making it
    // here rather than in a second command. It runs *after* the policy exists,
    // through the same path `set-scale` uses, so the state machine and the
    // trust warning are the ones that already govern arming rather than a
    // second, quieter copy of them.
    if enable {
        set_scale(context, armed, true, out)?;
    }
    Ok(())
}

/// Whether a label mutation adds or removes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LabelChange {
    Add,
    Remove,
}

/// Parse operator-supplied label strings through `b1`'s own validation.
///
/// The CLI does not re-implement what a label may contain: `Label::new` owns
/// that, so a rule added there reaches this command without an edit here.
fn parse_labels(raw: &[String]) -> Result<Vec<Label>, CliError> {
    raw.iter()
        .map(|label| Label::new(label).map_err(invalid))
        .collect()
}

/// Add or remove routing labels on an existing policy.
///
/// # Why the host label cannot be removed here
///
/// `b1` refuses it ([`runner_manager_domain::policy::ScalePolicy::remove_routing_label`]),
/// and this command surfaces that refusal rather than pre-empting it. The
/// reason is the one `RoutingLabels` documents: with no `AcquireJobs`, the host
/// identity baked into the derived label is the only thing that stops two hosts
/// racing for the same queued job by default.
fn mutate_labels(
    context: &Context,
    target: &ScaleTarget,
    raw_labels: &[String],
    change: LabelChange,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let labels = parse_labels(raw_labels)?;
    let store = context.store()?;
    let mut policy = find_policy(&store, target)?;
    let expected = policy.revision();

    if policy.routing_labels().is_none() {
        return Err(CliError::with_remedy(
            Failure::InvalidArgument,
            format!(
                "{target} is monitor-only, so it has no routing labels to change. Nothing was changed."
            ),
            format!(
                "runner-manager {} set-capacity {target} --max-capacity N",
                scope_word(target.scope())
            ),
        ));
    }

    let mut changed = Vec::new();
    for label in labels {
        let moved = match change {
            LabelChange::Add => policy.add_routing_label(label.clone()).map_err(invalid)?,
            LabelChange::Remove => policy.remove_routing_label(&label).map_err(invalid)?,
        };
        if moved {
            changed.push(label);
        }
    }

    if policy.revision() != expected {
        store
            .update_policy(&policy, expected)
            .map_err(store_failure)?;
    }

    let failed = write_failed("this label result");
    let verb = match change {
        LabelChange::Add => "now answers",
        LabelChange::Remove => "no longer answers",
    };
    if changed.is_empty() {
        writeln!(out, "No label changed; {target} already had them that way.").map_err(failed)?;
    } else {
        let list: Vec<&str> = changed.iter().map(Label::as_str).collect();
        writeln!(out, "{target} {verb}: {}", list.join(", ")).map_err(failed)?;
    }
    if let Some(current) = policy.routing_labels() {
        let all: Vec<&str> = current.iter().map(Label::as_str).collect();
        writeln!(out, "Routing labels: {}", all.join(", ")).map_err(failed)?;
        if current.additional().next().is_some() {
            writeln!(
                out,
                "warning: a label another runner also answers is a race this product cannot \
                 arbitrate. Whichever runner GitHub assigns first takes the job; the loser \
                 pays a capacity slot and a cold start before it exits."
            )
            .map_err(failed)?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn record_policy(
    store: &dyn Store,
    host: &Host,
    target: ScaleTarget,
    host_label: HostLabel,
    extra: Vec<Label>,
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
        extra,
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
    extra: Vec<Label>,
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
        Some(maximum) => {
            let mut labels = RoutingLabels::derive(&host_label, host.os, host.architecture);
            for label in extra {
                labels.add(label);
            }
            PolicyMode::autoscale(labels, 0, maximum).map_err(invalid)?
        }
        // A monitor-only policy starts no runner, so it has no label set to
        // put these in; `PolicyMode::monitor_only` has no field for them. They
        // are refused at parse time rather than dropped here -- see `add`.
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
    if let Err(initial_failure) = store.insert_policy(&policy) {
        // A failed write can be ambiguous: the database may have committed the
        // row before reporting an I/O failure. Re-read by the generated id
        // before deciding whether repair is an insert or an update. Trying a
        // second insert unconditionally leaves an ambiguously committed row in
        // `pending`, because the second insert correctly reports AlreadyExists.
        let persisted = store.policy(policy.id).map_err(store_failure)?;
        let was_persisted = persisted.is_some();
        let mut repair = match persisted {
            Some(existing) if existing == policy => existing,
            Some(_) => return Err(store_failure(initial_failure)),
            None => policy.clone(),
        };
        let expected_revision = repair.revision();
        if repair.repair_required().is_ok()
            && if was_persisted {
                store.update_policy(&repair, expected_revision).is_ok()
            } else {
                store.insert_policy(&repair).is_ok()
            }
        {
            let command = format!(
                "runner-manager {} remove {} --purge",
                scope_word(repair.target.scope()),
                repair.target
            );
            let failed = write_failed("this repair result");
            writeln!(
                out,
                "Policy storage failed after local preparation; {} was persisted in repair_required.",
                repair.target
            )
            .map_err(failed)?;
            writeln!(out, "repair: {command}").map_err(failed)?;
            return Err(CliError::with_remedy(
                Failure::LocalState,
                format!("the initial policy insert failed: {initial_failure}"),
                command,
            ));
        }
        return Err(store_failure(initial_failure));
    }
    write_add_result(out, &policy, host)
}

fn installation_for(
    target: &ScaleTarget,
    reachable: &runner_manager_github::ReachableTargets,
) -> Result<(u64, u32), CliError> {
    reachable.installations().iter().find(|installation| match target {
        ScaleTarget::Repository(repository) => installation.repositories.contains(repository),
        ScaleTarget::Organization(org) => matches!(&installation.account, InstallationAccount::Organization(installed) if installed == org),
    }).map(|installation| (installation.id, u32::try_from(installation.repositories.len()).unwrap_or(u32::MAX))).ok_or_else(|| {
        // The App IS installed somewhere — this branch is only reachable with
        // at least one installation — just not covering the target asked for.
        // Naming what it DOES reach is what turns this from a dead end into a
        // diagnosis: the operator installed it on the wrong repository, or on
        // an account that does not hold this one.
        let reaches = reachable
            .installations()
            .iter()
            .flat_map(|installation| installation.repositories.iter())
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let reaches = if reaches.is_empty() {
            "no repositories".to_string()
        } else {
            reaches.join(", ")
        };
        CliError::with_remedy(
            Failure::NotFound,
            format!(
                "the GitHub App is installed, but not on {target}, so this host cannot register \
                 a runner there. It currently reaches: {reaches}. Add {target} to the \
                 installation on GitHub. No policy was stored."
            ),
            "runner-manager auth status",
        )
    })
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
            // Every label, not just the derived one. `--label` was accepted and
            // stored, and printing only the host label read as though the rest
            // had been dropped -- which is the one thing an operator would want
            // this line to tell them.
            let all: Vec<&str> = labels.iter().map(Label::as_str).collect();
            writeln!(out, "Routing labels: {}", all.join(", ")).map_err(failed)?;
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
            // D21 requires the monitor-only path to repeat the grant's
            // CONSEQUENCES, not merely its consent-screen label -- and not the
            // whole sign-in disclosure either. Reprinting all twenty-five lines
            // of it after a one-line result buried the two lines that follow,
            // including the command that promotes the policy, and taught the
            // reader to scroll past the section that matters. `f2`'s obligation
            // is the three sentences in `write_grant_consequences`, which is
            // what an operator adding a second target needs to be reminded of.
            super::auth::write_grant_consequences(out).map_err(failed)?;
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
    // Resolved once for the whole list: every row's ephemeral fallback is the
    // same host root, and re-resolving it per policy would let two rows of one
    // table describe two different hosts.
    let host = super::host::local_host(&store)?;
    let host_root = workspace::host_root(context.paths(), host.as_ref());
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
            "{}\t{}\t{}\tenabled={}\tmax={}\tworkspace={}",
            policy.target,
            mode,
            policy.state(),
            policy.enabled(),
            maximum,
            policy.workspace_policy().kind()
        )
        .map_err(failed)?;

        // The detail line, which `d1` requires of the "repository detail" and
        // `05-user-workflows.md` requires to name the effective path, its
        // source, the leases, and the quarantined ones. It is a second line
        // rather than more tab-separated columns so that `cut -f2` keeps
        // working and the first line stays one policy per row.
        //
        // Assembled from the same read model `status --json` and `e1`'s screens
        // use, so the three cannot answer "where does this repository's next
        // attempt go" differently.
        let view = workspace::repository_workspace(&store, &host_root, &policy)?;
        let blocked = view
            .leases
            .iter()
            .filter(|lease| lease.cleanup_blocked)
            .count();
        // `02-target-architecture.md`: "Organization Settings renders workspace
        // mode as `ephemeral` and explains that persistent paths require
        // repository scope." The explanation is the row, not a disabled control
        // the operator has to guess about.
        let why = if scope == TargetScope::Organization {
            "; persistent workspaces require repository scope"
        } else {
            ""
        };
        writeln!(
            out,
            "workspace: {} root={} ({}) leases={} cleanup-blocked={blocked}{why}",
            view.kind(),
            view.effective_root()
                .map_or_else(|| view.host_root.rendered(), str::to_string),
            view.root_source_badge(),
            view.leases.len(),
        )
        .map_err(failed)?;
        // Leases outlive the mode that created them: a slot whose cleanup
        // failed still holds its lease after the repository has been returned
        // to ephemeral, and it is the thing that will refuse the operator's
        // next path change. So it is reported whatever the current mode says.
        for lease in view.leases.iter().filter(|lease| lease.cleanup_blocked) {
            writeln!(
                out,
                "workspace: slot s{} quarantined ({}); remediation available",
                lease.slot, lease.state
            )
            .map_err(failed)?;
        }
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
    apply_policy_mutation(
        context,
        &target,
        PolicyMutation {
            max_capacity: Some(raw_maximum),
            ..PolicyMutation::default()
        },
        None,
        out,
    )
}

fn set_scale(
    context: &Context,
    target: ScaleTarget,
    enabled: bool,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let observation = observe_scale(context, &target)?;
    let active = observation.active;
    let mut confirmation = None;
    if !enabled && active > 0 {
        let stdin = io::stdin();
        if !confirm_disable(active, out, &mut stdin.lock())? {
            return Err(CliError::new(
                Failure::Conflict,
                "disable cancelled; the policy was not changed",
            ));
        }
        confirmation = Some(observation);
    }
    apply_scale_confirmed(context, &target, enabled, confirmation, out)
}

/// What was observed before asking an operator to drain active work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScaleObservation {
    pub active: u16,
    policy_revision: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PolicyMutation {
    pub max_capacity: Option<u16>,
    pub enabled: Option<bool>,
    pub cache_policy: Option<CachePolicy>,
}

/// Re-observes the policy and active work without prompting. TUI code uses
/// this before displaying its own non-blocking confirmation.
pub fn observe_scale(
    context: &Context,
    target: &ScaleTarget,
) -> Result<ScaleObservation, CliError> {
    let store = context.store()?;
    let policy = find_policy(&store, target)?;
    let attempts = store
        .attempts_for_policy(policy.id)
        .map_err(store_failure)?;
    Ok(ScaleObservation {
        active: active_count_for(policy.id, attempts.iter()),
        policy_revision: policy.revision(),
    })
}

/// Shared post-confirmation mutation used by both CLI and TUI.
///
/// A disable confirmation is valid only for the exact policy revision and
/// active count the operator saw. If either changed, no mutation occurs and
/// the caller must render a fresh confirmation. This closes the stdin/TUI
/// time-of-check/time-of-use gap without ever reading stdin in the TUI loop.
pub fn apply_scale_confirmed(
    context: &Context,
    target: &ScaleTarget,
    enabled: bool,
    confirmation: Option<ScaleObservation>,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    apply_policy_mutation(
        context,
        target,
        PolicyMutation {
            enabled: Some(enabled),
            ..PolicyMutation::default()
        },
        confirmation,
        out,
    )
}

/// Applies a complete policy form as one optimistic, atomic store update.
/// Every requested domain transition is validated in memory before the single
/// write, so a late capacity/cache/confirmation failure leaves every column
/// unchanged.
pub fn apply_policy_mutation(
    context: &Context,
    target: &ScaleTarget,
    mutation: PolicyMutation,
    confirmation: Option<ScaleObservation>,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let store = context.store()?;
    let mut policy = find_policy(&store, target)?;
    let expected = policy.revision();
    let attempts = store
        .attempts_for_policy(policy.id)
        .map_err(store_failure)?;
    let observed_active = active_count_for(policy.id, attempts.iter());
    let mut active = observed_active;
    let mut guarded_revision = expected;
    let mut guarded_active = None;
    if mutation.enabled == Some(false) {
        if let Some(confirmed) = confirmation {
            // Use the exact values shown to the operator for both the domain
            // transition and the transactional predicates below. A newer
            // preflight read must never silently replace the confirmation.
            active = confirmed.active;
            guarded_revision = confirmed.policy_revision;
            guarded_active = Some(confirmed.active);
        } else if observed_active > 0 {
            return Err(CliError::new(
                Failure::Conflict,
                format!(
                    "{observed_active} active runner(s) must be confirmed before disabling; nothing was changed"
                ),
            ));
        } else {
            // Even an unprompted zero-active disable needs the count predicate:
            // an allocation racing this command must not slip between the read
            // and persistence.
            guarded_active = Some(0);
        }
    }

    let maximum = mutation.max_capacity.map(non_zero_capacity).transpose()?;
    if let Some(maximum) = maximum {
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
    }

    if let Some(enabled) = mutation.enabled {
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
            }
        } else if policy.enabled() {
            policy.request_disable().map_err(invalid)?;
            if active == 0 {
                policy.drain_completed(0).map_err(invalid)?;
            }
        }
    }

    if let Some(cache_policy) = mutation.cache_policy
        && policy.cache_policy != cache_policy
    {
        let mut fields = policy.to_persisted();
        fields.cache_policy = cache_policy;
        fields.revision = fields.revision.saturating_add(1);
        policy = ScalePolicy::from_persisted(fields).map_err(invalid)?;
    }

    if policy.revision() != expected {
        if let Some(expected_active) = guarded_active {
            store
                .update_policy_confirming_active_count(&policy, guarded_revision, expected_active)
                .map_err(store_failure)?;
        } else {
            store
                .update_policy(&policy, expected)
                .map_err(store_failure)?;
        }
    }

    if let Some(maximum) = maximum {
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
            let all: Vec<&str> = labels.iter().map(Label::as_str).collect();
            writeln!(out, "Routing labels: {}", all.join(", ")).map_err(failed)?;
        }
    }
    if let Some(enabled) = mutation.enabled {
        let failed = write_failed("this scale result");
        if enabled {
            writeln!(out, "Scaling enabled for {}.", policy.target).map_err(failed)?;
            writeln!(out, "{TRUST_WARNING}").map_err(failed)?;
        } else {
            writeln!(out, "{} is {} with {active} active runner(s); busy runners were not terminated. Cache and historical diagnostics were preserved.", policy.target, if active == 0 { "disabled" } else { "draining" }).map_err(failed)?;
        }
    }
    Ok(())
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use runner_manager_domain::attempt::RunnerAttempt;
    use runner_manager_domain::model::{Arch, AttemptId, HostId, Org, Os, OwnerRepo};
    use runner_manager_domain::store::SqliteStore;

    #[derive(Debug)]
    struct AmbiguousFirstPolicyInsert {
        inner: SqliteStore,
        fail_next_insert: AtomicBool,
        remove_policy_calls: AtomicUsize,
    }

    impl AmbiguousFirstPolicyInsert {
        fn new() -> Self {
            Self {
                inner: SqliteStore::open_in_memory().unwrap(),
                fail_next_insert: AtomicBool::new(true),
                remove_policy_calls: AtomicUsize::new(0),
            }
        }
    }

    impl Store for AmbiguousFirstPolicyInsert {
        fn put_host(&self, host: &Host) -> Result<(), StoreError> {
            self.inner.put_host(host)
        }

        fn host(&self, id: HostId) -> Result<Option<Host>, StoreError> {
            self.inner.host(id)
        }

        fn hosts(&self) -> Result<Vec<Host>, StoreError> {
            self.inner.hosts()
        }

        fn set_runner_root_override(
            &self,
            id: HostId,
            expected: Option<&runner_manager_domain::path::LocalAbsolutePath>,
            new_root: Option<&runner_manager_domain::path::LocalAbsolutePath>,
            expected_uncleaned: u16,
        ) -> Result<(), StoreError> {
            self.inner
                .set_runner_root_override(id, expected, new_root, expected_uncleaned)
        }

        fn insert_policy(&self, policy: &ScalePolicy) -> Result<(), StoreError> {
            if self.fail_next_insert.swap(false, Ordering::SeqCst) {
                self.inner.insert_policy(policy)?;
                return Err(StoreError::AlreadyExists {
                    what: "ambiguously committed policy",
                    id: policy.id.to_string(),
                });
            }
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
            self.remove_policy_calls.fetch_add(1, Ordering::SeqCst);
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
            self.inner.uncleaned_attempts_for_policy(policy_id)
        }

        fn slot_leases_for_policy(
            &self,
            policy_id: PolicyId,
        ) -> Result<Vec<RunnerAttempt>, StoreError> {
            self.inner.slot_leases_for_policy(policy_id)
        }

        fn uncleaned_ephemeral_attempts(&self) -> Result<Vec<RunnerAttempt>, StoreError> {
            self.inner.uncleaned_ephemeral_attempts()
        }

        fn remove_attempt(&self, id: AttemptId) -> Result<bool, StoreError> {
            self.inner.remove_attempt(id)
        }
    }

    /// The whole point of an extra label: a runner that answers what the
    /// repository's existing workflows already ask for.
    #[test]
    fn extra_labels_join_the_derived_host_label_and_the_host_label_survives_removal() {
        let store = SqliteStore::open_in_memory().unwrap();
        let local = host("ivanpc");
        store.put_host(&local).unwrap();
        let target = ScaleTarget::Repository(OwnerRepo::parse("octo/repo").unwrap());

        record_policy(
            &store,
            &local,
            target.clone(),
            HostLabel::new("ivanpc").unwrap(),
            vec![
                Label::new("self-hosted").unwrap(),
                Label::new("windows").unwrap(),
            ],
            Some(nz(2)),
            77,
            TargetCost::repository(),
            Vec::new(),
            &mut Vec::new(),
        )
        .unwrap();

        let stored = &store.policies().unwrap()[0];
        let labels = stored.routing_labels().expect("an autoscale policy");
        let all: Vec<&str> = labels.iter().map(Label::as_str).collect();
        assert!(
            all.contains(&"rm-ivanpc-linux-x64"),
            "the derived host label must still be there: {all:?}"
        );
        assert!(all.contains(&"self-hosted"), "{all:?}");
        assert!(all.contains(&"windows"), "{all:?}");
        assert_eq!(
            labels.as_registration_labels().len(),
            3,
            "all three go to `generate-jitconfig`; GitHub adds none of its own"
        );

        // The derived label is what stops two hosts racing for one job by
        // default, so removing it is refused -- and the refusal is `b1`'s,
        // surfaced here rather than re-implemented.
        let mut policy = stored.clone();
        assert!(
            policy
                .remove_routing_label(&Label::new("rm-ivanpc-linux-x64").unwrap())
                .is_err(),
            "the host label must not be removable"
        );
        assert!(
            policy
                .remove_routing_label(&Label::new("windows").unwrap())
                .unwrap(),
            "an added label is removable"
        );
    }

    /// A monitor-only policy has no label set to put them in, so asking is an
    /// error rather than a silent no-op.
    #[test]
    fn labels_on_a_monitor_only_policy_are_refused_rather_than_dropped() {
        let store = SqliteStore::open_in_memory().unwrap();
        let local = host("ivanpc");
        store.put_host(&local).unwrap();
        let target = ScaleTarget::Repository(OwnerRepo::parse("octo/repo").unwrap());
        record_policy(
            &store,
            &local,
            target.clone(),
            HostLabel::new("ivanpc").unwrap(),
            Vec::new(),
            None,
            77,
            TargetCost::repository(),
            Vec::new(),
            &mut Vec::new(),
        )
        .unwrap();

        let stored = &store.policies().unwrap()[0];
        assert!(
            stored.routing_labels().is_none(),
            "monitor-only carries no routing labels at all"
        );
    }

    /// `--enable` is the operator arming in one line, not creation arming
    /// itself. The default must stay non-arming: `repo add` is safe to run
    /// before you have decided anything.
    #[test]
    fn adding_without_enable_leaves_the_policy_disarmed() {
        let store = SqliteStore::open_in_memory().unwrap();
        let local = host("ivanpc");
        store.put_host(&local).unwrap();
        record_policy(
            &store,
            &local,
            ScaleTarget::Repository(OwnerRepo::parse("octo/repo").unwrap()),
            HostLabel::new("ivanpc").unwrap(),
            Vec::new(),
            Some(nz(2)),
            77,
            TargetCost::repository(),
            Vec::new(),
            &mut Vec::new(),
        )
        .unwrap();

        let stored = &store.policies().unwrap()[0];
        assert!(
            !stored.enabled(),
            "creation must never arm on its own; that is what makes `repo add` safe to run early"
        );
        assert_eq!(stored.state(), PolicyState::Pending);
        assert!(
            !stored.may_start_runners(),
            "a pending policy starts nothing until somebody says so"
        );
    }

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
                Vec::new(),
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
            assert!(text.contains("Routing labels: rm-home-linux-x64"), "{text}");
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
            Vec::new(),
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
        assert!(
            text.contains(
                "`Administration: Read and write` is NOT a narrow self-hosted-runner permission."
            ),
            "{text}"
        );
        assert!(
            text.contains("The same grant also permits DELETING, RENAMING and TRANSFERRING the repository, and"),
            "{text}"
        );
        assert!(
            text.contains("adding and removing collaborators."),
            "{text}"
        );

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
                Vec::new(),
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
    fn ambiguously_committed_initial_insert_is_updated_to_repair_required() {
        let store = AmbiguousFirstPolicyInsert::new();
        let local = host("machine");
        store.put_host(&local).unwrap();
        let policy_id = PolicyId::new_random();
        let mut output = Vec::new();
        let error = record_policy_with_id(
            &store,
            &local,
            targets()[0].clone(),
            HostLabel::new("home").unwrap(),
            Vec::new(),
            None,
            77,
            TargetCost::repository(),
            Vec::new(),
            policy_id,
            &mut output,
        )
        .unwrap_err();
        assert_eq!(error.class(), Failure::LocalState);
        assert_eq!(
            store.host(local.id).unwrap().unwrap().display_name,
            "machine"
        );
        let policies = store.policies().unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].id, policy_id);
        assert_eq!(policies[0].state(), PolicyState::RepairRequired);
        assert_eq!(policies[0].requested_host_label.as_str(), "home");
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("persisted in repair_required"), "{output}");
        assert!(
            output.contains("repair: runner-manager repo remove octo/repo --purge"),
            "{output}"
        );
        assert_eq!(
            store.remove_policy_calls.load(Ordering::SeqCst),
            0,
            "the failure path persists repair state but never deletes local or remote state"
        );
    }

    #[test]
    fn refusal_prints_the_ceiling_admission_actually_used() {
        let interval = RefreshInterval::default();
        let candidate = TargetCost::repository();
        let maximum = BudgetProjection::max_repository_targets(interval);
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
                Vec::new(),
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
                Vec::new(),
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
        let root = tempfile::TempDir::new().unwrap();
        let context = Context::resolve(Some(root.path()), &mut Vec::new()).unwrap();
        let store = context.store().unwrap();
        let local = host("home");
        store.put_host(&local).unwrap();
        let target = targets()[0].clone();
        let mut policy = ScalePolicy::new(
            PolicyId::new_random(),
            target.clone(),
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
        for id in 1..=2 {
            store
                .record_attempt(&RunnerAttempt::allocate(
                    AttemptId::from_u128(id),
                    policy.id,
                    format!("active-{id}"),
                    chrono::DateTime::from_timestamp(1_700_000_000 + id as i64, 0).unwrap(),
                ))
                .unwrap();
        }
        drop(store);
        let observation = observe_scale(&context, &target).unwrap();
        let mut output = Vec::new();
        apply_scale_confirmed(&context, &target, false, Some(observation), &mut output).unwrap();
        let stored = context.store().unwrap().policies().unwrap().remove(0);
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

    #[test]
    fn post_confirmation_seam_refuses_when_active_work_changes() {
        let root = tempfile::TempDir::new().unwrap();
        let context = Context::resolve(Some(root.path()), &mut Vec::new()).unwrap();
        let store = context.store().unwrap();
        let local = host("home");
        store.put_host(&local).unwrap();
        let target = targets()[0].clone();
        let mut policy = ScalePolicy::new(
            PolicyId::new_random(),
            target.clone(),
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
        drop(store);

        let confirmed = observe_scale(&context, &target).unwrap();
        assert_eq!(confirmed.active, 0);
        let store = context.store().unwrap();
        store
            .record_attempt(&RunnerAttempt::allocate(
                AttemptId::new_random(),
                policy.id,
                "new-active-work",
                chrono::DateTime::from_timestamp(1_700_000_001, 0).unwrap(),
            ))
            .unwrap();
        drop(store);

        let error =
            apply_scale_confirmed(&context, &target, false, Some(confirmed), &mut Vec::new())
                .unwrap_err();
        assert_eq!(error.class(), Failure::Conflict);
        assert!(
            find_policy(&context.store().unwrap(), &target)
                .unwrap()
                .enabled()
        );
    }

    #[test]
    fn drain_confirmation_refuses_the_same_active_count_at_a_new_revision() {
        let root = tempfile::TempDir::new().unwrap();
        let context = Context::resolve(Some(root.path()), &mut Vec::new()).unwrap();
        let store = context.store().unwrap();
        let local = host("home");
        store.put_host(&local).unwrap();
        let target = targets()[0].clone();
        let mut policy = ScalePolicy::new(
            PolicyId::new_random(),
            target.clone(),
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
        store
            .record_attempt(&RunnerAttempt::allocate(
                AttemptId::new_random(),
                policy.id,
                "active-work",
                chrono::DateTime::from_timestamp(1_700_000_001, 0).unwrap(),
            ))
            .unwrap();
        drop(store);

        let confirmed = observe_scale(&context, &target).unwrap();
        apply_policy_mutation(
            &context,
            &target,
            PolicyMutation {
                max_capacity: Some(3),
                ..PolicyMutation::default()
            },
            None,
            &mut Vec::new(),
        )
        .unwrap();
        let before = find_policy(&context.store().unwrap(), &target).unwrap();
        assert_eq!(confirmed.active, 1);

        let error =
            apply_scale_confirmed(&context, &target, false, Some(confirmed), &mut Vec::new())
                .unwrap_err();
        assert_eq!(error.class(), Failure::Conflict);
        assert_eq!(
            find_policy(&context.store().unwrap(), &target).unwrap(),
            before
        );
    }

    #[test]
    fn drain_confirmation_refuses_when_active_work_falls_to_zero() {
        let root = tempfile::TempDir::new().unwrap();
        let context = Context::resolve(Some(root.path()), &mut Vec::new()).unwrap();
        let store = context.store().unwrap();
        let local = host("home");
        store.put_host(&local).unwrap();
        let target = targets()[0].clone();
        let mut policy = ScalePolicy::new(
            PolicyId::new_random(),
            target.clone(),
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
        let attempt_id = AttemptId::new_random();
        store
            .record_attempt(&RunnerAttempt::allocate(
                attempt_id,
                policy.id,
                "active-work",
                chrono::DateTime::from_timestamp(1_700_000_001, 0).unwrap(),
            ))
            .unwrap();
        drop(store);

        let confirmed = observe_scale(&context, &target).unwrap();
        assert_eq!(confirmed.active, 1);
        context.store().unwrap().remove_attempt(attempt_id).unwrap();
        let before = find_policy(&context.store().unwrap(), &target).unwrap();

        let error =
            apply_scale_confirmed(&context, &target, false, Some(confirmed), &mut Vec::new())
                .unwrap_err();
        assert_eq!(error.class(), Failure::Conflict);
        assert_eq!(
            find_policy(&context.store().unwrap(), &target).unwrap(),
            before
        );
        assert!(before.enabled());
    }
}
