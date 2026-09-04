// owner: f1-cli-auth-host-status

//! `status` and `status --json` — one snapshot of this host.
//!
//! # The JSON is a compatibility surface, so it is versioned and pinned
//!
//! `f1`: *"A stable, scriptable snapshot for headless operation. Its schema is a
//! compatibility surface: version it, and never emit a credential into it."*
//! Both halves are enforced rather than intended:
//!
//! * [`SCHEMA_VERSION`] rides in the document, and
//!   `the_documented_schema_is_the_one_that_is_emitted` walks the emitted keys
//!   against a written-out list. Adding a field is a compatible change and
//!   updates that list; removing or renaming one is not, and fails there before
//!   it reaches somebody's `jq`.
//! * No field of any type below holds a secret. The credential appears as a
//!   **boolean** and as the store's location — `d2` publishes that location for
//!   `host show` to print — and the token itself is never loaded at all: this
//!   command asks the store whether a value is present, not what it is.
//!
//! # It contacts nothing
//!
//! A status command that needed GitHub would be useless on the one host that
//! most needs it: the offline one from Journey 4. So `status` reads local state
//! only, and says so in the document with `github_contacted: false` rather than
//! leaving a consumer to infer how fresh the answer is. Whether the *credential*
//! is still accepted is `auth status`'s question, and it is the command that
//! asks GitHub.

use std::io::{self, Write};

use runner_manager_domain::attempt::{active_count, active_count_for};
use runner_manager_domain::model::{RefreshInterval, StartMode, Timestamp};
use runner_manager_domain::policy::{PolicyMode, ScalePolicy};
use runner_manager_domain::store::Store;
use runner_manager_github::rest::refreshes_per_hour;
use runner_manager_platform::secrets::SecretStore;
use serde::Serialize;

use super::host::{FALLBACK_COST_MULTIPLE, HostBudget, local_host, max_repository_targets};
use super::workspace;
use super::{CliError, Context, Failure, StatusArgs, write_failed};

/// The version of the `status --json` document.
///
/// Bumped only when a consumer written against the previous version would
/// break: a removed field, a renamed one, or a changed meaning. Adding a field
/// leaves it alone, because a consumer that reads the fields it knows is
/// unaffected by one it does not.
///
/// Still `1` after `store_agrees_with_start_mode` was dropped, because that
/// happened before v1 was ever released — see [`Credential`] for why it went.
/// A field removed after release would be exactly the case this number exists
/// for.
///
/// # And still `1` after `d1` added the workspace fields
///
/// `03-migration-rollout.md` asks for "a schema version update or additive
/// compatibility contract, whichever the existing status schema tests require",
/// and the existing contract is the one written two paragraphs up: adding a
/// field is compatible, so the version does not move. Every workspace field is
/// an addition — `host.runner_root`, `host.runner_root_source`,
/// `host.configured_runner_root`, the two ephemeral counts, and the five
/// per-policy workspace fields. Nothing was removed, renamed, or given a new
/// meaning, so a consumer written against v1 reads exactly what it read before
/// and ignores the rest.
///
/// The claim is not left to a reading of the diff:
/// `the_workspace_fields_are_additive_so_the_version_does_not_move` asserts both
/// halves — that every v1 field is still present under its old name, and that
/// the number is still `1`. A future change that renames one of them fails there
/// and has to bump this constant.
pub const SCHEMA_VERSION: u32 = 1;

/// The keys `status --json` emitted at v1, before `d1` added anything.
///
/// The other half of the additive contract above: a *pinned* list of what a v1
/// consumer was promised, so "we only added fields" is measured rather than
/// asserted. It is not the current schema — that is
/// `the_documented_schema_is_the_one_that_is_emitted`, which grows — and it must
/// never be edited to match a rename. A rename is a version bump.
#[cfg(test)]
const SCHEMA_V1_HOST_FIELDS: &[&str] = &[
    "architecture",
    "capacity",
    "configured",
    "display_name",
    "headroom",
    "id",
    "in_use",
    "os",
    "refresh_interval_secs",
    "service_start_mode",
];

/// As [`SCHEMA_V1_HOST_FIELDS`], for one policy.
#[cfg(test)]
const SCHEMA_V1_POLICY_FIELDS: &[&str] = &[
    "active_attempts",
    "enabled",
    "id",
    "max_capacity",
    "min_capacity",
    "mode",
    "routing_labels",
    "scope",
    "state",
    "target",
];

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

/// One snapshot of this host, as `status --json` emits it.
#[derive(Debug, Clone, Serialize)]
pub struct StatusDocument {
    pub schema_version: u32,
    pub generated_at: Timestamp,
    pub product: Product,
    /// Always `false`: see the module documentation.
    pub github_contacted: bool,
    pub credential: Credential,
    pub host: HostSnapshot,
    pub budget: BudgetSnapshot,
    pub policies: Vec<PolicySnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Product {
    pub name: &'static str,
    pub version: &'static str,
}

/// What is known about the credential **without asking GitHub**.
///
/// `present` is the answer to "is there a value in the store", and nothing
/// here is the value. A consumer that needs to know whether GitHub still
/// accepts it runs `auth status`, which has five answers and an exit code for
/// each.
///
/// # `present` is only an answer when `unreadable` is null
///
/// There is a third state, and on the platform this product's persona actually
/// runs it is the ordinary one. A boot-mode host keeps the token in the
/// machine-scoped store, which on macOS is the System Keychain — decrypted with
/// a `root`-only master key, because the daemon that reads it runs as `root`.
/// So the operator's own `runner-manager status` cannot read it, and there is
/// nothing wrong.
///
/// This document used to *fail* there: one unreadable field ended the command
/// and printed no snapshot at all, so a boot-mode macOS host could not report
/// its capacity, its policies or its attempts without `sudo`. Reporting
/// `present: false` instead would have been worse — the operator would be sent
/// to `auth login`, which overwrites a credential that was never the problem.
///
/// So the failure to read is carried rather than thrown or flattened.
/// `unreadable` holds the reason, in the store's own words; `present` is
/// `false` and means nothing while it is set.
///
/// # There is deliberately no `store_agrees_with_start_mode`
///
/// An earlier draft of schema v1 carried one, from `d2`'s
/// `ActiveStore::agrees_with_start_mode`, and it was **constant `true`**:
/// [`Context::secret_store`] derives the scope
/// as `SecretScope::for_start_mode(start_mode)` and the same `start_mode` was
/// then handed back for the comparison, so it computed `f(x) == f(x)`.
///
/// `d2` justifies that check as comparing *"two independently persisted
/// facts"* — the store a process opened against the start mode recorded for the
/// **installed service** — and through this composition root they are not
/// independent, because one is computed from the other. It is `service status`'s
/// check (`f3`), where the recorded start mode really is a separate fact, and it
/// degenerates here.
///
/// A field that can never be `false` in a versioned compatibility surface is
/// worse than no field: a consumer branching on it gets assurance the document
/// cannot supply. It is dropped rather than faked, and nothing is lost — the two
/// values it was derived from, [`Credential::store_scope`] and
/// [`HostSnapshot::service_start_mode`], are both still here, so a consumer that
/// wants the comparison can make it and will know exactly what it compared.
#[derive(Debug, Clone, Serialize)]
pub struct Credential {
    pub present: bool,
    /// Why the store could not be read, or `null` when it was read.
    ///
    /// While this is set, `present` is `false` because it has to be something
    /// and carries no information.
    pub unreadable: Option<String>,
    pub store_scope: String,
    pub store_location: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostSnapshot {
    /// `false` before any command has created a host row; every field below is
    /// then the default one would be created with.
    pub configured: bool,
    pub id: Option<String>,
    pub display_name: Option<String>,
    pub os: Option<String>,
    pub architecture: Option<String>,
    pub capacity: u16,
    pub in_use: u16,
    pub headroom: u16,
    pub service_start_mode: String,
    pub refresh_interval_secs: u16,
    /// Where disposable runner attempts are created, resolved.
    ///
    /// `null` only when the platform default could not be resolved at all; see
    /// [`workspace::HostRoot`]. A consumer that needs the reason reads
    /// `runner_root_unavailable`.
    pub runner_root: Option<String>,
    /// `platform_default` or `configured` — a structured field rather than a
    /// display string, which is what `05-user-workflows.md`'s "Status JSON uses
    /// structured mode, source, root, slot, and lease fields" asks for.
    pub runner_root_source: String,
    /// The stored override, or `null` when the platform default is in force.
    /// Emitted beside the effective path so a consumer can tell "the operator
    /// chose this" from "this is what the platform happens to give".
    pub configured_runner_root: Option<String>,
    /// Why `runner_root` is `null`, when it is.
    pub runner_root_unavailable: Option<String>,
    /// Uncleaned ephemeral attempts that still occupy host capacity.
    pub active_ephemeral_attempts: u16,
    /// Uncleaned ephemeral attempts that are terminal: they hold no capacity
    /// and still own their directory, so they block a root change.
    pub cleanup_blocked_ephemeral_attempts: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct BudgetSnapshot {
    pub interval_secs: u16,
    pub refreshes_per_hour: u32,
    pub projected_requests_per_hour: u32,
    /// `true` when an organization target made the projection a floor.
    pub projection_is_floor: bool,
    pub allowance_requests_per_hour: u32,
    pub ceiling_requests_per_hour: u32,
    pub headroom_requests_per_hour: u32,
    pub exceeds_allowance: bool,
    pub max_repository_targets: u32,
    /// How far a per-repository cost can exceed the best case this projection
    /// prices it at. Emitted so a consumer reading `max_repository_targets` has
    /// the caveat in the same document as the number.
    pub best_case_multiple_when_paging: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicySnapshot {
    pub id: String,
    pub target: String,
    pub scope: String,
    pub mode: String,
    pub state: String,
    pub enabled: bool,
    pub min_capacity: u16,
    pub max_capacity: Option<u16>,
    pub routing_labels: Vec<String>,
    pub active_attempts: u16,
    /// Terminal attempts of this policy that have not been cleaned. They hold
    /// no capacity, still own their directory, and — if persistent — still hold
    /// a slot lease, which is why they are counted apart from
    /// [`Self::active_attempts`] rather than folded into it.
    pub cleanup_blocked_attempts: u16,
    /// `ephemeral` or `persistent`.
    pub workspace_mode: String,
    /// The configured persistent root, or `null` for an ephemeral policy.
    pub workspace_root: Option<String>,
    /// The directory this policy's next attempt is created under: its own root
    /// when persistent, the effective host root when not.
    pub workspace_effective_root: Option<String>,
    /// Which of the three settings decided `workspace_effective_root`:
    /// `repository`, `configured`, or `platform_default`. `d1` requires every
    /// surface to "identify platform-default, configured, and
    /// repository-specific sources", and naming it is cheaper for a consumer
    /// than inferring it from whether `workspace_root` is null.
    pub workspace_root_source: String,
    /// Every slot this policy still leases. Empty for an ephemeral policy, and
    /// never a file listing: `d1` requires these surfaces to identify a
    /// workspace "without enumerating workspace files".
    pub workspace_slots: Vec<SlotSnapshot>,
}

/// One durable slot lease.
#[derive(Debug, Clone, Serialize)]
pub struct SlotSnapshot {
    pub slot: u16,
    pub attempt: String,
    pub state: String,
    /// The attempt is terminal and uncleaned, so the slot is quarantined rather
    /// than merely busy.
    pub cleanup_blocked: bool,
}

impl From<&workspace::SlotLease> for SlotSnapshot {
    fn from(lease: &workspace::SlotLease) -> Self {
        Self {
            slot: lease.slot,
            attempt: lease.attempt.clone(),
            state: lease.state.clone(),
            cleanup_blocked: lease.cleanup_blocked,
        }
    }
}

impl PolicySnapshot {
    fn of(
        policy: &ScalePolicy,
        active_attempts: u16,
        workspace: &workspace::RepositoryWorkspace,
    ) -> Self {
        Self {
            id: policy.id.to_string(),
            target: policy.target.slug(),
            scope: workspace::scope_token(policy.target.scope()).to_string(),
            mode: match policy.mode() {
                PolicyMode::MonitorOnly => "monitor_only",
                PolicyMode::Autoscale(_) => "autoscale",
            }
            .to_string(),
            state: policy.state().to_string(),
            enabled: policy.enabled(),
            min_capacity: policy.min_capacity(),
            max_capacity: policy.max_capacity().map(std::num::NonZeroU16::get),
            routing_labels: policy
                .routing_labels()
                .map(registration_labels)
                .unwrap_or_default(),
            active_attempts,
            cleanup_blocked_attempts: workspace.attempts.cleanup_blocked,
            workspace_mode: workspace.kind().to_string(),
            workspace_root: workspace
                .policy
                .root()
                .map(|root| root.as_str().to_string()),
            workspace_effective_root: workspace.effective_root().map(str::to_string),
            workspace_root_source: workspace.root_source().to_string(),
            workspace_slots: workspace.leases.iter().map(SlotSnapshot::from).collect(),
        }
    }
}

/// The routing labels as GitHub stores them, or an empty list for a
/// monitor-only policy, which owns none by construction (D19).
fn registration_labels(labels: &runner_manager_domain::policy::RoutingLabels) -> Vec<String> {
    labels.as_registration_labels()
}

// ---------------------------------------------------------------------------
// Building it
// ---------------------------------------------------------------------------

/// Reads local state and assembles the snapshot.
///
/// # Errors
/// [`Failure::LocalState`] and [`Failure::SecretStore`].
pub fn snapshot(context: &Context) -> Result<StatusDocument, CliError> {
    let store = context.store()?;
    let host = local_host(&store)?;
    let attempts = store.attempts().map_err(|source| {
        CliError::new(
            Failure::LocalState,
            format!("cannot read this host's attempt journal: {source}"),
        )
    })?;
    let policies = store.policies().map_err(|source| {
        CliError::with_remedy(
            Failure::LocalState,
            format!("cannot read this host's policies: {source}"),
            "runner-manager host show",
        )
    })?;

    let start_mode = host
        .as_ref()
        .map_or_else(StartMode::default, |h| h.service_start_mode);
    let interval = host
        .as_ref()
        .map_or_else(RefreshInterval::default, |h| h.refresh_interval);
    let capacity = host
        .as_ref()
        .map_or(super::DEFAULT_HOST_CAPACITY, |h| h.host_capacity());
    let in_use = active_count(attempts.iter());

    let secrets = context.secret_store(start_mode)?;
    // `load()` rather than a "does the file exist" probe, because `d2` reports
    // a value it did not write as `Corrupt` rather than as absence — and a
    // status document that read a corrupt store as "no credential" would send
    // an operator to `auth login`, which overwrites the evidence.
    //
    // A store that cannot be read is reported, not thrown. See `Credential`:
    // on the platform this product is actually run on, the ordinary reason is
    // that the operator is not the account the daemon runs as, and a snapshot
    // of everything else is exactly what they asked for.
    let (present, unreadable) = match secrets.load() {
        Ok(value) => (value.is_some(), None),
        Err(source) => (false, Some(source.to_string())),
    };

    let targets: Vec<_> = policies.iter().map(|p| p.target.clone()).collect();
    let budget = HostBudget::of(interval, &targets);

    let runner_root = workspace::host_root(context.paths(), host.as_ref());
    let ephemeral = workspace::host_affected_attempts(&store)?;
    // The same `runner_root` every policy's ephemeral fallback reports, so the
    // host block and the policy block of one document cannot disagree about
    // where the next disposable attempt goes.
    let workspaces = policies
        .iter()
        .map(|policy| workspace::repository_workspace(&store, &runner_root, policy))
        .collect::<Result<Vec<_>, CliError>>()?;

    Ok(StatusDocument {
        schema_version: SCHEMA_VERSION,
        generated_at: context.clock().now(),
        product: Product {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        github_contacted: false,
        credential: Credential {
            present,
            unreadable,
            store_scope: secrets.scope().to_string(),
            store_location: secrets.location(),
        },
        host: HostSnapshot {
            configured: host.is_some(),
            id: host.as_ref().map(|h| h.id.to_string()),
            display_name: host.as_ref().map(|h| h.display_name.clone()),
            os: host.as_ref().map(|h| h.os.to_string()),
            architecture: host.as_ref().map(|h| h.architecture.to_string()),
            capacity,
            in_use,
            headroom: capacity.saturating_sub(in_use),
            service_start_mode: start_mode.to_string(),
            refresh_interval_secs: interval.as_secs(),
            runner_root: runner_root.effective_text().map(str::to_string),
            runner_root_source: runner_root.source().as_token().to_string(),
            configured_runner_root: runner_root
                .configured
                .as_ref()
                .map(|root| root.as_str().to_string()),
            runner_root_unavailable: runner_root.unavailable.clone(),
            active_ephemeral_attempts: ephemeral.active,
            cleanup_blocked_ephemeral_attempts: ephemeral.cleanup_blocked,
        },
        budget: BudgetSnapshot {
            interval_secs: interval.as_secs(),
            refreshes_per_hour: refreshes_per_hour(interval),
            projected_requests_per_hour: budget.requests_per_hour(),
            projection_is_floor: budget.is_floor(),
            allowance_requests_per_hour: budget.allowance(),
            ceiling_requests_per_hour: budget.ceiling(),
            headroom_requests_per_hour: budget.headroom(),
            exceeds_allowance: budget.exceeds_allowance(),
            max_repository_targets: max_repository_targets(interval),
            best_case_multiple_when_paging: FALLBACK_COST_MULTIPLE,
        },
        policies: policies
            .iter()
            .zip(workspaces.iter())
            .map(|(policy, workspace)| {
                PolicySnapshot::of(
                    policy,
                    active_count_for(policy.id, attempts.iter()),
                    workspace,
                )
            })
            .collect(),
    })
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// # Errors
/// The local-state and secret-store failures.
pub fn dispatch(context: &Context, args: &StatusArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let failed = write_failed("this host's status");
    let document = snapshot(context)?;
    if args.json {
        write_json(out, &document)
    } else {
        write_text(out, &document)
    }
    .map_err(failed)
}

/// Pretty-printed rather than compact, and with a trailing newline.
///
/// A document a person may `cat` as readily as pipe: `05-infrastructure.md`'s
/// disclosure procedure and every support conversation start with somebody
/// pasting this. `serde_json` is deterministic over these structs — field order
/// follows declaration order — so the output is stable enough to diff between
/// two hosts.
fn write_json(out: &mut dyn Write, document: &StatusDocument) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *out, document)
        .map_err(|source| io::Error::other(source.to_string()))?;
    writeln!(out)
}

fn write_text(out: &mut dyn Write, document: &StatusDocument) -> io::Result<()> {
    writeln!(
        out,
        "{} {}",
        document.product.name, document.product.version
    )?;
    writeln!(out, "  as of                     {}", document.generated_at)?;
    writeln!(out)?;

    if document.host.configured {
        writeln!(
            out,
            "Host: {} ({} {})",
            document.host.display_name.as_deref().unwrap_or("unnamed"),
            document.host.os.as_deref().unwrap_or("unknown"),
            document.host.architecture.as_deref().unwrap_or("unknown"),
        )?;
    } else {
        writeln!(
            out,
            "Host: not configured yet; the values below are the defaults."
        )?;
    }
    writeln!(
        out,
        "  capacity                  {} in use of {} ({} free)",
        document.host.in_use, document.host.capacity, document.host.headroom
    )?;
    writeln!(
        out,
        "  service start mode        {}",
        document.host.service_start_mode
    )?;
    writeln!(
        out,
        "  runner root               {} ({})",
        document
            .host
            .runner_root
            .as_deref()
            .unwrap_or("unavailable"),
        document.host.runner_root_source.replace('_', "-"),
    )?;
    if let Some(reason) = &document.host.runner_root_unavailable {
        writeln!(out, "  runner root problem       {reason}")?;
    }
    writeln!(
        out,
        "  ephemeral paths           {} active, {} awaiting cleanup",
        document.host.active_ephemeral_attempts, document.host.cleanup_blocked_ephemeral_attempts
    )?;
    writeln!(
        out,
        "  credential                {} in the {}-scoped store",
        match (&document.credential.unreadable, document.credential.present) {
            // Never "absent". An unreadable store has not answered the
            // question, and the two words an operator acts on differently must
            // not be the same word.
            (Some(_), _) => "not readable by this account",
            (None, true) => "present",
            (None, false) => "absent",
        },
        document.credential.store_scope
    )?;
    // The store's own words, on their own line, for the same reason the runner
    // root's problem gets one: the reason names a remedy and a two-column table
    // cell would truncate it.
    if let Some(reason) = &document.credential.unreadable {
        writeln!(out, "  credential problem        {reason}")?;
    }
    writeln!(
        out,
        "  GitHub contacted          no (this is a local snapshot; `auth status` asks GitHub)"
    )?;
    writeln!(out)?;

    writeln!(out, "Policies ({})", document.policies.len())?;
    if document.policies.is_empty() {
        writeln!(out, "  none yet -- `repo add` or `org add` creates one.")?;
    }
    for policy in &document.policies {
        writeln!(
            out,
            "  {:<40} {:<13} {:<10} {} active",
            policy.target, policy.mode, policy.state, policy.active_attempts
        )?;
        // `05-user-workflows.md`, "Status and activity": the two attempt shapes
        // are distinguished by their workspace, and a blocked slot says so
        // rather than being read as an ordinary busy one.
        writeln!(
            out,
            "  {:<40} {} attempt in {}",
            "",
            policy.workspace_mode,
            policy
                .workspace_effective_root
                .as_deref()
                .unwrap_or("an unresolved root"),
        )?;
        for slot in &policy.workspace_slots {
            writeln!(
                out,
                "  {:<40} slot s{} {}",
                "",
                slot.slot,
                if slot.cleanup_blocked {
                    "cleanup blocked; quarantined until remediation"
                } else {
                    "leased by a live attempt"
                }
            )?;
        }
    }
    writeln!(out)?;

    writeln!(
        out,
        "Shared REST budget: {} requests/hour projected of {} this host may spend",
        document.budget.projected_requests_per_hour, document.budget.allowance_requests_per_hour
    )?;
    writeln!(
        out,
        "  about {} repository targets fit at a {}s interval (best case; a repository whose",
        document.budget.max_repository_targets, document.budget.interval_secs
    )?;
    writeln!(
        out,
        "  counts have to walk pages costs up to {}x that)",
        document.budget.best_case_multiple_when_paging
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::Value;

    fn document() -> StatusDocument {
        StatusDocument {
            schema_version: SCHEMA_VERSION,
            generated_at: chrono::DateTime::from_timestamp(1_787_270_400, 0).unwrap(),
            product: Product {
                name: "runner-manager",
                version: "0.1.0",
            },
            github_contacted: false,
            credential: Credential {
                present: true,
                unreadable: None,
                store_scope: "machine".to_string(),
                store_location: "C:/ProgramData/runner-manager/secrets".to_string(),
            },
            host: HostSnapshot {
                configured: true,
                id: Some("00000000-0000-0000-0000-000000000001".to_string()),
                display_name: Some("home-win".to_string()),
                os: Some("windows".to_string()),
                architecture: Some("x64".to_string()),
                capacity: 2,
                in_use: 1,
                headroom: 1,
                service_start_mode: "boot".to_string(),
                refresh_interval_secs: 60,
                runner_root: Some("C:/rman".to_string()),
                runner_root_source: "platform_default".to_string(),
                configured_runner_root: None,
                runner_root_unavailable: None,
                active_ephemeral_attempts: 1,
                cleanup_blocked_ephemeral_attempts: 0,
            },
            budget: BudgetSnapshot {
                interval_secs: 60,
                refreshes_per_hour: 60,
                projected_requests_per_hour: 180,
                projection_is_floor: false,
                allowance_requests_per_hour: 2500,
                ceiling_requests_per_hour: 5000,
                headroom_requests_per_hour: 2320,
                exceeds_allowance: false,
                max_repository_targets: 13,
                best_case_multiple_when_paging: FALLBACK_COST_MULTIPLE,
            },
            policies: vec![PolicySnapshot {
                id: "00000000-0000-0000-0000-000000000010".to_string(),
                target: "owner/repo".to_string(),
                scope: "repository".to_string(),
                mode: "autoscale".to_string(),
                state: "active".to_string(),
                enabled: true,
                min_capacity: 0,
                max_capacity: Some(1),
                routing_labels: vec!["rm-home-win-x64".to_string()],
                active_attempts: 1,
                cleanup_blocked_attempts: 0,
                workspace_mode: "persistent".to_string(),
                workspace_root: Some("D:/ci-cache/project".to_string()),
                workspace_effective_root: Some("D:/ci-cache/project".to_string()),
                workspace_root_source: "repository".to_string(),
                workspace_slots: vec![SlotSnapshot {
                    slot: 2,
                    attempt: "00000000-0000-0000-0000-000000000020".to_string(),
                    state: "busy".to_string(),
                    cleanup_blocked: false,
                }],
            }],
        }
    }

    fn emitted() -> Value {
        let mut buffer = Vec::new();
        write_json(&mut buffer, &document()).expect("writing to a Vec");
        serde_json::from_slice(&buffer).expect("the document must be valid JSON")
    }

    fn keys(value: &Value, pointer: &str) -> Vec<String> {
        let at = value
            .pointer(pointer)
            .unwrap_or_else(|| panic!("the document must carry {pointer}"));
        let object = at
            .as_object()
            .unwrap_or_else(|| panic!("{pointer} must be an object, and is {at}"));
        let mut names: Vec<String> = object.keys().cloned().collect();
        names.sort();
        names
    }

    /// The compatibility surface, written out.
    ///
    /// A field removed or renamed fails here, in a diff whose reviewer can see
    /// the whole schema, rather than in a consumer's `jq` some weeks later.
    /// Adding a field is a compatible change and updates this list.
    #[test]
    fn the_documented_schema_is_the_one_that_is_emitted() {
        let emitted = emitted();

        assert_eq!(
            keys(&emitted, ""),
            [
                "budget",
                "credential",
                "generated_at",
                "github_contacted",
                "host",
                "policies",
                "product",
                "schema_version",
            ]
        );
        assert_eq!(keys(&emitted, "/product"), ["name", "version"]);
        assert_eq!(
            keys(&emitted, "/credential"),
            ["present", "store_location", "store_scope", "unreadable"]
        );
        assert_eq!(
            keys(&emitted, "/host"),
            [
                "active_ephemeral_attempts",
                "architecture",
                "capacity",
                "cleanup_blocked_ephemeral_attempts",
                "configured",
                "configured_runner_root",
                "display_name",
                "headroom",
                "id",
                "in_use",
                "os",
                "refresh_interval_secs",
                "runner_root",
                "runner_root_source",
                "runner_root_unavailable",
                "service_start_mode",
            ]
        );
        assert_eq!(
            keys(&emitted, "/budget"),
            [
                "allowance_requests_per_hour",
                "best_case_multiple_when_paging",
                "ceiling_requests_per_hour",
                "exceeds_allowance",
                "headroom_requests_per_hour",
                "interval_secs",
                "max_repository_targets",
                "projected_requests_per_hour",
                "projection_is_floor",
                "refreshes_per_hour",
            ]
        );
        assert_eq!(
            keys(&emitted, "/policies/0"),
            [
                "active_attempts",
                "cleanup_blocked_attempts",
                "enabled",
                "id",
                "max_capacity",
                "min_capacity",
                "mode",
                "routing_labels",
                "scope",
                "state",
                "target",
                "workspace_effective_root",
                "workspace_mode",
                "workspace_root",
                "workspace_root_source",
                "workspace_slots",
            ]
        );
        assert_eq!(
            keys(&emitted, "/policies/0/workspace_slots/0"),
            ["attempt", "cleanup_blocked", "slot", "state"]
        );
    }

    /// The additive compatibility contract [`SCHEMA_VERSION`] documents,
    /// measured in both directions.
    ///
    /// `03-migration-rollout.md` allows "a schema version update **or** an
    /// additive compatibility contract, whichever the existing status schema
    /// tests require". This is that contract: every field a v1 consumer was
    /// promised is still there under its old name, so the version does not move
    /// — and if one of them is ever renamed, this fails and the rename has to
    /// buy itself a version bump.
    #[test]
    fn the_workspace_fields_are_additive_so_the_version_does_not_move() {
        let emitted = emitted();
        let host = keys(&emitted, "/host");
        for field in SCHEMA_V1_HOST_FIELDS {
            assert!(
                host.iter().any(|name| name == field),
                "host.{field} was promised at schema v1 and is gone; that is a breaking \
                 change and needs SCHEMA_VERSION bumped, not this list edited"
            );
        }
        let policy = keys(&emitted, "/policies/0");
        for field in SCHEMA_V1_POLICY_FIELDS {
            assert!(
                policy.iter().any(|name| name == field),
                "policies[].{field} was promised at schema v1 and is gone"
            );
        }
        assert_eq!(
            SCHEMA_VERSION, 1,
            "the workspace fields are additions, and an addition is compatible: a consumer \
             reading only the fields it knows is unaffected"
        );
    }

    /// The workspace surface is structured, not a display string a consumer has
    /// to re-parse — `05-user-workflows.md`, "Status and activity".
    #[test]
    fn the_workspace_fields_are_structured_rather_than_rendered() {
        let emitted = emitted();

        assert_eq!(
            emitted["host"]["runner_root_source"],
            Value::from("platform_default"),
            "the source is a token, not the hyphenated badge `host show` prints"
        );
        assert_eq!(emitted["host"]["configured_runner_root"], Value::Null);
        assert!(emitted["host"]["active_ephemeral_attempts"].is_u64());
        assert!(emitted["host"]["cleanup_blocked_ephemeral_attempts"].is_u64());

        let policy = &emitted["policies"][0];
        assert_eq!(policy["workspace_mode"], Value::from("persistent"));
        assert_eq!(
            policy["workspace_root_source"],
            Value::from("repository"),
            "the third source `d1` names: this repository's own setting, not the host's"
        );
        assert_eq!(
            policy["workspace_root"],
            Value::from("D:/ci-cache/project"),
            "a persistent policy's root is its own, not the host's"
        );
        let slots = policy["workspace_slots"].as_array().expect("an array");
        assert_eq!(slots.len(), 1);
        assert_eq!(
            slots[0]["slot"],
            Value::from(2),
            "the slot is a number, so a consumer never parses `s2`"
        );
        assert!(
            slots[0]["cleanup_blocked"].as_bool().is_some(),
            "quarantine is a boolean, not a state string a consumer has to know the \
             vocabulary of"
        );

        // An ephemeral policy answers with the host root and no slots, so the
        // two shapes are distinguishable without reading a display line.
        let mut ephemeral = document();
        ephemeral.policies[0].workspace_mode = "ephemeral".to_string();
        ephemeral.policies[0].workspace_root = None;
        ephemeral.policies[0].workspace_effective_root = ephemeral.host.runner_root.clone();
        ephemeral.policies[0].workspace_root_source = "platform_default".to_string();
        ephemeral.policies[0].workspace_slots.clear();
        let mut buffer = Vec::new();
        write_json(&mut buffer, &ephemeral).unwrap();
        let value: Value = serde_json::from_slice(&buffer).unwrap();
        assert_eq!(value["policies"][0]["workspace_root"], Value::Null);
        assert_eq!(
            value["policies"][0]["workspace_root_source"], value["host"]["runner_root_source"],
            "an ephemeral policy inherits the host's source, and says which one it is"
        );
        assert_eq!(
            value["policies"][0]["workspace_effective_root"],
            value["host"]["runner_root"]
        );
        assert!(
            value["policies"][0]["workspace_slots"]
                .as_array()
                .expect("an array")
                .is_empty()
        );
    }

    /// No surface lists what is inside a workspace — `d1`: the sources
    /// "identify … without enumerating workspace files".
    #[test]
    fn no_rendering_enumerates_what_is_inside_a_workspace() {
        let mut buffer = Vec::new();
        write_text(&mut buffer, &document()).unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(
            text.contains("persistent attempt in D:/ci-cache/project"),
            "the human rendering names the root: {text}"
        );
        assert!(
            !text.contains("_work"),
            "a status line that named the retained directory would be one step from \
             listing it: {text}"
        );
    }

    /// A store this account may not read is reported, and never as "absent".
    ///
    /// The distinction is the whole point: `absent` sends an operator to `auth
    /// login`, and on a boot-mode macOS host — where the token is in the
    /// root-only System Keychain and the operator is not root — that would
    /// overwrite a credential that was never the problem. `snapshot` used to
    /// fail outright here instead, so the command printed no host, no policies
    /// and no budget either.
    #[test]
    fn an_unreadable_store_is_reported_rather_than_read_as_absent() {
        let mut document = document();
        document.credential.present = false;
        document.credential.unreadable = Some("only root may read /var/db/SystemKey".to_string());

        let mut buffer = Vec::new();
        write_text(&mut buffer, &document).unwrap();
        let text = String::from_utf8(buffer).unwrap();

        assert!(
            text.contains("credential                not readable by this account"),
            "{text}"
        );
        assert!(
            text.contains("credential problem        only root may read /var/db/SystemKey"),
            "the store's own words are what name the remedy: {text}"
        );
        assert!(
            !text.contains("credential                absent"),
            "an unreadable store has not answered the question, and `absent` is the one \
             answer that sends an operator to overwrite it: {text}"
        );
        // And the rest of the snapshot is still there, which is what failing
        // outright used to cost.
        assert!(text.contains("Policies (1)"), "{text}");
    }

    /// The version is in the document, and it is the constant. A schema that
    /// carried no version would leave a consumer nothing to branch on the day
    /// the shape does change.
    #[test]
    fn the_document_carries_its_own_version() {
        assert_eq!(emitted()["schema_version"], Value::from(SCHEMA_VERSION));
    }

    /// A consumer reads it by path and by type, with no special-casing: no
    /// string that has to be re-parsed, no field whose meaning depends on
    /// another.
    #[test]
    fn a_scripted_consumer_reads_it_without_special_casing() {
        let emitted = emitted();

        let capacity = emitted["host"]["capacity"]
            .as_u64()
            .expect("capacity is a number, not a string");
        let in_use = emitted["host"]["in_use"].as_u64().expect("a number");
        assert_eq!(capacity, 2);
        assert_eq!(in_use, 1);
        assert_eq!(
            emitted["host"]["headroom"].as_u64().expect("a number"),
            capacity - in_use,
            "headroom must be derivable and consistent, so a consumer can trust either"
        );

        assert!(
            emitted["credential"]["present"]
                .as_bool()
                .expect("a boolean, so a consumer never string-matches on it")
        );
        assert!(
            !emitted["github_contacted"].as_bool().expect("a boolean"),
            "the document must say plainly that it is a local snapshot"
        );

        let policies = emitted["policies"].as_array().expect("an array");
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0]["target"], Value::from("owner/repo"));
        assert_eq!(policies[0]["max_capacity"], Value::from(1));
        assert!(
            policies[0]["routing_labels"].is_array(),
            "labels are an array, not a comma-separated string a consumer has to split"
        );

        // A monitor-only policy's absent ceiling is `null`, not `0`: zero is a
        // capacity and absence is not.
        let mut monitor_only = document();
        monitor_only.policies[0].max_capacity = None;
        monitor_only.policies[0].mode = "monitor_only".to_string();
        let mut buffer = Vec::new();
        write_json(&mut buffer, &monitor_only).unwrap();
        let value: Value = serde_json::from_slice(&buffer).unwrap();
        assert_eq!(value["policies"][0]["max_capacity"], Value::Null);
    }

    /// The caveat travels with the number it qualifies, in both renderings.
    #[test]
    fn the_target_ceiling_carries_its_caveat_into_both_renderings() {
        assert_eq!(
            emitted()["budget"]["best_case_multiple_when_paging"],
            Value::from(FALLBACK_COST_MULTIPLE),
            "a consumer reading `max_repository_targets` must be able to read the multiple \
             it can be wrong by from the same document"
        );

        let mut buffer = Vec::new();
        write_text(&mut buffer, &document()).unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("best case"), "{text}");
        assert!(
            text.contains(&format!("{FALLBACK_COST_MULTIPLE}x")),
            "{text}"
        );
    }

    /// The document must be JSON at the top level, one object, with nothing
    /// printed around it: a consumer pipes stdout straight into a parser.
    #[test]
    fn nothing_is_printed_around_the_json() {
        let mut buffer = Vec::new();
        write_json(&mut buffer, &document()).unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.starts_with('{'), "got: {text}");
        assert!(
            text.ends_with("}\n"),
            "got the tail: {:?}",
            &text[text.len().saturating_sub(8)..]
        );
        serde_json::from_str::<Value>(&text).expect("parses whole");
    }

    /// Belt and braces over the schema test: no *field* of the document is a
    /// place a credential could be put.
    ///
    /// Scanned over key names rather than over the rendered text, because the
    /// store's location legitimately contains the word `token` on two of the
    /// three platforms — `.../secrets/user-access-token` is a path, not a
    /// value — and a scan that failed on that would be deleted by the next
    /// person who met it. The value-shaped scan over real command output lives
    /// in the integration suite, where the real fixture token exists to look
    /// for.
    #[test]
    fn no_field_of_the_document_is_a_place_to_put_a_credential() {
        fn walk(value: &Value, path: &str, found: &mut Vec<String>) {
            match value {
                Value::Object(fields) => {
                    for (name, child) in fields {
                        let here = format!("{path}/{name}");
                        let lowered = name.to_ascii_lowercase();
                        for forbidden in ["token", "secret", "device_code", "password", "key"] {
                            if lowered.contains(forbidden) {
                                found.push(here.clone());
                            }
                        }
                        walk(child, &here, found);
                    }
                }
                Value::Array(items) => {
                    for (index, child) in items.iter().enumerate() {
                        walk(child, &format!("{path}/{index}"), found);
                    }
                }
                _ => {}
            }
        }

        let mut offenders = Vec::new();
        walk(&emitted(), "", &mut offenders);
        assert!(
            offenders.is_empty(),
            "these fields name a credential, and `f1` requires this document to carry none: \
             {offenders:?}"
        );

        // And the emitted values carry no credential prefix either.
        let mut buffer = Vec::new();
        write_json(&mut buffer, &document()).unwrap();
        let text = String::from_utf8(buffer).unwrap();
        for prefix in ["ghu_", "gho_", "ghs_", "ghp_"] {
            assert!(!text.contains(prefix), "found {prefix:?} in: {text}");
        }
    }
}
