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
pub const SCHEMA_VERSION: u32 = 1;

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
}

impl PolicySnapshot {
    fn of(policy: &ScalePolicy, active_attempts: u16) -> Self {
        Self {
            id: policy.id.to_string(),
            target: policy.target.slug(),
            scope: match policy.target.scope() {
                runner_manager_domain::model::TargetScope::Repository => "repository",
                runner_manager_domain::model::TargetScope::Organization => "organization",
            }
            .to_string(),
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
    let present = secrets
        .load()
        .map_err(|source| {
            CliError::with_remedy(
                Failure::SecretStore,
                format!("cannot read the secret store: {source}"),
                "runner-manager auth logout, then runner-manager auth login",
            )
        })?
        .is_some();

    let targets: Vec<_> = policies.iter().map(|p| p.target.clone()).collect();
    let budget = HostBudget::of(interval, &targets);

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
            .map(|policy| PolicySnapshot::of(policy, active_count_for(policy.id, attempts.iter())))
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
        "  credential                {} in the {}-scoped store",
        if document.credential.present {
            "present"
        } else {
            "absent"
        },
        document.credential.store_scope
    )?;
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
            ["present", "store_location", "store_scope"]
        );
        assert_eq!(
            keys(&emitted, "/host"),
            [
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
                "enabled",
                "id",
                "max_capacity",
                "min_capacity",
                "mode",
                "routing_labels",
                "scope",
                "state",
                "target",
            ]
        );
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
