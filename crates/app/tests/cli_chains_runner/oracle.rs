// owner: b2-local-chain-runner
//
//! Expectation against observation, plane by plane.
//!
//! `02-target-architecture.md`, "After every action, the oracle compares":
//! the exit code and the stable semantic fields of stdout/stderr; the read
//! views where the action is one; persisted state through the public `Store`;
//! filesystem existence beneath the scenario's roots; and the fake GitHub's
//! request history. Each of those is a [`Plane`], and every divergence names
//! the plane it was found on so a failure says *what* disagreed as well as
//! *where*.
//!
//! The expectation is always computed by the model **before** the process
//! runs (see `run.rs`), so nothing here can be satisfied by the product
//! agreeing with itself.
//!
//! Human prose is checked for the model's semantic fragments, not whole
//! snapshots. The two machine-shaped reads are compared field by field:
//! `status --json` against the model's status projection, and the policy rows
//! of `repo list` / `org list` as a set against the model's list lines.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde_json::Value;

use crate::cli_chains::action::Action;
use crate::cli_chains::model::{Model, StatusProjection};
use crate::cli_chains::transition::Transition;
use crate::cli_chains::values::PathValue;

use super::observe::ObservedState;
use super::scenario::{Invocation, RealResolver};

/// Where a divergence was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Plane {
    /// The process exit code.
    Exit,
    /// Stdout/stderr fragments and the semantic read views.
    Output,
    /// Credential presence, the host record, policies and retained
    /// diagnostics, read through the public `Store` and the secret store.
    Store,
    /// Scratch directories, the package cache, and confinement inside the
    /// scenario.
    Filesystem,
    /// The fake GitHub's request history for this step.
    Requests,
    /// Protected values in output, logs, files, or a SQLite textual dump.
    Security,
}

impl Plane {
    /// Behavioral expectation planes. Security has its own protected-value by
    /// scanned-plane mutation matrix.
    pub const ALL: [Plane; 5] = [
        Plane::Exit,
        Plane::Output,
        Plane::Store,
        Plane::Filesystem,
        Plane::Requests,
    ];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Plane::Exit => "exit",
            Plane::Output => "output",
            Plane::Store => "store",
            Plane::Filesystem => "filesystem",
            Plane::Requests => "requests",
            Plane::Security => "security",
        }
    }
}

impl fmt::Display for Plane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One divergence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    pub plane: Plane,
    pub detail: String,
}

impl Mismatch {
    fn new(plane: Plane, detail: impl Into<String>) -> Self {
        Self {
            plane,
            detail: detail.into(),
        }
    }

    /// A protected value reached a scanned artifact.
    #[must_use]
    pub fn security(detail: impl Into<String>) -> Self {
        Self::new(Plane::Security, detail)
    }
}

/// Judges one executed action.
#[must_use]
pub fn judge_action(
    action: &Action,
    before: &Model,
    expected: &Transition,
    invocation: &Invocation,
    observed: &Result<ObservedState, String>,
    resolver: &RealResolver,
) -> Vec<Mismatch> {
    let mut found = Vec::new();

    if invocation.code != expected.exit.code() {
        found.push(Mismatch::new(
            Plane::Exit,
            format!(
                "expected {}, observed exit code {}",
                expected.exit.describe(),
                invocation.code
            ),
        ));
    }

    for (stream, fragments, text) in [
        ("stdout", &expected.stdout, &invocation.stdout),
        ("stderr", &expected.stderr, &invocation.stderr),
    ] {
        for fragment in fragments {
            let fragment = resolver.resolve_text(fragment);
            if !text.contains(&fragment) {
                found.push(Mismatch::new(
                    Plane::Output,
                    format!("{stream} lacks the fragment {fragment:?}"),
                ));
            }
        }
    }
    found.extend(
        read_view(action, before, &invocation.stdout, resolver)
            .into_iter()
            .map(|detail| Mismatch::new(Plane::Output, detail)),
    );

    found.extend(judge_state(&expected.next, observed));

    let requests: Vec<String> = expected
        .requests
        .iter()
        .map(|request| request.render())
        .collect();
    if invocation.requests != requests {
        found.push(Mismatch::new(
            Plane::Requests,
            format!(
                "expected requests {requests:?}, the fake GitHub saw {:?}",
                invocation.requests
            ),
        ));
    }
    found
}

/// Judges persisted state alone: after a seed, and as part of every action.
#[must_use]
pub fn judge_state(expected: &Model, observed: &Result<ObservedState, String>) -> Vec<Mismatch> {
    let observed = match observed {
        Ok(observed) => observed,
        Err(problem) => {
            return vec![Mismatch::new(
                Plane::Store,
                format!("the persisted state could not be read: {problem}"),
            )];
        }
    };
    let mut found: Vec<Mismatch> = store_differences(expected, &observed.model)
        .into_iter()
        .chain(
            observed
                .anomalies
                .iter()
                .map(|anomaly| format!("unmodelled store state: {anomaly}")),
        )
        .map(|detail| Mismatch::new(Plane::Store, detail))
        .collect();
    found.extend(
        filesystem_differences(expected, &observed.model)
            .into_iter()
            .chain(observed.stray.iter().cloned())
            .map(|detail| Mismatch::new(Plane::Filesystem, detail)),
    );
    found
}

/// The store-plane fields: credential, host record, policies, retained
/// diagnostics.
fn store_differences(expected: &Model, observed: &Model) -> Vec<String> {
    let mut found = Vec::new();
    if expected.credential != observed.credential {
        found.push(format!(
            "credential present: expected {}, observed {}",
            expected.credential, observed.credential
        ));
    }
    if expected.host != observed.host {
        found.push(format!(
            "host record: expected {:?}, observed {:?}",
            expected.host, observed.host
        ));
    }
    let keys: BTreeSet<_> = expected
        .policies
        .keys()
        .chain(observed.policies.keys())
        .collect();
    for key in keys {
        match (expected.policies.get(key), observed.policies.get(key)) {
            (Some(want), Some(have)) if want != have => {
                found.push(format!(
                    "policy {key}: expected {want:?}, observed {have:?}"
                ));
            }
            (Some(_), None) => found.push(format!("policy {key}: expected, but not stored")),
            (None, Some(have)) => {
                found.push(format!("policy {key}: stored but not expected: {have:?}"))
            }
            _ => {}
        }
    }
    if expected.retained != observed.retained {
        found.push(format!(
            "retained diagnostics: expected {:?}, observed {:?}",
            expected.retained, observed.retained
        ));
    }
    found
}

/// The filesystem-plane fields: scratch directories and the package cache.
fn filesystem_differences(expected: &Model, observed: &Model) -> Vec<String> {
    let mut found = Vec::new();
    if expected.directories != observed.directories {
        found.push(format!(
            "scratch directories: expected {:?}, observed {:?}",
            expected.directories, observed.directories
        ));
    }
    if expected.package_cache != observed.package_cache {
        found.push(format!(
            "package cache present: expected {}, observed {}",
            expected.package_cache, observed.package_cache
        ));
    }
    found
}

/// The semantic comparison of a read's machine-shaped output.
fn read_view(
    action: &Action,
    before: &Model,
    stdout: &str,
    resolver: &RealResolver,
) -> Vec<String> {
    match action {
        Action::StatusJson => match serde_json::from_str::<Value>(stdout) {
            Ok(document) => status_differences(&before.status(), &document, resolver),
            Err(error) => vec![format!("status --json is not JSON: {error}")],
        },
        Action::List(scope) => {
            let expected: BTreeSet<String> = before.list_lines(*scope).into_iter().collect();
            let observed: BTreeSet<String> = stdout
                .lines()
                .filter(|line| line.contains("\tenabled="))
                .map(str::to_string)
                .collect();
            if expected == observed {
                Vec::new()
            } else {
                vec![format!(
                    "{} list rows: expected {expected:?}, observed {observed:?}",
                    scope.word()
                )]
            }
        }
        _ => Vec::new(),
    }
}

/// `status --json` against the model's projection, field by field.
#[allow(
    clippy::too_many_lines,
    reason = "one flat field-by-field comparison reads best whole"
)]
fn status_differences(
    expected: &StatusProjection,
    document: &Value,
    resolver: &RealResolver,
) -> Vec<String> {
    let mut found = Vec::new();
    let mut field = |path: &str, want: Value| {
        let have = path
            .split('.')
            .fold(document, |value, segment| &value[segment]);
        if *have != want {
            found.push(format!("status.{path}: expected {want}, observed {have}"));
        }
    };
    field(
        "credential.present",
        Value::from(expected.credential_present),
    );
    field("credential.unreadable", Value::Null);
    field("host.configured", Value::from(expected.host_configured));
    field("host.capacity", Value::from(expected.capacity));
    field("host.in_use", Value::from(expected.in_use));
    field("host.headroom", Value::from(expected.headroom));
    field(
        "host.runner_root_source",
        Value::from(expected.runner_root_source),
    );
    field(
        "host.active_ephemeral_attempts",
        Value::from(expected.active_ephemeral_attempts),
    );
    field(
        "host.cleanup_blocked_ephemeral_attempts",
        Value::from(expected.cleanup_blocked_ephemeral_attempts),
    );
    field(
        "budget.projected_requests_per_hour",
        Value::from(expected.projected_requests_per_hour),
    );
    field(
        "budget.projection_is_floor",
        Value::from(expected.projection_is_floor),
    );
    field("github_contacted", Value::from(false));

    let configured = document["host"]["configured_runner_root"].as_str();
    if let Some(problem) = path_difference(
        "status.host.configured_runner_root",
        expected.configured_runner_root,
        configured,
        resolver,
    ) {
        found.push(problem);
    }

    let empty = Vec::new();
    let reported = document["policies"].as_array().unwrap_or(&empty);
    let observed: BTreeMap<(String, String), &Value> = reported
        .iter()
        .map(|policy| {
            (
                (
                    policy["scope"].as_str().unwrap_or_default().to_string(),
                    policy["target"]
                        .as_str()
                        .unwrap_or_default()
                        .to_ascii_lowercase(),
                ),
                policy,
            )
        })
        .collect();
    if observed.len() != reported.len() {
        found.push(format!(
            "status.policies holds {} entries for {} distinct targets",
            reported.len(),
            observed.len()
        ));
    }
    let wanted: BTreeMap<(String, String), _> = expected
        .policies
        .iter()
        .map(|policy| {
            (
                (policy.scope.to_string(), policy.target.to_ascii_lowercase()),
                policy,
            )
        })
        .collect();
    let keys: BTreeSet<_> = wanted.keys().chain(observed.keys()).cloned().collect();
    for key in keys {
        let label = format!("status.policies[{}:{}]", key.0, key.1);
        let (Some(want), Some(have)) = (wanted.get(&key), observed.get(&key)) else {
            let (present, absent) = if wanted.contains_key(&key) {
                ("expected", "reported")
            } else {
                ("reported", "expected")
            };
            found.push(format!("{label}: {present} but not {absent}"));
            continue;
        };
        let mut compare = |name: &str, want: Value| {
            if have[name] != want {
                found.push(format!(
                    "{label}.{name}: expected {want}, observed {}",
                    have[name]
                ));
            }
        };
        compare("target", Value::from(want.target.clone()));
        compare("mode", Value::from(want.mode));
        compare("state", Value::from(want.state));
        compare("enabled", Value::from(want.enabled));
        compare("min_capacity", Value::from(want.min_capacity));
        compare(
            "max_capacity",
            want.max_capacity.map_or(Value::Null, Value::from),
        );
        compare("active_attempts", Value::from(want.active_attempts));
        compare(
            "cleanup_blocked_attempts",
            Value::from(want.cleanup_blocked_attempts),
        );
        compare("workspace_mode", Value::from(want.workspace_mode));
        compare(
            "workspace_root_source",
            Value::from(want.workspace_root_source),
        );
        if let Some(problem) = path_difference(
            &format!("{label}.workspace_root"),
            want.workspace_root,
            have["workspace_root"].as_str(),
            resolver,
        ) {
            found.push(problem);
        }
        let labels: Vec<String> = have["routing_labels"]
            .as_array()
            .map(|labels| {
                labels
                    .iter()
                    .map(|label| resolver.symbolic_label(label.as_str().unwrap_or_default()))
                    .collect()
            })
            .unwrap_or_default();
        if !same_routing_labels(&want.routing_labels, &labels) {
            found.push(format!(
                "{label}.routing_labels: expected {:?}, observed {labels:?}",
                want.routing_labels
            ));
        }
    }
    found
}

/// The derived label first, then the optional labels in any order.
fn same_routing_labels(expected: &[String], observed: &[String]) -> bool {
    match (expected.split_first(), observed.split_first()) {
        (None, None) => true,
        (Some((want_first, want_rest)), Some((have_first, have_rest))) => {
            let want: BTreeSet<&String> = want_rest.iter().collect();
            let have: BTreeSet<&String> = have_rest.iter().collect();
            want_first == have_first && want == have && want_rest.len() == have_rest.len()
        }
        _ => false,
    }
}

/// A reported path against a modelled one.
fn path_difference(
    what: &str,
    expected: Option<PathValue>,
    reported: Option<&str>,
    resolver: &RealResolver,
) -> Option<String> {
    let observed = reported.map(|text| resolver.identify(text).ok_or(text));
    match (expected, observed) {
        (None, None) => None,
        (Some(want), Some(Ok(have))) if want == have => None,
        (want, have) => Some(format!(
            "{what}: expected {:?}, observed {:?}",
            want.map(PathValue::symbolic),
            have.map(|found| found.map(PathValue::symbolic))
        )),
    }
}
