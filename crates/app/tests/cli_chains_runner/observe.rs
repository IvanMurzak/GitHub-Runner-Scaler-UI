// owner: b2-local-chain-runner
//
//! What a step left behind, read back through public interfaces only and
//! rebuilt into the model's own shape.
//!
//! # Why the observation is a `Model`
//!
//! The model predicts a whole next state; the cheapest honest comparison is to
//! reconstruct the same shape from what the product persisted and compare the
//! two field by field. Everything here is read *after* the process exits and
//! from outside it: the public [`Store`] trait over the scenario's SQLite file,
//! the rooted secret store's `load`, and the filesystem. Nothing is read from
//! the command's own output, so a command cannot vouch for itself.
//!
//! # Anomalies
//!
//! Some product states have no spelling in the model: a policy in
//! `authentication_failed`, a root that names no scratch path, a routing host
//! label that is not the derived label of the stored host label, an attempt
//! belonging to a policy this scenario never saw. Those are collected as
//! anomalies rather than forced into a model value, and any anomaly is a
//! store-plane divergence.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use runner_manager_domain::model::PolicyId;
use runner_manager_domain::policy::{PolicyMode, PolicyState as StoredState};
use runner_manager_domain::store::Store;
use runner_manager_platform::secrets::SecretStore;

use crate::cli_chains::action::TargetKey;
use crate::cli_chains::model::{HostModel, Mode, Model, Policy, PolicyState, Tally};
use crate::cli_chains::values::PathValue;

use super::scenario::{DATABASE, OCCUPIED_CONTENTS, Scenario, key_of};

/// The persisted state after one step, in the model's shape.
#[derive(Debug, Clone)]
pub struct ObservedState {
    /// Credential, host, policies, retained diagnostics, directories and the
    /// package cache, as far as the model can spell them.
    pub model: Model,
    /// Store facts the model cannot spell. Any entry is a divergence.
    pub anomalies: Vec<String>,
    /// Confinement findings: something on disk inside the scenario that no
    /// modelled command may leave. Any entry is a divergence.
    pub stray: Vec<String>,
    /// Every path inside the scenario, relative and sorted, except the ones
    /// every process may create or rewrite whatever it does (see `is_churn`).
    /// Compared whole across a refused mutation.
    pub tree: Vec<String>,
}

/// Policy identities seen so far in one scenario, so an attempt whose policy
/// was removed can still be attributed to the target it belonged to.
#[derive(Debug, Clone, Default)]
pub struct Identities {
    known: BTreeMap<String, TargetKey>,
}

impl Identities {
    fn remember(&mut self, id: PolicyId, key: &TargetKey) {
        self.known.insert(id.to_string(), key.clone());
    }

    fn of(&self, id: PolicyId) -> Option<&TargetKey> {
        self.known.get(&id.to_string())
    }
}

/// Reads the scenario back.
///
/// # Errors
/// When a public interface cannot be read at all -- the database or the
/// secret store is unreadable. That is itself a divergence, reported by the
/// caller as one.
pub fn observe(scenario: &Scenario, identities: &mut Identities) -> Result<ObservedState, String> {
    let mut model = Model::fresh(scenario.installation);
    let mut anomalies = Vec::new();

    model.credential = scenario
        .secret_store()?
        .load()
        .map_err(|error| format!("the rooted secret store cannot be read: {error}"))?
        .is_some();

    if let Some(store) = scenario.store()? {
        read_store(scenario, &store, &mut model, &mut anomalies, identities)?;
    }

    for value in PathValue::ALL {
        if value.is_creatable_leaf()
            && scenario
                .resolver
                .absolute(value)
                .is_some_and(|path| path.is_dir())
        {
            model.directories.insert(value);
        }
    }
    model.package_cache = scenario.data.join("state").join("packages").is_dir();

    Ok(ObservedState {
        model,
        anomalies,
        stray: stray_entries(scenario),
        tree: tree(&scenario.root)
            .into_iter()
            .filter(|path| !is_churn(path))
            .collect(),
    })
}

fn read_store(
    scenario: &Scenario,
    store: &dyn Store,
    model: &mut Model,
    anomalies: &mut Vec<String>,
    identities: &mut Identities,
) -> Result<(), String> {
    let hosts = store
        .hosts()
        .map_err(|error| format!("cannot read hosts: {error}"))?;
    if hosts.len() > 1 {
        anomalies.push(format!(
            "{} host rows are stored; one data root holds one",
            hosts.len()
        ));
    }
    if let Some(host) = hosts.first() {
        let runner_root = host.runner_root_override.as_ref().and_then(|root| {
            let found = scenario.resolver.identify(root.as_str());
            if found.is_none() {
                anomalies.push(format!(
                    "the host runner root {} names no scratch path",
                    root.as_str()
                ));
            }
            found
        });
        model.host = Some(HostModel {
            capacity: host.host_capacity.get(),
            runner_root,
        });
    }

    let policies = store
        .policies()
        .map_err(|error| format!("cannot read policies: {error}"))?;
    let mut live: BTreeMap<String, TargetKey> = BTreeMap::new();
    for policy in &policies {
        let key = key_of(&policy.target);
        identities.remember(policy.id, &key);
        live.insert(policy.id.to_string(), key.clone());
        let host_label = policy.requested_host_label.as_str().to_string();
        let mode = match policy.mode() {
            PolicyMode::MonitorOnly => Mode::MonitorOnly,
            PolicyMode::Autoscale(_) => {
                let labels = policy
                    .routing_labels()
                    .expect("an autoscale policy has routing labels");
                let derived = scenario
                    .resolver
                    .symbolic_label(labels.host_label().as_str());
                let expected = crate::cli_chains::values::derived_symbol(&host_label);
                if derived != expected {
                    anomalies.push(format!(
                        "{key}: the routing host label is {derived}, not the derived {expected}"
                    ));
                }
                Mode::Autoscale {
                    max_capacity: policy.max_capacity().map_or(0, std::num::NonZeroU16::get),
                    extra_labels: labels
                        .additional()
                        .map(|label| scenario.resolver.symbolic_label(label.as_str()))
                        .collect::<BTreeSet<String>>(),
                }
            }
        };
        if policy.min_capacity() != 0 {
            anomalies.push(format!(
                "{key}: min capacity {} (the CLI never sets one)",
                policy.min_capacity()
            ));
        }
        let state = match policy.state() {
            StoredState::Pending => PolicyState::Pending,
            StoredState::Active => PolicyState::Active,
            StoredState::Draining => PolicyState::Draining,
            StoredState::Disabled => PolicyState::Disabled,
            StoredState::RepairRequired => PolicyState::RepairRequired,
            StoredState::AuthenticationFailed => {
                anomalies.push(format!("{key}: authentication_failed has no local road in"));
                PolicyState::Pending
            }
        };
        let workspace = policy.workspace_policy().root().and_then(|root| {
            let found = scenario.resolver.identify(root.as_str());
            if found.is_none() {
                anomalies.push(format!(
                    "{key}: the persistent root {} names no scratch path",
                    root.as_str()
                ));
            }
            found
        });
        if model.policies.contains_key(&key) {
            anomalies.push(format!("{key} is stored twice"));
        }
        model.policies.insert(
            key,
            Policy {
                display: policy.target.slug(),
                host_label,
                mode,
                enabled: policy.enabled(),
                state,
                workspace,
                attempts: Tally::default(),
            },
        );
    }

    let attempts = store
        .attempts()
        .map_err(|error| format!("cannot read the attempt journal: {error}"))?;
    for attempt in attempts {
        let state = attempt.state();
        let tally = |tally: &mut Tally| {
            if !state.is_terminal() {
                tally.active += 1;
            } else if state == runner_manager_domain::attempt::AttemptState::Cleaned {
                tally.cleaned += 1;
            } else {
                tally.awaiting_cleanup += 1;
            }
        };
        if let Some(key) = live.get(&attempt.policy_id.to_string()) {
            if let Some(policy) = model.policies.get_mut(key) {
                tally(&mut policy.attempts);
            }
        } else if let Some(key) = identities.of(attempt.policy_id) {
            tally(model.retained.entry(key.clone()).or_default());
        } else {
            anomalies.push(format!(
                "attempt {} belongs to policy {}, which this scenario never saw",
                attempt.id, attempt.policy_id
            ));
        }
    }
    Ok(())
}

/// Everything inside the scenario that no modelled command may leave.
///
/// * The scenario directory holds `data`, `roots` and `cwd` and nothing else,
///   so nothing was written beside the roots it was given.
/// * The child's working directory stays empty, so a relative path was never
///   resolved against it.
/// * `<roots>` holds `occupied.txt`, unchanged, and at most the three
///   creatable scratch directories.
/// * `<data>/state/rman` never exists: it is the inside-application-data value
///   every root command must refuse.
#[must_use]
pub fn stray_entries(scenario: &Scenario) -> Vec<String> {
    let mut stray = Vec::new();
    for entry in names(&scenario.root) {
        if !matches!(entry.as_str(), "data" | "roots" | "cwd") {
            stray.push(format!("<scenario>/{entry} was created"));
        }
    }
    for entry in names(&scenario.cwd) {
        stray.push(format!("<cwd>/{entry} was created"));
    }
    let occupied = scenario.roots.join("occupied.txt");
    match std::fs::read_to_string(&occupied) {
        Ok(text) if text == OCCUPIED_CONTENTS && occupied.is_file() => {}
        Ok(_) => stray.push("<roots>/occupied.txt was rewritten".to_string()),
        Err(error) => stray.push(format!("<roots>/occupied.txt is gone: {error}")),
    }
    let allowed: BTreeSet<&str> = ["occupied.txt", "alpha", "beta", "alpha/inner"].into();
    for entry in tree(&scenario.roots) {
        if !allowed.contains(entry.as_str()) {
            stray.push(format!("<roots>/{entry} was created"));
        }
    }
    if scenario.data.join("state").join("rman").exists() {
        stray.push("<data>/state/rman was created".to_string());
    }
    stray.sort();
    stray
}

/// Paths every invocation may touch regardless of what it does: the data root
/// and the four application-data directories the composition root creates
/// before routing any command (reads included), the database file, which any
/// command that opens the store (`status`, `host show` and `list` included)
/// creates empty, the operator log inside `logs/`, and SQLite's own sidecar
/// files. Their *contents* still count, except the log's: the database's
/// through the public `Store` projection every observation carries, so an
/// empty store and an absent one are the same modelled state and anything a
/// command wrote into it is not.
fn is_churn(path: &str) -> bool {
    matches!(
        path,
        "data" | "data/config" | "data/state" | "data/runtime" | "data/logs"
    ) || path
        .strip_prefix("data/")
        .is_some_and(|inside| inside.split('/').eq(DATABASE))
        || path.starts_with("data/logs/")
        || path.ends_with("-wal")
        || path.ends_with("-shm")
        || path.ends_with("-journal")
}

/// The names directly inside a directory, sorted.
fn names(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(directory)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// Every path under a directory, relative and `/`-separated, sorted.
fn tree(directory: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut pending = vec![(directory.to_path_buf(), String::new())];
    while let Some((path, prefix)) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            if entry.path().is_dir() {
                pending.push((entry.path(), relative.clone()));
            }
            found.push(relative);
        }
    }
    found.sort();
    found
}
