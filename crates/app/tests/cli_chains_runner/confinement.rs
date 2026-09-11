// owner: b2-local-chain-runner
//
//! Proof that the chains never reached anything outside their scenarios.
//!
//! `02-target-architecture.md`: every scenario "may not read or mutate a
//! developer's standard data directories, credential store, service
//! registration, or network." The runner makes that true by construction --
//! `--data-dir` on every process, a loopback fake GitHub, a per-case service
//! fixture tag -- and this module turns each of those constructions into an
//! observation that can fail.
//!
//! # Two kinds of evidence
//!
//! *Per invocation* ([`invocation_problems`]): the recorded argument vector
//! starts with the scenario's own `--data-dir`, only allowlisted command leaves
//! were run, the product itself announced that it was talking to the case's
//! loopback fixture rather than GitHub, and the service identity the case's tag
//! selects is a disposable fixture that can never name the product's
//! registration.
//!
//! *Around a whole run* ([`StandardFootprint`]): the platform-standard
//! application-data directories, database, service install record and secret
//! store locations -- resolved by the product's own `platform` crate, exactly as
//! the binary would resolve them without `--data-dir` -- are snapshotted before
//! and after. A location that did not exist before must not exist after.
//!
//! A location that already existed is reported but not judged: on a developer
//! workstation with the product installed, a running daemon legitimately
//! writes its own logs and database, and a check that failed on that would
//! fail for the one person least likely to be running the suite wrongly. On a
//! CI runner nothing exists beforehand, so there the check is total.

use std::collections::BTreeSet;
use std::path::PathBuf;

use runner_manager_platform::paths::AppPaths;
use runner_manager_platform::runner_root::default_runner_root;
use runner_manager_platform::secrets::{PlatformSecretStore, SecretScope};
use runner_manager_platform::service::ServiceIdentity;

use crate::cli_chains::action::ActionKind;

use super::run::CaseRun;

/// The standard locations, and which of them existed when snapshotted.
#[derive(Debug, Clone)]
pub struct StandardFootprint {
    /// `(what, where, existed)`.
    pub locations: Vec<(String, PathBuf, bool)>,
}

impl StandardFootprint {
    /// Resolves and inspects every standard location. Touches nothing.
    #[must_use]
    pub fn snapshot() -> Self {
        let mut locations: Vec<(String, PathBuf)> = Vec::new();
        if let Ok(paths) = AppPaths::discover() {
            for (name, path) in paths.all() {
                locations.push((format!("standard {name} directory"), path.to_path_buf()));
            }
            locations.push((
                "standard database".to_string(),
                paths.config_dir().join("runner-manager.sqlite3"),
            ));
            locations.push((
                "standard service install record".to_string(),
                paths.config_dir().join("service.toml"),
            ));
            // Where an ephemeral attempt goes when no root is configured:
            // `<system-drive>\rman` on Windows, the standard runtime directory
            // elsewhere. Every chain that never configures a root runs with
            // this as its effective root, so it is the one standard location a
            // chain could plausibly create by accident.
            if let Ok(root) = default_runner_root(&paths) {
                locations.push((
                    "platform-default runner root".to_string(),
                    root.as_path().to_path_buf(),
                ));
            }
        }
        for scope in [SecretScope::Machine, SecretScope::User] {
            if let Ok(store) = PlatformSecretStore::standard(scope) {
                locations.push((
                    format!("standard {scope}-scoped secret store"),
                    store.guard(),
                ));
            }
        }
        Self {
            locations: locations
                .into_iter()
                .map(|(what, path)| {
                    let existed = path.exists();
                    (what, path, existed)
                })
                .collect(),
        }
    }

    /// Every location that was absent in `self` and is present now.
    #[must_use]
    pub fn appeared_since(&self) -> Vec<String> {
        self.locations
            .iter()
            .filter(|(_, path, existed)| !existed && path.exists())
            .map(|(what, path, _)| format!("{what} {} appeared", path.display()))
            .collect()
    }
}

/// The per-invocation confinement evidence of one case run.
#[must_use]
pub fn invocation_problems(run: &CaseRun<'_>) -> Vec<String> {
    let mut problems = Vec::new();
    let data = run.resolver.data.to_string_lossy().into_owned();
    let allowed: BTreeSet<[&str; 2]> = ActionKind::ALL
        .iter()
        .map(|kind| kind.command_path())
        .collect();
    for invocation in run.invocations() {
        let argv = &invocation.argv;
        if argv.len() < 4 || argv[0] != "--data-dir" || argv[1] != data {
            problems.push(format!(
                "{argv:?} does not start with this scenario's --data-dir {data}"
            ));
            continue;
        }
        let leaf = [argv[2].as_str(), argv[3].as_str()];
        if !allowed.contains(&leaf) {
            problems.push(format!("{argv:?} runs a command outside the allowlist"));
        }
        // The product's own announcement, printed by the composition root
        // before any command is routed and only once it has refused every
        // override that is not loopback: the endpoint this process would have
        // talked to was this case's fixture.
        let announcement = format!("talking to {} instead of GitHub", run.github_base);
        if !invocation.stderr.contains(&announcement) {
            problems.push(format!(
                "{argv:?} did not report talking to the case's loopback fixture {}",
                run.github_base
            ));
        }
    }
    let identity = ServiceIdentity::fixture(&run.service_tag);
    if !identity.is_fixture() || identity.name() == ServiceIdentity::product().name() {
        problems.push(format!(
            "the service tag {} selects {}, which is not a disposable fixture",
            run.service_tag,
            identity.name()
        ));
    }
    if !run.service_tag.contains(&run.case.id.to_string()) {
        problems.push(format!(
            "the service tag {} does not name its case",
            run.service_tag
        ));
    }
    problems
}
