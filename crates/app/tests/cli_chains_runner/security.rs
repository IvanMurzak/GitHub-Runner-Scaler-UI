// owner: b3-local-corpus-security
//
//! Secret scanning for every local-chain transition.
//!
//! Output is scanned at the transition that produced it. Persistent planes
//! (logs, the temporary tree, and a textual dump of every SQLite column) are
//! rescanned after each transition, so the first leak becomes the first
//! divergence and carries the ordinary replay report.

use std::path::Path;

use runner_manager_domain::store::SqliteStore;

use crate::support::{
    file_contains, files_under, fixture_device_code, fixture_token, is_the_secret_store,
};

use super::scenario::{Invocation, Scenario};

/// A deliberately content-free value that production has no reason to emit.
#[must_use]
pub fn explicit_canary() -> String {
    format!("{}{}", "cli-chains-protected-", "canary-71d3e9b4")
}

/// Every value whose disclosure the suite rejects.
#[must_use]
pub fn protected_values() -> Vec<(&'static str, String)> {
    vec![
        ("fixture token", fixture_token()),
        ("fixture device code", fixture_device_code()),
        (
            "fixture JIT configuration",
            runner_manager_testkit::github::DEFAULT_JIT_CONFIG.to_string(),
        ),
        ("explicit canary", explicit_canary()),
    ]
}

/// A plane named separately so the controls prove that none is accidentally
/// omitted from collection or matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityPlane {
    Stdout,
    Stderr,
    Logs,
    DataTree,
    SqliteDump,
}

impl SecurityPlane {
    pub const ALL: [Self; 5] = [
        Self::Stdout,
        Self::Stderr,
        Self::Logs,
        Self::DataTree,
        Self::SqliteDump,
    ];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
            Self::Logs => "logs",
            Self::DataTree => "temporary data tree",
            Self::SqliteDump => "SQLite textual dump",
        }
    }
}

/// One scanned artifact.
#[derive(Debug, Clone)]
pub struct Fragment {
    pub plane: SecurityPlane,
    pub origin: String,
    pub text: String,
}

/// Every protected value found in `fragments`.
#[must_use]
pub fn findings(fragments: &[Fragment]) -> Vec<String> {
    let mut found = Vec::new();
    for (name, needle) in protected_values() {
        for fragment in fragments {
            if fragment.text.contains(&needle) {
                found.push(format!(
                    "{name} appears in {} ({})",
                    fragment.origin,
                    fragment.plane.name()
                ));
            }
        }
    }
    found
}

/// Collects every security plane after one transition.
pub fn collect(
    scenario: &Scenario,
    invocation: Option<&Invocation>,
) -> Result<Vec<Fragment>, String> {
    let mut fragments = Vec::new();
    if let Some(invocation) = invocation {
        fragments.push(Fragment {
            plane: SecurityPlane::Stdout,
            origin: "the action's stdout".to_string(),
            text: invocation.stdout.clone(),
        });
        fragments.push(Fragment {
            plane: SecurityPlane::Stderr,
            origin: "the action's stderr".to_string(),
            text: invocation.stderr.clone(),
        });
    }

    for path in files_under(&scenario.data) {
        if is_the_secret_store(&path) {
            // A rooted platform secret store is the one approved persistence
            // location for the fixture token. Every other file is scanned.
            continue;
        }
        let relative = path.strip_prefix(&scenario.data).unwrap_or(&path);
        let plane = if relative.starts_with(Path::new("logs")) {
            SecurityPlane::Logs
        } else {
            SecurityPlane::DataTree
        };
        for (name, needle) in protected_values() {
            if file_contains(&path, &needle) {
                fragments.push(Fragment {
                    plane,
                    origin: path.display().to_string(),
                    // Retain only the needle. This is enough for `findings`
                    // and avoids loading arbitrary binary database bytes as
                    // lossy text.
                    text: format!("{name}:{needle}"),
                });
            }
        }
    }

    if let Some(store) = scenario.store()? {
        fragments.push(Fragment {
            plane: SecurityPlane::SqliteDump,
            origin: "SqliteStore::dump_text()".to_string(),
            text: dump(&store)?,
        });
    }
    Ok(fragments)
}

fn dump(store: &SqliteStore) -> Result<String, String> {
    store
        .dump_text()
        .map_err(|error| format!("cannot dump SQLite for the security scan: {error}"))
}
