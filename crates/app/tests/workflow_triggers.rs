// owner: a1-workspace-ci-foundation
//
// Two of this repository's release-acceptance checks are one-line properties of
// a YAML file, which is exactly the kind of property that regresses silently:
//
//   * "release.yml contains exactly one trigger, workflow_dispatch"
//   * "ci.yml runs on pull-request open/synchronize/reopen and on push to
//     main, and contains no release trigger"
//
// (`.taskflow/2026-08-21-local-runner-manager/09-release-distribution.md`,
// Acceptance evidence; `07-security.md`, operational requirement 7.)
//
// Asserting them here makes them fail a pull request rather than a release
// rehearsal. a2 rewrites release.yml's steps and a3 adds one more; neither
// changes the trigger block, so neither should make this file fail.
//
// This file belongs to a1 and to the A group. It is not part of the CLI
// (group F) or TUI (group G) conflict domains.

use std::path::{Path, PathBuf};

fn workflow_path(name: &str) -> PathBuf {
    // crates/app -> repository root.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(".github")
        .join("workflows")
        .join(name)
}

fn read_workflow(name: &str) -> String {
    let path = workflow_path(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()))
}

/// The keys directly under the top-level `on:` block, in file order.
///
/// Deliberately a small scanner rather than a YAML dependency: the shape being
/// asserted is two levels deep, and a test that guards the dependency policy
/// should not itself need a new dependency.
fn triggers(source: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut inside_on_block = false;

    for line in source.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.trim_start().starts_with('#') {
            continue;
        }

        if !inside_on_block {
            if line == "on:" {
                inside_on_block = true;
            }
            continue;
        }

        // The block ends at the next key in column zero.
        let Some(indented) = line.strip_prefix("  ") else {
            break;
        };
        // Anything deeper than one level belongs to a trigger, not to `on:`.
        if indented.starts_with(' ') {
            continue;
        }
        if let Some((key, _)) = indented.split_once(':') {
            found.push(key.to_string());
        }
    }

    assert!(
        inside_on_block,
        "no top-level `on:` block found; the scanner is looking at the wrong thing"
    );
    found
}

#[test]
fn release_workflow_has_exactly_one_trigger() {
    let source = read_workflow("release.yml");

    assert_eq!(
        triggers(&source),
        vec!["workflow_dispatch".to_string()],
        "release.yml must have exactly one trigger. A `push`, `tag`, `schedule`, \
         or `release` trigger would make the only credential able to publish \
         run automatically, which D10 forbids."
    );

    assert!(
        source.contains("contents: write"),
        "release.yml must request the minimum permission needed to publish"
    );
}

#[test]
fn ci_workflow_triggers_on_pull_requests_and_pushes_to_main_only() {
    let source = read_workflow("ci.yml");

    assert_eq!(
        triggers(&source),
        vec!["pull_request".to_string(), "push".to_string()],
        "ci.yml must trigger on pull_request and push only, and must never \
         acquire a release trigger"
    );

    for event_type in ["opened", "synchronize", "reopened"] {
        assert!(
            source.contains(event_type),
            "ci.yml must run on pull-request `{event_type}`"
        );
    }
    assert!(
        source.contains("branches: [main]"),
        "ci.yml must run on push to `main`"
    );
}

#[test]
fn ci_workflow_defines_an_e2e_job_with_the_fixed_acceptance_command() {
    let source = read_workflow("ci.yml");

    assert!(
        source.contains("cargo test -p runner-manager-e2e -- --ignored"),
        "the e2e job's command is fixed here so that h1 fills the acceptance \
         suite in without ever editing this workflow"
    );
    assert!(
        source.contains("steps.guard.outputs.enabled == 'true'"),
        "the e2e job must be guarded by a step output rather than run \
         unconditionally, so that it skips instead of failing when its secret \
         is absent"
    );
}
