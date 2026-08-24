//! Guards the JavaScript runtimes of every external action used by CI.
//!
//! GitHub deprecates the Node runtime embedded in actions independently of the
//! Node version installed by a workflow. Keep this inventory exhaustive so a
//! newly added action cannot silently reintroduce a deprecated runtime.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

fn workflows_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(".github")
        .join("workflows")
}

fn workflow_paths() -> Vec<PathBuf> {
    let directory = workflows_directory();
    let mut paths: Vec<PathBuf> = fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()))
        .map(|entry| {
            entry
                .unwrap_or_else(|error| {
                    panic!("failed to inspect {}: {error}", directory.display())
                })
                .path()
        })
        .filter(|path| {
            path.is_file()
                && matches!(
                    path.extension().and_then(|extension| extension.to_str()),
                    Some("yml" | "yaml")
                )
        })
        .collect();
    paths.sort();
    paths
}

fn external_action_refs() -> Vec<(String, String)> {
    let mut refs = Vec::new();

    for path in workflow_paths() {
        let workflow = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_else(|| panic!("workflow path has no UTF-8 file name: {}", path.display()));
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));

        for line in source.lines() {
            let trimmed = line.trim_start();
            let value = trimmed
                .strip_prefix("uses: ")
                .or_else(|| trimmed.strip_prefix("- uses: "));

            if let Some(action_ref) = value.filter(|value| !value.starts_with("./")) {
                refs.push((workflow.to_owned(), action_ref.trim().to_string()));
            }
        }
    }

    refs
}

#[test]
fn external_workflow_actions_use_the_supported_node_24_majors() {
    let refs = external_action_refs();
    assert!(
        !refs.is_empty(),
        "the external-action inventory parsed no entries; the test must not pass vacuously"
    );

    let allowed = BTreeSet::from([
        "actions/cache@v6",
        "actions/checkout@v7",
        "actions/download-artifact@v8",
        "actions/setup-node@v7",
        "actions/upload-artifact@v7",
    ]);

    for (workflow, action_ref) in &refs {
        assert!(
            allowed.contains(action_ref.as_str()),
            "{workflow} uses `{action_ref}`, which is not one of the audited Node 24 action majors; update the official-action audit and this allow-list together"
        );
    }

    let found: BTreeSet<&str> = refs
        .iter()
        .map(|(_, action_ref)| action_ref.as_str())
        .collect();
    assert_eq!(
        found, allowed,
        "the audited action inventory changed; removing an action must not make its version assertion disappear unnoticed"
    );
}
