// owner: f1-workspace-security-acceptance

//! `docs/workspace-acceptance-evidence.md` says which test clears which gate.
//! This is what stops it from becoming a list of names that used to exist.
//!
//! ----------------------------------------------------------------------------
//! WHY A DOCUMENT AND A TEST RATHER THAN A COMMENT.
//! ----------------------------------------------------------------------------
//! `f1`'s Definition of Done opens with "every required-evidence item in ROADMAP
//! has a named automated test or recorded privileged pilot command and result".
//! A prose answer to that ages badly in exactly one way: somebody renames a test
//! — for good reasons, in a later task — and the claim silently becomes false
//! while every suite stays green. The rename is the failure mode, so the rename
//! is what this file catches.
//!
//! `crates/platform/tests/privileged_tests_are_wired_into_ci.rs` set the
//! precedent and states the reasoning in full: a gate that can vanish silently
//! is not a gate. That file asserts a CI job still names its tests; this one
//! asserts the evidence record still names tests that exist.
//!
//! ----------------------------------------------------------------------------
//! WHAT IS AND IS NOT ASSERTED.
//! ----------------------------------------------------------------------------
//! This asserts **linkage**, not results. Whether
//! `a_job_walks_every_state_and_cleans_every_artifact` passes is that test's
//! answer and `cargo test --workspace`'s; what is answered here is that the
//! evidence document still points at it, that nothing in the document points at
//! a function nobody wrote, and that no required item is left with no evidence
//! at all. A `pilot` line is held to the same standard against `ci.yml`: a
//! privileged command may be recorded here only while CI still runs it.
//!
//! ----------------------------------------------------------------------------
//! THE TASKFLOW CROSS-CHECK IS CONDITIONAL, DELIBERATELY.
//! ----------------------------------------------------------------------------
//! The authoritative list of required evidence lives in this feature's Taskflow
//! ledger. Read while it is there, so a bullet added to it cannot go unclaimed —
//! and skipped, with a printed line, once that Taskflow is archived out of the
//! tree. A product test that failed because a completed planning folder was
//! removed would be a landmine, and the evidence document survives the ledger it
//! was derived from.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// `crates/app` -> repository root.
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/app has two ancestors")
        .to_path_buf()
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} must be readable: {error}", path.display()))
}

/// One `###` item and the evidence recorded under it.
#[derive(Debug, Default)]
struct Item {
    tests: Vec<String>,
    pilots: Vec<String>,
}

/// The document, as `heading -> item`, keyed by the top-level `##` section.
fn evidence() -> BTreeMap<String, BTreeMap<String, Item>> {
    let path = repository_root().join("docs/workspace-acceptance-evidence.md");
    let source = read(&path);
    // An empty or truncated file would satisfy every `for` below by iterating
    // nothing, so the size is checked before anything is looked for.
    assert!(
        source.len() > 2_000,
        "{} is suspiciously short; the assertions below would pass vacuously",
        path.display()
    );

    let mut sections: BTreeMap<String, BTreeMap<String, Item>> = BTreeMap::new();
    let mut section = String::new();
    let mut item = String::new();
    for line in source.lines() {
        let trimmed = line.trim_end();
        if let Some(rest) = trimmed.strip_prefix("## ") {
            // Recorded lazily, when the section turns out to hold a `###` gate.
            // The document also carries prose sections explaining the format and
            // what a pilot row means, and an empty entry for each of those would
            // make "a section with no gate in it" indistinguishable from the
            // failure that assertion is looking for.
            section = rest.trim().to_owned();
            item.clear();
        } else if let Some(rest) = trimmed.strip_prefix("### ") {
            assert!(
                !section.is_empty(),
                "an evidence item must sit under a `##` section: {rest}"
            );
            item = rest.trim().to_owned();
            sections
                .entry(section.clone())
                .or_default()
                .entry(item.clone())
                .or_default();
        } else if let Some(rest) = trimmed.strip_prefix("- ") {
            let Some((kind, name)) = rest.split_once(' ') else {
                continue;
            };
            let Some(name) = name
                .trim()
                .strip_prefix('`')
                .and_then(|n| n.strip_suffix('`'))
            else {
                continue;
            };
            let Some(entry) = sections
                .get_mut(&section)
                .and_then(|items| items.get_mut(&item))
            else {
                continue;
            };
            match kind {
                "test" => entry.tests.push(name.to_owned()),
                "pilot" => entry.pilots.push(name.to_owned()),
                // Prose bullets in the surrounding explanation are not evidence
                // lines and are ignored rather than mis-parsed.
                _ => {}
            }
        }
    }
    sections
}

/// The name a line declares, if the line is a function declaration.
///
/// The modifiers are stripped one at a time rather than matched as a set of
/// whole prefixes: a test may be `async fn`, a helper `pub(crate) const fn`, and
/// the repository has both. Only a line that *starts* with a declaration counts,
/// so a doc comment naming `fn something(` does not put a name into the index
/// and cannot make a stale reference look live.
fn declared_function(line: &str) -> Option<String> {
    const MODIFIERS: [&str; 8] = [
        "pub(crate) ",
        "pub(super) ",
        "pub ",
        "default ",
        "const ",
        "async ",
        "unsafe ",
        "extern ",
    ];
    let mut rest = line.trim_start();
    while let Some(next) = MODIFIERS
        .iter()
        .find_map(|modifier| rest.strip_prefix(modifier))
    {
        rest = next.trim_start();
    }
    let name = rest.strip_prefix("fn ")?.split(['(', '<']).next()?.trim();
    (!name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_'))
    .then(|| name.to_owned())
}

/// Every **test** function declared in the repository's Rust sources.
///
/// Built once and searched, rather than one `grep` per name: the document names
/// more than eighty tests and this suite should not walk the tree eighty times.
///
/// Only functions carrying a test attribute go into the index, and that is the
/// whole point. An index of every `fn` would be satisfied by a private helper
/// that happens to share the name, and — the failure this file exists for — by a
/// gate whose `#[test]` was removed: the function would still be declared, this
/// suite would stay green, and the gate would have silently stopped running. The
/// attribute is what makes a name a gate, so the attribute is what is indexed.
fn declared_test_functions() -> BTreeSet<String> {
    let root = repository_root();
    let mut found = BTreeSet::new();
    let mut pending = vec![root.join("crates"), root.join("tests")];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                // A test attribute applies to the next declaration in its own
                // attribute block, so the marker survives the further attributes
                // and doc comments that may sit between the two — `#[cfg(windows)]
                // #[test]` and `#[test] #[ignore = "..."]` are both in this tree —
                // and is dropped at the blank line that separates one item from
                // the next.
                let mut attributed = false;
                for line in read(&path).lines() {
                    let trimmed = line.trim();
                    if let Some(name) = declared_function(line) {
                        if attributed {
                            found.insert(name);
                        }
                        attributed = false;
                    } else if trimmed.is_empty() {
                        attributed = false;
                    } else if trimmed.starts_with("#[")
                        && (trimmed.contains("test]") || trimmed.contains("test("))
                    {
                        attributed = true;
                    }
                }
            }
        }
    }
    assert!(
        found.len() > 500,
        "the test index found only {} names, which means the walk did not reach \
         the sources and every assertion below would be vacuous",
        found.len()
    );
    found
}

/// The `Required evidence before merge` bullets, normalised for comparison.
///
/// `None` when this feature's Taskflow is no longer in the tree, which is a
/// skip rather than a failure — see this file's header.
fn roadmap_requirements() -> Option<BTreeSet<String>> {
    let path = repository_root().join(".taskflow/2026-08-31-runner-workspace-locations/ROADMAP.md");
    if !path.is_file() {
        return None;
    }
    let source = read(&path);
    let section = source
        .split("## Required evidence before merge")
        .nth(1)
        .expect("the ledger states its required evidence")
        .split("\n## ")
        .next()
        .expect("the section ends at the next heading");

    let mut requirements = BTreeSet::new();
    let mut current = String::new();
    for line in section.lines() {
        if let Some(rest) = line.trim_end().strip_prefix("- ") {
            if !current.is_empty() {
                requirements.insert(normalise(&current));
            }
            current = rest.to_owned();
        } else if line.starts_with("  ") && !current.is_empty() {
            // A bullet wrapped across lines is one requirement.
            current.push(' ');
            current.push_str(line.trim());
        } else if line.trim().is_empty() && !current.is_empty() {
            requirements.insert(normalise(&current));
            current.clear();
        }
    }
    if !current.is_empty() {
        requirements.insert(normalise(&current));
    }
    assert!(
        requirements.len() >= 10,
        "the ledger's required-evidence list parsed to {} items, which is not the list \
         this test is about",
        requirements.len()
    );
    Some(requirements)
}

/// Collapsed whitespace, so a re-wrapped bullet is the same requirement.
fn normalise(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ---------------------------------------------------------------------------
// The assertions
// ---------------------------------------------------------------------------

/// Every gate names evidence, and every named test exists.
#[test]
fn every_recorded_gate_names_a_test_that_still_exists() {
    let sections = evidence();
    let declared = declared_test_functions();

    for section in ["Required evidence", "Rollback gate", "Secret posture"] {
        assert!(
            sections.get(section).is_some_and(|items| !items.is_empty()),
            "the `{section}` section records no gate at all"
        );
    }

    let mut checked = 0_usize;
    for items in sections.values() {
        for (item, entry) in items {
            assert!(
                !(entry.tests.is_empty() && entry.pilots.is_empty()),
                "`{item}` is listed as required evidence and names nothing that provides \
                 it; `f1`'s Definition of Done is that every item has a named automated \
                 test or a recorded privileged pilot command"
            );
            for test in &entry.tests {
                assert!(
                    declared.contains(test),
                    "`{item}` names the test `{test}`, and no `#[test] fn {test}` exists in \
                     this repository. Either the test was renamed -- update \
                     docs/workspace-acceptance-evidence.md to the new name -- or the gate \
                     it provided has been deleted, or has stopped being a test and no \
                     longer runs, each of which is a decision rather than a typo."
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked > 60,
        "only {checked} named tests were checked; the evidence document is not the one \
         this test was written against"
    );
}

/// A privileged pilot may be recorded only while CI still runs it.
#[test]
fn every_recorded_pilot_command_is_still_in_the_workflow() {
    let workflow = repository_root().join(".github/workflows/ci.yml");
    let source = read(&workflow);
    assert!(
        source.len() > 500,
        "{} is suspiciously short",
        workflow.display()
    );

    let mut checked = 0_usize;
    for items in evidence().values() {
        for (item, entry) in items {
            for pilot in &entry.pilots {
                assert!(
                    source.contains(pilot.as_str()),
                    "`{item}` records the privileged command `{pilot}`, which \
                     {} no longer runs. A gate whose command has left CI is recorded \
                     evidence for something nothing does.",
                    workflow.display()
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked >= 4,
        "only {checked} pilot commands were checked; the privileged and full-gate rows \
         are the ones this test exists for"
    );
}

/// The document claims exactly the ledger's required evidence, no more and no
/// fewer, for as long as the ledger is in the tree.
#[test]
fn the_recorded_gates_are_the_ones_the_ledger_requires() {
    let Some(required) = roadmap_requirements() else {
        eprintln!(
            "SKIP: this feature's Taskflow has been archived out of the tree, so the \
             evidence document is checked against itself only"
        );
        return;
    };

    let sections = evidence();
    let recorded: BTreeSet<String> = sections
        .get("Required evidence")
        .expect("the evidence document has a `Required evidence` section")
        .keys()
        .map(|item| normalise(item))
        .collect();

    let unclaimed: Vec<_> = required.difference(&recorded).collect();
    assert!(
        unclaimed.is_empty(),
        "the ledger requires evidence this document does not record: {unclaimed:#?}\n\
         Add a `### <item>` section for each, with the tests that provide it."
    );
    let invented: Vec<_> = recorded.difference(&required).collect();
    assert!(
        invented.is_empty(),
        "this document records required evidence the ledger does not ask for: \
         {invented:#?}\nAn item that is genuinely additional belongs under its own \
         `##` section, not under `Required evidence`."
    );
}

/// The two acceptance suites `f1` added are themselves in the document.
///
/// Without this, the pairing could drift in the one direction the checks above
/// cannot see: a new acceptance test that nothing records, which is the same
/// invisibility the document exists to remove -- just pointing the other way.
#[test]
fn the_acceptance_suites_this_task_added_are_recorded() {
    let named: BTreeSet<String> = evidence()
        .values()
        .flat_map(|items| items.values())
        .flat_map(|entry| entry.tests.iter().cloned())
        .collect();

    for test in [
        "a_production_like_version_two_database_upgrades_without_touching_a_directory",
        "the_slot_lease_index_guards_an_upgraded_database_immediately",
        "a_database_from_a_newer_build_is_refused_with_both_numbers",
        "a_backup_taken_before_the_upgrade_rolls_back_without_deleting_a_directory",
        "every_adversarial_root_is_refused_by_both_commands_and_changes_nothing",
        "a_repository_root_may_not_be_carved_out_of_the_host_runner_root",
        "this_platform_keeps_its_default_root_and_leases_a_repository_slot",
        "an_abnormal_exit_writes_no_crash_report",
        "security_gate_persistent_retention_requires_both_directions",
    ] {
        assert!(
            named.contains(test),
            "`{test}` is an acceptance test and is recorded against no gate"
        );
    }
}
