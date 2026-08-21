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
//
// ----------------------------------------------------------------------------
// WHY THESE ASSERT ON A PARSED PATH AND NOT ON `source.contains(..)`.
// ----------------------------------------------------------------------------
// A substring search over a whole workflow file is not a test of where the
// substring sits, and three of the assertions this file used to make were
// vacuous for exactly that reason:
//
//   * `contains("opened")` is satisfied by the word `reopened`, so iterating
//     over the pull-request event types asserted nothing on its first pass;
//   * `contains("branches: [main]")` passes just as happily when that line sits
//     under `pull_request` as under `push` — that is, it passes while the
//     clause it names is violated;
//   * `contains("contents: write")` is satisfied by a comment mentioning it,
//     and says nothing about the interesting property, which is the ABSENCE of
//     `id-token: write` and `packages: write`.
//
// So the scanner below resolves a dotted path — `on.push.branches` — and the
// assertions compare against it. Deliberately a small scanner rather than a
// YAML dependency: the shape being asserted is three levels deep in a file the
// A group owns and keeps uniformly two-space indented, and a test that guards
// the workspace dependency policy should not itself need a new dependency.

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

/// One key that a path resolved to.
struct Located {
    /// Whatever followed `key:` on the same line, trimmed. Empty when the key
    /// only introduces a nested block.
    inline: String,
    /// Every significant line nested under the key, as `(indent, text)` with
    /// `text` trimmed. Used to compare a whole block, not just one line of it.
    block: Vec<(usize, String)>,
}

/// A line's indentation and its content, or `None` for blank and comment lines.
fn significant(raw: &str) -> Option<(usize, &str)> {
    let trimmed = raw.trim_end();
    let body = trimmed.trim_start();
    if body.is_empty() || body.starts_with('#') {
        return None;
    }
    Some((trimmed.len() - body.len(), body))
}

/// Resolves a dotted key path — `["on", "push", "branches"]` — against the
/// two-space-indented workflow files this repository owns.
///
/// `None` means the path is absent, which is a first-class answer here: half of
/// what these tests assert is that a trigger is *not* present.
fn locate(source: &str, path: &[&str]) -> Option<Located> {
    assert!(!path.is_empty(), "an empty path matches nothing");

    // Segments matched so far. The next one, `path[matched]`, must appear at
    // indent `matched * 2`.
    let mut matched = 0usize;
    let mut lines = source.lines();

    while let Some(raw) = lines.next() {
        let Some((indent, body)) = significant(raw) else {
            continue;
        };

        if indent > matched * 2 {
            // Deeper than the level being scanned: it belongs to a sibling
            // subtree that has already been stepped past.
            continue;
        }
        if indent < matched * 2 {
            // Shallower: the enclosing block ended before the key appeared.
            return None;
        }

        let Some((key, rest)) = body.split_once(':') else {
            continue;
        };
        if key.trim() != path[matched] {
            // A sibling at this level. Keep looking within the same block.
            continue;
        }

        matched += 1;
        if matched < path.len() {
            continue;
        }

        let key_indent = indent;
        let mut block = Vec::new();
        for raw in lines.by_ref() {
            let Some((indent, body)) = significant(raw) else {
                continue;
            };
            if indent <= key_indent {
                break;
            }
            block.push((indent, body.to_string()));
        }
        return Some(Located {
            inline: rest.trim().to_string(),
            block,
        });
    }

    None
}

/// The keys directly under `path`, in file order.
fn child_keys(source: &str, path: &[&str]) -> Option<Vec<String>> {
    let located = locate(source, path)?;
    let child_indent = path.len() * 2;
    Some(
        located
            .block
            .iter()
            .filter(|(indent, _)| *indent == child_indent)
            .filter_map(|(_, text)| text.split_once(':'))
            .map(|(key, _)| key.trim().to_string())
            .collect(),
    )
}

/// The inline YAML list at `path` — `types: [opened, synchronize]`.
///
/// `None` for an absent path or for a key that is not an inline list; every
/// list in these two workflows uses the inline form.
fn inline_list_at(source: &str, path: &[&str]) -> Option<Vec<String>> {
    let located = locate(source, path)?;
    let inner = located
        .inline
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))?;
    Some(
        inner
            .split(',')
            .map(|item| item.trim().trim_matches(['"', '\'']).to_string())
            .filter(|item| !item.is_empty())
            .collect(),
    )
}

/// The keys directly under the top-level `on:` block, in file order.
fn triggers(source: &str) -> Vec<String> {
    child_keys(source, &["on"])
        .expect("no top-level `on:` block found; the scanner is looking at the wrong thing")
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
}

#[test]
fn release_workflow_requests_contents_write_and_nothing_else() {
    let source = read_workflow("release.yml");

    let permissions = locate(&source, &["permissions"])
        .expect("release.yml must declare a top-level `permissions:` block");

    // The whole block, not a substring of the file. The property worth holding
    // is not that `contents: write` appears somewhere — a comment satisfies
    // that — but that nothing else appears alongside it. `id-token: write` and
    // `packages: write` in particular would hand the one workflow that holds a
    // publishing credential the ability to mint more (`07-security.md`).
    let entries: Vec<&str> = permissions
        .block
        .iter()
        .map(|(_, text)| text.as_str())
        .collect();

    assert_eq!(
        entries,
        vec!["contents: write"],
        "release.yml's top-level permissions block must be exactly \
         `contents: write` — the minimum needed to publish, and no more"
    );
}

#[test]
fn ci_workflow_runs_on_the_right_pull_request_events_and_on_push_to_main() {
    let source = read_workflow("ci.yml");

    // Scoped to `on.pull_request.types`, so a comment mentioning an event does
    // not satisfy it and `reopened` cannot stand in for `opened`.
    assert_eq!(
        inline_list_at(&source, &["on", "pull_request", "types"]),
        Some(vec![
            "opened".to_string(),
            "synchronize".to_string(),
            "reopened".to_string(),
        ]),
        "ci.yml must run on pull-request opened, synchronize, and reopened"
    );

    // Scoped to `on.push.branches`, so the same list sitting under
    // `pull_request` instead does not satisfy it.
    assert_eq!(
        inline_list_at(&source, &["on", "push", "branches"]),
        Some(vec!["main".to_string()]),
        "ci.yml must run on push to `main`, and the branch filter must be on \
         `push` — under `pull_request` it would restrict which PRs build \
         instead"
    );
}

#[test]
fn ci_workflow_has_no_release_trigger() {
    let source = read_workflow("ci.yml");

    // Asserted as the absence of a forbidden set rather than as equality
    // against a two-item allow-list. The DoD clause is "ci.yml contains no
    // release trigger", and an allow-list is stricter than that in a way that
    // blocks the intended a2 design: a2 must run this same three-OS matrix on
    // the release commit, and the idiomatic way is `on: workflow_call` here
    // plus a `uses:` from release.yml. That third trigger is entirely benign,
    // and an equality assertion would red it.
    let found = triggers(&source);
    for forbidden in ["release", "schedule", "repository_dispatch"] {
        assert!(
            !found.contains(&forbidden.to_string()),
            "ci.yml must not trigger on `{forbidden}`: releases are manual only \
             and live in release.yml. Found triggers: {found:?}"
        );
    }

    // `push` is allowed; `push` with a tag filter is a release trigger wearing
    // a different hat, and is not.
    assert!(
        locate(&source, &["on", "push", "tags"]).is_none(),
        "ci.yml must not trigger on pushed tags: that is a release trigger \
         under another name"
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
