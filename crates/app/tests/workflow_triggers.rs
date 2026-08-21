// owner: a1-workspace-ci-foundation
//
// Several of this repository's release-acceptance checks are one-line
// properties of a YAML file, which is exactly the kind of property that
// regresses silently:
//
//   * "release.yml contains exactly one trigger, workflow_dispatch"
//   * "release.yml requests contents: write and nothing else"
//   * "ci.yml runs on pull-request open/synchronize/reopen and on push to
//     main, and contains no release trigger"
//   * "the acceptance suite serialises the shared fixture at workflow level"
//
// (`.taskflow/2026-08-21-local-runner-manager/09-release-distribution.md`,
// Acceptance evidence; `07-security.md`, operational requirement 7.)
//
// Asserting them here makes them fail a pull request rather than a release
// rehearsal. a2 rewrites release.yml's steps and a3 adds one more; neither
// changes the trigger block, so neither should make this file fail — but a2
// adding `id-token: write` to a release JOB is meant to red it, and does.
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
//
// ----------------------------------------------------------------------------
// A SMALL SCANNER MUST FAIL LOUDLY WHEN IT CANNOT PARSE.
// ----------------------------------------------------------------------------
// The scanner understands one YAML dialect: two-space block mappings, quoted or
// bare keys, and inline `[a, b]` lists. It does not understand flow mappings
// (`on: { push: {...} }`) or block sequences (`on:` then `  - push`), and both
// are legal YAML that GitHub accepts.
//
// That is survivable ONLY because no assertion below reads "absent" as "clean".
// `child_keys` returns an empty list for a shape it cannot parse, and "no
// forbidden trigger is in the empty list" is trivially true — so a security
// assertion phrased purely as an absence would pass on an unparseable file
// carrying a live `release` trigger. Every such assertion is therefore paired
// with a POSITIVE one: the triggers this workflow must have. An unparseable
// `on:` block then reds the very test that guards the property, rather than
// depending on a sibling test to notice.
//
// If a future change needs a shape this scanner does not read, the fix is to
// teach the scanner or to take the YAML dependency — not to relax a positive
// assertion.

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

/// The only triggers a non-release workflow in this repository may carry.
///
/// An ALLOW-LIST, and it has to be. Phrasing this as a denylist of release-ish
/// trigger names looks equivalent and is not: it admits every trigger nobody
/// thought to name, and the one that matters is `pull_request_target`, which
/// runs against the BASE repository with the base repository's secrets
/// available to a fork's pull request. This repository's workflows hold
/// `RUNNER_MANAGER_E2E_TOKEN` and `RUNNER_MANAGER_E2E_FIXTURE_TOKEN`, so that
/// trigger is a credential handout, not a convenience. `create` (which fires on
/// tag creation — a release trigger under another name) and `workflow_run` are
/// admitted by a denylist too.
///
/// It is nonetheless wider than the two triggers ci.yml uses today, because a2
/// must run this same three-OS matrix on the release commit and the idiomatic
/// way is `on: workflow_call` here plus a `uses:` from release.yml. a2 adds
/// that without editing this test.
const ALLOWED_TRIGGERS: [&str; 4] = ["pull_request", "push", "workflow_call", "workflow_dispatch"];

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

/// A YAML key with its surrounding quotes removed.
///
/// `key.trim()` alone leaves the quote characters attached, so a quoted key
/// matched nothing and the whole scanner walked straight past it: `"release":`
/// under `on:` satisfied every assertion in this file, and so did `"tags":`
/// under `push:`. Mirrors what `inline_list_at` already does to list items.
fn unquote(key: &str) -> &str {
    key.trim().trim_matches(['"', '\''])
}

/// Whether a key found in the file is the path segment being looked for.
///
/// One special case, and it is the top-level `on`. Under YAML 1.1 the bare word
/// `on` is the boolean `true` — which is why several formatters, Prettier among
/// them, rewrite `on:` to `"on":` the moment they touch a workflow, and why a
/// YAML 1.1 round-trip can emit `true:` instead. All of those are still the
/// trigger block. Without this, one formatter run would break every scoped
/// assertion in this file at once.
fn key_matches(key: &str, want: &str) -> bool {
    let key = unquote(key);
    if want == "on" {
        // `trim_matches` has already handled `"on"` and `'on'`.
        return key.eq_ignore_ascii_case("on") || key.eq_ignore_ascii_case("true");
    }
    key == want
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
        if !key_matches(key, path[matched]) {
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
            .map(|(key, _)| unquote(key).to_string())
            .collect(),
    )
}

/// The inline YAML list at `path` — `types: [opened, synchronize]`.
///
/// `None` for an absent path or for a key that is not an inline list; every
/// list in these workflows uses the inline form.
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

/// `contents: write` -> `("contents", "write")`, quotes and spacing normalised.
fn permission_entry(text: &str) -> (String, String) {
    match text.split_once(':') {
        Some((scope, level)) => (
            unquote(scope).to_string(),
            level.trim().trim_matches(['"', '\'']).to_string(),
        ),
        None => (unquote(text).to_string(), String::new()),
    }
}

/// Asserts that `source` carries the pull-request and push triggers this
/// repository's non-release workflows are built on, and nothing outside
/// [`ALLOWED_TRIGGERS`].
///
/// The positive half is not decoration. See the scanner note at the top of this
/// file: without it, a trigger block the scanner cannot read passes the
/// forbidden-trigger check by being empty.
fn assert_triggers(workflow: &str, source: &str) {
    let found = triggers(source);

    for required in ["pull_request", "push"] {
        assert!(
            found.contains(&required.to_string()),
            "{workflow} must trigger on `{required}`. Finding it absent does \
             NOT mean it was removed on purpose — it is far more likely that \
             the `on:` block was rewritten into a flow mapping or a block \
             sequence, which this file's scanner does not read, in which case \
             every absence-based assertion below is passing vacuously. \
             Parsed triggers: {found:?}"
        );
    }

    for trigger in &found {
        assert!(
            ALLOWED_TRIGGERS.contains(&trigger.as_str()),
            "{workflow} triggers on `{trigger}`, which is not in the allow-list \
             {ALLOWED_TRIGGERS:?}. `pull_request_target` in particular runs \
             against the BASE repository with its secrets exposed to fork pull \
             requests — this repository's workflows carry \
             RUNNER_MANAGER_E2E_TOKEN and RUNNER_MANAGER_E2E_FIXTURE_TOKEN. \
             `release`, `create`, `schedule`, `repository_dispatch` and \
             `workflow_run` are refused here too: releases are manual only and \
             live in release.yml. Parsed triggers: {found:?}"
        );
    }
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

    // ------------------------------------------------------------------------
    // AND THE SAME AT JOB LEVEL, WHICH IS WHERE IT WOULD ACTUALLY APPEAR.
    // ------------------------------------------------------------------------
    // A job-level `permissions:` REPLACES the top-level block for that job
    // rather than being bounded by it, so the assertion above constrains
    // exactly the one place the escalation is least likely to be written. a2
    // fills in these job bodies — including artifact signing, which is the
    // canonical reason to reach for `id-token: write` — so this half is the
    // half that has to hold.
    let jobs =
        child_keys(&source, &["jobs"]).expect("release.yml must declare a top-level `jobs:` block");
    assert!(
        !jobs.is_empty(),
        "no jobs parsed out of release.yml. As with the trigger scan, an empty \
         result here is a scanner failure and not a clean bill of health: every \
         job-level assertion below would pass vacuously."
    );

    for job in &jobs {
        let Some(permissions) = locate(&source, &["jobs", job.as_str(), "permissions"]) else {
            // No job-level block: the job inherits the top level, which the
            // first half of this test has already pinned.
            continue;
        };

        assert!(
            permissions.inline.is_empty(),
            "release.yml job `{job}` sets `permissions: {}` as a scalar. A \
             blanket grant — `write-all`, `read-all` — is precisely what this \
             test refuses; name the scopes.",
            permissions.inline
        );
        assert!(
            !permissions.block.is_empty(),
            "release.yml job `{job}` declares an empty `permissions:` block; \
             either name the scopes or delete the key"
        );

        for (_, text) in &permissions.block {
            let (scope, level) = permission_entry(text);
            assert!(
                matches!(
                    (scope.as_str(), level.as_str()),
                    ("contents", "write") | ("contents", "read")
                ),
                "release.yml job `{job}` requests `{text}`. A release job may \
                 request `contents: write` (or `contents: read`) and nothing \
                 else: `id-token: write` and `packages: write` would let the \
                 one workflow holding a publishing credential mint more \
                 (`07-security.md`)."
            );
        }
    }
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

    assert_triggers("ci.yml", &source);

    // `push` is allowed; `push` with a tag filter is a release trigger wearing
    // a different hat, and is not.
    assert!(
        locate(&source, &["on", "push", "tags"]).is_none(),
        "ci.yml must not trigger on pushed tags: that is a release trigger \
         under another name"
    );
}

#[test]
fn e2e_workflow_has_no_release_trigger_and_runs_when_ci_runs() {
    let source = read_workflow("e2e.yml");

    // The acceptance suite lives in its own file (see e2e.yml's header), and it
    // is the file that actually carries RUNNER_MANAGER_E2E_TOKEN and
    // RUNNER_MANAGER_E2E_FIXTURE_TOKEN. The trigger allow-list matters more
    // here than in ci.yml, not less.
    assert_triggers("e2e.yml", &source);

    assert!(
        locate(&source, &["on", "push", "tags"]).is_none(),
        "e2e.yml must not trigger on pushed tags"
    );

    // Splitting the suite out of ci.yml must not change WHEN it runs, so these
    // are ci.yml's triggers asserted a second time against the new file.
    assert_eq!(
        inline_list_at(&source, &["on", "pull_request", "types"]),
        Some(vec![
            "opened".to_string(),
            "synchronize".to_string(),
            "reopened".to_string(),
        ]),
        "e2e.yml must carry the same pull-request event types as ci.yml, or \
         splitting it out silently changed the acceptance coverage"
    );
    assert_eq!(
        inline_list_at(&source, &["on", "push", "branches"]),
        Some(vec!["main".to_string()]),
        "e2e.yml must carry the same push branch filter as ci.yml"
    );
}

#[test]
fn e2e_workflow_serialises_the_shared_fixture_at_workflow_level() {
    let source = read_workflow("e2e.yml");

    // ------------------------------------------------------------------------
    // WORKFLOW LEVEL, NOT JOB LEVEL — AND THE DIFFERENCE IS NOT COSMETIC.
    // ------------------------------------------------------------------------
    // GitHub keeps at most one in-progress plus one PENDING entry per
    // concurrency group, and a third arrival cancels the one already pending.
    // That cancellation is not governed by `cancel-in-progress`. So a
    // job-level group shared by three matrix legs does not queue them: leg 3
    // going pending CANCELS leg 2, mid-run, and `fail-fast: false` does not
    // help because a cancelled leg is not a skipped one.
    //
    // At workflow level the contending units are whole runs, so the worst case
    // is a queued run dropped before it starts rather than a leg killed part
    // way through a scenario with a runner still registered in the fixture org.
    let concurrency = locate(&source, &["concurrency"]).expect(
        "e2e.yml must declare a WORKFLOW-level `concurrency:` block; a \
         job-level one cancels matrix legs instead of serialising them",
    );
    let entries: Vec<&str> = concurrency
        .block
        .iter()
        .map(|(_, text)| text.as_str())
        .collect();
    assert_eq!(
        entries,
        vec!["group: e2e-fixture", "cancel-in-progress: false"],
        "e2e.yml's workflow-level concurrency must key on the shared fixture \
         and must never cancel in progress: cancelling mid-scenario strands a \
         registered runner in the fixture org, which is the exact state the \
         next run's post-conditions report as a failure"
    );

    let jobs =
        child_keys(&source, &["jobs"]).expect("e2e.yml must declare a top-level `jobs:` block");
    assert!(!jobs.is_empty(), "no jobs parsed out of e2e.yml");

    for job in &jobs {
        assert!(
            locate(&source, &["jobs", job.as_str(), "concurrency"]).is_none(),
            "e2e.yml job `{job}` declares its own `concurrency:` block. That is \
             the construct this file was split out to avoid — a group shared by \
             the matrix legs cancels them rather than serialising them. Leave \
             the serialisation at workflow level."
        );
    }

    // Serialises the legs WITHIN a run; the workflow-level block above
    // serialises runs against each other. Two mechanisms, both needed.
    assert_eq!(
        locate(&source, &["jobs", "e2e", "strategy", "max-parallel"]).map(|found| found.inline),
        Some("1".to_string()),
        "the e2e matrix must run one leg at a time: the three legs share one \
         disposable repo and one disposable org, and h1's post-conditions sweep \
         them repo-wide"
    );
}

#[test]
fn e2e_workflow_defines_the_fixed_acceptance_command_behind_a_guard() {
    let source = read_workflow("e2e.yml");

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

    // ci.yml must not quietly grow a second copy of the suite.
    let ci = read_workflow("ci.yml");
    assert!(
        !ci.contains("cargo test -p runner-manager-e2e"),
        "the acceptance suite belongs to e2e.yml alone. ci.yml's own \
         `concurrency` block cancels in-progress runs on pull requests, which \
         is exactly what must never happen to a fixture scenario."
    );
}
