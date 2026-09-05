// owner: f1-cli-auth-host-status
//
// ----------------------------------------------------------------------------
// D9's TWO CAPACITY LEVELS, AND THE BUDGET NUMBERS THAT MUST NOT CONTRADICT.
// ----------------------------------------------------------------------------
// `04-subsystem-contracts.md` requires the shared-budget limit to be "visible
// in host settings, because an operator who adds an eleventh repository needs
// to know why it was refused". Two numbers carry that: the projected hourly
// request count and the maximum target count. `crates/github` computes them by
// two paths that currently disagree -- 10 against 13 at the 60-second default
// -- and `crates/app/src/cli/host.rs` documents why, and derives both from one
// source instead.
//
// The unit tests there prove the arithmetic. What this file adds is that the
// numbers an operator actually sees, in two different renderings of the same
// state, are the same numbers.

mod support;

use serde_json::Value;
use support::{run, runner_manager};

fn show(data_dir: &std::path::Path) -> String {
    let outcome = run({
        let mut command = runner_manager(data_dir);
        command.args(["host", "show"]);
        command
    });
    assert_eq!(
        outcome.code, 0,
        "`host show` must work on any host, online or not; stderr: {}",
        outcome.stderr
    );
    outcome.stdout
}

fn status_json(data_dir: &std::path::Path) -> Value {
    let outcome = run({
        let mut command = runner_manager(data_dir);
        command.args(["status", "--json"]);
        command
    });
    assert_eq!(
        outcome.code, 0,
        "`status --json` must work headless; stderr: {}",
        outcome.stderr
    );
    serde_json::from_str(&outcome.stdout).unwrap_or_else(|error| {
        panic!(
            "`status --json` must emit parseable JSON ({error}):\n{}",
            outcome.stdout
        )
    })
}

/// Sets the host capacity, asserting the command succeeded.
///
/// A wrapper rather than a bare `run(..)`: `run` is `#[must_use]` precisely so
/// that an invocation whose outcome nobody looked at is visible, and "I only
/// wanted the side effect" is exactly the case where an unnoticed failure makes
/// every later assertion measure the wrong host.
fn set_capacity(data_dir: &std::path::Path, capacity: u16) {
    let outcome = run({
        let mut command = runner_manager(data_dir);
        command.args(["host", "set-capacity", &capacity.to_string()]);
        command
    });
    assert_eq!(
        outcome.code, 0,
        "`host set-capacity {capacity}` must succeed; stderr: {}",
        outcome.stderr
    );
}

/// The number after a label in `host show`'s aligned two-column layout.
fn field(text: &str, label: &str) -> String {
    text.lines()
        .find(|line| line.trim_start().starts_with(label))
        .unwrap_or_else(|| panic!("`host show` must print a {label:?} row:\n{text}"))
        .trim_start()
        .trim_start_matches(label)
        .trim()
        .to_string()
}

// ---------------------------------------------------------------------------
// host set-capacity
// ---------------------------------------------------------------------------

#[test]
fn a_fresh_machine_shows_the_default_and_says_it_is_a_default() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let text = show(data_dir.path());

    assert!(
        text.contains("no host record yet"),
        "a machine nobody has configured must say so rather than presenting a default as \
         a decision somebody made:\n{text}"
    );
    assert_eq!(field(&text, "host_capacity"), "1");
    assert_eq!(field(&text, "in use across policies"), "0");
}

#[test]
fn set_capacity_persists_and_show_displays_it() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");

    let set = run({
        let mut command = runner_manager(data_dir.path());
        command.args(["host", "set-capacity", "4"]);
        command
    });
    assert_eq!(set.code, 0, "stderr: {}", set.stderr);
    assert!(
        set.stdout.contains("host_capacity: 1 -> 4"),
        "the change must state both values, because `08-user-workflows.md` requires a limit \
         to display its current value before an edit:\n{}",
        set.stdout
    );
    assert!(
        set.stdout.contains("in use right now: 0"),
        "and the in-use total alongside it (D9):\n{}",
        set.stdout
    );

    let text = show(data_dir.path());
    assert_eq!(field(&text, "host_capacity"), "4");

    // A second process reads the same value: this is persistence, not memory.
    assert_eq!(
        status_json(data_dir.path())["host"]["capacity"],
        Value::from(4)
    );
}

/// Zero is not a configured host, it is a disabled one, and `Host` refuses to
/// hold it. The command must say which of the two it thinks the operator meant.
#[test]
fn set_capacity_refuses_zero_with_its_own_exit_code() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let outcome = run({
        let mut command = runner_manager(data_dir.path());
        command.args(["host", "set-capacity", "0"]);
        command
    });

    assert_eq!(
        outcome.code, 9,
        "the invalid-argument class; stderr: {}",
        outcome.stderr
    );
    assert!(
        outcome.stderr.contains("disabled one"),
        "the refusal must explain the distinction:\n{}",
        outcome.stderr
    );
    assert!(
        outcome
            .stderr
            .contains("try: runner-manager host set-capacity 1"),
        "and name the command that fixes it:\n{}",
        outcome.stderr
    );
}

/// `f1`: "Never infer a capacity value from runner count." A number that
/// appeared without an operator typing it would be exactly that.
#[test]
fn nothing_sets_a_capacity_except_set_capacity() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");

    // Several commands that touch local state, none of which is `set-capacity`.
    for arguments in [
        vec!["status", "--json"],
        vec!["host", "show"],
        vec!["auth", "logout"],
    ] {
        let outcome = run({
            let mut command = runner_manager(data_dir.path());
            command.args(&arguments);
            command
        });
        // Every one of these succeeds on a fresh data directory. `auth logout`
        // included: a host that held nothing to purge has still complied, which
        // is what `05-infrastructure.md`'s disclosure procedure needs. An
        // `|| code == 3` arm here would be dead, and would loosen the assertion
        // to admit an `auth status`-shaped failure that cannot occur.
        assert_eq!(
            outcome.code,
            0,
            "`{}` must succeed on a fresh data directory: {}",
            arguments.join(" "),
            outcome.stderr
        );
    }

    assert_eq!(
        status_json(data_dir.path())["host"]["capacity"],
        Value::from(1),
        "the capacity must still be the chosen default. A command that raised it on its own \
         would be inferring physical truth from something that is not a measurement."
    );
}

// ---------------------------------------------------------------------------
// host show: everything f1 requires to be visible
// ---------------------------------------------------------------------------

#[test]
fn host_show_displays_every_field_the_specification_names() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    set_capacity(data_dir.path(), 2);
    let text = show(data_dir.path());

    // D9: the value and the current total in use across policies.
    assert_eq!(field(&text, "host_capacity"), "2");
    assert_eq!(field(&text, "in use across policies"), "0");
    // `05-infrastructure.md` item 7: the start mode is visible here.
    assert_eq!(field(&text, "service start mode"), "boot");
    // D13: which secret store is actually in use.
    assert_eq!(field(&text, "secret store"), "machine-scoped");
    assert!(
        !field(&text, "store location").is_empty(),
        "the store's location is what `d2` publishes for this command to print:\n{text}"
    );
    // `c3`'s shared budget.
    assert_eq!(field(&text, "refresh interval"), "60s");
    assert_eq!(field(&text, "refreshes per hour"), "60");
    assert_eq!(field(&text, "projected requests/hour"), "0");
    assert!(
        text.contains("repository targets that fit at this interval: about"),
        "the maximum target count is a product constraint that must be visible in host \
         settings (`04-subsystem-contracts.md`):\n{text}"
    );
}

/// The whole point of `host.rs`'s single-source rule: `host show` must not
/// print two different answers to "how many targets fit".
#[test]
fn host_show_prints_one_target_ceiling_and_it_is_the_measured_one() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let text = show(data_dir.path());

    let ceilings: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("repository targets that fit"))
        .collect();
    assert_eq!(
        ceilings.len(),
        1,
        "exactly one target ceiling may be printed. `crates/github` offers two that \
         disagree -- `BudgetProjection::max_repository_targets` says 10 while \
         `BudgetProjection::admit` takes 6 -- and printing both is the defect this rule \
         exists to prevent. Found: {ceilings:?}"
    );
    assert!(
        ceilings[0].contains("about 6"),
        "the printed ceiling must be the one computed from the demand cost `c4` actually \
         issues -- two run listings plus a job listing per active run -- and not `c3`'s \
         estimate of two requests per repository, which would print the more generous \
         10. Got: {}",
        ceilings[0]
    );

    // And the other rendering of the same state must agree.
    assert_eq!(
        status_json(data_dir.path())["budget"]["max_repository_targets"],
        Value::from(6),
        "`host show` and `status --json` must agree; `g3` shows the same numbers in the \
         TUI and this is the CLI half of that parity"
    );
}

/// The ceiling is a best case, and `f1`'s brief requires that not to be
/// presented as exact: the activity count is priced at one request and can
/// spend four when it walks pages, and the demand poll is priced at its
/// steady state and can spend more while more runs are active.
#[test]
fn the_target_ceiling_is_hedged_and_the_fallback_multiple_is_stated() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let text = show(data_dir.path());

    assert!(
        text.contains("about 6"),
        "the number must be hedged:\n{text}"
    );
    assert!(
        text.contains("BEST-CASE"),
        "the caveat must be in the same output as the number:\n{text}"
    );
    assert!(
        text.contains("4x"),
        "and must state by how much the best case can be exceeded:\n{text}"
    );
    assert!(
        text.contains("not as a threshold"),
        "an operator must not read it as a hard limit:\n{text}"
    );

    assert_eq!(
        status_json(data_dir.path())["budget"]["best_case_multiple_when_paging"],
        Value::from(4),
        "a scripted consumer must be able to read the caveat from the same document as \
         the number it qualifies"
    );
}

// ---------------------------------------------------------------------------
// status --json
// ---------------------------------------------------------------------------

#[test]
fn status_json_is_versioned_and_carries_no_credential() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let document = status_json(data_dir.path());

    assert_eq!(
        document["schema_version"],
        Value::from(1),
        "the schema is a compatibility surface and must carry its version"
    );
    assert_eq!(
        document["credential"]["present"],
        Value::from(false),
        "the credential appears as a boolean, never as a value"
    );
    assert_eq!(
        document["github_contacted"],
        Value::from(false),
        "the document must say plainly that it is a local snapshot; a status command that \
         needed GitHub would be useless on the offline host from Journey 4"
    );
}

/// "A scripted consumer parses it without special-casing" — so this is what a
/// scripted consumer does: read by path, by type, and compute.
#[test]
fn a_scripted_consumer_reads_the_document_by_path_and_type() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    set_capacity(data_dir.path(), 3);
    let document = status_json(data_dir.path());

    let capacity = document["host"]["capacity"]
        .as_u64()
        .expect("capacity is a number, not a string a consumer has to parse");
    let in_use = document["host"]["in_use"].as_u64().expect("a number");
    let headroom = document["host"]["headroom"].as_u64().expect("a number");
    assert_eq!(capacity, 3);
    assert_eq!(headroom, capacity - in_use);

    assert!(
        document["policies"]
            .as_array()
            .expect("an array")
            .is_empty(),
        "a host with no policies has an empty array, not a null and not an absent key"
    );
    assert!(
        document["host"]["configured"].as_bool().expect("a boolean"),
        "after `set-capacity` the host record exists"
    );
    assert!(
        document["generated_at"]
            .as_str()
            .expect("an RFC 3339 string")
            .ends_with('Z'),
        "the timestamp is UTC, so two hosts' documents can be compared without a timezone"
    );
}

/// `status` and `host show` are two renderings of one snapshot, and an operator
/// who reads both must not have to reconcile them.
#[test]
fn the_two_renderings_agree_about_the_same_host() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    set_capacity(data_dir.path(), 5);

    let text = show(data_dir.path());
    let document = status_json(data_dir.path());

    assert_eq!(
        field(&text, "host_capacity"),
        document["host"]["capacity"].to_string()
    );
    assert_eq!(
        field(&text, "in use across policies"),
        document["host"]["in_use"].to_string()
    );
    assert_eq!(
        field(&text, "service start mode").trim(),
        document["host"]["service_start_mode"].as_str().unwrap()
    );
    assert_eq!(
        field(&text, "projected requests/hour"),
        document["budget"]["projected_requests_per_hour"].to_string()
    );
}

/// The human rendering is not the JSON one, and `status` without `--json` has
/// to be readable.
#[test]
fn status_without_json_is_prose_and_with_json_is_only_json() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");

    let prose = run({
        let mut command = runner_manager(data_dir.path());
        command.arg("status");
        command
    });
    assert_eq!(prose.code, 0, "stderr: {}", prose.stderr);
    assert!(
        !prose.stdout.trim_start().starts_with('{'),
        "plain `status` is for a person:\n{}",
        prose.stdout
    );
    assert!(
        prose.stdout.contains("Shared REST budget"),
        "and still carries the budget the design requires to be visible:\n{}",
        prose.stdout
    );

    let json = run({
        let mut command = runner_manager(data_dir.path());
        command.args(["status", "--json"]);
        command
    });
    assert!(
        json.stdout.trim_start().starts_with('{') && json.stdout.trim_end().ends_with('}'),
        "`--json` must emit the document and nothing around it, so stdout pipes straight \
         into a parser:\n{}",
        json.stdout
    );
}
