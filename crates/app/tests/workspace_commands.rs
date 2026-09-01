// owner: d1-workspace-cli-read-models
//
// ----------------------------------------------------------------------------
// THE FOUR REVIEWED COMMANDS, MEASURED AGAINST THE BINARY.
// ----------------------------------------------------------------------------
// `02-target-architecture.md` lists them exactly:
//
//   runner-manager host set-runtime-root --path PATH
//   runner-manager host reset-runtime-root
//   runner-manager repo set-workspace OWNER/REPO --mode ephemeral
//   runner-manager repo set-workspace OWNER/REPO --mode persistent --path PATH
//
// and `d1`'s Definition of Done asks for four things this file measures and
// `crates/app/src/cli/workspace.rs`'s unit tests cannot: that the generated help
// matches that surface, that the values round-trip through a *restarted*
// process, that a mutation is non-destructive, and that the human and JSON
// renderings agree about the source of every path. Everything here drives the
// real binary against a disposable data directory, because a handler that is
// right and a `--help` page that disagrees with it is exactly the failure the
// reviewed command list exists to prevent.
//
// ----------------------------------------------------------------------------
// WHY EVERY WORKSPACE ROOT IS A SECOND TEMPORARY DIRECTORY.
// ----------------------------------------------------------------------------
// `b1`'s preflight refuses a root that overlaps `config/`, `state/` or `logs/`,
// and `--data-dir` is where those three live. A workspace root *inside* the data
// directory would therefore be refused for a reason that has nothing to do with
// what is under test. Two `tempfile::TempDir`s, kept alive for the length of the
// test, are the isolation this suite needs -- and nothing is written outside
// them.

mod support;

use std::path::Path;

use runner_manager_domain::attempt::{AttemptOutcome, AttemptState, FailureReason};
use runner_manager_domain::model::{AttemptId, PolicyId};
use runner_manager_domain::store::{SqliteStore, Store};
use runner_manager_testkit::fixtures;
use serde_json::Value;
use support::{Outcome, run, runner_manager};

// ---------------------------------------------------------------------------
// Driving the binary
// ---------------------------------------------------------------------------

fn command(data_dir: &Path, arguments: &[&str]) -> Outcome {
    run({
        let mut command = runner_manager(data_dir);
        command.args(arguments);
        command
    })
}

/// Runs a command that must succeed, and says which one did not.
fn ok(data_dir: &Path, arguments: &[&str]) -> String {
    let outcome = command(data_dir, arguments);
    assert_eq!(
        outcome.code,
        0,
        "`{}` must succeed; stderr: {}",
        arguments.join(" "),
        outcome.stderr
    );
    outcome.stdout
}

fn status_json(data_dir: &Path) -> Value {
    serde_json::from_str(&ok(data_dir, &["status", "--json"]))
        .expect("`status --json` must emit parseable JSON")
}

fn database(data_dir: &Path) -> SqliteStore {
    SqliteStore::open(data_dir.join("config").join("runner-manager.sqlite3"))
        .expect("the commands above must have created the database")
}

/// A policy to hang a workspace setting on, seeded straight into the journal.
///
/// **Not `repo add`.** That command validates the target against GitHub and
/// refuses without a credential, so every test here would need a fake GitHub, a
/// device-flow login, and an installation fixture — three moving parts that have
/// nothing to do with a path setting, and that would make a workspace test fail
/// whenever `f2`'s discovery path changed. The host row *is* created through the
/// CLI, so the commands under test meet exactly the row they would in
/// production.
fn a_policy(data_dir: &Path, scope: Scope, slug: &str) -> PolicyId {
    // Creates this machine's host row on first use, and is a no-op after that.
    ok(data_dir, &["host", "set-capacity", "2"]);
    let store = database(data_dir);
    let host = store
        .hosts()
        .expect("the host table must be readable")
        .pop()
        .expect("`host set-capacity` creates this machine's row");
    let id = PolicyId::new_random();
    let builder = fixtures::policy()
        .id(id)
        .host(host.id)
        .autoscale("home-win", 1);
    let policy = match scope {
        Scope::Repository => builder.repository(slug),
        Scope::Organization => builder.organization(slug),
    }
    .active()
    .build();
    store.insert_policy(&policy).expect("a fresh policy id");
    id
}

#[derive(Clone, Copy)]
enum Scope {
    Repository,
    Organization,
}

fn a_repository(data_dir: &Path, slug: &str) -> PolicyId {
    a_policy(data_dir, Scope::Repository, slug)
}

/// Journals one attempt for `policy`, in the state the caller needs.
fn an_attempt(data_dir: &Path, policy: PolicyId, state: AttemptState, slot: Option<u16>) {
    let store = database(data_dir);
    let mut builder = fixtures::attempt()
        .id(AttemptId::new_random())
        .policy_id(policy)
        .state(state);
    if state.is_terminal() {
        builder = builder.outcome(AttemptOutcome::failed(FailureReason::ProcessStartFailed));
    }
    if let Some(slot) = slot {
        builder = builder.persistent_slot(slot);
    }
    store
        .record_attempt(&builder.build())
        .expect("the journal must accept a well-formed attempt");
}

/// The value after a label in `host show`'s aligned two-column layout.
fn field(text: &str, label: &str) -> String {
    text.lines()
        .find(|line| line.trim_start().starts_with(label))
        .unwrap_or_else(|| panic!("`host show` must print a {label:?} row:\n{text}"))
        .trim_start()
        .trim_start_matches(label)
        .trim()
        .to_string()
}

/// A directory that is not the data directory, for a runner or workspace root.
fn a_root(parent: &tempfile::TempDir, leaf: &str) -> String {
    parent
        .path()
        .join(leaf)
        .to_str()
        .expect("a temporary path must be UTF-8")
        .to_string()
}

// ---------------------------------------------------------------------------
// The generated help
// ---------------------------------------------------------------------------

/// `--help` describes the four reviewed commands, in their reviewed shapes.
///
/// The surface *list* is `cli_command_surface.rs`'s job. What this adds is the
/// argument shape of each leaf: a `host set-runtime-root` whose `--path` were
/// optional, or a `repo set-workspace` that had grown a third mode, would pass
/// there and fail here.
#[test]
fn the_generated_help_matches_the_four_reviewed_commands() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");

    let set_root = ok(data_dir.path(), &["host", "set-runtime-root", "--help"]);
    assert!(
        set_root.contains("--path <PATH>"),
        "the reviewed spelling is `host set-runtime-root --path PATH`: {set_root}"
    );

    let reset = ok(data_dir.path(), &["host", "reset-runtime-root", "--help"]);
    assert!(
        !reset.contains("--path"),
        "`host reset-runtime-root` takes no path in the reviewed surface: {reset}"
    );

    let set_workspace = ok(data_dir.path(), &["repo", "set-workspace", "--help"]);
    for fragment in ["<OWNER/REPO>", "--mode <MODE>", "--path <PATH>"] {
        assert!(
            set_workspace.contains(fragment),
            "`repo set-workspace` must offer {fragment}: {set_workspace}"
        );
    }
    assert!(
        set_workspace.contains("ephemeral") && set_workspace.contains("persistent"),
        "both reviewed modes must be named in the help: {set_workspace}"
    );

    // A doc comment on a clap field is what `--help` prints, so a note written
    // for the next maintainer ends up on an operator's screen. These are the
    // words that would give it away.
    for page in [&set_root, &reset, &set_workspace] {
        for leak in ["clap", "exit 2", "Failure::", "`a1`", "`e1`"] {
            assert!(
                !page.contains(leak),
                "{leak:?} is implementation commentary and must not reach the help page: \
                 {page}"
            );
        }
    }
}

/// D7 in the command surface: persistence is repository-scoped, so the
/// organization family must not offer it at all.
#[test]
fn persistent_configuration_is_absent_from_the_organization_commands() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");

    let help = ok(data_dir.path(), &["org", "--help"]);
    assert!(
        !help.contains("set-workspace"),
        "an organization runner accepts jobs from more than one repository, so a retained \
         workspace would cross a repository boundary (D7): {help}"
    );

    let refused = command(data_dir.path(), &["org", "set-workspace", "acme"]);
    assert_eq!(
        refused.code, 2,
        "and the command must not merely be unlisted; stderr: {}",
        refused.stderr
    );

    // The read surfaces still say what an organization's workspace is, rather
    // than leaving an unexplained gap.
    a_policy(data_dir.path(), Scope::Organization, "acme");
    let listed = ok(data_dir.path(), &["org", "list"]);
    assert!(
        listed.contains("workspace=ephemeral"),
        "an organization policy is ephemeral and says so: {listed}"
    );
    assert!(
        listed.contains("persistent workspaces require repository scope"),
        "`02-target-architecture.md` requires the reason, not a silent absence: {listed}"
    );
}

// ---------------------------------------------------------------------------
// The `--path` argument rules
// ---------------------------------------------------------------------------

/// Both halves of "rejects missing or forbidden `--path` combinations".
///
/// The two exit codes are deliberately different and both are documented in
/// `crates/app/src/cli/mod.rs`: a missing required argument is clap's usage
/// error (2), and a combination clap has no spelling for is
/// `invalid_argument` (9), the class defined as "well-formed for clap and wrong
/// for the domain". What must never happen is the third option -- accepting the
/// command and ignoring the path.
#[test]
fn the_path_argument_rules_are_enforced_in_both_directions() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let roots = tempfile::tempdir().expect("a temporary directory");
    a_repository(data_dir.path(), "octo/repo");

    let missing = command(
        data_dir.path(),
        &["repo", "set-workspace", "octo/repo", "--mode", "persistent"],
    );
    assert_eq!(
        missing.code, 2,
        "`--mode persistent` without `--path` is a usage error; stderr: {}",
        missing.stderr
    );

    let forbidden = command(
        data_dir.path(),
        &[
            "repo",
            "set-workspace",
            "octo/repo",
            "--mode",
            "ephemeral",
            "--path",
            &a_root(&roots, "ws"),
        ],
    );
    assert_eq!(
        forbidden.code, 9,
        "`--mode ephemeral` with `--path` is refused rather than silently ignored; \
         stderr: {}",
        forbidden.stderr
    );
    assert!(
        forbidden.stderr.contains("nothing was changed"),
        "the refusal must say the setting is untouched: {}",
        forbidden.stderr
    );
    assert!(
        !roots.path().join("ws").exists(),
        "a refused command must not have created the directory it refused to use"
    );

    // And `host set-runtime-root` has no pathless spelling at all.
    let hostless = command(data_dir.path(), &["host", "set-runtime-root"]);
    assert_eq!(
        hostless.code, 2,
        "`host set-runtime-root` requires `--path`; stderr: {}",
        hostless.stderr
    );
}

/// A path the domain refuses is refused with the command that fixes it, and no
/// directory is created on the way.
#[test]
fn an_unusable_path_is_refused_with_its_remediation() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");

    let relative = command(
        data_dir.path(),
        &["host", "set-runtime-root", "--path", "build/runners"],
    );
    assert_eq!(
        relative.code, 9,
        "Journey 6: a relative path is refused; stderr: {}",
        relative.stderr
    );
    assert!(
        relative.stderr.contains("host set-runtime-root"),
        "`05-user-workflows.md`'s sixth principle: make path errors actionable by printing \
         the exact command that fixes them: {}",
        relative.stderr
    );

    // Overlapping the application data tree is the refusal that protects the
    // database from a directory this product later removes recursively.
    let overlapping = command(
        data_dir.path(),
        &[
            "host",
            "set-runtime-root",
            "--path",
            data_dir
                .path()
                .join("config")
                .to_str()
                .expect("a UTF-8 temporary path"),
        ],
    );
    assert_eq!(
        overlapping.code, 9,
        "a root inside the application data tree is refused; stderr: {}",
        overlapping.stderr
    );

    // Neither refusal moved the stored value.
    let shown = ok(data_dir.path(), &["host", "show"]);
    assert_eq!(field(&shown, "runner root source"), "platform-default");
}

// ---------------------------------------------------------------------------
// Round-trips
// ---------------------------------------------------------------------------

/// The host root round-trips through a *restarted* process.
///
/// Every invocation of the binary is a fresh process that re-opens the SQLite
/// database, so "survives a daemon restart" is what this measures: the value is
/// written by one process and read back by three others.
#[test]
fn the_host_runner_root_round_trips_through_a_restarted_process() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let roots = tempfile::tempdir().expect("a temporary directory");
    let configured = a_root(&roots, "runners");

    let default_shown = ok(data_dir.path(), &["host", "show"]);
    let platform_default = field(&default_shown, "runner root");
    assert_eq!(
        field(&default_shown, "runner root source"),
        "platform-default",
        "an unconfigured host reports the platform default, not a stored value"
    );

    let set = ok(
        data_dir.path(),
        &["host", "set-runtime-root", "--path", &configured],
    );
    assert!(set.contains("Runner root configured."), "{set}");
    assert!(
        set.contains(&format!("Previous: {platform_default} (platform-default)")),
        "the previous configured value and its source are shown: {set}"
    );
    assert!(
        set.contains(&format!("Current:  {configured} (configured)")),
        "so are the new value and its source: {set}"
    );
    assert!(
        set.contains("No existing directory was moved or deleted."),
        "`03-migration-rollout.md` step 8: {set}"
    );
    assert!(
        Path::new(&configured).is_dir(),
        "the validated leaf is created after the checks pass, so the daemon does not have \
         to create it under load"
    );

    // Read back by three separate processes, in three renderings.
    let shown = ok(data_dir.path(), &["host", "show"]);
    assert_eq!(field(&shown, "runner root"), configured);
    assert_eq!(field(&shown, "runner root source"), "configured");

    let document = status_json(data_dir.path());
    assert_eq!(document["host"]["runner_root"], Value::from(&*configured));
    assert_eq!(
        document["host"]["runner_root_source"],
        Value::from("configured")
    );
    assert_eq!(
        document["host"]["configured_runner_root"],
        Value::from(&*configured),
        "the stored override is emitted beside the effective path, so a consumer can tell \
         an operator's choice from a platform accident"
    );

    let text = ok(data_dir.path(), &["status"]);
    assert!(text.contains(&configured), "{text}");

    // And reset puts it back, reporting the old value as retained.
    let reset = ok(data_dir.path(), &["host", "reset-runtime-root"]);
    assert!(reset.contains("reset to the platform default"), "{reset}");
    assert!(
        reset.contains(&format!("Previous: {configured} (configured)")),
        "{reset}"
    );
    assert!(
        reset.contains(&format!("Current:  {platform_default} (platform-default)")),
        "{reset}"
    );
    assert!(
        Path::new(&configured).is_dir(),
        "reset must not delete the directory it stopped pointing at"
    );

    let after = status_json(data_dir.path());
    assert_eq!(after["host"]["configured_runner_root"], Value::Null);
    assert_eq!(
        after["host"]["runner_root_source"],
        Value::from("platform_default")
    );

    // Idempotent: a second reset is a no-op that still succeeds.
    ok(data_dir.path(), &["host", "reset-runtime-root"]);
}

/// A repository round-trips both modes, and returning to ephemeral keeps every
/// slot on disk.
#[test]
fn a_repository_round_trips_persistent_and_ephemeral_modes() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let roots = tempfile::tempdir().expect("a temporary directory");
    let workspace = a_root(&roots, "ci-cache");
    a_repository(data_dir.path(), "octo/repo");

    let fresh = status_json(data_dir.path());
    assert_eq!(
        fresh["policies"][0]["workspace_mode"],
        Value::from("ephemeral"),
        "D3: `repo add` never configures persistence"
    );
    assert_eq!(fresh["policies"][0]["workspace_root"], Value::Null);

    let enabled = ok(
        data_dir.path(),
        &[
            "repo",
            "set-workspace",
            "octo/repo",
            "--mode",
            "persistent",
            "--path",
            &workspace,
        ],
    );
    for fragment in [
        "Workspace mode: persistent",
        &format!("Workspace root: {workspace}"),
        "Slots: created on demand as s1, s2, ...",
        "Retained: each slot's _work directory",
        "Disposable: runner binaries, JIT handoff, and lifecycle files",
        "No existing directory was moved or deleted.",
    ] {
        assert!(
            enabled.contains(fragment),
            "Journey 3's success output must contain {fragment:?}: {enabled}"
        );
    }
    assert!(
        Path::new(&workspace).is_dir(),
        "the persistent root's leaf is created once the checks pass"
    );

    // Leave a sentinel the way a job would, and prove no later mutation removes
    // it. `04-security-recovery.md`: "Sentinel files survive mode, root, policy
    // removal, and rollback tests."
    let sentinel = Path::new(&workspace).join("s1-sentinel.txt");
    std::fs::write(&sentinel, b"a previous job's cache").expect("the root must be writable");

    let persisted = status_json(data_dir.path());
    assert_eq!(
        persisted["policies"][0]["workspace_mode"],
        Value::from("persistent")
    );
    assert_eq!(
        persisted["policies"][0]["workspace_root"],
        Value::from(&*workspace)
    );
    assert_eq!(
        persisted["policies"][0]["workspace_effective_root"],
        Value::from(&*workspace)
    );

    let listed = ok(data_dir.path(), &["repo", "list"]);
    assert!(listed.contains("workspace=persistent"), "{listed}");
    assert!(
        listed.contains(&format!("root={workspace}")),
        "the repository detail names the root: {listed}"
    );

    let disabled = ok(
        data_dir.path(),
        &["repo", "set-workspace", "octo/repo", "--mode", "ephemeral"],
    );
    assert!(disabled.contains("Workspace mode: ephemeral"), "{disabled}");
    assert!(
        disabled.contains(&format!("every slot under {workspace} remains on disk")),
        "Journey 4 prints the old persistent path and states the slots remain: {disabled}"
    );
    assert!(
        disabled.contains("platform-default") || disabled.contains("configured"),
        "Journey 4 also prints the effective host runner root future attempts use: \
         {disabled}"
    );
    assert!(
        sentinel.is_file(),
        "returning to disposable mode must never delete retained data"
    );

    let back = status_json(data_dir.path());
    assert_eq!(
        back["policies"][0]["workspace_mode"],
        Value::from("ephemeral")
    );
    assert_eq!(back["policies"][0]["workspace_root"], Value::Null);
    assert_eq!(
        back["policies"][0]["workspace_effective_root"], back["host"]["runner_root"],
        "an ephemeral policy's next attempt goes under the effective host root"
    );
}

/// Moving a persistent root leaves the old one exactly where it was.
#[test]
fn moving_a_persistent_root_is_non_destructive() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let roots = tempfile::tempdir().expect("a temporary directory");
    let first = a_root(&roots, "first");
    let second = a_root(&roots, "second");
    a_repository(data_dir.path(), "octo/repo");

    let set = |path: &str| {
        ok(
            data_dir.path(),
            &[
                "repo",
                "set-workspace",
                "octo/repo",
                "--mode",
                "persistent",
                "--path",
                path,
            ],
        )
    };

    set(&first);
    let sentinel = Path::new(&first).join("kept.txt");
    std::fs::write(&sentinel, b"still here").expect("the first root must be writable");

    let moved = set(&second);
    assert!(
        moved.contains(&format!("every slot under {first} remains on disk")),
        "the retained old directory is reported: {moved}"
    );
    assert!(sentinel.is_file(), "and it is reported rather than removed");
    assert!(Path::new(&second).is_dir());

    // Re-saving the same path is accepted: a root does not overlap itself.
    let again = set(&second);
    assert!(
        again.contains(&format!("Workspace root: {second}")),
        "{again}"
    );
    assert!(
        !again.contains("remains on disk"),
        "nothing was left behind, because nothing moved: {again}"
    );
}

/// Two roots that contain one another can delete each other's workspaces, so
/// the second is refused and the first is untouched.
#[test]
fn two_configured_roots_may_not_overlap() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let roots = tempfile::tempdir().expect("a temporary directory");
    let host_root = a_root(&roots, "shared");
    a_repository(data_dir.path(), "octo/one");
    a_repository(data_dir.path(), "octo/two");

    ok(
        data_dir.path(),
        &["host", "set-runtime-root", "--path", &host_root],
    );

    let inside = Path::new(&host_root)
        .join("repo")
        .to_str()
        .expect("a UTF-8 temporary path")
        .to_string();
    let refused = command(
        data_dir.path(),
        &[
            "repo",
            "set-workspace",
            "octo/one",
            "--mode",
            "persistent",
            "--path",
            &inside,
        ],
    );
    assert_eq!(
        refused.code, 9,
        "a repository root inside the host runner root is refused; stderr: {}",
        refused.stderr
    );
    assert!(
        !Path::new(&inside).exists(),
        "and the refused directory is not created"
    );

    // Two repositories may not share one either, and the refusal names the
    // conflicting target (Journey 6).
    let shared = a_root(&roots, "one");
    ok(
        data_dir.path(),
        &[
            "repo",
            "set-workspace",
            "octo/one",
            "--mode",
            "persistent",
            "--path",
            &shared,
        ],
    );
    let collision = command(
        data_dir.path(),
        &[
            "repo",
            "set-workspace",
            "octo/two",
            "--mode",
            "persistent",
            "--path",
            &shared,
        ],
    );
    assert_eq!(
        collision.code, 9,
        "two repositories may not lease slots from one root; stderr: {}",
        collision.stderr
    );
    assert!(
        collision.stderr.contains("octo/one"),
        "the refusal names the conflicting target: {}",
        collision.stderr
    );
}

// ---------------------------------------------------------------------------
// The two refusal counts
// ---------------------------------------------------------------------------

/// A host-root change is refused while attempts still own the old root, and the
/// two counts are reported apart.
///
/// `d1`: *"Refuse active and cleanup-blocked affected attempts with separate
/// counts."* They are separate because the operator's next action is: an active
/// attempt drains on its own, a cleanup-blocked one needs recovery or
/// remediation, and one total would send them away to wait for a job that is not
/// running.
#[test]
fn a_host_root_change_is_refused_with_the_two_counts_apart() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let roots = tempfile::tempdir().expect("a temporary directory");
    let target = a_root(&roots, "runners");
    let policy = a_repository(data_dir.path(), "octo/repo");

    an_attempt(data_dir.path(), policy, AttemptState::Busy, None);
    an_attempt(data_dir.path(), policy, AttemptState::Failed, None);
    an_attempt(data_dir.path(), policy, AttemptState::Failed, None);

    let refused = command(
        data_dir.path(),
        &["host", "set-runtime-root", "--path", &target],
    );
    assert_eq!(
        refused.code, 11,
        "the conflict class; stderr: {}",
        refused.stderr
    );
    assert!(
        refused.stderr.contains("1 active"),
        "the active count is named: {}",
        refused.stderr
    );
    assert!(
        refused.stderr.contains("2 awaiting cleanup"),
        "and the cleanup-blocked count is named apart from it: {}",
        refused.stderr
    );
    assert!(
        !Path::new(&target).exists(),
        "a refused mutation creates no directory: the leaf comes after every \
         non-mutating check"
    );

    // `host show` had already reported the same two numbers, so the refusal is
    // predictable rather than a surprise at the moment of the change.
    let shown = ok(data_dir.path(), &["host", "show"]);
    assert_eq!(field(&shown, "active ephemeral paths"), "1");
    assert_eq!(field(&shown, "cleanup-blocked paths"), "2");
    assert_eq!(
        field(&shown, "runner root source"),
        "platform-default",
        "and nothing was written"
    );

    let document = status_json(data_dir.path());
    assert_eq!(
        document["host"]["active_ephemeral_attempts"],
        Value::from(1)
    );
    assert_eq!(
        document["host"]["cleanup_blocked_ephemeral_attempts"],
        Value::from(2)
    );
}

/// The same fence on the repository setting, and it counts *uncleaned* attempts
/// rather than active ones.
///
/// `04-security-recovery.md`: "A repository path setting cannot change while any
/// attempt for that policy is active **or unresolved**." A terminal attempt
/// holds no host capacity and still owns its slot, which is exactly why the
/// narrower active-only guard is not enough.
#[test]
fn a_repository_workspace_change_is_refused_by_an_uncleaned_attempt_alone() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let roots = tempfile::tempdir().expect("a temporary directory");
    let workspace = a_root(&roots, "ci-cache");
    let policy = a_repository(data_dir.path(), "octo/repo");

    // Terminal, so it counts against no capacity at all.
    an_attempt(data_dir.path(), policy, AttemptState::Failed, Some(2));

    let refused = command(
        data_dir.path(),
        &[
            "repo",
            "set-workspace",
            "octo/repo",
            "--mode",
            "persistent",
            "--path",
            &workspace,
        ],
    );
    assert_eq!(
        refused.code, 11,
        "the conflict class; stderr: {}",
        refused.stderr
    );
    assert!(
        refused.stderr.contains("0 active") && refused.stderr.contains("1 awaiting cleanup"),
        "an attempt that is invisible to capacity still blocks a path change, and the \
         message has to say which kind it is: {}",
        refused.stderr
    );
    assert!(
        !Path::new(&workspace).exists(),
        "and nothing was created on the way to the refusal"
    );

    // The quarantined slot is visible in both read surfaces, by number, with no
    // directory listing.
    let document = status_json(data_dir.path());
    let policy_json = &document["policies"][0];
    assert_eq!(policy_json["cleanup_blocked_attempts"], Value::from(1));
    let slots = policy_json["workspace_slots"].as_array().expect("an array");
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0]["slot"], Value::from(2));
    assert_eq!(slots[0]["cleanup_blocked"], Value::from(true));

    let listed = ok(data_dir.path(), &["repo", "list"]);
    assert!(
        listed.contains("slot s2 quarantined"),
        "`05-user-workflows.md` requires a blocked slot to say so rather than read as busy: \
         {listed}"
    );
}

// ---------------------------------------------------------------------------
// The trust warning and the secret posture
// ---------------------------------------------------------------------------

/// Enabling persistence states every clause `04-security-recovery.md` requires,
/// and neither command emits a credential or a JIT configuration.
#[test]
fn enabling_persistence_prints_the_trust_warning_and_no_credentials() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let roots = tempfile::tempdir().expect("a temporary directory");
    let workspace = a_root(&roots, "ws");
    a_repository(data_dir.path(), "octo/repo");

    let enabled = ok(
        data_dir.path(),
        &[
            "repo",
            "set-workspace",
            "octo/repo",
            "--mode",
            "persistent",
            "--path",
            &workspace,
        ],
    );

    for clause in [
        "_work are an input to later jobs",
        "cross branch and job boundaries",
        "untrusted fork or pull-request workflows",
        "does not delete old directories",
        "clean: false",
    ] {
        assert!(
            enabled.contains(clause),
            "the persistent trust warning must state {clause:?}: {enabled}"
        );
    }
    assert!(
        !enabled.contains("clean: false makes"),
        "the guidance must not claim `clean: false` alone creates persistence: {enabled}"
    );

    // The output of every workspace command is paths and counts, and paths are
    // not credentials. Scanned for the shapes `07-security.md` names.
    let corpus = format!(
        "{enabled}{}{}{}",
        ok(data_dir.path(), &["host", "show"]),
        ok(data_dir.path(), &["repo", "list"]),
        ok(data_dir.path(), &["status", "--json"]),
    );
    for prefix in ["ghu_", "gho_", "ghs_", "ghp_", "eyJ"] {
        assert!(
            !corpus.contains(prefix),
            "no workspace surface may carry a credential or a JIT configuration, and \
             {prefix:?} was found in:\n{corpus}"
        );
    }
}

// ---------------------------------------------------------------------------
// The renderings agree
// ---------------------------------------------------------------------------

/// The same state, three ways, with no contradiction.
///
/// `05-user-workflows.md`'s fourth principle is "use the same vocabulary and
/// validation in CLI, TUI, status, and README". The TUI is `e1`; these are the
/// three surfaces that exist now, and they read one another's numbers.
#[test]
fn the_human_and_json_renderings_identify_the_same_source() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let roots = tempfile::tempdir().expect("a temporary directory");
    a_repository(data_dir.path(), "octo/repo");

    let default_document = status_json(data_dir.path());
    let default_shown = ok(data_dir.path(), &["host", "show"]);
    assert_eq!(
        field(&default_shown, "runner root"),
        default_document["host"]["runner_root"]
            .as_str()
            .expect("the platform default must resolve on a supported host"),
        "the two renderings must not disagree about the effective path"
    );
    assert_eq!(
        field(&default_shown, "runner root source"),
        default_document["host"]["runner_root_source"]
            .as_str()
            .expect("a string")
            .replace('_', "-"),
        "one hyphenated badge for people and one snake_case token for scripts, of the same \
         fact"
    );
    assert_eq!(field(&default_shown, "active ephemeral paths"), "0");
    assert_eq!(field(&default_shown, "cleanup-blocked paths"), "0");
    assert_eq!(
        default_document["host"]["active_ephemeral_attempts"],
        Value::from(0)
    );
    assert_eq!(
        default_document["host"]["cleanup_blocked_ephemeral_attempts"],
        Value::from(0)
    );

    let configured = a_root(&roots, "runners");
    ok(
        data_dir.path(),
        &["host", "set-runtime-root", "--path", &configured],
    );

    let shown = ok(data_dir.path(), &["host", "show"]);
    let document = status_json(data_dir.path());
    assert_eq!(field(&shown, "runner root"), configured);
    assert_eq!(
        document["host"]["runner_root"],
        Value::from(&*configured),
        "and both moved together"
    );

    // No surface lists what is inside a workspace.
    let listed = ok(data_dir.path(), &["repo", "list"]);
    for surface in [&shown, &listed, &ok(data_dir.path(), &["status"])] {
        assert!(
            !surface.contains("_work"),
            "`d1` requires these surfaces to identify a workspace without enumerating \
             workspace files: {surface}"
        );
    }
}

/// A host-root change is effective without reinstalling the service.
///
/// The registration carries the four application-data directories and nothing
/// else, so the daemon reads the runner root from the migrated database on every
/// launch. This pins the *absence*: a runner-root argument added to the service
/// command line would silently make every existing registration stale.
#[test]
fn the_service_registration_carries_no_runner_root() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");

    let help = ok(data_dir.path(), &["daemon", "run", "--help"]);
    for forbidden in ["--runner-root", "--runtime-root", "--workspace-root"] {
        assert!(
            !help.contains(forbidden),
            "`daemon run` must take no runner-root argument, or a host-root change would \
             need `service install` run again: {help}"
        );
    }

    let install = ok(data_dir.path(), &["service", "install", "--help"]);
    assert!(
        !install.contains("runtime-root"),
        "and neither does the installer: {install}"
    );
}
