// owner: f1-workspace-security-acceptance

//! Wave 5's adversarial and supported-platform acceptance, measured against the
//! shipping binary.
//!
//! ----------------------------------------------------------------------------
//! WHAT THIS ADDS OVER `workspace_commands.rs`.
//! ----------------------------------------------------------------------------
//! `d1`'s suite proves the four reviewed commands do what they say: the help
//! matches, values round-trip through a restarted process, a move is
//! non-destructive, and the two renderings agree. It proves the *happy* surface
//! and two refusals.
//!
//! `f1` is the other side of the same commands. `04-security-recovery.md` lists
//! nine adversarial path shapes that must fail closed, and the property that
//! matters for every one of them is not only "this was refused" but **"and
//! nothing on this machine changed"** — no directory created, none removed, no
//! file rewritten, no stored value moved. A refusal that had already created the
//! leaf, or that had removed the directory it was pointed away from, would pass
//! an exit-code assertion and fail the security gate. So every case here is
//! measured against a whole-tree snapshot taken before it ran.
//!
//! The table is driven through the binary rather than through
//! `RootPreflight::check`, which `crates/platform/src/runner_root.rs` already
//! covers exhaustively at the unit level. What a unit test cannot answer is
//! whether the *operator's* two commands reach that validator at all: a handler
//! that created its leaf before validating, or a `repo set-workspace` that
//! skipped the overlap set, is invisible there and caught here.
//!
//! ----------------------------------------------------------------------------
//! DELETION IS CONFINED TO TEMPORARY ROOTS, BY CONSTRUCTION.
//! ----------------------------------------------------------------------------
//! `f1`'s scope says the adversarial cases run "with deletion confined to
//! temporary roots". Nothing in this file asks the product to delete anything:
//! every case is a refusal, and the assertion is that the tree is byte-identical
//! afterwards. The one shape that names a path outside a `TempDir` — the
//! filesystem root — is never created, never written to, and is refused before
//! any filesystem call that could touch it, which is the behaviour under test.

mod support;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use runner_manager_domain::attempt::AttemptState;
use runner_manager_domain::model::{AttemptId, PolicyId};
use runner_manager_domain::store::{SqliteStore, Store};
use runner_manager_testkit::fixtures;
use serde_json::Value;
use support::{Outcome, files_under, run, runner_manager};

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

/// The value after a label in the aligned two-column layout `host show` uses.
fn field(text: &str, label: &str) -> String {
    text.lines()
        .find(|line| line.trim_start().starts_with(label))
        .unwrap_or_else(|| panic!("`host show` must print a {label:?} row:\n{text}"))
        .trim_start()
        .trim_start_matches(label)
        .trim()
        .to_string()
}

/// Seeds this machine's host row and one repository policy, without GitHub.
///
/// The same reasoning `workspace_commands.rs` records: `repo add` validates the
/// target against GitHub and refuses without a credential, so a path test that
/// used it would need a device flow and an installation fixture to measure a
/// path refusal. The host row *is* created through the CLI, so the commands
/// under test meet the row they would in production.
fn a_repository(data_dir: &Path, slug: &str) -> PolicyId {
    ok(data_dir, &["host", "set-capacity", "2"]);
    let store = database(data_dir);
    let host = store
        .hosts()
        .expect("the host table must be readable")
        .pop()
        .expect("`host set-capacity` creates this machine's row");
    let id = PolicyId::new_random();
    store
        .insert_policy(
            &fixtures::policy()
                .id(id)
                .host(host.id)
                .autoscale("home-win", 2)
                .repository(slug)
                .active()
                .build(),
        )
        .expect("a fresh policy id");
    id
}

// ---------------------------------------------------------------------------
// Proving that nothing changed
// ---------------------------------------------------------------------------

/// Every path under `root`, with a file's bytes and a directory's presence.
///
/// A `BTreeMap` rather than a list so a failure prints the two trees in the same
/// order and the difference is readable. Directories are recorded as `None`, so
/// a directory that a refusal replaced with a file — or created and left empty —
/// is a difference rather than a match on the path alone.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    let mut found = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        found.insert(directory.clone(), None);
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // `symlink_metadata`: a link is recorded as the link it is, so a
            // case that followed one and copied a tree through it shows up.
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_dir() => pending.push(path),
                Ok(_) => {
                    let bytes = fs::read(&path).unwrap_or_default();
                    found.insert(path, Some(bytes));
                }
                Err(_) => {
                    found.insert(path, Some(Vec::new()));
                }
            }
        }
    }
    found
}

/// A refusal that left the machine alone, or a named difference.
fn assert_unchanged(before: &BTreeMap<PathBuf, Option<Vec<u8>>>, root: &Path, case: &str) {
    let after = snapshot(root);
    let appeared: Vec<_> = after
        .keys()
        .filter(|key| !before.contains_key(*key))
        .collect();
    let vanished: Vec<_> = before
        .keys()
        .filter(|key| !after.contains_key(*key))
        .collect();
    assert!(
        appeared.is_empty(),
        "{case}: a refusal created {appeared:?}; a path this product rejects must not \
         have had its leaf built first"
    );
    assert!(
        vanished.is_empty(),
        "{case}: a refusal removed {vanished:?}; `03-migration-rollout.md` step 8 says \
         no existing directory is moved or deleted"
    );
    assert!(
        before == &after,
        "{case}: a refusal rewrote a file inside the tree"
    );
}

// ---------------------------------------------------------------------------
// The adversarial table
// ---------------------------------------------------------------------------

/// One shape `04-security-recovery.md` says must fail closed.
struct Adversarial {
    /// What the case is, for the failure message.
    case: &'static str,
    /// The path the operator would type.
    path: String,
}

/// The link-shaped case, or `None` when this account may not create one.
///
/// A Windows junction needs no privilege, but a Windows *symlink* and some
/// hardened Linux mounts do, and `crates/platform/src/runner_root.rs` takes the
/// same way out for the same reason: a machine that cannot plant the link cannot
/// measure the refusal, and reporting that honestly is better than a green run
/// that verified nothing. The caller prints a `SKIP` line, so the absence is
/// visible in the log rather than silent.
fn plant_link(inside: &Path) -> Option<PathBuf> {
    let target = inside.join("link-target");
    fs::create_dir_all(&target).expect("a temporary directory is creatable");
    let link = inside.join("linked-root");

    #[cfg(windows)]
    {
        let created = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .output()
            .ok()?;
        if !created.status.success() {
            return None;
        }
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&target, &link).ok()?;
    }

    link.exists().then_some(link)
}

/// The shapes, built against a scratch directory that holds the two cases that
/// need something to already be there.
fn adversarial_cases(scratch: &Path) -> Vec<Adversarial> {
    let existing_file = scratch.join("a-file-not-a-directory");
    fs::write(&existing_file, b"this is a file").expect("a temporary file is writable");

    let mut cases = vec![
        Adversarial {
            // A root would make every attempt directory a sibling of the whole
            // filesystem, and the cleanup that removes an attempt directory
            // recursively is the reason this one is not merely untidy.
            case: "the filesystem root",
            path: if cfg!(windows) { "C:\\" } else { "/" }.to_owned(),
        },
        Adversarial {
            case: "a traversal component",
            path: scratch
                .join("here")
                .join("..")
                .join("there")
                .to_string_lossy()
                .into_owned(),
        },
        Adversarial {
            // A share can vanish or change identity mid-job, and its mount
            // identity cannot be proven; both spellings are refused.
            case: "a UNC share",
            path: if cfg!(windows) {
                "\\\\nas\\builds".to_owned()
            } else {
                "//nas/builds".to_owned()
            },
        },
        Adversarial {
            case: "a relative path",
            path: "build/runners".to_owned(),
        },
        Adversarial {
            case: "an existing file",
            path: existing_file.to_string_lossy().into_owned(),
        },
    ];

    if cfg!(windows) {
        cases.push(Adversarial {
            case: "the device namespace",
            path: "\\\\?\\C:\\rman".to_owned(),
        });
    }

    cases
}

/// Every adversarial shape is refused by **both** commands, and the machine is
/// byte-identical afterwards.
///
/// The two commands are asserted together on purpose. They share
/// `cli::workspace`'s validator, and a change that routed only one of them
/// through it would leave the other accepting a UNC path — which is precisely
/// the asymmetry `05-user-workflows.md` calls out when it requires CLI and TUI
/// (and, before them, the two CLI commands) to produce the same validation
/// outcome.
#[test]
fn every_adversarial_root_is_refused_by_both_commands_and_changes_nothing() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let scratch = tempfile::tempdir().expect("a temporary directory");
    a_repository(data_dir.path(), "octo/repo");

    let mut cases = adversarial_cases(scratch.path());
    match plant_link(scratch.path()) {
        Some(link) => cases.push(Adversarial {
            case: "a link-shaped root",
            path: link.to_string_lossy().into_owned(),
        }),
        None => eprintln!(
            "SKIP: this account may not create a link, so the link-shaped root case did not run"
        ),
    }

    for case in cases {
        for arguments in [
            vec!["host", "set-runtime-root", "--path", case.path.as_str()],
            vec![
                "repo",
                "set-workspace",
                "octo/repo",
                "--mode",
                "persistent",
                "--path",
                case.path.as_str(),
            ],
        ] {
            let before_data = snapshot(data_dir.path());
            let before_scratch = snapshot(scratch.path());

            let outcome = command(data_dir.path(), &arguments);

            assert_eq!(
                outcome.code,
                9,
                "{} must refuse {} as an invalid argument; stdout: {} stderr: {}",
                arguments.join(" "),
                case.case,
                outcome.stdout,
                outcome.stderr
            );
            // The remedy line specifically, not the binary's name anywhere in
            // the output: `error: ...` messages quote the operator's own path,
            // and a real installation's application data directory is itself
            // called `runner-manager`, so a looser match would go on passing
            // over a refusal that had dropped its `try:` line entirely.
            assert!(
                outcome.stderr.contains("try: runner-manager "),
                "{}: `05-user-workflows.md`'s sixth principle asks a path refusal to print \
                 the exact command that fixes it: {}",
                case.case,
                outcome.stderr
            );

            assert_unchanged(&before_data, data_dir.path(), case.case);
            assert_unchanged(&before_scratch, scratch.path(), case.case);
        }

        // And no refusal moved the stored settings.
        let shown = ok(data_dir.path(), &["host", "show"]);
        assert_eq!(
            field(&shown, "runner root source"),
            "platform-default",
            "{}: a refused path must not become the configured one",
            case.case
        );
        let document = status_json(data_dir.path());
        assert_eq!(
            document["policies"][0]["workspace_mode"],
            Value::from("ephemeral"),
            "{}: a refused path must not switch a repository into persistent mode",
            case.case
        );
    }
}

/// The overlap half of the same requirement, which needs two *valid* roots to
/// exist before either becomes adversarial.
///
/// `workspace_commands.rs` proves two repository roots may not contain one
/// another. The case that is not covered there, and that
/// `04-security-recovery.md` names explicitly, is the **host** runner root: a
/// repository whose persistent slots live inside the directory every disposable
/// attempt is created under would have its retained `_work` sitting where a
/// disposable cleanup runs.
#[test]
fn a_repository_root_may_not_be_carved_out_of_the_host_runner_root() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let roots = tempfile::tempdir().expect("a temporary directory");
    a_repository(data_dir.path(), "octo/repo");

    let host_root = roots.path().join("runners");
    ok(
        data_dir.path(),
        &[
            "host",
            "set-runtime-root",
            "--path",
            host_root.to_str().expect("a UTF-8 temporary path"),
        ],
    );

    for (case, candidate) in [
        ("inside the host runner root", host_root.join("octo-repo")),
        ("the host runner root itself", host_root.clone()),
        (
            "an ancestor of the host runner root",
            roots.path().to_path_buf(),
        ),
    ] {
        let before = snapshot(roots.path());
        let outcome = command(
            data_dir.path(),
            &[
                "repo",
                "set-workspace",
                "octo/repo",
                "--mode",
                "persistent",
                "--path",
                candidate.to_str().expect("a UTF-8 temporary path"),
            ],
        );
        assert_eq!(
            outcome.code, 9,
            "a repository workspace {case} must be refused; stderr: {}",
            outcome.stderr
        );
        assert_unchanged(&before, roots.path(), case);
    }

    // The host root itself is untouched by every refusal above.
    assert!(
        host_root.is_dir(),
        "the configured host runner root must survive a refused repository root"
    );
    let shown = ok(data_dir.path(), &["host", "show"]);
    assert_eq!(
        field(&shown, "runner root"),
        host_root.display().to_string()
    );
}

// ---------------------------------------------------------------------------
// The supported-platform gate
// ---------------------------------------------------------------------------

/// This operating system keeps its default and supports a repository persistent
/// slot.
///
/// One test rather than three `cfg` ones, because the *claim* is the same on
/// every leg and only the expected default differs. `f1`'s scope asks to "prove
/// macOS and Linux retain their defaults and support repository persistent
/// slots"; the way this repository proves anything on macOS and Linux is by
/// running the suite there, so this is written to be the test that runs on all
/// three and asserts the right thing on each.
///
/// The Windows arm asserts the *shape* `<drive>:\rman` rather than a literal
/// `C:`. Re-deriving the drive here would mean reading `%SystemDrive%`, which is
/// exactly the mutable value `b1`'s Definition of Done forbids the product from
/// trusting — a test that read it could pass while the product read it too.
/// `runner_root::tests::the_windows_default_ignores_a_rewritten_system_drive_variable`
/// is where that property is measured; what is measured here is that the binary
/// really reports a short root at a drive root, rather than the long application
/// path the short root exists to replace.
#[test]
fn this_platform_keeps_its_default_root_and_leases_a_repository_slot() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let roots = tempfile::tempdir().expect("a temporary directory");
    let policy = a_repository(data_dir.path(), "octo/repo");

    let shown = ok(data_dir.path(), &["host", "show"]);
    let default_root = field(&shown, "runner root");
    assert_eq!(field(&shown, "runner root source"), "platform-default");

    if cfg!(windows) {
        let mut characters = default_root.chars();
        let drive = characters.next().expect("a drive letter");
        assert!(
            drive.is_ascii_uppercase()
                && characters.as_str().eq_ignore_ascii_case(":\\rman")
                && default_root.len() == 7,
            "the Windows default must be `<system drive>:\\rman` -- short, at the drive \
             root, and not the long application path it replaces -- got {default_root:?}"
        );
    } else {
        assert_eq!(
            Path::new(&default_root),
            data_dir.path().join("runtime"),
            "macOS and Linux keep the existing application runtime directory as their \
             default; changing it would move every existing host's attempts"
        );
    }

    // The same platform supports a repository persistent workspace, end to end:
    // configured through the CLI, journalled as a lease, and read back by two
    // separate processes in two renderings.
    let workspace = roots.path().join("ci-cache");
    let workspace_argument = workspace.to_str().expect("a UTF-8 temporary path");
    let enabled = ok(
        data_dir.path(),
        &[
            "repo",
            "set-workspace",
            "octo/repo",
            "--mode",
            "persistent",
            "--path",
            workspace_argument,
        ],
    );
    assert!(
        enabled.contains("_work"),
        "enabling persistence states what is retained: {enabled}"
    );
    assert!(
        workspace.is_dir(),
        "the validated leaf is created once the checks pass"
    );

    let store = database(data_dir.path());
    for slot in [1_u16, 2] {
        store
            .record_attempt(
                &fixtures::attempt()
                    .id(AttemptId::new_random())
                    .policy_id(policy)
                    .state(AttemptState::Busy)
                    .persistent_slot(slot)
                    .runtime_path(
                        workspace
                            .join(format!("s{slot}"))
                            .to_str()
                            .expect("a UTF-8 temporary path")
                            .to_owned(),
                    )
                    .build(),
            )
            .expect("two distinct slots are leasable on this platform");
    }
    drop(store);

    let document = status_json(data_dir.path());
    assert_eq!(
        document["policies"][0]["workspace_mode"],
        Value::from("persistent")
    );
    assert_eq!(
        document["policies"][0]["workspace_root"],
        Value::from(workspace_argument)
    );
    let slots = document["policies"][0]["workspace_slots"]
        .as_array()
        .expect("a persistent policy reports its leases");
    // Sorted, because what is being measured is that the two leases are
    // *distinct*; the order the journal returns two attempts written in the same
    // millisecond is not a property this test is about.
    let mut leased: Vec<i64> = slots
        .iter()
        .map(|lease| lease["slot"].as_i64().expect("a slot number"))
        .collect();
    leased.sort_unstable();
    assert_eq!(
        leased,
        vec![1, 2],
        "two live attempts hold two distinct slots on this platform"
    );

    let listed = ok(data_dir.path(), &["repo", "list"]);
    assert!(
        listed.contains("workspace: persistent")
            && listed.contains(&format!("root={workspace_argument}"))
            && listed.contains("leases=2")
            && listed.contains("cleanup-blocked=0"),
        "the human rendering must agree with the document about the mode, the root and the two leases: {listed}"
    );
}

// ---------------------------------------------------------------------------
// The crash-report clause
// ---------------------------------------------------------------------------

/// > No JIT value, token, or credential appears in ... crash reports.
///
/// The strongest form this product can satisfy that clause in is that **there is
/// no crash report at all**: it installs no panic hook, writes no minidump, and
/// leaves no `*.crash`, `*.dmp` or `*.stackdump` behind, so there is no artifact
/// for a credential to reach. That is a claim about the shipping binary's
/// behaviour on an abnormal exit, so it is measured by causing one.
///
/// The abnormal exit is a database this build cannot read. It is the closest a
/// test can get to "the process died in a way nobody designed for" without a
/// panic hook to trigger, it exercises the fail-closed path
/// `04-security-recovery.md` requires of corrupt state, and it runs the whole
/// startup sequence first — so anything that would write a crash artifact has
/// been initialised by the time the failure happens.
#[test]
fn an_abnormal_exit_writes_no_crash_report() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    a_repository(data_dir.path(), "octo/repo");

    let before: Vec<PathBuf> = files_under(data_dir.path());
    let database_path = data_dir
        .path()
        .join("config")
        .join("runner-manager.sqlite3");

    // Not a valid SQLite file, and not a plausible one either: the header is
    // what the library checks first, so this fails at open rather than at the
    // first query, which is the earliest an abnormal exit can happen.
    fs::write(&database_path, b"this is not a database").expect("the fixture is writable");

    for arguments in [
        vec!["status"],
        vec!["status", "--json"],
        vec!["host", "show"],
        vec!["repo", "list"],
    ] {
        let outcome = command(data_dir.path(), &arguments);
        assert_ne!(
            outcome.code,
            0,
            "`{}` must fail closed on an unreadable journal; stdout: {}",
            arguments.join(" "),
            outcome.stdout
        );
        assert!(
            !outcome.both().contains("panicked at"),
            "`{}` must report unreadable local state rather than unwind: {}",
            arguments.join(" "),
            outcome.both()
        );
    }

    let after: Vec<PathBuf> = files_under(data_dir.path());
    let appeared: Vec<_> = after
        .iter()
        .filter(|path| !before.contains(path) && *path != &database_path)
        .collect();
    assert!(
        appeared.is_empty(),
        "an abnormal exit wrote {appeared:?}; this product has no crash-report artifact, \
         and adding one is a security decision because it would become a new place for a \
         credential to reach"
    );

    // Belt and braces: no crash-shaped file anywhere under the data directory,
    // whatever it might have been called.
    for path in &after {
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_ascii_lowercase();
        assert!(
            !(name.ends_with(".dmp")
                || name.ends_with(".crash")
                || name.ends_with(".stackdump")
                || name.contains("core.")),
            "a crash artifact appeared at {}",
            path.display()
        );
    }
}
