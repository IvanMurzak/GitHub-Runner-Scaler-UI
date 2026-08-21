// owner: a2-release-workflow
//
// a2's Definition of Done is written almost entirely as things a REHEARSAL
// DISPATCH would observe: dispatch with `1.2` and watch step 1 fail, dispatch
// with a version below the current release and watch step 2 fail, hand the
// signature check a stripped binary and watch the run stop. Every one of those
// rehearsals publishes under the project's name if it gets far enough, and the
// release workflow holds the only credential able to publish
// (`07-security.md`, operational requirement 7). A gate whose only test is a
// rehearsal is a gate that is first exercised by the release that needed it.
//
// So the decisions were extracted into `.github/scripts/release.sh`, and this
// file runs them directly -- on every pull request, on all three operating
// systems, with no credential, nothing tagged and nothing published. What is
// asserted here is what the rehearsal would have shown:
//
//   DoD "a rehearsal with 1.2, v1.2.3 and abc fails at step 1"
//       -> the_version_format_rejects_the_three_documented_bad_inputs
//   DoD "equal to and below the current release fails at step 2, for both
//        sources independently"
//       -> monotonicity_is_enforced_against_the_manifest_source
//          monotonicity_is_enforced_against_the_release_source_independently
//   DoD "the macOS signature check fails on a stripped binary"
//       -> the_macos_signature_check_refuses_an_unsigned_binary
//   DoD "a rehearsal with a failing test publishes nothing"
//       -> nothing_is_published_without_the_full_test_matrix
//   DoD "a release page lists five platform assets plus SHA256SUMS and an SBOM"
//       -> every_published_target_is_covered_by_the_build_matrix
//          the_sbom_describes_every_locked_package
//
// WHAT THIS FILE CANNOT REACH is recorded honestly rather than papered over:
// the real `codesign`, the real `gh release create`, and the real five-runner
// build matrix only exist on a dispatched run. The signature test below drives
// the script's DECISION with a stubbed `codesign` on PATH; it does not prove
// that Apple's tool says what the stub says.
//
// ----------------------------------------------------------------------------
// WHY THIS FILE CARRIES ITS OWN SMALL SCANNER.
// ----------------------------------------------------------------------------
// `workflow_triggers.rs` has one and this duplicates a little of it. That is
// deliberate: the two are separate integration-test binaries and this package
// has no library target to share helpers through, `workflow_triggers.rs`
// belongs to a1, and the shapes needed here -- the `needs:` graph and `run:`
// block scalars -- are not the shapes it reads. Teaching a1's file new tricks
// for a2's benefit would make a1's file fail for reasons a1 does not own.
//
// The same rule applies as there: no assertion below reads "absent" as "clean".
// Every scan that could return empty is paired with a positive assertion that
// the thing being scanned was found at all.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

// ----------------------------------------------------------------------------
// Locating things.
// ----------------------------------------------------------------------------

fn repository_root() -> PathBuf {
    // crates/app -> repository root.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("the repository root must exist")
}

fn read_workflow(name: &str) -> String {
    let path = repository_root()
        .join(".github")
        .join("workflows")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()))
}

/// A path in the form `bash` accepts on every platform.
///
/// Git Bash is an MSYS program: it understands `C:/dir/file` but a Windows path
/// spelled with backslashes reaches the script with its separators read as
/// escape characters.
fn posix(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn find_on_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
}

/// The `bash` that runs `.github/scripts/release.sh`.
///
/// ----------------------------------------------------------------------------
/// ON WINDOWS THIS MUST NOT BE `bash` FROM `PATH`, AND THAT IS NOT A PREFERENCE.
/// ----------------------------------------------------------------------------
/// `C:\Windows\System32\bash.exe` exists on stock Windows and on GitHub's
/// windows runner image, and it is not a shell: it is the WSL launcher, which
/// starts a Linux distribution. Where no distribution is installed it fails
/// with `execvpe(/bin/bash) failed: No such file or directory` -- measured on
/// the development host this task was implemented on, where it is the first
/// `bash` on `PATH`.
///
/// Git for Windows ships the real thing, and anyone who cloned this repository
/// has Git. So resolution goes through `git` rather than through `bash`.
///
/// This PANICS rather than skipping when nothing is found. ci.yml already
/// depends on bash existing on all three runner images -- every step in it
/// declares `shell: bash` -- so "no usable bash" is a broken environment, and
/// a test that quietly passed in one would be worth nothing.
fn bash_program() -> PathBuf {
    if let Some(explicit) = std::env::var_os("RUNNER_MANAGER_BASH") {
        return PathBuf::from(explicit);
    }

    if !cfg!(windows) {
        return PathBuf::from("bash");
    }

    let mut tried: Vec<PathBuf> = Vec::new();

    // `<root>\cmd\git.exe` and `<root>\bin\git.exe` both sit beside
    // `<root>\bin\bash.exe`.
    if let Some(git) = find_on_path("git.exe")
        && let Some(root) = git.parent().and_then(Path::parent)
    {
        let candidate = root.join("bin").join("bash.exe");
        if candidate.is_file() {
            return candidate;
        }
        tried.push(candidate);
    }

    let standard = PathBuf::from(r"C:\Program Files\Git\bin\bash.exe");
    if standard.is_file() {
        return standard;
    }
    tried.push(standard);

    panic!(
        "no usable bash found on Windows. Tried, in order: {tried:?}. \
         `bash` on PATH is deliberately NOT used as a fallback: on Windows it \
         resolves to C:\\Windows\\System32\\bash.exe, the WSL launcher, which \
         is a different program and fails outright when no distribution is \
         installed. Install Git for Windows, or set RUNNER_MANAGER_BASH to a \
         bash executable."
    );
}

fn release_script() -> PathBuf {
    let path = repository_root()
        .join(".github")
        .join("scripts")
        .join("release.sh");
    assert!(
        path.is_file(),
        "{} must exist: it is where release.yml's decisions live",
        path.display()
    );
    path
}

/// Runs a `release.sh` subcommand and returns its exit status and output.
fn run_release_script(arguments: &[&str]) -> (bool, String) {
    run_release_script_with_path(arguments, None)
}

fn run_release_script_with_path(arguments: &[&str], extra_path: Option<&Path>) -> (bool, String) {
    let (ok, out, err) = release_script_streams(arguments, extra_path);
    (ok, format!("{out}{err}"))
}

/// The two streams kept apart, for the subcommands whose stdout is a VALUE.
///
/// `manifest-version` and `latest-release-version` are captured by the workflow
/// with `$(...)`, so anything they write to stdout becomes the value. Merging
/// the streams -- which every other assertion here happily does, because it is
/// reading prose -- would let a progress line pass for a version.
fn release_script_streams(arguments: &[&str], extra_path: Option<&Path>) -> (bool, String, String) {
    let script = release_script();
    let mut command = Command::new(bash_program());
    command.arg(posix(&script));
    command.args(arguments);
    command.current_dir(repository_root());

    if let Some(directory) = extra_path {
        let existing = std::env::var_os("PATH").unwrap_or_default();
        let mut entries = vec![directory.to_path_buf()];
        entries.extend(std::env::split_paths(&existing));
        let joined = std::env::join_paths(entries).expect("PATH entries must join");
        command.env("PATH", joined);
    }

    let Output {
        status,
        stdout,
        stderr,
    } = command
        .output()
        .unwrap_or_else(|err| panic!("cannot run {}: {err}", posix(&script)));

    (
        status.success(),
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    )
}

fn release_script_stdout(arguments: &[&str]) -> String {
    let (ok, output) = run_release_script(arguments);
    assert!(
        ok,
        "release.sh {arguments:?} was expected to succeed:\n{output}"
    );
    output.trim().to_string()
}

// ----------------------------------------------------------------------------
// Step 1 -- the version format.
// ----------------------------------------------------------------------------

#[test]
fn the_version_format_rejects_the_three_documented_bad_inputs() {
    // The first three rows are the Definition of Done verbatim
    // (`.taskflow/2026-08-21-local-runner-manager/tasks/a2-release-workflow.md`).
    let rejected = [
        "1.2",       // DoD: a Cargo version has three components
        "v1.2.3",    // DoD: the `v` belongs to the tag, not the input
        "abc",       // DoD: not a version at all
        "",          // an empty required input still reaches the step
        "01.2.3",    // two spellings of one version means two tags for one release
        "1.2.3-rc1", // pre-releases are not a v1 channel (D12)
        "1.2.3+b1",
        "1.2.3.4",
        " 1.2.3",
        "1.2.3 ",
        "latest",
        "1.2.x",
        "^1.2.3",          // a Cargo requirement, not a version
        "1.2.3\nrm -rf /", // a newline must not smuggle a second command through
    ];

    for version in rejected {
        let (accepted, output) = run_release_script(&["check-format", version]);
        assert!(
            !accepted,
            "check-format accepted {version:?}, which must be rejected at step 1.\n{output}"
        );
    }

    // The positive half. Without it a `check-format` that rejected EVERYTHING
    // -- a broken pattern, a script that fails to start -- would pass every
    // assertion above while making releases impossible.
    let accepted = ["1.2.3", "0.1.0", "0.0.0", "10.20.30", "1.0.0"];
    for version in accepted {
        let (ok, output) = run_release_script(&["check-format", version]);
        assert!(
            ok,
            "check-format rejected {version:?}, which is a valid X.Y.Z version.\n{output}"
        );
    }
}

// ----------------------------------------------------------------------------
// Step 2 -- monotonicity, one source at a time.
// ----------------------------------------------------------------------------

#[test]
fn monotonicity_is_enforced_against_the_manifest_source() {
    // No published release, so only the Cargo.toml source can reject.
    for (version, manifest) in [("1.0.0", "1.0.0"), ("0.9.0", "1.0.0"), ("0.1.0", "1.0.0")] {
        let (accepted, output) = run_release_script(&["check-monotonic", version, manifest, ""]);
        assert!(
            !accepted,
            "check-monotonic accepted {version} against Cargo.toml {manifest}.\n{output}"
        );
        assert!(
            output.contains("Cargo.toml"),
            "the rejection must name the source that rejected it.\n{output}"
        );
    }

    for (version, manifest) in [("1.0.1", "1.0.0"), ("2.0.0", "1.0.0"), ("0.1.1", "0.1.0")] {
        let (ok, output) = run_release_script(&["check-monotonic", version, manifest, ""]);
        assert!(
            ok,
            "check-monotonic rejected {version}, which is above Cargo.toml {manifest}.\n{output}"
        );
    }
}

#[test]
fn monotonicity_is_enforced_against_the_release_source_independently() {
    // ------------------------------------------------------------------------
    // THE MANIFEST VERSION IS DELIBERATELY LOW IN EVERY ROW BELOW.
    // ------------------------------------------------------------------------
    // "Checking one source alone lets a manual edit to the other regress the
    // version" is the reason there are two sources, so a test that let the
    // Cargo.toml source do the rejecting would prove nothing about the release
    // source. At `0.1.0` the manifest check passes every time and only the
    // published-release check can produce the failure.
    for (version, release) in [("1.0.0", "1.0.0"), ("1.0.0", "1.1.0"), ("1.0.0", "2.0.0")] {
        let (accepted, output) =
            run_release_script(&["check-monotonic", version, "0.1.0", release]);
        assert!(
            !accepted,
            "check-monotonic accepted {version} against published release {release}.\n{output}"
        );
        assert!(
            output.contains("release"),
            "the rejection must name the source that rejected it.\n{output}"
        );
        assert!(
            output.contains("monotonic vs Cargo.toml OK"),
            "the manifest source must have PASSED here, or this test is not \
             exercising the release source at all.\n{output}"
        );
    }

    for (version, release) in [("1.0.1", "1.0.0"), ("2.0.0", "1.9.9")] {
        let (ok, output) = run_release_script(&["check-monotonic", version, "0.1.0", release]);
        assert!(
            ok,
            "check-monotonic rejected {version}, which is above release {release}.\n{output}"
        );
    }
}

#[test]
fn an_unreadable_release_source_is_not_an_absent_one() {
    // ------------------------------------------------------------------------
    // A TRANSIENT API FAILURE MUST NOT SILENTLY DOWNGRADE THE GATE TO ONE
    // SOURCE.
    // ------------------------------------------------------------------------
    // `gh api` exits non-zero for a 404, for a rate limit, for a network blip
    // and for a token whose scope was reduced. Reading the exit code alone
    // makes all four "no release yet", which hands `check-monotonic` an empty
    // third argument -- and it correctly treats that as "a first release cannot
    // regress". The two-source gate then quietly becomes a one-source gate at
    // exactly the moment the second source stopped working.
    //
    // The equal-version case would still be caught by the tag-collision check.
    // A LOWER one would not: a manually reversed Cargo.toml plus one transient
    // API failure publishes 1.0.0 while 2.0.0 is the latest release. So the
    // status is what decides, and only 404 means "nothing released yet".
    let temporary = tempfile::tempdir().expect("a temporary directory");

    let write = |name: &str, body: &str| -> String {
        let path = temporary.path().join(name);
        std::fs::write(&path, body).expect("the fixture must be writable");
        posix(&path)
    };

    // -- 200: the version comes back, with the tag's `v` stripped -------------
    let ok_response = write(
        "200.http",
        "HTTP/2.0 200 OK\r\nContent-Type: application/json\r\n\r\n\
         {\"id\":1,\"tag_name\":\"v2.0.0\",\"draft\":false}\n",
    );
    let (ok, stdout, stderr) =
        release_script_streams(&["latest-release-version", &ok_response], None);
    assert!(ok, "a 200 must succeed.\n{stdout}{stderr}");
    assert_eq!(
        stdout.trim(),
        "2.0.0",
        "STDOUT is the value the workflow captures with `$(...)`, so it must \
         carry the version and nothing else.\nstdout: {stdout:?}\nstderr: {stderr:?}"
    );

    // -- 404: the legitimate first-release state, and the ONLY one ------------
    let (ok, stdout, stderr) = release_script_streams(
        &[
            "latest-release-version",
            &write(
                "404.http",
                "HTTP/2.0 404 Not Found\r\n\r\n{\"message\":\"Not Found\"}\n",
            ),
        ],
        None,
    );
    assert!(
        ok,
        "a 404 is the first-release state and must not fail the run.\n{stdout}{stderr}"
    );
    assert_eq!(
        stdout.trim(),
        "",
        "a 404 must print no version at all: the EMPTY third argument is what \
         tells check-monotonic that a first release cannot be regressed. \
         Anything on stdout here becomes a version.\nstdout: {stdout:?}"
    );

    // -- everything else: a source that could not be READ ---------------------
    for (name, status_line) in [
        ("403.http", "HTTP/2.0 403 Forbidden"),
        ("429.http", "HTTP/2.0 429 Too Many Requests"),
        ("500.http", "HTTP/2.0 500 Internal Server Error"),
        ("502.http", "HTTP/1.1 502 Bad Gateway"),
        ("401.http", "HTTP/2.0 401 Unauthorized"),
    ] {
        let response = write(
            name,
            &format!("{status_line}\r\n\r\n{{\"message\":\"nope\"}}\n"),
        );
        let (accepted, output) = run_release_script(&["latest-release-version", &response]);
        assert!(
            !accepted,
            "{status_line} was treated as \"no release published yet\". It is \
             not: it means the published-release source could not be read, and \
             a run that continued would be checking monotonicity against \
             Cargo.toml alone.\n{output}"
        );
    }

    // -- and the case where `gh` produced nothing at all ----------------------
    let (accepted, output) =
        run_release_script(&["latest-release-version", &write("empty.http", "")]);
    assert!(
        !accepted,
        "an empty response means `gh` never answered. Absence must not read as \
         \"nothing has been released\".\n{output}"
    );
}

#[test]
fn the_manifest_version_is_read_from_the_workspace_package_section() {
    // The root manifest spells `version = "..."` five times -- once under
    // `[workspace.package]` and once in each `[workspace.dependencies]` entry
    // that pins a member -- so an unscoped read picks up whichever comes first.
    let manifest = repository_root().join("Cargo.toml");
    let version = release_script_stdout(&["manifest-version", &posix(&manifest)]);

    assert!(
        version.lines().count() == 1,
        "manifest-version must print exactly one version, got:\n{version}"
    );
    let (ok, _) = run_release_script(&["check-format", &version]);
    assert!(
        ok,
        "manifest-version returned {version:?}, which is not a valid X.Y.Z version"
    );
}

// ----------------------------------------------------------------------------
// Step 4 -- writing the version.
// ----------------------------------------------------------------------------

#[test]
fn setting_the_version_rewrites_every_line_that_pins_a_workspace_member() {
    // ------------------------------------------------------------------------
    // A ONE-LINE BUMP DOES NOT PRODUCE A STALE COMMENT. IT PRODUCES A WORKSPACE
    // THAT DOES NOT RESOLVE.
    // ------------------------------------------------------------------------
    // `[workspace.package].version` is single-sourced for the member packages,
    // which makes it tempting to treat the release version as one line. But the
    // root manifest also pins each member in `[workspace.dependencies]` with a
    // `path` AND a `version`, so that the published crate resolves from the
    // registry, and Cargo requires a path dependency to satisfy the version
    // stated beside it. Bumping only `[workspace.package]` gives:
    //
    //     error: failed to select a version for the requirement
    //            `runner-manager-domain = "^0.1.0"`
    //            candidate versions found which didn't match: 1.2.3
    //
    // ...at `cargo build` time, which in a release run is AFTER the tag has
    // been pushed. `verify-version` moves that discovery before the commit.
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let source = repository_root().join("Cargo.toml");
    let original = std::fs::read_to_string(&source).expect("the root manifest must be readable");
    let current = release_script_stdout(&["manifest-version", &posix(&source)]);

    // -- the positive path: set-version rewrites all of them ------------------
    let target = temporary.path().join("Cargo.toml");
    std::fs::write(&target, &original).expect("the copy must be writable");
    let output = release_script_stdout(&["set-version", "9.9.9", &posix(&target)]);
    assert!(
        output.contains("9.9.9"),
        "set-version must report what it wrote:\n{output}"
    );

    let written =
        std::fs::read_to_string(&target).expect("the rewritten manifest must be readable");
    assert_eq!(
        release_script_stdout(&["manifest-version", &posix(&target)]),
        "9.9.9",
        "[workspace.package] must carry the new version"
    );

    let stale: Vec<&str> = written
        .lines()
        .filter(|line| line.contains("path = \"crates/"))
        .filter(|line| line.contains("version = ") && !line.contains("\"9.9.9\""))
        .collect();
    assert!(
        stale.is_empty(),
        "these member pins were left at the old version, which makes the \
         workspace unresolvable:\n{stale:#?}"
    );

    let member_pins = written
        .lines()
        .filter(|line| line.contains("path = \"crates/") && line.contains("version = "))
        .count();
    assert!(
        member_pins > 0,
        "no `[workspace.dependencies]` entry pins a member by path and version. \
         Finding none does NOT mean the manifest stopped doing that -- it is far \
         more likely this scan stopped matching, in which case the staleness \
         check above passed vacuously."
    );

    // -- the negative path: a one-line bump must be REFUSED -------------------
    // Built by rewriting only the part of the real manifest that precedes
    // `[workspace.dependencies]`, which is exactly the edit that looks correct
    // and is not.
    // Located as a SECTION HEADER, not as a substring. The manifest's own
    // header comment names `[workspace.dependencies]` in prose some forty lines
    // before the table begins, so `find` on the bare string splits inside the
    // comment block -- which left the "one-line bump" fixture byte-identical to
    // the manifest it was supposed to differ from, and the test passed a
    // rewrite that had not happened.
    // Anchored to the newline that precedes it, which also keeps this correct
    // on a CRLF checkout -- `str::lines()` strips the `\r`, so counting line
    // lengths to rebuild a byte offset would drift by one per line.
    let split = original
        .find("\n[workspace.dependencies]")
        .map(|newline| newline + 1)
        .expect("the root manifest must declare a [workspace.dependencies] section");
    let (head, tail) = original.split_at(split);
    assert!(
        head.contains("[workspace.package]"),
        "the split must land after [workspace.package] and before the member \
         pins, or this fixture is not the one-line bump it claims to be"
    );
    let one_line_bump = format!(
        "{}{}",
        head.replace(&format!("version = \"{current}\""), "version = \"9.9.9\""),
        tail
    );
    assert_ne!(
        one_line_bump, original,
        "the fixture must actually differ from the manifest it was built from"
    );

    let half_done = temporary.path().join("OneLine.toml");
    std::fs::write(&half_done, &one_line_bump).expect("the fixture must be writable");

    let (accepted, output) = run_release_script(&["verify-version", "9.9.9", &posix(&half_done)]);
    assert!(
        !accepted,
        "verify-version accepted a manifest whose [workspace.dependencies] \
         entries still pin {current}. Cargo would refuse to resolve it, and by \
         then the release would already be tagged.\n{output}"
    );
    assert!(
        output.contains(&current),
        "the rejection must show which pin was left behind.\n{output}"
    );
}

/// A manifest exercising every shape a member pin is written in.
///
/// Four of these five entries were silently skipped when the rewrite keyed on
/// `path = "crates/`, and the check that was supposed to notice affirmed
/// success anyway, because its only floor was "at least one entry matched".
const EVERY_PIN_SHAPE: &str = r#"[workspace]
resolver = "3"
members = [
    "crates/agent",
    "crates/newthing",
    "tests",
    "crates/expanded",
]

[workspace.package]
version = "0.1.0"

[workspace.dependencies]
# The shape that always worked.
runner-manager-agent = { path = "crates/agent", version = "0.1.0" }
# A new member under crates/, which is the easy case.
runner-manager-newthing = { path = "crates/newthing", version = "0.1.0" }
# Key order reversed. TOML does not care and neither may the rewrite.
reversed = { version = "0.1.0", path = "crates/reversed" }
# A MEMBER THAT DOES NOT LIVE UNDER crates/. The root manifest already has one
# of these: `tests`, which is `runner-manager-e2e` in the lock.
runner-manager-e2e = { path = "tests", version = "0.1.0" }
# An ordinary external dependency, whose version must NOT be touched.
tokio = { version = "1.53.1", features = [
    "fs",
    "macros",
] }

# An expanded table. `path` and `version` are separate lines, and a
# line-oriented rewrite reaching `version` first does not yet know there is a
# `path` below it.
[workspace.dependencies.expanded]
version = "0.1.0"
path = "crates/expanded"
"#;

#[test]
fn setting_the_version_reaches_members_written_in_any_shape() {
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let manifest = temporary.path().join("Cargo.toml");
    std::fs::write(&manifest, EVERY_PIN_SHAPE).expect("the fixture must be writable");

    let output = release_script_stdout(&["set-version", "9.9.9", &posix(&manifest)]);
    assert!(
        output.contains("9.9.9"),
        "set-version must report what it wrote:\n{output}"
    );

    let written = std::fs::read_to_string(&manifest).expect("the rewrite must be readable");

    // Every member pin, in every shape, now says 9.9.9.
    for (label, pinned) in [
        (
            "under crates/",
            "path = \"crates/agent\", version = \"9.9.9\"",
        ),
        (
            "a new member",
            "path = \"crates/newthing\", version = \"9.9.9\"",
        ),
        (
            "reversed keys",
            "version = \"9.9.9\", path = \"crates/reversed\"",
        ),
        ("outside crates/", "path = \"tests\", version = \"9.9.9\""),
    ] {
        assert!(
            written.contains(pinned),
            "the {label} pin was not rewritten. Cargo requires a path \
             dependency to satisfy the version stated beside it, so this \
             workspace would not resolve -- and in a release run that is \
             discovered after the tag has been pushed.\nExpected: {pinned}\n\
             Got:\n{written}"
        );
    }

    // The expanded table, whose two keys are separate lines.
    let expanded = written
        .split_once("[workspace.dependencies.expanded]")
        .expect("the expanded table must survive the rewrite")
        .1;
    assert!(
        expanded.contains("version = \"9.9.9\""),
        "the expanded [workspace.dependencies.<name>] table still pins the old \
         version. Its `path` sits BELOW its `version`, which is exactly the \
         case a single line-oriented pass cannot decide.\n{expanded}"
    );

    // The negative half, and it is the one that matters: an external
    // dependency's version is not a workspace version and must be left alone.
    assert!(
        written.contains("tokio = { version = \"1.53.1\""),
        "set-version rewrote an external dependency's version requirement. It \
         may only touch entries that pin a PATH.\n{written}"
    );
    assert!(
        !written.contains("\"0.1.0\""),
        "some entry still carries the old version:\n{written}"
    );
}

#[test]
fn verify_version_refuses_a_manifest_it_could_only_partly_read() {
    // ------------------------------------------------------------------------
    // AFFIRMING SUCCESS OVER AN ENTRY IT NEVER LOOKED AT IS THE WHOLE FAILURE.
    // ------------------------------------------------------------------------
    // `verify-version` exists to move a resolution failure from `cargo build`,
    // which in a release run happens after the tag is pushed, to before the
    // commit. "Every entry my scan happened to match is correct" is worth
    // nothing as an affirmation, because the entry that breaks the release is
    // by definition the one the scan did not match. So a path stated in a shape
    // it cannot attribute to an entry has to be a REJECTION, not a smaller
    // count.
    let temporary = tempfile::tempdir().expect("a temporary directory");

    let unreadable = temporary.path().join("Unreadable.toml");
    std::fs::write(
        &unreadable,
        r#"[workspace]
members = ["crates/agent", "crates/orphan"]

[workspace.package]
version = "9.9.9"

[workspace.dependencies]
runner-manager-agent = { path = "crates/agent", version = "9.9.9" }
    path = "crates/orphan"
    version = "0.1.0"
"#,
    )
    .expect("the fixture must be writable");

    let (accepted, output) = run_release_script(&["verify-version", "9.9.9", &posix(&unreadable)]);
    assert!(
        !accepted,
        "verify-version affirmed a manifest in which one stated `path` belonged \
         to no entry it could read. Nothing checked that entry's version, and \
         nothing rewrote it either.\n{output}"
    );
    assert!(
        output.contains("crates/orphan"),
        "the rejection must name the path it could not attribute.\n{output}"
    );

    // And the positive half: the same check must PASS the manifest this
    // repository actually ships, or every rejection above is just a broken
    // scanner rejecting everything.
    let real = repository_root().join("Cargo.toml");
    let current = release_script_stdout(&["manifest-version", &posix(&real)]);
    let (ok, output) = run_release_script(&["verify-version", &current, &posix(&real)]);
    assert!(
        ok,
        "verify-version rejected the root manifest at its own current version \
         {current}.\n{output}"
    );

    // The success line has to report coverage rather than claim completeness.
    // `tests` is a declared member outside `crates/`, so a report that counted
    // only `crates/` pins would be describing a different manifest.
    assert!(
        output.contains("declared workspace members are pinned by path and version"),
        "verify-version must say how much of the manifest it covered, not \
         merely that what it looked at was fine.\n{output}"
    );
}

// ----------------------------------------------------------------------------
// Step 5 -- the macOS signature check.
// ----------------------------------------------------------------------------

/// Writes a fake `codesign` onto a directory that the test prepends to `PATH`.
///
/// Real `codesign` exists only on macOS, so on two of this repository's three
/// supported platforms the only way to exercise the DECISION is to control what
/// the tool says. This does not claim to model Apple's tool -- see the caveat
/// in this file's header -- it pins what `release.sh` does with each answer.
///
/// ----------------------------------------------------------------------------
/// `--display` HAS ITS OWN EXIT STATUS, AND IT IS NOT ALWAYS ZERO.
/// ----------------------------------------------------------------------------
/// `release.sh` rejects a binary on two independent grounds: a non-zero status
/// from `codesign --display`, and a message that says in words that nothing is
/// signed. Real `codesign -dv` on an unsigned Mach-O does BOTH -- it exits 1
/// and writes `<path>: code object is not signed at all`. A stub hard-wired to
/// exit 0 can therefore only ever reach the message branch, which left the
/// status branch with no coverage at all: replacing `status=$?` with `status=0`
/// in `release.sh` used to leave every test in this file green.
///
/// The two grounds are separated deliberately below: one configuration reaches
/// the message branch, another reaches the status branch and nothing else.
fn stub_codesign(directory: &Path, display_body: &str, display_exit: i32, verify_exit: i32) {
    // `$3` is the binary. `codesign --display --verbose=2 <binary>` puts the
    // path third; a stub printing `$2` would be reporting `--verbose=2` as the
    // thing it inspected.
    let script = format!(
        "#!/usr/bin/env bash\n\
         case \"$1\" in\n\
         --display) {display_body}; exit {display_exit} ;;\n\
         --verify)  exit {verify_exit} ;;\n\
         esac\n"
    );
    let path = directory.join("codesign");
    std::fs::write(&path, script).expect("the codesign stub must be writable");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("the codesign stub must be executable");
    }
}

#[test]
fn the_macos_signature_check_refuses_an_unsigned_binary() {
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let binary = temporary.path().join("runner-manager");
    std::fs::write(&binary, b"not really a mach-o").expect("the fake binary must be writable");
    let binary = posix(&binary);

    let stub_directory = temporary.path().join("stub");
    std::fs::create_dir_all(&stub_directory).expect("the stub directory must be creatable");

    // -- the state D12 requires: an ad-hoc signature, as the linker leaves it --
    stub_codesign(
        &stub_directory,
        r#"printf 'Executable=%s\nIdentifier=runner-manager\nSignature=adhoc\n' "$3" >&2"#,
        0,
        0,
    );
    let (ok, output) =
        run_release_script_with_path(&["verify-macos-signature", &binary], Some(&stub_directory));
    assert!(
        ok,
        "an ad-hoc signature is what the linker produces and what D12 requires; \
         it must pass.\n{output}"
    );

    // -- the DoD case: a deliberately stripped binary -------------------------
    // Real `codesign -dv` on an unsigned Mach-O exits 1 AND says so in words,
    // so the DoD case as it actually occurs is rejected on either ground. This
    // configuration is the message half; the one below it is the status half.
    stub_codesign(
        &stub_directory,
        r#"printf '%s: code object is not signed at all\n' "$3" >&2"#,
        1,
        1,
    );
    let (accepted, output) =
        run_release_script_with_path(&["verify-macos-signature", &binary], Some(&stub_directory));
    assert!(
        !accepted,
        "a binary carrying no signature must fail the run. An unsigned arm64 \
         Mach-O does not execute on Apple Silicon at all (D12).\n{output}"
    );

    // -- the status branch, and NOTHING ELSE ----------------------------------
    // ------------------------------------------------------------------------
    // THIS ROW EXISTS TO GIVE `status=$?` SOMETHING TO PROVE.
    // ------------------------------------------------------------------------
    // Every other row here is rejected by one of the two checks that read
    // `codesign`'s WORDS, so `release.sh`'s check on its exit STATUS had no
    // coverage at all: replacing `status=$?` with `status=0` left every
    // assertion in this file passing.
    //
    // This configuration is built so that the status is the only thing left to
    // reject on. The output names no "not signed" phrase, and it DOES carry a
    // `Signature=` line, so the two message checks both pass it; `--verify`
    // exits zero, so that passes too. Read the status as zero and this binary
    // is accepted outright -- which is what makes the assertion below a test of
    // the status check rather than of whatever happens to fail first.
    //
    // The state is not contrived: `codesign` reports what it managed to read
    // and still exits non-zero when it hits an error afterwards -- a truncated
    // or damaged signature, an unreadable resource fork, a file it cannot
    // finish parsing as a Mach-O.
    stub_codesign(
        &stub_directory,
        r#"printf 'Executable=%s\nSignature=adhoc\n' "$3" >&2; printf 'error reading resources\n' >&2"#,
        1,
        0,
    );
    let (accepted, output) =
        run_release_script_with_path(&["verify-macos-signature", &binary], Some(&stub_directory));
    assert!(
        !accepted,
        "`codesign --display` exiting non-zero must fail the run on the STATUS \
         alone. Everything this configuration SAYS would pass -- there is a \
         `Signature=` line, no \"not signed\" phrase, and `--verify` succeeds -- \
         so if this is accepted, the exit status is not being read.\n{output}"
    );
    assert!(
        output.contains("could not read a signature"),
        "the rejection must be the one the status branch produces.\n{output}"
    );

    // -- a signature that is present but does not verify ----------------------
    stub_codesign(
        &stub_directory,
        r#"printf 'Executable=%s\nSignature=adhoc\n' "$3" >&2"#,
        0,
        1,
    );
    let (accepted, output) =
        run_release_script_with_path(&["verify-macos-signature", &binary], Some(&stub_directory));
    assert!(
        !accepted,
        "`codesign --display` succeeding says a signature is THERE, not that it \
         is valid. A tampered binary must still fail.\n{output}"
    );

    // -- codesign answers, but names no signature at all ----------------------
    stub_codesign(
        &stub_directory,
        r#"printf 'Executable=%s\nIdentifier=runner-manager\n' "$3" >&2"#,
        0,
        0,
    );
    let (accepted, output) =
        run_release_script_with_path(&["verify-macos-signature", &binary], Some(&stub_directory));
    assert!(
        !accepted,
        "no `Signature=` or `Authority=` line means nothing established that a \
         signature exists, and absence must not read as success.\n{output}"
    );
}

// ----------------------------------------------------------------------------
// Step 6 -- the SBOM.
// ----------------------------------------------------------------------------

/// One `[[package]]` from `Cargo.lock`, read straight out of the file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LockedPackage {
    name: String,
    version: String,
    checksum: Option<String>,
}

/// `Cargo.lock`, parsed independently of the generator being tested.
///
/// ----------------------------------------------------------------------------
/// THE POINT IS THAT THESE VALUES DO NOT COME FROM THE SBOM.
/// ----------------------------------------------------------------------------
/// An assertion that rebuilds a component's expected fields out of that same
/// component's own fields is satisfied by any self-consistent document,
/// including one describing entirely the wrong dependency graph. The `purl`
/// check here used to be exactly that. Cross-checking against the lock makes
/// the SBOM answerable to something outside itself.
fn locked_packages() -> Vec<LockedPackage> {
    let lock = repository_root().join("Cargo.lock");
    let text = std::fs::read_to_string(&lock).expect("Cargo.lock must be readable");

    let mut packages = Vec::new();
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut checksum: Option<String> = None;

    let quoted = |line: &str, key: &str| -> Option<String> {
        let rest = line.trim_end().strip_prefix(key)?.trim_start();
        let rest = rest.strip_prefix('=')?.trim();
        rest.strip_prefix('"')?
            .strip_suffix('"')
            .map(str::to_string)
    };

    fn flush(
        name: &mut Option<String>,
        version: &mut Option<String>,
        checksum: &mut Option<String>,
        packages: &mut Vec<LockedPackage>,
    ) {
        if let (Some(package), Some(at)) = (name.take(), version.take()) {
            packages.push(LockedPackage {
                name: package,
                version: at,
                checksum: checksum.take(),
            });
        }
        *checksum = None;
    }

    for line in text.lines() {
        let line = line.trim_end();
        if line == "[[package]]" {
            flush(&mut name, &mut version, &mut checksum, &mut packages);
            continue;
        }
        if let Some(value) = quoted(line, "name") {
            name = Some(value);
        } else if let Some(value) = quoted(line, "version") {
            version = Some(value);
        } else if let Some(value) = quoted(line, "checksum") {
            checksum = Some(value);
        }
    }
    flush(&mut name, &mut version, &mut checksum, &mut packages);

    assert!(
        packages.len() > 100,
        "Cargo.lock parsed as {} packages, which means this parser is broken \
         rather than that the workspace has almost no dependencies",
        packages.len()
    );
    packages
}

/// Runs `sbom` and parses the result.
fn generate_sbom(directory: &Path, in_scope: Option<&Path>) -> serde_json::Value {
    let lock = repository_root().join("Cargo.lock");
    let output_path = directory.join("sbom.cdx.json");

    let mut arguments = vec![
        "sbom".to_string(),
        posix(&lock),
        posix(&output_path),
        "runner-manager".to_string(),
        "9.9.9".to_string(),
    ];
    if let Some(list) = in_scope {
        arguments.push(posix(list));
    }
    let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
    release_script_stdout(&borrowed);

    let text = std::fs::read_to_string(&output_path).expect("the SBOM must have been written");
    serde_json::from_str(&text).expect("the SBOM must be valid JSON")
}

#[test]
fn the_sbom_describes_every_locked_package() {
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let document = generate_sbom(temporary.path(), None);

    assert_eq!(document["bomFormat"], "CycloneDX");
    assert_eq!(document["specVersion"], "1.5");
    assert_eq!(document["metadata"]["component"]["name"], "runner-manager");
    assert_eq!(document["metadata"]["component"]["version"], "9.9.9");

    let components = document["components"]
        .as_array()
        .expect("the SBOM must carry a components array");

    let locked = locked_packages();
    assert_eq!(
        components.len(),
        locked.len() - 1,
        "the SBOM must list every locked package except the product itself, \
         which is `metadata.component`"
    );

    // ------------------------------------------------------------------------
    // DRIVEN FROM THE LOCK, NOT FROM THE DOCUMENT.
    // ------------------------------------------------------------------------
    // Every triple below is read out of `Cargo.lock`, and the SBOM is then
    // required to contain exactly it. A generator emitting a self-consistent
    // description of some other graph fails here, where rebuilding each
    // component's `purl` from its own `name` and `version` could not tell the
    // difference.
    let mut by_key: BTreeMap<(String, String), &serde_json::Value> = BTreeMap::new();
    for component in components {
        let name = component["name"]
            .as_str()
            .expect("every component is named");
        let version = component["version"]
            .as_str()
            .expect("every component has a version");
        assert!(
            by_key
                .insert((name.to_string(), version.to_string()), component)
                .is_none(),
            "{name} {version} was emitted twice"
        );
    }

    let mut hashed = 0usize;
    for package in &locked {
        if package.name == "runner-manager" {
            continue;
        }
        let key = (package.name.clone(), package.version.clone());
        let component = by_key.get(&key).unwrap_or_else(|| {
            panic!(
                "Cargo.lock locks {} {} and the SBOM does not describe it",
                package.name, package.version
            )
        });

        assert_eq!(
            component["purl"]
                .as_str()
                .expect("every component has a purl"),
            format!("pkg:cargo/{}@{}", package.name, package.version),
            "the package URL must be built from the LOCKED name and version"
        );

        match &package.checksum {
            Some(expected) => {
                let hashes = component["hashes"].as_array().unwrap_or_else(|| {
                    panic!(
                        "Cargo.lock records a checksum for {} {} and the SBOM \
                         carries no hash for it",
                        package.name, package.version
                    )
                });
                assert_eq!(hashes[0]["alg"], "SHA-256");
                assert_eq!(
                    hashes[0]["content"].as_str().expect("a hash has content"),
                    expected,
                    "{} {}: the SBOM's SHA-256 is not the one Cargo.lock records",
                    package.name,
                    package.version
                );
                hashed += 1;
            }
            None => assert!(
                component["hashes"].is_null(),
                "{} {} has no checksum in Cargo.lock -- it is a path dependency \
                 -- so the SBOM must not claim one",
                package.name,
                package.version
            ),
        }
    }

    // Three crates named outright, so that a lock parser returning plausible
    // rubbish is caught rather than agreeing with an equally broken generator.
    for anchor in ["serde", "anyhow", "tokio"] {
        assert!(
            locked.iter().any(|package| package.name == anchor),
            "{anchor} is a direct workspace dependency and must appear in \
             Cargo.lock; not finding it means this parser read nothing useful"
        );
    }

    assert!(
        hashed > components.len() / 2,
        "only {hashed} of {} components were cross-checked against a Cargo.lock \
         checksum, which means the checksum field is not being read",
        components.len()
    );

    // Without an in-scope list the document claims nothing about scope, rather
    // than claiming everything is in it.
    for component in components {
        assert!(
            component["scope"].is_null(),
            "no in-scope list was supplied, so no component may assert a scope: \
             {component}"
        );
    }
}

#[test]
fn the_sbom_marks_what_the_released_binary_does_not_contain() {
    // ------------------------------------------------------------------------
    // `Cargo.lock` IS THE WORKSPACE. THE BINARY IS NOT.
    // ------------------------------------------------------------------------
    // The lock resolves the whole workspace, so it contains `wiremock`,
    // `insta`, `assert_cmd`, `predicates` and `serial_test` -- test-only, in no
    // released binary -- along with the internal test crates, and with
    // `security-framework`, `windows-service` and `redox_syscall`, each
    // conditional on an operating system that four of the five artifacts were
    // not built for. Publishing that list as the CONTENTS of a binary makes the
    // SBOM a false-positive generator for anyone scanning the artifact.
    //
    // So the lock supplies the inventory and `cargo tree -e normal` supplies
    // the scope. That mapping is what is asserted here; the workflow's own
    // `cargo tree` invocation needs a runner and is asserted separately, by
    // shape.
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let locked = locked_packages();

    // Two real packages out of the lock stand in for "reaches the binary", and
    // everything else for "does not".
    let in_scope_packages: Vec<&LockedPackage> = ["serde", "anyhow"]
        .iter()
        .map(|wanted| {
            locked
                .iter()
                .find(|package| package.name == *wanted)
                .unwrap_or_else(|| panic!("{wanted} must be locked"))
        })
        .collect();

    let list = temporary.path().join("in-scope.txt");
    let body: String = in_scope_packages
        .iter()
        .map(|package| format!("{} {}\n", package.name, package.version))
        .collect();
    std::fs::write(&list, &body).expect("the in-scope list must be writable");

    let document = generate_sbom(temporary.path(), Some(&list));
    let components = document["components"]
        .as_array()
        .expect("the SBOM must carry a components array");

    let mut required = 0usize;
    let mut excluded = 0usize;
    for component in components {
        let name = component["name"]
            .as_str()
            .expect("every component is named");
        let version = component["version"]
            .as_str()
            .expect("every component has a version");
        let scope = component["scope"]
            .as_str()
            .unwrap_or_else(|| panic!("{name} {version} carries no scope: {component}"));

        let listed = in_scope_packages
            .iter()
            .any(|package| package.name == name && package.version == version);
        if listed {
            assert_eq!(
                scope, "required",
                "{name} {version} is in the in-scope list and must be marked as \
                 reaching the binary"
            );
            required += 1;
        } else {
            assert_eq!(
                scope, "excluded",
                "{name} {version} is NOT in the in-scope list, so the document \
                 must not assert it as part of the released binary"
            );
            excluded += 1;
        }
    }

    assert_eq!(
        required,
        in_scope_packages.len(),
        "every listed package must have come out `required`"
    );
    assert!(
        excluded > 10,
        "only {excluded} components came out `excluded`, which means the scope \
         is not being applied rather than that the lock is nearly all runtime"
    );

    // The whole inventory is still there. Scoping a component OUT must not
    // drop it: an SBOM's job is to say what is present, and `excluded` is a
    // statement about the artifact, not an omission from the document.
    assert_eq!(
        components.len(),
        locked.len() - 1,
        "scoping must not remove components from the inventory"
    );

    // An empty list would mark the entire graph excluded and say so with a
    // straight face, which is a worse document than one claiming nothing.
    let empty = temporary.path().join("empty.txt");
    std::fs::write(&empty, "\n  \n").expect("the empty list must be writable");
    let lock = repository_root().join("Cargo.lock");
    let (accepted, output) = run_release_script(&[
        "sbom",
        &posix(&lock),
        &posix(&temporary.path().join("never.json")),
        "runner-manager",
        "9.9.9",
        &posix(&empty),
    ]);
    assert!(
        !accepted,
        "an empty in-scope list must be refused: it would mark every component \
         excluded and publish that as a finding.\n{output}"
    );
}

#[test]
fn a_checksum_line_is_the_bare_asset_name_and_two_spaces() {
    // `sha256sum` in binary mode -- the default under Git Bash, where the
    // Windows build leg runs -- writes `<hash> *<name>`, while Linux and macOS
    // produce `<hash>  <name>`. SHA256SUMS is assembled from five legs and read
    // by the install script and by every package manifest, so one format has to
    // come out regardless of which leg produced the line.
    let license = repository_root().join("LICENSE");
    let line = release_script_stdout(&["sha256", &posix(&license)]);

    let (hash, name) = line
        .split_once("  ")
        .unwrap_or_else(|| panic!("a checksum line must be `<hash>  <name>`, got: {line:?}"));
    assert_eq!(hash.len(), 64, "not a SHA-256 digest: {hash:?}");
    assert!(
        hash.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "the digest must be lower-case hex: {hash:?}"
    );
    assert_eq!(
        name, "LICENSE",
        "the recorded name must be the bare asset name. A SHA256SUMS carrying \
         build-machine paths cannot be checked by whoever downloaded the assets."
    );
}

// ----------------------------------------------------------------------------
// A small scanner, for the properties that are shapes in the YAML.
// ----------------------------------------------------------------------------

/// A line's indentation and its content, or `None` for blanks and comments.
fn significant(raw: &str) -> Option<(usize, &str)> {
    let trimmed = raw.trim_end();
    let body = trimmed.trim_start();
    if body.is_empty() || body.starts_with('#') {
        return None;
    }
    Some((trimmed.len() - body.len(), body))
}

/// `jobs.<id>.needs` for every job, in file order.
fn job_dependencies(source: &str) -> BTreeMap<String, Vec<String>> {
    let mut graph: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut inside_jobs = false;
    let mut current: Option<String> = None;

    for raw in source.lines() {
        let Some((indent, body)) = significant(raw) else {
            continue;
        };

        if indent == 0 {
            inside_jobs = body.starts_with("jobs:");
            current = None;
            continue;
        }
        if !inside_jobs {
            continue;
        }

        if indent == 2 {
            if let Some((key, _)) = body.split_once(':') {
                let name = key.trim().trim_matches(['"', '\'']).to_string();
                graph.entry(name.clone()).or_default();
                current = Some(name);
            }
            continue;
        }

        if indent == 4
            && let Some(rest) = body.strip_prefix("needs:")
        {
            let rest = rest.trim();
            let items: Vec<String> = match rest.strip_prefix('[').and_then(|r| r.strip_suffix(']'))
            {
                Some(inner) => inner
                    .split(',')
                    .map(|item| item.trim().trim_matches(['"', '\'']).to_string())
                    .filter(|item| !item.is_empty())
                    .collect(),
                None if !rest.is_empty() => vec![rest.trim_matches(['"', '\'']).to_string()],
                None => Vec::new(),
            };
            if let Some(job) = current.as_ref() {
                graph.insert(job.clone(), items);
            }
        }
    }

    graph
}

/// Every job that `job` waits on, directly or through another job.
fn upstream_of(graph: &BTreeMap<String, Vec<String>>, job: &str) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut queue = vec![job.to_string()];
    while let Some(current) = queue.pop() {
        for parent in graph.get(&current).into_iter().flatten() {
            if seen.insert(parent.clone()) {
                queue.push(parent.clone());
            }
        }
    }
    seen
}

/// Every `run:` body in the file, inline commands and block scalars alike.
fn run_bodies(source: &str) -> Vec<String> {
    let mut bodies = Vec::new();
    let lines: Vec<&str> = source.lines().collect();
    let mut index = 0usize;

    while index < lines.len() {
        let Some((indent, body)) = significant(lines[index]) else {
            index += 1;
            continue;
        };

        let Some(rest) = body.strip_prefix("run:") else {
            index += 1;
            continue;
        };

        let rest = rest.trim();
        index += 1;

        if rest.starts_with('|') || rest.starts_with('>') {
            // A block scalar: everything indented past the `run:` key.
            let mut block = String::new();
            while index < lines.len() {
                let raw = lines[index];
                if raw.trim().is_empty() {
                    index += 1;
                    continue;
                }
                let line_indent = raw.trim_end().len() - raw.trim().len();
                if line_indent <= indent {
                    break;
                }
                block.push_str(raw);
                block.push('\n');
                index += 1;
            }
            bodies.push(block);
        } else {
            bodies.push(rest.to_string());
        }
    }

    bodies
}

/// One step of one job: enough of it to say what the step RUNS and when.
#[derive(Debug, Default, Clone)]
struct WorkflowStep {
    job: String,
    name: String,
    condition: String,
    run: String,
}

/// Every step in the file, attributed to its job, with its `if:` and `run:`.
///
/// ----------------------------------------------------------------------------
/// WHY THIS EXISTS RATHER THAN ANOTHER WHOLE-FILE SUBSTRING SEARCH.
/// ----------------------------------------------------------------------------
/// Scanning the concatenated `run:` bodies proves a command is executed
/// SOMEWHERE. It cannot express "the signature check runs only on macOS", and
/// that conditional is load-bearing: `runner.os == 'macOS'` is the single value
/// deciding whether the one gate D12 requires runs at all. Binding a command to
/// the step that carries it is the only way to assert the pair.
fn workflow_steps(source: &str) -> Vec<WorkflowStep> {
    let lines: Vec<&str> = source.lines().collect();
    let mut steps: Vec<WorkflowStep> = Vec::new();
    let mut inside_jobs = false;
    let mut job = String::new();
    let mut steps_indent: Option<usize> = None;
    let mut key_indent = 0usize;
    let mut index = 0usize;

    while index < lines.len() {
        let Some((indent, body)) = significant(lines[index]) else {
            index += 1;
            continue;
        };

        if indent == 0 {
            inside_jobs = body.starts_with("jobs:");
            job.clear();
            steps_indent = None;
            index += 1;
            continue;
        }
        if !inside_jobs {
            index += 1;
            continue;
        }
        if indent == 2 {
            job = body
                .split_once(':')
                .map(|(key, _)| key.trim().trim_matches(['"', '\'']).to_string())
                .unwrap_or_default();
            steps_indent = None;
            index += 1;
            continue;
        }

        let Some(start) = steps_indent else {
            if body == "steps:" {
                steps_indent = Some(indent);
            }
            index += 1;
            continue;
        };
        if indent <= start {
            // Out of the steps list; re-examine this line as a job-level key.
            steps_indent = None;
            continue;
        }

        let (key, starts_a_step) = match body.strip_prefix("- ") {
            Some(rest) => (rest, true),
            None => (body, false),
        };
        if starts_a_step {
            key_indent = indent + 2;
            steps.push(WorkflowStep {
                job: job.clone(),
                ..WorkflowStep::default()
            });
        } else if indent != key_indent || steps.is_empty() {
            // Nested under some other key (`env:`, `with:`), not a step key.
            index += 1;
            continue;
        }

        let step = steps.last_mut().expect("a step was just pushed or exists");
        if let Some(rest) = key.strip_prefix("name:") {
            step.name = rest.trim().to_string();
            index += 1;
        } else if let Some(rest) = key.strip_prefix("if:") {
            step.condition = rest.trim().to_string();
            index += 1;
        } else if let Some(rest) = key.strip_prefix("run:") {
            let rest = rest.trim();
            index += 1;
            if rest.starts_with('|') || rest.starts_with('>') {
                let mut block = String::new();
                while index < lines.len() {
                    let raw = lines[index];
                    if raw.trim().is_empty() {
                        index += 1;
                        continue;
                    }
                    let line_indent = raw.trim_end().len() - raw.trim().len();
                    if line_indent <= key_indent {
                        break;
                    }
                    block.push_str(raw);
                    block.push('\n');
                    index += 1;
                }
                step.run = block;
            } else {
                step.run = rest.to_string();
            }
        } else {
            index += 1;
        }
    }

    steps
}

/// `jobs.<id>.<key>` for every scalar key stated directly on a job.
fn job_scalars(source: &str) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut jobs: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut inside_jobs = false;
    let mut current = String::new();

    for raw in source.lines() {
        let Some((indent, body)) = significant(raw) else {
            continue;
        };
        if indent == 0 {
            inside_jobs = body.starts_with("jobs:");
            current.clear();
            continue;
        }
        if !inside_jobs {
            continue;
        }
        if indent == 2 {
            current = body
                .split_once(':')
                .map(|(key, _)| key.trim().trim_matches(['"', '\'']).to_string())
                .unwrap_or_default();
            jobs.entry(current.clone()).or_default();
            continue;
        }
        if indent == 4
            && let Some((key, value)) = body.split_once(':')
            && !value.trim().is_empty()
            && let Some(entry) = jobs.get_mut(&current)
        {
            entry.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    jobs
}

/// `jobs.<id>.strategy.matrix.include`, as a list of key/value maps.
fn matrix_include(source: &str, job: &str) -> Vec<BTreeMap<String, String>> {
    let mut entries: Vec<BTreeMap<String, String>> = Vec::new();
    let mut inside_jobs = false;
    let mut current = String::new();
    let mut include_indent: Option<usize> = None;

    for raw in source.lines() {
        let Some((indent, body)) = significant(raw) else {
            continue;
        };
        if indent == 0 {
            inside_jobs = body.starts_with("jobs:");
            current.clear();
            include_indent = None;
            continue;
        }
        if !inside_jobs {
            continue;
        }
        if indent == 2 {
            current = body
                .split_once(':')
                .map(|(key, _)| key.trim().trim_matches(['"', '\'']).to_string())
                .unwrap_or_default();
            include_indent = None;
            continue;
        }
        if current != job {
            continue;
        }

        match include_indent {
            None => {
                if body == "include:" {
                    include_indent = Some(indent);
                }
            }
            Some(start) if indent <= start => include_indent = None,
            Some(_) => {
                if let Some(item) = body.strip_prefix("- ") {
                    let mut entry = BTreeMap::new();
                    if let Some((key, value)) = item.split_once(':') {
                        entry.insert(key.trim().to_string(), value.trim().to_string());
                    }
                    entries.push(entry);
                } else if let Some((key, value)) = body.split_once(':')
                    && let Some(entry) = entries.last_mut()
                {
                    entry.insert(key.trim().to_string(), value.trim().to_string());
                }
            }
        }
    }

    entries
}

#[test]
fn every_release_sh_decision_is_reached_from_a_step() {
    // ------------------------------------------------------------------------
    // THE SUBCOMMANDS ARE TESTED IN ISOLATION EVERYWHERE ELSE IN THIS FILE.
    // ------------------------------------------------------------------------
    // That is the whole design: the decisions were extracted so they could be
    // run without a credential. But a decision nothing CALLS is a decision the
    // release does not make, and an extracted-and-tested subcommand looks
    // exactly as healthy in isolation whether or not a step still invokes it.
    //
    // Deleting the macOS signature step from release.yml -- the one step whose
    // absence makes a Definition-of-Done item false -- used to leave every test
    // in this file green. So did deleting step 2, which removes monotonicity
    // entirely. These assertions are what bind a subcommand to a step.
    let source = read_workflow("release.yml");
    let steps = workflow_steps(&source);

    assert!(
        steps.len() > 20,
        "only {} steps parsed out of release.yml, which means this scanner is \
         broken rather than that the workflow has almost no steps",
        steps.len()
    );

    for (subcommand, why) in [
        (
            "release.sh check-format",
            "step 1 -- without it a malformed version is never rejected",
        ),
        (
            "release.sh manifest-version",
            "step 2's first source -- the Cargo.toml version",
        ),
        (
            "release.sh latest-release-version",
            "step 2's second source -- the latest published release",
        ),
        (
            "release.sh check-monotonic",
            "step 2 -- without it a release can regress the version",
        ),
        (
            "release.sh set-version",
            "step 4 -- without it the artifacts carry the old version",
        ),
        (
            "release.sh check-native-runner",
            "steps 1-2 and 5 -- without it a repointed `runs-on` label builds \
             the wrong platform under the right artifact name",
        ),
        (
            "release.sh verify-macos-signature",
            "step 5 -- without it an unsigned arm64 binary ships, and it does \
             not execute on Apple Silicon at all (D12)",
        ),
        (
            "release.sh sha256",
            "step 6 -- without it there is nothing to build SHA256SUMS from",
        ),
        (
            "release.sh sbom",
            "step 6 -- the release page must carry an SBOM",
        ),
    ] {
        assert!(
            steps.iter().any(|step| step.run.contains(subcommand)),
            "no step in release.yml runs `{subcommand}`. It is {why}. The \
             subcommand's own tests in this file pass whether or not the \
             workflow still calls it, so this is the only assertion that \
             notices the step being deleted."
        );
    }

    // ------------------------------------------------------------------------
    // AND THE CONDITION THE SIGNATURE GATE HANGS ON.
    // ------------------------------------------------------------------------
    // `codesign` exists only on macOS, so the step must be conditional -- but
    // `runner.os` is then the single value deciding whether the gate runs, and
    // a condition naming the wrong thing disables it silently on the leg that
    // needs it.
    let signature: Vec<&WorkflowStep> = steps
        .iter()
        .filter(|step| step.run.contains("release.sh verify-macos-signature"))
        .collect();
    assert_eq!(
        signature.len(),
        1,
        "expected exactly one step to verify the macOS signature, found {}: {:?}",
        signature.len(),
        signature.iter().map(|step| &step.name).collect::<Vec<_>>()
    );
    let signature = signature[0];
    assert!(
        signature.condition.contains("runner.os == 'macOS'"),
        "the signature check must be gated on `runner.os == 'macOS'`, not on \
         the matrix target or the runner label: it is the OS that decides \
         whether `codesign` exists. Found `if: {}`",
        signature.condition
    );
    assert_eq!(
        signature.job, "build",
        "the signature check must run in the job that produced the binary, so \
         that what it inspects is this leg's own output"
    );
}

#[test]
fn every_build_label_is_proved_before_anything_is_written() {
    // ------------------------------------------------------------------------
    // THE ARCH ASSERTION CANNOT CATCH A LABEL THAT RESOLVES TO NO RUNNER.
    // ------------------------------------------------------------------------
    // GitHub treats an unrecognised `runs-on` label as a self-hosted label: the
    // job does not fail, it queues, and an assertion inside a job that never
    // starts never runs. `macos-15-intel` and `ubuntu-24.04-arm` are both
    // hosted labels GitHub has moved before, and both are overridable by
    // repository variable.
    //
    // `build` needs `tag`, so without a preflight that queue happens AFTER the
    // version commit and the tag are pushed: four legs green, one leg waiting,
    // nothing published, and an operator deleting a tag by hand. Running the
    // same assertion on the same labels above `tag` makes a dispatch that
    // cannot build a dispatch that changed nothing.
    let source = read_workflow("release.yml");
    let graph = job_dependencies(&source);

    assert!(
        graph.contains_key("preflight"),
        "release.yml must declare a `preflight` job. Parsed jobs: {:?}",
        graph.keys().collect::<Vec<_>>()
    );
    let above_tag = upstream_of(&graph, "tag");
    assert!(
        above_tag.contains("preflight"),
        "`tag` is the first job that cannot be undone, so `preflight` must sit \
         above it. Resolved upstream of tag: {above_tag:?}"
    );

    // The two matrices are separate lists because Actions cannot share one.
    // A preflight covering four of the five labels would be worse than none:
    // it would read as proof.
    let preflight = matrix_include(&source, "preflight");
    let build = matrix_include(&source, "build");
    assert_eq!(
        build.len(),
        5,
        "expected the five documented targets in the build matrix, parsed: {build:?}"
    );

    let labels = |entries: &[BTreeMap<String, String>]| -> BTreeSet<(String, String)> {
        entries
            .iter()
            .map(|entry| {
                (
                    entry
                        .get("target")
                        .unwrap_or_else(|| panic!("a matrix entry has no target: {entry:?}"))
                        .clone(),
                    entry
                        .get("os")
                        .unwrap_or_else(|| panic!("a matrix entry has no os: {entry:?}"))
                        .clone(),
                )
            })
            .collect()
    };
    assert_eq!(
        labels(&preflight),
        labels(&build),
        "`preflight` must check the same target/label pairs `build` will use, \
         including the repository-variable overrides. A label proved by nothing \
         is the one that hangs after the tag is pushed."
    );

    // A leg that starts and then wedges is a different failure, and the 360
    // minute default is what applies to it. `test` is exempt: it is a
    // reusable-workflow call, which takes no `timeout-minutes`.
    let jobs = job_scalars(&source);
    assert!(
        jobs.len() >= 6,
        "only {} jobs parsed out of release.yml: {:?}",
        jobs.len(),
        jobs.keys().collect::<Vec<_>>()
    );
    for (name, keys) in &jobs {
        if !keys.contains_key("runs-on") {
            continue;
        }
        let timeout = keys.get("timeout-minutes").unwrap_or_else(|| {
            panic!(
                "job `{name}` declares `runs-on` and no `timeout-minutes`, so \
                 GitHub's 360-minute default applies. This workflow pushes a tag \
                 before it builds anything: six hours of a wedged leg is six \
                 hours of a tag with nothing published."
            )
        });
        let minutes: u32 = timeout.parse().unwrap_or_else(|_| {
            panic!("job `{name}` has a non-numeric timeout-minutes: {timeout}")
        });
        assert!(
            (1..=60).contains(&minutes),
            "job `{name}` allows {minutes} minutes. A release build of this \
             workspace is minutes, not hours, and the whole point of the value \
             is to be far below the default."
        );
    }
}

#[test]
fn a_release_runner_must_be_native_in_both_os_and_architecture() {
    // ------------------------------------------------------------------------
    // `runner.arch` ALONE DOES NOT SAY "NATIVE".
    // ------------------------------------------------------------------------
    // An override pointing RUNNER_MANAGER_RELEASE_RUNS_ON_MACOS_X64 at a Linux
    // x64 label satisfies an architecture-only assertion. And `runner.os` is
    // exactly the value the signature gate is conditional on, so that override
    // would produce an ELF named as a macOS artifact and skip the one check
    // that would have noticed it.
    //
    // Driven through the subcommand rather than by reading the workflow's text:
    // an assertion that a `run:` body mentions `RUNNER_OS` is satisfied by a
    // body that mentions it and never compares it.
    let native = [
        ("x86_64-pc-windows-msvc", "Windows", "X64"),
        ("aarch64-apple-darwin", "macOS", "ARM64"),
        ("x86_64-apple-darwin", "macOS", "X64"),
        ("x86_64-unknown-linux-gnu", "Linux", "X64"),
        ("aarch64-unknown-linux-gnu", "Linux", "ARM64"),
    ];
    for (target, os, arch) in native {
        let (ok, output) = run_release_script(&["check-native-runner", target, os, arch]);
        assert!(
            ok,
            "check-native-runner rejected {target} on a {os} {arch} runner, \
             which is the native pairing this release matrix uses.\n{output}"
        );
    }

    // The architecture half.
    for (target, os, arch) in [
        ("x86_64-pc-windows-msvc", "Windows", "ARM64"),
        ("aarch64-apple-darwin", "macOS", "X64"),
        ("x86_64-unknown-linux-gnu", "Linux", "ARM64"),
        ("aarch64-unknown-linux-gnu", "Linux", "X64"),
    ] {
        let (accepted, output) = run_release_script(&["check-native-runner", target, os, arch]);
        assert!(
            !accepted,
            "{target} was accepted on a {arch} runner. Nothing here \
             cross-compiles.\n{output}"
        );
    }

    // The operating-system half, which an arch-only assertion misses entirely.
    // The first row is the live risk: a repository variable is what supplies
    // that label, and both values below are x64.
    for (target, os, arch, why) in [
        (
            "x86_64-apple-darwin",
            "Linux",
            "X64",
            "a Linux x64 label behind RUNNER_MANAGER_RELEASE_RUNS_ON_MACOS_X64 \
             would produce an ELF named as a macOS artifact -- and skip the \
             signature gate, which is conditional on runner.os",
        ),
        (
            "x86_64-pc-windows-msvc",
            "Linux",
            "X64",
            "a Linux runner cannot produce an MSVC binary",
        ),
        (
            "x86_64-unknown-linux-gnu",
            "macOS",
            "X64",
            "a macOS runner cannot produce a linux-gnu binary",
        ),
        (
            "aarch64-apple-darwin",
            "Linux",
            "ARM64",
            "matching architecture is not matching platform",
        ),
    ] {
        let (accepted, output) = run_release_script(&["check-native-runner", target, os, arch]);
        assert!(
            !accepted,
            "{target} was accepted on a {os} {arch} runner: {why}.\n{output}"
        );
        assert!(
            output.contains("must be built on a"),
            "the rejection must name what the target needed.\n{output}"
        );
    }

    // A target this mapping does not recognise must stop the run rather than
    // fall through as "fine".
    for target in [
        "riscv64gc-unknown-linux-gnu",
        "x86_64-unknown-freebsd",
        "nonsense",
    ] {
        let (accepted, output) =
            run_release_script(&["check-native-runner", target, "Linux", "X64"]);
        assert!(
            !accepted,
            "check-native-runner accepted the unrecognised target {target}. A \
             target it cannot classify is one it cannot vouch for.\n{output}"
        );
    }

    // And both jobs that use the matrix labels must actually call it:
    // `preflight` so the label is proved before the tag, `build` so this leg's
    // own runner is proved for the binary it is about to produce.
    let source = read_workflow("release.yml");
    let steps = workflow_steps(&source);
    for job in ["preflight", "build"] {
        assert!(
            steps
                .iter()
                .any(|step| step.job == job && step.run.contains("release.sh check-native-runner")),
            "job `{job}` must run `release.sh check-native-runner`. Parsed \
             steps for it: {:?}",
            steps
                .iter()
                .filter(|step| step.job == job)
                .map(|step| &step.name)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn nothing_is_published_without_the_full_test_matrix() {
    let source = read_workflow("release.yml");
    let graph = job_dependencies(&source);

    // Positive first: an unreadable `jobs:` block would make every reachability
    // assertion below pass over an empty graph.
    for required in ["validate", "test", "tag", "build", "sbom", "publish"] {
        assert!(
            graph.contains_key(required),
            "release.yml must declare a `{required}` job. Parsed jobs: {:?}",
            graph.keys().collect::<Vec<_>>()
        );
    }

    let upstream = upstream_of(&graph, "publish");
    for required in ["validate", "test", "tag", "build", "sbom"] {
        assert!(
            upstream.contains(required),
            "`publish` must wait, directly or transitively, on `{required}`. \
             A release that can publish without it is a release that publishes \
             untested or unbuilt code. Resolved upstream of publish: {upstream:?}"
        );
    }

    // Ordering, as `needs:` edges. `tag` is the first job that writes anything,
    // so both validation and the test matrix have to sit above it: a version
    // rejected at step 1 or a red test leg must leave no tag behind.
    let above_tag = upstream_of(&graph, "tag");
    assert!(
        above_tag.contains("validate") && above_tag.contains("test"),
        "`tag` writes the version commit and pushes the tag, so it must wait on \
         both `validate` and `test`. Resolved upstream of tag: {above_tag:?}"
    );

    let above_build = upstream_of(&graph, "build");
    assert!(
        above_build.contains("tag"),
        "`build` must wait on `tag` so the artifacts carry the version that was \
         written. Resolved upstream of build: {above_build:?}"
    );
}

#[test]
fn the_test_gate_calls_ci_rather_than_reimplementing_it() {
    let release = read_workflow("release.yml");
    assert!(
        release.contains("uses: ./.github/workflows/ci.yml"),
        "release.yml's test gate must CALL ci.yml. A copied matrix drifts, and a \
         drifted copy means the release is gated on checks CI used to run."
    );

    // The other half of the same seam: calling it only works if ci.yml offers
    // the entry point, and a1's trigger allow-list admits `workflow_call`
    // precisely so that a2 could add it without editing that test.
    let ci = read_workflow("ci.yml");
    let has_entry_point = ci
        .lines()
        .filter_map(significant)
        .any(|(indent, body)| indent == 2 && body.starts_with("workflow_call:"));
    assert!(
        has_entry_point,
        "ci.yml must declare `workflow_call:` in its `on:` block, or \
         release.yml's `uses:` cannot reach it"
    );
}

#[test]
fn every_published_target_is_covered_by_the_build_matrix() {
    let source = read_workflow("release.yml");

    // `env.RELEASE_TARGETS`, the list `publish` checks the assets against.
    let mut lines = source.lines();
    let key_indent = loop {
        match lines.next() {
            Some(line) if line.trim_start().starts_with("RELEASE_TARGETS:") => {
                break line.trim_end().len() - line.trim().len();
            }
            Some(_) => continue,
            None => panic!("release.yml must declare `env.RELEASE_TARGETS`"),
        }
    };
    let mut published: BTreeSet<String> = BTreeSet::new();
    for line in lines {
        let Some((indent, body)) = significant(line) else {
            continue;
        };
        if indent <= key_indent {
            break;
        }
        published.extend(body.split_whitespace().map(String::from));
    }

    // The `build` matrix, which cannot be generated from the list above: the
    // `env` context is not available in `jobs.<id>.strategy`.
    let built: BTreeSet<String> = source
        .lines()
        .filter_map(|line| line.trim().strip_prefix("- target:"))
        .map(|target| target.trim().to_string())
        .collect();

    assert!(
        published.len() >= 5,
        "expected the five documented targets in RELEASE_TARGETS, parsed: {published:?}"
    );
    assert_eq!(
        built, published,
        "the build matrix and RELEASE_TARGETS must name the same targets. They \
         are two lists because the `env` context is not available in a matrix, \
         and this is the assertion that keeps them from drifting -- a target \
         added to one and not the other either never gets built or never gets \
         checked for at publication."
    );

    // The five are named explicitly so that quietly dropping a platform from
    // both lists at once still fails (D11: the release page must list Windows,
    // macOS x64 and arm64, and Linux x64 and arm64).
    for target in [
        "x86_64-pc-windows-msvc",
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
    ] {
        assert!(
            published.contains(target),
            "{target} must be published. Parsed: {published:?}"
        );
    }
}

#[test]
fn the_release_workflow_never_deletes_or_overwrites_what_it_published() {
    let source = read_workflow("release.yml");

    // ------------------------------------------------------------------------
    // SCANNED OVER THE `run:` BODIES, NOT OVER THE FILE.
    // ------------------------------------------------------------------------
    // The spec requires this workflow to DOCUMENT the operator recovery --
    // "delete the tag, re-dispatch" -- in the workflow file itself
    // (`09-release-distribution.md`). So the file necessarily contains the
    // words `git tag -d`, in a comment, as instructions for a human. A
    // whole-file substring search cannot tell that apart from a step that runs
    // it, and would force the workflow to choose between documenting the
    // recovery and passing this test. What matters is not whether the string
    // appears but whether it is EXECUTED, so only executable text is scanned.
    let executable = run_bodies(&source).join("\n");
    assert!(
        !executable.is_empty(),
        "no `run:` bodies parsed out of release.yml; every absence asserted \
         below would be vacuous"
    );

    // "The workflow never deletes a published release"
    // (`09-release-distribution.md`). Deleting one breaks every checksum that
    // anyone pinned against it, so recovery is an operator decision every time.
    for forbidden in [
        "gh release delete",
        "release delete-asset",
        "git tag -d",
        "push --delete",
        "push -d ",
        "push --force",
        "push -f ",
        "--force-with-lease",
        "-X DELETE",
    ] {
        assert!(
            !executable.contains(forbidden),
            "a `run:` body in release.yml executes `{forbidden}`. Recovery from \
             a failed release is documented in the workflow header and performed \
             by an operator, never by the workflow itself."
        );
    }

    assert!(
        executable.contains("gh release create"),
        "release.yml must create the release -- the positive half, without which \
         every absence asserted above is satisfied by a workflow that publishes \
         nothing at all"
    );
    assert!(
        executable.contains("--verify-tag"),
        "`gh release create --verify-tag` refuses to invent a tag, so the \
         release can only ever be published against the tag the `tag` job \
         actually pushed"
    );
    assert!(
        executable.contains("git push --atomic"),
        "the version commit and the tag must be pushed atomically: a partial \
         push is exactly the tagged-but-unpublished state an operator then has \
         to clean up by hand"
    );

    // ------------------------------------------------------------------------
    // THE DECISIONS HAVE TO BE CALLED, NOT MERELY TO EXIST.
    // ------------------------------------------------------------------------
    // Every subcommand below is tested in isolation elsewhere in this file, and
    // an isolated test passes whether or not release.yml still invokes it. The
    // step/`if:` binding is asserted by
    // `every_release_sh_decision_is_reached_from_a_step`; these are the cheap
    // whole-file half of the same guard, and they red the moment a step
    // carrying one of them is deleted.
    for required in [
        "release.sh check-format",
        "release.sh check-monotonic",
        "release.sh latest-release-version",
        "release.sh set-version",
        "release.sh check-native-runner",
        "release.sh verify-macos-signature",
        "release.sh sbom",
    ] {
        assert!(
            executable.contains(required),
            "no `run:` body in release.yml executes `{required}`. The decision \
             it makes is one this workflow is required to make, and its own \
             tests cannot tell that the step invoking it is gone."
        );
    }

    // The SBOM's scope claim has to have a source. `release.sh sbom` accepts
    // the list as an optional argument and says nothing about scope without
    // one, so a workflow that stopped producing it would publish a document
    // that quietly dropped the distinction rather than one that fails.
    assert!(
        executable.contains("cargo tree"),
        "the SBOM's `scope` must be resolved from `cargo tree`, or the \
         published document describes the whole workspace lock as the contents \
         of the binary"
    );
    let generator = run_bodies(&source)
        .into_iter()
        .find(|body| body.contains("release.sh sbom"))
        .expect("a step must invoke `release.sh sbom`");
    assert!(
        generator.contains("in-scope.txt"),
        "the in-scope list must be passed to `release.sh sbom` as its fifth \
         argument. Without it the generator emits no `scope` at all, and the \
         release notes then describe a distinction the document does not \
         make:\n{generator}"
    );

    // The recovery procedure itself must stay documented in the file, which is
    // a requirement in its own right and also what makes the scoping above
    // load-bearing rather than a convenience.
    assert!(
        source.contains("OPERATOR RECOVERY"),
        "release.yml must document the operator recovery for a failure after \
         tagging (`09-release-distribution.md`)"
    );
}

#[test]
fn the_dispatch_input_never_reaches_a_shell_through_interpolation() {
    // ------------------------------------------------------------------------
    // THIS IS THE ONE WORKFLOW THAT TAKES FREE TEXT FROM A HUMAN AND HOLDS THE
    // PUBLISHING CREDENTIAL.
    // ------------------------------------------------------------------------
    // `${{ ... }}` is substituted into a `run:` body before the shell parses
    // it, so an expression inside a script is executed rather than read. For
    // the `version` input that inverts the whole design: step 1 exists to
    // reject inputs that are not `X.Y.Z`, and interpolation would run the input
    // before step 1 could look at it.
    //
    // Scoped to release.yml deliberately. ci.yml interpolates `runner.arch`
    // into an echo, which is a value GitHub sets and no user supplies; the rule
    // worth enforcing without exception is the one on the workflow that can
    // publish.
    let source = read_workflow("release.yml");
    let bodies = run_bodies(&source);

    assert!(
        bodies.len() > 10,
        "only {} `run:` bodies parsed out of release.yml, which means this scan \
         is broken rather than that the workflow has almost no steps",
        bodies.len()
    );

    for body in &bodies {
        assert!(
            !body.contains("${{"),
            "a `run:` body in release.yml interpolates a workflow expression. \
             Pass the value through `env:` and read it as a shell variable \
             instead:\n{body}"
        );
    }

    // And the positive half: the input has to reach the steps somehow, so
    // assert it does -- through `env:`.
    assert!(
        source.contains("VERSION: ${{ inputs.version }}"),
        "the version input must reach the steps through an `env:` binding"
    );
}
