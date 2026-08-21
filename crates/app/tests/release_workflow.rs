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

    let mut combined = String::from_utf8_lossy(&stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&stderr));
    (status.success(), combined)
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

// ----------------------------------------------------------------------------
// Step 5 -- the macOS signature check.
// ----------------------------------------------------------------------------

/// Writes a fake `codesign` onto a directory that the test prepends to `PATH`.
///
/// Real `codesign` exists only on macOS, so on two of this repository's three
/// supported platforms the only way to exercise the DECISION is to control what
/// the tool says. This does not claim to model Apple's tool -- see the caveat
/// in this file's header -- it pins what `release.sh` does with each answer.
fn stub_codesign(directory: &Path, display_body: &str, verify_exit: i32) {
    let script = format!(
        "#!/usr/bin/env bash\n\
         case \"$1\" in\n\
         --display) {display_body}; exit 0 ;;\n\
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
        r#"printf 'Executable=%s\nIdentifier=runner-manager\nSignature=adhoc\n' "$2" >&2"#,
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
    // `codesign --display` on an unsigned Mach-O says so in words.
    stub_codesign(
        &stub_directory,
        r#"printf '%s: code object is not signed at all\n' "$2" >&2"#,
        1,
    );
    let (accepted, output) =
        run_release_script_with_path(&["verify-macos-signature", &binary], Some(&stub_directory));
    assert!(
        !accepted,
        "a binary carrying no signature must fail the run. An unsigned arm64 \
         Mach-O does not execute on Apple Silicon at all (D12).\n{output}"
    );

    // -- a signature that is present but does not verify ----------------------
    stub_codesign(
        &stub_directory,
        r#"printf 'Executable=%s\nSignature=adhoc\n' "$2" >&2"#,
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
        r#"printf 'Executable=%s\nIdentifier=runner-manager\n' "$2" >&2"#,
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

#[test]
fn the_sbom_describes_every_locked_package() {
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let lock = repository_root().join("Cargo.lock");
    let output_path = temporary.path().join("sbom.cdx.json");

    release_script_stdout(&[
        "sbom",
        &posix(&lock),
        &posix(&output_path),
        "runner-manager",
        "9.9.9",
    ]);

    let text = std::fs::read_to_string(&output_path).expect("the SBOM must have been written");
    let document: serde_json::Value =
        serde_json::from_str(&text).expect("the SBOM must be valid JSON");

    assert_eq!(document["bomFormat"], "CycloneDX");
    assert_eq!(document["specVersion"], "1.5");
    assert_eq!(document["metadata"]["component"]["name"], "runner-manager");
    assert_eq!(document["metadata"]["component"]["version"], "9.9.9");

    let components = document["components"]
        .as_array()
        .expect("the SBOM must carry a components array");

    // The count is pinned to Cargo.lock rather than to a magic number: the SBOM
    // must describe the graph that was actually locked, and the product itself
    // is `metadata.component`, not one of its own dependencies.
    let locked = std::fs::read_to_string(&lock).expect("Cargo.lock must be readable");
    let locked_packages = locked
        .lines()
        .filter(|line| line.trim_end() == "[[package]]")
        .count();
    assert!(
        locked_packages > 1,
        "Cargo.lock parsed as {locked_packages} packages, which means this scan \
         is broken rather than that the workspace has no dependencies"
    );
    assert_eq!(
        components.len(),
        locked_packages - 1,
        "the SBOM must list every locked package except the product itself"
    );

    let mut hashed = 0usize;
    for component in components {
        let name = component["name"]
            .as_str()
            .expect("every component is named");
        let version = component["version"]
            .as_str()
            .expect("every component has a version");
        assert!(
            !name.is_empty(),
            "a component was emitted with an empty name"
        );
        assert_eq!(
            component["purl"]
                .as_str()
                .expect("every component has a purl"),
            format!("pkg:cargo/{name}@{version}"),
            "the package URL must identify the crate and its exact version"
        );
        if let Some(hashes) = component["hashes"].as_array() {
            assert_eq!(hashes[0]["alg"], "SHA-256");
            let content = hashes[0]["content"].as_str().expect("a hash has content");
            assert_eq!(content.len(), 64, "{name}: not a SHA-256 digest: {content}");
            hashed += 1;
        }
    }

    // Registry packages carry a checksum in Cargo.lock; the handful of workspace
    // members, which are path dependencies, do not. If NOTHING came out hashed
    // the checksum column was simply not being read.
    assert!(
        hashed > components.len() / 2,
        "only {hashed} of {} components carry a SHA-256, which means the \
         checksum field is not being read out of Cargo.lock",
        components.len()
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
