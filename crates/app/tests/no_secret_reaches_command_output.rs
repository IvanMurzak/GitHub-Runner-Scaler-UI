// owner: f1-cli-auth-host-status
//
// ----------------------------------------------------------------------------
// THE SECRET-INJECTION SCAN, OVER THE WHOLE COMMAND SURFACE.
// ----------------------------------------------------------------------------
// `f1`: "No command output contains a token, device code, or JIT blob, verified
// by a log scan over the full command set." `07-security.md`'s release gate is
// the same sentence one level up: "The user access token and the encoded JIT
// configuration are absent from logs, databases, snapshots, crash reports, and
// CLI output."
//
// ----------------------------------------------------------------------------
// A SCAN THAT CANNOT FAIL IS WORTH NOTHING, SO THIS ONE IS SHOWN TO FAIL.
// ----------------------------------------------------------------------------
// Two independent controls, because the two ways this test could rot are
// different:
//
//   1. `the_scanner_finds_every_needle_when_they_are_planted` runs the scanner
//      over a corpus that DOES contain all three secrets, and requires it to
//      report all three. A scanner that had stopped matching -- a changed
//      fixture, a normalisation that ate the needle -- fails here.
//
//   2. `the_scanned_corpus_contains_what_it_should_contain` requires the real
//      corpus to hold the values that are allowed and expected: the user code,
//      which `07-security.md` says is displayed by design, and output from
//      every command that was run. An empty corpus would otherwise pass the
//      main assertion perfectly.
//
// Without both, "no secret was found" is indistinguishable from "nothing was
// looked at".

mod support;

use std::path::{Path, PathBuf};

use support::{
    FIXTURE_USER_CODE, FakeGithub, fixture_device_code, fixture_token, run, runner_manager_against,
};

/// Every command in `02-target-architecture.md`'s exhaustive list, with
/// arguments that parse.
///
/// `auth login` and `auth logout` are handled separately below, because the
/// order matters: the login has to happen first so that a real token is in the
/// store while everything else runs, and the logout has to happen last so that
/// everything else runs with one to leak.
const COMMANDS: &[&[&str]] = &[
    &["--version"],
    &["--help"],
    &["auth", "status"],
    &["host", "set-capacity", "2"],
    &["host", "show"],
    &[
        "repo",
        "add",
        "owner/repo",
        "--host-label",
        "home-win",
        "--max-capacity",
        "1",
    ],
    &["repo", "list"],
    &["repo", "set-capacity", "owner/repo", "--max-capacity", "2"],
    &["repo", "set-scale", "owner/repo", "--enabled", "true"],
    &["repo", "remove", "owner/repo"],
    &[
        "org",
        "add",
        "acme",
        "--host-label",
        "home-win",
        "--max-capacity",
        "1",
    ],
    &["org", "list"],
    &["org", "set-capacity", "acme", "--max-capacity", "2"],
    &["org", "set-scale", "acme", "--enabled", "false"],
    &["org", "remove", "acme", "--purge"],
    &["daemon", "run"],
    &["service", "install", "--start-at", "boot"],
    &["service", "uninstall"],
    &["service", "status"],
    &["tui"],
    &["status"],
    &["status", "--json"],
];

/// The three values that must never appear, with the name each is known by.
fn needles() -> Vec<(&'static str, String)> {
    vec![
        ("the user access token", fixture_token()),
        ("the device code", fixture_device_code()),
        (
            "the encoded JIT configuration",
            runner_manager_testkit::github::DEFAULT_JIT_CONFIG.to_string(),
        ),
    ]
}

/// One piece of text that was produced by the run, and where it came from.
#[derive(Debug)]
struct Fragment {
    origin: String,
    text: String,
}

/// Which needles appear in a corpus, and where.
fn scan(corpus: &[Fragment]) -> Vec<String> {
    let mut found = Vec::new();
    for (name, needle) in needles() {
        for fragment in corpus {
            if fragment.text.contains(&needle) {
                found.push(format!("{name} appears in {}", fragment.origin));
            }
        }
    }
    found
}

fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found
}

/// Whether a path is inside the machine-scoped secret store.
///
/// The store is the **one** place the token is allowed to be — that is what it
/// is for — and on Linux `d2` keeps it there as a `0600` file rather than as
/// ciphertext, so a scan that included it would fail on one platform for the
/// correct behaviour. `d2`'s own `no_token_outside_the_store.rs` draws the same
/// line, and this is the CLI-side half of it.
fn is_the_secret_store(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == "secrets")
}

/// Runs the whole command surface with a real credential in the store and
/// returns everything it produced.
fn corpus_from_the_full_command_set(verbose: bool) -> (tempfile::TempDir, Vec<Fragment>) {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let github = FakeGithub::start();
    github.with_device_code();
    github.with_approval();
    github.with_installation(
        11,
        "operator",
        "User",
        "selected",
        &["operator/one", "operator/two"],
    );

    let mut corpus = Vec::new();

    let mut record = |name: String, arguments: &[&str]| {
        let outcome = run({
            let mut command = runner_manager_against(data_dir.path(), &github);
            if verbose {
                command.env("RUST_LOG", "trace");
            }
            command.args(arguments);
            command
        });
        corpus.push(Fragment {
            origin: format!("`{name}` stdout"),
            text: outcome.stdout,
        });
        corpus.push(Fragment {
            origin: format!("`{name}` stderr"),
            text: outcome.stderr,
        });
    };

    record("auth login".to_string(), &["auth", "login"]);
    for arguments in COMMANDS {
        record(arguments.join(" "), arguments);
    }
    record("auth logout".to_string(), &["auth", "logout"]);

    // Everything the commands left on disk, except the store itself.
    for path in files_under(data_dir.path()) {
        if is_the_secret_store(&path) {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        corpus.push(Fragment {
            origin: format!("the file {}", path.display()),
            text: String::from_utf8_lossy(&bytes).into_owned(),
        });
    }

    (data_dir, corpus)
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

#[test]
fn no_secret_reaches_the_output_of_any_command() {
    let (_data_dir, corpus) = corpus_from_the_full_command_set(false);
    let found = scan(&corpus);
    assert!(
        found.is_empty(),
        "`07-security.md`'s release gate: the user access token and the encoded JIT \
         configuration are absent from logs, databases, snapshots, crash reports, and CLI \
         output. Found:\n  {}",
        found.join("\n  ")
    );
}

/// The same, with diagnostics turned all the way up. `d1`'s sink redacts by
/// allowlist, so a field it has not been told about is redacted rather than
/// printed — but a value interpolated into a *message* is not a field, and
/// `trace` is where such a message would be.
#[test]
fn no_secret_reaches_the_diagnostics_at_trace_level() {
    let (_data_dir, corpus) = corpus_from_the_full_command_set(true);
    let found = scan(&corpus);
    assert!(
        found.is_empty(),
        "at RUST_LOG=trace. Found:\n  {}",
        found.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Control 1: the scanner can find what it is looking for
// ---------------------------------------------------------------------------

#[test]
fn the_scanner_finds_every_needle_when_they_are_planted() {
    let planted: Vec<Fragment> = needles()
        .into_iter()
        .map(|(name, value)| Fragment {
            origin: format!("a planted fragment for {name}"),
            text: format!("prefix {value} suffix"),
        })
        .collect();

    let found = scan(&planted);
    assert_eq!(
        found.len(),
        needles().len(),
        "the scanner must find all {} planted secrets, or the clean result above is a \
         needle that never matched. Found: {found:?}",
        needles().len()
    );

    // And one at a time, so a scanner that only ever matched the first is
    // caught too.
    for (name, value) in needles() {
        let single = [Fragment {
            origin: "one planted fragment".to_string(),
            text: value.clone(),
        }];
        assert_eq!(
            scan(&single).len(),
            1,
            "{name} alone must be found; the scanner cannot be relied on for the other \
             two if it cannot see this one"
        );
    }
}

/// The needles are also what the fixture actually uses. A test whose token
/// fixture drifted from the one the login stores would scan for a value the run
/// never produced.
#[test]
fn the_needles_are_the_values_the_run_really_handles() {
    assert!(
        fixture_token().starts_with("ghu_"),
        "the token fixture must be shaped like the user-to-server token `c2` mints, or \
         the scan is looking for something the product would never emit"
    );
    assert!(
        !fixture_token().is_empty() && fixture_token().len() > 20,
        "a short or empty needle would match by accident"
    );
    assert!(!fixture_device_code().is_empty());
    assert!(
        !runner_manager_testkit::github::DEFAULT_JIT_CONFIG.is_empty(),
        "the JIT fixture comes from `testkit`, so it stays the same value `e3` and `h1` \
         scan for"
    );
}

// ---------------------------------------------------------------------------
// Control 2: the corpus is not empty
// ---------------------------------------------------------------------------

#[test]
fn the_scanned_corpus_contains_what_it_should_contain() {
    let (data_dir, corpus) = corpus_from_the_full_command_set(true);

    let everything: String = corpus
        .iter()
        .map(|fragment| fragment.text.as_str())
        .collect();

    assert!(
        everything.contains(FIXTURE_USER_CODE),
        "the user code IS displayed by design (`07-security.md`), so its absence would \
         mean the login never ran and the whole scan was over nothing"
    );
    assert!(
        everything.contains("What you are about to grant"),
        "the disclosure must be in the corpus, for the same reason"
    );
    assert!(
        everything.contains("host_capacity"),
        "`host show` must be in the corpus"
    );
    assert!(
        everything.contains("\"schema_version\""),
        "`status --json` must be in the corpus"
    );
    assert!(
        everything.contains("task f2") && everything.contains("task f3"),
        "the declared-but-unimplemented commands must have been run too: the gate is over \
         the FULL command set, and a command nobody ran cannot leak in a test"
    );

    // The diagnostics file exists and was written to, so "no secret in the
    // logs" is a statement about logs that exist.
    let logs: Vec<PathBuf> = files_under(&data_dir.path().join("logs"));
    assert!(
        !logs.is_empty(),
        "the run must have produced diagnostics under logs/, or the log half of this scan \
         examined nothing"
    );
    let diagnostics: usize = logs
        .iter()
        .filter_map(|path| std::fs::metadata(path).ok())
        .map(|metadata| usize::try_from(metadata.len()).unwrap_or(usize::MAX))
        .sum();
    assert!(
        diagnostics > 0,
        "the diagnostics files are all empty, so scanning them proves nothing. Files: \
         {logs:?}"
    );
}

/// The token has to be *somewhere* after a login, or the scan above passed
/// because nothing was ever stored. It is in the secret store, and only there.
#[test]
fn the_token_is_in_the_store_and_nowhere_else_under_the_data_directory() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let github = FakeGithub::start();
    github.with_device_code();
    github.with_approval();
    github.with_no_installations();

    let login = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args(["auth", "login"]);
        command
    });
    assert_eq!(login.code, 0, "stderr: {}", login.stderr);

    let mut outside = Vec::new();
    let mut store_files = 0_usize;
    for path in files_under(data_dir.path()) {
        if is_the_secret_store(&path) {
            store_files += 1;
            continue;
        }
        if let Ok(bytes) = std::fs::read(&path)
            && String::from_utf8_lossy(&bytes).contains(&fixture_token())
        {
            outside.push(path.display().to_string());
        }
    }

    assert!(
        store_files > 0,
        "a successful login must have written something into the secret store; if it did \
         not, the assertion below is about a token that was never stored"
    );
    assert!(
        outside.is_empty(),
        "the token must live in the machine-scoped store and nowhere else -- not in \
         config, not in SQLite, not in the diagnostics: {outside:?}"
    );
}
