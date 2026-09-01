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
//
// ----------------------------------------------------------------------------
// WHICH THIRD OF THIS GATE IS ACTUALLY f1's, NEEDLE BY NEEDLE.
// ----------------------------------------------------------------------------
// An earlier version of this header concluded that the log half of the scan is
// redundant with `d1`'s redacting sink. That is right for two needles and wrong
// for the third, and the third is the one `07-security.md` singles out.
//
//   * The TOKEN is caught by `d1` on shape alone: `ghu_` is in
//     `TOKEN_PREFIXES` (`crates/platform/src/logging.rs:243`), so it is
//     scrubbed from a log whatever this crate does. Measured: leaking it as a
//     `tracing` FIELD and again interpolated into a `tracing` MESSAGE left both
//     log scans green. Writing it to STDOUT reddened both -- and nothing in
//     `d1` touches process stdout, so the stdout/stderr half of this scan is
//     unambiguously f1's own control.
//
//   * The DEVICE CODE is NOT caught by `d1`. `fixture_device_code()` is 36
//     characters -- under `OPAQUE_RUN_THRESHOLD = 40` (logging.rs:251) -- it
//     matches no `TOKEN_PREFIXES` entry, is not a JWT, and holds no `=`, `:` or
//     structural character for `redact_core` to split on, so it passes through
//     `redact_value` intact. Measured: interpolated into a `tracing` message it
//     reached `logs/runner-manager.log` and `no_secret_reaches_the_diagnostics_at_trace_level`
//     failed naming the file, while the `warn`-level scan stayed green because
//     `info!` was filtered out. For the device code the log half of this scan is
//     the ONLY control there is, and it must not be deleted as duplicated
//     coverage.
//
//   * The JIT BLOB cannot fire here at all. Nothing under `crates/app/src/`
//     mints or handles a JIT configuration and the fixture serves no route
//     returning one, so this needle is a forward-looking guard rather than a
//     measurement of this diff. That third of the gate is discharged by `e3`
//     and `h1`, which do handle one; the needle stays because it costs nothing
//     and because the command set here will grow.
//
// So: three needles, one measured by this file (the device code, in logs and on
// stdout), one measured by this file only on stdout (the token), and one not
// measured here at all (the JIT blob). "None found" means less than three
// clean results would suggest, and saying so is cheaper than a reader
// discovering it later.

mod support;

use std::path::PathBuf;

use support::{
    FIXTURE_USER_CODE, FakeGithub, file_contains, files_under, fixture_device_code, fixture_token,
    is_the_secret_store, run, runner_manager_against,
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
    // `d1`'s two host-root commands. `reset-runtime-root` is the pair member
    // that needs no argument: `set-runtime-root --path` would need a directory
    // that exists on every CI leg and overlaps no application data, which is a
    // per-run temporary path and cannot be written in a `const`. Its output is
    // scanned by `workspace_commands.rs` instead, where a `TempDir` is in scope.
    &["host", "reset-runtime-root"],
    &["host", "show"],
    &[
        "repo",
        "add",
        "acme/repo",
        "--host-label",
        "home-win",
        "--max-capacity",
        "1",
    ],
    &["repo", "list"],
    &["repo", "set-capacity", "acme/repo", "--max-capacity", "2"],
    &["repo", "set-scale", "acme/repo", "--enabled", "true"],
    // The ephemeral half of `repo set-workspace`, for the same reason as
    // `reset-runtime-root` above: it is the spelling that takes no path.
    &["repo", "set-workspace", "acme/repo", "--mode", "ephemeral"],
    &["repo", "remove", "acme/repo"],
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
    // Long-running and host-mutating commands are covered at their parser
    // boundary here. Their implemented handlers have focused f3 tests; running
    // them in a secret-output corpus would either hang forever or alter the
    // developer's real service manager.
    &["daemon", "run", "--help"],
    &["service", "install", "--help"],
    &["service", "uninstall", "--help"],
    &["service", "status"],
    &["tui"],
    &["status"],
    &["status", "--json"],
];

/// The three values that must never appear, with the name each is known by.
///
/// See the header for which of the three this file actually measures. They are
/// scanned together because a caller adding a fourth needle should not have to
/// decide which sub-scan it belongs to.
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

/// Runs the whole command surface with a real credential in the store and
/// returns everything it produced.
fn corpus_from_the_full_command_set(verbose: bool) -> (tempfile::TempDir, Vec<Fragment>) {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let github = FakeGithub::start();
    github.with_device_code();
    github.with_approval();
    github.with_installation(11, "acme", "Organization", "selected", &["acme/repo"]);

    let mut corpus = Vec::new();

    let mut record = |name: String, arguments: &[&str], expected_code: i32| {
        let outcome = run({
            let mut command = runner_manager_against(data_dir.path(), &github);
            if verbose {
                command.env("RUST_LOG", "trace");
            }
            command.args(arguments);
            command
        });
        assert_eq!(
            outcome.code,
            expected_code,
            "`{name}` did not exercise its intended path:\n{}",
            outcome.both()
        );
        corpus.push(Fragment {
            origin: format!("`{name}` stdout"),
            text: outcome.stdout,
        });
        corpus.push(Fragment {
            origin: format!("`{name}` stderr"),
            text: outcome.stderr,
        });
    };

    record("auth login".to_string(), &["auth", "login"], 0);
    for arguments in COMMANDS {
        let expected_code = if arguments[0] == "tui" { 1 } else { 0 };
        record(arguments.join(" "), arguments, expected_code);
    }
    record("auth logout".to_string(), &["auth", "logout"], 0);

    // Everything the commands left on disk, except the store itself.
    //
    // Read through `from_utf8_lossy` rather than as bytes, and deliberately so:
    // a fragment here is *text*, because stdout and stderr arrive as `String`
    // already and the scan runs over all of them together. That is safe while
    // every needle is ASCII — UTF-8 is self-synchronising and no ASCII byte is
    // ever a continuation byte, so a lossy conversion never consumes one into a
    // replacement character. `support::file_contains` is the byte-exact
    // spelling, and its documentation is where a future non-ASCII needle should
    // send somebody.
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

/// The same, with diagnostics turned all the way up.
///
/// This is the only control that guards the **device code**, and it is not
/// redundant with `d1`: at 36 characters the fixture falls under every shape
/// rule `d1` has, so it survives `redact_value` and reaches the log file. The
/// header sets out the measurement. `trace` rather than the default `warn`
/// because an `info!` carrying a secret is filtered out at `warn` and would
/// leave this green while the leak was real.
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
        everything.contains("Credential store:"),
        "the login's own output must be in the corpus, for the same reason"
    );
    assert!(
        everything.contains("host_capacity"),
        "`host show` must be in the corpus"
    );
    assert!(
        everything.contains("\"schema_version\""),
        "`status --json` must be in the corpus"
    );
    for arguments in COMMANDS {
        let command = arguments.join(" ");
        for stream in ["stdout", "stderr"] {
            let origin = format!("`{command}` {stream}");
            assert!(
                corpus.iter().any(|fragment| fragment.origin == origin),
                "{origin} must be in the scanned corpus: the gate is over the FULL command \
                 set, and a command nobody ran cannot leak in a test"
            );
        }
    }

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
        if file_contains(&path, &fixture_token()) {
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
