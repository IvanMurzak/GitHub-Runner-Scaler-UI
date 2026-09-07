// owner: b1-credential-broker
//
// ----------------------------------------------------------------------------
// `auth receive` MEASURED THROUGH A REAL PROCESS AND A REAL PIPE.
// ----------------------------------------------------------------------------
// The unit tests in `crates/app/src/cli/auth.rs` drive the pieces: the reader,
// the envelope check, the store call, the broker and its sink. They cannot
// drive the *command*, because `crates/app` is a `[[bin]]` with no `[lib]`
// target -- `a1` owns the manifest and `b1` may not add one -- so nothing under
// `tests/` can call into it.
//
// What only this file can measure is the thing the WSL provider actually talks
// to: a separate process, a real anonymous pipe on its stdin, a real exit code,
// and a real secret store on disk underneath a `--data-dir`. Three properties
// live here and nowhere else:
//
//   * the command is HIDDEN. `cli_command_surface.rs` transcribes the published
//     surface from `02-target-architecture.md` and asserts `--help` matches it
//     exactly, so a `receive` that showed up in help would red that file rather
//     than this one -- but nothing there proves the hidden command still RUNS,
//     which is the half a `hide = true` typo would break silently.
//   * a refusal leaves the host UNAUTHENTICATED, asked of the product rather
//     than of the store: `auth status` is what an operator and the provider
//     both read, and "nothing usable was persisted" is exactly the claim it
//     answers.
//   * nothing the handoff touched wrote the credential anywhere but the store,
//     including the diagnostics at `trace`, which is a file only a real process
//     produces.

mod support;

use support::{
    FakeGithub, files_under, fixture_token, is_the_secret_store, run, runner_manager,
    runner_manager_against,
};

/// A credential the WSL host is receiving. Assembled at run time, like every
/// other fixture secret in this suite, so the literal is in no compiled
/// artifact for the scan below to find in its own test binary.
fn wsl_access_canary() -> String {
    format!("{}{}", "ghu_", "b1ReceiveAccessCanary0000000000")
}

fn wsl_refresh_canary() -> String {
    format!("{}{}", "ghr_", "b1ReceiveRefreshCanary000000000")
}

/// A credential document as `UserAccessToken::to_stored_document` writes one.
fn document(access: &str, refresh: &str) -> String {
    format!(
        r#"{{"access_token":"{access}","refresh_token":"{refresh}",
             "access_expires_at":"2026-09-06T20:00:00Z",
             "refresh_expires_at":"2027-03-05T12:00:00Z"}}"#
    )
}

/// `Failure::InvalidArgument`, which is what every refusal on this endpoint
/// exits with. Transcribed rather than imported, because there is no library
/// target to import it from.
const INVALID_ARGUMENT: i32 = 9;

/// `Failure::NotAuthenticated`: no credential in the store at all.
const NOT_AUTHENTICATED: i32 = 3;

// ---------------------------------------------------------------------------
// Hidden, and hidden is not the same as absent
// ---------------------------------------------------------------------------

#[test]
fn receive_is_absent_from_help_and_still_runs() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");

    let help = run({
        let mut command = runner_manager(data_dir.path());
        command.args(["auth", "--help"]);
        command
    });
    assert_eq!(help.code, 0, "`auth --help` must succeed: {}", help.stderr);
    assert!(
        !help.stdout.contains("receive"),
        "`02-target-architecture.md` hides this command from ordinary help, and \
         `cli_command_surface.rs` asserts the published list is exhaustive:\n{}",
        help.stdout
    );

    // Hidden, not removed: clap still parses it, and its own help page exists
    // for whoever is debugging a provider.
    let own_help = run({
        let mut command = runner_manager(data_dir.path());
        command.args(["auth", "receive", "--help"]);
        command
    });
    assert_eq!(
        own_help.code, 0,
        "the hidden command must still be reachable: {}",
        own_help.stderr
    );
    assert!(
        own_help.stdout.contains("--start-at"),
        "got: {}",
        own_help.stdout
    );
}

/// The start mode is not defaulted here, because the process on the other end
/// of the pipe is the one that knows how the daemon it is provisioning starts.
#[test]
fn receive_refuses_to_guess_a_start_mode() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let outcome = run({
        let mut command = runner_manager(data_dir.path());
        command
            .args(["auth", "receive"])
            .write_stdin(document(&wsl_access_canary(), &wsl_refresh_canary()));
        command
    });
    assert_ne!(outcome.code, 0, "a missing start mode must not be guessed");
    assert!(
        outcome.stderr.contains("--start-at"),
        "the refusal must name what is missing: {}",
        outcome.stderr
    );
}

// ---------------------------------------------------------------------------
// The success path, asked of the product
// ---------------------------------------------------------------------------

/// A credential that arrived over a pipe is a credential this host is signed in
/// with — the same answer `auth login` would have produced, from the same
/// store.
#[test]
fn a_received_credential_is_one_auth_status_reports_as_authenticated() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let github = FakeGithub::start();
    github.with_installation(11, "acme", "Organization", "selected", &["acme/repo"]);

    let received = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command
            .args(["auth", "receive", "--start-at", "boot"])
            // The fixture token, not a canary: this document has to be usable
            // against the fake GitHub below, and the canary scan is its own
            // test.
            .write_stdin(document(&fixture_token(), &wsl_refresh_canary()));
        command
    });
    assert_eq!(
        received.code,
        0,
        "the handoff must succeed:\n{}",
        received.both()
    );
    assert!(
        received.stdout.contains("machine-scoped store"),
        "the report names the store it wrote, and nothing about the value: {}",
        received.stdout
    );
    assert!(
        received.stdout.contains("renews itself"),
        "a pair with a refresh half must be reported as renewable: {}",
        received.stdout
    );

    let status = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args(["auth", "status"]);
        command
    });
    assert_eq!(
        status.code,
        0,
        "the host is signed in with the credential it was handed:\n{}",
        status.both()
    );
}

/// `--start-at` names the store to write *and* the store this host will read.
///
/// Every reader — `auth status`, `repo add`, the daemon — resolves the secret
/// store from the start mode recorded in the local database, not from the flag
/// this command was given. A handoff that wrote the user-scoped store and left
/// the record saying `boot` would put a perfectly good credential somewhere
/// nothing ever looks, and `auth status` would answer `not_authenticated` on a
/// host that had just been provisioned successfully.
#[test]
fn receiving_for_a_start_mode_records_it_so_the_host_reads_the_store_it_wrote() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let github = FakeGithub::start();
    github.with_installation(11, "acme", "Organization", "selected", &["acme/repo"]);

    let received = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command
            .args(["auth", "receive", "--start-at", "login"])
            .write_stdin(document(&fixture_token(), &wsl_refresh_canary()));
        command
    });
    assert_eq!(
        received.code,
        0,
        "the handoff must succeed:\n{}",
        received.both()
    );
    assert!(
        received.stdout.contains("user-scoped store"),
        "`--start-at login` writes the user-scoped store: {}",
        received.stdout
    );

    let status = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args(["auth", "status"]);
        command
    });
    assert_eq!(
        status.code,
        0,
        "the store this host reads must be the one the handoff wrote:\n{}",
        status.both()
    );
}

// ---------------------------------------------------------------------------
// Every refusal, and the state each one leaves behind
// ---------------------------------------------------------------------------

/// Every way the input can fail to be a credential, exercised against the real
/// command, each one followed by the question that matters: is this host now
/// holding something?
///
/// The oversized case is exactly one byte past the ceiling rather than
/// comfortably past it, so the child consumes the whole of what the parent
/// writes. A much larger input would have the child stop reading and the parent
/// hit a broken pipe, which is a property of this test's plumbing rather than
/// of the product.
#[test]
fn every_refusal_leaves_the_host_with_nothing_stored() {
    let oversized = "x".repeat(64 * 1024 + 1);
    let truncated = format!(r#"{{"access_token":"{}"#, wsl_access_canary());
    let cases: Vec<(&str, &str)> = vec![
        ("an empty document", ""),
        ("whitespace only", "   \n"),
        ("prose", "not a credential at all"),
        (
            "an HTML error page",
            "<html><body>502 Bad Gateway</body></html>",
        ),
        ("an object with no access token", r#"{"refresh_token":"x"}"#),
        ("an empty access token", r#"{"access_token":""}"#),
        ("a JSON array", r#"["ghu_looksLikeAToken"]"#),
        ("a document one byte over the ceiling", oversized.as_str()),
        ("a truncated document", truncated.as_str()),
        // A field beside `access_token` of the wrong type fails the whole of
        // `UserAccessToken::from_stored_document`'s parse, and its pre-0.1.11
        // fallback then reads the entire JSON text as a bare access token. Both
        // of these used to be stored, reported as a success, and leave this
        // host holding a credential GitHub will never accept.
        (
            "a document whose access expiry is not an instant",
            r#"{"access_token":"ghu_x","access_expires_at":"tomorrow"}"#,
        ),
        (
            "a document whose refresh token is not a string",
            r#"{"access_token":"ghu_x","refresh_token":1234}"#,
        ),
    ];

    for (what, input) in cases {
        let data_dir = tempfile::tempdir().expect("a temporary directory");
        let github = FakeGithub::start();
        github.with_installation(11, "acme", "Organization", "selected", &["acme/repo"]);

        let refused = run({
            let mut command = runner_manager_against(data_dir.path(), &github);
            command
                .args(["auth", "receive", "--start-at", "boot"])
                .write_stdin(input.to_string());
            command
        });
        assert_eq!(
            refused.code,
            INVALID_ARGUMENT,
            "{what} must be refused as an invalid argument:\n{}",
            refused.both()
        );
        assert!(
            refused.stdout.is_empty(),
            "{what} must produce no report at all, and produced: {}",
            refused.stdout
        );
        assert!(
            refused.stderr.contains("Nothing was stored"),
            "{what} must say plainly that nothing was stored: {}",
            refused.stderr
        );

        let status = run({
            let mut command = runner_manager_against(data_dir.path(), &github);
            command.args(["auth", "status"]);
            command
        });
        assert_eq!(
            status.code,
            NOT_AUTHENTICATED,
            "after {what} the host must hold no credential at all:\n{}",
            status.both()
        );
    }
}

// ---------------------------------------------------------------------------
// The canary scan
// ---------------------------------------------------------------------------

/// `b1` Definition of Done 4, on the receiving side: the document reaches the
/// secret store and nothing else this process wrote.
///
/// Run at `RUST_LOG=trace` on purpose. `d1`'s redacting sink scrubs a `ghu_`
/// prefix on shape alone, so the access half would be caught there whatever
/// this crate did; the refresh half's `ghr_` and the report's own text are what
/// this measures, and an `info!` carrying either is filtered out at the default
/// `warn` level and would leave a leak green.
#[test]
fn no_part_of_a_received_credential_reaches_the_output_or_any_file_but_the_store() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");

    let received = run({
        let mut command = runner_manager(data_dir.path());
        command
            .env("RUST_LOG", "trace")
            .args(["auth", "receive", "--start-at", "boot"])
            .write_stdin(document(&wsl_access_canary(), &wsl_refresh_canary()));
        command
    });
    assert_eq!(
        received.code,
        0,
        "the handoff must succeed, or this scan measures nothing:\n{}",
        received.both()
    );

    // The store is the one place a credential is supposed to be, so it is the
    // one exemption -- the same line `no_secret_reaches_command_output.rs` and
    // `d2`'s `no_token_outside_the_store.rs` draw. On Linux the value is a
    // `0600` file rather than ciphertext, so a scan that included it would fail
    // on one platform for the correct behaviour.
    let mut corpus = vec![
        ("the command's stdout".to_string(), received.stdout.clone()),
        ("the command's stderr".to_string(), received.stderr.clone()),
    ];
    let mut files_seen = 0_usize;
    for path in files_under(data_dir.path()) {
        if is_the_secret_store(&path) {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        files_seen += 1;
        corpus.push((
            format!("the file {}", path.display()),
            String::from_utf8_lossy(&bytes).into_owned(),
        ));
    }
    assert!(
        files_seen > 0,
        "the run left no files to scan, so a clean result would mean nothing"
    );

    let found = scan(&corpus);
    assert!(
        found.is_empty(),
        "`03-security-and-lifecycle.md` guarantee 3: the credential document is absent from \
         logs, errors, status JSON and temporary files. Found:\n  {}",
        found.join("\n  ")
    );

    // ------------------------------------------------------------------------
    // THE CONTROL: A SCAN THAT CANNOT FAIL IS WORTH NOTHING.
    // ------------------------------------------------------------------------
    // The same scanner, over a corpus that DOES hold both halves, must report
    // both. Without this, a renamed canary or a normalisation that ate the
    // needle would leave the assertion above permanently and meaninglessly
    // green. `no_secret_reaches_command_output.rs` carries the same control for
    // the same reason.
    let planted: Vec<(String, String)> = needles()
        .into_iter()
        .map(|(name, value)| {
            (
                format!("a planted fragment for {name}"),
                format!("prefix {value} suffix"),
            )
        })
        .collect();
    assert_eq!(
        scan(&planted).len(),
        needles().len(),
        "the scanner must find every planted needle, or the clean result above says nothing"
    );
}

/// The two halves of the received credential, with the name each is known by.
fn needles() -> Vec<(&'static str, String)> {
    vec![
        ("the access token", wsl_access_canary()),
        ("the refresh token", wsl_refresh_canary()),
    ]
}

/// Which needles appear in a corpus of `(origin, text)`, and where.
fn scan(corpus: &[(String, String)]) -> Vec<String> {
    let mut found = Vec::new();
    for (name, needle) in needles() {
        for (origin, text) in corpus {
            if text.contains(&needle) {
                found.push(format!("{name} appears in {origin}"));
            }
        }
    }
    found
}
