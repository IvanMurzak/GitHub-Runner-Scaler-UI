// ----------------------------------------------------------------------------
// `daemon adopt-credential` MEASURED THROUGH A REAL PROCESS AND A REAL PIPE.
// ----------------------------------------------------------------------------
// An upgrading daemon reads its credential and pipes it into this command, run
// from the binary that replaces it, so that the new build is the writer of the
// keychain item it will read after the restart. `crates/app` has no library
// target, so the command can only be driven from here, as a process: the
// handover's own decisions are unit-tested beside it in `daemon.rs`, and that
// the command stays hidden yet reachable is `HIDDEN_BRIDGES` in
// `cli_command_surface.rs`.

mod support;

use support::{FakeGithub, fixture_token, run, runner_manager_against};

/// A credential document as `UserAccessToken::to_stored_document` writes one.
fn document(access: &str) -> String {
    format!(
        r#"{{"access_token":"{access}","refresh_token":"{}",
             "access_expires_at":"2026-09-06T20:00:00Z",
             "refresh_expires_at":"2027-03-05T12:00:00Z"}}"#,
        format_args!("{}{}", "ghr_", "adoptRefreshCanary000000000000")
    )
}

/// `Failure::InvalidArgument`.
const INVALID_ARGUMENT: i32 = 9;

/// `Failure::NotAuthenticated`: no credential in the store at all.
const NOT_AUTHENTICATED: i32 = 3;

/// The credential the old daemon handed over is one the host is signed in
/// with afterwards.
#[test]
fn an_adopted_credential_is_one_auth_status_reports_as_authenticated() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let github = FakeGithub::start();
    github.with_installation(11, "acme", "Organization", "selected", &["acme/repo"]);

    let adopted = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command
            .args(["daemon", "adopt-credential", "--start-at", "boot"])
            .write_stdin(document(&fixture_token()));
        command
    });
    assert_eq!(
        adopted.code,
        0,
        "the handover must store:\n{}",
        adopted.both()
    );
    assert!(
        adopted.stdout.contains("machine-scoped store"),
        "the report names the store, and nothing about the value: {}",
        adopted.stdout
    );

    let status = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args(["auth", "status"]);
        command
    });
    assert_eq!(status.code, 0, "signed in afterwards:\n{}", status.both());
}

/// Unlike `auth receive`, the handover never changes the recorded start mode:
/// the daemon handing over already runs under it, and a stray `--start-at`
/// must not move the host to a store its daemon does not read.
#[test]
fn adopting_records_no_start_mode() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let github = FakeGithub::start();

    let adopted = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command
            .args(["daemon", "adopt-credential", "--start-at", "login"])
            .write_stdin(document(&fixture_token()));
        command
    });
    assert_eq!(adopted.code, 0, "{}", adopted.both());

    // The host still records the default, `boot`, whose store is empty.
    let status = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args(["auth", "status"]);
        command
    });
    assert_eq!(
        status.code,
        NOT_AUTHENTICATED,
        "the recorded start mode moved:\n{}",
        status.both()
    );
}

#[test]
fn a_refused_document_leaves_nothing_stored() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let github = FakeGithub::start();

    for input in [String::new(), "not a credential document".to_string()] {
        let adopted = run({
            let mut command = runner_manager_against(data_dir.path(), &github);
            command
                .args(["daemon", "adopt-credential", "--start-at", "boot"])
                .write_stdin(input);
            command
        });
        assert_eq!(adopted.code, INVALID_ARGUMENT, "{}", adopted.both());
    }

    let status = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args(["auth", "status"]);
        command
    });
    assert_eq!(status.code, NOT_AUTHENTICATED, "{}", status.both());
}
