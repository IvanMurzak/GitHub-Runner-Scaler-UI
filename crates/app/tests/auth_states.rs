// owner: f1-cli-auth-host-status
//
// ----------------------------------------------------------------------------
// FOUR STATES, FOUR EXIT CODES, AND ONE THAT MUST NOT COLLAPSE INTO ANOTHER.
// ----------------------------------------------------------------------------
// `f1`: "Distinguish authenticated, not authenticated, revoked token, and
// authentication lockout as four separate reported states -- `c2` already
// separates them and the CLI must not collapse them."
//
// `03-control-flows.md` flow 4.3 says why the fourth one matters most: "A 403
// following repeated 401s indicates GitHub's temporary authentication lockout,
// not a permissions change; the agent backs off without further refresh
// attempts and reports it distinctly from `authentication_failed`." Reported as
// a revoked credential it would send an operator to `auth login`, which during
// a lockout makes the lockout longer.
//
// Every state below is reached by driving the real binary against a fixture
// that answers the way GitHub does, so what is measured is `c2`'s taxonomy
// arriving intact rather than this crate's opinion of it.

mod support;

use support::{
    FakeGithub, Reply, file_contains, files_under, fixture_token, run, runner_manager,
    runner_manager_against,
};

/// Signs in for real, so the following command reads a credential this suite
/// did not plant by hand.
fn signed_in(data_dir: &std::path::Path, github: &FakeGithub) {
    github.with_device_code();
    github.with_approval();
    github.with_no_installations();
    let outcome = run({
        let mut command = runner_manager_against(data_dir, github);
        command.args(["auth", "login"]);
        command
    });
    assert_eq!(
        outcome.code, 0,
        "the fixture login must succeed, or every assertion after it is about the wrong \
         thing. stdout:\n{}\nstderr:\n{}",
        outcome.stdout, outcome.stderr
    );
}

#[test]
fn a_machine_with_no_credential_reports_not_authenticated() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let github = FakeGithub::start();

    let outcome = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args(["auth", "status"]);
        command
    });

    assert_eq!(outcome.code, 3, "stderr: {}", outcome.stderr);
    assert!(
        outcome.stdout.contains("Credential: not_authenticated"),
        "{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("Nothing has been revoked"),
        "an unconfigured machine must not read as a broken one:\n{}",
        outcome.stdout
    );
    assert!(
        github.seen().is_empty(),
        "with no credential there is nothing to ask GitHub about, and asking anyway would \
         spend rate limit to learn nothing: {:?}",
        github.seen()
    );
}

/// A fixture with one installation reaching two named repositories, and a
/// credential already stored for it.
fn signed_in_with_two_repositories(data_dir: &std::path::Path) -> FakeGithub {
    let login = FakeGithub::start();
    signed_in(data_dir, &login);

    // The credential lives in the data directory, not in the fixture, so a
    // second fixture is simply a different GitHub for the same host.
    let github = FakeGithub::start();
    github.with_installation(
        42,
        "operator",
        "User",
        "selected",
        &["operator/one", "operator/two"],
    );
    github
}

#[test]
fn an_accepted_credential_reports_what_it_can_reach() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let github = signed_in_with_two_repositories(data_dir.path());

    let outcome = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args(["auth", "status"]);
        command
    });

    assert_eq!(outcome.code, 0, "stderr: {}", outcome.stderr);
    assert!(
        outcome.stdout.contains("Credential: authenticated"),
        "{}",
        outcome.stdout
    );
    assert!(
        outcome
            .stdout
            .contains("2 repositories and 0 organizations"),
        "the summary must count both kinds:\n{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("operator (user, installation 42"),
        "every installation is named unconditionally -- it is the account whose grant this \
         is, and there are few of them:\n{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("2 reachable"),
        "and each installation carries its own count, so the default output still \
         distinguishes two repositories from two hundred:\n{}",
        outcome.stdout
    );
    assert!(
        !outcome.stdout.contains("ALL repositories"),
        "a `selected` installation must not be labelled over-broad:\n{}",
        outcome.stdout
    );
}

/// The roll call is `--list`, and the default output says so.
///
/// An installation on an active account reaches hundreds of repositories.
/// Printing them all by default pushed the count and the over-broad warning off
/// the top of the terminal, so the output that existed to make an over-broad
/// installation visible was the output hiding it.
#[test]
fn the_repository_names_are_behind_list_and_the_default_says_where_they_are() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let github = signed_in_with_two_repositories(data_dir.path());

    let quiet = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args(["auth", "status"]);
        command
    });
    assert_eq!(quiet.code, 0, "stderr: {}", quiet.stderr);
    for repository in ["operator/one", "operator/two"] {
        assert!(
            !quiet.stdout.contains(repository),
            "{repository} must not be named without --list:\n{}",
            quiet.stdout
        );
    }
    assert!(
        quiet.stdout.contains("--list"),
        "a reader who wants the names must be told the flag that prints them, or the \
         information is not behind a flag, it is gone:\n{}",
        quiet.stdout
    );

    let listed = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args(["auth", "status", "--list"]);
        command
    });
    assert_eq!(listed.code, 0, "stderr: {}", listed.stderr);
    for repository in ["operator/one", "operator/two"] {
        assert!(
            listed.stdout.contains(repository),
            "`07-security.md` requires the reachable repositories to be nameable, so that an \
             over-broad installation is visible rather than assumed. Missing {repository} \
             in:\n{}",
            listed.stdout
        );
    }
}

/// The disclosure `auth login` no longer prints, and the command that does.
///
/// The counterpart of
/// `auth_onboarding.rs::the_login_screen_carries_no_permission_table`: that one
/// asserts the text is absent from the login screen, this one asserts it still
/// exists. Either alone would pass for a build that deleted the grant text
/// altogether.
#[test]
fn the_permission_report_carries_the_whole_grant() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let github = FakeGithub::start();

    let outcome = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args(["auth", "status", "--permissions"]);
        command
    });

    for needle in [
        "Administration: Read and write",
        "DELETING",
        "RENAMING",
        "TRANSFERRING",
        "collaborators",
        "Repository -> Metadata",
        "Organization -> Self-hosted runners",
        "monitor-only",
    ] {
        assert!(
            outcome.stdout.contains(needle),
            "`auth status --permissions` is where the grant text lives now, and it must \
             carry `{needle}`:\n{}",
            outcome.stdout
        );
    }
    assert!(
        github.seen().is_empty(),
        "the permission set is a property of the published App, not of this host, so \
         describing it must cost no request: {:?}",
        github.seen()
    );
}

/// And it is readable on a machine that has never signed in -- which is the
/// only time somebody is still deciding whether to grant it.
#[test]
fn the_permission_report_needs_no_credential() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let github = FakeGithub::start();

    let outcome = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args(["auth", "status", "--permissions"]);
        command
    });

    assert_eq!(
        outcome.code, 3,
        "the exit code still reports the credential, which is absent here; stdout:\n{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("Administration: Read and write"),
        "an operator deciding whether to sign in at all must be able to read the grant \
         first:\n{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("Credential: not_authenticated"),
        "and the credential answer is still given:\n{}",
        outcome.stdout
    );
}

/// Without the flag, `auth status` says nothing about permissions. The report
/// is on request precisely so that it is not on every run.
#[test]
fn the_permission_table_is_absent_without_the_flag() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let github = signed_in_with_two_repositories(data_dir.path());

    let outcome = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args(["auth", "status"]);
        command
    });

    assert!(
        !outcome.stdout.contains("Administration: Read and write"),
        "the permission table is `--permissions`, not the default:\n{}",
        outcome.stdout
    );
}

/// The over-broad case is the one `07-security.md` names, and it cannot be
/// shown by listing today's repositories: the installation also reaches ones
/// created later.
#[test]
fn an_over_broad_installation_is_called_out_rather_than_only_listed() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let login = FakeGithub::start();
    signed_in(data_dir.path(), &login);

    let github = FakeGithub::start();
    github.with_installation(7, "acme", "Organization", "all", &["acme/one"]);
    let outcome = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args(["auth", "status"]);
        command
    });

    assert_eq!(outcome.code, 0, "stderr: {}", outcome.stderr);
    assert!(
        outcome.stdout.contains("ALL repositories"),
        "an installation set to every repository on the account must say so:\n{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("created later"),
        "and must say why a list of names cannot show it:\n{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("1 repository and 1 organization"),
        "an organization account is a reachable target in its own right (D18), and is \
         counted alongside the repositories the installation reaches rather than instead \
         of them:\n{}",
        outcome.stdout
    );
}

#[test]
fn a_revoked_credential_is_reported_as_revoked_and_not_as_a_missing_one() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let login = FakeGithub::start();
    signed_in(data_dir.path(), &login);

    let github = FakeGithub::start();
    github.with_revoked_credential();
    let outcome = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args(["auth", "status"]);
        command
    });

    assert_eq!(
        outcome.code, 4,
        "revoked has its own exit code, distinct from not-authenticated's 3; stderr: {}",
        outcome.stderr
    );
    assert!(
        outcome.stdout.contains("Credential: revoked"),
        "{}",
        outcome.stdout
    );
    assert!(
        outcome.stderr.contains("auth login"),
        "the remedy for a revoked credential is a fresh one:\n{}",
        outcome.stderr
    );
}

/// GitHub's temporary authentication lockout: a `403` carrying `retry-after`
/// and no message body, after a `401`. `c2` recognises the pair; this asserts
/// the CLI does not flatten it back into "your credential is bad".
#[test]
fn a_lockout_is_reported_distinctly_and_never_advises_signing_in_again() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let login = FakeGithub::start();
    signed_in(data_dir.path(), &login);

    let github = FakeGithub::start();
    github.with_authentication_lockout(120);

    let outcome = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args(["auth", "status"]);
        command
    });

    assert_eq!(
        outcome.code, 5,
        "the lockout has its own exit code, distinct from revoked's 4; stdout:\n{}\n\
         stderr:\n{}",
        outcome.stdout, outcome.stderr
    );
    assert!(
        outcome.stdout.contains("Credential: locked_out"),
        "{}",
        outcome.stdout
    );
    assert!(
        outcome
            .stdout
            .contains("nothing wrong with the token itself"),
        "an operator in a lockout must be told their credential is fine:\n{}",
        outcome.stdout
    );
    assert!(
        !outcome.stderr.contains("auth login"),
        "and must NOT be told to sign in again -- `03-control-flows.md` flow 4.3: the agent \
         backs off without further refresh attempts. Signing in during a lockout extends \
         it.\n{}",
        outcome.stderr
    );
    assert!(
        outcome.stderr.contains("wait"),
        "the remedy is waiting:\n{}",
        outcome.stderr
    );
}

/// The distinction the lockout exists for: a `403` that *names* what is not
/// accessible is a permissions answer, not a lockout, and re-authenticating
/// will not change it either.
#[test]
fn a_permissions_refusal_is_not_reported_as_a_lockout() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let login = FakeGithub::start();
    signed_in(data_dir.path(), &login);

    let github = FakeGithub::start();
    github.route(
        "GET",
        "/user/installations",
        Reply::json(
            403,
            r#"{"message":"Resource not accessible by integration"}"#,
        ),
    );

    let outcome = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args(["auth", "status"]);
        command
    });

    assert_ne!(
        outcome.code, 5,
        "a `403` carrying a GitHub message is a permissions answer; latching a back-off on \
         it would silence this client for fifteen minutes over a grant that is simply \
         missing. stdout:\n{}\nstderr:\n{}",
        outcome.stdout, outcome.stderr
    );
    assert_eq!(
        outcome.code, 8,
        "it belongs in the refused class; stderr: {}",
        outcome.stderr
    );
}

/// An unreachable GitHub is its own answer. Reported as `revoked` it would tell
/// an operator with a dropped connection to obtain a new credential.
#[test]
fn an_unreachable_github_is_not_reported_as_a_bad_credential() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let login = FakeGithub::start();
    signed_in(data_dir.path(), &login);

    // Bind a port and drop the listener, so nothing is listening on it.
    let dead = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
        let port = listener.local_addr().expect("bound").port();
        drop(listener);
        format!("http://127.0.0.1:{port}/")
    };

    let outcome = run({
        let mut command = runner_manager(data_dir.path());
        command
            .env("RUNNER_MANAGER_GITHUB_BASE_URL", &dead)
            .env(
                "RUNNER_MANAGER_GITHUB_CLIENT_ID",
                support::FIXTURE_CLIENT_ID,
            )
            .env("RUNNER_MANAGER_GITHUB_APP_SLUG", support::FIXTURE_APP_SLUG)
            .args(["auth", "status"]);
        command
    });

    assert_eq!(
        outcome.code, 7,
        "the unreachable class, distinct from revoked (4) and not-authenticated (3); \
         stdout:\n{}\nstderr:\n{}",
        outcome.stdout, outcome.stderr
    );
    assert!(
        outcome.stdout.contains("Credential: unreachable"),
        "{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("may be perfectly good"),
        "an offline host must not be told its credential is bad:\n{}",
        outcome.stdout
    );
}

/// The four states `f1` names reach four different exit codes, measured over
/// the binary rather than over the enum.
///
/// All four, including the lockout — an earlier version of this test compared
/// three and the doc claimed four, which is the kind of gap that survives
/// precisely because the sentence above it reads correctly.
#[test]
fn the_reported_states_reach_distinct_exit_codes() {
    // not_authenticated
    let empty = tempfile::tempdir().expect("a temporary directory");
    let no_github = FakeGithub::start();
    let not_authenticated = run({
        let mut command = runner_manager_against(empty.path(), &no_github);
        command.args(["auth", "status"]);
        command
    })
    .code;

    // authenticated
    let signed = tempfile::tempdir().expect("a temporary directory");
    let login = FakeGithub::start();
    signed_in(signed.path(), &login);
    let reachable = FakeGithub::start();
    reachable.with_installation(1, "operator", "User", "selected", &["operator/one"]);
    let authenticated = run({
        let mut command = runner_manager_against(signed.path(), &reachable);
        command.args(["auth", "status"]);
        command
    })
    .code;

    // revoked
    let revoked_github = FakeGithub::start();
    revoked_github.with_revoked_credential();
    let revoked = run({
        let mut command = runner_manager_against(signed.path(), &revoked_github);
        command.args(["auth", "status"]);
        command
    })
    .code;

    // locked out
    let lockout_github = FakeGithub::start();
    lockout_github.with_authentication_lockout(120);
    let locked_out = run({
        let mut command = runner_manager_against(signed.path(), &lockout_github);
        command.args(["auth", "status"]);
        command
    })
    .code;

    let codes = [not_authenticated, authenticated, revoked, locked_out];
    let distinct: std::collections::BTreeSet<i32> = codes.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        codes.len(),
        "authenticated, not-authenticated, revoked and locked-out must all be tellable \
         apart from a script: {codes:?}"
    );
    assert_eq!(authenticated, 0, "only success exits zero");
}

// ---------------------------------------------------------------------------
// auth logout
// ---------------------------------------------------------------------------

#[test]
fn logout_leaves_no_token_and_names_the_authoritative_revocation() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let github = FakeGithub::start();
    signed_in(data_dir.path(), &github);

    let outcome = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args(["auth", "logout"]);
        command
    });

    assert_eq!(outcome.code, 0, "stderr: {}", outcome.stderr);
    assert!(
        outcome.stdout.contains("Removed the stored credential"),
        "{}",
        outcome.stdout
    );
    assert!(
        outcome
            .stdout
            .contains("Authoritative revocation is uninstalling the App at GitHub."),
        "`07-security.md` makes uninstalling the App the authoritative revocation, and a \
         logout that did not say so would let an operator read a local purge as one:\n{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("still valid at GitHub"),
        "{}",
        outcome.stdout
    );

    // The store is empty afterwards, measured through the product's own answer.
    let after = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args(["auth", "status"]);
        command
    });
    assert_eq!(
        after.code, 3,
        "after a logout the host is back to not-authenticated; stdout:\n{}",
        after.stdout
    );
    assert!(after.stdout.contains("Credential: not_authenticated"));

    // And nothing anywhere in the data directory holds the token.
    let planted = fixture_token();
    let mut offenders = Vec::new();
    for entry in files_under(data_dir.path()) {
        if file_contains(&entry, &planted) {
            offenders.push(entry.display().to_string());
        }
    }
    assert!(
        offenders.is_empty(),
        "`auth logout` must leave no token in the store: {offenders:?}"
    );
}

/// `05-infrastructure.md`'s credential-disclosure response runs `auth logout`
/// on **every** host, because the operator does not know which ones hold a
/// value. A host that held none must therefore not fail the procedure.
#[test]
fn logout_on_a_host_that_was_never_signed_in_succeeds() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let github = FakeGithub::start();

    let outcome = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args(["auth", "logout"]);
        command
    });

    assert_eq!(
        outcome.code, 0,
        "a host with nothing to purge has complied with the procedure; stderr: {}",
        outcome.stderr
    );
    assert!(
        outcome.stdout.contains("Nothing to remove"),
        "and it must say so rather than claiming to have removed something:\n{}",
        outcome.stdout
    );
    assert!(
        outcome
            .stdout
            .contains("Authoritative revocation is uninstalling the App at GitHub."),
        "the notice is owed either way:\n{}",
        outcome.stdout
    );
}

// ----------------------------------------------------------------------------
// The App override is a seam for a fake GitHub, and cannot hijack a real one.
// ----------------------------------------------------------------------------
// A `runner-manager-d17-spike` override left at MACHINE scope after a
// verification spike survived on a workstation, and the shipped 0.1.2 asked for
// authorization as the spike: an unfamiliar App name on the page where the
// operator grants `Administration: Read and write`, with nothing on screen to
// explain it. The variables now apply only alongside a fake-GitHub endpoint,
// which is the only thing they were ever for.
//
// Driven through the real binary with a real environment rather than through a
// unit test, because the property is about what a released `auth login` does on
// an operator's machine, and a unit test that re-implemented the rule would pass
// while the binary did something else.
#[test]
fn an_app_override_without_a_fake_github_is_ignored_and_said_to_be_ignored() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");

    let outcome = run({
        // NO `RUNNER_MANAGER_GITHUB_BASE_URL`: this is the shape of an
        // operator's machine talking to the real github.com, carrying a stale
        // override.
        let mut command = runner_manager(data_dir.path());
        command
            .env(
                "RUNNER_MANAGER_GITHUB_CLIENT_ID",
                support::FIXTURE_CLIENT_ID,
            )
            .env("RUNNER_MANAGER_GITHUB_APP_SLUG", support::FIXTURE_APP_SLUG)
            .args(["auth", "status"]);
        command
    });

    assert!(
        outcome.stderr.contains("ignoring"),
        "a stale override must be reported as IGNORED rather than obeyed in \
         silence; stderr:\n{}",
        outcome.stderr
    );
    // The published slug as a literal: `crates/app` is a binary crate, so an
    // integration test cannot import the constant. Pinning the string here means
    // renaming the App reds this test, which is correct -- a rename needs a
    // release, not only a setting change.
    assert!(
        outcome.stderr.contains("runner-manager-scaler"),
        "and the warning must name the App the sign-in will actually use; \
         stderr:\n{}",
        outcome.stderr
    );
    assert!(
        !outcome.stderr.contains(&format!(
            "authenticating as the GitHub App `{}`",
            support::FIXTURE_APP_SLUG
        )),
        "the binary must not report authenticating as the overridden App; \
         stderr:\n{}",
        outcome.stderr
    );
}

// ----------------------------------------------------------------------------
// THE STORE THAT COULD NOT BE READ, AND THE REPAIR THAT REFUSED TO RUN.
// ----------------------------------------------------------------------------
// `auth login` reads the existing credential to decide whether to resume rather
// than start a device flow. That read used to be fatal, so the one command that
// repairs an unreadable store was the one command that would not run against
// one.
//
// Both ways in are real and both were seen on real hosts. On macOS a keychain
// item is granted per application, so a self-upgrade leaves the new binary
// reading `-25293` from its own credential. On Windows the store's DACL grants
// OWNER RIGHTS, and a daemon renewing under `LocalSystem` becomes the owner, so
// the operator loses access to what they stored. Either way the operator is
// told to run `auth login`, does, and is refused.
//
// Corrupt bytes stand in for both here: they reach the same `Err` from
// `SecretStore::load`, without needing a second account or a keychain.

/// The repair must run against the thing it repairs.
#[test]
fn a_sign_in_is_not_refused_by_a_store_it_cannot_read() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let github = FakeGithub::start();
    signed_in(data_dir.path(), &github);

    let store = files_under(data_dir.path())
        .into_iter()
        .find(|path| support::is_the_secret_store(path))
        .expect("the sign-in above wrote a credential somewhere under the store");
    std::fs::write(&store, b"not a credential this build can read")
        .expect("the store file is writable");

    github.with_device_code();
    github.with_approval();
    github.with_no_installations();
    let outcome = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args(["auth", "login"]);
        command
    });

    assert_eq!(
        outcome.code, 0,
        "an unreadable credential is the ordinary condition of a host about to sign in, not a \
         reason to refuse. stdout:\n{}\nstderr:\n{}",
        outcome.stdout, outcome.stderr
    );
    assert!(
        outcome.stdout.contains("could not be read"),
        "the operator is told which of the two things happened -- resumed, or replaced. \
         stdout:\n{}",
        outcome.stdout
    );
}
