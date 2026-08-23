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

#[test]
fn an_accepted_credential_reports_what_it_can_reach() {
    let data_dir = tempfile::tempdir().expect("a temporary directory");
    let github = FakeGithub::start();
    signed_in(data_dir.path(), &github);

    // Re-route discovery to a real installation for the status call.
    let github2 = FakeGithub::start();
    github2.with_installation(
        42,
        "operator",
        "User",
        "selected",
        &["operator/one", "operator/two"],
    );
    // The credential lives in the data directory, not in the fixture, so a
    // second fixture is simply a different GitHub for the same host.
    let outcome = run({
        let mut command = runner_manager_against(data_dir.path(), &github2);
        command.args(["auth", "status"]);
        command
    });

    assert_eq!(outcome.code, 0, "stderr: {}", outcome.stderr);
    assert!(
        outcome.stdout.contains("Credential: authenticated"),
        "{}",
        outcome.stdout
    );
    for repository in ["operator/one", "operator/two"] {
        assert!(
            outcome.stdout.contains(repository),
            "`07-security.md` requires the reachable repositories to be listed by name, so \
             that an over-broad installation is visible rather than assumed. Missing \
             {repository} in:\n{}",
            outcome.stdout
        );
    }
    assert!(
        outcome
            .stdout
            .contains("2 repositories and 0 organizations"),
        "the summary must count both kinds:\n{}",
        outcome.stdout
    );
    assert!(
        !outcome.stdout.contains("ALL repositories"),
        "a `selected` installation must not be labelled over-broad:\n{}",
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
