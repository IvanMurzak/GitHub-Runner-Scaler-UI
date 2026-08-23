// owner: f2-cli-policy-commands

mod support;

use runner_manager_domain::attempt::AttemptState;
use runner_manager_domain::model::{AttemptId, ScaleTarget};
use runner_manager_domain::store::{SqliteStore, Store};
use runner_manager_testkit::fixtures::attempt;
use support::{
    FIXTURE_APP_SLUG, FIXTURE_CLIENT_ID, FakeGithub, fixture_token, run, runner_manager,
    runner_manager_against,
};

fn signed_in(data_dir: &std::path::Path) {
    let github = FakeGithub::start();
    github
        .with_device_code()
        .with_approval()
        .with_no_installations();
    let outcome = run({
        let mut command = runner_manager_against(data_dir, &github);
        command.args(["auth", "login"]);
        command
    });
    assert_eq!(outcome.code, 0, "{}", outcome.both());
}

fn database(data_dir: &std::path::Path) -> SqliteStore {
    SqliteStore::open(data_dir.join("config").join("runner-manager.sqlite3")).unwrap()
}

#[test]
fn scripted_policy_flow_uses_read_only_github_and_preserves_each_requested_label() {
    let data_dir = tempfile::tempdir().unwrap();
    signed_in(data_dir.path());
    let github = FakeGithub::start();
    github.with_installation(
        77,
        "octo",
        "Organization",
        "selected",
        &["octo/one", "octo/two"],
    );

    for (repository, label, maximum) in [
        ("octo/one", "home", None),
        ("octo/two", "office", Some("2")),
    ] {
        let outcome = run({
            let mut command = runner_manager_against(data_dir.path(), &github);
            command.args(["repo", "add", repository, "--host-label", label]);
            if let Some(maximum) = maximum {
                command.args(["--max-capacity", maximum]);
            }
            command
        });
        assert_eq!(outcome.code, 0, "{}", outcome.both());
        if maximum.is_some() {
            assert!(outcome.stdout.contains("Routing label: rm-office-"));
        } else {
            assert!(outcome.stdout.contains("Monitor-only"));
            assert!(outcome.stdout.contains("Administration: Read and write"));
        }
    }
    assert_eq!(
        github.seen(),
        [
            "GET /user/installations",
            "GET /user/installations/77/repositories",
            "GET /user/installations",
            "GET /user/installations/77/repositories",
        ],
        "add must spend exactly two read requests per discovery and make no GitHub writes"
    );

    let promote = run({
        let mut command = runner_manager(data_dir.path());
        command.args(["repo", "set-capacity", "octo/one", "--max-capacity", "2"]);
        command
    });
    assert_eq!(promote.code, 0, "{}", promote.both());
    assert!(promote.stdout.contains("Routing label: rm-home-"));

    let store = database(data_dir.path());
    let policies = store.policies().unwrap();
    let first = policies
        .iter()
        .find(|policy| policy.target == ScaleTarget::repository("octo/one").unwrap())
        .unwrap();
    let second = policies
        .iter()
        .find(|policy| policy.target == ScaleTarget::repository("octo/two").unwrap())
        .unwrap();
    assert_eq!(first.requested_host_label.as_str(), "home");
    assert_eq!(second.requested_host_label.as_str(), "office");
    assert!(
        first
            .routing_labels()
            .unwrap()
            .host_label()
            .as_str()
            .contains("home")
    );
    assert!(
        second
            .routing_labels()
            .unwrap()
            .host_label()
            .as_str()
            .contains("office")
    );

    for enabled in ["true", "false"] {
        let outcome = run({
            let mut command = runner_manager(data_dir.path());
            command.args(["repo", "set-scale", "octo/one", "--enabled", enabled]);
            command
        });
        assert_eq!(outcome.code, 0, "explicit {enabled}: {}", outcome.both());
    }

    let mut second = store
        .policies()
        .unwrap()
        .into_iter()
        .find(|policy| policy.target == ScaleTarget::repository("octo/two").unwrap())
        .unwrap();
    let expected = second.revision();
    second.repair_required().unwrap();
    store.update_policy(&second, expected).unwrap();
    let repair = run({
        let mut command = runner_manager(data_dir.path());
        command.args(["repo", "list"]);
        command
    });
    assert_eq!(repair.code, 0, "{}", repair.both());
    assert!(repair.stdout.contains("repair_required"));
    assert!(
        repair
            .stdout
            .contains("repair: runner-manager repo remove octo/two --purge")
    );
    assert!(
        github
            .seen()
            .iter()
            .all(|request| request.starts_with("GET ")),
        "reporting repair_required must not try a remote deletion"
    );
    let busy = attempt()
        .policy_id(second.id)
        .state(AttemptState::Busy)
        .github_runner_id(73)
        .process_id(4242)
        .build();
    store.record_attempt(&busy).unwrap();
    let refusal = run({
        let mut command = runner_manager(data_dir.path());
        command.args(["repo", "remove", "octo/two", "--purge"]);
        command
    });
    assert_eq!(refusal.code, 11, "{}", refusal.both());
    assert!(refusal.both().contains("1 active runner"));
    assert!(store.policy(second.id).unwrap().is_some());

    let first_id = first.id;
    drop(policies);
    let diagnostic = attempt()
        .id(AttemptId::new_random())
        .policy_id(first_id)
        .state(AttemptState::Finished)
        .build();
    store.record_attempt(&diagnostic).unwrap();
    let remove = run({
        let mut command = runner_manager(data_dir.path());
        command.args(["repo", "remove", "octo/one"]);
        command
    });
    assert_eq!(remove.code, 0, "{}", remove.both());
    assert!(remove.stdout.contains("diagnostics were preserved"));
    assert!(store.policy(first_id).unwrap().is_none());
    assert_eq!(store.attempts_for_policy(first_id).unwrap().len(), 1);

    store.remove_attempt(busy.id).unwrap();
    let purge = run({
        let mut command = runner_manager(data_dir.path());
        command.args(["repo", "remove", "octo/two", "--purge"]);
        command
    });
    assert_eq!(purge.code, 0, "{}", purge.both());
    assert!(purge.stdout.contains("purged its historical diagnostics"));
    assert!(store.policy(second.id).unwrap().is_none());
}

#[test]
fn explicit_boole_reach_repo_and_org_runtime_and_failures_redact_the_credential() {
    let empty = tempfile::tempdir().unwrap();
    for (scope, target, enabled) in [("repo", "octo/missing", "false"), ("org", "octo", "true")] {
        let outcome = run({
            let mut command = runner_manager(empty.path());
            command.args([scope, "set-scale", target, "--enabled", enabled]);
            command
        });
        assert_eq!(
            outcome.code,
            10,
            "clap must accept {scope} {enabled}: {}",
            outcome.both()
        );
    }

    let data_dir = tempfile::tempdir().unwrap();
    signed_in(data_dir.path());
    let missing = FakeGithub::start();
    missing.with_installation(88, "elsewhere", "User", "selected", &["elsewhere/repo"]);
    let absent = run({
        let mut command = runner_manager_against(data_dir.path(), &missing);
        command.args(["repo", "add", "octo/missing", "--host-label", "home"]);
        command
    });
    assert_eq!(absent.code, 10, "{}", absent.both());
    assert!(database(data_dir.path()).policies().unwrap().is_empty());

    let unavailable = run({
        let mut command = runner_manager(data_dir.path());
        command
            .env("RUNNER_MANAGER_GITHUB_BASE_URL", "http://127.0.0.1:9/")
            .env("RUNNER_MANAGER_GITHUB_CLIENT_ID", FIXTURE_CLIENT_ID)
            .env("RUNNER_MANAGER_GITHUB_APP_SLUG", FIXTURE_APP_SLUG)
            .args(["repo", "add", "octo/missing", "--host-label", "home"]);
        command
    });
    assert_eq!(unavailable.code, 7, "{}", unavailable.both());
    assert!(!unavailable.both().contains(&fixture_token()));
    assert!(database(data_dir.path()).policies().unwrap().is_empty());
}
