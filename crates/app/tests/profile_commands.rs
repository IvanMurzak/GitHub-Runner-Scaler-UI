mod support;

use runner_manager_domain::execution::{Backend, ExecutionPolicy, ImageReference, ResourceLimits};
use runner_manager_domain::store::{SqliteStore, Store};
use support::{FakeGithub, run, runner_manager, runner_manager_against};

fn signed_in(data_dir: &std::path::Path) {
    let github = FakeGithub::start();
    github
        .with_device_code()
        .with_approval()
        .with_no_installations();
    let result = run({
        let mut command = runner_manager_against(data_dir, &github);
        command.args(["auth", "login"]);
        command
    });
    assert_eq!(result.code, 0, "{}", result.both());
}

fn store(data_dir: &std::path::Path) -> SqliteStore {
    SqliteStore::open(data_dir.join("config/runner-manager.sqlite3")).unwrap()
}

#[test]
fn named_profiles_select_one_policy_and_legacy_ambiguity_is_closed() {
    let data_dir = tempfile::tempdir().unwrap();
    signed_in(data_dir.path());
    let github = FakeGithub::start();
    github.with_installation(77, "octo", "Organization", "selected", &["octo/one"]);
    let add_default = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args([
            "repo",
            "add",
            "octo/one",
            "--host-label",
            "home",
            "--max-capacity",
            "1",
        ]);
        command
    });
    assert_eq!(add_default.code, 0, "{}", add_default.both());
    let sole_profile = run({
        let mut command = runner_manager(data_dir.path());
        command.args(["repo", "profile", "show", "octo/one"]);
        command
    });
    assert_eq!(sole_profile.code, 0, "{}", sole_profile.both());
    assert!(
        sole_profile.stdout.contains("profile=default"),
        "{}",
        sole_profile.stdout
    );
    let add_named = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args([
            "repo",
            "profile",
            "add",
            "octo/one",
            "--name",
            "Py-Isolated",
            "--max-capacity",
            "2",
            "--execution",
            "native",
        ]);
        command
    });
    assert_eq!(add_named.code, 0, "{}", add_named.both());
    assert!(add_named.stdout.contains("rm-home-"));
    assert!(add_named.stdout.contains("py-isolated"));
    assert!(add_named.stdout.contains("static selector"));

    let policies = store(data_dir.path()).policies().unwrap();
    assert_eq!(policies.len(), 2);
    assert_ne!(policies[0].id, policies[1].id);
    let ambiguous = run({
        let mut command = runner_manager(data_dir.path());
        command.args(["repo", "set-capacity", "octo/one", "--max-capacity", "3"]);
        command
    });
    assert_eq!(ambiguous.code, 11, "{}", ambiguous.both());
    assert!(
        ambiguous
            .both()
            .contains("repo profile show octo/one --profile default"),
        "{}",
        ambiguous.both()
    );
    assert!(
        ambiguous
            .both()
            .contains("repo profile show octo/one --profile py-isolated"),
        "{}",
        ambiguous.both()
    );
    let selected = run({
        let mut command = runner_manager(data_dir.path());
        command.args([
            "repo",
            "set-capacity",
            "octo/one",
            "--profile",
            "PY-ISOLATED",
            "--max-capacity",
            "3",
        ]);
        command
    });
    assert_eq!(selected.code, 0, "{}", selected.both());
    let after = store(data_dir.path()).policies().unwrap();
    assert_eq!(
        after
            .iter()
            .find(|p| p.profile_name().as_str() == "default")
            .unwrap()
            .max_capacity()
            .unwrap()
            .get(),
        1
    );
    assert_eq!(
        after
            .iter()
            .find(|p| p.profile_name().as_str() == "py-isolated")
            .unwrap()
            .max_capacity()
            .unwrap()
            .get(),
        3
    );
}

#[test]
fn isolated_configuration_is_pinned_and_cannot_arm_without_provider() {
    let data_dir = tempfile::tempdir().unwrap();
    signed_in(data_dir.path());
    let github = FakeGithub::start();
    github.with_installation(77, "octo", "Organization", "selected", &["octo/one"]);
    let image = format!("registry.example/runner@sha256:{}", "a".repeat(64));
    let add = run({
        let mut command = runner_manager_against(data_dir.path(), &github);
        command.args([
            "repo",
            "profile",
            "add",
            "octo/one",
            "--name",
            "isolated",
            "--max-capacity",
            "1",
            "--execution",
            "isolated",
            "--backend",
            "oci",
            "--image",
            &image,
            "--cpu",
            "2000",
            "--memory",
            "2048",
            "--disk",
            "8192",
        ]);
        command
    });
    assert_eq!(add.code, 0, "{}", add.both());
    let policy = store(data_dir.path()).policies().unwrap().remove(0);
    let expected_execution = ExecutionPolicy::Isolated {
        backend: Backend::Oci,
        image: ImageReference::new(image.clone()).unwrap(),
        resources: ResourceLimits {
            cpu_millis: 2000,
            memory_mib: 2048,
            disk_mib: 8192,
        },
    };
    assert_eq!(policy.execution_policy(), &expected_execution);
    let show = run({
        let mut command = runner_manager(data_dir.path());
        command.args([
            "repo",
            "profile",
            "show",
            "octo/one",
            "--profile",
            "isolated",
        ]);
        command
    });
    assert_eq!(show.code, 0, "{}", show.both());
    let rendered_execution = show
        .stdout
        .lines()
        .find_map(|line| line.strip_prefix("execution details: "))
        .expect("profile inspection must render execution details");
    assert_eq!(
        serde_json::from_str::<ExecutionPolicy>(rendered_execution).unwrap(),
        expected_execution
    );
    let arm = run({
        let mut command = runner_manager(data_dir.path());
        command.args([
            "repo",
            "profile",
            "set-scale",
            "octo/one",
            "--profile",
            "isolated",
            "--enabled",
            "true",
        ]);
        command
    });
    assert_eq!(arm.code, 11, "{}", arm.both());
    assert!(arm.both().contains("host isolation status"));
    assert!(
        !store(data_dir.path())
            .policies()
            .unwrap()
            .remove(0)
            .enabled()
    );

    let status = run({
        let mut command = runner_manager(data_dir.path());
        command.args(["host", "isolation", "status", "--json"]);
        command
    });
    assert_eq!(status.code, 0, "{}", status.both());
    let json: serde_json::Value = serde_json::from_str(&status.stdout).unwrap();
    assert_eq!(json["schema_version"], 2);
    assert_eq!(json["scope"], "host prerequisites only");
    assert_eq!(json["policy_template_check"], "on enable and before JIT");
    let providers = json["providers"].as_array().expect("provider array");
    assert_eq!(providers.len(), 4);
    assert_eq!(
        providers
            .iter()
            .map(|provider| provider["backend"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "native",
            "oci",
            "windows_hyper_v_container",
            "virtual_machine"
        ]
    );
    for provider in providers {
        assert_eq!(provider.as_object().unwrap().len(), 3, "{provider}");
        assert!(
            matches!(
                provider["state"].as_str(),
                Some(
                    "ready"
                        | "unsupported"
                        | "not_installed"
                        | "permission_denied"
                        | "image_unavailable_or_incompatible"
                        | "degraded"
                )
            ),
            "{provider}"
        );
    }
}

#[test]
fn selected_native_profile_persists_workspace_and_warns_without_changing_sibling() {
    let data_dir = tempfile::tempdir().unwrap();
    signed_in(data_dir.path());
    let github = FakeGithub::start();
    github.with_installation(77, "octo", "Organization", "selected", &["octo/one"]);
    for args in [
        vec![
            "repo",
            "add",
            "octo/one",
            "--host-label",
            "home",
            "--max-capacity",
            "1",
        ],
        vec![
            "repo",
            "profile",
            "add",
            "octo/one",
            "--name",
            "native-cache",
            "--max-capacity",
            "2",
        ],
    ] {
        let result = run({
            let mut command = runner_manager_against(data_dir.path(), &github);
            command.args(args);
            command
        });
        assert_eq!(result.code, 0, "{}", result.both());
    }

    let before = store(data_dir.path()).policies().unwrap();
    let sibling = before
        .iter()
        .find(|policy| policy.profile_name().as_str() == "default")
        .unwrap()
        .clone();
    let workspace_parent = tempfile::tempdir().unwrap();
    let workspace_root = workspace_parent.path().join("native-slots");
    let workspace_text = workspace_root.to_str().unwrap();
    let persistent = run({
        let mut command = runner_manager(data_dir.path());
        command.args([
            "repo",
            "profile",
            "set-workspace",
            "octo/one",
            "--profile",
            "native-cache",
            "--mode",
            "persistent",
            "--path",
            workspace_text,
        ]);
        command
    });
    assert_eq!(persistent.code, 0, "{}", persistent.both());
    for warning in [
        "trusted-workflow optimization, not isolation",
        "untrusted fork or pull-request workflows",
    ] {
        assert!(
            persistent.stdout.contains(warning),
            "missing {warning:?}: {}",
            persistent.stdout
        );
    }

    let after = store(data_dir.path()).policies().unwrap();
    let selected = after
        .iter()
        .find(|policy| policy.profile_name().as_str() == "native-cache")
        .unwrap();
    assert_eq!(
        selected.workspace_policy().root().map(|root| root.as_str()),
        Some(workspace_text)
    );
    let unchanged_sibling = after
        .iter()
        .find(|policy| policy.profile_name().as_str() == "default")
        .unwrap();
    assert_eq!(unchanged_sibling, &sibling);
}

#[test]
fn profile_commands_mutate_and_remove_only_the_selected_sibling() {
    let data_dir = tempfile::tempdir().unwrap();
    signed_in(data_dir.path());
    let github = FakeGithub::start();
    github.with_installation(77, "octo", "Organization", "selected", &["octo/one"]);
    for args in [
        vec![
            "repo",
            "add",
            "octo/one",
            "--host-label",
            "home",
            "--max-capacity",
            "1",
        ],
        vec![
            "repo",
            "profile",
            "add",
            "octo/one",
            "--name",
            "build",
            "--max-capacity",
            "2",
        ],
    ] {
        let result = run({
            let mut command = runner_manager_against(data_dir.path(), &github);
            command.args(args);
            command
        });
        assert_eq!(result.code, 0, "{}", result.both());
    }
    let before = store(data_dir.path()).policies().unwrap();
    let default = before
        .iter()
        .find(|policy| policy.profile_name().as_str() == "default")
        .unwrap();
    let default_id = default.id;
    let default_revision = default.revision();
    let run_command = |args: &[&str]| {
        run({
            let mut command = runner_manager(data_dir.path());
            command.args(args);
            command
        })
    };
    for args in [
        vec!["repo", "profile", "list", "octo/one"],
        vec!["repo", "profile", "show", "octo/one", "--profile", "BUILD"],
        vec![
            "repo",
            "profile",
            "add-label",
            "octo/one",
            "--profile",
            "build",
            "--label",
            "gpu",
        ],
        vec![
            "repo",
            "profile",
            "remove-label",
            "octo/one",
            "--profile",
            "build",
            "--label",
            "gpu",
        ],
        vec![
            "repo",
            "profile",
            "set-workspace",
            "octo/one",
            "--profile",
            "build",
            "--mode",
            "ephemeral",
        ],
        vec![
            "repo",
            "profile",
            "set-execution",
            "octo/one",
            "--profile",
            "build",
            "--mode",
            "native",
        ],
    ] {
        let result = run_command(&args);
        assert_eq!(result.code, 0, "{}: {}", args.join(" "), result.both());
    }
    let image = format!("registry.example/runner@sha256:{}", "b".repeat(64));
    let enabled = run_command(&[
        "repo",
        "profile",
        "set-scale",
        "octo/one",
        "--profile",
        "build",
        "--enabled",
        "true",
    ]);
    assert_eq!(enabled.code, 0, "{}", enabled.both());
    let isolated_while_enabled = run({
        let mut command = runner_manager(data_dir.path());
        command.args([
            "repo",
            "profile",
            "set-execution",
            "octo/one",
            "--profile",
            "build",
            "--mode",
            "isolated",
            "--backend",
            "oci",
            "--image",
            &image,
        ]);
        command
    });
    assert_eq!(
        isolated_while_enabled.code,
        11,
        "{}",
        isolated_while_enabled.both()
    );
    assert!(
        isolated_while_enabled
            .both()
            .contains("set-scale octo/one --profile build --enabled false")
    );
    let unchanged = store(data_dir.path()).policies().unwrap();
    let build = unchanged
        .iter()
        .find(|policy| policy.profile_name().as_str() == "build")
        .unwrap();
    assert!(build.enabled());
    assert!(build.execution_policy().is_native());

    let disabled = run_command(&[
        "repo",
        "profile",
        "set-scale",
        "octo/one",
        "--profile",
        "build",
        "--enabled",
        "false",
    ]);
    assert_eq!(disabled.code, 0, "{}", disabled.both());
    let isolated = run({
        let mut command = runner_manager(data_dir.path());
        command.args([
            "repo",
            "profile",
            "set-execution",
            "octo/one",
            "--profile",
            "build",
            "--mode",
            "isolated",
            "--backend",
            "oci",
            "--image",
            &image,
        ]);
        command
    });
    assert_eq!(isolated.code, 0, "{}", isolated.both());
    let current = store(data_dir.path()).policies().unwrap();
    assert!(matches!(
        current
            .iter()
            .find(|p| p.profile_name().as_str() == "build")
            .unwrap()
            .execution_policy(),
        ExecutionPolicy::Isolated { .. }
    ));
    assert!(
        current
            .iter()
            .find(|p| p.id == default_id)
            .unwrap()
            .execution_policy()
            .is_native()
    );

    let workspace_parent = tempfile::tempdir().unwrap();
    let workspace_root = workspace_parent.path().join("isolated-slots");
    let workspace_text = workspace_root.to_str().unwrap();
    let persistent = run_command(&[
        "repo",
        "profile",
        "set-workspace",
        "octo/one",
        "--profile",
        "build",
        "--mode",
        "persistent",
        "--path",
        workspace_text,
    ]);
    assert_eq!(persistent.code, 9, "{}", persistent.both());
    assert!(persistent.both().contains("isolated execution"));
    assert!(
        !workspace_root.exists(),
        "an invalid isolated workspace must not create {}",
        workspace_root.display()
    );

    let add_label = run_command(&[
        "repo",
        "profile",
        "add-label",
        "octo/one",
        "--profile",
        "build",
        "--label",
        "gpu",
    ]);
    assert_eq!(add_label.code, 0, "{}", add_label.both());
    let show = run_command(&["repo", "profile", "show", "octo/one", "--profile", "build"]);
    assert_eq!(show.code, 0, "{}", show.both());
    for field in [
        "host_label=home",
        "labels=rm-home-",
        ",gpu",
        "state=",
        "min=0",
        "workspace=ephemeral",
        "workspace_path=-",
        "execution=isolated",
        "cpu_millis",
        "memory_mib",
        "disk_mib",
    ] {
        assert!(
            show.stdout.contains(field),
            "missing {field:?}: {}",
            show.stdout
        );
    }
    let remove = run_command(&[
        "repo",
        "profile",
        "remove",
        "octo/one",
        "--profile",
        "build",
    ]);
    assert_eq!(remove.code, 0, "{}", remove.both());
    let after = store(data_dir.path()).policies().unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].id, default_id);
    assert_eq!(after[0].revision(), default_revision);
}
