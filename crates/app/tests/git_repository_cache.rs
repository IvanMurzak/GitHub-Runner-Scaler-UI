//! Real Git + native cache launch integration. The optional acceptance runs the
//! official actions/checkout bundle against a private local Git transport.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use runner_manager_agent::dependency_caches::DependencyCaches;
use runner_manager_agent::lifecycle::{ExecutionProvider, NativeProcesses, ProviderDestroy};
use runner_manager_domain::attempt::AttemptState;
use runner_manager_domain::model::ScaleTarget;
use runner_manager_platform::dependency_cache::{CONFIG_FILE, CacheConfig};
use runner_manager_platform::runner_env::RunnerEnv;

fn git(path: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .output()
        .unwrap()
}

fn good(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}

fn manager(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_runner-manager"))
        .arg("--data-dir")
        .arg(root)
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn git_cache_cli_round_trips_host_and_repository_overrides() {
    let root = tempfile::tempdir().unwrap();
    good(manager(
        root.path(),
        &["host", "cache", "set-tool", "git", "--state", "off"],
    ));
    good(manager(
        root.path(),
        &[
            "repo",
            "cache",
            "set-tool",
            "Octo/Repo",
            "git",
            "--state",
            "on",
        ],
    ));
    let path = root.path().join("config").join(CONFIG_FILE);
    let target = ScaleTarget::repository("Octo/Repo").unwrap();
    let config = CacheConfig::load(&path).unwrap();
    assert_eq!(config.tools.get("git"), Some(&false));
    assert_eq!(
        config.target(&target).unwrap().tools.get("git"),
        Some(&true)
    );
    good(manager(
        root.path(),
        &[
            "repo",
            "cache",
            "set-tool",
            "Octo/Repo",
            "git",
            "--state",
            "default",
        ],
    ));
    assert!(
        !CacheConfig::load(&path)
            .unwrap()
            .target(&target)
            .is_some_and(|own| own.tools.contains_key("git"))
    );
    good(manager(
        root.path(),
        &["host", "cache", "set-tool", "git", "--state", "default"],
    ));
    assert!(!CacheConfig::load(&path).unwrap().tools.contains_key("git"));
    assert!(
        good(manager(root.path(), &["host", "cache", "show"]))
            .contains("RUNNER_MANAGER_GIT_CACHE_DIR")
    );
}

fn commit(path: &Path, content: &str) -> String {
    std::fs::write(path.join("tracked.txt"), content).unwrap();
    good(git(path, &["add", "tracked.txt"]));
    good(git(
        path,
        &[
            "-c",
            "user.name=Cache fixture",
            "-c",
            "user.email=cache@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "fixture",
        ],
    ));
    good(git(path, &["rev-parse", "HEAD"]))
}

fn finish_native_attempt(caches: &DependencyCaches, runtime: &Path) {
    let provider = NativeProcesses::new().with_dependency_caches(caches.clone());
    let attempt = runner_manager_testkit::fixtures::attempt()
        .state(AttemptState::Finished)
        .runtime_path(runtime.to_str().unwrap())
        .build();
    assert_eq!(
        provider.destroy(&attempt).unwrap(),
        ProviderDestroy::Destroyed
    );
}

#[test]
#[ignore = "requires node and the pinned official actions/checkout fixture; explicitly run in CI and local acceptance"]
fn official_checkout_fetches_exact_pr_commit_after_independent_cache_seed() {
    let action = PathBuf::from(
        std::env::var_os("RUNNER_MANAGER_CHECKOUT_ACTION")
            .expect("set RUNNER_MANAGER_CHECKOUT_ACTION to the pinned actions/checkout checkout"),
    );
    assert!(action.join("dist/index.js").is_file());
    assert_eq!(
        good(git(&action, &["rev-parse", "HEAD"])),
        "3d3c42e5aac5ba805825da76410c181273ba90b1",
        "acceptance uses a reviewed checkout version"
    );
    let root = tempfile::tempdir().unwrap();
    let runners = root.path().join("runners");
    let config_dir = root.path().join("config");
    let remote = root.path().join("remote");
    for directory in [&runners, &config_dir, &remote] {
        std::fs::create_dir(directory).unwrap();
    }
    good(git(&remote, &["init", "--initial-branch=main"]));
    let base = commit(&remote, "base revision");
    let runner_root = runners.clone();
    let caches = DependencyCaches::new(
        config_dir.join(CONFIG_FILE),
        Arc::new(move || Some(runner_root.clone())),
        None,
    );
    // Policy spelling is case-insensitive; GitHub's workspace uses canonical
    // repository casing even when the operator configured a lower-case name.
    let target = ScaleTarget::repository("octo/repo").unwrap();
    let first = runners.join("attempt-one");
    good(manager(
        root.path(),
        &["host", "cache", "set-tool", "git", "--state", "on"],
    ));
    std::fs::create_dir_all(first.join("bin")).unwrap();
    let _ = caches.for_launch(&target, &first, &RunnerEnv::default());
    let original = first.join("_work/Repo/Repo");
    std::fs::create_dir_all(original.parent().unwrap()).unwrap();
    good(git(
        &remote,
        &[
            "clone",
            "--local",
            "--no-hardlinks",
            remote.to_str().unwrap(),
            original.to_str().unwrap(),
        ],
    ));
    good(git(
        &original,
        &[
            "remote",
            "set-url",
            "origin",
            "https://github.com/Octo/Repo",
        ],
    ));
    std::fs::write(original.join("old-build-output"), b"must not cross jobs").unwrap();
    finish_native_attempt(&caches, &first);
    remove_dir_all::remove_dir_all(&first).unwrap();

    let pr = commit(&remote, "exact PR merge revision");
    good(git(&remote, &["update-ref", "refs/pull/42/merge", &pr]));
    let second = runners.join("attempt-two");
    std::fs::create_dir_all(second.join("bin")).unwrap();
    let variables = caches.for_launch(&target, &second, &RunnerEnv::default());
    assert!(
        variables
            .iter()
            .any(|(name, _)| *name == runner_manager_platform::git_cache::ENVIRONMENT)
    );
    let workspace = second.join("_work/Repo/Repo");
    assert_eq!(good(git(&workspace, &["rev-parse", "HEAD"])), base);
    assert!(!git(&workspace, &["cat-file", "-e", &pr]).status.success());
    assert!(!workspace.join("old-build-output").exists());
    assert!(!workspace.join(".git/objects/info/alternates").exists());
    let usage = runner_manager_platform::dependency_cache::prune(
        &runners.join("_cache"),
        Some(0),
        &runner_manager_platform::dependency_cache::runtime_holds_runner,
    )
    .unwrap();
    assert!(
        usage.pruned.is_empty(),
        "the attempt's lease pins its namespace against pruning"
    );
    assert!(usage.namespaces.iter().any(|namespace| namespace.in_use));
    // Removing the manager's cache cannot invalidate an already seeded job.
    remove_dir_all::remove_dir_all(runners.join("_cache")).unwrap();

    let temp = root.path().join("runner-temp");
    std::fs::create_dir(&temp).unwrap();
    let state = temp.join("state");
    std::fs::write(&state, b"").unwrap();
    let event = temp.join("event.json");
    std::fs::write(&event, b"{}").unwrap();
    let prefix = if cfg!(windows) { "file:///" } else { "file://" };
    let remote_url = format!(
        "{prefix}{}",
        remote.display().to_string().replace('\\', "/")
    );
    let git_config = temp.join("gitconfig");
    std::fs::write(
        &git_config,
        format!("[url \"{remote_url}\"]\n insteadOf = https://github.com/Octo/Repo\n"),
    )
    .unwrap();
    let checkout = Command::new("node")
        .arg(action.join("dist/index.js"))
        .current_dir(&workspace)
        .env("GITHUB_WORKSPACE", &workspace)
        .env("RUNNER_TEMP", &temp)
        .env("GITHUB_REPOSITORY", "Octo/Repo")
        .env("GITHUB_SERVER_URL", "https://github.com")
        .env("GITHUB_REF", "refs/pull/42/merge")
        .env("GITHUB_SHA", &pr)
        .env("GITHUB_EVENT_NAME", "pull_request")
        .env("GITHUB_EVENT_PATH", &event)
        .env("GITHUB_STATE", &state)
        .env("GITHUB_ACTIONS", "true")
        .env("INPUT_REPOSITORY", "Octo/Repo")
        .env("INPUT_REF", "")
        .env("INPUT_TOKEN", "not-a-real-token-local-transport-only")
        .env("INPUT_FETCH-DEPTH", "1")
        .env("INPUT_CLEAN", "true")
        .env("INPUT_PERSIST-CREDENTIALS", "false")
        .env("INPUT_SET-SAFE-DIRECTORY", "false")
        .env("GIT_CONFIG_GLOBAL", &git_config)
        .env("GIT_ALLOW_PROTOCOL", "file")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        checkout.status.success(),
        "official checkout failed:\n{}\n{}",
        String::from_utf8_lossy(&checkout.stdout),
        String::from_utf8_lossy(&checkout.stderr)
    );
    assert_eq!(good(git(&workspace, &["rev-parse", "HEAD"])), pr);
    assert_eq!(
        std::fs::read_to_string(workspace.join("tracked.txt")).unwrap(),
        "exact PR merge revision"
    );
    assert!(!workspace.join("old-build-output").exists());
    finish_native_attempt(&caches, &second);
    let pointer = std::fs::read_dir(runners.join("_cache/octo/repo/git"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
        .join("current.json");
    let before = std::fs::read(&pointer).unwrap();
    let alternates = workspace.join(".git/objects/info/alternates");
    std::fs::write(&alternates, b"unsupported-external-store\n").unwrap();
    finish_native_attempt(&caches, &second);
    assert_eq!(
        std::fs::read(&pointer).unwrap(),
        before,
        "a refused cache publication still allows native destruction and keeps the last good snapshot"
    );
    std::fs::remove_file(alternates).unwrap();
    good(manager(
        root.path(),
        &[
            "repo",
            "cache",
            "set-tool",
            "octo/repo",
            "git",
            "--state",
            "off",
        ],
    ));
    let third = runners.join("attempt-three");
    std::fs::create_dir_all(third.join("bin")).unwrap();
    let disabled = caches.for_launch(&target, &third, &RunnerEnv::default());
    assert!(
        !disabled
            .iter()
            .any(|(name, _)| *name == runner_manager_platform::git_cache::ENVIRONMENT)
    );
    assert!(!third.join("_work/Repo/Repo/.git").exists());
    finish_native_attempt(&caches, &third);
    assert_eq!(std::fs::read(&pointer).unwrap(), before);
}
