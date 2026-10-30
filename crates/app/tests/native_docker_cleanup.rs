//! Real CLI and opt-in Docker acceptance. The live test owns a unique set of
//! names and removes only that set. It never prunes an engine or its caches.

use std::path::Path;
use std::process::{Command, Output};

fn manager(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_runner-manager"))
        .arg("--data-dir")
        .arg(root)
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .unwrap()
}

fn ok(root: &Path, args: &[&str]) -> String {
    let result = manager(root, args);
    assert!(
        result.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}

#[test]
fn host_controls_default_to_report_and_do_not_walk_caches_or_workspaces() {
    let root = tempfile::tempdir().unwrap();
    let cache = root.path().join("runtime/_cache/owner/repo/sentinel");
    let work = root.path().join("persistent/s1/_work/sentinel");
    for path in [&cache, &work] {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"preserve me").unwrap();
    }
    let report: serde_json::Value =
        serde_json::from_str(&ok(root.path(), &["host", "docker-cleanup", "show"])).unwrap();
    assert_eq!(report["mode"], "report");
    assert_eq!(report["supported"], cfg!(target_os = "linux"));
    if cfg!(target_os = "linux") {
        for mode in ["off", "report", "apply"] {
            ok(
                root.path(),
                &["host", "docker-cleanup", "set-mode", "--mode", mode],
            );
            let shown: serde_json::Value =
                serde_json::from_str(&ok(root.path(), &["host", "docker-cleanup", "show"]))
                    .unwrap();
            assert_eq!(shown["mode"], mode);
        }
        ok(
            root.path(),
            &["host", "docker-cleanup", "set-mode", "--mode", "off"],
        );
        ok(root.path(), &["host", "docker-cleanup", "report"]);
        ok(root.path(), &["host", "docker-cleanup", "sweep"]);
    } else {
        assert!(
            !manager(
                root.path(),
                &["host", "docker-cleanup", "set-mode", "--mode", "apply"]
            )
            .status
            .success()
        );
        assert!(!root.path().join("config/docker-cleanup.json").exists());
        assert!(
            !manager(root.path(), &["host", "docker-cleanup", "report"])
                .status
                .success()
        );
        assert!(
            !manager(root.path(), &["host", "docker-cleanup", "sweep"])
                .status
                .success()
        );
    }
    assert_eq!(std::fs::read(cache).unwrap(), b"preserve me");
    assert_eq!(std::fs::read(work).unwrap(), b"preserve me");
}

#[cfg(target_os = "linux")]
#[test]
fn unresponsive_engine_startup_is_bounded_and_reaps_its_companion() {
    use runner_manager_agent::docker_cleanup::DockerCleanup;
    use runner_manager_domain::model::{AttemptId, HostId};
    use runner_manager_platform::runner_env::RunnerEnv;
    use std::os::unix::net::UnixListener;
    use std::time::{Duration, Instant};

    let root = tempfile::tempdir().unwrap();
    let socket = root.path().join("unresponsive.sock");
    // Connections can be established, but no response is ever supplied.
    let _listener = UnixListener::bind(&socket).unwrap();
    let mut cleanup = DockerCleanup::new(
        HostId::from_u128(1),
        &root.path().join("config"),
        &root.path().join("state"),
    );
    cleanup.companion = Some(env!("CARGO_BIN_EXE_runner-manager").into());
    let mut env = RunnerEnv::default();
    env.set("DOCKER_HOST", &format!("unix://{}", socket.display()))
        .unwrap();
    env.set("DOCKER_CONTEXT", "").unwrap();
    let started = Instant::now();
    let result = cleanup.launch_environment(AttemptId::from_u128(2), "owner/repo", &env);
    assert!(result.unwrap_err().to_string().contains("timed out"));
    assert!(started.elapsed() < Duration::from_secs(15));
    // The companion is killed and waited by launch_environment, before its
    // journal can advertise readiness or contain creation intents.
    let directory = cleanup.root.join(AttemptId::from_u128(2).to_string());
    assert!(!directory.join("ready").exists());
    let journal =
        runner_manager_agent::docker_cleanup::Journal::load(&directory.join("journal.json"))
            .unwrap();
    assert!(journal.proxy.is_none());
    assert!(journal.intents.is_empty());
}

#[cfg(target_os = "linux")]
mod live {
    use super::*;
    use runner_manager_agent::docker_cleanup::{DockerCleanup, Journal};
    use runner_manager_domain::attempt::AttemptState;
    use runner_manager_domain::model::{AttemptId, PolicyId};
    use runner_manager_domain::store::{SqliteStore, Store};
    use runner_manager_platform::runner_env::RunnerEnv;
    use runner_manager_testkit::fixtures;
    use std::io::Write;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    struct Fixture {
        nonce: String,
        endpoint: String,
        root: tempfile::TempDir,
        proxy_directory: Option<std::path::PathBuf>,
        extra_proxy_directories: Vec<std::path::PathBuf>,
        containers: Vec<String>,
        volumes: Vec<String>,
        network: Option<String>,
        image_tag: Option<String>,
    }

    impl Fixture {
        fn command(&self, proxy: bool) -> Command {
            let mut command = Command::new("docker");
            command.env_remove("DOCKER_CONTEXT");
            command.arg("--host").arg(if proxy {
                &self.endpoint
            } else {
                "unix:///var/run/docker.sock"
            });
            command
        }

        fn docker(&self, proxy: bool, args: &[&str]) -> String {
            let result = self.command(proxy).args(args).output().unwrap();
            assert!(
                result.status.success(),
                "docker {args:?}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            String::from_utf8(result.stdout).unwrap().trim().into()
        }

        fn exists(&self, kind: &str, name: &str) -> bool {
            self.command(false)
                .args([kind, "inspect", name])
                .output()
                .unwrap()
                .status
                .success()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            for directory in self
                .proxy_directory
                .iter()
                .chain(self.extra_proxy_directories.iter())
            {
                let _ = std::fs::write(directory.join("stop"), b"true");
                if let Ok(journal) = Journal::load(&directory.join("journal.json"))
                    && let Some(identity) = journal.proxy
                {
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while matches!(
                        identity.recheck(),
                        Ok(runner_manager_platform::process::Adoption::Live)
                    ) {
                        if Instant::now() >= deadline {
                            self.root.disable_cleanup(true);
                            eprintln!(
                                "companion PID={} has not exited; retaining its stop marker for safe shutdown",
                                identity.pid()
                            );
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
            }
            for container in &self.containers {
                let _ = self
                    .command(false)
                    .args(["container", "rm", "--force", "--volumes", container])
                    .output();
            }
            for volume in &self.volumes {
                let _ = self.command(false).args(["volume", "rm", volume]).output();
            }
            if let Some(network) = &self.network {
                let _ = self
                    .command(false)
                    .args(["network", "rm", network])
                    .output();
            }
            if let Some(image) = &self.image_tag {
                let _ = self.command(false).args(["image", "rm", image]).output();
            }
        }
    }

    #[test]
    #[ignore = "requires the native Linux Docker engine; run explicitly on a development host"]
    fn live_proxy_report_apply_recovery_streams_and_cache_preservation() {
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let mut fixture = Fixture {
            nonce: nonce.clone(),
            endpoint: String::new(),
            root: tempfile::tempdir().unwrap(),
            proxy_directory: None,
            extra_proxy_directories: Vec::new(),
            containers: Vec::new(),
            volumes: Vec::new(),
            network: None,
            image_tag: None,
        };
        let root = fixture.root.path().to_path_buf();
        ok(&root, &["host", "docker-cleanup", "show"]);
        let store = SqliteStore::open(root.join("config/runner-manager.sqlite3")).unwrap();
        let host = store.hosts().unwrap().pop().unwrap();
        let policy_id = PolicyId::new_random();
        let policy = fixtures::policy()
            .id(policy_id)
            .host(host.id)
            .autoscale("cleanup-live", 1)
            .build();
        store.insert_policy(&policy).unwrap();
        let attempt_id = AttemptId::new_random();
        let attempt = fixtures::attempt()
            .id(attempt_id)
            .policy_id(policy_id)
            .state(AttemptState::Busy)
            .github_runner_id(73)
            .process_id(std::process::id())
            .runtime_path(root.join("runtime/attempt").to_str().unwrap())
            .build();
        store.record_attempt(&attempt).unwrap();
        let mut cleanup = DockerCleanup::new(host.id, &root.join("config"), &root.join("state"));
        cleanup.companion = Some(env!("CARGO_BIN_EXE_runner-manager").into());
        let endpoint = cleanup
            .launch_environment(attempt_id, "fixture/repository", &RunnerEnv::default())
            .unwrap()
            .expect("local Docker proxy");
        fixture.endpoint = endpoint.to_string_lossy().into_owned();
        let directory = cleanup.root.join(attempt_id.to_string());
        fixture.proxy_directory = Some(directory.clone());
        let initial = Journal::load(&directory.join("journal.json")).unwrap();
        runner_manager_agent::docker_cleanup::write_json(
            &directory.join("runner.json"),
            &runner_manager_platform::process::ProcessIdentity::of_current_process().unwrap(),
        )
        .unwrap();
        eprintln!(
            "LIVE companion PID={} fixture={}",
            initial.proxy.as_ref().unwrap().pid(),
            fixture.nonce
        );
        let image = std::env::var("RUNNER_MANAGER_DOCKER_LIVE_IMAGE")
            .unwrap_or_else(|_| "ubuntu:24.04".into());
        if !fixture.exists("image", &image) {
            fixture.docker(false, &["pull", &image]);
        }
        let cache_file = root.join("runtime/_cache/owner/repo/sentinel");
        let retained_work = root.join("persistent/s1/_work/sentinel");
        for path in [&cache_file, &retained_work] {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"cache-sentinel").unwrap();
        }

        let named_cache = format!("rm-cleanup-live-cache-{nonce}");
        fixture.volumes.push(named_cache.clone());
        fixture.docker(true, &["volume", "create", &named_cache]);
        let network = format!("rm-cleanup-live-net-{nonce}");
        fixture.network = Some(network.clone());
        fixture.docker(true, &["network", "create", &network]);
        let owned = format!("rm-cleanup-live-owned-{nonce}");
        fixture.containers.push(owned.clone());
        let cache_mount = format!("{named_cache}:/cache");
        fixture.docker(
            true,
            &[
                "run",
                "-d",
                "--name",
                &owned,
                "--network",
                &network,
                "-v",
                "/volatile",
                "-v",
                &cache_mount,
                &image,
                "sh",
                "-c",
                "echo docker-cache-sentinel >/cache/sentinel; sleep 600",
            ],
        );
        let unrelated = format!("rm-cleanup-live-unrelated-{nonce}");
        fixture.containers.push(unrelated.clone());
        fixture.docker(
            false,
            &["run", "-d", "--name", &unrelated, &image, "sleep", "600"],
        );
        let kept = format!("rm-cleanup-live-kept-{nonce}");
        fixture.containers.push(kept.clone());
        fixture.docker(
            true,
            &[
                "run",
                "-d",
                "--name",
                &kept,
                "--label",
                "runner-manager.retain=true",
                &image,
                "sleep",
                "600",
            ],
        );

        // Docker attach upgrades and stdin half-close must still behave normally.
        let interactive_name = format!("rm-cleanup-live-interactive-{nonce}");
        fixture.containers.push(interactive_name.clone());
        let mut interactive = fixture
            .command(true)
            .args([
                "run",
                "--rm",
                "--name",
                &interactive_name,
                "-i",
                &image,
                "cat",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        interactive
            .stdin
            .take()
            .unwrap()
            .write_all(b"interactive-sentinel\n")
            .unwrap();
        let interactive = interactive.wait_with_output().unwrap();
        assert!(
            interactive.status.success(),
            "{}",
            String::from_utf8_lossy(&interactive.stderr)
        );
        assert_eq!(interactive.stdout, b"interactive-sentinel\n");

        // Use the existing engine builder without changing the selected builder
        // or pruning caches. The second build after cleanup must hit this layer.
        let build_context = root.join("build-context");
        std::fs::create_dir(&build_context).unwrap();
        std::fs::write(
            build_context.join("Dockerfile"),
            format!("FROM {image}\nRUN printf build-cache-sentinel > /cleanup-cache-marker\n"),
        )
        .unwrap();
        let image_tag = format!("rm-cleanup-live:{nonce}");
        fixture.image_tag = Some(image_tag.clone());
        let first_build = fixture
            .command(true)
            .args([
                "buildx",
                "build",
                "--builder",
                "default",
                "--load",
                "--progress=plain",
                "-t",
                &image_tag,
            ])
            .arg(&build_context)
            .output()
            .unwrap();
        assert!(
            first_build.status.success(),
            "{}",
            String::from_utf8_lossy(&first_build.stderr)
        );

        // Busy and unknown attempts are not eligible even in apply mode.
        ok(&root, &["host", "docker-cleanup", "report"]);
        assert!(fixture.exists("container", &owned));
        assert!(!directory.join("stop").exists());
        let recorded = Journal::load(&directory.join("journal.json")).unwrap();
        let temporary_volumes: Vec<_> = recorded
            .resources
            .iter()
            .filter(|resource| resource.implicit_volume)
            .map(|resource| resource.id.clone())
            .collect();
        assert_eq!(temporary_volumes.len(), 1);
        fixture.volumes.extend(temporary_volumes.clone());

        // A second tracked attempt borrows the first one's anonymous volume.
        // The first sweep must neither stop that attempt nor remove its mount.
        let parallel_id = AttemptId::new_random();
        let parallel_attempt = fixtures::attempt()
            .id(parallel_id)
            .policy_id(policy_id)
            .state(AttemptState::Busy)
            .github_runner_id(75)
            .process_id(std::process::id())
            .runtime_path(root.join("runtime/parallel").to_str().unwrap())
            .build();
        store.record_attempt(&parallel_attempt).unwrap();
        let parallel_endpoint = cleanup
            .launch_environment(parallel_id, "fixture/repository", &RunnerEnv::default())
            .unwrap()
            .unwrap();
        let parallel_directory = cleanup.root.join(parallel_id.to_string());
        fixture
            .extra_proxy_directories
            .push(parallel_directory.clone());
        let parallel_journal = Journal::load(&parallel_directory.join("journal.json")).unwrap();
        eprintln!(
            "LIVE parallel companion PID={}",
            parallel_journal.proxy.as_ref().unwrap().pid()
        );
        runner_manager_agent::docker_cleanup::write_json(
            &parallel_directory.join("runner.json"),
            &runner_manager_platform::process::ProcessIdentity::of_current_process().unwrap(),
        )
        .unwrap();
        let main_endpoint = fixture.endpoint.clone();
        fixture.endpoint = parallel_endpoint.to_string_lossy().into_owned();
        let parallel_container = format!("rm-cleanup-live-parallel-{nonce}");
        fixture.containers.push(parallel_container.clone());
        fixture.docker(
            true,
            &[
                "run",
                "-d",
                "--name",
                &parallel_container,
                "-v",
                &format!("{}:/borrowed", temporary_volumes[0]),
                &image,
                "sleep",
                "600",
            ],
        );
        fixture.endpoint = main_endpoint;

        // Simulate an ambiguous create response: preserve the intent but lose
        // the container record. Recovery must find it by exact labels.
        let mut ambiguous = recorded;
        ambiguous.resources.retain(|resource| {
            resource.kind != runner_manager_agent::docker_cleanup::Kind::Container
        });
        let late_operation = uuid::Uuid::new_v4().to_string();
        ambiguous
            .intents
            .push(runner_manager_agent::docker_cleanup::Intent {
                id: late_operation.clone(),
                kind: runner_manager_agent::docker_cleanup::Kind::Network,
                explicit_volume_destinations: Default::default(),
                inherits_volumes: false,
                settled: false,
            });
        runner_manager_agent::docker_cleanup::write_json(&directory.join("stop"), &true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while initial.proxy.as_ref().unwrap().recheck().unwrap()
            == runner_manager_platform::process::Adoption::Live
        {
            assert!(Instant::now() < deadline, "proxy did not exit");
            std::thread::sleep(Duration::from_millis(20));
        }
        runner_manager_agent::docker_cleanup::write_json(
            &directory.join("journal.json"),
            &ambiguous,
        )
        .unwrap();
        let mut cleaned = attempt.clone();
        cleaned
            .conclude(
                runner_manager_domain::attempt::AttemptOutcome::CompletedJob,
                fixtures::created_at(),
            )
            .unwrap();
        cleaned.clean(fixtures::created_at()).unwrap();
        store.record_attempt(&cleaned).unwrap();
        let report: serde_json::Value =
            serde_json::from_str(&ok(&root, &["host", "docker-cleanup", "report"])).unwrap();
        assert!(report["candidates"].as_u64().unwrap() >= 3, "{report}");
        assert_eq!(report["removed"], 0);
        assert!(fixture.exists("container", &owned));
        ok(
            &root,
            &["host", "docker-cleanup", "set-mode", "--mode", "apply"],
        );
        let applied: serde_json::Value =
            serde_json::from_str(&ok(&root, &["host", "docker-cleanup", "sweep"])).unwrap();
        assert!(applied["removed"].as_u64().unwrap() >= 2, "{applied}");
        assert!(
            applied["pending"].as_u64().unwrap() >= 1,
            "the borrowed volume must be deferred: {applied}"
        );
        assert!(!fixture.exists("container", &owned));
        assert!(!fixture.exists("network", &network));
        assert!(
            directory.join("journal.json").exists(),
            "an unresolved create must retain its journal even with no current resource"
        );
        let late_network = format!("rm-cleanup-live-late-{nonce}");
        fixture.network = Some(late_network.clone());
        fixture.docker(
            false,
            &[
                "network",
                "create",
                "--label",
                &format!("runner-manager.host={}", host.id),
                "--label",
                &format!("runner-manager.attempt={attempt_id}"),
                "--label",
                &format!("runner-manager.operation={late_operation}"),
                &late_network,
            ],
        );
        let late: serde_json::Value =
            serde_json::from_str(&ok(&root, &["host", "docker-cleanup", "sweep"])).unwrap();
        assert_eq!(late["removed"], 1);
        assert!(!fixture.exists("network", &late_network));
        for volume in &temporary_volumes {
            assert!(fixture.exists("volume", volume));
        }
        assert!(fixture.exists("container", &parallel_container));
        assert!(!parallel_directory.join("stop").exists());
        assert!(fixture.exists("container", &unrelated));
        assert!(fixture.exists("container", &kept));
        assert!(fixture.exists("volume", &named_cache));
        assert!(fixture.exists("image", &image));
        assert!(fixture.exists("image", &image_tag));
        let cached_build = fixture
            .command(false)
            .args([
                "buildx",
                "build",
                "--builder",
                "default",
                "--load",
                "--progress=plain",
                "-t",
                &image_tag,
            ])
            .arg(&build_context)
            .output()
            .unwrap();
        assert!(
            cached_build.status.success(),
            "{}",
            String::from_utf8_lossy(&cached_build.stderr)
        );
        assert!(
            String::from_utf8_lossy(&cached_build.stderr).contains("CACHED"),
            "the build cache was not reused: {}",
            String::from_utf8_lossy(&cached_build.stderr)
        );
        assert_eq!(std::fs::read(cache_file).unwrap(), b"cache-sentinel");
        assert_eq!(std::fs::read(retained_work).unwrap(), b"cache-sentinel");
        let cache_reader = format!("rm-cleanup-live-cache-reader-{nonce}");
        fixture.containers.push(cache_reader.clone());
        assert_eq!(
            fixture.docker(
                false,
                &[
                    "run",
                    "--rm",
                    "--name",
                    &cache_reader,
                    "-v",
                    &cache_mount,
                    &image,
                    "cat",
                    "/cache/sentinel"
                ]
            ),
            "docker-cache-sentinel"
        );
        let mut parallel_cleaned = parallel_attempt;
        parallel_cleaned
            .conclude(
                runner_manager_domain::attempt::AttemptOutcome::CompletedJob,
                fixtures::created_at(),
            )
            .unwrap();
        parallel_cleaned.clean(fixtures::created_at()).unwrap();
        store.record_attempt(&parallel_cleaned).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while fixture.exists("container", &parallel_container)
            || temporary_volumes
                .iter()
                .any(|volume| fixture.exists("volume", volume))
        {
            assert!(
                Instant::now() < deadline,
                "parallel cleanup or borrowed-volume retry did not finish"
            );
            ok(&root, &["host", "docker-cleanup", "sweep"]);
            std::thread::sleep(Duration::from_millis(50));
        }
        ok(&root, &["host", "docker-cleanup", "sweep"]);
        // A daemon may exit before its next maintenance tick. Its companion
        // must stop itself when the exact runner identity exits, not linger.
        struct OwnedRunner(std::process::Child);
        impl Drop for OwnedRunner {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut runner = OwnedRunner(Command::new("sleep").arg("600").spawn().unwrap());
        let runner_identity =
            runner_manager_platform::process::ProcessIdentity::resolve(runner.0.id()).unwrap();
        let second_id = AttemptId::new_random();
        let second = fixtures::attempt()
            .id(second_id)
            .policy_id(policy_id)
            .state(AttemptState::Busy)
            .github_runner_id(74)
            .process_id(runner.0.id())
            .runtime_path(root.join("runtime/second").to_str().unwrap())
            .build();
        store.record_attempt(&second).unwrap();
        cleanup
            .launch_environment(second_id, "fixture/repository", &RunnerEnv::default())
            .unwrap()
            .unwrap();
        let second_directory = cleanup.root.join(second_id.to_string());
        fixture
            .extra_proxy_directories
            .push(second_directory.clone());
        let second_journal = Journal::load(&second_directory.join("journal.json")).unwrap();
        let companion = second_journal.proxy.unwrap();
        eprintln!(
            "LIVE auto-exit companion PID={} runner PID={}",
            companion.pid(),
            runner.0.id()
        );
        runner_manager_agent::docker_cleanup::write_json(
            &second_directory.join("runner.json"),
            &runner_identity,
        )
        .unwrap();
        runner.0.kill().unwrap();
        runner.0.wait().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while matches!(
            companion.recheck().unwrap(),
            runner_manager_platform::process::Adoption::Live
        ) {
            assert!(Instant::now() < deadline, "companion outlived its runner");
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut second_cleaned = second;
        second_cleaned
            .conclude(
                runner_manager_domain::attempt::AttemptOutcome::CompletedJob,
                fixtures::created_at(),
            )
            .unwrap();
        second_cleaned.clean(fixtures::created_at()).unwrap();
        store.record_attempt(&second_cleaned).unwrap();
        ok(&root, &["host", "docker-cleanup", "sweep"]);
        assert!(!second_directory.exists());
        eprintln!(
            "LIVE PASS report/apply/recovery/attach/cache/persistent/unrelated; companion stopped"
        );
    }
}
