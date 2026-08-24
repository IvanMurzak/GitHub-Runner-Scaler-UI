// owner: d3-service-installers

//! Installer smoke tests against **the real service manager on this machine**.
//!
//! Everything in this file registers a genuine Windows service, starts it,
//! kills it, and removes it. Nothing else in this workspace does anything of the
//! kind, and three rules make that safe enough to be worth doing:
//!
//! 1. **Every registration is named by [`ServiceIdentity::fixture`]**, which
//!    produces `runner-manager-selftest-<unique>` — a name no operator
//!    installation can have and no other test run can collide with.
//! 2. **[`Fixture`] removes the registration in `Drop`**, so a panic, an
//!    assertion failure, or an early `?` cleans up exactly as a passing test
//!    does. `Drop` also goes at the manager directly afterwards, in case the
//!    library call that should have removed it was the thing that broke.
//! 3. **Nothing here ever names a registration it did not create.** Every
//!    destructive step checks `is_fixture()` first, and installation refuses
//!    rather than overwrites if the name is somehow already taken.
//!
//! # Why they are `#[ignore]`d
//!
//! An ordinary `cargo test --workspace` on a developer's laptop must not
//! register services. These run only when asked for by name, which is what
//! `.github/workflows/ci.yml`'s `service-install` job does.
//!
//! # Why this file is Windows only
//!
//! `d3`'s own scope note: *"All three installers are written here, in Wave 2,
//! because gate 3 requires verified boot-start recovery on Windows. macOS and
//! Linux installation and reboot recovery are validated in Wave 3 against this
//! same implementation."* The launchd and systemd backends are written, are
//! type-checked on every leg, and have their definitions asserted line by line
//! by the unit tests in `service.rs` — but nothing in this repository has yet
//! run `launchctl bootstrap` or `systemctl enable` for real, and a test that
//! claims to have done so would be worth less than this paragraph. Wave 3 adds
//! the two files; they drive the same [`ServiceOperations`] API this one does.
//!
//! # What these tests do **not** prove
//!
//! **Not the reboot.** *"After a real reboot with no interactive login, the
//! agent is running"* is not reachable from a test process, and nothing here
//! stands in for it. What is proved is that the registration a boot-time start
//! would use exists, names an absolute path that is there, runs under the
//! account the machine-scoped store's DACL admits, and carries a restart policy
//! the manager honours by measurement. The reboot itself is human gate 3.

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use runner_manager_domain::model::StartMode;
use runner_manager_platform::lock::{HostLock, LockKind};
use runner_manager_platform::paths::AppPaths;
use runner_manager_platform::service::{
    BinaryPath, HostControls, InstallRecord, InstallRequest, Installed, RestartPolicy,
    ServiceError, ServiceIdentity, ServiceOperations,
};
use windows_service::service::{ServiceAccess, ServiceExitCode};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

/// The prefix every registration this file creates carries, spelled out once so
/// that [`sweep`] can refuse anything else.
const FIXTURE_PREFIX: &str = "runner-manager-selftest-";

// ---------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------

/// One disposable registration, and everything it was installed against.
struct Fixture {
    identity: ServiceIdentity,
    operations: ServiceOperations,
    paths: AppPaths,
    binary: PathBuf,
    heartbeat: PathBuf,
    _root: tempfile::TempDir,
}

impl Fixture {
    /// Prepares a disposable host, and **refuses if the name is already taken**.
    fn new(tag: &str) -> Self {
        let identity = ServiceIdentity::fixture(&format!(
            "{tag}-{}-{}",
            std::process::id(),
            Utc::now().timestamp_subsec_nanos()
        ));
        assert!(
            identity.is_fixture() && identity.name().starts_with(FIXTURE_PREFIX),
            "a test must never be able to name a real registration, got {}",
            identity.name()
        );

        let root = tempfile::tempdir().expect("a temporary directory");
        let paths = AppPaths::rooted_at(root.path());
        paths.create_all().expect("the four directories");

        // A copy of the fixture service host, so that the recorded absolute
        // path is one this test owns and may delete.
        let binary = root.path().join("runner-manager-selftest.exe");
        std::fs::copy(fixture_service_host(), &binary).expect("a copy of the fixture host");

        let operations = ServiceOperations::with_controls(
            paths.clone(),
            identity.clone(),
            std::sync::Arc::new(HostControls),
        );

        // Enumerate before creating. A name this test generated cannot already
        // exist, so if one does something is very wrong and overwriting it
        // would be the worst available response.
        let existing = operations
            .status()
            .expect("the service manager can be asked");
        assert!(
            !existing.is_installed(),
            "{} already exists on this machine; refusing to touch it",
            identity.name()
        );

        Self {
            heartbeat: root.path().join("starts.tsv"),
            identity,
            operations,
            paths,
            binary,
            _root: root,
        }
    }

    /// Registers the fixture host, always on demand so that a registration
    /// which somehow escaped [`Drop`] cannot start with this machine.
    fn install(&self, mode: StartMode, restart: RestartPolicy) -> Installed {
        self.operations
            .install(&self.request(mode, restart))
            .expect("the fixture registers")
    }

    fn request(&self, mode: StartMode, restart: RestartPolicy) -> InstallRequest {
        InstallRequest::new(mode)
            .for_binary(&self.binary)
            .with_arguments([self.heartbeat.as_os_str()])
            .with_restart(restart)
            .started_on_demand()
    }

    /// Every line the fixture host has written, as `(started_at, pid)`.
    fn starts(&self) -> Vec<(DateTime<Utc>, u32)> {
        let Ok(text) = std::fs::read_to_string(&self.heartbeat) else {
            return Vec::new();
        };
        text.lines()
            .filter_map(|line| {
                let (at, pid) = line.split_once('\t')?;
                Some((
                    DateTime::parse_from_rfc3339(at).ok()?.with_timezone(&Utc),
                    pid.trim().parse().ok()?,
                ))
            })
            .collect()
    }

    /// Waits for the fixture host to have started `count` times.
    fn wait_for_starts(&self, count: usize, timeout: Duration) -> Vec<(DateTime<Utc>, u32)> {
        let deadline = Instant::now() + timeout;
        loop {
            let starts = self.starts();
            if starts.len() >= count {
                return starts;
            }
            assert!(
                Instant::now() < deadline,
                "the fixture host started {} time(s) in {timeout:?}, expected {count}",
                starts.len()
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Never panic in `Drop`: during an unwind a second panic aborts the
        // process, and an aborted test process runs no cleanup at all — which
        // is precisely the leak this implementation exists to prevent.
        if !self.identity.is_fixture() {
            return;
        }
        let _ = self.operations.stop();
        let _ = self.operations.uninstall();
        // Belt and braces. If the failure under test was *in* `uninstall`, the
        // call above did nothing; go at the manager directly.
        sweep(self.identity.name());
    }
}

/// Removes a registration by name, through the manager's own command-line
/// tools, and **only** if the name is one this file creates.
fn sweep(name: &str) {
    assert!(
        name.starts_with(FIXTURE_PREFIX),
        "sweep refuses to touch {name}: it is not a self-test fixture"
    );
    let _ = std::process::Command::new("sc.exe")
        .args(["delete", name])
        .output();
    let _ = std::process::Command::new("schtasks.exe")
        .args(["/Delete", "/TN", name, "/F"])
        .output();
}

/// The fixture service host, beside this test binary's own directory.
///
/// **It has to be built separately, and that is easy to get wrong.** A plain
/// `cargo test` builds every example, so running the whole suite produces it as
/// a side effect — but `cargo test --test privileged_service_installer`, which
/// is how these tests are actually selected, builds exactly one target and no
/// examples. `--examples` does not close the gap either: it builds the example
/// as a libtest harness under a hashed name, and that binary runs libtest and
/// exits rather than reporting itself to the Service Control Manager.
///
/// A missing one is a hard failure rather than a skip. A smoke test that
/// quietly did nothing would be the exact failure mode this whole run keeps
/// finding — and this assertion has already earned its place once, by turning
/// a CI job that would otherwise have passed while verifying nothing into a
/// red one that named the cause.
fn fixture_service_host() -> PathBuf {
    let test_binary = std::env::current_exe().expect("this test binary has a path");
    let candidate = test_binary
        .parent()
        .and_then(Path::parent)
        .expect("target/debug/deps has two ancestors")
        .join("examples")
        .join("service_host_fixture.exe");
    assert!(
        candidate.is_file(),
        "{} is missing, so there is nothing for the service manager to start. Build it first:\n\
         \n    cargo build -p runner-manager-platform --example service_host_fixture\n\n\
         `cargo test --test privileged_service_installer` does NOT build it; only a whole-crate \
         `cargo test` or the explicit command above does.",
        candidate.display()
    );
    candidate
}

/// The shipping binary whose hidden service entrypoint the installer records.
///
/// This is deliberately not the platform example: that fixture proves SCM and
/// restart-policy mechanics, while this binary proves the production command
/// actually calls `StartServiceCtrlDispatcher` and handles stop controls.
fn runner_manager_binary() -> PathBuf {
    let test_binary = std::env::current_exe().expect("this test binary has a path");
    let candidate = test_binary
        .parent()
        .and_then(Path::parent)
        .expect("target/debug/deps has two ancestors")
        .join("runner-manager.exe");
    assert!(
        candidate.is_file(),
        "{} is missing. Build the production service host first:\n\
         \n    cargo build -p runner-manager\n",
        candidate.display()
    );
    candidate
}

fn production_daemon_arguments(paths: &AppPaths) -> Vec<std::ffi::OsString> {
    [
        std::ffi::OsString::from("daemon"),
        std::ffi::OsString::from("run"),
        std::ffi::OsString::from("--service-config-dir"),
        paths.config_dir().as_os_str().to_owned(),
        std::ffi::OsString::from("--service-state-dir"),
        paths.state_dir().as_os_str().to_owned(),
        std::ffi::OsString::from("--service-runtime-dir"),
        paths.runtime_dir().as_os_str().to_owned(),
        std::ffi::OsString::from("--service-logs-dir"),
        paths.logs_dir().as_os_str().to_owned(),
    ]
    .into_iter()
    .collect()
}

fn wait_for_running(fixture: &Fixture, running: bool, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let observed = fixture
            .operations
            .status()
            .expect("SCM can report status")
            .registration()
            .is_some_and(|registration| registration.running);
        if observed == running {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{} did not become {} within {timeout:?}",
            fixture.identity.name(),
            if running { "RUNNING" } else { "STOPPED" }
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn scm_exit_code(fixture: &Fixture) -> ServiceExitCode {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .expect("the local SCM opens");
    manager
        .open_service(fixture.identity.name(), ServiceAccess::QUERY_STATUS)
        .expect("the fixture remains registered until its exit is inspected")
        .query_status()
        .expect("SCM reports the final service status")
        .exit_code
}

/// Whether this process can create services at all.
///
/// Reported as a failure rather than a skip, with the remedy: these tests are
/// selected by name, so a run that reaches them was asked for them.
fn require_elevation(error: &ServiceError) -> ! {
    panic!(
        "these tests register a real service and need administrative rights: {error}\n\
         Run them from an elevated prompt:\n\
         cargo test -p runner-manager-platform --test privileged_service_installer -- \
         --ignored --test-threads=1"
    );
}

// ---------------------------------------------------------------------------
// Install, inspect, remove
// ---------------------------------------------------------------------------

#[test]
#[ignore = "registers a real Windows service; run explicitly"]
fn install_status_and_uninstall_round_trip_against_the_real_service_manager() {
    let fixture = Fixture::new("round-trip");
    let installed = match fixture
        .operations
        .install(&fixture.request(StartMode::Boot, RestartPolicy::default()))
    {
        Ok(installed) => installed,
        Err(error @ ServiceError::NeedsElevation { .. }) => require_elevation(&error),
        Err(error) => panic!("{error}"),
    };

    // The record holds the resolved absolute path, not the one that was asked
    // for — item 6.
    assert_eq!(installed.record.binary, fixture.binary);
    assert!(installed.record.binary.is_absolute());
    assert!(
        installed.review.is_least_privilege(),
        "{}",
        installed.review
    );

    let status = fixture.operations.status().expect("a status");
    assert!(status.is_installed());
    assert_eq!(status.start_mode(), Some(StartMode::Boot));
    assert_eq!(
        status.log_file(),
        fixture.paths.logs_dir().join("runner-manager.log")
    );
    assert!(
        matches!(status.binary(), Some(BinaryPath::Current { .. })),
        "{status}"
    );

    // What the Service Control Manager itself says, read back rather than
    // assumed.
    let registration = status.registration().expect("the manager knows it");
    assert_eq!(
        registration.binary().as_deref(),
        Some(fixture.binary.as_path()),
        "the manager's own command line must name the recorded binary: {}",
        registration.command_line
    );
    assert_eq!(
        registration.restart_delay,
        Some(RestartPolicy::default().delay()),
        "the manager must report back the bounded delay that was configured"
    );
    let account = registration.account.as_deref().unwrap_or_default();
    assert!(
        account.eq_ignore_ascii_case("LocalSystem")
            || account.eq_ignore_ascii_case("NT AUTHORITY\\SYSTEM"),
        "the account must be the one the machine-scoped store's DACL admits, got {account}"
    );

    // The fixture is deliberately on-demand, and `service status` says so
    // rather than calling a service that will not come back after a reboot
    // healthy. That this is the *only* problem is the assertion: it shows the
    // boot-start check firing against a real manager, and shows nothing else
    // firing spuriously.
    let problems: Vec<&str> = status
        .problems()
        .iter()
        .map(|problem| problem.subject)
        .collect();
    assert_eq!(problems, vec!["start mode"], "{status}");

    let uninstalled = fixture.operations.uninstall().expect("an uninstall");
    assert!(uninstalled.removed_registration);
    assert!(uninstalled.removed_record);

    let after = fixture.operations.status().expect("a status");
    assert!(!after.is_installed(), "{after}");
}

#[test]
#[ignore = "installs and starts the production runner-manager binary as a real Windows service"]
fn production_daemon_entrypoint_reaches_running_and_handles_scm_stop() {
    let fixture = Fixture::new("production-entrypoint");
    std::fs::copy(runner_manager_binary(), &fixture.binary)
        .expect("the fixture owns a copy of runner-manager.exe");
    let request = InstallRequest::new(StartMode::Boot)
        .for_binary(&fixture.binary)
        .with_arguments(production_daemon_arguments(&fixture.paths))
        .started_on_demand();
    match fixture.operations.install(&request) {
        Ok(_) => {}
        Err(error @ ServiceError::NeedsElevation { .. }) => require_elevation(&error),
        Err(error) => panic!("{error}"),
    }

    fixture
        .operations
        .start()
        .expect("SCM starts the production entrypoint");
    wait_for_running(&fixture, true, Duration::from_secs(30));

    // The old production path never connected to SCM: it was killed at the
    // 30-second dispatcher timeout. Staying RUNNING beyond that boundary
    // discriminates the real fix from a transient status observation.
    std::thread::sleep(Duration::from_secs(32));
    assert!(
        fixture
            .operations
            .status()
            .expect("SCM can report the stable service")
            .registration()
            .is_some_and(|registration| registration.running),
        "the production service did not remain RUNNING past SCM's dispatcher timeout"
    );

    assert!(
        fixture
            .operations
            .stop()
            .expect("SCM delivers SERVICE_CONTROL_STOP"),
        "the service was expected to be running"
    );
    wait_for_running(&fixture, false, Duration::from_secs(30));
    assert_eq!(
        scm_exit_code(&fixture),
        ServiceExitCode::Win32(0),
        "the production daemon must report a clean exit after graceful drain"
    );
    fixture
        .operations
        .uninstall()
        .expect("the fixture registration is removed");
    assert!(
        fixture
            .operations
            .status()
            .expect("SCM can prove cleanup")
            .registration()
            .is_none(),
        "the production-entrypoint fixture leaked a service registration"
    );
}

#[test]
#[ignore = "registers a real Windows service; run explicitly"]
fn uninstall_leaves_configuration_sqlite_secrets_and_cache_byte_for_byte() {
    let fixture = Fixture::new("preserve");
    fixture.install(StartMode::Boot, RestartPolicy::default());

    let config = fixture.paths.config_dir();
    std::fs::write(config.join("runner-manager.db"), b"sqlite fixture").expect("writable");
    std::fs::create_dir_all(fixture.paths.state_dir().join("packages/2.330.0")).expect("writable");
    std::fs::write(
        fixture
            .paths
            .state_dir()
            .join("packages/2.330.0/runner.tar.gz"),
        b"cached runner package",
    )
    .expect("writable");
    std::fs::create_dir_all(fixture.paths.state_dir().join("secrets")).expect("writable");
    std::fs::write(
        fixture.paths.state_dir().join("secrets/user-access-token"),
        b"a stand-in for the stored credential",
    )
    .expect("writable");
    std::fs::write(
        fixture
            .paths
            .logs_dir()
            .join("runner-manager.log.2026-08-22"),
        b"diagnostics",
    )
    .expect("writable");

    let roots: Vec<PathBuf> = fixture
        .paths
        .all()
        .iter()
        .map(|(_, path)| (*path).to_path_buf())
        .collect();
    let before = tree(&roots);
    assert!(
        before.len() >= 5,
        "the fixture must hold the files this test is about: {before:#?}"
    );
    let record = InstallRecord::path(&fixture.paths);
    assert!(before.iter().any(|(path, _)| path == &record));

    fixture.operations.uninstall().expect("an uninstall");

    let after = tree(&roots);
    let expected: Vec<_> = before
        .iter()
        .filter(|(path, _)| path != &record)
        .cloned()
        .collect();
    assert_eq!(
        after, expected,
        "uninstall deleted more than its own record"
    );
    assert!(!record.exists(), "or it deleted nothing at all");
}

/// Every file under the given roots, with its contents, sorted.
fn tree(roots: &[PathBuf]) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(directory: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if let Ok(bytes) = std::fs::read(&path) {
                out.push((path, bytes));
            }
        }
    }
    let mut out = Vec::new();
    for root in roots {
        walk(root, &mut out);
    }
    out.sort();
    out
}

#[test]
#[ignore = "registers a real Windows service; run explicitly"]
fn a_binary_that_moves_after_install_is_reported_as_stale() {
    let fixture = Fixture::new("stale");
    fixture.install(StartMode::Boot, RestartPolicy::default());

    // The discriminator: while the binary is there, nothing complains about it.
    let healthy = fixture.operations.status().expect("a status");
    assert!(
        !healthy
            .problems()
            .iter()
            .any(|problem| problem.subject == "binary"),
        "{healthy}"
    );

    // The npm upgrade, reproduced: the file the registration names goes away
    // while the registration itself survives untouched.
    std::fs::remove_file(&fixture.binary).expect("the binary moves out from under the record");

    let stale = fixture.operations.status().expect("a status");
    assert!(
        matches!(stale.binary(), Some(BinaryPath::Missing { .. })),
        "{stale}"
    );
    assert!(
        stale
            .problems()
            .iter()
            .any(|problem| problem.subject == "binary"),
        "{stale}"
    );
    assert!(!stale.is_healthy(), "{stale}");

    // And the manager still holds the registration, which is what makes this a
    // silent failure rather than an obvious one.
    assert!(stale.registration().is_some(), "{stale}");
}

#[test]
#[ignore = "registers a real Windows service; run explicitly"]
fn installing_while_the_single_instance_lock_is_held_registers_nothing() {
    let fixture = Fixture::new("lock");
    let held = HostLock::try_acquire(&fixture.paths, LockKind::SingleInstance)
        .expect("this process takes the lock first");

    let error = fixture
        .operations
        .install(&fixture.request(StartMode::Boot, RestartPolicy::default()))
        .expect_err("a second agent must not be registered while one is running");
    assert!(matches!(error, ServiceError::LockHeld { .. }), "{error}");
    assert!(
        error.to_string().contains("already running"),
        "the refusal must be actionable: {error}"
    );

    // The real Service Control Manager must hold nothing, not merely the
    // library's record.
    let status = fixture.operations.status().expect("a status");
    assert!(status.registration().is_none(), "{status}");
    assert!(!status.is_installed(), "{status}");

    // The discriminator: release the lock and the identical call succeeds.
    drop(held);
    fixture.install(StartMode::Boot, RestartPolicy::default());
    assert!(
        fixture
            .operations
            .status()
            .expect("a status")
            .registration()
            .is_some()
    );
}

#[test]
#[ignore = "registers a real Windows service and a real scheduled task; run explicitly"]
fn switching_start_mode_moves_the_registration_between_the_two_windows_facilities() {
    let fixture = Fixture::new("switch");
    fixture.install(StartMode::Boot, RestartPolicy::default());

    let boot = fixture.operations.status().expect("a status");
    assert_eq!(
        boot.registration().map(|found| found.manager.manager()),
        Some("the Windows Service Control Manager"),
        "{boot}"
    );

    let change = fixture
        .operations
        .set_start_mode(StartMode::Login)
        .expect("Windows has no service that starts at logon, so this moves facility");
    assert!(change.changed);

    let login = fixture.operations.status().expect("a status");
    assert_eq!(
        login.registration().map(|found| found.manager.manager()),
        Some("Windows Task Scheduler"),
        "{login}"
    );
    assert_eq!(login.start_mode(), Some(StartMode::Login));
    assert_eq!(
        login
            .registration()
            .and_then(|found| found.binary())
            .as_deref(),
        Some(fixture.binary.as_path()),
        "the switch must carry the recorded path across, not re-resolve one"
    );
}

// ---------------------------------------------------------------------------
// The restart policy, measured
// ---------------------------------------------------------------------------

/// The delay this test configures.
///
/// Long enough that a manager ignoring it entirely is unmistakable — an
/// immediate restart lands inside a second — and short enough that the test
/// takes well under a minute.
const MEASURED_DELAY: Duration = Duration::from_secs(10);

#[test]
#[ignore = "registers, starts, and kills a real Windows service; run explicitly"]
fn a_killed_service_comes_back_and_no_sooner_than_the_bounded_delay() {
    let fixture = Fixture::new("restart");
    let restart = RestartPolicy::new(MEASURED_DELAY, Duration::from_secs(600))
        .expect("ten seconds is inside the supported range");
    fixture.install(StartMode::Boot, restart);

    fixture.operations.start().expect("the fixture host starts");
    let first = fixture.wait_for_starts(1, Duration::from_secs(30));
    let (_, pid) = first[0];

    // Kill it the way a crash would, so the manager sees a process that ended
    // without reporting a stop.
    let killed = std::process::Command::new("taskkill.exe")
        .args(["/F", "/PID", &pid.to_string()])
        .output()
        .expect("taskkill runs");
    assert!(
        killed.status.success(),
        "could not kill the fixture host: {}",
        String::from_utf8_lossy(&killed.stderr)
    );
    let killed_at = Utc::now();

    // The manager restarts it, or this waits out its timeout and fails.
    let starts = fixture.wait_for_starts(2, Duration::from_secs(90));
    let restarted_at = starts[1].0;
    assert_ne!(starts[1].1, pid, "the second start must be a new process");

    let measured = (restarted_at - killed_at)
        .to_std()
        .expect("the restart is after the kill");

    // `killed_at` is taken *after* `taskkill` returns, so it is at or after the
    // moment the process actually died. The measured gap is therefore an
    // under-estimate of the interval the manager waited, which makes the lower
    // bound below conservative: if this holds, the true interval holds too.
    // The quarter-second is clock and scheduler granularity, and is two orders
    // of magnitude below the difference between honouring the delay and
    // ignoring it.
    assert!(
        measured + Duration::from_millis(250) >= MEASURED_DELAY,
        "the service came back after {measured:?}, sooner than the {MEASURED_DELAY:?} bound: \
         the manager is not honouring the restart delay"
    );
    assert!(
        measured <= MEASURED_DELAY + Duration::from_secs(30),
        "the service took {measured:?} to come back, well past the {MEASURED_DELAY:?} bound"
    );

    eprintln!("measured restart interval: {measured:?} against a {MEASURED_DELAY:?} bound");
}
