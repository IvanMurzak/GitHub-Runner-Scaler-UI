// owner: d3-service-installers

//! A minimal service host, used by nothing but this crate's privileged
//! installer tests.
//!
//! # Why this exists at all
//!
//! One Definition-of-Done item cannot be satisfied by inspecting configuration:
//! *"A killed service restarts under the failure policy within the bounded
//! delay, and does not restart-loop faster than that bound."* Reading the
//! restart delay back out of the service manager proves the number was stored;
//! it does not prove the manager acts on it. The only way to measure the
//! interval is to have something the manager can actually start, kill, and
//! start again — and to have that something write down when it started.
//!
//! `runner-manager daemon run` is `f3`'s and does not exist yet, so this is the
//! stand-in. It does exactly two things: it reports itself started to whichever
//! service manager launched it, and it appends one line to the file named by its
//! first argument every time it starts. The test reads the timestamps.
//!
//! # And one more, for `b2`
//!
//! *"A boot service running as LocalSystem can create, materialize, and clean a
//! child below the default root"* has the same shape as the restart
//! requirement: no amount of reading a security descriptor proves it, because
//! the question is what a **different account** can do — and the account is
//! LocalSystem, which a test process cannot become. So when a second path
//! argument is given, this creates a child below it, writes a file inside, and
//! removes the child again, exactly as an attempt directory's life cycle does.
//! The outcome goes beside the heartbeat and the test reads it.
//!
//! # Why an example rather than a second binary
//!
//! `a1` owns every manifest in this workspace, and adding a `[[bin]]` would mean
//! editing one. Cargo discovers `examples/` with no manifest entry at all, and
//! builds them during `cargo test`, which is precisely the property needed here.
//!
//! # It is not the daemon and must never become it
//!
//! There is no reconciliation, no GitHub, no lock, no secret, and no state. If a
//! future change makes this look like a daemon, the change belongs in `f3`.

use std::io::Write as _;
use std::path::PathBuf;

/// Appends `<rfc3339 with milliseconds>\t<pid>` to the heartbeat file.
///
/// Appending rather than replacing is the whole mechanism: the interval the
/// test measures is the gap between two lines, so both starts have to survive.
fn record_start(path: &std::path::Path) {
    let line = format!(
        "{}\t{}\n",
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        std::process::id()
    );
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = file.write_all(line.as_bytes());
        let _ = file.flush();
    }
}

/// The path arguments this instance was registered with, in order.
///
/// They arrive as launch arguments rather than through the environment because
/// a service does not inherit the installing process's environment: Windows
/// hands a service the machine environment, and systemd and launchd hand a job
/// only what their definition names. An argument is the one channel all three
/// carry unchanged.
///
/// Flags are skipped rather than counted past. A boot registration also carries
/// `--windows-service-host`, and where the installer chooses to put it is not
/// something this fixture should have an opinion about.
fn path_arguments() -> Vec<PathBuf> {
    std::env::args_os()
        .skip(1)
        .filter(|argument| !argument.to_string_lossy().starts_with("--"))
        .map(PathBuf::from)
        .collect()
}

/// The heartbeat file this instance was registered with.
fn heartbeat_path() -> Option<PathBuf> {
    path_arguments().into_iter().next()
}

/// The runner root this instance was asked to exercise, when it was asked to.
fn runner_root() -> Option<PathBuf> {
    path_arguments().into_iter().nth(1)
}

/// Where the outcome of that exercise is written.
///
/// Beside the heartbeat rather than inside it: the test parses the heartbeat as
/// `<timestamp>\t<pid>` lines, and a third kind of line there would break the
/// restart measurement that file exists for.
fn workspace_outcome_path(heartbeat: &std::path::Path) -> PathBuf {
    let mut name = heartbeat.as_os_str().to_owned();
    name.push(".workspace");
    PathBuf::from(name)
}

/// The whole life cycle of an attempt directory, in three calls.
///
/// Create a child of the runner root, materialize something inside it, and
/// clean it up again. Each one needs a different right, which is why all three
/// are here rather than just the first: creating the child needs
/// `FILE_ADD_SUBDIRECTORY` on the root, writing inside it needs the root's ace
/// to have been *inherited* by the child, and removing it needs `DELETE` on
/// everything the recursion reaches.
fn exercise_workspace(root: &std::path::Path) -> std::io::Result<()> {
    let child = root.join(format!("selftest-{}", std::process::id()));
    std::fs::create_dir(&child)?;
    std::fs::write(child.join("marker"), b"a job would put its checkout here")?;
    std::fs::remove_dir_all(&child)
}

/// Records what [`exercise_workspace`] did, including why it could not.
///
/// The failure is written down rather than allowed to end the process: a
/// service that exits before reporting itself started tells the test only that
/// something went wrong, and the interesting part of an access-control failure
/// is which of the three calls refused.
fn record_workspace(heartbeat: &std::path::Path, root: &std::path::Path) {
    let outcome = match exercise_workspace(root) {
        Ok(()) => "ok".to_owned(),
        Err(error) => format!("error: {error}"),
    };
    let _ = std::fs::write(workspace_outcome_path(heartbeat), outcome);
}

#[cfg(windows)]
mod host {
    use std::ffi::OsString;
    use std::sync::mpsc;
    use std::time::Duration;

    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    windows_service::define_windows_service!(ffi_service_main, service_main);

    /// Runs under the Service Control Manager, or reports that there is none.
    ///
    /// `service_dispatcher::start` fails immediately with
    /// `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` when the process was not
    /// launched by the manager, which is how a run from a terminal is told
    /// apart from a run as a service without a flag either side could get
    /// wrong.
    pub fn run() {
        if let Err(error) = windows_service::service_dispatcher::start("", ffi_service_main) {
            eprintln!("this fixture only runs under the Windows Service Control Manager: {error}");
            std::process::exit(2);
        }
    }

    fn service_main(_arguments: Vec<OsString>) {
        let Some(path) = super::heartbeat_path() else {
            return;
        };
        let (stop_tx, stop_rx) = mpsc::channel();
        let handler = move |control| match control {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let Ok(status_handle) = service_control_handler::register("", handler) else {
            return;
        };
        let running = ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        };
        if status_handle.set_service_status(running.clone()).is_err() {
            return;
        }
        // After RUNNING, not before: a line written before the manager is told
        // the service started would be a line the test could see for a start
        // the manager does not consider to have happened.
        super::record_start(&path);
        if let Some(root) = super::runner_root() {
            super::record_workspace(&path, &root);
        }

        let _ = stop_rx.recv();
        let _ = status_handle.set_service_status(ServiceStatus {
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            ..running
        });
    }
}

#[cfg(unix)]
mod host {
    /// launchd and systemd both start an ordinary process and both stop it with
    /// `SIGTERM`, so there is no dispatcher to connect to and nothing to report.
    pub fn run() {
        let Some(path) = super::heartbeat_path() else {
            std::process::exit(2);
        };
        super::record_start(&path);
        if let Some(root) = super::runner_root() {
            super::record_workspace(&path, &root);
        }
        // Park until the service manager signals. The default `SIGTERM`
        // disposition ends the process, which is exactly the clean stop both
        // managers expect, so no handler is installed.
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }
}

fn main() {
    host::run();
}
