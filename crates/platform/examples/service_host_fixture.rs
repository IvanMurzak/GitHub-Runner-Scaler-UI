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

/// The heartbeat file this instance was registered with.
///
/// It arrives as a launch argument rather than through the environment because
/// a service does not inherit the installing process's environment: Windows
/// hands a service the machine environment, and systemd and launchd hand a job
/// only what their definition names. An argument is the one channel all three
/// carry unchanged.
fn heartbeat_path() -> Option<PathBuf> {
    std::env::args_os().nth(1).map(PathBuf::from)
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
