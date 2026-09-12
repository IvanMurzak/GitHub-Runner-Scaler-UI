#![cfg_attr(windows, windows_subsystem = "windows")]

//! Stable, no-console parent for a login-mode Windows daemon.
//!
//! Task Scheduler launches this image. The first argument is the versioned
//! console-subsystem daemon image and the remaining arguments belong to it.

use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::process::CommandExt as _;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const RESTART_DELAY: Duration = Duration::from_secs(2);
const MAX_RESTART_DELAY: Duration = Duration::from_secs(60);
const STABLE_CHILD_UPTIME: Duration = Duration::from_secs(5 * 60);
const UPGRADE_PENDING_EXIT_CODE: i32 = 21;
const SUPERVISED_ENVIRONMENT: &str = "RUNNER_MANAGER_SUPERVISED";

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() == 1 && matches!(arguments[0].to_str(), Some("--version" | "-V")) {
        println!("runner-manager-supervisor {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if arguments.is_empty() {
        return ExitCode::from(2);
    }
    let program = arguments.remove(0);

    let mut failures = 0_u32;
    loop {
        let started_at = Instant::now();
        let mut command = Command::new(&program);
        command
            .args(&arguments)
            .env(SUPERVISED_ENVIRONMENT, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);

        let status = match command.spawn().and_then(|mut child| child.wait()) {
            Ok(status) => status,
            Err(_) => {
                failures = failures.saturating_add(1);
                std::thread::sleep(restart_delay(failures));
                continue;
            }
        };
        if status.success() {
            return ExitCode::SUCCESS;
        }
        if status.code() == Some(UPGRADE_PENDING_EXIT_CODE) {
            failures = 0;
            continue;
        }
        failures = if started_at.elapsed() >= STABLE_CHILD_UPTIME {
            1
        } else {
            failures.saturating_add(1)
        };
        std::thread::sleep(restart_delay(failures));
    }
}

fn restart_delay(failures: u32) -> Duration {
    let exponent = failures.saturating_sub(1).min(5);
    RESTART_DELAY
        .saturating_mul(1_u32 << exponent)
        .min(MAX_RESTART_DELAY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crash_restart_backoff_is_bounded() {
        assert_eq!(restart_delay(1), Duration::from_secs(2));
        assert_eq!(restart_delay(2), Duration::from_secs(4));
        assert_eq!(restart_delay(6), Duration::from_secs(60));
        assert_eq!(restart_delay(u32::MAX), Duration::from_secs(60));
    }
}
