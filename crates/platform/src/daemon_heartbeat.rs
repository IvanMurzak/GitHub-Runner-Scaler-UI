//! Whether the daemon is making progress at all.
//!
//! A daemon blocked in a file system call answers nothing and logs nothing: on
//! a Mac after an update, one sat at 0% CPU for half an hour behind a pending
//! "would like to access files on a removable volume" question, while `service
//! status` said `verdict healthy` (launchd reported it running) and the
//! host-unfit record it could no longer re-stamp expired from `status`.
//!
//! So the daemon writes a heartbeat from its own async loop every
//! [`HEARTBEAT_INTERVAL`]. The loop runs on one thread, so any task that blocks
//! it stops the heartbeat too. A heartbeat older than [`STALLED_AFTER`] whose
//! process is still running is a stalled daemon. The record holds the
//! process's identity, so a daemon that crashed is told apart from one that is
//! stuck, and a graceful exit removes it.

use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::paths::AppPaths;
use crate::process::{Adoption, ProcessIdentity};
use crate::service::{ServiceError, read_state_record, remove_state_record, write_state_record};

/// The record, inside `state/`.
pub const HEARTBEAT_FILE: &str = "daemon-heartbeat.toml";

/// How often the daemon writes it.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

/// How old it may get before a running daemon counts as stalled: five missed
/// beats, so one slow pass does not trip it.
pub const STALLED_AFTER: Duration = Duration::from_secs(5 * HEARTBEAT_INTERVAL.as_secs());

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Heartbeat {
    schema_version: u32,
    process: ProcessIdentity,
    at: DateTime<Utc>,
}

/// What the heartbeat says about the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Liveness {
    /// No heartbeat: no daemon, one that exited cleanly, or one older than
    /// heartbeats.
    Unknown,
    /// Beating within [`STALLED_AFTER`].
    Beating { at: DateTime<Utc> },
    /// Its process still runs and has not beaten since `since`.
    Stalled { since: DateTime<Utc>, pid: u32 },
    /// Its process is gone.
    Exited,
}

impl Liveness {
    /// Why a stalled daemon reads unhealthy, with what to do. `None`
    /// otherwise.
    #[must_use]
    pub fn stall(&self, last_github_contact: Option<DateTime<Utc>>) -> Option<String> {
        let Self::Stalled { since, pid } = self else {
            return None;
        };
        let contact = last_github_contact.map_or_else(
            || "it has never reached GitHub".to_owned(),
            |at| format!("it last reached GitHub at {}", at.to_rfc3339()),
        );
        Some(format!(
            "the service (process {pid}) has made no progress since {}: its loop has not \
             beaten for over {} minutes, and {contact}. A daemon blocked in a file system call \
             looks like this, for example on a runner root behind a macOS question nobody has \
             answered (look for a dialog on the Mac's desktop). If nothing is waiting, restart \
             it: `runner-manager service stop` then `runner-manager service start`",
            since.to_rfc3339(),
            STALLED_AFTER.as_secs() / 60
        ))
    }
}

fn path(paths: &AppPaths) -> PathBuf {
    paths.state_dir().join(HEARTBEAT_FILE)
}

/// Records that this process's loop ran at `at`.
///
/// # Errors
/// The record could not be written, or this process's identity read.
pub fn beat(paths: &AppPaths, at: DateTime<Utc>) -> Result<(), ServiceError> {
    let process = ProcessIdentity::of_current_process().map_err(|error| ServiceError::Record {
        operation: "write",
        path: path(paths),
        detail: error.to_string(),
    })?;
    write_state_record(
        &path(paths),
        &Heartbeat {
            schema_version: 1,
            process,
            at,
        },
    )
}

/// Removes the record, on a graceful exit.
///
/// # Errors
/// The record exists and cannot be removed.
pub fn stop(paths: &AppPaths) -> Result<(), ServiceError> {
    remove_state_record(&path(paths))
}

/// What the record says at `now`.
#[must_use]
pub fn liveness(paths: &AppPaths, now: DateTime<Utc>) -> Liveness {
    let Ok(Some(heartbeat)) = read_state_record::<Heartbeat>(&path(paths)) else {
        return Liveness::Unknown;
    };
    // A process this account may not inspect (a boot-mode daemon seen by an
    // operator) is taken to be running: a stale heartbeat from it is the one
    // thing worth saying, and a crashed one leaves launchd or the SCM to say
    // it stopped.
    let running = !matches!(
        heartbeat.process.recheck(),
        Ok(Adoption::Gone | Adoption::PidRecycled { .. })
    );
    judge(heartbeat.at, heartbeat.process.pid(), running, now)
}

fn judge(at: DateTime<Utc>, pid: u32, running: bool, now: DateTime<Utc>) -> Liveness {
    if !running {
        Liveness::Exited
    } else if crate::wsl::fence::elapsed_at_least(at, now, STALLED_AFTER) {
        Liveness::Stalled { since: at, pid }
    } else {
        Liveness::Beating { at }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(minute: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_790_000_000 + minute * 60, 0).unwrap()
    }

    #[test]
    fn a_running_daemon_that_stopped_beating_is_stalled() {
        assert_eq!(
            judge(at(0), 7, true, at(4)),
            Liveness::Beating { at: at(0) }
        );
        assert_eq!(
            judge(at(0), 7, true, at(5)),
            Liveness::Stalled {
                since: at(0),
                pid: 7
            }
        );
        assert_eq!(judge(at(0), 7, false, at(30)), Liveness::Exited);
    }

    #[test]
    fn this_process_beats_and_a_graceful_exit_removes_the_record() {
        let root = tempfile::tempdir().unwrap();
        let paths = AppPaths::rooted_at(root.path());
        paths.create_all().unwrap();
        assert_eq!(liveness(&paths, Utc::now()), Liveness::Unknown);

        beat(&paths, Utc::now()).unwrap();
        assert!(matches!(
            liveness(&paths, Utc::now()),
            Liveness::Beating { .. }
        ));
        // The same running process, not heard from for long enough.
        let stalled = liveness(&paths, Utc::now() + chrono::Duration::minutes(6));
        assert!(matches!(stalled, Liveness::Stalled { pid, .. } if pid == std::process::id()));
        let said = stalled.stall(None).expect("a stall is a problem");
        assert!(said.contains("made no progress since"), "{said}");
        assert!(said.contains("never reached GitHub"), "{said}");

        stop(&paths).unwrap();
        assert_eq!(liveness(&paths, Utc::now()), Liveness::Unknown);
    }
}
