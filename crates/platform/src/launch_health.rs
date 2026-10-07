//! Whether this host's daemon can start runners at all.
//!
//! A managed WSL distribution once started no runner for 13 days while every
//! surface called it healthy. A guest launch claim had outlived its owner, so
//! every allocation was refused; the refusal was logged once a minute at WARN
//! and nothing else noticed. The daemon is the only process that sees those
//! refusals, and it shares no memory with `status`, `service status` or
//! `host doctor`, so it says so on disk: [`record_launches_blocked`] writes
//! [`LAUNCHES_BLOCKED_FILE`] once refusals have persisted, and the next granted
//! allocation removes it.
//!
//! The record alone has a blind spot: a daemon with no queued demand asks for
//! no allocation, so it never sees the refusal. [`stuck_launch_fence`] covers
//! that by reading the fence itself, from either side of the WSL boundary.

use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::paths::AppPaths;
use crate::service::{ServiceError, read_state_record, remove_state_record, write_state_record};
use crate::wsl::fence::{
    FENCE_DIRECTORY, FenceClaim, FenceOwner, FenceOwnerKind, GuestRecoveryConfig,
    OWNERLESS_CLAIM_GRACE, elapsed_at_least, fence_modified,
};

/// Present while the daemon's allocations keep being refused, inside
/// `state/`.
const LAUNCHES_BLOCKED_FILE: &str = "launches-blocked.toml";

const SCHEMA_VERSION: u32 = 1;

/// Consecutive refused allocations, with no launch of this daemon's own in
/// progress, before launches count as blocked.
pub const BLOCKED_AFTER_DEFERRALS: u32 = 5;

/// The least time those refusals must span. Brief contention is normal; five
/// minutes of nothing but refusals is not.
pub const BLOCKED_AFTER: Duration = Duration::from_secs(5 * 60);

/// How long a launch fence may be held before it counts as stuck. A launch
/// holds it through a package download, the registration and the spawn, which
/// take minutes at worst.
const FENCE_HELD_TOO_LONG: Duration = Duration::from_secs(30 * 60);

/// How to restart the service from inside a managed WSL distribution.
pub const GUEST_RESTART: &str =
    "`sudo systemctl restart runner-manager.service` inside the distribution";

/// How to restart a managed distribution's service from Windows.
#[must_use]
pub fn windows_restart(distribution: &str) -> String {
    format!("`wsl.exe -d {distribution} -u root systemctl restart runner-manager.service`")
}

/// Why this host starts no runner, and what ends it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchesBlocked {
    pub since: DateTime<Utc>,
    pub reason: String,
    pub remedy: String,
}

/// "since <when>: <reason>", the sentence every surface prints.
impl std::fmt::Display for LaunchesBlocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "since {}: {}", self.since.to_rfc3339(), self.reason)
    }
}

/// What refused an allocation, as the daemon saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockCause {
    /// The WSL launch fence exists and was not reclaimed.
    FenceHeld {
        directory: PathBuf,
        owner: Option<FenceOwner>,
    },
    /// Windows asked the distribution to drain for WSL recovery.
    DrainRequested { root: PathBuf },
    /// The fence or its configuration could not be used at all.
    FenceUnusable { detail: String },
    /// Another process kept the host-wide allocation lock.
    AllocationLockBusy { path: PathBuf },
}

impl BlockCause {
    /// The operator-facing reason and remedy, refused since `since`.
    #[must_use]
    pub fn blocked_since(&self, since: DateTime<Utc>, restart: &str) -> LaunchesBlocked {
        let (reason, remedy) = match self {
            Self::FenceHeld { directory, owner } => fence_held(directory, owner.as_ref(), restart),
            Self::DrainRequested { root } => (
                format!(
                    "Windows has asked this distribution to drain for WSL recovery ({})",
                    root.join(crate::wsl::fence::REQUEST_FILE).display()
                ),
                "run `runner-manager wsl status --distribution <name>` on Windows; launches resume \
                 when the recovery ends, and a request no watchdog maintains is retired after 5 \
                 minutes"
                    .to_string(),
            ),
            Self::FenceUnusable { detail } => (
                format!("the WSL launch fence cannot be used: {detail}"),
                "repair the managed host from Windows with `runner-manager wsl install \
                 --distribution <name>`"
                    .to_string(),
            ),
            Self::AllocationLockBusy { path } => (
                format!(
                    "another process keeps the runtime allocation lock ({})",
                    path.display()
                ),
                "stop the other runner-manager agent using this state directory".to_string(),
            ),
        };
        LaunchesBlocked {
            since,
            reason,
            remedy,
        }
    }
}

fn fence_held(directory: &Path, owner: Option<&FenceOwner>, restart: &str) -> (String, String) {
    let directory = directory.display();
    match owner {
        Some(owner) if owner.kind == FenceOwnerKind::WindowsRecovery => (
            format!(
                "Windows WSL recovery has held the launch fence ({directory}) since {}",
                owner.acquired_at.to_rfc3339()
            ),
            "run `runner-manager wsl status --distribution <name>` on Windows; a recovery no \
             watchdog maintains is retired 5 minutes after it stops"
                .to_string(),
        ),
        Some(owner) => (
            format!(
                "a runner launch by process {} has held the WSL launch fence ({directory}) since {}",
                owner.process_id,
                owner.acquired_at.to_rfc3339()
            ),
            format!(
                "if no runner is being registered, restart the service with {restart}; the \
                 restarted daemon reclaims a fence whose owner is gone"
            ),
        ),
        None => (
            format!("the WSL launch fence ({directory}) has no readable owner"),
            format!(
                "restart the service with {restart}; if the fence survives the restart, delete \
                 {directory} once no runner-manager launch is in progress"
            ),
        ),
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct LaunchesBlockedRecord {
    schema_version: u32,
    #[serde(flatten)]
    blocked: LaunchesBlocked,
}

/// Records that the daemon's allocations keep being refused.
///
/// # Errors
/// [`ServiceError::Record`] when `state/` cannot be written.
pub fn record_launches_blocked(
    paths: &AppPaths,
    blocked: &LaunchesBlocked,
) -> Result<(), ServiceError> {
    write_state_record(
        &launches_blocked_path(paths),
        &LaunchesBlockedRecord {
            schema_version: SCHEMA_VERSION,
            blocked: blocked.clone(),
        },
    )
}

/// Clears the record once an allocation is granted, or when a daemon starts.
///
/// # Errors
/// [`ServiceError::Record`] when the record exists and cannot be removed.
pub fn clear_launches_blocked(paths: &AppPaths) -> Result<(), ServiceError> {
    remove_state_record(&launches_blocked_path(paths))
}

/// The daemon's own record of blocked launches, if it wrote one.
///
/// # Errors
/// [`ServiceError::Record`] when the file exists and cannot be read or parsed.
pub fn recorded_launches_blocked(
    paths: &AppPaths,
) -> Result<Option<LaunchesBlocked>, ServiceError> {
    Ok(
        read_state_record::<LaunchesBlockedRecord>(&launches_blocked_path(paths))?
            .map(|record| record.blocked),
    )
}

/// Where the record lives.
#[must_use]
fn launches_blocked_path(paths: &AppPaths) -> PathBuf {
    paths.state_dir().join(LAUNCHES_BLOCKED_FILE)
}

/// A launch fence under `root` that has been held for longer than any launch
/// takes, from either side of the WSL boundary.
#[must_use]
pub fn stuck_launch_fence(
    root: &Path,
    now: DateTime<Utc>,
    restart: &str,
) -> Option<LaunchesBlocked> {
    let directory = root.join(FENCE_DIRECTORY);
    match FenceClaim::owner(root) {
        Ok(Some(owner)) => {
            let since = owner.acquired_at;
            elapsed_at_least(since, now, FENCE_HELD_TOO_LONG).then(|| {
                BlockCause::FenceHeld {
                    directory,
                    owner: Some(owner),
                }
                .blocked_since(since, restart)
            })
        }
        // A claimer writes its owner straight after creating the directory, so
        // one still missing after the reclaim grace is not a launch in progress.
        Ok(None) => {
            let since = fence_modified(root).ok()??;
            elapsed_at_least(since, now, OWNERLESS_CLAIM_GRACE).then(|| {
                BlockCause::FenceHeld {
                    directory,
                    owner: None,
                }
                .blocked_since(since, restart)
            })
        }
        Err(error) => Some(
            BlockCause::FenceUnusable {
                detail: error.to_string(),
            }
            .blocked_since(fence_modified(root).ok().flatten().unwrap_or(now), restart),
        ),
    }
}

/// Whether this host's own daemon starts no runner: its record first, then,
/// inside a managed WSL distribution, the fence itself.
#[must_use]
pub fn launches_blocked(paths: &AppPaths, now: DateTime<Utc>) -> Option<LaunchesBlocked> {
    if let Ok(Some(blocked)) = recorded_launches_blocked(paths) {
        return Some(blocked);
    }
    let config = GuestRecoveryConfig::read(paths).ok().flatten()?;
    stuck_launch_fence(&config.shared_root, now, GUEST_RESTART)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wsl::fence::FenceOwnerKind;

    fn paths(root: &Path) -> AppPaths {
        AppPaths::rooted_at(root)
    }

    #[test]
    fn the_record_round_trips_and_clears() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        assert_eq!(recorded_launches_blocked(&paths).unwrap(), None);
        let blocked = BlockCause::AllocationLockBusy {
            path: PathBuf::from("allocation.lock"),
        }
        .blocked_since(Utc::now(), GUEST_RESTART);
        record_launches_blocked(&paths, &blocked).unwrap();
        assert_eq!(
            recorded_launches_blocked(&paths).unwrap(),
            Some(blocked.clone())
        );
        assert_eq!(launches_blocked(&paths, Utc::now()), Some(blocked));
        clear_launches_blocked(&paths).unwrap();
        assert_eq!(launches_blocked(&paths, Utc::now()), None);
    }

    #[test]
    fn a_fence_is_stuck_only_once_it_outlives_any_launch() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            stuck_launch_fence(dir.path(), Utc::now(), GUEST_RESTART),
            None
        );
        let claim = FenceClaim::try_claim(dir.path(), FenceOwnerKind::GuestLaunch, None)
            .unwrap()
            .unwrap();
        assert_eq!(
            stuck_launch_fence(dir.path(), Utc::now(), GUEST_RESTART),
            None
        );
        let later = Utc::now() + chrono::Duration::minutes(31);
        let stuck = stuck_launch_fence(dir.path(), later, GUEST_RESTART).expect("stuck");
        assert!(
            stuck.reason.contains("runner launch by process"),
            "{stuck:?}"
        );
        assert!(stuck.remedy.contains("systemctl restart"), "{stuck:?}");
        drop(claim);
        assert_eq!(stuck_launch_fence(dir.path(), later, GUEST_RESTART), None);
    }

    #[test]
    fn an_unreadable_owner_is_reported_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let fence = dir.path().join(FENCE_DIRECTORY);
        std::fs::create_dir_all(&fence).unwrap();
        std::fs::write(fence.join(crate::wsl::fence::OWNER_FILE), b"{not json").unwrap();
        let stuck = stuck_launch_fence(dir.path(), Utc::now(), GUEST_RESTART).expect("stuck");
        assert!(stuck.reason.contains("cannot be used"), "{stuck:?}");
    }

    #[test]
    fn a_guest_reports_its_own_stuck_fence_without_a_record() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(&dir.path().join("app"));
        let shared = dir.path().join("shared");
        GuestRecoveryConfig::new(shared.clone())
            .write(&paths)
            .unwrap();
        let claim = FenceClaim::try_claim(&shared, FenceOwnerKind::GuestLaunch, None)
            .unwrap()
            .unwrap();
        claim.make_durable();
        assert_eq!(launches_blocked(&paths, Utc::now()), None);
        let later = Utc::now() + chrono::Duration::hours(1);
        assert!(launches_blocked(&paths, later).is_some());
    }
}
