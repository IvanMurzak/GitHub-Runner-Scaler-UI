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

/// How long a daemon's record counts after its last refusal. Refusals happen
/// only while there is demand, so a record no longer being refreshed means
/// nothing is being refused; a fence that is still stuck is caught by
/// [`stuck_launch_fence`] instead.
const RECORD_FRESH: Duration = Duration::from_secs(15 * 60);

/// Which side of the WSL boundary a report is written for: the commands it
/// can name, and the clock a fence is aged by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Viewpoint<'a> {
    /// Inside the managed distribution, whose name the guest does not know.
    Guest,
    /// On Windows, for one named distribution.
    Windows { distribution: &'a str },
}

impl Viewpoint<'_> {
    fn name(self) -> String {
        match self {
            Self::Guest => "<name>".to_string(),
            Self::Windows { distribution } => distribution.to_string(),
        }
    }

    fn restart(self) -> String {
        match self {
            Self::Guest => {
                "`sudo systemctl restart runner-manager.service` inside the distribution".into()
            }
            Self::Windows { distribution } => format!(
                "`wsl.exe -d {distribution} -u root systemctl restart runner-manager.service`"
            ),
        }
    }
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
    /// The fence's owner record exists and cannot be read, so it can never
    /// be judged, let alone reclaimed.
    FenceOwnerUnreadable { directory: PathBuf, detail: String },
    /// Windows asked the distribution to drain for WSL recovery.
    DrainRequested { root: PathBuf },
    /// The recovery configuration could not be used.
    FenceUnusable { detail: String },
    /// Another process kept the host-wide allocation lock.
    AllocationLockBusy { path: PathBuf },
}

impl BlockCause {
    /// The operator-facing reason and remedy, refused since `since`.
    #[must_use]
    pub fn blocked_since(&self, since: DateTime<Utc>, viewpoint: Viewpoint<'_>) -> LaunchesBlocked {
        let name = viewpoint.name();
        let restart = viewpoint.restart();
        let watch_recovery = format!(
            "launches resume when Windows finishes recovering it (`runner-manager wsl status \
             --distribution {name}` on Windows shows the phase), and coordination no watchdog \
             maintains is retired 5 minutes after it stops"
        );
        let (reason, remedy) = match self {
            Self::FenceHeld {
                directory,
                owner: Some(owner),
            } if owner.kind == FenceOwnerKind::WindowsRecovery => (
                format!(
                    "Windows WSL recovery holds the launch fence ({})",
                    directory.display()
                ),
                watch_recovery,
            ),
            Self::FenceHeld {
                directory,
                owner: Some(owner),
            } => (
                format!(
                    "a runner launch by process {} holds the WSL launch fence ({})",
                    owner.process_id,
                    directory.display()
                ),
                format!(
                    "if no runner is being registered, restart the service with {restart}; the \
                     restarted daemon reclaims a fence whose owner is gone"
                ),
            ),
            Self::FenceHeld {
                directory,
                owner: None,
            } => (
                format!(
                    "the WSL launch fence ({}) has no owner record",
                    directory.display()
                ),
                format!(
                    "restart the service with {restart}; if the fence survives the restart, \
                     delete {} once no runner-manager launch is in progress",
                    directory.display()
                ),
            ),
            Self::FenceOwnerUnreadable { directory, detail } => (
                format!("the WSL launch fence's owner record cannot be read: {detail}"),
                format!(
                    "delete {} once no runner-manager launch is in progress on {name}; no daemon \
                     reclaims a fence whose owner it cannot read",
                    directory.display()
                ),
            ),
            Self::DrainRequested { root } => (
                format!(
                    "Windows has asked this distribution to drain for WSL recovery ({})",
                    root.join(crate::wsl::fence::REQUEST_FILE).display()
                ),
                watch_recovery,
            ),
            Self::FenceUnusable { detail } => (
                format!("the WSL recovery configuration cannot be used: {detail}"),
                format!(
                    "repair the managed host from Windows with `runner-manager wsl install \
                     --distribution {name}`"
                ),
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

#[derive(Debug, Serialize, Deserialize)]
struct LaunchesBlockedRecord {
    schema_version: u32,
    /// The latest refusal, rewritten on each one. See [`RECORD_FRESH`].
    last_refused_at: DateTime<Utc>,
    #[serde(flatten)]
    blocked: LaunchesBlocked,
}

/// Records that the daemon's allocations keep being refused, the latest
/// refusal at `last_refused_at`.
///
/// # Errors
/// [`ServiceError::Record`] when `state/` cannot be written.
pub fn record_launches_blocked(
    paths: &AppPaths,
    blocked: &LaunchesBlocked,
    last_refused_at: DateTime<Utc>,
) -> Result<(), ServiceError> {
    write_state_record(
        &launches_blocked_path(paths),
        &LaunchesBlockedRecord {
            schema_version: SCHEMA_VERSION,
            last_refused_at,
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

/// The daemon's own record of blocked launches, if it wrote one and refused
/// an allocation within [`RECORD_FRESH`] of `now`.
///
/// # Errors
/// [`ServiceError::Record`] when the file exists and cannot be read or parsed.
pub fn recorded_launches_blocked(
    paths: &AppPaths,
    now: DateTime<Utc>,
) -> Result<Option<LaunchesBlocked>, ServiceError> {
    Ok(
        read_state_record::<LaunchesBlockedRecord>(&launches_blocked_path(paths))?
            .filter(|record| !elapsed_at_least(record.last_refused_at, now, RECORD_FRESH))
            .map(|record| record.blocked),
    )
}

fn launches_blocked_path(paths: &AppPaths) -> PathBuf {
    paths.state_dir().join(LAUNCHES_BLOCKED_FILE)
}

/// A launch fence under `root` that has been held for longer than any launch
/// takes, seen from `viewpoint`.
///
/// The guest ages a claim by the owner's own `acquired_at`, written by the
/// guest clock. Windows ages it by the directory's modification time, which
/// NTFS stamps with the Windows clock, because a WSL clock can lag the host's
/// by a long way after the machine sleeps.
#[must_use]
pub fn stuck_launch_fence(
    root: &Path,
    now: DateTime<Utc>,
    viewpoint: Viewpoint<'_>,
) -> Option<LaunchesBlocked> {
    let directory = root.join(FENCE_DIRECTORY);
    let modified = || fence_modified(root).ok().flatten();
    match FenceClaim::owner(root) {
        Ok(Some(owner)) => {
            let since = match viewpoint {
                Viewpoint::Guest => owner.acquired_at,
                Viewpoint::Windows { .. } => modified()?,
            };
            elapsed_at_least(since, now, FENCE_HELD_TOO_LONG).then(|| {
                BlockCause::FenceHeld {
                    directory,
                    owner: Some(owner),
                }
                .blocked_since(since, viewpoint)
            })
        }
        // A claimer writes its owner straight after creating the directory, so
        // one still missing after the reclaim grace is not a launch in progress.
        Ok(None) => {
            let since = modified()?;
            elapsed_at_least(since, now, OWNERLESS_CLAIM_GRACE).then(|| {
                BlockCause::FenceHeld {
                    directory,
                    owner: None,
                }
                .blocked_since(since, viewpoint)
            })
        }
        Err(error) => Some(
            BlockCause::FenceOwnerUnreadable {
                directory,
                detail: error.to_string(),
            }
            .blocked_since(modified().unwrap_or(now), viewpoint),
        ),
    }
}

/// Whether this host's own daemon starts no runner: its fresh record first,
/// then, inside a managed WSL distribution, the fence itself.
#[must_use]
pub fn launches_blocked(paths: &AppPaths, now: DateTime<Utc>) -> Option<LaunchesBlocked> {
    if let Ok(Some(blocked)) = recorded_launches_blocked(paths, now) {
        return Some(blocked);
    }
    let config = GuestRecoveryConfig::read(paths).ok().flatten()?;
    stuck_launch_fence(&config.shared_root, now, Viewpoint::Guest)
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
        let now = Utc::now();
        assert_eq!(recorded_launches_blocked(&paths, now).unwrap(), None);
        let blocked = BlockCause::AllocationLockBusy {
            path: PathBuf::from("allocation.lock"),
        }
        .blocked_since(now, Viewpoint::Guest);
        record_launches_blocked(&paths, &blocked, now).unwrap();
        assert_eq!(
            recorded_launches_blocked(&paths, now).unwrap(),
            Some(blocked.clone())
        );
        assert_eq!(launches_blocked(&paths, now), Some(blocked));
        clear_launches_blocked(&paths).unwrap();
        assert_eq!(launches_blocked(&paths, now), None);
    }

    /// A daemon refuses only while there is demand. A record nobody refreshes
    /// -- the demand went elsewhere, the service was stopped -- must not keep
    /// a host that would launch fine reported as blocked.
    #[test]
    fn a_record_no_refusal_refreshes_expires() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        let refused = Utc::now();
        let blocked = BlockCause::AllocationLockBusy {
            path: PathBuf::from("allocation.lock"),
        }
        .blocked_since(refused, Viewpoint::Guest);
        record_launches_blocked(&paths, &blocked, refused).unwrap();

        let soon = refused + chrono::Duration::minutes(14);
        assert_eq!(launches_blocked(&paths, soon), Some(blocked));
        let later = refused + chrono::Duration::minutes(16);
        assert_eq!(launches_blocked(&paths, later), None);
    }

    #[test]
    fn a_fence_is_stuck_only_once_it_outlives_any_launch() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            stuck_launch_fence(dir.path(), Utc::now(), Viewpoint::Guest),
            None
        );
        let claim = FenceClaim::try_claim(dir.path(), FenceOwnerKind::GuestLaunch, None)
            .unwrap()
            .unwrap();
        assert_eq!(
            stuck_launch_fence(dir.path(), Utc::now(), Viewpoint::Guest),
            None
        );
        let later = Utc::now() + chrono::Duration::minutes(31);
        let stuck = stuck_launch_fence(dir.path(), later, Viewpoint::Guest).expect("stuck");
        assert!(
            stuck.reason.contains("runner launch by process"),
            "{stuck:?}"
        );
        assert!(stuck.remedy.contains("systemctl restart"), "{stuck:?}");
        let windows = stuck_launch_fence(
            dir.path(),
            later,
            Viewpoint::Windows {
                distribution: "Ubuntu",
            },
        )
        .expect("stuck from Windows too");
        assert!(
            windows.remedy.contains("wsl.exe -d Ubuntu -u root"),
            "{windows:?}"
        );
        drop(claim);
        assert_eq!(
            stuck_launch_fence(dir.path(), later, Viewpoint::Guest),
            None
        );
    }

    /// Windows ages a claim by its own clock, not by the guest-written
    /// `acquired_at`: a WSL clock lagging the host's by an hour must not make a
    /// claim made a moment ago look stuck.
    #[test]
    fn windows_ages_a_fence_by_its_own_clock() {
        let dir = tempfile::tempdir().unwrap();
        let fence = dir.path().join(FENCE_DIRECTORY);
        std::fs::create_dir_all(&fence).unwrap();
        let lagging = FenceOwner {
            schema_version: crate::wsl::fence::SCHEMA_VERSION,
            kind: FenceOwnerKind::GuestLaunch,
            generation: None,
            process_id: 7,
            acquired_at: Utc::now() - chrono::Duration::hours(1),
            identity: None,
        };
        std::fs::write(
            fence.join(crate::wsl::fence::OWNER_FILE),
            serde_json::to_vec(&lagging).unwrap(),
        )
        .unwrap();
        let windows = Viewpoint::Windows {
            distribution: "Ubuntu",
        };
        assert_eq!(stuck_launch_fence(dir.path(), Utc::now(), windows), None);
        assert!(stuck_launch_fence(dir.path(), Utc::now(), Viewpoint::Guest).is_some());
    }

    #[test]
    fn an_unreadable_owner_is_reported_at_once_with_the_directory_to_delete() {
        let dir = tempfile::tempdir().unwrap();
        let fence = dir.path().join(FENCE_DIRECTORY);
        std::fs::create_dir_all(&fence).unwrap();
        std::fs::write(fence.join(crate::wsl::fence::OWNER_FILE), b"{not json").unwrap();
        let stuck = stuck_launch_fence(dir.path(), Utc::now(), Viewpoint::Guest).expect("stuck");
        assert!(stuck.reason.contains("cannot be read"), "{stuck:?}");
        assert!(stuck.remedy.starts_with("delete "), "{stuck:?}");
        assert!(!stuck.remedy.contains("wsl install"), "{stuck:?}");
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
