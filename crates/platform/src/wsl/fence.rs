//! Cross-boundary recovery fence shared by Windows and a managed WSL guest.
//!
//! Windows share locks, Unix `flock`, and SQLite byte-range locks do not
//! interoperate reliably through DrvFS. Directory creation does: exactly one
//! side can create the same directory. The directory is intentionally durable
//! on process death; an abandoned owner blocks recovery instead of allowing a
//! possibly concurrent runner launch.
//!
//! # A guest claim whose owner is provably gone is reclaimed
//!
//! Durability has a price: a guest daemon that dies mid-launch -- WSL shut down
//! under it, or the directory removal failing on DrvFS -- leaves a claim that
//! nothing ever removes, and every later launch on that distribution is refused
//! for good. That happened for 13 days on one host while the distribution
//! looked healthy. So a guest claim records its owner's [`ProcessIdentity`],
//! and [`try_claim_guest_launch`] reclaims one only when that owner is *provably*
//! gone: the process exited, its PID now belongs to somebody else, the claim
//! predates this boot, or this very process wrote it and its release failed.
//! A live owner, an owner that cannot be inspected, and a Windows recovery
//! claim are never touched. Only one guest launcher can exist per distribution,
//! because the guest configuration and the agent's single-instance lock live
//! under the same account's paths.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::discovery::{escaped_name_with_digest, validate_distribution_name};
use crate::paths::AppPaths;
use crate::process::{Adoption, ProcessIdentity};
use runner_manager_domain::model::ScaleTarget;

pub const GUEST_CONFIG_FILE: &str = "wsl-recovery.toml";
pub const REQUEST_FILE: &str = "drain-request.json";
pub const HEARTBEAT_FILE: &str = "guest-heartbeat.json";
pub const FENCE_DIRECTORY: &str = "launch-fence";
pub const OWNER_FILE: &str = "owner.json";
pub const RECOVERY_STATUS_FILE: &str = "recovery-status.json";
pub const SCHEMA_VERSION: u32 = 1;

/// Windows-side directory shared with one exact distribution.
pub fn recovery_root(paths: &AppPaths, distribution: &str) -> Result<PathBuf, super::WslError> {
    validate_distribution_name(distribution)?;
    Ok(paths
        .config_dir()
        .join("wsl-recovery")
        .join(escaped_name_with_digest(distribution)))
}

#[derive(Debug, thiserror::Error)]
pub enum FenceError {
    #[error("cannot {operation} WSL recovery state at {}: {source}", path.display())]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot decode WSL recovery state at {}: {source}", path.display())]
    Decode {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("WSL recovery state at {} has schema {found}, but this build supports {SCHEMA_VERSION}", path.display())]
    Schema { path: PathBuf, found: u32 },
}

fn io(operation: &'static str, path: &Path, source: std::io::Error) -> FenceError {
    FenceError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestRecoveryConfig {
    pub schema_version: u32,
    pub shared_root: PathBuf,
}

impl GuestRecoveryConfig {
    #[must_use]
    pub fn new(shared_root: PathBuf) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            shared_root,
        }
    }

    #[must_use]
    pub fn path(paths: &AppPaths) -> PathBuf {
        paths.config_dir().join(GUEST_CONFIG_FILE)
    }

    pub fn read(paths: &AppPaths) -> Result<Option<Self>, FenceError> {
        let path = Self::path(paths);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(io("read", &path, source)),
        };
        let value: Self = toml::from_str(&text).map_err(|source| FenceError::Io {
            operation: "decode",
            path: path.clone(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, source),
        })?;
        if value.schema_version != SCHEMA_VERSION {
            return Err(FenceError::Schema {
                path,
                found: value.schema_version,
            });
        }
        Ok(Some(value))
    }

    pub fn write(&self, paths: &AppPaths) -> Result<(), FenceError> {
        let path = Self::path(paths);
        let text = toml::to_string_pretty(self).map_err(|source| FenceError::Io {
            operation: "encode",
            path: path.clone(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, source),
        })?;
        atomic_write(&path, text.as_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrainRequest {
    pub schema_version: u32,
    pub generation: u64,
    pub requested_at: DateTime<Utc>,
}

impl DrainRequest {
    #[must_use]
    pub fn new(generation: u64, requested_at: DateTime<Utc>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            generation,
            requested_at,
        }
    }

    pub fn write(&self, root: &Path) -> Result<(), FenceError> {
        write_json(&root.join(REQUEST_FILE), self)
    }

    pub fn read(root: &Path) -> Result<Option<Self>, FenceError> {
        read_json(&root.join(REQUEST_FILE))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestHeartbeat {
    pub schema_version: u32,
    pub observed_at: DateTime<Utc>,
    pub acknowledged_generation: Option<u64>,
    pub local_active_attempts: Option<u32>,
    /// Attempts which the guest journal still considers to be executing a
    /// GitHub job. This lets recovery distinguish a stuck idle/listener
    /// process from work which must never be interrupted.
    #[serde(default)]
    pub local_busy_attempts: Option<u32>,
    pub managed_targets: Vec<ScaleTarget>,
    pub unmanaged_runner_services: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPhase {
    Healthy,
    Degraded,
    Draining,
    Recovering,
    Backoff,
    RecoveryBlocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryStatus {
    pub schema_version: u32,
    pub observed_at: DateTime<Utc>,
    pub phase: RecoveryPhase,
    pub consecutive_probe_failures: u8,
    pub reason: Option<String>,
    pub last_recovered_at: Option<DateTime<Utc>>,
}

impl RecoveryStatus {
    pub fn write(&self, root: &Path) -> Result<(), FenceError> {
        write_json(&root.join(RECOVERY_STATUS_FILE), self)
    }

    pub fn read(root: &Path) -> Result<Option<Self>, FenceError> {
        read_json(&root.join(RECOVERY_STATUS_FILE))
    }
}

impl GuestHeartbeat {
    pub fn write(&self, root: &Path) -> Result<(), FenceError> {
        write_json(&root.join(HEARTBEAT_FILE), self)
    }

    pub fn read(root: &Path) -> Result<Option<Self>, FenceError> {
        read_json(&root.join(HEARTBEAT_FILE))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceOwnerKind {
    GuestLaunch,
    WindowsRecovery,
}

/// Who holds the launch fence, as recorded by the holder.
///
/// Unlike the other documents here this one tolerates unknown fields, so that
/// a later build can add to the owner record without this build reading a
/// newer guest's claim as undecodable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FenceOwner {
    pub schema_version: u32,
    pub kind: FenceOwnerKind,
    pub generation: Option<u64>,
    pub process_id: u32,
    pub acquired_at: DateTime<Utc>,
    /// The claimer's PID plus start token, the record `HostLock` keeps. A PID
    /// alone cannot tell the owner from whatever holds that PID after a WSL
    /// restart. Absent in claims written before 0.4.35, and when the claimer
    /// could not read its own identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<ProcessIdentity>,
}

/// A successfully created cross-boundary directory claim.
#[derive(Debug)]
pub struct FenceClaim {
    directory: PathBuf,
    release_on_drop: bool,
}

impl FenceClaim {
    /// Attempt to claim the launch boundary. `Ok(None)` means another side
    /// owns it; absence or malformed owner metadata never makes it free.
    pub fn try_claim(
        root: &Path,
        kind: FenceOwnerKind,
        generation: Option<u64>,
    ) -> Result<Option<Self>, FenceError> {
        fs::create_dir_all(root).map_err(|source| io("create", root, source))?;
        let directory = root.join(FENCE_DIRECTORY);
        match fs::create_dir(&directory) {
            Ok(()) => {}
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => return Ok(None),
            Err(source) => return Err(io("claim", &directory, source)),
        }
        let owner = FenceOwner {
            schema_version: SCHEMA_VERSION,
            kind,
            generation,
            process_id: std::process::id(),
            acquired_at: Utc::now(),
            identity: ProcessIdentity::of_current_process().ok(),
        };
        if let Err(error) = write_json(&directory.join(OWNER_FILE), &owner) {
            let _ = fs::remove_dir_all(&directory);
            return Err(error);
        }
        Ok(Some(Self {
            directory,
            release_on_drop: true,
        }))
    }

    /// Leave a recovery claim durable. A restarted watchdog may adopt only a
    /// matching recovery owner; a guest-launch owner is never removed blindly.
    pub fn make_durable(mut self) {
        self.release_on_drop = false;
    }

    pub fn owner(root: &Path) -> Result<Option<FenceOwner>, FenceError> {
        read_json(&root.join(FENCE_DIRECTORY).join(OWNER_FILE))
    }

    pub fn release(mut self) -> Result<(), FenceError> {
        self.release_on_drop = false;
        remove_claim(&self.directory)
    }
}

impl Drop for FenceClaim {
    fn drop(&mut self) {
        if self.release_on_drop {
            let _ = remove_claim(&self.directory);
        }
    }
}

/// Whether at least `limit` has passed between `since` and `now`. A `since` in
/// the future -- clock skew -- has not.
#[must_use]
pub fn elapsed_at_least(
    since: DateTime<Utc>,
    now: DateTime<Utc>,
    limit: std::time::Duration,
) -> bool {
    (now - since).to_std().is_ok_and(|age| age >= limit)
}

/// When the fence directory under `root` was last modified, or `None` when
/// there is no fence.
pub(crate) fn fence_modified(root: &Path) -> Result<Option<DateTime<Utc>>, FenceError> {
    let directory = root.join(FENCE_DIRECTORY);
    match fs::metadata(&directory).and_then(|meta| meta.modified()) {
        Ok(modified) => Ok(Some(modified.into())),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(io("inspect", &directory, source)),
    }
}

/// How many times [`GuestLaunchClaim::release`] tries to remove the claim.
const RELEASE_ATTEMPTS: u32 = 3;
/// The pause before the first retry; each later one waits a step longer.
const RELEASE_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

/// Why a guest launch claim no longer has an owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaleGuestClaim {
    /// The recorded process has exited, or its PID now belongs to another
    /// process.
    OwnerExited,
    /// The claim was written before this boot, so its owner cannot be running.
    EarlierBoot,
    /// This process wrote the claim, no longer holds it, and could not remove
    /// it when it let go.
    ReleaseFailed,
    /// The claim never recorded an owner and is older than any claimer takes
    /// to write one.
    OwnerNeverRecorded,
}

impl std::fmt::Display for StaleGuestClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::OwnerExited => "owner_exited",
            Self::EarlierBoot => "earlier_boot",
            Self::ReleaseFailed => "release_failed",
            Self::OwnerNeverRecorded => "owner_never_recorded",
        })
    }
}

/// How long a claim directory may exist without `owner.json` before it is
/// treated as abandoned. Every claimer writes the owner straight after
/// creating the directory, so this is generous by orders of magnitude.
pub(crate) const OWNERLESS_CLAIM_GRACE: std::time::Duration =
    std::time::Duration::from_secs(5 * 60);

/// What reclaiming needs to know about processes. A port, so that every branch
/// can be exercised on every leg of the CI matrix.
pub(crate) trait ProcessProbe {
    /// This process's identity, when it can be read.
    fn current(&self) -> Option<ProcessIdentity>;
    /// What a recorded identity refers to now; `None` when the operating
    /// system will not say.
    fn recheck(&self, identity: &ProcessIdentity) -> Option<Adoption>;
    /// Whether anything holds `pid`; `None` when the operating system will not
    /// say.
    fn pid_alive(&self, pid: u32) -> Option<bool>;
    /// When this machine booted, where the platform reports it.
    fn boot_time(&self) -> Option<DateTime<Utc>>;
}

/// [`ProcessProbe`] against the machine this runs on.
pub(crate) struct HostProcesses;

impl ProcessProbe for HostProcesses {
    fn current(&self) -> Option<ProcessIdentity> {
        ProcessIdentity::of_current_process().ok()
    }

    fn recheck(&self, identity: &ProcessIdentity) -> Option<Adoption> {
        identity.recheck().ok()
    }

    fn pid_alive(&self, pid: u32) -> Option<bool> {
        match ProcessIdentity::resolve(pid) {
            Ok(_) => Some(true),
            Err(crate::process::ProcessError::NoSuchProcess { .. }) => Some(false),
            Err(_) => None,
        }
    }

    fn boot_time(&self) -> Option<DateTime<Utc>> {
        crate::process::boot_time()
    }
}

/// Decide whether a recorded guest launch owner is provably gone.
///
/// Must not be asked while this process holds the claim: a claim carrying this
/// process's own identity is read as one whose release failed. `None` means
/// the claim must be honoured -- a live owner, an owner the operating system
/// will not describe, and every Windows recovery claim.
fn stale_guest_owner(owner: &FenceOwner, probe: &dyn ProcessProbe) -> Option<StaleGuestClaim> {
    if owner.kind != FenceOwnerKind::GuestLaunch {
        return None;
    }
    let current = probe.current();
    if let Some(identity) = &owner.identity {
        if current.as_ref() == Some(identity) {
            return Some(StaleGuestClaim::ReleaseFailed);
        }
        return match probe.recheck(identity)? {
            Adoption::Live => None,
            Adoption::Gone | Adoption::PidRecycled { .. } => Some(StaleGuestClaim::OwnerExited),
        };
    }
    // No identity: written before 0.4.35, or by a claimer that could not read
    // its own. Judge it by the boot and the bare PID.
    if probe
        .boot_time()
        .is_some_and(|booted| owner.acquired_at < booted)
    {
        return Some(StaleGuestClaim::EarlierBoot);
    }
    if current.is_some_and(|me| me.pid() == owner.process_id) {
        // This process wrote it and lost it, or a predecessor holding this PID
        // earlier in the boot did. Neither is holding it now.
        return Some(StaleGuestClaim::ReleaseFailed);
    }
    match probe.pid_alive(owner.process_id)? {
        true => None,
        false => Some(StaleGuestClaim::OwnerExited),
    }
}

/// A stale guest claim that was removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReclaimedGuestClaim {
    pub reason: StaleGuestClaim,
    /// The record that was removed; `None` for a claim with no owner file.
    pub owner: Option<FenceOwner>,
}

impl std::fmt::Display for ReclaimedGuestClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)?;
        if let Some(owner) = &self.owner {
            write!(
                f,
                " (pid {}, acquired {})",
                owner.process_id,
                owner.acquired_at.to_rfc3339()
            )?;
        }
        Ok(())
    }
}

/// Fence directories this process holds a guest claim on right now.
///
/// Process-wide rather than per lock, because "this process holds it" is a
/// fact about the process: a daemon that reloads builds a new allocation lock,
/// and a claim from the previous generation must still not look abandoned.
static HELD_HERE: std::sync::Mutex<std::collections::BTreeSet<PathBuf>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

fn held_here() -> std::sync::MutexGuard<'static, std::collections::BTreeSet<PathBuf>> {
    HELD_HERE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The outcome of [`try_claim_guest_launch`].
#[derive(Debug)]
pub enum GuestClaimAttempt {
    Claimed {
        claim: GuestLaunchClaim,
        /// A stale claim that had to be removed first.
        reclaimed: Option<ReclaimedGuestClaim>,
    },
    /// Somebody that may still be running holds it.
    Busy,
}

/// A held guest launch claim. [`GuestLaunchClaim::release`] lets go of it and
/// reports a failure; dropping it lets go silently.
#[derive(Debug)]
pub struct GuestLaunchClaim {
    claim: Option<FenceClaim>,
}

impl GuestLaunchClaim {
    /// Release the claim, retrying the failures DrvFS reports transiently -- a
    /// handle the Windows side still has open, an antivirus scan.
    ///
    /// # Errors
    /// The last removal failure. The claim is left behind and the next launch
    /// reclaims it as one whose release failed; the caller should say so,
    /// because this once failed silently while a distribution started nothing
    /// for 13 days.
    pub fn release(mut self) -> Result<(), FenceError> {
        self.release_now()
    }

    fn release_now(&mut self) -> Result<(), FenceError> {
        let Some(mut claim) = self.claim.take() else {
            return Ok(());
        };
        claim.release_on_drop = false;
        let mut held = held_here();
        held.remove(&claim.directory);
        let mut result = Ok(());
        for attempt in 1..=RELEASE_ATTEMPTS {
            result = remove_claim(&claim.directory);
            if result.is_ok() || attempt == RELEASE_ATTEMPTS {
                break;
            }
            std::thread::sleep(RELEASE_RETRY_DELAY * attempt);
        }
        result
    }
}

impl Drop for GuestLaunchClaim {
    fn drop(&mut self) {
        let _ = self.release_now();
    }
}

/// Claim the guest launch boundary, first reclaiming a claim whose owner is
/// provably gone, and retrying once after that.
///
/// # Errors
/// [`FenceError`] when the fence cannot be created, read, or removed.
pub fn try_claim_guest_launch(root: &Path) -> Result<GuestClaimAttempt, FenceError> {
    try_claim_guest_launch_with(root, &HostProcesses, Utc::now())
}

pub(crate) fn try_claim_guest_launch_with(
    root: &Path,
    probe: &dyn ProcessProbe,
    now: DateTime<Utc>,
) -> Result<GuestClaimAttempt, FenceError> {
    let mut held = held_here();
    if held.contains(&root.join(FENCE_DIRECTORY)) {
        return Ok(GuestClaimAttempt::Busy);
    }
    let mut claim = FenceClaim::try_claim(root, FenceOwnerKind::GuestLaunch, None)?;
    let mut reclaimed = None;
    if claim.is_none() {
        reclaimed = reclaim_unheld(root, probe, now)?;
        if reclaimed.is_some() {
            claim = FenceClaim::try_claim(root, FenceOwnerKind::GuestLaunch, None)?;
        }
    }
    let Some(claim) = claim else {
        return Ok(GuestClaimAttempt::Busy);
    };
    held.insert(claim.directory.clone());
    Ok(GuestClaimAttempt::Claimed {
        claim: GuestLaunchClaim { claim: Some(claim) },
        reclaimed,
    })
}

/// Remove the guest launch claim under `root` when its owner is provably gone
/// and this process does not hold it. The daemon calls this at start, after
/// taking its single-instance lock and before any launch.
///
/// # Errors
/// [`FenceError`] when the claim cannot be read or removed.
pub fn reclaim_stale_guest_claim(root: &Path) -> Result<Option<ReclaimedGuestClaim>, FenceError> {
    reclaim_stale_guest_claim_with(root, &HostProcesses, Utc::now())
}

pub(crate) fn reclaim_stale_guest_claim_with(
    root: &Path,
    probe: &dyn ProcessProbe,
    now: DateTime<Utc>,
) -> Result<Option<ReclaimedGuestClaim>, FenceError> {
    let held = held_here();
    if held.contains(&root.join(FENCE_DIRECTORY)) {
        return Ok(None);
    }
    reclaim_unheld(root, probe, now)
}

/// The reclaim itself. The caller holds [`HELD_HERE`] and has checked that
/// this process does not hold the claim.
fn reclaim_unheld(
    root: &Path,
    probe: &dyn ProcessProbe,
    now: DateTime<Utc>,
) -> Result<Option<ReclaimedGuestClaim>, FenceError> {
    let directory = root.join(FENCE_DIRECTORY);
    let Some(owner) = FenceClaim::owner(root)? else {
        let abandoned = fence_modified(root)?
            .is_some_and(|modified| elapsed_at_least(modified, now, OWNERLESS_CLAIM_GRACE));
        if !abandoned || FenceClaim::owner(root)?.is_some() {
            return Ok(None);
        }
        remove_claim(&directory)?;
        return Ok(Some(ReclaimedGuestClaim {
            reason: StaleGuestClaim::OwnerNeverRecorded,
            owner: None,
        }));
    };
    let Some(reason) = stale_guest_owner(&owner, probe) else {
        return Ok(None);
    };
    // Re-read immediately before removing, so a claim that changed hands since
    // it was judged is not the one removed.
    if FenceClaim::owner(root)?.as_ref() != Some(&owner) {
        return Ok(None);
    }
    remove_claim(&directory)?;
    Ok(Some(ReclaimedGuestClaim {
        reason,
        owner: Some(owner),
    }))
}

pub fn clear_recovery(root: &Path, generation: u64) -> Result<(), FenceError> {
    let owner = FenceClaim::owner(root)?;
    if owner.as_ref().is_some_and(|owner| {
        owner.kind == FenceOwnerKind::WindowsRecovery && owner.generation == Some(generation)
    }) {
        remove_claim(&root.join(FENCE_DIRECTORY))?;
    }
    let request_path = root.join(REQUEST_FILE);
    if DrainRequest::read(root)?
        .as_ref()
        .is_some_and(|request| request.generation != generation)
    {
        return Ok(());
    }
    match fs::remove_file(&request_path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io("remove", &request_path, source)),
    }
}

/// Retire coordination written by a Windows recovery watchdog that no longer
/// has authority to run. A guest launch claim is deliberately preserved. The
/// fence and request may have different generations after a watchdog restart,
/// so each Windows-owned generation is cleared independently.
pub fn retire_windows_recovery(root: &Path) -> Result<(), FenceError> {
    let recovery_generation = FenceClaim::owner(root)?.and_then(|owner| {
        (owner.kind == FenceOwnerKind::WindowsRecovery)
            .then_some(owner.generation)
            .flatten()
    });
    if let Some(generation) = recovery_generation {
        clear_recovery(root, generation)?;
    }
    if let Some(request) = DrainRequest::read(root)? {
        clear_recovery(root, request.generation)?;
    }
    let status_path = root.join(RECOVERY_STATUS_FILE);
    match fs::remove_file(&status_path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io("remove", &status_path, source)),
    }
}

/// Retire Windows recovery coordination that no live watchdog is maintaining.
///
/// A watchdog keeps its recovery generation in memory only. When it exits
/// mid-recovery -- the Windows service or the companion task restarting while
/// WSL is being recovered -- its durable fence claim and drain request outlive
/// it, and its successor starts with a new generation. [`clear_recovery`] only
/// clears a matching generation, so the successor never clears them and every
/// guest launch stays fenced forever while WSL itself is healthy.
///
/// A live watchdog rewrites its drain request on every unhealthy observation,
/// so a request newer than `abandoned_after` means recovery is still being
/// driven and nothing is touched. A Windows-owned claim younger than that is
/// likewise left alone, because its owner may be between claiming the fence
/// and its next request write. A guest launch claim is never removed.
///
/// Returns `true` when abandoned coordination was retired.
pub fn retire_abandoned_windows_recovery(
    root: &Path,
    now: DateTime<Utc>,
    abandoned_after: std::time::Duration,
) -> Result<bool, FenceError> {
    let abandoned = |at: DateTime<Utc>| elapsed_at_least(at, now, abandoned_after);
    let request = DrainRequest::read(root)?;
    if request
        .as_ref()
        .is_some_and(|request| !abandoned(request.requested_at))
    {
        return Ok(false);
    }
    let windows_owner =
        FenceClaim::owner(root)?.filter(|owner| owner.kind == FenceOwnerKind::WindowsRecovery);
    if windows_owner
        .as_ref()
        .is_some_and(|owner| !abandoned(owner.acquired_at))
    {
        return Ok(false);
    }
    if request.is_none() && windows_owner.is_none() {
        return Ok(false);
    }
    retire_windows_recovery(root)?;
    Ok(true)
}

fn remove_claim(directory: &Path) -> Result<(), FenceError> {
    match fs::remove_dir_all(directory) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io("release", directory, source)),
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), FenceError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|source| io("create", parent, source))?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|source| io("write", path, source))?;
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|source| io("write", path, source))?;
    temporary
        .persist(path)
        .map(|_| ())
        .map_err(|error| io("replace", path, error.error))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), FenceError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|source| FenceError::Decode {
        path: path.to_path_buf(),
        source,
    })?;
    atomic_write(path, &bytes)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>, FenceError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io("read", path, source)),
    };
    let value: T = serde_json::from_slice(&bytes).map_err(|source| FenceError::Decode {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(Some(value))
}

/// Persistent runner services are outside runner-manager's attempt journal.
/// Their presence blocks automated WSL termination even while they look idle.
#[must_use]
pub fn unmanaged_runner_service_count() -> Option<u32> {
    if !cfg!(target_os = "linux") {
        return Some(0);
    }
    let mut names = std::collections::BTreeSet::new();
    for directory in [
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
    ] {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("actions.runner.") && name.ends_with(".service") {
                names.insert(name);
            }
        }
    }
    u32::try_from(names.len()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A [`ProcessProbe`] whose every answer is chosen by the test.
    #[derive(Default)]
    struct FakeProbe {
        current: Option<ProcessIdentity>,
        recheck: Option<Adoption>,
        pid_alive: Option<bool>,
        boot_time: Option<DateTime<Utc>>,
    }

    impl ProcessProbe for FakeProbe {
        fn current(&self) -> Option<ProcessIdentity> {
            self.current.clone()
        }
        fn recheck(&self, _: &ProcessIdentity) -> Option<Adoption> {
            self.recheck.clone()
        }
        fn pid_alive(&self, _: u32) -> Option<bool> {
            self.pid_alive
        }
        fn boot_time(&self) -> Option<DateTime<Utc>> {
            self.boot_time
        }
    }

    fn identity(pid: u32, token: &str) -> ProcessIdentity {
        serde_json::from_value(serde_json::json!({ "pid": pid, "start_token": token })).unwrap()
    }

    fn guest_owner(
        process_id: u32,
        acquired_at: DateTime<Utc>,
        identity: Option<ProcessIdentity>,
    ) -> FenceOwner {
        FenceOwner {
            schema_version: SCHEMA_VERSION,
            kind: FenceOwnerKind::GuestLaunch,
            generation: None,
            process_id,
            acquired_at,
            identity,
        }
    }

    /// Plants a guest claim exactly as an abandoned one looks on disk.
    fn plant(root: &Path, owner: &FenceOwner) {
        fs::create_dir_all(root.join(FENCE_DIRECTORY)).unwrap();
        write_json(&root.join(FENCE_DIRECTORY).join(OWNER_FILE), owner).unwrap();
    }

    fn claimed(attempt: GuestClaimAttempt) -> (GuestLaunchClaim, Option<ReclaimedGuestClaim>) {
        match attempt {
            GuestClaimAttempt::Claimed { claim, reclaimed } => (claim, reclaimed),
            GuestClaimAttempt::Busy => panic!("the launch was refused"),
        }
    }

    /// A child that has already exited: its PID is free or somebody else's.
    fn exited_child() -> u32 {
        let mut child = crate::process::tests::quick_exit().spawn().unwrap();
        child.wait().unwrap();
        child.pid()
    }

    #[test]
    fn a_guest_claim_whose_owner_exited_is_reclaimed_and_the_launch_proceeds() {
        let root = tempfile::tempdir().unwrap();
        let pid = exited_child();
        plant(
            root.path(),
            &guest_owner(pid, Utc::now(), Some(identity(pid, "platform:gone"))),
        );

        let (claim, reclaimed) =
            claimed(try_claim_guest_launch_with(root.path(), &HostProcesses, Utc::now()).unwrap());

        let reclaimed = reclaimed.expect("the dead owner's claim was reclaimed");
        assert_eq!(reclaimed.reason, StaleGuestClaim::OwnerExited);
        assert_eq!(reclaimed.owner.unwrap().process_id, pid);
        let owner = FenceClaim::owner(root.path()).unwrap().unwrap();
        assert_eq!(
            owner.identity,
            HostProcesses.current(),
            "the new claim is ours"
        );
        drop(claim);
        assert!(!root.path().join(FENCE_DIRECTORY).exists());
    }

    /// The incident: a claim written in an earlier WSL boot, whose PID is held
    /// now by a different process -- here, this one.
    #[test]
    fn a_guest_claim_from_an_earlier_boot_is_reclaimed_even_when_its_pid_is_reused() {
        let root = tempfile::tempdir().unwrap();
        let pid = std::process::id();
        plant(
            root.path(),
            &guest_owner(
                pid,
                Utc::now(),
                Some(identity(pid, "linux:earlier-boot:189")),
            ),
        );

        let (_claim, reclaimed) =
            claimed(try_claim_guest_launch_with(root.path(), &HostProcesses, Utc::now()).unwrap());

        assert_eq!(reclaimed.unwrap().reason, StaleGuestClaim::OwnerExited);
    }

    #[test]
    fn a_live_guest_claim_is_never_reclaimed() {
        let root = tempfile::tempdir().unwrap();
        let mut child = crate::process::tests::long_running().spawn().unwrap();
        let live = child.identity().clone();
        plant(
            root.path(),
            &guest_owner(child.pid(), Utc::now(), Some(live.clone())),
        );

        let attempt = try_claim_guest_launch_with(root.path(), &HostProcesses, Utc::now());
        let startup = reclaim_stale_guest_claim_with(root.path(), &HostProcesses, Utc::now());
        live.terminate(std::time::Duration::from_secs(5)).unwrap();
        child.wait().unwrap();

        assert!(matches!(attempt.unwrap(), GuestClaimAttempt::Busy));
        assert_eq!(startup.unwrap(), None);
        assert_eq!(
            FenceClaim::owner(root.path()).unwrap().unwrap().identity,
            Some(live)
        );
    }

    #[test]
    fn a_claim_this_process_holds_refuses_every_other_launch_of_it() {
        let root = tempfile::tempdir().unwrap();
        let (claim, reclaimed) =
            claimed(try_claim_guest_launch_with(root.path(), &HostProcesses, Utc::now()).unwrap());
        assert_eq!(reclaimed, None);
        assert!(matches!(
            try_claim_guest_launch_with(root.path(), &HostProcesses, Utc::now()).unwrap(),
            GuestClaimAttempt::Busy
        ));
        assert_eq!(
            reclaim_stale_guest_claim_with(root.path(), &HostProcesses, Utc::now()).unwrap(),
            None
        );
        drop(claim);
        claimed(try_claim_guest_launch_with(root.path(), &HostProcesses, Utc::now()).unwrap());
    }

    #[test]
    fn a_claim_this_process_failed_to_release_is_reclaimed_by_it() {
        let root = tempfile::tempdir().unwrap();
        let (mut claim, _) =
            claimed(try_claim_guest_launch_with(root.path(), &HostProcesses, Utc::now()).unwrap());
        // What a failed removal leaves: the claim let go, the directory kept.
        claim.claim.take().unwrap().make_durable();
        held_here().remove(&root.path().join(FENCE_DIRECTORY));
        drop(claim);
        assert!(root.path().join(FENCE_DIRECTORY).exists());

        let (_claim, reclaimed) =
            claimed(try_claim_guest_launch_with(root.path(), &HostProcesses, Utc::now()).unwrap());
        assert_eq!(reclaimed.unwrap().reason, StaleGuestClaim::ReleaseFailed);
    }

    #[test]
    fn a_windows_recovery_claim_is_never_reclaimed_by_the_guest() {
        let root = tempfile::tempdir().unwrap();
        let claim = FenceClaim::try_claim(root.path(), FenceOwnerKind::WindowsRecovery, Some(3))
            .unwrap()
            .unwrap();
        claim.make_durable();
        let dead = FakeProbe {
            recheck: Some(Adoption::Gone),
            pid_alive: Some(false),
            boot_time: Some(Utc::now() + chrono::Duration::days(1)),
            ..FakeProbe::default()
        };
        assert!(matches!(
            try_claim_guest_launch_with(root.path(), &dead, Utc::now()).unwrap(),
            GuestClaimAttempt::Busy
        ));
        assert!(root.path().join(FENCE_DIRECTORY).exists());
    }

    /// The record that blocked the incident host, as 0.4.34 wrote it.
    const PRE_0_4_35_RECORD: &str = r#"{
  "schema_version": 1,
  "kind": "guest_launch",
  "generation": null,
  "process_id": 189,
  "acquired_at": "2026-09-24T00:47:18.724Z"
}"#;

    #[test]
    fn an_old_schema_record_is_judged_by_the_boot_and_the_pid() {
        let old: FenceOwner = serde_json::from_str(PRE_0_4_35_RECORD).unwrap();
        assert_eq!(old.identity, None);
        let after = old.acquired_at + chrono::Duration::hours(1);
        let before = old.acquired_at - chrono::Duration::hours(1);
        let me = Some(identity(4242, "platform:me"));

        let rebooted = FakeProbe {
            boot_time: Some(after),
            pid_alive: Some(true),
            ..FakeProbe::default()
        };
        assert_eq!(
            stale_guest_owner(&old, &rebooted),
            Some(StaleGuestClaim::EarlierBoot)
        );

        let exited = FakeProbe {
            boot_time: Some(before),
            pid_alive: Some(false),
            ..FakeProbe::default()
        };
        assert_eq!(
            stale_guest_owner(&old, &exited),
            Some(StaleGuestClaim::OwnerExited)
        );

        let alive = FakeProbe {
            boot_time: Some(before),
            pid_alive: Some(true),
            current: me.clone(),
            ..FakeProbe::default()
        };
        assert_eq!(stale_guest_owner(&old, &alive), None);

        let unknown = FakeProbe::default();
        assert_eq!(stale_guest_owner(&old, &unknown), None);

        let mine = FakeProbe {
            boot_time: Some(before),
            pid_alive: Some(true),
            current: Some(identity(189, "platform:me")),
            ..FakeProbe::default()
        };
        assert_eq!(
            stale_guest_owner(&old, &mine),
            Some(StaleGuestClaim::ReleaseFailed)
        );
    }

    #[test]
    fn the_incident_record_is_reclaimed_at_daemon_start_after_a_wsl_restart() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join(FENCE_DIRECTORY)).unwrap();
        fs::write(
            root.path().join(FENCE_DIRECTORY).join(OWNER_FILE),
            PRE_0_4_35_RECORD,
        )
        .unwrap();
        let this_boot = FakeProbe {
            boot_time: Some("2026-10-07T00:00:00Z".parse().unwrap()),
            pid_alive: Some(true),
            ..FakeProbe::default()
        };

        let reclaimed = reclaim_stale_guest_claim_with(root.path(), &this_boot, Utc::now())
            .unwrap()
            .unwrap();

        assert_eq!(reclaimed.reason, StaleGuestClaim::EarlierBoot);
        assert!(!root.path().join(FENCE_DIRECTORY).exists());
        claimed(try_claim_guest_launch_with(root.path(), &this_boot, Utc::now()).unwrap());
    }

    #[test]
    fn an_ownerless_claim_is_reclaimed_only_after_the_grace() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join(FENCE_DIRECTORY)).unwrap();
        let probe = FakeProbe::default();
        assert_eq!(
            reclaim_stale_guest_claim_with(root.path(), &probe, Utc::now()).unwrap(),
            None
        );
        let later = Utc::now() + chrono::Duration::minutes(6);
        let reclaimed = reclaim_stale_guest_claim_with(root.path(), &probe, later)
            .unwrap()
            .unwrap();
        assert_eq!(reclaimed.reason, StaleGuestClaim::OwnerNeverRecorded);
        assert!(!root.path().join(FENCE_DIRECTORY).exists());
    }

    /// A release that cannot remove the claim says so, naming the path, and
    /// leaves a claim the next launch reclaims as one whose release failed.
    #[test]
    fn a_release_that_fails_reports_its_path_and_the_next_launch_reclaims_it() {
        let root = tempfile::tempdir().unwrap();
        let (claim, _) =
            claimed(try_claim_guest_launch_with(root.path(), &HostProcesses, Utc::now()).unwrap());
        // Something the removal cannot take away: a file where the claim
        // directory was, holding this process's own owner record.
        let directory = root.path().join(FENCE_DIRECTORY);
        let owner = fs::read(directory.join(OWNER_FILE)).unwrap();
        fs::remove_dir_all(&directory).unwrap();
        fs::write(&directory, b"not a directory").unwrap();
        assert!(
            remove_claim(&directory).is_err(),
            "the plant must make removal fail"
        );

        let error = claim.release().expect_err("the removal failed");
        assert!(error.to_string().contains(FENCE_DIRECTORY), "{error}");

        fs::remove_file(&directory).unwrap();
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join(OWNER_FILE), owner).unwrap();
        let (_claim, reclaimed) =
            claimed(try_claim_guest_launch_with(root.path(), &HostProcesses, Utc::now()).unwrap());
        assert_eq!(reclaimed.unwrap().reason, StaleGuestClaim::ReleaseFailed);
    }

    #[test]
    fn one_directory_has_exactly_one_owner_and_drop_releases_guest_claim() {
        let root = tempfile::tempdir().unwrap();
        let first = FenceClaim::try_claim(root.path(), FenceOwnerKind::GuestLaunch, None)
            .unwrap()
            .unwrap();
        assert!(
            FenceClaim::try_claim(root.path(), FenceOwnerKind::WindowsRecovery, Some(1))
                .unwrap()
                .is_none()
        );
        drop(first);
        assert!(
            FenceClaim::try_claim(root.path(), FenceOwnerKind::WindowsRecovery, Some(1))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn only_matching_recovery_generation_is_cleared() {
        let root = tempfile::tempdir().unwrap();
        let claim = FenceClaim::try_claim(root.path(), FenceOwnerKind::WindowsRecovery, Some(9))
            .unwrap()
            .unwrap();
        claim.make_durable();
        DrainRequest::new(9, Utc::now()).write(root.path()).unwrap();
        clear_recovery(root.path(), 8).unwrap();
        assert!(root.path().join(FENCE_DIRECTORY).exists());
        assert_eq!(
            DrainRequest::read(root.path()).unwrap().unwrap().generation,
            9
        );
        clear_recovery(root.path(), 9).unwrap();
        assert!(!root.path().join(FENCE_DIRECTORY).exists());
        assert!(!root.path().join(REQUEST_FILE).exists());
    }

    #[test]
    fn retiring_windows_recovery_handles_restarted_generations_but_keeps_guest_claims() {
        let root = tempfile::tempdir().unwrap();
        let claim = FenceClaim::try_claim(root.path(), FenceOwnerKind::WindowsRecovery, Some(7))
            .unwrap()
            .unwrap();
        claim.make_durable();
        DrainRequest::new(8, Utc::now()).write(root.path()).unwrap();
        RecoveryStatus {
            schema_version: SCHEMA_VERSION,
            observed_at: Utc::now(),
            phase: RecoveryPhase::RecoveryBlocked,
            consecutive_probe_failures: 9,
            reason: Some("stale".into()),
            last_recovered_at: None,
        }
        .write(root.path())
        .unwrap();

        retire_windows_recovery(root.path()).unwrap();

        assert!(!root.path().join(FENCE_DIRECTORY).exists());
        assert!(!root.path().join(REQUEST_FILE).exists());
        assert!(!root.path().join(RECOVERY_STATUS_FILE).exists());

        let guest = FenceClaim::try_claim(root.path(), FenceOwnerKind::GuestLaunch, None)
            .unwrap()
            .unwrap();
        guest.make_durable();
        DrainRequest::new(10, Utc::now())
            .write(root.path())
            .unwrap();
        retire_windows_recovery(root.path()).unwrap();
        assert!(root.path().join(FENCE_DIRECTORY).exists());
        assert!(!root.path().join(REQUEST_FILE).exists());
    }

    #[test]
    fn a_restarted_watchdog_retires_only_recovery_nobody_is_still_driving() {
        let root = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let window = std::time::Duration::from_secs(300);
        let old = now - chrono::Duration::minutes(10);
        let claim = FenceClaim::try_claim(root.path(), FenceOwnerKind::WindowsRecovery, Some(1))
            .unwrap()
            .unwrap();
        claim.make_durable();
        let owner_path = root.path().join(FENCE_DIRECTORY).join(OWNER_FILE);
        let backdate_owner = || {
            let mut owner = FenceClaim::owner(root.path()).unwrap().unwrap();
            owner.acquired_at = old;
            write_json(&owner_path, &owner).unwrap();
        };

        // A live watchdog keeps its request fresh: nothing is touched even
        // though the claim itself is old and of another generation.
        backdate_owner();
        DrainRequest::new(2, now - chrono::Duration::seconds(10))
            .write(root.path())
            .unwrap();
        assert!(!retire_abandoned_windows_recovery(root.path(), now, window).unwrap());
        assert!(root.path().join(FENCE_DIRECTORY).exists());

        // The incident: a dead generation's claim and request, WSL healthy.
        DrainRequest::new(2, old).write(root.path()).unwrap();
        assert!(retire_abandoned_windows_recovery(root.path(), now, window).unwrap());
        assert!(!root.path().join(FENCE_DIRECTORY).exists());
        assert!(!root.path().join(REQUEST_FILE).exists());
        assert!(!retire_abandoned_windows_recovery(root.path(), now, window).unwrap());

        // A freshly claimed fence whose request has not been rewritten yet.
        let claim = FenceClaim::try_claim(root.path(), FenceOwnerKind::WindowsRecovery, Some(3))
            .unwrap()
            .unwrap();
        claim.make_durable();
        assert!(!retire_abandoned_windows_recovery(root.path(), now, window).unwrap());
        assert!(root.path().join(FENCE_DIRECTORY).exists());
        remove_claim(&root.path().join(FENCE_DIRECTORY)).unwrap();

        // A guest launch claim is never retired, but an abandoned request is.
        let guest = FenceClaim::try_claim(root.path(), FenceOwnerKind::GuestLaunch, None)
            .unwrap()
            .unwrap();
        guest.make_durable();
        backdate_owner();
        DrainRequest::new(4, old).write(root.path()).unwrap();
        assert!(retire_abandoned_windows_recovery(root.path(), now, window).unwrap());
        assert!(root.path().join(FENCE_DIRECTORY).exists());
        assert!(!root.path().join(REQUEST_FILE).exists());
    }

    #[test]
    fn heartbeat_and_status_documents_replace_atomically() {
        let root = tempfile::tempdir().unwrap();
        let first = GuestHeartbeat {
            schema_version: SCHEMA_VERSION,
            observed_at: Utc::now(),
            acknowledged_generation: None,
            local_active_attempts: Some(1),
            local_busy_attempts: Some(1),
            managed_targets: Vec::new(),
            unmanaged_runner_services: Some(0),
        };
        let mut second = first.clone();
        second.local_active_attempts = Some(0);
        first.write(root.path()).unwrap();
        second.write(root.path()).unwrap();
        assert_eq!(GuestHeartbeat::read(root.path()).unwrap(), Some(second));

        let first = RecoveryStatus {
            schema_version: SCHEMA_VERSION,
            observed_at: Utc::now(),
            phase: RecoveryPhase::Degraded,
            consecutive_probe_failures: 1,
            reason: None,
            last_recovered_at: None,
        };
        let mut second = first.clone();
        second.phase = RecoveryPhase::Healthy;
        first.write(root.path()).unwrap();
        second.write(root.path()).unwrap();
        assert_eq!(RecoveryStatus::read(root.path()).unwrap(), Some(second));
    }
}
