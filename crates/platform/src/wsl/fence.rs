//! Cross-boundary recovery fence shared by Windows and a managed WSL guest.
//!
//! Windows share locks, Unix `flock`, and SQLite byte-range locks do not
//! interoperate reliably through DrvFS. Directory creation does: exactly one
//! side can create the same directory. The directory is intentionally durable
//! on process death; an abandoned owner blocks recovery instead of allowing a
//! possibly concurrent runner launch.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::discovery::{escaped_name_with_digest, validate_distribution_name};
use crate::paths::AppPaths;
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FenceOwner {
    pub schema_version: u32,
    pub kind: FenceOwnerKind,
    pub generation: Option<u64>,
    pub process_id: u32,
    pub acquired_at: DateTime<Utc>,
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
    fn heartbeat_and_status_documents_replace_atomically() {
        let root = tempfile::tempdir().unwrap();
        let first = GuestHeartbeat {
            schema_version: SCHEMA_VERSION,
            observed_at: Utc::now(),
            acknowledged_generation: None,
            local_active_attempts: Some(1),
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
