//! Host memory admission on disk: its setting, what the daemon is waiting for,
//! and the peaks this host measured.
//!
//! * **`config/memory.toml`** holds `host set-memory-margin`: whether admission
//!   is on and its margin. An absent file is the default (on, 1 GiB). A file
//!   rather than a column for the reason `polling.toml` gives: a schema step
//!   makes the database refuse to open under an older build.
//! * **`state/memory-admission.toml`** is written by the daemon whenever a
//!   profile starts or stops waiting for memory, and read by `status`, which
//!   runs in the operator's terminal while the daemon runs as a service.
//! * **`state/memory-peaks.toml`** keeps each profile's newest measured peaks,
//!   the host's own estimate when no coordinator gives one. It survives a
//!   daemon restart so the estimate does not start over.

use std::collections::BTreeMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use runner_manager_domain::memory::{MemoryFigures, MemorySettings};
use serde::{Deserialize, Serialize};

use crate::paths::AppPaths;
use crate::service::{ServiceError, read_state_record, write_state_record};

pub const SETTINGS_FILE: &str = "memory.toml";
pub const STATE_FILE: &str = "memory-admission.toml";
pub const PEAKS_FILE: &str = "memory-peaks.toml";

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Settings {
    schema_version: u32,
    enabled: bool,
    margin_bytes: u64,
}

fn settings_path(paths: &AppPaths) -> PathBuf {
    paths.config_dir().join(SETTINGS_FILE)
}

fn state_path(paths: &AppPaths) -> PathBuf {
    paths.state_dir().join(STATE_FILE)
}

/// Where the measured peaks are kept.
#[must_use]
pub fn peaks_path(paths: &AppPaths) -> PathBuf {
    paths.state_dir().join(PEAKS_FILE)
}

/// The configured setting, or the default when none was set.
///
/// # Errors
/// [`ServiceError::Record`] when the file exists and cannot be read or parsed.
pub fn settings(paths: &AppPaths) -> Result<MemorySettings, ServiceError> {
    Ok(
        read_state_record::<Settings>(&settings_path(paths))?.map_or_else(
            MemorySettings::default,
            |settings| MemorySettings {
                enabled: settings.enabled,
                margin_bytes: settings.margin_bytes,
            },
        ),
    )
}

/// Stores the setting.
///
/// # Errors
/// [`ServiceError::Record`] when `config/` cannot be written.
pub fn set_settings(paths: &AppPaths, settings: MemorySettings) -> Result<(), ServiceError> {
    write_state_record(
        &settings_path(paths),
        &Settings {
            schema_version: SCHEMA_VERSION,
            enabled: settings.enabled,
            margin_bytes: settings.margin_bytes,
        },
    )
}

/// One profile waiting for memory, as `status` shows it.
// `default` on every field: a CLI newer or older than the service's copy of
// the binary must still read what the service wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Waiting {
    pub policy_id: String,
    /// `repo:owner/name` or `org:login`, as `status` names targets.
    pub target: String,
    pub profile: String,
    /// The first refusal of this wait, and the latest.
    pub since: Option<DateTime<Utc>>,
    pub at: Option<DateTime<Utc>>,
    pub free_bytes: u64,
    pub reserved_bytes: u64,
    pub estimate_bytes: u64,
    /// `coordinator`, `local` or `default`.
    pub estimate_source: String,
    pub margin_bytes: u64,
}

impl Waiting {
    /// A wait recorded at `at` from `figures`.
    #[must_use]
    pub fn new(
        (policy_id, target, profile): (String, String, String),
        figures: &MemoryFigures,
        since: DateTime<Utc>,
        at: DateTime<Utc>,
    ) -> Self {
        Self {
            policy_id,
            target,
            profile,
            since: Some(since),
            at: Some(at),
            free_bytes: figures.free,
            reserved_bytes: figures.reserved,
            estimate_bytes: figures.estimate.bytes,
            estimate_source: figures.estimate.source.as_str().to_string(),
            margin_bytes: figures.margin,
        }
    }

    /// What a start needs available: the estimate and the margin.
    #[must_use]
    pub const fn needed_bytes(&self) -> u64 {
        self.estimate_bytes.saturating_add(self.margin_bytes)
    }

    /// What a start can count on: free memory less the reservations.
    #[must_use]
    pub const fn available_bytes(&self) -> u64 {
        self.free_bytes.saturating_sub(self.reserved_bytes)
    }
}

/// What the daemon last wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AdmissionState {
    pub schema_version: u32,
    pub written_at: Option<DateTime<Utc>>,
    pub waiting: Vec<Waiting>,
}

/// Records the profiles waiting for memory.
///
/// # Errors
/// [`ServiceError::Record`] when `state/` cannot be written.
pub fn record_waiting(
    paths: &AppPaths,
    waiting: Vec<Waiting>,
    now: DateTime<Utc>,
) -> Result<(), ServiceError> {
    write_state_record(
        &state_path(paths),
        &AdmissionState {
            schema_version: SCHEMA_VERSION,
            written_at: Some(now),
            waiting,
        },
    )
}

/// What the daemon last recorded; `None` before it ever wrote.
///
/// # Errors
/// [`ServiceError::Record`] when the file exists and cannot be read or parsed.
pub fn last_waiting(paths: &AppPaths) -> Result<Option<AdmissionState>, ServiceError> {
    read_state_record(&state_path(paths))
}

/// Each profile's newest measured peaks, oldest first, keyed by policy id.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Peaks {
    pub schema_version: u32,
    pub policies: BTreeMap<String, Vec<u64>>,
}

/// The measured peaks, empty when none were kept or the file is unreadable:
/// an estimate is a guess either way, and the default stands in.
#[must_use]
pub fn load_peaks(path: &std::path::Path) -> Peaks {
    read_state_record::<Peaks>(path)
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// Stores the measured peaks.
///
/// # Errors
/// [`ServiceError::Record`] when `state/` cannot be written.
pub fn save_peaks(path: &std::path::Path, peaks: &Peaks) -> Result<(), ServiceError> {
    write_state_record(
        path,
        &Peaks {
            schema_version: SCHEMA_VERSION,
            policies: peaks.policies.clone(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use runner_manager_domain::memory::{Estimate, EstimateSource};

    fn paths(dir: &tempfile::TempDir) -> AppPaths {
        AppPaths::rooted_at(dir.path())
    }

    #[test]
    fn the_setting_defaults_to_on_with_a_one_gib_margin_and_round_trips() {
        let dir = tempfile::tempdir().expect("dir");
        let paths = paths(&dir);
        assert_eq!(
            settings(&paths).expect("default"),
            MemorySettings::default()
        );
        assert!(MemorySettings::default().enabled);
        assert_eq!(MemorySettings::default().margin_bytes, 1 << 30);
        let off = MemorySettings {
            enabled: false,
            margin_bytes: 2 << 30,
        };
        set_settings(&paths, off).expect("written");
        assert_eq!(settings(&paths).expect("read"), off);
    }

    #[test]
    fn the_waiting_record_and_the_peaks_round_trip() {
        let dir = tempfile::tempdir().expect("dir");
        let paths = paths(&dir);
        assert_eq!(last_waiting(&paths).expect("absent"), None);
        let figures = MemoryFigures {
            free: 19 << 30,
            reserved: 16 << 30,
            estimate: Estimate {
                bytes: 6 << 30,
                source: EstimateSource::Coordinator,
            },
            margin: 1 << 30,
        };
        let now = Utc::now();
        let waiting = Waiting::new(
            ("p".into(), "repo:o/r".into(), "default".into()),
            &figures,
            now,
            now,
        );
        assert_eq!(waiting.needed_bytes(), 7 << 30);
        assert_eq!(waiting.available_bytes(), 3 << 30);
        record_waiting(&paths, vec![waiting.clone()], now).expect("written");
        let state = last_waiting(&paths).expect("read").expect("present");
        assert_eq!(state.waiting, vec![waiting]);

        let file = peaks_path(&paths);
        assert_eq!(load_peaks(&file), Peaks::default());
        let mut peaks = Peaks::default();
        peaks.policies.insert("p".into(), vec![1, 2, 3]);
        save_peaks(&file, &peaks).expect("written");
        assert_eq!(load_peaks(&file).policies, peaks.policies);
    }
}
