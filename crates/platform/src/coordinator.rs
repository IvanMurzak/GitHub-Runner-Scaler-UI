//! Whether this host has joined a coordinator, and how its link is doing.
//!
//! Two small records, one in each direction, like [`crate::polling`]:
//!
//! * **`config/coordinator.toml`** — the coordinator's URL, this host's id
//!   there and the name it was given. Written by `coordinator join`, removed
//!   by `coordinator leave`. Nothing secret: the host's private key lives in
//!   the secret store ([`crate::secrets::SecretItem::CoordinatorKey`]), never
//!   here. An absent file means "not configured", and the daemon then behaves
//!   exactly as it does without a coordinator.
//! * **`state/coordinator-link.toml`** — written by the daemon, read by
//!   `status`, `host doctor` and the TUI, which run in the operator's
//!   terminal while the daemon runs in a service.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::paths::AppPaths;
use crate::service::{ServiceError, read_state_record, remove_state_record, write_state_record};

/// The setting, inside `config/`.
pub const CONFIG_FILE: &str = "coordinator.toml";

/// The daemon's link state, inside `state/`.
pub const LINK_FILE: &str = "coordinator-link.toml";

const CONFIG_SCHEMA_VERSION: u32 = 1;
const LINK_SCHEMA_VERSION: u32 = 1;

/// What `coordinator join` recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatorConfig {
    pub schema_version: u32,
    /// The coordinator's origin, `https://host[:port]`.
    pub url: String,
    /// This host's id at the coordinator.
    pub host_id: String,
    /// The name the coordinator's operator gave this host.
    pub name: String,
    pub joined_at: DateTime<Utc>,
}

impl CoordinatorConfig {
    #[must_use]
    pub const fn new(url: String, host_id: String, name: String, joined_at: DateTime<Utc>) -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            url,
            host_id,
            name,
            joined_at,
        }
    }
}

fn config_path(paths: &AppPaths) -> PathBuf {
    paths.config_dir().join(CONFIG_FILE)
}

fn link_path(paths: &AppPaths) -> PathBuf {
    paths.state_dir().join(LINK_FILE)
}

/// The joined coordinator, or `None` when this host has not joined one.
///
/// # Errors
/// [`ServiceError::Record`] when the file exists and cannot be read.
pub fn configured(paths: &AppPaths) -> Result<Option<CoordinatorConfig>, ServiceError> {
    read_state_record(&config_path(paths))
}

/// Records the joined coordinator.
///
/// # Errors
/// [`ServiceError::Record`] when `config/` cannot be written.
pub fn save(paths: &AppPaths, config: &CoordinatorConfig) -> Result<(), ServiceError> {
    write_state_record(&config_path(paths), config)
}

/// Forgets the coordinator and the daemon's last link state.
///
/// # Errors
/// [`ServiceError::Record`] when either file cannot be removed.
pub fn forget(paths: &AppPaths) -> Result<(), ServiceError> {
    remove_state_record(&config_path(paths))?;
    remove_state_record(&link_path(paths))
}

/// The daemon's link to its coordinator, as it last wrote it.
// `default` on every field: an older or newer CLI must read what the service
// wrote.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LinkRecord {
    pub schema_version: u32,
    pub written_at: DateTime<Utc>,
    pub connected: bool,
    /// Since when the link has been in its current state.
    pub since: Option<DateTime<Utc>>,
    /// Why the link is down, as a fixed word (`unreachable`, `rejected`,
    /// `no_key`, …); never text from the wire.
    pub reason: Option<String>,
    pub last_wake_at: Option<DateTime<Utc>>,
    /// Wakes received since the daemon started.
    pub wakes_received: u64,
    /// How often the coordinator's reconciliation sweep runs, as its last
    /// `hello_ack` said; `None` when it runs none or never said.
    pub reconcile_interval_secs: Option<u32>,
    /// The targets that sweep covers, as `ScaleTarget::slug` writes them
    /// (`owner/repo`, or an organization's login).
    pub covered: Vec<String>,
}

impl LinkRecord {
    #[must_use]
    pub fn new(written_at: DateTime<Utc>) -> Self {
        Self {
            schema_version: LINK_SCHEMA_VERSION,
            written_at,
            ..Self::default()
        }
    }
}

/// Writes the link state.
///
/// # Errors
/// [`ServiceError::Record`] when `state/` cannot be written.
pub fn record_link(paths: &AppPaths, link: &LinkRecord) -> Result<(), ServiceError> {
    write_state_record(&link_path(paths), link)
}

/// The daemon's last link state, or `None` when it never wrote one.
///
/// # Errors
/// [`ServiceError::Record`] when the file exists and cannot be read.
pub fn last_link(paths: &AppPaths) -> Result<Option<LinkRecord>, ServiceError> {
    read_state_record(&link_path(paths))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_setting_and_the_link_round_trip_and_leave_removes_both() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let paths = AppPaths::rooted_at(dir.path());
        assert_eq!(configured(&paths).expect("absent"), None);
        let config = CoordinatorConfig::new(
            "https://runners.example.com".into(),
            "h-1".into(),
            "win-big".into(),
            Utc::now(),
        );
        save(&paths, &config).expect("written");
        assert_eq!(configured(&paths).expect("read"), Some(config));

        let mut link = LinkRecord::new(Utc::now());
        link.connected = true;
        link.wakes_received = 3;
        record_link(&paths, &link).expect("written");
        assert_eq!(last_link(&paths).expect("read"), Some(link));

        forget(&paths).expect("removed");
        assert_eq!(configured(&paths).expect("absent"), None);
        assert_eq!(last_link(&paths).expect("absent"), None);
        forget(&paths).expect("removing nothing is fine");
    }
}
