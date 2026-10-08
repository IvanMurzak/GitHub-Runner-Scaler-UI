//! The idle poll interval, and what the daemon measured its polling cost.
//!
//! Two small records, one in each direction:
//!
//! * **`config/polling.toml`** holds the idle poll interval
//!   (`host set-poll-interval --idle`). The *active* interval is the existing
//!   `hosts.refresh_interval_secs` column. The idle one lives in a file rather
//!   than a new column on purpose: a schema step makes the database refuse to
//!   open under an older build, and a polling preference is not worth making a
//!   downgrade impossible on every host it reaches. An absent file is the
//!   default.
//! * **`state/poll-traffic.toml`** is written by the daemon and read by
//!   `status`, `host show` and `host doctor`. They run in the operator's
//!   terminal and the daemon runs in a service, so the measurement has to be
//!   on disk, like `github-contact.toml` beside it.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use runner_manager_domain::model::IdlePollInterval;
use serde::{Deserialize, Serialize};

use crate::paths::AppPaths;
use crate::service::{ServiceError, read_state_record, write_state_record};

/// The idle-interval setting, inside `config/`.
pub const SETTINGS_FILE: &str = "polling.toml";

/// The daemon's measurement, inside `state/`.
pub const TRAFFIC_FILE: &str = "poll-traffic.toml";

const SETTINGS_SCHEMA_VERSION: u32 = 1;
const TRAFFIC_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Settings {
    schema_version: u32,
    idle_interval_secs: u16,
}

fn settings_path(paths: &AppPaths) -> PathBuf {
    paths.config_dir().join(SETTINGS_FILE)
}

/// Where the measurement lives.
#[must_use]
pub fn traffic_path(paths: &AppPaths) -> PathBuf {
    paths.state_dir().join(TRAFFIC_FILE)
}

/// The configured idle interval, or the default when none was set.
///
/// # Errors
/// [`ServiceError::Record`] when the file exists and cannot be read, parsed,
/// or holds a value under [`IdlePollInterval::MIN_SECS`]. A hand-edited `1`
/// is refused rather than obeyed, for the reason the floor exists.
pub fn idle_interval(paths: &AppPaths) -> Result<IdlePollInterval, ServiceError> {
    let path = settings_path(paths);
    let Some(settings) = read_state_record::<Settings>(&path)? else {
        return Ok(IdlePollInterval::default());
    };
    IdlePollInterval::from_secs(settings.idle_interval_secs).map_err(|error| ServiceError::Record {
        operation: "read",
        path,
        detail: error.to_string(),
    })
}

/// Store the idle interval.
///
/// # Errors
/// [`ServiceError::Record`] when `config/` cannot be written.
pub fn set_idle_interval(paths: &AppPaths, idle: IdlePollInterval) -> Result<(), ServiceError> {
    write_state_record(
        &settings_path(paths),
        &Settings {
            schema_version: SETTINGS_SCHEMA_VERSION,
            idle_interval_secs: idle.as_secs(),
        },
    )
}

/// What one daemon measured about its own polling, host-wide.
///
/// Every count covers the last hour at most; [`Self::observed_minutes`] says
/// how much of it. The rate-limit fields are the **account's** quota as GitHub
/// last reported it, which every host signed in as the same user shares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollTraffic {
    pub schema_version: u32,
    pub written_at: DateTime<Utc>,
    /// The intervals the daemon is polling at.
    pub idle_interval_secs: u16,
    pub active_interval_secs: u16,
    /// The most severe pace any target loop is running at: `idle`,
    /// `nominal`, or a slowdown (`stretched_low_budget`,
    /// `rate_limited_secondary`, …).
    pub pace: String,
    /// Targets polling at the idle interval, and at any other pace.
    pub targets_idle: u32,
    pub targets_total: u32,
    /// Why polling is slower than configured, when it is.
    pub throttled_because: Option<String>,
    pub observed_minutes: u32,
    /// `2xx` responses: charged against the primary limit.
    pub full: u32,
    /// `304` responses: free against the primary limit.
    pub not_modified: u32,
    /// Error responses: charged, not data.
    pub failed: u32,
    /// This host's busiest minute, every response counted.
    pub peak_requests_per_minute: u32,
    pub rate_limit_limit: Option<u64>,
    pub rate_limit_remaining: Option<u64>,
    pub rate_limit_used: Option<u64>,
    pub rate_limit_reset: Option<DateTime<Utc>>,
    /// Repository readings fetched, and how many of those were all `304`.
    pub demand_reads: u64,
    pub demand_unchanged_reads: u64,
    /// Readings handed to a second target instead of being fetched again.
    pub demand_shared_reads: u64,
    /// Polls withheld inside a rate-limit quiet period.
    pub demand_suppressed: u64,
}

impl PollTraffic {
    /// A record carrying the current schema version; the caller fills the
    /// rest.
    #[must_use]
    pub fn new(written_at: DateTime<Utc>) -> Self {
        Self {
            schema_version: TRAFFIC_SCHEMA_VERSION,
            written_at,
            idle_interval_secs: IdlePollInterval::DEFAULT_SECS,
            active_interval_secs: 0,
            pace: String::from("nominal"),
            targets_idle: 0,
            targets_total: 0,
            throttled_because: None,
            observed_minutes: 0,
            full: 0,
            not_modified: 0,
            failed: 0,
            peak_requests_per_minute: 0,
            rate_limit_limit: None,
            rate_limit_remaining: None,
            rate_limit_used: None,
            rate_limit_reset: None,
            demand_reads: 0,
            demand_unchanged_reads: 0,
            demand_shared_reads: 0,
            demand_suppressed: 0,
        }
    }

    /// Every response counted.
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.full
            .saturating_add(self.not_modified)
            .saturating_add(self.failed)
    }

    /// `count`, scaled from the observed minutes to an hour.
    #[must_use]
    pub fn per_hour(&self, count: u32) -> u32 {
        if self.observed_minutes == 0 {
            return 0;
        }
        u32::try_from(u64::from(count) * 60 / u64::from(self.observed_minutes)).unwrap_or(u32::MAX)
    }

    /// The share of responses that were `304`, in whole percent.
    #[must_use]
    pub fn not_modified_percent(&self) -> Option<u32> {
        let total = self.total();
        (total > 0).then(|| {
            u32::try_from(u64::from(self.not_modified) * 100 / u64::from(total)).unwrap_or(100)
        })
    }

    /// Whether polling is slower than configured.
    #[must_use]
    pub const fn is_throttled(&self) -> bool {
        self.throttled_because.is_some()
    }
}

/// Write the measurement.
///
/// # Errors
/// [`ServiceError::Record`] when `state/` cannot be written.
pub fn record_traffic(paths: &AppPaths, traffic: &PollTraffic) -> Result<(), ServiceError> {
    write_state_record(&traffic_path(paths), traffic)
}

/// The daemon's last measurement, or `None` when no daemon has written one.
///
/// # Errors
/// [`ServiceError::Record`] when the file exists and cannot be read or parsed.
pub fn last_traffic(paths: &AppPaths) -> Result<Option<PollTraffic>, ServiceError> {
    read_state_record(&traffic_path(paths))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> (tempfile::TempDir, AppPaths) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let paths = AppPaths::rooted_at(dir.path());
        (dir, paths)
    }

    #[test]
    fn an_absent_setting_is_the_default_and_a_stored_one_round_trips() {
        let (_dir, paths) = paths();
        assert_eq!(
            idle_interval(&paths).expect("a default"),
            IdlePollInterval::default()
        );
        let five = IdlePollInterval::from_secs(5).expect("the floor");
        set_idle_interval(&paths, five).expect("written");
        assert_eq!(idle_interval(&paths).expect("read back"), five);
    }

    #[test]
    fn a_hand_edited_value_under_the_floor_is_refused() {
        let (_dir, paths) = paths();
        std::fs::create_dir_all(paths.config_dir()).expect("config dir");
        std::fs::write(
            settings_path(&paths),
            "schema_version = 1\nidle_interval_secs = 1\n",
        )
        .expect("written");
        assert!(idle_interval(&paths).is_err());
    }

    #[test]
    fn the_measurement_round_trips() {
        let (_dir, paths) = paths();
        assert_eq!(last_traffic(&paths).expect("nothing yet"), None);
        let mut traffic = PollTraffic::new(Utc::now());
        traffic.full = 3;
        traffic.not_modified = 9;
        traffic.observed_minutes = 30;
        traffic.rate_limit_remaining = Some(4_000);
        record_traffic(&paths, &traffic).expect("written");
        let read = last_traffic(&paths).expect("read").expect("present");
        assert_eq!(read, traffic);
        assert_eq!(read.not_modified_percent(), Some(75));
        assert_eq!(read.per_hour(read.full), 6);
    }
}
