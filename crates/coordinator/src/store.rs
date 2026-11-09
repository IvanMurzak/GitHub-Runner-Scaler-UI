//! The coordinator's SQLite database: enrolled hosts and one-time invites
//! (stage 1), and the job weight statistics (stage 4, schema 2; schema 3 adds
//! each sample's queue wait): measured attempts, all-time counters and the
//! last placement decisions.
//!
//! An invite's code is shown once, to the operator who ran `invite`, and only
//! its SHA-256 is stored. A host's **public** key is stored; its private key
//! never leaves the host.

use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension as _, params};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

const SCHEMA_VERSION: i64 = 5;

/// The prefix every invite code carries, so one is recognisable in a paste.
pub const INVITE_PREFIX: &str = "rmc_";

/// Shortest and longest invite lifetime.
pub const MIN_INVITE_TTL: Duration = Duration::from_secs(60);
pub const MAX_INVITE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("the coordinator database failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("the database was written by a newer coordinator (schema {0})")]
    NewerSchema(i64),
    #[error("no host is named or numbered `{0}`")]
    NoSuchHost(String),
    #[error("`{0}` names more than one host; use its id")]
    Ambiguous(String),
    #[error("an active host is already named `{0}`; revoke it first or pick another name")]
    NameInUse(String),
    #[error("the host name must be 1-64 characters of letters, digits, `.`, `_` or `-`")]
    InvalidName,
    #[error("an invite lives between 1 minute and 7 days")]
    InvalidTtl,
}

/// Why an enrollment was refused. Deliberately one variant for every reason
/// a code is not usable — unknown, spent and expired look the same from
/// outside, so the endpoint cannot be used to probe codes.
#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    #[error("the enrollment code is not valid")]
    InvalidCode,
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// One enrolled host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostRecord {
    pub id: String,
    pub name: String,
    /// What the machine called itself when it enrolled.
    pub hostname: String,
    #[serde(skip)]
    pub public_key: String,
    pub enrolled_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_seen_at: Option<DateTime<Utc>>,
}

impl HostRecord {
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

/// A freshly issued invite. The code exists only in this value.
#[derive(Debug)]
pub struct Invite {
    pub code: SecretString,
    pub name: String,
    pub expires_at: DateTime<Utc>,
}

pub struct Store {
    connection: Connection,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Store")
    }
}

impl Store {
    /// Opens (creating if needed) the database at `path`.
    ///
    /// # Errors
    /// SQLite's, or a schema written by a newer build.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|error| {
                StoreError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
            })?;
        }
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        Self::prepare(connection)
    }

    /// A private in-memory database, for tests.
    ///
    /// # Errors
    /// SQLite's.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::prepare(Connection::open_in_memory()?)
    }

    fn prepare(connection: Connection) -> Result<Self, StoreError> {
        // The admin CLI and the server share the file.
        connection.busy_timeout(Duration::from_secs(5))?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(StoreError::NewerSchema(version));
        }
        if version < 1 {
            connection.execute_batch(
                "CREATE TABLE IF NOT EXISTS hosts (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    enrolled_at TEXT NOT NULL,
                    revoked_at TEXT,
                    last_seen_at TEXT
                );
                CREATE TABLE IF NOT EXISTS invites (
                    code_hash TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    used_at TEXT
                );
                PRAGMA user_version = 1;",
            )?;
        }
        if version < 2 {
            connection.execute_batch(
                "CREATE TABLE IF NOT EXISTS job_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_key TEXT NOT NULL,
                    repository TEXT NOT NULL,
                    host_id TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    duration_secs INTEGER,
                    peak_rss_bytes INTEGER,
                    cpu_avg_millicores INTEGER,
                    cpu_peak_millicores INTEGER
                );
                CREATE INDEX IF NOT EXISTS job_samples_by_key ON job_samples (job_key, id);
                CREATE INDEX IF NOT EXISTS job_samples_by_age ON job_samples (finished_at);
                CREATE TABLE IF NOT EXISTS counters (
                    name TEXT PRIMARY KEY,
                    value INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS placement_decisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    decision TEXT NOT NULL
                );
                PRAGMA user_version = 2;",
            )?;
        }
        if version < 3 {
            // 0.4.47: a sample's queue wait, by GitHub's webhooks. The column
            // may already be there: a rollback to 0.4.46 only lowers
            // `user_version`, and the admin CLI may upgrade the file at the
            // same moment as the server.
            if !has_column(&connection, "job_samples", "queue_wait_secs")?
                && let Err(error) = connection.execute(
                    "ALTER TABLE job_samples ADD COLUMN queue_wait_secs INTEGER",
                    [],
                )
                && !has_column(&connection, "job_samples", "queue_wait_secs")?
            {
                return Err(error.into());
            }
            connection.pragma_update(None, "user_version", 3)?;
        }
        if version < 4 {
            // The server's pending queues and open leases, saved every minute
            // for the admin CLI's `stats`, which runs in another process.
            connection.execute_batch(
                "CREATE TABLE IF NOT EXISTS live_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    saved_at TEXT NOT NULL,
                    state TEXT NOT NULL
                );
                PRAGMA user_version = 4;",
            )?;
        }
        if version < 5 {
            rekey_samples(&connection)?;
            connection.pragma_update(None, "user_version", 5)?;
        }
        Ok(Self { connection })
    }

    /// Issues a one-time code that enrolls one host under `name`.
    ///
    /// # Errors
    /// A bad name or lifetime, a name an active host already holds, SQLite.
    pub fn create_invite(
        &self,
        name: &str,
        ttl: Duration,
        now: DateTime<Utc>,
    ) -> Result<Invite, StoreError> {
        validate_name(name)?;
        if !(MIN_INVITE_TTL..=MAX_INVITE_TTL).contains(&ttl) {
            return Err(StoreError::InvalidTtl);
        }
        if name_taken(&self.connection, name)? {
            return Err(StoreError::NameInUse(name.to_string()));
        }
        let code = SecretString::from(format!(
            "{INVITE_PREFIX}{}",
            hex::encode(rand::random::<[u8; 16]>())
        ));
        let expires_at =
            now + chrono::TimeDelta::from_std(ttl).map_err(|_| StoreError::InvalidTtl)?;
        self.connection.execute(
            "INSERT INTO invites (code_hash, name, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![code_hash(code.expose_secret()), name, now, expires_at],
        )?;
        Ok(Invite {
            code,
            name: name.to_string(),
            expires_at,
        })
    }

    /// Spends `code` once, registering `public_key` as a new host.
    ///
    /// # Errors
    /// [`EnrollError::InvalidCode`] for an unknown, spent or expired code.
    pub fn enroll(
        &mut self,
        code: &str,
        hostname: &str,
        public_key: &str,
        now: DateTime<Utc>,
    ) -> Result<HostRecord, EnrollError> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(StoreError::from)?;
        let hash = code_hash(code.trim());
        let invite: Option<(String, DateTime<Utc>)> = transaction
            .query_row(
                "SELECT name, expires_at FROM invites WHERE code_hash = ?1 AND used_at IS NULL",
                params![hash],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(StoreError::from)?;
        let Some(name) = invite
            .filter(|(_, expires_at)| *expires_at > now)
            .map(|(name, _)| name)
        else {
            return Err(EnrollError::InvalidCode);
        };
        if name_taken(&transaction, &name)? {
            return Err(StoreError::NameInUse(name).into());
        }
        transaction
            .execute(
                "UPDATE invites SET used_at = ?2 WHERE code_hash = ?1",
                params![hash, now],
            )
            .map_err(StoreError::from)?;
        let record = HostRecord {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            hostname: sanitize_hostname(hostname),
            public_key: public_key.to_string(),
            enrolled_at: now,
            revoked_at: None,
            last_seen_at: None,
        };
        transaction
            .execute(
                "INSERT INTO hosts (id, name, hostname, public_key, enrolled_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    record.id,
                    record.name,
                    record.hostname,
                    record.public_key,
                    record.enrolled_at
                ],
            )
            .map_err(StoreError::from)?;
        transaction.commit().map_err(StoreError::from)?;
        Ok(record)
    }

    /// The host with this id, if it exists and is not revoked.
    ///
    /// # Errors
    /// SQLite's.
    pub fn active_host(&self, id: &str) -> Result<Option<HostRecord>, StoreError> {
        Ok(self
            .connection
            .query_row(
                &format!("{SELECT_HOST} WHERE id = ?1 AND revoked_at IS NULL"),
                params![id],
                host_from_row,
            )
            .optional()?)
    }

    /// Every host, enrolled first first.
    ///
    /// # Errors
    /// SQLite's.
    pub fn hosts(&self) -> Result<Vec<HostRecord>, StoreError> {
        let mut statement = self
            .connection
            .prepare(&format!("{SELECT_HOST} ORDER BY enrolled_at, id"))?;
        let rows = statement.query_map([], host_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Revokes the active host with this id or name.
    ///
    /// # Errors
    /// No such active host, a name shared by several, SQLite.
    pub fn revoke(&self, host: &str, now: DateTime<Utc>) -> Result<HostRecord, StoreError> {
        let matching: Vec<HostRecord> = self
            .hosts()?
            .into_iter()
            .filter(|record| record.is_active() && (record.id == host || record.name == host))
            .collect();
        let mut record = match matching.as_slice() {
            [] => return Err(StoreError::NoSuchHost(host.to_string())),
            [one] => one.clone(),
            _ => return Err(StoreError::Ambiguous(host.to_string())),
        };
        self.connection.execute(
            "UPDATE hosts SET revoked_at = ?2 WHERE id = ?1",
            params![record.id, now],
        )?;
        record.revoked_at = Some(now);
        Ok(record)
    }

    /// SQLite's `data_version`: it changes whenever **another** connection
    /// (the admin CLI's) commits to the file, and costs no query. The server
    /// watches it to act on a revocation at once.
    ///
    /// # Errors
    /// SQLite's.
    pub fn data_version(&self) -> Result<i64, StoreError> {
        Ok(self
            .connection
            .pragma_query_value(None, "data_version", |row| row.get(0))?)
    }

    /// Records that the host was heard from.
    ///
    /// # Errors
    /// SQLite's.
    pub fn touch(&self, id: &str, now: DateTime<Utc>) -> Result<(), StoreError> {
        self.connection.execute(
            "UPDATE hosts SET last_seen_at = ?2 WHERE id = ?1",
            params![id, now],
        )?;
        Ok(())
    }
}

/// 0.4.48: a sample's key loses the workflow, which was the run's title: from
/// `owner/repo/title/job` to `owner/repo/job`, so what was measured counts at
/// once. A title and a job name may both hold a `/`, so the split is a best
/// guess: at the last `/` without a space beside it, since GitHub names a
/// reusable workflow's jobs `caller / job`.
fn rekey_samples(connection: &Connection) -> Result<(), StoreError> {
    let rows: Vec<(i64, String, String)> = connection
        .prepare("SELECT id, job_key, repository FROM job_samples")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<_, _>>()?;
    let transaction = connection.unchecked_transaction()?;
    for (id, key, repository) in rows {
        // A key with a workflow is newer than this, seen again after a rollback.
        if key.contains('\u{1f}') {
            continue;
        }
        let Some(rest) = key
            .strip_prefix(&repository)
            .and_then(|rest| rest.strip_prefix('/'))
        else {
            continue;
        };
        let Some(job) = job_after_title(rest) else {
            continue;
        };
        transaction.execute(
            "UPDATE job_samples SET job_key = ?1 WHERE id = ?2",
            params![format!("{repository}/{job}"), id],
        )?;
    }
    transaction.commit()?;
    Ok(())
}

/// The job in `title/job`; `None` when `rest` holds no title (already rekeyed).
fn job_after_title(rest: &str) -> Option<&str> {
    let split = rest.char_indices().rev().find(|(at, c)| {
        *c == '/' && !rest[..*at].ends_with(' ') && !rest[at + 1..].starts_with(' ')
    })?;
    Some(rest[split.0 + 1..].trim())
}

/// Whether `table` has a column named `column`.
fn has_column(connection: &Connection, table: &str, column: &str) -> Result<bool, StoreError> {
    Ok(connection
        .prepare("SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2")?
        .exists(params![table, column])?)
}

/// One measured attempt: a job of `job_key` that ran on `host_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobSample {
    /// `owner/repo/job`, as [`crate::stats::JobIdentity::key`] makes it.
    pub job_key: String,
    /// `owner/repo`, lower-cased.
    pub repository: String,
    pub host_id: String,
    pub finished_at: DateTime<Utc>,
    /// The job's run time by GitHub's webhooks (`started_at` to
    /// `completed_at`), or the host's whole attempt when they did not say.
    pub duration_secs: Option<u64>,
    /// Queued to started, by GitHub's webhooks.
    pub queue_wait_secs: Option<u64>,
    pub peak_rss_bytes: Option<u64>,
    pub cpu_avg_millicores: Option<u32>,
    pub cpu_peak_millicores: Option<u32>,
}

/// The all-time counters `stats` shows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub launches: u64,
    pub wakes: u64,
    pub samples: u64,
}

fn to_sql(value: Option<u64>) -> Option<i64> {
    value.map(|value| i64::try_from(value).unwrap_or(i64::MAX))
}

fn from_sql(value: Option<i64>) -> Option<u64> {
    value.and_then(|value| u64::try_from(value).ok())
}

impl Store {
    /// Records a measured attempt, keeps only the newest `keep` of its job
    /// key, and drops every sample finished before `oldest`.
    ///
    /// # Errors
    /// SQLite's.
    pub fn record_sample(
        &mut self,
        sample: &JobSample,
        keep: u32,
        oldest: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO job_samples (job_key, repository, host_id, finished_at, duration_secs,
                peak_rss_bytes, cpu_avg_millicores, cpu_peak_millicores, queue_wait_secs)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                sample.job_key,
                sample.repository,
                sample.host_id,
                sample.finished_at,
                to_sql(sample.duration_secs),
                to_sql(sample.peak_rss_bytes),
                sample.cpu_avg_millicores,
                sample.cpu_peak_millicores,
                to_sql(sample.queue_wait_secs)
            ],
        )?;
        transaction.execute(
            "DELETE FROM job_samples WHERE job_key = ?1 AND id NOT IN (
                SELECT id FROM job_samples WHERE job_key = ?1 ORDER BY id DESC LIMIT ?2)",
            params![sample.job_key, keep],
        )?;
        transaction.execute(
            "DELETE FROM job_samples WHERE finished_at < ?1",
            params![oldest],
        )?;
        transaction.execute(
            "INSERT INTO counters (name, value) VALUES ('samples', 1)
             ON CONFLICT (name) DO UPDATE SET value = value + 1",
            [],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Every kept sample finished at or after `oldest`, oldest first.
    ///
    /// # Errors
    /// SQLite's.
    pub fn samples(&self, oldest: DateTime<Utc>) -> Result<Vec<JobSample>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT job_key, repository, host_id, finished_at, duration_secs, peak_rss_bytes,
                cpu_avg_millicores, cpu_peak_millicores, queue_wait_secs
             FROM job_samples WHERE finished_at >= ?1 ORDER BY id",
        )?;
        let rows = statement.query_map(params![oldest], |row| {
            Ok(JobSample {
                job_key: row.get(0)?,
                repository: row.get(1)?,
                host_id: row.get(2)?,
                finished_at: row.get(3)?,
                duration_secs: from_sql(row.get(4)?),
                peak_rss_bytes: from_sql(row.get(5)?),
                cpu_avg_millicores: row.get(6)?,
                cpu_peak_millicores: row.get(7)?,
                queue_wait_secs: from_sql(row.get(8)?),
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Adds to the all-time launch and wake counters.
    ///
    /// # Errors
    /// SQLite's.
    pub fn add_counters(&mut self, launches: u64, wakes: u64) -> Result<(), StoreError> {
        let transaction = self.connection.transaction()?;
        for (name, value) in [("launches", launches), ("wakes", wakes)] {
            if value > 0 {
                transaction.execute(
                    "INSERT INTO counters (name, value) VALUES (?1, ?2)
                     ON CONFLICT (name) DO UPDATE SET value = value + ?2",
                    params![name, i64::try_from(value).unwrap_or(i64::MAX)],
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// The all-time counters.
    ///
    /// # Errors
    /// SQLite's.
    pub fn counters(&self) -> Result<Counters, StoreError> {
        let mut statement = self
            .connection
            .prepare("SELECT name, value FROM counters")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut counters = Counters::default();
        for row in rows {
            let (name, value) = row?;
            let value = u64::try_from(value).unwrap_or(0);
            match name.as_str() {
                "launches" => counters.launches = value,
                "wakes" => counters.wakes = value,
                "samples" => counters.samples = value,
                _ => {}
            }
        }
        Ok(counters)
    }

    /// Records a placement decision (its JSON), keeping the newest `keep`.
    ///
    /// # Errors
    /// SQLite's.
    pub fn record_decision(&mut self, decision: &str, keep: u32) -> Result<(), StoreError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO placement_decisions (decision) VALUES (?1)",
            params![decision],
        )?;
        transaction.execute(
            "DELETE FROM placement_decisions WHERE id NOT IN (
                SELECT id FROM placement_decisions ORDER BY id DESC LIMIT ?1)",
            params![keep],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Replaces the saved live placement state (JSON).
    ///
    /// # Errors
    /// SQLite's.
    pub fn save_live_state(&self, state: &str, at: DateTime<Utc>) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO live_state (id, saved_at, state) VALUES (1, ?1, ?2)
             ON CONFLICT (id) DO UPDATE SET saved_at = ?1, state = ?2",
            params![at, state],
        )?;
        Ok(())
    }

    /// The live placement state the server last saved, and when.
    ///
    /// # Errors
    /// SQLite's.
    pub fn live_state(&self) -> Result<Option<(String, DateTime<Utc>)>, StoreError> {
        Ok(self
            .connection
            .query_row(
                "SELECT state, saved_at FROM live_state WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    /// The newest `limit` placement decisions, newest first, as JSON.
    ///
    /// # Errors
    /// SQLite's.
    pub fn decisions(&self, limit: u32) -> Result<Vec<String>, StoreError> {
        let mut statement = self
            .connection
            .prepare("SELECT decision FROM placement_decisions ORDER BY id DESC LIMIT ?1")?;
        let rows = statement.query_map(params![limit], |row| row.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

/// Whether an active (not revoked) host already holds `name`.
fn name_taken(connection: &Connection, name: &str) -> Result<bool, StoreError> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM hosts WHERE name = ?1 AND revoked_at IS NULL)",
        params![name],
        |row| row.get(0),
    )?)
}

const SELECT_HOST: &str =
    "SELECT id, name, hostname, public_key, enrolled_at, revoked_at, last_seen_at FROM hosts";

fn host_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<HostRecord> {
    Ok(HostRecord {
        id: row.get(0)?,
        name: row.get(1)?,
        hostname: row.get(2)?,
        public_key: row.get(3)?,
        enrolled_at: row.get(4)?,
        revoked_at: row.get(5)?,
        last_seen_at: row.get(6)?,
    })
}

fn code_hash(code: &str) -> String {
    hex::encode(Sha256::digest(code.as_bytes()))
}

fn validate_name(name: &str) -> Result<(), StoreError> {
    let valid = (1..=64).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if valid {
        Ok(())
    } else {
        Err(StoreError::InvalidName)
    }
}

/// A host's self-reported name, reduced to something safe to print.
fn sanitize_hostname(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .take(64)
        .collect();
    if cleaned.is_empty() {
        String::from("unknown")
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: Duration = Duration::from_secs(15 * 60);

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-11-07T12:00:00Z")
            .expect("a time")
            .with_timezone(&Utc)
    }

    #[test]
    fn an_invite_enrolls_exactly_one_host() {
        let mut store = Store::open_in_memory().expect("store");
        let invite = store
            .create_invite("linux-big", TTL, now())
            .expect("invite");
        let code = invite.code.expose_secret().to_string();
        assert!(code.starts_with(INVITE_PREFIX));

        let host = store
            .enroll(&code, "box", "PUBKEY", now())
            .expect("first use enrolls");
        assert_eq!(host.name, "linux-big");
        assert_eq!(
            store.active_host(&host.id).expect("read"),
            Some(host.clone())
        );

        assert!(matches!(
            store.enroll(&code, "box2", "OTHER", now()),
            Err(EnrollError::InvalidCode)
        ));
        assert_eq!(store.hosts().expect("hosts").len(), 1);
    }

    #[test]
    fn an_expired_or_unknown_code_is_refused_the_same_way() {
        let mut store = Store::open_in_memory().expect("store");
        let invite = store.create_invite("mac", TTL, now()).expect("invite");
        let later = now() + chrono::TimeDelta::minutes(16);
        assert!(matches!(
            store.enroll(invite.code.expose_secret(), "m", "K", later),
            Err(EnrollError::InvalidCode)
        ));
        assert!(matches!(
            store.enroll("rmc_00000000000000000000000000000000", "m", "K", now()),
            Err(EnrollError::InvalidCode)
        ));
    }

    #[test]
    fn only_the_hash_of_a_code_is_stored() {
        let store = Store::open_in_memory().expect("store");
        let invite = store.create_invite("win", TTL, now()).expect("invite");
        let stored: String = store
            .connection
            .query_row("SELECT code_hash FROM invites", [], |row| row.get(0))
            .expect("one row");
        assert_ne!(stored, invite.code.expose_secret());
        assert!(!stored.contains(invite.code.expose_secret()));
        assert_eq!(stored, code_hash(invite.code.expose_secret()));
    }

    #[test]
    fn a_revoked_host_is_no_longer_active_and_its_name_is_free_again() {
        let mut store = Store::open_in_memory().expect("store");
        let code = store.create_invite("win", TTL, now()).expect("invite").code;
        let host = store
            .enroll(code.expose_secret(), "w", "K", now())
            .expect("enrolled");
        assert!(matches!(
            store.create_invite("win", TTL, now()),
            Err(StoreError::NameInUse(_))
        ));
        let revoked = store.revoke("win", now()).expect("revoked by name");
        assert_eq!(revoked.id, host.id);
        assert_eq!(store.active_host(&host.id).expect("read"), None);
        assert!(matches!(
            store.revoke(&host.id, now()),
            Err(StoreError::NoSuchHost(_))
        ));
        store
            .create_invite("win", TTL, now())
            .expect("name reusable");
    }

    fn sample(key: &str, at: DateTime<Utc>) -> JobSample {
        JobSample {
            job_key: key.into(),
            repository: "octo/app".into(),
            host_id: "h1".into(),
            finished_at: at,
            duration_secs: Some(60),
            queue_wait_secs: Some(7),
            peak_rss_bytes: Some(u64::MAX),
            cpu_avg_millicores: Some(1500),
            cpu_peak_millicores: None,
        }
    }

    #[test]
    fn samples_are_capped_per_key_and_expire_and_counters_add_up() {
        let mut store = Store::open_in_memory().expect("store");
        let long_ago = now() - chrono::TimeDelta::days(200);
        for minute in 0..5 {
            let at = now() + chrono::TimeDelta::minutes(minute);
            store
                .record_sample(&sample("a", at), 3, long_ago)
                .expect("recorded");
        }
        store
            .record_sample(&sample("b", long_ago), 3, long_ago)
            .expect("recorded");
        let kept = store.samples(long_ago).expect("read");
        assert_eq!(kept.iter().filter(|s| s.job_key == "a").count(), 3);
        assert_eq!(kept[0].finished_at, now() + chrono::TimeDelta::minutes(2));
        assert_eq!(kept[0].peak_rss_bytes, Some(i64::MAX as u64), "saturated");
        // The next sample, 90 days on, drops the old one of `b`.
        let cutoff = now() - chrono::TimeDelta::days(90);
        store
            .record_sample(&sample("c", now()), 3, cutoff)
            .expect("recorded");
        let kept = store.samples(long_ago).expect("read");
        assert!(kept.iter().all(|s| s.job_key != "b"));
        assert_eq!(
            store
                .samples(now() + chrono::TimeDelta::days(1))
                .expect("read"),
            vec![]
        );
        store.add_counters(2, 7).expect("counted");
        store.add_counters(1, 0).expect("counted");
        assert_eq!(
            store.counters().expect("read"),
            Counters {
                launches: 3,
                wakes: 7,
                samples: 7,
            }
        );
        for index in 0..5 {
            store
                .record_decision(&format!("{{\"n\":{index}}}"), 2)
                .expect("recorded");
        }
        assert_eq!(store.live_state().expect("read"), None);
        store.save_live_state("{\"a\":1}", now()).expect("saved");
        store.save_live_state("{\"a\":2}", now()).expect("replaced");
        assert_eq!(
            store.live_state().expect("read"),
            Some(("{\"a\":2}".to_string(), now()))
        );
        assert_eq!(
            store.decisions(10).expect("read"),
            vec!["{\"n\":4}".to_string(), "{\"n\":3}".to_string()]
        );
    }

    #[test]
    fn a_stage_one_database_is_upgraded_in_place() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("coordinator.db");
        {
            let connection = Connection::open(&path).expect("open");
            connection
                .execute_batch(
                    "CREATE TABLE hosts (id TEXT PRIMARY KEY, name TEXT NOT NULL,
                        hostname TEXT NOT NULL, public_key TEXT NOT NULL,
                        enrolled_at TEXT NOT NULL, revoked_at TEXT, last_seen_at TEXT);
                     CREATE TABLE invites (code_hash TEXT PRIMARY KEY, name TEXT NOT NULL,
                        created_at TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT);
                     INSERT INTO hosts VALUES ('h1','win','w','K','2026-11-07T12:00:00Z',NULL,NULL);
                     PRAGMA user_version = 1;",
                )
                .expect("a stage-1 database");
        }
        let mut store = Store::open(&path).expect("upgraded");
        assert_eq!(store.hosts().expect("hosts").len(), 1, "hosts kept");
        let oldest = now() - chrono::TimeDelta::days(90);
        store
            .record_sample(&sample("a", now()), 30, oldest)
            .expect("the new tables exist");
        assert_eq!(
            store.samples(oldest).expect("read")[0].queue_wait_secs,
            Some(7)
        );
    }

    /// Samples keyed by a run's title (`load light [1,2] (e4)`) join under the
    /// job's name, whichever title they were measured under.
    #[test]
    fn samples_keyed_by_a_runs_title_are_rekeyed_by_job() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("coordinator.db");
        let oldest = now() - chrono::TimeDelta::days(90);
        {
            let mut store = Store::open(&path).expect("created");
            for key in [
                "octo/app/load light [1,2] (e4b)/light",
                "octo/app/fix/a slash in a title/light",
                "octo/app/CI/caller / build",
                "octo/app/caller / build",
                "octo/app/already",
            ] {
                store
                    .record_sample(&sample(key, now()), 30, oldest)
                    .expect("recorded");
            }
            store
                .connection
                .pragma_update(None, "user_version", 4)
                .expect("a schema-4 database");
        }
        let store = Store::open(&path).expect("upgraded");
        let keys: Vec<String> = store
            .samples(oldest)
            .expect("read")
            .into_iter()
            .map(|sample| sample.job_key)
            .collect();
        assert_eq!(
            keys,
            vec![
                "octo/app/light",
                "octo/app/light",
                "octo/app/caller / build",
                "octo/app/caller / build",
                "octo/app/already",
            ]
        );
    }

    #[test]
    fn a_stage_four_database_gains_the_queue_wait_and_keeps_its_samples() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("coordinator.db");
        let oldest = now() - chrono::TimeDelta::days(90);
        {
            let mut store = Store::open(&path).expect("created");
            store
                .record_sample(&sample("a", now()), 30, oldest)
                .expect("recorded");
            // As 0.4.46 left it: schema 2, no queue wait column.
            store
                .connection
                .execute_batch(
                    "ALTER TABLE job_samples DROP COLUMN queue_wait_secs;
                     PRAGMA user_version = 2;",
                )
                .expect("a schema-2 database");
        }
        let store = Store::open(&path).expect("upgraded");
        let kept = store.samples(oldest).expect("read");
        assert_eq!(kept.len(), 1, "the sample survived");
        assert_eq!(
            (kept[0].duration_secs, kept[0].queue_wait_secs),
            (Some(60), None)
        );
        // Rolled back to 0.4.46 (`user_version = 2`, the column kept), then
        // upgraded again: the column is not added twice.
        store
            .connection
            .pragma_update(None, "user_version", 2)
            .expect("rolled back");
        drop(store);
        let store = Store::open(&path).expect("upgraded again");
        assert_eq!(store.samples(oldest).expect("read").len(), 1);
    }

    #[test]
    fn bad_names_and_lifetimes_are_refused() {
        let store = Store::open_in_memory().expect("store");
        assert!(matches!(
            store.create_invite("has space", TTL, now()),
            Err(StoreError::InvalidName)
        ));
        assert!(matches!(
            store.create_invite("ok", Duration::from_secs(5), now()),
            Err(StoreError::InvalidTtl)
        ));
        assert_eq!(sanitize_hostname("a b\u{1b}[31m"), "ab31m");
    }
}
