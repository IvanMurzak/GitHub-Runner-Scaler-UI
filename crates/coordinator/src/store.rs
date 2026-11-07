//! The coordinator's SQLite database: enrolled hosts and one-time invites.
//!
//! An invite's code is shown once, to the operator who ran `invite`, and only
//! its SHA-256 is stored. A host's **public** key is stored; its private key
//! never leaves the host. Nothing else is kept in stage 1.

use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension as _, params};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

const SCHEMA_VERSION: i64 = 1;

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
        if self.active_name_taken(name)? {
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
        let invite: Option<(String, DateTime<Utc>)> = transaction
            .query_row(
                "SELECT name, expires_at FROM invites WHERE code_hash = ?1 AND used_at IS NULL",
                params![code_hash(code.trim())],
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
        let taken: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM hosts WHERE name = ?1 AND revoked_at IS NULL)",
                params![name],
                |row| row.get(0),
            )
            .map_err(StoreError::from)?;
        if taken {
            return Err(StoreError::NameInUse(name).into());
        }
        transaction
            .execute(
                "UPDATE invites SET used_at = ?2 WHERE code_hash = ?1",
                params![code_hash(code.trim()), now],
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

    fn active_name_taken(&self, name: &str) -> Result<bool, StoreError> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM hosts WHERE name = ?1 AND revoked_at IS NULL)",
            params![name],
            |row| row.get(0),
        )?)
    }
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
