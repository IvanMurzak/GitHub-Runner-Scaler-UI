// owner: b2-sqlite-persistence

//! SQLite persistence for configuration and recovery metadata.
//!
//! This is the only module in this crate that performs I/O, and it is a
//! deliberate exception rather than a loosened rule: everything `b1` owns stays
//! decidable with no network, no filesystem and no clock, and this module is the
//! seam where those decisions are made durable. [`Store`] is a trait for exactly
//! that reason — `b1`'s logic and the `testkit` fixtures remain usable with no
//! database at all, and only the code that genuinely needs durability names
//! [`SqliteStore`].
//!
//! # What is stored, and what is not
//!
//! **No credential of any kind is stored here.** The user access token lives in
//! the machine-scoped secret store (`d2`), and the encoded JIT configuration
//! lives in a restrictive temporary file that is deleted immediately after
//! handoff (`05-infrastructure.md`). There is no column for either, and
//! [`SqliteStore::dump_text`] exists partly so the security gate can prove that
//! against a populated database rather than against this paragraph.
//!
//! # The three guarantees this module is responsible for
//!
//! 1. **Every load re-validates.** A row is never trusted. Policies are rebuilt
//!    through [`ScalePolicy::from_persisted`], which re-runs D19's shape rules
//!    and `min <= max`; attempts through [`RunnerAttempt::from_persisted`], which
//!    re-runs the state/outcome/timestamp pairing; hosts through [`Host::new`]
//!    and [`RefreshInterval::from_secs`]. A hand-edited database therefore cannot
//!    inject a configuration the domain would refuse to construct in memory.
//! 2. **Schema migrations are forward-only and versioned, and an unknown newer
//!    version fails closed.** See [`SCHEMA_VERSION`] and [`MIGRATIONS`].
//! 3. **`ScalePolicy::revision` is an optimistic-concurrency token.**
//!    [`Store::update_policy`] matches on the revision the caller read and
//!    reports [`StoreError::StaleRevision`] when someone else got there first.
//!    That is what stops the TUI and a concurrent CLI invocation from silently
//!    overwriting each other, and it is tested with two real concurrent writers
//!    rather than by reasoning about the transaction.
//!
//! # Where the database lives
//!
//! Nowhere this module decides. [`SqliteStore::open`] takes a path and uses it.
//! Resolving the platform application-data directory is `d1`'s job
//! (`05-infrastructure.md`), and so is creating it: a missing parent directory is
//! reported as [`StoreError::Open`] here rather than silently created, because a
//! store that creates directories can create them in the wrong place.
//!
//! # A note on the two mapping directions
//!
//! [`PersistedPolicy`] and [`PersistedAttempt`] exist so the Rust half of the
//! column mapping is checked by name. Their own documentation points out that
//! the check stops at the field name — `PersistedAttempt { created_at:
//! row.get("last_state_change_at")?, .. }` still compiles. This module closes
//! that gap from both ends: every write binds by name with `:column`, every read
//! reads by name with `row.get("column")`, so the column name sits literally
//! beside the field name at each of the two crossings, and
//! `tests::every_column_lands_in_the_field_of_the_same_name` loads a row of
//! deliberately distinguishable values and asserts each landed where its name
//! says it did.

use std::fmt;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use rusqlite::types::{Value, ValueRef};
use rusqlite::{Connection, OptionalExtension, Row, ToSql, TransactionBehavior, named_params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use uuid::Uuid;

use crate::attempt::{AttemptError, AttemptOutcome, AttemptState, PersistedAttempt, RunnerAttempt};
use crate::model::{
    Arch, AttemptId, CachePolicy, Clock, Host, HostId, Os, PolicyId, RefreshInterval, ScaleTarget,
    StartMode, SystemClock, TargetScope, Timestamp, ValidationError,
};
use crate::policy::{PersistedPolicy, PolicyError, PolicyState, RoutingLabels, ScalePolicy};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything that can go wrong between a domain value and a database row.
///
/// The variants are split the way a *caller* has to branch, not the way the
/// implementation happens to fail. In particular [`StoreError::StaleRevision`] is
/// its own variant rather than a flavour of [`StoreError::Sqlite`], because a
/// concurrent edit is an ordinary outcome the CLI and the TUI must report as
/// "someone else changed this; re-read and try again", while an I/O failure is
/// not. [`StoreError::is_conflict`] is the predicate for that branch.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database file could not be opened. The parent directory belongs to
    /// `d1`; this module never creates it.
    #[error("the database at {path} could not be opened: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },

    /// Any other SQLite failure: a real I/O error, a locked database, a
    /// malformed file.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),

    /// The database was written by a newer build of this product.
    ///
    /// This fails closed on purpose. A newer version may have added a column
    /// this build does not write — which this build would then drop on its next
    /// write — or changed the meaning of one it does. Guessing is how a
    /// downgrade silently corrupts a configuration.
    #[error(
        "this database is at schema version {found}, but this build of \
         runner-manager understands version {supported}; upgrade runner-manager \
         rather than running it against a database from a newer version"
    )]
    SchemaTooNew { found: u32, supported: u32 },

    /// A migration did not apply. The transaction around it rolled back, so the
    /// database is still at the previous version.
    #[error("schema migration {version} ({name}) failed and was rolled back: {source}")]
    Migration {
        version: u32,
        name: &'static str,
        #[source]
        source: rusqlite::Error,
    },

    /// A write lost an optimistic-concurrency race. **Nothing was written.**
    ///
    /// The caller must re-read the policy and re-apply its change; it must not
    /// retry the value it holds, because that value was derived from a revision
    /// that no longer exists.
    #[error(
        "policy {id} was written against revision {expected}, but the stored \
         revision is now {found}; another process changed it first and nothing \
         was written"
    )]
    StaleRevision {
        id: PolicyId,
        expected: u64,
        found: u64,
    },

    /// The row a write was aimed at is not there.
    #[error("no {what} with id {id} is in the database")]
    NotFound { what: &'static str, id: String },

    /// An insert collided with an existing primary key.
    #[error("a {what} with id {id} is already in the database")]
    AlreadyExists { what: &'static str, id: String },

    /// A stored policy is not a legal policy. This is the hand-edited-database
    /// case: D19's shape rules and `min <= max` are re-run on every load.
    #[error("the stored policy {id} is not a legal policy: {source}")]
    CorruptPolicy {
        id: PolicyId,
        #[source]
        source: PolicyError,
    },

    /// A stored attempt is not a legal attempt: its state, outcome and
    /// timestamps do not pair the way this crate's own transitions pair them.
    #[error("the stored attempt {id} is not a legal attempt: {source}")]
    CorruptAttempt {
        id: AttemptId,
        #[source]
        source: AttemptError,
    },

    /// A stored host does not satisfy a domain constraint — a blank display
    /// name, or a refresh interval under the documented floor.
    #[error("the stored host {id} is not a legal host: {source}")]
    CorruptHost {
        id: HostId,
        #[source]
        source: ValidationError,
    },

    /// One column holds something that is not the kind of value it is declared
    /// to hold. The row is named so an operator can find and fix it.
    ///
    /// **`value` never repeats the whole payload, and how much it repeats
    /// depends on which column this is.** The row id is what an operator needs
    /// to find the row; the payload only helps them recognise it, and repeating
    /// all of it turns this error into a disclosure the moment it reaches a log.
    ///
    /// `table` and `column` are carried for the operator's sake and are also
    /// what decides the echo: a column whose shape the schema fixes gets a
    /// clipped echo of at most [`ECHO_LIMIT`] characters, and one that may hold
    /// text a caller chose gets position only, with none of the payload. The
    /// rule and the measurement behind it are on `FREE_FORM_COLUMNS`, beside the
    /// decoder that applies it. (Named rather than linked: it is private, and a
    /// link from here would not resolve for a reader of the public docs.)
    #[error("{table}.{column} of row {id} holds {value}, which is not {expected}")]
    CorruptColumn {
        table: &'static str,
        column: &'static str,
        id: String,
        /// At most [`ECHO_LIMIT`] characters of the offending payload for a
        /// constrained column, and none of it for a free-form one.
        value: String,
        expected: &'static str,
    },

    /// An integer that does not fit in a SQLite integer.
    ///
    /// SQLite has no unsigned 64-bit type, so a `u64` above `i64::MAX` has no
    /// representation. Refused rather than saturated: saturating stores one
    /// number and reads a different one back, silently, and the two values the
    /// domain carries as `u64` -- `installation_id` and `github_runner_id` --
    /// both come from GitHub, so a caller can reach this without doing anything
    /// unusual.
    #[error(
        "{what} is {value}, which does not fit in a SQLite integer; SQLite \
         integers are signed 64-bit and this store will not silently truncate one"
    )]
    UnrepresentableInteger { what: &'static str, value: u64 },

    /// A runtime path that is not valid UTF-8 and therefore cannot be stored as
    /// text.
    ///
    /// Lossy conversion is deliberately **not** used: `e3` deletes the runtime
    /// directory this path names, and a path mangled by U+FFFD substitution
    /// either fails to delete or names a different directory.
    #[error("attempt {attempt} has a runtime path that is not valid UTF-8: {path:?}")]
    UnrepresentablePath { attempt: AttemptId, path: PathBuf },
}

impl StoreError {
    /// Whether this is an optimistic-concurrency conflict rather than a failure.
    ///
    /// The Definition of Done requires that "a stale-`revision` write is rejected
    /// and the caller can distinguish it from an I/O error". This is that
    /// distinction, exposed so a caller need not match on the variant shape to
    /// make it.
    #[must_use]
    pub const fn is_conflict(&self) -> bool {
        matches!(self, StoreError::StaleRevision { .. })
    }
}

// ---------------------------------------------------------------------------
// Schema and migrations
// ---------------------------------------------------------------------------

/// One forward-only schema step.
#[derive(Debug, Clone, Copy)]
struct Migration {
    version: u32,
    name: &'static str,
    sql: &'static str,
}

/// The ordered, forward-only migration chain.
///
/// **There is exactly one entry today, and that is a fact about the product's
/// age rather than about this mechanism.** Nothing has shipped, so no database
/// exists at an older shape and there is no second step to write; splitting the
/// initial schema in two so the chain "looks like" a chain would be ceremony
/// that tests nothing. The runner, [`apply_migrations`], is written and tested as
/// a general one: its multi-step behaviour is exercised against a synthetic chain
/// in `tests::a_database_one_version_behind_gets_only_the_missing_step`, which is
/// the honest way to test a property the production chain cannot yet exhibit.
///
/// Adding a step means adding a numbered `.sql` file beside this module and one
/// entry here. It never means editing an applied file; see the header of
/// `store/migrations/0001_initial_schema.sql`.
const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "initial_schema",
    sql: include_str!("store/migrations/0001_initial_schema.sql"),
}];

/// The schema version this build writes and understands.
///
/// A database above this is refused with [`StoreError::SchemaTooNew`]; a database
/// below it is migrated up on open. Both directions are decided from the
/// `schema_migrations` table, which records every applied step and when.
pub const SCHEMA_VERSION: u32 = 1;

/// Created outside the numbered chain, because the chain needs somewhere to
/// record itself before its first step runs.
const BOOTSTRAP_SQL: &str = "\
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER NOT NULL PRIMARY KEY,
    name       TEXT    NOT NULL,
    applied_at TEXT    NOT NULL
) STRICT;";

/// Every table this module reads, in the order [`SqliteStore::dump_text`] prints
/// them.
const TABLES: &[&str] = &["schema_migrations", "hosts", "policies", "attempts"];

fn current_version(conn: &Connection) -> Result<u32, StoreError> {
    let max: Option<i64> =
        conn.query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })?;
    // A negative recorded version is corrupted bookkeeping, and it is reported
    // as that. Both directions of the old `unwrap_or(u32::MAX)` were wrong in
    // the same way: it did fail closed, which is right, but it failed closed
    // saying "this database is at schema version 4294967295", which is a number
    // no database has ever been at. The operator's next move is to look at
    // `schema_migrations`, and this says so.
    match max {
        None => Ok(0),
        Some(raw) => u32::try_from(raw).map_err(|_| StoreError::CorruptColumn {
            table: "schema_migrations",
            column: "version",
            id: raw.to_string(),
            value: clip(&raw.to_string()),
            expected: "a schema version this build could have written",
        }),
    }
}

/// Apply every step in `migrations` this database has not seen, in order.
///
/// Each step runs inside its own immediate transaction *together with* the row
/// that records it, so a step that fails leaves the database at the previous
/// version rather than half-migrated behind a version number claiming otherwise.
fn apply_migrations(
    conn: &mut Connection,
    migrations: &[Migration],
    clock: &dyn Clock,
) -> Result<u32, StoreError> {
    conn.execute_batch(BOOTSTRAP_SQL)?;

    let supported = migrations.last().map_or(0, |m| m.version);
    let found = current_version(conn)?;
    if found > supported {
        return Err(StoreError::SchemaTooNew { found, supported });
    }

    for migration in migrations.iter().filter(|m| m.version > found) {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = |source| StoreError::Migration {
            version: migration.version,
            name: migration.name,
            source,
        };
        tx.execute_batch(migration.sql).map_err(record)?;
        tx.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) \
             VALUES (:version, :name, :applied_at)",
            named_params! {
                ":version": i64::from(migration.version),
                ":name": migration.name,
                ":applied_at": timestamp_to_text(clock.now()),
            },
        )
        .map_err(record)?;
        tx.commit()?;
    }

    Ok(supported)
}

// ---------------------------------------------------------------------------
// The store trait
// ---------------------------------------------------------------------------

/// Durable storage for the three things that must survive a restart.
///
/// A trait rather than a concrete type so that `b1`'s logic and the `testkit`
/// fixtures stay usable with no database — a capacity calculation or a recovery
/// decision needs neither a file nor this trait — and so that a caller can be
/// written against storage without being written against SQLite.
///
/// `Send + Sync` because the agent holds one of these across tasks while the TUI
/// reads through the same handle. [`SqliteStore`] earns it with an internal
/// mutex; a test double should do the same rather than being `!Sync` and forcing
/// every caller to change shape.
pub trait Store: fmt::Debug + Send + Sync {
    /// Insert or replace this host.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`] on an I/O failure.
    fn put_host(&self, host: &Host) -> Result<(), StoreError>;

    /// One host, re-validated.
    ///
    /// # Errors
    /// [`StoreError::CorruptHost`] or [`StoreError::CorruptColumn`] for a row the
    /// domain refuses.
    fn host(&self, id: HostId) -> Result<Option<Host>, StoreError>;

    /// Every host, re-validated.
    ///
    /// # Errors
    /// As [`Store::host`].
    fn hosts(&self) -> Result<Vec<Host>, StoreError>;

    /// Add a policy that is not there yet.
    ///
    /// # Errors
    /// [`StoreError::AlreadyExists`] when the id is taken. Use
    /// [`Store::update_policy`] to change an existing policy: this call carries
    /// no revision check because there is no previous revision to check against.
    fn insert_policy(&self, policy: &ScalePolicy) -> Result<(), StoreError>;

    /// Write a changed policy, but only if nobody else changed it first.
    ///
    /// `expected_revision` is the revision the caller **read**, not the one the
    /// policy now carries: every successful domain mutation advances
    /// [`ScalePolicy::revision`], so a caller that loaded revision 3 and called
    /// `set_max_capacity` holds revision 4 and passes 3 here. The write matches
    /// on 3 and stores 4.
    ///
    /// # Errors
    /// [`StoreError::StaleRevision`] when the stored revision is not
    /// `expected_revision` — nothing is written, and the caller must re-read
    /// rather than retry — or [`StoreError::NotFound`] when the row is gone.
    fn update_policy(&self, policy: &ScalePolicy, expected_revision: u64)
    -> Result<(), StoreError>;

    /// Delete a policy, subject to the same revision check as a write.
    ///
    /// Deleting is a mutation like any other and races the same way: an operator
    /// removing a repository while the TUI enables it must not silently win.
    ///
    /// Attempts belonging to the policy are deliberately left in place; see the
    /// note on `attempts.policy_id` in the schema.
    ///
    /// # Errors
    /// As [`Store::update_policy`].
    fn remove_policy(&self, id: PolicyId, expected_revision: u64) -> Result<(), StoreError>;

    /// One policy, re-validated.
    ///
    /// # Errors
    /// [`StoreError::CorruptPolicy`] for a row violating D19's shape or
    /// `min <= max`; [`StoreError::CorruptColumn`] for an unreadable column.
    fn policy(&self, id: PolicyId) -> Result<Option<ScalePolicy>, StoreError>;

    /// Every policy, re-validated.
    ///
    /// # Errors
    /// As [`Store::policy`]. One corrupt row fails the whole call rather than
    /// being skipped: a silently short policy list is a host that quietly stops
    /// serving a repository, which is the failure nobody notices.
    fn policies(&self) -> Result<Vec<ScalePolicy>, StoreError>;

    /// Journal an attempt, inserting it or updating it in place.
    ///
    /// The journal has one writer — the agent holds the single-instance lock
    /// (`05-infrastructure.md`) — so there is no revision token here. `created_at`
    /// is written once at insert and is never overwritten by a later call, which
    /// is the storage half of the domain's "`created_at` never moves".
    ///
    /// # Errors
    /// [`StoreError::UnrepresentablePath`] for a non-UTF-8 runtime path,
    /// otherwise [`StoreError::Sqlite`].
    fn record_attempt(&self, attempt: &RunnerAttempt) -> Result<(), StoreError>;

    /// One attempt, re-validated.
    ///
    /// # Errors
    /// [`StoreError::CorruptAttempt`] for a state/outcome/timestamp combination
    /// this crate's transitions cannot produce.
    fn attempt(&self, id: AttemptId) -> Result<Option<RunnerAttempt>, StoreError>;

    /// Every attempt, oldest first. This is the input to `e3`'s startup
    /// recovery.
    ///
    /// # Errors
    /// As [`Store::attempt`].
    fn attempts(&self) -> Result<Vec<RunnerAttempt>, StoreError>;

    /// Every attempt of one policy, oldest first.
    ///
    /// # Errors
    /// As [`Store::attempt`].
    fn attempts_for_policy(&self, policy_id: PolicyId) -> Result<Vec<RunnerAttempt>, StoreError>;

    /// Forget one attempt. Returns whether a row was removed.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`] on an I/O failure.
    fn remove_attempt(&self, id: AttemptId) -> Result<bool, StoreError>;
}

// ---------------------------------------------------------------------------
// The rusqlite implementation
// ---------------------------------------------------------------------------

/// The rusqlite-backed [`Store`].
///
/// One connection behind a mutex. SQLite serialises writers anyway, so a
/// connection pool would buy concurrency the database does not offer; what the
/// mutex buys is `Sync`, so the agent can hold one handle across tasks.
///
/// Opened with `synchronous = FULL` and a request for WAL. `FULL` because this
/// journal exists precisely to survive an unclean stop: a handful of fsyncs per
/// runner attempt is not a cost worth trading for the chance of losing the last
/// write before a power cut. WAL so that a reader — the TUI — does not block the
/// agent's journal writes.
///
/// **The WAL half is a request, not a guarantee**, which is why
/// [`Self::journal_mode`] exists to report what actually happened. SQLite falls
/// back to `delete` where the directory cannot host WAL's shared-memory file,
/// and says so in the pragma's return row rather than by failing.
pub struct SqliteStore {
    conn: Mutex<Connection>,
    path: Option<PathBuf>,
    schema_version: u32,
    /// The journal mode this database actually ended up in, as SQLite reported
    /// it. Not necessarily `wal`; see [`SqliteStore::journal_mode`].
    journal_mode: String,
    clock_skew_repairs: AtomicU64,
}

impl fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteStore")
            .field("path", &self.path)
            .field("schema_version", &self.schema_version)
            .field("journal_mode", &self.journal_mode)
            .field(
                "clock_skew_repairs",
                &self.clock_skew_repairs.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl SqliteStore {
    /// Open (or create) the database at `path` and migrate it to
    /// [`SCHEMA_VERSION`].
    ///
    /// The path is used exactly as given. Resolving the platform
    /// application-data directory and creating it is `d1`'s job; a missing parent
    /// directory is reported rather than created.
    ///
    /// # Errors
    /// [`StoreError::Open`] when the file cannot be opened,
    /// [`StoreError::SchemaTooNew`] when the database came from a newer build,
    /// [`StoreError::Migration`] when a step fails.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        let conn = Connection::open(path).map_err(|source| StoreError::Open {
            path: path.to_path_buf(),
            source,
        })?;
        Self::with_migrations(conn, Some(path.to_path_buf()), MIGRATIONS)
    }

    /// An anonymous in-memory database, migrated to [`SCHEMA_VERSION`].
    ///
    /// For tests and for a dry run. It is private to this one connection — a
    /// second `open_in_memory` is a different database — so it cannot stand in
    /// for a file store in a test about two concurrent writers.
    ///
    /// # Errors
    /// As [`SqliteStore::open`].
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory().map_err(|source| StoreError::Open {
            path: PathBuf::from(":memory:"),
            source,
        })?;
        Self::with_migrations(conn, None, MIGRATIONS)
    }

    fn with_migrations(
        mut conn: Connection,
        path: Option<PathBuf>,
        migrations: &[Migration],
    ) -> Result<Self, StoreError> {
        // A row-returning pragma, so it cannot go through `execute`, and the row
        // it returns is the mode the database **ended up in** rather than the
        // one that was asked for. Discarding it was a real gap: where WAL is
        // unavailable -- it needs shared memory, which a network-mounted
        // application data directory or some container `/tmp` does not provide
        // -- SQLite quietly leaves the database in `delete` and says so in this
        // row. Two things then went wrong at once. This type's own
        // documentation promises "WAL so that a reader -- the TUI -- does not
        // block the agent's journal writes", and that promise silently stopped
        // holding in production with nothing anywhere to say so; and the `-wal`
        // assertion in `tests/store_journal.rs` failed on an otherwise healthy
        // build without explaining why.
        //
        // Recorded and warned about rather than refused. The journal is still
        // *correct* in `delete` mode, only less concurrent, and an operator
        // whose application data directory sits on a network mount wants a
        // working agent more than a principled refusal to start. The fact is
        // exposed through `SqliteStore::journal_mode` so a test can ask instead
        // of assuming and an operator can see it in a support bundle. An
        // in-memory database answers `memory`, which is correct and exempt.
        let journal_mode: String =
            conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if path.is_some() && !journal_mode.eq_ignore_ascii_case("wal") {
            tracing::warn!(
                path = ?path,
                journal_mode = %journal_mode,
                "this database did not enter WAL mode, so a reader will block \
                 the agent's journal writes. The usual cause is a directory \
                 that cannot host WAL's shared-memory file, such as a network \
                 mount."
            );
        }
        conn.pragma_update(None, "synchronous", "FULL")?;
        // Two processes will contend (the TUI and a CLI invocation), and the
        // loser of a write lock should wait briefly rather than fail: a
        // `database is locked` error surfaced to an operator who did nothing
        // wrong is indistinguishable from a bug. It is also what makes the
        // stale-revision answer deterministic instead of racing SQLITE_BUSY.
        conn.busy_timeout(Duration::from_secs(5))?;
        // No foreign key exists today (see the schema), but this is a
        // per-connection setting that silently defaults to off, so setting it
        // here is what would make a future migration's key actually enforced.
        conn.pragma_update(None, "foreign_keys", true)?;

        // `applied_at` is an audit stamp, not a decision input, which is why the
        // production clock is acceptable here and nowhere else in this crate.
        let schema_version = apply_migrations(&mut conn, migrations, &SystemClock)?;

        Ok(Self {
            conn: Mutex::new(conn),
            path,
            schema_version,
            journal_mode,
            clock_skew_repairs: AtomicU64::new(0),
        })
    }

    /// The schema version this database is at.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// The journal mode this database is actually in, lowercased by SQLite.
    ///
    /// `wal` for a healthy file store, `memory` for an in-memory one, and
    /// something else — `delete`, usually — where the directory cannot host
    /// WAL's shared-memory file. That last case is not a failure but it does
    /// mean a reader blocks the agent's journal writes, so it is worth showing
    /// an operator rather than assuming.
    #[must_use]
    pub fn journal_mode(&self) -> &str {
        &self.journal_mode
    }

    /// Whether a reader can read this database without blocking the agent's
    /// writes.
    ///
    /// True exactly when [`Self::journal_mode`] is `wal`. An in-memory store is
    /// **not** included: it is private to one connection, so the question does
    /// not arise for it.
    #[must_use]
    pub fn readers_do_not_block_writers(&self) -> bool {
        self.journal_mode.eq_ignore_ascii_case("wal")
    }

    /// The path this store was opened from, or `None` for an in-memory one.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// How many attempt timestamps this store has repaired for backwards clock
    /// movement since it was opened.
    ///
    /// See [`SqliteStore::normalise`] for what is repaired and why. A non-zero
    /// value means this machine's clock stepped backwards while an attempt was in
    /// flight; each repair is also logged at `warn`.
    #[must_use]
    pub fn clock_skew_repairs(&self) -> u64 {
        self.clock_skew_repairs.load(Ordering::Relaxed)
    }

    /// Every row of every table, as text, in a deterministic order.
    ///
    /// Two callers. An operator support bundle, and the security gate: the
    /// Definition of Done requires that "a grep of every fixture database and its
    /// dump finds no token-shaped value", and a dump produced here is a testable
    /// artifact where a `sqlite3 .dump` invocation in a shell script is not.
    ///
    /// This is safe to attach to a bug report **because no column carries a
    /// credential**, not because anything here redacts one. If a column ever
    /// does, this function becomes a disclosure and the schema is what has to
    /// change.
    ///
    /// # Errors
    /// [`StoreError::Sqlite`] on an I/O failure.
    pub fn dump_text(&self) -> Result<String, StoreError> {
        use std::fmt::Write as _;

        let conn = self.lock();
        let mut out = String::new();
        let _ = writeln!(out, "-- schema version {}", self.schema_version);
        for table in TABLES {
            let _ = writeln!(out, "-- table {table}");
            let mut stmt = conn.prepare(&format!("SELECT * FROM \"{table}\""))?;
            let columns: Vec<String> = stmt.column_names().into_iter().map(String::from).collect();
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                for (index, column) in columns.iter().enumerate() {
                    if index > 0 {
                        out.push_str(", ");
                    }
                    let _ = write!(out, "{table}.{column}={}", render(row.get_ref(index)?));
                }
                out.push('\n');
            }
        }
        Ok(out)
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        // A panicking writer cannot leave SQLite half-written: every write here
        // runs inside a statement or a transaction whose guard rolls back on
        // drop. So the poison flag says a Rust caller panicked, not that the
        // database is inconsistent, and refusing to serve the database over it
        // would turn one panic into a permanently unusable installation.
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Repair a persisted attempt whose timestamps run backwards, and say so.
    ///
    /// **The hazard.** [`RunnerAttempt`]'s in-memory transitions accept any `now`
    /// with no ordering check, while [`RunnerAttempt::from_persisted`] refuses
    /// `last_state_change_at < created_at` and `terminal_at < created_at`. So the
    /// domain can build in memory a value its own loader will not accept. The
    /// realistic trigger is not a hand-edited row: it is the wall clock stepping
    /// backwards between two transitions — an NTP correction, a VM snapshot
    /// restore, or an operator changing the clock on the home PC this product
    /// targets.
    ///
    /// **Why this clamps rather than rejecting or quarantining.** Rejecting
    /// leaves a row that neither this store nor the agent can ever load again;
    /// the attempt's capacity slot goes with it, its runtime directory is never
    /// cleaned, and there is no repair path short of an operator editing SQLite
    /// by hand. Quarantining preserves the evidence but has the same operational
    /// effect — the attempt becomes invisible to recovery, so a live child
    /// process goes unsupervised. Clamping costs one bounded thing: a recovery
    /// timeout measured from `created_at` rather than from a slightly earlier
    /// instant, which errs towards concluding a stuck attempt and giving its slot
    /// back, never towards holding it.
    ///
    /// **It is applied on the way in as well as on the way out.** Repairing only
    /// on load would still write the unloadable row, and the next reader — a
    /// different build, a different tool, an operator's `sqlite3` — would have to
    /// know about this function to make sense of it. Repairing on write keeps the
    /// database self-consistent; repairing on load handles rows this build did
    /// not write.
    ///
    /// **The clean fix is upstream and is not `b2`'s to make.** If
    /// `RunnerAttempt::move_to` and `::conclude` clamped `now` to at least
    /// `created_at`, the out-of-order value could not exist in memory at all and
    /// `from_persisted`'s strictness would be exactly right with nothing here to
    /// compensate for it. That is a change to `crates/domain/src/attempt.rs`,
    /// which `b1` owns; it is reported rather than worked around silently, and
    /// this is the defensive measure in the meantime.
    fn normalise(&self, mut fields: PersistedAttempt) -> PersistedAttempt {
        if fields.last_state_change_at < fields.created_at {
            tracing::warn!(
                attempt = %fields.id,
                created_at = %fields.created_at,
                last_state_change_at = %fields.last_state_change_at,
                "attempt last_state_change_at precedes created_at; the host clock \
                 stepped backwards. Clamping to created_at so the attempt stays \
                 recoverable; its recovery timeouts now measure from allocation."
            );
            fields.last_state_change_at = fields.created_at;
            self.clock_skew_repairs.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(terminal_at) = fields.terminal_at
            && terminal_at < fields.created_at
        {
            tracing::warn!(
                attempt = %fields.id,
                created_at = %fields.created_at,
                terminal_at = %terminal_at,
                "attempt terminal_at precedes created_at; the host clock stepped \
                 backwards. Clamping to created_at."
            );
            fields.terminal_at = Some(fields.created_at);
            self.clock_skew_repairs.fetch_add(1, Ordering::Relaxed);
        }
        fields
    }

    fn attempt_from_row(&self, row: &Row<'_>) -> Result<RunnerAttempt, StoreError> {
        let fields = self.normalise(persisted_attempt_from_row(row)?);
        let id = fields.id;
        RunnerAttempt::from_persisted(fields)
            .map_err(|source| StoreError::CorruptAttempt { id, source })
    }
}

impl Store for SqliteStore {
    fn put_host(&self, host: &Host) -> Result<(), StoreError> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO hosts (
                 id, display_name, os, architecture, host_capacity,
                 service_start_mode, refresh_interval_secs, created_at
             ) VALUES (
                 :id, :display_name, :os, :architecture, :host_capacity,
                 :service_start_mode, :refresh_interval_secs, :created_at
             )
             ON CONFLICT(id) DO UPDATE SET
                 display_name          = excluded.display_name,
                 os                    = excluded.os,
                 architecture          = excluded.architecture,
                 host_capacity         = excluded.host_capacity,
                 service_start_mode    = excluded.service_start_mode,
                 refresh_interval_secs = excluded.refresh_interval_secs,
                 created_at            = excluded.created_at",
            // `created_at` **is** in this DO UPDATE list, and `record_attempt`
            // deliberately leaves it out of its own. The asymmetry is intended
            // and the two columns are not the same kind of thing.
            //
            // An attempt's `created_at` is a domain fact with a rule attached:
            // "created_at never moves", enforced by
            // `RunnerAttempt::from_persisted`, which refuses a row whose other
            // timestamps precede it. Journal writes happen repeatedly over one
            // attempt's life, so excluding the column is what keeps the value
            // written at allocation authoritative.
            //
            // A host's `created_at` is the record of when this host was
            // registered, and `put_host` is a whole-record upsert of a value the
            // caller assembled -- there is no partial-update path and no
            // ordering rule against it. Writing back what the caller holds keeps
            // the row equal to the `Host` it was given, which is what
            // `a_host_round_trips_byte_identically_in_every_configuration`
            // asserts. Excluding it would silently discard a correction an
            // operator made on purpose.
            named_params! {
                ":id": uuid_text(host.id.as_uuid()),
                ":display_name": host.display_name.as_str(),
                ":os": token(&host.os),
                ":architecture": token(&host.architecture),
                ":host_capacity": i64::from(host.host_capacity.get()),
                ":service_start_mode": token(&host.service_start_mode),
                ":refresh_interval_secs": i64::from(host.refresh_interval.as_secs()),
                ":created_at": timestamp_to_text(host.created_at),
            },
        )?;
        Ok(())
    }

    fn host(&self, id: HostId) -> Result<Option<Host>, StoreError> {
        let conn = self.lock();
        let mut stmt = conn.prepare("SELECT * FROM hosts WHERE id = :id")?;
        let mut rows = stmt.query(named_params! { ":id": uuid_text(id.as_uuid()) })?;
        match rows.next()? {
            Some(row) => Ok(Some(host_from_row(row)?)),
            None => Ok(None),
        }
    }

    fn hosts(&self) -> Result<Vec<Host>, StoreError> {
        let conn = self.lock();
        let mut stmt = conn.prepare("SELECT * FROM hosts ORDER BY created_at, id")?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(host_from_row(row)?);
        }
        Ok(out)
    }

    fn insert_policy(&self, policy: &ScalePolicy) -> Result<(), StoreError> {
        let fields = policy.to_persisted();
        let params = policy_params(&fields)?;
        let conn = self.lock();
        conn.execute(
            "INSERT INTO policies (
                 id, target_scope, target_slug, installation_id, host_id,
                 routing_labels, min_capacity, max_capacity, enabled, state,
                 cache_policy, revision
             ) VALUES (
                 :id, :target_scope, :target_slug, :installation_id, :host_id,
                 :routing_labels, :min_capacity, :max_capacity, :enabled, :state,
                 :cache_policy, :revision
             )",
            &bind(&params)[..],
        )
        .map_err(|source| {
            if is_constraint_violation(&source) {
                StoreError::AlreadyExists {
                    what: "policy",
                    id: fields.id.to_string(),
                }
            } else {
                StoreError::Sqlite(source)
            }
        })?;
        Ok(())
    }

    fn update_policy(
        &self,
        policy: &ScalePolicy,
        expected_revision: u64,
    ) -> Result<(), StoreError> {
        let fields = policy.to_persisted();
        let mut params = policy_params(&fields)?;
        params.push((
            ":expected_revision",
            int(u64_to_sql("the expected revision", expected_revision)?),
        ));

        let mut conn = self.lock();
        // IMMEDIATE, not the default DEFERRED -- but not for the reason this
        // comment used to give, which was checkable and wrong.
        //
        // It claimed that DEFERRED would make two racing writers produce
        // SQLITE_BUSY on the loser instead of a clean stale-revision answer.
        // That hazard is real in SQLite (`SQLITE_BUSY_SNAPSHOT`, which the busy
        // handler deliberately refuses to retry, because retrying would hand
        // the reader a snapshot that has already moved) but it needs the *read*
        // to be inside the transaction. Here it is not: the caller read the
        // policy through `Store::policy`, in a separate implicit transaction
        // that has already ended, and this transaction runs the UPDATE as its
        // first statement. So the ordinary busy handler applies, the loser waits
        // out `busy_timeout` and then matches against the winner's revision and
        // gets `StaleRevision`. Measured: with `Deferred` here,
        // `two_concurrent_writers_race_and_exactly_one_wins` passes 15 runs out
        // of 15.
        //
        // What IMMEDIATE buys is that the paragraph above becomes true the day
        // the read moves inside -- a re-read to report the current revision, a
        // check-then-write, a batched multi-policy update. That is an ordinary
        // refactor whose failure mode is a raw `database is locked` in an
        // operator's face instead of the conflict this store promises to
        // distinguish, and no test here would catch it, because both writers
        // have to interleave *within* the transaction to show it. Taking the
        // write lock up front costs one uncontended acquisition and removes the
        // hazard before anyone can introduce it.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE policies SET
                 target_scope    = :target_scope,
                 target_slug     = :target_slug,
                 installation_id = :installation_id,
                 host_id         = :host_id,
                 routing_labels  = :routing_labels,
                 min_capacity    = :min_capacity,
                 max_capacity    = :max_capacity,
                 enabled         = :enabled,
                 state           = :state,
                 cache_policy    = :cache_policy,
                 revision        = :revision
             WHERE id = :id AND revision = :expected_revision",
            &bind(&params)[..],
        )?;
        if changed == 0 {
            // The transaction is dropped, and therefore rolled back, on return.
            return Err(conflict_or_missing(&tx, fields.id, expected_revision)?);
        }
        tx.commit()?;
        Ok(())
    }

    fn remove_policy(&self, id: PolicyId, expected_revision: u64) -> Result<(), StoreError> {
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "DELETE FROM policies WHERE id = :id AND revision = :expected_revision",
            named_params! {
                ":id": uuid_text(id.as_uuid()),
                ":expected_revision": u64_to_sql("the expected revision", expected_revision)?,
            },
        )?;
        if changed == 0 {
            return Err(conflict_or_missing(&tx, id, expected_revision)?);
        }
        tx.commit()?;
        Ok(())
    }

    fn policy(&self, id: PolicyId) -> Result<Option<ScalePolicy>, StoreError> {
        let conn = self.lock();
        let mut stmt = conn.prepare("SELECT * FROM policies WHERE id = :id")?;
        let mut rows = stmt.query(named_params! { ":id": uuid_text(id.as_uuid()) })?;
        match rows.next()? {
            Some(row) => Ok(Some(policy_from_row(row)?)),
            None => Ok(None),
        }
    }

    fn policies(&self) -> Result<Vec<ScalePolicy>, StoreError> {
        let conn = self.lock();
        let mut stmt = conn.prepare("SELECT * FROM policies ORDER BY id")?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(policy_from_row(row)?);
        }
        Ok(out)
    }

    fn record_attempt(&self, attempt: &RunnerAttempt) -> Result<(), StoreError> {
        let fields = self.normalise(attempt.to_persisted());
        let params = attempt_params(&fields)?;
        let conn = self.lock();
        conn.execute(
            "INSERT INTO attempts (
                 id, policy_id, github_runner_id, state, outcome, process_id,
                 runtime_path, created_at, terminal_at, last_state_change_at
             ) VALUES (
                 :id, :policy_id, :github_runner_id, :state, :outcome, :process_id,
                 :runtime_path, :created_at, :terminal_at, :last_state_change_at
             )
             ON CONFLICT(id) DO UPDATE SET
                 policy_id            = excluded.policy_id,
                 github_runner_id     = excluded.github_runner_id,
                 state                = excluded.state,
                 outcome              = excluded.outcome,
                 process_id           = excluded.process_id,
                 runtime_path         = excluded.runtime_path,
                 terminal_at          = excluded.terminal_at,
                 last_state_change_at = excluded.last_state_change_at",
            // `created_at` is absent from the DO UPDATE list on purpose: the
            // domain says it never moves, so the value written at allocation is
            // the one that stands and no later journal write can rewrite it.
            // `put_host` above does the opposite with its own `created_at`, and
            // its comment says why the two are not the same case.
            &bind(&params)[..],
        )?;
        Ok(())
    }

    fn attempt(&self, id: AttemptId) -> Result<Option<RunnerAttempt>, StoreError> {
        let conn = self.lock();
        let mut stmt = conn.prepare("SELECT * FROM attempts WHERE id = :id")?;
        let mut rows = stmt.query(named_params! { ":id": uuid_text(id.as_uuid()) })?;
        match rows.next()? {
            Some(row) => Ok(Some(self.attempt_from_row(row)?)),
            None => Ok(None),
        }
    }

    fn attempts(&self) -> Result<Vec<RunnerAttempt>, StoreError> {
        let conn = self.lock();
        let mut stmt = conn.prepare("SELECT * FROM attempts ORDER BY created_at, id")?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(self.attempt_from_row(row)?);
        }
        Ok(out)
    }

    fn attempts_for_policy(&self, policy_id: PolicyId) -> Result<Vec<RunnerAttempt>, StoreError> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT * FROM attempts WHERE policy_id = :policy_id ORDER BY created_at, id",
        )?;
        let mut rows =
            stmt.query(named_params! { ":policy_id": uuid_text(policy_id.as_uuid()) })?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(self.attempt_from_row(row)?);
        }
        Ok(out)
    }

    fn remove_attempt(&self, id: AttemptId) -> Result<bool, StoreError> {
        let conn = self.lock();
        let changed = conn.execute(
            "DELETE FROM attempts WHERE id = :id",
            named_params! { ":id": uuid_text(id.as_uuid()) },
        )?;
        Ok(changed > 0)
    }
}

// ---------------------------------------------------------------------------
// Domain -> row
// ---------------------------------------------------------------------------

/// Named bindings for one statement.
///
/// Owned [`Value`]s rather than references so that the insert and the update can
/// share one binding list. They bind the same twelve columns, and a duplicated
/// `named_params!` between them is exactly how two statements drift into
/// disagreeing about which column holds what.
type NamedParams = Vec<(&'static str, Value)>;

fn bind(params: &NamedParams) -> Vec<(&str, &dyn ToSql)> {
    params
        .iter()
        .map(|(name, value)| (*name, value as &dyn ToSql))
        .collect()
}

fn text(value: impl Into<String>) -> Value {
    Value::Text(value.into())
}

fn int(value: i64) -> Value {
    Value::Integer(value)
}

fn opt_text(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::Text)
}

fn opt_int(value: Option<i64>) -> Value {
    value.map_or(Value::Null, Value::Integer)
}

fn policy_params(fields: &PersistedPolicy) -> Result<NamedParams, StoreError> {
    Ok(vec![
        (":id", text(uuid_text(fields.id.as_uuid()))),
        (":target_scope", text(token(&fields.target.scope()))),
        (":target_slug", text(fields.target.slug())),
        (
            ":installation_id",
            int(u64_to_sql(
                "policies.installation_id",
                fields.installation_id,
            )?),
        ),
        (":host_id", text(uuid_text(fields.host_id.as_uuid()))),
        (
            ":routing_labels",
            opt_text(fields.routing_labels.as_ref().map(json)),
        ),
        (":min_capacity", int(i64::from(fields.min_capacity))),
        (
            ":max_capacity",
            opt_int(fields.max_capacity.map(|m| i64::from(m.get()))),
        ),
        (":enabled", int(i64::from(fields.enabled))),
        (":state", text(token(&fields.state))),
        (":cache_policy", text(token(&fields.cache_policy))),
        (
            ":revision",
            int(u64_to_sql("policies.revision", fields.revision)?),
        ),
    ])
}

fn attempt_params(fields: &PersistedAttempt) -> Result<NamedParams, StoreError> {
    let runtime_path =
        fields
            .runtime_path
            .to_str()
            .ok_or_else(|| StoreError::UnrepresentablePath {
                attempt: fields.id,
                path: fields.runtime_path.clone(),
            })?;
    Ok(vec![
        (":id", text(uuid_text(fields.id.as_uuid()))),
        (":policy_id", text(uuid_text(fields.policy_id.as_uuid()))),
        (
            ":github_runner_id",
            opt_int(
                fields
                    .github_runner_id
                    .map(|id| u64_to_sql("attempts.github_runner_id", id))
                    .transpose()?,
            ),
        ),
        (":state", text(token(&fields.state))),
        (":outcome", opt_text(fields.outcome.as_ref().map(json))),
        (":process_id", opt_int(fields.process_id.map(i64::from))),
        (":runtime_path", text(runtime_path)),
        (":created_at", text(timestamp_to_text(fields.created_at))),
        (
            ":terminal_at",
            opt_text(fields.terminal_at.map(timestamp_to_text)),
        ),
        (
            ":last_state_change_at",
            text(timestamp_to_text(fields.last_state_change_at)),
        ),
    ])
}

// ---------------------------------------------------------------------------
// Row -> domain
// ---------------------------------------------------------------------------

fn host_from_row(row: &Row<'_>) -> Result<Host, StoreError> {
    const TABLE: &str = "hosts";
    let id = HostId::from_uuid(uuid_column(row, TABLE, "id")?);
    let key = id.to_string();

    let display_name: String = row.get("display_name")?;
    let os: Os = token_column(row, TABLE, "os", &key)?;
    let architecture: Arch = token_column(row, TABLE, "architecture", &key)?;
    let host_capacity = NonZeroU16::new(u16_column(row, TABLE, "host_capacity", &key)?).ok_or(
        StoreError::CorruptColumn {
            table: TABLE,
            column: "host_capacity",
            id: key.clone(),
            value: "0".to_string(),
            expected: "a non-zero capacity; a host that declares zero is not a \
                       configured host but a disabled one",
        },
    )?;
    let service_start_mode: StartMode = token_column(row, TABLE, "service_start_mode", &key)?;
    let refresh_interval_secs = u16_column(row, TABLE, "refresh_interval_secs", &key)?;
    let created_at = timestamp_column(row, TABLE, "created_at", &key)?;

    // `Host::new` re-runs the display-name rule and `RefreshInterval::from_secs`
    // re-runs the 30-second floor, so a hand-edited row cannot install a host
    // with a blank name or one that polls every second.
    let mut host = Host::new(
        id,
        &display_name,
        os,
        architecture,
        host_capacity,
        created_at,
    )
    .map_err(|source| StoreError::CorruptHost { id, source })?;
    host.service_start_mode = service_start_mode;
    host.refresh_interval = RefreshInterval::from_secs(refresh_interval_secs)
        .map_err(|source| StoreError::CorruptHost { id, source })?;
    Ok(host)
}

fn policy_from_row(row: &Row<'_>) -> Result<ScalePolicy, StoreError> {
    const TABLE: &str = "policies";
    let id = PolicyId::from_uuid(uuid_column(row, TABLE, "id")?);
    let key = id.to_string();

    let scope: TargetScope = token_column(row, TABLE, "target_scope", &key)?;
    let slug: String = row.get("target_slug")?;
    // Rebuilt through the real constructors, so GitHub's naming rules run again
    // and a scope/slug pair that cannot exist — `organization` holding `o/r` —
    // is refused rather than loaded as an organization with a slash in its name.
    let target = match scope {
        TargetScope::Repository => ScaleTarget::repository(&slug),
        TargetScope::Organization => ScaleTarget::organization(&slug),
    }
    .map_err(|source| StoreError::CorruptPolicy {
        id,
        source: PolicyError::Invalid(source),
    })?;

    let routing_labels: Option<RoutingLabels> =
        json_column(row, TABLE, "routing_labels", &key, "a routing label set")?;
    let max_capacity = match u16_option_column(row, TABLE, "max_capacity", &key)? {
        Some(raw) => Some(NonZeroU16::new(raw).ok_or(StoreError::CorruptColumn {
            table: TABLE,
            column: "max_capacity",
            id: key.clone(),
            value: "0".to_string(),
            expected: "a non-zero ceiling; an autoscale policy that may start no \
                       runner is a monitor-only policy and stores NULL here",
        })?),
        None => None,
    };

    let fields = PersistedPolicy {
        id,
        target,
        installation_id: u64_column(row, TABLE, "installation_id", &key)?,
        host_id: HostId::from_uuid(uuid_column(row, TABLE, "host_id")?),
        routing_labels,
        min_capacity: u16_column(row, TABLE, "min_capacity", &key)?,
        max_capacity,
        enabled: bool_column(row, TABLE, "enabled", &key)?,
        state: token_column::<PolicyState>(row, TABLE, "state", &key)?,
        cache_policy: token_column::<CachePolicy>(row, TABLE, "cache_policy", &key)?,
        revision: u64_column(row, TABLE, "revision", &key)?,
    };

    // D19's shape rules and `min <= max` run here, on every load.
    ScalePolicy::from_persisted(fields).map_err(|source| StoreError::CorruptPolicy { id, source })
}

fn persisted_attempt_from_row(row: &Row<'_>) -> Result<PersistedAttempt, StoreError> {
    const TABLE: &str = "attempts";
    let id = AttemptId::from_uuid(uuid_column(row, TABLE, "id")?);
    let key = id.to_string();

    let runtime_path: String = row.get("runtime_path")?;
    Ok(PersistedAttempt {
        id,
        policy_id: PolicyId::from_uuid(uuid_column(row, TABLE, "policy_id")?),
        github_runner_id: u64_option_column(row, TABLE, "github_runner_id", &key)?,
        state: token_column::<AttemptState>(row, TABLE, "state", &key)?,
        outcome: json_column::<AttemptOutcome>(row, TABLE, "outcome", &key, "an attempt outcome")?,
        process_id: u32_option_column(row, TABLE, "process_id", &key)?,
        runtime_path: PathBuf::from(runtime_path),
        created_at: timestamp_column(row, TABLE, "created_at", &key)?,
        terminal_at: timestamp_option_column(row, TABLE, "terminal_at", &key)?,
        last_state_change_at: timestamp_column(row, TABLE, "last_state_change_at", &key)?,
    })
}

/// Why a revision-guarded write matched no row: someone else won, or the row is
/// gone. Both are ordinary and the caller does different things about them.
fn conflict_or_missing(
    tx: &rusqlite::Transaction<'_>,
    id: PolicyId,
    expected: u64,
) -> Result<StoreError, StoreError> {
    let found: Option<i64> = tx
        .query_row(
            "SELECT revision FROM policies WHERE id = :id",
            named_params! { ":id": uuid_text(id.as_uuid()) },
            |row| row.get(0),
        )
        .optional()?;
    Ok(match found {
        // The revision is read raw here rather than through `u64_column`, so it
        // is the one place a corrupt value could slip past the check every other
        // column gets. It used to be coerced with `unwrap_or(0)`, which turned a
        // hand-edited `-1` into the message "written against revision 0, but the
        // stored revision is now 0" -- a self-contradiction that reads as a bug
        // in this code and tells an operator nothing about the row that actually
        // needs fixing.
        Some(found) => match u64::try_from(found) {
            Ok(found) => StoreError::StaleRevision {
                id,
                expected,
                found,
            },
            Err(_) => StoreError::CorruptColumn {
                table: "policies",
                column: "revision",
                id: id.to_string(),
                value: clip(&found.to_string()),
                expected: "a non-negative integer",
            },
        },
        None => StoreError::NotFound {
            what: "policy",
            id: id.to_string(),
        },
    })
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/// A unit enum's on-disk token, taken from the domain's own serde naming.
///
/// Deriving the token from `serde` rather than writing a `match` here means the
/// stored token and the JSON token cannot drift apart, and
/// `tests::the_on_disk_tokens_are_pinned` fixes the actual strings so a rename in
/// the domain breaks a test rather than silently changing the on-disk format.
///
/// # Panics
/// If `T` does not serialise to a JSON string. Every caller passes a unit-only
/// enum and the pinning test covers each one.
fn token<T: Serialize + fmt::Debug>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(token)) => token,
        other => panic!(
            "{value:?} must serialise to a JSON string to be stored as a column \
             token, got {other:?}"
        ),
    }
}

/// # Panics
/// If `T`'s `Serialize` fails, which for the types stored here would mean an
/// unrepresentable value rather than an I/O error.
fn json<T: Serialize + fmt::Debug>(value: &T) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|e| panic!("{value:?} must serialise to JSON for storage: {e}"))
}

/// RFC 3339, always nanosecond precision, always `Z`.
///
/// Fixed width so the text sorts in instant order (`ORDER BY created_at` is a
/// real query here), and full precision so the round trip is exact: a format that
/// dropped sub-second digits would make `assert_eq!` on a reloaded [`Timestamp`]
/// fail for any value that came from the system clock.
fn timestamp_to_text(value: Timestamp) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}

fn uuid_text(value: &Uuid) -> String {
    value.hyphenated().to_string()
}

/// SQLite integers are signed 64-bit, so a `u64` above `i64::MAX` has no
/// representation.
///
/// This refuses rather than saturating. Saturating would write `i64::MAX` and
/// read `i64::MAX` back, so the value the caller stored and the value it later
/// loaded would differ with nothing to say so — and the path is reachable, not
/// theoretical: `RunnerAttempt::registered_idle` takes any `u64` as the GitHub
/// runner id, and `ScalePolicy` takes any `u64` as the installation id.
fn u64_to_sql(what: &'static str, value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::UnrepresentableInteger { what, value })
}

/// The most of a **constrained** column's payload an error message will ever
/// repeat.
///
/// Sixty characters identifies a value without reproducing it: a malformed
/// timestamp, an unrecognised token and a truncated UUID are all shorter than
/// this, and anything longer is a payload rather than a value.
///
/// It is not a limit that protects a *free-form* column, and it was once applied
/// to one. The private `FREE_FORM_COLUMNS` below carries the measurement of why
/// a fixed character budget is the wrong instrument there, and what replaced it.
pub const ECHO_LIMIT: usize = 60;

/// The columns whose payload includes text a **caller** chose, and which an
/// error message therefore may not echo at all.
///
/// **Why this is a per-column list and not one budget for every column.**
/// [`ECHO_LIMIT`] is a fixed character budget with no idea which column it is
/// echoing, and over `attempts.outcome` that is not a small imprecision. The
/// column holds the JSON of [`AttemptOutcome`], and reaching the free-form
/// `FailureReason::Other(String)` inside it costs a serde prefix of
/// `{"outcome":"failed","reason":{"other":"` — thirty-nine characters — which
/// leaves roughly twenty-one of the caller's own string inside a sixty-character
/// budget. That is a partial echo of a forty-character `ghu_…` token, and a
/// **complete** echo of any secret shorter than about twenty-one characters. The
/// rationale the budget was written with — "anything longer is a payload rather
/// than a value" — quietly assumes secrets are long, and short ones are the case
/// it lets straight through.
///
/// **The second-order failure is worse than the first.** The argument for
/// clipping leaned on `d1`'s redacting log sink catching a prefixed token that
/// slipped out. But that sink matches on *shape*, and a token cut after
/// twenty-one characters may no longer have the shape it matches — so clipping
/// can take a token the sink would have redacted and hand it on as a fragment
/// the sink will not. A partial echo is not a safer echo here; it is an echo
/// with the downstream control removed.
///
/// **What is echoed instead.** For a column on this list,
/// [`StoreError::CorruptColumn`] reports position only — how many bytes the
/// column holds and where the parse gave up — and none of the payload. That
/// costs nothing at every other column: `uuid_column`, `token_column`,
/// `parse_timestamp` and `current_version` all decode values whose shape the
/// *schema* fixes, so nothing a caller chose can reach them, and they keep the
/// full [`clip`] echo the diagnosability argument was made for.
///
/// **Why this list has one entry.** `attempts.outcome` is the column
/// `the_token_scanner_can_actually_fail` in `tests/store_journal.rs` proves is a
/// carrier, by planting a `ghu_…` in exactly that field. `policies.routing_labels`
/// is the other column read through `json_column`; its contents are operator
/// configuration rather than agent-captured failure text, and no test plants a
/// credential there. It is a list so that a second carrier can be added to it
/// without touching the decoder.
const FREE_FORM_COLUMNS: &[(&str, &str)] = &[("attempts", "outcome")];

/// Whether this column may have a caller's own text in it.
fn carries_free_form_text(table: &str, column: &str) -> bool {
    FREE_FORM_COLUMNS
        .iter()
        .any(|(t, c)| *t == table && *c == column)
}

/// One constrained column's payload, trimmed to something safe to put in an
/// error message.
///
/// **Only for a column whose shape the schema fixes.** A column that can hold
/// text a caller chose goes through [`position_only`] instead; see
/// [`FREE_FORM_COLUMNS`] for the measurement that separates the two.
///
/// Clipping rather than dropping the value entirely: an operator handed only a
/// row id has to go and read the row, and the first sixty characters are
/// usually enough to see what went wrong. The byte length is reported so a
/// truncated echo cannot be mistaken for the whole value.
fn clip(raw: &str) -> String {
    match raw.char_indices().nth(ECHO_LIMIT) {
        None => raw.to_string(),
        Some((cut, _)) => format!(
            "{}... ({} bytes in total, truncated)",
            &raw[..cut],
            raw.len()
        ),
    }
}

/// Everything an error may say about a [`FREE_FORM_COLUMNS`] payload: how much
/// of it there is, and where it stopped being parseable.
///
/// Neither figure is derived from the *content* of the value, so no part of it
/// can travel in the message — which is the point, since a prefix of it is
/// exactly what would evade `d1`'s shape-matching sink downstream.
///
/// It is still enough to work with. A byte count separates "this column is
/// empty" from "this column holds a megabyte", and a position separates a row
/// truncated mid-write from one whose first character is already wrong. The row
/// id, which is what an operator actually needs in order to go and look, is
/// carried by [`StoreError::CorruptColumn`] itself and is unaffected.
fn position_only(raw: &str, error: &serde_json::Error) -> String {
    format!(
        "a {}-byte payload that is not echoed (it stops parsing at line {}, column {})",
        raw.len(),
        error.line(),
        error.column()
    )
}

fn is_constraint_violation(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(inner, _)
            if inner.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

fn render(value: ValueRef<'_>) -> String {
    match value {
        ValueRef::Null => "NULL".to_string(),
        ValueRef::Integer(i) => i.to_string(),
        ValueRef::Real(f) => f.to_string(),
        ValueRef::Text(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        ValueRef::Blob(bytes) => bytes.iter().map(|b| format!("{b:02x}")).collect(),
    }
}

// ---------------------------------------------------------------------------
// Decoding helpers
// ---------------------------------------------------------------------------

fn uuid_column(
    row: &Row<'_>,
    table: &'static str,
    column: &'static str,
) -> Result<Uuid, StoreError> {
    let raw: String = row.get(column)?;
    Uuid::parse_str(&raw).map_err(|_| StoreError::CorruptColumn {
        table,
        column,
        // The unparseable id is the only handle on this row there is, so it is
        // both the id and the value here. Clipped in both places: a row whose
        // primary key is a megabyte of text is exactly the row an error message
        // must not repeat.
        id: clip(&raw),
        value: clip(&raw),
        expected: "a hyphenated UUID",
    })
}

fn token_column<T: DeserializeOwned>(
    row: &Row<'_>,
    table: &'static str,
    column: &'static str,
    id: &str,
) -> Result<T, StoreError> {
    let raw: String = row.get(column)?;
    serde_json::from_value(serde_json::Value::String(raw.clone())).map_err(|_| {
        StoreError::CorruptColumn {
            table,
            column,
            id: id.to_string(),
            value: clip(&raw),
            expected: "one of this column's recognised tokens",
        }
    })
}

/// The one decoder that reads a column which may carry a caller's own text, and
/// therefore the one that has to ask which column it is looking at before it
/// says anything about the payload. See [`FREE_FORM_COLUMNS`].
fn json_column<T: DeserializeOwned>(
    row: &Row<'_>,
    table: &'static str,
    column: &'static str,
    id: &str,
    expected: &'static str,
) -> Result<Option<T>, StoreError> {
    match row.get::<_, Option<String>>(column)? {
        None => Ok(None),
        Some(raw) => {
            serde_json::from_str(&raw)
                .map(Some)
                .map_err(|error| StoreError::CorruptColumn {
                    table,
                    column,
                    id: id.to_string(),
                    value: if carries_free_form_text(table, column) {
                        position_only(&raw, &error)
                    } else {
                        clip(&raw)
                    },
                    expected,
                })
        }
    }
}

fn timestamp_column(
    row: &Row<'_>,
    table: &'static str,
    column: &'static str,
    id: &str,
) -> Result<Timestamp, StoreError> {
    let raw: String = row.get(column)?;
    parse_timestamp(&raw, table, column, id)
}

fn timestamp_option_column(
    row: &Row<'_>,
    table: &'static str,
    column: &'static str,
    id: &str,
) -> Result<Option<Timestamp>, StoreError> {
    match row.get::<_, Option<String>>(column)? {
        None => Ok(None),
        Some(raw) => parse_timestamp(&raw, table, column, id).map(Some),
    }
}

fn parse_timestamp(
    raw: &str,
    table: &'static str,
    column: &'static str,
    id: &str,
) -> Result<Timestamp, StoreError> {
    chrono::DateTime::parse_from_rfc3339(raw)
        .map(|value| value.with_timezone(&chrono::Utc))
        .map_err(|_| StoreError::CorruptColumn {
            table,
            column,
            id: id.to_string(),
            value: clip(raw),
            expected: "an RFC 3339 timestamp",
        })
}

fn bool_column(
    row: &Row<'_>,
    table: &'static str,
    column: &'static str,
    id: &str,
) -> Result<bool, StoreError> {
    // Read as an integer and require 0 or 1 rather than accepting rusqlite's
    // "any non-zero is true": a column that records operator intent should not
    // have several spellings of yes, and a hand-edited `7` is a corrupted row
    // rather than an enthusiastic one.
    match row.get::<_, i64>(column)? {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(StoreError::CorruptColumn {
            table,
            column,
            id: id.to_string(),
            value: other.to_string(),
            expected: "0 or 1",
        }),
    }
}

macro_rules! integer_column {
    ($name:ident, $ty:ty, $expected:literal) => {
        fn $name(
            row: &Row<'_>,
            table: &'static str,
            column: &'static str,
            id: &str,
        ) -> Result<$ty, StoreError> {
            let raw: i64 = row.get(column)?;
            <$ty>::try_from(raw).map_err(|_| StoreError::CorruptColumn {
                table,
                column,
                id: id.to_string(),
                value: raw.to_string(),
                expected: $expected,
            })
        }
    };
}

macro_rules! integer_option_column {
    ($name:ident, $ty:ty, $expected:literal) => {
        fn $name(
            row: &Row<'_>,
            table: &'static str,
            column: &'static str,
            id: &str,
        ) -> Result<Option<$ty>, StoreError> {
            match row.get::<_, Option<i64>>(column)? {
                None => Ok(None),
                Some(raw) => {
                    <$ty>::try_from(raw)
                        .map(Some)
                        .map_err(|_| StoreError::CorruptColumn {
                            table,
                            column,
                            id: id.to_string(),
                            value: raw.to_string(),
                            expected: $expected,
                        })
                }
            }
        }
    };
}

integer_column!(u16_column, u16, "a value in 0..=65535");
integer_column!(u64_column, u64, "a non-negative integer");
integer_option_column!(u16_option_column, u16, "a value in 0..=65535");
integer_option_column!(u32_option_column, u32, "a value in 0..=4294967295");
integer_option_column!(u64_option_column, u64, "a non-negative integer");

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use crate::attempt::FailureReason;
    use crate::model::Label;
    use crate::policy::PolicyMode;

    // `b1`'s fixture ids, spelled as the UUID text a row holds, so a row written
    // by hand here and a `testkit` fixture in `tests/` describe the same objects.
    const HOST_UUID: &str = "00000000-0000-0000-0000-000000000001";
    const POLICY_UUID: &str = "00000000-0000-0000-0000-000000000010";
    const ATTEMPT_UUID: &str = "00000000-0000-0000-0000-000000000100";
    const LABELS_JSON: &str = r#"{"host_label":"rm-home-win-x64","additional":[]}"#;
    const COMPLETED_JOB: &str = r#"{"outcome":"completed_job"}"#;

    fn host_id() -> HostId {
        HostId::from_u128(0x0000_0001)
    }

    fn policy_id() -> PolicyId {
        PolicyId::from_u128(0x0000_0010)
    }

    fn attempt_id() -> AttemptId {
        AttemptId::from_u128(0x0000_0100)
    }

    fn ts(secs: i64) -> Timestamp {
        chrono::DateTime::from_timestamp(secs, 0).expect("a representable instant")
    }

    fn store() -> SqliteStore {
        SqliteStore::open_in_memory().expect("an in-memory database always opens")
    }

    // -- raw rows -----------------------------------------------------------
    //
    // Every corruption test below starts from a row the store itself would have
    // written and changes exactly one thing. A test that built its whole row by
    // hand would drift from the schema and start passing for the wrong reason.

    #[derive(Debug, Clone)]
    struct RawHost {
        id: String,
        display_name: String,
        os: String,
        architecture: String,
        host_capacity: i64,
        service_start_mode: String,
        refresh_interval_secs: i64,
        created_at: String,
    }

    impl Default for RawHost {
        fn default() -> Self {
            Self {
                id: HOST_UUID.to_string(),
                display_name: "home-pc".to_string(),
                os: "windows".to_string(),
                architecture: "x64".to_string(),
                host_capacity: 2,
                service_start_mode: "boot".to_string(),
                refresh_interval_secs: 60,
                created_at: timestamp_to_text(ts(1_000)),
            }
        }
    }

    impl RawHost {
        fn insert(&self, store: &SqliteStore) {
            store
                .lock()
                .execute(
                    "INSERT OR REPLACE INTO hosts (
                         id, display_name, os, architecture, host_capacity,
                         service_start_mode, refresh_interval_secs, created_at
                     ) VALUES (
                         :id, :display_name, :os, :architecture, :host_capacity,
                         :service_start_mode, :refresh_interval_secs, :created_at
                     )",
                    named_params! {
                        ":id": self.id,
                        ":display_name": self.display_name,
                        ":os": self.os,
                        ":architecture": self.architecture,
                        ":host_capacity": self.host_capacity,
                        ":service_start_mode": self.service_start_mode,
                        ":refresh_interval_secs": self.refresh_interval_secs,
                        ":created_at": self.created_at,
                    },
                )
                .expect("the raw host row is writable");
        }
    }

    #[derive(Debug, Clone)]
    struct RawPolicy {
        id: String,
        target_scope: String,
        target_slug: String,
        installation_id: i64,
        host_id: String,
        routing_labels: Option<String>,
        min_capacity: i64,
        max_capacity: Option<i64>,
        enabled: i64,
        state: String,
        cache_policy: String,
        revision: i64,
    }

    impl Default for RawPolicy {
        fn default() -> Self {
            Self {
                id: POLICY_UUID.to_string(),
                target_scope: "repository".to_string(),
                target_slug: "o/r".to_string(),
                installation_id: 1,
                host_id: HOST_UUID.to_string(),
                routing_labels: Some(LABELS_JSON.to_string()),
                min_capacity: 0,
                max_capacity: Some(2),
                enabled: 1,
                state: "active".to_string(),
                cache_policy: "retain_runner_package".to_string(),
                revision: 1,
            }
        }
    }

    impl RawPolicy {
        fn insert(&self, store: &SqliteStore) {
            store
                .lock()
                .execute(
                    "INSERT OR REPLACE INTO policies (
                         id, target_scope, target_slug, installation_id, host_id,
                         routing_labels, min_capacity, max_capacity, enabled,
                         state, cache_policy, revision
                     ) VALUES (
                         :id, :target_scope, :target_slug, :installation_id, :host_id,
                         :routing_labels, :min_capacity, :max_capacity, :enabled,
                         :state, :cache_policy, :revision
                     )",
                    named_params! {
                        ":id": self.id,
                        ":target_scope": self.target_scope,
                        ":target_slug": self.target_slug,
                        ":installation_id": self.installation_id,
                        ":host_id": self.host_id,
                        ":routing_labels": self.routing_labels,
                        ":min_capacity": self.min_capacity,
                        ":max_capacity": self.max_capacity,
                        ":enabled": self.enabled,
                        ":state": self.state,
                        ":cache_policy": self.cache_policy,
                        ":revision": self.revision,
                    },
                )
                .expect("the raw policy row is writable");
        }
    }

    #[derive(Debug, Clone)]
    struct RawAttempt {
        id: String,
        policy_id: String,
        github_runner_id: Option<i64>,
        state: String,
        outcome: Option<String>,
        process_id: Option<i64>,
        runtime_path: String,
        created_at: String,
        terminal_at: Option<String>,
        last_state_change_at: String,
    }

    impl Default for RawAttempt {
        fn default() -> Self {
            Self {
                id: ATTEMPT_UUID.to_string(),
                policy_id: POLICY_UUID.to_string(),
                github_runner_id: None,
                state: "allocated".to_string(),
                outcome: None,
                process_id: None,
                runtime_path: "runtime/policy/attempt".to_string(),
                created_at: timestamp_to_text(ts(1_000)),
                terminal_at: None,
                last_state_change_at: timestamp_to_text(ts(1_000)),
            }
        }
    }

    impl RawAttempt {
        fn insert(&self, store: &SqliteStore) {
            store
                .lock()
                .execute(
                    "INSERT OR REPLACE INTO attempts (
                         id, policy_id, github_runner_id, state, outcome, process_id,
                         runtime_path, created_at, terminal_at, last_state_change_at
                     ) VALUES (
                         :id, :policy_id, :github_runner_id, :state, :outcome, :process_id,
                         :runtime_path, :created_at, :terminal_at, :last_state_change_at
                     )",
                    named_params! {
                        ":id": self.id,
                        ":policy_id": self.policy_id,
                        ":github_runner_id": self.github_runner_id,
                        ":state": self.state,
                        ":outcome": self.outcome,
                        ":process_id": self.process_id,
                        ":runtime_path": self.runtime_path,
                        ":created_at": self.created_at,
                        ":terminal_at": self.terminal_at,
                        ":last_state_change_at": self.last_state_change_at,
                    },
                )
                .expect("the raw attempt row is writable");
        }
    }

    // -- the on-disk format -------------------------------------------------

    #[test]
    fn the_on_disk_tokens_are_pinned() {
        // A column token comes from the domain's own serde naming, which means a
        // rename in `b1` would silently change the on-disk format of every
        // existing database. These assertions turn that into a failing test here
        // instead. The three enums without an `ALL` constant are covered by an
        // exhaustive `match`, so a new variant is a compile error rather than an
        // unpinned token.
        for (state, expected) in [
            (AttemptState::Allocated, "allocated"),
            (AttemptState::JitReceived, "jit_received"),
            (AttemptState::Starting, "starting"),
            (AttemptState::Idle, "idle"),
            (AttemptState::Busy, "busy"),
            (AttemptState::Finished, "finished"),
            (AttemptState::Failed, "failed"),
            (AttemptState::Orphaned, "orphaned"),
            (AttemptState::Cleaned, "cleaned"),
        ] {
            assert_eq!(token(&state), expected);
        }
        assert_eq!(
            AttemptState::ALL.len(),
            9,
            "a new AttemptState needs a pinned token above"
        );

        for (state, expected) in [
            (PolicyState::Pending, "pending"),
            (PolicyState::Active, "active"),
            (PolicyState::Draining, "draining"),
            (PolicyState::Disabled, "disabled"),
            (PolicyState::RepairRequired, "repair_required"),
            (PolicyState::AuthenticationFailed, "authentication_failed"),
        ] {
            assert_eq!(token(&state), expected);
        }
        assert_eq!(
            PolicyState::ALL.len(),
            6,
            "a new PolicyState needs a pinned token above"
        );

        for os in Os::ALL {
            assert_eq!(
                token(&os),
                match os {
                    Os::Windows => "windows",
                    Os::MacOs => "mac_os",
                    Os::Linux => "linux",
                }
            );
        }
        for arch in Arch::ALL {
            assert_eq!(
                token(&arch),
                match arch {
                    Arch::X64 => "x64",
                    Arch::Arm64 => "arm64",
                    Arch::Arm32 => "arm32",
                }
            );
        }
        for mode in [StartMode::Boot, StartMode::Login] {
            assert_eq!(
                token(&mode),
                match mode {
                    StartMode::Boot => "boot",
                    StartMode::Login => "login",
                }
            );
        }
        for cache in [
            CachePolicy::RetainRunnerPackage,
            CachePolicy::DiscardRunnerPackage,
        ] {
            assert_eq!(
                token(&cache),
                match cache {
                    CachePolicy::RetainRunnerPackage => "retain_runner_package",
                    CachePolicy::DiscardRunnerPackage => "discard_runner_package",
                }
            );
        }
        for scope in [TargetScope::Repository, TargetScope::Organization] {
            assert_eq!(
                token(&scope),
                match scope {
                    TargetScope::Repository => "repository",
                    TargetScope::Organization => "organization",
                }
            );
        }

        // The stored token is not the runtime `Display` string, and for `Os` the
        // two genuinely differ: `Windows` displays as its GitHub label token
        // `win` and is stored as `windows`. Pinned so that "just use Display"
        // becomes a visibly breaking change rather than a silent format
        // migration.
        assert_eq!(Os::Windows.to_string(), "win");
        assert_eq!(token(&Os::Windows), "windows");
    }

    #[test]
    fn a_timestamp_round_trips_to_the_nanosecond() {
        // The system clock produces sub-second precision, so a text format that
        // truncated it would make every round-trip assertion on a `Host` or an
        // attempt fail for values production actually writes.
        let precise = chrono::DateTime::from_timestamp(1_787_270_400, 123_456_789)
            .expect("a representable instant");
        let text = timestamp_to_text(precise);
        assert_eq!(text, "2026-08-21T00:00:00.123456789Z");
        assert_eq!(
            parse_timestamp(&text, "t", "c", "id").expect("round trips"),
            precise
        );

        // Fixed width, so lexical order is instant order and `ORDER BY
        // created_at` means what it says.
        assert_eq!(timestamp_to_text(ts(0)).len(), text.len());
        assert!(timestamp_to_text(ts(0)) < timestamp_to_text(ts(1)));
    }

    // -- migrations ---------------------------------------------------------

    #[test]
    fn the_migration_chain_is_ordered_and_starts_at_one() {
        assert!(!MIGRATIONS.is_empty());
        assert_eq!(MIGRATIONS[0].version, 1);
        for pair in MIGRATIONS.windows(2) {
            assert!(
                pair[1].version > pair[0].version,
                "the chain must be strictly ascending; {} does not follow {}",
                pair[1].version,
                pair[0].version
            );
        }
        assert_eq!(
            MIGRATIONS.last().expect("non-empty").version,
            SCHEMA_VERSION,
            "SCHEMA_VERSION must be the last step in the chain, or a fresh \
             database reports a version it was never migrated to"
        );
    }

    #[test]
    fn a_fresh_database_gets_the_whole_chain() {
        let store = store();
        assert_eq!(store.schema_version(), SCHEMA_VERSION);

        let conn = store.lock();
        for table in TABLES {
            let count: i64 = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .expect("sqlite_master is readable");
            assert_eq!(count, 1, "{table} was not created");
        }

        let mut stmt = conn
            .prepare("SELECT version FROM schema_migrations ORDER BY version")
            .expect("prepared");
        let applied: Vec<i64> = stmt
            .query_map([], |row| row.get(0))
            .expect("queried")
            .collect::<Result<_, _>>()
            .expect("collected");
        assert_eq!(
            applied,
            MIGRATIONS
                .iter()
                .map(|m| i64::from(m.version))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_database_one_version_behind_gets_only_the_missing_step() {
        // The production chain has one step (see `MIGRATIONS`), so "one version
        // behind" cannot yet be expressed against it. The runner is general, and
        // this exercises the two properties that matter about it: an applied step
        // is not re-run, and a missing one is.
        const CHAIN: &[Migration] = &[
            Migration {
                version: 1,
                name: "first",
                sql: "CREATE TABLE step_one (id INTEGER NOT NULL PRIMARY KEY, \
                      note TEXT NOT NULL) STRICT;",
            },
            Migration {
                version: 2,
                name: "second",
                sql: "CREATE TABLE step_two (id INTEGER NOT NULL PRIMARY KEY) STRICT;",
            },
        ];

        let mut conn = Connection::open_in_memory().expect("in-memory");
        assert_eq!(
            apply_migrations(&mut conn, &CHAIN[..1], &SystemClock).expect("step one applies"),
            1
        );
        conn.execute(
            "INSERT INTO step_one (id, note) VALUES (1, 'written between the two steps')",
            [],
        )
        .expect("insertable");

        // Forward-only: `CREATE TABLE step_one` would fail outright if step one
        // were re-run, so a successful return already proves it was skipped, and
        // the surviving row proves nothing was rebuilt underneath it.
        assert_eq!(
            apply_migrations(&mut conn, CHAIN, &SystemClock).expect("only step two applies"),
            2
        );
        let note: String = conn
            .query_row("SELECT note FROM step_one WHERE id = 1", [], |row| {
                row.get(0)
            })
            .expect("the row written before the second step survives it");
        assert_eq!(note, "written between the two steps");
        let two: i64 = conn
            .query_row("SELECT count(*) FROM step_two", [], |row| row.get(0))
            .expect("step two created its table");
        assert_eq!(two, 0);
        assert_eq!(current_version(&conn).expect("readable"), 2);

        // Running the whole chain over an up-to-date database changes nothing,
        // which is what every ordinary open does.
        assert_eq!(
            apply_migrations(&mut conn, CHAIN, &SystemClock).expect("idempotent"),
            2
        );
        let applied: i64 = conn
            .query_row("SELECT count(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("readable");
        assert_eq!(applied, 2, "a step must be recorded exactly once");
    }

    #[test]
    fn a_database_from_a_newer_build_is_refused_rather_than_guessed_at() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("runner-manager.sqlite3");

        let store = SqliteStore::open(&path).expect("a fresh database opens");
        assert_eq!(store.schema_version(), SCHEMA_VERSION);
        drop(store);

        // A future build migrated it further than this build understands.
        let future = SCHEMA_VERSION + 1;
        {
            let conn = Connection::open(&path).expect("reopenable");
            conn.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) \
                 VALUES (?1, 'from_the_future', ?2)",
                rusqlite::params![i64::from(future), timestamp_to_text(ts(2_000))],
            )
            .expect("insertable");
        }

        let error = SqliteStore::open(&path).expect_err("a newer database must be refused");
        assert!(
            matches!(
                error,
                StoreError::SchemaTooNew { found, supported }
                    if found == future && supported == SCHEMA_VERSION
            ),
            "expected SchemaTooNew, got {error:?}"
        );
        let message = error.to_string();
        assert!(
            message.contains(&future.to_string()) && message.contains(&SCHEMA_VERSION.to_string()),
            "the error must name both versions so an operator knows which way to \
             move: {message}"
        );
        assert!(
            !error.is_conflict(),
            "a schema refusal is not an optimistic-concurrency conflict"
        );
    }

    #[test]
    fn a_corrupt_schema_version_is_named_rather_than_reported_as_four_billion() {
        // `current_version` used to coerce a negative recorded version with
        // `unwrap_or(u32::MAX)`. That failed closed, which is right, but it did
        // so by telling the operator "this database is at schema version
        // 4294967295" -- a number no database has been at, and one that reads as
        // a bug in this code rather than as a corrupt bookkeeping row.
        //
        // The bookkeeping table alone, holding one hand-edited row. `MAX` is
        // what `current_version` reads, so a corrupt row only decides the answer
        // when it is the highest one -- which for a negative value means it is
        // the only one, and that is exactly the state an aborted or edited first
        // migration leaves behind.
        let mut conn = Connection::open_in_memory().expect("in-memory");
        conn.execute_batch(BOOTSTRAP_SQL).expect("bootstrapped");
        conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) \
             VALUES (-1, 'hand_edited', ?1)",
            rusqlite::params![timestamp_to_text(ts(2_000))],
        )
        .expect("insertable");

        let error = current_version(&conn).expect_err("a negative version is not a version");
        assert!(
            matches!(
                &error,
                StoreError::CorruptColumn {
                    table: "schema_migrations",
                    column: "version",
                    ..
                }
            ),
            "expected a named corrupt column, got {error:?}"
        );
        let message = error.to_string();
        assert!(
            message.contains("-1") && !message.contains(&u32::MAX.to_string()),
            "the message must name the row's actual value: {message}"
        );

        // And it still fails closed: nothing re-applies a migration over this.
        assert!(apply_migrations(&mut conn, MIGRATIONS, &SystemClock).is_err());
    }

    #[test]
    fn a_negative_stored_revision_is_a_corrupt_column_and_not_revision_zero() {
        // `conflict_or_missing` reads `revision` raw, bypassing the check every
        // other column gets, and used to coerce with `unwrap_or(0)`. Against a
        // hand-edited `-1` that produced "written against revision 0, but the
        // stored revision is now 0" -- a sentence that contradicts itself and
        // sends the operator looking in the wrong place.
        let store = store();
        RawPolicy {
            revision: -1,
            ..RawPolicy::default()
        }
        .insert(&store);

        let policy = ScalePolicy::new(
            policy_id(),
            ScaleTarget::repository("o/r").expect("valid"),
            1,
            host_id(),
            PolicyMode::autoscale(
                RoutingLabels::from_host_label(Label::new("rm-home-win-x64").expect("valid")),
                0,
                NonZeroU16::new(2).expect("non-zero"),
            )
            .expect("valid"),
            CachePolicy::default(),
        );
        let error = store
            .update_policy(&policy, 0)
            .expect_err("the row's revision is not 0, so this matches nothing");
        assert!(
            matches!(
                &error,
                StoreError::CorruptColumn {
                    table: "policies",
                    column: "revision",
                    ..
                }
            ),
            "expected a named corrupt column, got {error:?}"
        );
        assert!(
            !error.is_conflict(),
            "a corrupt row is not a lost race, and a caller told to re-read and \
             retry would loop for ever on it"
        );
        assert!(
            error.to_string().contains("-1"),
            "the message must name the value that needs fixing: {error}"
        );
    }

    // -- what an error message repeats --------------------------------------

    #[test]
    fn a_corrupt_column_error_clips_the_payload_it_echoes() {
        assert_eq!(clip("short"), "short");

        let exact = "a".repeat(ECHO_LIMIT);
        assert_eq!(clip(&exact), exact, "the limit is an edge, not a target");

        let over = "a".repeat(ECHO_LIMIT + 1);
        let clipped = clip(&over);
        assert!(clipped.starts_with(&exact));
        assert!(
            clipped.contains(&format!("{} bytes in total", over.len())),
            "a clipped echo must say it is one: {clipped}"
        );

        // Multi-byte characters are cut on a character boundary, or this panics.
        let wide = "é".repeat(ECHO_LIMIT * 2);
        assert!(clip(&wide).starts_with(&"é".repeat(ECHO_LIMIT)));
    }

    #[test]
    fn a_secret_in_a_free_form_column_is_not_echoed_whole_into_the_error() {
        // "No column carries a credential" is a claim about the schema, and
        // `attempts.outcome` is where it stops being true: it holds the JSON of
        // an `AttemptOutcome`, and `FailureReason::Other(String)` inside that is
        // free-form text a caller chose. `the_token_scanner_can_actually_fail`
        // in `tests/store_journal.rs` plants a `ghu_...` there on purpose, to
        // prove the field is a real carrier.
        //
        // A malformed value in that column produces a `CorruptColumn`, whose
        // message goes wherever the error goes. This test was written when the
        // answer was a sixty-character clip, and its rationale was that `d1`'s
        // shape-matching sink would probably catch a prefixed token downstream
        // even if one leaked. It no longer rests on that, and should not: the
        // sink is a control that a *truncated* token can walk straight past,
        // which is the argument in `FREE_FORM_COLUMNS`. Nothing from this column
        // is echoed at all now, so the long payload below is a case of the rule
        // rather than the reason for it, and
        // `a_short_secret_in_the_free_form_column_is_not_echoed_at_all` covers
        // the length a clip could never have protected.
        let store = store();
        let blob = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0\
                    NTY3ODkrLwABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzA"
            .to_string();
        assert!(blob.len() > ECHO_LIMIT * 2);

        RawAttempt {
            state: "finished".to_string(),
            outcome: Some(format!(r#"{{"outcome":"went_home","detail":"{blob}"}}"#)),
            terminal_at: Some(timestamp_to_text(ts(2_000))),
            ..RawAttempt::default()
        }
        .insert(&store);

        let error = store
            .attempt(attempt_id())
            .expect_err("`went_home` is not an outcome");
        let StoreError::CorruptColumn { value, .. } = &error else {
            panic!("expected a corrupt column, got {error:?}");
        };
        assert!(
            !value.contains(&blob),
            "the whole payload must not be repeated: {value}"
        );
        assert!(
            value.chars().count() < blob.chars().count(),
            "the echo must be shorter than what it echoes"
        );
        // And not a prefix of it either. A base64 blob has no prefix for `d1`'s
        // sink to match on, so a leading fragment of one is exactly as
        // unredactable as the whole thing is.
        assert!(
            !value.contains(&blob[..8]),
            "no leading fragment of the payload may travel either: {value}"
        );

        // The row id is what an operator actually needs, and it is still there.
        assert!(
            error.to_string().contains(&attempt_id().to_string()),
            "the error must name the row to fix: {error}"
        );
    }

    #[test]
    fn a_short_secret_in_the_free_form_column_is_not_echoed_at_all() {
        // The case a fixed character budget cannot reach. `ECHO_LIMIT` is sixty
        // characters and does not know which column it is echoing; the serde
        // prefix that reaches `FailureReason::Other` is thirty-nine of them, so
        // a budget-based echo repeats about twenty-one characters of whatever
        // the caller put there. That is partial for a forty-character `ghu_`
        // token and complete for anything shorter -- and a *partial* token is
        // the worse of the two, because `d1`'s sink matches on shape and a
        // fragment may no longer have the shape it redacts.
        let planted = "ghs_9tokenish";
        let raw = format!(r#"{{"outcome":"failed","reason":{{"other":"{planted}"}}"#);

        // The counterfactual, asserted rather than described: this whole row
        // fits inside the budget, so the echo it authorises is not a clip of
        // the value but the entire value, secret included.
        assert!(raw.chars().count() < ECHO_LIMIT);
        assert_eq!(
            clip(&raw),
            raw,
            "a sixty-character budget repeats this row in full, which is what \
             makes the budget the wrong instrument at this column"
        );
        assert!(carries_free_form_text("attempts", "outcome"));

        // Malformed only in its final brace, so the failure is a real parse
        // failure and the secret sits where a caller would really have put it.
        let store = store();
        RawAttempt {
            state: "failed".to_string(),
            outcome: Some(raw.clone()),
            terminal_at: Some(timestamp_to_text(ts(2_000))),
            ..RawAttempt::default()
        }
        .insert(&store);

        let error = store
            .attempt(attempt_id())
            .expect_err("an unterminated object is not an attempt outcome");
        let rendered = error.to_string();

        assert!(
            !rendered.contains(planted),
            "the secret must not appear in the message: {rendered}"
        );
        assert!(
            !rendered.contains("ghs_"),
            "and neither must a prefixed fragment of it, which is what a \
             clipped echo would have produced and what `d1`'s shape-matching \
             sink would then have failed to redact: {rendered}"
        );
        for len in 4..=planted.len() {
            assert!(
                !rendered.contains(&planted[..len]),
                "no prefix of the secret may survive, and {:?} did: {rendered}",
                &planted[..len]
            );
        }

        // What is left is still diagnosable: the size of the payload, where it
        // gave up, and above all the row to go and look at.
        assert!(
            rendered.contains(&format!("{}-byte", raw.len())),
            "the message must say how much is there: {rendered}"
        );
        assert!(
            rendered.contains("stops parsing at line"),
            "and where it stopped: {rendered}"
        );
        assert!(
            rendered.contains(&attempt_id().to_string()),
            "the error must name the row to fix: {rendered}"
        );
    }

    #[test]
    fn a_constrained_column_still_echoes_what_it_holds() {
        // The other half of the per-column rule: the echo is removed at the one
        // column that can carry a caller's text, and nowhere else. A malformed
        // timestamp has the shape the schema fixes -- nothing a caller chose
        // can reach it -- so an operator still gets to see the value that needs
        // fixing, which is the diagnosability the clip was argued for.
        assert!(!carries_free_form_text("attempts", "created_at"));
        assert!(!carries_free_form_text("policies", "routing_labels"));

        let store = store();
        RawAttempt {
            created_at: "the third of never".to_string(),
            ..RawAttempt::default()
        }
        .insert(&store);

        let error = store
            .attempt(attempt_id())
            .expect_err("`the third of never` is not RFC 3339");
        assert!(
            error.to_string().contains("the third of never"),
            "a constrained column keeps its echo: {error}"
        );
    }

    #[test]
    fn the_journal_mode_is_read_back_rather_than_assumed() {
        // The pragma answers with the mode the database *ended up in*. Where WAL
        // is unavailable -- no shared-memory support, as on some network mounts
        // -- SQLite silently leaves the database in `delete` and says so in that
        // row, which this store used to discard.
        let memory = store();
        assert_eq!(
            memory.journal_mode(),
            "memory",
            "an in-memory database is exempt by construction"
        );
        assert!(
            !memory.readers_do_not_block_writers(),
            "there is no second reader of a private in-memory database, so the \
             question does not arise for it"
        );

        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("runner-manager.sqlite3");
        let file = SqliteStore::open(&path).expect("opens");
        let mode = file.journal_mode();

        // Not `assert_eq!(mode, "wal")`. That is the assumption this test is
        // named for refusing, and the same commit that named it removed exactly
        // this assertion from `tests/store_journal.rs` on the stated grounds
        // that it failed on a healthy build wherever WAL is unavailable. A
        // container whose `TMPDIR` is a tmpfs or a network mount gives
        // `tempfile::tempdir()` a directory that cannot host WAL's
        // shared-memory file, and SQLite then leaves the database in `delete`
        // and says so -- a correct answer, and a false red here.
        //
        // Both are legal; a third value would be a real finding, so the set is
        // closed rather than dropped.
        assert!(
            matches!(mode, "wal" | "delete"),
            "a file database is in WAL where the directory can host it and \
             `delete` where it cannot; {mode} is neither and is a finding"
        );

        // The agreement check is the substance, and it reads a second source to
        // make it: the presence of the write-ahead log *on disk*. Comparing
        // `readers_do_not_block_writers()` against `mode == "wal"` would not,
        // because the method is defined as that comparison -- it could only
        // ever have failed on a difference in letter case, which is not what a
        // message about readers and writers claims to be checking.
        //
        // `file` is still open here, which is what makes the file check sound:
        // SQLite creates the `-wal` beside the database on the first write (the
        // migrations above are one) and removes it only on a clean close of the
        // last connection.
        assert_eq!(
            file.readers_do_not_block_writers(),
            path.with_extension("sqlite3-wal").exists(),
            "in {mode} mode the claim about readers and the write-ahead log on \
             disk must be the same fact told twice"
        );
        assert!(
            format!("{file:?}").contains(mode),
            "an operator reading a support bundle should see the mode"
        );
    }

    // -- the column/field mapping ------------------------------------------

    #[test]
    fn every_column_lands_in_the_field_of_the_same_name() {
        // `PersistedAttempt` and `PersistedPolicy` make the *field* names
        // compile-checked and say plainly that the *column* names are not. This
        // is the test they ask for: every column holds a value that appears
        // nowhere else in its row, so a transposition cannot survive it.
        //
        // The pairs this is really about are `created_at`/`last_state_change_at`
        // (both `Timestamp`) and `installation_id`/`revision` (both `u64`): each
        // transposes without a compile error, and each was a real defect in an
        // earlier positional signature.
        //
        // **This covers the read direction only**, and the name does not say so.
        // Every row here is written by hand through a `Raw*::insert`, so a
        // transposition in `policy_params` or `attempt_params` -- the write half
        // of the same crossing -- is invisible to it. The write direction is
        // pinned transitively instead, by the round-trip tests in
        // `tests/store_journal.rs`: a read proven correct here plus a domain
        // value that survives a store-and-load unchanged leaves no room for the
        // write to be transposed. That inference holds, but it is an inference,
        // and a reader of this test should know which half they are looking at.
        let store = store();

        RawHost {
            host_capacity: 7,
            refresh_interval_secs: 45,
            created_at: timestamp_to_text(ts(1_234)),
            display_name: "distinguishable-name".to_string(),
            ..RawHost::default()
        }
        .insert(&store);

        let host = store.host(host_id()).expect("loads").expect("present");
        assert_eq!(host.id, host_id(), "hosts.id");
        assert_eq!(host.display_name, "distinguishable-name");
        assert_eq!(host.host_capacity.get(), 7, "hosts.host_capacity");
        assert_eq!(
            host.refresh_interval.as_secs(),
            45,
            "hosts.refresh_interval_secs"
        );
        assert_eq!(host.created_at, ts(1_234), "hosts.created_at");
        assert_eq!(host.os, Os::Windows, "hosts.os");
        assert_eq!(host.architecture, Arch::X64, "hosts.architecture");
        assert_eq!(
            host.service_start_mode,
            StartMode::Boot,
            "hosts.service_start_mode"
        );

        RawPolicy {
            installation_id: 111,
            revision: 222,
            min_capacity: 3,
            max_capacity: Some(9),
            enabled: 0,
            state: "pending".to_string(),
            cache_policy: "discard_runner_package".to_string(),
            target_slug: "owner/repo".to_string(),
            ..RawPolicy::default()
        }
        .insert(&store);

        let policy = store.policy(policy_id()).expect("loads").expect("present");
        assert_eq!(policy.id, policy_id(), "policies.id");
        assert_eq!(policy.host_id, host_id(), "policies.host_id");
        assert_eq!(
            policy.installation_id, 111,
            "policies.installation_id must not come from policies.revision"
        );
        assert_eq!(
            policy.revision(),
            222,
            "policies.revision must not come from policies.installation_id"
        );
        assert_eq!(policy.min_capacity(), 3, "policies.min_capacity");
        assert_eq!(
            policy.max_capacity().expect("autoscale").get(),
            9,
            "policies.max_capacity"
        );
        assert!(!policy.enabled(), "policies.enabled");
        assert_eq!(policy.state(), PolicyState::Pending, "policies.state");
        assert_eq!(
            policy.cache_policy,
            CachePolicy::DiscardRunnerPackage,
            "policies.cache_policy"
        );
        assert_eq!(policy.target.slug(), "owner/repo", "policies.target_slug");
        assert_eq!(
            policy.target.scope(),
            TargetScope::Repository,
            "policies.target_scope"
        );
        assert_eq!(
            policy
                .routing_labels()
                .expect("autoscale")
                .host_label()
                .as_str(),
            "rm-home-win-x64",
            "policies.routing_labels"
        );

        RawAttempt {
            github_runner_id: Some(73),
            process_id: Some(4_242),
            state: "finished".to_string(),
            outcome: Some(COMPLETED_JOB.to_string()),
            runtime_path: "runtime/distinguishable".to_string(),
            created_at: timestamp_to_text(ts(1_000)),
            last_state_change_at: timestamp_to_text(ts(2_000)),
            terminal_at: Some(timestamp_to_text(ts(3_000))),
            ..RawAttempt::default()
        }
        .insert(&store);

        let attempt = store
            .attempt(attempt_id())
            .expect("loads")
            .expect("present");
        assert_eq!(attempt.id, attempt_id(), "attempts.id");
        assert_eq!(attempt.policy_id, policy_id(), "attempts.policy_id");
        assert_eq!(
            attempt.github_runner_id(),
            Some(73),
            "attempts.github_runner_id"
        );
        assert_eq!(attempt.process_id(), Some(4_242), "attempts.process_id");
        assert_eq!(attempt.state(), AttemptState::Finished, "attempts.state");
        assert_eq!(
            attempt.outcome(),
            Some(&AttemptOutcome::CompletedJob),
            "attempts.outcome"
        );
        assert_eq!(
            attempt.runtime_path(),
            Path::new("runtime/distinguishable"),
            "attempts.runtime_path"
        );
        assert_eq!(
            attempt.created_at,
            ts(1_000),
            "attempts.created_at must not come from attempts.last_state_change_at"
        );
        assert_eq!(
            attempt.last_state_change_at(),
            ts(2_000),
            "attempts.last_state_change_at must not come from attempts.created_at; \
             every recovery timeout is measured from it"
        );
        assert_eq!(
            attempt.terminal_at(),
            Some(ts(3_000)),
            "attempts.terminal_at"
        );
    }

    // -- hand-corrupted rows ------------------------------------------------

    #[test]
    fn a_hand_corrupted_policy_shape_is_rejected_on_load() {
        // D19 says `MonitorOnly` requires both `routing_labels` and
        // `max_capacity` to be NULL and `Autoscale` requires both to be present.
        // The columns admit four combinations; two are illegal, and each gets its
        // own error rather than being coerced into something plausible.
        let store = store();

        RawPolicy {
            routing_labels: Some(LABELS_JSON.to_string()),
            max_capacity: None,
            ..RawPolicy::default()
        }
        .insert(&store);
        assert!(
            matches!(
                store.policy(policy_id()),
                Err(StoreError::CorruptPolicy {
                    source: PolicyError::AutoscaleWithoutMaxCapacity,
                    ..
                })
            ),
            "labels without a ceiling could oversubscribe the host"
        );

        RawPolicy {
            routing_labels: None,
            max_capacity: Some(2),
            ..RawPolicy::default()
        }
        .insert(&store);
        assert!(matches!(
            store.policy(policy_id()),
            Err(StoreError::CorruptPolicy {
                source: PolicyError::AutoscaleWithoutRoutingLabels,
                ..
            })
        ));

        RawPolicy {
            routing_labels: None,
            max_capacity: None,
            min_capacity: 1,
            ..RawPolicy::default()
        }
        .insert(&store);
        assert!(matches!(
            store.policy(policy_id()),
            Err(StoreError::CorruptPolicy {
                source: PolicyError::MonitorOnlyWithMinCapacity { min: 1 },
                ..
            })
        ));

        RawPolicy {
            min_capacity: 3,
            max_capacity: Some(2),
            ..RawPolicy::default()
        }
        .insert(&store);
        assert!(
            matches!(
                store.policy(policy_id()),
                Err(StoreError::CorruptPolicy {
                    source: PolicyError::InvertedCapacityRange { min: 3, max: 2 },
                    ..
                })
            ),
            "an inverted range makes clamp(demand, min, max) panic, so it must \
             not survive a load"
        );

        // A scope/slug pair that cannot exist: `Org::new` rejects a slash.
        RawPolicy {
            target_scope: "organization".to_string(),
            target_slug: "o/r".to_string(),
            ..RawPolicy::default()
        }
        .insert(&store);
        assert!(
            matches!(
                store.policy(policy_id()),
                Err(StoreError::CorruptPolicy {
                    source: PolicyError::Invalid(ValidationError::IllegalCharacter {
                        found: '/',
                        ..
                    }),
                    ..
                })
            ),
            "the target is rebuilt through the real constructor, so GitHub's \
             naming rules run again on load"
        );

        // And the columns that carry no domain type of their own.
        for (label, raw) in [
            (
                "a zero ceiling",
                RawPolicy {
                    max_capacity: Some(0),
                    ..RawPolicy::default()
                },
            ),
            (
                "a third spelling of enabled",
                RawPolicy {
                    enabled: 7,
                    ..RawPolicy::default()
                },
            ),
            (
                "an unrecognised state",
                RawPolicy {
                    state: "retired".to_string(),
                    ..RawPolicy::default()
                },
            ),
            (
                "a negative revision",
                RawPolicy {
                    revision: -1,
                    ..RawPolicy::default()
                },
            ),
            (
                "a routing label carrying the separator the runner splits on",
                RawPolicy {
                    routing_labels: Some(r#"{"host_label":"bad,label"}"#.to_string()),
                    ..RawPolicy::default()
                },
            ),
        ] {
            raw.insert(&store);
            assert!(
                matches!(
                    store.policy(policy_id()),
                    Err(StoreError::CorruptColumn { .. })
                ),
                "{label} must be reported as a corrupt column"
            );
        }
    }

    #[test]
    fn a_hand_corrupted_host_row_is_rejected_on_load() {
        let store = store();

        RawHost {
            refresh_interval_secs: 1,
            ..RawHost::default()
        }
        .insert(&store);
        assert!(
            matches!(
                store.host(host_id()),
                Err(StoreError::CorruptHost {
                    source: ValidationError::BelowFloor {
                        min: 30,
                        actual: 1,
                        ..
                    },
                    ..
                })
            ),
            "a hand-edited row must not make this host poll every second; the \
             floor is a rate-budget constraint"
        );

        RawHost {
            display_name: "   ".to_string(),
            ..RawHost::default()
        }
        .insert(&store);
        assert!(matches!(
            store.host(host_id()),
            Err(StoreError::CorruptHost {
                source: ValidationError::Empty { .. },
                ..
            })
        ));

        for (label, raw) in [
            (
                "zero capacity",
                RawHost {
                    host_capacity: 0,
                    ..RawHost::default()
                },
            ),
            (
                "an unsupported operating system",
                RawHost {
                    os: "plan9".to_string(),
                    ..RawHost::default()
                },
            ),
            (
                "a malformed created_at",
                RawHost {
                    created_at: "yesterday".to_string(),
                    ..RawHost::default()
                },
            ),
        ] {
            raw.insert(&store);
            assert!(
                matches!(store.host(host_id()), Err(StoreError::CorruptColumn { .. })),
                "{label} must be reported as a corrupt column"
            );
        }
    }

    #[test]
    fn a_hand_corrupted_attempt_row_is_rejected_on_load() {
        let store = store();

        for (label, raw) in [
            (
                "terminal with no outcome",
                RawAttempt {
                    state: "finished".to_string(),
                    outcome: None,
                    terminal_at: Some(timestamp_to_text(ts(2_000))),
                    ..RawAttempt::default()
                },
            ),
            (
                "non-terminal carrying an outcome",
                RawAttempt {
                    state: "busy".to_string(),
                    outcome: Some(COMPLETED_JOB.to_string()),
                    ..RawAttempt::default()
                },
            ),
            (
                "a failed attempt claiming it ran a job",
                RawAttempt {
                    state: "failed".to_string(),
                    outcome: Some(COMPLETED_JOB.to_string()),
                    terminal_at: Some(timestamp_to_text(ts(2_000))),
                    ..RawAttempt::default()
                },
            ),
            (
                "terminal with no terminal_at",
                RawAttempt {
                    state: "finished".to_string(),
                    outcome: Some(COMPLETED_JOB.to_string()),
                    terminal_at: None,
                    ..RawAttempt::default()
                },
            ),
        ] {
            raw.insert(&store);
            assert!(
                matches!(
                    store.attempt(attempt_id()),
                    Err(StoreError::CorruptAttempt { .. })
                ),
                "{label} must not load"
            );
        }

        for (label, raw) in [
            (
                "a negative process id",
                RawAttempt {
                    process_id: Some(-1),
                    ..RawAttempt::default()
                },
            ),
            (
                "an unrecognised state",
                RawAttempt {
                    state: "wedged".to_string(),
                    ..RawAttempt::default()
                },
            ),
            (
                "an outcome that is not one",
                RawAttempt {
                    state: "finished".to_string(),
                    outcome: Some(r#"{"outcome":"went_home"}"#.to_string()),
                    terminal_at: Some(timestamp_to_text(ts(2_000))),
                    ..RawAttempt::default()
                },
            ),
            (
                "a malformed created_at",
                RawAttempt {
                    created_at: "yesterday".to_string(),
                    ..RawAttempt::default()
                },
            ),
        ] {
            raw.insert(&store);
            assert!(
                matches!(
                    store.attempt(attempt_id()),
                    Err(StoreError::CorruptColumn { .. })
                ),
                "{label} must be reported as a corrupt column"
            );
        }
    }

    // -- optimistic concurrency ---------------------------------------------

    #[test]
    fn a_stale_revision_write_is_rejected_and_is_not_an_io_error() {
        let store = store();
        let mut policy = ScalePolicy::new(
            policy_id(),
            ScaleTarget::repository("o/r").expect("valid"),
            1,
            host_id(),
            PolicyMode::autoscale(
                RoutingLabels::from_host_label(Label::new("rm-home-win-x64").expect("valid")),
                0,
                NonZeroU16::new(2).expect("non-zero"),
            )
            .expect("valid"),
            CachePolicy::default(),
        );
        store.insert_policy(&policy).expect("inserted");
        assert_eq!(policy.revision(), 0);

        // The TUI reads revision 0 and enables the policy.
        let mut tui_copy = store.policy(policy_id()).expect("loads").expect("present");
        tui_copy.activate().expect("a pending policy activates");
        store
            .update_policy(&tui_copy, 0)
            .expect("the first write wins");
        assert_eq!(
            store
                .policy(policy_id())
                .expect("loads")
                .expect("present")
                .revision(),
            1
        );

        // A CLI invocation that read revision 0 before that write now tries its
        // own change.
        policy
            .set_max_capacity(NonZeroU16::new(5).expect("non-zero"))
            .expect("autoscale");
        let error = store
            .update_policy(&policy, 0)
            .expect_err("the second write must be rejected");
        assert!(
            matches!(
                error,
                StoreError::StaleRevision {
                    expected: 0,
                    found: 1,
                    ..
                }
            ),
            "expected a stale-revision rejection, got {error:?}"
        );
        assert!(
            error.is_conflict(),
            "the caller must be able to tell a lost race from an I/O failure"
        );

        // And nothing was written: the loser's ceiling is not in the database and
        // the winner's change is intact.
        let stored = store.policy(policy_id()).expect("loads").expect("present");
        assert_eq!(stored.max_capacity().expect("autoscale").get(), 2);
        assert!(stored.enabled());

        // Re-reading and re-applying succeeds, which is the documented recovery.
        let mut fresh = stored;
        fresh
            .set_max_capacity(NonZeroU16::new(5).expect("non-zero"))
            .expect("autoscale");
        store.update_policy(&fresh, 1).expect("the retry wins");
        assert_eq!(
            store
                .policy(policy_id())
                .expect("loads")
                .expect("present")
                .max_capacity()
                .expect("autoscale")
                .get(),
            5
        );
    }

    #[test]
    fn removing_a_policy_takes_the_same_revision_check() {
        let store = store();
        RawPolicy {
            revision: 4,
            ..RawPolicy::default()
        }
        .insert(&store);

        let error = store
            .remove_policy(policy_id(), 3)
            .expect_err("a stale delete must be rejected");
        assert!(error.is_conflict(), "got {error:?}");
        assert!(
            store.policy(policy_id()).expect("loads").is_some(),
            "a rejected delete must not delete"
        );

        store
            .remove_policy(policy_id(), 4)
            .expect("the current revision deletes");
        assert!(store.policy(policy_id()).expect("loads").is_none());
    }

    #[test]
    fn a_revision_guarded_write_to_a_missing_row_is_not_found_not_a_conflict() {
        let store = store();
        let error = store
            .remove_policy(policy_id(), 0)
            .expect_err("there is nothing to delete");
        assert!(
            matches!(error, StoreError::NotFound { what: "policy", .. }),
            "a missing row is a different problem from a lost race: {error:?}"
        );
        assert!(!error.is_conflict());
    }

    #[test]
    fn inserting_a_policy_twice_is_reported_as_already_existing() {
        let store = store();
        RawPolicy::default().insert(&store);
        let policy = store.policy(policy_id()).expect("loads").expect("present");
        let error = store.insert_policy(&policy).expect_err("the id is taken");
        assert!(
            matches!(error, StoreError::AlreadyExists { what: "policy", .. }),
            "got {error:?}"
        );
    }

    // -- the journal --------------------------------------------------------

    #[test]
    fn created_at_is_never_rewritten_by_a_later_journal_write() {
        let store = store();
        let allocated = RunnerAttempt::allocate(attempt_id(), policy_id(), "runtime/x", ts(1_000));
        store.record_attempt(&allocated).expect("journalled");

        // A later write claiming a different allocation instant. `created_at` is
        // absent from the upsert's DO UPDATE list precisely so this cannot move
        // it; every elapsed-time calculation downstream depends on it.
        let rewritten = RunnerAttempt::from_persisted(PersistedAttempt {
            created_at: ts(5_000),
            last_state_change_at: ts(5_000),
            ..allocated.to_persisted()
        })
        .expect("a legal attempt");
        store.record_attempt(&rewritten).expect("journalled");

        let stored = store
            .attempt(attempt_id())
            .expect("loads")
            .expect("present");
        assert_eq!(stored.created_at, ts(1_000), "created_at never moves");
        assert_eq!(
            stored.last_state_change_at(),
            ts(5_000),
            "every other column is updated in place"
        );
    }

    #[test]
    fn a_backwards_clock_is_clamped_on_write_and_on_load() {
        // The hazard `SqliteStore::normalise` exists for. `move_to` accepts any
        // `now`, so a wall clock stepping backwards between two transitions
        // builds an in-memory attempt that `from_persisted` refuses -- which
        // would leave a journal row nothing can ever load, holding a capacity
        // slot and an uncleaned runtime directory for ever.
        let store = store();
        let mut attempt =
            RunnerAttempt::allocate(attempt_id(), policy_id(), "runtime/x", ts(1_000));
        attempt
            .jit_received(ts(900))
            .expect("the domain accepts a backwards `now` with no ordering check");

        // The load path really would refuse this, so the repair below is
        // load-bearing rather than decorative.
        assert!(
            matches!(
                RunnerAttempt::from_persisted(attempt.to_persisted()),
                Err(AttemptError::TimestampsOutOfOrder {
                    field: "last_state_change_at",
                    ..
                })
            ),
            "if the domain ever accepts this, `normalise` is dead code and should go"
        );

        store.record_attempt(&attempt).expect("journalled");
        assert_eq!(store.clock_skew_repairs(), 1);
        {
            let conn = store.lock();
            let raw: String = conn
                .query_row(
                    "SELECT last_state_change_at FROM attempts WHERE id = ?1",
                    [ATTEMPT_UUID],
                    |row| row.get(0),
                )
                .expect("readable");
            assert_eq!(
                raw,
                timestamp_to_text(ts(1_000)),
                "the write path stores a row that can be read back, not one that \
                 poisons the journal"
            );
        }
        let back = store
            .attempt(attempt_id())
            .expect("loads")
            .expect("present");
        assert_eq!(back.last_state_change_at(), ts(1_000));
        assert_eq!(
            store.clock_skew_repairs(),
            1,
            "the stored row is already sound, so loading it repairs nothing"
        );

        // A row this build did not write -- an older version, or a hand edit --
        // is repaired on the way out instead.
        RawAttempt {
            created_at: timestamp_to_text(ts(1_000)),
            last_state_change_at: timestamp_to_text(ts(400)),
            state: "finished".to_string(),
            outcome: Some(COMPLETED_JOB.to_string()),
            terminal_at: Some(timestamp_to_text(ts(500))),
            ..RawAttempt::default()
        }
        .insert(&store);
        let repaired = store
            .attempt(attempt_id())
            .expect("loads")
            .expect("present");
        assert_eq!(repaired.last_state_change_at(), ts(1_000));
        assert_eq!(repaired.terminal_at(), Some(ts(1_000)));
        assert_eq!(
            store.clock_skew_repairs(),
            3,
            "both out-of-order timestamps are counted, and each is logged at warn"
        );
    }

    #[test]
    fn a_runtime_path_that_is_not_utf8_is_refused_rather_than_mangled() {
        // `e3` deletes the directory this path names. A lossy conversion would
        // either fail to delete or name a different directory, so the write is
        // refused instead.
        #[cfg(windows)]
        let bad: PathBuf = {
            use std::os::windows::ffi::OsStringExt as _;
            // An unpaired surrogate: a legal Windows path, not legal UTF-8.
            std::ffi::OsString::from_wide(&[0x0072, 0xD800]).into()
        };
        #[cfg(not(windows))]
        let bad: PathBuf = {
            use std::os::unix::ffi::OsStringExt as _;
            std::ffi::OsString::from_vec(vec![b'r', 0xFF]).into()
        };
        assert!(bad.to_str().is_none(), "the fixture path must be non-UTF-8");

        let store = store();
        let attempt = RunnerAttempt::allocate(attempt_id(), policy_id(), bad, ts(1_000));
        let error = store
            .record_attempt(&attempt)
            .expect_err("a path that cannot round-trip must not be stored");
        assert!(
            matches!(error, StoreError::UnrepresentablePath { .. }),
            "got {error:?}"
        );
    }

    #[test]
    fn an_integer_too_large_for_a_sqlite_integer_is_refused_rather_than_truncated() {
        // SQLite has no unsigned 64-bit type. Saturating at `i64::MAX` would
        // store one number and read a different one back with nothing to say so,
        // and both `u64` the domain carries -- the GitHub runner id and the
        // installation id -- come from GitHub, so this is a path a caller can
        // reach rather than a theoretical one.
        let store = store();

        let mut attempt =
            RunnerAttempt::allocate(attempt_id(), policy_id(), "runtime/x", ts(1_000));
        attempt.jit_received(ts(1_001)).expect("a legal transition");
        attempt
            .started(4_242, ts(1_002))
            .expect("a legal transition");
        attempt
            .registered_idle(u64::MAX, ts(1_003))
            .expect("the domain accepts any u64 as a runner id");
        let error = store
            .record_attempt(&attempt)
            .expect_err("a value SQLite cannot hold must not be silently truncated");
        assert!(
            matches!(
                error,
                StoreError::UnrepresentableInteger {
                    what: "attempts.github_runner_id",
                    value: u64::MAX,
                }
            ),
            "got {error:?}"
        );

        // The largest value that does fit still round-trips exactly, so the
        // refusal is an edge and not a blanket ceiling.
        let biggest = u64::try_from(i64::MAX).expect("i64::MAX is a valid u64");
        let mut ok = RunnerAttempt::allocate(
            AttemptId::from_u128(0x0000_0101),
            policy_id(),
            "runtime/y",
            ts(1_000),
        );
        ok.jit_received(ts(1_001)).expect("a legal transition");
        ok.started(1, ts(1_002)).expect("a legal transition");
        ok.registered_idle(biggest, ts(1_003))
            .expect("a legal transition");
        store.record_attempt(&ok).expect("journalled");
        assert_eq!(
            store
                .attempt(ok.id)
                .expect("loads")
                .expect("present")
                .github_runner_id(),
            Some(biggest)
        );

        // And the same on the policy side.
        let policy = ScalePolicy::new(
            policy_id(),
            ScaleTarget::repository("o/r").expect("valid"),
            u64::MAX,
            host_id(),
            PolicyMode::monitor_only(),
            CachePolicy::default(),
        );
        let error = store
            .insert_policy(&policy)
            .expect_err("an installation id SQLite cannot hold must not be truncated");
        assert!(
            matches!(
                error,
                StoreError::UnrepresentableInteger {
                    what: "policies.installation_id",
                    ..
                }
            ),
            "got {error:?}"
        );
    }

    #[test]
    fn attempts_are_listed_oldest_first_and_can_be_filtered_by_policy() {
        let store = store();
        let other_policy = PolicyId::from_u128(0x0000_0011);

        let first = RunnerAttempt::allocate(
            AttemptId::from_u128(0xA1),
            policy_id(),
            "runtime/a1",
            ts(1_000),
        );
        let second = RunnerAttempt::allocate(
            AttemptId::from_u128(0xA2),
            other_policy,
            "runtime/a2",
            ts(2_000),
        );
        let third = RunnerAttempt::allocate(
            AttemptId::from_u128(0xA3),
            policy_id(),
            "runtime/a3",
            ts(3_000),
        );
        for attempt in [&third, &first, &second] {
            store.record_attempt(attempt).expect("journalled");
        }

        assert_eq!(
            store
                .attempts()
                .expect("loads")
                .iter()
                .map(|a| a.created_at)
                .collect::<Vec<_>>(),
            vec![ts(1_000), ts(2_000), ts(3_000)],
            "insertion order must not decide read order"
        );

        assert_eq!(
            store.attempts_for_policy(policy_id()).expect("loads"),
            vec![first.clone(), third]
        );

        assert!(store.remove_attempt(first.id).expect("removable"));
        assert!(
            !store.remove_attempt(first.id).expect("idempotent"),
            "removing an absent attempt is not an error, it is a `false`"
        );
        assert_eq!(store.attempts().expect("loads").len(), 2);
    }

    #[test]
    fn the_store_is_usable_as_a_shared_trait_object() {
        // The agent holds one handle across tasks while the TUI reads through
        // it. If this stops compiling, every caller has to change shape.
        let concrete = store();
        RawHost::default().insert(&concrete);
        let store: Arc<dyn Store> = Arc::new(concrete);

        let handle = Arc::clone(&store);
        let seen = std::thread::spawn(move || handle.host(host_id()).expect("loads").is_some())
            .join()
            .expect("the reader thread did not panic");
        assert!(seen);
        assert!(store.policies().expect("loads").is_empty());
    }

    #[test]
    fn the_dump_names_every_table_and_reaches_every_column() {
        let store = store();
        RawHost::default().insert(&store);
        RawPolicy::default().insert(&store);
        RawAttempt::default().insert(&store);

        let dump = store.dump_text().expect("dumpable");
        for table in TABLES {
            assert!(
                dump.contains(&format!("-- table {table}")),
                "{table} is missing from the dump"
            );
        }
        assert!(dump.contains(&format!("-- schema version {SCHEMA_VERSION}")));
        assert!(dump.contains("hosts.display_name=home-pc"));
        assert!(dump.contains("policies.target_slug=o/r"));
        assert!(dump.contains("attempts.outcome=NULL"));
        assert!(
            dump.contains("attempts.runtime_path=runtime/policy/attempt"),
            "a dump that omitted a column would make the security scan vacuous"
        );

        // A free-form string reaches the dump, which is why `07-security.md`'s
        // scan runs over the dump rather than over the schema: the schema alone
        // cannot say what a caller put in `FailureReason::Other`.
        let reason = FailureReason::Other("no credential here".to_string());
        assert!(json(&AttemptOutcome::failed(reason)).contains("no credential here"));
    }
}
