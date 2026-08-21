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
    #[error("{table}.{column} of row {id} holds {value}, which is not {expected}")]
    CorruptColumn {
        table: &'static str,
        column: &'static str,
        id: String,
        value: String,
        expected: &'static str,
    },

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

fn current_version(conn: &Connection) -> Result<u32, rusqlite::Error> {
    let max: Option<i64> =
        conn.query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })?;
    // A negative or absurd recorded version is corrupted bookkeeping. Reading it
    // as "newer than anything this build knows" is the fail-closed direction: it
    // refuses to run rather than re-applying a migration over live data.
    Ok(max.map_or(0, |v| u32::try_from(v).unwrap_or(u32::MAX)))
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
/// Opened in WAL mode with `synchronous = FULL`. WAL so that a reader — the TUI
/// — does not block the agent's journal writes, and `FULL` because this journal
/// exists precisely to survive an unclean stop: a handful of fsyncs per runner
/// attempt is not a cost worth trading for the chance of losing the last write
/// before a power cut.
pub struct SqliteStore {
    conn: Mutex<Connection>,
    path: Option<PathBuf>,
    schema_version: u32,
    clock_skew_repairs: AtomicU64,
}

impl fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteStore")
            .field("path", &self.path)
            .field("schema_version", &self.schema_version)
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
        // A row-returning pragma, so it cannot go through `execute`. An
        // in-memory database answers `memory` and that is fine; nothing here
        // depends on the mode, only on not blocking a reader where the mode is
        // available.
        let _mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
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
            clock_skew_repairs: AtomicU64::new(0),
        })
    }

    /// The schema version this database is at.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
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
        let params = policy_params(&fields);
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
        let mut params = policy_params(&fields);
        params.push((":expected_revision", int(u64_to_sql(expected_revision))));

        let mut conn = self.lock();
        // IMMEDIATE, not the default DEFERRED: a deferred transaction takes its
        // write lock only at the UPDATE, so two writers that both read and then
        // upgrade produce SQLITE_BUSY on the second rather than a clean
        // stale-revision answer. Taking the lock up front makes the loser wait
        // and then see the winner's revision, which is the whole point of the
        // token.
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
                ":expected_revision": u64_to_sql(expected_revision),
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

fn policy_params(fields: &PersistedPolicy) -> NamedParams {
    vec![
        (":id", text(uuid_text(fields.id.as_uuid()))),
        (":target_scope", text(token(&fields.target.scope()))),
        (":target_slug", text(fields.target.slug())),
        (":installation_id", int(u64_to_sql(fields.installation_id))),
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
        (":revision", int(u64_to_sql(fields.revision))),
    ]
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
            opt_int(fields.github_runner_id.map(u64_to_sql)),
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
        Some(found) => StoreError::StaleRevision {
            id,
            expected,
            found: u64::try_from(found).unwrap_or(0),
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
/// representation. Nothing in this domain produces one — a revision counts
/// operator edits and an installation id is GitHub's — so the saturation is
/// unreachable in practice and is written down rather than left as an unchecked
/// cast.
fn u64_to_sql(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
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
        id: raw.clone(),
        value: raw,
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
            value: raw,
            expected: "one of this column's recognised tokens",
        }
    })
}

fn json_column<T: DeserializeOwned>(
    row: &Row<'_>,
    table: &'static str,
    column: &'static str,
    id: &str,
    expected: &'static str,
) -> Result<Option<T>, StoreError> {
    match row.get::<_, Option<String>>(column)? {
        None => Ok(None),
        Some(raw) => serde_json::from_str(&raw)
            .map(Some)
            .map_err(|_| StoreError::CorruptColumn {
                table,
                column,
                id: id.to_string(),
                value: raw,
                expected,
            }),
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
            value: raw.to_string(),
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
