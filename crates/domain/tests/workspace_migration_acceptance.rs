// owner: f1-workspace-security-acceptance

//! The migration, recovery-input and rollback half of Wave 5's acceptance.
//!
//! ----------------------------------------------------------------------------
//! WHAT THIS ADDS OVER `store.rs`'s OWN MIGRATION TESTS.
//! ----------------------------------------------------------------------------
//! `store::tests` already proves the *chain* — that a version-1 or version-2
//! database gains the three workspace columns, that every migrated row becomes
//! ephemeral, and that a newer database is refused. Those tests run inside the
//! crate against `MIGRATIONS[..n]`, and that is the right place for them.
//!
//! What they cannot do is the thing `03-migration-rollout.md` actually gates on,
//! because it is not a property of the chain:
//!
//! * **The upgrade happens next to real directories.** Phase 0's gate is "a
//!   copied production-like version-2 database opens, recovers an old attempt
//!   path, and starts no new attempt before recovery completes". The half a
//!   database test can carry is that the journalled paths still name the *old*
//!   directories, that those directories are still there afterwards, and that
//!   none of them is under the new default root. Every one of those is a
//!   filesystem fact, so this file plants the directories and reads them back.
//! * **The lease index has to be live the moment the upgrade finishes.** Every
//!   index test in `store.rs` starts from a database that was *created* at
//!   version 3. A `CREATE UNIQUE INDEX` that migration 3 forgot, or that a
//!   `ALTER TABLE` ordering broke, would pass all of them and fail only on an
//!   upgraded host — which is the only kind of host that matters here.
//! * **Rollback is a whole rehearsal, not an assertion.** "Rollback restores
//!   binary and database while leaving every runner and persistent directory
//!   untouched" spans a backup taken before the upgrade, an upgrade that writes
//!   version-3-only rows, a restore, and a filesystem that must be byte-for-byte
//!   what it was. There is nothing in `store.rs` to hang that on.
//!
//! ----------------------------------------------------------------------------
//! WHY THE OLD DATABASE IS BUILT FROM THE SHIPPED MIGRATION FILES.
//! ----------------------------------------------------------------------------
//! `MIGRATIONS` is private, so this file cannot ask the store for "the chain up
//! to 2". It applies `0001_initial_schema.sql` and `0002_policy_host_label.sql`
//! through `include_str!` instead — the same bytes a version-2 host really ran,
//! recorded in `schema_migrations` the same way [`apply_migrations`] records
//! them. A hand-written approximation of the old shape would be a fixture that
//! agrees with itself and with nothing else; these two files are history, and
//! the header of `0001` says they may never be edited, so they stay accurate.
//!
//! ----------------------------------------------------------------------------
//! NOTHING HERE IS WRITTEN OUTSIDE A `TempDir`.
//! ----------------------------------------------------------------------------
//! Every path this file creates, reads or compares is inside one
//! `tempfile::tempdir()`, and nothing is ever deleted by the code under test:
//! the properties being measured are all "this still exists and still says what
//! it said". `04-security-recovery.md`'s "No cleanup test writes outside its
//! temporary approved root" is therefore satisfied by construction rather than
//! by care.

use std::collections::BTreeMap;
use std::fs;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};

use runner_manager_domain::attempt::{AttemptState, RunnerAttempt};
use runner_manager_domain::model::{AttemptId, PolicyId};
use runner_manager_domain::path::LocalAbsolutePath;
use runner_manager_domain::store::{SCHEMA_VERSION, SqliteStore, Store, StoreError};
use runner_manager_domain::workspace::{AttemptWorkspace, WorkspacePolicy};
use runner_manager_testkit::fixtures;
use rusqlite::Connection;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// The version-2 host this file upgrades
// ---------------------------------------------------------------------------

/// The two steps a version-2 database has applied, as history wrote them.
const MIGRATION_0001: &str = include_str!("../src/store/migrations/0001_initial_schema.sql");
const MIGRATION_0002: &str = include_str!("../src/store/migrations/0002_policy_host_label.sql");

/// Fixed identifiers, so an assertion can name the row it is about.
const HOST_UUID: &str = "6f8b1f8c-0b3a-4a1e-9d2f-000000000001";
const REPOSITORY_POLICY_UUID: &str = "6f8b1f8c-0b3a-4a1e-9d2f-000000000002";
const ORGANIZATION_POLICY_UUID: &str = "6f8b1f8c-0b3a-4a1e-9d2f-000000000003";
const IDLE_ATTEMPT_UUID: &str = "6f8b1f8c-0b3a-4a1e-9d2f-000000000004";
const BUSY_ATTEMPT_UUID: &str = "6f8b1f8c-0b3a-4a1e-9d2f-000000000005";
const TERMINAL_ATTEMPT_UUID: &str = "6f8b1f8c-0b3a-4a1e-9d2f-000000000006";

const TIMESTAMP: &str = "2026-01-01T00:00:00.000000000Z";

/// A version-2 host as it exists on disk: a database, the application `runtime`
/// directory its attempts were created in, and the directory the new default
/// would put the *next* attempt in.
struct VersionTwoHost {
    /// Everything below here is disposable.
    root: tempfile::TempDir,
}

/// One planted directory and the file that proves it was not touched.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sentinel {
    directory: PathBuf,
    file: PathBuf,
    contents: String,
}

impl Sentinel {
    /// Creates the directory and writes the marker.
    fn plant(directory: PathBuf, contents: &str) -> Self {
        fs::create_dir_all(&directory).expect("a temporary directory is creatable");
        let file = directory.join("sentinel.txt");
        fs::write(&file, contents).expect("a temporary file is writable");
        Self {
            directory,
            file,
            contents: contents.to_owned(),
        }
    }

    /// Re-reads it, and says what a mismatch means.
    fn assert_untouched(&self, what_happened: &str) {
        assert!(
            self.directory.is_dir(),
            "{what_happened} removed {}, and `03-migration-rollout.md` says the \
             upgrade `does not move the old application runtime directory`",
            self.directory.display()
        );
        let found = fs::read_to_string(&self.file).unwrap_or_else(|error| {
            panic!(
                "{what_happened} made {} unreadable: {error}",
                self.file.display()
            )
        });
        assert_eq!(
            found,
            self.contents,
            "{what_happened} rewrote {}",
            self.file.display()
        );
    }
}

impl VersionTwoHost {
    /// Builds the database, plants the directories, and returns both.
    ///
    /// The attempt rows point at `runtime/<attempt>` under this host's own
    /// application data, which is exactly where a version-2 build put them, and
    /// deliberately **not** under [`Self::new_default_root`].
    fn plant() -> (Self, BTreeMap<&'static str, Sentinel>) {
        let root = tempfile::tempdir().expect("a temporary directory");
        let host = Self { root };

        fs::create_dir_all(host.database().parent().expect("a config directory"))
            .expect("creatable");

        let mut sentinels = BTreeMap::new();
        for (name, id) in [
            ("idle", IDLE_ATTEMPT_UUID),
            ("busy", BUSY_ATTEMPT_UUID),
            ("terminal", TERMINAL_ATTEMPT_UUID),
        ] {
            sentinels.insert(
                name,
                Sentinel::plant(
                    host.old_runtime_directory(id),
                    &format!("attempt {id} was created here by a version-2 build"),
                ),
            );
        }
        // The new default root, and a repository's persistent root, both of
        // which the rollback gate says are never deleted.
        sentinels.insert(
            "new-default-root",
            Sentinel::plant(host.new_default_root(), "the short root the upgrade adopts"),
        );
        sentinels.insert(
            "persistent-work",
            Sentinel::plant(
                host.persistent_root().join("s1").join("_work"),
                "a checkout a later persistent job expects to still be here",
            ),
        );

        host.write_version_two_database();
        (host, sentinels)
    }

    fn database(&self) -> PathBuf {
        self.root
            .path()
            .join("config")
            .join("runner-manager.sqlite3")
    }

    fn backup(&self) -> PathBuf {
        self.root.path().join("runner-manager.sqlite3.v2-backup")
    }

    /// Where a version-2 build created attempt directories.
    fn old_runtime_directory(&self, attempt: &str) -> PathBuf {
        self.root.path().join("runtime").join(attempt)
    }

    /// A stand-in for `%SystemDrive%\rman`: short, outside the application data,
    /// and holding nothing any journalled attempt names.
    fn new_default_root(&self) -> PathBuf {
        self.root.path().join("rman")
    }

    fn persistent_root(&self) -> PathBuf {
        self.root.path().join("persistent")
    }

    /// Applies migrations 1 and 2 and writes the rows a shipped build left.
    fn write_version_two_database(&self) {
        let conn = Connection::open(self.database()).expect("a temporary database is openable");
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                 version    INTEGER NOT NULL PRIMARY KEY,
                 name       TEXT    NOT NULL,
                 applied_at TEXT    NOT NULL
             ) STRICT;",
        )
        .expect("the bootstrap table is creatable");

        for (version, name, sql) in [
            (1, "initial_schema", MIGRATION_0001),
            (2, "policy_host_label", MIGRATION_0002),
        ] {
            conn.execute_batch(sql)
                .unwrap_or_else(|error| panic!("migration {version} applies: {error}"));
            conn.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) \
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![version, name, TIMESTAMP],
            )
            .expect("the step is recordable");
        }

        conn.execute(
            "INSERT INTO hosts (
                 id, display_name, os, architecture, host_capacity,
                 service_start_mode, refresh_interval_secs, created_at
             ) VALUES (?1, 'production-like', ?2, 'x64', 4, 'boot', 60, ?3)",
            rusqlite::params![HOST_UUID, native_os_token(), TIMESTAMP],
        )
        .expect("a version-2 host row");

        // One repository policy and one organization policy, because D7 makes
        // them migrate for different reasons: the repository one *could* have
        // been made persistent later and was not, and the organization one may
        // never be. An upgrade that guessed would be caught by either. The
        // organization row is monitor-only, which is D19's NULL/NULL shape, so
        // the two rows also differ in the pair of columns migration 3 sits
        // beside.
        for (id, scope, slug, labels, max_capacity) in [
            (
                REPOSITORY_POLICY_UUID,
                "repository",
                "owner/repo",
                Some(r#"{"host_label":"rm-home-win-x64","additional":[]}"#),
                Some(2_i64),
            ),
            (
                ORGANIZATION_POLICY_UUID,
                "organization",
                "owner",
                None,
                None,
            ),
        ] {
            conn.execute(
                "INSERT INTO policies (
                     id, target_scope, target_slug, installation_id, host_id,
                     requested_host_label, routing_labels, min_capacity,
                     max_capacity, enabled, state, cache_policy, revision
                 ) VALUES (?1, ?2, ?3, 42, ?4, 'home-pc', ?5, 0, ?6, 1,
                           'active', 'retain_runner_package', 7)",
                rusqlite::params![id, scope, slug, HOST_UUID, labels, max_capacity],
            )
            .expect("a version-2 policy row");
        }

        // Three attempts in three states, because migration 3 defaults the two
        // new attempt columns and a `NOT NULL DEFAULT` that only reached the
        // rows a test happened to look at is the failure this guards.
        for (id, state, terminal) in [
            (IDLE_ATTEMPT_UUID, "idle", None),
            (BUSY_ATTEMPT_UUID, "busy", None),
            (TERMINAL_ATTEMPT_UUID, "finished", Some(TIMESTAMP)),
        ] {
            let outcome = terminal.map(|_| r#"{"outcome":"exited_idle_without_work"}"#);
            conn.execute(
                "INSERT INTO attempts (
                     id, policy_id, github_runner_id, state, outcome, process_id,
                     runtime_path, created_at, terminal_at, last_state_change_at
                 ) VALUES (?1, ?2, NULL, ?3, ?4, NULL, ?5, ?6, ?7, ?6)",
                rusqlite::params![
                    id,
                    REPOSITORY_POLICY_UUID,
                    state,
                    outcome,
                    self.old_runtime_directory(id)
                        .to_str()
                        .expect("a temporary path is UTF-8"),
                    TIMESTAMP,
                    terminal,
                ],
            )
            .expect("a version-2 attempt row");
        }
    }
}

/// The `os` token this build will accept back out of the row it reads.
///
/// A host row is re-validated on load, so a fixture that always said `windows`
/// would fail on the two legs that are not Windows for a reason that has
/// nothing to do with a migration.
fn native_os_token() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "mac_os"
    } else {
        "linux"
    }
}

/// `MAX(version)` as it stands in the file, which is the number an older build
/// compares against its own `SCHEMA_VERSION` before it will open anything.
fn recorded_version(path: &Path) -> i64 {
    let conn = Connection::open(path).expect("the database file is openable");
    conn.query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
        row.get(0)
    })
    .expect("a recorded schema version")
}

fn ids() -> (PolicyId, PolicyId, [AttemptId; 3]) {
    let uuid =
        |raw: &str| Uuid::parse_str(raw).expect("the fixture identifiers are well-formed UUIDs");
    let parse_policy = |raw: &str| PolicyId::from_uuid(uuid(raw));
    let parse_attempt = |raw: &str| AttemptId::from_uuid(uuid(raw));
    (
        parse_policy(REPOSITORY_POLICY_UUID),
        parse_policy(ORGANIZATION_POLICY_UUID),
        [
            parse_attempt(IDLE_ATTEMPT_UUID),
            parse_attempt(BUSY_ATTEMPT_UUID),
            parse_attempt(TERMINAL_ATTEMPT_UUID),
        ],
    )
}

fn attempt_of(store: &SqliteStore, id: AttemptId) -> RunnerAttempt {
    store
        .attempt(id)
        .expect("the journal is readable")
        .unwrap_or_else(|| panic!("attempt {id} survives the upgrade"))
}

// ---------------------------------------------------------------------------
// Phase 0: the upgrade
// ---------------------------------------------------------------------------

/// > A copied production-like version-2 database opens, recovers an old attempt
/// > path, and starts no new attempt before recovery completes.
///
/// The half that is a database fact and the half that is a filesystem fact, in
/// one place. The ordering itself belongs to the launcher and is proved by
/// `lifecycle::tests::startup_adopts_a_live_process_and_refuses_launch_before_recovery`;
/// what is proved here is the *input* that ordering depends on — that after the
/// upgrade every attempt still names the exact directory it was created in, that
/// the directory is still there with its contents, and that it is not under the
/// root the next attempt would use.
#[test]
fn a_production_like_version_two_database_upgrades_without_touching_a_directory() {
    let (host, sentinels) = VersionTwoHost::plant();
    let (repository, organization, attempts) = ids();

    assert_eq!(
        recorded_version(&host.database()),
        2,
        "the fixture must start where a shipped build left it"
    );

    let store = SqliteStore::open(host.database()).expect("a version-2 database opens");
    assert_eq!(store.schema_version(), SCHEMA_VERSION);

    // Every host is on the platform default. Storing the *effective* path would
    // freeze this machine's default into the database.
    let hosts = store.hosts().expect("the host table is readable");
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].runner_root_override, None);
    assert!(!hosts[0].has_configured_runner_root());
    assert_eq!(
        hosts[0].host_capacity.get(),
        4,
        "migration 3 adds a column; it does not rewrite the ones beside it"
    );

    // Both policies, whatever their scope, are ephemeral.
    for id in [repository, organization] {
        let policy = store
            .policy(id)
            .expect("the policy table is readable")
            .expect("the policy survives the upgrade");
        assert_eq!(
            policy.workspace_policy(),
            &WorkspacePolicy::Ephemeral,
            "an upgrade must not retain a workspace the operator never selected"
        );
        assert_eq!(
            policy.revision(),
            7,
            "a migration is not a domain mutation and must not advance the \
             optimistic-concurrency token"
        );
    }

    // Every attempt is ephemeral, holds no lease, and still names its own
    // directory — which is what makes recovery remove the right one.
    for (id, expected_state) in attempts.into_iter().zip([
        AttemptState::Idle,
        AttemptState::Busy,
        AttemptState::Finished,
    ]) {
        let attempt = attempt_of(&store, id);
        assert_eq!(attempt.state(), expected_state);
        assert_eq!(attempt.workspace(), AttemptWorkspace::Ephemeral);
        assert!(!attempt.holds_slot_lease());
        assert_eq!(
            attempt.runtime_path(),
            host.old_runtime_directory(&id.to_string()),
            "`No journal row is rewritten merely to adopt the new default`"
        );
        assert!(
            !attempt.runtime_path().starts_with(host.new_default_root()),
            "a migrated attempt must not be pointed at the new default root; \
             cleanup would then remove a directory the attempt never used"
        );
    }

    // And nothing on disk moved.
    for sentinel in sentinels.values() {
        sentinel.assert_untouched("opening a version-2 database");
    }
}

/// The durable lease guard has to exist on an **upgraded** host, not only on one
/// that was created at version 3.
///
/// `store::tests::one_slot_is_leased_to_at_most_one_uncleaned_attempt` proves
/// the index enforces; every database it proves it against was born at version
/// 3. A migration that added the columns and lost the `CREATE UNIQUE INDEX` — or
/// ran it before the `ALTER TABLE` it depends on — would pass there and leave
/// every upgraded host with no final guard at all.
#[test]
fn the_slot_lease_index_guards_an_upgraded_database_immediately() {
    let (host, _sentinels) = VersionTwoHost::plant();
    let (repository, ..) = ids();

    let store = SqliteStore::open(host.database()).expect("a version-2 database opens");

    let slot = NonZeroU16::new(1).expect("one is not zero");
    let first = fixtures::attempt()
        .id(AttemptId::new_random())
        .policy_id(repository)
        .state(AttemptState::Busy)
        .persistent_slot(slot.get())
        .runtime_path(
            host.persistent_root()
                .join("s1")
                .to_str()
                .expect("a temporary path is UTF-8")
                .to_owned(),
        )
        .build();
    store
        .record_attempt(&first)
        .expect("the first lease on a fresh slot is granted");

    let second = fixtures::attempt()
        .id(AttemptId::new_random())
        .policy_id(repository)
        .state(AttemptState::Allocated)
        .persistent_slot(slot.get())
        .runtime_path(
            host.persistent_root()
                .join("s1")
                .to_str()
                .expect("a temporary path is UTF-8")
                .to_owned(),
        )
        .build();
    let refusal = store
        .record_attempt(&second)
        .expect_err("the index must refuse a second uncleaned lease on one slot");
    assert!(
        matches!(
            &refusal,
            StoreError::SlotAlreadyLeased { policy, slot: taken }
                if *policy == repository && *taken == slot.get()
        ),
        "an upgraded database must refuse the duplicate lease by name, got {refusal:?}"
    );

    let leases = store
        .slot_leases_for_policy(repository)
        .expect("the lease view is readable");
    assert_eq!(
        leases.len(),
        1,
        "exactly one uncleaned attempt may hold slot s1"
    );
}

/// > An older binary sees schema version 3 as newer than supported and fails
/// > closed.
///
/// Measured in the direction this build can actually measure it: a database one
/// step beyond `SCHEMA_VERSION` is refused with both numbers named, through the
/// same comparison an old build applies to a version-3 file.
#[test]
fn a_database_from_a_newer_build_is_refused_with_both_numbers() {
    let (host, sentinels) = VersionTwoHost::plant();

    let store = SqliteStore::open(host.database()).expect("a version-2 database opens");
    drop(store);

    let conn = Connection::open(host.database()).expect("openable");
    conn.execute(
        "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![
            i64::from(SCHEMA_VERSION) + 1,
            "a_step_this_build_never_shipped",
            TIMESTAMP
        ],
    )
    .expect("a newer build's bookkeeping");
    drop(conn);

    let refusal = SqliteStore::open(host.database())
        .expect_err("a database from a newer build must not be guessed at");
    assert!(
        matches!(
            refusal,
            StoreError::SchemaTooNew { found, supported }
                if found == SCHEMA_VERSION + 1 && supported == SCHEMA_VERSION
        ),
        "the refusal must name what it found and what it supports, got {refusal:?}"
    );
    assert!(!refusal.is_conflict(), "this is not a retryable conflict");

    // Failing closed is not a licence to delete anything on the way out.
    for sentinel in sentinels.values() {
        sentinel.assert_untouched("refusing a newer database");
    }
}

// ---------------------------------------------------------------------------
// The rollback gate
// ---------------------------------------------------------------------------

/// > Rollback restores binary and database while leaving every runner and
/// > persistent directory untouched.
///
/// The whole rehearsal, in the order `03-migration-rollout.md` states it: copy
/// the database while the daemon is stopped, upgrade, do version-3-only work
/// (configure a persistent repository and lease a slot), then put the old
/// database back and prove three things — the restored file is at the version
/// the old build supports, the upgraded file is at the version it rejects, and
/// every directory either build ever created is still there with its contents.
///
/// The *binary* half of "restores binary and database" is a download, and this
/// asserts the property that makes it safe rather than performing it: the two
/// files' recorded versions are what decide whether the old build opens or fails
/// closed, and they are read here from the files themselves.
#[test]
fn a_backup_taken_before_the_upgrade_rolls_back_without_deleting_a_directory() {
    let (host, sentinels) = VersionTwoHost::plant();
    let (repository, ..) = ids();

    // 1. Copy the database while the daemon is stopped.
    fs::copy(host.database(), host.backup()).expect("the backup is takeable");
    assert_eq!(
        recorded_version(&host.backup()),
        2,
        "the backup is the version-2 file an old build understands"
    );

    // 2. Upgrade, and do work only a version-3 build can do.
    let store = SqliteStore::open(host.database()).expect("a version-2 database opens");
    let persistent_root = LocalAbsolutePath::new(
        host.persistent_root()
            .to_str()
            .expect("a temporary path is UTF-8"),
    )
    .expect("a temporary absolute path is storable");
    let mut policy = store
        .policy(repository)
        .expect("readable")
        .expect("present");
    let revision = policy.revision();
    policy
        .set_workspace_policy(
            WorkspacePolicy::persistent(persistent_root, policy.target.scope())
                .expect("a repository may retain a workspace"),
        )
        .expect("a repository policy accepts a persistent workspace");
    store
        .update_policy_confirming_uncleaned_count(&policy, revision, 3)
        .expect("no uncleaned attempt blocks the change");
    store
        .record_attempt(
            &fixtures::attempt()
                .id(AttemptId::new_random())
                .policy_id(repository)
                .state(AttemptState::Busy)
                .persistent_slot(1)
                .runtime_path(
                    host.persistent_root()
                        .join("s1")
                        .to_str()
                        .expect("a temporary path is UTF-8")
                        .to_owned(),
                )
                .build(),
        )
        .expect("slot s1 is leased");
    drop(store);

    assert_eq!(
        recorded_version(&host.database()),
        i64::from(SCHEMA_VERSION),
        "the upgraded file records the version an old build must reject"
    );

    // 3. Roll back: restore the database an old binary understands.
    fs::copy(host.backup(), host.database()).expect("the backup is restorable");
    assert_eq!(
        recorded_version(&host.database()),
        2,
        "after rollback the live database is what the restored binary supports"
    );

    // The restored file really is the old shape, not a version-3 file wearing an
    // old version number: the columns migration 3 added are not there.
    let conn = Connection::open(host.database()).expect("openable");
    let columns: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('policies')")
        .expect("prepared")
        .query_map([], |row| row.get(0))
        .expect("queried")
        .collect::<Result<_, _>>()
        .expect("collected");
    assert!(
        !columns.iter().any(|column| column == "workspace_mode"),
        "the restored database must be the pre-upgrade shape, found {columns:?}"
    );
    drop(conn);

    // 4. And the operator's directories are all still there. This is the clause
    //    the gate is actually about: a rollback that tidied up would take the
    //    retained `_work` of a persistent repository with it.
    for sentinel in sentinels.values() {
        sentinel.assert_untouched("the rollback rehearsal");
    }

    // 5. Rolling forward again is the ordinary upgrade, not a special case.
    let reopened = SqliteStore::open(host.database()).expect("the restored database re-upgrades");
    assert_eq!(reopened.schema_version(), SCHEMA_VERSION);
    assert_eq!(
        reopened
            .policy(repository)
            .expect("readable")
            .expect("present")
            .workspace_policy(),
        &WorkspacePolicy::Ephemeral,
        "the version-3-only configuration was in the file that was replaced, so \
         the re-upgraded database is ephemeral again rather than half-restored"
    );
}
