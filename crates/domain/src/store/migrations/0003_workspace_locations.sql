-- owner: a2-workspace-store
--
-- Schema version 3. Forward-only, like every step before it: this file is
-- APPLIED ONCE per database and is then history. Migrations 1 and 2 are not
-- edited to add these columns, because a database that already ran them would
-- never see the edit (`03-migration-rollout.md`: "Add forward-only migration
-- `0003_workspace_locations.sql` and advance `SCHEMA_VERSION` from 2 to 3.
-- Never edit migrations 1 or 2").
--
-- STILL NO CREDENTIAL COLUMN, AND NONE MAY BE ADDED. A configured path is not a
-- credential -- `crates/domain/src/path.rs` says so explicitly and every
-- `LocalPathError` echoes the offending text -- but the scan in
-- `tests/store_journal.rs` passes over these columns too, so a caller that
-- managed to write a token-shaped root would fail it.

-- --------------------------------------------------------------------------
-- hosts: where disposable attempt directories are created.
-- --------------------------------------------------------------------------
--
-- The OVERRIDE is stored, not the effective path. `02-target-architecture.md`:
-- "`None` means use the platform default, which is resolved at runtime and
-- shown as such. Storing only the override allows a future platform-default
-- correction without rewriting every database." So NULL here is the normal
-- state of every host, and it is what every migrated row gets.
--
-- Re-validated on load through `LocalAbsolutePath::new`, which is the *native*
-- entry point: a Windows root in a database opened on Linux is corrupt state
-- and fails closed, as does a UNC path, a device path, a bare root, or a `..`
-- component (D10).
ALTER TABLE hosts ADD COLUMN runner_root_override TEXT;

-- --------------------------------------------------------------------------
-- policies: whether a repository's job workspace survives its attempts.
-- --------------------------------------------------------------------------
--
-- Two columns rather than one, because that is what SQLite holds; the pair is
-- rebuilt through `WorkspacePolicy::from_persisted`, which is what refuses
-- persistent-without-path, ephemeral-with-path, and -- D7 -- an organization
-- policy claiming to retain a workspace.
--
-- `DEFAULT 'ephemeral'` is the whole migration story for existing rows
-- (`03-migration-rollout.md`: "Every pre-migration policy and attempt becomes
-- ephemeral. This preserves the meaning of existing rows and prevents an
-- upgrade from retaining a workspace the operator never selected"). The default
-- also fills the column for a row written by an older code path that does not
-- name it; `workspace_path` has no default and is therefore NULL, which is the
-- only shape `ephemeral` admits.
ALTER TABLE policies ADD COLUMN workspace_mode TEXT NOT NULL DEFAULT 'ephemeral';
ALTER TABLE policies ADD COLUMN workspace_path TEXT;

-- --------------------------------------------------------------------------
-- attempts: the immutable allocation fact, and the durable slot lease.
-- --------------------------------------------------------------------------
--
-- `runtime_path` is deliberately left exactly as it is. A migrated attempt is
-- ephemeral, so recovery goes on removing the exact old application-data
-- directory it was created in; `03-migration-rollout.md` requires that "No
-- journal row is rewritten merely to adopt the new default", because rewriting
-- one would point cleanup at a directory the attempt never used.
ALTER TABLE attempts ADD COLUMN workspace_mode TEXT NOT NULL DEFAULT 'ephemeral';
ALTER TABLE attempts ADD COLUMN workspace_slot INTEGER;

-- The durable half of "one persistent slot is leased to at most one active
-- attempt" (invariant 5).
--
-- There is no slot table: every persistent attempt whose state is not `cleaned`
-- IS the lease, including a terminal one whose cleanup failed. The allocation
-- lock coordinates *selection*; this index is "the durable final guard against a
-- duplicate lease after a race or restart" (`03-migration-rollout.md`), and it
-- keeps holding across a daemon restart because it is a property of the rows
-- rather than of a process.
--
-- Partial, on both counts that matter. `workspace_mode = 'persistent'` keeps
-- every ephemeral attempt out of it, so the millions of NULL slots do not
-- collide with each other. `state <> 'cleaned'` is what releases the lease: a
-- cleaned historical row leaves the index and its slot becomes reusable, while
-- an uncleaned one -- quarantined, or awaiting a cleanup that failed --
-- continues to hold it (`04-security-recovery.md`, "Cleanup partly fails and
-- the slot is reused anyway").
CREATE UNIQUE INDEX one_uncleaned_persistent_attempt_per_slot
ON attempts (policy_id, workspace_slot)
WHERE workspace_mode = 'persistent' AND state <> 'cleaned';
