# Migration and rollout

## Database migration

Add forward-only migration `0003_workspace_locations.sql` and advance
`SCHEMA_VERSION` from 2 to 3. Never edit migrations 1 or 2.

Proposed columns:

```text
hosts.runner_root_override      TEXT NULL

policies.workspace_mode         TEXT NOT NULL DEFAULT 'ephemeral'
policies.workspace_path         TEXT NULL

attempts.workspace_mode         TEXT NOT NULL DEFAULT 'ephemeral'
attempts.workspace_slot         INTEGER NULL
```

Add a partial unique index equivalent to:

```sql
CREATE UNIQUE INDEX one_uncleaned_persistent_attempt_per_slot
ON attempts(policy_id, workspace_slot)
WHERE workspace_mode = 'persistent' AND state <> 'cleaned';
```

The allocation lock coordinates selection. The index is the durable final
guard against a duplicate lease after a race or restart.

Pure load-time domain validation enforces stored shapes SQLite cannot add
safely to the existing STRICT tables. Filesystem existence, writability, and
mount identity are operational preflight checks and never make database open
depend on a currently mounted drive:

```text
policy ephemeral  -> workspace_path IS NULL
policy persistent -> repository scope and workspace_path IS NOT NULL

attempt ephemeral  -> workspace_slot IS NULL
attempt persistent -> workspace_slot > 0
```

Every pre-migration policy and attempt becomes ephemeral. This preserves the
meaning of existing rows and prevents an upgrade from retaining a workspace the
operator never selected.

## Existing attempt recovery

Attempts already store their exact `runtime_path`. Migrated attempts are marked
ephemeral, so recovery continues to remove that exact old application-data path.
New Windows attempts use `%SystemDrive%\rman` after startup recovery completes.
No journal row is rewritten merely to adopt the new default.

This ordering is mandatory:

1. Open and migrate SQLite.
2. Resolve host and policy configuration.
3. Recover every pre-existing attempt using its journaled path and migrated
   ephemeral mode.
4. Only then allocate new attempts under the new effective roots.

## Windows default transition

The upgrade does not move the old application `runtime` directory. The daemon
preflights `%SystemDrive%\rman` before accepting new work:

- boot service installation creates it with the service account's access;
- login service and foreground daemon attempt ordinary creation;
- failure prevents new allocation and reports the exact
  `host set-runtime-root` remediation command;
- a readable but non-writable root is a hard error, not a fallback to the long
  old path.

A silent fallback would reintroduce the path-length failure and make the TUI's
effective-path display false.

## Configuration changes

Host and repository path mutations use this transaction boundary:

1. Resolve the target host or policy and current revision.
2. Count affected attempts whose state is not `cleaned`.
3. Refuse if the count is non-zero.
4. Validate the new path and overlap set without filesystem mutation.
5. Create the leaf if needed.
6. Persist the override or workspace policy atomically.
7. Print and render the effective new path.
8. State explicitly that the previous directory was neither moved nor removed.

The host store operation compares the expected old override and updates only
that column while confirming the uncleaned ephemeral count. The policy store
operation compares its revision and confirms the uncleaned policy-attempt count.
Both checks happen inside the same SQLite write transaction as the mutation.
The existing whole-record `put_host` and active-count-only policy guard are not
sufficient for these commands.

If directory creation succeeds but the database write loses an optimistic
concurrency race, the empty directory may remain. The command reports it. It
must never delete a directory it did not prove it created empty in this
invocation.

## Compatibility

- Existing command lines remain valid.
- `--data-dir` keeps its existing application-data meaning.
- Existing repository and organization policies remain ephemeral.
- Existing service registrations keep their four hidden application-directory
  arguments. Runner-root selection comes from the migrated database, so a host
  setting change does not require service reinstallation.
- Status JSON is versioned. Adding workspace fields requires a schema version
  update or additive compatibility contract, whichever the existing status
  schema tests require.
- An older binary sees schema version 3 as newer than supported and fails
  closed. Rollback therefore requires the pre-upgrade database backup.

## Rollout phases

### Phase 0: migration and platform proof

- Add domain values and migration 3.
- Prove version-2 databases migrate every policy and attempt to ephemeral.
- Prove newer databases still fail closed.
- Prove Windows default resolution produces `<system-drive>\rman` without a
  hard-coded `C:`.
- Prove macOS and Linux defaults are unchanged.

Gate: a copied production-like version-2 database opens, recovers an old
attempt path, and starts no new attempt before recovery completes.

### Phase 1: disposable root pilot

- Configure a disposable Windows test repository.
- Verify new attempt paths are below `C:\rman` on a normal C-drive host.
- Run success, failure, idle-exit, restart, and cleanup cases.
- Change the host override through CLI, then reset it.
- Repeat both mutations through TUI.

Gate: every new attempt uses the displayed effective root and no attempt
directory remains after terminal cleanup.

### Phase 2: one persistent repository

- Keep policy capacity at one.
- Configure a disposable persistent root through CLI.
- Run two jobs and prove both lease `s1` sequentially.
- Leave a Git-ignored cache marker in the first job and consume it in the
  second.
- Prove runner binaries, JIT handoff, process identity, and registration
  sidecars from the first attempt are absent before the second starts.
- Switch back to ephemeral and verify the old `s1/_work` remains untouched.

Gate: retained job data survives, sensitive runner data does not, and the
operator is told the retained directory still exists.

### Phase 3: concurrency and recovery

- Raise capacity and run overlapping jobs.
- Prove distinct stable slots and lowest-free reuse.
- Crash at every boundary from slot allocation through cleanup.
- Prove active journal rows prevent double lease after restart.
- Quarantine an unsafe or partially cleaned slot and prove its uncleaned journal
  row and unique index prevent reuse without consuming unrelated host capacity.

Gate: no two live attempts share a slot and recovery never deletes `_work` from
a persistent slot.

### Phase 4: cross-platform and documentation

- Repeat persistent slot acceptance on macOS and Linux.
- Verify CLI and TUI parity and accessibility.
- Update README commands and customization examples.
- Run the full workspace, privileged service, mutation, and end-to-end suites.

Gate: all supported OS checks are green and the README examples match `--help`.

## Rollback

Before upgrade, copy the SQLite database while the daemon is stopped. Rolling
back the binary requires restoring that version-2 database because old builds
correctly reject version 3.

Rollback never deletes `%SystemDrive%\rman` or repository persistent roots.
The operator drains policies, stops the daemon, restores the old database and
binary, and manually chooses whether retained directories should remain.
