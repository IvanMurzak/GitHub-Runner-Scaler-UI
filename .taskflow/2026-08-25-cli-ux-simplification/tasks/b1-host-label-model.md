---
id: "b1-host-label-model"
title: "Host.host_label, its persistence, and forward-only migration 0003"
group: "B"
sequence: 1
repo: "."
base_branch: "main"
depends_on: []
importance: 3
complexity: 6
security_critical: false
production_touching: true
model_hint: "top"
taskflow_refs: ["02-target-architecture.md", "05-migration-compatibility.md"]
---

## Goal

Give the host a routing identity of its own, and migrate every existing
database onto it **without changing where a single runner routes**. D3's model
half.

`production_touching` is set because this runs against databases operators
already have. There is no downgrade path: the chain fails closed on an unknown
newer version (`crates/domain/src/store.rs:30-31`).

## Scope & seams

**Files:** `crates/domain/src/model.rs`, `crates/domain/src/store.rs`,
`crates/domain/src/store/migrations/0003_host_label.sql` (new).

### The field

`Host` gains `host_label`. It is loaded as `Option<HostLabel>`, **not** as a
`HostLabel`: the migration leaves `''` for a host with no policies, and
`HostLabel::new` rejects empty (`crates/domain/src/model.rs:582-586`). A
`HostLabel` holding an illegal value would violate the store's stated invariant
that a hand-edited database "cannot inject a configuration the domain would
refuse to construct in memory" (`store.rs:26-29`).

### The migration

Append to `MIGRATIONS` (`crates/domain/src/store.rs:288-300`). The intended SQL
is in
[`05-migration-compatibility.md`](../05-migration-compatibility.md#the-sqlite-migration).
Three things in it are the design's **intent**, not a transcription, and must be
read from the schema before the SQL is written:

1. The exact column names `policies.requested_host_label` and
   `policies.host_id`, from `0001_initial_schema.sql` and
   `0002_policy_host_label.sql`.
2. That `policies` is `STRICT` but not `WITHOUT ROWID`, so `rowid` is available
   as insertion order. It has **no** `created_at` column
   (`0001_initial_schema.sql:43-67`) and its `id` is a random UUID, so `rowid`
   is the only ordering there is. Confirm it, then rely on it.
3. That `0002` gave `requested_host_label` the literal default `'host'`, so a
   pre-`0002` policy backfills to `host`. That is correct: `host` is exactly
   what the product uses for that policy today.

`TABLES` (`store.rs:319`) is **unchanged** — D4 adds no table.

### Not in scope

The CLI side of D3. `default_host_label()`, the resolution order, `host
set-label` and the `host show` lines belong to `a3` and `d1`. This task makes
the field exist, persist, and migrate.

## Definition of Done

1. `Host` carries `host_label`, round-trips through `SqliteStore`, and the
   on-disk token test (`store::tests::the_on_disk_tokens_are_pinned`) is
   extended rather than bypassed.
2. Migration `0003` applies to a database at version `2` and records itself in
   `schema_migrations`.
3. **The routing gate (G2).** Against a fixture database built at schema
   version `2` containing one host and one policy whose
   `requested_host_label` is `office`, `hosts.host_label` after migration is
   `office`. Built as a fixture, not by creating a fresh database with the new
   code.
4. A host with two policies backfills from the one with the lower `rowid`, and a
   test asserts which one that is.
5. A host with no policies backfills to `''`, loads as `None`, and no code path
   panics or constructs an invalid `HostLabel`.
6. Opening a `0003` database with a binary that only knows `0002` still fails
   closed with the existing error — assert it, since this is the first migration
   added since that behaviour was written.
7. `cargo test -p runner-manager-domain` passes.
8. `cargo test --workspace` compiles: adding a field to `Host` reaches every
   construction site, including `crates/testkit`.
