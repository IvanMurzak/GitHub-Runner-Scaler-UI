---
id: "a2-workspace-store"
title: "Persist workspace policy and durable slot leases"
group: "A"
sequence: 2
repo: "."
base_branch: "main"
depends_on: ["a1-workspace-domain"]
importance: 10
complexity: 10
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["02-target-architecture.md", "03-migration-rollout.md", "04-security-recovery.md"]
---

## Goal

Upgrade SQLite to schema 3 with lossless ephemeral defaults, durable uncleaned
slot leases, and race-safe host and repository path mutations.

## Scope & seams

- Add forward-only `0003_workspace_locations.sql`; never edit migrations 1 or
  2.
- Persist host runner-root override, policy workspace mode/path, and attempt
  workspace mode/slot.
- Add the partial unique index for one uncleaned persistent attempt per policy
  and slot.
- Rebuild every stored value through the domain constructors and fail closed on
  invalid mode, scope, path, or slot combinations.
- Add a targeted host-root write that compares the expected prior override,
  confirms uncleaned ephemeral attempts in the same transaction, and updates
  only the root column.
- Add a policy write that combines the existing revision check with an
  uncleaned policy-attempt count in the same transaction.
- Expose queries that distinguish active attempts from uncleaned slot leases.
- Do not probe paths or implement lifecycle allocation in the store.

## Definition of Done

- `SCHEMA_VERSION` is 3 and fresh, version-1, and version-2 databases migrate
  through the full immutable chain.
- Every migrated host override is null, policy is ephemeral, and attempt is
  ephemeral while its exact historical runtime path remains unchanged.
- A future schema still fails closed.
- Duplicate uncleaned persistent `(policy_id, slot)` writes fail atomically;
  cleaned historical rows do not block reuse.
- Host-root mutation cannot overwrite concurrent capacity or service-mode
  updates and refuses a changed expected override or uncleaned ephemeral count.
- Policy mutation refuses stale revision and changed uncleaned count in the
  same write transaction.
- Corrupt-row, dump, round-trip, migration fixture, and secret scan tests pass.
