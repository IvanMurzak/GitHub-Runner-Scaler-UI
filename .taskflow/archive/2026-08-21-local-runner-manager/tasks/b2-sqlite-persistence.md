---
id: "b2-sqlite-persistence"
title: "SQLite configuration store, schema migrations, attempt journal, and revision-based concurrency"
group: "B"
sequence: 2
repo: "."
depends_on: ["b1-domain-core"]
importance: 9
complexity: 6
security_critical: false
production_touching: false
model_hint: "mid"
taskflow_refs: ["04-subsystem-contracts.md", "05-infrastructure.md", "03-control-flows.md"]
---

## Goal

Persist `Host`, `ScalePolicy`, and `RunnerAttempt` durably enough that a
`repair_required` policy survives a restart and still produces an explicit
repair instruction, and that an agent restarting mid-flight can reconstruct
what it was doing. Persist **no credential of any kind**.

## Scope & seams

Owns `crates/domain/src/store.rs` and the schema/migration assets beside it.
Exposes a store trait plus its rusqlite implementation, so `b1`'s logic and the
`testkit` fixtures stay usable without a database.

- SQLite holds configuration and recovery metadata **only**. The user access
  token lives in the machine-scoped secret store (`d2`), never here — this is a
  `07-security.md` gate, verified by inspecting fixtures for secrets.
- Forward-only schema migrations with a recorded version; an unknown future
  version fails closed rather than guessing.
- Every load re-validates `b1`'s `PolicyMode` shape and `min <= max`
  invariants, so a hand-edited database cannot inject an illegal policy.
- `ScalePolicy.revision` implements optimistic concurrency: a write against a
  stale revision is rejected, which is what stops the TUI and a concurrent CLI
  invocation from silently overwriting each other.
- The attempt journal is durable across process death and is the input to
  `e3`'s startup recovery: it records `process_id`, `runtime_path`, state, and
  timestamps.
- Database and configuration live under the platform application-data
  directory (`d1`), never the current working directory. Take the path as an
  argument; do not resolve it here.

## Definition of Done

- Round-trip tests for `Host`, both `ScaleTarget` variants, both `PolicyMode`
  variants, and every `AttemptState`, restoring byte-identical domain values.
- A migration test runs the full chain on an empty database and on a database
  one version behind; an unknown newer version is refused with a clear error.
- A hand-corrupted row violating a `PolicyMode` shape invariant is rejected on
  load, not silently accepted.
- A stale-`revision` write is rejected and the caller can distinguish it from
  an I/O error.
- A journal written, then reopened after simulated process death, yields the
  same attempts with the same states.
- A grep of every fixture database and its dump finds no token-shaped value.
