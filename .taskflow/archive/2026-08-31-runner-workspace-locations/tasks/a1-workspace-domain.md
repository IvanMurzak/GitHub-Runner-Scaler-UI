---
id: "a1-workspace-domain"
title: "Define workspace and runner-root domain contracts"
group: "A"
sequence: 1
repo: "."
base_branch: "main"
depends_on: []
importance: 10
complexity: 8
security_critical: true
production_touching: false
model_hint: "top"
taskflow_refs: ["README.md", "02-target-architecture.md", "04-security-recovery.md"]
---

## Goal

Represent host runner-root overrides, repository workspace policy, immutable
attempt workspace allocation, and pure stored-path shape without filesystem
side effects.

## Scope & seams

- Extend `Host` with an optional configured runner-root override while keeping
  platform-default resolution outside the domain crate.
- Add `WorkspacePolicy::Ephemeral` and repository-only
  `WorkspacePolicy::Persistent`, defaulting all constructors to ephemeral.
- Add immutable `AttemptWorkspace::Ephemeral` and
  `AttemptWorkspace::PersistentSlot` facts to `RunnerAttempt`.
- Introduce the pure absolute, non-root, normalized local-path value required by
  persisted host and policy state. Reject relative paths, traversal, Windows
  UNC and device syntax, and unrepresentable values without probing the disk.
- Keep workspace policy distinct from runner package `CachePolicy`.
- Do not add filesystem creation, permission changes, CLI, TUI, or SQLite
  migration work in this task.

## Definition of Done

- New host, policy, and attempt values round-trip through their persisted
  structs and serde tokens without credentials.
- Organization policies cannot be constructed or restored as persistent.
- Persistent attempts require a positive slot; ephemeral attempts reject one.
- Workspace kind and slot cannot change after allocation.
- Pure path tests cover Unix absolute paths and Windows drive, UNC, device,
  root, traversal, and relative forms behind deterministic platform seams.
- Existing constructors and tests continue to produce ephemeral behavior.
- Domain crate tests, formatting, linting, and secret-shape tests pass.
