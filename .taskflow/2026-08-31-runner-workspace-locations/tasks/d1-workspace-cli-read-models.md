---
id: "d1-workspace-cli-read-models"
title: "Expose workspace settings through CLI and status"
group: "D"
sequence: 1
repo: "."
base_branch: "main"
depends_on: ["a2-workspace-store", "b1-runner-path-platform"]
importance: 10
complexity: 9
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["02-target-architecture.md", "03-migration-rollout.md", "05-user-workflows.md"]
---

## Goal

Provide the complete shared mutation and inspection surface for global
ephemeral placement and repository-only persistent workspaces.

## Scope & seams

- Add `host set-runtime-root --path`, `host reset-runtime-root`, and repository
  `set-workspace` commands with the reviewed argument rules.
- Implement handlers reusable by TUI, backed by the atomic store mutations and
  operational preflight rather than CLI-only logic.
- Refuse active and cleanup-blocked affected attempts with separate counts.
- Create a validated leaf only after all non-mutating checks pass; report an
  empty directory left by a lost write race without deleting it.
- Show previous configured value, new value, effective source, retained old
  directories, and persistent trust warning.
- Extend `host show`, repository detail/list surfaces, human status, and
  versioned status JSON with structured mode, source, root, slot, lease, and
  cleanup-blocked fields.
- Keep persistent configuration absent from organization commands.
- Keep service registrations compatible and make host-root changes effective
  without reinstalling the service.

## Definition of Done

- Generated help exactly matches all four reviewed commands and rejects missing
  or forbidden `--path` combinations.
- CLI round-trips configured and reset host roots plus repository persistent and
  ephemeral modes through daemon restart.
- Mutations are non-destructive and race tests prove no stale host or policy
  write and no active or cleanup-blocked path change.
- Human and JSON output identify platform-default, configured, and repository-
  specific sources without enumerating workspace files.
- Status JSON compatibility is intentionally versioned and pinned by tests.
- Command output contains the trust warning and no credentials or JIT material.
- CLI, service integration, command-surface, and output snapshot tests pass.
