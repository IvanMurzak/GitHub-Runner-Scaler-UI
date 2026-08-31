# Runner workspace locations implementation ledger

> This is this Taskflow's only live task-state record. It is not a product-wide
> roadmap.

**Design status:** Reviewed 2026-08-31. Confirmed architecture and security
defects were corrected; no unresolved P0 or P1 review finding remains.

**Task status:** Provisional work packages only. Immutable task specifications,
final dependency groups, and execution waves have not yet been derived by
Taskflow Tasks.

**Implementation status:** Not started. Planning-only work is in progress.

**Repository/base:** `C:\Projects\AI\GitHub-Runner-Scaler-UI` at `995f337`.

**Execution worktree:**
`C:\Projects\AI\GitHub-Runner-Scaler-UI-worktrees\runner-workspace-locations`.
Taskflow execution creates and verifies this isolated worktree before product
implementation. The primary working tree is not an execution target.

**Last updated:** 2026-08-31.

## Outcome

Deliver a short configurable host runner root with Windows default
`%SystemDrive%\rman`, plus repository-scoped persistent workspaces with stable
exclusive slots, CLI and TUI parity, durable recovery, safe cleanup, migration,
and user documentation.

## Waves

| Wave | Outcome | Gate |
|---|---|---|
| 0 | Domain contract, path validator, migration 3, and version-2 migration fixtures. | Migrated existing policies and attempts remain ephemeral. |
| 1 | Platform default resolution, Windows ACL creation, host and repository mutations, and status read models. | A Windows pilot resolves and writes `%SystemDrive%\rman`; path changes refuse active or cleanup-blocked attempts. |
| 2 | Persistent slot allocation, materialization, cleanup, recovery, quarantine, and concurrency. | Two sequential jobs reuse `s1`; concurrent jobs never share a slot; no runner secret survives. |
| 3 | CLI and TUI complete configuration surface with shared validation and messages. | CLI and TUI round-trip identical settings and refusal cases. |
| 4 | README, cross-platform acceptance, privileged service tests, security gates, and rollback rehearsal. | Full workspace and supported-OS gates are green. |

## Human gates

| # | Decision | Status | Blocks |
|---|---|---|---|
| 1 | Approve `%SystemDrive%\rman`, configurable host root, repository-only persistent slots, local absolute paths, non-destructive reconfiguration, and CLI/TUI parity. | GO recorded 2026-08-31. | Task derivation |
| 2 | Approve the real Windows ACL and service-account result for `%SystemDrive%\rman`. | Pending pilot evidence. | Wave 1 exit |
| 3 | Accept the persistent-workspace cross-job trust boundary after the two-job security demonstration. | Owner intent recorded; final GO pending evidence. | Wave 2 exit |

## Provisional dependency graph

```text
p1 domain + migration ─────┬── p3 lifecycle + slots ───────────┐
                           ├── p4 CLI + read models ──┐         │
p2 platform paths + ACL ───┘                         ├── p5 TUI ├── p7 acceptance
                                                     │         │
                                                     └── p6 docs
```

Taskflow Tasks may split or regroup these packages after adversarial review.
No provisional ID is an immutable task specification.

## Board

| Task (spec) | needs | repo/base | imp/cx | model | Status | Run / PR | Updated |
|---|---|---|---|---|---|---|---|
| p1 domain model and SQLite migration, spec pending | none | repo / `995f337` | 9/8 | top | planned | none | 2026-08-31 |
| p2 platform path defaults, validation, directory permissions, spec pending | none | repo / `995f337` | 10/8 | top | planned | none | 2026-08-31 |
| p3 slot allocation, lifecycle cleanup, recovery, and quarantine, spec pending | p1, p2 | repo / `995f337` | 10/10 | top | planned | none | 2026-08-31 |
| p4 CLI mutations, status, service integration, and compatibility, spec pending | p1, p2 | repo / `995f337` | 8/6 | mid | planned | none | 2026-08-31 |
| p5 TUI host and repository path editing with CLI parity, spec pending | p4 | repo / `995f337` | 9/8 | top | planned | none | 2026-08-31 |
| p6 README and operator documentation, spec pending | p4, p5 | repo / `995f337` | 6/4 | mid | planned | none | 2026-08-31 |
| p7 cross-platform, privileged, migration, mutation, and security acceptance, spec pending | p3, p4, p5 | repo / `995f337` | 10/9 | top | planned | none | 2026-08-31 |

## Required evidence before merge

- Version-2 database migrates to version 3 without retaining any existing
  workspace.
- Existing journal paths recover before new root allocation.
- Windows default derives from the system drive and creates `rman` with the
  intended ACL.
- Disposable success, failure, idle, and restart cases still remove the whole
  attempt directory.
- Persistent sequential jobs reuse a stable slot and retain `_work`.
- Persistent cleanup removes runner package copies, JIT handoff, process
  identity, runner registration identity, and lifecycle sidecars.
- Concurrent attempts have unique slots before any GitHub effect.
- A partial unique index rejects duplicate uncleaned persistent slot leases,
  including when the first attempt is terminal but cleanup is blocked.
- Path overlap, root, traversal, symlink, junction, UNC, and unwritable cases
  fail closed.
- Host and repository path writes atomically fence uncleaned attempts and do
  not overwrite concurrent host or policy settings.
- CLI and TUI produce the same stored values and validation outcomes.
- README commands match generated help and use placeholder paths.
- Full workspace tests and all existing README release gates remain green.

## Rollback gate

Migration 3 is forward-only and older binaries reject it. Execution must create
and verify a version-2 database backup before the first real-host upgrade.
Rollback restores binary and database while leaving every runner and persistent
directory untouched.

## Progress log

### 2026-08-31

- Owner defined one scope containing short defaults, global configuration,
  repository persistent slots, CLI, TUI, and repository detail editing.
- Owner selected `rman` instead of `rm` for the short Windows folder.
- Owner confirmed the remaining proposed contract.
- Repository evidence inspection completed.
- Architecture, migration, security, UX, and provisional roadmap documents
  drafted.
- Taskflow review verified current Microsoft path requirements, GitHub JIT
  `_work` behavior, self-hosted runner security guidance, and checkout cleanup.
- Review corrected slot lease truth from active attempts to all uncleaned
  attempts and added a partial unique database constraint.
- Review split pure stored-path validation from operational filesystem
  preflight, added host and repository root overlap checks, and made cleanup
  recovery independent of filesystem discovery.
- Review recorded the isolated implementation worktree path.
- No implementation or task derivation started.
