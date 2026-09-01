# Runner workspace locations implementation ledger

> This is this Taskflow's only live task-state record. It is not a product-wide
> roadmap.

**Design status:** Reviewed 2026-08-31. Confirmed architecture and security
defects were corrected; no unresolved P0 or P1 review finding remains.

**Task status:** Eleven immutable task specifications derived 2026-08-31 with
dependency-safe groups and execution waves. Wave 0 is complete; execution is
stopped by owner direction before Wave 1.

**Implementation status:** `a1-workspace-domain` merged through PR #34 with all
required checks green. Remaining tasks have not started.

**Repository/base:** `C:\Projects\AI\GitHub-Runner-Scaler-UI`; reviewed task
derivation base `ce7945d` on `main`.

**Execution worktree:**
`C:\Projects\AI\GitHub-Runner-Scaler-UI-worktrees\runner-workspace-locations`.
Taskflow execution creates and verifies this isolated worktree before product
implementation. The primary working tree is not an execution target.

**Last updated:** 2026-09-01.

## Outcome

Deliver a short configurable host runner root with Windows default
`%SystemDrive%\rman`, plus repository-scoped persistent workspaces with stable
exclusive slots, CLI and TUI parity, durable recovery, safe cleanup, migration,
and user documentation.

## Waves

| Wave | Outcome | Gate |
|---|---|---|
| 0 | `a1-workspace-domain` establishes immutable path and workspace values. | Pure domain shapes and ephemeral defaults are green. |
| 1 | `a2-workspace-store` and `b1-runner-path-platform` run independently. | Migration 3 is lossless; platform defaults and preflight are proven. |
| 2 | `b2-windows-root-acl`, `c1-effective-runtime-root`, and `d1-workspace-cli-read-models` run independently after their prerequisites. | Default-root access, ephemeral launch, and all CLI mutations are green. |
| 3 | `c2-persistent-slot-allocation` adds stable exclusive leases. | Sequential jobs reuse `s1`; concurrent jobs never share a slot. |
| 4 | `c3-persistent-cleanup-recovery` and `e1-workspace-tui` run independently. | Cleanup quarantines failures; CLI and TUI round-trip identical settings. |
| 5 | `f1-workspace-security-acceptance` and `g1-readme-workspace-guidance` run independently. | Full security, supported-OS, README, and rollback gates are green. |

## Human gates

| # | Decision | Status | Blocks |
|---|---|---|---|
| 1 | Approve `%SystemDrive%\rman`, configurable host root, repository-only persistent slots, local absolute paths, non-destructive reconfiguration, and CLI/TUI parity. | GO recorded 2026-08-31. | Task derivation |
| 2 | Approve the real Windows ACL and service-account result for `%SystemDrive%\rman`. | Owner authorized `b2` implementation 2026-09-01; approval of the produced ACL evidence is still required before merge. | `b2` merge and Wave 5 exit |
| 3 | Accept the persistent-workspace cross-job trust boundary after the two-job security demonstration. | Owner intent recorded; final GO pending evidence. | Wave 5 exit |
| 4 | Authorize any test that uses live GitHub credentials, a production repository, paid infrastructure, or an external side effect. | Not granted. Mocked and local work may proceed. | Only the specific live test |
| 5 | Confirm a verified version-2 database backup before any real host is migrated to schema 3. | Pending real-host rollout. | Production rollout only |

## Dependency graph

```text
a1 domain ──┬── a2 store ─────┬── c1 ephemeral ── c2 slots ──┬── c3 cleanup ──┬── f1 acceptance
            │                 │                               │                └── g1 README
            │                 └── d1 CLI ─────────────────────┼── e1 TUI ─────┘
            └── b1 platform ──┬── b2 Windows ACL ─────────────┘
                              ├── c1
                              └── d1
```

## Board

| Task (spec) | needs | repo/base | imp/cx | model | Status | Run / PR | Updated |
|---|---|---|---|---|---|---|---|
| [a1-workspace-domain](tasks/a1-workspace-domain.md) | none | `. / main` | 10/8 | top | ✅ | [PR #34](https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/pull/34), merge `66ba5a8` | 2026-08-31 |
| [a2-workspace-store](tasks/a2-workspace-store.md) | a1-workspace-domain | `. / main` | 10/10 | top | ✅ | run `01a05ac7-b731-704b-8753-5aa75b0b4fdb` | 2026-08-31 |
| [b1-runner-path-platform](tasks/b1-runner-path-platform.md) | a1-workspace-domain | `. / main` | 10/9 | top | ✅ | run `01a05ac7-c88a-7058-aecc-31cf32861cf6` | 2026-08-31 |
| [b2-windows-root-acl](tasks/b2-windows-root-acl.md) | b1-runner-path-platform | `. / main` | 9/9 | top | planned | none | 2026-09-01 |
| [c1-effective-runtime-root](tasks/c1-effective-runtime-root.md) | a2-workspace-store, b1-runner-path-platform | `. / main` | 10/8 | top | ✅ | PR #37 | 2026-09-01 |
| [c2-persistent-slot-allocation](tasks/c2-persistent-slot-allocation.md) | c1-effective-runtime-root | `. / main` | 10/10 | top | 🔵 | run `01a05ca5-c42b-70bc-be54-ec55b8622c11` | 2026-09-01 |
| [c3-persistent-cleanup-recovery](tasks/c3-persistent-cleanup-recovery.md) | c2-persistent-slot-allocation | `. / main` | 10/10 | top | planned | none | 2026-08-31 |
| [d1-workspace-cli-read-models](tasks/d1-workspace-cli-read-models.md) | a2-workspace-store, b1-runner-path-platform | `. / main` | 10/9 | top | 🔵 | run `01a05ca5-c4f0-70e7-8090-f88f09571984` | 2026-09-01 |
| [e1-workspace-tui](tasks/e1-workspace-tui.md) | c2-persistent-slot-allocation, d1-workspace-cli-read-models | `. / main` | 9/9 | top | planned | none | 2026-08-31 |
| [f1-workspace-security-acceptance](tasks/f1-workspace-security-acceptance.md) | b2-windows-root-acl, c3-persistent-cleanup-recovery, d1-workspace-cli-read-models, e1-workspace-tui | `. / main` | 10/10 | top | planned | none | 2026-08-31 |
| [g1-readme-workspace-guidance](tasks/g1-readme-workspace-guidance.md) | c3-persistent-cleanup-recovery, d1-workspace-cli-read-models, e1-workspace-tui | `. / main` | 8/4 | fast | planned | none | 2026-08-31 |

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
- Eleven immutable task specs, six execution waves, seven conflict groups, and
  explicit production, secret, and migration gates were derived.
- No implementation task started.
- Started `a1-workspace-domain` with the `implement-task` pipeline run
  `01a05a32-9a13-7038-ae8e-1c1627317abf`.
- The run halted before creating a worktree because the installed Pipeline CLI
  requires `.pipeline/.hooks/worktree-create.*` for `isolation: run`; no task
  implementation step ran.
- Validated the locally supplied hooks with an isolated create/destroy smoke
  test and started retry run `01a05a53-1114-7064-b583-443a34020101`; the
  original halted run remains diagnostic history.
- Retry run completed implement, code-review, simplify, and land. PR #34 merged
  as `66ba5a8` after all CI and E2E checks passed.
- Re-ran the timed-out worktree teardown successfully and verified the task
  worktree, environment file, local branch, and remote branch were removed.
- Stopped before Wave 1 by owner direction; no other Taskflow task was started.

### 2026-09-01

- Completed task c1-effective-runtime-root using implement-task pipeline via manual session loop. PR #37 created and merged.
- Implemented dynamically resolved paths in LifecycleLauncher and updated corresponding tests.
- Survived limit exhaustion, fixed missing simplify skill reference during retrospective, and marked c1 task as ✅.
- Reconciled a stale `b2-windows-root-acl` 🔵 row: no branch, worktree, or PR
  existed, so the row returned to `planned`.
- Started `c2-persistent-slot-allocation` and `d1-workspace-cli-read-models`
  concurrently with native `taskflow-implementer` worktree isolation.
- Owner clarified human gate 2 as approval of the produced ACL result rather
  than a precondition to implementation, and authorized `b2-windows-root-acl`
  to run. Its work holds at 🟣 for gate-2 approval before merge.
- Owner directed all task execution through the `implement-task` pipeline, so
  the three native workers were stopped before they created any branch or
  worktree and the round was re-dispatched on the pipeline engine.
- Started `c2-persistent-slot-allocation` and `d1-workspace-cli-read-models`
  as headless `pipeline drive` runs of `implement-task`.
- Held `b2-windows-root-acl` at `planned`: `implement-task` squash-merges in
  its `land` step, which cannot honour the gate-2 hold before merge.

