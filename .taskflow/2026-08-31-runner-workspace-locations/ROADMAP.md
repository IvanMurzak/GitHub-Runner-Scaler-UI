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
| [b2-windows-root-acl](tasks/b2-windows-root-acl.md) | b1-runner-path-platform | `. / main` | 9/9 | top | 🟣 | [PR #40](https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/pull/40) green, awaiting gate 2 | 2026-09-01 |
| [c1-effective-runtime-root](tasks/c1-effective-runtime-root.md) | a2-workspace-store, b1-runner-path-platform | `. / main` | 10/8 | top | ✅ | PR #37 | 2026-09-01 |
| [c2-persistent-slot-allocation](tasks/c2-persistent-slot-allocation.md) | c1-effective-runtime-root | `. / main` | 10/10 | top | ✅ | [PR #38](https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/pull/38), merge `dc62d57` | 2026-09-01 |
| [c3-persistent-cleanup-recovery](tasks/c3-persistent-cleanup-recovery.md) | c2-persistent-slot-allocation | `. / main` | 10/10 | top | ✅ | [PR #41](https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/pull/41), merge `bb30b7f` | 2026-09-01 |
| [d1-workspace-cli-read-models](tasks/d1-workspace-cli-read-models.md) | a2-workspace-store, b1-runner-path-platform | `. / main` | 10/9 | top | ✅ | [PR #39](https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/pull/39), merge `1ece70c` | 2026-09-01 |
| [e1-workspace-tui](tasks/e1-workspace-tui.md) | c2-persistent-slot-allocation, d1-workspace-cli-read-models | `. / main` | 9/9 | top | ✅ | [PR #42](https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/pull/42), merge `48230a4` | 2026-09-01 |
| [f1-workspace-security-acceptance](tasks/f1-workspace-security-acceptance.md) | b2-windows-root-acl, c3-persistent-cleanup-recovery, d1-workspace-cli-read-models, e1-workspace-tui | `. / main` | 10/10 | top | planned | none | 2026-08-31 |
| [g1-readme-workspace-guidance](tasks/g1-readme-workspace-guidance.md) | c3-persistent-cleanup-recovery, d1-workspace-cli-read-models, e1-workspace-tui | `. / main` | 8/4 | fast | 🔵 | run `01a05e06-d489-704a-b88b-29f93aa1f63c` | 2026-09-01 |

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
- Started `b2-windows-root-acl` as run
- `c2-persistent-slot-allocation` landed as PR #38 / `dc62d57` with all seven
  required checks green; every DoD item is covered by a named test in
  `crates/agent/src/lifecycle.rs`.
- Started `c3-persistent-cleanup-recovery` as run
  `01a05d10-6cea-703f-bb33-6bdbe8c86ab7` once group C was free again.
- `d1-workspace-cli-read-models` landed as PR #39 / `1ece70c` with all seven
  required checks green; help, round-trip, non-destructive race, source
  rendering, schema-version pinning, and trust-warning items each have a
  named test in `crates/app/tests/workspace_commands.rs`.
- Started `e1-workspace-tui` as run
  `01a05d2e-d03f-70b8-80fd-523601830504`.
- `b2-windows-root-acl` reached `land` and opened PR #40. The pre-merge guard
  halted the run before the squash-merge, so the pull request stays open for
  human gate 2. The run resumes at `land` once the owner records GO.
- `c3-persistent-cleanup-recovery` landed as PR #41 / `bb30b7f` with all seven
  required checks green; retention, link/junction fail-closed, quarantine
  across restart, journal-only recovery, and untouched old slots each have a
  named test in `crates/agent/src/lifecycle.rs`.
- PR #40 failed its required checks on every platform: Linux and macOS could
  not build because `previous_dacl` and `reconcile` are dead outside Windows
  under `-D warnings`, and Windows failed
  `runner_root_access::tests::a_directory_this_process_created_is_reported_as_narrow`.
  The Windows failure is an ACL-narrowing defect, so gate 2 cannot be judged
  on this revision. Resumed the run at `code-review` to repair the branch,
  with the pre-merge guard re-armed.
- Converted PR #40 to a draft so `gh pr merge` refuses deterministically,
  replacing the race-prone process guard as the gate-2 hold.
- `e1-workspace-tui` halted at `land`: PR #42 is open and unmerged because
  `snapshot_every_required_settings_state` fails on all three platforms and
  `tui_and_cli_store_byte_identical_workspace_values_and_render_one_message`
  fails on Linux and macOS. Both are test-fixture defects, not product
  defects: the parity fixture assumes the platform-default root is the same
  string on every host, which decision D1 deliberately makes false, and the
  stored snapshot embeds a host-specific path. Resumed at `code-review`.
- Both cross-platform escapes share one cause: the pipeline local gate runs
  only on the Windows development host, so a Linux or macOS difference
  cannot be caught before CI.
- The `b2` repair pass fixed both failures on the branch: `e36f1be` keeps the
  runner-root module off non-Windows builds and stops asserting a
  host-dependent outcome, verified by cross-compiling
  `cargo clippy -p runner-manager-platform --lib --target
  x86_64-unknown-linux-gnu -- -D warnings`, and `686872f` unified one
  fail-closed fallback. `land` then halted without pushing either commit and
  waited on the previous head’s stale checks, so execution pushed the branch
  itself and left the merge for gate 2.
- `land` also runs `gh pr ready` when it finds a draft PR, so a draft is not a
  durable hold while a run is driving `land`. The hold now rests on no run
  driving `land` for `b2` until the owner records gate 2 GO.
- `e1-workspace-tui` landed as PR #42 / `48230a4` with all seven required
  checks green. The repair shared one root fixture between the two surfaces
  and redacted the volatile markers from the snapshot, so both tests now
  prove the rendering rather than the host.
- PR #40 is green on `686872f`, including `check (windows-x86_64)` and the
  privileged installer smoke tests, so gate 2 can now be judged on real
  evidence.
- Started `g1-readme-workspace-guidance` as run
  `01a05e06-d489-704a-b88b-29f93aa1f63c`; `f1` remains blocked on `b2`.
  `01a05ca7-d5be-7000-829f-53ec8b04614e` with a pre-merge guard: the run is
  halted the moment `land` opens its pull request, so the squash-merge cannot
  run before human gate 2 is recorded GO. The run resumes at `land` after
  approval.
  its `land` step, which cannot honour the gate-2 hold before merge.

