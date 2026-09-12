# Windows service reliability and WSL self-healing ledger

**Design status:** Reviewed 2026-09-11; six findings applied, no owner question
open.
**Task status:** Derived 2026-09-11: 14 immutable specifications, four conflict
domains, waves 0-6.
**Implementation status:** Wave 0 in progress.
**Repository:** `.` / `main` at `db4c074`.
**Last updated:** 2026-09-11.

**Execution isolation:** `.claude/worktrees/wsl-self-healing-integration` from
`main`; task derivation may split further worktrees, but no implementation may
write through the operator's dirty primary worktree.

This is the only live task-state record for this Taskflow. Existing unrelated
working-tree changes in `crates/app/src/cli/daemon.rs`, `crates/github/src/lib.rs`
and `docs/spikes/token-expiry-and-renewal.md` belong to the operator and must be
preserved or isolated during execution.

## Execution waves

| Wave | Theme | Gate |
|---|---|---|
| 0 | `a1`, `b1` | G1, G2 and launcher feasibility |
| 1 | `a2`, `b2` | Supervisor core and guest fence |
| 2 | `a3`, `b3` | Reload protocol and pure recovery model |
| 3 | `a4`, `b4`, `c1` | Hidden immediate service, WSL watchdog, TUI model |
| 4 | `a5`, `b5` | Truthful service status and WSL task/status migration |
| 5 | `c2` | Cached TUI collection and responsiveness |
| 6 | `d1`, then `d2` | Cross-cutting gates, packaging and docs |

## Gates

**G1 — privilege evidence.** A non-elevated real Windows test under the owning
user can terminate and restart only a disposable named WSL2 distribution; the
test proves no other distribution changes state. If this fails, automatic
recovery is unsupported rather than elevated.

**G2 — race-free fence evidence.** A real WSL2/DrvFS test proves Windows and
Linux agree on the chosen lock/generation protocol across process death and
session-creation failure. No implementation task begins on an unproven locking
primitive.

**G3 — secret boundary.** Supervisor records, heartbeat, status JSON, TUI,
activity and logs contain no token, refresh token, JIT configuration or command
payload. Existing whole-flow secret scans include recovery failures.

**G4 — install means running.** On a logged-in Windows fixture,
`service install --start-at login` leaves the task running, creates no visible
console window, and records a fresh daemon heartbeat without a second command.

**G5 — durable reload.** Repeated policy add/remove and binary upgrade cycles
drain active jobs, reload into the intended version/configuration and remain
running beyond Task Scheduler's five-retry window.

**G6 — fail-closed safety.** Every missing/stale/contradictory proof, active
attempt, busy runner and unmanaged runner prevents termination. Property tests
interleave fence, assignment, completion, timeout and crash events and never
produce `terminate` while work may exist.

**G7 — bounded recovery.** Three classified failures plus a complete safety
proof terminate only the named disposable distribution, restore a verified
daemon, and cap retries. Unknown errors and an open circuit never terminate.

**G8 — status truth.** A stopped automatic local task is not healthy; all WSL
states in `05-tui-status-ux.md` render in CLI JSON/text and Windows TUI from the
same typed snapshot. Off Windows no WSL command is invoked.

**G9 — incident replay.** A fixture reproduces a `Running` lifecycle task plus
`0x8007274c` probe failures and queued matching jobs. With active work it waits;
after an acknowledged drain it recovers and ephemeral capacity returns without
operator action. A second case in which the guest cannot acknowledge drain
must remain `recovery_blocked` and must not terminate.

## Board

| id | Task (spec) | group | seq | needs | repo | base_branch | imp/cx | model | Status | Run / PR | Updated |
|---|---|---:|---:|---|---|---|---|---|---|---|---|
| a1-windows-launcher-spike | `tasks/a1-windows-launcher-spike.md` | A | 1 | — | . | main | 3/6 | top | 🔵 | worktree-a1-windows-launcher-spike | 2026-09-11 |
| a2-supervisor-core | `tasks/a2-supervisor-core.md` | A | 2 | a1 | . | main | 3/8 | top | not started | — | 2026-09-11 |
| a3-daemon-reload-contract | `tasks/a3-daemon-reload-contract.md` | A | 3 | a2 | . | main | 3/6 | top | not started | — | 2026-09-11 |
| a4-service-install-start | `tasks/a4-service-install-start.md` | A | 4 | a3 | . | main | 3/7 | top | not started | — | 2026-09-11 |
| a5-service-health | `tasks/a5-service-health.md` | A | 5 | a4 | . | main | 2/5 | mid | not started | — | 2026-09-11 |
| b1-wsl-safety-spikes | `tasks/b1-wsl-safety-spikes.md` | B | 1 | — | . | main | 3/8 | top | not started | — | 2026-09-11 |
| b2-guest-heartbeat-fence | `tasks/b2-guest-heartbeat-fence.md` | B | 2 | b1 | . | main | 3/9 | top | not started | — | 2026-09-11 |
| b3-wsl-recovery-model | `tasks/b3-wsl-recovery-model.md` | B | 3 | b2 | . | main | 3/8 | top | not started | — | 2026-09-11 |
| b4-wsl-windows-supervisor | `tasks/b4-wsl-windows-supervisor.md` | B | 4 | a2, b3 | . | main | 3/10 | top | not started | — | 2026-09-11 |
| b5-wsl-task-migration-status | `tasks/b5-wsl-task-migration-status.md` | B | 5 | b4 | . | main | 3/8 | top | not started | — | 2026-09-11 |
| c1-wsl-tui-model-render | `tasks/c1-wsl-tui-model-render.md` | C | 1 | b3 | . | main | 2/6 | mid | not started | — | 2026-09-11 |
| c2-wsl-tui-collection | `tasks/c2-wsl-tui-collection.md` | C | 2 | b5, c1 | . | main | 2/6 | mid | not started | — | 2026-09-11 |
| d1-acceptance-security-packaging | `tasks/d1-acceptance-security-packaging.md` | D | 1 | a5, b5, c2 | . | main | 3/9 | top | not started | — | 2026-09-11 |
| d2-docs-release | `tasks/d2-docs-release.md` | D | 2 | d1 | . | main | 2/3 | fast | not started | — | 2026-09-11 |

## Integration landing

| repo | base_branch | integration_ref | Final PR | Status | Updated |
|---|---|---|---|---|---|
| . | main | taskflow/windows-service-wsl-self-healing | — | pending | 2026-09-11 |

## Progress log

**2026-09-11 — planned.** The plan incorporates the live incident: a policy
change left the Windows login task stopped with exit 21; reinstall updated the
binary but did not start the new task; explicit start displayed a console; WSL
remained nominally running but could not create a session. Owner requested all
defects fixed and automatic WSL recovery only when active runners are proven
absent.

**2026-09-11 — reviewed.** Six findings were challenged against code and
authoritative Windows documentation and corrected without changing a product
decision:

| # | P | Finding | Correction |
|---|---|---|---|
| F1 | P0 | A long-lived supervisor cannot safely overwrite its own mapped executable during upgrade; the first design had no stable indirection. | Added a no-console stable launcher and versioned supervisor/daemon images with atomic selection. |
| F2 | P0 | G9 promised recovery even when the guest could not acknowledge the race-free drain fence, contradicting D6. | Split replay into acknowledged recovery and mandatory `recovery_blocked` cases. |
| F3 | P1 | Requiring fresh GitHub contact unconditionally makes a correctly idle/no-policy daemon unhealthy. | Health uses heartbeat universally and GitHub freshness only when a policy is due to poll. |
| F4 | P1 | A one-time unmanaged-runner audit becomes stale if a manual runner is installed later. | Guest heartbeat repeats the audit; every recovery requires the current finding. |
| F5 | P1 | Having every TUI probe every distribution duplicates session pressure and can worsen the incident it displays. | TUI consumes supervisor snapshots; only empty-provider capability discovery may invoke WSL. |
| F6 | P1 | Replacing the existing WSL hold task during upgrade can stop a guest daemon with active attempts. | Migration now uses the same acknowledged drain and retains the old task on failure. |

External requirements checked: Microsoft defines Task Scheduler `Hidden` as
UI visibility only, so it cannot solve console creation
(<https://learn.microsoft.com/windows/win32/taskschd/taskschedulerschema-hidden-settingstype-element>),
and defines `RestartOnFailure/Count` as a bounded number of attempts, so it is
not a normal reload transport
(<https://learn.microsoft.com/windows/win32/taskschd/taskschedulerschema-restartonfailure-settingstype-element>).

**2026-09-11 — tasks derived.** Fourteen PR-sized specs preserve strict
conflict domains. A and B serialize their respective lifecycle implementations;
C cannot collect until B exposes status; D owns only cross-cutting packaging,
acceptance and documentation. Wave 0 contains the two empirical gates that can
invalidate implementation mechanisms without weakening the fail-closed product
decision.
