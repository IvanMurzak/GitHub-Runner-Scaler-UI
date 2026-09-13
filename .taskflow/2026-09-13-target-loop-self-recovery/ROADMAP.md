# Per-target daemon self-recovery ledger

**Design status:** reviewed 2026-09-13; the live INFO replay resolved the
immediate causal chain and narrowed the first implementation wave.
**Task status:** derived 2026-09-13.
**Implementation status:** complete and live-verified.
**Repository:** `.` / `main`.
**Last updated:** 2026-09-13.

This file is the only live task-state record.

## Gates

- **G1 Incident replay:** unauthorized → stored replacement → cancellation →
  offline → success produces matching attempts without process/WSL restart.
- **G2 Isolation:** a stalled target cannot delay successful polling or runner
  creation for another target.
- **G3 Runner safety:** cancellation/restart of a target controller never kills
  a busy child and never terminates WSL.
- **G4 Readiness truth:** every enabled target contributes fresh typed state;
  host-wide contact alone cannot produce `READY`.
- **G5 Bounded startup:** 10,000 cleaned attempts do not enter lifecycle
  supervision and startup remains within the test budget.
- **G6 Auth rotation:** concurrent service/TUI renewal and external login select
  the newest stored generation without replaying a rotated refresh token.
- **G7 Platform:** Windows, Linux and macOS builds/tests pass; installed WSL
  systemd heartbeat writes through its hardened unit.

## Execution waves

| Wave | Theme | Gate |
|---|---|---|
| 1 | Core recovery and bounded journal views | G1, G2, G3, G5, G6 |
| 2 | Durable state, CLI/TUI readiness and WSL heartbeat | G4, G7 |
| 3 | Incident acceptance and release build | all gates |

## Board

| id | Task (spec) | group | seq | needs | repo | base_branch | imp/cx | model | Status | Run / PR | Updated |
|---|---|---:|---:|---|---|---|---|---|---|---|---|
| a1-wsl-fence-service-access | `tasks/a1-wsl-fence-service-access.md` | A | 1 | — | . | main | 3/7 | top | complete | local | 2026-09-13 |
| a2-fence-failure-visibility | `tasks/a2-fence-failure-visibility.md` | A | 2 | a1 | . | main | 3/5 | mid | complete | local | 2026-09-13 |
| b1-incident-tests-build | `tasks/b1-incident-tests-build.md` | B | 1 | a1, a2 | . | main | 3/7 | top | complete | local | 2026-09-13 |

## Integration landing

| repo | base_branch | integration_ref | Final PR | Status | Updated |
|---|---|---|---|---|---|

## Progress log

**2026-09-13 — planned.** Live read-only evidence and one safe service-only
restart established that process/systemd health and a fresh global GitHub
contact do not prove that `AI-Game-Dev-Server` is being reconciled. No Docker
daemon, container, WSL distribution, policy, credential, or workflow was
modified.

**2026-09-13 — reviewed.** The initial plan treated target-loop liveness as the
probable immediate cause. Temporary INFO telemetry falsified that hypothesis:
the loop was alive, observed 43 jobs, and allocated 14 starts. The confirmed P0
is the missing systemd write grant for the configured DrvFS fence; the confirmed
P1 is that permanent fence I/O failure collapses into quiet lock contention.
The broader per-target health and credential-generation strategy remains the
target architecture, while the release-blocking wave first repairs and exposes
the proven P0/P1.

**2026-09-13 — tasks derived.** Three dependency-ordered specs separate the
systemd convergence seam, typed runtime visibility, and incident/packaging
acceptance. No owner decision remains open.

**2026-09-13 — implemented and verified.** Guest configuration now atomically
converges an exact-path systemd `ReadWritePaths` drop-in, reloads systemd and
restarts only an active daemon when the grant changes. Heartbeat read and write
failures have distinct reason codes and allocation deferral is warning-level.
The complete workspace test suite and warnings-denied Clippy passed. Native
Windows and Linux release binaries were produced. The macOS cross-check reached
the native C dependency and then stopped because this Windows host has no Apple
SDK/compiler; macOS remains covered by its native CI leg. Live Ubuntu validation
restored the fence, published a fresh heartbeat through the hardened unit, kept
the service active, and left running job/container state under systemd's normal
cooperative handover.
