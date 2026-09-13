# Per-target daemon self-recovery

**Status:** reviewed 2026-09-13 from a live `0.4.20` incident on Windows +
managed Ubuntu WSL; tasks derived.

## Problem

GitHub Actions run `34745908455` exposed a gap between process health and
useful work. All nineteen jobs matched the Ubuntu policy, the host had twenty
free slots, and systemd reported the daemon running, yet no attempt was
created. The live journal showed an expired in-memory credential before the
run, cancelled target polls during WSL/service churn, and a later transport
failure for the exact repository. A host-wide contact timestamp subsequently
became fresh because another target succeeded, masking the affected target.

Temporary INFO telemetry then proved the immediate cause: the policy observed
43 matching jobs and allocated 14 starts, but every start was deferred because
`WslRecoveryAllocationLock` could not create its claim below the DrvFS shared
root. The installed systemd unit used `ProtectSystem=strict` and omitted that
root from `ReadWritePaths`. Renaming only the guest recovery configuration made
the same daemon immediately register busy ephemeral runners, proving the fence
permission—not GitHub labels, capacity, CPU, RAM, or Docker—was causal.

## Locked decisions

| ID | Decision | Status |
|---|---|---|
| D1 | Recovery is automatic and per target; one target may neither mask nor stall another. | Locked 2026-09-13 from owner request. |
| D2 | A target that misses its bounded progress deadline is cancelled and recreated with capped backoff; active runner processes remain supervised and are never killed by this watchdog. | Locked 2026-09-13, safety-preserving interpretation. |
| D3 | Authentication rejection reloads the machine store immediately and retries once with the replacement generation before declaring interactive login necessary. | Locked 2026-09-13 from the existing hot-login contract. |
| D4 | Readiness is computed from every due policy target, not from one host-wide successful contact. | Locked 2026-09-13 from owner requirement that failures be visible. |
| D5 | Historical `cleaned` attempts remain available for diagnostics but are excluded at the SQL boundary from supervision, allocation, heartbeat, and startup-recovery hot paths. | Locked 2026-09-13; no destructive history purge in this change. |
| D6 | Guest-heartbeat publication failure is reported independently and cannot claim healthy; it does not gate GitHub reconciliation. | Locked 2026-09-13. |

## Summary

Add a durable per-target progress snapshot, an outer deadline/restart owner for
each target loop, credential-generation reload on rejection, and narrow store
queries for live work. CLI/TUI readiness consumes the per-target snapshots and
names stale, unauthorized, offline, restarting and healthy states. Integration
tests replay the exact incident sequence and prove that matching queued jobs
eventually produce attempts without operator intervention.

## Documents

- `01-current-architecture.md` — verified incident and current seams.
- `02-target-architecture.md` — recovery state machine and invariants.
- `ROADMAP.md` — execution ledger and gates.
