# Windows service reliability and WSL self-healing

**Status:** Reviewed and task-derived 2026-09-11 against `main` at `db4c074`;
ready for execution. Six confirmed review findings are recorded in `ROADMAP.md`.

**Scope:** the Windows login service lifecycle, planned daemon hand-off,
service health, managed-WSL supervision and the Windows TUI. The GitHub runner
lifecycle remains authoritative for job ownership; no recovery operation may
terminate a distribution while safety is unknown.

## Problem

One incident exposed a chain of independent defects:

1. `service install --start-at login` re-registers a logon-triggered task but
   does not start it in the already-open session (`crates/app/src/cli/service.rs:216-335`).
2. The task launches the console-subsystem executable with `Hidden=false`, so
   an interactive terminal appears (`crates/platform/src/service.rs:1804-1824`).
3. A policy-set change deliberately drains and exits with
   `UpgradePending`, trusting the service manager to reload it
   (`crates/app/src/cli/daemon.rs:292-355`). The real task stopped with result
   `0x15` and did not return.
4. `ServiceStatus::is_healthy` ignores whether the daemon is running and calls
   any problem-free registration healthy (`crates/platform/src/service.rs:4519-4540`).
5. A managed WSL2 distribution can remain nominally `Running` while every new
   WSL session fails. The current lifecycle task is only a direct
   `wsl.exe ... wsl-host hold` invocation (`crates/platform/src/wsl/task.rs:196-216`),
   so it cannot diagnose or recover the condition.
6. The TUI snapshot contains repository, runner and local-agent data but no
   Windows WSL host state (`crates/app/src/tui/screens.rs:246-265`,
   `crates/app/src/tui/shell.rs:456-618`).

The observed WSL failure was `Wsl/Service/0x8007274c`; Ubuntu's kernel log
simultaneously showed high-order page allocation failures and vsock/session
leader timeouts under a 6 GiB WSL cap. A single persistent runner therefore
processed nineteen jobs serially while no ephemeral WSL runners appeared.

## Locked decisions

| ID | Decision | Status | Consequence |
|---|---|---|---|
| D1 | `service install` is convergent to **registered and running now**, not merely registered for the next login. | Locked 2026-09-11 from owner request | Install starts the new registration and rolls back/report-fails if start cannot be confirmed. |
| D2 | Windows login services use a product-owned, no-console supervisor executable. The supervisor owns child restart/backoff; Task Scheduler remains the bootstrapping owner. | Locked 2026-09-11 | No terminal window; planned reloads and crashes do not depend on Task Scheduler's five-retry budget. |
| D3 | Policy-set changes reload inside the supervised lifetime after all owned attempts drain. Binary upgrades replace the service copy and are relaunched by the supervisor. | Locked 2026-09-11 | `UpgradePending` is no longer overloaded as the normal policy-reload signal seen by Task Scheduler. |
| D4 | A stopped automatic service is unhealthy after a bounded installation/startup grace. Status must distinguish `starting`, `running`, `stopped`, `restart_backoff`, and `failed`; registration integrity remains a separate fact. | Locked 2026-09-11 | `verdict healthy` can no longer accompany a persistently stopped task. |
| D5 | Managed WSL auto-recovery is enabled only after a safety audit establishes a dedicated Runner Manager host. Existing distributions with unmanaged runner services enter `recovery_blocked`, never terminate automatically. | Locked 2026-09-11, fail-closed interpretation of owner requirement | The existing `ubuntu-server-runner` must be removed/moved or explicitly brought under management before Ubuntu can auto-recover. |
| D6 | WSL recovery requires a Windows-side supervisor under the distribution-owning user, three consecutive bounded probe failures, a shared drain fence acknowledged by the Linux daemon, zero local active attempts, and zero busy/online managed GitHub runners. Any missing, stale, unauthorized or contradictory evidence blocks recovery. | Locked 2026-09-11 | No administrator grant is required by design; availability loses to job safety. No TUI process is required. |
| D7 | Recovery terminates only the named distribution (`wsl.exe --terminate NAME`), never `wsl --shutdown`, then restarts and verifies systemd, daemon heartbeat and GitHub contact with capped exponential backoff and a circuit breaker. | Locked 2026-09-11 | Docker Desktop and other distributions are outside the blast radius; repeated failures become visible rather than a restart loop. |
| D8 | On Windows, the TUI always carries a WSL capability/health section. Off Windows it carries no WSL probe and renders `not supported` only where a cross-platform presentation explicitly includes the field. | Locked 2026-09-11 | Windows states cover unsupported, not installed, no distributions, unmanaged, healthy, degraded, unreachable, draining, recovering, backoff and recovery-blocked. |
| D9 | WSL self-healing settings are per distribution, persisted in the non-secret Windows provider record, default to safe observation for upgraded installations, and become automatic after a successful dedicated-host audit. | Locked 2026-09-11 | No upgrade silently gains destructive authority; a fresh/reconverged install can enable safe automatic recovery. |

## Review disposition

The review preserved all product decisions and corrected six feasibility and
consistency gaps: supervisor self-update now uses versioned child images; TUI
reads cached supervisor state rather than multiplying WSL probes; health does
not require periodic GitHub traffic from an idle host; unmanaged-runner audit
is continuous; WSL task migration drains before replacement; and incident
replay distinguishes recoverable acknowledged drain from a fail-closed guest
that cannot acknowledge it.

## Summary

The target has two durable Windows supervisors: the local-service supervisor
and one per managed WSL distribution. Both run invisibly as the owning user and
publish explicit state. The WSL supervisor never equates “unreachable” with
“safe to terminate”: it first establishes a drain fence and proves that no
managed or unmanaged runner can be interrupted. The TUI consumes the same
typed snapshot as CLI status, so status words cannot drift between surfaces.

## Document map

| Document | Contents |
|---|---|
| `01-current-architecture.md` | Verified behavior and existing seams. |
| `02-target-architecture.md` | Supervisors, state ownership and compatibility. |
| `03-windows-service-lifecycle.md` | Hidden launch, immediate start, reload and health semantics. |
| `04-wsl-recovery-safety.md` | Detection, drain proof, recovery flow and circuit breaker. |
| `05-tui-status-ux.md` | Windows-only collection and complete status vocabulary. |
| `ROADMAP.md` | Gates, waves and the sole task-state ledger. |
