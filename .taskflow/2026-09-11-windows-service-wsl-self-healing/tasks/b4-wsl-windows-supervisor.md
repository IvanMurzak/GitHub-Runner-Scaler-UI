---
id: "b4-wsl-windows-supervisor"
title: "Supervise, drain and recover a managed WSL distribution"
group: "B"
sequence: 4
repo: "."
base_branch: "main"
depends_on: ["a2-supervisor-core", "b3-wsl-recovery-model"]
importance: 3
complexity: 10
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["02-target-architecture.md", "04-wsl-recovery-safety.md"]
---

## Goal

Run the per-distribution Windows watchdog and recover only after the complete
safety proof.

## Scope & seams

Add bounded probes, heartbeat reader, Windows credential/target authorization
audit, GitHub managed-runner inventory/removal, exact named termination,
restart verification, recovery log/state and circuit breaker to the supervisor.

## Definition of Done

- Three failures plus complete proof recover the named disposable distro.
- Active/unmanaged/unknown/unauthorized/stale cases wait without termination.
- Other distributions and Docker Desktop are never targeted.
- Recovery restores systemd daemon heartbeat and GitHub contact or backs off.

