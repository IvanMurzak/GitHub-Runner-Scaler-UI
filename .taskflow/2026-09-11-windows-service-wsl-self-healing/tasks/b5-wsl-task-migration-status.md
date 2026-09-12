---
id: "b5-wsl-task-migration-status"
title: "Migrate WSL lifecycle tasks and expose recovery status"
group: "B"
sequence: 5
repo: "."
base_branch: "main"
depends_on: ["b4-wsl-windows-supervisor"]
importance: 3
complexity: 8
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["02-target-architecture.md", "05-tui-status-ux.md"]
---

## Goal

Make `wsl install/status/detach` own the supervised lifecycle safely.

## Scope & seams

Replace direct hold task actions only through acknowledged drain, extend
provider records and `WslStatusDocument`, preserve foreign-task refusal and
make detach stop the supervisor without terminating the distribution.

## Definition of Done

- Fresh install creates and starts a least-privilege hidden supervisor task.
- Existing active hold tasks migrate only after drain; failure retains them.
- Status reports eligibility, supervisor, heartbeat, recovery and veto state.
- Detach removes only product Windows state/task and leaves Linux/data intact.

