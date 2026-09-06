# ROADMAP — managed WSL host

The table below is the sole live task-state record.

## Gates

- **G1 owner scope:** satisfied 2026-09-06 by D1-D7.
- **G2 security:** independent device-flow credential, stdin-only handoff and
  canary leak tests must pass before merge.
- **G3 production/release:** owner explicitly requested release `0.4.0` and
  installation on IvanPC. The irreversible release workflow may run only after
  implementation CI is green.
- **G4 migration:** do not remove the existing task
  `GitHub Actions Linux Runner - Ubuntu WSL` until managed status and a live job
  are green.

## Waves

- Wave 1: platform/provider primitives.
- Wave 2: CLI orchestration and credential broker.
- Wave 3: acceptance tests and documentation.
- Wave 4: release, install, adoption and live verification.

## Board

| Task (spec) | needs | repo/base | imp/cx | model | Status | Run / PR | Updated |
|---|---|---|---|---|---|---|---|
| [a1-wsl-platform-adapter](tasks/a1-wsl-platform-adapter.md) | — | ./main | 9/9 | top | 🔵 | pipeline `01a078d5-1e25-7050-899e-148a4578a38e` | 2026-09-06 |
| [b1-credential-broker](tasks/b1-credential-broker.md) | — | ./main | 10/8 | top | 🔵 | pipeline `01a078d9-cdbe-70f3-a422-49f05296c1c8` | 2026-09-06 |
| [b2-wsl-cli-orchestration](tasks/b2-wsl-cli-orchestration.md) | a1, b1 | ./main | 10/10 | top | ⚪ | — | 2026-09-06 |
| [b3-acceptance-docs](tasks/b3-acceptance-docs.md) | b2 | ./main | 8/6 | top | ⚪ | — | 2026-09-06 |

## Progress log

| Date | Event |
|---|---|
| 2026-09-06 | Architecture set created from repository, workstation, Microsoft WSL and GitHub token-rotation evidence. D1-D7 locked from the owner's explicit requirements. |
| 2026-09-06 | Review closed P1 lifecycle-shell and pre-login availability gaps plus P2 destructive command naming. Repository evidence and authoritative Microsoft/GitHub constraints otherwise support the design; no owner decision changed. |
| 2026-09-06 | Immutable task specs created in groups A and B. Independent platform and credential foundations may execute together; orchestration and acceptance follow sequentially. |
| 2026-09-06 | Wave 1 dispatched in two isolated pipeline runs: platform adapter `01a078d5-1e25-7050-899e-148a4578a38e` and credential broker `01a078d5-1ebc-70bf-9e17-fc4e910cedd4`. |
| 2026-09-06 | Credential run was returned to pending because concurrent native worktree provisioning contended on `.git/config`; no implementation ran and the platform run continues. It will be redispatched after A1 releases the repository worktree lock. |
| 2026-09-06 | Credential broker redispatched as `01a078d9-cdbe-70f3-a422-49f05296c1c8` after the one-time platform worktree provisioning phase completed. |
