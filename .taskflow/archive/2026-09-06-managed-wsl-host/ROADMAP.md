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
| [a1-wsl-platform-adapter](tasks/a1-wsl-platform-adapter.md) | — | ./main | 9/9 | top | ✅ | [PR #53](https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/pull/53), `f983cd3` | 2026-09-06 |
| [b1-credential-broker](tasks/b1-credential-broker.md) | — | ./main | 10/8 | top | ✅ | [PR #52](https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/pull/52), `ffb5f37` | 2026-09-06 |
| [r1-macos-credential-test-correction](tasks/r1-macos-credential-test-correction.md) | — | ./worktree-01a078d9… | 9/3 | mid | ✅ | `7d301cd`, PR #52 | 2026-09-06 |
| [b2-wsl-cli-orchestration](tasks/b2-wsl-cli-orchestration.md) | a1, b1 | ./main | 10/10 | top | ✅ | [PR #54](https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/pull/54), `eaf8abd` | 2026-09-07 |
| [r2-windows-line-ending-test-correction](tasks/r2-windows-line-ending-test-correction.md) | — | ./worktree-01a079e2… | 8/2 | mid | ✅ | `4578db5`, PR #54 | 2026-09-07 |
| [b3-acceptance-docs](tasks/b3-acceptance-docs.md) | b2 | ./main | 8/6 | top | ✅ | [PR #55](https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/pull/55), `ca74c71` | 2026-09-07 |

## Progress log

| Date | Event |
|---|---|
| 2026-09-06 | Architecture set created from repository, workstation, Microsoft WSL and GitHub token-rotation evidence. D1-D7 locked from the owner's explicit requirements. |
| 2026-09-06 | Review closed P1 lifecycle-shell and pre-login availability gaps plus P2 destructive command naming. Repository evidence and authoritative Microsoft/GitHub constraints otherwise support the design; no owner decision changed. |
| 2026-09-06 | Immutable task specs created in groups A and B. Independent platform and credential foundations may execute together; orchestration and acceptance follow sequentially. |
| 2026-09-06 | Wave 1 dispatched in two isolated pipeline runs: platform adapter `01a078d5-1e25-7050-899e-148a4578a38e` and credential broker `01a078d5-1ebc-70bf-9e17-fc4e910cedd4`. |
| 2026-09-06 | Credential run was returned to pending because concurrent native worktree provisioning contended on `.git/config`; no implementation ran and the platform run continues. It will be redispatched after A1 releases the repository worktree lock. |
| 2026-09-06 | Credential broker redispatched as `01a078d9-cdbe-70f3-a422-49f05296c1c8` after the one-time platform worktree provisioning phase completed. |
| 2026-09-06 | A1 passed implementation, independent review, simplification and every PR check; PR #53 merged as `f983cd3`. Pipeline teardown timed out, so exact worktree cleanup remains. |
| 2026-09-06 | B1 PR #52 passed Linux, Windows, both E2E jobs and privileged Windows smoke, but macOS exposed a test-only Keychain caching assumption. No merge occurred. R1 dispatched against the preserved clean PR worktree to replace that oracle with an injected failing store and rerun all checks. |
| 2026-09-06 | R1 replaced the platform-file corruption assumption with an injected unreadable store and proved zero active-store calls. All seven PR checks passed, including macOS arm64 and the 13-minute Windows workspace suite; PR #52 merged as `ffb5f37`. A1 and B1 foundations are complete. |
| 2026-09-06 | B2 public CLI/orchestration dispatched in isolated pipeline run `01a079e2-e745-7045-8702-c95dd27ee27c` after both foundation dependencies merged. |
| 2026-09-06 | B2 PR #54 passed six checks, but its source-shape test assumed LF and failed on the Windows CRLF checkout. R2 records the narrow correction against the preserved PR branch; production behavior remains unchanged. |
| 2026-09-07 | R2 made the source-shape test CRLF-independent. Independent review also closed B2 preflight-capacity, adopted-unit activation and credential-scope reporting gaps. All seven checks passed, including the 13-minute Windows suite; PR #54 merged as `eaf8abd`. |
| 2026-09-07 | Wave 3 acceptance tests and operator documentation dispatched after B2 merged green. |
| 2026-09-07 | B3 added isolated CLI acceptance, secret-output canaries, privileged Windows/WSL lifecycle coverage, operator docs and deterministic release/changelog guards. All seven checks passed; PR #55 merged as `ca74c71`. Source implementation is release-ready. |
| 2026-09-11 | Completion re-verified against `main`: every board entry is green, PRs #52-#55 are merged, and the feature shipped in release 0.4.0. Taskflow archived. |
