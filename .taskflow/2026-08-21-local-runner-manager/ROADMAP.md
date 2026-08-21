# Local Runner Manager implementation ledger

> This is this taskflow's implementation ledger, not a workspace-wide product
> roadmap.

**Design status:** Reviewed 2026-08-21
**Implementation status:** Not started
**Last updated:** 2026-08-21

**Execution host:** this repository, `IvanMurzak/GitHub-Runner-Scaler-UI`. The
transfer from `ai-pipeline` is complete, so `/taskflow-tasks` and
`/taskflow-execute` run here against an empty Rust workspace.

## Execution timeline

| Wave | Phase | Outcome | Gate |
|---|---|---|---|
| 0 | P0 | Rust workspace, `rust-toolchain.toml`, committed `Cargo.lock`, `.gitignore`, matrix CI on PR and `main` (D10), release-workflow skeleton, and deterministic domain model. None of these exist today; `HEAD` contains only `LICENSE`. | Owner approves the crate/binary/package name (human gate 1). |
| 1 | P0 | GitHub App onboarding, machine-scoped secret storage, host and repository capacity CLI (D9), and read-only REST inventory. | App permissions reviewed and the `Administration: Read and write` consequence accepted (human gate 2). |
| 2 | P1 | Actions-service scale-set adapter, job acquisition, JIT ephemeral runner lifecycle, both capacity ceilings, cleanup, and local logs. | One-repository Windows pilot succeeds, including boot-start recovery (human gate 3). |
| 3 | P2, P3 (macOS) | Ratatui keyboard/mouse dashboard, host and repository settings screens, accessible error states, and cross-platform service installers. | Windows and macOS acceptance journeys pass (human gate 4). |
| 4 | P3 (Linux), P4 | Linux validation, resilience/security hardening, documentation, README download buttons, release artifacts, distribution channels, and public beta. | Security, offline, and cross-platform gates pass; rollback drill executed per OS (human gate 5). |

Phase identifiers refer to `06-migration-rollout.md`.

## Human-approval gates

1. Repository identity is settled (`IvanMurzak/GitHub-Runner-Scaler-UI`, public,
   MIT, created 2026-08-21). Approve the crate, binary, and package name, and
   GitHub App ownership, before any application registration or secret
   generation.
2. Approve GitHub App permissions — including the `Administration: Read and
   write` consequence in `07-security.md` — and the first repository
   installation before the pilot.
3. Approve each host's `host_capacity` and each policy's `max_capacity` after an
   observed workload measurement; no automatic value is inferred from runner
   count.
4. Approve retirement of legacy persistent runners only after the scale-set
   pilot has completed a representative workflow.
5. Approve public release after the security, offline, and cross-platform gates
   in this taskflow pass.

## Board

| Task (spec) | needs | imp/cx | model | Status | Run / PR | Updated |
|---|---|---|---|---|---|---|
| _Populated only by `/taskflow-tasks`._ |  |  |  |  |  |  |

## Progress log

| Date | Entry |
|---|---|
| 2026-08-21 | Taskflow created. D1-D5 locked. |
| 2026-08-21 | Taskflow transferred into `IvanMurzak/GitHub-Runner-Scaler-UI`. Repository exists (public, MIT, `LICENSE` only); no product code, workspace manifest, or CI exists yet. |
| 2026-08-21 | `/taskflow-review` completed: three independent reviews (repository truth, external conformance, internal consistency). Corrections applied in one batch. D6-D8 promoted to the README ledger as locked; D9-D14 added from owner requirements; D12 and D13 recorded as REVISED. Added `09-release-distribution.md`. Key factual correction: scale-set JIT configuration comes from the Actions service, not the public REST `generate-jitconfig` endpoint, which cannot serve a scale set. |
