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
| 0 | P0 | Rust workspace, `rust-toolchain.toml`, committed `Cargo.lock`, `.gitignore`, matrix CI on PR and `main` (D10), release-workflow skeleton, and deterministic domain model. None of these exist today; `HEAD` contains only `LICENSE`. | Satisfied 2026-08-21: name is `runner-manager` (human gate 1). |
| 1 | P0 | **D17 spike first** (user-to-server token drives the Actions-service scale-set chain), then device-flow onboarding (D3), machine-scoped token storage, host and repository capacity CLI (D9), and read-only REST inventory. | D17 spike green; published App registered and its permissions reviewed with the `Administration: Read and write` consequence accepted (human gate 2). |
| 2 | P1 | Actions-service scale-set adapter, job acquisition, JIT ephemeral runner lifecycle, both capacity ceilings, cleanup, and local logs. | One-repository Windows pilot succeeds, including boot-start recovery (human gate 3). |
| 3 | P2, P3 (macOS) | Ratatui keyboard/mouse dashboard, host and repository settings screens, accessible error states, and cross-platform service installers. | Windows and macOS acceptance journeys pass (human gate 4). |
| 4 | P3 (Linux), P4 | Linux validation, resilience/security hardening, documentation, install scripts, release artifacts, distribution channels, and public beta. | Security, offline, and cross-platform gates pass; rollback drill executed per OS (human gate 5). |

Phase identifiers refer to `06-migration-rollout.md`.

## Human-approval gates

1. Satisfied 2026-08-21. Repository identity is settled
   (`IvanMurzak/GitHub-Runner-Scaler-UI`, public, MIT) and the crate, binary,
   and package name is `runner-manager`. Approve GitHub App ownership before
   any application registration or secret generation.
2. Approve the **published** App's permission set — including the
   `Administration: Read and write` consequence in `07-security.md`, which every
   future user inherits — and its configuration (device flow on, token
   expiration opted out, no private key, no webhook). This is a one-time,
   product-wide approval, not a per-user one. Blocked until the D17 spike is
   green.
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
| 2026-08-21 | Owner revised authentication after review: D3 REVISED to device flow against a single published GitHub App, so no user creates an App and no server or client secret exists anywhere. D15 (App manifest) WITHDRAWN as superseded. D16 rejects a second `gh`-credential path. D17 requires a spike proving a user-to-server token drives the Actions-service scale-set chain before any auth work; the contingency if it fails is in `07-security.md`. D11 gained a hosted install script; D14 REVISED to drop download buttons, making every advertised install path a terminal path and removing the signing question entirely. Product name confirmed as `runner-manager`; human gate 1 satisfied. |
| 2026-08-21 | `/taskflow-review` completed: three independent reviews (repository truth, external conformance, internal consistency). Corrections applied in one batch. D6-D8 promoted to the README ledger as locked; D9-D14 added from owner requirements; D12 and D13 recorded as REVISED. Added `09-release-distribution.md`. Key factual correction: scale-set JIT configuration comes from the Actions service, not the public REST `generate-jitconfig` endpoint, which cannot serve a scale set. |
