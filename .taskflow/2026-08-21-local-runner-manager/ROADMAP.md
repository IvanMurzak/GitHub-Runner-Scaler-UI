# Local Runner Manager implementation ledger

> This is this taskflow's implementation ledger, not a workspace-wide product
> roadmap.

**Design status:** Reviewed 2026-08-21
**Task status:** Specified 2026-08-21 (`/taskflow-tasks`) — 23 tasks in 8 groups
**Implementation status:** Not started
**Last updated:** 2026-08-21

**Execution host:** this repository, `IvanMurzak/GitHub-Runner-Scaler-UI`. The
transfer from `ai-pipeline` is complete, so `/taskflow-execute` runs here
against an empty Rust workspace.

Immutable task specifications live in [`tasks/`](tasks/); its
[README](tasks/README.md) carries the coefficient legend, the model rubric, and
the group-to-path map. **This file is the only mutable record of task state.**

## Execution timeline

| Wave | Phase | Outcome | Gate |
|---|---|---|---|
| 0 | P0 | Rust workspace, `rust-toolchain.toml`, committed `Cargo.lock`, `.gitignore`, matrix CI on PR and `main` (D10), release-workflow skeleton, and deterministic domain model. None of these exist today; `HEAD` contains only `LICENSE`. | Satisfied 2026-08-21: name is `runner-manager` (human gate 1). |
| 1 | P0 | **D17 spike first** (user-to-server token drives the Actions-service scale-set chain), then device-flow onboarding (D3), machine-scoped token storage, host and repository capacity CLI (D9), and read-only REST inventory. | D17 spike green; published App registered and its permissions reviewed with the `Administration: Read and write` consequence accepted (human gate 2). |
| 2 | P1 | Actions-service scale-set adapter at repository and organization scope (D18), monitor-only policies (D19), job acquisition, JIT ephemeral runner lifecycle, both capacity ceilings, cleanup, local logs, and the service installers. | One-repository Windows pilot succeeds, including boot-start recovery (human gate 3). |
| 3 | P2, P3 (macOS) | Ratatui keyboard/mouse dashboard, host and repository settings screens, accessible error states, and macOS validation of the Wave 2 service installers. | Windows and macOS acceptance journeys pass (human gate 4). |
| 4 | P3 (Linux), P4 | Linux validation, the end-to-end and security acceptance suite, the full release workflow, install scripts, distribution channels, README, and public beta. | Security, offline, and cross-platform gates pass; rollback drill executed per OS (human gate 5). |

Phase identifiers refer to `06-migration-rollout.md`.

**One deviation from the original wave text, recorded deliberately.** All three
service installers ship in Wave 2 as `d3`, not in Wave 3, because gate 3
requires verified boot-start recovery on Windows and there is no honest way to
deliver that without the installer. Wave 3 and Wave 4 *validate* the same
implementation on macOS and Linux; no second implementation task exists.

## Waves as tasks

```text
Wave 0   a1
Wave 1   c1 -> c2 -> c3            b1 -> b2            d1 -> d2            f1
Wave 2   c4 -> c5    e1 -> e2 -> e3    d3    f2 -> f3
Wave 3   g1 -> g2 -> g3
Wave 4   h1    a2 -> a3
```

Arrows are `depends_on`; columns are groups and may run in parallel where
dependencies allow. Wave 1 opens with **`c1` alone** — every other Wave 1 task
except `b1` and `d1` is downstream of it, because D17 gates all authentication
work and a negative result reopens D3.

## Human-approval gates

Dispatch stops at each gate until the owner records GO in the progress log.

| # | Gate | Blocks |
|---|---|---|
| 1 | Satisfied 2026-08-21. Repository identity is settled (`IvanMurzak/GitHub-Runner-Scaler-UI`, public, MIT) and the crate, binary, and package name is `runner-manager`. Approve GitHub App ownership before any application registration or secret generation. | — |
| 2 | Approve the **published** App's permission set — including the `Administration: Read and write` consequence in `07-security.md`, which every future user inherits — and its configuration (device flow on, token expiration opted out, no private key, no webhook). One-time and product-wide, not per user. Blocked until the D17 spike is green. | `c2` and everything downstream |
| 3 | Approve each host's `host_capacity` and each policy's `max_capacity` after an observed workload measurement. No value is inferred from runner count. | Wave 2 exit |
| 4 | Approve retirement of legacy persistent runners only after the scale-set pilot has completed a representative workflow. | Wave 3 exit |
| 5 | Approve public release after the security, offline, and cross-platform gates in this taskflow pass. | `a2`, `a3` |

Two further human actions are prerequisites rather than gates, and both are
irreversible-adjacent, so `/taskflow-execute` must confirm them before
dispatching the task that needs them:

- **Before `c1`:** a human registers a *throwaway* GitHub App (device flow on,
  expiration opted out, permission set per `07-security.md`), installs it on a
  disposable repository and organization, and supplies the public `client_id`.
  This is not the published App — gate 2 approves that one, and gate 2 is
  itself blocked on `c1`.
- **Before `a2`'s first real dispatch:** the release workflow publishes public
  artifacts under the project's name. Rehearse against a pre-release version
  before any real one.

## Board

Legend: ⬜ pending · 🟦 in progress · 🟨 blocked · ✅ done · ⛔ failed.
`needs` lists direct dependencies only.

| Task (spec) | needs | imp/cx | model | Status | Run / PR | Updated |
|---|---|---|---|---|---|---|
| [a1-workspace-ci-foundation](tasks/a1-workspace-ci-foundation.md) | — | 10/5 | mid | ⬜ pending | | |
| [b1-domain-core](tasks/b1-domain-core.md) | a1 | 10/8 | top | ⬜ pending | | |
| [b2-sqlite-persistence](tasks/b2-sqlite-persistence.md) | b1 | 9/6 | mid | ⬜ pending | | |
| [c1-d17-scale-set-spike](tasks/c1-d17-scale-set-spike.md) | a1 | 10/8 | top | ⬜ pending | | |
| [c2-device-flow-auth](tasks/c2-device-flow-auth.md) | c1, b1 | 10/7 | top | ⬜ pending | | |
| [c3-rest-inventory-gateway](tasks/c3-rest-inventory-gateway.md) | c2 | 8/6 | mid | ⬜ pending | | |
| [c4-actions-service-admin](tasks/c4-actions-service-admin.md) | c2 | 10/8 | top | ⬜ pending | | |
| [c5-scale-set-message-protocol](tasks/c5-scale-set-message-protocol.md) | c4 | 10/9 | top | ⬜ pending | | |
| [d1-platform-core](tasks/d1-platform-core.md) | a1 | 9/6 | top | ⬜ pending | | |
| [d2-machine-secret-store](tasks/d2-machine-secret-store.md) | d1 | 10/7 | top | ⬜ pending | | |
| [d3-service-installers](tasks/d3-service-installers.md) | d1, b2 | 8/7 | top | ⬜ pending | | |
| [e1-reconciliation-capacity](tasks/e1-reconciliation-capacity.md) | b1, c5, d1 | 10/8 | top | ⬜ pending | | |
| [e2-runner-package-cache](tasks/e2-runner-package-cache.md) | c3, d1, b1 | 8/6 | top | ⬜ pending | | |
| [e3-jit-lifecycle-recovery](tasks/e3-jit-lifecycle-recovery.md) | e1, e2, b2, d1 | 10/8 | top | ⬜ pending | | |
| [f1-cli-auth-host-status](tasks/f1-cli-auth-host-status.md) | b2, c3, d2 | 9/6 | top | ⬜ pending | | |
| [f2-cli-policy-commands](tasks/f2-cli-policy-commands.md) | f1, c4 | 9/7 | mid | ⬜ pending | | |
| [f3-cli-daemon-service](tasks/f3-cli-daemon-service.md) | f2, e3, d3 | 7/4 | mid | ⬜ pending | | |
| [g1-tui-shell-input](tasks/g1-tui-shell-input.md) | f1 | 8/8 | top | ⬜ pending | | |
| [g2-tui-screens](tasks/g2-tui-screens.md) | g1, c3 | 8/6 | mid | ⬜ pending | | |
| [g3-tui-settings-parity](tasks/g3-tui-settings-parity.md) | g2, f2 | 8/6 | mid | ⬜ pending | | |
| [h1-e2e-security-acceptance](tasks/h1-e2e-security-acceptance.md) | f3, g3, d3 | 9/7 | top | ⬜ pending | | |
| [a2-release-workflow](tasks/a2-release-workflow.md) | a1 | 8/6 | top | ⬜ pending | | |
| [a3-distribution-and-readme](tasks/a3-distribution-and-readme.md) | a2 | 8/6 | top | ⬜ pending | | |

## Rules beside the board

1. **This board is the only mutable task-state record.** The ready set is
   computed from `needs` plus completed rows at dispatch time; it is never
   stored anywhere. Task files in `tasks/` are immutable and carry no status.
2. **Only `/taskflow-execute` writes board rows or the progress log**, and only
   after ground-truth verification — a merged pull request and green CI, not an
   implementer's report. Implementers report; they never edit a spec or this
   board, and never review or merge their own diff.
3. **A workspace-wide planning system, if one is ever added, gets one thin
   pointer to this ROADMAP** and never a duplicate record per task. No such
   system exists in this repository today.
4. **A group is one merge-conflict domain.** Its tasks run strictly in ascending
   `sequence`, one at a time. Groups run in parallel only where `depends_on`
   allows. The group-to-path map is in [`tasks/README.md`](tasks/README.md).
5. **Manifests are A-group property.** Task `a1` owns every `Cargo.toml` and the
   full `[workspace.dependencies]` table; later tasks consume dependencies with
   `workspace = true`. Adding a **new external crate** is therefore an A-group
   change, not a local one. This is what keeps `Cargo.lock` — the one file every
   Rust task would otherwise touch — out of the parallel conflict surface. If a
   dependency turns out to be missing, stop and raise it rather than editing the
   root manifest from another group.
6. **`c1` is a stop-the-line task.** A RED result on D17 reopens D3 and
   invalidates `07-security.md` in full. No C, E, or F task is dispatched until
   the spike is GREEN at both scopes, and reopening D3 is an owner decision.

## Progress log

| Date | Entry |
|---|---|
| 2026-08-21 | Taskflow created. D1-D5 locked. |
| 2026-08-21 | Taskflow transferred into `IvanMurzak/GitHub-Runner-Scaler-UI`. Repository exists (public, MIT, `LICENSE` only); no product code, workspace manifest, or CI exists yet. |
| 2026-08-21 | Owner decisions closing the review: D21 publishes exactly one GitHub App, rejecting a second read-only App for monitor-only users; the resulting `Administration: Read and write` grant for dashboard-only users is accepted and converted into a disclosure requirement in README, `auth login`, and `add` output. D11 REVISED to drop Scoop: npm and the install script both cover Windows. No owner-facing open questions remain; the only unresolved item is the D17 spike. |
| 2026-08-21 | Owner decisions: D18 supports scale sets at both repository and organization scope; D19 adds a monitor-only policy mode, matching the repository description; D20 confirms that `add` never enables scaling. `ScalePolicy` replaces `RepositoryPolicy` with a `ScaleTarget` sum type and an enforced `PolicyMode` invariant. Recorded consequence: a GitHub App grants its whole permission set per installation, so a monitor-only user still grants `Administration: Read and write`; whether to split into two published Apps is an open question that must be settled before the App is registered. `.gitignore` added to the repository. |
| 2026-08-21 | Owner revised authentication after review: D3 REVISED to device flow against a single published GitHub App, so no user creates an App and no server or client secret exists anywhere. D15 (App manifest) WITHDRAWN as superseded. D16 rejects a second `gh`-credential path. D17 requires a spike proving a user-to-server token drives the Actions-service scale-set chain before any auth work; the contingency if it fails is in `07-security.md`. D11 gained a hosted install script; D14 REVISED to drop download buttons, making every advertised install path a terminal path and removing the signing question entirely. Product name confirmed as `runner-manager`; human gate 1 satisfied. |
| 2026-08-21 | `/taskflow-review` completed: three independent reviews (repository truth, external conformance, internal consistency). Corrections applied in one batch. D6-D8 promoted to the README ledger as locked; D9-D14 added from owner requirements; D12 and D13 recorded as REVISED. Added `09-release-distribution.md`. Key factual correction: scale-set JIT configuration comes from the Actions service, not the public REST `generate-jitconfig` endpoint, which cannot serve a scale set. |
| 2026-08-21 | `/taskflow-tasks` completed: 23 immutable specifications in 8 conflict-domain groups, waves 0-4, written to `tasks/`. Minor same-domain work was merged rather than split — `a3` carries all four distribution channels plus the README, `d1` carries six platform primitives, `f3` carries both `daemon` and `service`, `g2` carries all four read-only screens — and work was split only where one pull request would be unreviewable (`c4`/`c5`, `e1`/`e2`/`e3`). Two structural decisions recorded: `a1` owns every manifest and the whole module skeleton, which removes `Cargo.lock` and module lists from the parallel conflict surface and lets CLI (`F`) and TUI (`G`) be separate groups inside one crate; and `d3` moves to Wave 2 because gate 3 requires Windows boot-start recovery. |
