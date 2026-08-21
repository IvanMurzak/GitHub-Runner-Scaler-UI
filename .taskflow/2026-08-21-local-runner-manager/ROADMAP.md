# Local Runner Manager implementation ledger

> This is this taskflow's implementation ledger, not a workspace-wide product
> roadmap.

**Design status:** Re-reviewed 2026-08-21 (`/taskflow-review`) — **D4 REVISED**
**Task status:** **Superseded.** The 23 specifications in `tasks/` predate the D4
revision and must be re-derived by `/taskflow-tasks`.
**Implementation status:** Not started. One spike executed (`c1`, complete).
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
| 0 | P0 | Rust workspace, `rust-toolchain.toml`, committed `Cargo.lock`, `.gitignore`, matrix CI on PR and `main` (D10), release-workflow skeleton, and deterministic domain model. None of these exist today; `HEAD` carries only `LICENSE`, `.gitignore`, this taskflow, and the D17 spike record. | Satisfied 2026-08-21: name is `runner-manager` (human gate 1). |
| 1 | P0 | **D17 spike — done, GREEN.** Then device-flow onboarding (D3), machine-scoped token storage, host and repository capacity CLI (D9), and read-only REST inventory. | Published App registered and its permissions reviewed with the `Administration: Read and write` consequence accepted (human gate 2). Organization-scope `generate-jitconfig` proven. |
| 2 | P1 | REST demand polling at repository and organization scope (D18), monitor-only policies (D19), JIT ephemeral runner lifecycle, both capacity ceilings, cleanup, local logs, and the service installers. | One-repository Windows pilot succeeds, including boot-start recovery (human gate 3). |
| 3 | P2, P3 (macOS) | Ratatui keyboard/mouse dashboard, host and repository settings screens, accessible error states, and macOS validation of the Wave 2 service installers. | Windows and macOS acceptance journeys pass (human gate 4). |
| 4 | P3 (Linux), P4 | Linux validation, the end-to-end and security acceptance suite, the full release workflow, install scripts, distribution channels, README, and public beta. | Security, offline, and cross-platform gates pass; rollback drill executed per OS (human gate 5). |

Phase identifiers refer to `06-migration-rollout.md`.

**One deviation from the original wave text, recorded deliberately.** All three
service installers ship in Wave 2 as `d3`, not in Wave 3, because gate 3
requires verified boot-start recovery on Windows and there is no honest way to
deliver that without the installer. Wave 3 and Wave 4 *validate* the same
implementation on macOS and Linux; no second implementation task exists.

## Waves as tasks

**Superseded by the D4 revision.** The wave graph below described the task set
in `tasks/`, which no longer matches the design. `/taskflow-tasks` re-derives
both. The wave *phases* in the timeline above still hold; only the task
decomposition changed.

## Human-approval gates

Dispatch stops at each gate until the owner records GO in the progress log.

| # | Gate | Blocks |
|---|---|---|
| 1 | Satisfied 2026-08-21. Repository identity is settled (`IvanMurzak/GitHub-Runner-Scaler-UI`, public, MIT) and the crate, binary, and package name is `runner-manager`. Approve GitHub App ownership before any application registration or secret generation. | — |
| 2 | Approve the **published** App's permission set — including the `Administration: Read and write` consequence in `07-security.md`, which every future user inherits — and its configuration (device flow on, token expiration opted out, no private key, no webhook). One-time and product-wide, not per user. **No longer blocked:** the D17 spike is green. | the auth task and everything downstream |
| 3 | Approve each host's `host_capacity` and each policy's `max_capacity` after an observed workload measurement. No value is inferred from runner count. | Wave 2 exit |
| 4 | Approve retirement of legacy persistent runners only after the autoscale pilot has completed a representative workflow. | Wave 3 exit |
| 5 | Approve public release after the security, offline, and cross-platform gates in this taskflow pass. | the release and distribution tasks |

Two further human actions are prerequisites rather than gates, and both are
irreversible-adjacent, so `/taskflow-execute` must confirm them before
dispatching the task that needs them:

- **Done 2026-08-21:** the throwaway App `runner-manager-d17-spike` was
  registered and installed on the repository and on `Tap-Top-Fun`, and the D17
  spike ran against it. Delete that App now that the spike is closed.
- **Before the release task's first real dispatch:** the release workflow
  publishes public artifacts under the project's name. Rehearse against a
  pre-release version before any real one.

## Board

**No active board.** The 23 rows produced on 2026-08-21 were invalidated the
same day by the D4 revision and have been removed rather than left to rot into
a record that disagrees with the design. Nothing is lost: every row was
`⬜ pending`.

| Work | State | Evidence |
|---|---|---|
| `c1-d17-scale-set-spike` | ✅ **complete** | `docs/spikes/d17-user-to-server-scale-set-chain.md`. Do not re-run. |
| everything else | not started | — |

`/taskflow-tasks` rebuilds this board against the corrected design. What the
re-derivation must carry forward, and what it must drop:

| Carry forward | Drop |
|---|---|
| The A/B/D/F/G/H group shape and its conflict domains — untouched by D4 | `c5` entirely: no message protocol, no `AcquireJobs`, no contract tests, no revision pinning |
| `a1` owning every manifest and the module skeleton, which is what keeps `Cargo.lock` out of the parallel conflict surface | Most of `c4`: the two-stage credential chain and scale-set administration both disappear |
| `d3` in Wave 2, because gate 3 needs Windows boot-start recovery | `protocol_flag`, `scale_set_id`, and `scale_set_name` from the domain model |
| `c1` as complete | The spike's own human prerequisite — already satisfied |

Two new obligations the previous set did not have: prove organization-scope
`generate-jitconfig` before building D18's org path, and enforce the REST budget
ceiling in `04-subsystem-contracts.md`, which now bounds how many targets one
host can serve.

## Rules beside the board

1. **This board is the only mutable task-state record.** The ready set is
   computed from `needs` plus completed rows at dispatch time; it is never
   stored anywhere. Task files in `tasks/` are immutable and carry no status —
   which is why the D4 revision retires the set rather than editing it.
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
6. **`c1` did its job.** It was declared stop-the-line, it returned GREEN on
   D17 and RED on D4, and the plan changed rather than the evidence. The
   equivalent rule for the re-derived set: prove organization-scope
   `generate-jitconfig` before any org-path task is dispatched, because D18
   currently rests on an untested endpoint.

## Progress log

| Date | Entry |
|---|---|
| 2026-08-21 | Taskflow created. D1-D5 locked. |
| 2026-08-21 | Taskflow transferred into `IvanMurzak/GitHub-Runner-Scaler-UI`. Repository exists (public, MIT, `LICENSE` only); no product code, workspace manifest, or CI exists yet. |
| 2026-08-21 | Owner decisions closing the review: D21 publishes exactly one GitHub App, rejecting a second read-only App for monitor-only users; the resulting `Administration: Read and write` grant for dashboard-only users is accepted and converted into a disclosure requirement in README, `auth login`, and `add` output. D11 REVISED to drop Scoop: npm and the install script both cover Windows. No owner-facing open questions remain; the only unresolved item is the D17 spike. |
| 2026-08-21 | Owner decisions: D18 supports scale sets at both repository and organization scope; D19 adds a monitor-only policy mode, matching the repository description; D20 confirms that `add` never enables scaling. `ScalePolicy` replaces `RepositoryPolicy` with a `ScaleTarget` sum type and an enforced `PolicyMode` invariant. Recorded consequence: a GitHub App grants its whole permission set per installation, so a monitor-only user still grants `Administration: Read and write`; whether to split into two published Apps is an open question that must be settled before the App is registered. `.gitignore` added to the repository. |
| 2026-08-21 | Owner revised authentication after review: D3 REVISED to device flow against a single published GitHub App, so no user creates an App and no server or client secret exists anywhere. D15 (App manifest) WITHDRAWN as superseded. D16 rejects a second `gh`-credential path. D17 requires a spike proving a user-to-server token drives the Actions-service scale-set chain before any auth work; the contingency if it fails is in `07-security.md`. D11 gained a hosted install script; D14 REVISED to drop download buttons, making every advertised install path a terminal path and removing the signing question entirely. Product name confirmed as `runner-manager`; human gate 1 satisfied. |
| 2026-08-21 | `/taskflow-review` completed: three independent reviews (repository truth, external conformance, internal consistency). Corrections applied in one batch. D6-D8 promoted to the README ledger as locked; D9-D14 added from owner requirements; D12 and D13 recorded as REVISED. Added `09-release-distribution.md`. Key factual correction: scale-set JIT configuration comes from the Actions service, not the public REST `generate-jitconfig` endpoint, which cannot serve a scale set. |
| 2026-08-21 | `/taskflow-review` (second pass) completed. **D4 REVISED** from runner scale sets to public REST JIT ephemeral runners, on owner decision, after the `c1` spike returned direct evidence: scale-set creation is denied `403 needs Administer Permissions` on four independent credential/scope combinations (personal repo and free org, each with `ghu_` and `gho_`), while `POST /repos/…/actions/runners/generate-jitconfig` returns `201` on the same account with the same `Administration: write` permission and the same runner group. Registering a runner into a group is permitted; administering the group is not. **D17 RESOLVED GREEN** at both scopes; the per-user-App contingency in `07-security.md` is not adopted. **D18** keeps both scopes but its org mechanism is now `generate-jitconfig`, which is **unverified**. Corrections applied across all ten design documents: the Actions-service protocol, `AcquireJobs`, `protocol_flag`, `scale_set_id`, `scale_set_name`, and three derived credentials are removed; routing moves from a scale-set name to a label set; the rate-limit analysis is redone because demand polling now shares the 5,000/hour REST budget, which caps a host at roughly 10 targets at the 60-second default. The task set in `tasks/` is superseded and must be re-derived. |
| 2026-08-21 | `/taskflow-tasks` completed: 23 immutable specifications in 8 conflict-domain groups, waves 0-4, written to `tasks/`. Minor same-domain work was merged rather than split — `a3` carries all four distribution channels plus the README, `d1` carries six platform primitives, `f3` carries both `daemon` and `service`, `g2` carries all four read-only screens — and work was split only where one pull request would be unreviewable (`c4`/`c5`, `e1`/`e2`/`e3`). Two structural decisions recorded: `a1` owns every manifest and the whole module skeleton, which removes `Cargo.lock` and module lists from the parallel conflict surface and lets CLI (`F`) and TUI (`G`) be separate groups inside one crate; and `d3` moves to Wave 2 because gate 3 requires Windows boot-start recovery. |
