# Local Runner Manager implementation ledger

> This is this taskflow's implementation ledger, not a workspace-wide product
> roadmap.

**Design status:** Re-reviewed 2026-08-21 (`/taskflow-review`) — **D4 REVISED**
**Task status:** Re-derived 2026-08-21 (`/taskflow-tasks`) against the corrected
design. 23 immutable specifications in [`tasks/`](tasks/), 9 conflict-domain
groups, waves 0-4.
**Implementation status:** In execution since 2026-08-21 via `/taskflow-execute`
(`--parallel=6 --review=medium --scope=all --merge=on-green`). One spike
complete (`c1`); `v1` and `a1` merged. Round 2 in flight: `b1` plus an
A-group correction round on `a1`.
**Last updated:** 2026-08-21

**Execution host:** this repository, `IvanMurzak/GitHub-Runner-Scaler-UI`. The
transfer from `ai-pipeline` is complete, so `/taskflow-execute` runs here
against an empty Rust workspace.

Immutable task specifications live in [`tasks/`](tasks/); its
[README](tasks/README.md) carries the coefficient legend, the model rubric, the
group-to-path map, and the record of what the D4 revision changed.
**This file is the only mutable record of task state.**

## Execution timeline

| Wave | Phase | Outcome | Gate |
|---|---|---|---|
| 0 | P0 | Rust workspace, `rust-toolchain.toml`, committed `Cargo.lock`, matrix CI on PR and `main` (D10), release-workflow skeleton, and the deterministic domain model with its persistence. None of these exist today; `HEAD` carries only `LICENSE`, `.gitignore`, this taskflow, and the D17 spike record. | Satisfied 2026-08-21: name is `runner-manager` (human gate 1). |
| 1 | P0 | Organization-scope `generate-jitconfig` proven (`v1`). Then device-flow onboarding (D3), machine-scoped token storage, platform primitives, read-only REST inventory with the shared request budget, and the full host and policy configuration CLI including both capacity levels (D9) and monitor-only policies (D19). Nothing scales yet: `add` never arms a host (D20). | Published App registered and its permissions reviewed with the `Administration: Read and write` consequence accepted (human gate 2). Organization-scope `generate-jitconfig` proven by `v1`. |
| 2 | P1 | REST demand polling at repository and organization scope (D18), JIT ephemeral runner lifecycle, runner package cache, both capacity ceilings enforced, cleanup, local logs, the service installers, and the `daemon`/`service` command surface. | One-repository Windows pilot succeeds, including boot-start recovery (human gate 3). |
| 3 | P2, P3 (macOS) | Ratatui keyboard/mouse dashboard, host and policy settings screens with CLI parity, accessible error states, and macOS validation of the Wave 2 service installers. | Windows and macOS acceptance journeys pass (human gate 4). |
| 4 | P3 (Linux), P4 | Linux validation, the end-to-end and security acceptance suite, the full release workflow, install scripts, distribution channels, README, and public beta. | Security, offline, and cross-platform gates pass; rollback drill executed per OS (human gate 5). |

Phase identifiers refer to `06-migration-rollout.md`.

**Three deviations from the original wave text, recorded deliberately.**

1. All three service installers ship in Wave 2 as `d3`, not in Wave 3, because
   gate 3 requires verified boot-start recovery on Windows and there is no
   honest way to deliver that without the installer. Wave 3 and Wave 4
   *validate* the same implementation on macOS and Linux; no second
   implementation task exists.
2. `f2` — the `repo` and `org` command families — is in Wave 1, not Wave 2.
   After D4 `add` creates nothing remotely and arms nothing, so the entire
   configuration surface is buildable before the agent exists. Wave 1 therefore
   ends at "everything is configurable and nothing runs", which is exactly what
   human gate 2 needs to approve.
3. `v1` runs in Wave 1 rather than being folded into `c4`. It is the same class
   of task as `c1`: a cheap experiment that decides whether a design path
   exists. Running it before the org code is written is the lesson `c1` already
   taught at a cost of one full design revision.

## Waves as tasks

```text
Wave 0   a1 ──┬── b1 ── b2
              │
Wave 1        ├── v1                                  (org JIT proof, no deps in code)
              ├── c1 ✅ ── c2 ── c3
              ├── d1 ── d2
              └── (c3 + d2 + b2) ── f1 ── f2

Wave 2   (c3 + b1 + v1) ── c4 ── e1 ─┬── e3 ── f3
                            e2 ──────┘
                     (d1 + b2) ── d3 ──────────┘

Wave 3   f1 ── g1 ── g2 ── g3

Wave 4   a1 ── a2 ── a3
         (f3 + g3 + d3 + v1) ── h1
```

Parallelism the graph allows: groups **V**, **C**, **D**, and **B** run
concurrently from Wave 0/1; **F** starts as soon as `c3`, `d2`, and `b2` land;
**A**'s release work (`a2`, `a3`) is independent of every product group and is
scheduled last only because it publishes.

## Human-approval gates

Dispatch stops at each gate until the owner records GO in the progress log.

| # | Gate | Blocks |
|---|---|---|
| 1 | Satisfied 2026-08-21. Repository identity is settled (`IvanMurzak/GitHub-Runner-Scaler-UI`, public, MIT) and the crate, binary, and package name is `runner-manager`. | — |
| 2 | **GO recorded 2026-08-21.** Approve the **published** App's permission set — including the `Administration: Read and write` consequence in `07-security.md`, which every future user inherits — and its configuration (device flow on, token expiration opted out, no private key, no webhook). One-time and product-wide, not per user. Approve on the evidence from `v1` that organization-scope `generate-jitconfig` works. **No longer blocked by D17:** the spike is green. | `c2` and everything downstream of it |
| 3 | Approve each host's `host_capacity` and each policy's `max_capacity` after an observed workload measurement. No value is inferred from runner count. | Wave 2 exit |
| 4 | Approve retirement of legacy persistent runners only after the autoscale pilot has completed a representative workflow. | Wave 3 exit |
| 5 | Approve public release after the security, offline, and cross-platform gates in this taskflow pass. | `a2`, `a3`, and the release rehearsal |

Two further human actions are prerequisites rather than gates, and both are
irreversible-adjacent, so `/taskflow-execute` must confirm them before
dispatching the task that needs them:

- **Before `v1` is dispatched:** an App with `Organization → Self-hosted
  runners: Read and write`, installed on a disposable organization. The
  throwaway App `runner-manager-d17-spike` already satisfies this. **Run `v1`
  before deleting it**, then delete it — the ROADMAP previously called for
  immediate deletion, and doing that first would make `v1` wait for human
  gate 2 for no reason.
- **Before the release task's first real dispatch:** the release workflow
  publishes public artifacts under the project's name. Rehearse against a
  pre-release version before any real one.

## Board

23 tasks. `/taskflow-execute` is the only writer of the Status, Run / PR, and
Updated columns.

| Task (spec) | needs | imp/cx | model | Status | Run / PR | Updated |
|---|---|---|---|---|---|---|
| **Wave 0** | | | | | | |
| [a1-workspace-ci-foundation](tasks/a1-workspace-ci-foundation.md) | — | 10/5 | mid | ✅ done | `b67ca43` (local merge) | 2026-08-21 |
| [b1-domain-core](tasks/b1-domain-core.md) | a1 | 10/8 | top | 🔵 in progress | round 2 (local) | 2026-08-21 |
| [b2-sqlite-persistence](tasks/b2-sqlite-persistence.md) | b1 | 9/6 | mid | ⬜ pending | | |
| **Wave 1** | | | | | | |
| [v1-org-jit-verification](tasks/v1-org-jit-verification.md) | c1 | 9/3 | mid | ✅ done | `e5d7d1c` (local merge) | 2026-08-21 |
| [c1-d17-scale-set-spike](tasks/c1-d17-scale-set-spike.md) | a1 | 10/8 | top | ✅ complete | `docs/spikes/d17-user-to-server-scale-set-chain.md` | 2026-08-21 |
| [c2-device-flow-auth](tasks/c2-device-flow-auth.md) | c1, b1 | 10/7 | top | ⬜ pending | | |
| [c3-rest-inventory-gateway](tasks/c3-rest-inventory-gateway.md) | c2 | 8/6 | mid | ⬜ pending | | |
| [d1-platform-core](tasks/d1-platform-core.md) | a1 | 9/6 | top | ⬜ pending | | |
| [d2-machine-secret-store](tasks/d2-machine-secret-store.md) | d1 | 10/7 | top | ⬜ pending | | |
| [f1-cli-auth-host-status](tasks/f1-cli-auth-host-status.md) | b2, c3, d2 | 9/6 | top | ⬜ pending | | |
| [f2-cli-policy-commands](tasks/f2-cli-policy-commands.md) | f1 | 9/6 | mid | ⬜ pending | | |
| **Wave 2** | | | | | | |
| [c4-demand-and-jit-gateway](tasks/c4-demand-and-jit-gateway.md) | c3, b1, v1 | 10/7 | top | ⬜ pending | | |
| [e1-reconciliation-capacity](tasks/e1-reconciliation-capacity.md) | b1, c4, d1 | 10/8 | top | ⬜ pending | | |
| [e2-runner-package-cache](tasks/e2-runner-package-cache.md) | c3, d1, b1 | 8/6 | top | ⬜ pending | | |
| [e3-jit-lifecycle-recovery](tasks/e3-jit-lifecycle-recovery.md) | e1, e2, b2, d1 | 10/8 | top | ⬜ pending | | |
| [d3-service-installers](tasks/d3-service-installers.md) | d1, b2 | 8/7 | top | ⬜ pending | | |
| [f3-cli-daemon-service](tasks/f3-cli-daemon-service.md) | f2, e3, d3 | 7/4 | mid | ⬜ pending | | |
| **Wave 3** | | | | | | |
| [g1-tui-shell-input](tasks/g1-tui-shell-input.md) | f1 | 8/8 | top | ⬜ pending | | |
| [g2-tui-screens](tasks/g2-tui-screens.md) | g1, c3 | 8/6 | mid | ⬜ pending | | |
| [g3-tui-settings-parity](tasks/g3-tui-settings-parity.md) | g2, f2 | 8/6 | mid | ⬜ pending | | |
| **Wave 4** | | | | | | |
| [h1-e2e-security-acceptance](tasks/h1-e2e-security-acceptance.md) | f3, g3, d3, v1 | 9/7 | top | ⬜ pending | | |
| [a2-release-workflow](tasks/a2-release-workflow.md) | a1 | 8/6 | top | ⬜ pending | | |
| [a3-distribution-and-readme](tasks/a3-distribution-and-readme.md) | a2 | 8/6 | top | ⬜ pending | | |

Status vocabulary (`/taskflow-execute`'s, adopted 2026-08-21 so board and
orchestrator share one set): `⬜ pending`, `🔵 in progress`, `🟣 verified,
merge held`, `✅ done`, `🔒 blocked on a gate`, `⛔ blocked on a dependency or
failure`.

## Rules beside the board

1. **This board is the only mutable task-state record.** The ready set is
   computed from `needs` plus completed rows at dispatch time; it is never
   stored anywhere. Task files in `tasks/` are immutable and carry no status —
   which is why the D4 revision retired the previous set rather than editing it.
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
6. **A spike that returns RED stops the line; it does not get worked around.**
   `c1` was declared stop-the-line, returned GREEN on D17 and RED on D4, and the
   plan changed rather than the evidence. `v1` inherits the rule: if
   organization-scope `generate-jitconfig` is denied, D18's organization path is
   an owner decision, and neither `c4`'s org path nor `f2`'s `org` family is
   started until that decision exists.
7. **Do not reintroduce a job reservation.** There is no `AcquireJobs`
   equivalent on the REST path. `b1`, `c4`, and `e1` each say so explicitly
   because a well-meaning implementer will otherwise build a local lease to
   "fix" the surplus-runner case. The surplus runner is an accepted, bounded
   cost (`02-target-architecture.md`), and `h1` scenario 8 proves the bound.

## Progress log

| Date | Entry |
|---|---|
| 2026-08-21 | Taskflow created. D1-D5 locked. |
| 2026-08-21 | Taskflow transferred into `IvanMurzak/GitHub-Runner-Scaler-UI`. Repository exists (public, MIT, `LICENSE` only); no product code, workspace manifest, or CI exists yet. |
| 2026-08-21 | Owner decisions closing the review: D21 publishes exactly one GitHub App, rejecting a second read-only App for monitor-only users; the resulting `Administration: Read and write` grant for dashboard-only users is accepted and converted into a disclosure requirement in README, `auth login`, and `add` output. D11 REVISED to drop Scoop: npm and the install script both cover Windows. No owner-facing open questions remain; the only unresolved item is the D17 spike. |
| 2026-08-21 | Owner decisions: D18 supports both repository and organization scope; D19 adds a monitor-only policy mode, matching the repository description; D20 confirms that `add` never enables scaling. `ScalePolicy` replaces `RepositoryPolicy` with a `ScaleTarget` sum type and an enforced `PolicyMode` invariant. Recorded consequence: a GitHub App grants its whole permission set per installation, so a monitor-only user still grants `Administration: Read and write`. `.gitignore` added to the repository. |
| 2026-08-21 | Owner revised authentication after review: D3 REVISED to device flow against a single published GitHub App, so no user creates an App and no server or client secret exists anywhere. D15 (App manifest) WITHDRAWN as superseded. D16 rejects a second `gh`-credential path. D17 requires a spike proving a user-to-server token drives the credential chain before any auth work. D11 gained a hosted install script; D14 REVISED to drop download buttons. Product name confirmed as `runner-manager`; human gate 1 satisfied. |
| 2026-08-21 | `/taskflow-review` completed: three independent reviews (repository truth, external conformance, internal consistency). Corrections applied in one batch. D6-D8 promoted to the README ledger as locked; D9-D14 added from owner requirements; D12 and D13 recorded as REVISED. Added `09-release-distribution.md`. |
| 2026-08-21 | `/taskflow-tasks` (first derivation): 23 specifications in 8 conflict-domain groups, written to `tasks/`. |
| 2026-08-21 | `c1` executed. **D17 GREEN** at both scopes; **D4 RED** — scale-set creation denied `403 needs Administer Permissions` on four independent credential/scope combinations, while `generate-jitconfig` returned `201` on the same account and permission. Evidence: `docs/spikes/d17-user-to-server-scale-set-chain.md`. |
| 2026-08-21 | `/taskflow-review` (second pass) completed. **D4 REVISED** to public REST JIT ephemeral runners on owner decision. **D17 RESOLVED GREEN**; the per-user-App contingency is not adopted. **D18** keeps both scopes but its org mechanism becomes `generate-jitconfig`, unverified. Corrections applied across all ten design documents: the Actions-service protocol, `AcquireJobs`, `protocol_flag`, `scale_set_id`, `scale_set_name`, and three derived credentials removed; routing moved from a scale-set name to a label set; the rate-limit analysis redone because demand polling now shares the 5,000/hour REST budget, capping a host at roughly 10 targets at the 60-second default. The first task set was declared superseded. |
| 2026-08-21 | `/taskflow-tasks` (second derivation) completed against the corrected design. 23 specifications in 9 groups. `c5` deleted outright and the old `c4` replaced by `c4-demand-and-jit-gateway`; `v1-org-jit-verification` added as a new stop-the-line spike in its own group, so D18's untested organization endpoint is proven before code is built on it and without stalling group C behind a human prerequisite. Nine specifications carry forward byte-identical, twelve were revised — chiefly `b1` (routing-label derivation and `runs-on` matching replace the scale-set name; the surplus attempt becomes a first-class outcome), `e1` (no acquisition step, and the in-flight-attempt term that stops a still-queued job from starting a second runner), and `f2` (`add` creates nothing remotely, so the partial-creation failure mode is gone). Two scheduling changes recorded: `f2` moves to Wave 1 because configuration no longer touches GitHub state, and `v1` runs in Wave 1 against the throwaway App **before** it is deleted. Two design-level observations raised to the owner: an organization target's REST cost scales with its installed repository count, which the per-target budget table does not model; and `03-control-flows.md` flow 4.3 still says a 401 triggers a token "refresh" that D3 removed the means to perform. |
| 2026-08-21 | `/taskflow-execute` run started: `--parallel=6 --review=medium --scope=all --merge=on-green`, execution tier `toolkit` (pipeline 0.24.0). Owner decisions recorded at preflight: (a) worker branches are **not** pushed and **no pull requests are opened** — each verified diff is merged into local `main`, and only `main` is pushed; (b) `main` carries no branch protection and no rulesets, so `on-green` has no API-defined green and falls back to a stated local gate — review complete, every DoD item verified against the tree, and the workspace build/test/fmt/clippy gate passing locally — with CI on `main` checked after each push; (c) GO for `v1` against the surviving throwaway App and its disposable organization; (d) standing constraint from the owner — **no GitHub organization, repository, or App is ever deleted by this run or any worker**; `v1` deletes only the one ephemeral runner it creates. Preflight also added `/.claude/worktrees/` to `.gitignore`, without which host-placed worker worktrees surface as untracked paths and halt the postflight isolation check. |
| 2026-08-21 | **`v1` complete — D18 organization scope is GREEN.** `POST /orgs/{org}/actions/runners/generate-jitconfig` returns `201`, and decisively **on the narrow `organization_self_hosted_runners=write` permission with no `organization_administration`**, so the result transfers to the published App rather than only to the throwaway one. Stop-the-line was not triggered. Evidence: `docs/spikes/d18-org-jit-verification.md`, merged `e5d7d1c`. Three facts `c4`, `f2` and `b1` must build against: (1) `runner_group_id` is **mandatory** — omitting it is `422`, there is no server-side default — and an unusable group answers `403` **or** `404`, so error handling keyed on `404` alone misreports; a non-default group id other than `1` also returns `201`, so `1` is not special. (2) **No labels are added implicitly** — `runs-on: self-hosted` will not match unless `self-hosted` is requested explicitly — and labels are stored **lowercased**, so `b1`'s routing-label matching should be case-insensitive. (3) The organization ends with zero runners, re-verified read-only from a fresh token. Untested and recorded as such: no job ever ran, so this proves registration and not execution — `h1`'s live org-scoped job remains the end-to-end proof. |
| 2026-08-21 | `v1` reviewed at `--review=medium` (advisory gating — none of these blocked the merge). Verdict and evidence confirmed sound; DoD conformance met; no product code, no spec or board edit, no overreach. Eleven advisory findings, four worth acting on. **A:** the write-up commits the real device-flow `client_id` paired with the org, the account login and two installation ids, which the task's scope clause forbids literally — mitigated because that same client id and org name are already on `main` from the D17 spike, so the marginal exposure is the two installation ids. **B:** the document's own secret-hygiene section certifies the wrong artifact — it says the committed *scripts* carry the client id, but the scripts carry only a placeholder and take `-ClientId` as a parameter; the real one is in the *document*. **D:** the recorded permission set is a **1:1 match** with the published App's declared set in `07-security.md` — four for four, nothing extra — which is a materially stronger basis for human gate 2 than the "no `organization_administration`" argument the document actually makes, and it is currently left unstated. **E:** the stated-limits list omits the one condition most likely to surprise `f2` — every call was made by a user who **administers** the organization, and a user-to-server token's authority is installation permissions ∩ the user's own rights, so it is unknown whether a non-owner member on the same installation gets `201` or `403`. Also advisory: **C** Point 1's field table mixes observations from two different runners across two rounds; **F** "the Phase 0 gate is met" overstates — it closes one of five conjoined conditions; **G** the automated multi-label assertion uses `>=` on a count, so it reports GREEN precisely when GitHub would be adding implicit labels (the fact was established by human reading, not by that check); **H** round 1 has no `try`/`finally`, so a throw between create and delete would have orphaned a runner — nothing was orphaned, but the next spike inherits the shape; **I** the stop-the-line branch prints "stopping" and then continues into differential probes; **J** a quotation attributed to human gate 2 does not exist verbatim (faithful in substance); **K** the third copy of the device-flow harness dropped its evidence-write on both early-exit paths. Recorded as a positive: the spike retires D17's unconfirmed "runner groups are a paid-plan feature" hypothesis for group creation via public REST. |
| 2026-08-21 | **Human gate 2: GO.** The owner approved the published App's single permission set — Repository `Administration: Read and write`, Repository `Actions: Read`, Repository `Metadata: Read`, Organization `Self-hosted runners: Read and write` — with device flow on, token expiration opted out, no private key and no webhook, and explicitly accepted the recorded consequence: `Administration: Read and write` also permits deleting, renaming and transferring a repository and adding or removing collaborators, it is unavoidable for repository-scope JIT registration, and every future user inherits it including monitor-only ones (D21). Approved on `v1`'s evidence that organization-scope registration succeeds on the narrow organization permission alone. `c2` and everything downstream are unblocked; `c2` still waits on `b1` in the dependency graph. Separately, the owner directed that `v1`'s committed identifiers be redacted before `main` is pushed — the two installation ids and the parenthesised `client_id` (review finding A), together with the secret-hygiene paragraph that certifies the wrong artifact (finding B). `main` is held unpushed until that correction lands. |
| 2026-08-21 | `v1` correction round merged (`fec3cc3`), closing review findings A and B on owner instruction before `main` is pushed. The real device-flow `client_id` and both installation ids were removed from `docs/spikes/d18-org-jit-verification.md`, and its secret-hygiene paragraph — which certified the *scripts*, when the scripts carry only a placeholder and the real id was in the *document* — was rewritten to describe the files as they actually are. Extended to `docs/spikes/d17-user-to-server-scale-set-chain.md` for consistency. **The exposure split is the part worth recording.** The two installation ids (`155426287`, `155419555`) existed only in the unpushed D18 document: `origin/main` was still at `f95d1e2` while local `main` had advanced to `42bac00`, so those identifiers were removed before ever reaching `origin` and redaction did real protective work. The `client_id`, by contrast, is already public on `origin/main` through the D17 spike document, byte-identical to its pushed copy — removing it from `HEAD` stops it being copied forward into the next spike but does **not** un-publish it. Un-publishing would require rewriting history on a public repository *and* retiring the identifier; the cheap and reliable form of the latter is deleting the throwaway App `runner-manager-d17-spike`, which is already on the "a human must delete these" list and is the owner's action alone — this run deletes nothing. A device-flow `client_id` is public by design and is paired with no secret anywhere in the repository, so this is hygiene rather than an incident. |
| 2026-08-21 | **`a1` complete.** Six-crate virtual workspace (`app`, `domain`, `github`, `agent`, `platform`, `testkit`) plus a seventh `runner-manager-e2e` acceptance package, toolchain pinned to `1.94.0` (not a channel alias), committed `Cargo.lock` at 448 packages, the full `[workspace.dependencies]` table, 40 module skeleton files each stamped with its owning task, a three-OS CI matrix on pull request and push to `main`, and a `workflow_dispatch`-only release skeleton. Merged `b67ca43`. Verified by the orchestrator re-running the gates itself on the merged `main`, not from the worker's report: `cargo build`, `cargo test`, `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` all green; `ci.yml` carries no release, schedule or tag trigger; `release.yml` carries exactly one trigger; the `e2e` job's guard step publishes an output every later step keys on, so an absent secret makes the job succeed with steps skipped rather than fail. **Two DoD clauses remain open and are recorded as such rather than counted:** "passes in CI on all three matrix legs" — no leg has ever executed, since nothing has been pushed, and macOS and Linux have therefore never compiled (`aws-lc-rs`, bundled SQLite and `security-framework` are the specific exposures); and "a pull request against this branch shows CI as a status check", which is structurally unreachable under the owner's no-PR decision. The first closes itself when `main` is pushed, because `ci.yml` triggers on push to `main`. |
| 2026-08-21 | `a1` reviewed at `--review=medium` (advisory). The reviewer read all 22 downstream task specifications against the dependency table and the module skeleton — the right test, since `a1`'s whole purpose is that no later task edits a manifest. Module skeleton: **clean**, all 40 files present with correct owner stamps, collision risk genuinely closed. Dependency table: **four gaps that would each force a later task to edit a manifest**, dispatched immediately as an A-group correction round rather than left to be discovered mid-wave. **F1** `reqwest` lacks `stream`, so `e2` could not stream a 150-300 MB runner package and would have to buffer it in RAM, with no partial file to remove on checksum mismatch. **F2** `reqwest` lacks `query`, which `c3` and `c4` both need for pagination — two group-C tasks that would have edited one manifest. **F3** the `windows` crate lacks `Win32_System_Threading` (`GetProcessTimes`, which `d1`'s recycled-PID discriminator and `e3`'s restart recovery both need), `Win32_Security_Authorization` (`SetNamedSecurityInfoW`, which `d2`'s ACL assertion needs) and `Win32_Storage_FileSystem`. **F4** no `libc` or `sysinfo` is declared at all, so `d1`'s process identity has no macOS or Linux implementation. **F5** `secrecy` is absent from `crates/agent` and `crates/app`, the two crates that handle the JIT blob and the token. Also dispatched: **F6**, the e2e job's three inputs cannot create demand — the published App's permission set has Actions *read* and no Contents grant, so it can neither commit a fixture workflow nor dispatch a run, leaving seven of `h1`'s eight scenarios unreachable and `h1` contractually unable to add a fourth input; **F7** the hardcoded hosted runner labels make `h1` scenario 5 (recovery after a real reboot) structurally impossible; **F8** three e2e legs share one disposable repo with no serialisation; **F9/F10** three of the workflow tests are whole-file substring searches that assert nothing (`"opened"` is a substring of `"reopened"`; the `branches: [main]` check passes even if it sits under `pull_request`), and the strict trigger equality would red on `a2`'s natural `workflow_call` implementation. Deliberately **not** actioned: F11 (guard step → guard job, cosmetic), SHA-pinning the two first-party actions (a separate hardening decision, not required by `07-security.md`), and the cache-key strategy. The reviewer endorsed all eight of the implementer's flagged judgment calls, including the DoD-versus-Scope conflict over the workspace root package name, which it resolved in favour of Scope's virtual manifest. Supply chain is clean: two actions, both first-party, no third-party action anywhere. |
| 2026-08-21 | Round 2 dispatched: `b1-domain-core`, and an A-group correction round on `a1` closing findings F1-F10. `d1` and `a2` were **ready and deliberately withheld for one round** — `d1` because F3 and F4 are precisely the dependencies it needs and dispatching it against the gap would waste the worker, `a2` because a group is one conflict domain and the A-group correction holds that slot. Both dispatch as soon as the correction merges. |
| 2026-08-21 | **First CI execution: green on all three legs.** `main` pushed (`1aea47a`); run `32486727519` concluded `success` with `check (windows-x86_64)`, `check (linux-x86_64)` and `check (macos-arm64)` all passing. This closes the `a1` DoD clause "passes in CI on all three matrix legs", which no local run could answer — macOS and Linux had never compiled, and `aws-lc-rs`, bundled SQLite and `security-framework` were the named exposures. All three built clean. The `e2e` job also concluded `success` **with its work skipped**: the guard step ran, published `enabled=false` because no secret is configured, and the five following steps each report `skipped` while the job reports success. That verifies the DoD clause "the `e2e` job skips — not fails — when its secret is unset" as observed behaviour rather than as read YAML. The only `a1` clause still open is "a pull request against this branch shows CI as a status check", which is structurally unreachable while the owner's no-PR decision stands; CI is instead proven on the push-to-`main` trigger. |
