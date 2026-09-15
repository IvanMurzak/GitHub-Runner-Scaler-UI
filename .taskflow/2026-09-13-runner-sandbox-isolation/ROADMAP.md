# Runner sandbox isolation ledger

**Design status:** reviewed 2026-09-13; no open finding or owner decision.
**Task status:** derived 2026-09-13.
**Implementation status:** a1 and a2 merged into the integration ref; b1
is dispatched.
**Repository:** `.` / `main`.
**Last updated:** 2026-09-15.

This file is the only live task-state record.

## Locked decision gates

- **DG1 Threat model:** dependency isolation for trusted workflows; no hostile-code claim.
- **DG2 OS identity:** preserve Windows/macOS/Linux semantics and labels.
- **DG3 Persistence:** V1 refuses persistent workspaces and arbitrary host mounts.
- **DG4 Rollout:** native gates may graduate independently.
- **DG5 Runtime ownership:** integrate operator-installed runtimes/images and report prerequisites.
- **DG6 Profiles:** labels select named native or isolated profiles under one repository.
- **DG7 UX:** CLI and TUI expose full profile/provider control and diagnostics.

## Acceptance gates

- **G1 Migration:** existing policies become native `default` profiles and recover unchanged.
- **G2 Routing:** one repository runs native and isolated profiles concurrently; a job matches at most one.
- **G3 Fail closed:** isolated profiles never start natively after provider failure.
- **G4 Environment:** dependencies and residue cannot cross isolated attempts or mutate the host.
- **G5 Secrets:** JIT/credentials are absent from provider metadata, config, disks, logs and arguments.
- **G6 Recovery:** crash/reboot adoption and cleanup preserve ownership and capacity.
- **G7 Linux:** rootless OCI acceptance passes natively.
- **G8 WSL:** the contract passes inside managed WSL without DrvFS runtime state.
- **G9 Windows:** native Windows acceptance passes on every declared edition/version.
- **G10 macOS:** native VM acceptance passes on every declared architecture/version.
- **G11 UX:** CLI/TUI control every profile field and cannot mutate a sibling profile.
- **G12 Actions compatibility:** action classes report precise supported/refused capability.

## Execution waves

| Wave | Theme | Gates |
|---|---|---|
| 1 | Profile domain/store, execution domain/native provider | G1, G3 |
| 2 | Routing, isolated lifecycle, CLI | G2-G6, G11 |
| 3 | TUI plus Linux/WSL, Windows and macOS providers in parallel | G7-G11 |
| 4 | Integrated native acceptance and documentation | all gates |

## Board

| id | Task (spec) | group | seq | needs | repo | base_branch | imp/cx | model | Status | Run / PR | Updated |
|---|---|---:|---:|---|---|---|---|---|---|---|---|
| a1-profile-domain-store | `tasks/a1-profile-domain-store.md` | A | 1 | — | . | main | 9/8 | top | ✅ | [PR #70](https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/pull/70) / a157f3c | 2026-09-15 |
| a2-routing-reconcile | `tasks/a2-routing-reconcile.md` | A | 2 | a1-profile-domain-store | . | main | 9/7 | top | ✅ | [PR #71](https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/pull/71) / 95901da | 2026-09-15 |
| b1-execution-domain-provider | `tasks/b1-execution-domain-provider.md` | B | 1 | a1-profile-domain-store | . | main | 10/9 | top | 🔵 | worktree-b1-execution-domain-provider / implement-task | 2026-09-15 |
| b2-isolated-lifecycle | `tasks/b2-isolated-lifecycle.md` | B | 2 | b1-execution-domain-provider, a2-routing-reconcile | . | main | 10/10 | top | pending | — | 2026-09-13 |
| c1-profile-cli | `tasks/c1-profile-cli.md` | C | 1 | a2-routing-reconcile, b1-execution-domain-provider | . | main | 8/7 | top | pending | — | 2026-09-13 |
| c2-profile-tui | `tasks/c2-profile-tui.md` | C | 2 | c1-profile-cli | . | main | 8/8 | top | pending | — | 2026-09-13 |
| d1-linux-wsl-oci | `tasks/d1-linux-wsl-oci.md` | D | 1 | b2-isolated-lifecycle | . | main | 10/10 | top | pending | — | 2026-09-13 |
| d2-windows-hyperv | `tasks/d2-windows-hyperv.md` | E | 1 | b2-isolated-lifecycle | . | main | 9/10 | top | pending | — | 2026-09-13 |
| d3-macos-vm | `tasks/d3-macos-vm.md` | F | 1 | b2-isolated-lifecycle | . | main | 9/10 | top | pending | — | 2026-09-13 |
| g1-acceptance-docs | `tasks/g1-acceptance-docs.md` | G | 1 | c2-profile-tui, d1-linux-wsl-oci, d2-windows-hyperv, d3-macos-vm | . | main | 10/9 | top | pending | — | 2026-09-13 |

## Integration landing

| repo | base_branch | integration_ref | Final PR | Status | Updated |
|---|---|---|---|---|---|
| . | main | runner-sandbox-isolation | — | 🔵 | 2026-09-15 |

## Progress log

**2026-09-13 — planned.** Repository inspection confirmed that disposable
attempts currently isolate directory lifetime but launch `Runner.Listener`
directly as a native child. WSL is a separately managed Linux host, so it can
reuse a guest-local Linux provider. Official platform documentation confirmed
that native support requires different backends: OCI for Linux/WSL,
Hyper-V-isolated Windows containers or VMs for Windows, and macOS VMs through
Virtualization.framework. No product code, database, runtime, runner, policy or
external system was changed.

**2026-09-13 — revised.** Owner required multiple configurations for one
repository, selected per job by labels, plus complete CLI/TUI control. The plan
now uses named profiles with immutable selectors. Reconciliation already groups
multiple policies per target; CLI target uniqueness and first-match mutation are
the main current blockers. D1 was revised and D6-D9 were locked. No product code
or external state was changed.

**2026-09-13 — reviewed.** No P0 finding. P1 corrections made selectors derived
and non-overridable, scoped mutation fences to `PolicyId`, documented static
`runs-on` requirements, added provider diagnostics visibility and changed
four-platform certainty to feasibility-gated support. P2 wording and ROADMAP
state were aligned. No product decision changed.

**2026-09-13 — tasks derived.** Ten immutable PR-sized specs cover profile
identity/routing, execution journalling/lifecycle, complete CLI/TUI, three native
provider tracks and integrated acceptance. Groups and dependencies permit the
platform tracks to overlap after the common provider lifecycle lands. Execution
branch is `isolation/runner-sandbox-profiles`; Merge on Green is required.

**2026-09-13 — execution preflight stopped before dispatch.** The installed
Taskflow Execute contract requires the registered custom agent named
`taskflow-implementer` and forbids substituting a generic agent. This Codex
session's spawn interface exposes task name/model/effort but no custom-agent
selector, so it cannot request that registered agent. Per the skill, every row
remains pending/ready and no integration ref, worktree, worker, PR, merge or
product change was created. Resume with `--scope=all --parallel=4
--merge=on-green --integration-branch=isolation/runner-sandbox-profiles` in a
session whose spawn interface supports registered custom agents.

**2026-09-15 — execution resumed.** Owner selected the `implement-task`
pipeline for every implementation, native Codex subagents in dedicated git
worktrees, task PRs into `runner-sandbox-isolation`, and merge on green. The
integration ref was created from `main`, pushed, and verified remotely. Its
pipeline landing step was configured to leave green task PRs open for Taskflow
verification and merge. The a1 slot was provisioned from the verified
integration ref; no product code has been merged yet.

**2026-09-15 — a1 integrated.** `implement-task` completed review,
simplification and landing as task PR #70. A migration coverage finding was
fixed at the same PR head; the raw v3 upgrade test compares all legacy policy,
host and attempt fields. The exact local gate and seven CI/E2E checks passed
at head 76846bf. PR #70 was squash-merged into `runner-sandbox-isolation` at
a157f3c and the remote ref was verified. a2 and b1 are now dependency-ready.

**2026-09-15 — a2 dispatched.** The a2 task slot was provisioned from the
verified remote integration ref and its PR base recorded as
`runner-sandbox-isolation`. The pipeline's manager and fresh executor require
the available native agent slots while a task runs, so b1 is held ready for
the next dispatch.

**2026-09-15 — a2 integrated.** The native Codex session-loop variant of
`implement-task` completed implementation, independent review,
simplification, and landing. Task PR #71 passed the exact local gate and seven
CI/E2E checks at head 7b17625. The scheduler verified routing refusals,
shared-target accounting, remedies, and capacity evidence, then squash-merged
it into `runner-sandbox-isolation` at 95901da. b1 is the next ready task.

**2026-09-15 — b1 dispatched.** The b1 task slot was provisioned from the
verified remote integration ref and its branch-scoped PR base was read back as
`runner-sandbox-isolation`. The Codex session-loop `implement-task` pipeline
will run all implementation, review, simplification, and landing steps in an
isolated run worktree.
