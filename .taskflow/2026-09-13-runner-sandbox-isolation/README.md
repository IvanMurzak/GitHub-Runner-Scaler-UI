# Label-routed runner profile isolation

**Status:** adversarially reviewed 2026-09-13; decisions locked and no open
finding remains before task derivation. No product code has been changed.

## Problem

Runner Manager currently gives each ephemeral attempt a unique directory, but
starts GitHub's `Runner.Listener` as a normal child of the host. A workflow can
therefore observe or mutate host-level toolchains, package databases, processes,
registry/configuration and network state. Two jobs that request incompatible
Python or system dependency versions can influence each other even though their
workspace directories are different.

The requested behavior is multiple named runner profiles under one repository.
Each profile owns routing labels, capacity, workspace and execution settings. A
job selects a profile through `runs-on`; native and isolated jobs may therefore
coexist in the same workflow and use the same local action.

## Decisions

| ID | Decision | Status |
|---|---|---|
| D1 | **REVISED:** isolation is configured per named runner profile under a repository. One repository may have native and isolated profiles selected by labels. An isolated profile never falls back to a native process. | Revised and locked 2026-09-13 from owner clarification. |
| D2 | The first use case is dependency and toolchain reproducibility, including installing a repository-specific Python and system packages without mutating the host. | Locked 2026-09-13 from owner scenario. |
| D3 | “Isolated” preserves the profile host OS: Windows remains Windows, macOS remains macOS, and Linux/WSL remains Linux. | Locked 2026-09-13 as the compatibility-preserving interpretation. |
| D4 | Use one provider contract and platform-specific backends; ship by native acceptance gate rather than pretending simultaneous backend maturity. | Locked 2026-09-13. |
| D5 | V1 isolated profiles require ephemeral workspaces and refuse arbitrary host mounts. | Locked 2026-09-13 as the safe initial contract. |
| D6 | V1 guarantees dependency/environment isolation for trusted workflows, not containment of actively hostile code. The UI and docs must state that boundary. | Locked 2026-09-13 from the original dependency-conflict use case and the recommended V1 strategy accepted by continuation to implementation. |
| D7 | Every autoscaling profile has a unique immutable routing selector. Demand matches only when `runs-on` explicitly contains it, so optional-label overlap cannot make two profiles claim one job. | Locked 2026-09-13 from owner clarification. |
| D8 | Profile creation, routing, execution backend/image/resources, capacity, workspace and diagnostics have full CLI and TUI control. | Locked 2026-09-13 from owner request. |
| D9 | Implementation follows Taskflow review/tasks, uses four parallel agents, an isolation branch, and Merge on Green. | Locked 2026-09-13 from owner request. |

## Recommendation

Adopt the provider architecture now, but stage support rather than presenting
four unequal mechanisms as one finished guarantee:

1. Introduce `repository -> runner profiles`; reuse the existing one-poll-per-target reconciliation grouping.
2. Linux and managed WSL: rootless OCI containers, with a pinned image digest,
   ephemeral writable layer and no host runtime socket mount.
3. Windows: spike Hyper-V-isolated Windows containers against the supported
   client/server editions and representative workflows; retain a full Hyper-V
   VM backend as the compatibility/security fallback.
4. macOS: spike disposable macOS VMs through Apple's Virtualization framework.
   There is no native macOS-container equivalent.
5. Expose a backend only after native lifecycle/recovery/cleanup acceptance
   passes. Until then, `required` isolation is visibly unavailable on that host.

This makes all four environments achievable behind one product model, but it is
not a small feature. Linux/WSL is a practical first release. Native Windows and
especially native macOS should be treated as separate platform projects with
image lifecycle, privileges, licensing and hardware prerequisites.

## Documents

- `01-current-architecture.md` — verified current launch, persistence and WSL seams.
- `02-target-architecture.md` — provider contract, lifecycle and data model.
- `03-platform-strategy.md` — backend matrix, feasibility and staged delivery.
- `04-security-recovery.md` — threat boundary, secrets, cleanup and crash recovery.
- `05-routing-profiles.md` — multi-profile labels, CLI compatibility and TUI control.
- `06-review-findings.md` — adversarial review findings and corrections.
- `ROADMAP.md` — decision gates, waves and the future execution ledger.
