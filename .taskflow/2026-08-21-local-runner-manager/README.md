# Local Runner Manager

**Status:** Reviewed 2026-08-21 (`/taskflow-review`); ready for `/taskflow-tasks`
**Scope:** This repository — `IvanMurzak/GitHub-Runner-Scaler-UI` (public, MIT).
The taskflow was drafted in the separate `IvanMurzak/ai-pipeline` repository and
transferred here. It proposes no change to `ai-pipeline`, and implementation
executes in this repository.

## Problem

Home and small-team hosts need GitHub Actions capacity without keeping many
persistent runners registered and idle. The product is a local-first,
cross-platform terminal application that configures repository-specific
autoscaling, starts host-local JIT ephemeral runners only when jobs need them,
and presents an accessible Ratatui dashboard plus scriptable CLI.

## Locked decisions

This table is the sole decision ledger. `02-target-architecture.md` restates
D1-D8 with rationale but never carries decision status.

| ID | Decision | Status | Consequence |
|---|---|---|---|
| D1 | The product is a separate public repository with no code, runtime, credential, or deployment dependency on `ai-pipeline`. | Locked 2026-08-21 | Satisfied: `IvanMurzak/GitHub-Runner-Scaler-UI` exists (public, MIT, `LICENSE` only at `HEAD`). Implementation begins here from an empty Rust workspace. |
| D2 | One host-local agent instance manages only the runners it creates on that host. | Locked 2026-08-21 | Windows, macOS, and Linux hosts have independent capacity and ownership boundaries. |
| D3 | v1 authenticates only through a GitHub App. | Locked 2026-08-21 | No PAT, device flow, or cloud control plane is included. Repository-scoped scale sets require `Administration: Read and write`; see `07-security.md`. |
| D4 | v1 autoscaling uses GitHub Runner Scale Sets and JIT ephemeral runners. | Locked 2026-08-21 | A runner performs one job and is removed; persistent runner start/stop is not a v1 path. Scale-set JIT configuration comes from the Actions service, not the public REST JIT endpoint. |
| D5 | The binary supports `daemon run` and optional OS-service installation. | Locked 2026-08-21 | Operators can run interactively or make the local controller survive reboots. |
| D6 | Rust single binary with Ratatui/Crossterm and direct HTTPS clients. | Locked 2026-08-21 | Small deployable surface and native cross-platform TUI; public-preview scale-set protocol needs adapter contract tests. |
| D7 | Default `min_capacity=0`; every policy requires explicit `max_capacity`. | Locked 2026-08-21 | Eliminates idle runners and prevents accidental host oversubscription; cold starts are accepted by default. |
| D8 | The TUI is local and never a remote controller. | Locked 2026-08-21 | Fits D2 and avoids a second authentication/network surface. |
| D9 | Capacity is limited at two independent levels: per repository policy (`max_capacity`) and per host (`host_capacity`). Both are settable from the CLI and are visible and editable in TUI settings, showing their current values. | Locked 2026-08-21 | Owner requirement 2026-08-21. Adds `Host.host_capacity`, `host set-capacity`, `repo set-capacity`, and a host settings screen. |
| D10 | CI runs the full test suite on pull-request open/update and on merge to `main`. Releases are produced only by a manually dispatched workflow that takes the version as an argument, rejects a malformed or non-increasing version, runs all tests, then builds and publishes artifacts. | Locked 2026-08-21 | Owner requirement 2026-08-21. No automatic release trigger of any kind exists. |
| D11 | v1 distribution channels are GitHub Releases archives, an npm wrapper package, a Homebrew tap, a Scoop bucket, and `cargo install`. | Locked 2026-08-21 | Owner decision 2026-08-21. `winget` is excluded from the product entirely: npm covers Windows, and `microsoft/winget-pkgs` moderation would add an external release blocker. |
| D12 | v1 ships no paid code signing. SHA-256 checksums and an SBOM are mandatory; the free ad-hoc signature required for arm64 macOS execution is mandatory. | REVISED 2026-08-21 (was "signed release artifacts", `07-security.md`) | Terminal installers set no quarantine or Mark-of-the-Web attribute, so package-manager installs face no Gatekeeper or SmartScreen prompt. Paid certificates are reconsidered at GA. |
| D13 | The installed service starts at machine boot, and the GitHub App private key is therefore stored machine-scoped rather than in the operator's user keychain. | REVISED 2026-08-21 (was "OS keychain/credential vault", `05-infrastructure.md`) | Owner requires unattended start after reboot. A boot-time service cannot read a per-user keychain on any supported OS. Local administrator/root can read the key; `07-security.md` records the accepted trade-off. |
| D14 | The repository `README.md` leads with copy-paste install commands and presents animated SVG download buttons below them. | Locked 2026-08-21 | Buttons must be fully legible and clickable without animation, because GitHub does not reliably animate README SVGs in every browser. |

## Summary

`runner-manager` is one Rust binary with three modes: interactive TUI, normal
CLI commands, and a long-running local agent. It uses GitHub HTTPS REST for
inventory and the Actions service scale-set protocol for demand and JIT
provisioning, not a hosted backend or Kubernetes. A repository policy enables
scaling for a particular host; the host agent reports a strict physical
capacity, receives demand, acquires assigned jobs, obtains a scale-set JIT
configuration, starts an isolated runner child process, and removes that
runtime after one job.

The TUI displays all authorized runners, selected repositories with their
in-progress workflow counts, aggregate activity, health, and both capacity
limits. Keyboard and mouse are first-class controls. CLI configuration is
primary: TUI settings reuse the same domain commands and never create a second
policy path.

## Document map

| File | Purpose |
|---|---|
| `01-current-architecture.md` | Evidence boundary, external platform facts, and planned seams. |
| `02-target-architecture.md` | Product architecture, roles, and implementation decisions. |
| `03-control-flows.md` | End-to-end normal, failure, expiry, and offline flows. |
| `04-subsystem-contracts.md` | Models, REST boundaries, precedence rules, and test strategy. |
| `05-infrastructure.md` | Local deployment, service installation, secrets, and rollback. |
| `06-migration-rollout.md` | Adoption phases, gates, legacy disposition, and rollback. |
| `07-security.md` | Credentials, threats, controls, and release gates. |
| `08-user-workflows.md` | Operator journeys and measurable TUI/CLI UX budgets. |
| `09-release-distribution.md` | CI, manual release workflow, distribution channels, and README download buttons. |
| `ROADMAP.md` | This taskflow's implementation ledger. |

## Glossary

| Term | Meaning |
|---|---|
| Host agent | The local `daemon run` process that owns one machine's runner lifecycle. |
| Scale set | GitHub-side demand-routing group. Its **name** is the routing token a workflow targets with `runs-on`. |
| JIT runner | A runner configured just in time with a short-lived encoded configuration issued by the Actions service. |
| Ephemeral runner | A runner that executes one job and then deregisters. |
| Repository policy | Local configuration binding one authorized repository to one host's scale set and its `max_capacity`. |
| Host identity | Operator-chosen stable host label (`--host-label`), persisted as `Host.display_name` and used as the host component of the generated scale-set name. |
| Host capacity | `Host.host_capacity`: the ceiling on concurrent runners across every policy on this machine. |
| Actions service | The `_apis/runtime/runnerscalesets` tenant endpoint that serves scale-set demand, job acquisition, and JIT configuration. It is not `api.github.com`. |
