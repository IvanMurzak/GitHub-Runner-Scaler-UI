# Local Runner Manager

**Status:** Tasks specified 2026-08-21 (`/taskflow-tasks`); ready for
`/taskflow-execute`. 23 immutable specifications in `tasks/`; waves, human
gates, and live state are in `ROADMAP.md`.
**Design status:** Reviewed 2026-08-21 (`/taskflow-review`)
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
| D1 | The product is a separate public repository with no code, runtime, credential, or deployment dependency on `ai-pipeline`. | Locked 2026-08-21 | Satisfied: `IvanMurzak/GitHub-Runner-Scaler-UI` exists (public, MIT). `HEAD` carries `LICENSE`, `.gitignore`, this taskflow, and the D17 spike record under `docs/spikes/`. Implementation begins from an empty Rust workspace. |
| D2 | One host-local agent instance manages only the runners it creates on that host. | Locked 2026-08-21 | Windows, macOS, and Linux hosts have independent capacity and ownership boundaries. |
| D3 | Authentication is the OAuth 2.0 **device flow** against one GitHub App that the project publishes. The user never creates a GitHub App, never picks permissions, and never handles a private key file. | REVISED 2026-08-21 (was "v1 authenticates only through a GitHub App" created by each user) | Onboarding is three actions. The project registers the App once, enables device flow, and opts **out** of user-token expiration so that no client secret and therefore no server is ever needed; `client_id` is public by design and ships in the binary. The project never generates a private key for the App. Consequences and the trust cost are in `07-security.md`. |
| D4 | v1 autoscaling uses **public REST JIT ephemeral runners**. Runner scale sets and the Actions-service protocol are rejected. | REVISED 2026-08-21 (was "Runner Scale Sets and JIT ephemeral runners") | Disproved by the D17 spike, `docs/spikes/d17-user-to-server-scale-set-chain.md`. Scale-set creation returns `403 needs Administer Permissions` on every target reachable from a free plan — personal repository and free organization, with both a `ghu_` and a `gho_` credential — while `POST /repos/{owner}/{repo}/actions/runners/generate-jitconfig` returns `201` on the same account, the same `Administration: write` permission, and the same runner group. Registering a runner into a group is permitted; administering the group is not. A runner still performs one job and is removed. **Accepted costs:** no `AcquireJobs`, so two hosts can start a runner for the same queued job; and demand polling now consumes the same 5,000 requests/hour budget as inventory, which lowers the number of targets one host can serve. |
| D5 | The binary supports `daemon run` and optional OS-service installation. | Locked 2026-08-21 | Operators can run interactively or make the local controller survive reboots. |
| D6 | Rust single binary with Ratatui/Crossterm and direct HTTPS clients. | Locked 2026-08-21 | Small deployable surface and native cross-platform TUI. After D4 every GitHub call is documented, stable REST, so no public-preview protocol adapter or revision pinning is needed. |
| D7 | Default `min_capacity=0`; every policy requires explicit `max_capacity`. | Locked 2026-08-21 | Eliminates idle runners and prevents accidental host oversubscription; cold starts are accepted by default. |
| D8 | The TUI is local and never a remote controller. | Locked 2026-08-21 | Fits D2 and avoids a second authentication/network surface. |
| D9 | Capacity is limited at two independent levels: per scale policy (`max_capacity`) and per host (`host_capacity`). Both are settable from the CLI and are visible and editable in TUI settings, showing their current values. | Locked 2026-08-21 | Owner requirement 2026-08-21. Adds `Host.host_capacity`, `host set-capacity`, `repo set-capacity`, and a host settings screen. |
| D10 | CI runs the full test suite on pull-request open/update and on merge to `main`. Releases are produced only by a manually dispatched workflow that takes the version as an argument, rejects a malformed or non-increasing version, runs all tests, then builds and publishes artifacts. | Locked 2026-08-21 | Owner requirement 2026-08-21. No automatic release trigger of any kind exists. |
| D11 | v1 distribution channels are a hosted install script (`curl \| sh`, `irm \| iex`), an npm wrapper package, a Homebrew tap, `cargo install`, and the GitHub Releases archives all of them consume. | REVISED 2026-08-21 (Scoop removed) | Owner decision 2026-08-21. Neither `winget` nor Scoop is a product channel: npm and the install script both cover Windows, and every extra channel is a manifest to keep in sync on each release. On Windows without Node, `irm \| iex` is the path. |
| D12 | v1 ships no paid code signing. SHA-256 checksums and an SBOM are mandatory; the free ad-hoc signature required for arm64 macOS execution is mandatory. | REVISED 2026-08-21 (was "signed release artifacts", `07-security.md`) | Terminal installers set no quarantine or Mark-of-the-Web attribute, so package-manager installs face no Gatekeeper or SmartScreen prompt. Paid certificates are reconsidered at GA. |
| D13 | The installed service starts at machine boot, and the GitHub App private key is therefore stored machine-scoped rather than in the operator's user keychain. | REVISED 2026-08-21 (was "OS keychain/credential vault", `05-infrastructure.md`) | Owner requires unattended start after reboot. A boot-time service cannot read a per-user keychain on any supported OS. Local administrator/root can read the key; `07-security.md` records the accepted trade-off. |
| D14 | The repository `README.md` offers only copy-paste install commands. There are no direct-download buttons. | REVISED 2026-08-21 (was "animated SVG download buttons") | Every documented install path runs through a terminal, which sets neither `com.apple.quarantine` nor Mark-of-the-Web, so no user meets a Gatekeeper block or SmartScreen warning on any supported OS. Release archives are still published; they are simply not the advertised path. |
| D15 | GitHub App Manifest onboarding. | WITHDRAWN 2026-08-21, superseded by D3 | The manifest solved the cost of each user creating an App. D3 removes that step entirely, so the manifest, its temporary loopback listener, and the narrowing of the "no inbound surface" rule are all unnecessary. |
| D16 | The product offers exactly one authentication path. Reusing an existing GitHub CLI (`gh`) credential is explicitly rejected for v1. | Locked 2026-08-21 | Owner decision 2026-08-21. It would save two actions but add a second authentication path with different scope semantics (`gh` carries a broad `repo` scope), its own tests, and its own threat row. Revisitable without redesign. |
| D18 | Autoscaling is supported at **both** repository and organization scope. | REVISED 2026-08-21 (mechanism only; scope decision unchanged) | Owner decision 2026-08-21. Adds an `org` command family, makes the policy target a sum type, and requires the published App to declare organization permissions alongside repository ones. Organization scope uses the narrower `Organization → Self-hosted runners: Read and write`. After D4, the org mechanism is `POST /orgs/{org}/actions/runners/generate-jitconfig`; **untested** — the spike could not reach it because the available credential lacked `admin:org`. |
| D19 | A policy may be **monitor-only**: `repo add`/`org add` without `--max-capacity` creates a policy that shows runners and workflow counts and never starts a runner. | Locked 2026-08-21 | Owner decision 2026-08-21; matches the repository description, which presents autoscaling as optional. **Consequence:** a GitHub App declares one permission set for every installation, so a monitor-only user still grants `Administration: Read and write`. Least privilege for monitor-only would require a second published App; see the open question in `02-target-architecture.md`. |
| D20 | `repo add`/`org add` create a policy in `pending` and never enable scaling; enabling is an explicit `set-scale`. | Locked 2026-08-21 | Owner confirmed 2026-08-21. Creating a policy never arms a host, at the cost of one extra command in Journey 1. |
| D21 | The project publishes exactly **one** GitHub App. A second, read-only App for monitor-only users is rejected. | Locked 2026-08-21 | Owner decision 2026-08-21, resolving the open question in `02-target-architecture.md`. **Accepted consequence:** because an App grants its whole declared permission set per installation, a monitor-only user (D19) also grants `Administration: Read and write`, which permits deleting, renaming, and transferring the repository. This must be disclosed in the README and by the CLI at install time, not left to GitHub's consent screen. Narrowing it later would force every installation to re-consent. |
| D17 | Before any other authentication work, a spike proves that a user-to-server token drives the GitHub credential chain. | **RESOLVED GREEN 2026-08-21** | Executed; result in `docs/spikes/d17-user-to-server-scale-set-chain.md`. A `ghu_` token minted a runner registration token and completed the Actions-service admin exchange at **both** repository and organization scope, with the same scopes and a 20-minute admin-token TTL as a `gho_` credential. D3 is confirmed and the per-user-App contingency in `07-security.md` is not needed. The same run disproved D4, which is a separate result. |

## Summary

`runner-manager` is one Rust binary with three modes: interactive TUI, normal
CLI commands, and a long-running local agent. It uses GitHub HTTPS REST for
everything — inventory, demand, and JIT provisioning — with no hosted backend,
no Kubernetes, and no Actions-service protocol (D4). A scale policy enables
scaling for a particular host; the host agent reports a strict physical
capacity, polls for queued jobs matching the policy's routing labels, obtains a
JIT configuration from the public REST endpoint, starts an isolated runner
child process, and removes that runtime after one job.

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
| `09-release-distribution.md` | CI, manual release workflow, install script, and distribution channels. |
| `ROADMAP.md` | This taskflow's implementation ledger: waves, human gates, and the task status board. |
| `tasks/` | 23 immutable task specifications, grouped by merge-conflict domain. |

## Glossary

| Term | Meaning |
|---|---|
| Host agent | The local `daemon run` process that owns one machine's runner lifecycle. |
| Routing labels | The label set a JIT runner is registered with. A workflow targets them with `runs-on`. After D4 this replaces the scale-set name as the routing token, and unlike a scale set it may carry more than one label. |
| JIT runner | A runner configured just in time with a short-lived encoded configuration issued by `POST …/actions/runners/generate-jitconfig` at repository or organization scope. |
| Ephemeral runner | A runner that executes one job and then deregisters. |
| Scale policy | Local configuration binding one target — a repository or an organization (D18) — to one host. In `autoscale` mode it owns routing labels and a `max_capacity`; in `monitor_only` mode it owns neither (D19). |
| Host identity | Operator-chosen stable host label (`--host-label`), persisted as `Host.display_name` and used as the host component of the generated routing label. |
| Host capacity | `Host.host_capacity`: the ceiling on concurrent runners across every policy on this machine. |
| Actions service | The `_apis/runtime/runnerscalesets` tenant protocol. **Not used** (D4); retained here only so the term is recognisable in the spike record. |
| Device flow | OAuth 2.0 Device Authorization Grant. The user enters a short code at `github.com/login/device`; the tool polls for the resulting token. Needs only a public `client_id`, no redirect and no client secret. |
| Published App | The single GitHub App registered once by this project and installed by users on their own repositories. Distinct from a per-user App, which this product does not ask anyone to create. |
| User access token | The user-to-server token the device flow returns. It is the only GitHub credential this product stores. |
