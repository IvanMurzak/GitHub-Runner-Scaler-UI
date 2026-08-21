# Target architecture

## Principles

1. **Local first:** no hosted backend, inbound port, remote command listener,
   or cross-host control plane.
2. **One host owns its runners:** an agent can display authorized global data
   but can create, stop, or remove only runtimes tagged with its host identity.
3. **Scale to physical truth:** capacity is owner-configured at two levels —
   per policy and per host — not inferred from the number of archived runner
   directories.
4. **Ephemeral by default:** every workload runner has one job, one workspace,
   and one cleanup path.
5. **CLI is the source of configuration truth:** TUI settings dispatch the
   same commands and validations as noninteractive commands.
6. **HTTPS only, two protocols:** typed GitHub REST over `api.github.com` for
   inventory, and the Actions service scale-set protocol for demand, job
   acquisition, and JIT configuration. Neither GraphQL, Kubernetes, nor a
   separate server is required.

## Components

```text
+---------------------+   HTTPS REST (api.github.com): inventory, counts
| runner-manager      |------------------------------------------------+
|                     |                                                |
| CLI + Ratatui TUI   |   HTTPS (Actions service): scale sets, long     |
| Domain + SQLite     |   poll, AcquireJobs, JIT config                 v
| Host Agent          |------------------------------------------> GitHub Actions
| GitHub App gateway  |<-----------------------------------------------+
| Platform adapter    |
+----------+----------+
           |
           | spawn isolated local child process
           v
  JIT ephemeral runner -> one workflow job -> deregister -> cleanup
```

The single binary has these commands. This list is exhaustive.

```text
runner-manager auth login
runner-manager auth status
runner-manager auth logout
runner-manager host set-capacity N
runner-manager host show
runner-manager repo add OWNER/REPO --host-label HOST [--max-capacity N]
runner-manager repo list
runner-manager repo set-capacity OWNER/REPO --max-capacity N
runner-manager repo set-scale OWNER/REPO --enabled true
runner-manager repo remove OWNER/REPO [--purge]
runner-manager org add ORG --host-label HOST [--max-capacity N]
runner-manager org list
runner-manager org set-capacity ORG --max-capacity N
runner-manager org set-scale ORG --enabled true
runner-manager org remove ORG [--purge]
runner-manager daemon run
runner-manager service install [--start-at boot|login] | uninstall | status
runner-manager tui
runner-manager status --json
```

`repo add` is the primary, automation-safe configuration workflow. `tui` is
an optional view and editing surface, not a required background process.

`repo add` and `org add` create the policy in the `pending` state and never
enable scaling; the operator enables it explicitly with `set-scale` (D20). This
keeps policy creation non-arming, at the cost of one extra command in Journey 1.

Omitting `--max-capacity` creates a **monitor-only** policy (D19): the target
appears in the dashboard with its runners and in-progress workflow counts, no
scale set is created, and the agent never starts a runner for it. Supplying
`--max-capacity` later with `set-capacity` promotes it to `autoscale`.

## Workspace shape

```text
<repo root>/
  Cargo.toml         # virtual workspace manifest
  Cargo.lock         # committed
  rust-toolchain.toml
  .github/workflows/ # ci.yml and release.yml (see 09-release-distribution.md)
  install/           # install.sh and install.ps1, published per release
  crates/app/        # clap commands, Ratatui shell, presentation state; [[bin]] runner-manager
  crates/domain/     # policy and lifecycle state machine
  crates/github/     # device flow, user token, REST + Actions-service adapters
  crates/agent/      # scale-set reconciliation and JIT lifecycle
  crates/platform/   # process, filesystem, machine-scoped secret store, service, OS adapters
  crates/testkit/    # fake clock, fake GitHub gateway, fixture builders
```

`crates/` sits at the repository root; there is no nested product directory.

The implementation language is Rust. Ratatui plus Crossterm provides the TUI;
Tokio drives async I/O; Reqwest performs HTTPS; SQLite stores non-secret local
configuration and lifecycle journal. Exact dependency versions are selected in
implementation, pinned with `Cargo.lock` and `rust-toolchain.toml`, and
reviewed. Crate compatibility was verified at review time (Ratatui 0.30 keeps
Crossterm as its default backend and re-exports it).

## Runtime roles

| Role | Runs where | May do | Must not do |
|---|---|---|---|
| TUI/CLI client | Operator terminal on the host | Read and change local policy and host capacity, inspect GitHub state. | Own a second agent lock or hold the user access token in display state. |
| Host agent | One local machine | Poll assigned scale sets, acquire assigned jobs, provision host-local JIT runners up to policy and host capacity. | Manage a different host or expose a network API. |
| JIT runner child | Temporary host directory | Execute exactly one assigned job. | Reuse workspace or credentials after cleanup. |
| Published GitHub App | GitHub | Declare the permission set and be installed by the user on repositories they choose. | Hold a private key, mint installation tokens, or receive a broader installation than the user selected. |

## Architecture decisions

Rationale only. `README.md` carries decision status and is authoritative.

| ID | Decision | Rationale and trade-off |
|---|---|---|
| D1 | Separate public repository; no `ai-pipeline` dependency. | Maintains a clean product, release, and trust boundary. |
| D2 | One host-local agent manages only local runners. | Avoids remote administration and gives clear resource ownership; global inventory remains read-only. |
| D3 | Device flow against one published App. | Three-action onboarding with no server, no client secret, and no key file; the cost is a non-expiring user token at rest and a trust dependency on the published App. Repository-scoped scale sets still force `Administration: Read and write`. |
| D4 | Scale sets with JIT ephemeral runners only. | Correct GitHub autoscaling model and clean per-job state; requires a local listener, an Actions-service protocol adapter, and cold-start time. |
| D5 | `daemon run` plus optional OS service installation. | Works for interactive debugging and unattended home hosts; adds platform installer test work. |
| D6 | Rust single binary with Ratatui/Crossterm and direct HTTPS clients. | Small deployable surface and native cross-platform TUI; public-preview scale-set protocol needs adapter contract tests. |
| D7 | Default `min_capacity=0`; every policy requires explicit `max_capacity`. | Eliminates idle runners and prevents accidental host oversubscription; cold starts are accepted by default. |
| D8 | The TUI is local and never a remote controller. | Fits D2 and avoids a second authentication/network surface. |
| D9 | Two capacity levels: policy `max_capacity` and host `host_capacity`. | A single per-policy limit cannot stop N policies from jointly oversubscribing one machine; the host ceiling is the physical-safety guarantee. |
| D13 | Boot-start service with machine-scoped key storage. | Unattended restart after reboot is the point of the product on a home host; the cost is that a per-user keychain can no longer hold the key. |

## Policy and reconciliation

Each enabled `autoscale` policy creates one scale set for one host, at either
repository or organization scope (D18). The scale set **name** is the routing
token and encodes the product, host identity, and host OS — for example
`rm-home-win-x64`. It must be unique within its runner group. `monitor_only`
policies create no scale set and take no part in reconciliation.
Workflows target it with `runs-on: <scale-set-name>`, never the legacy generic
`self-hosted` label. Additional labels are optional metadata only, because
GitHub documents scale sets as having a single label and multi-label support is
feature-flagged on GHES.

On every scale-set response:

```text
acquire(job_available_messages)                       # mandatory, before scaling
desired      = clamp(total_assigned_jobs, min_capacity, max_capacity)
host_headroom = host_capacity - active_owned_runners_all_policies
to_start     = max(0, min(desired - active_owned_runners, host_headroom))
```

`min_capacity <= max_capacity` is validated on write, so the clamp is always
well-defined. `min_capacity` is fixed at 0 in v1; a warm minimum is deferred.

The agent requests one JIT configuration per `to_start` from the Actions
service, allocates a unique runtime directory, launches the runner, and records
its process identity. It never stops a busy runner to scale down. After
completion or a confirmed unclaimed JIT expiry, it removes the runtime
directory. Runner binaries and approved tool caches are retained separately from
job workspaces.

## UI information architecture

| Screen | Content | Primary interactions |
|---|---|---|
| Dashboard | Total in-progress workflows, assigned jobs, online/busy runners, host capacity used/total, health. | `Tab`, arrows, mouse click, `F5` refresh. |
| Repositories | Authorized repositories; each row shows `(in-progress workflow count)`, scale state, `max_capacity`, and agent health. | Select, type-to-filter, enter detail. |
| Runners | All authorized GitHub runners with owner, OS, labels, online/busy/ephemeral state; local ownership is visually distinct. | Sort, filter, inspect. |
| Repository settings | Enable/disable scaling, scale-set name, `max_capacity`, cache policy, and safe preview. | Form navigation with keyboard or mouse. |
| Host settings | Current `host_capacity` and current total across policies, service start mode, refresh interval. | Edit and confirm. |
| Activity and errors | Lifecycle events, retries, rate limits, cleanup outcome, and actionable remediation. | Copy-safe diagnostics, acknowledge errors. |

No screen displays the user access token, Actions-service admin tokens,
message-queue tokens, encoded JIT configuration, or command lines containing
them. The device-flow *user code* is displayed by design during `auth login`
and only then.

## Requirement traceability

| Requirement | Mechanism | Acceptance evidence |
|---|---|---|
| Windows, macOS, and Linux support | Rust platform adapter and one host-local daemon per host. | Native CI/service smoke tests on each OS (`09-release-distribution.md`). |
| Lightweight terminal UI | One binary; Ratatui rendering and asynchronous snapshot reads. | Frame-budget test in `04-subsystem-contracts.md` and snapshot tests. |
| Keyboard and mouse navigation | Crossterm event reducer plus focusable controls, with explicit mouse capture. | Reducer tests and the interaction budgets in `08-user-workflows.md`. |
| List all visible runners | Paginated GitHub runner inventory, marked local or external. | Multi-page REST fixture and runner-table snapshot. |
| Repository list with active Action counts | Per-repository `in_progress` workflow-run count, rendered in parentheses. | REST fixture and repository-list snapshot. |
| Aggregate running Actions | Summed in-progress workflow count, separate from busy-runner count. | Workflow-count aggregation tests. |
| Settings for repository autoscaling | Versioned `ScalePolicy`, shared by CLI and TUI. | CLI/TUI parity tests and policy persistence test. |
| Per-repository and host-wide runner limits, visible and editable (D9) | `ScalePolicy.max_capacity`, `Host.host_capacity`, `repo set-capacity`, `host set-capacity`, host settings screen. | Host-ceiling enforcement test and settings round-trip test. |
| Headless operations, especially repository add | `repo add` command with noninteractive validation and JSON status. | Scripted end-to-end CLI test. |
| No idle runners when unused | `min_capacity=0`, scale-set listener, JIT ephemeral lifecycle. | Idle-host zero-runner assertion. |
| Honest offline behavior | Long-poll backoff, `offline` state, per-screen status bar, 24h queue-cancellation warning. | Journey 4 gate in `08-user-workflows.md`. |
| Human-friendly modern view | Dashboard, focused tables, health/error states, text-plus-color status. | Journey gates in `08-user-workflows.md`. |
| Tested on every PR and merge (D10) | `.github/workflows/ci.yml` matrix. | CI required-check status on the pull request. |
| Manual, validated, tested releases (D10) | `.github/workflows/release.yml`, `workflow_dispatch` only. | Release-workflow rehearsal in `09-release-distribution.md`. |
| One-command install per OS (D11) | Install script, npm wrapper, Homebrew tap, `cargo install`. | Per-channel install smoke test on each OS, asserting no security prompt, including a Windows host with no Node. |
| Three-action onboarding (D3) | Device flow against the published App, then an installation URL. | Device-flow round-trip test and Journey 1 gate in `08-user-workflows.md`. |
| Repository and organization scale sets (D18) | `ScaleTarget` sum type; `repo` and `org` command families sharing one domain path. | Target-equivalence domain tests and one live organization-scoped job. |
| Optional autoscaling / monitor-only (D19) | `PolicyMode`, enforced shape invariants, reconciliation skips `MonitorOnly`. | Monitor-only policy starts no runner; promotion to `autoscale` round-trip test. |

## Owner-facing open questions

None. D21 settled the last one on 2026-08-21: the project publishes exactly
one GitHub App, and monitor-only users therefore grant the full permission
set. The disclosure obligation that follows is a requirement in
`07-security.md`, not an open question.

The product name is settled: the binary, workspace root package, published
crate, and npm package are all named `runner-manager` (RESOLVED 2026-08-21).
The repository keeps its own name, `IvanMurzak/GitHub-Runner-Scaler-UI`.

D1-D21 in `README.md` resolve every product-policy decision needed to begin
implementation. The only unresolved item is technical, not product: the D17
spike must confirm that a user-to-server token drives the Actions-service
scale-set chain.
