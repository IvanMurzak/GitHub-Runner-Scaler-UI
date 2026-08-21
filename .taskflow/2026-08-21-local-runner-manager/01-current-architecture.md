# Current architecture and evidence boundary

## Evidence-only finding

The target application repository exists but contains no application code. This
checkout — `https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI` — holds only
`LICENSE` at `HEAD` plus this taskflow. There are no submodules, no build
manifest, no source tree, and no CI. This document therefore infers no change
seams from the current checkout; the target structure is defined in
`02-target-architecture.md`.

This taskflow was drafted in the `IvanMurzak/ai-pipeline` repository, a separate
cloud-control-plane product with its own submodules, and transferred here. That
repository is explicitly out of scope: none of its code, submodules,
credentials, or deployment paths may be imported, vendored, called, or deployed
by this product (D1).

## Citation convention

A bare `` `file:line` `` citation refers to a path in **this** checkout.
Citations into external repositories are prefixed with their host and revision,
for example `github.com/actions/scaleset@main:README.md:1-7`. This distinction
is load-bearing: an unqualified external citation is indistinguishable from a
local one and cannot be verified.

## Authoritative external constraints

| Constraint | Evidence | Design consequence |
|---|---|---|
| GitHub documents Windows 10/11 64-bit and Windows Server 2016/2019/2022 64-bit, macOS 11.0 (Big Sur) or later, and nine Linux distributions (RHEL/CentOS/Oracle 8+, Fedora 29+, Debian 10+, Ubuntu 20.04+, Mint 20+, openSUSE 15.2+, SLES 15 SP2+) as supported runner platforms. Supported architectures are x64 on all three, ARM64 on all three (**public preview**), and ARM32 on Linux only. | GitHub self-hosted runner reference, "Supported operating systems" and "Supported architectures". | The binary and host adapters target Windows, macOS, and Linux on x64 and ARM64. `repo add` validates the host OS/architecture against this matrix and warns that ARM64 is public preview — the persona's Apple Silicon Mac mini is an ARM64 host. |
| The runner application itself needs minimal idle resources, but workflow hardware demand belongs to the host. | GitHub self-hosted runner reference, "Requirements for self-hosted runner machines." | Autoscaling prevents idle runner processes; `max_capacity` and `host_capacity` protect real host resources. |
| GitHub recommends ephemeral runners for autoscaling and does not recommend autoscaling persistent runners. | GitHub self-hosted runner reference, "Ephemeral runners for autoscaling." | D4 is JIT plus ephemeral only. |
| GitHub's Scale Set Client is standalone, outside Kubernetes, and supplies scale-set, JIT, and message-session primitives. | `github.com/actions/scaleset@main:README.md:1-7`. | A local host agent can implement this topology without ARC or a server. |
| Demand is the current `statistics.TotalAssignedJobs`, not a count of individual messages. Max capacity is sent as the `X-ScaleSetMaxCapacity` header. | `github.com/actions/scaleset@main:README.md:40-79`; `session_client.go:151`. | Reconciliation uses the reported aggregate and an explicit capacity ceiling. |
| Scale-set JIT configuration is issued by the Actions service, not by the public REST API. | `github.com/actions/scaleset@main:client.go:686-694` — `POST {actions_service_url}/_apis/runtime/runnerscalesets/{scale_set_id}/generatejitconfig`; request body is only `{name, workFolder}` (`types.go:93-96`). | The `github` crate must implement the Actions-service protocol. See "Edge cases" item 5. |
| A scale set's **name** is the routing token; GitHub documents scale sets as carrying a single label, and multi-label support is feature-flagged on GHES. | GitHub Actions concepts, "Runner scale sets": "you must configure your workflow to reference the runner scale set's name"; `github.com/actions/scaleset@main:client.go:499` (names unique within a runner group). | Routing identity lives in the scale-set name, not in a label set. |
| Ratatui is a Rust crate for interactive terminal dashboards; its example uses Crossterm events. Crossterm does not emit mouse or paste events unless explicitly enabled. | `github.com/ratatui/ratatui@main:README.md:26-28,42-61`; `docs.rs/crossterm` `event` module: "Mouse and focus events are not enabled by default." | Ratatui renders; Crossterm provides keyboard and mouse input only after explicit `EnableMouseCapture` and the `bracketed-paste` feature. |
| GitHub REST provides runner **inventory** and runner-application download metadata. | GitHub REST self-hosted runners reference, "List self-hosted runners" and "List runner applications for a repository"; both require `Administration: read`. | Read models use typed HTTPS REST clients. JIT provisioning does not. |
| A queued job is automatically cancelled after 24 hours. | GitHub Actions limits reference, "Queued job cancellation". | An agent offline for more than 24 hours loses queued work; the offline state must say so. |

Source URLs are retained so a transferred taskflow is self-contained:

- https://docs.github.com/en/actions/reference/runners/self-hosted-runners
- https://docs.github.com/en/actions/reference/limits
- https://docs.github.com/en/actions/concepts/runners/runner-scale-sets
- https://docs.github.com/en/rest/actions/self-hosted-runners
- https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
- https://docs.github.com/en/actions/tutorials/use-actions-runner-controller/authenticate-to-the-api
- https://github.com/actions/scaleset/blob/main/README.md
- https://github.com/ratatui/ratatui/blob/main/README.md

## Edge cases already known

1. A job matching no online runner remains queued and is automatically
   cancelled after 24 hours, so a stopped persistent runner is not a reliable
   autoscaling primitive. The scale-set listener must receive demand before it
   creates a JIT runner.
2. A host cannot run container actions or service containers merely because it
   runs Docker; GitHub's self-hosted runner reference requires Linux for those
   workflow features. Repository policy validation must surface that limitation
   on macOS and Windows.
3. A JIT configuration is sensitive and short-lived. It cannot be persisted in
   configuration, logs, UI state, or crash reports.
4. The Scale Set Client is Public Preview
   (`github.com/actions/scaleset@main:README.md:1-3`). Its protocol adapter
   needs revision pinning and contract tests.
5. **The public REST endpoint `POST /repos/{owner}/{repo}/actions/runners/generate-jitconfig`
   cannot serve a scale set.** It requires a `runner_group_id` and a `labels`
   array and registers an ordinary ephemeral runner into a runner *group*. Such
   a runner is never counted in `statistics.TotalAssignedJobs` and never
   receives a job acquired by the scale-set session. Scale-set JIT
   configuration must come from the Actions service endpoint above.
6. Every `JobAvailable` message must be answered with `AcquireJobs` before
   reconciliation. GitHub cancels and requeues an unacquired assignment up to
   three times with incremental delays
   (`github.com/actions/scaleset@main:README.md:114`).
7. GitHub rejects runners older than 30 days from the latest release. A pinned
   immutable package cache with no freshness policy will silently start failing
   every job on a long-lived host.

## Planned seam index

| Seam | Responsibility | Ownership |
|---|---|---|
| CLI/TUI shell | Parse commands, render read models, dispatch domain commands. | `app` crate |
| Domain | Policies, capacity, ownership, state transitions, validation. | `domain` crate |
| GitHub gateway | GitHub App auth, REST inventory, workflow counts. | `github` crate |
| Actions-service gateway | Scale-set administration, message sessions, job acquisition, JIT configuration. | `github` crate, isolated behind `ScaleSetGateway` |
| Agent | Reconcile demand, spawn/observe/remove runner processes, recover after restart. | `agent` crate |
| Host adapter | Paths, locks, processes, machine-scoped secret store, service installer, OS metadata. | `platform` crate |
