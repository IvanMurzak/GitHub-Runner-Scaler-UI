# Current architecture and evidence boundary

## Evidence-only finding

The target application repository exists but contains no application code. This
checkout — `https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI` — holds
`LICENSE`, `.gitignore`, this taskflow, and the D17 spike record under
`docs/spikes/` at `HEAD`. There are no submodules, no build manifest, no source
tree, and no CI. This document therefore infers no change
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
| GitHub's Scale Set Client is standalone, outside Kubernetes, and supplies scale-set, JIT, and message-session primitives. | `github.com/actions/scaleset@main:README.md:1-7`. | Establishes that a local host agent needs neither ARC nor a server. The scale-set half of that topology is unusable here (D4); the local-agent conclusion survives. |
| Demand, in the scale-set model, is `statistics.TotalAssignedJobs`. That model is unavailable (D4). | `github.com/actions/scaleset@main:README.md:40-79`. | Reconciliation instead derives demand from queued workflow runs and their jobs over public REST, and applies an explicit capacity ceiling. |
| Scale-set JIT configuration is issued by the Actions service, not by the public REST API — and scale-set administration is denied to a free-plan identity. | `github.com/actions/scaleset@main:client.go:686-694`; and the D17 spike, `docs/spikes/d17-user-to-server-scale-set-chain.md`, which received `403 needs Administer Permissions` on scale-set creation from four independent credential/scope combinations. | **The product does not use scale sets (D4).** JIT configuration comes from the public REST endpoint instead. See "Edge cases" item 5. |
| A JIT ephemeral runner is registered with an arbitrary **label set**, which `runs-on` targets. | GitHub REST, "Create configuration for a just-in-time runner for a repository"; verified `201` in the D17 spike with `labels: ["rm-probe","self-hosted"]`. | Routing identity lives in the label set. Unlike a scale set, more than one label is supported. |
| Ratatui is a Rust crate for interactive terminal dashboards; its example uses Crossterm events. Crossterm does not emit mouse or paste events unless explicitly enabled. | `github.com/ratatui/ratatui@main:README.md:26-28,42-61`; `docs.rs/crossterm` `event` module: "Mouse and focus events are not enabled by default." | Ratatui renders; Crossterm provides keyboard and mouse input only after explicit `EnableMouseCapture` and the `bracketed-paste` feature. |
| GitHub REST provides runner **inventory**, runner-application download metadata, and JIT runner configuration. | GitHub REST self-hosted runners reference; `Administration: read` for inventory, `Administration: write` for `generate-jitconfig`. | Every GitHub interaction in the product is typed HTTPS REST against `api.github.com`. There is no second protocol and no second host. |
| A queued job is automatically cancelled after 24 hours. | GitHub Actions limits reference, "Queued job cancellation". | An agent offline for more than 24 hours loses queued work; the offline state must say so. |
| GitHub documents the device flow as the way a headless or CLI application obtains a user access token, and states that a public client cannot secure a client secret. Only `client_id` is required to start it. | GitHub Apps docs, "Building a CLI with a GitHub App" and "Generating a user access token for a GitHub App". | D3: the tool ships a public `client_id`, holds no secret, needs no redirect listener, and needs no server. |
| User-to-server token expiration is an opt-in/opt-out setting on the App. Opted in, the token lasts 8 hours and refreshing it **requires the client secret**. Opted out, tokens do not expire and no refresh exists. | GitHub Apps docs, "Refreshing user access tokens": "The client secret is required when refreshing user access tokens." | The published App must opt **out**, otherwise refresh would force a server to hold the secret. The cost is a non-expiring token at rest, recorded in `07-security.md`. |
| Device flow must be explicitly enabled on the App registration. | GitHub Apps docs, "Building a CLI with a GitHub App": "you must enable device flow for your app." | A one-time configuration step on the published App, recorded in `06-migration-rollout.md` Phase 0. |

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
   autoscaling primitive. The agent must observe queued demand and register a
   JIT runner before that bound.
2. A host cannot run container actions or service containers merely because it
   runs Docker; GitHub's self-hosted runner reference requires Linux for those
   workflow features. Repository policy validation must surface that limitation
   on macOS and Windows.
3. A JIT configuration is sensitive and short-lived. It cannot be persisted in
   configuration, logs, UI state, or crash reports.
4. **Resolved by D4.** The Scale Set Client's Public Preview status
   (`github.com/actions/scaleset@main:README.md:1-3`) was the top technical risk
   in `06-migration-rollout.md`. Dropping scale sets removes it, along with the
   revision pinning, contract tests, and `protocol_flag` it required.
5. **Inverted by evidence.** `POST /repos/{owner}/{repo}/actions/runners/generate-jitconfig`
   cannot serve a scale set — it registers a runner into a runner *group*, and
   such a runner is never counted in `statistics.TotalAssignedJobs`. That
   remains true, and it is now the reason the product does **not** use scale
   sets rather than the reason it must use the Actions service. The D17 spike
   established the decisive asymmetry: registering a runner into runner group 1
   returns `201`, while administering that same group to create a scale set
   returns `403 needs Administer Permissions`, on the same account with the same
   `Administration: write` permission.
6. **No job reservation exists.** `AcquireJobs` was the scale-set mechanism that
   reserved an assignment for one listener. The REST path has no equivalent, so
   two hosts polling the same target can both start a runner for one queued job.
   The surplus runner finds no work and exits, but it consumed a capacity slot
   and a cold start. Mitigation is host-scoped routing labels plus the
   `max_capacity` and `host_capacity` ceilings; see `03-control-flows.md`.
7. GitHub rejects runners older than 30 days from the latest release. A pinned
   immutable package cache with no freshness policy will silently start failing
   every job on a long-lived host.
8. **Resolved GREEN by the D17 spike.** A user-to-server token does drive the
   GitHub credential chain — it minted a runner registration token and completed
   the Actions-service admin exchange at both repository and organization scope,
   producing the same scopes and TTL as an OAuth user token. D3 is confirmed.
   Evidence: `docs/spikes/d17-user-to-server-scale-set-chain.md`.
9. **Demand polling shares the REST budget.** Under scale sets, long-poll demand
   was separate from `api.github.com` rate limits. It no longer is. Demand
   polling, runner inventory, and workflow counts now draw on the same
   5,000 requests/hour ceiling, which lowers how many targets one host can
   serve. `04-subsystem-contracts.md` carries the revised budget.

## Planned seam index

| Seam | Responsibility | Ownership |
|---|---|---|
| CLI/TUI shell | Parse commands, render read models, dispatch domain commands. | `app` crate |
| Domain | Policies, capacity, ownership, state transitions, validation. | `domain` crate |
| GitHub gateway | GitHub App auth, REST inventory, workflow counts, queued-job demand, JIT runner configuration. | `github` crate |
| Agent | Reconcile demand, spawn/observe/remove runner processes, recover after restart. | `agent` crate |
| Host adapter | Paths, locks, processes, machine-scoped secret store, service installer, OS metadata. | `platform` crate |
