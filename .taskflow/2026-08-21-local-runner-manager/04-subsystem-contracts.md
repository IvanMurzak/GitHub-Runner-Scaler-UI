# Subsystem rules, data, and tests

## Persistent local data

SQLite contains configuration and recovery metadata only. The user access
token is stored in the platform machine-scoped secret store, never SQLite.

```text
Host {
  id: UUID, display_name: String, os: Os, architecture: Arch,
  host_capacity: NonZeroU16, service_start_mode: StartMode,
  refresh_interval_secs: u16, created_at: Timestamp
}
ScalePolicy {
  id: UUID, target: ScaleTarget, installation_id: u64,
  host_id: UUID, mode: PolicyMode,
  scale_set_id: Option<String>, scale_set_name: Option<String>,
  enabled: bool, state: PolicyState,
  min_capacity: u16, max_capacity: Option<NonZeroU16>,
  protocol_flag: ProtocolCompat, cache_policy: CachePolicy, revision: u64
}
ScaleTarget = Repository(OwnerRepo) | Organization(Org)
PolicyMode  = MonitorOnly | Autoscale
RunnerAttempt {
  id: UUID, policy_id: UUID, github_runner_id: Option<u64>,
  state: AttemptState, process_id: Option<u32>, runtime_path: Path,
  created_at: Timestamp, terminal_at: Option<Timestamp>
}
```

`ScaleTarget` carries D18: a policy targets either one repository or one whole
organization. The two differ only in which GitHub endpoints and which App
permission the gateway uses; ownership, capacity, and lifecycle rules are
identical.

`PolicyMode` carries D19 and is an enforced invariant, not a convention:

- `MonitorOnly` requires `scale_set_id`, `scale_set_name`, and `max_capacity`
  to be `None`. The policy is read-only: it contributes runners and workflow
  counts to the dashboard and is skipped entirely by reconciliation.
- `Autoscale` requires all three to be `Some`.

A write that violates either shape is rejected in the domain layer, so an
autoscale policy without a capacity ceiling cannot be persisted.

`Host.host_capacity` is the ceiling on concurrent runner attempts across every
policy on this machine (D9). `ScalePolicy.max_capacity` is the per-policy
ceiling. Both are settable from the CLI and editable in TUI settings, which
display their current values alongside the current in-use count.

`min_capacity <= max_capacity` is validated on every write of an `Autoscale`
policy, so `clamp(total_assigned_jobs, min_capacity, max_capacity)` is always
well-defined. `min_capacity` is fixed at 0 in v1.

`AttemptState` is:

```text
allocated -> jit_received -> starting -> idle | busy
idle | busy -> finished | failed | orphaned
finished | failed | orphaned -> cleaned
```

`idle` means the runner process is registered and awaiting its single job
assignment; it is short-lived and is not an idle *persistent* runner. Only
terminal attempts may be cleaned. `busy` cannot transition to cleanup due to a
scale-down request.

`PolicyState` is:

```text
pending -> active | repair_required
active  -> draining -> disabled
any     -> authentication_failed        (recoverable by re-authentication)
```

`enabled` records operator intent; `state` records observed lifecycle. Both are
persisted, so a `repair_required` policy survives a restart and still yields an
explicit repair instruction instead of a silent destructive retry.

## GitHub gateway contract

Two distinct hosts are involved. `api.github.com` serves inventory; the Actions
service tenant (`_apis/runtime/runnerscalesets`) serves scale-set operations.
They have different authentication, different versioning, and different
rate-limit semantics.

| Operation | Protocol | Result |
|---|---|---|
| Obtain a user access token | `github.com/login/device` device flow, public `client_id` only | Non-expiring user-to-server token. No redirect, no client secret, no server. |
| Discover repositories the App is installed on | `api.github.com`, user-to-server REST | Authorized repository set. |
| List runners | `api.github.com` REST, paginated; `/repos/{o}/{r}/actions/runners` or `/orgs/{org}/actions/runners` by policy target | Runner id, labels, OS, status, busy, ephemeral. |
| Count activity | `api.github.com` REST workflow runs filtered to `in_progress`, per repository; an organization policy aggregates across the repositories the App is installed on | Per-target and aggregate workflow count. |
| Download runner application | `api.github.com` REST runner-downloads metadata | OS/architecture URL plus optional `sha256_checksum`. |
| Manage scale sets and message sessions | Actions-service `ScaleSetGateway` | Scale-set create/update/delete, session create/refresh, ownership metadata. |
| Receive demand and acquire jobs | Actions-service long poll | `statistics.TotalAssignedJobs`, `JobAvailable` messages, `AcquireJobs`, `DeleteMessage` acknowledgement. |
| Generate JIT config | Actions-service `_apis/runtime/runnerscalesets/{id}/generatejitconfig` | Encoded JIT config for a scale-set runner; request body is `{name, workFolder}`. |

The public REST endpoint `POST /repos/{owner}/{repo}/actions/runners/generate-jitconfig`
is **not** used. It requires a `runner_group_id` and a `labels` array, registers
a runner into a runner *group* rather than a scale set, and produces a runner
that the scale-set session can never assign work to.

All `api.github.com` requests set `X-GitHub-Api-Version` and an explicit
`Accept` header. The scale-set adapter uses the Actions service's own
`api-version` and is not covered by REST rate-limit headers. Pagination is
mandatory; the dashboard must not treat a first page as a complete inventory.
The `api.github.com` gateway honors `retry-after`, `x-ratelimit-remaining` and
`x-ratelimit-reset`, idempotency semantics, and cancellation.

The scale-set protocol is Public Preview. It is isolated behind
`ScaleSetGateway`; no TUI, CLI, domain, or platform module can deserialize its
wire messages directly. `ScalePolicy.protocol_flag` allows a single policy
to be pinned to a known-compatible protocol revision or disabled if the preview
protocol drifts.

## Ownership and precedence

1. A policy's `host_id` and unique scale-set name determine ownership. A
   `MonitorOnly` policy owns nothing and can never be the reason a runner
   starts.
2. A host agent may act only on attempts persisted under its `host_id`.
3. GitHub runner status is authoritative for remote job status; local process
   state is authoritative only for a child process owned by this agent.
4. A user-requested disable beats demand and starts draining.
5. `max_capacity` beats reported demand, and `host_capacity` beats
   `max_capacity`. The host-wide allocator prevents the sum of active attempts
   across policies from exceeding `Host.host_capacity`.
6. Runtime cache retention is optional; job workspace retention is always
   disabled in v1.

## Refresh and backpressure

The TUI reads an in-memory snapshot. The agent independently refreshes runner
inventory and workflow counts on a bounded interval, default 60 seconds with a
hard floor of 30 seconds per repository. That worst case is roughly 240
requests per hour per repository against the 5,000 requests/hour minimum that
applies to the token in use. `repo add` computes the projected hourly budget and
refuses a configuration that would exceed half of that floor. Manual refresh
coalesces with an in-flight request. Rate limiting increases refresh delay and
is displayed, never hidden. Long-poll demand is separate from UI refresh and is
not stopped while the TUI is closed.

## Test approach

| Layer | Required tests |
|---|---|
| Domain | State transitions for `AttemptState` and `PolicyState`, `PolicyMode` shape invariants in both directions, repository/organization target equivalence, capacity math including the host ceiling and the `min <= max` invariant, workflow-count aggregation, disable/drain precedence, ownership rejection, and recovery decisions with fake time. |
| GitHub gateway | Device-flow round trip including `authorization_pending`, `slow_down`, `expired_token`, and `access_denied`; HTTP fixtures for pagination, rate limits, 401 on a revoked token, 403 auth lockout, and the two-stage Actions-service token exchange. |
| Scale-set adapter | Contract tests against the pinned protocol revision: demand decoding, `JobAvailable` to `AcquireJobs`, `DeleteMessage` acknowledgement, session-token refresh, JIT generation, and fail-closed decoding of unknown critical fields. |
| Agent | Fake process and filesystem tests for spawn failure, restart/orphan cleanup, busy protection, idle-host zero-runner assertion, host-ceiling enforcement across multiple policies, and no duplicate runners under lock contention. |
| Platform | Windows/macOS/Linux path, lock, machine-scoped secret store, and service adapter contract tests; privileged installer smoke tests on native CI runners; stale-binary-path detection after an npm-managed upgrade. |
| CLI/TUI parity | Same-command dispatch equality, policy and host-capacity persistence round-trip, monitor-only to autoscale promotion, scripted noninteractive `repo add`, `org add`, `host set-capacity`, and `status --json`. |
| UI | Ratatui snapshot tests for all screens, keyboard/mouse reducer tests, frame-budget test, resize behavior, focus order, and redaction. |
| Security | Process-inspection, two-job contamination, corrupted-runner-package rejection, and secret-injection log-scan gates from `07-security.md`. |
| End-to-end | A disposable GitHub test repository runs a real JIT job for each supported host OS. |

Release acceptance requires at least one successful JIT job, a forced
network-outage recovery, a JIT-expiry recovery, and a policy-disable drain on
Windows, macOS, and Linux.
