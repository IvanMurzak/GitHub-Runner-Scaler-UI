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
  routing_labels: Option<NonEmpty<Label>>,
  enabled: bool, state: PolicyState,
  min_capacity: u16, max_capacity: Option<NonZeroU16>,
  cache_policy: CachePolicy, revision: u64
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

- `MonitorOnly` requires `routing_labels` and `max_capacity` to be `None`. The
  policy is read-only: it contributes runners and workflow counts to the
  dashboard and is skipped entirely by reconciliation.
- `Autoscale` requires both to be `Some`.

A write that violates either shape is rejected in the domain layer, so an
autoscale policy without a capacity ceiling or without a routing label cannot
be persisted.

D4 removed `scale_set_id`, `scale_set_name`, and `protocol_flag` from this
model. `routing_labels` replaces the scale-set name as the routing token, and
it is a non-empty set rather than a single value because a JIT runner may carry
several labels where a scale set carried one.

`Host.host_capacity` is the ceiling on concurrent runner attempts across every
policy on this machine (D9). `ScalePolicy.max_capacity` is the per-policy
ceiling. Both are settable from the CLI and editable in TUI settings, which
display their current values alongside the current in-use count.

`min_capacity <= max_capacity` is validated on every write of an `Autoscale`
policy, so `clamp(demand, min_capacity, max_capacity)` is always
well-defined. `min_capacity` is fixed at 0 in v1.

`AttemptState` is:

```text
allocated -> jit_received -> starting -> idle | busy
idle -> busy
allocated | jit_received | starting -> failed | orphaned
idle | busy -> finished | failed | orphaned
finished | failed | orphaned -> cleaned
```

`idle` means the runner process is registered and awaiting its single job
assignment; it is short-lived and is not an idle *persistent* runner. Only
terminal attempts may be cleaned. `busy` cannot transition to cleanup due to a
scale-down request.

**AMENDED 2026-08-21, on owner decision during execution.** Two edge sets were
added: `idle -> busy`, and terminal edges out of the three pre-registration
states. The original diagram was internally inconsistent and had a concrete
operational consequence, all three of which `b1`'s implementation and its
review made executable rather than theoretical.

- **`idle -> busy` was missing** while `e3`'s Scope step 4 moves an attempt
  through `jit_received`, `starting`, `idle`, `busy` *in sequence*. The diagram
  read `idle` and `busy` as alternative outcomes of `starting`, so a runner that
  registered, was observed idle, and then picked up a job had nowhere legal to
  go. The definition of `idle` immediately above — "registered and awaiting its
  single job assignment" — describes a state that by construction precedes a
  job, which settles it in `e3`'s favour.
- **No terminal edge existed out of `allocated`, `jit_received` or `starting`.**
  Because an attempt counts against host capacity for exactly as long as it is
  non-terminal, an attempt that could not reach a terminal state **held a host
  capacity slot permanently**: two failed JIT requests on a `host_capacity: 2`
  host wedged that host into starting zero runners, with no error state, no
  cleanup path, and nothing operator-visible. `orphaned` is included for the
  restart case, where a pre-registration attempt is found after the agent
  restarts.
- **Five of the seven `FailureReason` variants were unreachable** —
  `JitRequestFailed`, `JitExpired`, `RunnerPackageUnverified`,
  `RunnerVersionRejected` and `ProcessStartFailed` — although
  `03-control-flows.md` flow 2 names each by name as a condition the agent must
  record. Every one of them occurs at a pre-registration state.

`b1` implemented the original diagram faithfully rather than inventing edges,
and surfaced the gap as an explicit `NoLegalTransition` outcome with a test
named for it. That was the correct behaviour for an implementer facing an
inconsistent contract, and it is why the defect was found before `e3` was
written rather than after.

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

After D4 there is exactly one host and one protocol: typed REST against
`api.github.com`. The Actions-service tenant, with its separate authentication,
versioning, and rate-limit semantics, is gone.

| Operation | Endpoint | Result |
|---|---|---|
| Obtain a user access token | `github.com/login/device` device flow, public `client_id` only | Non-expiring user-to-server token. No redirect, no client secret, no server. |
| Discover installed targets | user-to-server REST | Authorized repository and organization set. |
| List runners | `/repos/{o}/{r}/actions/runners` or `/orgs/{org}/actions/runners`, paginated | Runner id, labels, OS, status, busy, ephemeral. |
| Count activity | workflow runs filtered to `in_progress`; an organization policy aggregates across installed repositories | Per-target and aggregate workflow count. |
| **Read demand** | workflow runs filtered to `queued`, then their jobs, matched against the policy's `routing_labels` | Count of queued jobs this policy should serve. |
| Download runner application | runner-downloads REST | OS/architecture URL plus optional `sha256_checksum`. |
| **Generate JIT configuration** | `POST /repos/{o}/{r}/actions/runners/generate-jitconfig`, or the `/orgs/{org}/` form; body `{name, runner_group_id, labels, work_folder}` | `encoded_jit_config` plus the runner reference. Needs `Administration: write` at repository scope. |

Verified 2026-08-21: the repository endpoint returns `201` on a personal
free-plan account with runner group 1. The organization endpoint is
**unverified**.

All requests set `X-GitHub-Api-Version` and an explicit `Accept` header.
Pagination is mandatory; the dashboard must not treat a first page as a
complete inventory. The gateway honors `retry-after`, `x-ratelimit-remaining`,
and `x-ratelimit-reset`, idempotency semantics, and cancellation.

**There is no job reservation.** The scale-set model's `AcquireJobs` has no REST
equivalent, so demand is advisory: another host may take a job this host has
already started a runner for. `02-target-architecture.md` records the bounding
controls.

## Ownership and precedence

1. A policy's `host_id` and its host-scoped `routing_labels` determine
   ownership. A `MonitorOnly` policy owns nothing and can never be the reason a
   runner starts.
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
inventory, workflow counts, **and demand** on a bounded interval, default 60
seconds with a hard floor of 30 seconds per target.

D4 changed this analysis materially. Under scale sets, long-poll demand was
carried by the Actions service and did **not** consume the `api.github.com`
budget. Demand now shares one ceiling with everything else:

| Per target, per hour | at the 60 s default | at the 30 s floor |
|---|---|---|
| queued runs plus their jobs (demand) | ~120 | ~240 |
| runner inventory | ~60 | ~120 |
| in-progress workflow count | ~60 | ~120 |
| **total** | **~240** | **~480** |

The ceiling for a user-to-server token is **5,000 requests/hour**, measured
2026-08-21. `add` computes the projected hourly budget and refuses a
configuration that would exceed **half** of it, which allows roughly **10
targets per host** at the 60-second default and **5** at the 30-second floor.

That limit is a product constraint, not an implementation detail: it must be
stated in `repo add` output and visible in host settings, because an operator
who adds an eleventh repository needs to know why it was refused.

Manual refresh coalesces with an in-flight request. Rate limiting increases the
refresh delay and is displayed, never hidden. Demand polling continues while the
TUI is closed.

## Test approach

| Layer | Required tests |
|---|---|
| Domain | State transitions for `AttemptState` and `PolicyState`, `PolicyMode` shape invariants in both directions, repository/organization target equivalence, capacity math including the host ceiling and the `min <= max` invariant, label-matching of queued jobs, workflow-count aggregation, disable/drain precedence, ownership rejection, and recovery decisions with fake time. |
| GitHub gateway | Device-flow round trip including `authorization_pending`, `slow_down`, `expired_token`, and `access_denied`; HTTP fixtures for pagination, rate limits, 401 on a revoked token, and 403 auth lockout. |
| Demand and JIT | Queued-run and job fixtures including `runs-on` forms that must and must not match the policy's labels; `generate-jitconfig` request shape, `201` decoding, and failure modes; budget projection against the documented ceiling. |
| Agent | Fake process and filesystem tests for spawn failure, restart/orphan cleanup, busy protection, idle-host zero-runner assertion, host-ceiling enforcement across multiple policies, no duplicate runners under lock contention, and the surplus-runner path where a JIT runner receives no job and exits on idle timeout. |
| Platform | Windows/macOS/Linux path, lock, machine-scoped secret store, and service adapter contract tests; privileged installer smoke tests on native CI runners; stale-binary-path detection after an npm-managed upgrade. |
| CLI/TUI parity | Same-command dispatch equality, policy and host-capacity persistence round-trip, monitor-only to autoscale promotion, budget refusal, scripted noninteractive `repo add`, `org add`, `host set-capacity`, and `status --json`. |
| UI | Ratatui snapshot tests for all screens, keyboard/mouse reducer tests, frame-budget test, resize behavior, focus order, and redaction. |
| Security | Process-inspection, two-job contamination, corrupted-runner-package rejection, and secret-injection log-scan gates from `07-security.md`. |
| End-to-end | A disposable GitHub test repository runs a real JIT job for each supported host OS. |

Release acceptance requires at least one successful JIT job, a forced
network-outage recovery, a JIT-expiry recovery, and a policy-disable drain on
Windows, macOS, and Linux, plus one live organization-scoped job proving D18's
currently unverified org path.
