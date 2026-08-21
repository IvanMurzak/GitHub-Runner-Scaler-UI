---
id: "c3-rest-inventory-gateway"
title: "REST inventory: paginated runners, in-progress workflow counts, runner downloads, rate limits, and the testkit fake gateway"
group: "C"
sequence: 3
repo: "."
depends_on: ["c2-device-flow-auth"]
importance: 8
complexity: 6
security_critical: false
production_touching: false
model_hint: "mid"
taskflow_refs: ["04-subsystem-contracts.md", "02-target-architecture.md", "01-current-architecture.md"]
---

## Goal

Provide every read model the dashboard and the CLI display, over
`api.github.com`, with pagination and rate-limit behaviour that is correct
rather than convenient — and provide the fake gateway that lets groups E, F,
and G test against it without a network.

## Scope & seams

Owns `crates/github/src/rest.rs` and `crates/testkit/src/github.rs`. Builds on
`c2`'s authenticated client; adds no second auth path.

| Operation | Endpoint | Result |
|---|---|---|
| List runners | `/repos/{o}/{r}/actions/runners` or `/orgs/{org}/actions/runners`, by policy target | id, labels, OS, status, busy, ephemeral |
| Count activity | workflow runs filtered to `in_progress` per repository; an organization policy aggregates across the repositories the App is installed on | per-target and aggregate counts |
| Runner download metadata | runner-downloads REST | OS/architecture URL plus **optional** `sha256_checksum` |

**Pagination is mandatory.** The dashboard must never treat a first page as a
complete inventory — a target with more runners than one page is the normal
case for an organization, and a silently truncated list reads as "no runners"
rather than as an error.

**Rate limits.** Honour `retry-after`, `x-ratelimit-remaining`, and
`x-ratelimit-reset`; support cancellation; coalesce a manual refresh with an
in-flight request. Rate limiting increases the refresh delay and is
**surfaced**, never hidden (`04-subsystem-contracts.md`, Refresh and
backpressure).

**Budget projection.** Expose the projected hourly request budget for a
candidate refresh interval, so `f2`'s `repo add` can refuse a configuration
that would exceed half of the 5,000 requests/hour floor. The default interval
is 60 seconds with a hard floor of 30 seconds per repository.

`sha256_checksum` being optional in GitHub's schema is a fact this layer must
pass through faithfully — as an optional value, never as an empty string or a
default. Task `e2` fails closed on its absence, and it can only do that if this
layer does not paper over it.

**Not in scope:** the Actions-service protocol (`c4`, `c5`), and the public
`generate-jitconfig` REST endpoint, which is **not used at all**. It requires a
`runner_group_id` and a `labels` array, registers a runner into a runner
*group* rather than a scale set, and produces a runner the scale-set session
can never assign work to (`01-current-architecture.md`, edge case 5).

## Definition of Done

- A multi-page runner fixture returns every runner across all pages, for both
  repository and organization targets.
- In-progress workflow counts are correct per repository and correctly
  aggregated for an organization target, and stay distinct from the busy-runner
  count — they are different numbers with different meanings.
- `retry-after` is obeyed; an exhausted rate limit produces a distinct,
  displayable state rather than an opaque error.
- A manual refresh issued during an in-flight request coalesces into one
  request; a cancelled request stops in-flight work.
- An absent `sha256_checksum` surfaces as absent and is distinguishable from an
  empty value.
- The projected hourly budget for a given interval and target count is computed
  and asserted against the documented floor.
- The public `generate-jitconfig` endpoint appears nowhere in the crate.
- `crates/testkit/src/github.rs` offers a fake gateway with programmable
  pagination, rate limits, revoked-token `401`, and lockout `403`, and is used
  by at least one test outside this crate.
