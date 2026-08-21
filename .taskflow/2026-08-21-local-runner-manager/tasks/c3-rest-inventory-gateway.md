---
id: "c3-rest-inventory-gateway"
title: "REST inventory: paginated runners, in-progress workflow counts, runner downloads, rate limits, shared request budget, and the testkit fake gateway"
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
`c2`'s authenticated client; adds no second auth path. Demand polling and JIT
configuration are `c4`, and they consume this task's budget accounting.

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

**The shared request budget (D4 consequence).** Under scale sets, demand
arrived over a long poll that did not touch this budget. It does now, and that
makes the budget a product constraint rather than an implementation detail:
demand, runner inventory, and in-progress counts draw on **one** ceiling of
5,000 requests/hour. Own the budget model here, because this is the layer that
sees every request:

- Account for all three request classes, at roughly 240 requests per target per
  hour at the 60-second default and 480 at the 30-second floor
  (`04-subsystem-contracts.md`).
- An **organization** target's demand and activity cost scales with the number
  of repositories the App is installed on there, because workflow runs are a
  per-repository resource. Project an organization target from its installed
  repository count, not as a flat per-target constant, or the projection will
  understate the real cost by exactly that factor.
- Expose the projection for a candidate interval and target set, so `f2`'s
  `repo add` and `org add` can refuse a configuration that would exceed **half**
  the floor, and so `f1`'s `host show` and `g3`'s host settings can display the
  remaining headroom and the resulting maximum target count.

`sha256_checksum` being optional in GitHub's schema is a fact this layer must
pass through faithfully — as an optional value, never as an empty string or a
default. Task `e2` fails closed on its absence, and it can only do that if this
layer does not paper over it.

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
- The projected hourly budget is computed for a given interval and target set
  and asserted against the documented ceiling, including a case that shows an
  organization target with N installed repositories costing materially more
  than a repository target.
- The projection reproduces the documented figures: roughly 10 targets per host
  at the 60-second default and 5 at the 30-second floor.
- `crates/testkit/src/github.rs` offers a fake gateway with programmable
  pagination, rate limits, revoked-token `401`, and lockout `403`, and is used
  by at least one test outside this crate.
