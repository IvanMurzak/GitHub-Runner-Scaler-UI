---
id: "c5-scale-set-message-protocol"
title: "Scale-set message session: long poll, demand, AcquireJobs, acknowledgement, JIT generation, and contract tests"
group: "C"
sequence: 5
repo: "."
depends_on: ["c4-actions-service-admin"]
importance: 10
complexity: 9
security_critical: false
production_touching: false
model_hint: "top"
taskflow_refs: ["04-subsystem-contracts.md", "03-control-flows.md", "01-current-architecture.md", "06-migration-rollout.md"]
---

## Goal

Build the second half of `ScaleSetGateway`: the message session that carries
demand into the product and the JIT endpoint that turns demand into a runner.
This is the part of the design with the least documentation and the most ways
to be subtly wrong, so it is specified by behaviour and pinned by contract
tests rather than by shape.

## Scope & seams

Owns `crates/github/src/scaleset/session.rs`.

**Session lifecycle.** Create a message session against a scale set; refresh
its **message-queue access token**, which is independent of `c4`'s admin token
and has its own refresh path; close cleanly on drain.

**Long poll.** Send the agent's `max_capacity` as the `X-ScaleSetMaxCapacity`
header. Decode `statistics.TotalAssignedJobs` as the aggregate demand signal —
demand is that aggregate, **not** a count of individual messages
(`github.com/actions/scaleset@main:README.md:40-79`). Counting messages instead
produces a plausible number that is wrong under exactly the conditions that
matter.

**Acquisition is mandatory and ordered.** Every `JobAvailable` message must be
answered with `AcquireJobs`, carrying the message's runner-request identifiers,
**before** capacity is reconciled. GitHub cancels and requeues an unacquired
assignment up to three times with incremental delays and then stalls
(`01-current-architecture.md`, edge case 6). Expose this ordering in the API
shape so a caller cannot reconcile first by accident.

**Acknowledgement.** `DeleteMessage` acknowledges a processed message, and the
last processed message id is passed to the next `GetMessage`. An acknowledged
message must never be replayed as a fresh capacity count after a reconnect
(`03-control-flows.md`, flow 3.4) — that is how an offline blip turns into
duplicate runners.

**JIT generation.**
`POST {actions_service_url}/_apis/runtime/runnerscalesets/{scale_set_id}/generatejitconfig`
with request body `{name, workFolder}` and nothing else. The encoded result is
sensitive and short-lived: return it as a value the caller must consume, never
persist it here, never log it, never include it in an error body.

**Fail-closed decoding.** Unknown *critical* fields fail the decode rather than
being ignored. The protocol is Public Preview and will drift
(`01-current-architecture.md`, edge case 4); a decoder that shrugs at an
unrecognised field will happily start runners on a changed contract.

**Revision pinning.** Pin the protocol revision `c1` recorded, and honour
`ScalePolicy.protocol_flag` so a single policy can be pinned to a
known-compatible revision or disabled if the preview protocol drifts.

## Definition of Done

- Contract tests run against the pinned revision and cover: demand decoding,
  `JobAvailable` to `AcquireJobs`, `DeleteMessage` acknowledgement, session
  token refresh, and JIT generation.
- Demand is asserted to come from `statistics.TotalAssignedJobs`; a fixture with
  three messages and a `TotalAssignedJobs` of one yields one, not three.
- Reconciling before acquiring is impossible through the public API — proven by
  a test, not by a comment.
- A reconnect after acknowledgement does not re-deliver the acknowledged
  message as new demand; the last-processed id is carried into the next poll.
- An unknown critical field fails the decode; an unknown non-critical field
  does not.
- A session-token expiry mid-poll refreshes and resumes without dropping a
  message.
- The JIT response is absent from every log, error body, and debug
  representation; a secret-injection scan over a full generate cycle finds no
  encoded configuration.
- `protocol_flag` pinning and disabling are both exercised.
