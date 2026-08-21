---
id: "c4-actions-service-admin"
title: "Actions-service credential chain and scale-set administration at repository and organization scope"
group: "C"
sequence: 4
repo: "."
depends_on: ["c2-device-flow-auth"]
importance: 10
complexity: 8
security_critical: true
production_touching: false
model_hint: "top"
taskflow_refs: ["04-subsystem-contracts.md", "03-control-flows.md", "07-security.md", "01-current-architecture.md"]
---

## Goal

Build the first half of `ScaleSetGateway`: the two-stage credential chain that
reaches the Actions service, and scale-set administration on top of it, at both
scopes (D18). This is a different host, a different auth model, and a different
versioning scheme from `api.github.com`, and conflating the two is the single
easiest way to get this subsystem wrong.

## Scope & seams

Owns `crates/github/src/scaleset/{mod,auth}.rs`. Implements against the
protocol revision the `c1` spike observed and recorded.

**Two hosts, not one.** `api.github.com` serves inventory (`c3`). The Actions
service tenant — `_apis/runtime/runnerscalesets` — serves scale-set operations.
They have different authentication, different versioning, and different
rate-limit semantics. The Actions-service adapter uses the service's own
`api-version` and is **not** covered by REST rate-limit headers, so `c3`'s
rate-limit handling must not be reused here as if it applied.

**Credential chain** (`03-control-flows.md`, flow 4.2). Two stages, both
memory-only:

1. The user token mints a **runner registration token** — consumed immediately
   in the registration exchange, never persisted, never logged.
2. The registration exchange yields an **Actions-service admin token and tenant
   URL**, refreshed 60 seconds before expiry. A leak grants scale-set
   administration for the token's full lifetime, so it is redacted from all
   logs and from error bodies, which is where such values usually escape.

**Scale-set administration.** Create, resolve, update, and delete a scale set
for one host at the policy's scope, and read its ownership metadata. The scale
set's **name** is the routing token a workflow targets with `runs-on`; it
encodes product, host identity, and host OS — for example `rm-home-win-x64` —
and must be unique within its runner group. Scale sets carry a single label and
multi-label support is feature-flagged on GHES, so routing identity lives in
the name, never in a label set. Additional labels are optional metadata only.

**Scope difference.** Repository scope operates under
`Administration: Read and write`; organization scope under the narrower
`Organization → Self-hosted runners: Read and write`, which confers no ability
to delete, rename, or transfer anything. Expose that difference to callers so
`f2` can tell the operator that organization scope is the safer choice where
both are possible (`07-security.md`).

**Partial creation.** A scale set created remotely while the local transaction
fails must be reportable as `repair_required` with an explicit repair
operation. Never resolve a partial state by silently retrying a destructive
delete (`03-control-flows.md`, flow 1).

**Isolation.** No TUI, CLI, domain, or platform module may deserialize a wire
message from this protocol. Everything crossing the boundary is a domain type.

## Definition of Done

- The full chain — user token to registration token to admin token and tenant
  URL — is tested against fixtures, including a mid-flight expiry that triggers
  refresh at the 60-second boundary and not later.
- Registration token, admin token, and tenant credentials are memory-only:
  a test asserts none reaches SQLite, configuration, logs, or an error body,
  including the error path where a request fails with a body echoing headers.
- Scale-set create, resolve, update, and delete are tested at repository scope
  and at organization scope, sharing one test body, proving the target
  equivalence `b1` defines.
- A duplicate scale-set name within a runner group is rejected with a
  distinguishable error, not a silent overwrite.
- A simulated failure after remote creation yields `repair_required` plus a
  concrete repair instruction, and performs no delete.
- The generated scale-set name encodes product, host identity, and host OS, and
  is stable across runs for the same host and policy.
- No public type in this module exposes a wire-format struct.
