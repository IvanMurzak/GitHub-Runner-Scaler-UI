---
id: "b1-domain-core"
title: "Domain model, both state machines, PolicyMode and capacity invariants, ownership and precedence, testkit clock and fixtures"
group: "B"
sequence: 1
repo: "."
depends_on: ["a1-workspace-ci-foundation"]
importance: 10
complexity: 8
security_critical: false
production_touching: false
model_hint: "top"
taskflow_refs: ["04-subsystem-contracts.md", "02-target-architecture.md", "03-control-flows.md"]
---

## Goal

Build the deterministic core every other crate is measured against: the model
types, the two state machines, and the invariants that make an incorrect
configuration **unrepresentable** rather than merely discouraged. This is the
one place in the product where correctness is fully testable without a network,
a filesystem, or a clock, and it should stay that way.

## Scope & seams

Owns `crates/domain/src/{model,policy,attempt,capacity}.rs` and
`crates/testkit/src/{clock,fixtures}.rs`. Pure logic only: no I/O, no rusqlite
(that is `b2`), no HTTP.

**Types**, exactly as specified in `04-subsystem-contracts.md`: `Host`,
`ScalePolicy`, `ScaleTarget = Repository(OwnerRepo) | Organization(Org)`,
`PolicyMode = MonitorOnly | Autoscale`, `RunnerAttempt`, `AttemptState`,
`PolicyState`, `ProtocolCompat`, `CachePolicy`.

**`PolicyMode` as an enforced invariant, not a convention (D19).**
`MonitorOnly` requires `scale_set_id`, `scale_set_name`, and `max_capacity` all
`None`; `Autoscale` requires all three `Some`. A write violating either shape is
rejected here, in the domain, so an autoscale policy with no capacity ceiling
cannot be constructed — including by `b2` when loading a hand-edited database.
Prefer a representation where the illegal combination cannot be built at all
over one that is merely validated on the way in.

**`ScaleTarget` equivalence (D18).** Repository and organization targets differ
only in which GitHub endpoint and which App permission the gateway later uses.
Ownership, capacity, lifecycle, and precedence rules are identical, and the
tests must assert that equivalence directly rather than duplicating cases.

**State machines**, with every transition outside the diagram rejected:

```text
AttemptState: allocated -> jit_received -> starting -> idle | busy
              idle | busy -> finished | failed | orphaned
              finished | failed | orphaned -> cleaned
PolicyState:  pending -> active | repair_required
              active  -> draining -> disabled
              any     -> authentication_failed
```

`idle` means registered and awaiting its single assignment — it is not an idle
persistent runner. Only terminal attempts may be cleaned; `busy` must never
reach cleanup because of a scale-down request. `enabled` records operator
intent and `state` records observed lifecycle; both are independent fields.

**Capacity math (D7, D9).**

```text
desired       = clamp(total_assigned_jobs, min_capacity, max_capacity)
host_headroom = host_capacity - active_owned_runners_all_policies
to_start      = max(0, min(desired - active_owned_runners, host_headroom))
```

`min_capacity <= max_capacity` is validated on every `Autoscale` write, so the
clamp is always well-defined; `min_capacity` is fixed at 0 in v1. Express the
host ceiling as a first-class allocator over all policies, not as a check a
caller may forget.

**Ownership and precedence** (`04-subsystem-contracts.md`): a policy's
`host_id` plus unique scale-set name determine ownership; a `MonitorOnly`
policy owns nothing and can never be the reason a runner starts; an agent may
act only on attempts under its own `host_id`; a user-requested disable beats
demand; `max_capacity` beats reported demand and `host_capacity` beats
`max_capacity`.

**Testkit**: a controllable fake clock and fixture builders for hosts,
policies, and attempts, usable by groups C, E, F, and G. Do not touch
`crates/testkit/src/github.rs` — group C owns it.

## Definition of Done

- Every `AttemptState` and `PolicyState` transition is tested in both
  directions: each legal transition succeeds, each illegal one is rejected.
- `PolicyMode` shape invariants are tested in both directions for both modes,
  including the rejection of an `Autoscale` policy with `max_capacity: None`.
- Repository and organization targets are proven equivalent by a shared test
  body, not by two copies of the same assertions.
- Capacity math is tested including: the host ceiling binding across two or
  more policies, `desired` clamping above and below, zero headroom, and the
  `min <= max` rejection.
- Disable-during-demand yields draining, and a `busy` attempt cannot be cleaned.
- An attempt belonging to another `host_id` is rejected.
- Recovery decisions are tested against the fake clock with no real time
  dependency; the crate has no I/O dependency in `Cargo.toml`'s used set.
