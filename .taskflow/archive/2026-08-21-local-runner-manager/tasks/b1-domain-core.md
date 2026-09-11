---
id: "b1-domain-core"
title: "Domain model, both state machines, PolicyMode and capacity invariants, routing-label derivation and matching, ownership and precedence, testkit clock and fixtures"
group: "B"
sequence: 1
repo: "."
depends_on: ["a1-workspace-ci-foundation"]
importance: 10
complexity: 8
security_critical: false
production_touching: false
model_hint: "top"
taskflow_refs: ["04-subsystem-contracts.md", "02-target-architecture.md", "03-control-flows.md", "01-current-architecture.md"]
---

## Goal

Build the deterministic core every other crate is measured against: the model
types, the two state machines, the routing-label rules that replace the
scale-set name after D4, and the invariants that make an incorrect
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
`PolicyState`, `CachePolicy`.

D4 removed `scale_set_id`, `scale_set_name`, and `protocol_flag` from this
model. Do not reintroduce them under another name. `routing_labels:
Option<NonEmpty<Label>>` is the routing token, and it is a **non-empty set**
rather than a single value because a JIT runner may carry several labels where
a scale set carried one.

**`PolicyMode` as an enforced invariant, not a convention (D19).**
`MonitorOnly` requires `routing_labels` and `max_capacity` both `None`;
`Autoscale` requires both `Some`. A write violating either shape is rejected
here, in the domain, so an autoscale policy with no capacity ceiling or no
routing label cannot be constructed — including by `b2` when loading a
hand-edited database. Prefer a representation where the illegal combination
cannot be built at all over one that is merely validated on the way in.

**`ScaleTarget` equivalence (D18).** Repository and organization targets differ
only in which GitHub endpoint and which App permission the gateway later uses.
Ownership, capacity, lifecycle, and precedence rules are identical, and the
tests must assert that equivalence directly rather than duplicating cases.

**Routing labels (D4).** Two rules live here, and together they are the whole
of the product's routing identity:

1. **Derivation.** From the operator's `--host-label`, the host OS, and the
   host architecture, derive the default label in the shape
   `02-target-architecture.md` gives — `rm-home-win-x64`. The default is
   **host-scoped by construction**, which matters more than it looks: with no
   `AcquireJobs` there is no job reservation, and a host-scoped label is the
   only control that stops two hosts from starting a runner for the same queued
   job (`01-current-architecture.md`, edge case 6). Optional descriptive labels
   may be added to the set; the derived host label may not be dropped from it.
2. **Matching.** Given a queued job's `runs-on`, decide whether this policy
   should serve it. GitHub assigns a job to a runner whose label set is a
   **superset** of the job's required labels, so the predicate is: the job's
   required label set is a subset of this policy's `routing_labels`. Handle
   every documented `runs-on` form — a single string, an array of labels, and
   the `group`/`labels` map — and treat a `runs-on` that cannot be resolved
   statically (an expression such as `${{ … }}`) as **not** demand, reported as
   unresolvable rather than silently counted or silently dropped.

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

**The surplus attempt is a normal outcome, not a failure.** Because demand is
advisory, a started runner may find no work and exit on its idle timeout
(`03-control-flows.md`, flow 2.7). That attempt is terminal and cleaned like
any other, but it must carry an outcome distinguishing "ran a job" from
"exited idle without work". Model that distinction here, not in the renderer:
`g2` and the activity log must show an idle exit differently from a failure,
and they can only do that if the domain records which one happened.

**Capacity math (D7, D9).**

```text
demand        = queued jobs whose required labels match this policy's routing labels
desired       = clamp(demand, min_capacity, max_capacity)
host_headroom = host_capacity - active_owned_runners_all_policies
to_start      = max(0, min(desired - active_owned_runners, host_headroom))
```

`min_capacity <= max_capacity` is validated on every `Autoscale` write, so the
clamp is always well-defined; `min_capacity` is fixed at 0 in v1. Express the
host ceiling as a first-class allocator over all policies, not as a check a
caller may forget.

The `- active_owned_runners` term is load-bearing under REST demand in a way it
was not under scale sets: the same job stays `queued` across consecutive polls
while its runner is starting, so a formula that ignores attempts already in
flight starts a fresh runner on every poll until the job is finally picked up.

**Ownership and precedence** (`04-subsystem-contracts.md`): a policy's
`host_id` and its host-scoped `routing_labels` determine ownership; a
`MonitorOnly` policy owns nothing and can never be the reason a runner starts;
an agent may act only on attempts under its own `host_id`; a user-requested
disable beats demand; `max_capacity` beats reported demand and `host_capacity`
beats `max_capacity`.

**Testkit**: a controllable fake clock and fixture builders for hosts,
policies, and attempts, usable by groups C, E, F, and G. Do not touch
`crates/testkit/src/github.rs` — group C owns it.

## Definition of Done

- Every `AttemptState` and `PolicyState` transition is tested in both
  directions: each legal transition succeeds, each illegal one is rejected.
- `PolicyMode` shape invariants are tested in both directions for both modes,
  including the rejection of an `Autoscale` policy with `max_capacity: None`
  and of one with `routing_labels: None`.
- Repository and organization targets are proven equivalent by a shared test
  body, not by two copies of the same assertions.
- Label derivation produces a host-scoped default that differs between two
  hosts given the same target; the derived label cannot be removed from the
  set, while optional labels can.
- Label matching is tested as a table over every `runs-on` form — string,
  array, and `group`/`labels` map — with cases that must match, cases that must
  not, and an unresolvable expression reported as unresolvable rather than
  counted or dropped.
- Capacity math is tested including: the host ceiling binding across two or
  more policies, `desired` clamping above and below, zero headroom, headroom
  smaller than the per-policy allowance, and **the same queued job present on
  two consecutive polls yielding one attempt, not two**.
- An attempt that exits idle without work reaches a terminal state carrying an
  outcome distinguishable from a failure.
- Disable-during-demand yields draining, and a `busy` attempt cannot be cleaned.
- An attempt belonging to another `host_id` is rejected.
- Recovery decisions are tested against the fake clock with no real time
  dependency; the crate has no I/O dependency in `Cargo.toml`'s used set.
