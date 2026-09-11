---
id: "e1-reconciliation-capacity"
title: "Reconciliation loop: REST demand polling, two-level capacity allocation, monitor-only skip, budget-aware interval, offline backoff"
group: "E"
sequence: 1
repo: "."
depends_on: ["b1-domain-core", "c4-demand-and-jit-gateway", "d1-platform-core"]
importance: 10
complexity: 8
security_critical: false
production_touching: false
model_hint: "top"
taskflow_refs: ["03-control-flows.md", "02-target-architecture.md", "04-subsystem-contracts.md", "01-current-architecture.md"]
---

## Goal

Drive the loop that turns GitHub demand into a decision to start runners — and
that refuses to start them when it should not. Every ceiling in this product is
enforced here, so a defect in this task is a defect that oversubscribes a
person's home machine.

## Scope & seams

Owns `crates/agent/src/reconcile.rs`. Defines the `RunnerLauncher` port that
`e3` implements, so the decision logic is testable with no process, no
filesystem, and no network.

**Order of operations, per `03-control-flows.md` flow 2.** On every demand
refresh, for each `Autoscale` policy in `active`:

```text
demand        = queued jobs whose runs-on matches this policy's routing labels
desired       = clamp(demand, min_capacity, max_capacity)
host_headroom = host_capacity - active_owned_runners_all_policies
to_start      = max(0, min(desired - active_owned_runners, host_headroom))
```

**There is no acquisition step, and this task must not invent one.** The
scale-set model called `AcquireJobs` to reserve an assignment before scaling;
the REST path has no equivalent (`01-current-architecture.md`, edge case 6).
Demand is advisory. Two consequences are load-bearing here:

1. **A surplus runner is an accepted outcome, not a bug to engineer around.**
   Another host serving the same labels may take the job first; this host's
   runner then finds no work and exits on its idle timeout, having cost one
   capacity slot and one cold start. Treat that terminal outcome as normal and
   distinct from a failure (`b1`), and do not add a claim, a lease, or a local
   reservation to prevent it.
2. **The same job is still `queued` on the next poll** while its runner starts.
   The `- active_owned_runners` term is what stops that from starting a second
   runner, and then a third. This is the single most likely way this task goes
   wrong, and it is silent when it does — the user sees runaway runners, not an
   error.

**Two ceilings, one allocator (D9).** `max_capacity` beats reported demand and
`host_capacity` beats `max_capacity`. Take the host-wide allocation lock (`d1`)
before creating each runtime, so the sum of active attempts across **all**
policies on this machine can never exceed `Host.host_capacity`. A per-policy
check alone cannot stop N policies from jointly oversubscribing one host.

**Monitor-only (D19).** A `MonitorOnly` policy is skipped entirely by
reconciliation. It owns no routing labels, takes no part in demand, and can
never be the reason a runner starts — assert this rather than relying on its
`max_capacity` being absent.

**Never scale down a busy runner.** Scale-down removes nothing that is
executing a job; capacity is reclaimed only when an attempt reaches a terminal
state.

**Budget-aware polling (D4 consequence).** Demand shares one 5,000
requests/hour ceiling with inventory and workflow counts
(`04-subsystem-contracts.md`). Poll on a bounded interval, default 60 seconds,
with a hard floor of 30 seconds per target. Honour the rate-limit signals `c3`
surfaces by increasing the delay and reporting it, never by hiding it, and
never by dropping below the floor to catch up.

**Offline (`03-control-flows.md` flow 3.3).** When GitHub is unreachable: start
no new runner, retain existing runner processes, report `offline`, and back off
with jitter. The offline state carries the fact that GitHub cancels queued jobs
after 24 hours, so a prolonged outage loses queued work — that bound is stated,
not implied. Recovery needs no bookkeeping: demand is recomputed from the
current queued-job set on every poll rather than accumulated from a message
stream, so a reconnect cannot double-count work.

**Emit lifecycle events** for the activity view (`g2`) and the local log sink,
carrying no credential.

## Definition of Done

- No reservation, claim, lease, or acquisition call exists in the crate; a test
  or review note records that this is deliberate rather than missing.
- A job that remains `queued` across three consecutive polls while its attempt
  is `starting` yields exactly **one** attempt — the test fails if the
  in-flight term is dropped from the formula.
- Capacity math is tested at the boundaries: demand above `max_capacity`,
  demand below `min_capacity`, zero host headroom, and headroom smaller than
  the per-policy allowance.
- Two policies on one host with `host_capacity` smaller than the sum of their
  `max_capacity` values never exceed `host_capacity` under concurrent
  reconciliation — asserted under simulated lock contention, with no duplicate
  runners.
- A `MonitorOnly` policy under maximum demand starts zero runners and issues no
  demand request.
- A surplus attempt that receives no job reaches a terminal state recorded as an
  idle exit, is cleaned, and is not reported as a failure.
- A scale-down request with a busy attempt removes nothing and leaves the
  attempt `busy`.
- The poll interval respects the 30-second floor and the 60-second default,
  increases under a rate-limit signal, and the increase is visible in emitted
  state rather than silent.
- An unreachable GitHub yields `offline`, zero new runners, retained existing
  processes, and jittered backoff; recovery resumes polling and does not
  double-count a job that was already being served.
- The idle-host assertion holds: no demand means zero runner processes and zero
  attempts out of terminal state.
- No emitted event contains a token, a JIT blob, or a credential header.
