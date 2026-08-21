---
id: "e1-reconciliation-capacity"
title: "Reconciliation loop: acquire-before-scale, two-level capacity allocation, monitor-only skip, offline backoff"
group: "E"
sequence: 1
repo: "."
depends_on: ["b1-domain-core", "c5-scale-set-message-protocol", "d1-platform-core"]
importance: 10
complexity: 8
security_critical: false
production_touching: false
model_hint: "top"
taskflow_refs: ["03-control-flows.md", "02-target-architecture.md", "04-subsystem-contracts.md"]
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

**Order of operations, per `03-control-flows.md` flow 2.** On every scale-set
response:

```text
acquire(job_available_messages)                       # mandatory, first
desired       = clamp(total_assigned_jobs, min_capacity, max_capacity)
host_headroom = host_capacity - active_owned_runners_all_policies
to_start      = max(0, min(desired - active_owned_runners, host_headroom))
```

Acquisition comes first and is not conditional on the capacity outcome. An
unacquired assignment is cancelled and requeued by GitHub up to three times and
then stalls, so skipping acquisition because `to_start` is zero would silently
stall the user's queue.

**Two ceilings, one allocator (D9).** `max_capacity` beats reported demand and
`host_capacity` beats `max_capacity`. Take the host-wide allocation lock (`d1`)
before creating each runtime, so the sum of active attempts across **all**
policies on this machine can never exceed `Host.host_capacity`. A per-policy
check alone cannot stop N policies from jointly oversubscribing one host.

**Monitor-only (D19).** A `MonitorOnly` policy is skipped entirely by
reconciliation. It has no scale set, takes no part in demand, and can never be
the reason a runner starts — assert this rather than relying on its
`max_capacity` being absent.

**Never scale down a busy runner.** Scale-down removes nothing that is
executing a job; capacity is reclaimed only when an attempt reaches a terminal
state.

**Offline (`03-control-flows.md` flow 3.3).** When GitHub is unreachable: start
no new JIT runner, retain existing runner processes, report `offline`, and back
off with jitter. The offline state carries the fact that GitHub cancels queued
jobs after 24 hours, so a prolonged outage loses queued work — that bound is
stated, not implied. On recovery, re-establish the credential chain and resume
long polling without replaying an acknowledged message as new demand.

**Emit lifecycle events** for the activity view (`g2`) and the local log sink,
carrying no credential.

## Definition of Done

- `AcquireJobs` is called for every `JobAvailable` message before any capacity
  computation, including when the computation would yield zero — proven by a
  test that fails if the order is swapped.
- Capacity math is tested at the boundaries: demand above `max_capacity`,
  demand below `min_capacity`, zero host headroom, and headroom smaller than
  the per-policy allowance.
- Two policies on one host with `host_capacity` smaller than the sum of their
  `max_capacity` values never exceed `host_capacity` under concurrent
  reconciliation — asserted under simulated lock contention, with no duplicate
  runners.
- A `MonitorOnly` policy under maximum demand starts zero runners and opens no
  session.
- A scale-down request with a busy attempt removes nothing and leaves the
  attempt `busy`.
- An unreachable GitHub yields `offline`, zero new runners, retained existing
  processes, and jittered backoff; recovery resumes polling and does not
  re-count an acknowledged message.
- The idle-host assertion holds: no demand means zero runner processes and zero
  attempts out of terminal state.
- No emitted event contains a token, a JIT blob, or a credential header.
