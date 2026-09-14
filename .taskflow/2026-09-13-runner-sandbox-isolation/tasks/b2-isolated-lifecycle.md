---
id: "b2-isolated-lifecycle"
title: "Crash-safe isolated environment lifecycle"
group: "B"
sequence: 2
repo: "."
base_branch: "main"
depends_on: ["b1-execution-domain-provider", "a2-routing-reconcile"]
importance: 10
complexity: 10
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["02-target-architecture.md", "04-security-recovery.md"]
---

## Goal

Prepare, start, supervise, recover and destroy one isolated environment per JIT
attempt without native fallback or duplicate ownership.

## Scope & seams

Implement durable prepare/environment transitions, pre-JIT capability/image
resolution, one-time handoff abstraction, capacity accounting, stop/destroy and
startup orphan reconciliation. Use fake providers for exhaustive crash points.

## Definition of Done

- Provider readiness precedes JIT; every failure remains profile-local and native never starts.
- Kill-at-every-transition tests adopt/destroy exactly one owned environment.
- Terminal environments retain capacity until confirmed absent.
- Generation+attempt ownership prevents deleting unrelated resources.
- Diagnostics are typed, bounded and redacted; lifecycle suites pass.

