---
id: "a2-fence-failure-visibility"
title: "Expose permanent fence failures"
group: "A"
sequence: 2
repo: "."
base_branch: "main"
depends_on: ["a1-wsl-fence-service-access"]
importance: 3
complexity: 5
security_critical: true
production_touching: false
model_hint: "mid"
taskflow_refs: ["02-target-architecture.md"]
---

## Goal

Stop reporting configured-fence I/O failures as invisible ordinary contention.

## Scope & seams

Give allocation-lock refusal a closed reason, retain fail-closed behavior, log
actionable non-secret failure, and make positive-demand repeated deferral
available to readiness diagnostics.

## Definition of Done

- Contention and configuration/I/O failure remain behaviorally fail-closed but
  are distinguishable in events/tests.
- Positive demand plus fence I/O failure emits a warning naming the fence class.
- No path can bypass an active Windows recovery fence.
- Secret-log scans remain green.
