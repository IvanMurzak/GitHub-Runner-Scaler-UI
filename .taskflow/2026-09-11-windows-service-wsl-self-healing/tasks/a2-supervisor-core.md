---
id: "a2-supervisor-core"
title: "Implement versioned Windows supervisor core and durable state"
group: "A"
sequence: 2
repo: "."
base_branch: "main"
depends_on: ["a1-windows-launcher-spike"]
importance: 3
complexity: 8
security_critical: false
production_touching: true
model_hint: "top"
taskflow_refs: ["02-target-architecture.md", "03-windows-service-lifecycle.md"]
---

## Goal

Ship a no-console stable launcher and reusable supervisor state machine.

## Scope & seams

Add the Windows-only binary target, versioned image manifest, atomic commit,
child creation without console, graceful stop, exit classification, backoff,
circuit breaker, heartbeat and redacted logging. Keep scaling logic in the CLI
child.

## Definition of Done

- Launcher and supervisor build/package beside every Windows CLI artifact.
- A mapped image is never overwritten or removed.
- Reload, upgrade, failure, stop and circuit-open transitions are deterministic
  under a fake clock/process port and real-process smoke test.
- State/diagnostics pass existing secret scans.

