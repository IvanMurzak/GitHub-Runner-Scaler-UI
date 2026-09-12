---
id: "a1-windows-launcher-spike"
title: "Prove a no-console stable launcher and Task Scheduler lifecycle"
group: "A"
sequence: 1
repo: "."
base_branch: "main"
depends_on: []
importance: 3
complexity: 6
security_critical: false
production_touching: true
model_hint: "top"
taskflow_refs: ["03-windows-service-lifecycle.md", "ROADMAP.md#G4"]
---

## Goal

Prove the executable/subsystem, process-tree and task XML design on real
Windows before production integration.

## Scope & seams

Add an example/test-only GUI-subsystem launcher under `crates/platform`, extend
privileged scheduled-task fixtures, and document versioned image selection and
stop propagation. Do not change production registration yet.

## Definition of Done

- A real login task starts without creating a console window.
- The stable launcher starts, observes and restarts versioned console children.
- Stop and non-zero child exit behavior are proven through Task Scheduler.
- Microsoft `Hidden` semantics are not treated as console suppression.

