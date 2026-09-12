---
id: "a3-daemon-reload-contract"
title: "Separate daemon reload, upgrade and failure exits"
group: "A"
sequence: 3
repo: "."
base_branch: "main"
depends_on: ["a2-supervisor-core"]
importance: 3
complexity: 6
security_critical: false
production_touching: true
model_hint: "top"
taskflow_refs: ["03-windows-service-lifecycle.md"]
---

## Goal

Make planned drain/reload a first-class supervisor protocol rather than a Task
Scheduler failure.

## Scope & seams

Change `cli/daemon.rs` exit classification and hand-off payload, preserving
indefinite drain for active attempts. Update CLI exit-code accountability and
tests without overwriting the operator's existing edits in this file.

## Definition of Done

- Policy-set reload and binary upgrade have distinct machine-readable exits.
- Both wait for every owned attempt; unexpected loop failure remains failure.
- Supervisor restarts the right committed binary/configuration.
- Repeated policy changes do not exhaust an external restart count.

