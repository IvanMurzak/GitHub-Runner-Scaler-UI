---
id: "a4-service-install-start"
title: "Make Windows login service install hidden and immediately running"
group: "A"
sequence: 4
repo: "."
base_branch: "main"
depends_on: ["a3-daemon-reload-contract"]
importance: 3
complexity: 7
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["03-windows-service-lifecycle.md", "ROADMAP.md#G4"]
---

## Goal

Converge `service install --start-at login` to a hidden, running supervised
daemon in the current login session.

## Scope & seams

Update owned-copy staging, service record, task action/read-back, immediate
start/wait and rollback. Preserve `InteractiveToken`, `LeastPrivilege`, DPAPI
scope and boot/SCM behavior.

## Definition of Done

- Successful install returns only after task and daemon heartbeat are current.
- No console appears and no shell intermediary is registered.
- Failed start restores or clearly reports the prior working registration.
- Reinstall, uninstall, mode switch and privileged Windows tests pass.

