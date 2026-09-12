---
id: "c2-wsl-tui-collection"
title: "Collect cached WSL supervisor status without session pressure"
group: "C"
sequence: 2
repo: "."
base_branch: "main"
depends_on: ["b5-wsl-task-migration-status", "c1-wsl-tui-model-render"]
importance: 2
complexity: 6
security_critical: false
production_touching: false
model_hint: "mid"
taskflow_refs: ["05-tui-status-ux.md"]
---

## Goal

Feed Windows TUI from durable supervisor snapshots without multiplying WSL
commands.

## Scope & seams

Extend the event-source collection/cancellation generation. Read all provider
snapshots locally; allow one bounded fallback capability/list query only when
no provider exists.

## Definition of Done

- Two concurrent TUIs do not increase managed-distribution probe frequency.
- Stale/slow/cancelled state retains last data and renders truthfully.
- GitHub refresh remains independent and responsive.

