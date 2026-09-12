---
id: "c1-wsl-tui-model-render"
title: "Add complete WSL host states to TUI presentation"
group: "C"
sequence: 1
repo: "."
base_branch: "main"
depends_on: ["b3-wsl-recovery-model"]
importance: 2
complexity: 6
security_critical: false
production_touching: false
model_hint: "mid"
taskflow_refs: ["05-tui-status-ux.md"]
---

## Goal

Render the complete WSL state vocabulary without platform access in frame code.

## Scope & seams

Extend immutable snapshots, Dashboard section, detail navigation, tones,
responsive layout and copy-safe activity for every specified state.

## Definition of Done

- All eleven states render with distribution, freshness, attempts and remedy.
- Narrow, no-color, focus/mouse and snapshot tests remain stable.
- Non-Windows presentation invokes no WSL operation.

