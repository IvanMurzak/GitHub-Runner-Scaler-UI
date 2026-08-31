---
id: "e1-workspace-tui"
title: "Edit runner roots and repository workspaces in TUI"
group: "E"
sequence: 1
repo: "."
base_branch: "main"
depends_on: ["c2-persistent-slot-allocation", "d1-workspace-cli-read-models"]
importance: 9
complexity: 9
security_critical: true
production_touching: false
model_hint: "top"
taskflow_refs: ["02-target-architecture.md", "04-security-recovery.md", "05-user-workflows.md"]
---

## Goal

Let an operator inspect, edit, validate, reset, and save the same host and
repository workspace settings from the terminal dashboard.

## Scope & seams

- Add Host Settings controls for effective runner root, source, edit, paste,
  reset, inline validation, refusal preview, and save.
- Add Repository Settings controls for ephemeral or persistent mode, conditional
  path editing, effective path, active and cleanup-blocked slot leases, trust
  warning, and retained-directory notice.
- Render organization workspace mode as ephemeral with an explanation that
  persistence requires repository scope.
- Reuse the CLI mutation handlers and typed errors. Do not duplicate path or
  active-attempt policy in widgets.
- Implement keyboard and mouse focus plus full text editing, bracketed paste,
  horizontal scrolling, cancel, accept, and compact-terminal behavior.
- Keep current value, validation error, and save action visible in constrained
  layouts; never enumerate workspace file names.

## Definition of Done

- TUI and CLI save byte-identical stored values and render the same refusal
  reason for every validation fixture.
- Saved values survive context recreation, daemon restart, and screen reload.
- Path fields support typing, Backspace, Delete, Home, End, arrows, paste,
  Escape, Enter, copy, mouse focus, and horizontal scrolling.
- Reset clears only the host override; returning a repository to ephemeral
  leaves old slot directories untouched and says so.
- Snapshots cover default, configured, persistent, invalid, active refusal,
  cleanup-blocked refusal, warning, and compact terminal states.
- TUI unit, interaction, snapshot, accessibility, and secret-output tests pass.
