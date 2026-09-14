---
id: "c2-profile-tui"
title: "Repository profile navigation and isolation controls in TUI"
group: "C"
sequence: 2
repo: "."
base_branch: "main"
depends_on: ["c1-profile-cli"]
importance: 8
complexity: 8
security_critical: false
production_touching: true
model_hint: "top"
taskflow_refs: ["02-target-architecture.md", "05-routing-profiles.md"]
---

## Goal

Give TUI users parity with all profile CLI operations and diagnostics.

## Scope & seams

Group/indent profiles below repositories; add profile create/select/drain/remove
flows and settings controls for selector, labels, capacity, workspace, execution,
backend, image, resources and capability. Dispatch shared CLI handlers.

## Definition of Done

- Native and isolated sibling profiles are independently selectable/editable.
- Complete `runs-on` and static-selector/trust warnings are visible and copyable.
- Unsupported providers show precise reason/remedy and cannot be saved/enabled incorrectly.
- Keyboard/mouse/focus/compact-width/snapshot tests cover every new element.
- TUI never selects first profile implicitly or exposes secrets/provider raw output.

