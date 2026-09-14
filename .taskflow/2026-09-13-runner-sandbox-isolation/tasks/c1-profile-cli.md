---
id: "c1-profile-cli"
title: "Complete profile and execution CLI"
group: "C"
sequence: 1
repo: "."
base_branch: "main"
depends_on: ["a2-routing-reconcile", "b1-execution-domain-provider"]
importance: 8
complexity: 7
security_critical: false
production_touching: true
model_hint: "top"
taskflow_refs: ["02-target-architecture.md", "05-routing-profiles.md"]
---

## Goal

Expose creation, mutation, draining/removal and inspection of every runner
profile/execution field without ambiguous target selection.

## Scope & seams

Add `repo profile` commands and shared handlers; keep legacy single-profile
commands. Add host provider preflight/status JSON. Fence mutations by selected
PolicyId and preserve explicit confirmation/remedies.

## Definition of Done

- CLI controls profile labels/capacity/workspace/execution/backend/image/resources.
- Omitted profile works only for exactly one match; otherwise lists corrected commands.
- `repo add` creates `default`; destructive operations affect no sibling.
- Static-selector and trusted-workflow warnings are visible/copyable.
- Command accountability, chain corpus, snapshots and JSON schema tests pass.

