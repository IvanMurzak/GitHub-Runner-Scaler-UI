---
id: "a2-routing-reconcile"
title: "Unambiguous profile demand routing and target budget"
group: "A"
sequence: 2
repo: "."
base_branch: "main"
depends_on: ["a1-profile-domain-store"]
importance: 9
complexity: 7
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["01-current-architecture.md", "05-routing-profiles.md"]
---

## Goal

Make static `runs-on` selectors route a queued job to at most one profile while
retaining one GitHub poll and one request-budget charge per target.

## Scope & seams

Extend `RoutingLabels` matching, reconciliation tally/diagnostics, daemon target
groups and budget projection. Preserve current explicit handling of unresolvable
expressions. Add multi-profile native/isolated model tests.

## Definition of Done

- Matching requires the profile selector; optional labels cannot substitute.
- Missing, multiple or overlapping selectors launch nothing and emit remedies.
- Native and isolated jobs in one target produce one allocation each.
- Equal targets are polled/charged once; capacities remain per policy and host-wide.
- Reconcile/daemon/budget tests pass without weakening existing routing tests.

