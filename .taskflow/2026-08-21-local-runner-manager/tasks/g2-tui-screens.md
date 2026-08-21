---
id: "g2-tui-screens"
title: "Dashboard, Repositories, Runners, and Activity screens with accessible loading, empty, offline, and rate-limited states"
group: "G"
sequence: 2
repo: "."
depends_on: ["g1-tui-shell-input", "c3-rest-inventory-gateway"]
importance: 8
complexity: 6
security_critical: false
production_touching: false
model_hint: "mid"
taskflow_refs: ["02-target-architecture.md", "08-user-workflows.md", "03-control-flows.md", "04-subsystem-contracts.md"]
---

## Goal

Deliver every read-only screen (Journeys 2 and 4). All four are one task: they
share one table component, one state vocabulary, and one snapshot harness, and
splitting them would mean writing that three more times.

## Scope & seams

Owns `crates/app/src/tui/screens.rs`. Reads the in-memory snapshot only; the
agent refreshes it independently on a bounded interval, and long-poll demand
continues while the TUI is closed.

| Screen | Content | Interactions |
|---|---|---|
| Dashboard | Total in-progress workflows, assigned jobs, online/busy runners, host capacity used/total, health | `Tab`, arrows, mouse click, `F5` |
| Repositories | Authorized targets, each row showing `(in-progress workflow count)`, scale state, `max_capacity`, agent health | Select, type-to-filter, enter detail |
| Runners | All authorized GitHub runners with owner, OS, labels, online/busy/ephemeral state | Sort, filter, inspect |
| Activity and errors | Lifecycle events, retries, rate limits, cleanup outcome, remediation | Copy-safe diagnostics, acknowledge |

**Numbers that are not the same number.** In-progress workflow count, assigned
jobs, and busy runners are three distinct aggregates. Render them distinctly;
conflating them is the most likely way this screen misleads an operator.

**Ownership and mode are visible.** Locally owned runners are **visually
distinct** from external ones, and legacy persistent runners appear through
GitHub inventory clearly marked external — the product displays them and never
starts, stops, or relabels them (`06-migration-rollout.md`). A `MonitorOnly`
policy is visually distinct from an autoscaling one in **every** screen that
lists policies (D19).

**Offline (Journey 4).** The offline condition is discoverable from every
screen in **one action** and is never presented as zero workload or a
successful scale-down. The error panel identifies the last successful GitHub
contact, the retry delay, the local remediation, and a warning that GitHub
cancels queued jobs after 24 hours — stated, not implied.

**Distinct states.** Loading, empty, unauthorized, rate-limited, and offline
each have their own content and an actionable command. Rate limiting is
displayed, never hidden.

**Table behaviour.** Focus, selected row, sort order, and scroll position
survive a refresh where the selected item still exists. Type-to-filter reaches
any row in one additional action regardless of list length.

## Definition of Done

- Snapshot tests for all four screens in loading, populated, empty,
  unauthorized, rate-limited, and offline states.
- Dashboard-to-repository detail takes at most **3 keyboard actions or 2 mouse
  actions**, excluding intra-list row navigation; asserted by counting.
- Type-to-filter reaches an arbitrary repository in one additional action with a
  long list.
- In-progress workflow count, assigned jobs, and busy runners are rendered as
  three distinct values and are asserted to differ in a fixture where they do.
- Locally owned runners, external runners, and monitor-only policies are each
  distinguishable **without colour** — asserted on a colourless render.
- The offline state is reachable in one action from each of the four screens
  and states the 24-hour queue-cancellation bound verbatim.
- A refresh preserves focus, selected row, sort order, and scroll position when
  the selected item still exists, and degrades predictably when it does not.
- Diagnostics in the activity panel are copy-safe and contain no credential.
