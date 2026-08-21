---
id: "g3-tui-settings-parity"
title: "Host and policy settings screens dispatching the same domain commands as the CLI, with parity tests"
group: "G"
sequence: 3
repo: "."
depends_on: ["g2-tui-screens", "f2-cli-policy-commands"]
importance: 8
complexity: 6
security_critical: false
production_touching: false
model_hint: "mid"
taskflow_refs: ["08-user-workflows.md", "02-target-architecture.md", "04-subsystem-contracts.md", "03-control-flows.md"]
---

## Goal

Deliver Journey 3 — change both capacity limits and arm or drain a policy from
the TUI — while proving the property that keeps this product coherent: the TUI
creates **no second configuration path**. It dispatches `f2`'s commands and
`f1`'s host commands, and inherits their validation exactly.

## Scope & seams

Owns `crates/app/src/tui/settings.rs`.

**Host settings (`h`).** Show the current `host_capacity` **and** the current
total in use across policies before any edit. Edit and confirm. Show and switch
the service start mode between `boot` and `login` without reinstalling (`d3`),
and set the refresh interval, respecting the 30-second per-repository floor.

**Policy settings (`s`).** Toggle scaling enabled, set `max_capacity`, show the
generated scale-set name and local host identity, set the cache policy, and
give a safe preview before confirming. Both limits always display their current
value before an edit (D9) — an operator must never have to guess what they are
changing from.

**Monitor-only.** A `MonitorOnly` policy shows its mode plainly and offers
promotion by setting `max_capacity`; the screen must not present controls that
do nothing in that mode.

**Disable path** (`03-control-flows.md`, flow 5). At most two confirmations —
the policy confirmation and the active-runner drain confirmation. Disabling with
active work says **draining**, gives the count of active runners, and never
promises immediate termination.

**Fork warning.** Repeat the fork and untrusted-pull-request trust-boundary
warning on enablement, matching `f2`.

**Parity is the deliverable.** Every mutation goes through the same handler the
CLI invokes. A validation that exists in `f2` must be impossible to bypass
here — including the `min <= max` invariant, the `PolicyMode` shape invariant,
the projected rate-limit budget refusal, and the `pending`-on-create rule.

## Definition of Done

- Each settings screen completes its task in at most **5 focused form actions**,
  counted and asserted.
- Both `host_capacity` and `max_capacity` display their current value, and
  `host_capacity` displays the current total in use, before an edit.
- CLI/TUI parity tests assert that the TUI mutation and the equivalent CLI
  command produce byte-identical persisted state, for: host capacity, policy
  capacity, enable, disable, and monitor-only promotion.
- Every `f2` validation rejects the same input from the TUI, including the
  rate-limit budget refusal and the inverted `min`/`max` pair.
- The disable path uses at most two confirmations, reports "draining" with the
  active runner count, and terminates nothing immediately.
- The service start mode switches between `boot` and `login` from this screen
  without a reinstall, and `host show` reflects the change.
- A monitor-only policy shows its mode, offers promotion, and exposes no
  no-op control.
- Settings round-trip through persistence and survive a TUI restart.
