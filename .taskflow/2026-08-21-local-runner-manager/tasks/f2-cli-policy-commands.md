---
id: "f2-cli-policy-commands"
title: "repo and org command families: non-arming add, monitor-only mode, capacity, set-scale, drain and remove"
group: "F"
sequence: 2
repo: "."
depends_on: ["f1-cli-auth-host-status", "c4-actions-service-admin"]
importance: 9
complexity: 7
security_critical: false
production_touching: false
model_hint: "mid"
taskflow_refs: ["02-target-architecture.md", "03-control-flows.md", "08-user-workflows.md", "04-subsystem-contracts.md", "07-security.md"]
---

## Goal

Deliver the primary, automation-safe configuration surface (D18, D19, D20). CLI
is the source of configuration truth: the TUI later dispatches these same
commands, so any validation that lives only in a form is a validation that does
not exist.

## Scope & seams

Owns `crates/app/src/cli/policy.rs`. Implements both families over one domain
path — the repository and organization variants differ only in which endpoint
and permission the gateway uses (`b1` target equivalence), and must not become
two parallel implementations:

```text
repo add OWNER/REPO --host-label HOST [--max-capacity N]
repo list | repo set-capacity | repo set-scale --enabled BOOL | repo remove [--purge]
org  add ORG --host-label HOST [--max-capacity N]
org  list | org set-capacity | org set-scale --enabled BOOL | org remove [--purge]
```

**`add` never arms a host (D20).** It creates the policy in `pending` and never
enables scaling. Enabling is an explicit `set-scale`. The cost is one extra
command in Journey 1 and it is deliberate.

**`add` validation** (`03-control-flows.md`, flow 1, step 4): confirm the
target is installed for the App; validate host OS/architecture against the
supported matrix and warn that ARM64 is public preview; validate
`min_capacity <= max_capacity`; create or resolve the host-owned scale set at
the policy's scope; write one local transaction. Refuse a configuration whose
projected hourly request budget would exceed half the documented floor (`c3`).
Print the scale-set name to put in `runs-on`, and the next command. Never echo
a secret.

**Monitor-only (D19).** Omitting `--max-capacity` creates a `MonitorOnly`
policy: no scale set is created, the command stops after recording the target,
and the output states plainly that no runner will ever be started for it — and
repeats the `Administration: Read and write` disclosure, because a
dashboard-only user is the one least likely to expect a write grant (D21).
`set-capacity` later promotes the policy to `Autoscale`.

**Scope advice.** Where both scopes are possible, say that organization scope
operates under the narrower `Organization → Self-hosted runners` grant and is
the safer choice (`07-security.md`).

**Fork warning.** Warn on policy enablement that fork and untrusted
pull-request workflows must not be enabled on a personal host until the operator
explicitly accepts the trust boundary.

**Disable and remove** (`03-control-flows.md`, flow 5). `set-scale --enabled
false` asks for explicit confirmation when active runners exist, moves the
policy to `draining`, states "draining" with the count of active runners, and
never promises immediate termination. Deleting requires an explicit `--purge`;
disabling never deletes cache or historical diagnostics.

**Failure states.** A missing installation, a duplicate policy, an invalid
capacity, an inverted `min`/`max` pair, or an unavailable GitHub API leaves no
active policy. A partially created remote scale set is recorded as
`repair_required` and the command prints an explicit repair operation rather
than silently retrying a destructive deletion.

## Definition of Done

- `repo add` and `org add` are covered by one shared test body proving target
  equivalence, not two copies.
- `add` leaves the policy `pending` and scaling disabled in every case,
  including with `--max-capacity`.
- `add` with no `--max-capacity` creates a `MonitorOnly` policy, creates no
  scale set, states that no runner will start, and repeats the permission
  disclosure. `set-capacity` promotes it to `Autoscale` and the round trip is
  asserted.
- Each failure case — missing installation, duplicate, invalid capacity,
  inverted `min`/`max`, API unavailable — leaves no active policy and explains
  itself in one screenful with no credential in the output.
- A simulated partial remote creation yields `repair_required` plus a printed
  repair operation, and no delete is attempted.
- A configuration exceeding half the projected rate-limit floor is refused with
  the computed numbers shown.
- Disabling with active runners requires confirmation, reports "draining" with
  the active count, and does not terminate a busy runner.
- `remove` without `--purge` preserves cache and diagnostics; with `--purge` it
  removes them and refuses while an active runner exists.
- The whole flow runs end to end from a script with no interactive prompt other
  than the documented confirmations.
