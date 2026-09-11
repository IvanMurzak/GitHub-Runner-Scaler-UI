---
id: "f2-cli-policy-commands"
title: "repo and org command families: non-arming add, monitor-only mode, routing labels, budget refusal, capacity, set-scale, drain and remove"
group: "F"
sequence: 2
repo: "."
depends_on: ["f1-cli-auth-host-status"]
importance: 9
complexity: 6
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

**`add` creates nothing remotely (D4).** This is the change that most reduces
this task's risk relative to the scale-set design: there is no remote object to
create at add time, so the partial-creation failure mode is gone entirely
(`03-control-flows.md`, flow 1.4). `repair_required` survives only for a policy
whose **local** transaction is inconsistent, and the command still prints an
explicit repair operation rather than silently retrying anything destructive.

**`add` validation** (`03-control-flows.md`, flow 1, step 4), all local or
read-only:

1. Confirm the target is installed for the App.
2. Validate host OS and architecture against the supported matrix (`d1`) and
   warn that ARM64 is public preview; surface that container actions and
   service containers require Linux when the host is macOS or Windows.
3. Validate `min_capacity <= max_capacity`.
4. Derive the host-scoped routing label (`b1`) and print it, so the operator can
   put it in `runs-on`.
5. Check the projected hourly REST budget (`c3`) and **refuse** a configuration
   that would exceed half the 5,000 requests/hour floor, showing the computed
   numbers and the resulting maximum target count. An operator who adds an
   eleventh repository needs to know why it was refused
   (`04-subsystem-contracts.md`). For an organization target the projection
   scales with its installed repository count, so the refusal can arrive
   earlier than a repository target would suggest — say so in the message.
6. Write one local transaction, then print the next command.

Never echo a secret.

**Two hosts, one label.** The printed label is host-scoped by construction
because there is no job reservation: two hosts given the same label will both
start runners for the same queued job, and the surplus one exits having wasted
a slot (`01-current-architecture.md`, edge case 6). If the operator overrides
the derived label with one already recorded for another host, say what that
means rather than silently accepting it.

**Monitor-only (D19).** Omitting `--max-capacity` creates a `MonitorOnly`
policy: no routing label is reserved, the command stops after recording the
target, and the output states plainly that no runner will ever be started for
it — and repeats the `Administration: Read and write` disclosure, because a
dashboard-only user is the one least likely to expect a write grant (D21).
`set-capacity` later promotes the policy to `Autoscale`, which is also when its
routing label is derived.

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
capacity, an inverted `min`/`max` pair, a budget refusal, or an unavailable
GitHub API leaves no active policy and explains itself in one screenful.

## Definition of Done

- `repo add` and `org add` are covered by one shared test body proving target
  equivalence, not two copies.
- `add` leaves the policy `pending` and scaling disabled in every case,
  including with `--max-capacity`.
- `add` makes no state-changing GitHub request — asserted against the fake
  gateway, which fails the test if one is issued.
- `add` prints the derived routing label, and the label differs for the same
  target added from two different `--host-label` values.
- `add` with no `--max-capacity` creates a `MonitorOnly` policy, reserves no
  routing label, states that no runner will start, and repeats the permission
  disclosure. `set-capacity` promotes it to `Autoscale`, derives its label, and
  the round trip is asserted.
- A configuration exceeding half the projected rate-limit floor is refused with
  the computed numbers and the maximum target count shown, for a repository
  target and for an organization target whose installed repository count is
  what pushes it over.
- Each failure case — missing installation, duplicate, invalid capacity,
  inverted `min`/`max`, API unavailable — leaves no active policy and explains
  itself in one screenful with no credential in the output.
- An inconsistent local transaction yields `repair_required` plus a printed
  repair operation, and no delete is attempted.
- Disabling with active runners requires confirmation, reports "draining" with
  the active count, and does not terminate a busy runner.
- `remove` without `--purge` preserves cache and diagnostics; with `--purge` it
  removes them and refuses while an active runner exists.
- The whole flow runs end to end from a script with no interactive prompt other
  than the documented confirmations.
