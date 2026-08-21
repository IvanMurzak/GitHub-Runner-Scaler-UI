---
id: "c4-demand-and-jit-gateway"
title: "REST demand polling and JIT configuration at repository and organization scope, with no job reservation"
group: "C"
sequence: 4
repo: "."
depends_on: ["c3-rest-inventory-gateway", "b1-domain-core", "v1-org-jit-verification"]
importance: 10
complexity: 7
security_critical: true
production_touching: false
model_hint: "top"
taskflow_refs: ["04-subsystem-contracts.md", "02-target-architecture.md", "03-control-flows.md", "07-security.md", "01-current-architecture.md"]
---

## Goal

Deliver the two GitHub operations the autoscaler is built on after D4: read
demand from queued workflow jobs, and obtain a just-in-time configuration for
one ephemeral runner. This task replaces the Actions-service credential chain
and message protocol that the D17 spike disproved
(`docs/spikes/d17-user-to-server-scale-set-chain.md`); it is one task rather
than the two it replaces because both are documented, stable REST against a
host and a credential that already exist.

## Scope & seams

Owns `crates/github/src/{demand,jit}.rs`, and extends `c3`'s fake gateway in
`crates/testkit/src/github.rs` with demand and JIT fixtures.

**Demand** (`04-subsystem-contracts.md`, Read demand). Fetch workflow runs
filtered to `queued`, resolve their jobs, and count the jobs whose `runs-on`
matches the policy's `routing_labels`. The matching predicate itself is `b1`'s
and must not be re-implemented here; this task owns fetching, pagination, and
turning the result into a demand count per policy.

For an **organization** target there is no organization-wide workflow-run
endpoint, so demand is the aggregate over the repositories the App is installed
on in that organization. That is a real cost, not a detail: every added
repository multiplies this policy's share of the shared 5,000 requests/hour
ceiling. Report the per-poll request count to `c3`'s budget model rather than
estimating it there.

**JIT configuration.**

```text
POST /repos/{owner}/{repo}/actions/runners/generate-jitconfig
POST /orgs/{org}/actions/runners/generate-jitconfig
body {name, runner_group_id, labels, work_folder}
 -> 201 {encoded_jit_config, runner{…}}
```

Verified `201` at repository scope on a free personal account with runner group
1, the same permission that is denied scale-set administration. The
organization form is proven by `v1`, which is this task's hard prerequisite —
if `v1` came back RED the organization half of this task does not exist and
D18 is an owner decision, not an implementation choice.

Failure modes are distinct outcomes, not one error: `403` (the permission or
the plan does not allow it — terminal and operator-actionable), `404` (target
or runner group not found), `422` (rejected label set or name). A `403` must
never become a retry loop; the D17 spike is the record of what that response
means and what it does not.

**The JIT blob is the one short-lived secret in the product** (`07-security.md`,
credential inventory). Return it in a wrapper type whose `Debug` and `Display`
redact, which does not serialise, and which zeroises on drop. This crate never
writes it to disk and never puts it in an error message; the restrictive
handoff is `d1`'s primitive and `e3`'s job.

**There is no job reservation, and nothing here may pretend otherwise.**
`AcquireJobs` has no REST equivalent, so demand is advisory: another host may
take a job this host has already started a runner for
(`01-current-architecture.md`, edge case 6). Do not add a claim, a lease, or a
local reservation table to compensate — the bounding controls are host-scoped
labels and the two capacity ceilings, and they live in `b1` and `e1`.

## Definition of Done

- A queued-runs plus jobs fixture yields the correct demand count, with a
  `runs-on` table covering forms that must match, forms that must not, and an
  unresolvable expression, delegating the predicate to `b1`.
- Pagination is exercised for both queued runs and jobs; a truncated first page
  never reads as low demand.
- An organization target aggregates demand across its installed repositories,
  and its reported per-poll request count grows with that repository count.
- `generate-jitconfig` sends exactly the documented body shape and decodes a
  `201` into the encoded configuration plus the runner reference, at repository
  scope and at organization scope, under one shared test body.
- `403`, `404`, and `422` each produce a distinct outcome; `403` is terminal
  and carries an operator action, and no code path retries it.
- The JIT blob is absent from `Debug` output, from `Display`, from any error
  value, from serialisation, and from a log scan over the full request path;
  its wrapper zeroises on drop.
- No reservation, claim, lease, or acknowledgement call exists anywhere in the
  crate, asserted by review and named in the crate documentation so a later
  reader does not add one.
- The fake gateway offers programmable queued-run, job, and `generate-jitconfig`
  responses including each failure mode, and is used by an `e1` test.
