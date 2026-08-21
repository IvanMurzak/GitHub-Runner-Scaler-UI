# D18 organization-scope `generate-jitconfig` — result

**GREEN. `POST /orgs/{org}/actions/runners/generate-jitconfig` returns `201`,
on the narrow organization permission the design plans to ship.**
**Date:** 2026-08-21 · **Task:** [`v1-org-jit-verification`](../../.taskflow/2026-08-21-local-runner-manager/tasks/v1-org-jit-verification.md)

The D17 spike proved the **repository** form and explicitly did not reach the
organization form, so everything D18 promises at organization scope rested on
the assumption that `/orgs/` behaves like `/repos/`
([`d17-user-to-server-scale-set-chain.md`](d17-user-to-server-scale-set-chain.md),
section 5). That assumption is now tested. It holds.

The stop-the-line rule was **not** triggered: the call was not denied, so
nothing was worked around.

## Resources used — a human must delete these

Nothing here was deleted by the spike, and nothing here should be deleted by a
machine. Both survive this task by owner instruction.

| Resource | Identifier | Note |
|---|---|---|
| Throwaway GitHub App | **`runner-manager-d17-spike`** (`Iv23li39jMQVdEuupmI2`) | Device flow enabled. Shared with the D17 spike. |
| Disposable organization | **`Tap-Top-Fun`** | Free plan. Org installation id `155426287`. |
| Personal installation of the same App | account `IvanMurzak`, installation id `155419555` | Not exercised by this spike; listed for completeness. |

The spike created and deleted **four ephemeral runners** and **one runner
group**. It deleted no organization, no repository and no App.

## Method

Device flow to a `ghu_` user-to-server token, then the call under test —
the method proven in [`d17-spike.ps1`](d17-spike.ps1), reused unchanged.

| Round | Script | Purpose |
|---|---|---|
| 1 | [`d18-org-jit-spike.ps1`](d18-org-jit-spike.ps1) | The four points the task enumerates. |
| 2 | [`d18-org-jit-probe2.ps1`](d18-org-jit-probe2.ps1) | Turn two round-1 assertions into evidence: non-`1` group ids, and label semantics. |
| 3 | [`d18-app-permissions.ps1`](d18-app-permissions.ps1) | Read-only. **Which** permission authorized the `201`. |

Each round is a separate device-flow authorization; the token is held in memory
and never written to disk.

---

## Point 1 — the call returns `201`

```text
POST https://api.github.com/orgs/Tap-Top-Fun/actions/runners/generate-jitconfig
Authorization: Bearer ghu_<redacted>
X-GitHub-Api-Version: 2022-11-28

{"name":"rm-d18-spike-ivanpc-1753","runner_group_id":1,
 "labels":["rm-d18-spike","windows","x64","self-hosted-rm"],"work_folder":"_work"}

  -> 201 Created
```

Decisive response fields:

| Field | Value |
|---|---|
| top-level keys | `runner`, `encoded_jit_config` — exactly two |
| `runner.id` | `73` |
| `runner.name` | `rm-d18-spike-ivanpc-1753` |
| `runner.runner_group_id` | `1` |
| `runner.busy` | `false` |
| `runner.status` | `offline` |
| `runner.os` | `windows` |
| `runner.version` | `2.336.0` |
| `encoded_jit_config` | 4088 characters, **not recorded** |

The response shape is **identical to the repository form** — same two top-level
keys, same `runner` object. `c4` can deserialize one type for both scopes.

### The permission that authorized it

This is what makes the verdict transferable to the published App. `07-security.md`
plans to ship the narrow `Organization → Self-hosted runners: Read and write`.
The organization installation actually holds:

```text
GET /user/installations
  -> 200
  account 'Tap-Top-Fun' (Organization), repository_selection=all
  permissions: actions=read, administration=write, metadata=read,
               organization_self_hosted_runners=write
```

**`organization_self_hosted_runners=write` is present and
`organization_administration` is absent.** The `201` was therefore not riding a
broader organization grant. The `administration=write` also present is the
*repository* permission and cannot authorize an `/orgs/` endpoint.

`07-security.md` line 56 can drop its "**Unverified**" marker as written — the
permission it names is the one that was exercised.

## Point 2 — which `runner_group_id` is usable

**Group `1` is usable, it is this organization's default, and it must be
discovered rather than hardcoded.**

```text
GET /orgs/Tap-Top-Fun/actions/runner-groups
  -> 200  total_count 1
     id=1 name='Default' default=true visibility=all
```

The differential, which is what makes "group 1 is usable" a finding rather than
a restatement:

| `runner_group_id` sent | Response | Meaning for `c4` |
|---|---|---|
| `1` (the default) | **`201`** | usable |
| `3` (created for this test, **not** default, **not** 1) | **`201`**, `runner.runner_group_id` = `3` | **any administrable group id works — the value 1 is not special** |
| `2` | `403 Forbidden` | exists but is not administrable (the GitHub-hosted group; matches D17's `403 GitHub hosted runner groups cannot be modified`) |
| `99999` | `404 Not Found` | does not exist |
| omitted | `422` `Invalid input: object is missing required key: runner_group_id` | **the field is required** |

Two consequences `c4` must implement against:

1. **`runner_group_id` is mandatory** at organization scope. There is no
   server-side default, so the gateway must resolve a group id before it can
   register anything.
2. **An unusable group id yields `403` *or* `404` depending on why.** Error
   handling keyed on `404` alone will misreport the hosted-group case.

### On "what the response is when the default group is not 1"

The task asks this because the repository call used group 1 and nothing
established that the organization default matches. On `Tap-Top-Fun` the default
**is** `1`, so a non-`1` *default* could not be observed directly. Rather than
assert the gap away, round 2 created a second group:

```text
POST /orgs/Tap-Top-Fun/actions/runner-groups {"name":"rm-d18-probe-group-5713","visibility":"all"}
  -> 201  id 3  default=false
```

and registered against it successfully. That answers the question behind the
question: **a group id other than `1` is fully usable**, so an organization
whose default is not `1` presents no new failure mode. The group was deleted
(`204`) and the organization is back to a single `Default` group.

Worth flagging: this free organization **could** create an additional runner
group. D17's leading hypothesis — that runner groups are a paid-plan feature —
is not supported for *group creation via public REST* on this account. That
hypothesis was only ever offered to explain scale-set denial and is not
load-bearing for D4 or D18, but it should not be repeated as established fact.

## Point 3 — a multi-label `labels` array is accepted

```text
labels: ["rm-d18-spike","windows","x64","self-hosted-rm"]   -> 201, all four present
labels: ["rm-d18-spike"]                                    -> 201, single label fine
labels: []                                                  -> 422 Invalid property /labels:
                                                                 1 item required; only 0 were supplied
```

Multi-label routing is available, which is what D4's revised design needs. Four
further facts, each of which changes what `f2` and `g3` must document:

1. **No labels are added implicitly.** The `201` carries *exactly* the labels
   requested — no `self-hosted`, no OS, no architecture. A workflow written as
   `runs-on: self-hosted` will **not** match a runner registered without that
   label.
2. **`self-hosted` is accepted as an explicit label.** Sending
   `["self-hosted","rm-d18-spike","Windows","X64"]` returned `201` with all four.
   It is not reserved or rejected. So the fix for (1) is available, and `c4`
   should include the labels a user's `runs-on` will name.
3. **Labels are lowercased.** `Windows` and `X64` came back as `windows` and
   `x64`. `b1`'s `runs-on` matching should compare case-insensitively.
4. **Label order is not preserved**, and every label comes back with
   `type: read-only` (contrast D17's scale-set labels, which were `type: System`).

At least one label is required, so `c4` has no empty-label edge case to handle.

## Point 4 — the runner was deleted and the organization is clean

| Step | Call | Result |
|---|---|---|
| before | `GET /orgs/Tap-Top-Fun/actions/runners` | `200` `total_count 0` |
| during | `GET /orgs/Tap-Top-Fun/actions/runners` | `200` `total_count 1` — `73:rm-d18-spike-ivanpc-1753:offline` |
| delete | `DELETE /orgs/Tap-Top-Fun/actions/runners/73` | **`204`** |
| after | `GET /orgs/Tap-Top-Fun/actions/runners` | `200` `total_count 0` |

Round 2's three additional runners (`74`, `75`, `76`) and the probe runner group
(`3`) were each deleted with `204`. Round 3 re-checked the organization from a
fresh token, read-only:

```text
GET /orgs/Tap-Top-Fun/actions/runners       -> 200 total_count 0
GET /orgs/Tap-Top-Fun/actions/runner-groups -> 200 total_count 1: id=1 'Default' default=true
```

**The organization ends with zero runners and its original single runner group**,
as the D17 spike left the repository. A registered-but-never-started JIT runner
deletes cleanly; no reaping or timeout was needed.

---

## Secret hygiene

No token and no JIT blob is recorded here or anywhere in the repository.

- All three spike scripts route every call through a helper that redacts
  `gh[usop]_…` and any `encoded_jit_config` value before a response body is
  printed; the JIT config is only ever reported as a character count.
- Tokens are held in memory for the life of a run and never written to disk.
- Evidence JSON was written **outside** the repository, to the session
  scratchpad, not to `docs/spikes/`.
- The committed scripts contain the public `client_id` only, which is designed
  to be public in a device flow and is paired with no secret.

## What is still untested

Honest limits of this result:

1. **No job has ever run on an organization-scoped JIT runner.** This proves
   registration, not execution. All four runners were deleted at
   `status: offline`, having never started. `h1`'s live organization-scoped job
   remains the real end-to-end proof.
2. **Whether the runner binary adds default labels at startup** is unknown. The
   `201` adds none, but no runner was launched with one of these configs, so
   point 3's consequence (1) is proven at registration time only.
3. **`runner.os = windows` on a runner that never connected** is presumably a
   default rather than a detected value. Do not treat it as meaningful.
4. **One organization, one plan.** `Tap-Top-Fun` is free-plan with
   `repository_selection=all`. An organization installed against *selected*
   repositories was not tested, and neither was a Team or Enterprise plan.
5. **The demand signal at organization scope** — `GET /orgs/{org}/…` queued-run
   polling — was not exercised. Only the registration endpoint was. The
   observation already raised on the ROADMAP, that an organization target's REST
   cost scales with its installed repository count, is untouched by this spike.

## Impact on the taskflow

No design document was edited by this task; these are the consequences for
whoever does.

| Item | Consequence |
|---|---|
| **D18 organization path** | **Unblocked.** `c4`'s organization code path and `f2`'s `org` command family may proceed. |
| `README.md` D18 row | "**untested**" is now false. |
| `02-target-architecture.md` lines 204, 225–226 | "unverified"/"must be proven before D18's org path is built" — satisfied. |
| `06-migration-rollout.md` lines 21–22, 30, and risk row 106 | The Phase 0 gate is met; the risk did not materialize. |
| `07-security.md` line 56 | Drop "**Unverified**": the narrow `Organization → Self-hosted runners: Read and write` is exactly what authorized the `201`. |
| `ROADMAP.md` human gate 2 | Its evidence precondition — "approve on the evidence from `v1` that organization-scope `generate-jitconfig` works" — is available. |
| `c4-demand-and-jit-gateway` | Gains three hard requirements: resolve `runner_group_id` (mandatory, not defaulted); handle `403` *and* `404` for unusable groups; one response type serves both scopes. |
| `b1-domain-core` | `runs-on` label matching should be case-insensitive. |
| `f2` / `g3` / `08-user-workflows.md` | Must state that `self-hosted` is not implicit and has to be requested explicitly if a workflow's `runs-on` names it. |

## Verdict

**GREEN — close D18's organization question.** The endpoint works, on the
permission the design intends to ship, with multi-label routing and a group id
that need not be `1`. Do not treat it as proof that a job *executes* at
organization scope; that is `h1`'s job.
