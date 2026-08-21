# D17 spike — result

**D17 is GREEN. D4 is RED. A viable replacement for D4 is proven working.**
**Date:** 2026-08-21 · **Task:** [`c1-d17-scale-set-spike`](../../.taskflow/2026-08-21-local-runner-manager/tasks/c1-d17-scale-set-spike.md)

Three separate results. They must not be conflated.

| # | Result | Consequence |
|---|---|---|
| 1 | A user-to-server token drives the credential chain at **both** scopes | **D3 stands.** D17 answered; no contingency needed. |
| 2 | Scale-set **creation** is denied on every target this account can reach | **D4 fails.** Not a permissions or credential problem. |
| 3 | Public REST JIT ephemeral runners work on the same free account | **A replacement architecture exists and is proven.** |

## 1. D17: GREEN at both scopes

Device flow with `runner-manager-d17-spike` (`Iv23li39jMQVdEuupmI2`).

| Link | repo scope | org scope (`Tap-Top-Fun`) |
|---|---|---|
| 1 — device flow → `ghu_` | **GREEN** | — |
| 2 — mint registration token | **GREEN** | **GREEN** |
| 3 — `RemoteAuth` → admin token | **GREEN**, tenant `…ghubeus25` | **GREEN**, tenant `…ghubeus3` |

Both scopes returned `token_schema OAuthAccessToken`, identical
`scp ActionsRuntime.RunnerManage Framework.GenericRead Identity.ReadRefs LocationService.Connect`,
and a **20-minute** TTL. The `ghu_` and `gho_` runs were byte-identical in scope
and identity, confirming the structural finding from
`actions/scaleset@main:client.go`: once the registration token exists, the
Actions service never sees the original credential.

**D3 is not reopened. The device-flow, published-App, serverless design works.**

## 2. D4: scale-set creation is denied

```text
POST {tenant}_apis/runtime/runnerscalesets?api-version=6.0-preview
  → 403 AccessDeniedException
    "System:ServiceIdentity;DDDDDDDD-… needs Administer Permissions"
```

Reproduced on **four** independent combinations — personal repo and free
organization, each with a `ghu_` and a `gho_` credential — with the identical
error string and the identical placeholder identity.

### The request shape is correct, proven by differential response

| Variant | Response | What it proves |
|---|---|---|
| `runnerGroupId: 1` + labels + `RunnerSetting` | `403` needs Administer Permissions | the ARC-shaped request reaches group authorization |
| no `runnerGroupId` | `404 No runner group found with identifier 0` | the service resolves the group; the field is required and ours was valid |
| `name` only | `404` identifier 0 | same |
| `api-version=6.0-preview.1` | `403` identical | not a protocol-version issue |
| `runnerGroupId: 2` (GitHub Actions) | `403 GitHub hosted runner groups cannot be modified` | **a different, group-specific error** — the service is fully processing the request and denying at the permission check, not rejecting it as malformed |

`GET _apis/runtime/runnergroups` returns `200` with
`id 1 "Default" isDefaultGroup:true`. Reads succeed; administration is denied.

### Also ruled out

Wrong App permission (GitHub documents repo scope as needing exactly
`Administration: Read and write` + `Metadata: Read-only`, both declared);
unsupported scope (documented as supported); token expiry (20-minute TTL, reads
with the same token succeed).

### Leading explanation, undocumented

Every target available to this account is on a **free** plan
(`owner.type User, plan null`; `Tap-Top-Fun plan=free`). Runner groups are an
organization feature — "Organization owners using the GitHub Team plan can
create additional organization-level runner groups" — and a scale set is
created *inside* a runner group. The placeholder service identity is consistent
with an identity never bound to an administrable group.

**Neither GitHub's documentation nor the ARC documentation states a plan
requirement for runner scale sets.** This explanation fits every observation
but is not confirmed. Confirming it needs a GitHub Team organization, which
this account does not have.

## 3. The replacement: public REST JIT ephemeral runners — proven working

```text
POST /repos/{owner}/{repo}/actions/runners/generate-jitconfig
  body {"name","runner_group_id":1,"labels":[…],"work_folder":"_work"}
  → 201 Created   runner id 2, encoded_jit_config (4112 chars)
```

On the **same personal free account**, the **same `Administration: write`
permission**, and the **same runner group 1** that refuses scale-set
administration. Deleted cleanly afterwards; zero runners remain.

The distinction is exact: **registering a runner into a group is permitted;
administering the group is not.** Scale sets require the latter. JIT ephemeral
runners require only the former.

`01-current-architecture.md` edge case 5 correctly says this endpoint cannot
serve a *scale set*. That objection is now moot, because the scale set is what
has to go.

### What the replacement costs and gains

| | Scale sets (D4, unavailable) | Public REST JIT (available) |
|---|---|---|
| Demand signal | `statistics.TotalAssignedJobs` from a long poll | poll `GET /actions/runs?status=queued` and job-level detail |
| Job assignment | `AcquireJobs` reserves the job for this host | none — a job may be taken by any matching runner |
| Routing | scale-set **name**, single label | **labels**, and multi-label works here |
| Latency | push-ish (long poll) | bounded by the poll interval |
| Rate limit | separate from REST | consumes the REST budget already modelled in `04-subsystem-contracts.md` |
| Protocol risk | Public Preview, needs pinning, contract tests, `protocol_flag` | documented stable REST |
| Works on free plans | **no** | **yes** |

The loss that matters is `AcquireJobs`. Without it, two hosts can start a
runner for the same queued job. Mitigations — a host-scoped label, the existing
`max_capacity` and `host_capacity` ceilings, and accepting that a surplus
ephemeral runner simply exits — are a design question, not a spike question.

## 4. Impact on the taskflow

Owner decision required. This is not an implementation detail.

| Item | Status |
|---|---|
| D3, D16, D17 | **Unaffected.** Confirmed working. |
| **D4** (scale sets + JIT) | **Fails.** Must be replaced by public REST JIT ephemeral runners. |
| **D18** (both scopes) | Survives in the new shape — `/orgs/{org}/actions/runners/generate-jitconfig` is the org equivalent, **untested** (the `gh` token lacks `admin:org`). |
| `01-current-architecture.md` edge cases 4, 5, 6 | Edge case 5's conclusion inverts; 4 and 6 (preview protocol, `AcquireJobs`) become moot. |
| `04-subsystem-contracts.md` Actions-service rows | Removed; `ScalePolicy.protocol_flag`, `scale_set_id`, `scale_set_name` all lose their meaning. |
| Task **`c4`** | Mostly deleted — only the credential chain survives, and only if anything still needs it. |
| Task **`c5`** | **Deleted entirely.** No message protocol, no `AcquireJobs`, no contract tests, no revision pinning. |
| Task **`e1`** | Reconciliation rewritten against a REST demand signal. |
| Tasks `f2`, `g3`, `08-user-workflows.md` | "scale-set name in `runs-on`" becomes "labels in `runs-on`" throughout. |

The product gets **simpler**: the highest-complexity task in the taskflow
(`c5`, complexity 9) disappears, and with it the public-preview protocol drift
risk that `06-migration-rollout.md` lists as its top technical risk.

## 5. What is still untested

- Organization-scope `generate-jitconfig` (needs `admin:org`, or a device-flow
  run extended to call it).
- A real job actually executing on a JIT ephemeral runner end to end.
- Whether a GitHub Team organization would in fact permit scale-set creation —
  i.e. whether the plan hypothesis is right. This matters only if the owner
  wants to keep D4 for paid-plan users.

## 6. Verdict

**D17: GREEN — close it.**
**D4: RED — reopen it.** Do not start `c4`, `c5`, or `e1`; `c5` should probably
not exist. Route the D4 replacement through `/taskflow-review` before any
further task work.

Nothing was left behind: 0 scale sets and 0 registered runners on the
repository, and the probe runner was deleted.
