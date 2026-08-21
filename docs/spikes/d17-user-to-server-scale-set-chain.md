# D17 spike — can a user-to-server token drive the Actions-service scale-set chain?

**Status: D17 answered GREEN — and a separate, larger blocker found at link 4.**
**Date:** 2026-08-21 · **Task:** [`c1-d17-scale-set-spike`](../../.taskflow/2026-08-21-local-runner-manager/tasks/c1-d17-scale-set-spike.md)

Two independent results. They must not be conflated.

1. **The D17 question is settled: yes.** A GitHub App user-to-server token
   (`ghu_`) mints a runner registration token and completes the
   Actions-service admin exchange. D3 is not reversed by anything found here.
2. **Scale-set *creation* is denied on this target, for every credential type
   tried.** This is not D17 and not a permissions mistake. It blocks D4 and the
   product's primary persona, and it needs an owner decision.

## 1. D17: GREEN

Run 2026-08-21, published-flow App `runner-manager-d17-spike`
(`client_id Iv23li39jMQVdEuupmI2`), device flow, against
`IvanMurzak/GitHub-Runner-Scaler-UI`.

| Link | Result | Evidence |
|---|---|---|
| 1 — device flow → user token | **GREEN** | token family `ghu_` — a genuine App user-to-server token, not an OAuth or PAT credential. `authorization_pending` observed and handled. |
| 2 — mint registration token, repo scope | **GREEN** | `200`, token length 29 |
| 3 — `RemoteAuth` exchange | **GREEN** | `200`; tenant `pipelinesghubeus25…`; `token_schema OAuthAccessToken`; `scp ActionsRuntime.RunnerManage Framework.GenericRead Identity.ReadRefs LocationService.Connect`; TTL **20 min** |

This confirms the structural finding from `actions/scaleset@main:client.go`:
the Actions service never sees the original credential. Once the registration
token exists, `/actions/runner-registration` issues its own JWT and everything
downstream authenticates with that. The `ghu_` and `gho_` runs produced
**byte-identical** scope sets and the same service identity, which is the
strongest possible form of this evidence.

**Consequence:** D3 stands. `c2` is unblocked *with respect to D17*.

## 2. The blocker: scale-set creation is denied

```text
POST {tenant}_apis/runtime/runnerscalesets?api-version=6.0-preview
  → 403 AccessDeniedException
    "Access denied. System:ServiceIdentity;DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD
     needs Administer Permissions permissions to perform the action."
```

### What has been ruled out

| Suspected cause | Ruled out by |
|---|---|
| The user-to-server token is weaker than an installation token or PAT | The `gho_` (OAuth user) token, minted independently via the `gh` CLI, produces the **identical** error, the identical `scp`, and the identical service identity. The failure is credential-type-independent. |
| Wrong or missing App permission | GitHub documents repository scope as requiring exactly `Administration: Read and write` + `Metadata: Read-only`. The App declares both. |
| Repository scope is unsupported | GitHub documents repository scope as a supported ARC configuration: `Administration: Read and write` is "only required when configuring Actions Runner Controller to register at the repository scope". |
| Invalid `runnerGroupId` | `GET _apis/runtime/runnergroups` returns `200` with `id 1 "Default" isDefaultGroup:true` and `id 2 "GitHub Actions"`. Group 1 exists and was the one requested. |
| Malformed request body | Body matches `actions/scaleset` `RunnerScaleSet` exactly, including the capitalised `RunnerSetting` json tag. A malformed body would return a validation error, not `AccessDeniedException`. |
| Expired admin token | The token was minted seconds earlier and has a 20-minute TTL. Read calls with the same token return `200`. |

### The surviving hypothesis

**The target is a repository owned by a personal account.**
`IvanMurzak/GitHub-Runner-Scaler-UI` has `owner.type: User`, and the account
has `plan: null`. Runner *groups* are an organization feature — GitHub's own
wording is "Organization owners using the GitHub Team plan can create
additional organization-level runner groups" — and a scale set is created
inside a runner group. The service identity coming back as the placeholder
`DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD` rather than a real GUID is consistent
with an identity that was never bound to an administrable group.

This is a hypothesis, not a conclusion. It has not been tested.

### The one experiment that settles it

Install the App on an organization the owner administers and re-run with
`-Org`. Available: `Tap-Top-Fun` and `WetFish-Co`, both `role=admin`, both
`plan=free`.

| Outcome | Meaning | Cost to the taskflow |
|---|---|---|
| Org **free** succeeds | Repository scope on a *personal account* is the blocker. | D18 inverts: organization scope becomes the only viable path, not the safer optional one. Journey 1 (`repo add`) stops being the primary journey. |
| Org **free** also fails | Scale sets require GitHub Team or Enterprise. | D4 fails for the entire target audience. The home-host persona in `08-user-workflows.md` has neither. Autoscaling would need a different primitive, and that reopens the architecture, not a decision. |

## 3. What this does and does not change

- **D3 / D17: no change.** The device flow, the published-App model, and the
  serverless design are all confirmed working end to end.
- **D4 (scale sets + JIT ephemeral): at risk**, pending the org test.
- **D18 (both scopes supported): at risk of inverting.** The design currently
  presents repository scope as primary and organization scope as the safer
  option; the evidence points the other way.
- **`08-user-workflows.md` persona: at risk.** A home-host operator with
  personal repositories is precisely the case that just failed.

## 4. Corrections already earned for `c4` / `c5`

Independent of the blocker, the run produced facts the design should absorb:

| Fact | Where it lands |
|---|---|
| Actions-service admin JWT lives **20 minutes** | `04-subsystem-contracts.md` says refresh 60 s before expiry — correct, but the cadence is ~19 min, worth stating. |
| `api-version=6.0-preview` accepted (also `6.0-preview.1`) | `c5`'s pinned protocol revision. |
| `scp` is `ActionsRuntime.RunnerManage Framework.GenericRead Identity.ReadRefs LocationService.Connect` | `c4` contract test can assert this. |
| Tenant is a per-owner `pipelinesghubeus*` host, not `api.github.com` | Confirms the two-host split in `04-subsystem-contracts.md`. |
| `GET _apis/runtime/runnergroups` works read-only | `c4` should resolve the group by name rather than assume id 1, as ARC does. |

## 5. Verdict

**D17: GREEN. Do not reopen D3.**

**Do not start `c4`/`c5`/`e1`** until the organization test resolves whether
scale sets can be created at all for this audience. That is a product
question, not an implementation one, and it belongs to the owner.

Nothing was left behind on the repository: creation failed, so no scale set
exists to clean up, and the cleanup path re-mints its own admin token before
deleting.
