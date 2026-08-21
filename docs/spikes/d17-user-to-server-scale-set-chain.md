# D17 spike — can a user-to-server token drive the Actions-service scale-set chain?

**Status: PARTIAL — 3 of 6 links proven, D3 not yet cleared.**
**Date:** 2026-08-21 · **Task:** [`c1-d17-scale-set-spike`](../../.taskflow/2026-08-21-local-runner-manager/tasks/c1-d17-scale-set-spike.md)

D3 (device flow against one published GitHub App, no server, no client secret,
no private key) rests on an assumption GitHub does not document: that a
**user-to-server** token can drive the whole Actions-service chain. GitHub
documents that chain for installation tokens and for PATs
(`01-current-architecture.md`, edge case 8).

## The finding that changes the shape of the risk

**The Actions service never sees the original credential.** Reading
`actions/scaleset@main:client.go`, the chain is:

```text
user credential ──▶ POST /repos|orgs/…/actions/runners/registration-token
                          │
                          ▼  Authorization: RemoteAuth <registration-token>
                    POST https://api.github.com/actions/runner-registration
                          │
                          ▼  returns { url: <tenant>, token: <admin JWT> }
                    everything downstream authenticates with that JWT
```

After the registration token is minted, the original credential is gone from
the picture. `/actions/runner-registration` sees only the registration token,
and issues a fresh Actions-service JWT of its own. Scale-set administration,
sessions, `AcquireJobs`, and `generatejitconfig` all authenticate with that JWT
or with the session's message-queue token — never with the user's credential.

So D17 does not really have six independent unknowns. It has **one**: can a
user-to-server token mint a runner registration token? Everything after that is
credential-agnostic by construction, and that property is now verified rather
than assumed.

## What was proven empirically

Run 2026-08-21 against `IvanMurzak/GitHub-Runner-Scaler-UI` using the GitHub
CLI's OAuth **user** token (`gho_`, scopes `gist, read:org, repo, workflow`).
This is not the target token family, but it is a user-type token rather than a
PAT or an installation token, which is the distinction that matters here.

| Link | Result | Evidence |
|---|---|---|
| 2 — mint registration token, repo scope | **GREEN** | `POST /repos/…/actions/runners/registration-token` → `200`, token `ACFW…`, len 29 |
| 3 — `RemoteAuth` exchange | **GREEN** | `POST /actions/runner-registration` → `200`, returned `url`, `token`, `token_schema` |
| 4 — admin token reaches the tenant | **GREEN (read-only)** | `GET {tenant}_apis/runtime/runnerscalesets?api-version=6.0-preview` → `200 {"count":0,"value":[]}`; also `_apis/connectionData` → `200`, `deploymentType: hosted` |

Facts recovered from the admin JWT, all load-bearing for `c4`:

| Property | Observed value | Consequence |
|---|---|---|
| `token_schema` | `OAuthAccessToken` | The service labels the schema it derived the JWT from; a user-type credential is an accepted input. |
| `scp` | `ActionsRuntime.RunnerManage Framework.GenericRead Identity.ReadRefs LocationService.Connect` | Exactly the scale-set administration capability set. |
| `nbf` → `exp` | **20 minutes** | `04-subsystem-contracts.md` says refresh 60 s before expiry. The real budget is 20 min, so refresh cadence is ~19 min, not hourly. |
| `owner_id` | `R_kgDO…` (Repository node id) | The JWT is scoped to the target, not to the user. |
| tenant URL | `https://pipelinesghubeus25.actions.githubusercontent.com/<guid>/` | Per-tenant host; not `api.github.com`. Confirms the two-host split. |
| `api-version` | `6.0-preview` and `6.0-preview.1` both accepted | Pin `6.0-preview`; `c5` records this as the pinned revision. |

## What is still open

| Link | State | Why it is not yet answered |
|---|---|---|
| 1 — device flow → `ghu_` token | **UNTESTED** | Needs a registered App with device flow enabled. Well documented and low risk, but untested. |
| 2 — **`ghu_` at link 2** | **UNTESTED — this is the real D17 question** | `gho_` (OAuth App) and `ghu_` (GitHub App user-to-server) are different token families. GitHub's REST reference lists *GitHub App user access tokens* as supported for this endpoint with `Administration: write`, but the docs are not proof. |
| 2 — organization scope | **UNTESTED** | The `gh` token lacks `admin:org`, so all three visible orgs returned `403 "You must be an org admin or have the runners and runner groups fine-grained permission"`. That is a **scope** limitation of the OAuth token, not a token-family result — a GitHub App uses permissions (`Organization → Self-hosted runners: Read and write`), not OAuth scopes, so this says nothing either way about D18. |
| 4 — create/delete a scale set | **UNTESTED** | State-changing; deliberately not run against a real repository. |
| 5 — session, demand, `AcquireJobs`, `DeleteMessage` | **UNTESTED** | Needs a scale set and a queued job. |
| 6 — `generatejitconfig` | **UNTESTED** | Needs a scale set. |

## How to finish it

[`d17-spike.ps1`](d17-spike.ps1) runs all six links end to end, prints no
credential, and deletes the scale set and session it creates:

```powershell
pwsh ./docs/spikes/d17-spike.ps1 -ClientId Iv23xxxxxxxx -Repo owner/disposable-repo -Org disposable-org
```

It asserts the token family is `ghu_` and marks the run AMBER if it is not, so
a run that accidentally uses the wrong credential cannot be mistaken for a
green D17. Omitting `-Org` marks organization scope AMBER rather than passing
silently.

## Verdict

**Not yet GREEN.** Do not treat D3 as cleared and do not start `c2`.

The residual risk is materially smaller than when D17 was written: the
undocumented, protocol-shaped part of the chain — the `RemoteAuth` exchange and
the tenant handshake — is proven to work from a user-type credential, and is
proven to be blind to which credential minted the registration token. What
remains is one REST call's permission behaviour on one token family, plus the
mechanical confirmation of the scale-set operations.

If the `ghu_` run fails at link 2, the contingency in `07-security.md` — a
per-user GitHub App with installation tokens from a locally held private key —
is the only known alternative, and reopening D3 is an owner decision, not this
task's.
