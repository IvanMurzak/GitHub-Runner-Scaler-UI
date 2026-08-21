---
id: "c1-d17-scale-set-spike"
title: "D17 spike: prove a user-to-server token drives the full Actions-service scale-set chain"
group: "C"
sequence: 1
repo: "."
depends_on: ["a1-workspace-ci-foundation"]
importance: 10
complexity: 8
security_critical: true
production_touching: false
model_hint: "top"
taskflow_refs: ["01-current-architecture.md", "07-security.md", "06-migration-rollout.md"]
---

## Goal

Answer the one unresolved technical question in this taskflow before any
authentication code is written (D17). D3 — device flow against a single
published App, no server, no client secret, no private key — rests on an
assumption GitHub does not document: that a **user-to-server** token can drive
the entire Actions-service chain. GitHub documents that chain for installation
tokens and for PATs. Nothing in the reviewed sources confirms or denies it for
user-to-server tokens (`01-current-architecture.md`, edge case 8).

A negative result reverses D3 and changes `07-security.md` in full. Building
the auth path first and discovering this afterwards would waste the entire C, E,
and F line of work.

## Scope & seams

**Human prerequisite, before dispatch.** A human must register a *throwaway*
GitHub App with device flow enabled, user-token expiration opted out, and the
permission set in `07-security.md`, install it on a disposable test repository
and a disposable test organization, and supply its public `client_id` to the
spike. This is deliberately **not** the published product App: human gate 2
approves that one, and is itself blocked until this spike is green. The
throwaway App is deleted when the spike concludes.

Write a throwaway spike binary or example under `crates/github/examples/` plus
its written result in `docs/spikes/d17-user-to-server-scale-set-chain.md`. This
is exploratory code; it is not the adapter. `c4` and `c5` implement the real
thing, informed by what this learns.

Prove, in order, each link of the chain, recording the exact request, the exact
response status, and the decisive response fields for each:

1. Device flow with only a public `client_id` returns a user access token.
2. That token mints a **runner registration token** at repository scope and at
   organization scope.
3. The registration token completes the Actions-service registration exchange,
   yielding an admin token and a tenant URL.
4. The admin token creates a scale set and opens a **message session**.
5. A queued job produces demand, and `AcquireJobs` succeeds against it.
6. `POST {actions_service_url}/_apis/runtime/runnerscalesets/{id}/generatejitconfig`
   with body `{name, workFolder}` returns a usable JIT configuration.

Test both scopes: repository scope runs under `Administration: Read and write`,
organization scope under the narrower `Organization → Self-hosted runners`.
A chain that works at one scope and not the other is a materially different
answer from a clean pass and must be reported as such.

Record the pinned protocol revision observed, and any response field whose
absence or drift would break the adapter — `c5` pins against this.

**If any link fails**, stop and report precisely which one and how. Do not
work around it, and do not proceed to `c2`. The only known alternative is the
contingency in `07-security.md`: a per-user GitHub App with installation tokens
derived from a locally held private key, which reverses D3 and restores the
onboarding cliff. Reopening D3 is an owner decision, not this task's.

No secret from the spike may be committed. The user code is shown on screen by
design; the device code, the registration token, the admin token, the
message-queue token, and the JIT blob never are.

## Definition of Done

- `docs/spikes/d17-user-to-server-scale-set-chain.md` records a per-link
  verdict, the request and response evidence for each, the observed protocol
  revision, and an explicit **GREEN** or **RED** conclusion for D17 at
  repository scope and at organization scope separately.
- On green: a single spike run performs all six links end to end and a real job
  is acquired and JIT-configured on the disposable repository.
- On red: the failing link is identified with its status and response body, the
  document states that D3 is reopened, and no further C-group work begins.
- The spike commits no token, no JIT blob, and no `client_id`-plus-secret pair;
  a log scan of its output finds no credential.
- The throwaway App and disposable repository are recorded so a human can
  delete them.
