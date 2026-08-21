---
id: "v1-org-jit-verification"
title: "Verification spike: prove organization-scope generate-jitconfig before D18 org work is built"
group: "V"
sequence: 1
repo: "."
depends_on: ["c1-d17-scale-set-spike"]
importance: 9
complexity: 3
security_critical: true
production_touching: false
model_hint: "mid"
taskflow_refs: ["01-current-architecture.md", "06-migration-rollout.md", "07-security.md", "04-subsystem-contracts.md"]
---

## Goal

Close the one endpoint D18 rests on that nobody has ever called. The D17 spike
proved `POST /repos/{owner}/{repo}/actions/runners/generate-jitconfig` returns
`201` on a free personal account, and it explicitly did **not** reach the
organization form because the available credential lacked `admin:org`
(`docs/spikes/d17-user-to-server-scale-set-chain.md`, section 5). Everything
D18 promises at organization scope currently rests on the assumption that the
`/orgs/` form behaves like the `/repos/` form.

That assumption has already been wrong once in this taskflow, at a cost of a
full design revision. The whole point of this task is that it costs hours and
answers the question before `c4` builds an organization code path and `f2`
ships an `org` command family on top of it.

## Scope & seams

A verification spike, not an adapter: throwaway code, a written result, and
nothing that survives into the product. Owns `docs/spikes/` and
`crates/github/examples/`, which is why it is its own group — it shares no file
with any implementation task and must not queue behind one.

**Human prerequisite, before dispatch.** A GitHub App with device flow enabled
and `Organization → Self-hosted runners: Read and write`, installed on a
disposable organization the operator administers. The throwaway App from the
D17 spike, `runner-manager-d17-spike`, is already installed on such an
organization; run this **before deleting it** and the prerequisite costs
nothing. Otherwise this task waits for the published App and human gate 2.

Reuse the method already proven in `docs/spikes/d17-spike.ps1` — device flow to
a `ghu_` token, then the call under test. Prove, recording the exact request,
the exact status, and the decisive response fields:

1. `POST /orgs/{org}/actions/runners/generate-jitconfig` with body
   `{name, runner_group_id, labels, work_folder}` returns `201` with an
   `encoded_jit_config` and a runner reference.
2. Which `runner_group_id` is usable at organization scope, and what the
   response is when the default group is not `1`. The repository call used
   group 1; nothing establishes that the organization default matches.
3. A multi-label `labels` array is accepted, since routing after D4 is a label
   set rather than a single name.
4. The created runner is deleted afterwards and the organization is left with
   zero runners, as the D17 spike left the repository.

**Stop-the-line rule, inherited from `c1`.** If the call is denied, stop.
Record the status and the response body, state that D18's organization path is
blocked, and do not work around it — no fallback to repository-scope
registration inside an organization, no retry with a broader token. Whether
D18 keeps both scopes is an owner decision, exactly as D4 was.

No secret from this spike may be committed: not the token, not the encoded JIT
configuration, not a `client_id` paired with anything else.

## Definition of Done

- `docs/spikes/d18-org-jit-verification.md` records an explicit **GREEN** or
  **RED** verdict for organization-scope `generate-jitconfig`, with the request,
  the response status, and the decisive fields for each of the four points
  above.
- On GREEN: a runner was created at organization scope and deleted, the
  organization ends with zero runners, and the usable `runner_group_id` and
  multi-label behaviour are stated as facts `c4` can implement against.
- On RED: the failing status and body are recorded, the document states that
  D18's organization path is blocked pending an owner decision, and neither
  `c4`'s organization path nor `f2`'s `org` family is started.
- A log scan of the spike output finds no token and no JIT blob, and the
  repository contains neither.
- The App and disposable organization used are named in the document so a human
  can delete them.
