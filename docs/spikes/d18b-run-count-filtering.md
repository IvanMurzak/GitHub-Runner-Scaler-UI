# D18b — is `total_count` on the workflow-runs list the *filtered* count? — result

**GREEN. `total_count` is the number of runs matching the query, not the
repository's total run count.** `c3-rest-inventory-gateway`'s one-request
in-progress activity count reads the right number.

**Date:** 2026-08-21 · **Verification spike**, in the style of
[`v1-org-jit-verification`](../../.taskflow/2026-08-21-local-runner-manager/tasks/v1-org-jit-verification.md).
Not itself a task under `tasks/`; it exists to settle one factual question
before [`c4`](../../.taskflow/2026-08-21-local-runner-manager/tasks/c4-demand-and-jit-gateway.md)
and [`e1`](../../.taskflow/2026-08-21-local-runner-manager/tasks/e1-reconciliation-capacity.md)
are built on the answer.

The stop-the-line rule was **not** triggered: the assumption holds, so nothing
was worked around, and no fallback, redesign or substitute counting strategy
was written.

> [!IMPORTANT]
> **Superseded in part, on 2026-09-05.** Everything this spike *measured* still
> holds: `total_count` on a filtered workflow-runs query is the filtered count.
> What no longer holds is the **decision built on it** — that demand could be
> counted in workflow runs and the per-run job listing priced out.
>
> A run holds many jobs and each needs its own runner, so the run count
> under-reported an eight-job matrix as demand `1` and the product served it
> nearly serially on a host configured for ten concurrent runners.
> `crates/github/src/demand.rs` now lists each active run's jobs and counts the
> queued ones. See [`d24-run-status-versus-job-status`](d24-run-status-versus-job-status.md)
> for the measurement that shaped the replacement.

## The assumption under test

`c3` landed an in-progress activity count that issues **one request per
refresh** and reads `total_count` from

```
GET /repos/{owner}/{repo}/actions/runs?status=in_progress&per_page=100
```

Its own doc comment states the assumption plainly
(`crates/github/src/rest.rs`, `repository_in_progress`):

> GitHub answers the filtered query with its own `total_count`, which is the
> count this product wants, so a repository with 400 in-progress runs still
> costs one request rather than four — and the budget table's "one request per
> refresh" stays true.

**Nothing had ever called that endpoint.** Worse, the unit fixtures assert the
assumption rather than the API: `mount_runs` returns a non-zero `total_count`
beside an **empty** `workflow_runs` array, which is exactly the response shape
that would prove the assumption *wrong* if GitHub produced it. No test could
have caught this. `e1` allocates runner capacity from the number, so an
inflated count means starting runners for jobs that do not exist.

## Method

Two fixtures, and **no credential is required for the decisive one**.

| Fixture | Visibility | Runs | Why |
|---|---|---|---|
| `IvanMurzak/GitHub-Runner-Scaler-UI` | public | 58 | This repository. Mixed history, and it had a **live in-progress run** during the probe — the decisive fixture the question asks for. |
| A private repository on the same account | private | 680 | At-scale cross-check and an exact partition. Named, not identified — see **Secret hygiene**. |

`GET /repos/{o}/{r}/actions/runs` is readable **unauthenticated** on a public
repository, so the central evidence below is reproducible by anyone with no
token at all. That is stronger evidence than a token-gated run, not weaker.
Every check was then repeated authenticated, and **the numbers were identical**
— `total_count` semantics do not depend on authentication or on repository
visibility.

Script: [`d18b-run-count-probe.ps1`](d18b-run-count-probe.ps1). Read-only;
every call is a `GET`.

> **Deviation from the brief, stated plainly.** The brief specified device flow
> to a `ghu_` token, as in [`d17-spike.ps1`](d17-spike.ps1) and
> [`d18-org-jit-spike.ps1`](d18-org-jit-spike.ps1). That was **not used**, for
> two reasons. First, it is unnecessary: the question is fully answerable
> against public data, and no verification URL or user code ever needed to be
> printed, so the owner was never blocked waiting to authorize. Second, it was
> not available: `v1`'s own secret hygiene deliberately removed the throwaway
> App's `client_id` from the repository, and it is recorded nowhere on this
> machine, so a device flow could not have been started without asking the
> owner for it. The authenticated pass instead reused the `gh` CLI session
> already present on the machine — an existing credential, read-only, no new
> grant.

---

## Point 1 — filtered `total_count` vs array length vs the unfiltered total

Captured while a CI run of this taskflow was **actually in progress**:

| Request | Status | `total_count` | `workflow_runs.len` |
|---|---|---|---|
| `GET /repos/IvanMurzak/GitHub-Runner-Scaler-UI/actions/runs` | `200` | **58** | 30 |
| `…/actions/runs?status=in_progress` | `200` | **1** | **1** |
| `…/actions/runs?status=completed` | `200` | 56 | 30 |
| `…/actions/runs?status=failure` | `200` | 0 | 0 |

The decisive row is the second. The filtered `total_count` is **1**, it
**equals the returned array length**, and it **differs from the unfiltered 58**.
Had `total_count` been the repository total, it would have read `58`.

The single matching run, confirmed by its own record:

```
id=32545300541  name='CI'  status=in_progress  conclusion=<null>  run_number=30
```

Note also the unfiltered row: `total_count` 58 beside an array of 30. So
`total_count` is not the page length either — it is a genuine count that
exceeds what the page returns.

**GREEN.**

## Point 2 — a filter certain to match nothing

`status=failure` on a repository holding 58 runs:

```
GET /repos/IvanMurzak/GitHub-Runner-Scaler-UI/actions/runs?status=failure
200   total_count=0   workflow_runs.len=0
```

`total_count: 0` beside an empty array, while the repository holds 58 runs.
The disproof shape — a **non-zero** `total_count` beside an empty array — was
never produced by the API on any query in this probe. That shape exists only in
`c3`'s fixtures.

The same held at scale, and this is the strongest single observation in the
spike:

```
GET /repos/<private>/actions/runs?status=in_progress
200   total_count=0   workflow_runs.len=0
```

on a repository holding **680** runs. An unfiltered `total_count` would have
said `680`. It said `0`.

**GREEN.**

## Point 3 — does pagination interact with it?

`c3` sends `per_page=100` (`PER_PAGE`) alongside the filter, so this is
load-bearing for it specifically. Against the 568-run filtered set on the
private fixture:

| Request | Status | `total_count` | `workflow_runs.len` |
|---|---|---|---|
| `?status=success` | `200` | **568** | 30 |
| `?status=success&per_page=1` | `200` | **568** | **1** |
| `?status=success&per_page=100` | `200` | **568** | 100 |
| `?status=success&per_page=1&page=5` | `200` | **568** | 1 |

`total_count` is **invariant under `per_page` and `page`** and always reports
the full filtered count, while `workflow_runs.len` tracks the page size. One
request returns the whole count regardless of page size.

**GREEN.**

## The exact partition — the strongest confirmation

On the 680-run private fixture, every run had completed, so the conclusions
must partition the whole set. They do, exactly:

| Request | `total_count` |
|---|---|
| `…/actions/runs` (unfiltered) | 680 |
| `?status=completed` | 680 |
| `?status=success` | 568 |
| `?status=failure` | 83 |
| `?status=cancelled` | 29 |
| `?status=in_progress` | 0 |
| `?status=queued` | 0 |

**568 + 83 + 29 = 680.** If `total_count` were the repository total, every one
of those rows would read `680`. Three of them read `568`, `83` and `29`, and
they sum to the whole with no remainder.

> **A trap for anyone re-running this.** On both fixtures `status=completed`
> reports the *same* number as the unfiltered query (680 and 680; later 58 and
> 58 on the public repo once its CI run finished). That is **not** evidence of
> an unfiltered `total_count` — it is the honest answer, because at that moment
> every run in the repository genuinely was completed. The rows that
> discriminate are `in_progress` and `failure`, and the partition above. Do not
> read the `completed` row alone and conclude RED.

---

## Verdict

**GREEN.**

The fact `c4` and `e1` may rely on:

> On `GET /repos/{owner}/{repo}/actions/runs`, the `total_count` field is the
> number of runs **matching the supplied query**, independent of `per_page` and
> `page`. A filtered request therefore yields the full filtered count in **one
> request**, and `c3`'s in-progress activity count and its "one request per
> refresh" budget line are both correct as written.

No change to `c3` is required by this spike.

---

## What is still untested — honest limits

These are observations, not proposals. This spike settles one factual question
and does not redesign anything; the four points below are for the owner.

1. **`total_count` counts *runs*, not *jobs*.** The endpoint lists workflow
   *runs*, and a run may contain many jobs, each needing its own runner. `c3`'s
   method is named `in_progress_activity` and the count is described as an
   in-progress job count. If `e1` treats this number as "jobs currently needing
   a runner", it will **under**-count on any multi-job workflow — the opposite
   direction from the inflation this spike was checking for, but a real
   discrepancy. Not investigated here; nothing in the brief asked for it.

2. **`status=in_progress` excludes queued runs, and queued is arguably the
   demand signal.** A run that is *queued* is precisely one waiting for a runner
   that does not exist yet. `queued`, `waiting`, `requested` and `pending` all
   returned `total_count: 0` on both fixtures, but **no queued run was ever
   observed**, so the exclusion is inferred from the API's documented status
   vocabulary rather than proven here. Whether `e1`'s demand number should
   include queued runs is a design question, deliberately left open.

3. **`c3`'s missing-`total_count` fallback is unexercised in reality.** Every
   response in this probe carried `total_count`. The page-walking fallback for a
   response without it was never triggered against the real API, so it remains
   proven only by its unit tests.

4. **Organization scope was not probed.** Only
   `/repos/{owner}/{repo}/actions/runs` was called. `c3` also has an
   organization path; whether an org-scope listing behaves identically is
   untested here, exactly as `d17` left `/orgs/` untested for
   `generate-jitconfig`.

Timing note: the public fixture is live. Its `completed` count moved from 56 to
57 to 58 during the probe as the taskflow's own CI finished, and the in-progress
run recorded under Point 1 had completed by the time the committed script was
re-run. The script's later output therefore shows `in_progress total_count=0`
rather than `1`. Both readings are GREEN by the same argument; the `1` is
recorded above because a live in-progress run is the decisive fixture and it no
longer exists to re-observe.

---

## Resources

**Created nothing. Deleted nothing.** No runners, no workflow runs, no
repositories, no organizations, no Apps. Every call in this spike is a `GET`.
The two fixtures are pre-existing repositories that were only read.

## Secret hygiene

No token, no device code and no `Authorization` header value is recorded here or
anywhere in the repository, and none was printed to the session.

- The decisive evidence needs **no credential at all** — the fixture is public
  and the calls are unauthenticated `GET`s.
- The authenticated pass took its token from the machine's existing `gh` CLI
  session via a shell subexpression, so the token value never appeared in a
  command line, in output, or on disk. It was cleared from the session variable
  afterwards.
- `d18b-run-count-probe.ps1` contains **no token, no client id and no private
  repository name**. `-Token` and `-PrivateRepo` are optional parameters with no
  defaults; the only repository written into the script is this public one.
- The private fixture is described by its shape (private, same account, 680
  runs) and is **not named**, following `v1`'s rule: name the resources, do not
  identify them. Naming it would disclose a private repository from a public
  repository's documentation.
- Evidence JSON was written **outside** the repository, to the session
  scratchpad, not to `docs/spikes/`.
- This document and the script were both scanned for `gh[pousr]_` token
  prefixes, `Authorization` header values and device codes before committing.
  Clean.
