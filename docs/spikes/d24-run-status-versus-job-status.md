# D24 — does a workflow run stay `queued` while it still holds a queued job? — result

**GREEN, and narrower than it looks. `queued` takes precedence over
`in_progress` at the run level: in 44 samples covering 25 states that held at
least one queued job, no run ever reported `in_progress` while one of its jobs
was `queued`.** That is what makes `?status=queued` the primary demand signal.
It is *not* enough on its own, and the reason is stated below.

**Date:** 2026-09-05 · **Verification spike.** It exists to settle one factual
question behind the reversal of the run-counting decision recorded in
[`d18b-run-count-filtering`](d18b-run-count-filtering.md), and to keep the
resulting design from resting on an inference nobody measured.

## Why the question came up

Demand had been counted in workflow **runs**. A run holds many jobs and each
needs its own runner, so an eight-job matrix reported as demand `1`: the host
started one runner, that runner took one job, and the next poll saw the same run
still queued and started one more. A machine configured for ten concurrent
runners served the matrix nearly serially while its queue depth on GitHub grew.

Replacing the run count with a job count means listing each active run's jobs.
That immediately raises the question this spike answers: **which runs have to be
listed?** Listing only `?status=queued` runs is one request cheaper per
repository per poll, and is correct only if a run reports `queued` for as long as
any of its jobs is waiting.

## Method

A repository already using this product (`IvanMurzak/ai-game-dev-software`, the
`tests` workflow — five jobs, four of them `runs-on: [self-hosted, windows]`,
no `needs:` between them) was polled every ~15 seconds for about ten minutes
across four real CI runs. Each sample listed both

```
GET /repos/{owner}/{repo}/actions/runs?status=queued&per_page=20
GET /repos/{owner}/{repo}/actions/runs?status=in_progress&per_page=20
```

and then, for every run either query returned,

```
GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs?per_page=100
```

recording the run's own `status` beside a tally of its jobs' statuses.

**Created nothing. Deleted nothing.** Read-only requests against runs that CI
produced on its own; no runners, workflow runs, repositories or Apps were
created, cancelled or removed.

## Findings

**1. A run with a queued job reports `queued`, even while another of its jobs is
running.** The decisive shape, seen repeatedly:

```
01:10:57 RUN 33934322983 runstatus=queued jobs=[completed:3 in_progress:1 queued:1]
01:14:57 RUN 33935491153 runstatus=queued jobs=[in_progress:2 queued:3]
01:15:57 RUN 33935491153 runstatus=queued jobs=[completed:1 in_progress:2 queued:2]
```

A run that was simultaneously running two jobs and holding three more in the
queue reported `queued`, not `in_progress`.

**2. A run reports `in_progress` only once nothing is left queued.** The same run
minutes later:

```
01:17:42 RUN 33935491153 runstatus=in_progress jobs=[completed:3 in_progress:2]
01:18:45 RUN 33935491153 runstatus=in_progress jobs=[completed:4 in_progress:1]
```

**3. No counterexample in 44 samples.** Filtering every sample for
`runstatus=in_progress` holding a `queued:` job returned nothing. 25 of the 44
samples held at least one queued job, so the negative is drawn from a population
that could have produced a counterexample rather than from a quiet window.

**4. The under-count the reversal was for is visible in the raw data.** At
`01:14:57` the repository had one queued run holding three queued jobs. The run
count reported demand `1`. The job count reports `3`.

## What this does *not* establish, and why the design polls both anyway

Every run sampled had **independent jobs**. A job held by `needs:` is not queued
while its dependency runs; it enters the queue when the dependency finishes, at
a moment when its run has long since started. Whether GitHub moves the run's
status *back* to `queued` at that point is a claim about a state transition this
spike never observed, because no sampled workflow had a `needs:` edge.

The consequence is asymmetric, which is what decided it:

* If the run does flip back, polling `in_progress` costs one extra request per
  repository per poll and finds nothing.
* If it does not, polling only `queued` misses a dispatchable job entirely — the
  same class of defect the whole reversal was written to fix, in a form that is
  harder to notice because it only appears on workflows with dependencies.

So `crates/github/src/demand.rs` polls **both**, and treats them differently:
`queued` is the primary signal and gets the larger run cap
(`MAX_QUEUED_RUNS_PER_REPOSITORY_PER_POLL`), while `in_progress` is a safety net
with a smaller one (`MAX_IN_PROGRESS_RUNS_PER_REPOSITORY_PER_POLL`). Finding 1
is what justifies that ranking; the unobserved `needs:` case is what justifies
the second query existing at all.

**If a later spike measures the `needs:` transition and finds that GitHub does
return the run to `queued`, the `in_progress` pass can be deleted** and the
per-poll cost drops by one request per repository. That would be a real saving
and it needs a measurement, not an argument.

## Reproducing

`docs/spikes/d24-run-status-probe.sh` is the sampler, and needs `gh` already
authenticated with `actions:read` on the target repository. It reads only; run
it against a repository that has CI in flight, since it observes runs rather
than creating them.
