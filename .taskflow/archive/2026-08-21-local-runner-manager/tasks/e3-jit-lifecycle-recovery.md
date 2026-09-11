---
id: "e3-jit-lifecycle-recovery"
title: "JIT attempt lifecycle: runtime allocation, secure JIT handoff, process supervision, idle-exit and cleanup, and restart recovery"
group: "E"
sequence: 3
repo: "."
depends_on: ["e1-reconciliation-capacity", "e2-runner-package-cache", "b2-sqlite-persistence", "d1-platform-core"]
importance: 10
complexity: 8
security_critical: true
production_touching: false
model_hint: "top"
taskflow_refs: ["03-control-flows.md", "07-security.md", "04-subsystem-contracts.md", "05-infrastructure.md"]
---

## Goal

Implement `e1`'s `RunnerLauncher`: take a decision to start one runner and carry
it through JIT configuration, launch, one job, and cleanup — and reconstruct
that state correctly after a crash or a reboot. This is where a leaked JIT
config, a contaminated workspace, or an orphaned process would come from.

## Scope & seams

Owns `crates/agent/src/lifecycle.rs`.

**Per-attempt flow** (`03-control-flows.md`, flow 2, steps 5–8):

1. Allocate a unique runtime directory `runtime/<policy-id>/<attempt-id>/` and
   record the attempt as `allocated` in the journal (`b2`) **before** anything
   remote happens, so a crash leaves a recoverable trace rather than an
   invisible one.
2. Request one JIT configuration per runner from `c4`, at the policy's scope,
   carrying the policy's routing labels.
3. Write the JIT configuration **only** to a restrictive temporary file (`d1`),
   launch the runner process, and remove the file immediately after successful
   handoff. The JIT configuration is **never** a command-line argument — a
   process listing would expose it (`07-security.md`, threat table).
4. Supervise the process; move the attempt through `jit_received`, `starting`,
   `idle`, `busy` using local process state plus GitHub telemetry, per the
   precedence rule: GitHub runner status is authoritative for remote job status,
   local process state only for a child this agent owns.
5. On exit, preserve redacted diagnostics, remove the workspace and every JIT
   artifact, and mark the attempt terminal, then `cleaned`.

**The idle exit is a first-class path** (`03-control-flows.md`, flow 2.7).
Because there is no job reservation, a runner may accept one job **or** find
none and exit on its idle timeout after another host took the work. Both are
terminal and both are cleaned identically, but the attempt records which one
happened (`b1`), because the dashboard must show an idle exit distinctly from a
failure and the operator must not be sent chasing a fault that did not occur.

**Retry policy.** A failed JIT request, download, process start, or a runner
exit before job acceptance is retried with bounded exponential backoff **while
the demand that justified it persists**. An expired JIT configuration is
discarded, its runtime directory removed, and a new configuration requested only
if current demand still requires the capacity. A `403` from `c4` is terminal and
operator-actionable, never retried. The agent never reports a job as complete —
GitHub remains the source of truth for workflow outcome.

**Recovery** (`03-control-flows.md`, flow 3.2). On startup, read the lifecycle
journal, discover surviving child processes, and reconcile them against GitHub
**before** creating any new runner. An attempt whose process is gone and whose
runner is unknown to GitHub is `orphaned` and cleaned; an attempt whose process
still runs is adopted, not duplicated. This is the path that makes boot-start
recovery (Journey 5) work.

**No workspace reuse, ever.** Job workspace retention is disabled in v1. A
workspace is removed after both successful and failed runs, so no hostile
workflow can leave data for a later job.

## Definition of Done

- A full attempt runs `allocated` → `jit_received` → `starting` → `busy` →
  `finished` → `cleaned` against fakes, with the journal written at each step.
- An attempt that receives no job runs `allocated` → … → `idle` → terminal →
  `cleaned`, recorded as an idle exit and asserted to be distinguishable from a
  failed attempt in both the journal and the emitted events.
- A native process-inspection test confirms the JIT configuration never appears
  in any process command line on any supported OS.
- The JIT temporary file is deleted after a successful handoff **and** after a
  failed launch; a test asserts the file is absent in both cases.
- A two-job contamination test proves the second job sees nothing from the
  first: the workspace is removed after both a successful and a failed run.
- Spawn failure, JIT-request failure, and exit-before-acceptance each retry with
  bounded backoff while demand persists, and stop when it goes away; a `403`
  produces no retry at all.
- An expired JIT configuration removes its runtime directory and only
  re-requests when demand still calls for it.
- Restart recovery: a journal containing a live process adopts it without
  starting a duplicate; a journal containing a dead process with no GitHub
  runner marks it `orphaned` and cleans it; neither case creates a new runner
  before reconciliation completes.
- After a successful job and cleanup, no runner remains registered at GitHub
  and no runtime directory remains on disk.
- Redacted diagnostics survive cleanup and contain no credential or JIT blob.
