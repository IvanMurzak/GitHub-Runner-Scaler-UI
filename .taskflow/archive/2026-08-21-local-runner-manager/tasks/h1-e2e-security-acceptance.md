---
id: "h1-e2e-security-acceptance"
title: "End-to-end acceptance and security-gate suite against a disposable GitHub repository and organization, per supported OS"
group: "H"
sequence: 1
repo: "."
depends_on: ["f3-cli-daemon-service", "g3-tui-settings-parity", "d3-service-installers", "v1-org-jit-verification"]
importance: 9
complexity: 7
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["04-subsystem-contracts.md", "07-security.md", "06-migration-rollout.md", "08-user-workflows.md", "05-infrastructure.md"]
---

## Goal

Prove, against real GitHub rather than fixtures, that the product does what it
claims on each supported OS — and turn the `07-security.md` release gates from
a list of intentions into a suite that fails a pull request. Every crate has its
own tests; this is the only place the whole chain runs together.

## Scope & seams

Owns the workspace-root `tests/` acceptance crate. Runs through the `e2e` CI job
that `a1` already defined, and **skips cleanly** when its repository secret is
absent, so a fork or an offline contributor is not blocked.

**Fixture.** A disposable GitHub test repository and a disposable test
organization, each with a workflow whose `runs-on` names the routing label the
product generated, and that label recorded (`06-migration-rollout.md`, Phase 0).

**Acceptance scenarios**, each on Windows, macOS, and Linux
(`04-subsystem-contracts.md`, Release acceptance):

1. At least one successful real JIT job, from demand through cleanup.
2. Forced network-outage recovery.
3. JIT-expiry recovery.
4. Policy-disable drain.
5. Boot-start recovery after a real reboot with no interactive login.
6. One live **organization-scoped** job, proving D18's second scope end to end.
   `v1` proved the endpoint; this proves a job actually runs through it.
7. A monitor-only policy under real demand starting zero runners.
8. **Two-host contention** (`07-security.md`, threat table). Two hosts
   deliberately configured with the same routing label both start a runner for
   one queued job; assert that one job runs, the surplus runner exits on its
   idle timeout, that exit is recorded as an idle exit rather than a failure,
   and it is cleaned like any other attempt. This is the accepted cost of
   having no `AcquireJobs`, and the release must demonstrate it is bounded
   rather than assume it.

**Security gates** (`07-security.md`), as failing tests rather than checklists:

- Process-inspection: no JIT configuration in any process command line.
- Two-job contamination: a second job sees nothing left by the first.
- Corrupted-runner-package rejection, and refusal when no checksum is published.
- Secret-injection log scan: the **user access token** and the **encoded JIT
  configuration** — the product's entire sensitive surface after D4 — are absent
  from logs, databases, snapshots, crash reports, and CLI output.
- Revoked-token rejection: the affected policies move to
  `authentication_failed` with a precise remediation command, and no runner is
  created.
- Config and SQLite fixtures contain no usable credential.
- Workspace removal after both successful and failed runs.
- Restart and duplicate-poll test: no duplicate runners, including the case
  where the same job is still `queued` while its runner starts.
- Budget refusal: a target set projected above half the documented REST ceiling
  is refused by `add`, with the computed numbers shown.

**Post-condition for every scenario.** No runner remains registered at GitHub
and no runtime directory remains on disk, and the old runner label has not been
reused.

Reporting matters as much as passing: each scenario names the OS, the scope,
and the observed evidence, because human gates 3, 4, and 5 are approved from
this output.

## Definition of Done

- All eight acceptance scenarios pass on Windows, macOS, and Linux, with
  per-OS, per-scenario evidence recorded.
- Every security gate listed above exists as a test that fails when its control
  is deliberately removed — verified by removing one and observing the failure.
- The suite skips cleanly, without failing, when its secret is absent.
- Every scenario ends with zero registered runners, zero runtime directories,
  and no reused legacy label.
- A rollback drill — label restore, drain, terminal-state verification, legacy
  re-enable — is executed and recorded once per supported OS
  (`05-infrastructure.md`, Rollback).
- The suite's output is a single readable report per OS, suitable for attaching
  to a human gate approval.
