---
id: "b1-incident-tests-build"
title: "Replay the incident and build all platforms"
group: "B"
sequence: 1
repo: "."
base_branch: "main"
depends_on: ["a1-wsl-fence-service-access", "a2-fence-failure-visibility"]
importance: 3
complexity: 7
security_critical: true
production_touching: false
model_hint: "top"
taskflow_refs: ["01-current-architecture.md", "02-target-architecture.md"]
---

## Goal

Prove the live failure cannot recur and produce a new local build.

## Scope & seams

Add an incident fixture with matching demand and an initially unwritable fence,
WSL provisioning/adoption coverage, cross-platform tests, and release-profile
build verification. Do not publish a release in this task.

## Definition of Done

- The pre-fix fixture yields 14 deferred starts and no attempts.
- Converged service access allows the same fixture to create attempts.
- Workspace tests and clippy pass with warnings denied.
- Windows release build and Linux target build complete.
- Manual WSL status confirms heartbeat publication with the temporary bypass
  removed and existing Docker containers unaffected.
