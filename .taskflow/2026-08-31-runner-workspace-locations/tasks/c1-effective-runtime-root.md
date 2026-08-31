---
id: "c1-effective-runtime-root"
title: "Launch disposable attempts from the effective host root"
group: "C"
sequence: 1
repo: "."
base_branch: "main"
depends_on: ["a2-workspace-store", "b1-runner-path-platform"]
importance: 10
complexity: 8
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["01-current-architecture.md", "02-target-architecture.md", "03-migration-rollout.md"]
---

## Goal

Use configured or platform-default host runner roots for new ephemeral attempts
while preserving exact-path recovery and complete cleanup.

## Scope & seams

- Resolve the effective host root once per allocation from host override then
  platform default, independently of `AppPaths` and `--data-dir`.
- Preflight the effective root before accepting new allocation and return the
  exact host-root remediation command on failure.
- Keep the current short random attempt child naming, journal-before-external-
  effects ordering, package lease behavior, and full recursive cleanup.
- Recover migrated attempts from their exact stored runtime paths before any
  new allocation under the new Windows default.
- Keep existing service directory arguments compatible while making runner-root
  selection dynamic from durable host state.
- Do not implement repository persistent slots in this task.

## Definition of Done

- A new Windows ephemeral attempt uses `%SystemDrive%\rman\<attempt>` by default;
  a host override wins; macOS and Linux defaults remain unchanged.
- `--data-dir` still moves application data but does not override an explicit
  runner-root setting.
- Old journal rows recover and clean their old exact paths before a new attempt
  starts.
- Success, failure, idle exit, launch failure, cancellation, and restart remove
  the complete ephemeral directory and release package leases.
- Existing disposable contamination mutants and path-length regression tests
  remain green.
- Agent lifecycle and daemon integration tests pass.
