---
id: "d1-acceptance-security-packaging"
title: "Prove incident recovery, packaging and secret boundaries"
group: "D"
sequence: 1
repo: "."
base_branch: "main"
depends_on: ["a5-service-health", "b5-wsl-task-migration-status", "c2-wsl-tui-collection"]
importance: 3
complexity: 9
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["ROADMAP.md#G3", "ROADMAP.md#G9"]
---

## Goal

Close cross-component gates on real artifacts and the original incident shape.

## Scope & seams

Update package manifests/installers/checksums, command accountability, real
process/service fixtures, secret scans and incident replay. Preserve unrelated
dirty changes and current package channels.

## Definition of Done

- Windows packages contain launcher, supervisor and CLI with verified hashes.
- `Running` task plus classified WSL failure waits for active work, recovers
  after acknowledged drain, and blocks without acknowledgment.
- No secret appears in any new state/log/status/TUI surface.
- Workspace CI and privileged opt-in gates pass.

