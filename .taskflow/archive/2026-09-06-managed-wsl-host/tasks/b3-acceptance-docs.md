---
id: "b3-acceptance-docs"
title: "Add end-to-end acceptance coverage and managed WSL operator documentation"
group: "B"
sequence: 3
repo: "."
base_branch: "main"
depends_on: ["b2-wsl-cli-orchestration"]
importance: 8
complexity: 6
security_critical: true
production_touching: false
model_hint: "top"
taskflow_refs: ["README.md", "02-target-architecture.md", "03-security-and-lifecycle.md"]
---

## Goal

Make the feature shippable and reproducible from public documentation, with an
acceptance harness that guards the security and adoption promises.

## Scope & seams

- Document prerequisites, fresh install, adoption, independent authentication,
  policy setup through `--host`, capacity, status, detach, login availability,
  Docker diagnostics and recovery.
- Add a release note/changelog entry appropriate for `0.4.0` using the repository's
  existing documentation conventions.
- Add unprivileged end-to-end tests over fake WSL/process/task controls and a
  Windows-only ignored privileged smoke test that uses a uniquely named fixture
  task/distribution seam and performs complete cleanup.
- Extend secret-output and shippable-mutant/command-surface guards for every new
  private/public command.

## Definition of Done

1. A new operator can configure a second Linux host without any undocumented
   staging directory, PowerShell token extraction, manual systemd unit or manual
   scheduled task.
2. Documentation says clearly that each host needs an independent sign-in and
   why refresh-token sharing fails.
3. Acceptance tests cover fresh provisioning, existing-host adoption, two
   independent distros, rerun convergence, detach and all injected failures.
4. Canary scans cover stdout, stderr, logs, provider records, task XML, argv and
   environment.
5. CI wiring compiles/runs the appropriate tests on Windows and keeps privileged
   tests isolated/ignored unless explicitly selected.
6. Full locked workspace test, format, clippy and release-workflow contract tests
   pass.

