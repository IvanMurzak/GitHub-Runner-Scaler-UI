---
id: "c1-wsl-chain-corpus"
title: "Add 32 deterministic mocked WSL transition scenarios"
group: "C"
sequence: 1
repo: "."
base_branch: "main"
depends_on: []
importance: 9
complexity: 7
security_critical: true
production_touching: false
model_hint: "top"
taskflow_refs: ["01-current-architecture.md", "02-target-architecture.md", "03-coverage-model.md"]
---

## Goal

Extend the existing private WSL acceptance harness with at least 32 named,
deterministic transition scenarios without invoking real WSL or host services.

## Scope & seams

- Extend `crates/app/src/cli/wsl_acceptance.rs`, factoring a private sibling
  module only if it improves ownership without exposing test seams to production.
- Reuse `Workstation`, `ScriptedRunner`, fake assets, fake issuer, provider
  records, and request histories; do not substitute either unrelated
  `FakeGithub` type.
- Cover `wsl list`, repeated `wsl install`, `wsl status`, `wsl detach`, and
  selected-host proxy behavior across fresh, adopted, healthy, drifted, partial,
  detached, and re-attached states.
- Include exact/case-sensitive distribution names, capacity changes, repeated
  convergence, per-stage failures, bounded outputs, and credential canaries.
- Give every case a stable `wsl-NNNN` identifier and first-divergence diagnostics.

## Definition of Done

1. The checked-in WSL inventory contains and executes at least 32 meaningful
   named cases in the default binary test target on every OS.
2. No scenario calls real `wsl.exe`, Task Scheduler, systemd, GitHub, or an
   external network endpoint.
3. Script histories and provider records prove ordering, literal argv, retry or
   convergence behavior, and non-destructive detach.
4. Secret canaries appear only in the intended anonymous-stdin seam and are
   absent from output, errors, records, argv, environment, and debug text.
5. Removing a stage, reordering a required request, or leaking a canary makes an
   acceptance control fail.
6. App binary tests, workspace nextest, format, and clippy gates pass.
