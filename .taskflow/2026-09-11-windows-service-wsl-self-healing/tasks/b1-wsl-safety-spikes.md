---
id: "b1-wsl-safety-spikes"
title: "Prove non-elevated named termination and cross-boundary drain fence"
group: "B"
sequence: 1
repo: "."
base_branch: "main"
depends_on: []
importance: 3
complexity: 8
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["04-wsl-recovery-safety.md", "ROADMAP.md#G1", "ROADMAP.md#G2"]
---

## Goal

Establish the two platform facts required before automatic termination exists.

## Scope & seams

Using only a disposable named WSL2 distribution under owner gate OG1, test
unelevated `--terminate` isolation and candidate DrvFS lock/generation behavior
across Windows/Linux process death and WSL session failure. Record the selected
primitive or mark automatic recovery unsupported.

## Definition of Done

- No existing/user workload distribution is terminated.
- Same-user non-elevated capability is proven or rejected explicitly.
- A race-free fence primitive is demonstrated with reproducible fixtures.
- Findings update architecture facts, not locked product safety decisions.

