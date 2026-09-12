---
id: "b3-wsl-recovery-model"
title: "Implement fail-closed WSL recovery state and evidence model"
group: "B"
sequence: 3
repo: "."
base_branch: "main"
depends_on: ["b2-guest-heartbeat-fence"]
importance: 3
complexity: 8
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["04-wsl-recovery-safety.md", "05-tui-status-ux.md"]
---

## Goal

Encode failure classification, proof freshness, vetoes, backoff and circuit
breaking as a pure deterministic model.

## Scope & seams

Add domain/platform types and provider-record migration. Model consecutive
probe windows, drain generations, local/GitHub evidence, managed registration
removal and all public recovery states.

## Definition of Done

- Property tests never emit terminate under missing, stale or contradictory
  evidence, active work or unmanaged runners.
- Only classified transport/session failures advance toward recovery.
- Existing records migrate to observation-only; no secret enters state.

