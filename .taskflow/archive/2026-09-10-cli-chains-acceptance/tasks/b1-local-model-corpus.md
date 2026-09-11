---
id: "b1-local-model-corpus"
title: "Define the pure local CLI model and deterministic transition corpus"
group: "B"
sequence: 1
repo: "."
base_branch: "main"
depends_on: []
importance: 9
complexity: 7
security_critical: false
production_touching: false
model_hint: "top"
taskflow_refs: ["02-target-architecture.md", "03-coverage-model.md"]
---

## Goal

Create an independent, deterministic model of the allowed local CLI state and a
checked-in inventory of at least 256 meaningful transition cases.

## Scope & seams

- Add test-private modules beneath `crates/app/tests/cli_chains/` for model
  state, typed actions, pure transitions, equivalence-class values, corpus
  generation, stable case identifiers, and coverage witnesses.
- Model host, repository, organization, workspace, credential-presence, and
  diagnostics-retention state described in `03-coverage-model.md`.
- Generate only typed allowlisted actions. Never translate arbitrary corpus text
  into a process command.
- Retain cases that witness compatible mutating-action pairs, refusal classes,
  restart persistence, cross-scope interactions, or security/recovery
  invariants. Reject semantically duplicate padding.
- Keep expected transitions independent of production store and command code.

## Definition of Done

1. The inventory contains at least 256 stable `local-NNNN` cases and records
   why each case contributes coverage.
2. Every compatible mutating-action pair has at least one named witness; an
   intentionally removed witness makes a coverage completeness test fail.
3. Pure-transition tests cover success, refusal atomicity, idempotent reads,
   boundary capacities, label rules, workspace guards, and repo/org coexistence.
4. Corrupting an expected state delta makes a model self-test fail without
   consulting production state.
5. No production source, manifest dependency, or workflow is changed.
