---
id: "b2-local-chain-runner"
title: "Run local model actions through real CLI process boundaries"
group: "B"
sequence: 2
repo: "."
base_branch: "main"
depends_on: ["b1-local-model-corpus"]
importance: 10
complexity: 8
security_critical: true
production_touching: false
model_hint: "top"
taskflow_refs: ["01-current-architecture.md", "02-target-architecture.md", "03-coverage-model.md"]
---

## Goal

Build the black-box acceptance runner that executes each typed action as a fresh
`runner-manager` process and detects the first divergence from the pure model.

## Scope & seams

- Add `crates/app/tests/cli_chains_acceptance.rs` and reuse/refactor the existing
  integration `support` helpers only where the behavior is generally useful.
- Give every case an isolated temporary data root, unique service fixture tag,
  loopback fake GitHub, and model instance; retain existing environment and
  proxy sanitisation.
- Translate only the typed action enum into literal argv and run the real binary
  once per action so parsing, exit mapping, context resolution, SQLite reopen,
  logging, and filesystem persistence stay in scope.
- Compare exit class, semantic output, public `Store` projection, relevant files,
  and bounded fake-GitHub request history after every transition.
- Emit stable case ID, corpus version/seed, pre-state, action prefix, expected
  transition, observed result, and fake call history at the first failure.

## Definition of Done

1. The runner executes representative success and refusal journeys across host,
   repo, org, workspace, status, and authentication setup/teardown.
2. Every invocation is confined to its temporary roots and loopback endpoint;
   tests prove standard app paths and the product service identity are untouched.
3. Refused mutations leave database and filesystem observations unchanged.
4. Deliberate exit, output, store, filesystem, and request-history mismatches
   each make the oracle fail at the responsible action.
5. A single stable case can be selected for local diagnosis while default
   nextest execution cannot omit any case.
6. App integration tests, workspace format, and clippy gates pass.
