# CLI Chains Acceptance Tests

Design reviewed and immutable implementation tasks derived 2026-09-10.
Confirmed repository and specification defects were corrected without changing
the owner's Rust-based or mocked-WSL decisions.

## Problem

The CLI has strong command-focused tests and several hand-written journeys, but
no executable reference model that systematically checks long sequences,
invalid transitions, persistence across process restarts, or pairwise
interaction coverage. The owner requested hundreds of meaningful combinations
that gate pull requests and releases on Windows, macOS, and Linux.

## Decisions

| ID | Decision | Status | Consequence |
|---|---|---|---|
| D1 | Implement the suite in Rust and reuse repository-native test facilities; do not add bash/PowerShell scenario scripts to CI. | LOCKED 2026-09-10 | Scenarios are portable, reviewable Rust tests discovered by the existing test command. |
| D2 | Exercise WSL behavior through the unprivileged scripted adapter in ordinary CI. | LOCKED 2026-09-10; factual rationale corrected by review | Current hosted Windows images include WSL, but a suitable provisioned distribution is not a stable cross-platform prerequisite. |
| D3 | Use a deterministic checked-in transition corpus and pure reference model, with at least 256 local and 32 WSL cases. | LOCKED 2026-09-10 (owner confirmed) | Failures have stable identifiers and replay data; no new property-testing dependency or random CI input is required. |
| D4 | Use layered command accountability, not an unsafe Cartesian product over arbitrary argv. | LOCKED 2026-09-10 (owner confirmed) | Local state uses real CLI subprocesses; WSL uses its scripted seam; destructive/long-lived commands remain in dedicated or privileged harnesses and must be classified. |
| D5 | Validate every action immediately against exit/output, public store state, filesystem effects, fake calls, and secret canaries. | REVIEWED 2026-09-10 | The production result cannot serve as its own oracle, and failures localise to the first divergent transition. |

## Scope summary

The main suite lives in `crates/app/tests/cli_chains_acceptance.rs` and drives
the actual binary repeatedly against an isolated data root. WSL sequences extend
the existing private `Workstation` harness. A coverage manifest maps every
published command leaf to generated, scripted, dedicated, privileged, or
surface-only evidence and fails closed when the command surface grows.

## Document map

- [`01-current-architecture.md`](01-current-architecture.md): repository truth,
  existing harnesses, CI, and platform boundaries.
- [`02-target-architecture.md`](02-target-architecture.md): harness layering,
  action grammar, oracles, safety, gates, and execution isolation.
- [`03-coverage-model.md`](03-coverage-model.md): combination definition,
  transition semantics, invariants, replay, and command accountability.
- [`tasks/README.md`](tasks/README.md): immutable implementation contracts and
  conflict-domain ownership.
- [`ROADMAP.md`](ROADMAP.md): sole live task state and review log.

## Review outcome

The review closed seven findings: four P1 architecture/coverage gaps and three
P2 factual or operational defects. No P0 guarantee failure and no unresolved
owner decision remain. Details and evidence are recorded in the ROADMAP review
log.
