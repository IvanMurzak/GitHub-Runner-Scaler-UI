---
id: "d1-cross-track-gates"
title: "Join command accountability, corpus counts, replay, and three-OS gates"
group: "D"
sequence: 1
repo: "."
base_branch: "main"
depends_on: ["a1-command-accountability", "b3-local-corpus-security", "c1-wsl-chain-corpus"]
importance: 9
complexity: 5
security_critical: true
production_touching: false
model_hint: "top"
taskflow_refs: ["README.md", "02-target-architecture.md", "03-coverage-model.md"]
---

## Goal

Close the feature with fail-closed cross-track evidence that the complete local
and WSL inventories run, every command leaf is accounted for, and failures are
replayable on the repository's existing CI matrix.

## Scope & seams

- Replace provisional coverage-manifest evidence paths with the exact tests
  delivered by B and C; keep dedicated and privileged classifications tied to
  existing repository tests.
- Add contract checks that inventory counts, executed counts, stable IDs,
  coverage witnesses, and manifest classifications agree without parsing
  transient nextest presentation text.
- Verify ordinary tests require no workflow mutation, privilege, standard
  credential access, real service registration, real WSL distribution, or
  non-loopback network.
- Document local full-suite and single-case replay commands alongside the test
  code or operator/developer documentation using repository conventions.
- Run the complete locked workspace gates and reconcile any cross-platform
  assumptions exposed by current tests without weakening the reviewed counts or
  invariants.

## Definition of Done

1. The accountability manifest names exact evidence for all published leaves
   and fails for missing, stale, duplicate, or safety-unjustified entries.
2. Default test execution proves all 256+ local and 32+ WSL cases ran exactly
   once, with unique stable identifiers and complete pairwise witnesses.
3. Replay documentation reproduces a selected case and explains its diagnostics
   without permitting CI to select a subset.
4. `cargo metadata --locked`, `cargo fmt --check`, workspace all-feature build,
   `cargo clippy --all-targets -- -D warnings`, `cargo nextest run --workspace`,
   and `cargo test --doc --workspace` pass locally where platform-applicable.
5. Existing CI contracts prove the non-ignored tests run on Windows x64, macOS
   ARM64, Linux x64, pull requests, main pushes, and the release call path.
6. README and ROADMAP accurately describe the delivered evidence without adding
   task status anywhere outside ROADMAP.
