# CLI Chains Acceptance Tests

## Problem
The runner-manager CLI has a wide surface area of commands (`wsl`, `daemon`, `service`, `repo`, `org`, `update`). While individual components and single commands are well-tested, we lack a comprehensive acceptance suite that verifies **long sequences** of these commands (e.g., installation -> adding repositories -> changing parameters -> removing repositories) and their side-effects in combination. The owner requested hundreds of combinations spanning edge cases to run reliably in GitHub Actions on macOS, Linux, and Windows.

## Status
Planning phase. Investigating the best approach to generate and validate hundreds of command sequences securely and efficiently on all CI runners.

## Decisions
- **D1 (2026-09-10)**: We will not use shell scripts (bash/pwsh) directly in GitHub Actions. We will write these tests in Rust using the existing `ScriptedRunner` and `FakeGitHub` architecture so they run blazingly fast locally and in CI across Windows, macOS, and Linux without requiring actual WSL or real network interactions. 
- **D2 (2026-09-10)**: WSL-specific edge cases will be tested via the existing unprivileged mock adapter (as the real hosted GitHub Actions Windows runners do not support WSL2).

## Summary
This taskflow will design and implement a new combinatorial acceptance testing module for the CLI. It will generate hundreds of logical command sequences (using property-based testing principles or explicit scenario recipes) and assert the correct state mutations, ensuring high reliability against regressions on every Pull Request.

## Document Map
- `01-current-architecture.md`: Details the existing acceptance testing harnesses (`wsl_acceptance.rs`, `FakeGitHub`).
- `02-target-architecture.md`: Proposes the design for generating and running the CLI command chains.
- `ROADMAP.md`: The execution plan and wave tracker.
