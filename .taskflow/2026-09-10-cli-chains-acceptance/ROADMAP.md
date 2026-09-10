# Execution Roadmap

This file is the sole live task-state record. Task specifications must not carry
a status field.

**Design status:** Reviewed and decomposed into immutable task specs on
2026-09-10. No owner question remains.

**Execution isolation:** each implementation task receives an isolated worktree
under
`C:/tmp/pipeline-worktrees/github-runner-scaler-ui-cli-chains/<task-run-id>`.
The shared checkout is reserved for scheduling, review records, and this file.

## Execution waves

1. **Wave 1 — independent foundations:** A1 classifies the public command
   surface, B1 defines the pure local model/corpus, and C1 builds the isolated
   mocked WSL corpus. These groups have distinct conflict domains and may run in
   parallel.
2. **Wave 2 — local process harness:** B2 connects B1's typed transitions to the
   real CLI process boundary and after-action oracle.
3. **Wave 3 — local completeness/security:** B3 executes the full 256-case
   inventory and closes security, mutation, replay, and timing evidence.
4. **Wave 4 — cross-track closure:** D1 starts only after A1, B3, and C1 are
   complete, then reconciles exact evidence mappings and all repository gates.

Within group B, tasks run by ascending sequence and never overlap. Other groups
may overlap only when their `depends_on` entries are satisfied.

## Tasks

| Task (spec) | needs | repo/base | imp/cx | model | Status | Run / PR | Updated |
|---|---|---|---|---|---|---|---|
| [a1-command-accountability](tasks/a1-command-accountability.md) | — | ./main | 8/4 | mid | Pending | — | 2026-09-10 |
| [b1-local-model-corpus](tasks/b1-local-model-corpus.md) | — | ./main | 9/7 | top | Pending | — | 2026-09-10 |
| [b2-local-chain-runner](tasks/b2-local-chain-runner.md) | b1 | ./main | 10/8 | top | Pending | — | 2026-09-10 |
| [b3-local-corpus-security](tasks/b3-local-corpus-security.md) | b2 | ./main | 10/8 | top | Pending | — | 2026-09-10 |
| [c1-wsl-chain-corpus](tasks/c1-wsl-chain-corpus.md) | — | ./main | 9/7 | top | Pending | — | 2026-09-10 |
| [d1-cross-track-gates](tasks/d1-cross-track-gates.md) | a1, b3, c1 | ./main | 9/5 | top | Pending | — | 2026-09-10 |

## Review findings

| ID | Severity | Confirmed finding | Correction |
|---|---|---|---|
| F1 | P1 | The proposal treated `ScriptedRunner`, WSL `Workstation`, an HTTP fake GitHub, a gateway fake GitHub, a simulated filesystem, and in-memory SQLite as one reusable harness. Repository evidence shows they live at different visibility and abstraction boundaries (`wsl_acceptance.rs:471-604`, `app/tests/support/mod.rs:178-576`, `testkit/src/github.rs:372-470`). | Split the design into a real-binary local-state track and a private scripted WSL track; documented each double's role. |
| F2 | P1 | “Hundreds or thousands” had no definition, action grammar, invariant set, coverage criterion, deterministic seed, or replay format, so a large but redundant corpus could satisfy the wording. | Added minimum counts, compatible-pair coverage, pure transition semantics, invariants, stable case IDs, and failure diagnostics in `02`/`03`. |
| F3 | P1 | Arbitrary chains across `daemon`, `service`, `update`, `tui`, and WSL would hang, replace a binary, own a terminal, or mutate host platform state (`cli/mod.rs:581-627,1494-1538,1682-1703`). | Added an allowlisted action enum and a fail-closed command-leaf accountability manifest; unsafe leaves remain in dedicated/privileged harnesses. |
| F4 | P1 | The plan claimed state verification but did not prevent the implementation from using production results as its oracle or missing atomicity, persistence, filesystem, request-budget, and secret-leak regressions. | Specified an independent model and after-each-action multi-plane oracle with mutation-sensitive gates. |
| F5 | P2 | The example `wsl update` does not exist; the command surface defines repeatable `wsl install` (`cli/mod.rs:631-640`). | Replaced it with repeated `wsl install` and aligned the WSL corpus to real leaves. |
| F6 | P2 | The current-architecture document said centralized journeys were absent, but `policy_commands.rs:84-255` and `workspace_commands.rs:369-954` already contain long real-process sequences. | Reframed the gap as systematic model/transition coverage and made existing journeys inputs rather than duplicates. |
| F7 | P2 | D2's rationale said hosted Windows runners do not support WSL2. The current official Windows image inventory lists WSLv1 and WSL2. The plan also lacked an execution worktree path, and README duplicated live status. | Corrected the external fact while retaining mocked WSL, recorded an isolated worktree root, and made ROADMAP the sole live state record. |

## Change log

| Date | Event |
|---|---|
| 2026-09-10 | Taskflow created in planning state. |
| 2026-09-10 | Adversarial review closed F1-F7. Repository feasibility, current GitHub-hosted image facts, nextest discovery, command safety, security oracles, deterministic replay, and cross-document consistency were reconciled. No product decision changed. |
| 2026-09-10 | Owner explicitly confirmed the proposed split between real CLI chains and mocked WSL scenarios, the 256+32 minimum inventories, and the all-command accountability map; D3 and D4 are locked. |
| 2026-09-10 | `taskflow-tasks` derived six immutable specs in four conflict domains. Wave 1 can run A1, B1, and C1 concurrently; B2/B3 are sequential; D1 is the final join gate. |
