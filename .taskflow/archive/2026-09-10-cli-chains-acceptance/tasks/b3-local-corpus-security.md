---
id: "b3-local-corpus-security"
title: "Complete 256 local chains with security and runtime evidence"
group: "B"
sequence: 3
repo: "."
base_branch: "main"
depends_on: ["b2-local-chain-runner"]
importance: 10
complexity: 8
security_critical: true
production_touching: false
model_hint: "top"
taskflow_refs: ["02-target-architecture.md", "03-coverage-model.md"]
---

## Goal

Execute the complete local transition inventory and prove its state, security,
replay, and bounded-runtime guarantees on the default test path.

## Scope & seams

- Wire all `local-NNNN` inventory entries into default execution; no ignored,
  sampled, randomized, or CI-only subset may stand in for the full corpus.
- Complete after-each-action readbacks through status, host, repo, org, public
  store, filesystem, and fake request history wherever the model exposes them.
- Scan fixture tokens, device codes, JIT values, and explicit canaries across
  stdout, stderr, logs, the temporary data tree, and SQLite textual dumps.
- Add mutation-sensitive controls for leak scans, atomic refusals, independent
  expectations, complete corpus selection, and pairwise witnesses.
- Record total and slowest-case timings against the 60-second soft per-OS target;
  report overages without skipping or converting elapsed time into correctness.

## Definition of Done

1. At least 256 meaningful named cases execute under the default nextest run and
   the suite asserts the inventory/execution counts agree.
2. All invariants in `03-coverage-model.md` have named evidence and failures
   identify the first divergent transition with replay data.
3. Injecting each protected canary into every scanned plane makes a test fail;
   clean runs contain none of them.
4. The suite reports total and slowest-case timing and stays within the initial
   soft target on representative CI hardware or records actionable overage data.
5. Existing focused CLI acceptance tests remain intact and non-duplicated
   except for helpers deliberately factored into shared support.
6. App integration tests, workspace nextest, format, and clippy gates pass.
