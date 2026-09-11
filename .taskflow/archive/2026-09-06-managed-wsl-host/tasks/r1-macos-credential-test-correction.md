---
id: "r1-macos-credential-test-correction"
title: "Replace the macOS Keychain corruption assumption in credential broker tests"
group: "R"
sequence: 1
repo: "."
base_branch: "worktree-01a078d9-cdbe-70f3-a422-49f05296c1c8"
depends_on: []
importance: 9
complexity: 3
security_critical: true
production_touching: false
model_hint: "mid"
taskflow_refs: ["03-security-and-lifecycle.md", "tasks/b1-credential-broker.md"]
---

## Goal

Correct PR #52's one cross-platform test defect without weakening the proof that
the credential broker never reads the active host secret store.

## Scope & seams

- Work only in the preserved worktree
  `C:/tmp/pipeline-worktrees/github-runner-scaler-ui-ebf6e420/01a078d9-cdbe-70f3-a422-49f05296c1c8`
  on the existing PR #52 branch.
- Replace `the_broker_succeeds_when_the_active_windows_store_cannot_even_be_read`'s
  platform-backed file corruption setup. macOS Keychain may keep an item through
  an open handle even when the backing test file is overwritten, so this is not
  a deterministic unreadable-store oracle.
- Use an injectable `SecretStore` test double whose `load` deterministically
  fails or records/panics if called. Drive the real broker path and prove it
  succeeds without invoking that store. Keep the distinct Windows/WSL canaries
  and all existing leak assertions.
- Do not change broker production behavior or relax any assertion to special-case
  macOS.

## Definition of Done

1. The test proves the active store load count is zero (or would fail immediately
   if called) while a fresh WSL credential is delivered.
2. No test mutates a Keychain backing file and infers live Keychain state from it.
3. Focused auth tests and `cargo test --workspace` pass locally.
4. Format and clippy pass.
5. The correction is committed and pushed to PR #52's existing branch; all PR
   checks, including macOS arm64, are green before merge.

