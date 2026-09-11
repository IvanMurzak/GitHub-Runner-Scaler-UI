---
id: "r2-windows-line-ending-test-correction"
title: "Make the WSL proxy source-shape test independent of checkout line endings"
group: "R"
sequence: 2
repo: "."
base_branch: "worktree-01a079e2-e745-7045-8702-c95dd27ee27c"
depends_on: []
importance: 8
complexity: 2
security_critical: false
production_touching: false
model_hint: "mid"
taskflow_refs: ["tasks/b2-wsl-cli-orchestration.md"]
---

## Goal

Correct PR #54's Windows-only test defect without weakening the assertion that
the WSL host proxy does not configure or intercept standard streams.

## Scope & seams

- Work only in the preserved worktree
  `C:/tmp/pipeline-worktrees/github-runner-scaler-ui-ebf6e420/01a079e2-e745-7045-8702-c95dd27ee27c`
  on the existing PR #54 branch.
- Fix `cli::wsl::tests::the_proxy_configures_no_stream_of_its_own`. Its
  `include_str!("wsl.rs")` helper searches for LF-only syntax and panics after
  GitHub's Windows checkout converts Rust source to CRLF.
- Make the source-shape assertion line-ending-independent, preferably by
  normalizing the included source inside the test/helper. Do not change proxy
  production behavior, weaken the stream assertions, or add a repository-wide
  line-ending policy merely to accommodate this test.

## Definition of Done

1. The focused WSL proxy test passes from a CRLF checkout and still fails if
   stdin, stdout, or stderr configuration is introduced into the proxy body.
2. Existing WSL CLI tests pass locally.
3. Format, clippy, and `cargo test --workspace` pass.
4. The correction is committed and pushed to PR #54's existing branch; all PR
   checks, including Windows x86_64, are green before merge.
