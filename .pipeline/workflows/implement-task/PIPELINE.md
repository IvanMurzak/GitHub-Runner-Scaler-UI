# implement-task — one runner-manager task from implementation to merge

One run implements one task in an isolated worktree, reviews and simplifies the
branch, then publishes one final state and squash-merges it after every GitHub
check is green. The executable definition is `pipeline.yml`; this file explains
the contract to maintainers.

## End state

The requested change and its tests are committed on a run worktree branch,
reviewed with fixes, simplified where useful, and merged into `main` through a
pull request. The completed worktree and local run branch are then reaped by the
pipeline CLI.

## Publishing invariant

Only `land` may write to GitHub. Earlier steps may read an issue referenced by
the task, but they commit locally and never push or create a PR. `land` publishes
the final reviewed branch once, waits for the complete PR check rollup from both
`.github/workflows/ci.yml` and `.github/workflows/e2e.yml`, and merges only after
`pipeline ci-wait` exits 0.

The four steps have `self_improve: false`. A completed run uses the pipeline
CLI's built-in worktree teardown, so edits made to the workflow inside the run
would otherwise be deleted with the worktree. Workflow changes are reviewed and
committed normally from the main checkout instead.

## Project context

- This repository is the Rust workspace for `runner-manager`. Workspace members
  live in `crates/` and `tests/`; the root `Cargo.toml`, `Cargo.lock`, and
  `rust-toolchain.toml` define the build.
- The local gate intentionally mirrors the ordinary CI job: locked metadata,
  formatting, all-feature workspace build, shippable-mutant scan, clippy with
  warnings denied, and workspace tests. Privileged installer tests and ignored
  end-to-end scenarios remain CI/task-specific gates because they require
  platform privileges or fixture credentials.
- When the task names a file under `.taskflow/`, that immutable task spec and
  its linked architecture set provide the acceptance criteria and locked
  decisions. For an ordinary issue or free-form task, the task text, existing
  behavior, tests, README, and GitHub workflows are authoritative.
- No consumer worktree hooks are required. With no `.pipeline/.hooks/` present,
  the installed pipeline CLI provisions and tears down an external worktree
  itself. `PIPELINE_WT_ROOT` may override its default slot root.
- `pipeline`, `git`, Cargo, and an authenticated `gh` must be on `PATH`.

## Start a run

```text
/pipeline:run <repo>/.pipeline/workflows/implement-task '<task text, issue reference, or .taskflow task path>'
```

A run halted at `land` keeps its worktree. Resume the same run after addressing
the reported blocker; `land` reuses an existing open PR for the run branch.
