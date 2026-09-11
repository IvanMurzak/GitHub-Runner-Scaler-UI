---
id: "a1-workspace-ci-foundation"
title: "Rust workspace, pinned toolchain, shared dependency table, crate and module skeleton, CI matrix, release-workflow skeleton"
group: "A"
sequence: 1
repo: "."
depends_on: []
importance: 10
complexity: 5
security_critical: false
production_touching: false
model_hint: "mid"
taskflow_refs: ["02-target-architecture.md", "06-migration-rollout.md", "09-release-distribution.md"]
---

## Goal

Turn a repository that contains only `LICENSE`, `.gitignore`, and this taskflow
into a buildable, tested, six-crate Rust workspace, and establish the two
properties every later task depends on: **every manifest is owned here**, and
**every module file a later group will edit already exists**. Without both, 22
parallel tasks collide on `Cargo.lock` and on module declaration lists.

## Scope & seams

Creates the workspace shape in `02-target-architecture.md` exactly — `crates/`
at the repository root, no nested product directory:

```text
Cargo.toml          virtual workspace manifest + full [workspace.dependencies]
Cargo.lock          committed
rust-toolchain.toml pinned toolchain
crates/{app,domain,github,agent,platform,testkit}/
.github/workflows/{ci.yml,release.yml}
```

**Manifest ownership.** The root manifest declares every external dependency
the design names — Tokio, Reqwest, Ratatui with its default Crossterm backend,
Clap, rusqlite, Serde, uuid, thiserror, tracing — with exact versions, and each
crate manifest consumes them with `workspace = true`. Crate manifests are
written here for all six crates, including dependencies a crate does not use
yet, so that no later task edits a manifest. Record in the root manifest a
comment stating that adding a new external crate is an A-group change.

**Module skeleton.** Create every module file later groups own, each an empty
`pub mod` declaration plus a one-line `// owner: <task-id>` comment:

```text
crates/app/src/main.rs, cli/{mod,auth,host,policy,status,daemon,service}.rs,
                        tui/{mod,shell,screens,settings}.rs
crates/domain/src/{lib,model,policy,attempt,capacity,store}.rs
crates/github/src/{lib,device_flow,rest,demand,jit}.rs
crates/agent/src/{lib,reconcile,package,lifecycle}.rs
crates/platform/src/{lib,os,paths,lock,process,secrets,service,logging}.rs
crates/testkit/src/{lib,clock,fixtures,github}.rs
tests/                 (workspace-root acceptance suite, owner h1)
```

`main.rs` wires `cli` and `tui` behind the command dispatch so groups F and G
never edit the same file.

**CI** (`ci.yml`, D10): triggers `pull_request: [opened, synchronize, reopened]`
and `push: branches: [main]`. Matrix `windows-latest`, `macos-latest`,
`ubuntu-latest`, with the macOS job on ARM64. Each job runs `cargo fmt --check`,
`cargo clippy --all-targets -- -D warnings`, and `cargo test --workspace`
against the pinned toolchain with a dependency cache. Add a separate `e2e` job
that runs a fixed command (`cargo test -p runner-manager-e2e -- --ignored`) and
**skips cleanly when its repository secret is absent**, so task `h1` fills the
suite in without ever editing this workflow. No release trigger exists here.

**Release skeleton** (`release.yml`): `workflow_dispatch` with a required
`version` input and `permissions: contents: write`, and nothing else. Task `a2`
fills in the steps. Creating the file here, with its trigger and permission
block already correct, keeps the "exactly one trigger" acceptance check
(`09-release-distribution.md`) true from the first commit.

Out of scope: any product logic, any release step body, any install script.

## Definition of Done

- `cargo build --workspace`, `cargo test --workspace`, `cargo fmt --check`, and
  `cargo clippy --all-targets -- -D warnings` all pass locally and in CI on all
  three matrix legs.
- `Cargo.lock` is committed; `rust-toolchain.toml` pins a specific stable
  version, not a channel alias.
- Every module file listed above exists and compiles; every crate manifest is
  complete; no crate manifest needs editing to add a dependency the design
  already names.
- The workspace root package, binary, and published crate name are all
  `runner-manager` (`02-target-architecture.md`, RESOLVED 2026-08-21).
- `ci.yml` runs on pull-request open/synchronize/reopen and on push to `main`,
  and contains no release trigger. `release.yml` contains exactly one trigger,
  `workflow_dispatch`.
- The `e2e` CI job is present and skips — not fails — when its secret is unset.
- A pull request against this branch shows CI as a status check.
