# 02 Target Architecture

## Objective

Add deterministic, model-based acceptance coverage for hundreds of meaningful
CLI state transitions while preserving the production parser, process-restart,
filesystem, SQLite, output, and exit-code boundaries. Keep platform-destructive
or non-terminating commands in their purpose-built harnesses.

“Hundreds” means at least 256 distinct, named transition cases in the default
test run. The suite reports the exact case name, seed, initial model, action
list, and first divergent observation on failure, so every failure is directly
replayable.

## Architecture

### 1. Black-box local-state chains

Create `crates/app/tests/cli_chains_acceptance.rs` and factor only generally
useful helpers from `crates/app/tests/support/mod.rs`. Each scenario owns one
temporary data root and invokes the real binary once per action through the
existing `runner_manager` / `runner_manager_against` wrapper. This deliberately
tests process restart and SQLite persistence; it does not call `cli::route`
directly or substitute an in-memory database.

The action grammar is an enum, not arbitrary strings. Its initial allowlist is:

- host: `set-capacity`, `set-runtime-root`, `reset-runtime-root`, `show`;
- repository: `add`, `list`, `set-capacity`, `set-scale`, `add-label`,
  `remove-label`, `set-workspace`, `remove`;
- organization: `add`, `list`, `set-capacity`, `set-scale`, `add-label`,
  `remove-label`, `remove`;
- readback: `status --json`;
- authentication setup/teardown needed by policy discovery, using the existing
  loopback HTTP fixture and fake credentials.

The generator produces a fixed checked-in corpus from a stable seed. It covers
valid and invalid transitions, duplicate operations, missing targets, boundary
capacities, repeated labels, derived-label removal refusal, workspace-mode/path
rules, overlapping roots, active-attempt removal refusal, idempotent reads, and
repo/org coexistence. Pairwise transition coverage is mandatory for every
compatible mutating action pair; longer curated journeys cover interactions
that require three or more steps. No new property-testing dependency is needed.

### 2. Executable reference model

The suite maintains a small model containing only externally observable state:
host capacity/runtime-root selection, credential presence, repository and
organization policies, their capacities/enabled state/labels/workspace mode,
and expected diagnostics retention. Each action returns an expected exit class
and state delta.

After every action, the oracle compares:

1. exit code and the stable semantic fields of stdout/stderr;
2. `status --json`, `host show`, `repo list`, and `org list` as applicable;
3. persisted SQLite state through the public `Store` interface;
4. filesystem existence/non-existence beneath the scenario's temporary roots;
5. fake-GitHub request history, proving read-only discovery and bounded calls;
6. secret canaries against stdout, stderr, logs, the data tree, and SQLite text.

Human prose is checked for required semantic fragments, not entire snapshots,
unless an existing command contract already pins exact output. Generated paths,
UUIDs, timestamps, and derived host labels are normalised before comparison.

### 3. WSL chains remain at the WSL seam

Extend `crates/app/src/cli/wsl_acceptance.rs` (or factor a private sibling module
under `cli::wsl`) so its existing `Workstation` drives deterministic sequences
of `wsl list`, repeated `wsl install`, `wsl status`, `wsl detach`, and proxied
selected-host commands. Use `ScriptedRunner` histories plus provider-record and
output assertions as the oracle. Do not invoke real `wsl.exe`, install a
distribution, or claim that the black-box local-state model simulates WSL.

At least 32 named WSL transition cases cover fresh/adopted/drifted/partial
states, exact distribution names, capacity changes, repeat installation,
detach/re-attach, injected stage failures, and secret redaction.

### 4. Explicit non-generative boundary

The combinatorial generator does not execute `daemon run`, `service install`,
`service uninstall`, `update` without `--check`, `tui`, hidden commands, or real
WSL operations. These are long-lived, terminal-owning, self-replacing, or host
mutating. Their existing dedicated tests remain authoritative. The new suite
adds a coverage-manifest test that enumerates every published command leaf and
maps it to one of:

- modelled local chain;
- scripted WSL chain;
- existing dedicated acceptance test;
- privileged CI test;
- intentionally non-executable surface check.

The manifest fails when a new command leaf is added without a classification.
This gives the requested wide-surface accountability without pretending every
Cartesian product is safe or meaningful.

## Determinism, isolation, and runtime budget

- Every scenario gets a unique temporary data root, service fixture tag, fake
  GitHub server, and model. It may not read or mutate a developer's standard
  data directories, credential store, service registration, or network.
- Generated cases are independent tests or are serialised inside one test
  binary with explicit case isolation; they do not share mutable environment
  variables. The existing wrapper's environment sanitisation is retained.
- The corpus order and seed are fixed. A single-case filter/environment input
  may select a case for local replay, but cannot change the default CI corpus.
- A wall-clock assertion is not used as a correctness oracle. Instead, CI gets
  an agreed soft budget recorded by the suite summary; the task initially
  targets 60 seconds per OS for all local and WSL chain cases combined. A
  runtime overage is reported with the slowest cases and is not silently
  skipped.

## CI and acceptance gates

No workflow edit is required for ordinary coverage: both the binary unit-test
module and app integration-test target are discovered by `cargo nextest run
--workspace`. Cargo documents that integration tests can execute the package's
binary, and that the binary is built for them:
<https://doc.rust-lang.org/cargo/commands/cargo-test.html>.

Completion requires:

1. the checked-in suite inventory contains at least 256 named local transition
   cases and 32 named WSL transition cases, and the default nextest run executes
   the complete inventories;
2. all compatible mutating action pairs have a recorded coverage witness;
3. deliberately corrupted model expectations make the oracle fail;
4. a deliberately leaked canary makes every relevant secret scan fail;
5. a newly added unclassified command leaf makes the coverage manifest fail;
6. `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and
   `cargo nextest run --workspace` pass;
7. the suite passes on the repository's Windows x64, macOS ARM64, and Linux x64
   CI legs without privileged operations or external network access.

## Execution isolation

Implementation tasks run in separate worktrees rooted at
`C:/tmp/pipeline-worktrees/github-runner-scaler-ui-cli-chains/<task-run-id>`.
The shared checkout remains the Taskflow scheduler and ROADMAP writer.
