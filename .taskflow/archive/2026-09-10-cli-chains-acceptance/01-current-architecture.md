# 01 Current Architecture

## Test targets and CI

`runner-manager` is a binary-only package (`crates/app/Cargo.toml:8-13`). Cargo
therefore exposes two materially different places for CLI coverage:

1. Unit tests compiled with the binary can reach private CLI seams. The managed
   WSL suite is mounted this way by `#[path = "wsl_acceptance.rs"] mod
   acceptance` (`crates/app/src/cli/wsl.rs:5417-5418`).
2. Files under `crates/app/tests/` are separate integration-test binaries. Their
   shared `support` module launches the real `runner-manager` executable with a
   disposable `--data-dir`, sanitised `RUNNER_MANAGER_*` and proxy variables,
   and a unique service fixture name (`crates/app/tests/support/mod.rs:75-145`).

The three-OS `check` matrix runs Windows x64, macOS ARM64, and Linux x64
(`.github/workflows/ci.yml:64-86`), then executes `cargo nextest run
--workspace` (`.github/workflows/ci.yml:132-148`). The release workflow calls
that same CI workflow, so a non-ignored test in either target is a pull-request,
main-branch, and release gate. This matches cargo-nextest's documented default
of running all discovered non-ignored workspace tests:
<https://nexte.st/docs/running/>.

## Existing stateful acceptance coverage

The repository already has stateful command journeys; the gap is systematic
transition coverage and a reusable model oracle, not an absence of sequential
tests.

- `crates/app/tests/policy_commands.rs:84-255` signs in, adds two repository
  policies, changes capacity and scaling, observes repair state, exercises busy
  removal refusal, and removes/purges policies across repeated real process
  invocations.
- `crates/app/tests/workspace_commands.rs:369-954` covers persisted host and
  repository workspace changes, overlap/refusal rules, warnings, and human/JSON
  agreement.
- `crates/app/tests/host_capacity_and_status.rs:91-439` covers persisted host
  capacity and status contracts.
- `crates/app/src/cli/wsl_acceptance.rs:471-604` owns a private `Workstation`
  fixture for WSL operations. It combines a temporary application-data tree
  with `ScriptedRunner`, fake release assets, and a fake credential issuer.

The published commands are `auth`, `host`, `repo`, `org`, `daemon`, `service`,
`tui`, `status`, `update`, and `wsl` (`crates/app/src/cli/mod.rs:581-627`). The
WSL mutation is `wsl install`; there is no `wsl update` subcommand. Re-running
`wsl install` performs installation or update (`crates/app/src/cli/mod.rs:631-640`).

## Test doubles are not interchangeable

There are three similarly named but distinct facilities:

- `crates/app/tests/support/mod.rs:178-576` defines a private loopback HTTP
  `FakeGithub` for authentication and repository-discovery behavior while a
  real CLI subprocess runs.
- `crates/testkit/src/github.rs:372-470` defines a domain gateway
  `FakeGithub`. It models inventory, demand, JIT registration, failures, and
  rate limits; it is not the HTTP authentication fixture.
- `ScriptedRunner` records and answers WSL/process requests
  (`crates/platform/src/wsl/exec.rs:781-900`). The WSL `Workstation` that wraps
  it is private to the WSL acceptance module and does not dispatch arbitrary
  CLI commands.

Consequently, a new sibling module cannot merely combine `Workstation`,
`ScriptedRunner`, both `FakeGithub` types, and an in-memory database into one
existing harness. Shared integration helpers must be reused from
`crates/app/tests/support/`; WSL chains must extend or factor the private WSL
fixture; daemon gateway behavior belongs to the testkit fake.

## Composition and safety boundaries

`run` resolves a fresh `Context` on each invocation and routes commands through
the production composition root (`crates/app/src/cli/mod.rs:1568-1651`). This is
valuable for persistence testing, but it also means a generic command generator
cannot safely dispatch every command:

- `daemon run` is intentionally long-lived.
- `service install` and `service uninstall` mutate the host service manager.
- `update` downloads and replaces an executable.
- `tui` owns the terminal.
- WSL commands address Windows/WSL platform state unless driven through the
  existing scripted WSL seam.

Those commands already have dedicated harnesses and privileged CI boundaries.
A combinatorial suite must use an allowlist of modelled actions and must never
turn an arbitrary generated token into an unrestricted process invocation.

## Current external constraints

The earlier plan's statement that GitHub-hosted Windows runners do not support
WSL2 is stale. The current `windows-latest` image is Windows Server 2025, and
its image inventory lists both WSLv1 and WSL2:
<https://github.com/actions/runner-images/blob/main/images/windows/Windows2025-Readme.md>.
GitHub only guarantees the documented runner image and its ephemeral VM
environment; it does not guarantee that a suitable Linux distribution is
installed and provisioned for this product. The current GitHub-hosted runner
reference is <https://docs.github.com/en/actions/reference/runners/github-hosted-runners>.
The decision to keep ordinary WSL acceptance unprivileged and scripted remains
sound because it is deterministic, cross-platform, and does not depend on
mutable hosted-image state.
