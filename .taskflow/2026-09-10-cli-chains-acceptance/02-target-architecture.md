# 02 Target Architecture

To satisfy the requirement of covering hundreds to thousands of edge-case sequences (e.g. `repo add` -> `wsl update` -> `repo list` -> `repo remove`), we will create a dedicated acceptance module: `crates/app/src/cli/chains_acceptance.rs`.

## Design
1. **Unprivileged Execution**: Like `wsl_acceptance.rs`, this new module will use mock abstractions (like `ScriptedRunner`, `FakeGitHub`, and in-memory `SqliteStore` databases) so that thousands of scenarios execute in milliseconds across Linux, macOS, and Windows.
2. **Combinatorial Generation**: We will use a property-based test approach or a large explicit recipe list (similar to `e2e_security_acceptance.rs`) to dispatch chains of CLI commands.
3. **Assertions**: After each chain, the system state (database, simulated file system, fake systemd/launchd state) will be verified against a model.
4. **Integration**: Adding `chains_acceptance.rs` directly to the `cli` module ensures it runs inside the `cargo nextest run --workspace` step in `ci.yml`, gating every Pull Request and Release.

This approach guarantees robust edge-case coverage without incurring the heavy I/O and CI constraints (e.g. WSL availability) of traditional shell-script E2E tests.
