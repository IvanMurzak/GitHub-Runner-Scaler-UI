# 01 Current Architecture

The project has multiple layers of testing:
1. **Unit tests**: Found adjacent to source files.
2. **Acceptance tests**: `crates/app/src/cli/wsl_acceptance.rs`, which uses `Workstation` and `ScriptedRunner` to test the WSL host feature without invoking real `wsl.exe`.
3. **E2E Security Tests**: `tests/tests/e2e_security_acceptance.rs` driven by `tests/e2e-host-controller`, which runs actual binaries against a FakeGitHub backend, but requires a pre-built workspace and runs locally via `cargo test -p runner-manager-e2e`.

Currently, CLI commands for `repo`, `org`, `daemon` are tested in their respective modules (e.g. `crates/app/src/cli/policy.rs`), but there is no centralized acceptance test suite that executes long, sequential chains of commands (install, add repo, modify repo, delete repo) in a combinatorial fashion to ensure system consistency across operations.
