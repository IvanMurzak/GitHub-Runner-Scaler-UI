# Execution Roadmap

| Task (spec) | needs | repo/base | imp/cx | model | Status | Run / PR | Updated |
|---|---|---|---|---|---|---|---|
| Review 01 & 02 | - | .taskflow/... | - | - | Pending | - | - |
| Define Test Scenarios | Review | crates/app/src/cli/ | - | - | Pending | - | - |
| Implement Test Harness | Scenarios | crates/app/src/cli/ | - | - | Pending | - | - |
| Add Edge Case Tests | Harness | crates/app/src/cli/ | - | - | Pending | - | - |

## Waves
1. **Wave 1:** Agree on the target architecture for combinatorial CLI testing (01/02 docs).
2. **Wave 2:** Build the harness (e.g. extending `Workstation` or `CommandRunner` to accept command arrays).
3. **Wave 3:** Inject 100+ edge-case sequences.
