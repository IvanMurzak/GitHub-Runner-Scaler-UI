# Task specifications

Eleven immutable specifications across five conflict domains. Derived
2026-08-25 from the reviewed design; **specs never carry `status`**, and
[`../ROADMAP.md`](../ROADMAP.md) is the only live task-state record.

## Groups are conflict domains

One group owns a set of files, and no file appears in two groups. A group runs
by ascending `sequence`; independent groups may overlap when dependencies allow.

| Group | Owns | Why these files are one domain |
|---|---|---|
| **A** | `crates/app/src/cli/mod.rs`, `crates/app/src/cli/policy.rs`, `crates/app/src/cli/auth.rs`, and the test files that exercise them: `crates/app/tests/cli_command_surface.rs`, `policy_commands.rs`, `no_secret_reaches_command_output.rs`, `auth_onboarding.rs`, `auth_states.rs` | The clap tree and the policy handlers cannot be changed apart: renaming a `RepoCommand` variant breaks `dispatch_repo` in the same commit. `cli_command_surface.rs` is here because the design list, the transcribed `SURFACE`, and the tree must land together or `main` goes red — and for the same reason each of these test files is owned by the task that changes the behaviour it asserts, so no task leaves the suite failing. `auth.rs` is here because D4's disclosure spans it and `policy.rs`. |
| **B** | `crates/domain/src/model.rs`, `crates/domain/src/store.rs`, `crates/domain/src/store/migrations/` | The `Host` field, its persistence, and its migration. |
| **C** | `crates/platform/src/service.rs`, `crates/platform/src/lock.rs`, `crates/app/src/cli/service.rs` | One error message, the value it is built from, and the CLI mapper that attaches its `try:` line. No other group touches `cli/service.rs`. |
| **D** | `crates/app/src/cli/host.rs`, `crates/app/src/cli/status.rs`, `crates/app/src/tui/shell.rs`, `crates/app/src/tui/screens.rs`, `crates/app/tests/host_capacity_and_status.rs` | Everything that *displays* the host label without owning it, plus the test file that asserts it. |
| **E** | `tests/` (the e2e crate and `host-controller.sh`), `README.md`, `crates/app/tests/readme_disclosure.rs`, `crates/app/tests/release_channels.rs`, `crates/domain/src/policy.rs` (doc comments only), `crates/testkit/src/fixtures.rs` (doc comments only) | End-to-end harness and prose, which follow the surface rather than define it. |

Two ownership notes that are easy to get wrong:

- `crates/domain/src/policy.rs` is in **E**, not **B**. Group B changes
  `model.rs`, `store.rs` and the migrations; group E changes only doc comments
  in `policy.rs`. Different files, no overlap.
- **Every `crates/app/tests/*.rs` file has exactly one owning group**, listed
  above. A task that changes behaviour also updates the test file asserting it,
  in the same commit. No task is permitted to hand a failing test to a later
  one.

## Coefficient legend

`importance` and `complexity` are 1–10. `model_hint` follows the rubric:
complexity 1–4 → `fast`, 5–7 → `mid`, 8–10 → `top`, **raised one tier** when
`security_critical` or `production_touching` is set.

| Task | imp | cx | security | production | model | Why the tier |
|---|---|---|---|---|---|---|
| `a1-warning-scope-and-argv-hints` | 2 | 4 | no | no | fast | Localised message and argv work. |
| `a2-command-surface` | 3 | 6 | no | **yes** | top | A breaking CLI contract change that ships to users; mid raised one tier. |
| `a3-host-label-resolution` | 3 | 5 | no | no | mid | Resolution order plus a refusal path with a real hazard behind it. |
| `a4-policy-copy` | 2 | 4 | no | no | fast | Strings, already specified verbatim. |
| `a5-disclosure-scope` | 3 | 5 | **yes** | no | top | Amends a security disclosure obligation; mid raised one tier. |
| `b1-host-label-model` | 3 | 6 | no | **yes** | top | A schema migration against operators' existing databases. |
| `c1-lock-remedy` | 2 | 3 | no | no | fast | One error message from a value already carried. |
| `d1-host-label-commands` | 2 | 4 | no | no | fast | One new command, two report lines. |
| `d2-status-and-tui-labels` | 2 | 3 | no | no | fast | One JSON field and two hint strings. |
| `e1-test-suite-migration` | 3 | 5 | no | no | mid | Mechanical, but spread across five files and an e2e harness. |
| `e2-docs-and-release-note` | 2 | 3 | no | no | fast | Prose, with one owner gate. |

## Owner gates

| Gate | Before | What the owner decides |
|---|---|---|
| **G4** | `a5-disclosure-scope` merges | That the D21 disclosure clause may be amended as D4 describes. If refused, `a5` falls back to the documented alternative and nothing else changes. |
| **G3** | `e2-docs-and-release-note` merges | That the `0.1.5` breaking-change note is complete: four removed commands, their replacements, and the statement that `host set-capacity` is unchanged. |

No task touches money, secrets, or an irreversible external effect. `b1`'s
migration is forward-only and runs against a local database; it is gated by
test, not by an owner.

## The one ordering that cannot be relaxed

`a2` changes the design list, the transcribed `SURFACE` constant, and the clap
tree **in one commit**. `crates/app/tests/cli_command_surface.rs:15-17` states
why the constant is hand-transcribed rather than derived, and the test compares
the two lists in both directions — so splitting `a2` turns `main` red for the
duration.
