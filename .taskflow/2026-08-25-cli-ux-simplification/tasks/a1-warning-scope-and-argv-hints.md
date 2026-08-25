---
id: "a1-warning-scope-and-argv-hints"
title: "Scope the App-override warning to commands it can affect, and diagnose the two argv dead ends"
group: "A"
sequence: 1
repo: "."
base_branch: "main"
depends_on: []
importance: 2
complexity: 4
security_critical: false
production_touching: false
model_hint: "fast"
taskflow_refs: ["02-target-architecture.md", "04-message-inventory.md"]
---

## Goal

Stop printing an advisory warning above six of every seven outputs, and make the
two argv mistakes in the captured session say what to do. D5 and D7.

Nothing about the command surface changes, so this task lands before `a2` and
is independently revertable.

## Scope & seams

**Files:** `crates/app/src/cli/mod.rs` only.

### D5 — warning scope

`warn_about_an_app_override` is called from `Context::resolve`
(`crates/app/src/cli/mod.rs:711`), which every command reaches, including the
TUI (`crates/app/src/tui/mod.rs:16`).

Split the two branches of `write_app_override_warning` (`mod.rs:1392-1425`) by
audience:

- **Overrides in force** (`RUNNER_MANAGER_GITHUB_BASE_URL` set): unchanged.
  Every command keeps warning. This branch describes what the process is
  actually doing.
- **Overrides ignored**: emitted only for `auth login`, `auth status`,
  `daemon run`, `service install`, `service uninstall`, `service status`.

Express the second rule as a predicate over the parsed `Command`, written beside
`is_decorated_report` (`mod.rs:1109-1122`), which already classifies commands
this way. `Context::resolve` gains the information it needs, or the call moves
to where the command is known — either is acceptable; do not duplicate the
decision in two places.

`write_app_override_warning` itself must keep its current signature and text so
the existing test that drives it directly keeps passing.

Do **not** delete the ignored-branch warning. `mod.rs:1358-1373` records the
incident it exists for: a `runner-manager-d17-spike` override survived at
machine scope and shipped `0.1.2` authenticating as the spike.

### D7 — swapped noun and verb

Before `Cli::parse()` in `dispatch` (`mod.rs:970`), inspect `argv`. When
`argv[1]` is a family verb (`add`, `list`, `set`, `remove`, `show`, `install`,
`uninstall`, `status`, `login`, `logout`, `run`, `set-capacity`, `set-label`)
**and** `argv[2]` is a family (`repo`, `org`, `host`, `auth`, `daemon`,
`service`), print the hint from
[`04-message-inventory.md`](../04-message-inventory.md#8-swapped-noun-and-verb-new-d7)
with the remaining arguments preserved, and exit `2`.

Exit code `2` is required, not incidental: clap owns it for usage errors
(`mod.rs:135-140`), and a script must not distinguish this hint from the error
it replaces.

Both orders remain **unaccepted**. This diagnoses; it does not add aliases. The
`SURFACE` test must stay meaningful.

### D7 — unknown flag

Replace clap's `tip: to pass '--enabled' as a value, use '-- --enabled'` for
unknown long flags with the accepted flags of the subcommand actually reached,
read from the clap `Command` so the list cannot drift from the tree.

## Definition of Done

1. `RUNNER_MANAGER_GITHUB_CLIENT_ID` set with no `RUNNER_MANAGER_GITHUB_BASE_URL`
   produces **no stderr output** from `repo add`, `repo list`, `host show`,
   `status`, and `tui`; and still produces the warning from `auth login`,
   `auth status`, `daemon run`, and all three `service` subcommands. Asserted
   per command, so a future command is silent by default.
2. With `RUNNER_MANAGER_GITHUB_BASE_URL` pointing at a loopback fake, the
   in-force warning still appears on every command, unchanged.
3. `runner-manager add repo octo/one` exits `2` and stderr contains
   `try: runner-manager repo add octo/one`.
4. `runner-manager show host` exits `2` and names `runner-manager host show`.
5. A genuine unknown subcommand (`runner-manager frobnicate`) is unaffected and
   keeps clap's own error.
6. `runner-manager repo add octo/one --nonesuch` names the flags `repo add`
   accepts and does **not** contain the string `-- --nonesuch`.
7. `cargo test -p runner-manager-app` passes, including the existing test that
   drives `write_app_override_warning` directly.
8. `crates/app/tests/cli_command_surface.rs` is untouched and passes — this task
   changes no command.
