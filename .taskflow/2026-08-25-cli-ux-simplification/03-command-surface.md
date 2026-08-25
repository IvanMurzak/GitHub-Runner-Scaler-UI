# Target command surface

**This list is exhaustive.** It replaces the list at
`.taskflow/2026-08-21-local-runner-manager/02-target-architecture.md:41-59` as
the authority `crates/app/tests/cli_command_surface.rs` transcribes by hand.
That test must keep transcribing rather than deriving; see
[`01-current-architecture.md`](01-current-architecture.md#the-command-tree).

```text
runner-manager auth login
runner-manager auth status
runner-manager auth logout
runner-manager host set-capacity N
runner-manager host set-label LABEL
runner-manager host show
runner-manager repo add OWNER/REPO [--host-label HOST] [--max-capacity N] [--enabled [BOOL]]
runner-manager repo list
runner-manager repo set OWNER/REPO [--max-capacity N] [--enabled BOOL]
runner-manager repo remove OWNER/REPO [--purge]
runner-manager org add ORG [--host-label HOST] [--max-capacity N] [--enabled [BOOL]]
runner-manager org list
runner-manager org set ORG [--max-capacity N] [--enabled BOOL]
runner-manager org remove ORG [--purge]
runner-manager daemon run
runner-manager service install [--start-at boot|login] | uninstall | status
runner-manager tui
runner-manager status [--json]
```

## Diff against `0.1.4`

| Family | `0.1.4` | Target | Change |
|---|---|---|---|
| `auth` | `login`, `status`, `logout` | same | — |
| `host` | `set-capacity`, `show` | `set-capacity`, `set-label`, `show` | **+1** (D3) |
| `repo` | `add`, `list`, `set-capacity`, `set-scale`, `remove` | `add`, `list`, `set`, `remove` | **−1** (D2) |
| `org` | `add`, `list`, `set-capacity`, `set-scale`, `remove` | `add`, `list`, `set`, `remove` | **−1** (D2) |
| `daemon` | `run` | same | — |
| `service` | `install`, `uninstall`, `status` | same | — |
| `tui`, `status` | — | same | — |

Net: 20 leaf commands, down from 21.

## The `SURFACE` constant

`crates/app/tests/cli_command_surface.rs:26-40` becomes:

```rust
const SURFACE: [(&str, &[&str]); 8] = [
    ("auth", &["login", "status", "logout"]),
    ("host", &["set-capacity", "set-label", "show"]),
    ("repo", &["add", "list", "set", "remove"]),
    ("org", &["add", "list", "set", "remove"]),
    ("daemon", &["run"]),
    ("service", &["install", "uninstall", "status"]),
    ("tui", &[]),
    ("status", &[]),
];
```

## Argument definitions

### `repo add` / `org add`

| Argument | Type | Required | Notes |
|---|---|---|---|
| `OWNER/REPO` or `ORG` | positional | yes | Unchanged. |
| `--host-label HOST` | `Option<String>` | **no** (was yes) | Per-policy override. Default: `Host.host_label` (D3). |
| `--max-capacity N` | `Option<u16>` | no | Unchanged. Omitted means monitor-only (D19). |
| `--enabled [BOOL]` | `Option<bool>` | no | **New** (D1). `num_args = 0..=1`, `default_missing_value = "true"`. Requires `--max-capacity`. |

### `repo set` / `org set`

| Argument | Type | Required | Notes |
|---|---|---|---|
| `OWNER/REPO` or `ORG` | positional | yes | |
| `--max-capacity N` | `Option<u16>` | no | Promotes a monitor-only policy, as `set-capacity` did. |
| `--enabled [BOOL]` | `Option<bool>` | no | `--enabled false` drains, with the existing confirmation. |

At least one of the two must be given; `repo set X` alone is a usage error
naming both flags. This maps one-to-one onto `PolicyMutation`
(`crates/app/src/cli/policy.rs:504-509`), whose `cache_policy` field stays
TUI-only and is not exposed on the CLI by this work.

**One edge `--enabled`'s optional value creates.** With `num_args = 0..=1`,
`runner-manager repo set --enabled OWNER/REPO` — flag before positional —
makes clap offer `OWNER/REPO` to `--enabled` as its value, which then fails to
parse as a bool. The failure is loud and immediate, not silent, but its message
is about a bool and the mistake was word order. A task must assert this case and
give it a message naming the real problem:

```text
error: `--enabled` was given `IvanMurzak/AI-Game-Dev-App` as its value.
       Put the repository first: runner-manager repo set IvanMurzak/AI-Game-Dev-App --enabled
```

This is the price of accepting both `--enabled` and `--enabled true`, and it is
worth paying: the transcript shows both spellings being typed, and neither
word order was.

### `host set-label`

| Argument | Type | Required | Notes |
|---|---|---|---|
| `LABEL` | positional | yes | Validated by `HostLabel::new`. Matches `host set-capacity N`, which is also positional. |

## Help text

Every `about` line is rewritten to say what the command does for the operator,
not what it does to the model. The current `repo set-scale` reads *"Arm or drain
a policy"* (`crates/app/src/cli/mod.rs:504`) — accurate, and two domain terms
the reader has not met yet.

| Command | Target `about` |
|---|---|
| `repo add` | `Watch a repository, and optionally start runners for it on this machine.` |
| `repo set` | `Change a repository policy's capacity, or turn its scaling on and off.` |
| `repo list` | `List repository policies, their capacity, and their routing labels.` |
| `repo remove` | `Stop managing a repository on this machine.` |
| `host set-label` | `Set this machine's routing name, which its runner labels are built from.` |
| `host show` | `This machine's routing label, capacity, secret store, and REST budget.` |

`org` mirrors `repo` with "organization" in place of "repository".

## Exit codes

Unchanged. `Failure` (`crates/app/src/cli/mod.rs:199`) gains no variant;
`2` remains clap's, including for the D7 swapped-order hint.
