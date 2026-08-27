---
id: "a2-command-surface"
title: "The target command surface: repo/org set, add --enabled, optional --host-label, host set-label"
group: "A"
sequence: 2
repo: "."
base_branch: "main"
depends_on: ["a1-warning-scope-and-argv-hints", "b1-host-label-model"]
importance: 3
complexity: 6
security_critical: false
production_touching: true
model_hint: "top"
taskflow_refs: ["03-command-surface.md", "02-target-architecture.md", "05-migration-compatibility.md"]
---

## Goal

Land the whole surface change of D1, D2 and D3 in **one commit**: the design
list, the hand-transcribed `SURFACE`, the clap tree, and the dispatch arms that
must compile against it.

`production_touching` is set because this removes four commands operators may
have scripted. That is accepted at `0.1.4` (D2); the release note is `e2`'s.

## Scope & seams

**Files:** `crates/app/src/cli/mod.rs`, `crates/app/src/cli/policy.rs` (dispatch
and handler wiring only — copy is `a4`'s),
`crates/app/tests/cli_command_surface.rs`,
`crates/app/tests/policy_commands.rs`,
`crates/app/tests/no_secret_reaches_command_output.rs`.

The last two are in scope because they drive the removed commands by name
(`policy_commands.rs:140,178,263`;
`no_secret_reaches_command_output.rs:103-104,116-117`) and would fail the moment
the tree changes. **This task leaves the suite green; it does not hand a failing
test to a later task.**

### The surface

Exactly [`03-command-surface.md`](../03-command-surface.md). Summarised:

- `repo`/`org`: `set-capacity` and `set-scale` are **removed**; `set` replaces
  both, taking `--max-capacity N` and `--enabled BOOL`.
- `repo`/`org` `add`: `--host-label` becomes `Option<String>`; `--enabled`
  is added.
- `host`: `set-label LABEL` is added.
- **`host set-capacity` is not touched.** It is the host ceiling (D9) and
  merely shares a name fragment with a command being removed. A global
  find-and-replace on `set-capacity` breaks it.

### `--enabled` accepts both spellings

`num_args = 0..=1`, `default_missing_value = "true"`, on **both** `add` and
`set`, so `--enabled`, `--enabled true` and `--enabled false` all parse. clap is
`4.6.6` (`Cargo.toml:155`), which supports this. The uniformity is the point:
the captured session typed both spellings one command apart.

Two argument rules:

1. On `add`, `--enabled` **requires** `--max-capacity`, refused at parse time
   with the message in
   [`04-message-inventory.md`](../04-message-inventory.md#4-monitor-only-cannot-be-armed).
   Without a capacity the policy is monitor-only (D19) and has no routing label
   to arm; refusing before the GitHub round-trip `add` performs is a real
   saving as well as a clearer failure.
2. On `set`, at least one of the two flags must be given.

### The word-order edge `--enabled` creates

`repo set --enabled OWNER/REPO` offers the positional to `--enabled` as its
value. See
[`03-command-surface.md`](../03-command-surface.md#repo-set--org-set) for the
required message; a bool-parse error naming the repository is not acceptable.

### Why this cannot be split

`crates/app/tests/cli_command_surface.rs:15-17` states that the `SURFACE`
constant is transcribed from the design **by hand**, on purpose, and the test
compares the design's list against `--help` in both directions. Changing the
tree without the constant, or either without the design list, turns `main` red.
Update `cli_command_surface.rs`'s header comment to cite
`03-command-surface.md` as its source.

### Handlers

`dispatch_repo`/`dispatch_org` (`crates/app/src/cli/policy.rs:22-87`) collapse
their two arms into one `set` arm onto `apply_policy_mutation`
(`policy.rs:556`), which already applies capacity and enable as one atomic,
optimistically-concurrent write and is already driven that way by the TUI. **No
new store path is needed, and none may be added.**

`add` resolves its label through `--host-label` when given; the fallback to
`Host.host_label` is `a3`'s. Until `a3` lands, `add` with no `--host-label` may
fail — but it must fail with a real error, never a panic.

Existing behaviour to preserve, each currently asserted:

- `add` with no `--enabled` still creates a disabled policy and still says
  `pending; scaling is disabled` (D20's default survives).
- `set --enabled false` still routes through `confirm_disable`
  (`policy.rs:699`) when runners are active.
- Duplicate `add` still fails `Failure::Conflict` (`policy.rs:226-227`).
- `Failure` gains no variant; `2` stays clap's.

## Definition of Done

1. `--help` for the root and for each family lists exactly
   [`03-command-surface.md`](../03-command-surface.md), verified by the existing
   two-direction test with `SURFACE` updated to eight families / twenty leaves.
2. `runner-manager repo set-scale X --enabled true` exits `2`. So does
   `repo set-capacity`, `org set-scale`, `org set-capacity`.
3. `runner-manager host set-capacity 4` still works, unchanged.
4. `repo set X --enabled`, `--enabled true`, and `--enabled false` all parse to
   the expected `Option<bool>`; so do the same three on `repo add`. Replaces
   `repository_and_organization_set_scale_parse_explicit_true_and_false`
   (`mod.rs:1701`).
5. `repo add X --enabled` with no `--max-capacity` fails at parse time, before
   any network call, naming `--max-capacity` in its remedy.
6. `repo set X` with neither flag fails, naming both.
7. `repo set --enabled X` fails with the word-order message, not a bool-parse
   error.
8. `repo set X --max-capacity 6 --enabled` performs **one** store write:
   asserted through the policy's `revision`, which must advance by one.
9. `Cli::command().debug_assert()` passes (`mod.rs:1690`).
10. `cargo build --workspace` and `cargo test -p runner-manager-app` both pass.
    No test is left failing for a later task. The e2e crate (`tests/`) is
    `e1`'s and may still name the old commands at this point; it is not built by
    `-p runner-manager-app`.
