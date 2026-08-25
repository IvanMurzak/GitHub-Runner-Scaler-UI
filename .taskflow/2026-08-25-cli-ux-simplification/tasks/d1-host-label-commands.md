---
id: "d1-host-label-commands"
title: "host set-label, and host show reports the routing label"
group: "D"
sequence: 1
repo: "."
base_branch: "main"
depends_on: ["a2-command-surface", "b1-host-label-model"]
importance: 2
complexity: 4
security_critical: false
production_touching: false
model_hint: "fast"
taskflow_refs: ["02-target-architecture.md", "04-message-inventory.md", "03-command-surface.md"]
---

## Goal

Make the routing identity readable and changeable. A label nobody can read is a
label nobody can put in `runs-on` — and today no command prints it.

## Scope & seams

**Files:** `crates/app/src/cli/host.rs`,
`crates/app/tests/host_capacity_and_status.rs`.

`a2` has already declared `host set-label LABEL` in the tree; this task
implements it.

### `host show`

Insert two lines after `id` (`crates/app/src/cli/host.rs:472-479`), per
[`04-message-inventory.md`](../04-message-inventory.md#5-host-show):

```text
  host label                ivanpc
  routing label             rm-ivanpc-win-x64
```

The routing label comes from `RoutingLabels::derive` over the host's label, OS
and architecture — the same function `add` uses, never a second formatting of
the same string.

`host show` reads no network (`host.rs:451-453`) and must keep doing so. Where
the host has no label yet (`None` after `b1`'s migration), print what
`default_host_label()` would produce and say it is not yet recorded, in the same
spirit as the existing no-host-record branch (`host.rs:465-470`).

### `host set-label LABEL`

Positional, matching `host set-capacity N`. Validates through `HostLabel::new`.

It **warns and does not refuse** when policies already exist, per
[`04-message-inventory.md`](../04-message-inventory.md#6-host-set-label-new).
Changing the host label does not re-derive labels already reserved on existing
policies: those keep their `requested_host_label`, and only new policies pick up
the new default. Saying so at the moment of change is the only reason this
command prints anything beyond the new value.

Use the `write_failed("this host's ...")` noun convention.

**One declared carve-out into group A's file.**
`every_command_names_the_operation_whose_output_failed` (`crates/app/src/cli/mod.rs:1628-1685`)
holds a table of commands and the noun each must use, and it calls the handlers
directly — so the entry for `host set-label` cannot be added before this task's
handler exists. `d1` therefore owns **that test function alone** inside
`mod.rs`. It touches nothing else in the file, and `a3`, `a4` and `a5` touch
nothing inside it. Should a merge conflict arise anyway, `d1` rebases; group A
does not wait.

## Definition of Done

1. `host show` prints the host label and the routing label, and the routing
   label equals what `repo add` reserves for a policy created with no
   `--host-label` on the same machine. Asserted by comparing the two, not by
   hard-coding a string.
2. `host show` still issues no network request.
3. `host set-label office` changes the value; a following `host show` reports
   `office` and `rm-office-<os>-<arch>`.
4. `host set-label` on a host with existing policies prints the warning naming
   the count, and those policies' routing labels are **unchanged** afterwards.
5. `host set-label "Bad Name!"` is refused by `HostLabel::new`'s rules with a
   remedy, and the stored label is unchanged.
6. `host set-capacity` is untouched and `host_capacity_and_status.rs`'s existing
   assertions on it pass unmodified.
7. `every_command_names_the_operation_whose_output_failed` (`mod.rs:1628`)
   covers `host set-label`.
8. `cargo test -p runner-manager-app` passes.
