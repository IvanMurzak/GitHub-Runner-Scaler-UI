---
id: "a3-host-label-resolution"
title: "Derive the routing label from the host, and refuse to guess when the machine has no name"
group: "A"
sequence: 3
repo: "."
base_branch: "main"
depends_on: ["a2-command-surface"]
importance: 3
complexity: 5
security_critical: false
production_touching: false
model_hint: "mid"
taskflow_refs: ["02-target-architecture.md", "04-message-inventory.md"]
---

## Goal

Make `--host-label` genuinely optional: `repo add` with no flag uses the host's
own label, derived once from the machine name. D3's CLI half.

## Scope & seams

**Files:** `crates/app/src/cli/mod.rs` (`create_local_host`,
`default_host_label`), `crates/app/src/cli/policy.rs` (resolution on the `add`
path).

### Resolution order

1. `--host-label` on the command, if given. Unchanged semantics: still stored
   as `ScalePolicy.requested_host_label`, still a per-policy override.
2. Otherwise `Host.host_label` (`b1`).

### `default_host_label()`

New, beside `local_display_name()` (`crates/app/src/cli/mod.rs:1511-1521`).
Sanitises the machine name into something `HostLabel::new` accepts
(`crates/domain/src/model.rs:580-610`): lower-case; every character outside
`[a-z0-9_-]` replaced with `-`; runs of `-` collapsed; leading and trailing `-`
trimmed; truncated to `HostLabel::MAX_LEN` (64).

`Host.host_label` is set from it when the host record is created
(`mod.rs:1471`), and when a migrated host loaded `None`.

### The fallback must not be defaulted from — this is the point of the task

`local_display_name()` returns the constant `"this host"` when neither
`COMPUTERNAME` nor `HOSTNAME` is set (`mod.rs:1512-1520`). Sanitised that is
`this-host`, **identical on every such machine**. Two hosts would then reserve
the same routing label — the hazard the product already warns about at
`crates/app/src/cli/policy.rs:261` (*"Both hosts may start for the same queued
job"*), and which is invisible across machines because that check reads only the
local database.

So `default_host_label()` returns `Option<HostLabel>` and yields `None` when
`local_display_name()` produced its fallback. `add` with no `--host-label` then
fails with the message in
[`04-message-inventory.md`](../04-message-inventory.md#4b-no-derivable-host-label-found-during-review-d3).

Detect the fallback by asking `local_display_name()` whether it found a
variable, not by string-comparing its output against `"this host"` — a machine
genuinely named "this host" is absurd, but a string comparison against a
constant that lives elsewhere is the kind of coupling that rots.

## Definition of Done

1. With `COMPUTERNAME=IvanPC`, a fresh install's `repo add octo/one
   --max-capacity 1` reserves `rm-ivanpc-win-x64` with no `--host-label` given.
2. `--host-label office` still overrides, and still records `office` as that
   policy's `requested_host_label`.
3. Two policies added with different explicit `--host-label` values on one host
   keep their own labels — `monitor_policy_keeps_its_own_label_when_another_policy_is_added_before_promotion`
   (`crates/app/src/cli/policy.rs:1090`) still passes.
4. With neither `COMPUTERNAME` nor `HOSTNAME` set, `repo add` with no
   `--host-label` **fails** naming `host set-label`, and no policy is stored.
   Asserted; a default of `this-host` fails this task.
5. Sanitisation is unit-tested for: mixed case, a space, a dot, a leading
   hyphen, a 70-character name, and a name of only punctuation (which yields
   `None`, not an empty label).
6. A host migrated by `b1` with `host_label = ''` loads as `None` and is filled
   from `default_host_label()` on next use, taking the same path a fresh install
   takes.
7. `cargo test -p runner-manager-app` passes.
