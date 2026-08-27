---
id: "d2-status-and-tui-labels"
title: "status --json carries host_label, and the TUI stops teaching the old add command"
group: "D"
sequence: 2
repo: "."
base_branch: "main"
depends_on: ["d1-host-label-commands"]
importance: 2
complexity: 3
security_critical: false
production_touching: false
model_hint: "fast"
taskflow_refs: ["02-target-architecture.md", "05-migration-compatibility.md"]
---

## Goal

Expose the host label to scripts, and stop the TUI printing an onboarding hint
that is wrong after D3. Both found during review.

## Scope & seams

**Files:** `crates/app/src/cli/status.rs`, `crates/app/src/tui/shell.rs`,
`crates/app/src/tui/screens.rs`,
`crates/app/tests/host_capacity_and_status.rs`.

### `status --json`

`HostSnapshot` (`crates/app/src/cli/status.rs:116-121`) gains `host_label`.
Additive for consumers — nothing is removed or renamed — but **not silent for
us**: `status.rs:510-524` pins the exact `/host` key list, and that assertion is
edited deliberately, with `host_label` in its correct sorted position.

The text `status` renders (`status.rs:332-339`) may show the label too, at the
implementer's discretion; the JSON field is the requirement.

Do not extend `/credential` or `/budget`. `status --json` is a schema-stable
document and this task adds exactly one key to exactly one object.

### The TUI's onboarding hints

`crates/app/src/tui/shell.rs:1111` prints:

```text
runner-manager repo add OWNER/REPO --host-label <host> --max-capacity 1
```

`--host-label` is no longer required, so this teaches a longer command than the
product needs. Replace it with the D1 form.

`crates/app/src/tui/screens.rs:631` carries the empty-state action
`Action: runner-manager repo add OWNER/REPO`, which remains correct — but
`screens.rs:1044,1050` pin that screen by **line count, byte count and FNV
hash**. If the text changes at all, those pins change with it, in the same
commit, with the new values computed rather than guessed.

`shell.rs:2991` asserts the empty-state screen contains `repo add`; re-check it
rather than assuming it still holds.

This task changes no TUI behaviour, layout or key binding — only strings.

## Definition of Done

1. `status --json` emits `/host/host_label`, and `status.rs:510-524`'s key list
   is updated to include it in sorted position.
2. A consumer reading only the previously-pinned keys is unaffected: no key is
   removed or renamed, asserted by the same test.
3. `status --json` remains valid JSON and is still undecorated — `is_decorated_report`
   (`crates/app/src/cli/mod.rs:1109`) still excludes it.
4. The TUI onboarding hint no longer contains `--host-label`.
5. Every pinned TUI snapshot passes with recomputed values; no pin is deleted or
   loosened to make a test pass.
6. `cargo test -p runner-manager-app` passes.
