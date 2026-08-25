---
id: "a4-policy-copy"
title: "Rewrite every policy result, remedy and next-step string"
group: "A"
sequence: 4
repo: "."
base_branch: "main"
depends_on: ["a3-host-label-resolution"]
importance: 2
complexity: 4
security_critical: false
production_touching: false
model_hint: "fast"
taskflow_refs: ["04-message-inventory.md"]
---

## Goal

Put the useful line above the cautious one, and stop naming commands that no
longer exist. The strings are already specified verbatim.

## Scope & seams

**Files:** `crates/app/src/cli/policy.rs` (copy only),
`crates/app/tests/policy_commands.rs`.

Implement sections 1, 2, 3, 4 and 4a of
[`04-message-inventory.md`](../04-message-inventory.md). Section 2's
installation-keyed branch is `a5`'s; this task writes the reordered layout with
the disclosure unconditional, so `a5` changes only *when* it prints.

Specific sites:

| Site | Change |
|---|---|
| `write_add_result` (`policy.rs:353-408`) | New layout: result, routing label with its origin, then a numbered next-step block. `pending` leaves the result line; `scaling is off` / `scaling is ON` replaces it. |
| `policy.rs:371` | `Next: ... set-scale` becomes the numbered block naming `repo set` or `service install`. |
| `policy.rs:390` | `Promote it with: ... set-capacity` becomes `Start runners for it: ... repo set ... --max-capacity N --enabled`. |
| `policy.rs:400-406` | The ARM64 and Linux-container warnings keep their text and move **below** the next-step block. |
| `policy.rs:623-631` | Monitor-only refusal keeps its class, gains the one-command remedy. |
| `policy.rs:226-227` | Duplicate `add` gains a remedy naming `repo set`. Found during review. |
| `policy.rs:667-694` | One result block for the whole mutation instead of one per field. |
| `policy.rs:693` | The drain wording is **unchanged**. It deliberately promises nothing about termination. |
| `policy.rs:20` `TRUST_WARNING` | **Unchanged**, and still printed exactly once, at the moment scaling is armed. |

Two strings that must not move or change:

- `write_grant_consequences`'s three sentences (`crates/app/src/cli/auth.rs:139-154`)
  are reproduced character for character. `policy_commands.rs:115` and
  `policy.rs:1056-1070` assert them sentence by sentence, and that is
  deliberate: `auth.rs:120-135` records that shortening the disclosure "reds a
  test rather than quietly weakening a disclosure".
- `Failure` classes are unchanged. A remedy is new text on an existing class,
  never a new class.

## Definition of Done

1. Every string in sections 1, 2, 3, 4 and 4a of
   [`04-message-inventory.md`](../04-message-inventory.md) is produced, asserted
   per case.
2. On an armed `add`, the next-step block appears **above** any platform warning
   and above the trust warning; asserted by byte offset, not by presence.
3. On a monitor-only `add`, the promotion command appears **above** the three
   consequence sentences; asserted by byte offset. This is the specific defect
   the task exists to fix.
4. The three consequence sentences are still present and byte-identical.
5. `repo set X --max-capacity 6 --enabled` prints one result block naming both
   the capacity and the new scaling state, not two blocks.
6. `repo set X --enabled false` with active runners still prompts, and still
   prints the unchanged draining sentence.
7. Duplicate `add` prints a remedy naming `repo set`.
8. `cargo test -p runner-manager-app` passes.
