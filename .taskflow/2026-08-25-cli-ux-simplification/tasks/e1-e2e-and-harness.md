---
id: "e1-e2e-and-harness"
title: "Move the end-to-end suite and the host-controller harness onto repo set"
group: "E"
sequence: 1
repo: "."
base_branch: "main"
depends_on: ["a4-policy-copy"]
importance: 3
complexity: 5
security_critical: false
production_touching: false
model_hint: "mid"
taskflow_refs: ["05-migration-compatibility.md"]
---

## Goal

Keep the acceptance suite and the manual harness driving a command that exists.
These live outside `crates/app`, so `a2` could not fix them without reaching
into another group's files.

## Scope & seams

**Files:** `tests/tests/e2e_security_acceptance.rs`, `tests/host-controller.sh`.

| Site | Now | After |
|---|---|---|
| `tests/tests/e2e_security_acceptance.rs:689,1145` | Builds argv containing `"set-scale"` | `"set"` |
| `tests/host-controller.sh:25` | `repo set-scale "$2" --enabled false` | `repo set "$2" --enabled false` |

This is mechanical, but not blind. Two things to check rather than assume:

1. **What each e2e site is actually asserting.** A security-acceptance test that
   arms a policy and one that drains it need different flags now that one
   command does both. Read the surrounding case before substituting.
2. **Whether the harness's `drain` action still means what it did.**
   `repo set --enabled false` still routes through `confirm_disable`
   (`crates/app/src/cli/policy.rs:699`) when runners are active, and the harness
   is non-interactive. If the old path avoided the prompt by luck rather than by
   design, say so in the pull request rather than adding `yes |`.

While in these files, add nothing. New coverage for `repo set` and
`add --enabled` belongs to `a2` and `a4`, which own the app crate's tests.

## Definition of Done

1. Neither file contains `set-scale` or a `repo`/`org` `set-capacity`.
2. `cargo test -p tests` (the end-to-end crate) passes, or — if it requires
   credentials or network this environment lacks — it **compiles** and every
   skipped case is named in the pull request. Do not report a compile as a pass.
3. `tests/host-controller.sh` is shellcheck-clean to whatever standard the file
   already meets, and its `drain` action is exercised at least once.
4. Any prompt the harness now meets is handled by making the command
   non-interactive by design, not by piping `yes`.
5. `grep -rn "set-scale" tests/` returns nothing.
