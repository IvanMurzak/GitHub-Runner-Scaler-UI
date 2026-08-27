# CLI UX simplification implementation ledger

> This is this taskflow's implementation ledger, not a workspace-wide product
> roadmap. The 2026-08-21 taskflow keeps its own.

**Design status:** Reviewed 2026-08-25 (`/taskflow-review`). Seven decisions
locked in [`README.md`](README.md#locked-decisions); **D3 and D4 narrowed** by
two confirmed P0/P1 findings, recorded as `REVISED`. Eight findings applied.
**Task status:** Derived 2026-08-25 (`/taskflow-tasks`). **11 immutable
specifications** in [`tasks/`](tasks/), 5 conflict-domain groups, waves 0-5.
Ready for `/taskflow-execute`.
**Implementation status:** Not started, with one exception: **G4 was exercised
by the owner on 2026-08-27 and D4 superseded**, and the resulting change to
`auth login`, `auth status` and the grant text shipped on its own. See the
progress log.
**Last updated:** 2026-08-27

**Execution isolation:** every task runs in its own git worktree under
`.claude/worktrees/`, which this repository already uses. Group **A** is a
single conflict domain precisely because `cli/mod.rs`, `cli/policy.rs` and
`cli/auth.rs` cannot be edited concurrently; it runs strictly by `sequence`.
There is exactly one declared cross-group carve-out, in
[`tasks/d1-host-label-commands.md`](tasks/d1-host-label-commands.md).

**Execution host:** this repository, `IvanMurzak/GitHub-Runner-Scaler-UI`, from
`main` at `c3ae616` (version `0.1.4`). The 2026-08-21 taskflow is stopped with
16 of 23 tasks done; this work touches `crates/app/src/cli`, one field and one
migration in `crates/domain`, one error message in `crates/platform`, plus
tests and `README.md`. **It does not resume, unblock, or depend on that
taskflow's remaining tasks.**

**Task ids collide across taskflows and do not refer to each other.** The
2026-08-21 taskflow has its own `a1`-`a3`, `f1`-`f3` and so on; this one's
`a1`-`a5`, `b1`, `c1`, `d1`-`d2` and `e1`-`e2` are unrelated to them. Every
reference in this folder means *this* folder's task unless it names the other
taskflow's path.

**This file is the only mutable record of task state.**

## Execution timeline

| Wave | Tasks | Theme | Gate |
|---|---|---|---|
| 0 | `a1`, `b1`, `c1` | Everything with no dependency: warning scope and argv hints (D5, D7), the `Host.host_label` field and migration `0003` (D3's model half), and the lock remedy (D6). Three groups, fully parallel. | CI green; **G2** on `b1`. Each is independently revertable. |
| 1 | `a2` | The surface contract, in one commit: design list → transcribed `SURFACE` → clap tree → dispatch arms. | `--help` and the design list agree in both directions; `Cli::command().debug_assert()` passes. |
| 2 | `a3`, `d1` | Host-label resolution and refusal (D3's CLI half); `host set-label` and the `host show` lines. | An upgraded database routes exactly as before (**G2** end to end). |
| 3 | `a4`, `d2` | Every policy string (D1, D2, D3); `status --json` gains `host_label` and the TUI hints drop `--host-label`. | **G1** — Journey 1 in three commands, zero failures. **G5** — noise budget. |
| 4 | `a5`, `e1` | Disclosure keyed on the installation, `auth status` gains the grant (D4); the e2e suite and harness move onto `repo set`. | **G4**, owner gate, before `a5` merges. |
| 5 | `e2` | README quick start, the `0.1.5` breaking-change note, the doc-comment sweep. | **G3**, owner gate. |

```text
Wave 0   a1 ──────────────┐
         b1 ──┬───────────┤
         c1   │           │
Wave 1        └── a2 ─────┤
Wave 2        ┌── a3 ─────┤        d1 (needs a2 + b1)
Wave 3        └── a4 ─────┤        d2 (needs d1)
Wave 4            a5 [G4] │        e1 (needs a4)
Wave 5                    └──────  e2 [G3] (needs e1 + d1)
```

Group A is the critical path and is strictly serial: `a1 → a2 → a3 → a4 → a5`.
Groups B, C, D and E provide what parallelism the graph has — `b1` and `c1` run
beside `a1` from the start, and `d1`/`d2`/`e1` run beside `a4`/`a5`.

`a2` is the choke point and the one task that **cannot** be split.
`crates/app/tests/cli_command_surface.rs:15-17` states that the surface list is
hand-transcribed rather than derived, and the test compares it against `--help`
in both directions — so landing the tree without the constant, or either without
the design list, turns `main` red for the duration.

## Gates

**G1 — Journey 1.** On a clean host with a valid credential and a machine name
that sanitises to a usable label, reaching an armed repository takes **at most
three `runner-manager` invocations and zero failed ones**, excluding the
workflow edit. Measured by driving the binary, not by reading the README.

```text
runner-manager repo add OWNER/REPO --max-capacity 6 --enabled
runner-manager service install
```

The gate says three, not two, to leave room for `host set-label` on a machine
whose name sanitises badly.

**G2 — No silent re-routing.** A database created by `0.1.4` with at least one
policy must, after migration `0003`, derive the same routing label for a new
policy added with no `--host-label` as `0.1.4` would have derived for that
policy's promotion. Asserted against a fixture database, not a freshly created
one.

**G3 — Breaking change is discoverable.** The `0.1.5` release note names all
four removed commands and their replacements, and states that
`host set-capacity` is unchanged. A removed command's clap error does not name
its successor, so the note is the only place a user finds it.

**G4 — Disclosure is not weakened.** Every property in
[`05-migration-compatibility.md`](05-migration-compatibility.md#d4-is-a-security-decision-and-is-reviewed-as-one)
holds, verified by test. **Human gate:** the owner accepts the D21 amendment, or
D4 falls back to the documented alternative and the rest of the work ships
unchanged.

**G5 — Noise budget.** On a host with no override variables set, `repo add`,
`repo list`, `repo set`, `host show` and `status` write **nothing to stderr** on
success. Asserted per command, so a future warning has to be argued for.

## Board

Legend: white circle = not started, blue = in flight, purple = done but
unreviewed, green tick = merged, red = blocked. Only `/taskflow-execute` writes
to this table.

| Task (spec) | needs | repo/base | imp/cx | model | Status | Run / PR | Updated |
|---|---|---|---|---|---|---|---|
| [`a1-warning-scope-and-argv-hints`](tasks/a1-warning-scope-and-argv-hints.md) | — | `.` / `main` | 2/4 | fast | not started | — | 2026-08-25 |
| [`b1-host-label-model`](tasks/b1-host-label-model.md) | — | `.` / `main` | 3/6 | top | not started | — | 2026-08-25 |
| [`c1-lock-remedy`](tasks/c1-lock-remedy.md) | — | `.` / `main` | 2/3 | fast | not started | — | 2026-08-25 |
| [`a2-command-surface`](tasks/a2-command-surface.md) | `a1`, `b1` | `.` / `main` | 3/6 | top | not started | — | 2026-08-25 |
| [`a3-host-label-resolution`](tasks/a3-host-label-resolution.md) | `a2` | `.` / `main` | 3/5 | mid | not started | — | 2026-08-25 |
| [`d1-host-label-commands`](tasks/d1-host-label-commands.md) | `a2`, `b1` | `.` / `main` | 2/4 | fast | not started | — | 2026-08-25 |
| [`a4-policy-copy`](tasks/a4-policy-copy.md) | `a3` | `.` / `main` | 2/4 | fast | not started | — | 2026-08-25 |
| [`d2-status-and-tui-labels`](tasks/d2-status-and-tui-labels.md) | `d1` | `.` / `main` | 2/3 | fast | not started | — | 2026-08-25 |
| [`a5-disclosure-scope`](tasks/a5-disclosure-scope.md) | `a4`, **G4** | `.` / `main` | 3/5 | top | not started | — | 2026-08-25 |
| [`e1-e2e-and-harness`](tasks/e1-e2e-and-harness.md) | `a4` | `.` / `main` | 3/5 | mid | not started | — | 2026-08-25 |
| [`e2-docs-and-release-note`](tasks/e2-docs-and-release-note.md) | `e1`, `d1`, **G3** | `.` / `main` | 2/3 | fast | not started | — | 2026-08-25 |

`b1` and `a2` are `top` because they are `production_touching` — a migration
against operators' existing databases, and a breaking CLI contract — which
raises `mid` one tier. `a5` is `top` because it is `security_critical`. The
rubric and the per-task reasoning are in [`tasks/README.md`](tasks/README.md).

## Progress log

**2026-08-25 — planned.** Seven decisions locked over two rounds with the owner.
Two of the owner's answers conflicted — removing both `set-capacity` and
`set-scale` while putting every flag on `add` would have left no way to disable
a running policy, which is the drain path — and the conflict was raised and
resolved to `repo set` before any document was written.

Two findings during evidence-gathering changed the design from what the
decisions assumed:

- **D1 and D2 need no new store path.** `apply_policy_mutation`
  (`crates/app/src/cli/policy.rs:556`) already applies capacity and enable as
  one atomic, optimistically-concurrent write, and the TUI already drives it
  that way. The CLI's two-command split exists only in the clap tree.
- **D4 needs no new table.** `policies.installation_id` already records which
  installation each policy was created against
  (`0001_initial_schema.sql:52`), so "has this grant been acknowledged" is a
  query over existing rows rather than stored state. This removed a table, a
  `TABLES` change, and a second source of truth from the design.

One design assumption was corrected against the schema: `policies` has **no**
`created_at` column, so "oldest policy" in migration `0003` must order by
`rowid`.

**2026-08-25 — reviewed.** Eight findings confirmed against the working tree and
applied. Two narrowed a locked decision; neither reverses one.

| # | P | Finding | Applied |
|---|---|---|---|
| F1 | **P0** | D4's short form points at `runner-manager auth status` for the full grant text, but `auth status` never names the permission — `auth.rs:617-830` contains no `CRITICAL_PERMISSION`, `Administration` or `permissions`, and `write_disclosure` is called only from `login` (`auth.rs:386`). The pointer would be false. | D4 scope now includes `auth status` printing `PERMISSIONS` (`auth.rs:87-110`) and the three consequence sentences. Recorded as **D4 REVISED**. |
| F2 | **P1** | D3's default would derive from `local_display_name()`'s fallback constant `"this host"` when neither `COMPUTERNAME` nor `HOSTNAME` is set (`mod.rs:1512-1520`), giving **every such machine the same routing label** — the collision the product already warns about at `policy.rs:261`, and which is invisible across machines because that check reads only the local database. | `default_host_label()` returns `None` on the fallback; `add` then asks for `--host-label` or `host set-label`. Recorded as **D3 REVISED**. |
| F3 | P1 | `repo add` on an existing target already fails `Failure::Conflict` (`policy.rs:226-227`) with no remedy. After D1 an operator will re-run a near-miss `add` and hit it. Not in the original call-site sweep. | Added to the call-site table and to [`04-message-inventory.md`](04-message-inventory.md#4a-duplicate-add-found-during-review). |
| F4 | P1 | The TUI prints `repo add OWNER/REPO --host-label <host> --max-capacity 1` (`tui/shell.rs:1111`) and pins its empty-state text by byte count and FNV hash (`tui/screens.rs:1044,1050`). Stale under D3, and not in the sweep. | Added as work item `u12`. |
| F5 | P1 | `status --json`'s `/host` key list is pinned exactly (`status.rs:510-524`), so adding `host_label` is a deliberate schema-test edit, not the silent addition `02` implied. | Wording corrected; folded into `u12`. |
| F6 | P2 | `store.rs:30-35` cited for the forward-only rule; it is `30-31`. | Corrected. |
| F7 | P2 | `--enabled` with `num_args = 0..=1` lets `repo set --enabled OWNER/REPO` consume the positional as a bool value, failing with a message about bools rather than about word order. | Documented with required copy in [`03-command-surface.md`](03-command-surface.md). |
| F8 | P2 | No execution-isolation path recorded. | Worktree path added above. |

Also confirmed, and needing no change: clap is `4.6.6`
(`Cargo.toml:155`), which supports `num_args` and `default_missing_value`;
`policies` carries `installation_id` so D4 needs no table; `docs/`, `install/`,
`npm/` and `.github/` name neither removed command; and the TUI drives
`apply_policy_mutation` directly, so D1/D2 do not reach it.

**2026-08-25 — tasks derived.** Eleven specifications, five conflict-domain
groups, waves 0-5. Three decomposition decisions worth recording, because each
resolves a risk the plan flagged:

1. **`a2` is deliberately large.** The plan asked whether the tree could be
   declared with not-implemented arms and its handlers attached later — the
   `f1`/`f2` pattern this repository already uses (`crates/app/src/cli/mod.rs:11-24`).
   It cannot here: `f1` *added* commands, and `a2` *renames and removes* them, so
   `dispatch_repo` stops compiling in the same commit. The tree, the transcribed
   `SURFACE`, the design list and the dispatch arms are therefore one task.
2. **Every `crates/app/tests/*.rs` file has exactly one owning group.** The
   first draft put the whole test suite in group E, which would have let `a2`
   merge with `policy_commands.rs` and `no_secret_reaches_command_output.rs`
   failing. Test files now belong to the task that changes the behaviour they
   assert; no task may hand a failing test to a later one.
3. **One cross-group carve-out is declared rather than avoided.** `d1` owns the
   single test function `every_command_names_the_operation_whose_output_failed`
   (`mod.rs:1628-1685`) inside group A's file, because that table calls handlers
   directly and cannot name `host set-label` before `d1` writes it. Everything
   else in that file stays group A's.

**2026-08-27 — G4 exercised, out of order, and D4 superseded.** The owner read
a real `auth login` transcript on a host with 202 reachable repositories — over
240 lines, of which 25 were the permission table and 202 were repository names —
and decided the disclosure comes off the login screen entirely rather than
staying on it as `a5` assumed.

That is gate **G4**, granted ahead of wave 4 and granted *wider* than `a5`
proposed. Landed on `feat/simplify-ux` as a standalone change, because it needs
none of `a1`-`a4`: it touches `crates/app/src/cli/auth.rs`, the `auth` arm of
the clap tree, and the three test files that assert on `auth` output.

| Was | Is |
|---|---|
| `auth login` opens with `write_disclosure`, 25 lines | `auth login` prints no permission text; `write_disclosure` is deleted |
| The grant is reachable only by signing in | `auth status --permissions` renders `PERMISSIONS` with no credential and no request |
| `auth status` names every reachable repository | The count and each installation are unconditional; the roll call is `auth status --list` |
| — | `auth login --list` does the same for the discovery it prints |

`a5`'s remaining half is unaffected and still worth doing: keying the
`repo add` disclosure on `policies.installation_id` so that a second policy
against an acknowledged installation prints the one-line note. **Definition of
Done items 1 and 7 no longer describe the product** — item 1 required the
twenty-five lines to survive on `auth login`, and item 7 required `auth status`
to print the table unconditionally rather than on `--permissions`. Read them as
superseded by this entry; items 2-6 and 8-11 stand.

The disclosure is not weaker for it, and that is asserted in both directions:
`auth_onboarding.rs::the_login_screen_carries_no_permission_table` requires the
text to be absent from the login screen, and
`auth_states.rs::the_permission_report_carries_the_whole_grant` requires the
same strings to be present in `auth status --permissions`. Either test alone
would pass for a build that deleted the grant text outright, which is the
failure mode a removal like this actually has.

**Next:** `/taskflow-execute`. Wave 0 is `a1`, `b1` and `c1` in parallel; **G4**
is now granted, so `a5` reaches wave 4 with only its `repo add` half left.
