# Task specifications

> **SUPERSEDED 2026-08-21 — do not execute this set.**
>
> `/taskflow-review` established that D4 (runner scale sets) is unusable and the
> owner replaced it with public REST JIT ephemeral runners. That invalidates 13
> of the 23 specifications below, deletes `c5` outright, and collapses most of
> `c4`. Task files are immutable, so they are **not** patched in place; the set
> must be re-derived by `/taskflow-tasks` against the corrected design.
>
> `c1-d17-scale-set-spike` is **complete** — it is what produced the evidence.
> Its result lives in `docs/spikes/d17-user-to-server-scale-set-chain.md` and it
> must not be re-run. Everything else was `pending` and nothing is lost.

These files are **immutable specifications**. They carry no status field and are
never edited to record progress. All live task state — status, run, PR, dates —
exists only in [`../ROADMAP.md`](../ROADMAP.md), which `/taskflow-execute` owns.

The design set this decomposes is `../README.md` and `../01-…` through
`../09-…`. A task never restates a design decision; it cites it.

## Coefficient legend

| Field | Range | Meaning |
|---|---|---|
| `importance` | 1–10 | Consequence if this task is wrong or missing. Orders otherwise-ready work and communicates risk. |
| `complexity` | 1–10 | Architectural depth, cross-cutting surface, and correctness cliffs — not line count. |
| `security_critical` | bool | The task's primary content is a credential path or a control from the `07-security.md` threat table. |
| `production_touching` | bool | The task changes something that acts on a public release, a user's machine at boot, or a published artifact. |

## Model rubric

`complexity >= 8` → `top`; `5–7` → `mid`; `<= 4` → `fast`.
Either `security_critical` or `production_touching` raises the result one tier;
`top` stays `top`. The tiers map to the consumer project's approved models.

This taskflow contains no `fast` task. That is a property of the work, not an
oversight: the product is a from-scratch cross-platform systems binary whose
smallest unit still spans a credential path, an OS adapter, or a public
artifact.

## Groups

A group is **one merge-conflict domain**. Tasks inside a group run strictly in
ascending `sequence`, one at a time. Groups run in parallel only where
`depends_on` allows.

| Group | Conflict domain (paths) | Tasks |
|---|---|---|
| A | `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `.github/workflows/`, `install/`, `npm/`, `packaging/`, `README.md` | a1, a2, a3 |
| B | `crates/domain/`, `crates/testkit/src/{clock,fixtures}.rs` | b1, b2 |
| C | `crates/github/`, `crates/testkit/src/github.rs`, `docs/spikes/` | c1, c2, c3, c4, c5 |
| D | `crates/platform/` | d1, d2, d3 |
| E | `crates/agent/` | e1, e2, e3 |
| F | `crates/app/src/cli/` | f1, f2, f3 |
| G | `crates/app/src/tui/` | g1, g2, g3 |
| H | `tests/` (workspace-root integration and acceptance suite) | h1 |

### Why `crates/app` is two groups

`crates/app` holds both the CLI and the TUI. They are separate conflict domains
only because task **a1** creates the whole module skeleton up front —
`main.rs`, `cli/`, and `tui/` — so no later task edits a file another group
owns. F and G therefore never touch the same file; G depends on F for command
parity (`02-target-architecture.md`, principle 5), which is an ordering
constraint, not a conflict.

### Why no task edits a shared manifest

Task **a1** owns every `Cargo.toml` in the workspace and the full
`[workspace.dependencies]` table. Later tasks add dependencies with
`workspace = true` only. Introducing a **new external crate** is therefore an
A-group change, not a local one. This is what keeps `Cargo.lock` — a file every
Rust task would otherwise touch — out of the parallel conflict surface.

## Sizing

One task is one reviewable pull request. Same-file minor work is merged rather
than split: `a3` carries all four distribution channels plus the README,
`d1` carries six platform primitives, `f3` carries both the `daemon` and
`service` command surfaces, and `g2` carries all four read-only TUI screens.
Work was split only where a single PR would otherwise be unreviewable — the
Actions-service adapter is `c4` + `c5`, and the agent is `e1` + `e2` + `e3`.
