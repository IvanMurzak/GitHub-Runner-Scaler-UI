# Task specifications

These files are **immutable specifications**. They carry no status field and are
never edited to record progress. All live task state — status, run, PR, dates —
exists only in [`../ROADMAP.md`](../ROADMAP.md), which `/taskflow-execute` owns.

The design set this decomposes is `../README.md` and `../01-…` through
`../09-…`. A task never restates a design decision; it cites it.

## Re-derived after the D4 revision (2026-08-21)

This is the **second** derivation of this task set. The first, written earlier
the same day, decomposed a design in which autoscaling used runner scale sets
and the Actions-service protocol. The `c1` spike disproved that mechanism, the
owner replaced D4 with public REST JIT ephemeral runners, and
`/taskflow-review` corrected all ten design documents. Because task files are
immutable, the previous set was retired rather than patched.

What changed, so a reader of the git history is not confused:

| Then | Now |
|---|---|
| `c4-actions-service-admin` — two-stage credential chain, scale-set administration | **deleted**; nothing remote is created at `add` time any more |
| `c5-scale-set-message-protocol` — long poll, `AcquireJobs`, acknowledgement, contract tests, revision pinning | **deleted**; it was the highest-complexity task in the set and no longer exists |
| — | `c4-demand-and-jit-gateway` — REST queued-job demand plus `generate-jitconfig` at both scopes |
| — | `v1-org-jit-verification` — proves the organization endpoint D18 rests on, which has never been called |
| `scale_set_id`, `scale_set_name`, `protocol_flag` in the domain model | `routing_labels`, a non-empty label set, plus derivation and `runs-on` matching rules |
| `e1` acquired jobs before scaling | `e1` polls advisory demand and must not invent a reservation |

`c1-d17-scale-set-spike` is left exactly as written and is **complete**. It
describes the design it was dispatched under, which is the point: it is the
record of the experiment that changed the design. Its result lives in
`../../docs/spikes/d17-user-to-server-scale-set-chain.md` and it must not be
re-run.

Of the twenty-three specifications, **nine carry forward byte-identical** —
`a2`, `a3`, `b2`, `c1`, `c2`, `d1`, `d2`, `d3`, `e2`, none of which ever
depended on the scale-set mechanism — **twelve were revised**, and **two are
new**. Nothing was lost in the revision: every row in the previous board was
`⬜ pending` except `c1`.

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

No task in this set resolves to `fast`. That is a property of the work, not an
oversight: the product is a from-scratch cross-platform systems binary whose
smallest unit still spans a credential path, an OS adapter, or a public
artifact. The two tasks that score `fast` on complexity alone — `v1` and `f3` —
are both raised a tier, one for handling the real credential chain and one for
installing a boot-time service.

## Groups

A group is **one merge-conflict domain**. Tasks inside a group run strictly in
ascending `sequence`, one at a time. Groups run in parallel only where
`depends_on` allows.

| Group | Conflict domain (paths) | Tasks |
|---|---|---|
| A | `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `.github/workflows/`, `install/`, `npm/`, `packaging/`, `README.md` | a1, a2, a3 |
| B | `crates/domain/`, `crates/testkit/src/{clock,fixtures}.rs` | b1, b2 |
| C | `crates/github/src/`, `crates/testkit/src/github.rs` | c1, c2, c3, c4 |
| V | `docs/spikes/`, `crates/github/examples/` | v1 |
| D | `crates/platform/` | d1, d2, d3 |
| E | `crates/agent/` | e1, e2, e3 |
| F | `crates/app/src/cli/` | f1, f2, f3 |
| G | `crates/app/src/tui/` | g1, g2, g3 |
| H | `tests/` (workspace-root integration and acceptance suite) | h1 |

### Why the verification spike is its own group

`v1` is stop-the-line for D18's organization path and for nothing else. Placed
inside group C it would sit ahead of the device flow and the inventory gateway
in sequence order and stall both behind a task that needs a human to supply an
organization. It shares no file with any implementation task — it writes only a
spike record and throwaway example code — so it is its own conflict domain and
runs in parallel from the first wave. `c4` and `h1` depend on it, which is what
enforces "prove the endpoint before building on it" through the graph rather
than through prose. `c1` predates this split and stays in C.

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
than split: `a3` carries all four distribution channels plus the README, `d1`
carries six platform primitives, `f3` carries both the `daemon` and `service`
command surfaces, and `g2` carries all four read-only TUI screens.

Work was split only where a single PR would otherwise be unreviewable: the
agent is `e1` + `e2` + `e3`. The GitHub gateway is no longer among those cases —
D4 collapsed two Actions-service tasks into one REST task, `c4`, because
demand and JIT provisioning are now two documented endpoints against a host and
a credential the crate already has.
