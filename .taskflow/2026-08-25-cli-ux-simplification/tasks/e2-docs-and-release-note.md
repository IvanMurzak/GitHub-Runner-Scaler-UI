---
id: "e2-docs-and-release-note"
title: "README quick start, the 0.1.5 breaking-change note, and the doc-comment sweep"
group: "E"
sequence: 2
repo: "."
base_branch: "main"
depends_on: ["e1-e2e-and-harness", "d1-host-label-commands"]
importance: 2
complexity: 3
security_critical: false
production_touching: false
model_hint: "fast"
taskflow_refs: ["05-migration-compatibility.md", "03-command-surface.md", "02-target-architecture.md"]
---

## Goal

Make the documented path the short one, and make the breaking change
discoverable — a removed command's clap error does not name its successor, so
the release note is the only place a user finds it.

**Owner gate G3 must be granted before this merges.**

## Scope & seams

**Files:** `README.md`, `crates/app/tests/readme_disclosure.rs` and
`crates/app/tests/release_channels.rs` (only if the rewrite moves an anchor they
assert), `crates/domain/src/policy.rs` and `crates/testkit/src/fixtures.rs`
(doc comments only).

### `README.md`

Quick start (`README.md:27-38`) becomes the target Journey 1: sign in, one
`repo add` carrying `--max-capacity` and `--enabled`, `service install`. Drop
`--host-label` from the example and explain in one sentence that the routing
label is derived from the machine name and is shown by `host show`.

The command table (`README.md:62-70`) follows
[`03-command-surface.md`](../03-command-surface.md): `repo set` and
`org set` replace the two removed rows, and `host set-label` joins the `host`
row.

**Three README constraints are enforced by test and must survive:**

1. The `What you are granting` section precedes every install command
   (`readme_disclosure.rs:186-210`).
2. All four documented install channels appear
   (`readme_disclosure.rs:128-140`).
3. No download button, raw `<img>`, or direct-download link
   (`readme_disclosure.rs:300-370`).

Do not touch the disclosure section's wording. If the quick-start rewrite moves
a byte offset those tests measure, update the test's expectation only where it
is an offset, never where it is an obligation.

### The `0.1.5` release note

A **Breaking changes** section carrying, verbatim, the four mappings in
[`05-migration-compatibility.md`](../05-migration-compatibility.md#release-note-obligation),
plus the sentence that **`host set-capacity` is unchanged** — its name contains
one of the two fragments being removed, and a reader skimming will assume
otherwise.

### The doc-comment sweep

`crates/domain/src/policy.rs:853,1003,1217,1228,1243,1251,1315,1337,2400` and
`crates/testkit/src/fixtures.rs:357,605` name `set-scale` or `set-capacity` in
prose. Update the prose. **Change no behaviour in either crate**; if a comment's
claim is now wrong about more than a command name, say so in the pull request
rather than fixing the code here.

## Definition of Done

1. `README.md`'s quick start reaches an armed repository in three commands and
   names no removed command.
2. `grep -n "set-scale\|repo set-capacity\|org set-capacity" README.md` returns
   nothing; `host set-capacity` is still present in the command table.
3. `crates/app/tests/readme_disclosure.rs` and `release_channels.rs` pass. Any
   edit to them changes an offset, never an obligation, and each such edit is
   named in the pull request.
4. The release note exists with all four mappings and the `host set-capacity`
   sentence, and **G3 is granted** before merge.
5. No `.rs` file in `crates/domain` or `crates/testkit` changed except doc
   comments — verifiable by the diff containing only comment lines in those
   crates.
6. `cargo test --workspace` passes.
7. `.taskflow/2026-08-21-local-runner-manager/` is **not edited**. It is a
   historical record; this taskflow supersedes its command list rather than
   rewriting it.
