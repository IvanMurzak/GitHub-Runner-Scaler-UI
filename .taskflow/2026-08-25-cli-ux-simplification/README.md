# CLI user-experience simplification

**Status:** Tasks derived 2026-08-25 (`/taskflow-tasks`) against the reviewed
design; ready for `/taskflow-execute`. **11 immutable specifications** in
[`tasks/`](tasks/), 5 conflict-domain groups; waves, gates and live state are in
[`ROADMAP.md`](ROADMAP.md).
**Design status:** Reviewed 2026-08-25 (`/taskflow-review`); D3 and D4
**REVISED** by two confirmed findings, all eight logged in
[`ROADMAP.md`](ROADMAP.md#progress-log).
**Scope:** `IvanMurzak/GitHub-Runner-Scaler-UI` at `c3ae616`, product version
`0.1.4`. CLI surface, CLI copy, one domain field, one SQLite migration, and the
documents and tests that mirror them. No change to the agent, the JIT lifecycle,
the GitHub gateway, or the TUI's behaviour.

## Problem

A real first-run session, captured verbatim in
[`01-current-architecture.md`](01-current-architecture.md#the-captured-session),
took **eleven invocations to arm one repository**. Seven of them failed. The
documented path is four commands (`README.md:29-38`); the operator never found
it.

The failures are not one bug. They are six distinct classes, and each is a
design choice the code makes deliberately:

| # | What the operator hit | Where it is decided |
|---|---|---|
| 1 | `add repo X` — verb-noun instead of noun-verb — got clap's bare `unrecognized subcommand 'add'` | `crates/app/src/cli/mod.rs:437` |
| 2 | `--host-label` is required on every `add`, and its right answer is the machine name the tool already reads | `crates/app/src/cli/mod.rs:516`, `mod.rs:1511` |
| 3 | `--enabled` and `--max-capacity` are rejected by the command that would most naturally take them, under clap's misleading `use '-- --enabled'` tip | `crates/app/src/cli/mod.rs:511-537` |
| 4 | Arming a repository needs three commands (`add` then `set-capacity` then `set-scale`) | D20/D19; `crates/app/src/cli/policy.rs:456,474` |
| 5 | An advisory warning that changed no outcome printed above six of seven outputs | `crates/app/src/cli/mod.rs:711` |
| 6 | `service install` refused and offered a remedy that does not remedy it | `crates/platform/src/service.rs:3251,508` |

Plus a seventh, visible in the transcript but not an error: the five-line
`Administration: Read and write` disclosure printed above the one line the
operator needed next (`crates/app/src/cli/policy.rs:387`).

**None of this is a defect in the product's substance.** Every message is
accurate, every refusal is deliberate, and each carries a comment explaining
why. The defect is cumulative: correct-and-cautious at every step composes into
a first run that reads as a series of rejections.

## Locked decisions

This table is the sole decision ledger for **this** taskflow. Where a decision
amends the 2026-08-21 taskflow's ledger, the amendment is named explicitly;
that ledger is not edited by this work.

| ID | Decision | Status | Amends | Consequence |
|---|---|---|---|---|
| D1 | `repo add`/`org add` accept `--max-capacity N` and `--enabled [BOOL]`, so one command can create and arm a policy. Omitting `--enabled` still creates the policy disabled. | Locked 2026-08-25 | **D20** (relaxed) | D20's guarantee — creating a policy never arms a host — is preserved as the default rather than as a prohibition. Journey 1 drops from 4 commands to 3. `apply_policy_mutation` (`crates/app/src/cli/policy.rs:556`) already performs capacity-and-enable as one atomic write, so no new transactional path is introduced. |
| D2 | `repo set-capacity` and `repo set-scale` (and the `org` pair) are **removed** and replaced by one `repo set` / `org set` taking `--max-capacity N` and `--enabled BOOL`. | Locked 2026-08-25 | — | Breaking change, accepted at `0.1.4`. The `repo`/`org` families go from 5 subcommands to 4, and `add` and `set` share one flag vocabulary. `host set-capacity` is **not** affected: it is the host ceiling (D9) and keeps its name. Every call site is listed in [`05-migration-compatibility.md`](05-migration-compatibility.md). |
| D3 | The routing identity is a **host** property. `Host` gains `host_label`, defaulted on first use from `COMPUTERNAME`/`HOSTNAME`, readable and settable with `host show` / `host set-label`. `--host-label` on `add` becomes an optional per-policy override. **Where the machine reports no name, nothing is derived and the operator is asked** — the fallback constant would give every such machine the same routing label. | REVISED 2026-08-25 (fallback narrowed; review finding F2) | — | Matches D2 of the 2026-08-21 ledger — one host, one runner-owning identity. Costs one domain field, one forward-only migration (`0003`), and one new subcommand. In the captured session the derived default would have been `ivanpc`, which is exactly what the operator typed by hand. |
| D4 | The full `Administration: Read and write` disclosure prints on `auth login` and on the first policy creation per **installation id** not yet acknowledged; afterwards, one line naming the grant plus a pointer to `auth status`. **`auth status` gains the permission table and the consequence sentences**, because today it carries neither and the pointer would be false. | REVISED 2026-08-25 (`auth status` added to scope; review finding F1) | **D21** (disclosure clause) | The obligation's substance is kept — no operator creates a policy against a newly granted installation without seeing the consequences — while the repetition that buried the next command is dropped. Acknowledgement is keyed on `Installation.id`, so a **new** grant re-discloses — and needs no new state, because `policies.installation_id` (`crates/domain/src/store/migrations/0001_initial_schema.sql:52`) already records it. Requires the security review in [`05-migration-compatibility.md`](05-migration-compatibility.md#d4-is-a-security-decision-and-is-reviewed-as-one). |
| D5 | The *ignoring* branch of the App-override warning is emitted only by `auth login`, `auth status`, `daemon run`, and the `service` family. The *talking to a fake GitHub* branch keeps warning on every command. | Locked 2026-08-25 | — | The ignoring branch is advisory by construction: in it the variables have no effect. Restricting it to the commands where a wrong App identity would actually bite removes the noise without weakening the case the warning was added for. |
| D6 | `service install` still refuses while the single-instance lock is held, but the remedy names the holding process and how to stop it on this platform. | Locked 2026-08-25 | — | Message-only. The refusal is the race the lock exists to prevent and is not relaxed. |
| D7 | Two argv-level hints: a swapped noun/verb (`add repo X`) prints `did you mean: runner-manager repo add X?`, and an unknown flag lists the flags that command accepts instead of clap's `-- --flag` tip. | Locked 2026-08-25 | — | No surface change; both orders are **not** accepted, only diagnosed. Costs one pre-parse inspection of argv and one clap error-formatting override. |

## Summary

Seven changes, one theme: **the tool already knows the answer to most of what it
demands, and says the most alarming true thing before the most useful one.**

- D3 stops asking for a value it can derive.
- D1 and D2 collapse a three-command ceremony into one command, and give
  mutation a single verb.
- D4 and D5 stop repeating what has already been read.
- D6 and D7 make the two dead ends in the session say what to do.

The measurable target is Journey 1 from a signed-in binary: **three commands,
zero failures, and nothing printed above the line that matters.** The gate is in
[`ROADMAP.md`](ROADMAP.md#gates).

## Document map

| Document | What it holds |
|---|---|
| [`01-current-architecture.md`](01-current-architecture.md) | The captured session, and every behaviour above verified at `file:line`, with the change seams that already exist. |
| [`02-target-architecture.md`](02-target-architecture.md) | The target design for each decision, its trade-offs, and what is deliberately not changed. |
| [`03-command-surface.md`](03-command-surface.md) | The exact target command surface. This is the contract `crates/app/tests/cli_command_surface.rs` mirrors. |
| [`04-message-inventory.md`](04-message-inventory.md) | Every user-visible string this work changes, before and after. |
| [`05-migration-compatibility.md`](05-migration-compatibility.md) | The breaking change's blast radius, the SQLite migration, and the security review D4 needs. |
| [`tasks/`](tasks/) | 11 immutable task specifications and the group, coefficient and gate legend. Specs carry no `status`. |
| [`ROADMAP.md`](ROADMAP.md) | Waves, gates, progress log, and the task board. The only live task-state record. |
