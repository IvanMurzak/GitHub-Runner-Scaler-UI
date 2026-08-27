---
id: "a5-disclosure-scope"
title: "Disclose the grant on change rather than on repetition, and give auth status the grant it points at"
group: "A"
sequence: 5
repo: "."
base_branch: "main"
depends_on: ["a4-policy-copy"]
importance: 3
complexity: 5
security_critical: true
production_touching: false
model_hint: "top"
taskflow_refs: ["02-target-architecture.md", "05-migration-compatibility.md", "04-message-inventory.md"]
---

## Goal

Print the full consequence text where it is news, and a pointer where it is not.
D4, which amends the disclosure clause of D21 and of `07-security.md` in the
2026-08-21 taskflow.

**Owner gate G4 must be granted before this merges.** If refused, implement the
documented fallback instead — keep the disclosure on every policy creation, with
only `a4`'s reordering — and close this task without the rest.

## Scope & seams

**Files:** `crates/app/src/cli/policy.rs` (the disclosure branch),
`crates/app/src/cli/auth.rs`, `crates/app/tests/policy_commands.rs`,
`crates/app/tests/auth_states.rs`.

### The rule

| Situation | What prints |
|---|---|
| `auth login` | `write_disclosure` (`auth.rs:158`), the full twenty-five lines. **Unchanged.** |
| First policy creation against an installation id not yet acknowledged | `write_grant_consequences` (`auth.rs:139-154`), the three sentences. **Text unchanged.** |
| Any later policy creation against an acknowledged installation | The one-line note from [`04-message-inventory.md`](../04-message-inventory.md#2-repo-add--monitor-only). |

### Acknowledgement needs no new state

An installation is acknowledged when **at least one policy row already carries
its `installation_id`**. That column exists
(`crates/domain/src/store/migrations/0001_initial_schema.sql:52`) and is written
on every `add` from the value `installation_for` (`policy.rs:317`) already
resolves — so no extra request, no new table, no second source of truth.

Do **not** add a table, a column, or a state file for this. If the query turns
out to be impossible with the current `Store` trait, add a read method; do not
add storage.

Two consequences to implement deliberately, not to work around:

- A **new** installation re-discloses, which is the point: that is when the
  operator's grant changed.
- Removing every policy for an installation makes the next `add` disclose
  again. Correct — that operator is back to their first policy against that
  grant.

### `auth status` must first become somewhere the pointer can point

**Verified: it is not, today.** `auth status` (`auth.rs:617-830`) never mentions
the permission — that range contains no `CRITICAL_PERMISSION`, `Administration`
or `permissions` — and `write_disclosure` is called from exactly one place,
`login` (`auth.rs:386`). Shipping the pointer without this makes the tool lie.

So `auth status`, for an authenticated credential, appends the permission table
and the three consequence sentences per
[`04-message-inventory.md`](../04-message-inventory.md#4c-auth-status-gains-the-grant-found-during-review-d4).
Render the rows from `PERMISSIONS` (`auth.rs:87-110`) — the same constant
`write_disclosure` uses — so the two cannot drift.

This also gives the operator the first way to re-read the disclosure without
signing in again.

## Definition of Done

1. `auth login` still prints the full twenty-five-line disclosure;
   `crates/app/tests/auth_onboarding.rs` passes **unmodified**.
2. The first policy created against an installation prints the three sentences,
   byte-identical. `policy_commands.rs:115`'s sentence-by-sentence assertions
   survive, retargeted at this case.
3. A second policy against the **same** installation prints the one-line note
   and not the three sentences.
4. A policy against a **different** installation prints the three sentences
   again, even though the operator has added policies before. Asserted with two
   installation ids in one database.
5. Removing every policy for an installation and adding again re-discloses.
6. `auth logout` does not reset acknowledgement — it deletes no policy rows.
   Asserted, because the mechanism is implicit and a future change to `logout`
   could break it silently.
7. `auth status` for an authenticated credential names every row of
   `PERMISSIONS` and the three consequence sentences; asserted against the
   constant, not against a copied literal.
8. `auth status` for an unauthenticated credential does **not** print the
   permission table — there is no grant to describe.
9. No new table, column, or file. `TABLES` (`crates/domain/src/store.rs:319`) is
   unchanged, and the migration chain gains no entry.
10. `crates/app/tests/readme_disclosure.rs` passes unmodified: the README's
    obligations are untouched by this task.
11. `cargo test --workspace` passes.
