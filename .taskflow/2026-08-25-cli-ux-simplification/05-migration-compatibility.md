# Migration and compatibility

## The breaking change

D2 removes four leaf commands: `repo set-capacity`, `repo set-scale`,
`org set-capacity`, `org set-scale`. Anyone invoking them gets clap's usage
error and exit code `2`.

`host set-capacity` is **not** removed. It is a different command with a
different meaning (the host ceiling, D9) that happens to share a name fragment.
Every task specification touching this area must state that explicitly, because
a global find-and-replace on `set-capacity` would silently break it.

### Every live call site

Verified with `grep -rn "set-capacity\|set-scale"` over the working tree,
excluding `target/`, `.taskflow/` and `.claude/`.

| File | Lines | What it is | Action |
|---|---|---|---|
| `crates/app/src/cli/mod.rs` | 497-538, 549-594 | The clap tree for both families | Replace `SetCapacity`/`SetScale` with `Set`; add `--enabled`/`--host-label` changes to `Add` |
| `crates/app/src/cli/mod.rs` | 1701 | `repository_and_organization_set_scale_parse_explicit_true_and_false` | Rewrite against `repo set` and both `--enabled` spellings |
| `crates/app/src/cli/policy.rs` | 27-87 | `dispatch_repo` / `dispatch_org` arms | Collapse two arms into one |
| `crates/app/src/cli/policy.rs` | 456, 474 | `set_capacity`, `set_scale` | Replace with one `set` entry point onto `apply_policy_mutation` |
| `crates/app/src/cli/policy.rs` | 371, 390, 627, 743 | Remedy and next-step strings naming the removed commands | Rewrite per [`04-message-inventory.md`](04-message-inventory.md) |
| `crates/app/src/cli/policy.rs` | 226-227 | **Duplicate `add` already fails** with `Failure::Conflict`, "a policy for {target} already exists. Nothing was changed." | Its remedy must now name `repo set`; found during review, not in the original sweep |
| `crates/app/src/cli/status.rs` | 116-121, 510-524 | `HostSnapshot` and the pinned `/host` JSON key list | Add `host_label` to both (D3) |
| `crates/app/src/tui/shell.rs` | 1111 | Onboarding hint: `repo add OWNER/REPO --host-label <host> --max-capacity 1` | Stale under D3; found during review |
| `crates/app/src/tui/shell.rs` | 2991 | Asserts the empty-state screen contains `repo add` | Re-check after the hint is rewritten |
| `crates/app/src/tui/screens.rs` | 631, 1044, 1050 | Empty-state action text, **pinned by byte count and FNV hash** | Changing the text breaks the pinned snapshot deliberately; found during review |
| `crates/app/tests/cli_command_surface.rs` | 26-40 | The hand-transcribed `SURFACE` | Update to [`03-command-surface.md`](03-command-surface.md) |
| `crates/app/tests/no_secret_reaches_command_output.rs` | 103-104, 116-117 | Command list driven for redaction | Replace the four entries with two `set` entries |
| `crates/app/tests/policy_commands.rs` | 140, 178, 263 | Behavioural tests | Rewrite against `repo set`; add coverage for `add --enabled` |
| `tests/host-controller.sh` | 25 | Harness disables a policy between scenarios | `repo set "$2" --enabled false` |
| `tests/tests/e2e_security_acceptance.rs` | 689, 1145 | Builds argv containing `"set-scale"` | Replace with `"set"` |
| `README.md` | 35, 64-65 | Quick start step 3 and the command table | Rewrite to the target Journey 1 |
| `crates/domain/src/policy.rs` | 853, 1003, 1217, 1228, 1243, 1251, 1315, 1337, 2400 | Doc comments naming `set-scale`/`set-capacity` | Update prose; **no behaviour change in this crate for D1/D2** |
| `crates/testkit/src/fixtures.rs` | 357, 605 | Doc comments | Update prose |

`docs/`, `install/`, `npm/` and `.github/` contain no reference to either
command — verified, so no packaging or workflow file changes for D2.

**The TUI is unaffected by D1/D2.** It calls `apply_policy_mutation` directly
rather than shelling out, and the only command names it prints are the `repo
add` onboarding hints above, which change for D3's sake, not D2's.

### Release note obligation

`0.1.5` release notes must carry a **Breaking changes** section giving the
replacement for each removed command verbatim, because the failure mode is a
usage error that does not name a successor. Concretely:

```text
runner-manager repo set-capacity X --max-capacity N   ->  runner-manager repo set X --max-capacity N
runner-manager repo set-scale    X --enabled true     ->  runner-manager repo set X --enabled
runner-manager org  set-capacity X --max-capacity N   ->  runner-manager org  set X --max-capacity N
runner-manager org  set-scale    X --enabled false    ->  runner-manager org  set X --enabled false
```

`host set-capacity` is unchanged — say so in the note, since its name is one of
the two being removed elsewhere.

## The SQLite migration

`0003_host_label.sql`, appended to `MIGRATIONS`
(`crates/domain/src/store.rs:288-300`). Forward-only; the chain refuses to open
a database newer than the binary (`store.rs:30-31`), which is the existing
downgrade behaviour and is not changed.

```sql
ALTER TABLE hosts ADD COLUMN host_label TEXT NOT NULL DEFAULT '';

UPDATE hosts
   SET host_label = COALESCE((
       SELECT p.requested_host_label
         FROM policies p
        WHERE p.host_id = hosts.id
        ORDER BY p.rowid ASC
        LIMIT 1
   ), '');
```

That is the whole migration. **D4 adds no table** — see
[`02-target-architecture.md`](02-target-architecture.md#acknowledgement-key-and-why-it-needs-no-new-state):
`policies.installation_id` (`0001_initial_schema.sql:52`) already records which
installation each policy was created against, so "has this installation been
acknowledged" is a query over rows that already exist. `TABLES`
(`crates/domain/src/store.rs:319`) is therefore unchanged.

Four properties a task must verify rather than assume:

1. **Column names come from the schema, not from here.**
   `policies.requested_host_label` and `policies.host_id` are read from
   `0001_initial_schema.sql` and `0002_policy_host_label.sql` before this SQL is
   written.
2. **`rowid` really is available.** `policies` is `STRICT` but not
   `WITHOUT ROWID`, and has no `created_at` column
   (`0001_initial_schema.sql:43-67`), so `rowid` is the only insertion ordering
   there is. Confirm, then rely on it.
3. **Routing is preserved.** A database with one policy routing to
   `rm-office-linux-x64` must, after migration, produce `rm-office-linux-x64`
   for the next policy added with no `--host-label`. This is the migration's
   single behavioural assertion. Note that `0002` gave `requested_host_label`
   the literal default `'host'`, so a pre-`0002` policy backfills to `host` —
   which is exactly what the product uses for that policy today, and is the
   behaviour to preserve rather than improve mid-migration.
4. **Empty is a valid state.** A host with no policies keeps `''`, and the CLI
   resolves it from `default_host_label()` on next use. `HostLabel::new` rejects
   empty (`crates/domain/src/model.rs:582-586`), so the column is loaded as
   `Option<HostLabel>` rather than as a `HostLabel` holding an illegal value.

## D4 is a security decision and is reviewed as one

D4 amends the disclosure clause of D21 and of `07-security.md` in the
2026-08-21 taskflow. It must not be implemented as a copy change.

**What must hold after the change:**

| Property | How it is verified |
|---|---|
| `auth login` still prints the full 25-line disclosure | `crates/app/tests/auth_onboarding.rs` — unchanged |
| The three consequence sentences print, character for character, on the first policy against an installation | `crates/app/tests/policy_commands.rs:115`, retargeted |
| A **new** installation re-discloses even for an operator who has added policies before | New test: acknowledge id A, add against id B, assert the three sentences |
| A suppressed disclosure still names the grant and points at `auth status` | New test on the short form |
| **`auth status` actually carries what the pointer promises** | New test. Verified during review that it does not today: `auth.rs:617-830` never mentions the permission, and `write_disclosure` is called only from `login` (`auth.rs:386`). D4 is incoherent without this. |
| `auth logout` does not clear acknowledgement | It deletes no policy rows, so acknowledgement is unaffected by construction. Assert it, because the mechanism is implicit. |
| Removing every policy for an installation re-discloses on the next `add` | New test. This is intended, not a regression. |
| The README's `What you are granting` section is untouched | `crates/app/tests/readme_disclosure.rs` — unchanged |

**What is stored:** nothing new. The rule reads `policies.installation_id`,
which the product already writes. No token, no token hash, no login, and no new
table for `crates/app/tests/no_secret_reaches_command_output.rs` to reason
about.

**If the review rejects D4**, the fallback is "keep it verbatim every time" —
the current behaviour — with only the reordering from
[`04-message-inventory.md`](04-message-inventory.md#2-repo-add--monitor-only)
applied, so the next-step line sits above the disclosure instead of below it.
That is a pure copy change. D4's task must therefore be sequenced so that
rejecting it blocks none of D1, D2, D3, D5, D6 or D7.

## Ordering constraints

1. **The design list before the test before the tree.**
   [`03-command-surface.md`](03-command-surface.md) is the authority
   `cli_command_surface.rs` transcribes. Landing a clap change first turns that
   test red on `main`.
2. **D3's migration before D3's flag default.** `--host-label` cannot become
   optional until `Host.host_label` exists and is backfilled, or an upgraded
   install silently re-routes.
3. **D1/D2's surface change before their copy change.** The strings in
   [`04-message-inventory.md`](04-message-inventory.md) name `repo set`, which
   must exist first.
4. **D5, D6, D7 are independent** of everything above and of each other.

## Documentation to update

| File | Why |
|---|---|
| `README.md` | Quick start (four commands to three), command table, routing-label explanation |
| `npm/README.md` | Contains no policy commands; verify still true after the rewrite |
| `.taskflow/2026-08-21-local-runner-manager/02-target-architecture.md` | Its command list is superseded by `03-command-surface.md`. **Do not edit it** — that taskflow is a historical record. Add the pointer in this taskflow instead, and change `cli_command_surface.rs`'s header comment to cite this document as its source. |
| `.taskflow/2026-08-21-local-runner-manager/08-user-workflows.md` | Journeys 1, 1a and 3 describe the old command sequence. Same rule: superseded here, not edited there. |
