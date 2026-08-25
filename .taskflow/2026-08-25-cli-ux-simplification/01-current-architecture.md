# Current architecture

Everything below was read from the working tree at `c3ae616` (version `0.1.4`).
Line numbers are that commit's.

## The captured session

Eleven invocations, seven failures, one repository armed. Annotated with the
class each failure belongs to.

| # | Invocation | Outcome | Class |
|---|---|---|---|
| 1 | `add repo IvanMurzak/AI-Game-Dev-App` | `error: unrecognized subcommand 'add'` | 1 — word order |
| 2 | `repo add IvanMurzak/AI-Game-Dev-App` | `error: the following required arguments were not provided: --host-label <HOST>` | 2 — derivable required argument |
| 3 | `repo add ... --host-label IvanPC` | Succeeded. Warning + result + 5-line disclosure + promote hint + platform warning | 5, 7 — noise |
| 4 | `tui` | Warning, then the terminal UI | 5 — noise |
| 5 | `repo add ... --host-label IvanPC --enabled true` | `error: unexpected argument '--enabled' found` + `tip: to pass '--enabled' as a value, use '-- --enabled'` | 3 — flag not where expected |
| 6 | `repo add ... --host-label IvanPC --enabled` | Same error, same misleading tip | 3 |
| 7 | `service install` | `error: cannot install the service while an agent is already running` + `try: runner-manager service status` | 6 — remedy that does not remedy |
| 8 | `repo set-scale ... --host-label IvanPC --enabled true` | `error: unexpected argument '--host-label' found` | 3 |
| 9 | `repo set-scale ... --enabled true` | `error: monitor-only policies cannot be enabled` + `try: ... set-capacity ... --max-capacity N` | 4 — the three-command dance |
| 10 | `repo set-scale ... --enabled true --max-capacity 5` | `error: unexpected argument '--max-capacity' found` | 3 |
| 11 | `repo set-capacity ... --max-capacity 6` then `repo set-scale ... --enabled true` | Armed | 4 |

Two facts about the operator matter for the design that follows. They typed
`IvanPC` — their own `COMPUTERNAME` — as the host label, and they twice reached
for a single command carrying both `--max-capacity` and `--enabled`. Both
instincts are the target design.

## Verified behaviour

### The command tree

Declared whole in one file (`crates/app/src/cli/mod.rs:437-660`) so that
`--help` describes a surface that exists before its handlers do. Families are
noun-first: `auth`, `host`, `repo`, `org`, `daemon`, `service`, plus the
bare `tui` and `status`. No aliases are registered anywhere in the tree —
`grep -n "alias" crates/app/src/cli/mod.rs` returns nothing — so `add repo`
reaches clap's unknown-subcommand path with no product-specific hint.

The surface is a **contract enforced in two directions**.
`crates/app/tests/cli_command_surface.rs:26-40` transcribes the command list
from `02-target-architecture.md` of the 2026-08-21 taskflow **by hand**, on
purpose, and asserts that `--help` and the design list are the same set. Its
header states the reason: deriving the list from the clap tree "would make this
test agree with whatever the tree says, which is the one thing it must not do".

> **Consequence for this work:** no CLI surface change is a code change alone.
> It is a design-document change, then the transcribed constant, then the tree.
> That ordering is a hard constraint on task sequencing.

### `--host-label`

`RepoAddArgs.host_label` is `String`, not `Option<String>`
(`crates/app/src/cli/mod.rs:516`), so clap requires it on every `add`. It is
validated by `HostLabel::new` (`crates/domain/src/model.rs:580-610`): ASCII
alphanumerics, `-` and `_`, no leading or trailing `-`, at most 64 characters,
lower-cased on construction. `IvanPC` therefore becomes `ivanpc`, and
`RoutingLabels::derive` produces `rm-ivanpc-win-x64`.

The value is stored **per policy** as `ScalePolicy.requested_host_label`
(`crates/domain/src/policy.rs:946,986`). Two policies on one host may
legitimately carry different labels; the test
`monitor_policy_keeps_its_own_label_when_another_policy_is_added_before_promotion`
(`crates/app/src/cli/policy.rs:1090`) asserts exactly that.

Meanwhile `local_display_name()` (`crates/app/src/cli/mod.rs:1511-1521`) already
reads `COMPUTERNAME` then `HOSTNAME`, falling back to the constant
`"this host"`. It is used for `Host.display_name` and is documented as "a
display string with no authority behind it: nothing routes, matches, or
authorises on it".

`Host` has no label field. `host show` (`crates/app/src/cli/host.rs:458-505`)
prints display name, id, `host_capacity`, in-use, headroom, start mode and the
secret store — **no routing label anywhere**. An operator who forgets the label
they used has no command that tells them.

### The three-command dance

`RepoAddArgs` (`mod.rs:511-522`) takes `--host-label` and an optional
`--max-capacity`, and nothing else. `RepoSetCapacityArgs` (`mod.rs:524-530`)
takes only `--max-capacity`; `RepoSetScaleArgs` (`mod.rs:532-538`) takes only
`--enabled`. Passing either flag to the other command is an unknown-argument
error — which is invocations 5, 6, 8 and 10 of the session.

Underneath, the split does not exist. `set_capacity` (`policy.rs:456`) and
`set_scale` (`policy.rs:474`) both funnel into

```rust
pub fn apply_policy_mutation(
    context: &Context,
    target: &ScaleTarget,
    mutation: PolicyMutation,        // { max_capacity, enabled, cache_policy }
    confirmation: Option<ScaleObservation>,
    out: &mut dyn Write,
) -> Result<(), CliError>
```

at `policy.rs:556`, documented as applying "a complete policy form as one
optimistic, atomic store update ... so a late capacity/cache/confirmation
failure leaves every column unchanged". `policy.rs:596-631` promotes a
monitor-only policy when `max_capacity` is present and then evaluates `enabled`
in the same in-memory pass, before the single write at `policy.rs:658-668`.

> **Consequence for this work:** a combined `--max-capacity` + `--enabled`
> command needs **no new transactional path**. The TUI already drives this
> function with both fields set (`crates/app/src/tui/settings.rs`), so the
> combined behaviour is already exercised in production code — just not from the
> CLI.

The refusal an operator meets at invocation 9 is `policy.rs:620-631`:
monitor-only policies cannot be enabled, remedied with `set-capacity`. It is a
correct refusal that exists only because the two flags cannot be given together.

### The App-override warning

`Context::resolve` calls `warn_about_an_app_override` at
`crates/app/src/cli/mod.rs:711` — on the composition root, so **every** command
that resolves a context emits it, including `tui` (`crates/app/src/tui/mod.rs:16`).

`write_app_override_warning` (`mod.rs:1392-1425`) has two branches:

- `RUNNER_MANAGER_GITHUB_BASE_URL` points at a fake GitHub: the overrides
  **are in force**, and the warning names the App actually being authenticated
  as. Materially load-bearing.
- Otherwise: the overrides are **ignored**, and the warning says so. This is the
  branch in the transcript.

The doc comment (`mod.rs:1358-1373`) records why the second branch exists: a
`runner-manager-d17-spike` override survived at machine scope on a workstation
and shipped `0.1.2` asking for authorization as the spike. That is a real
incident, and the fix is not to delete the warning — it is to stop printing it
where nothing about the outcome depends on it.

### The disclosure

`write_add_result` (`policy.rs:353-408`) prints, for a monitor-only policy:
the result line, `Monitor-only: ...`, then `write_grant_consequences`
(`crates/app/src/cli/auth.rs:139-154`) — a blank line, three sentences, a blank
line — then the promotion command, then any platform warnings.

`auth.rs:120-135` records that this short form already **replaced** the
twenty-five-line `write_disclosure`, for precisely the reason this taskflow
exists: the long form "buried the two lines the operator actually needed next —
the promotion command among them". The obligation is asserted sentence by
sentence in `crates/app/tests/policy_commands.rs:115` and
`crates/app/src/cli/policy.rs:1056-1070`, so shortening further "reds a test
rather than quietly weakening a disclosure".

`Installation.id` (`crates/github/src/lib.rs:1790`) is a `u64` GitHub
installation identifier, already resolved on the `add` path via
`installation_for` (`policy.rs:317`). It is not a secret and does not appear in
`crates/app/tests/no_secret_reaches_command_output.rs`'s redaction set.

### `service install` and the lock

`ServiceOperations::install` (`crates/platform/src/service.rs:3242-3260`) takes
the single-instance lock as step 2 of a documented six-step order and holds it
for the whole install, "so a daemon that starts halfway through cannot end up
racing a registration". On contention, `refuse_while_an_agent_runs`
(`service.rs:3489-3500`) maps `LockError::Held` to `ServiceError::LockHeld`
(`service.rs:508`).

`LockError::Held` (`crates/platform/src/lock.rs:167-178`) already carries
`kind`, `path`, and `holder: Option<LockHolder>` — and the rendered message in
the transcript proves the holder was known: PID 6212, the binary path, and the
hold time all appeared. What follows is `LockKind::advice`
(`lock.rs:106-120`), which says "Stop the other agent, or wait for it to exit"
without saying **how**, and the CLI-level remedy is
`try: runner-manager service status` — a command that reports the registration
and would not have helped.

> **Consequence for this work:** the data needed for an actionable remedy is
> already in the error value. This is a formatting change, not a plumbing one.

### Word-order and unknown-flag errors

Both come from clap defaults. clap's `suggestions` feature gives "did you mean"
for near-miss spellings, but `add` is not a misspelling of `repo` — it is a real
word in the wrong position, so nothing fires. The `tip: to pass '--enabled' as a
value, use '-- --enabled'` line is clap's generic unknown-argument hint; it is
accurate for a positional that looks like a flag and actively misleading here,
where `--enabled` is simply not a flag this subcommand has.

`Cli::command().debug_assert()` runs in
`the_command_tree_is_well_formed` (`crates/app/src/cli/mod.rs:1690`), so any
tree change is validated at test time.

## Change seams that already exist

| Seam | Where | What it gives this work |
|---|---|---|
| `apply_policy_mutation` | `policy.rs:556` | Atomic capacity+enable in one write. D1 and D2 need no new store path. |
| Forward-only migration chain | `crates/domain/src/store.rs:288-300` | Two migrations exist (`0001_initial_schema.sql`, `0002_policy_host_label.sql`). D3 adds `0003`. |
| `local_display_name()` | `mod.rs:1511` | The default host label source for D3. Needs a sanitiser to satisfy `HostLabel::new`. |
| `LockError::Held { holder }` | `lock.rs:167` | PID, path and start time for D6's remedy, already carried. |
| `Installation.id` | `crates/github/src/lib.rs:1790` | The non-secret acknowledgement key for D4. |
| `CliError::with_remedy` | `mod.rs:345` | Every failure already renders `error:` then `try:`. D6 and D7 write into an existing shape. |
| Buffered decorated reports | `mod.rs:1063-1090` | `Repo`, `Org`, `Host` output is buffered and aligned before printing, so a redesigned result block is a copy change. |

## Constraints this work must not break

1. **The surface test's direction of authority.** `cli_command_surface.rs`
   must keep transcribing the design by hand. Do not make it derive from clap.
2. **D20's default.** `add` without `--enabled` must still create a disabled
   policy (`policy_commands.rs` asserts `pending; scaling is disabled`).
3. **The disclosure obligation.** `07-security.md` of the 2026-08-21 taskflow
   requires the grant's consequences wherever a monitor-only policy is created.
   D4 narrows *when*, never *whether*.
4. **No secret in output.** `no_secret_reaches_command_output.rs:91-117` drives
   the command list; removing `set-capacity`/`set-scale` changes that list.
5. **`host set-capacity` keeps its name.** It is the host ceiling (D9) and is
   unrelated to the policy commands D2 removes.
