# Target architecture

The exhaustive target command list is in
[`03-command-surface.md`](03-command-surface.md); the exact strings are in
[`04-message-inventory.md`](04-message-inventory.md). This document holds the
design and the trade-offs.

## Principle

One principle governs all seven decisions, and it is a refinement of the
2026-08-21 taskflow's Principle 5 ("CLI is the source of configuration truth"):

> **A command asks only for what it cannot know, and says the useful thing
> before the alarming one.**

Nothing about the product's caution changes. What changes is *when* caution is
spent: on the operator's attention, which is finite, and which the current
design spends on a warning that changes no outcome and a disclosure the reader
has already met.

## D1 + D2 — one add, one set

### Shape

```text
repo add OWNER/REPO [--host-label HOST] [--max-capacity N] [--enabled [BOOL]]
repo set OWNER/REPO [--max-capacity N] [--enabled BOOL]
```

`org` is identical with `ORG` in place of `OWNER/REPO`. `set-capacity` and
`set-scale` do not exist in either family.

### `--enabled` accepts both spellings, on both commands

`#[arg(long, value_name = "BOOL", num_args = 0..=1, default_missing_value = "true", action = ArgAction::Set)]`.

So `--enabled`, `--enabled true`, and `--enabled false` all parse. This is not
decoration: the captured session typed `--enabled true` **and** bare `--enabled`
one command apart, and a design that accepted only one of them would have
produced one of the same two errors. The uniformity across `add` and `set` is
the point — a flag that means one thing on one subcommand and another on its
sibling is the defect D2 exists to remove.

### `--enabled` on `add` requires `--max-capacity`

A policy created with no capacity is monitor-only (D19), and a monitor-only
policy has no routing label to arm. `repo add X --enabled` with no capacity is
therefore refused **before any GitHub call**, by argument validation rather
than by `apply_policy_mutation`, with a message that states the rule and gives
the one-command fix. `add` still performs a GitHub round-trip to resolve the
installation, so failing at parse time is a real saving as well as a clearer
one.

`repo set X --enabled true` on an existing monitor-only policy keeps today's
refusal (`policy.rs:620-631`) with its remedy rewritten to the single
command that now does the job:

```text
try: runner-manager repo set OWNER/REPO --max-capacity N --enabled true
```

### D20 is relaxed, not withdrawn

D20 guarantees that creating a policy never arms a host. The target keeps that
as the **default**: no `--enabled`, no arming, and the existing assertion on
`pending; scaling is disabled` continues to hold for the flagless form. What
D20 loses is its second, unstated property — that arming can only ever happen
in a separate invocation. That property bought a confirmation step the product
does not otherwise ask for, and cost every operator one command. The exchange is
deliberate: an operator who types `--enabled` has stated the intent that the
second command existed to elicit.

### Why `set` and not idempotent `add`

An idempotent `add` would be one subcommand smaller. It was rejected because
`add` would then be the verb that disables a running policy and starts a drain
— a destructive transition (`policy.rs:640-646`) reached through a word that
means *create*. `set` names the operation it performs.

### Cost

Every existing script, README snippet and blog post using `repo set-capacity`
or `repo set-scale` breaks with a clap usage error (exit `2`). This is accepted
at `0.1.4`, pre-1.0. The full call-site list and the release-note obligation
are in [`05-migration-compatibility.md`](05-migration-compatibility.md).

## D3 — the host owns its routing identity

### Model change

`Host` gains one field:

```rust
pub struct Host {
    // ...
    pub host_label: HostLabel,
}
```

Resolution order when a policy needs a label:

1. `--host-label` on the command, if given (per-policy override; unchanged
   semantics, still stored as `ScalePolicy.requested_host_label`).
2. Otherwise `Host.host_label`.

`Host.host_label` is set once, when the host record is created
(`crates/app/src/cli/mod.rs:1471`), from a new `default_host_label()` that
sanitises `local_display_name()` into something `HostLabel::new` accepts:

- lower-case;
- every character outside `[a-z0-9_-]` replaced with `-`;
- runs of `-` collapsed, leading and trailing `-` trimmed;
- truncated to `HostLabel::MAX_LEN` (64);
- if the result is empty, the literal `host`.

`COMPUTERNAME=IvanPC` yields `ivanpc`, and `RoutingLabels::derive` yields
`rm-ivanpc-win-x64` — the label the operator produced by hand.

### The fallback must not be defaulted from

**Verified during review:** `local_display_name()` falls back to the constant
`"this host"` when neither `COMPUTERNAME` nor `HOSTNAME` is set
(`crates/app/src/cli/mod.rs:1512-1520`). Sanitised, that is `this-host` — the
**same value on every such machine**. Defaulting from it would give two hosts
the same routing label, which is precisely the hazard the product already warns
about at `crates/app/src/cli/policy.rs:261`: *"routing label ... is already
recorded for another host. Both hosts may start for the same queued job."* That
warning is local-database-scoped and cannot see the other machine, so a
cross-machine collision would be silent.

So `default_host_label()` returns `None`, not `this-host`, when
`local_display_name()` produced the fallback. In that case `repo add` with no
`--host-label` fails with:

```text
error: this machine reports no name, so there is no routing label to derive.
  try: runner-manager host set-label <name>    (then re-run this command)
```

This narrows D3 rather than contradicting it: the decision is that the tool
stops asking for a value it can derive, and on a machine with no name there is
no value to derive. Asking is then correct, and guessing would be the defect.

### Surfacing it

`host show` gains two lines, because a routing label nobody can read is a label
nobody can put in `runs-on`:

```text
  host label                ivanpc
  routing label             rm-ivanpc-win-x64
```

`host set-label LABEL` changes it. It validates through `HostLabel::new` and
**warns** — it does not refuse — when policies already carry a derived label,
because changing the host label does not retroactively re-derive labels already
reserved on existing policies. Those keep their `requested_host_label`; only
new policies pick up the new default. Saying so at the moment of change is the
whole reason the command prints anything.

### Why a host field rather than only a flag default

Defaulting the flag alone would have been a two-line change. It was rejected
because it leaves the oddity that produced the confusion: the routing identity
would still be a per-policy value with no home, invisible in `host show`, and
recoverable only by reading a policy back. Principle 2 of the 2026-08-21
taskflow — *one host owns its runners* — implies the host owns the identity
those runners route on. The per-policy override survives for the case that
motivated it (staging one repository onto a differently-labelled lane), and is
now genuinely an override rather than the only representation.

### Migration

`0003_host_label.sql`, forward-only, in the existing chain
(`crates/domain/src/store.rs:288-300`):

1. `ALTER TABLE hosts ADD COLUMN host_label TEXT NOT NULL DEFAULT ''`.
2. Backfill each host from the `requested_host_label` of its **oldest** policy,
   so an existing install keeps routing exactly as it does today.
3. Where a host has no policies, leave `''`; the CLI treats empty as "not yet
   resolved" and fills it from `default_host_label()` on next use, which is the
   same path a fresh install takes.

Step 2 matters: an operator whose only policy routes to `rm-office-linux-x64`
must not silently acquire `rm-thinkpad-linux-x64` as their default on upgrade.

**"Oldest" has to be `rowid`.** `policies` has no `created_at` column
(`0001_initial_schema.sql:43-67`) and its `id` is a random UUID, so neither
orders by time. SQLite's implicit `rowid` is insertion order for these tables —
they are `STRICT` but not `WITHOUT ROWID` — and is the only ordering available.
A task must confirm that before relying on it rather than taking it from here.

`requested_host_label` was added by `0002_policy_host_label.sql` with
`DEFAULT 'host'`, so a policy created before that migration carries the literal
`host`. Backfilling it is still correct: `host` is precisely the value the
product uses today when promoting that policy, so copying it preserves current
behaviour rather than inventing a better one during a migration.

## D4 — disclose on change, not on repetition

### Rule

| Situation | What prints |
|---|---|
| `auth login` | `write_disclosure` — the full twenty-five lines. Unchanged. |
| First policy creation against an installation id not yet acknowledged | `write_grant_consequences` — the three sentences. Unchanged text. |
| Any later policy creation against an acknowledged installation | One line: the permission named, and `runner-manager auth status` for the full text. |

### `auth status` must first become a place the pointer can point

**Verified during review:** `auth status` (`crates/app/src/cli/auth.rs:617-830`)
prints the credential state, the store location, the reachable installations and
their remedies, and **never names the grant or its consequences** — searching
that range for `CRITICAL_PERMISSION`, `Administration`, or `permissions` returns
nothing. `write_disclosure` is called from exactly one place, `login`
(`auth.rs:386`).

So the short form's pointer would be false as the code stands. D4 therefore
includes: `auth status` prints the permission table and the three consequence
sentences for an authenticated credential.

This is a scope addition rather than a decision change, and it is an
improvement in its own right — `auth status` exists to answer "what does this
credential let the tool do", and that is the one question it does not currently
answer. It also means the operator can re-read the disclosure at any time
**without signing in again**, which is not possible today.

### Acknowledgement key, and why it needs no new state

`Installation.id` (`crates/github/src/lib.rs:1790`), a `u64` GitHub assigns.
Already resolved on the `add` path by `installation_for` (`policy.rs:317`), so
no extra request is made. It is not a secret and is not in the redaction set
(`crates/app/tests/no_secret_reaches_command_output.rs`).

**The `policies` table already stores it.** `installation_id INTEGER NOT NULL`
is a column of `policies` in `0001_initial_schema.sql:52`. So the rule is a
query, not a new table:

> An installation is acknowledged when at least one policy row already carries
> its `installation_id`.

A policy against installation *X* is proof the operator already created one
against *X*, and therefore already read the consequences. No new table, no new
column, nothing for a migration to backfill, and no second source of truth that
could disagree with the policies it describes.

It is also self-correcting in the right direction: `repo remove`-ing every
policy for an installation makes the next `add` disclose again, which is
correct — that operator is back to their first policy against that grant.

Keying on the installation rather than on the credential is the stronger
choice, and is why this decision is defensible against D21: the disclosure
re-prints exactly when the operator's grant **changes** — a second account, a
new organization, a re-install after removing the App — which is the moment the
consequences are newly relevant. A credential-keyed rule would stay silent
through all of those.

`auth logout` deletes no policy rows, so it does not reset acknowledgement.
That is deliberate: the grant on GitHub survives a local logout, so
re-disclosing on the next sign-in of the same account would be theatre.

### What is not weakened

- The full disclosure at sign-in is untouched.
- The three sentences are untouched, character for character; the tests at
  `crates/app/tests/policy_commands.rs:115` and
  `crates/app/src/cli/policy.rs:1056-1070` continue to assert them, now against
  the first-add-per-installation case.
- The README's `What you are granting` section and its gate
  (`crates/app/tests/readme_disclosure.rs`) are untouched.

## D5 — warn where it can bite

`warn_about_an_app_override` moves off the composition root
(`crates/app/src/cli/mod.rs:711`) and becomes a function of the command:

| Branch | Emitted by |
|---|---|
| Overrides **in force** (fake GitHub) | Every command. Unchanged — this one describes what the process is actually doing. |
| Overrides **ignored** | `auth login`, `auth status`, `daemon run`, `service install`, `service uninstall`, `service status`. |

The rule is stated as a predicate over the parsed `Command`, in the same file
and beside `is_decorated_report` (`mod.rs:1109-1122`) which already does exactly
this kind of per-command classification. `write_app_override_warning` itself
does not change, so the existing test that drives it directly keeps working; a
new test asserts the predicate, one command at a time, so a future command is
silent-by-default rather than noisy-by-default.

**Why those six.** A stale override matters when the process is about to
authenticate as an App (`auth login`), when it reports which App it is
(`auth status`), or when it is about to run unattended for weeks with whatever
identity it resolved (`daemon`, `service`). `repo add` reads an existing
credential and cannot be sent to the wrong consent screen; `status`, `host show`
and `repo list` do not authenticate at all.

## D6 — a remedy that remedies

`ServiceError::LockHeld` (`crates/platform/src/service.rs:508`) keeps its
refusal and gains a remedy built from the `LockHolder` the error already carries
(`crates/platform/src/lock.rs:167-178`): the process id, the binary path, and
the platform's own way to stop it — `Stop-Process -Id <pid>` on Windows,
`kill <pid>` elsewhere — followed by the command to retry.

The `try: runner-manager service status` remedy is replaced, not supplemented:
it pointed at a command that reports the registration, which is not what is
wrong. Where the holder is unknown (`holder: None`, a race of microseconds),
the remedy falls back to naming the lock file and saying the lock clears when
the holding process exits.

`LockKind::advice` (`lock.rs:106-120`) keeps its sentence about the OS releasing
the lock, including after a crash. That sentence is the one that stops an
operator deleting a lock file by hand, and it stays.

## D7 — diagnose the two dead ends

### Swapped noun and verb

Before `Cli::parse()`, inspect `argv`. If `argv[1]` is one of the family verbs
(`add`, `list`, `set`, `remove`, `show`, `install`, `uninstall`, `status`,
`login`, `logout`, `run`, `set-capacity`, `set-label`) **and** `argv[2]` is one
of the families (`repo`, `org`, `host`, `auth`, `daemon`, `service`), print

```text
error: unrecognized subcommand 'add'
  try: runner-manager repo add IvanMurzak/AI-Game-Dev-App
```

with the remaining arguments preserved, and exit with clap's usage code `2`.
Both orders are **not** accepted — the table stays noun-first, and the surface
test stays meaningful. Only the diagnosis improves.

Exit code `2` is deliberate: this is a usage error, clap owns that code
(`mod.rs:135-140`), and a script must not be able to tell this hint apart from
the error it replaces.

### Unknown flag

clap's `tip: to pass '--enabled' as a value, use '-- --enabled'` is suppressed
for unknown long flags and replaced with the accepted flags for the subcommand
that was actually reached, read from the clap `Command` so it cannot drift:

```text
error: unexpected argument '--enabled' found
  this command accepts: --host-label, --max-capacity, --enabled
```

After D1 that particular example stops occurring, which is the point: the hint
exists for the flags that will be typed at the *next* command whose vocabulary
someone guesses.

## Deliberately not changed

| Thing | Why |
|---|---|
| Noun-first command families | Changing to verb-first, or accepting both, doubles the surface a reader and the surface test must cover. D7 diagnoses the mistake instead. |
| `host set-capacity` | The host ceiling (D9). Renaming it for symmetry with `repo set` would break a command nobody complained about. |
| D19 monitor-only | Untouched. `add` with no `--max-capacity` still creates a monitor-only policy. |
| The disable confirmation | `confirm_disable` (`policy.rs:699-715`) still prompts before draining active runners, now from `repo set --enabled false`. |
| `TRUST_WARNING` on enable | `policy.rs:20`. It fires exactly once, at the moment scaling is armed, which is where it belongs. |
| The TUI | It calls `apply_policy_mutation` directly and is unaffected by D1/D2. It gains the host label in its settings screen from D3, and nothing else. |
| `status --json` | Schema-stable. No field is removed. `host_label` is **added** to `/host`. Additive for consumers, but not silent for us: `crates/app/src/cli/status.rs:510-524` pins the exact `/host` key list, so the addition is a deliberate, reviewed edit to that assertion. |

## Target Journey 1

From a signed-in binary, on a machine whose name is usable as a label:

```text
runner-manager repo add IvanMurzak/AI-Game-Dev-App --max-capacity 6 --enabled
runner-manager service install
```

Two commands, plus the workflow edit that puts the printed routing label into
`runs-on`. The gate in [`ROADMAP.md`](ROADMAP.md#gates) is stated as three, to
leave room for `host set-label` on a machine whose name sanitises badly.
