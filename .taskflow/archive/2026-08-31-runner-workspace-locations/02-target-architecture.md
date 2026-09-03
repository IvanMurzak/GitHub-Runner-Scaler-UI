# Target architecture

## Invariants

1. Config, SQLite, logs, diagnostics, and package cache remain in `AppPaths`.
2. Runner placement is a separate host configuration with a short Windows
   default.
3. Disposable workspace behavior remains the default and retains full cleanup.
4. Persistence is explicit, repository-scoped, visible, and reversible without
   deleting data.
5. One persistent slot is leased to at most one active attempt.
6. Uncleaned attempt rows, the database lease constraint, and the allocation
   lock remain authoritative; the filesystem is never scanned to infer
   ownership or capacity.
7. Runner credentials and lifecycle sidecars never survive a cleaned attempt.
8. CLI and TUI use the same domain mutations, path validation, active-attempt
   checks, and messages.

## Path concepts

The implementation separates three concepts that currently share one path:

| Concept | Contents | Lifetime | Configuration |
|---|---|---|---|
| Application paths | config, SQLite, logs, diagnostics, package cache | product lifetime | Existing platform discovery and `--data-dir` |
| Host runner root | disposable attempt directories | attempt lifetime | Host override or platform default |
| Repository persistent root | stable repository slots | operator-managed | Repository workspace policy |

### Platform defaults

| Platform | Effective host runner root |
|---|---|
| Windows | `%SystemDrive%\rman`, normally `C:\rman` |
| macOS | Existing `AppPaths::runtime_dir()` |
| Linux | Existing `AppPaths::runtime_dir()` |

Windows root discovery belongs in the platform crate. It obtains the Windows
system-directory volume through the platform API rather than trusting a
mutable environment variable, while presenting the result as `%SystemDrive%`
to users. It never assumes `C:` in tests or code. A missing or unusable system
drive fails with an actionable path error. Service installation creates the
default directory with the service account's required access. An interactive
or login agent that cannot create it tells the operator to configure a writable
host root.

### Precedence

For one launch:

```text
repository WorkspacePolicy::Persistent(path)
    > Host.runner_root_override
    > platform default_runner_root
```

`--data-dir` continues to relocate application data. It no longer represents
the normal way to shorten or move runner workspaces and does not override an
explicit runner-root setting.

## Domain model

### Host

Add:

```text
Host.runner_root_override: Option<LocalAbsolutePath>
```

`None` means use the platform default, which is resolved at runtime and shown
as such. Storing only the override allows a future platform-default correction
without rewriting every database. `host show`, status JSON, and Host Settings
show both the effective path and whether it is `platform-default` or
`configured`.

The store exposes a targeted host-root mutation rather than writing a stale
whole `Host` value. In one SQLite transaction it compares the previously read
override, confirms the count of uncleaned ephemeral attempts, and updates only
`runner_root_override`. This prevents a simultaneous capacity or service-mode
change from being overwritten.

### Repository policy

Add:

```text
WorkspacePolicy = Ephemeral | Persistent { root: LocalAbsolutePath }
ScalePolicy.workspace_policy: WorkspacePolicy
```

`Ephemeral` is the migration and constructor default. Rebuilding a persisted
organization policy with `Persistent` is corrupt state and fails closed.
`WorkspacePolicy` is separate from `CachePolicy`: runner-package retention and
job-workspace retention answer different questions and have different cleanup
paths.

The repository mutation extends the existing optimistic policy revision guard
with an uncleaned-attempt count checked in the same write transaction. A
separate read followed by `update_policy` is not an adequate fence.

### Attempt

Add immutable allocation facts:

```text
AttemptWorkspace = Ephemeral | PersistentSlot { slot: NonZeroU16 }
RunnerAttempt.workspace: AttemptWorkspace
```

`runtime_path` remains the exact path used by the attempt. The workspace kind
and slot number tell recovery which cleanup algorithm is legal. Neither may
change after allocation.

No slot table is required. Every persistent attempt whose state is not
`cleaned` is a durable slot lease, including a terminal attempt whose cleanup
failed. A partial unique database index rejects two uncleaned rows for the same
policy and slot. Persistent directories provide retained bytes but never lease
truth.

## Directory layout

### Disposable

```text
<effective-host-root>/
  <12-char-attempt>/
    bin/
    externals/
    _work/
    lifecycle sidecars
```

The complete `<12-char-attempt>` directory is removed on cleanup, matching
current behavior.

### Persistent repository

```text
<configured-repository-root>/
  s1/
    bin/ and runner files      recreated for one attempt
    lifecycle sidecars         recreated for one attempt
    _work/                     retained across attempts
  s2/
    ...
```

Names are `s1`, `s2`, and so on to minimize path length. The slot root is the
runner runtime, preserving the runner's standard relative `_work` folder and
avoiding dependence on unverified absolute `work_folder` behavior.

Before materialization, a reusable slot must contain only a valid real `_work`
directory or be empty. The verified runner package is copied into the slot for
the attempt. After conclusion, persistent cleanup removes every slot-root entry
except `_work`. It then releases the package lease and marks the attempt clean.

If `_work` is a symlink, junction, reparse point, file, or otherwise unsafe, the
slot is quarantined by leaving the attempt not-cleaned. It consumes capacity
until recovery or operator remediation; allocation does not silently choose it
again.

## Slot allocation

Allocation runs while holding the existing host allocation lock:

1. Load uncleaned attempts for the policy.
2. Collect the slot numbers held by persistent attempts, including terminal
   attempts awaiting cleanup.
3. Select the lowest positive slot not held by an active attempt.
4. Refuse a number above the policy `max_capacity`.
5. Build `<persistent-root>/sN` and validate containment.
6. Create or validate the slot directory.
7. Journal the allocated attempt with workspace kind, slot, and exact path
   before package or GitHub effects.

This provides stable reuse without pre-creating directories. Lowering capacity
does not delete higher-numbered slots. They become reusable only if capacity is
raised again. Files remain operator-owned until manually removed.

## Cleanup and recovery

Cleanup dispatches by journaled workspace kind:

```text
Ephemeral       -> remove runtime_path recursively
PersistentSlot  -> retain only runtime_path/_work, remove all other entries
```

Both paths must complete before the attempt becomes `cleaned`. Recovery uses
the same dispatcher. A process that survived a restart is still terminated or
observed according to current lifecycle rules before any directory cleanup.

Path changes are refused while affected attempts are active or awaiting
cleanup. Therefore no attempt that can still touch its journaled path needs
rewriting. Once all affected attempts are cleaned:

- changing the host runner root affects only new ephemeral attempts;
- changing repository persistent path affects only new persistent attempts;
- old directories are reported but never copied or removed;
- changing a repository back to ephemeral preserves every old slot.

## Path validation

Validation has two layers so opening the database never depends on current
filesystem availability.

The pure stored-shape validator is called by database load, CLI, TUI, and
mutations. It requires:

- an absolute path native to the current host;
- a non-root directory;
- no lexical or canonical overlap with config, state, logs, package cache, or
  diagnostics;
- no equality, ancestor, or descendant overlap between the effective host
  runner root and any repository persistent root;
- no equality, ancestor, or descendant overlap with another repository's
  persistent root;
- no UNC, device namespace, or syntactically remote path;
- no `..` traversal after normalization;
- containment of every derived attempt or slot path below the validated root.

The operational preflight runs before a mutation is committed and before the
daemon accepts new allocation. It requires a local filesystem identity, an
existing writable directory or a creatable leaf below a writable parent, and a
stable canonical path for any existing component. A platform that cannot prove
the configured location is local fails closed. TUI preview may run this check,
but database load does not.

Neither layer deletes or changes permissions on an operator path as a side
effect. Directory creation and the narrowly scoped default-root ACL operation
are explicit application steps after validation passes.

## CLI

```text
runner-manager host set-runtime-root --path PATH
runner-manager host reset-runtime-root

runner-manager repo set-workspace OWNER/REPO --mode ephemeral
runner-manager repo set-workspace OWNER/REPO --mode persistent --path PATH
```

Rules:

- `persistent` requires `--path`.
- `ephemeral` rejects `--path` so an ignored argument cannot mislead.
- organization commands expose no persistent workspace option.
- mutations refuse active or cleanup-blocked attempts and report both counts.
- success output shows old configured value, new configured value, effective
  path, and whether existing directories were left behind.
- `host show`, `repo list`, `status`, and `status --json` expose effective mode
  and path without listing files inside workspaces.

## TUI

Host Settings adds an editable runner-root control with:

- current effective path;
- source badge: `platform-default` or `configured`;
- text entry and bracketed paste;
- reset-to-default action;
- inline absolute/local/writable/overlap validation;
- active-attempt refusal preview;
- save through the CLI mutation handler.

Repository Settings adds:

- workspace mode toggle: `ephemeral` or `persistent`;
- persistent path editor visible only in persistent mode;
- current effective path;
- active and cleanup-blocked slot leases;
- a trust warning that retained bytes can affect later jobs;
- a non-destructive notice when changing mode or path leaves old directories;
- save through the same repository mutation used by CLI.

Organization Settings renders workspace mode as `ephemeral` and explains that
persistent paths require repository scope.

## Documentation

After implementation, README `Commands` includes the new command families.
`Store runner data somewhere else` shows complete placeholder commands:

```powershell
runner-manager host set-runtime-root --path "<GLOBAL_RUNNER_ROOT>"

runner-manager repo set-workspace OWNER/REPO `
  --mode persistent `
  --path "<REPOSITORY_WORKSPACE_ROOT>"
```

The checkout tip remains next to this guidance and explains that persistence is
opt-in. It must not claim `clean: false` alone makes an ephemeral workspace
persistent.
