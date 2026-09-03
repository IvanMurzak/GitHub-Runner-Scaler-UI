# Current architecture

## Evidence boundary

This document describes the repository at commit `995f337` plus the uncommitted
Taskflow folder. Every claim about current behavior cites a source file and line.
Planning documents are not evidence that product behavior already exists.

## Authoritative external constraints

These requirements were rechecked during Taskflow review on 2026-08-31:

- Microsoft documents the traditional `MAX_PATH` limit as 260 characters and
  states that removing it requires both an enabled system setting and a
  `longPathAware` application manifest. A short default remains necessary
  because a workflow can invoke tools that have not opted in:
  <https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation>.
- GitHub's JIT runner API defines `work_folder` relative to the runner install
  directory and defaults it to `_work`. Keeping the slot root as the runner
  install directory preserves this supported layout:
  <https://docs.github.com/en/rest/actions/self-hosted-runners>.
- GitHub warns that self-hosted runner hardware is not guaranteed to be clean
  between jobs and that retained state can be persistently compromised by
  untrusted workflow code. Persistent mode therefore cannot be presented as an
  isolation feature:
  <https://docs.github.com/en/actions/reference/security/secure-use>.
- The official `actions/checkout` input `clean` defaults to true and runs
  `git clean -ffdx` plus `git reset --hard HEAD`. Retaining Git-ignored build
  outputs requires an explicit workflow choice in addition to a persistent
  runner slot: <https://github.com/actions/checkout/blob/main/README.md>.

## Path discovery and service capture

`AppPaths` currently owns four application-data directories: config, state,
runtime, and logs. On Windows, runtime resolves below
`%LOCALAPPDATA%\IvanMurzak\runner-manager\data`, while macOS and Linux use their
platform application-data roots (`crates/platform/src/paths.rs:31-37`).
`AppPaths::discover` obtains all four from `ProjectDirs` and appends `runtime` to
the local data directory (`crates/platform/src/paths.rs:196-210`).

`--data-dir` does not select only runner placement. `AppPaths::rooted_at` moves
config, state, runtime, and logs together below one supplied root
(`crates/platform/src/paths.rs:213-228`). The installed service captures the
resolved runtime path as a hidden `--service-runtime-dir` argument alongside the
other three application directories (`crates/app/src/cli/service.rs:112-125`).

Consequences:

- there is no independent host runner-root setting;
- shortening Windows runner paths currently requires moving every application
  directory and reinstalling the service;
- a path stored in the service registration is static until service install is
  run again.

## Host and policy persistence

`Host` persists identity, OS, architecture, capacity, service start mode,
refresh interval, and creation time. It has no runner-root field
(`crates/domain/src/model.rs:1040-1057`). The `hosts` table has the same shape
(`crates/domain/src/store/migrations/0001_initial_schema.sql:21-40`), and the
whole-record upsert writes exactly those fields (`crates/domain/src/store.rs:903-951`).

`ScalePolicy` persists target, installation, host ownership, requested host
label, mode, enabled state, cache policy, and revision. It has no workspace mode
or workspace path (`crates/domain/src/policy.rs:932-952`). `PersistedPolicy`
likewise has no workspace configuration (`crates/domain/src/policy.rs:979-997`).
The `policies` table has no path or workspace column
(`crates/domain/src/store/migrations/0001_initial_schema.sql:43-68`).

Schema changes are forward-only numbered migrations. The production chain is at
version 2 and a newer unknown database fails closed (`crates/domain/src/store.rs:263-306`).
This change therefore requires a new migration rather than editing either
applied migration.

## Runtime allocation

One `LifecycleLauncher` receives one `runtime_root` at construction
(`crates/agent/src/lifecycle.rs:977-1027`). The daemon supplies
`context.paths().runtime_dir()` to every managed target, so all policies share
the same root (`crates/app/src/cli/daemon.rs:156-186`).

For each attempt, the launcher creates a random ID and appends a 12-character
ID-derived directory name to that common root
(`crates/agent/src/lifecycle.rs:1596-1630`). The shortened name exists because a
real Windows checkout reached 264 characters against a 260-character limit
(`crates/agent/src/lifecycle.rs:417-439`). The full attempt identity and absolute
runtime path are journaled in SQLite; `attempts.runtime_path` is required and
survives policy deletion for recovery
(`crates/domain/src/store/migrations/0001_initial_schema.sql:72-100`).

There is no stable slot identity, slot lease table, workspace generation, or
distinction between disposable runner material and retained job workspace.

## Cleanup and recovery

After preserving redacted diagnostics, `clean_attempt` calls
`remove_dir_all(attempt.runtime_path())` for production attempts. Only a missing
directory is treated as already clean (`crates/agent/src/lifecycle.rs:1441-1466`).
The package lease is released only after directory removal succeeds
(`crates/agent/src/lifecycle.rs:1467-1474`).

`CachePolicy` can retain or discard the verified runner package, but job
workspace retention has no representable value and
`retains_job_workspace()` always returns false
(`crates/domain/src/model.rs:340-375`). Existing lifecycle tests deliberately
reject two-attempt workspace reuse and assert complete cleanup.

Recovery is safer than filesystem discovery because attempts carry the exact
runtime path. Any new slot behavior must preserve this property: the journal,
not directory names, decides which path and process the host owns.

## CLI seams

The host command family currently contains only `set-capacity` and `show`
(`crates/app/src/cli/mod.rs:518-530`). Its dispatcher has the same exhaustive
surface (`crates/app/src/cli/host.rs:383-391`). A new host runtime-root command
requires additions at both seams and a shared handler usable by TUI.

The repository command family contains add, list, capacity, scale, label, and
remove operations, but no workspace command (`crates/app/src/cli/mod.rs:541-557`).
Repository and organization dispatch are currently intentionally parallel
(`crates/app/src/cli/policy.rs:22-110`). Persistent configuration must be an
explicit repository-only exception rather than being added mechanically to the
organization family.

## TUI seams

Host Settings loads capacity, use, service mode, refresh interval, and request
budget, but no filesystem path (`crates/app/src/tui/settings.rs:39-72`). Its
apply path reuses CLI host handlers for capacity and service mode, then writes
refresh interval (`crates/app/src/tui/settings.rs:399-430`).

Repository Settings loads policy mode, enabled state, capacity, labels, package
cache policy, and active runner count (`crates/app/src/tui/settings.rs:170-228`).
The editable draft contains only enabled, capacity, and cache policy
(`crates/app/src/tui/settings.rs:288-307`). The rendered forms expose no path
editor (`crates/app/src/tui/settings.rs:635-735`).

The current TUI pattern is suitable for extension: load a durable form, edit a
draft, preview validation, then dispatch the same mutation used by CLI. Path
entry adds text-editing and paste behavior that numeric and toggle controls do
not exercise today.

## Existing guarantees this change revises

The earlier architecture states that every runner has one disposable workspace
and may never reuse it. The source model, lifecycle cleanup, security tests, and
acceptance mutants all encode that rule. Persistent mode deliberately revises
the guarantee only for an explicitly configured repository. Disposable mode
must retain the original guarantee byte for byte in behavior and evidence.
