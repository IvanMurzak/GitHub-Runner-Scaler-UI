# Runner workspace locations

**Status:** Architecture reviewed 2026-08-31 against repository evidence and
current Microsoft and GitHub documentation. Confirmed planning defects were
corrected. No implementation tasks have been derived and no product code is
changed by this Taskflow.

**Scope:** `runner-manager` host runtime placement, repository-scoped persistent
workspaces, stable slots, CLI and TUI configuration, migration, recovery,
security, tests, and README guidance.

## Problem

The current Windows runtime root is long before a repository name is added. A
real checkout already reached 264 characters and failed against the 260
character path limit. Operators also need two distinct storage behaviors:

1. a short host-wide root where disposable runner attempts are created and
   removed; and
2. an opt-in persistent root for a specific repository, where stable slots
   retain job files and caches between runner attempts.

The current product has only the first behavior, rooted under application data,
and always removes the entire attempt directory. It has no host runtime-root
setting, repository workspace setting, persistent slot model, or TUI path
editor.

## Owner decisions

This is the sole decision ledger for this Taskflow.

| ID | Decision | Status | Consequence |
|---|---|---|---|
| D1 | Windows uses `%SystemDrive%\rman` as the default host runner root, normally `C:\rman`. The name is short and avoids similarity to the destructive `rm` command. | Locked 2026-08-31 | New Windows hosts minimize path depth. macOS and Linux retain their platform-standard runtime default. |
| D2 | The host runner root is editable through both CLI and TUI Host Settings. | Locked 2026-08-31 | CLI and TUI call the same validation and persistence path. |
| D3 | Disposable mode remains the default. Attempts under the host runner root are unique and removed after success, failure, idle exit, and recovery cleanup. | Locked 2026-08-31 | Existing isolation remains the safe default. |
| D4 | A repository policy may opt into a persistent absolute path through CLI or TUI Repository Settings. | Locked 2026-08-31 | Persistence is repository-scoped configuration, not a global cache toggle. |
| D5 | Persistent repositories use stable exclusive slots and reuse them across attempts. | Locked 2026-08-31 | Concurrent jobs never share one slot. Slot count grows only as concurrency requires. |
| D6 | Persistent mode retains the job workspace, including Git-ignored files. Runner binaries, JIT handoff material, process identity, registration identity, and other lifecycle sidecars remain disposable. | Locked 2026-08-31 | Build caches survive without persisting runner credentials or process control files. |
| D7 | Persistent workspace mode is supported only for repository policies. | Locked 2026-08-31 | An organization-scoped JIT runner can accept work from multiple repositories and no reservation reveals which repository will be assigned before launch. |
| D8 | Path precedence is repository persistent path, then configured host runner root, then platform default. | Locked 2026-08-31 | Repository opt-in never changes another policy's location. |
| D9 | A path change is refused while affected attempts are active. Existing directories are never moved or deleted automatically. | Locked 2026-08-31 | Reconfiguration is non-destructive and recovery metadata remains truthful. |
| D10 | Configured paths must be absolute local filesystem paths. UNC paths and network shares are rejected. | Locked 2026-08-31 | Runner correctness and recovery never depend on a remote filesystem. |
| D11 | CLI and TUI display the effective path, configured source, workspace mode, active and cleanup-blocked slot leases, and validation errors. | Locked 2026-08-31 | Operators can understand current behavior before changing it. |

## Proposed command surface

```text
runner-manager host set-runtime-root --path PATH
runner-manager host reset-runtime-root

runner-manager repo set-workspace OWNER/REPO --mode ephemeral
runner-manager repo set-workspace OWNER/REPO --mode persistent --path PATH
```

`repo add` remains non-arming and does not gain a second workspace configuration
path. An operator adds a policy, configures its workspace, then enables scaling.

## Summary

Application data and runner data become separate concepts. Config, SQLite,
logs, diagnostics, and the verified package cache remain under `AppPaths`.
`Host.runner_root` selects disposable runner placement. A repository policy's
persistent workspace configuration overrides that placement and owns stable
slots. Each slot retains only its job workspace; one-attempt runner material is
recreated and scrubbed around every use.

The attempt journal remains authoritative for recovery. Persistent slot leases
are durable and allocated under the existing host allocation lock. Filesystem
directory names are never used as the source of truth for ownership or active
capacity.

## Document map

| File | Purpose |
|---|---|
| `01-current-architecture.md` | Verified current behavior and exact change seams. |
| `02-target-architecture.md` | Target data model, path precedence, slot lifecycle, CLI, and TUI design. |
| `03-migration-rollout.md` | Forward-only SQLite migration, service transition, compatibility, and rollout gates. |
| `04-security-recovery.md` | Persistent-state trust boundary, path validation, cleanup, recovery, and threats. |
| `05-user-workflows.md` | Host and repository configuration journeys, TUI behavior, messages, and README examples. |
| `ROADMAP.md` | Planning ledger, dependency waves, gates, and future task board. |

## Out of scope

- Persistent workspaces for organization-scoped policies.
- Remote, UNC, NFS, SMB, cloud-synced, or object-storage workspace roots.
- Automatic migration, copying, or deletion of old workspace directories.
- Sharing a slot between concurrent attempts.
- Treating a persistent workspace as a security boundary for untrusted code.
- Implementing the change during the planning stage.
