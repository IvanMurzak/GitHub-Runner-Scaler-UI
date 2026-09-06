# Target architecture

## Public surface

Windows builds add:

```text
runner-manager wsl list
runner-manager wsl install --distribution NAME [--capacity N]
runner-manager wsl status --distribution NAME [--json]
runner-manager wsl detach --distribution NAME
runner-manager --host wsl:NAME <existing command ...>
```

`--host local` is the default and preserves every existing invocation. On a
non-Windows build, `wsl` and `--host wsl:...` fail with an actionable
unsupported-platform error rather than disappearing from help.

`wsl install` performs a convergent transaction:

1. Validate that `NAME` is installed as WSL2, starts as root, and runs systemd.
2. Resolve and verify the Linux release artifact whose semantic version exactly
   matches the controlling Windows binary and whose architecture matches the
   distribution.
3. Install/upgrade `/usr/local/bin/runner-manager` atomically.
4. Preserve an existing Linux credential. If absent, run a new Windows-side
   GitHub device flow and stream the stored credential document to the Linux
   binary's private receive command.
5. Set capacity only when `--capacity` was supplied; otherwise preserve the
   existing value or use the product default on a clean host.
6. Run the existing Linux `service install --start-at boot`.
7. Register a product-owned, per-distribution Windows login task that launches
   WSL and keeps it alive. Re-running updates that task in place.
8. Read back Linux auth, service and host status. Success means all three are
   healthy; partial work is reported precisely and remains safe to rerun.

Existing commands addressed through `--host wsl:NAME` are proxied to the exact
Linux binary with inherited stdin/stdout/stderr and the original arguments.
`auth login` is the one deliberate exception: Windows owns the interactive
device flow and uses the private credential handoff, because that is both more
reliable for browser interaction and the only design that can guarantee a new,
independent token pair without a staging store.

## Components

### Platform WSL adapter

A Windows implementation behind testable command-executor and task-control
traits owns:

- UTF-16-safe parsing of `wsl.exe --list --verbose` output;
- exact distribution-name validation and argument-vector invocation (never a
  shell-built command);
- WSL version, architecture, root and systemd probes;
- bounded child execution with stdin piping and exit/status capture;
- deterministic scheduled-task XML, identity and status;
- atomic Linux artifact copy/install through a root-owned staging file.

No PowerShell script, registry mutation, `.wslconfig` rewrite or distribution
installation is hidden behind this adapter.

### Credential broker

Refactor authentication into `acquire_user_credential`, which returns a
`UserAccessToken` without persisting it. Local login calls it and stores as now.
WSL login sends `to_stored_document()` through an anonymous stdin pipe to:

```text
runner-manager auth receive --start-at boot
```

`receive` is hidden from ordinary help, is accepted only on stdin, imposes a
small bounded document size, parses the existing credential envelope, stores it
through `PlatformSecretStore`, and emits no secret. It rejects terminal stdin
to prevent accidental paste workflows and exists solely as the cross-process
platform bridge.

### Provider record

The Windows config directory contains one non-secret record per managed WSL
distribution: schema version, exact distribution name, task identity, installed
runner-manager version and last verified time. Credential material, GitHub JIT
configuration and repository policies are never mirrored into this record.

The record is advisory: status verifies actual WSL/service state and reports
drift. A missing record never licenses deletion inside a distribution.

### Lifecycle task

The Windows task is named from a stable escaped distribution identity and runs
at user logon with least privilege. WSL distributions are registered per user,
so this feature promises unattended Linux availability after that user's logon,
not before any interactive logon after a Windows reboot. Status states that
constraint explicitly.

The task executes `wsl.exe` with an argument vector equivalent to:

```text
--distribution NAME --user root --exec /usr/local/bin/runner-manager wsl-host hold
```

`wsl-host hold` is a hidden Linux-only command. It verifies systemd, starts the
existing unit by argument-vector process execution, and then remains alive with
signal-aware shutdown so WSL does not retire the distribution. No shell text is
constructed. Only the product-owned task is updated or removed. The Linux
systemd service remains the daemon authority and restart supervisor.

## Compatibility

- Existing local CLI, files, service registrations and status JSON are unchanged.
- Existing WSL data, policies, runtime roots and credentials are adopted.
- Multiple named WSL2 distributions are supported independently.
- WSL1, missing systemd, unsupported Linux architecture and absent root access
  are explicit preflight failures with no credential issued.
- `wsl detach` removes only the Windows lifecycle task and provider record;
  it does not unregister WSL, uninstall the Linux service, or delete Linux data.

## Release and migration

Each implementation task uses an isolated worktree under the pipeline CLI's
external worktree root; the shared checkout remains the scheduler/release
checkout. The source change lands on `main`; the existing release workflow publishes
`0.4.0`. On IvanPC, install the Windows `0.4.0` artifact, run managed adoption
for `Ubuntu` with capacity 8, verify both Windows and Linux managers plus a live
Linux job, then remove the legacy hand-created keep-alive task. No credential is
rotated merely to adopt a healthy existing Linux store.
