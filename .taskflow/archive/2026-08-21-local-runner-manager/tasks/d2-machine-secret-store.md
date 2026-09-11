---
id: "d2-machine-secret-store"
title: "Machine-scoped secret store for the user access token, with a user-scoped variant for --start-at login"
group: "D"
sequence: 2
repo: "."
depends_on: ["d1-platform-core"]
importance: 10
complexity: 7
security_critical: true
production_touching: false
model_hint: "top"
taskflow_refs: ["05-infrastructure.md", "07-security.md", "02-target-architecture.md"]
---

## Goal

Store the one persisted GitHub credential this product has, in a place a
**boot-time** service can read (D13). This constraint is the whole reason the
task exists: a service that starts at machine boot runs outside any user's
login session, so macOS LaunchAgents and per-user Windows Credential Manager
vaults are unavailable to it.

## Scope & seams

Owns `crates/platform/src/secrets.rs`. One trait, three implementations, plus a
user-scoped variant:

| OS | Machine-scoped store |
|---|---|
| Windows | DPAPI **machine** scope |
| macOS | System Keychain |
| Linux | `0600` file plus systemd credentials |

Operations: store, load, delete. `auth logout` purges locally; uninstalling the
App at GitHub is the authoritative revocation and is not this layer's job.

**The user-scoped variant is not optional.** `service install --start-at login`
exists precisely for operators who reject machine-scoped storage
(`07-security.md`), and in that mode the token lives in the per-user store and
the agent does not run until the operator logs in. Both variants implement the
same trait, and the active one is a recorded, inspectable choice — `host show`
and `service status` report which is in use.

**The accepted trade-off, implemented honestly.** A local administrator or root
on this machine can read a machine-scoped secret. The threat model already
assumes a hostile *workflow* can run on this host; it does not assume a hostile
local administrator, because such an account can already read the runner's own
credentials and job workspaces. Do not attempt to defeat that; do ACL the
stored value to the service account so it is not readable by an ordinary local
user.

The token never appears in SQLite, configuration, logs, diagnostics, UI state,
or a command-line argument. `client_id` is public by design and is not a secret
this store handles.

## Definition of Done

- Store, load, and delete round-trip on Windows, macOS, and Linux in native CI,
  for both the machine-scoped and the user-scoped variant.
- A stored value is readable by the service account and **not** readable by an
  unprivileged local user, asserted per OS.
- On Linux, the file mode is verified as `0600` and the systemd-credentials
  path is exercised.
- Delete leaves no recoverable remnant, and a load after delete reports absence
  rather than an error that a caller might mistake for a transient failure.
- The active store variant is reported and matches the configured start mode.
- A machine-scoped value written before a simulated reboot is readable by a
  process running with no interactive login session.
- A repository-wide scan of fixtures, databases, logs, and snapshots after a
  full store-and-load cycle finds no token-shaped value outside the store.
