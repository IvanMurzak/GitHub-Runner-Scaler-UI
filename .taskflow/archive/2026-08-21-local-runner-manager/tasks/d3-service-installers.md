---
id: "d3-service-installers"
title: "Cross-platform service installation: Windows service, launchd, systemd, with absolute-path recording and stale-path detection"
group: "D"
sequence: 3
repo: "."
depends_on: ["d1-platform-core", "b2-sqlite-persistence"]
importance: 8
complexity: 7
security_critical: false
production_touching: true
model_hint: "top"
taskflow_refs: ["05-infrastructure.md", "08-user-workflows.md", "09-release-distribution.md", "06-migration-rollout.md"]
---

## Goal

Make the local controller survive a reboot with nobody logged in (D5, D13).
Journey 5 is the whole point of the product on a home host: the machine
reboots, and work resumes by itself.

## Scope & seams

Owns `crates/platform/src/service.rs` and the per-OS service definitions.
Registers `daemon run` for the current host; `f3` provides the command surface.
`--start-at boot` is the default; `--start-at login` remains available.

Requirements from `05-infrastructure.md`, each individually testable:

1. Refuse a second instance when the local lock (`d1`) is held.
2. Run under a least-privilege account that can read the secret store (`d2`)
   and write the configured cache and runtime directories — and no more.
3. Set a restart-on-failure policy with a bounded delay.
4. Preserve a local diagnostic log path and expose it through `service status`.
5. `service uninstall` removes the service and deletes **no** configuration,
   secret, or cache.
6. Resolve and record the **absolute** path of the running binary at install
   time, and report a stale or missing path through `service status`.
7. Expose the current start mode in `host show` and in TUI host settings, and
   allow switching between `boot` and `login` **without reinstalling**.

**Why requirement 6 is not housekeeping.** An `npm i -g` binary lives under the
active Node installation's global prefix, which moves when the operator
switches Node versions with a version manager. A recorded absolute path then
points at nothing, and the service fails to start after a toolchain change the
operator will not connect to this product. `service status` must call that out
as an **error**, not report health. The install script does not have this
failure mode, which is why `a3` lists it first.

**Scope note on waves.** All three installers are written here, in Wave 2,
because gate 3 requires verified boot-start recovery on Windows. macOS and
Linux installation and reboot recovery are validated in Wave 3 against this
same implementation; no second implementation task exists.

## Definition of Done

- `service install`, `uninstall`, and `status` work on Windows (service), macOS
  (launchd), and Linux (systemd), verified by privileged installer smoke tests
  on native CI runners.
- After a real reboot with **no interactive login**, the agent is running and
  has read its token from the machine-scoped store.
- `service status` reports the start mode, the resolved absolute binary path,
  the diagnostic log path, and the last successful GitHub contact.
- A binary moved or deleted after install makes `service status` report a stale
  path as an error; the npm-upgrade case is exercised explicitly by moving the
  binary out from under a recorded path.
- Installing while the single-instance lock is held is refused with an
  actionable message.
- A killed service restarts under the failure policy within the bounded delay,
  and does not restart-loop faster than that bound.
- `uninstall` leaves configuration, SQLite, secrets, and cache intact, asserted
  by comparing before and after.
- Switching between `boot` and `login` takes effect without a reinstall, and
  the reported start mode changes accordingly.
- The service account's permissions are documented in the repository and
  verified least privilege by an explicit check.
