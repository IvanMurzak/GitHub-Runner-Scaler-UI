# Current architecture

## Windows login service

- `service install` copies the package-owned executable into the application
  state directory and registers it (`crates/app/src/cli/service.rs:216-286`).
  It persists the selected mode and prints the registration, but there is no
  post-registration `start` call (`crates/app/src/cli/service.rs:287-335`).
- The login registration is an `InteractiveToken` task at `LeastPrivilege`
  (`crates/platform/src/service.rs:1804-1805`). This is the correct identity:
  it can read the user-scoped DPAPI credential and matches the WSL owner.
- The rendered task explicitly sets `<Hidden>false</Hidden>` and invokes the
  console application directly (`crates/platform/src/service.rs:1824-1839`).
- The task asks Task Scheduler for five one-minute restart attempts. The
  platform abstraction already exposes `start` (`crates/platform/src/service.rs:8622`),
  but install does not use it.

## Daemon hand-off

- The daemon captures the initial served-target set and watches it beside the
  runner loops (`crates/app/src/cli/daemon.rs:280-324`).
- When that set changes it drains every loop, then returns the same
  `UpgradePending` failure used for binary replacement
  (`crates/app/src/cli/daemon.rs:332-355`, `479-505`).
- Binary replacement safely renames the running image aside and copies the
  package source into its place (`crates/app/src/cli/daemon.rs:607-625`).
- There is no persistent parent process between Task Scheduler and `daemon
  run`; therefore every planned reload is externally indistinguishable from a
  failed task and consumes service-manager restart policy.

## Service status

- `ServiceStatus::is_running` reads the actual registration state
  (`crates/platform/src/service.rs:4527-4532`).
- `ServiceStatus::is_healthy` independently tests only that `problems` is empty
  (`crates/platform/src/service.rs:4534-4540`). A login registration that is
  stopped is currently a note, so output can say both `state not running` and
  `verdict healthy`.
- The durable GitHub contact timestamp already exists and is printed; it can
  support a stale-daemon distinction without adding a secret or network call.

## Managed WSL

- A provider record stores non-secret distribution/task/version metadata and
  is advisory (`crates/platform/src/wsl/record.rs:59-177`).
- The lifecycle task executes `wsl.exe --distribution NAME --user root --exec
  ... wsl-host hold` directly (`crates/platform/src/wsl/task.rs:196-216`).
- `wsl-host hold` starts the systemd unit and waits inside Linux
  (`crates/app/src/cli/wsl.rs:2773-2972`). Once the Windows-to-Linux session is
  wedged, the task remains `Running` and has no observer outside that session.
- WSL command requests already carry a timeout and cancellation token
  (`crates/platform/src/wsl/exec.rs:248-348`, `614-761`), so bounded health
  probes have an existing primitive.
- `wsl status` already produces a rich `WslStatusDocument` with readiness,
  binary, credential, systemd, task, diagnostics and drift
  (`crates/app/src/cli/wsl.rs:871-1003`, `1141-1245`). It lacks supervisor,
  heartbeat, recovery and safety state.

## TUI

- The TUI reads a local status document every sixty seconds and separately
  refreshes GitHub inventory (`crates/app/src/tui/shell.rs:50`, `198-279`,
  `456-618`).
- Rendering receives an immutable `Snapshot`, keeping filesystem/process
  access outside frame rendering (`crates/app/src/tui/shell.rs:148-193`).
- `Snapshot` currently holds metrics, repositories, runners and activity only
  (`crates/app/src/tui/screens.rs:246-265`). This is the seam for a typed WSL
  summary without teaching rendering to invoke WSL.

## Incident evidence

On 2026-09-11 the Windows task was `Ready`, last result `0x15`, with no GitHub
contact after 2026-09-10. Reinstall updated the service copy from 0.4.8 to
0.4.13 but left the newly registered task unstarted (`0x41303`) until an
explicit `Start-ScheduledTask`. That launch opened a console window because
the task is interactive and not hidden.

The Ubuntu task stayed `Running`, while `wsl status` returned
`Wsl/Service/0x8007274c`. The distribution kernel reported VMBus/vsock accept
timeouts and high-order allocation failure. This is exactly the split a
Windows-side supervisor must observe: task liveness did not imply WSL
reachability.

