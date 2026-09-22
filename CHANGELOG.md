# Changelog

What changed in each release, in the terms an operator upgrading would care
about. The published GitHub Release for a version carries the checksums, the
SBOM and the verification steps; this file carries what the version *does*.

Versions are `X.Y.Z` and are set by the release workflow, so the top entry names
the version being prepared rather than the version in `Cargo.toml`.

## 0.4.28

### Fixes

- A launch's timings now include how long it waited for the host allocation
  lock while another runner was being launched, and that wait counts toward the
  one-minute slow-launch warning. A launch that fails now logs
  `attempt_launch_failed` with the same step timings, including the step it
  failed in.
- The macOS package copy in `.runner-package/` is removed from a runner root the
  host no longer uses, such as after the host root override changes or a
  persistent repository is removed or moves its workspace.
- A job runs as the account that owns `.runner-package/`, so it could replace the
  runner binaries every later runner on the host was cloned from. The daemon
  now records a fingerprint of each copy it builds, from every file's inode,
  size, mode, owner and change time, and rebuilds a copy whose fingerprint has
  moved. A restarted daemon rebuilds each copy once before using it.

## 0.4.27

### Fixes

- A runner took minutes to come online when the runner root was on a different
  volume from the package cache and that disk was busy: every launch copied the
  whole runner package (about 9,000 files) byte for byte, while holding the
  host allocation lock that every other launch waits for. On one macOS host a
  queued job waited four minutes for that copy. On macOS the daemon now keeps
  one copy of the package in `.runner-package/` under the runner root and makes
  each runner an APFS clone of it, so a launch copies no package data after the
  first. On Linux the copy is a reflink where the filesystem supports one.
- Launch retries and step timings are logged. A retried package copy, JIT
  request or process start is a warning, and a launch that takes longer than a
  minute logs a warning naming how long the package copy, the JIT request and
  the process start each took.

## 0.4.26

### Fixes

- A Linux service installed by 0.4.15 or older kept its original systemd unit
  through every upgrade. That unit handed the daemon a copy of the credential
  frozen at service start (`LoadCredential=`) and no write access to the
  credential store, so the daemon could neither renew the token nor see one
  renewed by the TUI. Once the frozen token expired it stopped starting runners
  until someone restarted it. `service status` now reports an outdated unit, and
  a managed WSL host rewrites it and restarts the service automatically on
  `wsl install` and on each WSL start.
- A service whose credential GitHub rejects is no longer reported as healthy.
  The daemon records the rejection, and `service status`, `status --json`, the
  TUI readiness panel and the Windows TUI's WSL host rows show it with the
  `auth login` command that fixes it. A managed WSL host in this state shows as
  `signed out`.
- A WSL recovery watchdog that exited while recovering left its launch fence
  and drain request behind, and its successor never cleared them. A healthy
  distribution then stayed fenced and started no runner, logging only
  `allocation_lock_unavailable`. A watchdog that finds WSL healthy now retires
  recovery coordination that no live watchdog has refreshed for five minutes.

### Features

- The TUI header shows every service version it can see: the local service,
  each managed WSL host's service, and the app. A TUI started with
  `--host wsl:NAME` labels its service as that WSL host's.

## 0.4.25

### Fixes

- A TUI or CLI command that can read the machine-scoped credential but cannot
  write it, such as one run without `sudo` on a boot-mode macOS host, no longer
  renews the token. It used to spend the shared refresh token when the renewal
  window opened, fail to store the replacement, and leave the service with a
  pair GitHub had already retired, so the host stayed unauthorized until the
  next `auth login`. Such a process now leaves renewal to the service and picks
  up the renewed credential from the store.

## 0.4.24

### Features

- The TUI runner table now shows `Busy for` immediately after `Status`. Local
  runners use the journaled busy transition time; runners observed on another
  managed host are timed continuously from their first busy observation. The
  duration updates live, resets when work ends, remains sortable, and yields
  space before the repository, status, or runner identity on narrow terminals.

## 0.4.23

### Fixes

- Managed WSL hosts now have a per-user Windows recovery companion. The boot
  service keeps that companion running through Task Scheduler, while the
  companion holds the distribution open and can recover a wedged WSL transport
  in the Windows account that owns the distribution.
- Automatic WSL recovery now distinguishes busy work from stale active attempt
  records. It restarts only the affected distribution and only after a matching
  drain acknowledgement, two fresh idle guest heartbeats, two complete idle
  GitHub inventory reads, and checks for unmanaged runner services.
- Windows WSL transport failures are no longer reported as missing systemd.
  When a fresh guest heartbeat survives the control-path failure, the TUI shows
  the host as degraded instead of blocked and explains the guarded recovery.
- The TUI detects lifecycle tasks from older releases that have only the direct
  WSL keep-alive. It shows the exact convergent `wsl install` command that
  replaces them with the recovery companion.

## 0.4.22

### Fixes

- Windows startup recovery no longer stops the entire service when a late child
  process still holds an ephemeral runner workspace. The isolated cleanup is
  reported and retried on later passes while unrelated repositories continue
  receiving runners.
- Terminal and already-cleaned ephemeral attempts now use the same retry-safe
  handling for locked residue. Missing directories remain successful cleanup,
  persistent checkouts remain untouched, and journal or package-accounting
  failures still fail closed.

## 0.4.21

### Fixes

- A managed WSL host now gives its hardened systemd service write access to the
  exact Windows recovery-fence directory. Existing installations converge the
  drop-in in place, reload systemd, and restart only an active service, so an
  unwritable fence can no longer leave queued Linux jobs unserved indefinitely.
- Permanent allocation-fence contention and WSL heartbeat read/write failures
  now reach warning diagnostics with distinct reason codes instead of looking
  like a healthy but idle host.
- Ephemeral attempts marked `cleaned` now reap a workspace that a late child
  process recreates after the original cleanup. The retry does not replay the
  package lease release or mutate the completed journal record.

## 0.4.20

### Fixes

- A Windows boot service no longer mistakes user-owned WSL distributions for
  failed hosts when it runs as LocalSystem. On upgrade it retires only the
  obsolete Windows recovery request and fence, leaving guest launch ownership
  untouched, so healthy WSL runners are not blocked by false recovery state.
- Dashboard readiness problems now describe only the latest live probe. A
  resolved service or WSL problem cannot remain beside a `READY` verdict or be
  copied as a repair the operator no longer needs.
- Manual and automatic TUI refreshes now show a fixed-width animated activity
  track beside both refresh labels. Unsupported WSL information is rendered as
  muted context instead of an actionable accent.
- Lifecycle unit tests keep their runner root inside the test temporary
  directory, so a correctly secured production `C:\rman` cannot make the local
  workspace suite fail.

## 0.4.19

### Fixes

- Windows service removal now treats SCM error 1072 (already marked for
  deletion) as an in-progress successful uninstall and waits for the service
  name to be released, so `service uninstall && service install` is reliable.
- Unhealthy `wsl status` output and TUI readiness now show the direct,
  convergent `wsl install --distribution NAME` repair command and explain that
  an existing Linux service must not be uninstalled first.

## 0.4.18

### Fixes

- Stopped-service remediation in the TUI and `service status` now uses the
  supported, convergent `service install --start-at boot|login` command instead
  of suggesting the nonexistent `service start` subcommand.

## 0.4.17

### Fixes

- The release workflow now waits until npm can resolve all five platform
  packages before publishing the root wrapper. It then performs a clean install
  with optional dependencies enabled and executes the installed binary, so an
  npm package that is still being processed cannot leave a temporarily broken
  `runner-manager` command while the workflow reports success.

## 0.4.16

### Fixes

- The TUI now continuously reports operational readiness separately from
  GitHub inventory: stopped or missing services, legacy Windows tasks without
  the restart supervisor, service-manager/permission failures, login-only
  availability, and unhealthy managed WSL hosts appear in the header,
  Dashboard, and Activity view with copy-safe remediation commands. Wide
  Dashboards place concrete problems and fixes beside the workload summary;
  narrow terminals stack them, and `c` copies the fixes directly.
- The TUI now proactively renews GitHub credentials even when no service is
  installed and when the host has no policies. Credential rotation is guarded
  by an OS file lock, so a service and TUI sharing a store cannot replay the
  same one-time refresh token.
- Linux and WSL systemd services now receive narrowly scoped write access to
  the credential-store directory, allowing a successful refresh exchange to
  atomically persist the rotated pair under `ProtectSystem=strict`.
- Legacy Windows login tasks now migrate themselves to the windowless restart
  supervisor before the daemon starts, so an upgrade cannot exhaust Task
  Scheduler's finite retry count and leave the registered service stopped. If
  an elevated task's ACL prevents replacement, it bootstraps the same permanent
  supervisor directly without requiring administrator rights.
- `service status` now recognises Task Scheduler's omitted default
  `Enabled=true` value and reports a stopped login task as unhealthy.

## 0.4.15

### Reliability

- Linux and WSL ephemeral runner cleanup now unlinks .NET diagnostic FIFOs
  without opening them, preventing the reconcile loop from waiting forever for
  a nonexistent pipe peer after a runner exits.

## 0.4.14

### Reliability

- Windows login-mode service installation now starts the agent immediately
  through a windowless supervisor, restarts unexpected daemon failures with
  bounded backoff, and reloads planned policy changes without consuming the
  Task Scheduler retry budget.
- The Windows daemon can now self-heal a failed managed WSL2 distribution after
  a five-minute failure threshold, but only with a cross-boundary launch fence,
  an acknowledged idle drain, complete GitHub inventory, and no unmanaged
  runner service. Recovery targets one named distribution and is circuit-broken.
- The Windows TUI now distinguishes degraded, draining, recovering, backoff,
  and recovery-blocked WSL states.
- WSL lifecycle tasks now configure the guest heartbeat and shared launch
  fence required by safe recovery.

## 0.4.13

### Fixes

- WSL service and distribution startup failures during the root preflight are
  now reported as retryable provisioning failures instead of incorrectly
  claiming that the distribution cannot start as root.

## 0.4.12

### Quality and compatibility

- Added fail-closed accountability for every published CLI command leaf.
- Added deterministic local and mocked-WSL command-chain corpora with
  real-process execution, replayable case IDs, security and leak scans,
  mutation controls, and cross-track CI and release gates.
- Corrected the documented exact WSL replay command and hardened CI contract
  checks across Windows, macOS, and Linux.

## 0.4.11

### Features
- Added dynamic system metrics (local capacity, online runners, busy runners) to the terminal window title.
## 0.4.9

### Fixes

- Fixed an issue where `runner-manager update` did not correctly hand over the service upgrade to the WSL instance when invoked via proxy.
- Fixed caching logic bugs on Windows that led to frozen folders by using an improved directory removal algorithm to circumvent locks on read-only package manager files.

## 0.4.8

### Fixes

- Fixed a race condition where multiple concurrent processes (e.g., a background daemon and a foreground TUI) attempting to renew an expired token could trigger a replay attack block from GitHub.

## 0.4.7

### Performance

- The runner package materialization step now uses an optimized `cp -a` on Unix platforms (including WSL) instead of sequential file copying, reducing the runner startup delay from ~30 seconds to practically zero.

## 0.4.6

### TUI inventory and diagnostics improvements

- Managed runner names whose GitHub inventory omits the lifetime flag are now
  shown as ephemeral and managed by another host instead of persistent and
  external.
- Repository and runner selection now scrolls only at viewport edges, while
  Dashboard previews remain independent of full-screen selection, filtering,
  and scrolling.
- Repository and runner tables, including both Dashboard previews, can be
  sorted in either direction by clicking any visible column header.
- Repository and host settings use semantic colours, and Activity timestamps
  use a shorter UTC format.
- The header shows the current TUI and registered service-binary versions at
  the upper right and refreshes the service version with the local snapshot.
- Releases now publish the application and its four internal libraries to
  crates.io through short-lived OIDC credentials, making the documented
  `cargo install runner-manager` channel real.

## 0.4.5

### Resource Leak Fixes & CI Optimizations

- Fixed severe ephemeral workspace accumulation in the fallback `C:\rman` directory.
- Resolved a Windows process-tree zombie leak caused by race conditions during force termination.
- Optimized the CI build matrix using `cargo-nextest`, `rust-cache`, and `sccache`,
  while excluding Cargo's bin directory so cache cleanup cannot delete the
  `rustup` proxies from a persistent self-hosted runner.

## 0.4.4

### macOS runner-volume access guidance

- The Dashboard now highlights a macOS Full Disk Access denial for the
  boot-service runner volume and opens the relevant System Settings pane from
  the warning.

## 0.4.3

### Idle host upgrade fix

- A daemon whose policies are all disabled now watches its service source for
  upgrades, so Windows and WSL services hand over without a manual restart.

## 0.4.2

### Policy re-enable fix

- A fully drained and disabled scaling policy can now be enabled again through
  the normal `set-scale --enabled true` command.

## 0.4.1

### WSL adoption and policy recovery fixes

- An enabled but inactive systemd unit is now started when `wsl install`
  adopts it, so a convergent install cannot report success while leaving the
  Linux daemon stopped.
- A daemon now detects an already-newer source binary immediately at startup,
  allowing its service-owned copy to hand over even when the package was
  upgraded while the daemon was stopped.
- Repeating `set-scale --enabled false` after the last busy runner exits now
  completes `draining` to `disabled`; the policy can then be enabled normally.

## 0.4.0

### A WSL2 distribution can now be a second managed runner host (Windows)

One Windows workstation can serve Windows jobs and Linux jobs at the same time.
`runner-manager wsl install --distribution NAME` turns a WSL2 distribution you
already have into a fully managed host, and every command you already use
reaches it through the new global `--host wsl:NAME` selector.

New commands, all Windows:

- `runner-manager wsl list` names this machine's distributions and says which of
  them are managed.
- `runner-manager wsl install --distribution NAME [--capacity N]` provisions or
  converges one, in eight ordered stages.
- `runner-manager wsl status --distribution NAME [--json]` reports that host's
  real state, read from the distribution rather than from any local record.
- `runner-manager wsl detach --distribution NAME` stops managing it and deletes
  no Linux data.
- `--host local|wsl:NAME` is global. `local` is the default and every existing
  invocation means exactly what it meant before.

What this replaces: a hand-installed second binary, a hand-written systemd unit,
a hand-made Windows keep-alive task, and a credential moved between hosts by
hand. `README.md`'s "Run Linux jobs too" section is the whole procedure.

### Each host holds its own GitHub credential

`runner-manager --host wsl:NAME auth login` runs the browser sign-in on Windows,
where the browser is, and hands the credential it issues straight into the Linux
host's own machine store over an anonymous pipe. It is never written down on the
Windows side, and the Windows host's own credential is never read for transfer.

This is a correctness requirement rather than tidiness: GitHub invalidates both
halves of a token pair whenever either half is renewed, so two daemons sharing
one credential would take turns signing each other out. `wsl install` issues a
credential only when the distribution holds none of its own, so re-running it on
a working host never sends you back to a browser.

### Provisioning is convergent, and adoption is the same command

`wsl install` probes before it writes. An existing Linux runner-manager, its
credential, its policies, its runtime root and an already-enabled service unit
are adopted rather than replaced, and capacity changes only when you pass
`--capacity`. Every stage reports whether it changed anything, a preflight
failure changes nothing at all, and the documented remedy for any later failure
is to fix what the message names and run the command again.

### Availability is stated rather than implied

WSL distributions are registered per Windows user, so a managed Linux host is
available after that user logs on and not between a Windows reboot and the first
interactive logon. `wsl status` says so on every run.

### Docker is diagnosed, never installed

`wsl status` reports whether the distribution can run containers and says what
that means for your jobs. It is never a reason to refuse provisioning, and this
release installs no workload dependency on your behalf.

### `detach` is deliberately not `uninstall`

It removes this machine's lifecycle task and its record of the host. The
distribution stays registered with WSL, and its runner-manager, service,
credential, policies, workspaces and packages stay where they are. The command
prints the explicit Linux commands to run if you want to undo that half too.

### Unchanged

Every existing local command, file, service registration and `status --json`
document is unchanged. `--host local` is the default, so nothing you have
scripted needs editing.



