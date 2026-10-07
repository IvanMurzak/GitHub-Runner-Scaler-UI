# Changelog

What changed in each release, in the terms an operator upgrading would care
about. The published GitHub Release for a version carries the checksums, the
SBOM and the verification steps; this file carries what the version *does*.

Versions are `X.Y.Z` and are set by the release workflow, so the top entry names
the version being prepared rather than the version in `Cargo.toml`.

## 0.4.35

### Fixes

- Updating a managed WSL host no longer needs administrator rights. `wsl install` from an
  ordinary prompt used to drain the Linux service, swap its binary and restart it, and then exit
  24 with `cannot register the scheduled task runner-manager-wsl-… without elevation: Access is
  denied`, leaving the Windows lifecycle task on the previous companion and the Windows-side
  record on the previous version. The task named its Windows companion by version
  (`runner-manager-wsl-0.4.34.exe`), so every update was a new task definition, and replacing a
  task that an elevated prompt created is refused to an ordinary token. The companion now lives
  at version-independent paths (`state/bin/runner-manager-wsl.exe` and
  `runner-manager-wsl-supervisor.exe`) that an update swaps in place, `wsl install` leaves the
  task alone when it is already the one it would write, and a running companion notices the new
  file and restarts onto it by itself (its guest holder is replaced within seconds; the Linux
  service is not touched).
- The first `wsl install` after upgrading from 0.4.34 or earlier moves the task to the new
  paths once. If Windows refuses that without administrator rights, `wsl install` asks for them
  with one administrator prompt, the same one `host prepare` uses, and restarts the running
  companion onto the new task. Where no prompt can be shown (a script, an SSH session), it says
  the change is needed once and prints the exact command to run from an elevated prompt.
  Registering a distribution's task for the first time works the same way. The versioned
  companion copies are removed once nothing runs them.
- `runner-manager update` names every managed WSL host that runs an older version, with the
  `wsl install --distribution NAME` command that updates it. It does not run that command
  itself: updating a WSL host drains that host's jobs with no deadline, and `update` returns as
  soon as this machine's own binary is replaced.
- `host cache prune` works from an ordinary prompt on a host whose service runs as another
  account (LocalSystem on Windows, root elsewhere). It used to fail with `cannot write
  …\_cache\.usage.json: Access is denied`; it now asks the service installed from this account's
  directories to prune, waits for its answer and prints it. The service takes the request within
  five seconds even while a scheduled pass is running. When no service takes it, or the service
  cannot prune either, the command says so at once and names the remedy.

## 0.4.34

### Features

- Native runners keep their dependency and tool caches between jobs, on Windows, macOS, Linux
  and managed WSL hosts, with nothing to configure per machine. Each runner starts with
  variables such as `npm_config_cache`, the pnpm store (`npm_config_store_dir`,
  `PNPM_CONFIG_STORE_DIR`), `YARN_GLOBAL_FOLDER`, `BUN_INSTALL_CACHE_DIR`, `NUGET_PACKAGES`,
  `PIP_CACHE_DIR`, `UV_CACHE_DIR`, `GOMODCACHE`/`GOCACHE`, `ELECTRON_BUILDER_CACHE`,
  `PLAYWRIGHT_BROWSERS_PATH` and, on macOS and Linux, `XDG_CACHE_HOME`, pointing under
  `<runner root>/_cache`. `RUNNER_TOOL_CACHE` and `AGENT_TOOLSDIRECTORY` keep the toolchains
  `setup-node`, `setup-go` and `setup-java` download, and `DOTNET_INSTALL_DIR` the SDKs
  `setup-dotnet` installs. pnpm finds its store and `actions/cache` paths stop changing every
  job. `CARGO_HOME`, `GRADLE_USER_HOME`, Maven, Poetry, pub and Bundler are opt-in, because those
  directories hold more than a cache. `host cache show` lists every variable.
- Each repository has its own cache namespace, so one repository's jobs cannot plant packages
  another's install. Organization policies have none until `org cache set-enabled ORG --enabled
  true`, and two repositories share one only when both are given the same name with
  `repo cache set-namespace OWNER/REPO --shared NAME`. Caches that are not safe for concurrent
  writers (the Actions tool cache, `setup-dotnet`, Cypress, Poetry, Maven) are kept per
  concurrent runner.
- The service keeps the caches under a cap, 20 GiB by default, by removing the least recently
  used namespaces that no runner is using, every 30 minutes. `host cache prune` does it now,
  `host cache set-max-size N` changes the cap, and `status`, `status --json` (a new `caches`
  block) and `host show` report the size.
- `host cache`, `repo cache` and `org cache` turn caches or single tools on and off and move the
  root (`host cache set-root --path PATH`, checked like a runner root, so network shares and WSL
  `/mnt/c` paths are refused). A cache root outside the runner roots gets the same `host doctor`
  checks, and `host prepare` excludes it from Defender with them.

### Fixes

- macOS login-mode hosts keep their GitHub credential across `runner-manager update`. The login
  keychain ties an item to the exact build that wrote it: an ad-hoc signed binary is known by the
  hash of its code, so every release was a stranger to the item the previous one wrote, the new
  daemon failed with `-25293` on every start, and somebody had to run `auth login` at the Mac.
  Granting the item to every application does not help there; measured on macOS 27, the login
  keychain refuses another build regardless. Now the old daemon, which can still read the
  credential, hands it to the new binary just before it restarts, and the new binary writes it
  again as its own. **The first update to this version still needs one sign-in**, because the
  version doing that update is the old one: after it, run
  `runner-manager auth login --start-at login` in a Terminal in the Mac's desktop session. Updates
  after that need none.
- `service status` and the TUI report a daemon that cannot read its stored credential, with the
  exact `auth login` command, instead of `healthy`. The daemon records the failure when it starts
  and clears it as soon as a read succeeds.
- `host doctor`'s `macos.keychain_credential` check passes after an update once the credential
  has been handed over. When it still fails, it says why (an item written by a build that did not
  hand it over) and that the sign-in has to happen in a Terminal on the Mac, not over SSH.
- `host doctor` no longer passes the keychain check on the strength of the previous binary: right
  after an update the last GitHub contact was the old daemon's, made during its drain, so the
  check said "reached GitHub 0 minute(s) ago" while every start of the new daemon failed with
  `-25293`. A contact now counts only if it is newer than the service binary, and the daemon's own
  record that it cannot read its credential fails the check outright. `macos.launchd_priority`
  no longer says the service runs at normal priority while it is not running.
- The macOS keychain error says which of three things happened: the System Keychain read by an
  account that is not root, a login keychain locked for this session (an SSH session cannot use
  the desktop session's unlocked login keychain, so even a healthy credential reads `-25293` there),
  or an item written by a different build. It no longer claims that signing in once survives
  upgrades.

### Operator notes

- A cache any of whose variables is already set in `runner.env` or in the service's own
  environment (a systemd drop-in, the launchd plist, a machine-wide Windows variable), in any
  letter case, is left entirely to that setting, so hosts that set cache locations by hand keep
  them; remove those settings to use the new layout.
- A `caches.toml` that does not parse stops native launches, before anything is registered with
  GitHub, like a broken `runner.env`: it may hold a decision to turn a repository's caches off.
  Any other cache problem starts the runner without caches and is logged.
- Isolated runners get no caches; their providers mount no host directory.
- npm 12 prints `Unknown env config "store-dir"`, caused by the pnpm 9/10 variable. Turn `pnpm`
  off for a repository that does not use it to silence it.
- `setup-python` on macOS ignores the tool cache and installs under
  `/Users/runner/hostedtoolcache`.

## 0.4.33

### Features

- `runner-manager host doctor` checks whether this machine is ready to run jobs, without
  changing anything or needing administrator rights: on Windows the runner account's
  symbolic-link privilege, `LongPathsEnabled`, git's system `core.longpaths`, Defender real-time
  scanning of the runner roots, whether the service runs unattended as LocalSystem, the Windows
  PowerShell execution policy and PowerShell 7; on macOS a `Background` LaunchAgent or throttled
  runners, Spotlight indexing the runner root, and whether the service binary can still read its
  keychain credential; everywhere a runner root that does not answer within 5 seconds (a hung
  external disk or network mount), a capacity larger than memory and cores allow, and any tools
  named with `host required-tools`. `--json` prints a versioned document. It exits with the new
  code 25 (`host_unfit`) when a required check fails.
- `runner-manager host prepare` fixes what the doctor found. It asks before changing anything
  (`--yes` skips the question; `--only CHECK` narrows it), and asks for administrator rights once,
  for every fix that needs them: a UAC prompt on Windows, the system password dialog or `sudo` on
  macOS. A refused prompt is reported and the rest carries on. Excluding the runner roots from
  Defender and turning on Developer Mode lower security and are never applied by `--yes` alone:
  they need `--allow-av-exclusion` or `--allow-developer-mode`, or a yes to their own question.
  Each change is recorded with the value it replaced, and `host prepare --revert CHECK` restores
  it.
- `service install` reports the checks for the account the service will run as and, on a
  terminal, offers to fix them first. `status` and `service status` show a one-line summary
  (`status --json` gains a `doctor` block). The dashboard lists failing checks in its readiness
  panel, and `f` fixes them.

### Operator notes

- The service now starts no runner while a **required** check fails. It logs `host_unfit`, every
  launch is refused with reason `host_unfit` before anything is registered with GitHub, and
  `status` shows since when and why. It re-checks every five minutes. On Windows a service
  installed with `--start-at login` runs with a standard token and cannot create symbolic links
  unless Developer Mode is on, so such a host stops starting runners after this update until you
  run `runner-manager host prepare --allow-developer-mode` or reinstall the service with
  `--start-at boot`. A check that cannot be evaluated never holds runners back.

## 0.4.32

### Fixes

- macOS runners now really run at normal priority. The 0.4.31 fix did not work: launchd applies
  the LaunchAgent's `ProcessType = Background` to every process the daemon starts, and a runner
  cannot leave it, so runners stayed at priority 4 on efficiency cores. The daemon's own warning
  (`runner_started_at_background_priority`) reported it. The plist now says
  `ProcessType = Interactive`, the value GitHub's own runner service uses, and a runner starts
  at priority 31, the same as a classic runner. The daemon runs at that priority too; it mostly
  waits.
- An existing installation is repaired without `service install`. After `runner-manager update`,
  the new daemon finds the old `ProcessType` in its plist, rewrites the plist and has launchd load
  the job again. It does this only when it starts with no runner, which is always the case right
  after the upgrade drain, so no job is interrupted. The start mode is kept. `service status`
  reports a plist that still carries the old value, with the command that restarts the service so
  it repairs itself. A plist that has the right `ProcessType` is left alone, including any edits
  made to it; one with the old value is replaced whole, as `service install` would replace it.

## 0.4.31

### Features

- `runner-manager host env set NAME=VALUE`, `host env unset NAME` and `host env show` manage
  `runner.env` in the configuration directory: variables every native runner on the host starts
  with, such as cache locations. They reach the next runner without a restart. `host show`
  names the file and how many variables it sets. `TMPDIR`, `TEMP`, `TMP` and
  `ACTIONS_RUNNER_INPUT_*` cannot be set, and errors never print a value. A `runner.env` that
  does not parse stops native launches until it is fixed, before any runner is registered with
  GitHub, rather than starting runners without it.

### Fixes

- macOS runners no longer inherit the service's background priority. The LaunchAgent runs the
  daemon as a background process, and every runner it started ran on efficiency cores with
  throttled I/O, 4 to 20 times slower than a classic runner. The daemon stays in the background;
  each runner leaves it as it starts, and a warning is logged if that ever fails.
- macOS runners find Homebrew tools: `/opt/homebrew/bin`, `/opt/homebrew/sbin` and
  `/usr/local/bin` go ahead of the service's minimal `PATH` when they exist, and `LANG` defaults
  to `en_US.UTF-8` when the service has none. Without `zstd` on the path `actions/cache` fell back
  to gzip and never hit. `runner.env` overrides either.
- Windows runners get a profile of their own (`USERPROFILE`, `HOME`, `APPDATA`,
  `LOCALAPPDATA`) inside the attempt directory instead of sharing the service account's, where
  concurrent jobs collided on `~/.bun`, the npm cache and the pnpm store. Caches under that
  profile start empty for every job; share one deliberately with `runner.env`. .NET known-folder
  APIs still report the service account's profile.
- Windows attempt workspaces holding a junction that denies listing to everyone, such as the
  `INetCache\Content.IE5` junction WinINet creates, are now removed. Cleanup unlinks every
  junction and symbolic link before removing the tree.
- A cleanup that keeps failing is retried with per-attempt backoff, from 30 seconds up to 30
  minutes, instead of on every poll, both by the reconciler and by runner supervision, and is
  logged once per retry instead of twice. Its warning names the reason
  (`ephemeral_workspace_could_not_be_removed`) rather than `other`.
- The log no longer redacts `kind`, `delay_secs` and `remaining` on rate-limit warnings, or long
  `snake_case` reasons such as `late_ephemeral_workspace_could_not_be_removed`.

## 0.4.30

### Features

- `runner-manager update --force` can reconcile a running service installed
  from a different source binary. It keeps a recoverable backup of that source,
  then lets the existing daemon finish every running job before switching its
  private binary; the command does not forcibly stop the service or cancel a job.
  `update --check --force` previews the action without changing files.

### Operator notes

- On macOS a new binary may need a fresh login-Keychain grant. The command
  warns about this and prints the exact `auth login` command for the service
  binary and existing data directory. Wait until `service status` reports the
  new version before signing in again. Authentication does not remove runner
  profiles, settings or the database.

## 0.4.29

### Features

- Named runner profiles can route different jobs from one repository to native
  or isolated execution. The CLI and TUI expose profile, capacity, workspace,
  backend and readiness controls; provider failure never falls back to native.
- Linux and managed WSL support rootless OCI isolation with pinned images and
  fail-closed resource limits. Windows has a Hyper-V-isolated backend, still
  preview-held where its native host acceptance is outstanding. The macOS VM
  backend is **not** part of this release.

### Fixes

- Upgrading from 0.4.28 migrates the local database from schema 3 to schema 5,
  preserving existing runner policies as native default profiles. Older binaries
  cannot read the upgraded database; keep a recoverable backup before upgrading.
- Cleaned native attempt history with a legacy process identity is readable
  without rewriting its journal or relaxing checks on active attempts.
- Runner profiles accept jobs requiring a case-insensitive subset of their labels,
  including jobs that omit the immutable selector. Extra profile labels are allowed.
  Jobs matching multiple local profiles are visibly refused, including overlaps with
  inactive isolated profiles, rather than scaling twice or falling back to native execution.

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
- A job runs as the account that owns the runner package cache under `state/`
  and the macOS copy in `.runner-package/`, so it could replace the runner
  binaries every later runner on the host was copied from. The daemon now
  records a fingerprint of each package tree it installs or builds, from every
  file's inode, size, mode, owner and change time, and uses a tree only while
  its fingerprint still matches. A cache entry it did not install in this run,
  or one that has changed, is downloaded again and verified against GitHub's
  published checksum, so a restarted daemon downloads the runner package once
  before its first launch. Not on Windows.

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
- Managed WSL isolated runners can use an operator-provisioned, root-owned OCI
  storage helper backed by finite Linux filesystems. The provider requires the
  helper's bounded-store attestation and keeps returning
  `DiskQuotaUnavailable` for ordinary rootless Podman storage that cannot
  enforce the requested disk cap. The same helper and its provider resources
  now have a terminate/restart acceptance that verifies generation-fenced
  adoption, cleanup accounting, and no duplicate JIT registration.

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
