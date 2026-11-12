# Changelog

What changed in each release, in the terms an operator upgrading would care
about. The published GitHub Release for a version carries the checksums, the
SBOM and the verification steps; this file carries what the version *does*.

Versions are `X.Y.Z` and are set by the release workflow, so the top entry names
the version being prepared rather than the version in `Cargo.toml`.

## 0.4.67

### Fixed

- A Linux service updates itself. Its sandbox keeps the binary it was installed
  from read-only to it, so the daily update and the one the coordinator starts
  failed with "Read-only file system" after downloading the release; now a
  transient systemd unit copies the verified binary into place. A host on an
  older release has to be updated once by hand (`sudo runner-manager update`).
- A macOS service installed through npm or Homebrew updates itself. launchd
  gives it a `PATH` without `/opt/homebrew/bin`, so the update failed with "npm
  is not on this PATH"; the package manager is now also looked for beside the
  copy it installed, and runs with that directory on `PATH`. A host on an older
  release has to be updated once by hand (`runner-manager update`).

## 0.4.66

### Added

- The coordinator's dashboard keeps its Queue, Running and Recent lists across a
  restart (every coordinator update is one): they are saved every minute and at
  shutdown, and restored at start. A restored queued job the sweep no longer
  lists, and a running job whose runner its machine no longer lists, are dropped,
  so jobs that ended during the restart do not linger.
- A machine lists its runners in every heartbeat, from the moment each starts.
  The Running and Recent lists name the machine as soon as a job starts; before,
  a job showed no machine until the machine noticed it, and a short job often never got
  a machine.
- A machine reports its disk's size: the card shows the disk as used / total with
  a meter, where it showed only the free space.
- The machine card's history shows memory beside CPU.

### Changed

- Activity charts read better on wide ranges: points are averaged into fewer,
  period-aligned groups; jobs and busy slots are stacked columns, CPU is a row per
  machine with its average and peak, memory a smoothed line per machine.
- The summary tiles show jobs as running / queued in one tile.
- Meters turn yellow from 50%, orange from 75% and red from 90%.
- A Windows machine's card shows the version its WSL host actually runs, not
  what `wsl install` last installed there (stale once the distribution updated
  itself).

## 0.4.65

### Added

- A job can keep off machines carrying a label: `runs-on: [self-hosted,
  linux, x64, not-wsl]`. GitHub matches labels positively only, so
  runner-manager reads `not-<label>` as "the machine must not carry
  `<label>`", on the host's own demand and in the coordinator's placement
  alike: a profile carrying `<label>` never serves the job, and the runner
  started for it registers with `not-<label>` so GitHub hands it the job.
  A job without a `not-` label is matched exactly as before, except that a
  profile label already starting with `not-` is now read as an exclusion.
- Every runner of a machine running inside WSL now carries the label `wsl`,
  and every runner of any other machine `not-wsl`, without configuration.
  `runs-on: [.., not-wsl]` keeps jobs whose wall-clock time matters off WSL
  machines. `status` lists them as derived labels, and the coordinator's
  dashboard marks exclusions among a job's or a profile's labels. A profile
  inside WSL that was told apart from a sibling only by a hand-added `wsl`
  label now overlaps it: remove one of them.
- A job asking for a label and for `not-` that label, or for `not-` alone,
  is never counted as demand, and the host (`routing_refused`,
  `unsatisfiable_exclusion`) and the coordinator say so in their logs.
  `add-label` refuses a label that contradicts one the profile carries.
- Coordinator protocol: a host says it understands exclusions
  (`hello.label_exclusions`); a `launch` names its job's `exclusions`; a host
  refuses one its profile cannot honour with `excluded`. A coordinator places
  a pool job naming an exclusion only on such a host, so upgrade the hosts
  and the coordinator before writing `not-` labels into pool jobs (`not-wsl`
  works with an older coordinator too).

## 0.4.64

### Added

- The dashboard shows each machine's runner-manager builds: the one its
  service runs and the installed app it upgrades from (npm, Homebrew, the
  release archive, `cargo install`), with a note when a newer release is
  out or the service is waiting for its jobs to restart into a newer app.
  A WSL distribution is marked WSL, and a Windows machine lists the version
  it last installed in each WSL distribution it manages. Hosts report this
  in their heartbeat from this version on.
- **Update** in a machine's panel updates its runner-manager through the
  coordinator, on a host that allowed changes there (`coordinator
  remote-changes allow`, which from this version covers this update too).
  The host answers at once and does what its daily automatic update does:
  it installs the newest published release through the channel that
  installed the app, and the service restarts into it once its running jobs
  finish. The panel shows how it went. The coordinator names no version and
  no source. A host with automatic updates off (`host set-auto-update
  false`) refuses it. `runner-manager --host remote:NAME update` does the
  same.

### Fixed

- A service whose recorded source is a checkout's `target/release` path
  holding a release binary that `update --force` put there was never updated
  by the daily automatic update. It now is, like a release archive; any
  other build in a checkout is still left alone.
- A service running as root no longer updates, daily or from the
  coordinator, an app another account owns (a Homebrew prefix, an nvm npm):
  root left files there that account could no longer replace, and Homebrew
  refuses to run as root.

## 0.4.63

### Fixed

- A Mac reported less free memory than it had, to the coordinator and to
  its own memory admission: free plus inactive pages counted inactive app
  memory, which only compression frees, and left out the active file
  cache, which macOS drops on demand. Reading 8.3 GB of files on a 24 GiB
  Mac mini made it report 1.6 GB less free while what it could hand out
  grew by 2 GB. A Mac now reports free, file-backed and purgeable pages:
  what Activity Monitor does not count as used. Like Linux's
  `MemAvailable` it counts the file cache, but holds none of it back; the
  admission and placement margins are that reserve.

## 0.4.62

### Fixed

- A `container:` job on a Linux boot service whose steps run as the image's
  own user (`runuser -u ci`, `USER` in the image) could not run a toolchain
  it installed with `setup-node`, `setup-go` or `setup-java`: `env: 'node':
  Permission denied`. Since 0.4.57 the default ACL on shared cache
  directories gave every account outside the `rm-runner` group nothing, so a
  folder created under `/__t` was `2770`, and the image's user is outside the
  group. Shared caches now let any account read and run what is in them, as a
  umask of `022` did before 0.4.57; only the pool's group may write. A cache
  shared by 0.4.57 to 0.4.61 is opened up at the next launch that uses it.

## 0.4.61

### Added

- Remote management through the coordinator (protocol version 5). A person
  signed in to the coordinator's dashboard can read a host's repositories,
  profiles and limits, and change them on a host whose operator allowed it
  there with `runner-manager coordinator remote-changes allow`. Reads are
  always answered; changes are off until allowed. A host runs only
  repository and capacity commands, never one that signs in, installs,
  updates or removes the service. Every command is recorded on both sides:
  in the coordinator's database (`GET /api/audit`) and in the host's
  `state/remote-commands.jsonl`.
- `runner-manager coordinator login [--url URL]` signs the CLI in to a
  coordinator with GitHub: it prints a link and a code, the person approves
  the code in a browser signed in to the dashboard (the same
  `COORDINATOR_DASHBOARD_USERS` list), and the session (90 days) is kept in
  that account's own secret store, never the service's.
  `runner-manager coordinator logout` ends it on both sides, and
  `runner-manager coordinator hosts [--json]` lists the hosts with whether
  each is online, takes commands, and allows changes.
- `--host remote:NAME` runs a command on the host the coordinator knows as
  NAME, as in `runner-manager --host remote:ivan-ms-a2 repo set-capacity
  octo/app --max-capacity 4`, with that host's own output and exit code.
- `runner-manager repo list --json`: one versioned document of the host's
  capacity and every repository policy with its profile, labels, limit and
  workspace.
- The coordinator serves `/auth/cli/*` for the CLI sign-in and accepts a CLI
  session as `Authorization: Bearer` on `/api/*`. Its database moves to
  schema 8 (schema 7 adds the command record; 8 marks each session as a
  browser's or the CLI's).

## 0.4.60

### Changed

- `runner-manager wsl install` moves a distribution first set up before
  0.4.57 from `/root` to `/var/lib/runner-manager`, the tree every root
  service uses, through the same `service install --start-at boot` move:
  the old tree is kept, and its jobs then run under their own `rm-runner-N`
  accounts.
- That move, from `wsl install` or `sudo runner-manager service install
  --start-at boot`, now waits for an idle host: with an attempt still active
  in the old tree's database, or a process still running from its runtime,
  the service is started again unchanged and the move happens on a later run.
  An operator's drop-in that names the old tree stops it too, with that file
  named, since the moved service could not see the directory it points to.

### Fixed

- `deploy/coordinator/install-updater.sh` hands `.git` back to the account
  the update timer runs as when a command once run with sudo left part of it
  to root, which made every update fail at `git fetch`. `update.sh` says so
  when a fetch fails.
- Linux and macOS hosts report their CPU load as the share of CPU time spent
  busy since the last heartbeat (`/proc/stat`, `HOST_CPU_LOAD_INFO`), 0 to
  100, as Windows hosts already did. They reported the one-minute load
  average over the CPU count, a queue length that runs far past 100 on a host
  waiting on its disks, so the coordinator dashboard showed CPU above 100 %
  and placement could treat such a host as busier than it was. The dashboard
  caps an older host's figure at 100.

## 0.4.59

### Fixed

- A WSL host first set up before 0.4.57 starts again after
  `runner-manager wsl install` rewrites its systemd unit. Its directories are
  under `/root`, which the unit's `ProtectHome=tmpfs` hid, and systemd failed
  the unit before it started (`226/NAMESPACE`, "Failed to set up mount
  namespacing"). A boot unit now binds directories under `/root`, `/home` or
  `/run/user` back with `BindPaths=`, and the WSL update creates any that are
  missing before it replaces the unit.

## 0.4.58

### Added

- Coordinator web dashboard at the coordinator's own address: machines with
  CPU, memory, disk and runner slots, the queued, running and recently
  finished self-hosted jobs, pool queues and leases, and a week of history as
  charts. It works on phones and desktops, signs in with GitHub, and lets in
  only the logins in `COORDINATOR_DASHBOARD_USERS`. Off until
  `COORDINATOR_DASHBOARD_CLIENT_ID` and its secret are set. The coordinator's
  database moves to schema 6.
- Each release publishes the coordinator images to GHCR
  (`ghcr.io/ivanmurzak/runner-manager-coordinator` and `-backup`), with build
  provenance attestations.
- `deploy/coordinator/update.sh` and a systemd timer keep a coordinator on the
  newest release: every 15 minutes it backs up the database, moves to the new
  release, checks its health, and rolls back to the previous version and
  database if the new one does not come up. The dashboard shows its status.

## 0.4.57

### Changed

- Linux boot services run each concurrent runner as an account of its own,
  `rm-runner-1` to `rm-runner-32` in the group `rm-runner`, instead of every
  runner as `rm-runner`. A job can no longer read another job's workspace or
  its runner's credentials, read its processes' environment, or signal them.
  Dependency caches stay shared: each cache directory belongs to the group,
  is set-group-ID and carries a default ACL, so every runner can use and
  update it. Re-register with `sudo runner-manager service install --start-at
  boot` to create the accounts; until then runners keep sharing `rm-runner`.
- Handing an attempt to its account and sharing caches with the pool walk the
  tree through directory descriptors and never follow a link at any depth, so
  a job cannot redirect those `root` changes by swapping a directory for a
  link mid-walk.

### Added

- A Docker policy for native Linux jobs, checked by the per-attempt Docker
  proxy: host bind mounts outside the job's own attempt and caches,
  privileged containers and execs, added capabilities and devices, weakened
  security profiles, host namespaces, LAN networks, containers the job did
  not create, host-wide prunes and the swarm, plugin and secret APIs. It
  starts in `audit`, recording each violation without refusing it;
  `host docker-policy report` summarises them and `host docker-policy
  set-mode --mode enforce` refuses them. `host docker-policy allow-path`
  admits a host directory every job may mount. Podman's native API is
  reported as `unchecked_api`.
- The Docker socket the GitHub runner mounts into `container:` jobs and service
  containers is now the job's proxy socket instead of the engine's own, so
  Docker inside job containers is accounted and checked like any other step.
- `host protect-path add|remove|list`: host directories no runner or job may
  reach on Linux. The systemd unit lists them in `InaccessiblePaths=`, applied
  at the next `service install --start-at boot`, and the Docker proxy refuses
  a container mount of one in every policy mode, `audit` and `off` included.
- Isolated execution works under a Linux boot service: the daemon reaches the
  system's rootful Podman service through its socket, and every isolated job
  runs in a container with its own user namespace (`--userns=auto`) and its
  own network namespace, so two jobs can listen on the same port without
  colliding or reaching each other. `host isolation prepare` sets up the
  subordinate id ranges and `podman.socket`; `host isolation set-disk-quota
  --required false` accepts storage that cannot enforce a quota.
  `host isolation status` now probes the OCI provider instead of always
  reporting it not installed.

## 0.4.56

### Changed

- Linux boot services run every job as a new system account, `rm-runner`,
  instead of as `root`. `service install --start-at boot` creates it, and the
  daemon keeps only the capabilities it needs to start runners as that account
  and to hand them their directories: `CAP_SETUID`, `CAP_SETGID`, `CAP_KILL`,
  `CAP_CHOWN`, `CAP_FOWNER` and `CAP_DAC_OVERRIDE`. A job runs with no
  capabilities at all. npm, `node-gyp` and `tar`, which failed as a
  capability-less `root` with `EPERM` changing the owner of extracted files,
  now work. Re-register existing services with
  `sudo runner-manager service install --start-at boot`.
- The Git checkout cache is not offered to `rm-runner` jobs: preparing it ran
  `git` as the daemon over a checkout the job wrote.

## 0.4.55

### Fixed

- Linux services no longer set `RestrictSUIDSGID=yes`. Its seccomp filter
  answers `openat2` with `ENOSYS`, and GNU tar 1.35 extracts through `openat2`
  with no fallback, so every job that unpacked an archive, including the
  runner downloading an action, failed with `Cannot open: Function not
  implemented`. `NoNewPrivileges=yes` and the read-only filesystem outside the
  service's own `0700` directories still cover what it guarded against.
  `service status` reports existing units as outdated; re-register them with
  `sudo runner-manager service install --start-at boot`.
- A Linux runner whose service cannot write its own `HOME` (a boot service's
  `/root`, which the unit makes read-only and hides) gets its own `HOME` inside
  its attempt directory, as a Windows runner already does. Actions that install
  into `~`, such as `oven-sh/setup-bun` (`mkdir '/root/.bun/bin'`), no longer
  fail. A login service keeps the operator's `HOME`.

## 0.4.54

### Fixed

- GitHub sign-in checks credential-store write permissions before requesting a
  device code. Boot-mode permission errors suggest the absolute native binary
  with `sudo`, so npm installations managed by nvm do not require Node on
  root's PATH. `auth logout` gives the same `sudo` command when it cannot
  remove a boot-mode credential. Every other remedy that says to run
  `sudo runner-manager …` (re-registering a drifted service, signing in again,
  granting workspace access, updating) also names the native binary whenever
  it is not on `sudo`'s `secure_path`.
- On Linux, `root` keeps its data in `/var/lib/runner-manager` and
  `/var/log/runner-manager` instead of whichever home directory `sudo` left in
  `$HOME`, so a boot service no longer fails with `Permission denied` on an
  operator's private directories. Boot units keep no capabilities and hide
  every home directory with `ProtectHome=tmpfs`, so workflow jobs cannot read
  other accounts' files. `service install --start-at boot` refuses directories
  a boot service could not use, and re-running it moves an existing boot
  service's configuration and state into the system tree. The least-privilege
  review compares the capability bounding set as a set.
- Service status includes systemd drop-ins and reports the account the service
  manager says the service runs as, instead of the account saved at
  installation time. Every manager now reports it in the same spelling, and a
  placeholder such as a raw SID falls back to the saved account. `ExecStart`
  prefixes such as `-` and `@` and `RestartSec` values with units such as
  `1min` are read correctly.
- Applying the data directories no longer re-runs `chmod` on directories that
  already have mode `0700`, and a directory another account owns, such as one
  reached with `--data-dir` under `sudo`, is used as it is rather than failing
  the command.

## 0.4.53

### Added

- **Memory admission before every runner start.** The coordinator filtered hosts by memory only for
  the pool jobs it placed; a host's own demand (a repository, organization or selector label) was
  bounded only by `host_capacity` and `max_capacity`, so MacM6 (24 GiB) could start an 11.8 GiB
  Unreal build beside four 5.9 GiB App builds. Now the daemon starts a runner, whoever asked for
  it, only when free memory less what its running attempts may still grow into (each holds its
  estimate less what it uses now, until it ends) holds the runner's estimate plus a margin. The
  estimate is per profile, for the heaviest job its labels can take: the coordinator's figure for
  the target (from this host's own runs once it has any), else the p90 of the last 20 job peaks
  this host measured for the profile (or a heavier one of the newest three), else 1 GiB.
  A refused start is deferred, not failed: the job stays queued, the next pass asks again,
  `status` shows `waiting for memory: … needs X GiB (… estimate + … margin), Y GiB free less Z GiB reserved for running jobs` (and
  `memory` in `status --json`), and the log says `memory_deferred` with `free_bytes`,
  `reserved_bytes`, `estimate_bytes`, `estimate_source` and `margin_bytes`. With nothing running
  a runner always starts, however large (`memory_admitted_alone`). In a simulation of MacM6 with
  that queue the busiest moment went from 32.0 GiB to 17.4 GiB, the queue taking 16 ticks instead
  of 10. See [Keep heavy jobs from crowding one machine](README.md#keep-heavy-jobs-from-crowding-one-machine).
- **`runner-manager host set-memory-margin SIZE|off|on`**: the free memory kept beyond the
  estimate (default `1GiB`, in `config/memory.toml`; a size needs a unit), or admission off. On by default; `host show`
  prints the setting and the free memory now. A running service applies a change to its next start.
- **Coordinator: `memory_estimates` for each host's targets** (additive, version-4 links): after
  each `hello` and whenever they change, the heaviest job's expected peak per target, from that
  host's own runs once it has any (another OS's build measured elsewhere does not count). A host older than 0.4.53 skips the message; with an older
  coordinator the host estimates from its own measurements.
- A heavy profile waiting for memory is served before lighter profiles that began waiting after
  it, so steady light work cannot keep it waiting for ever.
- **Launch refusal `memory`.** A coordinator launch the host's memory cannot hold (counting the
  launches it accepted whose runners are not up yet) is refused with reason `memory`, and the
  coordinator places the job elsewhere; it keeps the host a candidate as for a capacity refusal.
  An older coordinator reads the reason as `other`.

### Changed

- The host samples its runners' process trees every 2 seconds while memory admission is on, not
  only while joined to a coordinator, and so also concludes an exited runner's attempt within
  seconds without a coordinator. Turning admission off without a coordinator stops the sampling.

## 0.4.52

### Added

- **`runs-on: rm-pool-any`: a shared pool across operating systems.** A host of any OS may opt a
  profile in with `repo profile set-pool OWNER/REPO [--profile NAME] --pool on --any` (or
  `org set-pool ORG --pool on --any`; `--pool off --any` removes it), beside its own OS pool label on the
  same profile or on another. The coordinator's candidates for such a job are every connected host whose
  profile carries the label, whatever its OS, and its usual scores and statistics choose: in the
  simulation a fast Linux host and a slow Mac with more memory, mean run 466 s without statistics to
  197 s once learned. Extra labels (`[rm-pool-any, heavy]`) narrow it as they do an OS pool. Only one
  profile of a target on a host may carry it. A host directs an `rm-pool-any` profile only when its
  coordinator says it places that pool; with an older coordinator the profile counts its own demand, so
  upgrade the coordinator first. See [Shared pools](docs/coordinator.md#shared-pools).
- **A host's CPU load counts in placement.** Idle cores (cores less the last heartbeat's CPU load) add up
  to `cpu` points (weight 1, `COORDINATOR_PLACEMENT_WEIGHTS` `cpu=`), and a host at or above
  `COORDINATOR_CPU_BUSY_PERCENT` (90 %) is a last resort: tried after every other host that can take the
  job, never excluded. Simulated against a host 95 % busy with work of its own: round-robin started 30
  jobs there over 3 seeds, placement none; mean run 348 s to 238 s.
- **Free disk in every heartbeat, and a low-disk guard.** A host now measures free space on its runner
  root's volume at every heartbeat, not only at connect. A host under `COORDINATOR_MIN_DISK_FREE`
  (10 GiB) is a last resort, after a busy one. Simulated with a 4 GiB host: round-robin started 30 jobs
  there, placement none.
- `stats` shows the **connected hosts** with their cores, CPU load, free memory, free disk and slots, and
  each placement score its `cpu` points, CPU load, free disk and last-resort reason; `--json` adds
  `connected` and those score fields. `runner-manager-coordinator hosts list` shows a connected host's CPU
  load and free disk, and its `--json` adds `connected`. `a pool queue was weighed` adds the chosen host's
  cores, CPU load, free disk and last-resort reason.

All protocol changes are additive: an older host or coordinator ignores them and works as before, with
one exception: a profile carrying both its OS pool label and `rm-pool-any` under a coordinator older
than 0.4.52 serves its OS pool jobs from its own polling, up to 5 minutes late; keep the labels on
separate profiles until the coordinator is upgraded. `stats --json` is schema version 4.
`hosts list` says how old its connected-host figures are.

## 0.4.51

### Fixed

Placement between several hosts of one pool had only ever run with one host per pool. A
deterministic simulation of the real placement code over several hosts
(`crates/coordinator/tests/balance_sim.rs`, numbers are its own) found the following, each now
fixed and asserted there.

- **A heavy job no longer starts on a host too small for it because the big host's slots are all
  taken.** A job no host could hold is run anywhere, and only hosts with a free slot were asked. It now
  waits for the big host. Jobs already measured landing on a host too small, with heavy jobs in a queue of
  their own: 6 in 9 rounds to none.
- **A long build's memory stays counted on its host until it ends.** The reservation lapsed 2 minutes
  after a job started, and a build whose peak comes later left its host reading free, so more builds
  landed there: up to 18 GiB past a 64 GiB host. It now counts against the host's total memory, through a
  broken link too, until the attempt's report, a heartbeat saying the host runs fewer jobs than are held
  for it, or 6 hours.
- **A launch reserves the job its runner took**, once a webhook names it, rather than the queue's next
  heaviest when it was placed. A job taken by a runner whose launch was already gone now counts too.
- **A job that turned heavy is seen at its next run**, not after four. What it is expected to need is
  its p90, or more if one of its 3 newest samples needed more. A job heavy from then on: on a host too small
  for its first four runs to its first only.
- **Placement now finds out which host is faster.** A host that never ran a job other hosts have run
  scores as fastest for it until its first run finishes. The host with the most memory otherwise kept
  every job for good: a job twice as fast on a smaller host ran on the bigger one for ever. Mean run 595 s
  to 238 s.
- **A warm workspace no longer beats a measured result.** A host measured over at least 3 runs as more
  than 10% slower than usual at a job loses its `cache` points for it, since its measured times already hold
  what the checkout saves. With a warm workspace on a slow host, mean run 178 s to 155 s by the sixth round.
- **A failed job no longer reads as a fast one.** How long a job that did not succeed took is not kept
  as its duration: one failing at once made its host look the fastest there is. Its memory still counts.
- **The biggest host idle and still too short for a job's estimate no longer holds that job for ever.**
  It runs on that host. With its estimate following its newest samples, one spike could otherwise stall it for good.

### Changed

- **Heavy jobs wait for the memory they need.** A third 28 GiB job on a 64 GiB host now waits about 15
  minutes for the first to finish rather than take the host 18 GiB past its memory, so such a burst takes longer
  to finish: about 1,800 s, from 1,400 to 1,950 s with memory overcommitted. Light jobs in the same queue wait with
  a heavy one, since a runner started for them could take it instead. Give heavy jobs a label of their own
  (`runs-on: [rm-pool-linux, heavy]`) to spare them: see
  [Weighted placement](docs/coordinator.md#weighted-placement).
- `a pool queue was weighed` and `a pool queue is not placed` gain `committed_bytes`.

## 0.4.50

### Fixed

- **A stalled package download no longer holds a host's launches for good.** A
  download had no time limit, and every copy of the package waits for it. It now
  fails after 30 seconds without a connection or 60 seconds without a byte, however
  long a download that keeps sending takes. Its partial file is removed, the launches
  queued behind it get its failure and retry on their own back-off.
- **A native runner's slot on Linux frees within about 10 seconds of its process
  exiting, not at the next scheduled poll (about 60 seconds).** The 2-second check
  read a runner that had exited as still running, because an exited process stays in
  the process table until the daemon collects it, and only a pass did that. Launches
  were refused with `max_capacity` for that long (live: 35 refusals in 90 seconds). A
  pass also no longer waits for a coordinator launch's bring-up. The host log says
  how long each took: `attempt_slot_released`, `exit_to_report_ms`.
- **A coordinator launch starts at once, whatever its target is doing.** One accepted
  while its target's pass polled GitHub or brought up a batch of runners waited for
  that. Each target now serves its launches beside its passes, under the same host
  lock, journal and ceilings; a pass does not supervise a runner still coming up.
- **Launches now reserve strictly oldest first across a host's targets and
  profiles**, in the order the host accepted them, rather than a younger one waiting
  for at most 2 seconds. Only the reservation is ordered, a lock hold and a journal
  write, so one slow package holds nothing up. An older launch that cannot reserve at
  all is passed over after 2 seconds without progress, once, and the log says so
  (`older_launch_passed_over`). `attempt_launch_slow` gains `order_wait_ms`.
- **Jobs of the same name in two workflows no longer share statistics, when the
  workflow is known.** With the GitHub App, a job's key gains its run's workflow file,
  from the sweep or one request per run. Existing samples keep working under the job
  alone, with no migration, and hosts of any version are unaffected. See
  [Job statistics](docs/coordinator.md#job-statistics).

### Security

- **An edit a job makes to the shared runner package no longer reaches later jobs'
  runners.** 0.4.49 shares a prepared package between attempts, and on Windows did
  not look at it again. Each launch's copy is now read in full against what the
  package's digest-verified archive holds, outside the host lock. One that differs is
  removed and not used, and a shared package that differs too is prepared again
  (`package_copy_differs`, `package_verify_failed`). Windows now downloads the package
  at the first launch after a daemon starts, as Linux and macOS already did. Jobs on
  one account, and above all a boot-mode host whose jobs run as root or LocalSystem, are
  still not isolated: see
  [what this does and does not guarantee](docs/coordinator.md#shared-runner-packages).

### Added

- **The coordinator's log says why a host does not fit a job.** `a pool queue was
  weighed` and `no_memory_fit` carry `free_ram_bytes`, `reserved_bytes`,
  `ram_margin_bytes`, `required_bytes` and `total_ram_bytes` for the candidate nearest
  to fitting. The fit rule itself is unchanged.
- **A daily backup of the coordinator's database.** The compose file gains a `backup`
  service keeping the last 7 consistent copies; `docker compose up -d --build` starts
  it. To keep them on another disk, and to restore, see
  [Back up and restore](docs/coordinator.md#back-up-and-restore).

## 0.4.49

### Fixed

- **Runners of one host no longer start one at a time.** The host-wide allocation
  lock was held for a runner's whole start, package copy included, so one slow
  package held every other target back (live: 143 s, with 40 other launches
  deferred). The lock now covers only the reservation, which is journalled: every
  ceiling holds as before, and a daemon that dies before the runner is up leaves an
  attempt that startup recovery concludes. Runners then prepare at the same time, a
  quarter of the host's cores at once and at least two, and register in parallel.
  On a WSL guest the launch fence is shared by the launches in progress: a Windows
  drain request stops new ones and waits for those.
- **A host serving two targets no longer downloads the runner package at every
  switch between them.** Each target kept its own record of the package tree it
  trusted. One target's reinstall replaced the tree the other had recorded, which
  then reinstalled in turn. The record is now shared. The first launch after a
  daemon starts still downloads the package once, by design.
- **A launch being worked on is no longer dropped.** The 45-second limit dropped
  launches whose runner was waiting for a turn. It now counts from a start that
  failed for a real reason. A launch whose runner is coming up keeps its lease past
  its lifetime, for up to 15 minutes, because the heartbeat that lists it now renews
  the lease at the coordinator. So does one waiting for its target's loop to finish
  bringing up other runners of its profile. A launch whose runner is up and took no
  job expires as before, and one whose runner failed coming up is retried within the
  45 seconds. Upgrade the coordinator first: an older one does not renew a lease, so
  a slow runner's job can be placed a second time, leaving a surplus runner.
- **Launches start oldest first across the targets of a host.** A younger launch
  lets an older one reserve first, for at most 2 seconds, and runners take their
  turns to prepare in the order they were reserved.

### Added

- `attempt_launch_slow` and its siblings in the host log say where a start went:
  `turn_wait_ms`, `package_wait_ms`, `package_install_ms`, `package_verify_ms`,
  `package_copy_ms`, `package_downloaded` and `prepare_ms`, beside the existing
  fields.

## 0.4.48

### Fixed

- **A job's statistics now apply to its next run, whatever the run is called.**
  A job's key included GitHub's `workflow_name`, which is the run's title, so a
  workflow with a `run-name` got a new key at every dispatch. Its samples were
  never found, and almost every queue was estimated at its repository's p90
  (104 of 106 placements in a live test). The key is now `owner/repo/job`, and
  existing samples are rekeyed on upgrade, as a best guess where a run title or
  job name holds a `/`. Jobs with the same name in two workflows of one
  repository now share their statistics.
- **A job that ended stops reserving memory.** A lease's estimate stayed reserved
  on its host for 2 minutes after its runner took a job, even if the job had
  already finished, so a run of short jobs could keep a host "full" for the next
  ones. It is released as soon as the job ends.
- **A launch that cannot start no longer holds its job for 2 minutes.** A host
  counts its other repositories' open launches against its slots, and refuses a
  launch it has no slot for. It drops one it can no longer start, or that has no
  runner after 45 s for any reason, and tells the coordinator at once, which
  places the job again. Its heartbeat's free slots leave out those its waiting
  launches have spoken for. Two launches can no longer share one runner.
- **A launch outlives a runner that took nothing.** When the idle runner serving
  a launch exits without a job, the host starts another or hands it to another
  waiting runner, and the lease stays open.
- **The lease list in a heartbeat is current.** In 0.4.47 a target with nothing
  running could list a launch that had already ended until its next poll.
- **A queue no longer reserves its heaviest job for every runner.** Each lease
  reserves the queue's next heaviest job, so one heavy job among light ones
  counts once. A host must still hold the heaviest job, since a runner can take
  any of them.
- **A pool job is weighed by its own memory use.** A job only the coordinator's
  sweep had seen counted as its repository's p90, so a light job could be
  estimated at a heavy neighbour's memory and passed over by a host with room
  for it. The sweep now names the jobs it lists, as a webhook does.
- **A repository just added is covered within seconds, not 10 minutes.** The
  coordinator reads its GitHub App's repositories again (at most every 30 s)
  when a host advertises one they do not include, or a webhook names one. Until now such a repository stayed in `fallback`: its pool jobs
  were only woken, and waited for the host's next poll.
- **`repo add` no longer refuses a repository the coordinator will poll for
  you.** The REST budget (also in `host show`, `host set-poll-interval` and the
  TUI) counts a coordinated target at the coordinated interval instead of 60 s.
  A new repository (not a new organization) on a host whose link is up and whose
  coordinator runs a sweep is counted the same way, with a printed note. If
  coordination is lost, a set that no longer fits stretches its charged polls to
  the interval `repo add` would allow (64 s for 11 repositories) and keeps starting
  runners. `host set-poll-interval` now also refuses a shorter `--coordinated`
  that would go over the budget.

### Changed

- **Only a job's own samples can keep it off a host.** A job never measured used
  to be held back by its repository's p90, so one heavy job could block every new
  job of that repository. Now such a job is only ranked by that figure, and
  reserves at most `COORDINATOR_DEFAULT_JOB_RAM`. It may land on a host too small
  for what it turns out to need, once: from its first sample it is filtered by
  its own figure.

### Added

- The coordinator's `a pool queue was weighed` log line says how many of the
  queue's jobs are named, measured and unnamed.

### Upgrade notes

- The coordinator's database moves to schema 5: sample keys lose the run's title.
  To roll back, stop the service and run
  `sqlite3 coordinator.db 'PRAGMA user_version = 4'`; 0.4.47 then starts new keys
  beside these.
- The launch fixes are on the host, so hosts need 0.4.48 too. An older host keeps
  working: only the coordinator's fixes apply to it.

## 0.4.47

### Fixed

- **Coordinator statistics show a job's real run time.** A job's duration in
  `coordinator stats` is now GitHub's own `started_at` to `completed_at`, so a
  14-second job reads 14 s instead of the 60-80 s its runner lived (start-up,
  waiting for the job and cleanup included). Only when GitHub's `completed`
  webhook never arrives (within 2-3 minutes) does a sample fall back to the
  host's measured time. Peak memory and CPU are measured by the host as before.
  Samples recorded by 0.4.45-0.4.46 keep their old durations until newer runs
  replace them (the last 30 per job).
- **A freed slot is used at once.** When a runner ends, the host tells the
  coordinator its free slots right away instead of at its next heartbeat (up
  to 15 s later), and the coordinator places a waiting pool job on it
  immediately. A joined host also notices within about 2 seconds that a
  runner's process has exited and frees its slot then, instead of at the
  target's next poll (up to 60 s). Cleanup of the runner's files never held
  the slot; a container, VM or WSL runner still keeps it until its
  environment is proven gone, as before, and its host reports the free slot
  as soon as that cleanup is done.
- **Hosts reconnect within 30 seconds after a coordinator restart.** The
  link's reconnect wait now stops at 30 s, random spread included (it could
  reach 90 s, which added up to minutes), and starts over after a connection
  that stayed up for over a minute. A refused key or version still waits up
  to 5 minutes.
- **A pool job no longer waits minutes behind a launch that is not coming.**
  A lease (a launch the coordinator sent to a host) used to count for 5
  minutes even after its host had dropped it, for example after the link
  reconnected, or after another runner of that host took the job. The
  coordinator now closes it, and places the job again at once, when the host
  connects again, when the host's heartbeat no longer lists it, or when
  another runner of the same host takes a job of that queue. A lease lasts
  2 minutes at most by default, set with `COORDINATOR_LEASE_TTL`
  (`--lease-ttl`, at least 30 s).
- **Adding or removing a repository on a host no longer interrupts the
  others.** `repo add`, `repo remove` or enabling or disabling a profile used
  to make the daemon finish every running job, stop every target and drop its
  coordinator link and accepted launches before reloading. Now only the
  changed repository's loop starts or winds down, within 30 seconds. The
  link, its launches and every other repository keep running.
- **Accepted launches start together, at once.** Each launch a host accepted
  used to wait for its own pass, 5 seconds after the previous one (6 launches
  took 25 s more to start). Now every launch open at that moment is started
  in one go, without polling GitHub. The runners are still created one after
  another under the host's allocation lock, so every capacity ceiling holds.
- A test of the runner process fixture could read its readiness file before
  it was written and fail at random.

### Added

- **Queue wait in `coordinator stats`.** How long jobs waited from being queued
  to starting on a runner (GitHub's `created_at` to `started_at`), as p50 and
  p90 over all samples and per job: the figure that shows whether jobs wait
  for a free host.
- **Why a pool job waits.** `coordinator stats` lists the pool queues with
  fewer runners on their way than jobs queued, the oldest job's wait, and the
  reason: no host serves it, unfit or draining, no free slot, not enough
  memory, refused by a host (with the host's reason), or no answer. It also
  lists the open leases per host with their age. The coordinator logs the
  same reason, at most once a minute per queue.

### Upgrade notes

- `coordinator stats --json` (on a host and on the coordinator) is schema
  version 3: `p50_duration_secs` is the job's run time, and
  `p50_queue_wait_secs` and `p90_queue_wait_secs` are new, overall and per job,
  as are `pending`, `leases` and `live_at`.
- The coordinator's database moves to schema 4 (one new column, one new
  table). To roll back to 0.4.46, stop the service and run
  `sqlite3 coordinator.db 'PRAGMA user_version = 2'`.
- The coordinator protocol stays at version 4 and every change is additive:
  0.4.47 hosts and coordinators work with 0.4.45-0.4.46 ones. An older host
  still gets prompt placement once its next heartbeat shows a free slot; an
  older coordinator ignores the extra heartbeat and its lease list. An older
  host's leases are still closed when it reconnects or another of its runners
  takes the job, and otherwise expire as before.

## 0.4.46

### Fixed

- 0.4.45 reached the GitHub Release and the install scripts, but not the
  `runner-manager` crate on crates.io, npm or Homebrew; 0.4.46 publishes the
  same coordinator features to every channel. Nothing else changed: the
  coordinator protocol and every command behave exactly as in 0.4.45.
- Internal: the coordinator wire protocol now lives in the already-published
  `runner-manager-domain` crate, and a test fails any pull request whose crates.io
  publish list misses a crate `runner-manager` depends on.

## 0.4.45

### Added

- **An optional coordinator.** `runner-manager-coordinator` is a small
  self-hosted server (container image, Caddy example and `docs/coordinator.md`
  included) that hosts can join so they poll as soon as a job is queued instead
  of at their next interval. Each host still decides under its own limits and
  GitHub credential. Without a coordinator, or while it is unreachable, a host
  behaves exactly as in 0.4.44. Protocol and database notes: `docs/coordinator.md`.
- `runner-manager coordinator join URL --code CODE`, `coordinator status [--json]`
  and `coordinator leave`. A host authenticates with an Ed25519 key created at
  `join` and stored beside the GitHub credential, enrolling with a one-time code;
  `hosts revoke` on the server closes its live connection within a second.
- **Webhook wake.** The coordinator receives GitHub's `workflow_job` webhooks
  (HMAC-verified) and wakes the hosts that serve the job's repository and
  labels. A woken target is polled at most once every 5 seconds and never
  inside a rate-limit back-off.
- **Reconciliation sweep.** Given a personal GitHub App
  (`COORDINATOR_GITHUB_APP_ID`, `COORDINATOR_GITHUB_APP_PRIVATE_KEY_FILE`), the
  coordinator reads the queues of the repositories its hosts serve every 2
  minutes with conditional requests, and wakes hosts for jobs whose webhook was
  lost. Without the App, every target stays in `fallback`.
- **Poll modes per target:** `standalone` (no coordinator), `coordinated` (link
  up and the target covered by the sweep: polled every 300 s while none of this
  host's runners runs for it, `host set-poll-interval --coordinated`, at least
  60 s) and `fallback` (link down for 30 s or
  target not covered: the normal intervals, at once). `status`, `host doctor`
  (`github.polling`, `coordinator.link`), `coordinator status` and the TUI show
  the mode and the link.
- **Shared pools.** `repo profile set-pool OWNER/REPO [--profile NAME] --pool on|off`
  and `org set-pool ORG --pool on|off` give a profile this host's pool label
  (`rm-pool-windows`, `rm-pool-linux` or `rm-pool-macos`). For a job with
  `runs-on: rm-pool-…`, the coordinator sends exactly one host a `launch`; the
  host still applies every local ceiling and may refuse, and the coordinator
  then tries the next one. In `fallback` and `standalone` a pool profile serves
  its own demand as before. A second pool profile on one target, another OS's
  pool label or an unknown `rm-pool-` label is refused; `profile list` and
  `profile show` print `pool=`.
- **Job weight statistics and weighted placement.** A joined host samples each
  native runner's process tree (peak memory, CPU, duration) and reports it; the
  coordinator keeps the last 30 samples per `repository/workflow/job` for up to
  90 days and places pool jobs by memory fit, warm workspace, headroom and each
  host's past speed (`COORDINATOR_PLACEMENT_WEIGHTS`). With no statistics the
  order is warm workspace, then free memory, then fewest busy slots.
  `runner-manager-coordinator stats` and `runner-manager coordinator stats`
  show the heaviest jobs and the last placement decisions.
- Heartbeats report free memory on macOS and CPU load on Windows.

## 0.4.44

### Added

- Daily release checks in the TUI and background daemon, coordinated across
  processes and persisted across restarts. Automatic updates default to enabled
  for both new and existing installations. Host settings and
  `host set-auto-update true|false` control installation; checks continue when disabled.
- Automatic updates reuse the installation channel and checksum validation.
  Background services drain active jobs before restarting, and the TUI restores
  its terminal and relaunches with the original arguments. Windows, macOS,
  Linux and WSL share the scheduler. Update results are saved in
  `state/update-status.txt`.

## 0.4.43

### Fixes

- Changes to `host set-capacity` take effect without restarting the service,
  including on WSL hosts. All projects share the current host ceiling, which
  is checked again under the allocation lock before each new runner attempt.
  Lowering the limit preserves existing attempts and waits for free capacity.
- Missing host records and unreadable host settings block new runners and
  report their own diagnostic reasons. An unreadable local journal no longer
  makes a busy host switch to the faster idle polling interval (#113).

## 0.4.42

### Added

- Native repository runners can reuse an independent local Git object cache,
  including across ephemeral attempts and profiles with different workspace
  directories. Enable it in Host/Repository Settings or with
  `repo cache set-tool OWNER/REPO git --state on`. It is off by default and
  supports standard GitHub HTTPS checkout; the workflow still fetches its exact
  ref/commit. Existing dependency-cache roots, limits and pruning apply.
- Native Linux/WSL runners account for temporary Docker resources through a
  per-attempt local proxy. The default `report` mode does not delete resources;
  `host docker-cleanup set-mode --mode apply` enables cleanup after an attempt
  is cleaned. Named volumes, build caches, images and unrelated resources are
  preserved; no global prune is used.

### Fixes

- Completed-attempt summaries expire after 30 days and retain at most 1,000
  files. Rotating service logs retain at most 30 files per stem. Dependency
  caches and persistent workspaces are excluded from diagnostics cleanup.
- Owned Windows Hyper-V container cleanup also removes anonymous volumes.
- Unix file locks release immediately when their owning guard is dropped,
  even while a subprocess temporarily holds a duplicate descriptor.
- Git cache publication keeps concurrent shallow histories, excludes stale
  refs and credentials from new workspaces, and stages checkout copies outside
  retained workspaces for crash cleanup. Oversized merged shallow metadata is
  refused before replacing the last readable copy.
- Docker accounting journals enforce their reader's size limit before atomic
  replacement and bound reads even if a file grows during inspection.

## 0.4.41

### Fixes

- Autoscaling starts additional runners for queued jobs even when other runners are busy.
  Busy runners still consume host and policy capacity, but only unassigned runners that
  are preparing, starting, or idle cover queued demand. This prevents the last few jobs
  of a parallel workflow from staying queued while capacity is available (#108).
- `update --force` recognizes the application's `X.Y.Z+git.<sha>` source-build
  identity when upgrading an installed service to a newer published release.
  Version comparisons still prevent downgrades and same-version replacements
  with different bytes; published release versions remain strictly `X.Y.Z`.

## 0.4.40

### Fixes

- `runner-manager update` on a Windows copy installed with npm no longer says npm is not on the
  PATH when it is. Rust's process API looks only for `npm.exe`, and npm ships as `npm.cmd`, so
  `update` now searches the PATH with each `PATHEXT` extension the way `cmd.exe` does and runs
  the `npm.cmd` it finds. Unlike `cmd.exe` it skips the current directory and relative PATH
  entries, and tries only `.exe`, `.com`, `.cmd` and `.bat`. `host doctor`'s tool checks use
  the same search. The standard library escapes the arguments for `cmd.exe`, so no command line
  is assembled by hand.
- `update` on an npm copy passes `--prefix` with the prefix that copy lives in, so it updates
  the copy you ran and not the global prefix of the account running it. Seen on a machine with two
  accounts, each with its own copy under `%APPDATA%\npm`, where the machine PATH lists the first
  account's copy first. Afterwards `update` runs the updated binary and says which version it now
  reports. A copy that is not a global install (one in a project's `node_modules`, or a
  dependency of another package) is refused with the npm command to run, instead of having a
  second copy installed somewhere else.
- When the newest release is already installed but the service still runs an older build (for
  example after `npm install --global` was run by hand), `update` no longer says "Nothing to do".
  It says the service still runs the older build and starts the same job-safe swap that
  follows an update: the service finishes every running job, then restarts on the new build.
  It does this by giving the file the service watches a new modification time; the file's
  contents are not changed. If the service is not running, `update` says so and names the
  command that starts it, after which it swaps by itself. When the service was installed from
  another copy, `update` names `runner-manager update --force`, which hands this copy over
  without interrupting a job. After
  an update the same case used to name `service install`, which refuses while the service runs.
  A registration from before the service ran its own copy is still told to re-register with
  `service install`. `--check` reports what would happen and changes nothing.
- The advice for a service that has stopped making progress, in `status`, `service status` and
  `status --json`, named `runner-manager service stop` and `service start`, which do not exist.
  It now names the service manager's own restart command for the service's start mode:
  `Restart-Service` or `schtasks` on Windows, `launchctl kickstart` on macOS, and
  `systemctl restart` on Linux. The Windows install script's advice for a binary it cannot
  replace no longer names `service stop` either.

## 0.4.39

### Fixes

- Native runners start with `POWERSHELL_TELEMETRY_OPTOUT=1` on every platform, so a job's
  PowerShell step shells on Windows no longer hang at startup while another job runs. The cause
  is a telemetry lock in PowerShell 7.6.6 and earlier, which the first `pwsh` of each job takes
  in its fresh profile and keeps until it exits, while the first `pwsh` of every other job waits
  for it with no timeout. Seen as several `pwsh` step shells holding their runners for two hours
  with no output and almost no CPU. The opt-out makes PowerShell skip that code. macOS and Linux
  get it too, as a precaution.
- A non-empty value the service's own environment already has for `POWERSHELL_TELEMETRY_OPTOUT`
  is left as it is, and `runner.env` overrides it like any other default:
  `runner-manager host env set POWERSHELL_TELEMETRY_OPTOUT=0` turns PowerShell telemetry back
  on. `host env show` lists it.
- The 0.4.31 note that .NET known-folder APIs still report the service account's profile was
  not true of local application data, which follows `USERPROFILE`; the README and
  `host env show` now say so.

## 0.4.38

### Features

- A repository with nothing happening is polled for queued jobs every 10 seconds instead of every
  60, so a job that arrives on an idle host gets its runner up to 50 seconds sooner. The polls
  are conditional requests: the service keeps each listing's `ETag`, sends it back with
  `If-None-Match`, and GitHub answers `304 Not Modified` while nothing changed. GitHub does not
  count a `304` against the hourly rate limit, so idle polling is free against it. A repository
  with a runner up or runs in progress, or a job this host matched but has not started, is still
  polled every 60 seconds.
- `runner-manager host set-poll-interval --idle 10s --active 60s` sets both intervals. The idle
  interval is at least 5 seconds and the active one at least 30 (the active one is the existing
  refresh interval). A running service reads them again every 15 seconds and each target adopts
  them at its next poll, without a restart. An organization target too large to poll that often
  stretches its own idle interval to stay under 300 requests a minute.
- A repository covered by two targets on one host, such as an organization and a repository
  inside it, is read once for both within the idle interval, and every target shares one set of
  `ETag`s.
- The hourly rate limit is your GitHub user's, shared by every host signed in as you. Every
  response carries what is left of it, and the service now slows down on it: under a fifth left,
  it polls at twice the active interval, under a twentieth at four times, never past the hour's
  reset. A secondary rate limit (`429`, or a `403` saying so) now stops every poll on the host,
  not only the one that met it, until the `retry-after` GitHub sent, or a minute without one,
  doubling each time it comes back after a wait has ended. Answers to one limit that arrive
  together count once, and the loops wake a few seconds apart rather than all at once.
- `host show` and `status` print what polling actually cost, measured by the service: full
  (`200`) and `304` responses per hour and the share that were `304`, the busiest minute against
  GitHub's 900-a-minute secondary limit, what is left of the hourly limit, and whether polling is
  throttled and why. The old projection is still printed, as the cost if no poll were answered
  `304`. `status --json` carries the measurement under `polling`. A new `host doctor` check,
  `github.polling`, reports the same and never blocks runners.

### Fixes

- A second account on a machine whose service another account installed is told so, and is
  no longer told to break it. A Windows host's boot service had been installed by one
  administrator, and another account that had once run a login-mode install opened
  `runner-manager tui`: RUNNER READINESS: BLOCKED, a "STALE" service binary, a start mode
  "mismatch", a secret store "MISMATCH" and a login-only warning, with `service uninstall`,
  `service install` and `auth login` as the fixes. All of it compared that account's abandoned
  0.4.30 record against the other installation's registration. Followed from that account,
  those fixes would have stopped, replaced or broken a service that was running jobs. The
  service manager's registration names the data directories the service runs against, and when
  they are not this account's, `service status`, `status`, `host doctor` and the TUI now report
  the service as the other installation's: its state, its account, the data root it was
  installed from and whose that is. Where this account can read that installation's records, the
  report shows that installation's own problems, each with the account to fix it from, and none
  of the owner's remedies, since those act on the directories of whoever runs them. Where it
  cannot, it says that, and to look from an elevated terminal or as that account, instead of
  guessing. No reinstall or sign-in is suggested for it. The TUI shows UNKNOWN rather than BLOCKED
  when it cannot read the service, and notes that its counts are this account's own
  configuration, which the service does not run. `status` never runs the other installation's
  binary, so its `service_binary_version` is `null`. `status --json` carries the other
  installation's data root as `product.service_installed_from`, and the `host doctor --json`
  document carries it as `service_installed_from`. `host doctor` reads that installation's own
  records for its service checks. The same holds on macOS and Linux for a root-owned boot service
  seen by a user with a leftover login record. A registration made before the directory options
  existed names no directories, so it is still judged as this account's own.
- `service install`, `service uninstall`, the TUI's start-mode switch, and the service start and
  stop used by updates refuse another installation's registration. They name the account it has
  to be changed from, where they used to replace, remove or restart it with this account's
  directories.
- `runner-manager host forget-local` moves an account's unused configuration (its old install
  record, database, host row and policies) into a `forgotten-<time>` directory inside its
  configuration directory. Nothing is deleted, so moving the files back restores it. It leaves the
  state, runtime and log directories where they are, including on macOS, where they sit inside the
  configuration directory. It refuses while a service on the machine runs against that
  configuration, while a service manager cannot be asked, or while an agent holds its lock. It
  never touches the service's own directories or any secret store. The service report names it
  when it finds such a record.

## 0.4.37

### Changes

- The macOS binaries are signed with the project's Developer ID Application certificate, under
  one identifier for every release and both architectures (`io.github.IvanMurzak.runner-manager`),
  with the hardened runtime and a secure timestamp. They are not notarized: every documented
  install path is a terminal command, which Gatekeeper does not check. macOS ties the service's
  login-keychain item, and its permission to read a runner root on a removable volume, to the
  binary's signature. An ad-hoc signature names the hash of one exact build, so every update asked
  again on the Mac's desktop whether runner-manager "would like to access files on a removable
  volume", and the service started no runner until somebody clicked Allow. A Developer ID
  signature is matched by its identifier and Team ID instead, and the next release has both.
- **The first update to a signed build asks one last time.** To macOS, 0.4.37 is a new program,
  because 0.4.36 and earlier are ad-hoc signed. Expect the removable-volume question once more on
  a Mac whose runner root is on an external volume, and click Allow on its desktop. The service
  still hands its keychain credential to the new build while it upgrades; where that does not
  run, `runner-manager auth login` once more by the new build ends it. From 0.4.37 on, updates
  keep both grants.
- Releases: the signing material lives in the repository's `release` environment (secrets
  `MAC_CSC_LINK` and `MAC_CSC_KEY_PASSWORD`, variable `MAC_SIGN_IDENTITY`). The workflow signs
  through a keychain of its own that is deleted when signing ends, and checks, before anything is
  packaged, that the signature's designated requirement names the identifier and the Team ID
  rather than a code hash. With no material configured the binaries are ad-hoc signed and the run
  says so in a warning. With part of it configured, or none while the variable
  `RUNNER_MANAGER_REQUIRE_DEVELOPER_ID` is `true`, the release refuses before it tags anything;
  it also rehearses the signing on a throwaway binary first, so a wrong password or certificate
  is found before the tag as well.
  A release can then be dispatched only from a branch the environment admits (`main`).

## 0.4.36

### Fixes

- `auth login` on a Mac with no service installed, run as an ordinary account, signs in for a
  login-mode service. It used to assume `boot`, reached for the System keychain only root may
  write, and failed after the device code with `SecKeychainItemCreateFromContent returned -61`.
  The assumed mode is printed with the flag that picks the other one, and recorded, so `repo
  add`, `auth status` and the service look in the same store. A `-61` from the System keychain
  now says that only root may write it and names `sudo runner-manager auth login --start-at
  boot` and `runner-manager auth login --start-at login`.
- A short job is recorded `completed_job`. A job of a few seconds starts and ends between two
  polls, so GitHub was never seen reporting the runner busy, and its clean exit was recorded
  `failed / process_exited_unexpectedly`, with a replacement runner started for it (3 of 5
  attempts on a new Mac). The runner's own diagnostics now decide: a job worker's log in its
  `_diag` directory means it ran a job. The same evidence settles two related errors. A runner
  GitHub showed assigned that never started the job, and exited 0, is recorded
  `exited_idle_without_work` rather than `completed_job`, and a live one goes back to `idle`, so
  the idle timeout holds it again. A runner that finished its job before GitHub took it off the
  list is recorded `completed_job` rather than `orphaned`.
- `service status` no longer tells a Mac that signs its runner account in automatically that it
  will not resume after an unattended reboot. It reads automatic login and FileVault: it says
  nothing for a host that comes back by itself, and names the System Settings steps for one that
  does not. The dashboard's "starts only after this user signs in" warning follows it.
- On a login-mode Mac reached over SSH, `repo add`, `org add` and `auth status` work. The SSH
  session cannot unlock the login keychain, so they failed with its error while the service, in
  the desktop session, used the credential every poll. They now ask the running service what the
  credential reaches; the answer crosses through the state directory and never holds the
  credential. `status` says the credential is in use by the service when the service reached
  GitHub in the last 15 minutes, instead of calling it unreadable.
- A runner root on an external volume that macOS has not yet let the service read is reported
  as such. After an update, macOS asks again whether runner-manager "would like to access files
  on a removable volume", because it ties the answer to the exact build, and until somebody
  clicks Allow on the Mac's desktop the service's listing of the root waits and it starts no
  runner. `host.runner_root_responsive` now says that a privacy question is probably waiting and
  which button answers it, and, when the answer was no, where to turn it on (System Settings >
  Privacy & Security > Files & Folders). A refusal is a failure; it used to be "unknown", which
  let runners start on a root they could not use.
- `service status` is not healthy while the service starts no runner because a required host
  check fails; it used to say `verdict healthy`. It names what the service found and the fix,
  and so does `status`, under `host unfit because`.
- A daemon that stops making progress reads as such. One blocked in a file system call sat at 0%
  CPU for half an hour after an update, writing nothing, while launchd reported it running and
  `service status` said `verdict healthy`. The daemon now writes a heartbeat from its loop every
  minute; when a running daemon has not beaten for five minutes, `service status` is not healthy
  and `status` says `daemon stalled`, with the last GitHub contact and what to do. Its host-unfit
  record no longer expires from `status` while it is stalled, and host checks that do not finish
  within two minutes count as a failure (`host.checks`) instead of holding the daemon back
  silently. Reading a runner's diagnostics is bounded as well.
- `wsl install` (and anything else that raises a UAC prompt) asks for administrator rights from
  a session on the Windows desktop even with no terminal, as when a script or an agent runs it.
  A UAC prompt is a desktop dialog; it used to be refused with "this session has no terminal".
  Sessions with no desktop (services, scheduled tasks that run whether or not anybody is signed
  in, SSH logins) are still refused, and a change that lowers security still needs its flag or
  an answer on a terminal.
- `host doctor` reports a required check the running service finds failing as failing, with the
  service's finding, even when its own look passes. Over SSH it used to list the runner root
  itself, from a session macOS was not asking about, and call it passing.
- The release's crates.io publish no longer fails when the crates.io index trails its API. In
  0.4.35, `runner-manager` "failed to select a version for runner-manager-agent ^0.4.35" right
  after that crate was uploaded, and only a re-run published it. Each crate is now awaited in
  both the API and the sparse index Cargo resolves from, with a backoff inside one fifteen-minute
  budget, and a dependent whose workspace dependency the index does not show yet is retried.
  Versions already published are still skipped.
- The Spotlight check's remedy names `/Users/Shared/rman.noindex`. It used to suggest
  `…/Application Support/…/runtime.noindex`, a path with a space that `host set-runtime-root`
  also refused.

### Features

- `host doctor` checks a Mac's power settings, and `host prepare` fixes them with one
  administrator prompt (`pmset -a …`), recording the values it replaced so `host prepare
  --revert` puts them back: `macos.sleep` (`sleep 0`), `macos.disk_sleep` (`disksleep 0`) and
  `macos.autorestart` (`autorestart 1`) are recommended, `macos.wake_on_lan` (`womp 1`) is
  informational.
- `macos.unattended_login` reports whether the service comes back after an unattended restart:
  automatic login as the service's account for a login-mode service, and FileVault off for
  either mode. It prints the System Settings steps and never changes automatic login or
  FileVault itself.
- `macos.runner_root_location` reports a runner root with a space in its path, or inside the
  home folder of the account the service runs as, where every job's `TMPDIR` is too (a test
  that builds a stand-in home folder from `TMPDIR` then nests it inside the real one). The
  default root is unchanged; the remedy is `host set-runtime-root --path
  /Users/Shared/rman.noindex`.

### Notes

- Job steps see SIGPIPE ignored, so `yes | head` exits 1 rather than 141. That comes from the
  GitHub Actions runner, not from runner-manager: .NET ignores SIGPIPE in `Runner.Listener` and
  `Runner.Worker` and its process start keeps an ignored disposition for every step, on classic
  runners too (actions/runner#2684). runner-manager starts the listener with the default
  disposition, and a test now pins that.

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
- A managed WSL host no longer stops starting runners for good when its daemon dies mid-launch.
  The guest's launch claim on the fence it shares with Windows was never removed once its owner
  was gone. A WSL restart, a killed daemon, or a removal that failed on `/mnt/c` left it in
  place, and every later launch was refused (`allocation_deferred
  reason=allocation_lock_unavailable`) while the host reported itself healthy. One host started
  nothing for 13 days that way. A guest claim now records its owner's process identity, and the
  daemon reclaims a claim whose owner has provably gone. That covers a process that exited, a
  PID that now belongs to another process, a claim written before this boot, and a claim this
  same daemon failed to remove. The daemon checks at start and again before each launch. Claims
  written by 0.4.34 and earlier carry no identity. They are judged by the boot time, by whether
  they predate the running daemon, and by the recorded PID, so the claim that blocked that host is
  reclaimed by the updated daemon even when only the distribution, not the WSL VM, restarted. A
  live owner, an owner that cannot be inspected, and a Windows recovery claim are never touched.
- A launch claim that cannot be released is retried and then logged with its path and the error,
  instead of being dropped silently. That includes a claim given back because Windows asked the
  distribution to drain.
- `status`, `status --json` (new `product.service_launches_blocked`), `service status`, `wsl
  status` and `host doctor` (new Recommended check `host.launches`) report a host that starts no
  runner, with the reason and the remedy. That covers five refusals in a row spanning at least
  five minutes, and a launch fence held for more than 30 minutes. A run of refusals restarts after
  five quiet minutes. The record expires 15 minutes after the last refusal, so a host whose demand
  went elsewhere is not reported blocked forever. `wsl status` reads the fence from Windows too,
  aged by the Windows clock, so it catches a guest that is too old to report or that has no queued
  job to be refused. Its fix line names the restart command rather than a reinstall, which would
  not unblock the fence, and `wsl install` no longer refuses a provisioned host only because its
  launches are blocked. A fence whose owner record cannot be read names the directory to delete.

### Operator notes

- A Windows host still on 0.4.34 or earlier cannot read the owner record a 0.4.35 guest writes
  while that guest is launching. It logs `abandoned WSL recovery coordination could not be
  inspected` until both sides run the same version. Update Windows first, then bring the guest up
  to date with `runner-manager wsl install --distribution NAME`, which `wsl status` already asks
  for whenever the two versions differ.

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
