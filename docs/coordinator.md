# The optional coordinator

The coordinator is a small server you host yourself. It receives GitHub's `workflow_job`
webhooks and wakes the `runner-manager` hosts that serve the job's repository and labels, so a
new job starts as soon as a host polls, not up to a minute later. It is optional: without it,
every host polls GitHub on its own exactly as before.

Design and owner decisions: [`.taskflow/2026-11-07-coordinator-server/README.md`](../.taskflow/2026-11-07-coordinator-server/README.md).
Stage 1: the coordinator wakes hosts. Stage 2: with its own GitHub App configured, it also runs a
**reconciliation sweep** over the hosts' repositories, and hosts it covers poll GitHub rarely (see
[Poll modes](#poll-modes)). Stage 3: for jobs that ask for a **shared pool label**
(`runs-on: rm-pool-linux`), the coordinator picks exactly one host to start the runner (see
[Shared pools](#shared-pools)). Stage 4: hosts report what each job used, and the coordinator
places pool jobs by those statistics (see [Job statistics](#job-statistics)). Every other job:
hosts still compute demand themselves.

## What it can and cannot do

- It receives `workflow_job` events signed with your webhook secret, and tells connected hosts
  "poll target X now".
- With a GitHub App configured, it reads the queued jobs of the repositories its hosts serve with
  the App's own installation tokens (read-only), and tells the hosts which of their targets that
  sweep covers. Nothing else.
- For a queued pool job it sends one host a `launch` ("start one runner of this pool profile"),
  which that host checks against its own policy, `max_capacity`, host capacity, `host doctor`
  fitness and drain state before it starts anything; a host may refuse, and the coordinator then
  asks the next one.
- It never sees a host's GitHub token, a JIT configuration, a job log or source code. A host checks
  every wake against nothing: it simply polls, and its own policies, capacity and `host doctor`
  checks decide whether a runner starts.
- A woken target is polled at most once every 5 seconds, and never while GitHub has asked that
  host to slow down. A compromised coordinator can at worst make hosts poll a little more often,
  or (by claiming coverage it does not have) poll a covered idle target only every 5 minutes, or
  (through launches) fill pool profiles up to the ceilings their owners set, or leave them idle
  for as long as it holds them in coordinated mode.
- Hosts connect **out** over `wss://`, so they keep working behind NAT. If the coordinator is
  down, hosts poll on their own; nothing waits for it.

## Deploy

You need a machine with Docker, a DNS name pointing at it (for example `runners.example.com`),
and ports 80 and 443 open. Caddy obtains the TLS certificate.

```bash
git clone https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI.git
cd GitHub-Runner-Scaler-UI/deploy/coordinator
echo "COORDINATOR_HOST=runners.example.com" > .env
openssl rand -hex 32 > webhook_secret && chmod 600 webhook_secret
docker compose up -d --build
curl https://runners.example.com/healthz          # ok
```

The webhook secret is read from the file only; it is never an argument and never logged.
The SQLite database (enrolled hosts and invites) lives in the `coordinator-data` volume.

Without Docker, build `cargo build --release -p runner-manager-coordinator` and run

```bash
COORDINATOR_PUBLIC_URL=https://runners.example.com \
COORDINATOR_WEBHOOK_SECRET_FILE=/etc/runner-manager-coordinator/webhook_secret \
COORDINATOR_DB=/var/lib/runner-manager-coordinator/coordinator.db \
runner-manager-coordinator serve --listen 127.0.0.1:8080
```

behind any TLS proxy that forwards `/webhook`, `/connect` (WebSocket), `/enroll` and
`/healthz`. Pass `--trust-forwarded-for` only when the proxy is the sole client, so per-address
rate limits see real client addresses.

## Connect GitHub: a personal GitHub App

The webhook comes from a GitHub App you own (one URL per coordinator, so the shared
`runner-manager` App cannot be used). The same App's installation tokens are what the
reconciliation sweep reads the queue with.

1. GitHub, **Settings > Developer settings > GitHub Apps > New GitHub App**.
2. **Webhook**: active. **Webhook URL** `https://runners.example.com/webhook`.
   **Webhook secret**: the contents of `webhook_secret`.
3. **Repository permissions**: **Actions: Read-only** and **Metadata: Read-only** (GitHub
   selects Metadata itself). Nothing else.
4. **Subscribe to events**: **Workflow job**.
5. **Where can this GitHub App be installed?** Only on this account.
6. Create it. Note the **App ID** on its page, and under **Private keys** click **Generate a
   private key**: GitHub downloads a `.pem` file.
7. **Install App** on the repositories or the organization your hosts serve. An organization
   target is covered by the sweep only when the App is installed on **All repositories** of
   that organization; a repository target, when the App is installed on that repository.

GitHub sends a `ping` at once; the App's **Advanced > Recent Deliveries** should show it
answered `200`. An unsigned or wrongly signed delivery is answered `401` with no body.

### Turn on the reconciliation sweep

Put the private key next to the compose file and give the coordinator its path and the App ID:

```bash
cp ~/Downloads/your-app.*.private-key.pem github_app_key.pem && chmod 600 github_app_key.pem
echo "COORDINATOR_GITHUB_APP_ID=123456" >> .env
cat > docker-compose.override.yml <<'YAML'
services:
  coordinator:
    environment:
      COORDINATOR_GITHUB_APP_ID: ${COORDINATOR_GITHUB_APP_ID}
      COORDINATOR_GITHUB_APP_PRIVATE_KEY_FILE: /run/secrets/github_app_key
      # COORDINATOR_RECONCILE_INTERVAL: 2m   # at least 30s
    secrets:
      - github_app_key
secrets:
  github_app_key:
    file: ./github_app_key.pem
YAML
docker compose up -d --build
docker compose logs coordinator | grep "reconciliation sweep"
```

Without Docker, set `COORDINATOR_GITHUB_APP_ID` and `COORDINATOR_GITHUB_APP_PRIVATE_KEY_FILE`
(or `COORDINATOR_GITHUB_APP_PRIVATE_KEY` with the PEM itself) for `serve`. The key is read from
the file or the environment only, never an argument, and neither it, the JWTs signed with it
nor the installation tokens are ever logged. Both the downloaded PKCS#1 key (`BEGIN RSA PRIVATE
KEY`) and PKCS#8 (`BEGIN PRIVATE KEY`) are accepted. For GitHub Enterprise Server, also set
`COORDINATOR_GITHUB_API_URL`.

What the sweep does, every `COORDINATOR_RECONCILE_INTERVAL` (2 minutes by default):

- Every 10 minutes, it lists the App's installations and the repositories each can read, signing
  a short JWT (RS256, nine minutes) with the key. Each installation gets an installation token,
  replaced when less than 10 minutes of its hour are left.
- For each repository a connected host serves, it lists the queued and in-progress runs and the
  queued jobs in them, with conditional requests: an unchanged listing is a `304`, free against
  the installation's hourly quota. A rate-limited installation is left alone until the time
  GitHub names.
- From 0.4.67 it also reads by its id each run a `queued` webhook named, until none of its jobs is
  queued (at most 4 such runs per repository per sweep, in turn, for at most 6 hours). GitHub's
  `status=queued` run listing can leave a queued run out for good; its jobs then waited with
  every host idle. A wake carries the run too, and a host on 0.4.67 or later reads that run by
  its id the same way.
- For each queued job that no wake was sent for within the interval (by the webhook or an
  earlier sweep), it wakes the hosts whose enabled profiles can take it. A job is identified by
  its repository and required labels.
- It tells every host, in a `hello_ack`, which of its targets the sweep covers: only the ones
  whose queues it could read this time. A repository it could not read (a missing Actions
  permission, a rate limit, a refused token) is not covered, so its hosts poll it themselves.

## Poll modes

Each of a host's targets is in one of three modes, shown per target by `runner-manager status`
(`coordinator.targets` in `--json`), `host doctor` (`github.polling`, `coordinator.link`),
`coordinator status` and the TUI dashboard:

| Mode | When | Polling |
|---|---|---|
| `standalone` | the host has not joined a coordinator | idle 10 s / active 60 s |
| `coordinated` | the link is up and the coordinator's sweep covers the target | every 300 s (`host set-poll-interval --coordinated 300s`, at least 60 s) |
| `fallback` | joined, but the link has been down for 30 s, or the target is not covered | idle 10 s / active 60 s |

In `coordinated`, wakes still bring a poll forward (at most one every 5 seconds), and a target this
host is running a runner for keeps the normal intervals, so a slot that frees up is used for work
that is already queued. A link that drops keeps `coordinated` for 30 seconds, so a quick reconnect
changes nothing; after that every target polls on its own again at once. A coordinator without a
GitHub App covers nothing, so its hosts are in `fallback` and behave as in stage 1.

The coordinator reads its GitHub App's installations and their repositories every 10 minutes, and
at once (at most every 30 seconds, followed by a sweep) when a host advertises a target those
listings do not include, or a webhook names a repository a host serves that they do not include. A
repository just added on a host is therefore normally covered within seconds. A repository listed
but unreadable (the App lacks Actions permission there) stays in `fallback` until that is fixed: a
fresh listing would change nothing, so none is asked for.

`repo add` and `host show` count a `coordinated` target at the coordinated interval (one poll every
300 s by default), not the refresh interval, and every other target at the refresh interval. A new
target has no coverage yet, because a coordinator only reports on what a host advertised. While the
link is up and the coordinator's sweep runs, a new repository is counted at the coordinated interval
too, and `repo add` prints a note saying so. A new organization is always counted at the refresh
interval, for what its repositories cost. With the link down, or no sweep, every target is counted
at the refresh interval as without a coordinator. `host set-poll-interval` refuses a shorter active
or coordinated interval that would take the configured targets over the budget.

A set admitted this way can exceed the host's budget (2,500 requests an hour) once its targets poll
on their own: the coordinator does not cover one, or the link stays down past 30 seconds. Charged
polls then stretch, on every target not waiting on the coordinator (including a coordinated one
running a runner), to the interval at which the targets polling on their own fit the budget at the
price `repo add` uses: 64 s for 11 repositories, 116 s for 20. Runners keep starting, and idle
polls, answered 304 and not charged, keep their pace. A set `repo add` would admit at the default
interval is not affected. This is pacing, not a guarantee: `host show` projects a higher worst case
per poll than `repo add` prices, and an organization counts as one repository here.

A dropped link reconnects after 1 second, then waits twice as long after every failed attempt,
never more than 30 seconds between attempts (a random part of up to a third of the wait spreads a
fleet out; a refused key or version waits up to 5 minutes). A connection that stayed up longer than
a minute starts that over, so hosts are back within about 30 seconds of a coordinator restart.

Upgrading to stage 4 moves the coordinator's database to schema 2 (three new tables). A stage-3
coordinator refuses to open it (`written by a newer coordinator`): to roll back, restore the
database from before the upgrade, or stop the service and run
`sqlite3 coordinator.db 'PRAGMA user_version = 1'` (the stage-3 code never reads the new
tables, and a later upgrade keeps them). 0.4.47 moved it to schema 4 (a `queue_wait_secs` column on the samples, a `live_state` table) and
0.4.48 to schema 5 (sample keys without the run's title); to roll back to 0.4.46, `sqlite3 coordinator.db 'PRAGMA user_version = 2'` the same
way (0.4.46 never reads the column, and upgrading again keeps it).

The protocol is versioned: a stage-1 host and this coordinator, or this host and a stage-1
coordinator, settle on version 1 and work as stage 1 did (the host is then in `fallback`).

## Shared pools

Without a coordinator, a job reaches a host through a label that host carries, usually its own
`rm-<host>-<os>-<arch>` selector. Two hosts carrying the same label both start a runner for the
same job, and the one that loses exits idle after wasting a slot. A **pool label** lets the
coordinator choose instead (design decisions D4 and D10):

| Label | Hosts |
|---|---|
| `rm-pool-linux` | Linux hosts (and a managed WSL distribution joined as its own host) |
| `rm-pool-windows` | Windows hosts |
| `rm-pool-macos` | macOS hosts |
| `rm-pool-any` | hosts of any OS that opted in (0.4.52) |

On each host, give the profile that should serve the pool its OS's pool label, or `rm-pool-any`
with `--any`:

```bash
runner-manager repo profile set-pool octo/app [--profile NAME] --pool on    # repository target
runner-manager org set-pool octo --pool on                                   # organization target
runner-manager repo profile set-pool octo/app [--profile NAME] --pool on --any   # rm-pool-any
runner-manager repo profile show octo/app --profile NAME                     # pool=rm-pool-linux,rm-pool-any
```

`set-pool` adds this host's own pool label, or with `--any` the OS-agnostic `rm-pool-any`;
`--pool off [--any]` removes it, and `add-label` with a pool label works the same way. A label in
the reserved `rm-pool-` namespace that is neither this host's OS pool nor `rm-pool-any`
(`rm-pool-windows` on Linux, or an unknown class such as `rm-pool-linux-heavy`) is refused. At
most one profile of a target on a host may carry each pool label: a pool job selects its profile
by that label alone, and two profiles matching one job fall under the existing rule that
overlapping profiles start no runner, so `set-pool` refuses the second one and names the first.
One profile may carry both its OS pool label and `rm-pool-any`, or two profiles may split them;
either way each pool job matches exactly one profile. The TUI's profile settings show a pool line
per pool label, ready to copy.

**`rm-pool-any`** is for jobs whose steps run on any OS the opted-in hosts have (a script in a
portable language, a container-free tool run): its candidates are every host whose profile for the
repository carries `rm-pool-any`, whatever its OS, and placement then chooses by its usual scores, so
as statistics accumulate the host measured fastest at that job wins. Only opt in a profile on hosts
where those jobs really work. A host directs an `rm-pool-any` profile by launches only when its
coordinator says it places that pool (`hello_ack.any_pool`, 0.4.52); with an older coordinator such a
profile counts its own demand, as in `fallback` (every host carrying the label may start a runner and
the surplus exits idle), so upgrade the coordinator before opting hosts in. A profile carrying both its
OS pool label and `rm-pool-any` stops being directed for its OS pool too under an older coordinator:
that coordinator keeps offering it launches it refuses, and its OS pool jobs start from its own reading
of the queue, at the coordinated poll interval (5 minutes) rather than at once. Keep the two labels on
separate profiles while an older coordinator may be in use.

Then switch the workflows that may run on any machine of that OS:

```yaml
jobs:
  build:
    runs-on: rm-pool-linux          # any Linux host of the pool; the coordinator picks one
  release:
    runs-on: rm-home-linux-x64      # still pinned to one machine by its own selector
```

Labels can be combined (`runs-on: [rm-pool-linux, gpu]`, `runs-on: [rm-pool-any, heavy]`): only
pool profiles carrying every label are candidates.

An exclusion keeps a pool job off some hosts (0.4.65, see the README's
[`not-<label>`](../README.md#keep-a-job-off-some-machines-not-label)):
`runs-on: [rm-pool-linux, not-wsl]` goes to a Linux pool host that is not a WSL distribution. A
profile is a candidate for `not-X` only when it does not carry `X`, and only on a host that says it
understands exclusions (`hello.label_exclusions`, 0.4.65): an older host would register a runner
without `not-X`, which GitHub never hands the job. The `launch` names the job's exclusions
(`exclusions`), the host registers the runner with them, and it refuses with `excluded` a launch
whose profile carries what it excludes. Every host of 0.4.65 or later advertises `wsl` or `not-wsl`
on all its profiles, so even an older coordinator places `not-wsl` jobs correctly. For any other
exclusion, a runner of the profile that was already waiting idle may be counted toward the launch
without carrying `not-X`; the job then waits until that runner exits idle (or the lease expires
and the job is placed again). A job asking for a label and its exclusion together is never placed
(`a queued job's labels can never be satisfied` in the coordinator's log, for the `queued`
webhook).

### How a host is chosen

When a pool job is queued (webhook `queued`, or counted by the sweep), the coordinator picks one
**candidate**: a connected version-3 host whose target serving the repository is covered by the
sweep, with an enabled pool profile whose labels cover the job, not unfit, not draining, and with
a free slot by its last heartbeat once the launches already sent to it are counted. With job
statistics it weighs the candidates (see [Weighted placement](#weighted-placement)); without
any for that queue it prefers a profile with a persistent workspace for that repository (a warm
checkout), then the most free RAM, then the fewest busy slots. Either way a **last resort** goes after
every other candidate (0.4.52): a host whose last heartbeat reports its CPU load at or above
`COORDINATOR_CPU_BUSY_PERCENT` (90 %), or less free disk on its runner root's volume than
`COORDINATOR_MIN_DISK_FREE` (10 GiB; low disk is the worse). It is not excluded: when no other host can
take the job now, it gets it. A host older than 0.4.52 reports its disk only at connect; that figure
is used until a heartbeat carries one. The CPU load is the share of the host's CPU time spent busy
between two heartbeats, 0 to 100 on every operating system from 0.4.60; an older Linux or macOS
host reports its one-minute load average over its CPU count instead, which can exceed 100 (the
dashboard shows it capped at 100). It sends that host a `launch` and waits up to 10 seconds for the
answer; a refusal (`max_capacity`, `host_capacity`, `memory` from 0.4.53, `unfit`, `draining`,
`disabled`, `not_coordinated`, ...) or no answer moves on to the next candidate. A host refuses with
`memory` when its own [memory admission](#memory-estimates-for-the-hosts-own-admission) would not
start the runner; like a capacity refusal it keeps the host a candidate for a job too big for the rest. A job no candidate can take
waits and is retried every 5 seconds, and at once whenever a host reports a runner ended or a
heartbeat with more free slots than its last one. A version-4 host of 0.4.47 or later sends that
heartbeat right after its `attempt_finished`, so a freed slot takes the next queued job within
moments rather than at the host's next heartbeat (15 seconds).

A host frees a native runner's slot when it concludes the attempt, before it deletes the runner's
files: cleanup never holds a slot. It concludes the attempt on its target's next pass, and while
it is joined the host checks every 2 seconds whether a live runner's process has exited and, if
so, runs that pass at once (at most 5 seconds after the previous one) instead of at the target's
next scheduled poll (up to 60 seconds later). So a slot frees within about 5 to 10 seconds of the runner's
process exiting, and `attempt_slot_released` in the host's log says how long it took from when that was
seen (`exit_to_report_ms`; `attempt_slot_release_slow` above 15 seconds). Two things still delay it: a
target GitHub has asked to slow down, whose pass waits for that, and a target with a profile outside
coordinated placement, whose pass waits while it brings up the runners it decided to start itself. A pass
waits for no coordinator launch. The host cannot see when a job ended, only when its runner exited; a runner
that outlives its job for a while holds its slot for that while. A runner in a container, a VM or a WSL distribution
keeps its slot until its environment is proven gone and cleaned up, deliberately: until then it
may still be running. Its host sends a heartbeat as soon as that cleanup is done.

A launch is a **lease** for 2 minutes (`COORDINATOR_LEASE_TTL`, `--lease-ttl`, at least 30
seconds). GitHub hands a runner *any* queued job its labels cover, so the coordinator counts per
repository and label set: it never holds more leases than jobs are queued. When a lease's runner
takes a job (the host's `attempt_started`) the lease is held until the webhook takes that job out
of the queue (at most 30 seconds), so the job is not placed twice meanwhile. A lease also closes,
and its job, if still queued, is placed again at once:

- when its attempt ends (`attempt_finished`), unless its runner exited idle: that runner took
  nothing, so the host keeps the launch and starts another runner, or gives it to another waiting
  runner;
- when its host disconnects or connects again (a new link starts with no launch: the host
  dropped its open ones when it lost the old link, even one that never closed cleanly);
- when its host's heartbeat no longer lists it: a 0.4.47 host names the launches it still
  holds open in every heartbeat, after the attempt reports that would explain a missing one;
- when another runner of the same host takes a job of the same queue (the webhook names the
  runner): a runner started for no lease, or for a dropped one, took the job the lease's runner
  was coming for, so the host is told to drop that launch;
- when it expires. When a job leaves the queue another way (cancelled, or taken by a runner
outside the pool), the surplus lease is cancelled (`cancel_launch`) and its host starts no runner
for it. The sweep's listing corrects lost webhooks, job by job; a listing GitHub truncated only ever adds
jobs.

A queue left with fewer runners on their way than jobs says why, at most once a minute per queue
in the log (`a pool queue is not placed`, with `reason` and, for a refusal, `refusal`) and in
`stats`: `no_candidate` (no connected, covered host serves it with an enabled pool profile),
`unfit_or_draining`, `no_free_slot`, `no_memory_fit`, `refused` (the last host tried refused:
`max_capacity`, `host_capacity`, ...), or `unanswered`.

### On the host

A pool profile is **directed** while its target is `coordinated` on a version-3 link: for pool
jobs it starts runners only for the launches it accepted, never from its own reading of the queue
(which every host of the pool sees the same way). A job the profile covers that asks for no pool
label (`runs-on: [self-hosted, macOS]` on a profile that also carries `rm-pool-macos`) is not placed
by the coordinator, which only wakes every host serving it; the profile serves such jobs from its own
reading, in the pass that read them, as every host carrying those labels does (0.4.70; before, they
waited in the queue with every host of the pool idle). Move a workflow's jobs to the pool label to
have them placed. It accepts a launch only when its own allocator, over its
own attempts and ceilings, grants one more runner, counting the launches its other profiles hold
open: slots are the host's. A launch it can no longer start (another profile's runner took the
slot since) is dropped, newest first, and the next heartbeat, sent at once, closes its lease; so is
one no runner could be started for since 45 seconds ago (a warning in the host's log). Waiting a turn
does not count, and neither does a runner still being brought up: the heartbeat goes on listing that
launch, which renews its lease at the coordinator, for up to 15 minutes. A launch whose runner is up
and took no job keeps the lease's lifetime. A heartbeat's free slots leave out the ones its launches with no runner yet have spoken for.
Accepted launches start their runners at once:
the link signals the target's loop, which starts every launch open at that moment in one go,
without polling GitHub, so the 5-second gap between polls does not apply; the next full pass
stays where it was scheduled. Each runner's slot is reserved and journalled one after another under
the host-wide allocation lock, the same lock every pass takes, so the ceilings hold exactly. The lock
is then released: runners of all targets of the host get their packages and register at the same time,
oldest first. A quarter of its cores (at least two) prepare at once; registration is not bounded. A
daemon that dies in between leaves a journalled attempt, which startup recovery concludes.

Launches do not wait for their target's pass. Each target serves its launches beside its passes, so one
accepted while the pass polls GitHub or brings up a batch is reserved and brought up at once, through the
same lock and the same journal, so every ceiling and the per-repository counts hold as before. A pass does
not supervise a runner still coming up: it has no process and no registration yet, and supervision starts
at the first pass after it is up or has failed. Draining stops new launches and waits for those coming up.

Launches reserve in the order this host accepted them, across its targets and profiles: a launch reserves
after the older launches of the host that may still reserve. A reservation is a lock hold and a journal
write, and everything slow comes after it and runs at the same time, so this order costs a burst only those
writes, however large the burst. The older launch does not hold a younger one up for long if it cannot
reserve at all (a target added a moment ago that has no loop yet, a profile the host cannot start now): 2
seconds with no older launch reserving passes it over, once (`older_launch_passed_over` in the log), and a
launch whose start failed is not waited for. A launch whose runner exited idle waits again behind those
already waiting.

A slow launch is a warning in the host's log, `attempt_launch_slow`, saying where the time went:
`order_wait_ms` (older launches reserving first), `lock_wait_ms`, `turn_wait_ms`, `materialize_ms` (of which `package_wait_ms`, `package_install_ms`,
`package_verify_ms`, `package_copy_ms`, and `package_downloaded`), `prepare_ms`, `register_ms`,
`spawn_ms`. The first launch after a daemon starts downloads the package again: a tree this process
did not install may hold a job's edits. After that, it is shared by every target, and each launch's copy
is read against the package's archive (see [Shared runner packages](#shared-runner-packages)), which
`package_verify_ms` counts.

A download that sends nothing for 60 seconds, or cannot connect in 30, fails and is tried again; a slow one
that keeps sending takes as long as it takes. Its partial file is removed and was never going to be used: an
archive is only unpacked once its digest matches. The launches queued behind a download that failed get its
failure, and retry on their own back-off, rather than each spending another stall in turn.

A repository added or removed on a host (`repo add`, `repo remove`, a profile enabled or disabled)
changes only its own target loop: a new target gets a loop of its own within 30 seconds, a removed
one has its loop finish its runners and stop. The coordinator link, its accepted launches (unless
their profile is gone) and every other target keep running; the link describes the new set of
targets at its next heartbeat. When the last repository goes, the daemon finishes its runners and
reloads as before. In `fallback` and `standalone`, against a
version-2 coordinator, or without the GitHub App's sweep, a pool profile is an ordinary profile:
it polls and starts runners from its own demand, and a surplus runner exits idle as before.

Hosts and coordinators of different versions keep working together: a version-2 host serving a
pool label is woken for pool jobs as in stage 2 and computes its own demand; a version-3 host
connected to a version-2 coordinator never sees a launch and serves its pool profiles from its
own demand. A version-3 host connected to this (version-4) coordinator reports no usage: its
attempts count towards durations only. Against a version-3 coordinator, a version-4 host's link
works as before and `coordinator stats` says the coordinator is too old.

## Job statistics

### What a host measures

While a host has joined a coordinator (or, from 0.4.53, while its memory admission is on), every 2
seconds it looks at the process tree of each live **native** runner of its own policies, on a worker thread so its reconcile loop never waits:

| OS | How |
|---|---|
| Linux | `/proc/<pid>/stat` of every process: parent, CPU ticks (with reaped children's), resident pages |
| macOS | `proc_listallpids`, then `proc_pidinfo` (`PROC_PIDT_SHORTBSDINFO` for the parent, readable for any account, so a `sudo` step stays in the tree; `PROC_PIDTASKINFO` for resident size and CPU time) |
| Windows | one Toolhelp snapshot for the parent links, then `GetProcessMemoryInfo` (working set) and `GetProcessTimes` per process; a process created before its supposed parent names a dead parent whose PID was reused and is not counted. Native runners run in no Job Object, so there is no job accounting to read. |

When the attempt ends, its `attempt_finished` carries `usage`: the tree's peak resident memory
(summed per process, so shared pages count more than once; the coordinator caps it at the
host's memory), its average CPU over the attempt and its busiest 2-second interval (in
thousandths of a CPU), and how many samples were taken. CPU is the sum of the increases of the
tree's CPU time between looks, so a process that exits loses at most its last 2 seconds. The
average CPU and the host's `duration_secs` are the attempt's, from its creation to its end:
runner start, idle wait for a job and cleanup included. A sample's duration is not (see below).

What is not seen: a runner in a container, a VM or a WSL distribution (no host process to look
at, no usage reported); work that leaves the tree, such as `container:` jobs and `docker build`
run by `dockerd`, or daemons that detach (a Gradle daemon, a `nohup` server); disk growth of the
workspace (walking a checkout every few seconds is not cheap). The figures are a floor for such
jobs.

### How a sample is kept

GitHub's `workflow_job` webhooks `in_progress` and `completed` name the runner that took the job
together with the repository and the job (matrix values included, as GitHub expands
them: `build (ubuntu, 3.12)`), and the job's `created_at`, `started_at` and `completed_at`. The
coordinator remembers that only for runner names `runner-manager` registers
(`runner-manager-...`), joins it with the host's report of the same runner name, in whichever
order they arrive (a report waits up to 15 minutes for its job to be named, a webhook 6 hours for
its report, 10,000 of each at most, the oldest dropped first), and stores one sample per attempt
that ran a job, completed or failed (an out-of-memory kill is what placement must learn), under
the job's key with the host that ran it. An attempt that exited idle is not a sample.

A job's key is `owner/repo/job`, and the workflow file (`.github/workflows/ci.yml`) of its run when
that is known, so jobs of the same name in two workflows keep apart. GitHub's `workflow_name` on a job
is the run's title, which a `run-name` changes at every dispatch, and nothing else on a webhook names
the workflow, so the file comes from the run: from the sweep's listing, or from one request per run
(`GET .../actions/runs/{id}`) the first time a webhook names a run of a pool job or of a
`runner-manager` runner and no sweep has listed it. So it needs the GitHub App; without one every key
is the job alone, as it was. A request that fails is not repeated, and that run's samples are kept
under the job alone, which is also where samples from before 0.4.50 stay, with no migration.

What weighs a job: its workflow's samples, and until it has enough, those kept under the job alone too. A
queued job whose workflow is not known yet counts every sample of its name, in any workflow, so it
does not read as never measured; it can then be estimated from the other workflow's job, until a sweep
names it. A workflow's own samples stand alone once 3 of them measured memory. `stats` lists each key as it was kept: `octo/app/build [.github/workflows/ci.yml]`. To roll
back, nothing needs doing: an older coordinator reads a key with a workflow as a job it never sees
queued, and goes on from the samples under the job alone.

A sample's **duration** is the job's own run time, `started_at` to `completed_at`, so a 14-second
job reads 14 seconds and not the minute its runner lived. A job that did not succeed has none, since how
fast it failed says nothing of its host; its memory still counts. Its **queue wait** is `created_at` to
`started_at`: how long the job waited for a runner, which placement exists to keep short. A report
whose job is named waits 2 to 3 minutes for the `completed` webhook (normally seconds away, in
either direction); if it never comes, the sample is recorded with the host's attempt duration
instead. Samples recorded before 0.4.47 carry the attempt duration and no queue wait; the newest
30 per job replace them.

The SQLite database keeps the last 30 samples per key (`COORDINATOR_STATS_SAMPLES`, 1-1000) and
drops any older than 90 days. From them: p50 duration, p50 and p90 queue wait, p90 peak memory,
p90 average CPU, and per host its median duration over the usual one (the mean of every host's
median).

### Weighted placement

A runner takes any queued job its labels cover, so placement weighs a pool **queue** (repository
and labels), not a single job:

1. **Demand**: the heaviest expected peak memory among the jobs queued there. A job's expected peak
   is its p90, or more if one of its 3 newest samples needed more: over 30 samples a p90 alone would
   go on reading a job that turned heavy as light for three more runs. A job never measured
   counts as its repository's p90 (over all its samples); a repository never measured as
   `COORDINATOR_DEFAULT_JOB_RAM` (2 GiB). The sweep names the jobs it lists just as a webhook
   does (same job id and name), so a job only the sweep saw is weighed by its own
   samples. A job never measured, or with no name to go by, counts as the repository's p90 or the
   default.
2. **Filter**: a host whose free memory (by its last heartbeat) less the estimates of its
   launches whose runner has not taken a job yet cannot hold the demand plus
   `COORDINATOR_RAM_MARGIN` (512 MiB) is passed over. A host that reports no free memory is not
   filtered. Each launch reserves the queue's next heaviest job, so one heavy job among light
   ones counts once; the host must still hold the heaviest job, since a runner can take any of
   them. "Free memory" is what the OS says new work can have: Linux's `MemAvailable`, Windows'
   available physical memory, macOS's free, file-backed and purgeable pages. Only the jobs' own samples filter: a job never measured counts for the estimate and the ranking,
   not the filter, so another job's heavy samples never keep it waiting, though it may land on a host
   too small for what it turns out to need. It reserves at most `COORDINATOR_DEFAULT_JOB_RAM`. Nor is anything filtered when the
   demand plus the margin is more than the total memory of every host that serves the queue, a host
   with no slot free just now or whose refusal says only that its slots are taken included: no host could
   ever hold it, so the job runs where the score says. When the biggest hosts are all free to take it, idle and still too
   short, what holds their memory is nothing placement can wait out, and the job runs on one of them.
   Otherwise the job waits for a host big enough, and does not start on one too small because that
   host's slots are taken. The estimates of a host's launches stay reserved
   for 2 minutes after their runner took its job, while the build's memory ramps up, or until
   that job ends, whichever is first; and until that job ends they count against the host's total
   memory, since a build's peak can come after those 2 minutes with its host's heartbeat showing that
   memory free until then. That survives a broken link, and ends at the attempt's report, when the host's
   heartbeat says it runs fewer jobs than are held for it (the largest are kept), or after 6 hours. Once a webhook names the job a launch's runner took,
   the launch reserves that job's expected peak rather than the queue's next heaviest, and a runner with
   no lease left counts for the job it took.
3. **Score** = `cache` x warm workspace (0 or 1; 0 when, after at least 3 runs of a job, this host is measured more than 10% slower
   than usual at it, since measured durations already hold what its checkout saves) +
   `headroom` x (memory free after the job, as a share of the host's memory) + `speed` x (how much
   faster than usual this host ran these jobs, -1 to 1; a host that never ran a job other hosts have
   run counts as 1 for it until its first run finishes, or the host with the most headroom would keep
   every job and the others would never be compared; a warm host, or much more headroom, still outscores
   this, and a host whose samples have aged out of the 30 kept counts as not having run it) + `cpu` x
   (its idle cores, cores x (1 - CPU load) by its last heartbeat, as a share of the most any candidate has
   idle; 0 for a host that reports no CPU load) - `bigfit` x (1 when the
   heaviest measured queue waiting elsewhere needs at least twice this one's memory and fits only
   this host of this queue's candidates, and this queue fits another).
4. **Order**: hosts that fit first; among them, last resorts (busy CPU, then low disk) after the rest;
   then the best score, ties in stage 3's order. With no statistics at all for the queue, stage 3's
   order alone after the last-resort rule: warm workspace, most free memory, fewest busy slots.

A runner takes any job of its queue, so a runner started for a light job can take a heavy one queued
after it, and a host starts a launch's runner at once, so cancelling the launch does not stop it. For the
same reason a queue's light jobs wait with its heaviest: while a heavy job waits for memory, a runner
started for a light one elsewhere could take the heavy one instead. A job waiting for a big host has no
priority over what else that host is given, so a busy host of another queue can keep it waiting. Jobs that
are much heavier than their neighbours do best with **a label of their own**
(`runs-on: [rm-pool-linux, heavy]`), which makes them a queue of their own: in the simulation in
`crates/coordinator/tests/balance_sim.rs`, the light jobs' median wait falls from up to minutes to the 15
seconds a runner takes to come up, and no heavy job lands on a host too small once measured.

Weights are set with `COORDINATOR_PLACEMENT_WEIGHTS` (`--placement-weights`), any subset of
`cache=4,headroom=2,speed=1,bigfit=1.5,cpu=1`, each 0 to 100. What makes a host a last resort is set
with `COORDINATOR_CPU_BUSY_PERCENT` (`--cpu-busy-percent`, 1 to 100, default 90) and
`COORDINATOR_MIN_DISK_FREE` (`--min-disk-free`, default `10GiB`). For example, a fleet where checkouts are
cheap but one host is much bigger than the rest:

```yaml
services:
  coordinator:
    environment:
      COORDINATOR_PLACEMENT_WEIGHTS: cache=1,bigfit=3
      COORDINATOR_DEFAULT_JOB_RAM: 4GiB
```

Every decision is logged with host ids, the estimate in bytes, where it came from and the scores
(per host at `debug`), never a repository, workflow, job or runner name, and the last 50 are kept
in the database. `a pool queue was weighed`, and `a pool queue is not placed` with `no_memory_fit`, say
what decided the fit for the candidate nearest to fitting: `free_ram_bytes` (its last heartbeat),
`reserved_bytes` (its open launches), `committed_bytes`, `ram_margin_bytes`, `required_bytes` (absent when no job is measured,
or no host could ever hold it, so nothing is filtered) and `total_ram_bytes`. A host fits when free less
reserved, and total less `committed_bytes` (every launch and job on it not yet ended), both hold required plus
margin, so a low or stale free figure can be told from memory spoken for. From 0.4.52 it also carries the
chosen host's `chosen_cores`, `chosen_cpu_load_percent`, `chosen_disk_free_bytes` and `chosen_last_resort`
(`cpu_busy`, `low_disk`, absent when none), how many candidates were `last_resorts`, and the
`cpu_busy_percent` and `min_disk_free_bytes` in force; the per-host `placement score` lines carry
`cores`, `cpu_load_percent`, `disk_free_bytes`, `last_resort` and the `cpu` points.

### Memory estimates for the host's own admission

From 0.4.53 a host checks its free memory before it starts any runner, its own demand included
(README, "Keep heavy jobs from crowding one machine"). On a version-4 link the coordinator sends it,
after each `hello` and whenever the figures change (looked at every 60 seconds), a
`memory_estimates` message: for each of the host's targets with measured jobs, the heaviest job
key's expected peak (its p90, or a heavier one of its newest three runs), taken from that host's own
samples once it has any for the target (a job measured only on other hosts, such as another OS's
build, is likely one its labels never take) and from every host's otherwise, with the sample count
and whether only its own runs spoke. Targets are named once however their case varies, and the
message is trimmed to fit one frame. A runner takes any job its labels match, so one figure per target
stands for its heaviest job. A target never measured is left out, and the host falls back to the
p90 of the peaks it measured itself, then to 1 GiB; it also forgets the coordinator's figures when the
link ends. A host older than 0.4.53 skips the message as
one it does not know; a coordinator older than 0.4.53 never sends it, and reads a `memory` refusal
as `other`.

### Reading `stats`

On the coordinator's machine, `runner-manager-coordinator stats [--json]`; on any joined host,
`runner-manager coordinator stats [--json]`. The host opens a **query session** of its own: the
same signed challenge as its link, then one request and one answer; the daemon's link is not
replaced and stays up. A boot-mode host needs administrator rights to read its key, as `join`
does. A coordinator older than version 4 is reported as such.

```text
Job statistics: the last 30 samples per job, kept 90 days
  launches accepted 41, wakes sent 312, samples recorded 97
  queue wait (queued to started): p50 3s, p90 41s

Heaviest jobs (p90 peak memory, p90 CPU, p50 run time, p50/p90 queue wait, samples):
  octo/app/build (linux, 3.12)
      6.2 GiB  3.40 cores  11m 05s  wait 4s/52s  (14)
      on linux (4f1c...)            9 samples  p50 9m 50s  0.85x the usual time
      on win-big (77aa...)          5 samples  p50 13m 10s  1.14x the usual time

Samples per host:
  linux (4f1c...)                 61 samples over 9 jobs, p90 peak memory 4.1 GiB

Last placements, newest first (scores in points):
  2m 10s ago  octo/app [rm-pool-linux] needs 6.2 GiB (job), weighted: 4f1c...
      4f1c...   fits     free after 38.0 GiB   cache 0.00 headroom 1.18 speed 0.15 cpu 0.80 bigfit -0.00 = 2.13  (cpu 12%, disk free 210.4 GiB)
      9b20...   too full free after 0 MiB      cache 4.00 headroom 0.00 speed 0.00 cpu 0.10 bigfit -0.00 = 4.10  (cpu 93%, disk free 6.1 GiB)  last resort: low disk

Connected hosts:
  4f1c...                  linux     32 cores  cpu  12%  ram free 40.2 GiB   disk free 210.4 GiB  slots 6 free 2 busy
```

- **Queue wait**: queued to started over every kept sample, then per job. A p90 that grows
  means jobs wait for a free host.
- **Heaviest jobs**: the 20 job keys with the largest p90 peak memory, and per host how its
  median compares with the usual duration (below 1x: faster).
- **Pool queues waiting for a runner**: each queue (repository and labels) with fewer runners
  on their way than jobs queued, the oldest job's wait (since the coordinator first saw it), and why
  no more is placed (see above).
- **Connected hosts** (0.4.52): each connected host's OS, cores, and by its last heartbeat its CPU
  load, free memory, free disk on its runner root's volume and slots, as live or as saved as the
  open leases below. `--json` adds `connected`; `decisions[].scores[]` add `cpu`, `cpu_load_percent`,
  `disk_free_bytes` and `last_resort`.
- **Open leases**: per host, each launch not yet closed, its state (`offered`, `accepted`,
  `claimed`) and age. On a host's `stats` these are live; the admin CLI on the coordinator's
  machine reads the copy the server saves every minute (`as of ... ago`).
- `--json` is schema version 3 since 0.4.47: `p50_duration_secs` is the job's run time,
  `p50_queue_wait_secs` / `p90_queue_wait_secs` are added (overall and per job), and `pending`,
  `leases` and `live_at`. Schema version 4 since 0.4.52 adds `connected` and the scores'
  `cpu`, `cpu_load_percent`, `disk_free_bytes` and `last_resort`.
- Names are printed with control, bidirectional and zero-width characters removed: a workflow
  or job name is whatever a pull request wrote.
- **Last placements**: what the queue was estimated to need and why (`job`, `repository` or
  `default`), `weighted` or `stage3`, the host chosen (or `no host fits`, shown at most once a
  minute per queue), and every candidate's score parts. A host marked `too full` was passed
  over whatever its score.
- The counters are all-time; launches and wakes reach the database within a minute.

Repository and job names in `stats` come from your own repositories' webhooks; they
are shown to your enrolled hosts and on the coordinator's machine, never logged.

## Enroll a host

On the coordinator's machine, issue a one-time code (valid 15 minutes by default, usable once;
only its hash is stored):

```bash
docker compose exec coordinator runner-manager-coordinator invite --name win-big [--ttl 30m]
```

On the host:

```bash
runner-manager coordinator join https://runners.example.com --code rmc_...
runner-manager coordinator status
```

`join` creates an Ed25519 key pair. The private key goes into the same secret store as the
GitHub credential (System Keychain, DPAPI, or the protected file on Linux, per the host's start
mode); the coordinator stores only the public key. On a boot-mode host run `join` with
administrator rights, as `auth login`. The running service picks the setting up within 15
seconds; no restart is needed. Every connection is a fresh challenge: the coordinator sends a
random nonce and the host signs it together with the coordinator's origin.

`status`, `host doctor` (check `coordinator.link`, information only) and the TUI dashboard show
whether the link is connected, or disconnected since when and why.

## Administer

```bash
docker compose exec coordinator runner-manager-coordinator hosts list [--json]
docker compose exec coordinator runner-manager-coordinator hosts revoke win-big   # name or id
```

A revoked host's live connection is closed within a second and it cannot reconnect. The admin
command is another process writing the same SQLite file, so the server watches SQLite's
`data_version` (changed only by another connection's commit, read without a query) every 500 ms
and, when it moved, closes the connections of hosts that are no longer active. There is no admin
endpoint to signal it, on purpose: see the security notes.
To move a host to a new key, revoke it, issue a new invite, then on the host run
`runner-manager coordinator leave` and `join` again.

## Back up and restore

The compose file runs a `backup` service: once a day (at its first start, then whenever the newest copy is
a day old) it copies the database with `VACUUM INTO`, which is safe while the coordinator is writing, checks
the copy with `PRAGMA integrity_check` and that it holds tables, and keeps the last 7 as
`coordinator-<UTC time>.db`, mode `0600`, in the `coordinator-backups` volume. A failed run says so in
`docker compose logs backup`, keeps nothing, removes no earlier copy, and tries again in an hour; the time of
the newest file is the way to check it is working.

That volume is on the same disk as the database, which protects against a bad upgrade or a damaged
database and not against losing the disk. To keep the copies elsewhere, replace the volume with a path on
another disk, owned by account 10001 (`sudo chown 10001:10001 /mnt/backups/coordinator`), in
`docker-compose.override.yml`, or copy them off the machine:

```yaml
services:
  backup:
    volumes:
      - coordinator-data:/data
      - /mnt/backups/coordinator:/backups
```

The copies hold what the database holds: enrolled hosts' names, hostnames and public keys, when each was
last seen, hashes of invites, repository and job names, statistics and placement decisions. No GitHub
credential is in there, nor the webhook secret. Treat them as private all the same.

To restore, stop the writers, run `backup.sh restore` with the copy's name through the backup image, and
start again. It stops nothing itself, so run it only with the coordinator stopped. It refuses a name that
is not one of its copies and a copy that fails `PRAGMA integrity_check`, leaving the database as it was;
otherwise it replaces the database and removes the old one's WAL files. Hosts reconnect on their own; a
host enrolled after that copy was made must `coordinator leave` and join again with a new invite. Samples and counters since the copy are lost.

**A restore undoes what happened since the copy, revocations included.** A host revoked since then is
accepted again, and an invite used since then, if it has not expired, can be used again. After restoring,
run `hosts list` and revoke again whatever you revoked since that copy was made, before you expose the
coordinator again if you can.

```bash
docker compose stop coordinator backup
docker compose run --rm --no-deps --entrypoint ls backup -1 /backups
docker compose run --rm --no-deps backup restore coordinator-20261109T030000Z.db
docker compose up -d
```

A copy from an older version is upgraded when the coordinator opens it. One from a newer version is refused
(`written by a newer coordinator`): see the rollback notes under [Poll modes](#poll-modes).

## Web dashboard

The coordinator can serve a dashboard at its public address (`https://runners.example.com/`):
the machines with their CPU, memory, disk and runner slots, the jobs queued and running on
self-hosted runners, the last jobs to finish, pool queues and leases, and a week of history as
charts (jobs queued and running, CPU, busy slots and memory per machine). It works on a phone as
well as a desktop, and follows the system's light or dark theme.

Only GitHub accounts you name get in. Sign-in is GitHub's OAuth web flow; the GitHub token it
yields is used once to read who signed in and is dropped. The session is a random cookie
(`HttpOnly`, `Secure`, `SameSite=Lax`, 30 days); the database keeps only its SHA-256, so a backup
signs nobody in. A login taken off the list is out at its next request. Without the settings
below the dashboard does not exist: its paths answer 404.

1. On GitHub, **Settings → Developer settings → OAuth Apps → New OAuth App**: any name, homepage
   `https://runners.example.com`, authorization callback URL
   `https://runners.example.com/auth/callback`. Generate a client secret. (The App from
   [Connect GitHub](#connect-github-a-personal-github-app) works too, with the same callback URL
   added; a separate OAuth App keeps the two apart.)
2. On the server, beside `.env`:

   ```bash
   printf '%s' 'THE_CLIENT_SECRET' > dashboard_client_secret && chmod 600 dashboard_client_secret
   sudo chown 10001:10001 dashboard_client_secret     # the coordinator image's account
   cat >> .env <<'ENV'
   COORDINATOR_DASHBOARD_CLIENT_ID=Ov23li...
   COORDINATOR_DASHBOARD_USERS=your-login,a-colleague
   ENV
   ```

   and in `docker-compose.override.yml`:

   ```yaml
   services:
     coordinator:
       environment:
         COORDINATOR_DASHBOARD_CLIENT_SECRET_FILE: /run/secrets/dashboard_client_secret
       secrets:
         - dashboard_client_secret
   secrets:
     dashboard_client_secret:
       file: ./dashboard_client_secret
   ```

3. `docker compose up -d`. The log says `no dashboard sign-in is configured` while any of the
   three is missing.

The page loads nothing from elsewhere (GitHub avatars aside) and is served with a strict
Content-Security-Policy. History is a sample a minute per machine, kept 7 days in the same
database (schema 6, from 0.4.58). On a wide range the charts average the samples into fewer
points (about 90 per line, 48 columns), aligned to whole periods so a refresh does not reshape the
past: jobs and busy slots as stacked columns, CPU as a row per machine with its average and peak,
memory as a line per machine.

The job lists are built from the `workflow_job` webhooks. From 0.4.66 they are saved every minute
and at shutdown, and restored at start when the save is under an hour old, so an update no longer
empties them. What the restart missed is settled afterwards: a restored queued job the sweep no
longer lists left the queue, and a running job whose runner its machine no longer lists ended. A
machine on 0.4.66 or later lists its runners in every heartbeat from the moment each starts, so
the Running list names the machine as soon as a job starts (before, it waited for the machine to
notice the job, and a job of a few seconds often never got a machine). Such a machine also reports
its disk's size, shown as used / total.

A Windows machine's card names the version of the WSL distribution it manages: the one its own
WSL host runs when exactly one WSL host shares the machine's name, else what `wsl install` last put
there (which an update inside the distribution leaves behind).

Without a proxy in front, forward `/`, `/assets/*`, `/auth/*` and `/api/*` as well as the four
endpoints in [Deploy](#deploy).

## Remote management

A person signed in to the coordinator can read, and where allowed change, the repositories and
limits of a host that joined it, from the dashboard or from `runner-manager` on any machine. It
needs the [web dashboard](#web-dashboard) configured, and hosts and coordinator at 0.4.61 or later
(protocol version 5).

### What a host allows

The coordinator only relays `runner-manager` arguments; the host parses them and decides. It runs
nothing outside this list, and never anything that signs in, installs, removes the service, or
addresses another host (`--host`, `--data-dir`):

| Kind | Commands | Answered |
| --- | --- | --- |
| Read | `status`, `host show`, `repo list [--json]`, `repo profile list`, `repo profile show` | always |
| Change | `host set-capacity`; `repo add`, `remove`, `set-capacity`, `set-scale`, `add-label`, `remove-label`, `set-workspace`; `repo profile add`, `remove`, `set-capacity`, `set-scale`, `add-label`, `remove-label`, `set-workspace`; `update` (from 0.4.64, no flags) | only after `runner-manager coordinator remote-changes allow` **on that host** |

Changes are off until the host's own operator turns them on there:

```bash
runner-manager coordinator remote-changes allow    # on the host; `deny` takes it back
runner-manager coordinator remote-changes status
```

The host runs a command as its service would, in its own data directories, and answers with the
command's exit code and output (up to 48 KiB). The running service tells the coordinator within a
minute when the choice changes; the dashboard and `coordinator hosts` show it.

### Versions and updates

From 0.4.64 each host's heartbeat names its runner-manager builds, and the dashboard shows them on
the machine's card and in its panel:

- **service**: the build the service runs now;
- **app**: the installed binary the service was installed from and upgrades itself from (npm,
  Homebrew, the release archive, `cargo install`), usually the `runner-manager` on the machine's
  command line;
- on Windows, the version each managed WSL distribution was last given by `wsl install`. A WSL
  distribution is a host of its own at the coordinator, with its own service and app, marked WSL.

An app newer than the service means the service is finishing its jobs before it restarts into it.

**Update** in a machine's panel sends `update` to the host. The host answers at once that it
started, and in the background does what its daily automatic update does: it updates the app to
the newest GitHub release through the channel that installed it (the release archive is checked
against the release's `SHA256SUMS`; npm, Homebrew and cargo install from their own registries,
npm and cargo pinned to that release's version); the coordinator names no version and no source.
The service then stops taking new jobs, waits for its running ones without a deadline, and
restarts into the new build. The dashboard shows the progress and how it ended, with the end of
the package manager's output when it failed; the audit trail records only that it was started.

A host refuses, and says why, when its operator turned automatic updates off (`host
set-auto-update false`), when its service was installed from a build in a checkout (a release
binary that `update --force` put at such a path, with the copy it keeps beside it, is updated like
the release archive), and when its service runs as root and the app belongs to another account (a
Homebrew prefix, an nvm npm). A WSL distribution is updated through its own host.

### Sign in the CLI

```bash
runner-manager coordinator login                     # the coordinator this host joined
runner-manager coordinator login --url https://runners.example.com
```

`login` prints a link and a code (and opens a browser on a desktop). Open the link in a browser
signed in to the dashboard (or sign in there; you come back to it), check that the page shows the
same code, and approve. The person is checked against the same `COORDINATOR_DASHBOARD_USERS`
list as the dashboard; the machine's enrollment key plays no part. The CLI is then handed a
session token for 90 days, kept in the user-scoped secret store of whoever ran `login` (a `0600`
file under `~/.local/share/runner-manager/secrets` on Linux, DPAPI on Windows, the login keychain
on macOS), never in the service's. `runner-manager coordinator logout` ends it on both sides. A
login taken off the list is refused at its next request, as in the browser.

### Run a command on a host

```bash
runner-manager coordinator hosts                     # name, online, manageable, remote changes
runner-manager --host remote:ivan-ms-a2 repo list
runner-manager --host remote:ivan-ms-a2 repo set-capacity octo/app --max-capacity 4
runner-manager --host remote:ivan-ms-a2 status
```

`NAME` is the host's name at the coordinator (or its id). The output and the exit code are the
host's own, its refusal included. Before anything is sent, `--host remote:` says when this account
is not signed in, names the hosts when `NAME` is not one, and says when the host is offline or too
old to take commands; the coordinator waits up to a minute for an answer.

### HTTP

| Method and path | Who | Answer |
| --- | --- | --- |
| `POST /auth/cli/start` | anyone, rate-limited per address | `{"device_code", "user_code": "BCDF-GHJK", "verification_url", "interval_secs": 3, "expires_in_secs": 600}` |
| `GET /auth/cli?code=` | a browser | the approval page (Approve / Deny) |
| `POST /auth/cli/approve` | a browser's session cookie, this origin | form `code`, `decision=approve\|deny` |
| `POST /auth/cli/poll` | the CLI, `{"device_code"}` | `428 {"status":"pending"}`, `403 denied`, `410 expired`, or once `200 {"token", "login"}` |
| `POST /auth/cli/logout` | `Authorization: Bearer` | `204` |
| `GET /api/overview` | a session | hosts with `online`, `manageable`, `remote_changes`, and from 0.4.64 `versions` (`service`, `app`, `app_source`, `updatable`, `update`, `wsl`, `wsl_guest`) |
| `POST /api/hosts/{id}/command` | a session; a cookie also needs this origin | `{"argv": [...]}` to `{"request_id", "exit_code", "stdout", "stderr", "truncated"}`; `503` offline, `409` too old, `504` no answer |
| `GET /api/hosts/{id}/config` | a session | the host's `repo list --json` and `remote_changes` |
| `GET /api/audit` | a session | the last 100 remote commands |

Every `/api/*` route takes the browser's cookie or the CLI's `Authorization: Bearer <token>`. A
token is only accepted as a bearer token and a cookie only as a cookie; a bearer request needs no
`Origin` (a browser never sends the header on its own), and a token cannot approve another
sign-in. Pending sign-ins are kept in memory for 10 minutes (a restart forgets them), the device
code by its hash only; sessions are kept by their SHA-256 (schema 8 marks each `web` or `cli`).

### The audit trail

Both sides record every command: the coordinator in its database (`remote_commands`: when, who,
which host, the arguments, how it ended, the newest 1000; `GET /api/audit` and the dashboard show
them), and the host in `state/remote-commands.jsonl` beside its other state (when, by whom, the
arguments, the exit code; moved to `.jsonl.1` at 1 MiB). The coordinator's log carries the host and
the outcome only, never the arguments.

### Security model

A person on the allowlist, or anyone holding their session, can read every host's repositories
and limits, and change those of hosts that allowed changes. So can anyone who controls the
coordinator itself: a compromised coordinator can change, within the list above, any host that
ran `remote-changes allow`. It can never change a host that did not, and no host runs anything
outside the list, whoever asks: no shell, no sign-in, no service removal. An update it starts
installs only the newest published release, through the channel the host's operator installed
it with, as the daily automatic update would; a host with automatic updates off refuses it. From
0.4.64 `remote-changes allow` covers this update too. A host that
does not want to be managed at all keeps changes off (the default), or leaves the coordinator.

## Updates

Each release publishes the coordinator's two images to GHCR, built from `deploy/coordinator/Dockerfile`
and `Dockerfile.backup` at the release tag, for linux/amd64, with a build provenance attestation:

```
ghcr.io/ivanmurzak/runner-manager-coordinator:X.Y.Z          (and :latest)
ghcr.io/ivanmurzak/runner-manager-coordinator-backup:X.Y.Z   (and :latest)
```

The compose file runs the version `.env` names as `COORDINATOR_VERSION` (`latest` when unset).
`docker compose up -d --build` still builds both from the checkout instead. A deployment that pulls
can keep itself on the newest release with `deploy/coordinator/update.sh`, run every 15 minutes by a
systemd timer.

GHCR makes a new package private. The owner makes both packages public once (on GitHub: the package →
Package settings → Change visibility → Public); until then the machine has to `docker login ghcr.io`
as its deploy account, with a token that has `read:packages`.

### Switch an existing deployment

For a deployment made from source as under [Deploy](#deploy), once, as the account that owns the checkout
and is in the `docker` group (`ubuntu` below); X.Y.Z is the newest release, one that has `update.sh`:

```bash
cd /opt/services/runner-coordinator              # the checkout
git fetch --tags && git checkout vX.Y.Z
cd deploy/coordinator
echo "COORDINATOR_VERSION=X.Y.Z" >> .env
docker compose pull && docker compose up -d
docker compose up -d --force-recreate caddy      # the release's Caddyfile
sudo ./install-updater.sh                        # or: sudo ./install-updater.sh --user ubuntu
```

`install-updater.sh` writes `runner-coordinator-update.service` and `.timer` into `/etc/systemd/system`
with this checkout as the working directory and that account as the user, creates `state/`, and starts
the timer (5 minutes after boot, then every 15 minutes, up to 2 minutes later at random). The units hold
no secret. They are copies: run it again when a release changes them, or to move them to another
checkout. The checkout is left on a release tag (a detached HEAD) from now on.

### What an update does

The timer runs `update.sh` in `deploy/coordinator`. It asks the GitHub API (no token) for the newest
release that is neither a draft nor a prerelease and compares it with `COORDINATOR_VERSION` in `.env`;
when that is missing it updates. When the newest release is newer:

1. It refuses, changing nothing, when tracked files in the checkout have local changes (it never discards
   them), when the release predates `update.sh`, or when the release's images cannot be pulled (not
   published yet, private, no network). The next run tries again. The images pulled here are the ones
   step 4 starts.
2. It takes a backup through the backup service (`backup.sh once`) and remembers its name.
3. It checks out the release tag, so the compose file, the Caddyfile and `update.sh` are the release's,
   and sets `COORDINATOR_VERSION`. `.env`, `docker-compose.override.yml`, the secrets and `state/` are
   untracked and stay as they are.
4. `docker compose up -d`, and `caddy` recreated when the Caddyfile changed.
5. It waits up to 2 minutes for `runner-manager-coordinator --version` in the container to print the new
   version and for `https://$COORDINATOR_HOST/healthz` (through this machine's Caddy) to answer `ok`.

Two runs never overlap (`state/update.lock`). A run that finds nothing to do changes nothing.

### Rollback

When the new version is not healthy in time, `update.sh` goes back by itself: the previous checkout and
`COORDINATOR_VERSION`, then the restore under [Back up and restore](#back-up-and-restore) with the backup
of step 2 (`docker compose stop coordinator backup`, then `backup.sh restore <name>` through the backup
image), then `docker compose up -d`, and the same health check for the previous version.
The database is restored because the new version may already have upgraded it, and an older coordinator
refuses such a database. What happened in the minutes between the backup and the restore is lost; the
warning there about revocations applies.

The version that failed is held back: the timer does not try it again, and takes the next release when
there is one. `./update.sh --version X.Y.Z` tries it again. If the rollback fails too, the status says so,
the unit fails, and the machine needs a hand: `journalctl -u runner-coordinator-update` shows each step.

### Status

`update.sh` writes `state/status.json` after every run. The coordinator reads it (mounted read-only at
`/run/coordinator-update`) and shows it on its dashboard:

```json
{"state":"updated","current":"0.4.58","previous":"0.4.57","latest":"0.4.58","checked_at":1794355480,"changed_at":1794355480,"message":"moved from 0.4.57 to 0.4.58; database backup coordinator-20261110T030000Z.db"}
```

`state` is `updated`, `rolled_back`, `failed` (the move or the check failed; `message` says what), or
`current` (nothing to do). `previous` is the version that ran before the last change at `changed_at`;
times are Unix seconds. A run that GitHub's rate limit stopped keeps the last state and says so.

```bash
systemctl list-timers runner-coordinator-update.timer   # when it runs next
systemctl status runner-coordinator-update.service      # the last run
journalctl -u runner-coordinator-update                 # every run, step by step
./update.sh --check                                     # running and newest version; changes nothing
```

### Pause, or move by hand

```bash
sudo systemctl disable --now runner-coordinator-update.timer   # pause
sudo systemctl enable --now runner-coordinator-update.timer    # resume
./update.sh --version 0.4.57      # in deploy/coordinator: move to that release, older or newer
```

`--version` makes the same move, with the same backup, health check and rollback. Moving to an older
release holds back the newest one, so the timer does not undo it; it updates again at the next release.
A move to an older release whose coordinator cannot open the newer database fails its health check and
rolls back. To go back past a database upgrade, restore a backup from before it as under
[Back up and restore](#back-up-and-restore) (see the rollback notes under [Poll modes](#poll-modes)).

## Security notes

- Public endpoints: `/webhook` (HMAC-SHA256 checked in constant time before anything else,
  1 MiB body limit, repeated `X-GitHub-Delivery` ids ignored), `/connect` (signed challenge, for
  the link and for a `stats` query session alike),
  `/enroll` (one-time code), `/healthz`. Connection and enrollment attempts are rate-limited
  per client address, and so are CLI sign-ins (`/auth/cli/start`).
- [Remote management](#remote-management): commands reach a host only for a signed-in person on
  the allowlist, from the list a host allows, and changes only on a host whose operator allowed
  them there.
- The admin commands run on the coordinator's own machine against its database; there is no
  remote admin endpoint. An enrolled host may only read `stats` over its signed link.
- Logs carry identifiers, counts and fixed words: never the secret, a code, a key, a signature,
  or text from a webhook body.

### Shared runner packages

A host prepares a runner package once and copies it for each runner, so a package is shared between
attempts, and between targets. A native runner's job runs under the account that owns that package, with or
without a coordinator, so it can write to it: permissions cannot stop an account that can change them back.
So the package is not trusted because it was left alone. It is checked.

When the daemon downloads a package, it reads the archive once into memory (150 to 300 MB, for that step),
checks those bytes against GitHub's published SHA-256, unpacks them, and records from them what every entry
must be: file contents (SHA-256) and sizes, symlink targets and, on Linux and macOS, whether what the archive
marks executable is. That record stays in the daemon's memory, since a file could be rewritten by the same
account. Then, for every launch, after the package is copied into the runner's own directory and before
anything is registered, the daemon reads the whole copy against the record, on up to 4 threads, outside the
host allocation lock and the package's locks. It does hold that launch's preparation turn. `package_verify_ms`
counts it. On Linux and macOS, a change to the shared tree's `ctime` also discards it before the copy, cheaply.

A copy that differs, by contents, size, a missing entry or an added one, is removed and not used, and
`package_copy_differs` in the host log gives `reason` (`modified`, `missing`, `unexpected`, `unreadable`). The
shared package is then read too, as it is when a copy fails outright. If it differs, it is no longer
trusted (`package_verify_failed`), and the next attempt, the launch's own retry or a later launch, downloads
it afresh. If it reads clean, it is kept: the copy's disk or another job was at fault. A change that only moved
the shared tree's `ctime` still costs a download on Linux and macOS (`reason=changed`). Each daemon start has no
record, so the first launch after one downloads the package, on Windows as on Linux and macOS (Windows from
0.4.50). There, a process with a handle or its working directory inside the old tree can fail that launch until
it exits, since the tree is replaced by renaming it.

**What this guarantees:** against a job that can edit the shared package but not the daemon, a runner starts
only from a copy that matched the digest-verified archive at the moment it was read, by the entries' contents,
sizes, kinds and names, and an edit to the shared package does not reach a later job's runner. It catches
what a job did by mistake, or left behind for later, where nothing else would.

**What it does not guarantee:**

- A native job runs under the daemon's own account, so it can usually reach the daemon too: replace its binary,
  or its configuration, or read its memory where the OS allows. Then no check by the daemon holds. On a
  boot-mode host that account is root on Linux and macOS and LocalSystem on Windows, so this is certain there.
  Use an isolated execution policy (containers or VMs) for jobs you do not trust, or do not run them on a shared
  host. The same goes for `sudo` in a step.
- A job running under the same account at that moment can edit a runner's copy *after* it was read and
  before or while it runs, and can edit the workspaces, tool caches and dependency caches other jobs use,
  or read their files. Nothing here isolates jobs on one account from each other. Use an isolated execution
  policy (containers or VMs) for jobs you do not trust, or do not run them on a shared host.
- A boot-mode service runs as root on Linux and macOS and as LocalSystem on Windows, and its native runners run
  with it, so a job on such a host can change the daemon itself, its memory, or what it downloads. No check by
  the daemon holds against that: this protects a host in practice only when jobs run under an account that
  cannot reach the daemon's process, which means an isolated execution policy. The same goes for `sudo` in a step.
- Extended attributes, NTFS alternate streams, ACLs, owners, times and mode bits other than a file being
  executable are not compared.
- The check starts from GitHub's published digest, so it trusts GitHub.
- A persistent slot's retained `_work` is the job's own and is not checked.

