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
at once (at most every 30 seconds, followed by a sweep) when a host advertises a target its sweep
does not cover, or a webhook names a repository a host serves that the sweep does not know. A
repository just added on a host is therefore normally covered within seconds.

`repo add` and `host show` count a `coordinated` target at the coordinated interval (one poll every
300 s by default), not the refresh interval, and every other target at the refresh interval. A new
target has no coverage yet, because a coordinator only reports on what a host advertised. While the
link is up and the coordinator's sweep runs, the new target is counted at the coordinated interval
too; if that is what admits it, `repo add` prints a note saying so. With the link down, or no sweep,
every target is counted at the refresh interval as without a coordinator.

A set of targets admitted this way can exceed the host's budget (2,500 requests an hour) when its
targets poll on their own: the coordinator does not cover one, or the link stays down past 30
seconds. Charged polls of a target not in `coordinated` then stretch to the interval that fits the
budget (64 s for 11 repositories, 116 s for 20). Runners keep starting, and idle polls, answered 304
and not charged, keep their pace. A set that fits at the default interval is not affected.

A dropped link reconnects after 1 second, then waits twice as long after every failed attempt,
never more than 30 seconds between attempts (a random part of up to a third of the wait spreads a
fleet out; a refused key or version waits up to 5 minutes). A connection that stayed up longer than
a minute starts that over, so hosts are back within about 30 seconds of a coordinator restart.

Upgrading to stage 4 moves the coordinator's database to schema 2 (three new tables). A stage-3
coordinator refuses to open it (`written by a newer coordinator`): to roll back, restore the
database from before the upgrade, or stop the service and run
`sqlite3 coordinator.db 'PRAGMA user_version = 1'` (the stage-3 code never reads the new
tables, and a later upgrade keeps them). 0.4.47 moves it to schema 4 (a `queue_wait_secs` column on
the samples, and a `live_state` table); to roll back to 0.4.46, `sqlite3 coordinator.db 'PRAGMA user_version = 2'` the same
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

On each host, give the profile that should serve the pool its OS's pool label:

```bash
runner-manager repo profile set-pool octo/app [--profile NAME] --pool on    # repository target
runner-manager org set-pool octo --pool on                                   # organization target
runner-manager repo profile show octo/app --profile NAME                     # pool=rm-pool-linux
```

`set-pool` adds this host's own pool label; `add-label` with a pool label works the same way. A
label in the reserved `rm-pool-` namespace that is not this host's (`rm-pool-windows` on Linux, or
an unknown class such as `rm-pool-linux-heavy`) is refused. At most one profile of a target on a
host may carry the pool label: a pool job selects its profile by that label alone, and two
profiles matching one job fall under the existing rule that overlapping profiles start no
runner, so `set-pool` refuses the second one and names the first. The TUI's profile settings
show the pool line ready to copy.

Then switch the workflows that may run on any machine of that OS:

```yaml
jobs:
  build:
    runs-on: rm-pool-linux          # any Linux host of the pool; the coordinator picks one
  release:
    runs-on: rm-home-linux-x64      # still pinned to one machine by its own selector
```

Labels can be combined (`runs-on: [rm-pool-linux, gpu]`): only pool profiles carrying every label
are candidates.

### How a host is chosen

When a pool job is queued (webhook `queued`, or counted by the sweep), the coordinator picks one
**candidate**: a connected version-3 host whose target serving the repository is covered by the
sweep, with an enabled pool profile whose labels cover the job, not unfit, not draining, and with
a free slot by its last heartbeat once the launches already sent to it are counted. With job
statistics it weighs the candidates (see [Weighted placement](#weighted-placement)); without
any for that queue it prefers a profile with a persistent workspace for that repository (a warm
checkout), then the most free RAM, then the fewest busy slots. It sends that host a `launch` and waits up to 10 seconds for the
answer; a refusal (`max_capacity`, `host_capacity`, `unfit`, `draining`, `disabled`,
`not_coordinated`, ...) or no answer moves on to the next candidate. A job no candidate can take
waits and is retried every 5 seconds, and at once whenever a host reports a runner ended or a
heartbeat with more free slots than its last one. A version-4 host of 0.4.47 or later sends that
heartbeat right after its `attempt_finished`, so a freed slot takes the next queued job within
moments rather than at the host's next heartbeat (15 seconds).

A host frees a native runner's slot when it concludes the attempt, before it deletes the runner's
files: cleanup never holds a slot. It concludes the attempt on its target's next pass, and while
it is joined the host checks every 2 seconds whether a live runner's process has exited and, if
so, runs that pass at once (at most 5 seconds after the previous one) instead of at the target's
next scheduled poll (up to 60 seconds later). A runner in a container, a VM or a WSL distribution
keeps its slot until its environment is proven gone and cleaned up, deliberately: until then it
may still be running. Its host sends a heartbeat as soon as that cleanup is done.

A launch is a **lease** for 2 minutes (`COORDINATOR_LEASE_TTL`, `--lease-ttl`, at least 30
seconds). GitHub hands a runner *any* queued job its labels cover, so the coordinator counts per
repository and label set: it never holds more leases than jobs are queued. When a lease's runner
takes a job (the host's `attempt_started`) the lease is held until the webhook takes that job out
of the queue (at most 30 seconds), so the job is not placed twice meanwhile. A lease also closes,
and its job, if still queued, is placed again at once:

- when its attempt ends (`attempt_finished`);
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

A pool profile is **directed** while its target is `coordinated` on a version-3 link: it starts
runners only for the launches it accepted, never from its own reading of the queue (which every
host of the pool sees the same way). It accepts a launch only when its own allocator, over its
own attempts and ceilings, grants one more runner. Accepted launches start their runners at once:
the link signals the target's loop, which starts every launch open at that moment in one go,
without polling GitHub, so the 5-second gap between polls does not apply; the next full pass
stays where it was scheduled. The runners themselves are still created one after another under
the host-wide allocation lock, the same lock every pass takes, so the ceilings hold exactly.

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

While a host has joined a coordinator, every 2 seconds it looks at the process tree of each live
**native** runner of its own policies, on a worker thread so its reconcile loop never waits:

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
together with the repository, the workflow and the job (matrix values included, as GitHub expands
them: `build (ubuntu, 3.12)`), and the job's `created_at`, `started_at` and `completed_at`. The
coordinator remembers that only for runner names `runner-manager` registers
(`runner-manager-...`), joins it with the host's report of the same runner name, in whichever
order they arrive (a report waits up to 15 minutes for its job to be named, a webhook 6 hours for
its report, 10,000 of each at most, the oldest dropped first), and stores one sample per attempt
that ran a job, completed or failed (an out-of-memory kill is what placement must learn), under
the key `owner/repo/workflow/job` with the host that ran it. An attempt that exited idle is not
a sample.

A sample's **duration** is the job's own run time, `started_at` to `completed_at`, so a 14-second
job reads 14 seconds and not the minute its runner lived. Its **queue wait** is `created_at` to
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

1. **Demand**: the heaviest p90 peak memory among the jobs queued there. A job never measured
   counts as its repository's p90 (over all its samples); a repository never measured as
   `COORDINATOR_DEFAULT_JOB_RAM` (2 GiB). The sweep names the jobs it lists just as a webhook
   does (same job id, workflow and job name), so a job only the sweep saw is weighed by its own
   samples. Only a job with no name to go by counts as the repository's p90 or the default.
2. **Filter**: a host whose free memory (by its last heartbeat) less the estimates of its
   launches whose runner has not taken a job yet cannot hold the demand plus
   `COORDINATOR_RAM_MARGIN` (512 MiB) is passed over. A host that reports no free memory is not
   filtered. When the demand is the global default (nothing measured for that repository),
   nothing is filtered: a guess never keeps a job waiting. Nor is anything filtered when the
   demand plus the margin is more than every candidate's total memory: no host could ever hold
   it, so the job runs where the score says. The estimates of a host's launches stay reserved
   for 2 minutes after their runner took its job, while the build's memory ramps up.
3. **Score** = `cache` x warm workspace (0 or 1) + `headroom` x (memory free after the job, as a
   share of the host's memory) + `speed` x (how much faster than usual this host ran these jobs,
   -1 to 1) - `bigfit` x (1 when the heaviest measured queue waiting elsewhere needs at least
   twice this one's memory and fits only this host of this queue's candidates, and this queue
   fits another).
4. **Order**: the best score first, ties in stage 3's order. With no statistics at all for the
   queue, stage 3's order alone: warm workspace, most free memory, fewest busy slots.

Weights are set with `COORDINATOR_PLACEMENT_WEIGHTS` (`--placement-weights`), any subset of
`cache=4,headroom=2,speed=1,bigfit=1.5`, each 0 to 100. For example, a fleet where checkouts are
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
in the database.

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
  octo/app/CI/build (linux, 3.12)
      6.2 GiB  3.40 cores  11m 05s  wait 4s/52s  (14)
      on linux (4f1c...)            9 samples  p50 9m 50s  0.85x the usual time
      on win-big (77aa...)          5 samples  p50 13m 10s  1.14x the usual time

Samples per host:
  linux (4f1c...)                 61 samples over 9 jobs, p90 peak memory 4.1 GiB

Last placements, newest first (scores in points):
  2m 10s ago  octo/app [rm-pool-linux] needs 6.2 GiB (job), weighted: 4f1c...
      4f1c...   fits     free after 38.0 GiB   cache 0.00 headroom 1.18 speed 0.15 bigfit -0.00 = 1.33
      9b20...   too full free after 0 MiB      cache 4.00 headroom 0.00 speed 0.00 bigfit -0.00 = 4.00
```

- **Queue wait**: queued to started over every kept sample, then per job. A p90 that grows
  means jobs wait for a free host.
- **Heaviest jobs**: the 20 job keys with the largest p90 peak memory, and per host how its
  median compares with the usual duration (below 1x: faster).
- **Pool queues waiting for a runner**: each queue (repository and labels) with fewer runners
  on their way than jobs queued, the oldest job's wait, and why no more is placed (see above).
- **Open leases**: per host, each launch not yet closed, its state (`offered`, `accepted`,
  `claimed`) and age. On a host's `stats` these are live; the admin CLI on the coordinator's
  machine reads the copy the server saves every minute (`as of ... ago`).
- `--json` is schema version 3 since 0.4.47: `p50_duration_secs` is the job's run time,
  `p50_queue_wait_secs` / `p90_queue_wait_secs` are added (overall and per job), and `pending`,
  `leases` and `live_at`.
- Names are printed with control, bidirectional and zero-width characters removed: a workflow
  or job name is whatever a pull request wrote.
- **Last placements**: what the queue was estimated to need and why (`job`, `repository` or
  `default`), `weighted` or `stage3`, the host chosen (or `no host fits`, shown at most once a
  minute per queue), and every candidate's score parts. A host marked `too full` was passed
  over whatever its score.
- The counters are all-time; launches and wakes reach the database within a minute.

Repository, workflow and job names in `stats` come from your own repositories' webhooks; they
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

## Security notes

- Public endpoints: `/webhook` (HMAC-SHA256 checked in constant time before anything else,
  1 MiB body limit, repeated `X-GitHub-Delivery` ids ignored), `/connect` (signed challenge, for
  the link and for a `stats` query session alike),
  `/enroll` (one-time code), `/healthz`. Connection and enrollment attempts are rate-limited
  per client address.
- The admin commands run on the coordinator's own machine against its database; there is no
  remote admin endpoint. An enrolled host may only read `stats` over its signed link.
- Logs carry identifiers, counts and fixed words: never the secret, a code, a key, a signature,
  or text from a webhook body.
