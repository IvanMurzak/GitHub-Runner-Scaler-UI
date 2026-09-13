# Current architecture and incident evidence

## Daemon construction

The daemon reads the credential once and builds one shared authenticated client
(`crates/app/src/cli/daemon.rs:160-225`). Startup recovery runs synchronously
for every target before target loops are spawned
(`crates/app/src/cli/daemon.rs:250-325`). Each target then runs independently in
a `JoinSet` (`crates/app/src/cli/daemon.rs:328-349`).

Credential maintenance runs every fifteen minutes
(`crates/app/src/cli/daemon.rs:582-615`). A stored-credential source is attached
to the client, but the live incident still logged repeated renewal failures and
`unauthorized` readings until the daemon restarted.

## Polling and health

One target reconciliation awaits its complete pass without an outer progress
deadline (`crates/app/src/cli/daemon.rs:1294-1317`). Individual HTTP requests
have a thirty-second timeout (`crates/github/src/lib.rs:173`), but a demand pass
contains two run listings and one job listing per selected run
(`crates/github/src/demand.rs:760-780`), so total target progress is not bounded
by one request timeout.

Any successful target writes the same host-wide contact file
(`crates/app/src/cli/daemon.rs:1220-1244`,
`crates/app/src/cli/daemon.rs:1317-1333`). Consequently, a healthy unrelated
repository can conceal a target that is offline, unauthorized, stalled, or
continually restarting.

Lifecycle supervision asks the journal for every historical attempt of a policy
(`crates/agent/src/lifecycle.rs:1837-1881`), although cleaned attempts are
immediately skipped. The store already exposes narrower active and uncleaned
queries (`crates/domain/src/store.rs:688-721`), while the general query loads
all matching rows (`crates/domain/src/store.rs:1301-1315`,
`crates/domain/src/store.rs:1730-1745`). The incident database contains 3,271
cleaned attempts and no live attempts.

## Live incident

- Run `34745908455` entered the queue at `2026-09-13T07:42:47Z` with nineteen
  `self-hosted,linux,x64` jobs.
- Policy `a678029f-8b91-4bd5-bee4-d5ebd927b571` is
  `IvanMurzak/AI-Game-Dev-Server`, enabled, active, maximum 14, and carries all
  three labels plus the derived host label.
- The WSL host had 20 free slots. No non-cleaned attempt existed.
- The journal recorded `unauthorized` through `07:40:32Z`, cancelled passes
  during service/WSL restarts, then `offline` for this exact policy at
  `08:06:32Z`.
- Restarting only `runner-manager.service` was safe but took 63 seconds to drain.
  The replacement daemon later refreshed the host-wide GitHub-contact record,
  while the affected policy still created no attempt.
- The guest heartbeat repeatedly failed because its shared Windows directory
  was empty/unwritable from the hardened systemd service. That warning is a
  separate observability defect; its task is concurrent with reconciliation
  (`crates/app/src/cli/daemon.rs:397-405`,
  `crates/app/src/cli/daemon.rs:527-579`).
- INFO replay showed `demand=43`, `desired=14`, `to_start=14`, followed by no
  attempt. `WslRecoveryAllocationLock` maps every configured fence I/O error to
  `AllocationLockBusy` (`crates/agent/src/reconcile.rs:1128-1178`) and
  `AllocationDeferred` is logged only at DEBUG
  (`crates/agent/src/reconcile.rs:1569-1571`). This made a permanent permission
  error look like harmless contention and made the dashboard claim readiness.
- `systemd_unit` grants only the ordinary application and secret directories
  (`crates/platform/src/service.rs:1549-1565`). Guest recovery is configured
  later by the Windows lifecycle task (`crates/app/src/cli/wsl.rs:243-313`), so
  an adopted or freshly installed service never receives write access to the
  DrvFS recovery root.

## Failure classes to preserve

Offline transport, rate limiting, lockout, rejected credentials, cancellation,
slow-but-progressing pagination, and a locally unreadable journal require
different remedies. Recovery must not turn an unknown demand reading into zero
or terminate an active runner.
