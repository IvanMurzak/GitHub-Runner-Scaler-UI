# Target architecture

## Components

```text
Task Scheduler (interactive user, least privilege, hidden launcher)
  |-- local supervisor
  |     `-- child: daemon run
  |           `-- repository reconcilers / runner attempts
  |
  `-- WSL supervisor (one per managed distribution)
        |-- bounded Windows-side WSL probes
        |-- reads provider recovery state + Linux heartbeat
        |-- acquires drain fence and verifies GitHub inventory
        `-- wsl.exe --terminate NAME -> restart -> verify

TUI / CLI status
  `-- read-only typed snapshots from the same durable state
```

The supervisor is a small product-owned Windows GUI-subsystem binary, shipped
beside `runner-manager.exe`. It creates no console window, logs through the
existing redacted diagnostics path, and uses no elevated token. It is stable
process ownership, not business logic: the daemon remains the scaling owner
and the WSL adapter remains the platform owner. The task points at a stable
launcher; versioned supervisor/daemon child images are staged beside it. An
upgrade never overwrites the mapped supervisor image and the stable launcher
atomically selects the committed version on the next child cycle.

## Local service supervision

The login task runs the supervisor, not the CLI binary. The supervisor starts
the service-owned CLI as a child with no console, translates stop requests,
and classifies exits:

- clean requested shutdown: exit;
- policy reload: restart immediately after the child has drained;
- upgrade hand-off: start the newly copied binary;
- unexpected failure: capped exponential backoff with jitter, durable failure
  count and circuit-open state.

Task Scheduler's restart policy remains a final guard for supervisor failure,
not the normal reload mechanism. `service install` registers, starts, waits for
a running state/heartbeat, and only then reports success. Replacement rollback
restores both binary and registration if that convergence fails.

## WSL supervision

The WSL lifecycle task also runs the Windows supervisor. Its child is the
existing `wsl.exe ... wsl-host hold`, preserving systemd semantics. The parent
can distinguish a healthy long-lived child from a hung WSL transport because
it runs independent bounded probes.

Linux writes a redacted heartbeat and runner-safety snapshot into the Windows
provider directory through a narrowly permissioned DrvFS path. The snapshot
contains generation, timestamp, policy identities, managed attempt IDs,
managed runner IDs/names, active count, drain acknowledgment and unmanaged
runner discovery; it contains no token, JIT configuration, command output or
workspace content.

Recovery is fail-closed and follows `04-wsl-recovery-safety.md`. Existing
provider records migrate without automatic termination authority. A healthy
reconvergence audits the distribution and promotes it to automatic recovery
only if no unmanaged runner service is present.

## State ownership

| State | Authoritative owner | Consumer |
|---|---|---|
| local runner attempts | local daemon store/journal | local supervisor status, TUI |
| WSL attempts and drain acknowledgement | Linux daemon heartbeat under Windows provider directory | WSL supervisor |
| GitHub busy/online runner state | GitHub REST inventory | WSL supervisor safety gate |
| WSL reachability and transport failure | bounded Windows probe | supervisor, CLI/TUI |
| recovery phase/backoff/circuit | Windows provider recovery record | supervisor, CLI/TUI |
| registration integrity | Task Scheduler read-back | service/WSL status |

No advisory provider record alone authorizes termination.

## Compatibility and deployment

- Existing `runner-manager` login registrations are replaced on the next
  `service install`/update with the hidden supervisor action.
- Existing WSL tasks are replaced by a supervisor action only after the Linux
  heartbeat path is installed and verified, the old guest daemon has
  acknowledged drain, and its owned attempts are terminal. A failed migration
  retains the old task.
- Off Windows, supervisor and probing code is not built into runtime paths;
  domain/presentation types remain testable cross-platform.
- Existing JSON fields are preserved. New service and WSL recovery fields are
  additive under a schema-version bump where exact-key tests require it.
- No automatic `wsl --shutdown` is ever introduced.
