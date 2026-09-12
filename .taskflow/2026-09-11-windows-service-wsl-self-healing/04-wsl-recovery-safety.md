# WSL recovery safety

## Principle

Unreachable does not mean idle. Recovery proceeds only from affirmative,
current evidence; absence, timeout, stale state, authorization failure or an
unmanaged runner is a veto.

## Eligibility audit

A distribution is recovery-eligible only after a healthy in-guest audit proves:

- runner-manager owns its systemd unit and all runner processes/services it
  can discover;
- no manually installed GitHub runner service exists, and the audit is
  repeated in every heartbeat rather than trusted forever;
- every autoscale target and routing identity is represented in the published
  heartbeat;
- the Windows provider directory supports the required cross-boundary atomic
  file and locking semantics;
- the Windows credential can read runner inventory for every published target.

An existing unmanaged runner such as `ubuntu-server-runner` yields
`recovery_blocked: unmanaged_runner`. There is no “trust me” bypass that can
silently end its job.

## Drain fence

Before every JIT creation/runner launch, the Linux daemon participates in a
cross-boundary generation fence. The Windows supervisor requests generation
`N` to drain; Linux acknowledges `N`, stops creating runners, and continues
reconciling existing attempts to terminal state. The supervisor requires:

1. a fresh heartbeat acknowledging `N`;
2. local active-attempt count zero for two consecutive heartbeats;
3. GitHub inventory zero busy managed runners and zero online managed
   registrations for two consecutive reads;
4. no unmanaged-runner finding;
5. continued exclusive ownership of the recovery fence.

If the guest is too damaged to acknowledge the fence, automatic recovery is
blocked. This is intentional: without acknowledgment, a race-free guarantee
that no new job will start is impossible. TUI and logs name the veto and offer
an operator-only forced recovery outside the automatic path.

An online idle managed registration is removed through the existing
authenticated GitHub lifecycle before the zero-registration proof. Failure to
remove or re-read it is a veto. The fence prevents the Linux daemon from
creating its replacement during this interval.

## Failure detection

Only known transport/session failures are auto-recoverable, including bounded
probe timeout and classified WSL service/vsock failures such as
`Wsl/Service/0x8007274c`. Three consecutive failures spanning at least five
minutes are required. Unsupported platform, WSL1, missing distribution,
foreign task, authentication failure, invalid configuration and ordinary
workload diagnostic failures are not restart triggers.

## Recovery sequence

```text
healthy
  -> suspect (probe failure 1/3)
  -> degraded (2/3)
  -> draining (fence requested/acknowledged)
  -> safe_to_restart (all safety proofs current)
  -> terminating_named_distribution
  -> starting
  -> verifying
  -> healthy
```

The action is exactly `wsl.exe --terminate <validated-name>`. After termination
the supervisor starts the hold child, waits for systemd/daemon heartbeat and a
fresh GitHub contact, then releases the fence. Failures use capped exponential
backoff. A bounded number in a rolling window opens a circuit and requires a
healthy manual `wsl install` reconvergence or explicit reset; it never loops
forever.

## Security and audit

The task stays `InteractiveToken`/`LeastPrivilege` under the WSL-owning user.
No administrator token, service account, inbound socket or duplicated Linux
credential is introduced. Every transition and veto is emitted to redacted
structured logs and a bounded durable activity journal. Distribution names
continue through the existing validation and argv construction; no shell is
used.

Microsoft documents `wsl --terminate <Distribution Name>` as the command that
terminates the named distribution and `wsl --shutdown` as terminating all
distributions and the WSL2 VM; the latter is therefore outside this design:
<https://learn.microsoft.com/windows/wsl/basic-commands>. Microsoft does not
document a no-elevation guarantee, so the real non-elevated gate in `ROADMAP`
is authoritative for product support rather than an assumption.
