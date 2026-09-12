# Windows TUI: WSL status UX

## Placement

On Windows, Dashboard gains a compact `WSL hosts` section above inventory
previews. A dedicated read-only detail view is reachable from it when at least
one distribution/provider exists. The TUI reads durable snapshots published by
the Windows supervisors; it does not run per-distribution WSL health probes.
One bounded/cancelable capability/list discovery is allowed only when there is
no provider/supervisor state. Frame rendering remains pure and never invokes
`wsl.exe`.

The section is still shown when no distribution exists so the operator can
distinguish unsupported WSL from an empty installation. Non-Windows builds do
not run a probe.

## Status vocabulary

| State | Meaning | Tone |
|---|---|---|
| `not_supported` | platform/build cannot host WSL | muted |
| `not_installed` | Windows WSL feature/executable absent | muted |
| `no_distributions` | WSL exists but no distributions are registered | muted |
| `unmanaged` | distribution exists with no provider record | plain |
| `healthy` | managed WSL2, service and heartbeat current | OK |
| `degraded` | reachable but binary/service/credential/diagnostic drift exists | warning |
| `unreachable` | bounded probes fail; recovery threshold not yet met | bad |
| `draining` | recovery fence acknowledged; waiting for jobs | busy |
| `recovering` | named distribution is being terminated/started/verified | busy |
| `restart_backoff` | prior recovery failed; retry scheduled | warning |
| `recovery_blocked` | safety proof unavailable, unmanaged runner, auth failure or circuit open | bad |

Each row shows distribution, WSL version when known, service/daemon state,
active managed attempts, last successful probe, recovery state and concise
veto/remediation. Detail includes the full redacted problem and backoff/circuit
timestamps.

## Snapshot and responsiveness

Supervisor snapshot reads are local and bounded independently of the existing
GitHub inventory refresh. The fallback capability discovery has its own
cancellation and strict timeout. Slow or stale state retains the last snapshot
and publishes `unreachable`/`loading`; F5 cancels and replaces both
generations. Multiple supervisors do the probing, so opening two TUIs cannot
double the WSL process/session pressure.

The CLI `wsl status --json` and TUI consume one typed model. Exact-key schema
tests and narrow-terminal rendering tests cover every state and ensure status
copy remains stable and secret-free.
