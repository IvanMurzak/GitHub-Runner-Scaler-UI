# Target architecture

## Per-target progress owner

Each managed target has a supervisor task outside the reconciliation future.
The worker publishes typed milestones: `starting`, `supervising`, `polling`,
`allocating`, `sleeping`, and `restarting`, with start/completion timestamps,
last successful demand observation, failure class, consecutive failures, and
next retry. The supervisor enforces a whole-pass deadline derived from the
known request/page budget plus margin. On expiry it cancels only that poll,
records `stalled`, rebuilds the target worker/client view, and retries with
capped jitter. It never terminates runner children.

A panic or unexpected target-loop return is treated identically. Other targets
continue and publish their own state. Repeated failures remain automatic but
visible; backoff is capped so a transient failure cannot silence a target for
the lifetime of GitHub's queue.

## Credential generations

The secret store is the durable source of truth. The authenticated client tracks
a non-secret generation fingerprint. On `401`, it acquires the existing renewal
lock, rereads the store, and if the generation changed retries once immediately
with that pair. Only the process holding the still-current refresh pair performs
the refresh exchange. A failed refresh followed by a newer stored generation is
recovery, not `interactive sign-in required`.

## Hot-path journal views

Startup recovery and ordinary supervision load only uncleaned attempts for the
target. Allocation uses active/uncleaned views as its existing contracts require.
Full history remains available to diagnostic/status consumers. Add supporting
indexes and regression tests with thousands of cleaned rows so startup and one
idle reconciliation remain bounded.

## Truthful readiness

Persist one non-secret snapshot per target using atomic replacement. A target is
ready only when its loop is alive and either its most recent due poll succeeded
or it is legitimately sleeping until the next nominal poll. `offline`,
`unauthorized`, `stalled`, `restarting`, stale/missing progress, and repeated
cancellation degrade or block readiness. Host readiness aggregates all enabled
autoscale targets; a success from another repository cannot overwrite failure.

The existing host-wide contact timestamp remains a compatibility summary but is
not a readiness proof. CLI and TUI show target, last successful demand poll,
current phase, failure, retry time, and the applicable automatic/manual remedy.

## WSL guest heartbeat

Guest recovery configuration converges a product-owned systemd drop-in granting
write access to the exact configured shared recovery directory. It uses atomic
replacement, a quoted/validated absolute path, `daemon-reload`, and restarts the
unit only when the effective drop-in changed. The ordinary unit remains tightly
sandboxed; `/mnt`, the Windows user profile, and the wider application-data tree
are never granted.

Heartbeat write errors retain their detailed non-secret OS cause and feed WSL
readiness. They do not cancel or suppress GitHub target loops.

Fence acquisition distinguishes expected contention from configuration/I/O
failure. Expected contention remains a deferred retry; an unreadable configured
fence is an actionable warning carrying a closed reason and is reflected in
readiness. Demand greater than zero plus repeated deferral may never remain
`READY`.

## Acceptance invariants

1. Matching queued jobs cause attempts after a stale credential is replaced in
   the store, without daemon restart.
2. One permanently hanging target is cancelled/recreated while another target
   continues polling.
3. A transient offline result retries and eventually allocates within a bounded
   interval.
4. No watchdog path kills a busy runner or restarts the whole WSL distribution.
5. One healthy target cannot make a failed target or host `READY`.
6. Thousands of cleaned attempts do not materially delay daemon startup.
7. WSL heartbeat publication succeeds under the installed hardening policy and
   failures are actionable in status/TUI.
