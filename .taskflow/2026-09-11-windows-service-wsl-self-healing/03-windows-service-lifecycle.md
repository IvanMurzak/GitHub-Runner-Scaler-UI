# Windows service lifecycle

## Install transaction

`service install --start-at login` must finish in this order:

1. acquire the existing single-instance/install lock;
2. stage the CLI and supervisor owned copies;
3. replace the Task Scheduler registration with the hidden supervisor action;
4. persist the service record and start mode;
5. explicitly start the task in the current session;
6. wait for Task Scheduler `Running` and a new supervisor/daemon heartbeat;
7. commit staged copies and report success.

Any failure after registration restores the previous registration/copies when
possible and returns a non-zero error naming the failed phase. “Installed” may
never mean “will perhaps run at the next login.” Boot/SCM behavior keeps its
existing platform-specific start semantics.

## Hidden process

`Hidden=true` is retained as Task Scheduler metadata but is not relied on to
hide a console. A dedicated Windows GUI-subsystem stable launcher is the task
action. It selects a committed versioned supervisor image, which redirects
child stdout/stderr to the existing redacted service log path and never shells
through PowerShell or `cmd.exe`.

This avoids quoting drift, execution-policy dependence, mapped-image overwrite
failure and flashing console windows. The supervisor image is copied and
versioned with the service CLI; status reports launcher, supervisor and daemon
versions and garbage-collects only images no live process names.

## Reload and restart

Policy-set changes use a dedicated child exit classification, not
`UpgradePending`. The child drains owned attempts indefinitely, exits with a
reload code, and the supervisor immediately launches a fresh child. Binary
upgrade uses a distinct code after successful copy replacement. Unexpected
exits back off and eventually open a circuit; successful stable runtime resets
the failure count.

The supervisor owns graceful stop propagation. It never force-kills a child
that reports active attempts. Existing bounded shutdown behavior remains only
for an explicit operator/service-manager stop, not an upgrade or reload.

## Health model

Registration, process and functional contact are separate axes. The public
summary states one of:

- `starting`: task/supervisor began within the startup grace;
- `running`: supervisor and daemon heartbeat are current;
- `restart_backoff`: supervisor is alive and waiting to restart a failed child;
- `stopped`: automatic registration exists but is not running outside grace;
- `failed`: circuit open, stale heartbeat, malformed registration or version
  mismatch.

`healthy` requires `running`, correct registration/copies, readable credential
scope and a supervisor/daemon heartbeat no older than the documented
threshold. A GitHub-contact freshness requirement applies only while at least
one active policy is due to poll; an idle host with no policies is not made
unhealthy merely because it correctly issues no GitHub request. Status remains
read-only and does not start the task as a side effect.
