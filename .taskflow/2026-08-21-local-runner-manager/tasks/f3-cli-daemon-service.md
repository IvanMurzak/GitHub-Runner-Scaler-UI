---
id: "f3-cli-daemon-service"
title: "daemon run and service install/uninstall/status command surface"
group: "F"
sequence: 3
repo: "."
depends_on: ["f2-cli-policy-commands", "e3-jit-lifecycle-recovery", "d3-service-installers"]
importance: 7
complexity: 4
security_critical: false
production_touching: true
model_hint: "mid"
taskflow_refs: ["02-target-architecture.md", "05-infrastructure.md", "08-user-workflows.md"]
---

## Goal

Expose the agent and the service installer as commands (D5). Both are thin
wrappers over work `e3` and `d3` already did, which is why they are one task
rather than two.

## Scope & seams

Owns `crates/app/src/cli/{daemon,service}.rs`.

```text
daemon run
service install [--start-at boot|login] | service uninstall | service status
```

**`daemon run`.** Take the single-instance lock (`d1`), load active policies,
start their demand-polling loops on the configured interval, run `e1`'s
reconciliation with `e3`'s launcher, and shut down gracefully: stop accepting
new work, let busy runners finish, and release the lock. A second `daemon run`
on the same host is refused with an actionable message naming the holder.

**`service` commands.** Register `daemon run` for the current host through
`d3`, defaulting to `--start-at boot`. `service status` reports the start mode,
the resolved absolute binary path with an explicit **error** when it is stale,
the diagnostic log path, and the last successful GitHub contact.

Both commands are noninteractive and scriptable, return distinct exit codes per
failure class, and print no credential.

## Definition of Done

- `daemon run` starts, reconciles, and shuts down gracefully without
  terminating a busy runner.
- A second `daemon run` while the lock is held is refused with a message naming
  the holder and a distinct exit code.
- `service install` with each `--start-at` value registers correctly on
  Windows, macOS, and Linux; `uninstall` and `status` behave per `d3`.
- `service status` reports a stale binary path as an error rather than
  appearing healthy, exercised by moving the binary after install.
- `service status` reports the last successful GitHub contact, and reports
  `offline` honestly when there has not been one.
- Both commands run unattended from a script with no interactive prompt.
