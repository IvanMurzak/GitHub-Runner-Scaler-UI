---
id: "f1-cli-auth-host-status"
title: "CLI command tree, auth login/status/logout with the permission disclosure, host capacity commands, and status --json"
group: "F"
sequence: 1
repo: "."
depends_on: ["b2-sqlite-persistence", "c3-rest-inventory-gateway", "d2-machine-secret-store"]
importance: 9
complexity: 6
security_critical: true
production_touching: false
model_hint: "top"
taskflow_refs: ["02-target-architecture.md", "08-user-workflows.md", "07-security.md", "03-control-flows.md"]
---

## Goal

Turn the crates into a usable binary and deliver Journey 1's authentication
half: three user actions from a clean machine to an authenticated tool. This
task also owns the disclosure obligation D21 converted from a consequence into
a requirement — the user must learn what `Administration: Read and write` means
from **this tool**, before the browser opens, not from GitHub's consent screen.

## Scope & seams

Owns `crates/app/src/cli/{mod,auth,host,status}.rs` and the composition root
that wires domain, github, and platform together.

**Command tree.** Declare the full command surface from
`02-target-architecture.md` — the list there is exhaustive — so `f2`, `f3`, and
`g1` attach to a shape that already exists. Implement here:

```text
auth login | auth status | auth logout
host set-capacity N | host show
status --json
```

**`auth login` (D3).** Print the permission statement **before** opening the
browser: the permission table and the plain fact that
`Administration: Read and write` also permits deleting, renaming, and
transferring the repository, and that it binds monitor-only users too. Then run
`c2`'s device flow, print the canonical `github.com/login/device` URL and the
user code, poll, store the token via `d2`, and print the installation URL when
the App is not yet installed anywhere.

**`auth status`.** Show which repositories and organizations the token can
actually reach, so an over-broad installation is **visible rather than
assumed** (`07-security.md`). Distinguish authenticated, not authenticated,
revoked token, and authentication lockout as four separate reported states —
`c2` already separates them and the CLI must not collapse them.

**`auth logout`.** Purge the local secret store and say plainly that
authoritative revocation is uninstalling the App at GitHub.

**`host set-capacity` / `host show` (D9).** Set and display `host_capacity`
alongside the current total in use across policies, plus the service start mode
and the active secret-store variant. Never infer a capacity value from runner
count — human gate 3 exists because that number comes from an observed
workload measurement.

`host show` also displays the **shared REST budget** (`c3`): the configured
refresh interval, the projected hourly request count for the current target
set, and the maximum number of targets this host can serve at that interval.
After D4 demand polling shares one 5,000 requests/hour ceiling with inventory,
which is what bounds a host to roughly 10 targets at the 60-second default
(`04-subsystem-contracts.md`). The design requires that limit to be visible in
host settings; `g3` shows the same numbers in the TUI, and this is the CLI half
of that parity.

**`status --json`.** A stable, scriptable snapshot for headless operation. Its
schema is a compatibility surface: version it, and never emit a credential into
it.

**Error copy.** Every failure explains itself in one screenful, without
exposing credentials, and names the command that fixes it.

## Definition of Done

- `runner-manager --version` and `--help` work; the help text lists the full
  command surface from `02-target-architecture.md` and nothing beyond it.
- Onboarding from a clean machine to an authenticated tool takes at most **3
  user actions**: one command, one code entry, one repository selection. Counted
  and asserted in a scripted walkthrough.
- The `Administration: Read and write` disclosure appears in `auth login`
  output **before** the browser step; a copy test asserts its presence and
  position.
- `auth status` reports the reachable repository and organization set, and
  distinguishes authenticated, unauthenticated, revoked, and lockout states.
- `auth logout` leaves no token in the store and states the GitHub-side
  revocation step.
- `host set-capacity` persists and `host show` displays the value, the current
  in-use total, the start mode, the store variant, the refresh interval, the
  projected hourly request count, and the maximum target count at that interval.
- `status --json` emits a versioned, schema-stable document containing no
  credential; a scripted consumer parses it without special-casing.
- Every command returns a distinct non-zero exit code per failure class, usable
  from a script.
- No command output contains a token, device code, or JIT blob, verified by a
  log scan over the full command set.
