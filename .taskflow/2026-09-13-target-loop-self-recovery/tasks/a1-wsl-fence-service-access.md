---
id: "a1-wsl-fence-service-access"
title: "Converge exact WSL fence write access"
group: "A"
sequence: 1
repo: "."
base_branch: "main"
depends_on: []
importance: 3
complexity: 7
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["01-current-architecture.md", "02-target-architecture.md"]
---

## Goal

Make guest recovery configuration atomically converge a least-privilege systemd
drop-in that grants the daemon write access to exactly its DrvFS shared root.

## Scope & seams

Change the Linux `wsl-host` configuration path and service adapter helpers.
Validate/quote absolute paths, update atomically, reload systemd, and restart
only on effective change. Preserve the base unit hardening and adopted-service
behavior.

## Definition of Done

- Exact-path drop-in generation and idempotence are unit tested.
- Unsafe/newline/non-absolute paths are rejected.
- A changed drop-in reloads/restarts; unchanged configuration does neither.
- No parent `/mnt` or Windows profile directory is writable.
- Existing WSL install reconverges an adopted service.
