---
id: "b1-credential-broker"
title: "Add independent device-flow acquisition and stdin-only Linux credential receive"
group: "B"
sequence: 1
repo: "."
base_branch: "main"
depends_on: []
importance: 10
complexity: 8
security_critical: true
production_touching: false
model_hint: "top"
taskflow_refs: ["01-current-architecture.md", "02-target-architecture.md", "03-security-and-lifecycle.md"]
---

## Goal

Create a reusable credential broker that can issue an independent GitHub App
credential directly into a Linux machine store without reading or staging the
Windows host credential.

## Scope & seams

- Refactor local `auth login` so device-flow acquisition is separately callable
  and local behavior/output remains compatible.
- Add the hidden `auth receive --start-at boot|login` endpoint. It accepts only
  non-terminal stdin, reads at most 64 KiB, converts the existing stored
  credential document into the existing credential type/store path, and emits
  metadata only.
- Expose a broker operation that runs device flow in the interactive Windows
  process and hands `to_stored_document()` directly to a supplied secret sink.
- Do not add token export, token printing, active-store copying, sync, temporary
  files, environment variables or argv transport.

## Definition of Done

1. Existing local login/auth tests remain unchanged in observable behavior.
2. Receive rejects TTY stdin, empty/oversized/malformed documents and wrong
   platform/store conditions without persisting a usable value.
3. A valid access/refresh document round-trips into a rooted Linux-style secret
   store and renewal metadata remains intact.
4. Tests inject distinct Windows access/refresh canaries and WSL access/refresh
   canaries, proving the active Windows store is never loaded and no canary
   appears in output, logs, argv, environment or temporary files.
5. Failure at every device-flow and sink stage leaves no staging credential.
6. App, GitHub and platform focused tests plus workspace format/clippy pass.

