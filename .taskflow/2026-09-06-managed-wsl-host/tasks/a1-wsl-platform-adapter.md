---
id: "a1-wsl-platform-adapter"
title: "Add tested WSL discovery, execution, artifact install and lifecycle task primitives"
group: "A"
sequence: 1
repo: "."
base_branch: "main"
depends_on: []
importance: 9
complexity: 9
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["01-current-architecture.md", "02-target-architecture.md", "03-security-and-lifecycle.md"]
---

## Goal

Give the Windows build a production-quality, fully testable platform adapter for
managing a named WSL2 distribution without shell-built commands or secret
persistence.

## Scope & seams

- Add a `crates/platform` WSL module with injectable process and scheduled-task
  controls. Non-Windows builds expose the same model with an explicit
  unsupported-platform result.
- Discover installed distributions and WSL versions from real `wsl.exe` output,
  including UTF-16LE/NUL output and names containing spaces or punctuation.
- Probe exact distribution identity, WSL2, supported Linux architecture, root
  execution and systemd readiness.
- Execute a selected distribution with a literal argv vector, bounded stdout and
  stderr, timeout/cancellation, optional anonymous stdin bytes, and exit status.
  Secrets must never enter `Debug`, errors, tracing, argv or environment.
- Provide atomic exact-version Linux binary staging/install primitives suitable
  for an already-running service. Reuse/refactor existing verified release
  metadata and checksum behavior where possible; do not introduce an unverified
  download path.
- Render/register/query/remove one stable, product-owned, per-distribution
  least-privilege login task. Its action invokes the hidden Linux hold command;
  it never embeds shell text.
- Persist only the specified non-secret provider record under app config using
  atomic replacement and a schema version.

## Definition of Done

1. Fixture tests cover normal and malformed UTF-8/UTF-16 discovery, default
   markers, names with spaces, WSL1 refusal and unsupported architecture.
2. Tests prove every Linux invocation is an argv vector and credential canaries
   occur only in captured child stdin, nowhere observable or persisted.
3. Scheduled-task rendering/control tests cover per-distribution identity,
   quoting, idempotent replacement, foreign-task refusal and non-destructive
   detach.
4. Artifact tests prove exact semantic version/architecture selection, SHA-256
   verification, atomic destination replacement and preservation on failure.
5. Provider-record tests prove schema handling, atomicity and absence of secret,
   policy and JIT fields.
6. `cargo test -p runner-manager-platform` and workspace clippy/format gates pass
   on supported CI platforms.

