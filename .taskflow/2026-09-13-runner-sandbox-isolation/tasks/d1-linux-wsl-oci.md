---
id: "d1-linux-wsl-oci"
title: "Rootless OCI provider for Linux and managed WSL"
group: "D"
sequence: 1
repo: "."
base_branch: "main"
depends_on: ["b2-isolated-lifecycle"]
importance: 10
complexity: 10
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["03-platform-strategy.md", "04-security-recovery.md"]
---

## Goal

Implement dependency-isolated one-job environments through an operator-installed
rootless OCI runtime on native Linux and inside managed WSL.

## Scope & seams

Probe Podman-compatible runtime/capabilities, resolve pinned image digest, create
unprivileged container with limits/no forbidden mounts, copy runner/bootstrap,
deliver JIT one-time, supervise/remove by ownership labels, and report readiness.

## Definition of Done

- Conflicting Python/system packages do not affect host or sibling attempt.
- No host/container socket, device, app data or DrvFS runtime path is mounted.
- Runtime/image/permission failures fail closed with typed diagnostics.
- Crash/reboot/orphan cleanup and secret scans pass with real rootless OCI fixtures.
- Native Linux and managed WSL acceptance evidence is recorded.

