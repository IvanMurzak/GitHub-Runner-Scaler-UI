---
id: "d3-macos-vm"
title: "Disposable native macOS VM provider"
group: "F"
sequence: 1
repo: "."
base_branch: "main"
depends_on: ["b2-isolated-lifecycle"]
importance: 9
complexity: 10
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["03-platform-strategy.md", "04-security-recovery.md"]
---

## Goal

Implement a disposable native macOS guest provider backed by an
operator-installed/configured Virtualization.framework-compatible runtime/image.

## Scope & seams

Define/probe the helper protocol and entitlement/image/architecture readiness;
clone fresh writable disk, boot/bootstrap, use private guest channel for JIT,
supervise/stop/destroy, and recover owned VMs. Never auto-install an image.

## Definition of Done

- Native macOS runner starts from pinned compatible template with fresh disk.
- Missing entitlement/helper/image/architecture fails before JIT with remedy.
- Attempts share no writable guest disk or forbidden host directories.
- Crash/reboot/orphan/secret/resource tests pass on each declared Mac architecture.
- No Linux VM is reported as native macOS isolation.

