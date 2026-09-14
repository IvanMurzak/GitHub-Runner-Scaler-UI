---
id: "d2-windows-hyperv"
title: "Hyper-V-isolated Windows container provider"
group: "E"
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

Implement native Windows dependency isolation with Hyper-V-isolated Windows
containers and truthful unsupported/incompatible reporting.

## Scope & seams

Probe edition/features/runtime/image compatibility, force Hyper-V isolation,
implement prepare/start/inspect/stop/destroy and one-time JIT delivery. Refuse
process isolation, Linux containers and unsupported workflow capabilities.

## Definition of Done

- A Windows runner executes in a verified Hyper-V-isolated Windows container.
- Missing Hyper-V, wrong runtime mode/image build/edition fail before JIT.
- No native fallback or forbidden host mounts/sockets occur.
- Restart/orphan/secret/resource-limit tests pass on declared Windows variants.
- Unsupported desktop/device/container-action cases are explicit in CLI/TUI/status.

