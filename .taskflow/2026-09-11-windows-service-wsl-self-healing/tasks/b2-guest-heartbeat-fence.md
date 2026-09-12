---
id: "b2-guest-heartbeat-fence"
title: "Publish WSL guest heartbeat and enforce drain fence"
group: "B"
sequence: 2
repo: "."
base_branch: "main"
depends_on: ["b1-wsl-safety-spikes"]
importance: 3
complexity: 9
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["04-wsl-recovery-safety.md"]
---

## Goal

Give Windows current, race-free proof of guest runner activity and prevent new
assignments while recovery drains.

## Scope & seams

Add heartbeat schema/atomic writer, generation fence at the pre-JIT/pre-launch
boundary, drain acknowledgment, active-attempt inventory and continuous
unmanaged runner service/process audit to the Linux daemon.

## Definition of Done

- No runner can be created after a drain generation is acknowledged.
- Active jobs continue and heartbeat until terminal; zero is confirmed twice.
- Unmanaged runner discovery blocks eligibility continuously.
- Heartbeat is permissioned, bounded, crash-safe and secret-free.

