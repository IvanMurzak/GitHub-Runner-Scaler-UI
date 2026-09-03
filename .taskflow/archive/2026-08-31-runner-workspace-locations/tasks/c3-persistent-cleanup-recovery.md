---
id: "c3-persistent-cleanup-recovery"
title: "Clean and recover persistent slots safely"
group: "C"
sequence: 3
repo: "."
base_branch: "main"
depends_on: ["c2-persistent-slot-allocation"]
importance: 10
complexity: 10
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["02-target-architecture.md", "03-migration-rollout.md", "04-security-recovery.md"]
---

## Goal

Retain exactly `_work`, scrub runner identity and lifecycle state, and keep an
unsafe or partly cleaned slot quarantined across restarts.

## Scope & seams

- Dispatch cleanup by the immutable workspace kind stored on the attempt.
- For a persistent slot derive the journaled root from exact runtime path and
  slot, verify any surviving policy agrees, and prove lexical plus canonical
  containment before deletion.
- Enumerate direct slot entries with literal filesystem APIs, preserve only a
  real non-link `_work` directory, and remove every other entry.
- Verify runner binaries, registration identity, JIT handoff, process identity,
  and lifecycle sidecars are absent before releasing package lease and marking
  the attempt cleaned.
- On any containment, link, enumeration, deletion, or verification failure keep
  the attempt uncleaned, retain the slot lease, emit redacted remediation, and
  retry through normal recovery.
- Preserve current process identity and termination ordering before cleanup.

## Definition of Done

- Sequential jobs retain a Git-ignored marker under `_work` while runner state
  from the first attempt is absent before the second starts.
- Unix symlink and Windows junction or reparse substitutions fail closed and no
  test deletion escapes its approved temporary root.
- Injected partial deletion keeps the slot unavailable across restart but does
  not consume active host capacity.
- Recovery handles a missing policy from exact journal facts without scanning
  directories for ownership.
- Switching mode or path after all attempts are cleaned leaves every old slot
  untouched.
- Crash-boundary, recycled-PID, cleanup mutant, secret scan, and recovery tests
  pass.
