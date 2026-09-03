---
id: "c2-persistent-slot-allocation"
title: "Allocate and materialize stable persistent slots"
group: "C"
sequence: 2
repo: "."
base_branch: "main"
depends_on: ["c1-effective-runtime-root"]
importance: 10
complexity: 10
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["02-target-architecture.md", "04-security-recovery.md", "05-user-workflows.md"]
---

## Goal

Give an opted-in repository the lowest free stable exclusive `sN` slot and
recreate one-attempt runner material without disturbing a safe retained `_work`.

## Scope & seams

- Select the repository persistent root before the host root when policy mode
  is persistent.
- Under the existing host allocation lock, collect every uncleaned persistent
  lease for the policy and select the lowest free positive slot within
  `max_capacity`.
- Validate `<root>/sN` containment, create or validate the slot, and journal its
  workspace mode, slot, and exact runtime path before package or GitHub effects.
- Before materialization accept only an empty slot or a slot containing one real
  `_work` directory; refuse link-like or unknown entries until cleanup handles
  them.
- Copy the verified runner package around retained `_work` and keep GitHub's
  relative JIT `work_folder` equal to `_work`.
- Let the database unique lease constraint be the final race fence.

## Definition of Done

- Two sequential allocations for capacity one choose `s1` and preserve the
  exact same `_work` path.
- Concurrent allocations never share a slot and journal unique leases before a
  JIT request.
- A terminal but uncleaned attempt continues to reserve its slot without being
  counted as active host capacity.
- Lowering capacity does not delete higher slots; later raising it permits them
  when no uncleaned lease exists.
- Package materialization neither overwrites nor recursively follows retained
  `_work`.
- Organization policies and ephemeral repositories never enter slot allocation.
- Allocation, concurrency, retry, and package lease tests pass.
