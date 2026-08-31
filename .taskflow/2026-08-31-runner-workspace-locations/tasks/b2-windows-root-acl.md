---
id: "b2-windows-root-acl"
title: "Secure the Windows default runner root"
group: "B"
sequence: 2
repo: "."
base_branch: "main"
depends_on: ["b1-runner-path-platform"]
importance: 9
complexity: 9
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["03-migration-rollout.md", "04-security-recovery.md"]
---

## Goal

Create and verify `%SystemDrive%\rman` with the minimum access needed by boot,
login, and foreground execution modes.

## Scope & seams

- Extend Windows service installation and service-mode transition planning to
  create or reconcile only the platform default runner root.
- Admit `SYSTEM`, Administrators, and the selected login or foreground identity
  as required; prevent inherited broad local-user write access.
- Do not rewrite ACLs on custom operator paths. Preflight and report their
  existing permissions instead.
- Make directory and ACL operations transactional where current service
  installation rollback supports it, and report any non-reversible existing
  directory state explicitly.
- Add privileged inspection output without exposing identities beyond what
  existing service status already reports.

## Definition of Done

- A boot service running as LocalSystem can create, materialize, and clean a
  child below the default root.
- A login scheduled task can do the same as the selected invoking user after a
  mode transition.
- Ordinary unrelated local users receive no inherited write grant in the
  privileged Windows acceptance test.
- Existing broad ACLs are reported and fail the security preflight rather than
  being silently accepted.
- Custom roots are never re-ACLed by this feature.
- Windows service installer, rollback, descriptor, and privileged tests pass;
  non-Windows builds remain unaffected.
