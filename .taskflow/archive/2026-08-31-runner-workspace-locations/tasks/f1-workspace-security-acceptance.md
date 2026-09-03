---
id: "f1-workspace-security-acceptance"
title: "Prove workspace migration, isolation, and recovery"
group: "F"
sequence: 1
repo: "."
base_branch: "main"
depends_on: ["b2-windows-root-acl", "c3-persistent-cleanup-recovery", "d1-workspace-cli-read-models", "e1-workspace-tui"]
importance: 10
complexity: 10
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["03-migration-rollout.md", "04-security-recovery.md", "ROADMAP.md"]
---

## Goal

Exercise the completed feature as one system across supported platforms and
prove the migration, cleanup, concurrency, service, and rollback gates.

## Scope & seams

- Add end-to-end fixtures for version-2 migration, exact old-path recovery, new
  default allocation ordering, and future-schema refusal.
- Run disposable success, failure, idle, cancellation, restart, and cleanup
  cases without relaxing existing contamination gates.
- Run two-job persistent retention, runner-state scrubbing, concurrent slot,
  cleanup failure, quarantine, and crash-boundary cases.
- Exercise root, overlap, remote, traversal, symlink, junction, permission, and
  deletion-failure adversarial cases with deletion confined to temporary roots.
- Add real Windows boot and login service smoke coverage for default root and
  ACL behavior behind the existing privileged-test gate.
- Prove macOS and Linux retain their defaults and support repository persistent
  slots.
- Rehearse backup-based schema rollback without deleting any runner directory.
- Fix only confirmed integration defects within the reviewed contract. Any new
  product decision returns to the owner and pauses this task.

## Definition of Done

- Every required-evidence item in ROADMAP has a named automated test or recorded
  privileged pilot command and result.
- Disposable and persistent two-job tests prove their opposite retention
  guarantees simultaneously.
- No JIT value, token, or credential appears in database, directories outside
  restrictive handoff, logs, status JSON, TUI snapshots, or crash reports.
- Windows privileged evidence shows the resolved system drive, restrictive ACL,
  boot identity, login identity, creation, and cleanup.
- Full workspace tests, formatting, linting, supported-platform checks,
  privileged gates where available, and mutation tests pass.
- Rollback evidence restores the old database and binary while leaving all
  workspace directories untouched.
