---
id: "b1-runner-path-platform"
title: "Resolve and preflight local runner roots"
group: "B"
sequence: 1
repo: "."
base_branch: "main"
depends_on: ["a1-workspace-domain"]
importance: 10
complexity: 9
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["02-target-architecture.md", "03-migration-rollout.md", "04-security-recovery.md"]
---

## Goal

Resolve the short Windows default and provide one operational validator for
local, writable, non-overlapping runner roots without changing application-data
placement.

## Scope & seams

- Add a runner-root concept beside `AppPaths`, not inside its config/state/log
  layout.
- Resolve Windows from the system-directory volume and append `rman`; keep
  macOS and Linux defaults equal to the existing runtime directory.
- Provide injectable platform seams so tests never assume `C:` or the current
  machine's mounts.
- Operationally preflight local filesystem identity, canonical containment,
  writable existing directories, and creatable leaves below writable parents.
- Reject filesystem roots, remote or unprovable filesystem identity, host and
  repository root overlap, protected application-data overlap, repository to
  repository overlap, symlink escapes, and existing files.
- Canonicalize the nearest existing parent for a not-yet-created leaf.
- Return typed actionable errors shared by CLI, TUI, daemon, and recovery.
- Keep creation and ACL mutation as explicit callers outside validation.

## Definition of Done

- Windows default renders `<system-drive>\rman` and normally `C:\rman` without
  reading a mutable `%SystemDrive%` value as authority.
- macOS and Linux defaults are byte-identical to their previous runtime paths.
- Table-driven tests cover local, remote, UNC, device, root, overlap,
  unwriteable, symlink or junction, existing-file, and creatable-leaf cases.
- Validation performs no deletion or permission mutation.
- Derived attempt and slot paths have tested lexical and canonical containment.
- Platform crate tests, formatting, linting, and supported-target builds pass.
