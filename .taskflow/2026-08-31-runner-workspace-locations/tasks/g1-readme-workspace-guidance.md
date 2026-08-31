---
id: "g1-readme-workspace-guidance"
title: "Document runner placement and persistent caches"
group: "G"
sequence: 1
repo: "."
base_branch: "main"
depends_on: ["c3-persistent-cleanup-recovery", "d1-workspace-cli-read-models", "e1-workspace-tui"]
importance: 8
complexity: 4
security_critical: false
production_touching: false
model_hint: "fast"
taskflow_refs: ["02-target-architecture.md", "04-security-recovery.md", "05-user-workflows.md"]
---

## Goal

Help users quickly find the default path, change global runner placement, opt
one repository into persistent slots, preserve ignored build outputs, and
understand the trust boundary.

## Scope & seams

- Update the README Commands code block from generated CLI help.
- Replace the current `--data-dir` runner-placement implication with complete
  global and repository commands using `<GLOBAL_RUNNER_ROOT>` and
  `<REPOSITORY_WORKSPACE_ROOT>` placeholders.
- State the Windows default `%SystemDrive%\rman` and example `C:\rman`, plus the
  unchanged macOS and Linux default behavior.
- Include the command to return a repository to ephemeral mode and state that
  no old directory is moved or deleted.
- Keep the official `actions/checkout` `clean: false` example next to persistent
  workspace guidance and explain that it does not create persistence alone.
- Present the cross-job trust warning in user-benefit language and keep each
  feature line concise.
- Preserve the current user-first section order, collapsible installation
  details, terminal-dashboard placement, GIF placeholders, and character rules.

## Definition of Done

- Every documented command runs through the real Clap parser and matches
  generated help.
- README disclosure and command-surface tests cover the new defaults, complete
  placeholder commands, ephemeral reset, checkout setting, warning, and
  non-deletion statement.
- No text claims `--data-dir` is the host runner-root control after the feature.
- No text claims `clean: false` retains files in ephemeral mode.
- No prohibited em dash character appears in README.
- Markdown structure tests, README tests, link checks, and formatting gates
  pass.
