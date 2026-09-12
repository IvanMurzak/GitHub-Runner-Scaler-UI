---
id: "d2-docs-release"
title: "Document self-maintenance, recovery limits and migration"
group: "D"
sequence: 2
repo: "."
base_branch: "main"
depends_on: ["d1-acceptance-security-packaging"]
importance: 2
complexity: 3
security_critical: false
production_touching: false
model_hint: "fast"
taskflow_refs: ["README.md", "03-windows-service-lifecycle.md", "04-wsl-recovery-safety.md", "05-tui-status-ux.md"]
---

## Goal

Make automatic behavior, safety vetoes and operator remediation discoverable.

## Scope & seams

Update README, service-account/security docs, CLI help, status examples and
CHANGELOG. Explain dedicated-host eligibility and observation-only migration.

## Definition of Done

- No documentation tells users to manually start after install or keep a
  console window open.
- Recovery states, thresholds, no-elevation evidence and fail-closed limits are
  explicit.
- Migration names unmanaged runners and the safe path to eligibility.
