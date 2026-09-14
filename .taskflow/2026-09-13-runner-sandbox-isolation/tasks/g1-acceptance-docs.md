---
id: "g1-acceptance-docs"
title: "Cross-platform profile isolation acceptance and documentation"
group: "G"
sequence: 1
repo: "."
base_branch: "main"
depends_on: ["c2-profile-tui", "d1-linux-wsl-oci", "d2-windows-hyperv", "d3-macos-vm"]
importance: 10
complexity: 9
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["03-platform-strategy.md", "04-security-recovery.md", "05-routing-profiles.md"]
---

## Goal

Close every support gate with reproducible evidence and document the exact V1
guarantee, prerequisites, configuration and limitations.

## Scope & seams

Add native CI/manual-host fixtures for same-workflow native+isolated jobs,
dependency conflict, residues, provider loss, crash/reboot and secret inspection.
Update README, CLI help, security disclosure and release notes.

## Definition of Done

- G1-G12 have automated or explicitly required-native evidence; no mock closes a native gate.
- Full workspace fmt, warnings-denied Clippy and tests pass.
- README includes CLI/TUI journeys, platform matrix and static selector examples.
- Docs say trusted dependency isolation, not hostile-code containment.
- Unsupported platform/action combinations fail closed and are not advertised supported.

