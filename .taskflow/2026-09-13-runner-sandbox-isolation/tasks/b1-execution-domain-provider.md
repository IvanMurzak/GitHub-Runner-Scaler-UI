---
id: "b1-execution-domain-provider"
title: "Execution policy, attempt identity and native provider"
group: "B"
sequence: 1
repo: "."
base_branch: "main"
depends_on: ["a1-profile-domain-store"]
importance: 10
complexity: 9
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["02-target-architecture.md", "04-security-recovery.md"]
---

## Goal

Introduce fail-closed execution policy and provider contracts while preserving
the current native lifecycle exactly.

## Scope & seams

Add execution/backend/image/resource types, policy validation, forward-only
attempt/policy persistence and `AttemptExecution`. Extract native spawning into
the provider contract with capability, lifecycle and redacted diagnostics.

## Definition of Done

- Old rows are native and old live attempts recover unchanged.
- Isolated+ersistent and malformed/unknown provider shapes fail closed.
- Native provider passes all existing spawn/JIT secrecy/process identity tests.
- Attempts durably distinguish native process and isolated environment identity.
- No secret is added to SQLite, arguments, provider metadata or logs.

