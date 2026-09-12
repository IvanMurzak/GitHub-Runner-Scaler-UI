---
id: "a5-service-health"
title: "Report truthful supervised service health"
group: "A"
sequence: 5
repo: "."
base_branch: "main"
depends_on: ["a4-service-install-start"]
importance: 2
complexity: 5
security_critical: false
production_touching: false
model_hint: "mid"
taskflow_refs: ["03-windows-service-lifecycle.md", "ROADMAP.md#G8"]
---

## Goal

Prevent a stopped automatic task or stale daemon from receiving a healthy
verdict.

## Scope & seams

Add typed runtime states and heartbeat/contact age to service status text/JSON,
while retaining registration-integrity diagnostics and idle/no-policy rules.

## Definition of Done

- Starting, running, backoff, stopped and failed render distinctly.
- Stopped outside grace is unhealthy; idle/no-policy current heartbeat is
  healthy without GitHub traffic.
- Exact JSON keys/schema and service status tests are updated.

