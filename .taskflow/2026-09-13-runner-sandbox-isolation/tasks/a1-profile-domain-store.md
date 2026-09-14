---
id: "a1-profile-domain-store"
title: "Named runner profiles and forward-only persistence"
group: "A"
sequence: 1
repo: "."
base_branch: "main"
depends_on: []
importance: 9
complexity: 8
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["02-target-architecture.md", "05-routing-profiles.md", "06-review-findings.md"]
---

## Goal

Allow multiple case-insensitive named policies for one repository while
preserving every existing row/workflow as native profile `default`.

## Scope & seams

Add validated `ProfileName`, derived immutable selector semantics and profile
identity to domain/testkit. Add a new forward-only SQLite migration, named
persisted fields, composite uniqueness and load-time validation. Never edit old
migrations. Update all named store mappings and round-trip/migration tests.

## Definition of Done

- Existing databases migrate byte-preservingly to one native `default` profile.
- `(host,target,profile)` is unique case-insensitively; same target/different profiles work.
- Selectors are derived/non-overridable and cannot be reused as sibling optional labels.
- Corrupt/ambiguous stored shapes fail closed with typed errors.
- Domain/store/testkit suites and warnings-denied checks pass.

