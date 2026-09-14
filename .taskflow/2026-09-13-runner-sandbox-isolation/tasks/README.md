# Task specs

Immutable implementation specs derived from the reviewed architecture on
2026-09-13. `ROADMAP.md` is the only live status record. Groups are conflict
domains; sequence is strict within a group and cross-group `depends_on` controls
readiness. Execution uses isolation branch `isolation/runner-sandbox-profiles`
with Merge on Green.

