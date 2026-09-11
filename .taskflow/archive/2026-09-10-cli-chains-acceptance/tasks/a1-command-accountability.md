---
id: "a1-command-accountability"
title: "Classify every published CLI leaf in a fail-closed coverage manifest"
group: "A"
sequence: 1
repo: "."
base_branch: "main"
depends_on: []
importance: 8
complexity: 4
security_critical: true
production_touching: false
model_hint: "mid"
taskflow_refs: ["README.md", "02-target-architecture.md", "03-coverage-model.md"]
---

## Goal

Make every published command leaf accountable to generated, scripted,
dedicated, privileged, or intentionally surface-only evidence, and fail when
the command surface grows without a reviewed classification.

## Scope & seams

- Extend the existing command-surface integration tests; do not create a second
  source of truth for Clap's public tree.
- Record for each public leaf its coverage class, concrete evidence file/test,
  and any safety reason that excludes it from generated execution.
- Exclude hidden commands from the public inventory while separately proving
  their intentional hiding remains covered by existing surface tests.
- Reject missing classifications, stale command paths, duplicate rows, and an
  exclusion that names no existing evidence.
- Keep the manifest test-only and avoid workflow or production command changes.

## Definition of Done

1. Every public leaf under `auth`, `host`, `repo`, `org`, `daemon`, `service`,
   `tui`, `status`, `update`, and `wsl` has exactly one classification.
2. Adding a synthetic unclassified leaf makes the guard fail, and a stale or
   duplicate mapping is also mutation-sensitive.
3. Generated execution exclusions state a concrete safety boundary and link to
   a dedicated or privileged test where applicable.
4. The test runs in the default workspace nextest invocation on all three CI
   platforms.
5. App integration tests, workspace format, and clippy gates pass.
