---
id: "a2-release-workflow"
title: "Manual release workflow: version validation, full test gate, cross-target artifacts, checksums, SBOM"
group: "A"
sequence: 2
repo: "."
depends_on: ["a1-workspace-ci-foundation"]
importance: 8
complexity: 6
security_critical: false
production_touching: true
model_hint: "top"
taskflow_refs: ["09-release-distribution.md", "07-security.md"]
---

## Goal

Fill in `.github/workflows/release.yml` so that the only way to publish is a
deliberate human dispatch that cannot publish an invalid version, cannot
publish untested code, and cannot publish an unverifiable artifact (D10, D12).

## Scope & seams

Implements the ordered steps in `09-release-distribution.md`, each of which
fails the run:

1. **Validate format.** Reject any `version` input that is not `X.Y.Z` semver.
   `1.2`, `v1.2.3`, and `abc` must all fail here.
2. **Validate monotonicity.** Read both the current `Cargo.toml` version and
   the latest published GitHub Release, and reject unless `version` is strictly
   greater than **both**. Checking one source alone lets a manual edit to the
   other regress the version.
3. **Run every test.** The same three-OS matrix as CI, on the release commit.
4. **Write the version.** Set `version` in `Cargo.toml`, refresh `Cargo.lock`,
   commit, tag `vX.Y.Z`. The workflow owns the version number; no manual bump
   precedes it.
5. **Build artifacts** on native runners for `x86_64-pc-windows-msvc`,
   `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-gnu`,
   `aarch64-unknown-linux-gnu`. Verify each macOS binary carries at least an
   ad-hoc signature — an unsigned arm64 Mach-O does not execute on Apple
   Silicon at all (D12). Verify, do not assume the linker did it.
6. **Package** `.zip` for Windows, `.tar.gz` for macOS/Linux; emit `SHA256SUMS`
   and an SBOM.
7. **Publish** the GitHub Release with every artifact attached.

Failure semantics are part of the contract: if a step after tagging fails, the
run stops with the tag present and no release published, and the workflow never
deletes a published release. Document the operator recovery — delete the tag,
re-dispatch — in the workflow file itself.

Keep `permissions: contents: write` and the single `workflow_dispatch` trigger
from `a1`. No paid code signing is introduced (D12).

Step 8 of the design's list — updating install scripts, npm, and the Homebrew
tap — belongs to `a3`, which adds it to this workflow.

## Definition of Done

- A rehearsal dispatch with `1.2`, with `v1.2.3`, and with `abc` fails at
  step 1 in every case.
- A rehearsal dispatch with a version equal to, and one below, the current
  release fails at step 2, for both the `Cargo.toml` source and the GitHub
  Release source independently.
- A rehearsal with a deliberately failing test publishes nothing.
- A successful rehearsal produces a release page listing Windows, macOS x64 and
  arm64, and Linux x64 and arm64 assets plus `SHA256SUMS` and an SBOM.
- The macOS signature check fails the run when given a deliberately stripped
  binary.
- `release.yml` still contains exactly one trigger and no elevated permission
  beyond `contents: write`.
