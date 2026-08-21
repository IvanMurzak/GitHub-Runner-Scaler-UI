# CI, release, and distribution

Owner requirements D10, D11, D12, and D14.

## Continuous integration

One workflow, `.github/workflows/ci.yml`, triggered by:

```text
pull_request:  types: [opened, synchronize, reopened]
push:          branches: [main]
```

Job matrix: `windows-latest`, `macos-latest`, `ubuntu-latest`. Each job runs
`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and
`cargo test --workspace`, against the toolchain pinned in
`rust-toolchain.toml`, with a committed `Cargo.lock` and a dependency cache.

The macOS job runs on ARM64 so the platform that the persona actually uses is
the platform that is tested. CI is a required status check on `main`.

There is no release trigger in this workflow.

## Release workflow

One workflow, `.github/workflows/release.yml`, with a single trigger:

```text
workflow_dispatch:
  inputs:
    version:  { required: true, description: "X.Y.Z" }
```

No `push`, `tag`, `schedule`, or `release` trigger exists. Permissions are the
minimum needed to publish: `contents: write`.

Ordered steps, each of which fails the run:

1. **Validate format.** Reject any `version` that is not `X.Y.Z` semver.
2. **Validate monotonicity.** Read the current `Cargo.toml` version and the
   latest published GitHub Release. Reject the run unless `version` is strictly
   greater than both. This is the "error if the version is lower than the
   current one" requirement, checked against both sources so a manual edit to
   either one cannot let a regression through.
3. **Run every test.** The same matrix as CI, on the release commit. A single
   failure stops the release before anything is published.
4. **Write the version.** Set `version` in `Cargo.toml`, refresh `Cargo.lock`,
   commit, and tag `vX.Y.Z`. The workflow owns the version number; no manual
   bump is expected beforehand.
5. **Build artifacts** on native runners for each target
   (`x86_64-pc-windows-msvc`, `aarch64-apple-darwin`, `x86_64-apple-darwin`,
   `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`). Verify that each
   macOS binary carries at least an ad-hoc signature; an unsigned arm64 Mach-O
   will not execute on Apple Silicon at all.
6. **Package** as `.zip` for Windows and `.tar.gz` for macOS/Linux, and emit
   `SHA256SUMS` plus an SBOM.
7. **Publish** the GitHub Release with all artifacts attached.
8. **Update the downstream channels** — npm packages, Homebrew tap formula, and
   Scoop bucket manifest — each pinned to the published checksums.

If any step after tagging fails, the run stops with the tag present and no
release published; the operator deletes the tag and re-dispatches. The workflow
never deletes a published release.

## Distribution channels (D11)

| Channel | Platforms | Notes |
|---|---|---|
| GitHub Releases archives | all | The substrate. Every other channel pulls these artifacts and pins their checksums. Also the target of the README download buttons. |
| npm wrapper package | all | Thin package with per-platform binaries as `optionalDependencies`, the pattern esbuild and similar tools use. This is the Windows story, which is why `winget` is excluded entirely. |
| Homebrew tap | macOS, Linux | One formula in a `homebrew-tap` repository, updated by the release workflow. |
| Scoop bucket | Windows | One JSON manifest. Serves Windows operators who do not have Node. |
| `cargo install` | all | Builds from source; free for a Rust project and matches the audience. |

`winget` is not a product channel. npm covers Windows, and
`microsoft/winget-pkgs` moderation would put an external reviewer on the
critical path of every release.

### Why no paid code signing (D12)

Gatekeeper acts only on files carrying `com.apple.quarantine`, and SmartScreen
acts only on files carrying Mark-of-the-Web. Browsers set these attributes;
`curl`, `tar`, `brew`, `scoop`, `npm`, and `cargo` do not. Every channel above
except the README buttons therefore installs with no security prompt and no
certificate.

Two things remain mandatory and are free:

- **Ad-hoc signature on arm64 macOS binaries.** macOS refuses to execute
  unsigned native arm64 code. The linker produces this automatically; the
  release workflow verifies it rather than assuming it.
- **SHA-256 checksums and an SBOM** on every artifact.

Operators who use the README download buttons instead of a package manager will
see a Gatekeeper block on macOS and a SmartScreen warning on Windows. The
README documents the one-line quarantine removal beside the buttons. Paid
Authenticode and Apple Developer certificates are reconsidered at GA if that
path becomes the common one.

### npm and the boot-start service

An `npm i -g` binary lives under the active Node installation's global prefix,
which moves when the operator switches Node versions. Because the installed
service records an absolute binary path (`05-infrastructure.md`), a Node
upgrade can leave the service pointing at a path that no longer exists.
`service status` must detect and report this; the install smoke test covers the
npm-upgrade case explicitly.

## README download buttons (D14)

The repository `README.md` opens with copy-paste install commands, one per
channel. Below them sit three clickable download buttons, one per OS.

Mechanics:

- Each button is a hand-authored SVG in `assets/`, animated with a `<style>`
  block inside the SVG file itself, wrapped as
  `<a href="..."><img src="assets/download-windows.svg"></a>`.
- Links use `https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases/latest/download/<asset>`,
  GitHub's documented stable latest-release address, so the README never needs
  editing at release time.
- `<picture>` with `prefers-color-scheme` supplies a dark-theme variant.

Constraint: **the button must be fully legible and clickable as a static
image.** GitHub does not reliably animate README SVGs in every browser — an
open, unaddressed report describes animation failing in Firefox while working
in Chrome. Animation is decoration; it may never carry the OS name, the word
"Download", or any other information the reader needs.

The asset filenames embed the version-independent target, for example
`runner-manager-windows-x64.zip`, so the `latest/download/` links stay valid
across releases.

## Acceptance evidence

| Requirement | Evidence |
|---|---|
| Tests run on PR open/update and on merge to `main` | CI required-check history on a pull request and on `main`. |
| Release is manual only | `release.yml` contains exactly one trigger, `workflow_dispatch`. |
| Malformed version rejected | Rehearsal run with `1.2`, `v1.2.3`, and `abc` fails at step 1. |
| Non-increasing version rejected | Rehearsal run with a version equal to and below the current release fails at step 2. |
| Tests gate the release | Rehearsal run with a deliberately failing test publishes nothing. |
| Artifacts published per OS | Release page lists Windows, macOS x64/arm64, and Linux x64/arm64 assets plus `SHA256SUMS` and SBOM. |
| One-command install per OS | Journey 0 gate in `08-user-workflows.md`. |
| Buttons resolve correctly | Each `latest/download/` link fetched after a release returns the expected asset. |
| Buttons work without animation | Static render of each SVG is reviewed for legibility with animation disabled. |
