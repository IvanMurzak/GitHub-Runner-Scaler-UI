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

The macOS job runs on ARM64 so the platform the persona actually uses is the
platform that is tested. CI is a required status check on `main`.

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
   greater than both. Checking both sources means a manual edit to either one
   cannot let a regression through.
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
8. **Update the downstream channels** — the install scripts, npm packages, and
   the Homebrew tap formula — each pinned to the published checksums.

If a step after tagging fails, the run stops with the tag present and no
release published; the operator deletes the tag and re-dispatches. The workflow
never deletes a published release.

## Distribution channels (D11)

| Channel | Platforms | Notes |
|---|---|---|
| Install script | all | `curl -fsSL <url>/install.sh \| sh`, and `irm <url>/install.ps1 \| iex` on Windows. The universal fallback for a host with no package manager — notably Linux, where Homebrew is uncommon and no `.deb`/`.rpm` is produced. |
| npm wrapper package | all | Thin package with per-platform binaries as `optionalDependencies`, the pattern esbuild and similar tools use. |
| Homebrew tap | macOS, Linux | One formula in a `homebrew-tap` repository, updated by the release workflow. |
| `cargo install` | all | Builds from source; free for a Rust project and matches the audience. |
| GitHub Releases archives | all | The substrate every channel above pulls from and pins checksums against. Published every release, but not an advertised install path (D14). |

Neither `winget` nor Scoop is a product channel. On Windows, npm serves anyone
with Node and `irm <url>/install.ps1 | iex` serves everyone else, so a third
Windows channel would add a manifest to keep in sync on every release without
reaching a user the first two miss. `microsoft/winget-pkgs` would also put an
external reviewer on the critical path of every release.

### The install script

`install.sh` and `install.ps1` live in `install/` and are published with each
release. Each script must:

1. detect OS and architecture and select the matching asset;
2. download it from `releases/latest/download/`, GitHub's documented stable
   latest-release address, so the scripts never need editing at release time;
3. verify the SHA-256 against the published `SHA256SUMS` and abort on mismatch;
4. install to a **stable, toolchain-independent** path —
   `~/.local/bin` on macOS/Linux, `%LOCALAPPDATA%\Programs\runner-manager` on
   Windows — and report how to add it to `PATH` if it is not already there;
5. be idempotent, and support a pinned `--version`.

Point 4 matters beyond tidiness: because the installed service records an
absolute binary path (`05-infrastructure.md`), an install location that moves
would break unattended start. A script-installed binary has a fixed home; an
`npm i -g` binary does not.

The README also shows the two-step form — download, read, then run — for
operators who will not pipe a remote script into a shell.

### Why no paid code signing (D12)

Gatekeeper acts only on files carrying `com.apple.quarantine`, and SmartScreen
acts only on files carrying Mark-of-the-Web. Browsers set these attributes;
`curl`, `irm`, `tar`, `brew`, `npm`, and `cargo` do not. Since D14
removed direct-download buttons, **every documented install path is a terminal
path**, so no user meets a security prompt on any supported OS and no
certificate is needed to avoid one.

Two things remain mandatory and are free:

- **Ad-hoc signature on arm64 macOS binaries.** macOS refuses to execute
  unsigned native arm64 code. The linker produces this automatically; the
  release workflow verifies it rather than assuming it.
- **SHA-256 checksums and an SBOM** on every artifact, verified by the install
  script and pinned by every package manifest.

Paid Authenticode and Apple Developer certificates are reconsidered at GA only
if a browser-download path is ever reintroduced.

### npm and the boot-start service

An `npm i -g` binary lives under the active Node installation's global prefix,
which moves when the operator switches Node versions. Because the installed
service records an absolute binary path, a Node upgrade can leave the service
pointing at a path that no longer exists. `service status` must detect and
report this, and the install smoke test covers the npm-upgrade case explicitly.
The install script does not have this failure mode, which is one reason it is
listed first.

## README structure (D14)

The repository `README.md` states the GitHub App permission set and what
`Administration: Read and write` implies **before** the install commands (D21),
then gives copy-paste install commands, one block per channel, install script
first. There are no direct-download buttons and no
download images: every advertised path is a terminal command.

Release archives remain published and linkable at
`https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases/latest/download/<asset>`
for anyone who wants them, but the README does not present them as the way in.

An animated terminal demo of the TUI is optional and, if added, must not be
required to understand how to install or use the product.

## Acceptance evidence

| Requirement | Evidence |
|---|---|
| Tests run on PR open/update and on merge to `main` | CI required-check history on a pull request and on `main`. |
| Release is manual only | `release.yml` contains exactly one trigger, `workflow_dispatch`. |
| Malformed version rejected | Rehearsal run with `1.2`, `v1.2.3`, and `abc` fails at step 1. |
| Non-increasing version rejected | Rehearsal run with a version equal to and below the current release fails at step 2. |
| Tests gate the release | Rehearsal run with a deliberately failing test publishes nothing. |
| Artifacts published per OS | Release page lists Windows, macOS x64/arm64, and Linux x64/arm64 assets plus `SHA256SUMS` and SBOM. |
| One-command install per OS | Journey 0 gate in `08-user-workflows.md`, run on a machine that has never built the product. |
| No install path triggers a security prompt | Each channel installed and launched on a clean Windows and a clean macOS host with no Gatekeeper block and no SmartScreen warning. |
| Install script verifies integrity | Script aborts on a deliberately corrupted asset. |
| Permission disclosure is present (D21) | README states the grant before the install commands; `auth login` and monitor-only `add` repeat it. Copy reviewed each release. |
| Install path survives a toolchain change | Service still starts after a Node version switch, or `service status` reports the stale path as an error. |
