---
id: "a3-distribution-and-readme"
title: "Install scripts, npm wrapper, Homebrew tap, release channel updates, and README with the permission disclosure"
group: "A"
sequence: 3
repo: "."
depends_on: ["a2-release-workflow"]
importance: 8
complexity: 6
security_critical: true
production_touching: true
model_hint: "top"
taskflow_refs: ["09-release-distribution.md", "07-security.md", "08-user-workflows.md", "05-infrastructure.md"]
---

## Goal

Deliver every v1 distribution channel (D11) and the README that fronts them
(D14, D21), so that one terminal command installs a working, checksum-verified
binary on each supported OS with **no security prompt**, and so that no user
reaches an install command without first reading what
`Administration: Read and write` means.

This task deliberately carries four channels plus the README as one unit: each
is individually small, they share the same published checksums, and splitting
them would guarantee they drift apart between releases.

## Scope & seams

**`install/install.sh` and `install/install.ps1`.** Each script must:

1. detect OS and architecture and select the matching asset;
2. download from `releases/latest/download/`, GitHub's documented stable
   latest-release address, so the scripts never need editing at release time;
3. verify SHA-256 against the published `SHA256SUMS` and **abort on mismatch**;
4. install to a stable, toolchain-independent path — `~/.local/bin` on
   macOS/Linux, `%LOCALAPPDATA%\Programs\runner-manager` on Windows — and report
   how to add it to `PATH` when it is not already there;
5. be idempotent and support a pinned `--version`.

Point 4 is load-bearing, not tidiness: `service install` records an **absolute**
binary path (`05-infrastructure.md`), so an install location that moves breaks
unattended start.

**npm wrapper.** A thin package with per-platform binaries as
`optionalDependencies`, the pattern esbuild uses. Document in its README that an
`npm i -g` binary lives under the active Node global prefix, which moves when
the operator switches Node versions, and that `service status` reports the
resulting stale path.

**Homebrew tap.** One formula in a `homebrew-tap` repository, pinned to the
published checksum.

**Release integration.** Add step 8 to `release.yml`: update the install
scripts, npm packages, and the tap formula, each pinned to the checksums this
run published.

**README (D14, D21).** Structure, in order: what the product is; the GitHub App
permission table from `07-security.md` and a plain statement that
`Administration: Read and write` also permits deleting, renaming, and
transferring the repository, and that it binds monitor-only users too; **then**
copy-paste install commands, one block per channel, install script first; then
the two-step download-read-run form for operators who will not pipe a remote
script into a shell. No direct-download buttons and no download images — every
advertised path is a terminal path, which is exactly why no certificate is
needed (D12, D14). Neither `winget` nor Scoop appears (D11).

## Definition of Done

- On a clean Windows, a clean macOS, and a clean Linux host that has never
  built the product, each channel installs a working binary and
  `runner-manager --version` succeeds — including a Windows host with **no Node
  installed**, which `irm … | iex` must serve.
- No install path triggers a Gatekeeper block or a SmartScreen warning on a
  clean Windows and a clean macOS host.
- Each install script aborts, with a clear message and a non-zero exit, when
  pointed at a deliberately corrupted asset.
- Each install script is idempotent: running it twice leaves one working
  binary. `--version X.Y.Z` installs that exact version.
- The Homebrew formula and npm package resolve to the same checksums the
  release published.
- The README states the permission set and the `Administration: Read and write`
  consequence **before** the first install command, and contains no
  direct-download button or image.
