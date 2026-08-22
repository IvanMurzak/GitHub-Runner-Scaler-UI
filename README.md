# runner-manager

**Local-first autoscaling for ephemeral GitHub Actions self-hosted runners.**

You own a machine — a desktop, a Mac mini, a spare server. `runner-manager`
watches the repositories and organizations you point it at, starts an ephemeral
self-hosted runner on that machine when a job is queued for it, and lets the
runner exit when the job is done. Nothing idles waiting for work, and nothing
about your machine is exposed to the internet.

It is one binary with two faces: a CLI (`runner-manager repo add`,
`service install`, `daemon run`) and a full-screen terminal UI
(`runner-manager tui`) for watching what is running.

- **No server, no webhook, no inbound port.** The tool polls GitHub over HTTPS.
  It opens no listening socket of any kind, so nothing has to be forwarded,
  tunnelled or exposed for it to work.
- **No GitHub App to create, no private key to handle.** You authenticate with
  GitHub's device flow — one command, one code, one approval — and install the
  project's published App on the repositories you choose.
- **Ephemeral runners only.** Each job gets a runner registered just in time
  and a workspace that is deleted afterwards. No long-lived runner sits around
  holding a token and a dirty working directory.
- **Boot-start service on Windows, macOS and Linux.** The machine reboots with
  nobody logged in and the agent comes back by itself.

It is deliberately **not** a hosted product, a control plane, or a fleet
manager. One person, their own machines, their own repositories.

---

## What you are granting

**Read this before you install anything.** It is not a formality, and it is not
the same conversation GitHub's installation screen will have with you.

Using `runner-manager` means installing the project's **published GitHub App**.
That App declares one permission set, the same for every user:

| Permission | Level | Why it is needed |
|---|---|---|
| Repository → Administration | **Read and write** | Registering a just-in-time runner at repository scope (`generate-jitconfig`). |
| Repository → Actions | Read | Counting in-progress workflow runs, which is the demand signal. |
| Repository → Metadata | Read | Mandatory for any repository access. |
| Organization → Self-hosted runners | Read and write | Registering a just-in-time runner at organization scope. |

### `Administration: Read and write` is not a narrow runner permission

GitHub does not offer a repository permission that means "may register a
self-hosted runner". `Administration` is the one that authorizes it, and **the
same grant also permits deleting, renaming and transferring the repository, and
adding and removing collaborators.**

That is unavoidable for repository-scoped runner registration. It is stated
here rather than left to the installation screen because it is a real cost, and
because a permission list on a consent dialog does not tell you what the words
mean.

### It binds you even if you only ever watch

`runner-manager` can be run purely as a dashboard: add a repository with no
capacity and it will never start a runner for it, only report what GitHub is
doing. **That mode grants exactly the same permissions.** A GitHub App grants
its whole declared permission set on installation; there is no per-installation
subset, and there is no read-only variant of this App.

So a user who wants nothing but in-progress workflow counts still grants the
ability to delete their repositories. Splitting the product across two published
Apps would fix that; it was rejected to keep one registration, one audit
surface and one onboarding path. The cost is accepted and disclosed rather than
hidden.

### Organization scope is materially narrower — prefer it

At **organization** scope the registration call is authorized by
`Organization → Self-hosted runners: Read and write` alone. That permission
confers no ability to delete, rename or transfer anything.

This is measured, not assumed: a verification spike registered an ephemeral
runner against an organization holding
`organization_self_hosted_runners=write` and **no** `organization_administration`
([`docs/spikes/d18-org-jit-verification.md`](docs/spikes/d18-org-jit-verification.md)).

Where both are possible, use an organization-scoped policy. The tool says so at
policy creation too.

### What you are trusting, and how to revoke it

- The project **never generates a private key** for the published App. A private
  key is what mints installation tokens; without one, the project cannot act on
  anyone's repositories even in principle. You cannot verify that from outside,
  and that is the irreducible price of "install our App".
- The App declares **no webhook URL**, so it receives no events from your
  repositories.
- Your access token is stored in the machine-scoped OS secret store, never in
  config, never in the database, never in logs.
- **Revoke completely at any time** by uninstalling the App or revoking the
  authorization in GitHub settings. Neither needs the project's cooperation.
  `runner-manager auth logout` also purges the local copy.

Full detail, including the threat model and the accepted trade-offs, is in
[`.taskflow/2026-08-21-local-runner-manager/07-security.md`](.taskflow/2026-08-21-local-runner-manager/07-security.md).

---

## Install

Every supported path is a terminal command. That is deliberate: Gatekeeper on
macOS and SmartScreen on Windows act on the quarantine flags a *browser* sets,
and `curl`, `irm`, `tar`, `brew`, `npm` and `cargo` do not set them — so no
install below triggers a security prompt on any supported OS.

### Install script — recommended

Installs to a fixed location that does not move when a toolchain moves:
`~/.local/bin` on macOS and Linux, `%LOCALAPPDATA%\Programs\runner-manager` on
Windows. That matters if you intend to run it as a boot-start service, because
the service records the binary's absolute path.

**macOS, Linux**

```sh
curl -fsSL https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases/latest/download/install.sh | sh
```

**Windows** (Windows PowerShell 5.1 or PowerShell 7 — no Node required)

```powershell
irm https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases/latest/download/install.ps1 | iex
```

Both scripts detect your OS and CPU, fetch the matching archive, **verify its
SHA-256 against the release's published `SHA256SUMS`, and abort without
installing anything if it does not match**. Running either script twice leaves
exactly one working binary.

To pin a version — note that a piped script gets no arguments of its own, so it
needs an explicit separator:

```sh
curl -fsSL https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases/latest/download/install.sh | sh -s -- --version 1.2.3
```

```powershell
$env:RUNNER_MANAGER_INSTALL_VERSION = '1.2.3'
irm https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases/latest/download/install.ps1 | iex
```

### npm

```sh
npm i -g runner-manager
```

A thin wrapper whose per-platform binaries are `optionalDependencies`, so npm
installs only the one that matches your machine.

**One caveat if you want a boot-start service.** An `npm i -g` binary lives
under the *active* Node installation's global prefix, which moves when you
switch Node versions with `nvm`, `fnm`, `volta` or `asdf`. Because
`service install` records the binary's absolute path, a Node upgrade can leave
the installed service pointing at a path that no longer exists.
`runner-manager service status` detects this and reports the recorded path as
stale rather than reporting the service as healthy; re-run `service install` to
fix it. The install script above has no such failure mode. See
[`npm/README.md`](npm/README.md).

### Homebrew

```sh
brew install IvanMurzak/tap/runner-manager
```

macOS and Linux. The formula is pinned to the SHA-256 the release published.

### Cargo

```sh
cargo install runner-manager
```

Builds from source. Needs a Rust toolchain; the version required is in
[`rust-toolchain.toml`](rust-toolchain.toml).

### If you will not pipe a remote script into a shell

Entirely reasonable. Download the script, read it, then run it — the two steps
that `|` collapses into one:

```sh
curl -fsSL -o install.sh https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases/latest/download/install.sh
less install.sh
sh ./install.sh
```

```powershell
irm https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases/latest/download/install.ps1 -OutFile install.ps1
Get-Content .\install.ps1 | more
Get-Content .\install.ps1 -Raw | iex
```

**Why the last line is not `.\install.ps1`.** On a Windows *client* the default
`LocalMachine` execution policy is `Restricted`, so running a downloaded `.ps1`
file fails with *"cannot be loaded because running scripts is disabled on this
system"* — after you have already read it, which is the worst possible moment.
`Get-Content ... | iex` runs the same text without involving the policy at all,
and it keeps the read-first property that is the whole point of this section.
If you would rather run the file, `powershell -ExecutionPolicy Bypass -File
.\install.ps1` also works.

The scripts are short and are the same files as
[`install/install.sh`](install/install.sh) and
[`install/install.ps1`](install/install.ps1) in this repository.

`install.sh` needs `curl` (or `wget`), `tar`, the POSIX text tools every
system already has — `awk`, `sed`, `grep`, `cut`, `tr`, `mktemp` — and **a
SHA-256 tool: `sha256sum`, `shasum` or `openssl`.** That last one is not
optional and there is no flag to skip it: on a host with none of the three the
script refuses to install rather than installing something it could not verify.
`install.ps1` needs only what ships with Windows PowerShell 5.1, and in
practice only `Invoke-WebRequest`. It does **not** require `Get-FileHash` or
`Expand-Archive`: both live in modules that a rearranged `PSModulePath` or the
default `Restricted` execution policy can put out of reach, so the digest and
unpack steps fall back to the .NET framework types behind those cmdlets when
the modules cannot be loaded. The SHA-256 check is computed on both paths and
there is no path that skips it.

### Confirm it worked

```sh
runner-manager --version
```

If the command is not found, the installer printed the one line needed to add
its directory to your `PATH`. Neither script edits a shell profile or the
registry on your behalf.

---

## Quick start

```sh
# 1. Authenticate. Prints a URL and a short code; you approve in the browser.
runner-manager auth login

# 2. Install the published App on the repositories you choose
#    (the previous command prints the URL).

# 3. Point a repository at this machine.
runner-manager repo add OWNER/REPO --host-label home-win --max-capacity 1

# 4. Copy the routing label it prints into your workflow's `runs-on:`.

# 5. Arm it.
runner-manager repo set-scale OWNER/REPO --enabled true

# 6. Keep it running across reboots.
runner-manager service install
```

Then watch it work:

```sh
runner-manager tui
```

Monitor-only is step 3 without `--max-capacity`: the repository appears in the
UI with its runners and in-progress workflow count, and no runner is ever
started for it. It still requires the same App installation — see
[What you are granting](#what-you-are-granting).

---

## Verifying a release yourself

Every release publishes `SHA256SUMS` and a CycloneDX SBOM alongside the
archives. The install scripts check the digest for you; to check by hand, fetch
the checksum file and the archive from the release and run:

```sh
sha256sum -c SHA256SUMS       # Linux, or Git Bash on Windows
shasum -a 256 -c SHA256SUMS   # macOS
```

The SBOM marks components with `"scope": "excluded"` when they are in the
workspace lock file but not in the binary you downloaded — test-only crates,
and crates conditional on an operating system you did not download. A scan that
ignores `scope` will report advisories against code these artifacts do not
contain.

macOS binaries carry an ad-hoc signature, which is what lets arm64 builds
execute at all; the release workflow verifies it is present before publishing.
There is no paid code-signing certificate on any platform, and none is needed,
because every documented install path above is a terminal command.

---

## Supported platforms

| OS | Architectures |
|---|---|
| Windows | x64 (ARM64 via the install script, using the x64 build under emulation) |
| macOS | Apple Silicon, Intel |
| Linux | x64, ARM64 (glibc; on musl, build with `cargo install`) |

---

## Licence

MIT — see [LICENSE](LICENSE).
