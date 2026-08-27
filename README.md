# runner-manager

**Local-first autoscaling for ephemeral GitHub Actions self-hosted runners.**

Point `runner-manager` at the repositories or organizations you own. When a job is queued,
it registers a just-in-time runner on your machine, lets it take the job, and removes it
when the job ends. Nothing idles between jobs, and nothing on your machine listens on the
network.

One binary, two faces: a CLI for setup and scripting, and a full-screen terminal UI
(`runner-manager tui`) for watching it work.

## Features

- ✅ **No inbound port, webhook, or server** — the agent polls GitHub over HTTPS.
- ✅ **Ephemeral runners** — a fresh just-in-time runner and workspace per job.
- ✅ **Boot-start service** on Windows, macOS and Linux.
- ✅ **Capacity ceilings** per machine and per policy.
- ✅ **Monitor-only mode** — watch a repository without ever starting a runner.
- ✅ **Terminal UI** — live dashboard, runners, activity, and settings.
- ✅ **Credentials in the OS secret store** — never in config, the database, or logs.

## Quick start

Not installed yet? See [Install](#install).

```sh
# 1. Sign in. Prints a code to enter on GitHub, then the URL to install the App.
runner-manager auth login

# 2. Point a repository at this machine. Omit --max-capacity for monitor-only.
runner-manager repo add OWNER/REPO --host-label home --max-capacity 1

# 3. Arm it.
runner-manager repo set-scale OWNER/REPO --enabled true

# 4. Keep it running across reboots.
runner-manager service install
```

Step 2 prints the routing label it reserved — `rm-home-win-x64` for host label `home` on a
Windows x64 machine. Send jobs to it:

```yaml
jobs:
  build:
    runs-on: rm-home-win-x64
```

Then watch it work:

```sh
runner-manager tui
```

Organizations use the same commands with `org` in place of `repo`.

## Commands

| Command | What it does |
|---|---|
| `auth login`, `auth status`, `auth logout` | Sign in with GitHub's device flow, check the stored credential against GitHub, purge it. `auth status --list` names every repository the credential reaches; `auth status --permissions` reprints the grant below. |
| `host show`, `host set-capacity N` | This machine's runner ceiling, secret store, and projected REST budget. |
| `repo add`, `repo list`, `repo set-capacity`, `repo set-scale`, `repo remove` | Repository-scoped policies. |
| `org add`, `org list`, `org set-capacity`, `org set-scale`, `org remove` | The same, organization-scoped. |
| `status`, `status --json` | One snapshot of this host, for a human or for a script. |
| `daemon run` | Run the agent in the foreground — what the service runs, and useful for watching it. |
| `service install`, `service status`, `service uninstall` | Register the agent with the OS service manager, `--start-at boot` (default) or `login`. |
| `tui` | Open the terminal UI. |

Every command accepts `--data-dir DIR` to use a different config, state and runtime root.
Failures name the command that fixes them and exit with a distinct code per failure class.

## Terminal UI

`d` dashboard · `r` repositories · `n` runners · `a` activity · `s` repository settings ·
`h` host settings · `/` filter · `o` sort · `c` copy · `F5` refresh · `?` help · `q` quit

## What you are granting

Signing in installs a GitHub App on the repositories or organizations you pick, with one
permission set for every user:

| Permission | Level | Why it is needed |
|---|---|---|
| Repository → Administration | **Read and write** | Registering a just-in-time runner at repository scope. |
| Repository → Actions | Read | Counting in-progress workflow runs, the demand signal. |
| Repository → Metadata | Read | Mandatory for any repository access. |
| Organization → Self-hosted runners | Read and write | Registering a just-in-time runner at organization scope. |

- `Administration: Read and write` is the only permission that authorizes runner
  registration, and the same grant permits deleting, renaming and transferring the
  repository, and adding or removing collaborators.
- A monitor-only dashboard grants the same permissions — an App grants its whole declared
  set on installation.
- Organization scope is narrower: registration there needs only `Self-hosted runners: Read
  and write` ([verified](docs/spikes/d18-org-jit-verification.md)).
- Revoke any time in GitHub settings; `runner-manager auth logout` purges the local copy.
  The project generates no private key, and the App declares no webhook URL.

`runner-manager auth status --permissions` prints this same table at a prompt. It needs no
credential and makes no request, so it can be read before deciding to sign in at all.

## Install

**npm** — any OS with Node 18+:

```sh
npm i -g @ivan-murzak/runner-manager
```

**Homebrew** — macOS, Linux:

```sh
brew install IvanMurzak/tap/runner-manager
```

**Install script** — macOS, Linux, no Node needed:

```sh
curl -fsSL https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases/latest/download/install.sh | sh
```

**Install script** — Windows, PowerShell 5.1 or 7, no Node needed:

```powershell
irm https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases/latest/download/install.ps1 | iex
```

Then check it:

```sh
runner-manager --version
```

Every path above is a terminal command, deliberately: Gatekeeper on macOS and SmartScreen
on Windows act on the quarantine flag a *browser* sets, and `curl`, `irm`, `tar`, `brew`,
`npm` and `cargo` do not set one — so no install here raises a security prompt.

### Which one to pick

The **install script** is the one to use for a boot-start service. It installs to a fixed
location — `~/.local/bin`, or `%LOCALAPPDATA%\Programs\runner-manager` on Windows — that
does not move when a toolchain moves, and `service install` records the binary's absolute
path.

An **npm** global binary lives under the *active* Node prefix, which moves when you switch
versions with nvm, fnm, volta or asdf. `runner-manager service status` reports the recorded
path as stale when that happens; re-run `service install` to fix it. The npm package name is
scoped: plain `runner-manager` on npmjs.com is an unrelated project.

### Install script details

Both scripts detect your OS and CPU, verify the archive's SHA-256 against the release's
published `SHA256SUMS`, and abort without installing anything if it does not match. To pin a
version — a piped script gets no arguments of its own, hence the separator:

```sh
curl -fsSL https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases/latest/download/install.sh | sh -s -- --version 1.2.3
```

```powershell
$env:RUNNER_MANAGER_INSTALL_VERSION = '1.2.3'
irm https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases/latest/download/install.ps1 | iex
```

### Read the script before running it

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

The last line runs the script's text rather than the file on purpose: a Windows client's
default execution policy is `Restricted`, which refuses `.\install.ps1` after you have
already read it.

### From source

```sh
cargo install runner-manager
```

Or from a checkout of this repository, which is how to run it before the first release is
tagged:

```sh
cargo build --release -p runner-manager
```

The binary lands in `target/release/`. Both need the Rust toolchain pinned in
[rust-toolchain.toml](rust-toolchain.toml). Put it somewhere permanent before
`service install` records its absolute path.

If `runner-manager --version` is not found after installing, the installer printed the one
line that adds its directory to your `PATH`. Neither script edits a shell profile or the
registry on your behalf.

## Supported platforms

| OS | Architectures |
|---|---|
| Windows | x64 (ARM64 via the install script, running the x64 build under emulation) |
| macOS | Apple Silicon, Intel |
| Linux | x64, ARM64 (glibc; on musl, build from source) |

## Licence

MIT — see [LICENSE](LICENSE).
