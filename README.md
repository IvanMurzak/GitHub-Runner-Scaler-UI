# runner-manager

**Local-first autoscaling for ephemeral GitHub Actions self-hosted runners.**

Use your own Windows, macOS or Linux machine to pick up GitHub Actions jobs only when work
is waiting. `runner-manager` registers a just-in-time runner, lets it complete one job and
removes it afterwards. You get local compute without an idle runner or an inbound network
service.

<!-- GIF placeholder: overview of the runner-manager terminal UI and a job lifecycle. -->

## Features

- ✅ **Works behind NAT:** no inbound ports, webhooks or servers.
- ✅ **Starts clean:** every job gets a fresh runner, and a fresh workspace by default.
- ✅ **Survives reboots:** auto-starts on Windows, macOS or Linux.
- ✅ **Protects hardware:** set concurrency limits for every target.
- ✅ **Tests safely:** monitor demand before enabling automation.
- ✅ **Shows live activity:** inspect runners, jobs and errors in the TUI.
- ✅ **Reuses build caches:** opt one repository into persistent workspaces.
- ✅ **Secures credentials:** secrets stay in the operating system store.

## Install

Install on any OS with Node.js 18 or newer:

```sh
npm i -g @ivan-murzak/runner-manager
```

<details>
<summary>Other installation methods and details</summary>

### Homebrew

On macOS or Linux:

```sh
brew install IvanMurzak/tap/runner-manager
```

### Install script

On macOS or Linux, with no Node.js installation required:

```sh
curl -fsSL https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases/latest/download/install.sh | sh
```

On Windows with PowerShell 5.1 or 7, with no Node.js installation required:

```powershell
irm https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases/latest/download/install.ps1 | iex
```

Then check the installation:

```sh
runner-manager --version
```

Every path above is a terminal command, deliberately: Gatekeeper on macOS and SmartScreen
on Windows act on the quarantine flag a *browser* sets, and `curl`, `irm`, `tar`, `brew`,
`npm` and `cargo` do not set one, so no install here raises a security prompt.

### Which one to pick

The **install script** is the one to use for a boot-start service. It installs to a fixed
location (`~/.local/bin`, or `%LOCALAPPDATA%\Programs\runner-manager` on Windows) that
does not move when a toolchain moves, and `service install` records the binary's absolute
path.

An **npm** global binary lives under the *active* Node prefix, which moves when you switch
versions with nvm, fnm, volta or asdf. `runner-manager service status` reports the recorded
path as stale when that happens; re-run `service install` to fix it. The npm package name is
scoped: plain `runner-manager` on npmjs.com is an unrelated project.

### Install script details

Both scripts detect your OS and CPU, verify the archive's SHA-256 against the release's
published `SHA256SUMS`, and abort without installing anything if it does not match. To pin a
version. A piped script gets no arguments of its own, hence the separator:

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

</details>

## Quick start

These four commands connect one repository, allow one concurrent job and keep the agent
running after a reboot:

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

The `repo add` command prints the routing label it reserved, such as `rm-home-win-x64` for
host label `home` on a Windows x64 machine. Use that label in the repository workflow:

```yaml
jobs:
  build:
    runs-on: rm-home-win-x64
```

Queue a workflow, then watch the runner start and complete the job:

```sh
runner-manager tui
```

Organizations use the same commands with `org` in place of `repo`.

<!-- GIF placeholder: adding a repository, enabling scaling and watching its first job. -->

## Commands

```bash
runner-manager auth login                                      # Sign in with GitHub's device flow
runner-manager auth status [--list] [--permissions]            # Inspect access and App permissions
runner-manager auth logout                                     # Purge the local credential

runner-manager host show                                       # Show capacity, secret store and REST budget
runner-manager host set-capacity N                             # Limit concurrent runners on this machine
runner-manager host set-runtime-root --path PATH               # Put disposable runner workspaces under PATH
runner-manager host reset-runtime-root                         # Return runner placement to the platform default

runner-manager repo add OWNER/REPO --host-label HOST           # Add a repository in monitor-only mode
runner-manager repo add OWNER/REPO --host-label HOST \
  --max-capacity N [--label LABEL] [--enable]                  # Allow runners for a repository
runner-manager repo list                                       # List repository policies
runner-manager repo set-capacity OWNER/REPO --max-capacity N   # Change repository capacity
runner-manager repo set-scale OWNER/REPO --enabled BOOL        # Enable scaling or drain runners
runner-manager repo add-label OWNER/REPO --label LABEL         # Add a runs-on label
runner-manager repo remove-label OWNER/REPO --label LABEL      # Remove a runs-on label
runner-manager repo set-workspace OWNER/REPO --mode ephemeral  # Discard the workspace after every job
runner-manager repo set-workspace OWNER/REPO \
  --mode persistent --path PATH                                # Keep each slot's _work between jobs
runner-manager repo remove OWNER/REPO [--purge]                # Remove a policy and optional retained data

runner-manager org add ORG --host-label HOST                   # Add an organization in monitor-only mode
runner-manager org add ORG --host-label HOST \
  --max-capacity N [--label LABEL] [--enable]                  # Allow runners for an organization
runner-manager org list                                        # List organization policies
runner-manager org set-capacity ORG --max-capacity N           # Change organization capacity
runner-manager org set-scale ORG --enabled BOOL                # Enable scaling or drain runners
runner-manager org add-label ORG --label LABEL                 # Add a runs-on label
runner-manager org remove-label ORG --label LABEL              # Remove a runs-on label
runner-manager org remove ORG [--purge]                        # Remove a policy and optional retained data

runner-manager status [--json]                                 # Print a host snapshot
runner-manager daemon run                                      # Run the agent in the foreground
runner-manager service install [--start-at boot|login]         # Start the agent automatically
runner-manager service status                                  # Check service health
runner-manager service uninstall                               # Remove the service but keep local state
runner-manager tui                                             # Open the terminal dashboard
```

Add `--help` to any command to see every option. Failures name the command that fixes them
and use a distinct exit code for each failure class.

## Customize your setup

### Choose where runners work

By default every job runs in a disposable workspace under this machine's runner root. On Windows
that root is `%SystemDrive%\rman`, normally `C:\rman`, so build paths stay short. macOS and
Linux keep using the platform runtime directory, exactly as before. `runner-manager host show`
prints the effective path and whether it is `platform-default` or `configured`.

Put runners somewhere else, such as a faster disk:

```powershell
runner-manager host set-runtime-root --path "<GLOBAL_RUNNER_ROOT>"
```

Go back to the platform default:

```powershell
runner-manager host reset-runtime-root
```

Both take effect for the next runner and never relocate a running one. Both are also refused
while this host still has runner attempts it has not cleaned up, naming how many are active and
how many are awaiting cleanup, so run them once the host is idle. No existing directory is moved
or deleted.

### Keep a build cache between jobs

Slow to warm up? Give one repository persistent workspaces, so its dependency and build
caches survive from job to job:

```powershell
runner-manager repo set-workspace OWNER/REPO `
  --mode persistent `
  --path "<REPOSITORY_WORKSPACE_ROOT>"
```

Concurrent runners lease numbered slots, `s1`, `s2` and so on, under that directory. Each
slot keeps its `_work` directory for the next job that leases it. Runner binaries, the
registration handoff and lifecycle files are still removed after every job.

Then stop the workflow's checkout from wiping the cache it just filled:

```yaml
- uses: actions/checkout@v7
  with:
    clean: false
```

`clean: false` on its own does not make a workspace persistent. In the default mode
`runner-manager` removes the whole workspace after every job, whatever the checkout does.
Set the repository to persistent mode first; the checkout setting only stops Git from
deleting the retained files.

Persistence is for workflows you trust, and it is not isolation. Files under `_work` become
an input to later jobs on the same slot, so executables, generated sources and caches can
cross branch and job boundaries. Keep untrusted fork and pull-request workflows on the
default mode. Persistence is repository-scoped for the same reason: an organization policy
can accept jobs from many repositories, so it always uses fresh workspaces.

Go back to a fresh workspace for every job:

```powershell
runner-manager repo set-workspace OWNER/REPO --mode ephemeral
```

Like the host commands, this one is refused while the repository still has a runner attempt
awaiting cleanup, so run it once that repository is idle. Switching off persistence, or moving
it to another directory, keeps every slot you already have: no old directory is moved or
deleted. Remove the ones you no longer want yourself.

### Store application data somewhere else

Add `--data-dir DIR` to any command to place config, state, logs and the package cache under
your chosen root. Set `RUNNER_MANAGER_DATA_DIR` to make it the default. On macOS and Linux it
also moves the platform-default runner root, which lives inside that tree; on Windows it does
not. Either way it is not how you choose runner placement: `host set-runtime-root` decides that,
and it wins over the platform default everywhere. Re-run `runner-manager service install` after
changing the root.

### Adapt the dashboard to your terminal

Set `NO_COLOR` to remove colour, `TERM=dumb` to remove glyphs too, or
`RUNNER_MANAGER_TUI_ASCII=1` for ASCII frames. Use `RUNNER_MANAGER_TUI_LIGHT=1` for light
rows and `RUNNER_MANAGER_TUI_PLAIN_ROWS=1` for unshaded rows.

## Use the terminal dashboard

Open the live dashboard with `runner-manager tui`. Use these shortcuts to reach the view or
action you need:

`d` dashboard · `r` repositories · `n` runners · `a` activity · `s` repository settings ·
`h` host settings · `/` filter · `o` sort · `c` copy · `F5` refresh · `?` help · `q` quit

Every status is also written in words, so the dashboard remains usable without colour or
box-drawing characters.

<!-- GIF placeholder: navigating repositories, runners, activity and settings in the TUI. -->

## What you are granting

Before signing in, review the GitHub App permissions that every installation receives:

| Permission | Level | Used for |
|---|---|---|
| Repository → Administration | **Read and write** | Registering a just-in-time runner for a repository. |
| Repository → Actions | Read | Detecting queued and in-progress workflow runs. |
| Repository → Metadata | Read | Accessing the repository identity required by GitHub. |
| Organization → Self-hosted runners | Read and write | Registering runners at organization scope. |

`Administration: Read and write` also permits deleting, renaming and transferring the
repository, and adding or removing collaborators. GitHub does not offer a narrower
repository permission for registering runners. A user who only monitors jobs grants the
same permissions because a GitHub App grants its complete permission set on installation.

Prefer organization scope when it fits your setup: it uses the narrower
`Organization → Self-hosted runners` grant ([verified](docs/spikes/d18-org-jit-verification.md)).
You can revoke the App in GitHub settings at any time and run `runner-manager auth logout`
to purge the local credential. The project creates no private key and declares no webhook.

To review this information from the terminal before signing in, run:

```sh
runner-manager auth status --permissions
```

## Supported platforms

| OS | Architectures |
|---|---|
| Windows | x64 (ARM64 via the install script, running the x64 build under emulation) |
| macOS | Apple Silicon, Intel |
| Linux | x64, ARM64 (glibc; on musl, build from source) |

## Licence

MIT. See [LICENSE](LICENSE).
