# runner-manager

[![npm version](https://img.shields.io/npm/v/@ivan-murzak/runner-manager.svg?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/@ivan-murzak/runner-manager)
[![Crates.io](https://img.shields.io/crates/v/runner-manager?style=for-the-badge&logo=rust)](https://crates.io/crates/runner-manager)
[![GitHub Release](https://img.shields.io/github/v/release/IvanMurzak/GitHub-Runner-Scaler-UI?style=for-the-badge&logo=github)](https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases)
[![Release Status](https://img.shields.io/github/actions/workflow/status/IvanMurzak/GitHub-Runner-Scaler-UI/release.yml?style=for-the-badge&logo=github)](https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

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

## Update

One command, whichever way you installed it:

```sh
runner-manager update
```

It works out how this copy was installed, compares your version against the
newest release, and updates through that same channel. An install-script or
standalone binary is replaced in place; `npm`, `brew` and `cargo` are asked to
do their own job. The archive it downloads is verified against the release's
published SHA-256 before anything is replaced, and a mismatch installs nothing.

To see what it would do without changing anything:

```sh
runner-manager update --check
```

If the agent is installed as a service, you do not need to do anything else.
`service install` registers a copy of the binary rather than the file a package
manager owns, so the running daemon notices the new version, finishes every job
it is holding, swaps its copy and is restarted by the operating system. Until it
does, `runner-manager service status` still reports the old version. That is the
hand-over in progress, not a failed update.

`update` refuses two things rather than overwriting them: a `cargo build` inside
a checkout of this repository, and the private copy the service runs. Both name
what to do instead.

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
runner-manager update [--check]                                # Install the newest release over this one

runner-manager wsl list                                        # Name this machine's WSL distributions
runner-manager wsl install --distribution NAME [--capacity N]  # Make a WSL2 distribution a second runner host
runner-manager wsl status --distribution NAME [--json]         # Report that host's real state
runner-manager wsl detach --distribution NAME                  # Stop managing it, deleting no Linux data
```

Add `--help` to any command to see every option. Failures name the command that fixes them
and use a distinct exit code for each failure class.

## Run Linux jobs too: manage a WSL2 distribution

One Windows workstation can serve Windows jobs and Linux jobs at the same time. On Windows,
`runner-manager wsl install` turns a WSL2 distribution you already have into a second managed
host: it installs the matching Linux binary, signs that host in with its own GitHub credential,
installs the Linux service, and registers a Windows task that keeps the distribution running.
Each host then has its own capacity, its own policies and its own runner label.

You never create a staging folder, copy a token out of a Windows credential store, hand-write a
systemd unit, or make a scheduled task yourself. If a step of this section asks you to,
it is a defect in the product.

### Before you start

- **Windows.** The `wsl` family and `--host wsl:...` exist on every platform and refuse, with a
  reason, on anything but Windows.
- **An installed WSL2 distribution** with any name. Check with `runner-manager wsl list`, which
  prints the exact spelling each command needs. WSL1 is refused and names the conversion command.
- **systemd inside it.** Put `systemd=true` under `[boot]` in that distribution's `/etc/wsl.conf`
  and run `wsl --terminate NAME`. Without systemd there is no Linux service to install, and the
  preflight refuses before anything is changed.
- **Root inside it,** which is the default for a distribution you have not reconfigured.
- **x86-64 or 64-bit ARM.** Those are the Linux architectures this project publishes.
- **A browser on this Windows machine,** for the one sign-in described below.

Nothing here installs a distribution, edits `.wslconfig`, or touches the registry.

### Make it a runner host

```powershell
runner-manager wsl list
runner-manager wsl install --distribution Ubuntu --capacity 8
```

`wsl install` runs eight stages in order and prints what each one did:

1. Preflight: WSL2, root, architecture, systemd, and whether the task name is free.
2. The release archive matching this Windows build's exact version, checksum verified.
3. The Linux binary, replaced atomically.
4. The credential, issued only if that distribution does not already hold one.
5. Capacity, only when you passed `--capacity`.
6. The Linux systemd service. If its active private copy is older, its daemon
   cooperatively stops accepting new jobs, waits without a deadline for its local
   work journal to drain, replaces the copy, and lets systemd restart it. The
   installer waits for that restarted process before continuing; it never uses a
   systemd stop to upgrade a running service. A legacy copy that cannot provide
   this handover is left running and the upgrade refuses rather than risking a job.
7. The Windows login task that keeps the distribution alive.
8. A read-back of the real state, which is what decides whether the command succeeded.

Nothing is changed and no sign-in happens until the preflight has passed.

### Adopting a distribution that already runs runner-manager

The same command. `wsl install` is convergent, so it probes before it writes and adopts what
is already correct: a valid credential is kept, and an active service is adopted rather than reinstalled.
Policies, the runtime root and in-flight work are left alone.
An active out-of-date service takes the cooperative handover above; a disabled active
unit is handled the same way before it is enabled again. Capacity changes only when
you pass `--capacity`. Re-running it on a healthy host changes nothing, and is the
documented way to upgrade that host after you update on the Windows side.

### Each host signs in separately

`runner-manager --host wsl:Ubuntu auth login` runs the browser sign-in on Windows, where the
browser is, and hands the credential it issues straight into the Linux host's own machine store
over a pipe. The credential is never written down on Windows.

Each host needs its own sign-in, and copying one is not an option that merely looks untidy: it
does not work. GitHub invalidates both halves of a token pair whenever either half is renewed,
so two daemons sharing one credential take turns logging each other out. `wsl install` does the
sign-in for you when the distribution holds no credential of its own, and skips it when it does.

### Configure it with the commands you already use

`--host local` is the default and is this machine. `--host wsl:NAME` carries any command in the
list above into that distribution instead:

```powershell
runner-manager --host wsl:Ubuntu repo add OWNER/REPO --host-label home --max-capacity 4
runner-manager --host wsl:Ubuntu repo set-scale OWNER/REPO --enabled true
runner-manager --host wsl:Ubuntu repo list
runner-manager --host wsl:Ubuntu host set-capacity 4
runner-manager --host wsl:Ubuntu status
```

The Linux host reserves its own routing label, such as `rm-home-linux-x64`, so a workflow picks
Windows or Linux by choosing which label it runs on. `--capacity` on `wsl install` and
`--host wsl:NAME host set-capacity N` set the same number; use whichever fits the moment.

### Check what is really there

```powershell
runner-manager wsl status --distribution Ubuntu
runner-manager wsl status --distribution Ubuntu --json
```

Every line is read from the distribution and from Task Scheduler, never from this machine's
record of it, and the record is reported separately as drift when the two disagree. The report
names the WSL version, the Linux binary, the credential, the systemd unit, the lifecycle task,
the capacity, and the workload diagnostics below. `--json` is versioned and safe to script
against.

**When this host is available.** WSL distributions are registered per Windows user, so this
feature promises unattended Linux availability **after that user logs on**, not between a
Windows reboot and the first interactive logon. `wsl status` says so on every run rather than
leaving you to discover it after a restart.

**Docker is diagnosed, not installed.** If the distribution runs a Docker engine, status reports
its version; if not, status says container jobs would fail while ordinary jobs still run. It is
never a reason to refuse provisioning, and this tool never installs a workload dependency for
you.

### When something goes wrong

Every failure names the stage it happened in and whether anything was changed.
A preflight failure changed nothing at all. Any later failure leaves the earlier stages
standing, and the remedy is always the same: fix what the message names and then
run `wsl install` again. It will skip whatever is already correct.

```powershell
runner-manager wsl status --distribution Ubuntu   # what is actually in place
runner-manager wsl install --distribution Ubuntu  # converge the rest
```

A scheduled task of this product's name that this product did not create is never modified or
removed. If you made a keep-alive task by hand, `wsl install` stops and asks you to rename or
remove it first.

### Stop managing it

```powershell
runner-manager wsl detach --distribution Ubuntu
```

`detach` removes this machine's lifecycle task and its record of the host, and nothing else. It
is deliberately not called `uninstall`: the distribution stays registered with WSL, and its
runner-manager, service, credential, policies, workspaces and packages all stay exactly where
they are. The command prints the explicit Linux commands to run inside the distribution if you
want to undo that half as well.

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

The repositories view lists each policy's `runs-on` labels beside its capacity and health;
`s` opens the settings for the selected repository, where the optional labels can be edited
in place. The host label above them is fixed, because it is the identity that keeps two
machines from answering each other's jobs, so only the descriptive labels are editable.
Saving makes the stored set equal exactly what is on the line.

Every status is also written in words, so the dashboard remains usable without colour or
box-drawing characters.

<!-- GIF placeholder: navigating repositories, runners, activity and settings in the TUI. -->

## What you are granting

Before signing in, review the GitHub App permissions that every installation receives:

| Permission | Level | Used for |
|---|---|---|
| Repository → Administration | **Read and write** | Registering a just-in-time runner for a repository. |
| Repository → Actions | Read | Detecting queued jobs and the runs that hold them. |
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
