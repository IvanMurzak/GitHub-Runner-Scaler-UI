# @ivan-murzak/runner-manager (npm wrapper)

Local-first autoscaling manager for ephemeral GitHub Actions self-hosted
runners, with a CLI and a Ratatui TUI.

> **Read this before you install.** Using this tool means installing the
> project's published GitHub App, which declares **Repository → Administration:
> Read and write** — a permission that also allows deleting, renaming and
> transferring the repository, and adding or removing collaborators. It applies
> even if you only ever use `runner-manager` as a read-only dashboard. The full
> permission set and the narrower organization-scoped alternative are in
> [What you are granting](#what-you-are-granting) below.

```sh
npm i -g @ivan-murzak/runner-manager
runner-manager --version
```

This package is a thin wrapper. The binary itself lives in one of five
per-platform packages, declared here as `optionalDependencies`, so npm installs
only the one that matches your OS and CPU:

| Platform package | os / cpu | Rust target |
|---|---|---|
| `@ivan-murzak/runner-manager-win32-x64` | `win32` / `x64` | `x86_64-pc-windows-msvc` |
| `@ivan-murzak/runner-manager-darwin-arm64` | `darwin` / `arm64` | `aarch64-apple-darwin` |
| `@ivan-murzak/runner-manager-darwin-x64` | `darwin` / `x64` | `x86_64-apple-darwin` |
| `@ivan-murzak/runner-manager-linux-x64` | `linux` / `x64` | `x86_64-unknown-linux-gnu` |
| `@ivan-murzak/runner-manager-linux-arm64` | `linux` / `arm64` | `aarch64-unknown-linux-gnu` |

Each platform package records, in its `package.json`, the release archive its
binary was taken from and that archive's published SHA-256 — the same digest
listed in the release's `SHA256SUMS`.

## Read this before `service install`

**An `npm i -g` binary does not have a fixed home, and this product records an
absolute path.**

`npm i -g` installs into the *active* Node installation's global prefix. If you
manage Node with `nvm`, `fnm`, `volta`, `asdf`, Homebrew, or a Windows
installer upgrade, that prefix is different for every Node version — something
like:

```text
~/.nvm/versions/node/v20.11.0/bin/runner-manager
~/.nvm/versions/node/v22.3.0/bin/runner-manager      <- after `nvm install 22`
```

`runner-manager service install` resolves and records the **absolute** path of
the binary at the moment you run it. So switching Node versions after
installing the service leaves the service pointing at a path that no longer
exists, and nothing tells you until the next unattended boot, when the agent
does not come up.

`runner-manager service status` detects this and reports the recorded path as
**stale** rather than reporting the service as healthy. If you see that:

```sh
npm i -g @ivan-murzak/runner-manager   # into the Node version you are now using
runner-manager service install        # re-records the new absolute path
```

**If you want a boot-start service, prefer the install script.** It installs to
`~/.local/bin` (macOS, Linux) or `%LOCALAPPDATA%\Programs\runner-manager`
(Windows), neither of which moves when a toolchain moves:

```sh
curl -fsSL https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases/latest/download/install.sh | sh
```

```powershell
irm https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases/latest/download/install.ps1 | iex
```

This package is the right choice when you already manage tooling with npm and
you run `runner-manager` interactively or from a script, rather than as a
boot-start service.

## Windows on ARM

npm will not install an `"cpu": ["x64"]` package onto an arm64 host, and no
arm64 Windows build is published, so this package cannot serve Windows on ARM.
The install script can: it uses the x64 build through the built-in emulation
layer.

## What you are granting

Using this tool means installing the project's published GitHub App, and that
App declares **Repository → Administration: Read and write**. That permission
also allows deleting, renaming and transferring the repository, and adding or
removing collaborators. It applies even if you only ever use `runner-manager`
as a read-only dashboard.

The full permission table, why the grant is unavoidable at repository scope,
and why organization scope is materially narrower are in the
[repository README](https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI#what-you-are-granting).
Read it before you run `auth login`.

## Licence

MIT. Source: <https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI>
