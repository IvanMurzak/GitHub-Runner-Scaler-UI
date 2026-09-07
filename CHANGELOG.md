# Changelog

What changed in each release, in the terms an operator upgrading would care
about. The published GitHub Release for a version carries the checksums, the
SBOM and the verification steps; this file carries what the version *does*.

Versions are `X.Y.Z` and are set by the release workflow, so the top entry names
the version being prepared rather than the version in `Cargo.toml`.

## 0.4.0

### A WSL2 distribution can now be a second managed runner host (Windows)

One Windows workstation can serve Windows jobs and Linux jobs at the same time.
`runner-manager wsl install --distribution NAME` turns a WSL2 distribution you
already have into a fully managed host, and every command you already use
reaches it through the new global `--host wsl:NAME` selector.

New commands, all Windows:

- `runner-manager wsl list` names this machine's distributions and says which of
  them are managed.
- `runner-manager wsl install --distribution NAME [--capacity N]` provisions or
  converges one, in eight ordered stages.
- `runner-manager wsl status --distribution NAME [--json]` reports that host's
  real state, read from the distribution rather than from any local record.
- `runner-manager wsl detach --distribution NAME` stops managing it and deletes
  no Linux data.
- `--host local|wsl:NAME` is global. `local` is the default and every existing
  invocation means exactly what it meant before.

What this replaces: a hand-installed second binary, a hand-written systemd unit,
a hand-made Windows keep-alive task, and a credential moved between hosts by
hand. `README.md`'s "Run Linux jobs too" section is the whole procedure.

### Each host holds its own GitHub credential

`runner-manager --host wsl:NAME auth login` runs the browser sign-in on Windows,
where the browser is, and hands the credential it issues straight into the Linux
host's own machine store over an anonymous pipe. It is never written down on the
Windows side, and the Windows host's own credential is never read for transfer.

This is a correctness requirement rather than tidiness: GitHub invalidates both
halves of a token pair whenever either half is renewed, so two daemons sharing
one credential would take turns signing each other out. `wsl install` issues a
credential only when the distribution holds none of its own, so re-running it on
a working host never sends you back to a browser.

### Provisioning is convergent, and adoption is the same command

`wsl install` probes before it writes. An existing Linux runner-manager, its
credential, its policies, its runtime root and an already-enabled service unit
are adopted rather than replaced, and capacity changes only when you pass
`--capacity`. Every stage reports whether it changed anything, a preflight
failure changes nothing at all, and the documented remedy for any later failure
is to fix what the message names and run the command again.

### Availability is stated rather than implied

WSL distributions are registered per Windows user, so a managed Linux host is
available after that user logs on and not between a Windows reboot and the first
interactive logon. `wsl status` says so on every run.

### Docker is diagnosed, never installed

`wsl status` reports whether the distribution can run containers and says what
that means for your jobs. It is never a reason to refuse provisioning, and this
release installs no workload dependency on your behalf.

### `detach` is deliberately not `uninstall`

It removes this machine's lifecycle task and its record of the host. The
distribution stays registered with WSL, and its runner-manager, service,
credential, policies, workspaces and packages stay where they are. The command
prints the explicit Linux commands to run if you want to undo that half too.

### Unchanged

Every existing local command, file, service registration and `status --json`
document is unchanged. `--host local` is the default, so nothing you have
scripted needs editing.
