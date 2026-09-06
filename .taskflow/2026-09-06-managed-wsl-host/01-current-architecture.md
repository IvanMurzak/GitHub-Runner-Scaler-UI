# Current architecture

## Verified product behavior

| Fact | Evidence | Consequence |
|---|---|---|
| The public CLI has one process-wide `--data-dir` and local `auth`, `host`, `repo`, `org`, `daemon`, `service`, `tui`, `status`, and `update` commands. | `crates/app/src/cli/mod.rs:454-493` | There is no host/provider selector or WSL command surface. |
| Authentication runs GitHub device flow in the current process and writes the resulting stored credential document into the selected local secret store. | `crates/app/src/cli/auth.rs:454-460`, `crates/app/src/cli/auth.rs:583-601` | A Windows-side broker can reuse device flow, but needs an explicit secret-safe handoff seam instead of a staging store. |
| Renewal replaces the stored credential after refresh. | `crates/app/src/cli/auth.rs:383-409` | Two daemons must never share a refresh token pair. GitHub invalidates the old access and refresh tokens after refresh. |
| The platform secret-store abstraction stores a `SecretString`; scope is derived from boot versus login mode. | `crates/platform/src/secrets.rs:138-173`, `crates/platform/src/secrets.rs:486-499` | Linux can receive the opaque stored document and persist it through its native machine store. |
| Windows machine secrets are DPAPI files under `%ProgramData%`; Linux boot secrets are a separate platform-native store. | `crates/platform/src/secrets.rs:1080-1111`; `crates/platform/src/service.rs:945-1011` | Copying the Windows DPAPI blob is neither portable nor an acceptable provider protocol. |
| The service layer already installs SCM/Task Scheduler, launchd, and systemd registrations for the current OS. | `crates/platform/src/service.rs:35-54`, `crates/platform/src/service.rs:1308-1332` | The Linux half needs no second daemon implementation; the missing component is cross-environment orchestration. |
| Linux boot mode installs a system unit, while Windows login mode uses Task Scheduler. | `crates/platform/src/service.rs:1461-1469`, `crates/platform/src/service.rs:6100-6189` | A WSL host needs both: systemd inside the distribution and a Windows login task to start/keep the distribution alive. |
| `service install` copies the executable to stable service state and upgrades hand over safely. | `README.md:154-163` | Provisioning should use the same Linux service command and preserve its update semantics. |
| Release is a manually dispatched versioned workflow that validates, commits the version, tags atomically, builds native artifacts and publishes them. | `.github/workflows/release.yml:140-166`, `.github/workflows/release.yml:363-466`, `.github/workflows/release.yml:725-870` | `0.4.0` must be published through the existing workflow, not by ad-hoc local assets. |

## Workstation evidence (2026-09-06)

- Windows `runner-manager 0.3.2` is an SCM boot service and healthy.
- WSL `Ubuntu` is version 2; `runner-manager 0.3.2` is a healthy root systemd
  boot service with its own machine credential.
- A hand-created Windows scheduled task named
  `GitHub Actions Linux Runner - Ubuntu WSL` currently keeps WSL alive.
- The target migration therefore exercises adoption, not a clean install.

## External constraints

- Microsoft documents `wsl --list --verbose` as the way to enumerate installed
  distributions and versions, and `wsl --distribution <name> --user <name>` as
  the supported way to run in a selected distribution:
  <https://learn.microsoft.com/en-us/windows/wsl/basic-commands>.
- WSL systemd requires WSL 0.67.6 or newer and can be verified with
  `systemctl status`; current Ubuntu installations enable it by default:
  <https://learn.microsoft.com/en-us/windows/wsl/systemd>.
- GitHub states that using a refresh token invalidates both that refresh token
  and the old access token. Sharing one stored document between the two daemons
  therefore causes deterministic credential loss:
  <https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens>.

## Change seams

1. `crates/app/src/cli/mod.rs`: host selection, command dispatch and help.
2. `crates/app/src/cli/auth.rs`: reusable device-flow acquisition without a
   local write, plus the internal receiving endpoint.
3. `crates/platform`: WSL discovery, invocation, Windows scheduled-task
   definition/control and secret-safe child stdin.
4. `crates/app/src/cli/update.rs`: release metadata/download logic to reuse for
   exact-version Linux provisioning rather than duplicate it.
5. CLI acceptance/security tests, README and release notes.

