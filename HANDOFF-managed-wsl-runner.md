# Handoff: managed Windows + WSL2 runner host

Snapshot date: 2026-09-07 (America/Los_Angeles).

## Owner goal and non-negotiable constraints

Ivan wants this one physical Windows machine to execute both Windows and Linux
GitHub Actions jobs. Linux must run in the existing WSL2 `Ubuntu`
distribution, with capacity 8. This must be a reusable feature in the
`runner-manager` product, not machine-specific scripts or a separate service
created only for one repository. Windows and WSL must have independent GitHub
credentials. The existing hand-made WSL keep-alive task must not be removed
until the new managed host and a live Linux job are proven green.

Target repository currently waiting for the Linux label:
`IvanMurzak/AI-Game-Dev-Server`. Its Test workflow requests
`[self-hosted, Linux, rm-ivanpc-linux-x64]` and its PostgreSQL service uses a
GitHub-allocated free host port (`5432/tcp`), so parallel runners do not share a
fixed port.

## Product work completed

The implementation is in this repository, not in local helper scripts.

- Taskflow architecture and evidence are under
  `.taskflow/2026-09-06-managed-wsl-host/`; its `ROADMAP.md` is the state source.
- PR #53 (`f983cd3`) added the Windows/WSL platform provider: discovery,
  root execution, probes, exact-version Linux artifact verification, owned
  login task and provider records.
- PR #52 (`ffb5f37`) added independent device-flow credential brokering over
  anonymous stdin into the WSL host. The Windows credential is not read or
  copied. A macOS test-only correction was also completed.
- PR #54 (`eaf8abd`) added the reusable CLI/product orchestration:
  `wsl list/install/status/detach`, global `--host local|wsl:NAME`, adoption,
  resumability, preflight-before-auth, systemd activation, Docker diagnostics,
  status drift reporting and non-destructive detach. A Windows CRLF test
  correction and additional B2 edge-case fixes are included.
- PR #55 (`ca74c71`) added isolated acceptance tests, secret-output canaries,
  privileged Windows+WSL lifecycle coverage, operator docs, changelog and
  deterministic release/mutation guards.
- All seven required checks were green on PRs #54 and #55, including the
  13-minute Windows workspace suite and privileged Windows tests.
- Taskflow completion was committed as `6dc39f8`.

Public product surface now includes:

```powershell
runner-manager wsl list
runner-manager wsl install --distribution NAME [--capacity N]
runner-manager wsl status --distribution NAME [--json]
runner-manager wsl detach --distribution NAME
runner-manager --host wsl:NAME <existing command...>
```

## Release completed

Do **not** dispatch the release again.

- Version: `0.4.0`
- Release workflow run: https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/actions/runs/34114223305
- Result: `completed / success`; validation, all native preflights, full test
  matrix, privileged WSL lifecycle, version/tag, five native builds, SBOM,
  GitHub publication and distribution-channel updates all succeeded.
- GitHub release: https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases/tag/v0.4.0
- Release commit now at remote `main`: `70ed15219de399f0c3baf4db13b6e58989cb3fb9`
  (`release: 0.4.0`).
- Published assets include `install.ps1`, `install.sh`, Windows x86-64 and
  Linux x86-64 archives, all other supported native archives, `SHA256SUMS` and
  the CycloneDX SBOM.

The local checkout is still at `6dc39f8`; the next agent should start with a
fast-forward pull to receive the release commit.

## Current machine state (installation is NOT finished)

- Windows CLI/service are still `runner-manager 0.3.2`.
- Windows SCM service is installed, boot-started and running as SYSTEM. Its
  machine DPAPI credential exists and its last GitHub contact was healthy.
- `runner-manager service status` warns that `C:\rman` is writable by ordinary
  users. This pre-existing warning must be investigated/preserved; do not
  silently delete or rewrite its contents.
- WSL distributions: `Ubuntu` (WSL2, running) and `docker-desktop` (WSL2,
  running). Only `Ubuntu` is the intended managed runner host.
- The Ubuntu binary is still `runner-manager 0.3.2`.
- Running `runner-manager service status` as the ordinary WSL user reads the
  user's paths and reports an unhealthy/missing install record. `sudo -n`
  cannot inspect the root-owned service because sudo requires a password.
  The new Windows-side `wsl install/status` commands execute through WSL as
  root and are the authoritative adoption path; do not “repair” the user-side
  paths manually.
- Earlier verified state indicates the actual Linux daemon/policy used the
  root-owned machine store and a policy for `IvanMurzak/AI-Game-Dev-Server`
  with maximum 8 and routing label `rm-ivanpc-linux-x64`. Adoption is designed
  to preserve credential, policies, runtime root and in-flight work; verify
  this after upgrading instead of recreating it blindly.
- Legacy manual scheduled task still exists and is running:
  `GitHub Actions Linux Runner - Ubuntu WSL`.
- Product-owned tasks use the separate prefix `runner-manager-wsl`, so the
  legacy task can coexist during migration.

At snapshot time, these `AI-Game-Dev-Server` Test runs were queued for the
Linux self-hosted label and are useful live acceptance candidates:

- push run `34099417152`
- push run `34089469522`
- pull-request run `34099391220`

There is also a queued scheduled `LiteLLM Price Watch` run `34123349236`; it is
not the primary Linux-host acceptance target.

## What remains, in order

1. Update the checkout and install the official Windows 0.4.0 release:

   ```powershell
   git pull --ff-only
   irm https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases/latest/download/install.ps1 | iex
   runner-manager --version
   runner-manager service status
   ```

   Expect `runner-manager 0.4.0` for the CLI and the service binary. Handle any
   UAC prompt normally. Do not replace the product install with a custom copy.

2. Discover and adopt Ubuntu through the product feature:

   ```powershell
   runner-manager wsl list
   runner-manager wsl install --distribution Ubuntu --capacity 8
   ```

   The command performs eight convergent stages and installs the exact matching
   Linux 0.4.0 asset. It should preserve a valid independent Ubuntu credential
   and existing policy. If it starts GitHub device flow, complete that login for
   Ubuntu; never copy or export the Windows credential. On any later-stage
   failure, use the printed remedy and rerun the same install command.

3. Verify the real managed state from Windows:

   ```powershell
   runner-manager wsl status --distribution Ubuntu
   runner-manager wsl status --distribution Ubuntu --json
   runner-manager --host wsl:Ubuntu auth status
   runner-manager --host wsl:Ubuntu repo list
   runner-manager --host wsl:Ubuntu status
   runner-manager --host wsl:Ubuntu host set-capacity 8
   ```

   Required result: Ubuntu is WSL2; Linux binary/service and the
   `runner-manager-wsl...` login task are healthy; independent credential is
   healthy; capacity is 8; policy for `IvanMurzak/AI-Game-Dev-Server` remains
   enabled with label `rm-ivanpc-linux-x64`. Docker must be reported honestly.
   It is diagnostic only and the product must not install Docker.

   If the repository policy is genuinely absent after inspection, configure it
   with the product commands (do not add a duplicate):

   ```powershell
   runner-manager --host wsl:Ubuntu repo add IvanMurzak/AI-Game-Dev-Server --host-label ivanpc --max-capacity 8
   runner-manager --host wsl:Ubuntu repo set-scale IvanMurzak/AI-Game-Dev-Server --enabled true
   ```

4. Confirm the Windows side still serves Windows jobs: verify its local
   credential, repository list/policies, capacity and service health. The WSL
   work must not disable or share credentials with the Windows host.

5. Let one of the queued `AI-Game-Dev-Server` Test runs start, or dispatch the
   Test workflow if none remains queued. Watch it to completion, and verify on
   GitHub that jobs used `rm-ivanpc-linux-x64`, scaled ephemeral Linux runners,
   handled the dynamic PostgreSQL port and cleaned the runners up afterward.

   Useful commands:

   ```powershell
   gh run list -R IvanMurzak/AI-Game-Dev-Server --workflow Test --limit 10
   gh run watch 34099417152 -R IvanMurzak/AI-Game-Dev-Server --exit-status
   ```

6. Only after managed `wsl status` is healthy **and** a live Linux job is green,
   remove the legacy manual keep-alive task. Verify the exact task name first:

   ```powershell
   Get-ScheduledTask -TaskName 'GitHub Actions Linux Runner - Ubuntu WSL'
   Stop-ScheduledTask -TaskName 'GitHub Actions Linux Runner - Ubuntu WSL'
   Unregister-ScheduledTask -TaskName 'GitHub Actions Linux Runner - Ubuntu WSL' -Confirm:$false
   runner-manager wsl status --distribution Ubuntu
   ```

   This is the only local migration artifact intended for removal. The new
   product-owned `runner-manager-wsl...` task must remain.

7. Final evidence to record: Windows and Ubuntu both on 0.4.0, both credentials
   independent/healthy, both daemons healthy, Ubuntu capacity 8, correct Linux
   label/policy, product-owned lifecycle task running, live workflow green and
   ephemeral runner cleanup complete. Then append the installation/live result
   to the Taskflow `ROADMAP.md` progress log if desired.

## Safety notes

- Do not rerun release 0.4.0 or create another release for this handoff.
- Do not delete/re-register the Ubuntu distribution.
- Do not run `wsl detach` during installation; it is the product's intentional
  non-destructive de-management command, not a repair step.
- Do not remove the legacy task before the managed task and a live job are
  proven.
- Do not expose, print, copy or reuse either host's credential.
- Do not create another ad-hoc service, scheduled task, credential bridge or
  local script. The point of 0.4.0 is that `runner-manager` owns this lifecycle.
