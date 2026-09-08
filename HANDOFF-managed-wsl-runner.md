# Handoff: managed Windows + WSL2 runner host

Final snapshot: 2026-09-07 (America/Los_Angeles).

## Outcome

The requested migration is complete. This physical machine is managed by
`runner-manager` as two independent GitHub Actions hosts:

- native Windows host: healthy `runner-manager 0.4.3` Windows service;
- WSL2 `Ubuntu` host: healthy `runner-manager 0.4.3` systemd service, capacity
  8, Docker available, and policy `IvanMurzak/AI-Game-Dev-Server` active with
  labels `self-hosted`, `Linux`, and `rm-ivanpc-linux-x64`.

No repository-specific service, keep-alive script, or credential-copying shim
remains. The product-owned scheduled task
`runner-manager-wsl-Ubuntu-710eb4f4` keeps the WSL distribution available
after the owning Windows user logs on. The former manual task
`GitHub Actions Linux Runner - Ubuntu WSL` was removed after live acceptance.

WSL distributions are per Windows user, so the managed Ubuntu host becomes
available after that account's first interactive logon following a Windows
reboot. This limitation is reported by `runner-manager wsl status`.

## Credentials

The two hosts authenticate independently:

- Windows uses its existing machine-scoped DPAPI store under
  `C:\ProgramData\IvanMurzak\runner-manager\secrets`;
- Ubuntu uses a root-owned mode-0600 file at
  `/var/lib/runner-manager/secrets/user-access-token`.

The WSL credential was issued independently through the product broker over
anonymous stdin. The Windows credential was neither read nor copied. Repeated
`wsl install` runs preserve the Ubuntu credential.

## Product work and releases

The reusable implementation is in this repository:

- PR #52: independent credential broker;
- PR #53: Windows/WSL platform provider;
- PR #54: WSL CLI and orchestration;
- PR #55: acceptance, security tests, and operator documentation;
- PR #56: WSL adoption, service-version status, automatic handover, and drain
  recovery fixes;
- PR #57: allow a disabled policy to be enabled again;
- PR #58: keep upgrade handover active when every policy is disabled.

Final installed release: `v0.4.3`.

- Release: https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases/tag/v0.4.3
- Release run: https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/actions/runs/34182412652
- Release commit: `0796338` (`release: 0.4.3`)

The release workflow completed successfully across Linux, macOS, Windows, and
privileged Windows/WSL tests; it published five native archives, installers,
SHA256SUMS, CycloneDX SBOM, npm packages, and the Homebrew update. Both the
standalone Windows installer and npm CLI are 0.4.3. Windows and Ubuntu service
copies automatically handed over to 0.4.3.

## Live acceptance evidence

The manager scaled to eight local Linux attempts for the queued Test workflows.
GitHub reported online `runner-manager-*` runners with exactly the requested
Linux labels. Completed jobs included successful `Backend Tests` and
`Access Matrix`; runner names rotated between jobs, proving ephemeral cleanup.

Successful complete Test runs after enabling the managed host include:

- https://github.com/IvanMurzak/AI-Game-Dev-Server/actions/runs/34173575613
- https://github.com/IvanMurzak/AI-Game-Dev-Server/actions/runs/34172503497
- https://github.com/IvanMurzak/AI-Game-Dev-Server/actions/runs/34171499907

Earlier run 34089469522 also proved the PostgreSQL service-container path with
GitHub's dynamic host port. Some other Test runs failed in their own test gates;
their jobs were nevertheless routed to the managed Linux runners.

After the queue drained, final status reported:

- `active`, `enabled=true`, maximum capacity 8;
- `in_use=0`, headroom 8;
- zero active ephemeral attempts and zero cleanup-blocked attempts;
- no `runner-manager-*` runner left registered at GitHub.

## Normal verification commands

```powershell
$rm = "$env:LOCALAPPDATA\Programs\runner-manager\runner-manager.exe"
& $rm wsl status --distribution Ubuntu
& $rm --host wsl:Ubuntu auth status
& $rm --host wsl:Ubuntu repo list
& $rm --host wsl:Ubuntu status --json
& $rm status --json
```

Re-running the following is convergent and preserves credentials and policy:

```powershell
& $rm wsl install --distribution Ubuntu --capacity 8
```

## Remaining work

None for this migration. Do not recreate the removed legacy task, share the two
credential stores, or add repository-specific services/scripts. Keep the
product-owned scheduled task and both managed services.
