# Security and lifecycle

## Credential guarantees

1. A WSL host receives a newly issued credential unless its own Linux machine
   store is already authenticated.
2. The active Windows credential is never read for transfer.
3. The credential document crosses the Windows/Linux boundary only through an
   anonymous stdin pipe. It is absent from argv, environment, provider records,
   logs, errors, status JSON, temporary files and scheduled-task XML.
4. The receiving process accepts at most 64 KiB, writes directly through the
   native secret store and zeroizes/drops transient buffers as supported by the
   existing secrecy types.
5. A failed handoff leaves no Windows credential copy. A successful handoff is
   read back only as authenticated/unauthenticated metadata.
6. Refresh remains local to each daemon. No sync or replication path exists.

Security tests inject recognizable access, refresh and JIT canaries and scan
all observable outputs and persisted Windows files.

## Provisioning failure model

| Stage | Failure result | Rerun behavior |
|---|---|---|
| WSL/systemd preflight | No mutation and no device login | Fix prerequisite and rerun. |
| Artifact resolve/download/checksum | No Linux destination replacement | Redownload and rerun. |
| Binary atomic install | Old binary remains executable | Rerun installs exact version. |
| Device flow | No provider record and no Windows staging secret | Restart login. |
| Linux secret store | Credential is not used; precise secret-store error | Fix ownership/permissions and rerun login. |
| Linux service install | Binary/credential/state remain; no deletion | Fix service error and rerun. |
| Windows lifecycle task | Linux service may be healthy but host is reported partial | Fix Task Scheduler and rerun. |
| Final verification | All actual states shown; never claim healthy from record alone | Repair the named drift and rerun. |

## Adoption and uninstall

Adoption probes before writing. It preserves a valid credential, policy DB,
runtime root and active attempts. Updating the binary uses the existing service
handover where possible; otherwise installation first drains/refuses according
to existing service rules.

`wsl detach` is intentionally non-destructive. It stops/removes only the
product-owned Windows task and removes the non-secret provider record. The WSL
distribution, Linux service, credentials, policies, workspaces and packages
remain. Output names explicit Linux commands an operator may run separately.

## Production gate on IvanPC

Before deleting the legacy task:

- Windows `service status` is healthy at `0.4.0`.
- `wsl status --distribution Ubuntu` reports WSL2, exact Linux `0.4.0`, an
  authenticated independent machine store, systemd running, service healthy,
  lifecycle task running/ready and capacity 8.
- An `AI-Game-Dev-Server` Linux workflow job is acquired, completes, and its
  ephemeral runner is removed.
- Windows jobs remain routable and the Windows daemon remains healthy.

The gate is evaluated after the IvanD login task has started. It does not claim
that a per-user WSL distribution is available before the first user logon after
a Windows reboot.
