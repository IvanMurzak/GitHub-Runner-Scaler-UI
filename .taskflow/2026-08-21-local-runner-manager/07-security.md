# Security architecture

## GitHub App permissions

Repository-scoped scale sets require:

| Permission | Level | Why |
|---|---|---|
| Repository → Administration | Read and write | Required by the runner registration token and scale-set JIT generation at repository scope. |
| Repository → Actions | Read | In-progress workflow-run counts. |
| Repository → Metadata | Read | Mandatory for repository access. |

`Administration: Read and write` is **not** a narrow self-hosted-runner
permission. The same grant permits deleting, renaming, and transferring the
repository and adding or removing collaborators. This is unavoidable for
repository-scoped scale sets and must be explicitly accepted by the owner
before the pilot. Organization-scoped scale sets instead use the narrower
`Organization → Self-hosted runners: Read and write`; that alternative is an
open question in `02-target-architecture.md`. GitHub Apps cannot authenticate
runners at the enterprise level at all.

## Credential inventory

| Credential or sensitive value | Source | Storage | Exposure rule |
|---|---|---|---|
| GitHub App private key | Owner-created GitHub App | Machine-scoped secret store (D13) | Never config, SQLite, logs, diagnostics, UI, or command argument. |
| GitHub App JWT | Derived locally | Memory only | At most 10 minutes; never logged. |
| Installation access token | GitHub token exchange | Memory only | 1-hour lifetime; refresh single-flight; redact all HTTP headers. |
| Runner registration token | `POST /repos/.../actions/runners/registration-token` | Memory only | Consumed immediately in the Actions-service registration exchange; never persisted or logged. |
| Actions-service admin token and tenant URL | Actions-service registration exchange | Memory only | Refreshed 60s before expiry; redact from all logs and error bodies. A leak grants scale-set administration for its full lifetime. |
| Message-queue access token | Scale-set session create/refresh | Memory only | Refreshed on session token expiry; never persisted. |
| JIT configuration | Actions-service JIT endpoint | Restrictive temporary handoff only | Delete immediately after launch; never persist. |
| Repository checkout/secrets | Workflow execution | Disposable attempt workspace | Delete after attempt; never show file names/content in normal UI. |

## Machine-scoped key storage: accepted trade-off

D13 moves the private key out of the operator's user keychain so a boot-time
service can read it. The consequence is that any local administrator or root
account on that machine can read the key. Compensating controls:

- The secret store entry is ACL'd to the service account only, and the store is
  the OS machine-scoped facility, not a plain file, wherever one exists.
- `auth logout` purges it, and the credential-disclosure response in
  `05-infrastructure.md` is a documented, rehearsed procedure.
- The threat model already assumes a hostile *workflow* can run on this host;
  it does not assume a hostile local administrator, because such an account can
  already read the runner's own credentials and job workspaces.
- Operators who reject this trade-off can use `service install --start-at login`
  and keep a user-scoped store, accepting no unattended restart.

## Threats and controls

| Threat | Control | Security gate |
|---|---|---|
| A stolen config file grants GitHub access. | Private key is secret-store-only; config contains no usable token. | Inspect config and SQLite fixtures for secrets. |
| A process listing reveals a JIT config. | Do not pass JIT data as a command-line argument; use restrictive file/pipe handoff. | Native process-inspection test. |
| A hostile workflow leaves data for a later job. | JIT ephemeral runner and per-attempt workspace deletion. | Two-job contamination test. |
| One host controls another host. | No listener/control API; host identity restricts reconciliation. | Domain ownership and integration rejection tests. |
| A compromised TUI renderer or dependency sends commands. | No plugin system and no script evaluation. | Dependency and static security review. |
| API replay or duplicate listener creates too many runners. | Single instance lock, durable attempt journal, idempotent keys, `max_capacity`, and `host_capacity`. | Restart and duplicate-message test. |
| Public-preview protocol drifts. | Isolated adapter, pinned revision, typed decode validation, fail closed on unknown critical fields, `protocol_flag` per policy. | Contract test against the supported protocol revision. |
| Logs disclose repository secrets. | Structured allowlist logging with unconditional redaction of tokens, headers, JIT blobs, and paths. | Secret-injection log scan. |
| A tampered or substituted runner package executes on the host. | GitHub-supplied download metadata only; mandatory SHA-256 verification before extraction; fail closed when no checksum is published; immutable versioned cache. | Corrupted-package rejection test. |
| A local administrator reads the machine-scoped private key. | Service-account ACL on the store; documented accepted trade-off; `--start-at login` escape hatch. | Store-permission verification test per OS. |
| A published release artifact is tampered with in transit. | SHA-256 checksums and SBOM published with every release; package-manager manifests pin the checksum. | Checksum-mismatch rejection test in the install smoke test. |

## Handling rules

1. All GitHub traffic uses HTTPS with normal certificate validation; no
   `--insecure` mode exists.
2. The daemon exposes no inbound HTTP, socket, or RPC control surface in v1.
3. TUI and CLI require local OS access; service installation does not create a
   privileged interactive command channel.
4. The App must be installed only in repositories the operator selects.
5. Fork and untrusted pull-request workflows must not be enabled on a personal
   host until the operator explicitly accepts the trust boundary; UI warns on
   repository policy enablement.
6. Dependency updates, SHA-256 checksum publication, and SBOM generation are
   release requirements.
7. The release workflow holds the only credential able to publish; it runs on
   `workflow_dispatch` only, requests the minimum `contents: write` permission,
   and never runs automatically (D10).

## Security release gates

- Threat-table tests pass on every supported OS.
- Private key, App JWT, installation token, registration token, Actions-service
  admin token, message-queue token, and JIT blob are absent from logs,
  databases, snapshots, crash reports, and CLI output.
- A job workspace is removed after both successful and failed runs.
- Service account permissions are documented and verified least privilege, and
  the `Administration: Read and write` consequence is recorded as accepted.
- An owner reviews GitHub App permissions and repository installation scope.
- Every published artifact has a SHA-256 checksum and an SBOM. Paid code
  signing is not a v1 gate (D12); the free ad-hoc signature required for arm64
  macOS execution is verified present on the macOS artifacts.
