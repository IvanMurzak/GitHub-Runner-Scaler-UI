# Security architecture

## Authentication model (D3)

The project registers **one** GitHub App and publishes it. Users install that
App on repositories they choose and authenticate with the OAuth 2.0 device
flow. No user creates a GitHub App, chooses permissions, or handles a key file.

Three properties make this serverless:

1. The device flow needs only `client_id`, which is public by design and ships
   compiled into the binary. GitHub documents that a public client cannot
   secure a client secret; this design never tries to.
2. The published App **opts out of user-token expiration**, so there is no
   refresh token and therefore no client secret to hold. Opting in would force
   a server into the design.
3. The project **never generates a private key** for the App. A private key is
   what mints installation tokens; without one, the project cannot act on any
   user's repositories even in principle.

### Trust cost, stated plainly

Users must trust the App registration itself. If the project ever generated a
private key for it, it could mint installation tokens for every installation.
Users cannot verify from outside that no key exists. This is the irreducible
price of "install our App" and it does not exist in a bring-your-own-App
design. Compensating commitments:

- The permission set is fixed, minimal, and published here.
- The App declares no webhook URL, so it receives no repository events.
- Users revoke completely by uninstalling the App or revoking the
  authorization; neither requires the project's cooperation.

### D17 resolved; the contingency is not needed

D17 asked whether a user-to-server token can drive the GitHub credential chain.
**It can** — proven 2026-08-21 at both repository and organization scope
(`docs/spikes/d17-user-to-server-scale-set-chain.md`). The contingency — each
user registering their own GitHub App and the tool using installation tokens
from a locally held private key — is therefore **not** adopted. It stays
recorded only so a future reversal of D3 has a starting point.

The same spike disproved D4 and moved the product to public REST JIT ephemeral
runners. That change *reduces* this document's scope: three derived credentials
disappear entirely.

## GitHub App permissions

The published App declares one permission set, used for both scopes (D18):

| Permission | Level | Why |
|---|---|---|
| Repository → Administration | Read and write | JIT runner registration at repository scope (`generate-jitconfig`). |
| Repository → Actions | Read | In-progress workflow-run counts. |
| Repository → Metadata | Read | Mandatory for repository access. |
| Organization → Self-hosted runners | Read and write | JIT runner registration at organization scope. Narrower than the repository grant: it confers no ability to delete, rename, or transfer anything. **Unverified** for `generate-jitconfig` as of 2026-08-21. |

An organization-scoped policy therefore operates under a materially smaller
grant than a repository-scoped one. Where both are possible, organization scope
is the safer choice and the UI says so at policy creation.

`Administration: Read and write` is **not** a narrow self-hosted-runner
permission. The same grant permits deleting, renaming, and transferring the
repository and adding or removing collaborators. It is unavoidable for
repository-scoped JIT runner registration. Because every user installs the same published
App, this is a one-time product-wide decision that every future user inherits,
and it must be stated prominently wherever the App is offered — not left for
GitHub's installation screen to disclose.

**This binds monitor-only users too, and that is an accepted cost (D21).** D19
lets a user run the product purely as a dashboard, but a GitHub App grants its
whole declared permission set on installation; there is no per-installation
subset. A user who wants only in-progress workflow counts still grants the
ability to delete their repositories. Splitting the product across two
published Apps would fix that and was rejected on 2026-08-21 to keep one
registration, one audit surface, and one onboarding path.

Because the cost is accepted rather than removed, disclosure becomes a
requirement rather than a courtesy:

- The repository `README.md` states the permission set and what
  `Administration: Read and write` implies, before the install commands.
- `auth login` prints the same statement before opening the browser, and
  `repo add`/`org add` repeat it when creating a monitor-only policy, where a
  user is least likely to expect a write grant.
- The permission set cannot be narrowed later without forcing every existing
  installation to re-consent, so it is fixed at registration time.

GitHub Apps cannot authenticate runners at the enterprise level at all, so
D18's two scopes are the complete set.

## Credential inventory

| Credential or sensitive value | Source | Storage | Exposure rule |
|---|---|---|---|
| App `client_id` | Compiled into the binary | Not secret | Public by design; may appear in logs and documentation. |
| User access token | Device flow | Machine-scoped secret store (D13) | The only persisted GitHub credential. Never config, SQLite, logs, diagnostics, UI, or command argument. |
| Device code and user code | Generated per `auth login` run | Memory only | Single-use, short-lived; the user code is shown on screen by design, the device code never is. |
| JIT configuration | `POST …/actions/runners/generate-jitconfig` | Restrictive temporary handoff only | Delete immediately after launch; never persist. |
| Repository checkout/secrets | Workflow execution | Disposable attempt workspace | Delete after attempt; never show file names/content in normal UI. |

D4 deleted three rows from the table above — the runner registration token,
the Actions-service admin token and tenant URL, and the message-queue access
token. None exists in the REST JIT design. The product now holds exactly one
persisted GitHub credential and one short-lived sensitive value.

## The non-expiring token: accepted trade-off

Opting out of user-token expiration is what removes the server from the design,
and it means a long-lived bearer token sits on an always-on machine. Compared
with a classic PAT it is materially narrower — limited to the published App's
declared permission set and only the repositories or organizations where the
user installed the App — but it does not expire on its own. Compensating controls:

- Stored only in the machine-scoped secret store, ACL'd to the service account.
- `auth logout` purges it locally; uninstalling the App invalidates it at
  GitHub, which is the authoritative revocation.
- `auth status` shows which repositories the token can reach, so an over-broad
  installation is visible rather than assumed.
- The credential-disclosure response in `05-infrastructure.md` is documented
  and rehearsed.

## Machine-scoped storage: accepted trade-off

D13 stores the token machine-scoped rather than in the operator's user keychain
so a boot-time service can read it. Any local administrator or root account on
that machine can therefore read it. The threat model already assumes a hostile
*workflow* can run on this host; it does not assume a hostile local
administrator, because such an account can already read the runner's own
credentials and job workspaces. Operators who reject this can use
`service install --start-at login` and keep a user-scoped store, accepting no
unattended restart.

## Threats and controls

| Threat | Control | Security gate |
|---|---|---|
| A stolen config file grants GitHub access. | Token is secret-store-only; config contains no usable credential, and `client_id` alone grants nothing. | Inspect config and SQLite fixtures for secrets. |
| A stolen user access token is used indefinitely. | Narrow permission set, installation limited to user-selected repositories, machine-scoped ACL'd storage, revocation by uninstall, `auth status` surfaces reachable repositories. | Revoked-token rejection test; documented disclosure response. |
| A process listing reveals a JIT config. | Do not pass JIT data as a command-line argument; use restrictive file/pipe handoff. | Native process-inspection test. |
| A hostile workflow leaves data for a later job. | JIT ephemeral runner and per-attempt workspace deletion. | Two-job contamination test. |
| One host controls another host. | No listener/control API; host identity restricts reconciliation. | Domain ownership and integration rejection tests. |
| A compromised TUI renderer or dependency sends commands. | No plugin system and no script evaluation. | Dependency and static security review. |
| API replay or a duplicate agent creates too many runners. | Single instance lock, durable attempt journal, idempotent keys, `max_capacity`, and `host_capacity`. | Restart and duplicate-poll test. |
| Two hosts start a runner for the same queued job. | No `AcquireJobs` equivalent exists on the REST path, so this is bounded rather than prevented: host-scoped routing labels, both capacity ceilings, and an ephemeral runner that exits on idle timeout when it finds no work. | Two-host contention test asserting the surplus runner exits and is cleaned. |
| ~~Public-preview protocol drifts.~~ | **Retired by D4.** The product speaks only documented, stable REST; there is no preview protocol, adapter, pinned revision, or `protocol_flag`. | — |
| Logs disclose repository secrets. | Structured allowlist logging with unconditional redaction of tokens, headers, JIT blobs, and paths. | Secret-injection log scan. |
| A tampered or substituted runner package executes on the host. | GitHub-supplied download metadata only; mandatory SHA-256 verification before extraction; fail closed when no checksum is published; immutable versioned cache. | Corrupted-package rejection test. |
| A phishing page imitates the device-flow prompt to harvest a code. | The tool prints the canonical `github.com/login/device` URL and never proxies or embeds the approval page; documentation states the code is only ever entered on that GitHub domain. | Onboarding copy review. |
| The published App registration is compromised. | No private key exists to steal; permission set is fixed and public; users revoke by uninstalling without project involvement. | App-registration configuration audit each release. |
| A published release artifact is tampered with in transit. | SHA-256 checksums and SBOM published with every release; the install script verifies before installing; package manifests pin the checksum. | Checksum-mismatch rejection test in the install smoke test. |

## Handling rules

1. All GitHub traffic uses HTTPS with normal certificate validation; no
   `--insecure` mode exists.
2. The product exposes **no** inbound HTTP, socket, or RPC surface anywhere, in
   any command. The device flow is poll-based, so not even a transient loopback
   redirect listener is required.
3. TUI and CLI require local OS access; service installation does not create a
   privileged interactive command channel.
4. The App must be installed only in repositories the user selects, and
   `auth status` must make the current installation scope visible.
5. Fork and untrusted pull-request workflows must not be enabled on a personal
   host until the operator explicitly accepts the trust boundary; UI warns on
   policy enablement.
6. Dependency updates, SHA-256 checksum publication, and SBOM generation are
   release requirements.
7. The release workflow holds the only credential able to publish; it runs on
   `workflow_dispatch` only, requests the minimum `contents: write` permission,
   and never runs automatically (D10).
8. The project never generates a private key for the published App. If one is
   ever needed, that is a reversal of D3 and requires a recorded decision.

## Security release gates

- Threat-table tests pass on every supported OS.
- The user access token and the encoded JIT configuration are absent from logs,
  databases, snapshots, crash reports, and CLI output.
- A job workspace is removed after both successful and failed runs.
- The published App's configuration is audited: device flow enabled, user-token
  expiration opted out, no private key generated, no webhook URL, permission
  set unchanged from the table above.
- Service account permissions are documented and verified least privilege.
- The `Administration: Read and write` disclosure appears in the README before
  the install commands, in `auth login` output, and in `repo add`/`org add`
  output for monitor-only policies. Copy is reviewed each release.
- Every published artifact has a SHA-256 checksum and an SBOM. Paid code
  signing is not a v1 gate (D12); the free ad-hoc signature required for arm64
  macOS execution is verified present on the macOS artifacts.
