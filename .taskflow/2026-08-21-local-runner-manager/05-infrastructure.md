# Infrastructure, deployment, and rollback

## Deployment model

There is no server deployment. Each operator installs the same binary on a
supported local host, normally through a package manager
(`09-release-distribution.md`):

```text
Windows: runner-manager.exe + optional Windows service
macOS:   runner-manager + optional launchd job
Linux:   runner-manager + optional systemd service
```

The daemon requires outbound HTTPS only. It owns:

```text
config/      non-secret TOML and SQLite database
state/       agent lock, attempt journal, retained runner package/cache
runtime/     per-attempt disposable directories
logs/        rotating redacted agent diagnostics
```

Platform-standard application-data directories are used; no repository or
runner material is stored in the current working directory by default.

## Secrets and configuration

| Item | Location | Rotation/removal |
|---|---|---|
| GitHub user access token | Machine-scoped secret store: DPAPI machine scope (Windows), System Keychain (macOS), `0600` file plus systemd credentials (Linux) | Re-issue via `auth login`; delete on `auth logout`; revoke on GitHub by uninstalling the App. |
| App `client_id`, installation id, host and policy settings | Local config/SQLite | `client_id` is public by design and is compiled into the binary; the rest is mutable by CLI/TUI and not secret. |

| Runner registration token | Memory only | Consumed immediately in the Actions-service registration exchange. |
| Actions-service admin token and tenant URL | Memory only | Refreshed 60 seconds before expiry; never persisted. |
| Message-queue access token | Memory only | Refreshed on session token expiry; never persisted. |
| Encoded JIT configuration | Restrictive temporary file or process-safe handoff | Delete immediately after runner start or failed start. |
| Runner package checksum/version | Local cache metadata | Revalidated on download and refresh. |

The user access token is machine-scoped rather than user-scoped because D13
requires the service to start at machine boot. A boot-time service runs outside any
user's login session and cannot read a per-user keychain on any supported OS:
macOS LaunchAgents start only at login, and Windows Credential Manager vaults
are per-user. The accepted consequence is that a local administrator or root
account on this machine can read the key; `07-security.md` records this
trade-off and its compensating controls.

The installer creates no GitHub App and no scale policy. Those operations
require explicit operator commands after installation.

## Service behavior

`service install` registers `daemon run` for the current host and defaults to
`--start-at boot`. It must:

1. refuse a second instance when the local lock is held;
2. run under a least-privilege account that can read the machine-scoped secret
   store and write its configured cache and runtime directories;
3. set a restart-on-failure policy with bounded delay;
4. preserve a local diagnostic log path and expose it through
   `service status`;
5. support `service uninstall` without deleting configuration, secrets, or
   cache;
6. resolve and record the **absolute** path of the running binary at install
   time, and report a stale or missing path through `service status`. This
   matters because an npm-installed binary lives under the active Node
   installation's global prefix, which moves when the operator switches Node
   versions with a version manager;
7. expose the current start mode in `host show` and in TUI host settings, and
   allow switching between `boot` and `login` without reinstalling the product.

`--start-at login` remains available for operators who prefer the token in a
user-scoped store; in that mode the agent does not run until the operator
logs in, and `service status` says so.

## Runner package lifecycle

The agent obtains runner download metadata through GitHub, selects only the
current host OS/architecture, verifies the published SHA-256 checksum, and
extracts a versioned immutable package cache. Each JIT runtime is a copy or
link from that cache plus a unique workspace.

`sha256_checksum` is an optional field in GitHub's response schema. When it is
absent the agent fails closed and requires an operator-pinned digest rather
than installing an unverified package.

The agent re-checks the published runner version on a bounded interval and
before each cold start, and downloads a newer package when the cached version
is more than 30 days older than the latest release. GitHub rejects runners
older than 30 days from executing workflows and plans to block them at
registration, so a version-rejection response is a terminal, operator-actionable
condition, not a retryable error. A version cache may be pruned only when no
active attempt references it.

## Rollback

1. Restore workflow labels to the previously documented runner target, so no
   new job routes to the scale set. Doing this first prevents jobs from queuing
   against a scale set that is about to have no runners; a queued job is
   cancelled by GitHub after 24 hours.
2. `repo set-scale OWNER/REPO --enabled false` drains the policy.
3. Wait for active attempts to become terminal, then stop the daemon/service.
4. If needed, re-enable a legacy persistent runner with a non-overlapping
   label.
5. Preserve logs and SQLite for diagnosis; use `repo remove --purge` only
   after confirming no active runner and no desired recovery data.

The installer rollback is binary replacement plus service removal. It never
deletes the stored user access token automatically.

## Credential-disclosure response

This is the procedure for the "any suspected key or JIT disclosure" rollback
trigger in `06-migration-rollout.md`:

1. Revoke the authorization for the published App in GitHub account settings,
   which invalidates the leaked user access token immediately.
2. Run `auth logout` on every host to purge the machine-scoped secret store.
3. Run `auth login` on each host to obtain a fresh token.
4. Allow in-flight attempts to finish or terminate them, then verify through
   GitHub inventory that no runner remains registered.
5. Review the App's installation scope and permissions.

Registration, admin, and message-queue tokens are memory-only and expire
without action.
