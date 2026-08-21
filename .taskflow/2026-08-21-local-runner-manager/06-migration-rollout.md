# Migration and rollout

Phase numbers map to ROADMAP waves as recorded in `ROADMAP.md`.

## Phase 0: prepare

- Establish the Rust workspace, `rust-toolchain.toml`, committed `Cargo.lock`,
  `.gitignore`, and matrix CI in this repository.
- **Run the D17 spike before any other authentication work:** prove that a
  user-to-server token obtained by the device flow can mint a runner
  registration token, complete the Actions-service admin exchange, open a
  message session, call `AcquireJobs`, and generate a scale-set JIT config. A
  negative result reverses D3; do not build the auth path until this is green.
- Register the project's single published GitHub App once, under an
  owner-approved account, with exactly the permissions listed in
  `07-security.md`. Enable device flow. Opt **out** of user-token expiration.
  Do **not** generate a private key. Explicitly accept the
  `Administration: Read and write` consequence.
- Create a disposable test repository and document its scale-set name.
- Measure one representative workload on each host to choose `max_capacity`
  and `host_capacity`.

**Gate:** The D17 spike passes. The published App is installable, device flow
works end to end from a clean machine, the App installation is limited to the
disposable repository, and the user token is stored in the selected
machine-scoped secret store.

## Phase 1: one-host, one-repository pilot

- Install the binary on Windows with `host_capacity=1` and `max_capacity=1`.
- Add one repository through the CLI, then enable one scale-set policy.
- Change one test workflow to `runs-on: <scale-set-name>`.
- Run a successful job, then test JIT expiry, network loss, restart recovery,
  boot-start recovery after a real reboot, and drain.

**Gate:** No runner remains registered or running after successful job cleanup;
the old runner label has not been reused; the service comes back by itself
after a reboot without an interactive login.

## Phase 2: production repository adoption

- Add repositories one at a time through CLI.
- Keep legacy persistent runners available only with distinct labels during the
  observation period.
- Move workflows to the scale-set name in small batches.
- Observe capacity against both ceilings, startup latency, rate-limit behavior,
  cache health, runner-version freshness, and cleanup outcomes.

**Gate:** Every migrated repository completes a representative workflow, the
host stays within `host_capacity`, and the host remains within its approved
resource budget.

## Phase 3: macOS and Linux

- Repeat the pilot with separate `home-macos` and `home-linux` host labels.
- Explicitly reject workflows that depend on Linux-only container actions when
  a macOS or Windows policy is selected.
- Validate native service installation, boot start, sleep/reboot recovery, and
  machine-scoped secret store behavior on each OS.
- Note that ARM64 is public preview at GitHub; record it in the acceptance
  record for the Apple Silicon host.

**Gate:** A representative workflow completes on macOS and on Linux, with
native service installation and reboot recovery verified on each, and the
threat-table tests from `07-security.md` passing on both.

## Phase 4: public beta

- Publish the first release through the manual release workflow.
- Publish the install scripts, npm wrapper, Homebrew tap, and Scoop bucket, and
  verify a clean one-command install on each OS from a machine that has never
  built the product.
- Verify that no install path triggers a Gatekeeper block or SmartScreen
  warning on a clean macOS and a clean Windows host.
- Verify device-flow onboarding end to end as a user who has never seen the
  product: install, `auth login`, install the App, first job.

**Gate:** Security, offline, and cross-platform gates pass; a rollback drill
has been executed once per supported OS.

## Legacy disposition

Legacy persistent runners are not imported as managed runners. The TUI can
display them through GitHub inventory, clearly marks them as external, and
never starts, stops, or relabels them. They are retired only by a human after
workflow labels no longer route work to them.

## Risks and mitigations

| Risk | Mitigation | Rollback trigger |
|---|---|---|
| Scale-set public-preview protocol changes | Isolated adapter, pinned revision, contract tests, `protocol_flag` per policy. | Repeated protocol failure or incompatible API response. |
| Host overload | Explicit per-policy `max_capacity` and host-wide `host_capacity`, start at one. | Sustained resource pressure or failed jobs. |
| Slow cold start | Versioned local package/cache and measured optional warm minimum later. | Job startup violates agreed operational target. |
| Cleanup failure | Journal, startup recovery, redacted diagnostics, no workspace reuse. | Orphaned runner/workspace persists after recovery. |
| Misrouted workflow | Unique scale-set names and pilot isolation. | Job reaches an unintended host/OS. |
| Credential exposure | Machine-scoped secret store, memory-only derived tokens, redaction, strict file permissions. | Any suspected token/JIT disclosure. |
| The D17 assumption fails: user-to-server tokens cannot drive the scale-set chain | Spike runs first in Phase 0, before any auth implementation. Contingency is the per-user GitHub App with installation tokens, documented in `07-security.md`. | Spike returns a negative result; D3 is reopened. |
| The published App becomes a single point of trust and failure | The project never generates a private key for it, so it cannot mint installation tokens for anyone. Permission set is fixed and published. Users revoke by uninstalling. | Any compromise of the App registration itself. |
| Runner package goes stale and jobs start failing | 30-day freshness check before each cold start; version rejection treated as terminal, not retryable. | Repeated version-rejection responses. |
| Prolonged host outage silently loses queued work | Offline state names the 24-hour queue-cancellation bound. | Outage approaching 24 hours with queued demand. |
| Service start mode breaks after a Node upgrade | `service install` records an absolute binary path; `service status` reports a stale path. | Service fails to start after a toolchain change. |

Rollback procedure: see `05-infrastructure.md` Rollback, and Credential-disclosure
response for the key-disclosure trigger. A rollback drill — label restore,
drain, terminal-state verification, legacy re-enable — is executed once per
supported OS before public release.
