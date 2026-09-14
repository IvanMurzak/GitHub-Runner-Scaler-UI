# Security and recovery contract

## Threat boundary

Two useful products fit the word “sandbox”, but they are not interchangeable:

1. **Reproducible trusted-workflow environment.** Prevent accidental dependency,
   filesystem and process contamination. Rootless containers are appropriate on
   Linux/WSL; platform VMs/Hyper-V containers fill the native OS gaps.
2. **Hostile-workflow security boundary.** Assume repository code actively tries
   to escape. Require VM-grade isolation (or a separately audited hardened
   container boundary), no host sockets/devices/directories, controlled egress,
   bounded resources, guest patching and explicit secret policy.

Under D6, documentation and UI must not claim that the proposed OCI V1 safely
executes hostile pull requests. “Dependency-isolated trusted workflow” is the
explicit product boundary.

## Baseline controls in either model

- Fresh writable layer/disk for every attempt; destroy it after the single job.
- Pinned and verified image/template identity before JIT registration.
- CPU, memory, process-count and disk limits counted against host capacity.
- No host home, application-data directory, runner package cache, credential
  store, container socket, hypervisor socket or device mounted by default.
- A dedicated guest identity; installation privileges are guest-local only.
- Network enabled initially for GitHub and dependency downloads, with policy
  hooks reserved for later allowlisting.
- Provider metadata contains non-secret ownership and diagnostics only.
- Host logs receive bounded/redacted provider output, never job environment or
  JIT content.

## One-time JIT delivery

Do not encode JIT configuration in OCI command arguments, environment stored by
the runtime, VM configuration, cloud-init, image layers or labels. Create an
ephemeral provider channel after the environment exists: an anonymous pipe,
vsock/virtio socket, or memory-backed in-guest file with restrictive permissions.
The guest bootstrap places it only into `Runner.Listener`'s initial environment,
then deletes/zeroes its handoff before reporting `running`. This preserves the
current final-spawn property (`crates/platform/src/process.rs:625-653`).

## Crash-safe state machine

```text
allocated -> preparing -> prepared -> jit_received -> starting -> running
     |            |           |             |             |          |
     +------------+-----------+-------------+-------------+----------+
                                  failure/terminal -> destroying -> cleaned
                                                           |
                                                     cleanup_deferred
```

Every transition is durable before the next irreversible effect. If the manager
dies:

- `allocated/preparing` with no provider resource can be concluded safely;
- a journalled environment is inspected and adopted or destroyed;
- an owned provider resource with no live journal row is quarantined and
  surfaced, not immediately deleted;
- a running environment remains supervised and is never duplicated;
- a terminal environment holds capacity until absence is proven; and
- cleanup retries are idempotent and provider-generation aware.

Provider resources carry a random generation as well as attempt ID so that a
reused runtime name cannot make recovery stop somebody else's environment.

## Persistent data

Current persistent slots intentionally retain arbitrary `_work` bytes between
jobs (`README.md:477-509`). That conflicts with the simplest “fresh sandbox”
guarantee. V1 refuses `workspace=persistent + execution=isolated`.

A later cache feature should declare named cache volumes with repository scope,
size limits, mount destinations, cleanup ownership and a warning that cached
executables are inputs to later jobs. It must never persist the VM/container root
disk, runner credentials or lifecycle sidecars.

Native and isolated profiles for one repository share no writable filesystem,
environment or runtime merely because their GitHub target is equal. Target
grouping exists only for authentication and one-copy demand polling.

## Required acceptance

1. Native and isolated jobs from one workflow run concurrently under distinct
   selectors; only native execution observes the host toolchain.
2. Two isolated profiles install conflicting Python/system packages and observe
   only their pinned environments; the host is unchanged.
3. A first job's filesystem, process and environment markers are absent from the
   next isolated attempt.
4. Provider unavailable, image mismatch and permission loss block only the
   affected policy and never cause a native start.
5. Kill Runner Manager at every state transition; restart adopts or destroys
   exactly one owned environment without duplicate JIT runners.
6. Reboot the host with prepared, running and cleanup-deferred environments and
   verify durable capacity/accounting.
7. Inspect host process lists, provider metadata, VM/container configuration,
   journal, logs and image layers for JIT content and credentials.
8. Attempt mount/socket/device escapes and resource exhaustion under the selected
   D6 threat model.
9. Validate native Linux, WSL2, supported Windows client/server variants, macOS
   Intel and Apple Silicon independently; no mocked backend can close a native
   support gate.
