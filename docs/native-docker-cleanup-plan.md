# Native Linux Docker resource accounting

Native runners use a shared Docker engine. Removing the runner process and its
workspace does not remove containers or anonymous volumes owned by that engine.
Cleanup must preserve shared build caches and resources belonging to other jobs.

## Operator controls

`host docker-cleanup show` displays support and the current mode. Configuration
lives in `config/docker-cleanup.json`; the daemon reads changes without a restart.

- `off`: do not account for new attempts or delete tracked Docker resources.
- `report` (default): account for new attempts and report candidates without
  deleting Docker resources. Automatic inventories are throttled to hourly per
  completed attempt; an explicit `host docker-cleanup report` inventories now.
- `apply`: remove eligible resources after their attempt reaches `Cleaned`.

Use `host docker-cleanup set-mode --mode apply` after reviewing the report.
`host docker-cleanup sweep` uses the configured mode. Windows and macOS expose
support information but reject enabling/applying this Linux feature. A managed
WSL guest is addressed with `--host wsl:Ubuntu`.

## Ownership and recovery

Each native Linux attempt gets a private Unix-socket proxy and a companion
process. Only the runner's `DOCKER_HOST` changes. The shared engine, dependency
cache variables and persistent workspace paths stay in place. Explicit remote
endpoints and selected Docker contexts bypass accounting.

Before forwarding container, anonymous-volume or network creation, the proxy
durably records a unique operation intent and adds host, attempt and operation
labels. It records exact resource IDs and creation fingerprints before releasing
a successful create response, including implicit anonymous image volumes found
by inspecting the new container. Request bodies, credentials, environment values
and container logs are never journalled. Explicit mount destinations are stored
as digests, not raw paths.

Journals live in `state/docker-cleanup/<attempt UUID>/`, outside disposable
workspaces. Writes use an atomic replacement and directory sync.
JSON publications are limited to the same 8 MiB bound as journal reads; an
oversized update leaves the previous recovery journal intact. Reads remain
bounded if the file grows after its metadata was inspected. Private
directories are mode 0700 and sockets 0600. The companion survives daemon reloads
but exits when the exact runner process disappears, or after 30 seconds if its
parent never starts the runner. Startup is bounded to five seconds. An accounting
startup error is fail-open in report mode and fail-closed in apply mode.

A cross-process sweep lock serializes cleanup. Each journal is checked against
the authoritative attempt Store; unknown, non-native or non-cleaned attempts are
retained. The companion is stopped and its exact process identity must be gone
before the journal can be reconciled. Cleanup verifies the Linux engine identity,
resource labels and creation fingerprints. A malformed journal defers that
attempt without blocking other attempts.

Recovery finds creations using all three exact ownership labels. An ambiguous
request keeps its unresolved intent even if an inventory is empty: a Docker
operation might still finish later. Such a record can remain as small metadata
indefinitely rather than losing the ownership evidence. Only known journal files
are removed, and unexpected directory entries preserve the metadata.

## Preservation rules

Cleanup removes tracked temporary containers first, then their recorded
anonymous volumes and networks. Container removal is forced; volume and network
removal is never forced, so Docker atomically refuses deletion while another
container uses them. Failures remain pending for retry.

Always preserved:

- Explicitly named volumes, even names shaped like anonymous volume IDs.
- Volumes explicitly supplied to a container and inherited `VolumesFrom` mounts.
- Resources created with `runner-manager.retain=true`.
- Buildx builder containers recognized by their standard name or BuildKit state
  mount, Docker images, and engine build caches.
- Filesystem dependency/package caches and persistent runner workspaces.
- Unknown historical resources and resources belonging to other attempts.

No global prune is used. The mechanism is accounting for trusted native
workflows, not a security boundary against Docker-root clients. A workflow can
bypass the proxy by selecting another endpoint/context or accessing the raw
engine socket. Resources created outside accounting, or removed concurrently
before their anonymous-volume associations can be inspected, cannot be safely
reconstructed from age or a detached-volume inventory and may need manual
cleanup. This change does not repair existing Docker snapshot metadata errors.

## Verification

Unit tests cover ownership conflicts, retained/named/reused volumes, inherited
mounts, ID reuse, engine mismatch, in-use retries, durable schema validation and
bounded HTTP framing. CLI integration runs on Windows and Linux and checks that
cache/workspace sentinels survive mode changes and sweeps.

The opt-in real-engine acceptance test is enabled in the Linux CI job:

```sh
cargo test -p runner-manager --test native_docker_cleanup \
  live::live_proxy_report_apply_recovery_streams_and_cache_preservation \
  -- --ignored --exact --nocapture
```

It exercises container creation, interactive attach and streaming, read-only
reporting, recovery after losing recorded IDs, a late network creation after an
empty recovery pass, a volume shared by concurrent attempts, and automatic
companion exit. Named-volume, unrelated-resource, retain-label, dependency-cache
and persistent-workspace sentinels remain intact. A real BuildKit build is
repeated after cleanup and must report a cache hit. Fixtures use unique names,
record their helper PIDs and remove only resources they created.

Review fixes include retaining ambiguous intents, checking stored Docker
contexts, isolating corrupt journals, bounding companion startup, verifying
runner identity for companion lifetime, and validating journal associations.
