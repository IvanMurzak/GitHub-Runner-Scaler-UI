# Resource accumulation on IVANPC (2026-10-30)

Investigated against runner-manager 0.4.41, commit `13f00ef`. Measurements below
precede the operator-authorized cleanup. They are filesystem measurements and
runtime inventories, not an attribution of every byte to runner-manager.

## Findings

| Resource | Observation | Cause and scope |
| --- | --- | --- |
| Docker volumes in Ubuntu | About 66 GiB on disk; Docker's cleanup reported 69.9 GB reclaimed | Detached volumes survived their containers. The original per-volume metadata was not retained before cleanup, so individual jobs cannot now be reconstructed. |
| Stopped Docker containers | 13 containers, some seven weeks old; also `Dead` container metadata | Native workflows share Docker. A manager process-tree cleanup cannot remove Docker-daemon-owned resources. Several names reference application-specific validation/test containers; ownership by the manager's isolation provider was not established. |
| Legacy Linux runners | About 21 GiB under `/home/ivan/actions-runners`, with 13 separately installed systemd units | Outside the current manager runtime root (`/root/.local/share/runner-manager/runtime`). Removing a unit does not remove its files. No evidence these directories are leaked current ephemeral attempts. |
| Legacy Windows workspace | About 1.85 GiB in `f8496a8fbc47_old` | Outside the current configured runner root. No journal ownership was established; automatic recursive deletion would be unsafe. |
| Manager diagnostics | 7,843 Windows files and 18,877 Linux files | Confirmed retention defect: `LifecycleLauncher::preserve_diagnostics` writes one UUID-named file per concluded attempt outside its workspace. Nothing expired these files. Daily rotating logs also had no file-count limit. |
| Dependency caches | Roughly 14 GiB each on Windows and Linux, each configured for a 20 GiB cap | Intentional retained data, separate from disposable workspaces. No cleanup-blocked attempts were reported at inspection. |

## Docker mechanism

The installed GitHub Actions runner package was 2.338.0. Its
[`DockerCommandManager.DockerRemove`](https://github.com/actions/runner/blob/v2.338.0/src/Runner.Worker/Container/DockerCommandManager.cs)
calls `docker rm --force` without `--volumes`. This leaves anonymous image/service
volumes behind, consistent with the observed PostgreSQL service containers and
many detached volume names. Workflows that launch their own containers also need
their own cleanup, including failure and cancellation paths. This establishes a
leak mechanism, not proof that all reclaimed volumes came from one project.

The manager's current Linux isolated provider uses Podman with
`--image-volume=ignore`, so it does not create implicit image volumes. Windows
Hyper-V container removal, however, also omitted `--volumes` in all four removal
paths. An image declaring a volume can therefore leave it behind even when the
container is rejected during configuration attestation. That is a separate
confirmed code defect; this Windows backend was not responsible for the Linux
Docker volume accumulation observed here.

Docker also reported missing snapshot metadata during disk accounting. The
retention changes do not claim to repair containerd metadata or explain the
original WSL `E_UNEXPECTED` failure.

## Changes on `fix/resource-retention`

- Keep at most 30 daily files per rotating log stem.
- On daemon startup and hourly, including the no-policy path, expire canonical
  `<attempt UUID>.log` summaries after 30 days and keep at most the newest 1,000.
  The scan is off the async executor, skips directories and symlinks, leaves
  unrelated files and caches alone, and retries failed removals on later passes.
- Remove anonymous volumes with an owned Windows Hyper-V container in normal
  cleanup and each preparation rollback, using `docker rm --force --volumes`.
- Add native Linux per-attempt Docker accounting with default read-only report
  mode and opt-in apply mode. Exact ownership journals survive daemon reloads;
  only cleaned attempts qualify. Named volumes, images, build caches, filesystem
  dependency caches and persistent workspaces are preserved. No global Docker
  prune is added to the daemon. See [design and verification](native-docker-cleanup-plan.md).

These changes require a built and installed new binary to affect this machine.
The running 0.4.41 services are not replaced by this investigation.
