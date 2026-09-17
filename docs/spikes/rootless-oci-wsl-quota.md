# Rootless OCI writable-layer quota on managed WSL

The Linux/WSL OCI provider requires an operator-installed Podman-compatible
runtime with rootless user mappings, cgroup v2 CPU/memory/pids controllers, and
a working hard writable-layer size quota. It refuses an isolated policy before
requesting GitHub JIT when that quota is unavailable. The provider is for
dependency-isolated trusted workflows under the D6 product boundary.

On the September 2026 Windows test host, the managed Ubuntu 24.04.3 LTS WSL2
distribution ran Podman 4.9.3 as UID 1000 with 65,536 subordinate UIDs and GIDs.
`podman info --format json` reported `rootless: true`, cgroup v2 with CPU,
memory, and pids controllers, graph root in `/home/ivan/.local/share/containers`,
and run root in `/run/user/1000/containers`.

The default WSL ext filesystem refused the required quota:

```text
wsl -d Ubuntu -- podman create --storage-opt size=1024m \
  docker.io/library/ubuntu@sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254 true
exit 1: storage option overlay.size and overlay.inodes only supported for backingFS XFS. Found extfs
```

An XFS loopback graph root mounted with project quotas also refused the
rootless quota setup:

```text
wsl -d Ubuntu -- env CONTAINERS_STORAGE_CONF=/home/ivan/.local/share/containers/xfs-fixture/storage.conf \
  podman --storage-opt size=1024m info --format '{{.Store.GraphRoot}}'
exit 1: Filesystem does not support Project Quota: failed to mknod .../overlay/backingFsBlockDev.tmp: operation not permitted
```

The provider's typed `DiskQuotaUnavailable` probe covers both refusals before
image pull, allocation, or JIT. The XFS preflight is needed because merely
checking that the graph root is on XFS would have reported false readiness.
Podman's [create options](https://docs.podman.io/en/latest/markdown/podman-create.1.html)
describe the resource and log-driver controls; the containers/storage
[quota documentation](https://github.com/containers/storage/blob/main/docs/containers-storage.conf.5.md#quotas)
specifies XFS project quotas for overlay writable layers.

A separate rootless WSL fixture omitted the quota only to inspect the other
controls. A pinned Ubuntu digest container accepted a test sentinel through
`podman start --attach --interactive` stdin, exited successfully, and had
`Mounts=[]`, log driver `none`, pids limit 128, memory limit 512 MiB, and CPU
limit 1.0. The sentinel was absent from before/after container inspect metadata.
Podman warned that `/` was not a shared mount on WSL; the inspected container
still had no explicit mounts, and nested container behavior was not exercised.
The fixture was removed. This proves the stdin channel and observed container
configuration on this host; it did not execute a real GitHub runner or job.

With the quota deliberately omitted, a rootless Ubuntu fixture with only
`CHOWN`, `SETUID`, `SETGID`, `DAC_OVERRIDE`, and `FOWNER` guest capabilities
installed `python3-minimal` and reported Python 3.12.3. A fresh sibling from
the same pinned image then reported `sibling-clean` because `python3` was
absent. Dropping every capability prevented `apt` from switching to its
unprivileged `_apt` identity; the five named capabilities are therefore part
of the provider's guest-local package installation profile. Both fixtures were
removed by `podman run --rm`.

## Managed WSL bounded-store helper acceptance

The rootless project-quota failure does not prevent an operator from supplying a
harder outer bound. On September 16, 2026, the same managed Ubuntu distribution
passed `tests/managed-wsl-oci-acceptance.sh` with an operator-provisioned,
root-owned Podman-compatible helper. The disposable helper routed the provider's
`--storage-opt size=1024m` probe and create into a 1,024 MiB ext4 loop filesystem
mounted inside the distribution. It removed only the unsupported Podman option;
the whole graph root remained inside that finite filesystem. The helper checked
the loop mount and capacity before attesting schema 1 mode
`exclusive-filesystem-pool`. The production adapter accepted extfs only with
that exact attestation. Plain Podman and incomplete or false attestations still
returned `DiskQuotaUnavailable`.

All Podman commands ran as UID 1000 through the configured helper. The graph
root, run root, helper, build target, temporary attempt packages and runner
runtime were absolute Linux paths outside `/mnt`; no host path, device, Podman
socket or Docker socket entered a container. The production provider resolved
the pinned Ubuntu digest, prepared and started two simultaneous containers,
installed versions 1.0 and 2.0 of the same Debian package independently, and
then proved a fresh sibling contained neither package state nor executable. A
1,100 MiB `fallocate` failed with `ENOSPC` against the 1,024 MiB filesystem; the
fixture removed the partial allocation inside that command so Podman retained
space to journal the exit and perform normal owned cleanup.

The same run exercised stdin-only synthetic JIT delivery, inspect/log/history
and exported-rootfs sentinel scans, CPU/memory/pids controls, normal destruction,
crash-gap orphan discovery and adoption, and a final independent container
sweep. The root-owned helper, loop mount, loop image, graph root, cargo target
and temporary files were removed after the evidence run. This closes the real
managed-WSL container-boundary gate through the production prepare/start path.
It does not claim a GitHub runner job or reboot continuity; those require JIT
fixture secrets and a reboot-resumable host.

## GitHub-hosted native Linux acceptance

CI run `35170389901` exercised the secret-free native fixture on GitHub's
`ubuntu-24.04` image (Ubuntu 24.04.5, Podman 4.9.3). The harness used the hosted
runner's documented passwordless `sudo` only to create and mount a disposable
6 GiB XFS loopback filesystem with `prjquota`; every Podman and provider command
ran as the ordinary runner user. Podman reported rootless mode, 65,536
subordinate UIDs/GIDs, cgroup v2 CPU/memory/pids controllers, and the dedicated
XFS graph root. GitHub documents the hosted Linux privilege model in its
[hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners#administrative-privileges),
and containers/storage documents the XFS project-quota requirement in its
[storage configuration reference](https://github.com/containers/storage/blob/main/docs/containers-storage.conf.5.md#quotas).

The real `podman --storage-opt size=1024m info` preflight refused that store:

```text
Filesystem does not support Project Quota: failed to mknod .../overlay/backingFsBlockDev.tmp: operation not permitted
```

This is a rootless Podman limitation, not a missing XFS mount option: Podman
maintainers confirm that rootless users cannot create the device node and that
project IDs are not namespaced
([upstream issue](https://github.com/containers/podman/issues/16424)). The
production provider returned the typed `DiskQuotaUnavailable` result before
image allocation or JIT. CI requires that refusal and fails if Podman ever
starts accepting the preflight, forcing the fixture to move to the full
provider prepare path instead of silently retaining the reduced path.

After proving the production refusal, the fixture omitted only the unavailable
per-container storage option and exercised the remaining provider lifecycle on
the hard-bounded 6 GiB loopback store. It verified the pinned Ubuntu amd64 image
digest; empty host mounts, bind mounts and device requests; no Podman or Docker
socket; CPU/memory/pids controls; two simultaneous containers installing
versions 1.0 and 2.0 of the same generated Debian package without changing each
other or the host; a fresh third container with neither package state nor tool;
normal stop/destroy; and discovery of exactly one crash-gap orphan followed by
owned cleanup. A 7 GiB `fallocate` failed against the 6 GiB backing filesystem.
A synthetic JIT sentinel passed through provider stdin and was absent from
container inspect, disabled logs, image history and exported root filesystems.
All containers were independently swept before the XFS fixture was unmounted.

This native gate does **not** claim a GitHub runner job. The repository has no
JIT/fixture secrets for this job, and rootless Podman 4.9.3 cannot enforce the
required per-container 1 GiB writable-layer cap even on XFS with project quotas.
Consequently a full provider prepare/start remains unavailable with plain
Podman, and real demand-to-JIT plus reboot continuity remain open. Managed WSL
can use the separately attested bounded-store helper described above. Without
that operator-provisioned helper, the hard per-container cap remains mandatory
and affected policies continue to fail closed before JIT.
