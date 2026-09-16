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

Native Linux with quota-capable rootless storage was not available for this
run. Managed WSL real-job, conflicting-package, reboot/orphan, resource
exhaustion, and JIT credential-plane acceptance remain open until a rootless
hard-quota-capable storage configuration is demonstrated. The provider keeps
affected isolated policies closed and leaves native execution available.
