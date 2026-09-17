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
1,100 MiB `dd` wrote zeroes through fuse-overlayfs until ext4 returned `ENOSPC`;
`df -B1` reported only one 4 KiB block available on that same filesystem. The
fixture removed the partial allocation inside that command so Podman retained
space to journal the exit and perform normal owned cleanup. This replaced the earlier
`fallocate`-only probe, whose failure could have meant that overlay allocation
was unsupported rather than that the filesystem cap was reached.

The same run exercised stdin-only synthetic JIT delivery, inspect/log/history
and exported-rootfs sentinel scans, CPU/memory/pids controls, normal destruction,
crash-gap orphan discovery and adoption, and a final independent container
sweep. The root-owned helper, loop mount, loop image, graph root, cargo target
and temporary files were removed after the evidence run. This closes the real
managed-WSL container-boundary gate through the production prepare/start path.
It does not claim a GitHub runner job; the distribution-restart boundary is
measured separately below.

## Managed WSL distribution restart continuity

On September 16, 2026,
`tests/managed-wsl-oci-restart-acceptance.ps1 -Distribution Ubuntu` completed a
real distribution stop/start boundary without rebooting Windows. The harness
created the same root-owned 1,024 MiB ext4 helper, four production-provider
resources, and a durable SQLite journal containing `prepared`, running-like
`starting`, `cleanup_deferred`, and crash-gap `preparing` attempts. It flushed
the nested loop filesystem, recorded the WSL kernel boot ID and PID 1 start
time, and then issued exactly `wsl --terminate Ubuntu`.

On the next distribution start, PID 1 had a new start time while the WSL kernel
boot ID was unchanged, so the evidence is a distribution restart rather than a
Windows or WSL VM reboot. The harness remounted the finite store, recreated the
rootless `/run/user/1000` runtime directory, and started a fresh provider
process. All four journal rows still counted against capacity and all four
labelled resources were enumerable. Recovery refused a different generation,
adopted the crash-gap resource carrying the exact attempt and generation,
destroyed every owned resource, and left zero uncleaned journal rows and zero
provider resources. The lifecycle restart regression separately covered every
isolated transition and observed zero JIT registrations during recovery. Final
cleanup removed the helper, loop mount, loop image, graph root, build target,
runtime directories, and containers.

This closes continuity across termination of the managed distribution. A full
Windows reboot remains a separate host boot acceptance boundary.

## One-time live JIT acceptance

PR 74 also carries a temporary, label-gated workflow and a live mode in the
managed-WSL harness. The workflow only queues for same-repository pull request
74 when label `d1-live-jit-pr74-20260916` is added, and its job requires that
unique self-hosted label. Removing the label leaves future pushes unable to
queue the job.

The operator generates one repository JIT configuration with the unique label
and pipes only `encoded_jit_config` to the harness's stdin. The harness verifies
a SHA-256-pinned Actions runner package, keeps its extracted bytes on the WSL
Linux filesystem, and exercises production `OciProcesses::prepare` and
`OciProcesses::start`. The workflow checks out the PR and writes package,
process, and filesystem markers. The Rust acceptance scans container inspect,
process arguments, logs, image history, and the stopped writable layer for the
JIT value before destroying the container. Neither the value nor an API token
is written to an argument, log, or evidence file.

The live runner does retain GitHub's required `ACTIONS_RUNNER_INPUT_JITCONFIG`
startup input in the listener process environment while that listener is alive.
That environment is confined to the isolated container and disappears when the
one-time runner exits; it is not included in inspect metadata, logs, history, or
the exported writable layer. The current GitHub runner interface therefore does
not support a stronger live-process-environment claim.

## GitHub-hosted native Linux acceptance

The PR's native `ubuntu-24.04` gate now uses the same bounded-storage contract as
managed WSL instead of stopping at plain Podman's XFS quota refusal. The harness
uses the hosted runner's documented passwordless `sudo` only to create and mount
a disposable 1,024 MiB ext4 loop filesystem and install a root-owned,
non-writable helper under `/usr/local/libexec`. Every Podman and production
provider command runs as the ordinary runner user through that helper, with
fuse-overlayfs and no unbounded fallback. GitHub documents the hosted Linux
privilege model in its
[hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners#administrative-privileges),
while the helper's capacity and loop-device checks supply the hard-cap
attestation plain rootless Podman cannot.

The production provider performs resolve, image verification, prepare, stdin
handoff, inspect, stop, orphan discovery, adoption, and destroy on the bounded
path. It verifies the pinned Ubuntu digest; empty host mounts, binds, and device
requests; no engine socket; CPU/memory/pids controls; conflicting package
versions isolated between simultaneous containers; a clean sibling; and the
synthetic JIT sentinel absent from inspect, disabled logs, image history, and
exported root filesystems. The cap probe writes 1,100 MiB of zeroes through the
container overlay, requires `No space left on device`, and requires `df -B1` to
show at least 512 MiB of real growth and no more than 1 MiB available before
removing the partial file. An independent sweep then requires no container to
remain before the helper, mount, loop image,
graph root, and run root are removed.

This native gate does **not** claim a GitHub runner job; PR 74's separate live
JIT workflow supplies that evidence. A full Windows reboot remains outside the
hosted Linux boundary. Plain Podman still fails closed when no attested helper
can enforce the requested cap.
