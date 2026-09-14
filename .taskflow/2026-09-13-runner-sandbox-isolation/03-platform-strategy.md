# Platform strategy

## Why one backend is not credible

GitHub requires a Linux self-hosted runner for Docker container actions and
service containers. Its experimental container hooks are Linux-only, and
`ACTIONS_RUNNER_REQUIRE_JOB_CONTAINER` only rejects workflows that omit their own
job container; it does not turn a Windows/macOS runner into an isolated native
job. See GitHub's [self-hosted runner reference](https://docs.github.com/en/actions/reference/runners/self-hosted-runners)
and [container customization documentation](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/customize-containers).

Docker Desktop on Windows/macOS primarily supplies Linux containers through a
Linux VM. That is useful for a new Linux host label, but cannot honestly preserve
native Windows/macOS workflow semantics. The product needs one contract with
different backends.

## Backend matrix

| Host exposed to GitHub | Recommended backend | Guarantee and constraints | Initial status |
|---|---|---|---|
| Linux | Rootless OCI (prefer runtime-neutral support, prove Podman first) | Fresh Linux root filesystem/process namespace; shared host kernel; explicit limits and no privileged/socket mounts. Rootless Podman automatically uses a user namespace but needs subordinate UID/GID configuration. | Practical V1 |
| WSL2 Linux | Same rootless OCI provider running inside the managed distribution | Same job semantics as Linux, with WSL2 already providing an outer VM/kernel boundary from Windows. Runtime and storage must live in the Linux filesystem, not DrvFS. | Practical V1 after dedicated acceptance |
| Windows | Hyper-V-isolated Windows container; full Hyper-V VM fallback | Windows container gets its own kernel under Hyper-V isolation, but requires supported Windows editions/features/runtime and compatible Windows base images. Desktop/UI/device-heavy workflows may require a full VM. | Mandatory spike |
| macOS | Disposable macOS VM via Virtualization.framework | Native macOS guest with VM boundary. Requires image install/update lifecycle, entitlement, same-architecture planning and substantial disk/boot management. There is no native macOS container backend. | Mandatory spike; largest track |

Microsoft documents that Windows containers have process and Hyper-V isolation,
with Hyper-V providing a separate kernel and hardware-level boundary
([isolation modes](https://learn.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/hyperv-container)).
The required editions/features and nested-virtualization constraints are not
universal
([Windows container requirements](https://learn.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/system-requirements)),
and Windows image/host compatibility has its own matrix
([version compatibility](https://learn.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/version-compatibility)).

Apple's Virtualization framework can create and manage macOS and Linux VMs
([framework overview](https://developer.apple.com/documentation/virtualization)).
A macOS guest needs a compatible restore image, boot loader, platform
configuration and installation lifecycle
([installation guide](https://developer.apple.com/documentation/virtualization/installing-macos-on-a-virtual-machine)).

Rootless OCI materially reduces host privilege, but it is not the same security
boundary as a VM. Podman's documented rootless mode creates a user namespace and
requires `/etc/subuid`/`/etc/subgid`
([Podman rootless documentation](https://docs.podman.io/en/stable/markdown/podman.1.html)).

## Workflow compatibility

An isolated image must define a baseline contract: shell, Git, certificates and
the libraries needed by the GitHub runner. Everything else may be installed by
the job into the disposable guest. For reproducibility, repositories should pin
an image digest or a versioned VM template rather than request “latest”.

Docker actions and `services:` are a separate compatibility problem. Mounting
the host Docker socket breaks the sandbox boundary. Docker-in-Docker commonly
requires privileged operation; GitHub's own ARC documentation identifies that
requirement, while Docker warns that `--privileged` is not securely sandboxed.
See [ARC container modes](https://docs.github.com/en/actions/how-tos/manage-runners/use-actions-runner-controller/deploy-runner-scale-sets)
and [Docker privileged mode](https://docs.docker.com/reference/cli/docker/container/run/).
V1 should therefore:

- refuse Docker-dependent workflows unless a separately accepted nested-runtime
  profile is configured;
- never mount the host OCI socket into an untrusted job;
- treat privileged nested containers as incompatible with a hostile-code threat
  model; and
- test ordinary script actions, JavaScript actions, container actions and
  service containers as separate capability classes.

## Delivery strategy

### Wave 0: contract and native no-op migration

Land the domain/storage/provider boundary while all existing policies remain
native. Prove that upgrades and current recovery are unchanged.

### Wave 1: Linux and WSL preview

Ship rootless OCI behind an explicit preview flag/profile. Validate Python and
system-package conflicts, parallel jobs, daemon restart, host reboot, image pull
failure, disk exhaustion and orphan cleanup on native Linux and managed WSL.

### Wave 2: Linux and WSL supported

Remove preview only after security/recovery gates and representative Actions
compatibility pass. This is the first useful product milestone.

### Wave 3: Windows feasibility then preview

Spike Windows client and Server separately. Choose Hyper-V-isolated containers
only if the required runner/actions/tooling work in supported base images;
otherwise choose disposable Hyper-V VMs. Do not weaken the policy name to fit a
process-only mechanism.

### Wave 4: macOS feasibility then preview

Build or integrate a VM helper, golden-image pipeline, clone/reset strategy and
guest control channel. Validate Apple Silicon and Intel separately if both remain
supported product targets.

## Scope assessment

All four environments have a plausible native backend, subject to mandatory
spikes and acceptance gates; “supported everywhere” is a multi-release program.
Linux/WSL is moderate. Windows is high complexity
because prerequisites and base-image compatibility vary. macOS is very high
complexity because Runner Manager would acquire a VM image lifecycle in addition
to process lifecycle. A simultaneous four-platform launch would put recovery and
cleanup reliability at unnecessary risk.
