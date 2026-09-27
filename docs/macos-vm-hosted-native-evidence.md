# macOS VM hosted-native evidence

Physical acceptance must observe `running`, not merely `booting`, before its
service-crash or manual-reboot recovery test. `running` follows the private JIT
acknowledgement; the harness additionally requires the real guest job to be
`in_progress` on that exact registered runner ID. Offline registration, a
replacement attempt, or an already-completed job cannot supply recovery evidence.

The CI `macOS VM helper` matrix executes the compiled Swift helper on GitHub's
official `macos-latest` ARM64 and `macos-15-intel` runners. It provides real-host
evidence for a limited set of prerequisites:

- the release executable is ad-hoc signed with the repository's
  `com.apple.security.virtualization` entitlement, `codesign` verifies it, and
  the running helper observes that entitlement through Security.framework;
- the helper performs a real `clonefile(2)` operation in its store, while native
  tests verify clone independence and cleanup;
- the running helper calls `VZVirtualMachine.isSupported`, and its readiness
  booleans remain false when that runtime check is false;
- native Unix-domain socket tests exercise framed guest replies, peer closure,
  bounded reads, and timeout cleanup; and
- protocol tests verify that public metadata omits supervisor recovery fields.

The Intel job is a fail-closed compatibility probe. It must report
`architecture: x86_64` while macOS guest virtualization and all dependent
readiness fields remain false. The helper's macOS guest implementation uses
`VZMacPlatformConfiguration`, which Apple documents for macOS guests on Apple
silicon.

This hosted probe cannot close native VM acceptance. GitHub explicitly
documents that its macOS larger runners do not support nested virtualization;
the job records the actual `VZVirtualMachine.isSupported` result on the standard
hosted labels used by this repository rather than inferring availability from
the runner label. Apple documents that property as the runtime availability
check and requires a macOS restore image to obtain the supported hardware model
used to install a bootable macOS VM. CI has neither an operator signing identity
nor an operator-prepared, digest-pinned template containing an operator-provided
guest bootstrap that implements this repository's RMV1 contract. The repository
ships the host helper and defines that wire/process-control contract; it does
not ship a guest LaunchDaemon or claim that registering a manifest proves one
is present. Downloading Apple's current restore image would still not
supply that bootstrap and would introduce a large mutable network input, so CI
does not download, repackage, cache, or redistribute a macOS image.

A real acceptance run therefore still requires an operator-controlled Apple
silicon Mac that reports `VZVirtualMachine.isSupported == true`, a production
signing identity, and an Apple-authorized restore image used to prepare the
pinned template. That run must boot the helper's real configuration and verify
the virtio socket bootstrap, JIT erasure, process/resource limits, stop/destroy,
reboot recovery, disk isolation, and secret forensics.

The reproducible operator procedure is
[`scripts/macos-vm-acceptance.sh`](../scripts/macos-vm-acceptance.sh). Its
workflow uses the production provider and a one-time JIT runner, while the
harness records exact helper metadata, kills and observes restart of a
disposable user-owned login LaunchAgent in `gui/501`, prepares a durable pre-reboot receipt, verifies a
different host boot, checks orphan cleanup and capacity accounting, scans host
and guest surfaces for credential-shaped content, and removes only resources
whose ownership it can prove. The harness never reboots the host or downloads a
restore image.

The harness bounds the upstream route job separately (one hour) from cold
runner-package materialization and VM preparation (30 minutes). It retains the
route job state and requires a successful route producing the VM job before
starting the latter deadline. These waits do not replace any guest attestation
or relax ownership, resource, crash/reboot, or secret-forensics checks.
Within preparation, the helper's runner archive has a separate 15-minute
deadline and the adapter bounds the whole pre-JIT helper prepare call to 20
minutes. Guest boot and private-channel operations retain their shorter
deadlines; start, stop, destroy and other adapter calls remain bounded to five
minutes.

Primary references:

- [Apple: `VZVirtualMachine.isSupported`](https://developer.apple.com/documentation/virtualization/vzvirtualmachine/issupported)
- [Apple: `VZVirtualMachineConfiguration`](https://developer.apple.com/documentation/virtualization/vzvirtualmachineconfiguration)
- [Apple: Virtualize macOS on a Mac](https://developer.apple.com/documentation/virtualization/virtualize-macos-on-a-mac)
- [Apple: `VZMacPlatformConfiguration`](https://developer.apple.com/documentation/virtualization/vzmacplatformconfiguration)
- [GitHub: macOS larger runner limitations](https://docs.github.com/en/actions/reference/runners/larger-runners#limitations-for-macos-larger-runners)
