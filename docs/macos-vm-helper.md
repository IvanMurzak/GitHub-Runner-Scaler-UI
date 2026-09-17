# macOS VM helper protocol

Runner Manager can execute an isolated macOS profile through an
operator-installed helper backed by Apple's Virtualization.framework. Runner
Manager does not download, install, patch, or select macOS restore images. The
operator owns the helper and a compatible, pinned VM template.

Apple documents CPU and memory as `VZVirtualMachineConfiguration` properties,
and virtio sockets as the host/guest port-based communication device. Process
count is not a Virtualization.framework VM configuration property, so this
protocol requires the helper's guest bootstrap to enforce it inside the guest:
[VM configuration](https://developer.apple.com/documentation/virtualization/vzvirtualmachineconfiguration),
[virtio socket configuration](https://developer.apple.com/documentation/virtualization/vzvirtiosocketdeviceconfiguration).

The executable defaults to `runner-manager-macos-vm`. Set
`RUNNER_MANAGER_MACOS_VM_HELPER` to an absolute executable path when the helper
is installed elsewhere. The daemon service account must be able to execute the
helper and access its template and VM store.

This repository ships the native helper as a Swift package in
`native/macos-vm-helper`. Install it on the VM host with a signing identity:

```sh
sudo native/macos-vm-helper/install.sh --signing-identity 'Developer ID Application: Example (TEAMID)'
```

The installer builds the helper, signs it with
`com.apple.security.virtualization`, verifies the resulting signature, and
installs it at `/usr/local/libexec/runner-manager-macos-vm` with a command link
in `/usr/local/bin`. `--signing-identity -` is useful for a local development
build, but is not production signing evidence. `probe` verifies the running
executable's signature and entitlement with Security.framework rather than
assuming that the entitlement file used at build time survived installation.

The helper targets macOS 13 or later. Apple documents
[`VZMacPlatformConfiguration`](https://developer.apple.com/documentation/virtualization/vzmacplatformconfiguration)
as the platform configuration for macOS guests on Apple silicon. The package
is compiled and unit-tested on both GitHub-hosted ARM64 and Intel Macs, but the
Intel binary reports the macOS VM capability unavailable. An Intel compile is
not evidence that an Intel host can boot this macOS guest configuration.
The exact native operations exercised on hosted runners, and the remaining
operator-hardware acceptance boundary, are recorded in
[macOS VM hosted-native evidence](macos-vm-hosted-native-evidence.md).

Every invocation begins with `--protocol-version 1`. Successful read commands
write one JSON value to stdout and nothing sensitive to stderr. Responses are
limited to 64 KiB. Exit code 66 means a named image or environment is absent,
77 means permission was denied, and 78 means the request or protocol is not
supported. Other nonzero exits report a degraded helper.
Runner Manager gives every helper operation one five-minute deadline covering
JIT stdin, bounded stdout, and process completion. On expiry it terminates the
helper and reports a typed timeout diagnostic; no operation retries a JIT
handoff.

## Readiness and image contract

`probe --json` returns:

```json
{
  "protocol_version": 1,
  "architecture": "arm64",
  "virtualization_framework": true,
  "macos_guest_entitlement": true,
  "private_jit_channel": true,
  "fresh_writable_disks": true,
  "resource_limits": true,
  "process_limits": true
}
```

`architecture` is `arm64` or `x86_64` and must equal the host architecture.
Runner Manager refuses the provider before asking GitHub for JIT configuration
unless every boolean is true.

`image inspect --image vm-version:<version>@sha256:<template-digest> --json`
returns:

```json
{
  "protocol_version": 1,
  "image": "vm-version:macos-15.1-arm64-v3@sha256:<64 lowercase hex characters>",
  "template_digest": "<the same 64 hex characters>",
  "guest_os": "macos",
  "architecture": "arm64",
  "immutable": true,
  "bootstrap_ready": true
}
```

The response must repeat the requested image exactly and independently report
the same template digest. A version label without a digest, a digest mismatch,
a Linux guest, a mutable template, an architecture mismatch, or a template
without the runner bootstrap is rejected before JIT. Mutable aliases such as
`latest` cannot be expressed by the `vm-version:` image grammar. The digest is
the immutable identity of the installed bootable template, not merely the
restore-image download; changing any template content requires a new digest.

### Registering a template

Start with a macOS VM installed using Apple's
[installation procedure](https://developer.apple.com/documentation/virtualization/installing-macos-on-a-virtual-machine).
Install the guest bootstrap described below as a boot LaunchDaemon, shut the VM
down, and register its disk, auxiliary storage, and serialized hardware model:

```sh
sudo runner-manager-macos-vm --protocol-version 1 template register \
  --version macos-15.1-arm64-v3 \
  --architecture arm64 \
  --disk-mib 32768 \
  --bootstrap-port 22022 \
  --disk /path/to/VM.bundle/Disk.img \
  --auxiliary-storage /path/to/VM.bundle/AuxiliaryStorage \
  --hardware-model /path/to/VM.bundle/HardwareModel
```

The command copies the artifacts into the helper's mode-0700 template store,
makes them read-only, and returns a manifest containing the complete pinned
image reference. Its SHA-256 identity covers the version, guest OS,
architecture, exact logical disk size, the SHA-256 of all three artifacts, the
bootstrap protocol and port, and the process-limit contract. `image inspect`
rehashes all artifacts before it reports the template ready. The writable disk
limit must equal the template disk's logical size; the helper never claims that
Virtualization.framework can shrink an installed macOS disk.

Apple requires each virtual Mac to retain compatible hardware-model and
auxiliary-storage data, and requires unique machine identity for concurrently
running VMs. The helper therefore creates a fresh machine identifier and a
fresh APFS clone of both the disk and auxiliary storage for every attempt. If
the store volume cannot perform a real `clonefile(2)` copy-on-write clone, probe
or prepare fails closed.

## Environment lifecycle

`prepare` receives an environment name, host ID, attempt ID, random generation,
pinned image and template digest, host architecture, CPU/memory/disk limits, a
locked `--process-limit 512`, and the extracted runner source directory. It also
always receives:

```text
--fresh-writable-disk --no-host-shares --private-jit-channel
```

The helper clones a new writable disk, copies the runner into the guest, and
prepares the private guest-control channel. It must not mount the source path or
any host home, application-data directory, credential store, runtime socket,
device, or prior attempt disk into the VM.

The native helper archives the already-extracted runner into the private
environment bundle during `prepare`. On boot it transmits that archive over the
virtio socket before transmitting JIT. It never configures a directory-sharing
device, so neither the runner source path nor any other host path is visible to
the guest. The guest must finish copying and verifying the archive before it
accepts JIT.

`inspect --environment <id> --json` and `list --host <host-id> --json` return one
record or an array of records with this shape:

```json
{
  "protocol_version": 1,
  "environment_id": "rm-<attempt>-<generation>",
  "state": "prepared",
  "host_id": "<uuid>",
  "attempt_id": "<uuid>",
  "generation": "<random generation>",
  "image": "vm-version:macos-15.1-arm64-v3@sha256:<digest>",
  "template_digest": "<digest>",
  "guest_os": "macos",
  "architecture": "arm64",
  "writable_disk_id": "<unique nonempty id>",
  "fresh_writable_disk": true,
  "shared_host_paths": [],
  "jit_channel": "private",
  "applied_cpu_millis": 2000,
  "applied_memory_mib": 4096,
  "applied_disk_mib": 32768,
  "applied_process_limit": 512,
  "runner_exit_code": null
}
```

States are `prepared`, `booting`, `running`, `exited`, or `stopped`. The helper
sets `runner_exit_code` only after the runner exits. Runner Manager trusts no
resource for destructive work unless host, attempt, generation, image, guest
OS, architecture, fresh-disk, share, and channel metadata all match the durable
attempt journal. Before JIT, all four applied limits must exactly equal the
policy request and locked process baseline. A helper that cannot enforce or
report the guest process limit must return readiness with
`process_limits: false`; Runner Manager then fails closed.

`start --environment <id> --jit-stdin` reads the complete encoded JIT document
from stdin. The helper sends it through the private guest channel, places it
only in `Runner.Listener`'s initial environment, erases the handoff, and returns
success only after the guest accepted it. The JIT document must never enter VM
configuration, command arguments, files, disks, logs, or resource metadata.

The helper process that answers `start` launches a detached, per-environment
supervisor. That supervisor owns the `VZVirtualMachine` for its lifetime and
writes its PID plus a random generation token to private durable metadata. A
later invocation regards that PID as live only if `KERN_PROCARGS2` still shows
the exact supervisor mode and token; this prevents PID reuse from turning
`stop` into a signal to an unrelated process. The public `inspect` and `list`
documents never include those recovery fields.

### Required guest bootstrap protocol

The repository does **not** ship this guest program. The operator who prepares
the pinned image must install a boot LaunchDaemon implementing the contract
below and validate that image with the native acceptance harness. The shipped
Swift executable is the host helper: it configures Virtualization.framework,
owns VM resources and speaks RMV1 to the operator-provided guest component.
Template registration records the operator's assertion that the bootstrap is
present; only a real boot and acknowledgement can establish acceptance
evidence.

Virtualization.framework has CPU-count and memory-size configuration and a
fixed-size disk attachment, but it has no process-tree limit. A template may
set `bootstrap_ready: true` only when it contains a boot LaunchDaemon that
implements all of this protocol:

1. Listen only on the manifest's virtio-socket port. Do not listen on TCP, a
   shared directory, a serial port, or a host-mounted filesystem.
2. Read the four bytes `RMV1`, then an unsigned big-endian 32-bit JSON-header
   length, the JSON header, exactly `runner_archive_bytes` archive bytes, and
   exactly `jit_bytes` JIT bytes. Reject extra, short, oversized, duplicate, or
   wrong-generation requests. The header names only lengths, identities,
   SHA-256, and controls; it never contains JIT.
3. Verify the runner archive SHA-256, extract it into a new attempt directory
   without permitting absolute paths, `..`, or links that escape that
   directory, then erase the received archive. Never write JIT to a file,
   disk-backed log, command argument, VM metadata, or crash report.
4. Use a dedicated, non-admin runner UID that has no other processes and cannot
   call `setuid`. In the runner child, drop supplementary groups and switch to
   that UID, call `setrlimit(RLIMIT_NPROC)` with both soft and hard values equal
   to 512, and confirm both values with `getrlimit`. The child must acknowledge
   those values to the bootstrap over an inherited pipe immediately before
   `exec`, so the bootstrap is attesting the process that will become
   `Runner.Listener`, not its own limit.
5. Put the received value only in
   `ACTIONS_RUNNER_INPUT_JITCONFIG` for the initial environment of
   `bin/Runner.Listener run`. Erase every bootstrap copy before returning an
   `accepted` reply. The reply is a big-endian 32-bit length followed by JSON
   containing protocol version, `status: "accepted"`, environment, generation,
   runner PID, `applied_process_limit: 512`,
   `process_limit_mechanism: "rlimit_nproc_dedicated_uid"`, and
   `runner_uid_exclusive: true`.
6. Keep the socket open. After the runner exits, send one more framed JSON reply
   with `status: "exited"` and `runner_exit_code`, then close it. Do not include
   JIT, environment values, runner output, or file paths in either reply.

The host helper rejects the start unless the acknowledgement matches every
field exactly. A template without this bootstrap cannot be registered as
native acceptance evidence, and a future bootstrap using a different process
control needs a new template schema and helper implementation. Compilation,
mock replies, or a manifest assertion do not satisfy this gate.

`stop` and `destroy` receive the environment, host, attempt, and generation.
They are idempotent. `destroy` removes the writable disk and VM configuration;
`inspect` must then report absence with exit code 66. `list` remains discovery
only: Runner Manager quarantines unmatched resources and never deletes from
enumeration alone.

CPU requests must be an exact multiple of 1000 millis because
`VZVirtualMachineConfiguration.cpuCount` is an integer. Memory MiB is converted
exactly to bytes and checked against the framework's allowed range. The helper
calls `validate()` on the final configuration and reports the requested values
only after validation. Disk enforcement is the exact logical size of the
verified template and its fresh writable clone. Unsupported fractional CPU,
memory, disk, bootstrap, signing, or host-architecture combinations fail
before JIT is requested or consumed.

## Operator validation

Run `runner-manager host isolation status` as the daemon service account. This
reports host prerequisites only because it has no policy image. A ready helper
still does not make an incompatible profile ready: enabling or starting a
profile checks that policy's exact version and template digest before JIT and
names the failing image in its remedy.

Native support is a platform gate. Protocol unit tests cover ownership,
recovery behavior, fresh disks, resource arguments, and secret transport on
every development host, but release acceptance must exercise real Apple-silicon
hardware, the only architecture on which this provider currently declares
native macOS guests available. Intel CI remains a required fail-closed probe.

### Reproducible native acceptance

GitHub-hosted ARM64 macOS runners cannot perform this gate because nested
virtualization is unavailable. Use a physical Apple-silicon Mac or a dedicated
bare-metal Apple-silicon host. Install the signed helper and register the
operator-prepared template first, build the PR's `runner-manager` release
binary, authenticate its dedicated absolute `--data-dir`, export `GH_TOKEN` for
the fixture repository (with pull-request and issue-label write plus Actions
write permissions), then run the guarded phases:

```sh
common=(
  --repository OWNER/REPO
  --image 'vm-version:macos-15.1-arm64-v3@sha256:<digest>'
  --data-dir /var/db/runner-manager-d3-acceptance/data
  --runner-manager "$PWD/target/release/runner-manager"
  --pull-request 79
  --workflow-ref worktree-01a0ac40-2810-7021-8119-413dbbb9884a
)

sudo -E scripts/macos-vm-acceptance.sh audit "${common[@]}"
sudo -E scripts/macos-vm-acceptance.sh run-job "${common[@]}" \
  --allow-service-install --allow-profile --allow-service-restart
sudo -E scripts/macos-vm-acceptance.sh prepare-before-reboot "${common[@]}" \
  --allow-profile
# Reboot macOS manually. The harness never invokes a reboot command.
sudo -E scripts/macos-vm-acceptance.sh verify-after-reboot "${common[@]}"
sudo -E scripts/macos-vm-acceptance.sh recovery-forensics "${common[@]}"
sudo -E scripts/macos-vm-acceptance.sh cleanup "${common[@]}" --allow-cleanup
sudo -E scripts/macos-vm-acceptance.sh rollback "${common[@]}" --allow-rollback
```

`audit` refuses a non-ARM host, a virtual host where
`VZVirtualMachine.isSupported` is false, a missing entitlement, non-APFS clone
support, an incompatible digest-pinned template, an existing helper resource,
or missing GitHub/product authentication. `run-job` requires exact 2 CPU, 4096
MiB, template-sized disk and 512-process attestations, no host shares, a fresh
writable-disk identity, guest secret scans, and launchd restart/adoption while
the job is live. `prepare-before-reboot` creates a second fresh-disk identity
and durable receipt. `verify-after-reboot` requires the boot epoch to advance,
the boot LaunchDaemon to return, provider resources and capacity to reach zero,
and host secret scans to pass. Cleanup and rollback require separate flags and
act only on identities stored in the receipt. The harness creates, applies, and
deletes a unique repository label for each job. That `pull_request:labeled`
trigger is deliberate: GitHub does not register a new `workflow_dispatch`
workflow from an unmerged PR, so a dispatch-only gate could not validate the PR
before merge. The workflow is pinned to same-repository PR 79 and rejects every
other event.

The Swift CI jobs establish source compatibility on GitHub-hosted ARM64 and
Intel machines. Native acceptance still requires an operator-signed helper, a
real bootstrap-ready pinned image, APFS clone verification, a successful real
VM boot and JIT job, limit observation inside the guest, cleanup/recovery after
host-process failure, and the applicable Apple hardware/OS combinations. The
current helper deliberately reports unavailable for an Intel macOS guest; an
Intel package build is not a substitute for that missing platform capability.
