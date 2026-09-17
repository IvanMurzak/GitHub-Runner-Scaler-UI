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

`stop` and `destroy` receive the environment, host, attempt, and generation.
They are idempotent. `destroy` removes the writable disk and VM configuration;
`inspect` must then report absence with exit code 66. `list` remains discovery
only: Runner Manager quarantines unmatched resources and never deletes from
enumeration alone.

## Operator validation

Run `runner-manager host isolation status` as the daemon service account. This
reports host prerequisites only because it has no policy image. A ready helper
still does not make an incompatible profile ready: enabling or starting a
profile checks that policy's exact version and template digest before JIT and
names the failing image in its remedy.

Native support is a platform gate. Protocol unit tests cover ownership,
recovery behavior, fresh disks, resource arguments, and secret transport on
every development host, but release acceptance must separately exercise Intel
and Apple Silicon Macs that the product declares supported.
