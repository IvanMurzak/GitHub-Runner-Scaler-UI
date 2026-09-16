# macOS VM helper protocol

Runner Manager can execute an isolated macOS profile through an
operator-installed helper backed by Apple's Virtualization.framework. Runner
Manager does not download, install, patch, or select macOS restore images. The
operator owns the helper and a compatible, pinned VM template.

The executable defaults to `runner-manager-macos-vm`. Set
`RUNNER_MANAGER_MACOS_VM_HELPER` to an absolute executable path when the helper
is installed elsewhere. The daemon service account must be able to execute the
helper and access its template and VM store.

Every invocation begins with `--protocol-version 1`. Successful read commands
write one JSON value to stdout and nothing sensitive to stderr. Responses are
limited to 64 KiB. Exit code 66 means a named image or environment is absent,
77 means permission was denied, and 78 means the request or protocol is not
supported. Other nonzero exits report a degraded helper.

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
  "resource_limits": true
}
```

`architecture` is `arm64` or `x86_64` and must equal the host architecture.
Runner Manager refuses the provider before asking GitHub for JIT configuration
unless every boolean is true.

`image inspect --image vm-version:<version> --json` returns:

```json
{
  "protocol_version": 1,
  "image": "vm-version:macos-15.1-arm64-v3",
  "guest_os": "macos",
  "architecture": "arm64",
  "immutable": true,
  "bootstrap_ready": true
}
```

The response must repeat the requested image exactly. A Linux guest, a mutable
template, an architecture mismatch, or a template without the runner bootstrap
is rejected before JIT. Mutable aliases such as `latest` cannot be expressed by
the `vm-version:` image grammar.

## Environment lifecycle

`prepare` receives an environment name, host ID, attempt ID, random generation,
pinned image, host architecture, CPU/memory/disk limits, and the extracted
runner source directory. It also always receives:

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
  "image": "vm-version:macos-15.1-arm64-v3",
  "guest_os": "macos",
  "architecture": "arm64",
  "writable_disk_id": "<unique nonempty id>",
  "fresh_writable_disk": true,
  "shared_host_paths": [],
  "jit_channel": "private",
  "runner_exit_code": null
}
```

States are `prepared`, `booting`, `running`, `exited`, or `stopped`. The helper
sets `runner_exit_code` only after the runner exits. Runner Manager trusts no
resource for destructive work unless host, attempt, generation, image, guest
OS, architecture, fresh-disk, share, and channel metadata all match the durable
attempt journal.

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

Run `runner-manager host isolation status` as the daemon service account. A
ready helper still does not make an incompatible profile ready: enabling or
starting a profile repeats the pinned-template check before JIT.

Native support is a platform gate. Protocol unit tests cover ownership,
recovery behavior, fresh disks, resource arguments, and secret transport on
every development host, but release acceptance must separately exercise Intel
and Apple Silicon Macs that the product declares supported.
