# Native Windows Hyper-V acceptance

This manual harness validates the preview Windows isolation provider on a real
Windows 11 Pro/Enterprise or Windows Server Standard/Datacenter host. It uses
the production `runner-manager` service, GitHub polling/JIT path, and
Hyper-V-isolated Docker provider. It never reboots the machine.

Run every phase from an elevated Windows PowerShell. Start with a release build
of this PR and a `runner-manager` credential already stored for boot service
mode. `gh auth status` must also succeed. The manual workflow must exist on the
ref passed to `-WorkflowRef`; GitHub normally requires a `workflow_dispatch`
workflow to be present on the default branch.

```powershell
cargo build --release
$common = @{
  Repository = 'OWNER/REPO'
  StatePath = 'C:\d2-acceptance\state.json'
  DataDir = 'C:\d2-acceptance\runner-manager'
}

.\scripts\windows-hyperv-acceptance.ps1 @common -Phase audit
.\scripts\windows-hyperv-acceptance.ps1 @common -Phase prepare-before-reboot -AllowEnableContainers
```

Read the preparation output and reboot Windows yourself if Windows says it is
required. The script has no reboot code. After that boot, verify prerequisites,
switch Docker Desktop only when needed, and pull the exact pinned image:

```powershell
.\scripts\windows-hyperv-acceptance.ps1 @common -Phase verify-after-reboot `
  -AllowSwitchDockerToWindows -AllowPullImage
```

The job phase creates a uniquely named, capacity-one profile, installs the PR
binary as the production service, dispatches the manual workflow with its
unique label, captures live Docker configuration, and forces one daemon process
termination. The Service Control Manager restarts the daemon; its production
reconciler must adopt the journalled container and remove it after the job.

```powershell
.\scripts\windows-hyperv-acceptance.ps1 @common -Phase run-job `
  -AllowReplaceService -AllowServiceRestart -AllowCreatePolicy
```

The workflow queries the Job Object inherited by its PowerShell process and
requires an exact 256-process active limit plus kill-on-close. The host captures
the pinned image, Hyper-V isolation, CPU/memory/disk limits, NAT network, empty
mount/device lists, unprivileged mode, restart identity, final journal status,
and workflow log. Evidence is scanned in place against the current `gh` token
without printing or persisting that token.

Forensics is always read-only and may be repeated after any failure:

```powershell
.\scripts\windows-hyperv-acceptance.ps1 @common -Phase recovery-forensics
```

Cleanup removes the temporary profile. Rollback verifies the saved service
binary hash, restores the prior service registration and running state, returns
Docker Desktop to its prior engine mode, removes the image only if this run
pulled it, and returns Containers to its prior feature state. Disabling the
feature can require another manual reboot; rollback never initiates one.

```powershell
.\scripts\windows-hyperv-acceptance.ps1 @common -Phase cleanup -AllowCleanup
.\scripts\windows-hyperv-acceptance.ps1 @common -Phase rollback -AllowRollbackChanges
```

Keep the protected state directory and evidence until the result is reviewed.
If a job phase fails, collect `recovery-forensics` before cleanup or rollback.
