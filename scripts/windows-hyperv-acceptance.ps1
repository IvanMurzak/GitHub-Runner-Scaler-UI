#Requires -Version 5.1
<#
.SYNOPSIS
Native Windows client/Server acceptance and maintenance harness for the
Hyper-V-isolated container provider.

.DESCRIPTION
This script is phase-oriented and intentionally never reboots Windows. Audit
and recovery-forensics are read-only. Every phase that changes Windows,
Docker, the runner-manager service, or repository policy has a separate opt-in
switch. Run each phase from a new elevated PowerShell after reading its report.

The state file is the rollback contract. Keep it until cleanup and rollback
have both completed.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('audit', 'prepare-before-reboot', 'verify-after-reboot', 'run-job', 'recovery-forensics', 'cleanup', 'rollback')]
    [string]$Phase,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Repository,

    [string]$StatePath = (Join-Path $PSScriptRoot '.windows-hyperv-acceptance/state.json'),
    [string]$RunnerManager = (Join-Path (Split-Path $PSScriptRoot -Parent) 'target/release/runner-manager.exe'),
    [Parameter(Mandatory = $true)]
    [ValidateScript({ [IO.Path]::IsPathRooted($_) })]
    [string]$DataDir,
    [string]$WorkflowRef,
    [ValidateRange(60, 900)]
    [int]$JobHoldSeconds = 180,
    [ValidateRange(300, 3600)]
    [int]$JobTimeoutSeconds = 1200,

    [switch]$AllowEnableContainers,
    [switch]$AllowSwitchDockerToWindows,
    [switch]$AllowPullImage,
    [switch]$AllowReplaceService,
    [switch]$AllowServiceRestart,
    [switch]$AllowCreatePolicy,
    [switch]$AllowCleanup,
    [switch]$AllowRollbackChanges
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Image = 'mcr.microsoft.com/windows/servercore@sha256:22505496dd4229dba63453ba0c6dc31c06fd3e11810e5b8e429aa6b16dab2457'
$Workflow = 'windows-hyperv-native-acceptance.yml'
$ProviderLabel = 'runner-manager.provider=windows-hyper-v-container'
$RepoRoot = Split-Path $PSScriptRoot -Parent

function Assert-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "phase '$Phase' requires an elevated PowerShell (Run as administrator)"
    }
}

function Assert-Command([string]$Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "required command '$Name' was not found"
    }
}

function Require-OptIn([bool]$Value, [string]$Name, [string]$Effect) {
    if (-not $Value) {
        throw "$Effect was refused. Re-run this explicit phase with -$Name after reviewing audit state."
    }
}

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList,
        [switch]$AllowFailure,
        [switch]$DiscardOutput
    )
    $output = & $FilePath @ArgumentList 2>&1
    $exit = $LASTEXITCODE
    if (($exit -ne 0) -and (-not $AllowFailure)) {
        $safe = ($ArgumentList | ForEach-Object {
            if ($_ -match '(?i)(token|jit|secret|authorization)') { '<redacted-argument>' } else { $_ }
        }) -join ' '
        throw "'$FilePath $safe' failed with exit code $exit"
    }
    if (-not $DiscardOutput) { return @($output | ForEach-Object { $_.ToString() }) }
}

function Get-StringHash([string]$Value) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Resolve-ExecutableFromServicePath([string]$PathName) {
    if ([string]::IsNullOrWhiteSpace($PathName)) { return $null }
    if ($PathName[0] -eq '"') {
        $end = $PathName.IndexOf('"', 1)
        if ($end -gt 1) { return $PathName.Substring(1, $end - 1) }
    }
    return ($PathName -split '\s+', 2)[0]
}

function Get-ServiceSnapshot([string]$Name) {
    $cim = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
    if (-not $cim) {
        return [ordered]@{ exists = $false; name = $Name }
    }
    $exe = Resolve-ExecutableFromServicePath $cim.PathName
    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $delayed = try { [bool](Get-ItemPropertyValue -LiteralPath $serviceKey -Name DelayedAutoStart -ErrorAction Stop) } catch { $false }
    return [ordered]@{
        exists = $true
        name = $Name
        state = [string]$cim.State
        start_mode = [string]$cim.StartMode
        delayed_auto_start = $delayed
        account = [string]$cim.StartName
        process_id = [uint32]$cim.ProcessId
        path_name = [string]$cim.PathName
        executable = $exe
        executable_sha256 = if ($exe -and (Test-Path -LiteralPath $exe -PathType Leaf)) { (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
    }
}

function ConvertFrom-TomlPath([string]$Value) {
    return $Value.Replace('\\', '\').Replace('\"', '"')
}

function Get-TomlString([string]$Text, [string]$Name) {
    $pattern = '(?m)^' + [Regex]::Escape($Name) + '\s*=\s*(?:"((?:\\.|[^"])*)"|''([^'']*)'')\s*$'
    if ($Text -match $pattern) {
        if ($Matches[1]) { return ConvertFrom-TomlPath $Matches[1] }
        return $Matches[2]
    }
    return $null
}

function Get-ServiceRecordSnapshot([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [ordered]@{ exists = $false; path = $Path }
    }
    $text = Get-Content -LiteralPath $Path -Raw
    $serviceName = Get-TomlString $text 'service_name'
    $startModeValue = Get-TomlString $text 'start_mode'
    $startMode = if ($startModeValue) { $startModeValue.ToLowerInvariant() } else { $null }
    $binary = Get-TomlString $text 'binary'
    $source = Get-TomlString $text 'source_binary'
    $restoreSource = if ($source -and (Test-Path -LiteralPath $source -PathType Leaf)) { $source } else { $binary }
    return [ordered]@{
        exists = $true
        path = $Path
        service_name = $serviceName
        start_mode = $startMode
        binary = $binary
        binary_sha256 = if ($binary -and (Test-Path -LiteralPath $binary -PathType Leaf)) { (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
        source_binary = $source
        restore_source = $restoreSource
        restore_source_sha256 = if ($restoreSource -and (Test-Path -LiteralPath $restoreSource -PathType Leaf)) { (Get-FileHash -LiteralPath $restoreSource -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
        scheduled_task_state = $(try { [string](Get-ScheduledTask -TaskName 'runner-manager' -ErrorAction Stop).State } catch { $null })
        restore_with_default_paths = $false
    }
}

function Test-SamePath([string]$Left, [string]$Right) {
    if (-not $Left -or -not $Right) { return $false }
    try {
        return [string]::Equals([IO.Path]::GetFullPath($Left).TrimEnd('\'), [IO.Path]::GetFullPath($Right).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)
    } catch { return $false }
}

function Find-DefaultServiceRecord($Service) {
    if (-not $Service.exists -or -not $env:LOCALAPPDATA) { return $null }
    $path = Join-Path $env:LOCALAPPDATA 'IvanMurzak/runner-manager/config/service.toml'
    $record = Get-ServiceRecordSnapshot $path
    if (-not $record.exists -or $record.service_name -ne 'runner-manager' -or -not (Test-SamePath $record.binary $Service.executable)) { return $null }
    if (-not $record.binary_sha256 -or $record.binary_sha256 -ne $Service.executable_sha256) { return $null }
    $record.restore_with_default_paths = $true
    return $record
}

function Backup-ServiceRecord($State) {
    if (-not $State.service_record.exists) { return }
    $backup = Join-Path (Split-Path $StatePath -Parent) 'prior-service'
    Protect-StateDirectory $backup
    Copy-Item -LiteralPath $State.service_record.path -Destination (Join-Path $backup 'service-prior.toml') -Force
    if ($State.service_record.restore_source -and (Test-Path -LiteralPath $State.service_record.restore_source -PathType Leaf)) {
        Copy-Item -LiteralPath $State.service_record.restore_source -Destination (Join-Path $backup (Split-Path $State.service_record.restore_source -Leaf)) -Force
        $supervisor = Join-Path (Split-Path $State.service_record.restore_source -Parent) 'runner-manager-supervisor.exe'
        if (Test-Path -LiteralPath $supervisor -PathType Leaf) {
            Copy-Item -LiteralPath $supervisor -Destination (Join-Path $backup 'runner-manager-supervisor.exe') -Force
        }
    }
}

function Get-OptionalFeatureState([string]$Name) {
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $Name -ErrorAction Stop
        return [string]$feature.State
    } catch {
        return 'Unavailable'
    }
}

function Get-WindowsTruth {
    $os = Get-CimInstance Win32_OperatingSystem
    $computer = Get-ComputerInfo -Property WindowsProductName, WindowsEditionId, OsBuildNumber
    $edition = [string]$computer.WindowsEditionId
    $build = [uint32]$computer.OsBuildNumber
    $productType = [uint32]$os.ProductType
    $family = if ($productType -eq 1) { 'client' } elseif ($productType -in 2, 3) { 'server' } else { 'unknown' }
    $supported = $false
    $reason = $null
    if ($family -eq 'client') {
        $supported = ($build -ge 22000) -and ($edition -in @('Professional', 'Enterprise'))
        if (-not $supported) { $reason = 'client acceptance requires Windows 11 Pro or Enterprise (build 22000 or newer)' }
    } elseif ($family -eq 'server') {
        $supported = ($build -ge 14393) -and ($edition -in @('ServerStandard', 'ServerDatacenter'))
        if (-not $supported) { $reason = 'Server acceptance requires non-evaluation Standard or Datacenter, Server 2016 or newer' }
    } else {
        $reason = "unsupported Win32_OperatingSystem ProductType $productType"
    }
    return [ordered]@{
        product_name = [string]$computer.WindowsProductName
        edition_id = $edition
        build = $build
        product_type = $productType
        family = $family
        supported = $supported
        refusal = $reason
        last_boot_utc = ([DateTime]$os.LastBootUpTime).ToUniversalTime().ToString('o')
    }
}

function Get-DockerSnapshot {
    $docker = Get-Command docker.exe -ErrorAction SilentlyContinue
    $serverOs = $null
    $serverVersion = $null
    $context = $null
    if ($docker) {
        $contextLines = Invoke-External docker.exe @('context', 'show') -AllowFailure
        if ($LASTEXITCODE -eq 0) { $context = ($contextLines -join "`n").Trim() }
        $osLines = Invoke-External docker.exe @('version', '--format', '{{.Server.Os}}') -AllowFailure
        if ($LASTEXITCODE -eq 0) { $serverOs = ($osLines -join "`n").Trim() }
        $versionLines = Invoke-External docker.exe @('version', '--format', '{{.Server.Version}}') -AllowFailure
        if ($LASTEXITCODE -eq 0) { $serverVersion = ($versionLines -join "`n").Trim() }
    }
    $services = @('com.docker.service', 'docker') | ForEach-Object { Get-ServiceSnapshot $_ }
    $desktopCli = @(
        "$env:ProgramFiles\Docker\Docker\DockerCli.exe",
        "$env:ProgramFiles\Docker\Docker\resources\DockerCli.exe"
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    return [ordered]@{
        cli = if ($docker) { $docker.Source } else { $null }
        context = $context
        server_os = $serverOs
        server_version = $serverVersion
        desktop_cli = $desktopCli
        services = @($services)
    }
}

function Get-ImagePresent {
    if (-not (Get-Command docker.exe -ErrorAction SilentlyContinue)) { return $false }
    Invoke-External docker.exe @('image', 'inspect', $Image) -AllowFailure -DiscardOutput
    return ($LASTEXITCODE -eq 0)
}

function New-AuditState {
    Assert-Command gh.exe
    $windows = Get-WindowsTruth
    $docker = Get-DockerSnapshot
    $hyperV = if ($windows.family -eq 'server') {
        try { [string](Get-WindowsFeature -Name Hyper-V -ErrorAction Stop).InstallState } catch { Get-OptionalFeatureState 'Microsoft-Hyper-V-All' }
    } else { Get-OptionalFeatureState 'Microsoft-Hyper-V-All' }
    $containers = if ($windows.family -eq 'server') {
        try { [string](Get-WindowsFeature -Name Containers -ErrorAction Stop).InstallState } catch { Get-OptionalFeatureState 'Containers' }
    } else { Get-OptionalFeatureState 'Containers' }
    $gitCommit = ((Invoke-External git.exe @('-C', $RepoRoot, 'rev-parse', 'HEAD')) -join '').Trim()
    $service = Get-ServiceSnapshot 'runner-manager'
    $serviceRecord = Join-Path $DataDir 'config/service.toml'
    $serviceRecordSnapshot = Get-ServiceRecordSnapshot $serviceRecord
    if ($service.exists -and -not $serviceRecordSnapshot.exists) {
        $defaultRecord = Find-DefaultServiceRecord $service
        if ($defaultRecord) { $serviceRecordSnapshot = $defaultRecord }
    }
    return [ordered]@{
        schema_version = 1
        created_utc = [DateTime]::UtcNow.ToString('o')
        machine = $env:COMPUTERNAME
        repository = $Repository
        repo_root = $RepoRoot
        git_commit = $gitCommit
        image = $Image
        data_dir = $DataDir
        windows = $windows
        features = [ordered]@{ hyper_v = $hyperV; containers = $containers }
        docker = $docker
        image_was_present = Get-ImagePresent
        runner_service = $service
        service_record = $serviceRecordSnapshot
        prepared_containers = $false
        switched_docker = $false
        pulled_image = $false
        replaced_service = $false
        acceptance_id = $null
        profile_name = $null
        profile_created = $false
        unique_label = $null
        workflow_run_id = $null
        evidence_dir = $null
        cleanup_complete = $false
        rollback_complete = $false
    }
}

function Protect-StateDirectory([string]$Directory) {
    if (-not (Test-Path -LiteralPath $Directory)) { New-Item -ItemType Directory -Path $Directory -Force | Out-Null }
    $acl = Get-Acl -LiteralPath $Directory
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) }
    $rights = [Security.AccessControl.FileSystemRights]::FullControl
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagation = [Security.AccessControl.PropagationFlags]::None
    foreach ($account in @([Security.Principal.WindowsIdentity]::GetCurrent().Name, 'BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM')) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($account, $rights, $inherit, $propagation, 'Allow')
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Directory -AclObject $acl
}

function Save-State($State) {
    $parent = Split-Path $StatePath -Parent
    Protect-StateDirectory $parent
    $temporary = "$StatePath.tmp"
    $State | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $StatePath -Force
}

function Load-State {
    if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
        throw "state file '$StatePath' does not exist; run the audit phase first"
    }
    $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    if ($state.schema_version -ne 1 -or $state.machine -ne $env:COMPUTERNAME -or $state.repository -ne $Repository) {
        throw "state file does not belong to schema 1 on this machine and repository"
    }
    return $state
}

function Set-StateProperty($State, [string]$Name, $Value) {
    $State | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
}

function Assert-SupportedHost($State) {
    if (-not $State.windows.supported) { throw [string]$State.windows.refusal }
    $hyperV = [string]$State.features.hyper_v
    if ($hyperV -notin @('Enabled', 'Installed')) { throw "Hyper-V must already be enabled; observed '$hyperV'. This harness never enables it." }
}

function Invoke-Audit {
    if (Test-Path -LiteralPath $StatePath) {
        $old = Load-State
        if (-not $old.rollback_complete -and ($old.prepared_containers -or $old.switched_docker -or $old.replaced_service -or $old.profile_name)) {
            throw "an unfinished acceptance state already exists at '$StatePath'; use recovery-forensics, cleanup, or rollback"
        }
    }
    $state = New-AuditState
    $backup = Join-Path (Split-Path $StatePath -Parent) 'prior-service'
    if ($state.runner_service.exists -and $state.runner_service.executable -and (Test-Path -LiteralPath $state.runner_service.executable)) {
        Protect-StateDirectory $backup
        Copy-Item -LiteralPath $state.runner_service.executable -Destination (Join-Path $backup 'runner-manager-prior.exe') -Force
    }
    Backup-ServiceRecord $state
    Save-State $state
    $state | ConvertTo-Json -Depth 12
}

function Enable-ContainersOnly($State) {
    Assert-SupportedHost $State
    if ([string]$State.features.containers -in @('Enabled', 'Installed')) {
        Write-Output 'Containers is already enabled; nothing changed.'
        return
    }
    Require-OptIn $AllowEnableContainers 'AllowEnableContainers' 'enabling the Windows Containers feature'
    if (-not $PSCmdlet.ShouldProcess('Windows feature Containers', 'enable without restarting Windows')) { return }
    if ($State.windows.family -eq 'server') {
        $result = Install-WindowsFeature -Name Containers -Restart:$false
        if (-not $result.Success) { throw 'Install-WindowsFeature did not report success' }
    } else {
        $result = Enable-WindowsOptionalFeature -Online -FeatureName Containers -All -NoRestart
        if ($result.RestartNeeded) { Write-Output 'Containers enabled; Windows reports a restart is needed.' }
    }
    Set-StateProperty $State prepared_containers $true
    Save-State $State
    Write-Output 'Preparation complete. This script did not reboot Windows. Reboot manually, then run verify-after-reboot.'
}

function Switch-DockerAndPull($State) {
    Assert-SupportedHost $State
    $containersNow = if ($State.windows.family -eq 'server') {
        try { [string](Get-WindowsFeature -Name Containers -ErrorAction Stop).InstallState } catch { Get-OptionalFeatureState 'Containers' }
    } else { Get-OptionalFeatureState 'Containers' }
    if ($containersNow -notin @('Enabled', 'Installed')) { throw "Containers is not enabled after reboot (observed '$containersNow')" }
    if ($State.prepared_containers) {
        $boot = [DateTime](Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        if ($boot.ToUniversalTime() -le [DateTime]$State.created_utc) { throw 'Windows has not rebooted since prepare-before-reboot; reboot manually first' }
    }
    $dockerNow = Get-DockerSnapshot
    if ($dockerNow.server_os -ne 'windows') {
        Require-OptIn $AllowSwitchDockerToWindows 'AllowSwitchDockerToWindows' 'switching Docker Desktop to the Windows engine'
        if ($State.windows.family -ne 'client' -or -not $dockerNow.desktop_cli) {
            throw 'Docker is not in Windows mode and no supported Docker Desktop client switch is available; switch the Server runtime manually'
        }
        if ($PSCmdlet.ShouldProcess('Docker Desktop engine', 'switch to Windows containers')) {
            Invoke-External $dockerNow.desktop_cli @('-SwitchWindowsEngine') -DiscardOutput
            Set-StateProperty $State switched_docker $true
            Save-State $State
            $deadline = [DateTime]::UtcNow.AddMinutes(3)
            do {
                Start-Sleep -Seconds 3
                $dockerNow = Get-DockerSnapshot
            } until ($dockerNow.server_os -eq 'windows' -or [DateTime]::UtcNow -ge $deadline)
        }
    }
    if ($dockerNow.server_os -ne 'windows') { throw "Docker server OS is '$($dockerNow.server_os)', expected 'windows'" }
    if (-not (Get-ImagePresent)) {
        Require-OptIn $AllowPullImage 'AllowPullImage' "pulling $Image"
        if ($PSCmdlet.ShouldProcess($Image, 'pull exact Windows image digest')) {
            Invoke-External docker.exe @('pull', $Image) -DiscardOutput
            Set-StateProperty $State pulled_image $true
            Save-State $State
        }
    }
    $inspect = Invoke-External docker.exe @('image', 'inspect', '--format', '{{.Os}}|{{.Architecture}}|{{index .RepoDigests 0}}', $Image)
    $metadata = ($inspect -join "`n").Trim()
    if ($metadata -notmatch '^windows\|amd64\|.*@sha256:22505496dd4229dba63453ba0c6dc31c06fd3e11810e5b8e429aa6b16dab2457$') {
        throw "pulled image metadata did not attest windows|amd64 and the exact digest: $metadata"
    }
    Invoke-Runner @('host', 'isolation', 'status', '--json') | Out-Null
    Save-State $State
}

function Get-RunnerArgs {
    if ($DataDir) { return @('--data-dir', $DataDir) }
    return @()
}

function Invoke-Runner([string[]]$Arguments, [switch]$AllowFailure) {
    $all = @(Get-RunnerArgs) + $Arguments
    Invoke-External $RunnerManager $all -AllowFailure:$AllowFailure
}

function Invoke-RunnerConfirmed([string[]]$Arguments, [switch]$AllowFailure) {
    $all = @(Get-RunnerArgs) + $Arguments
    $output = 'yes' | & $RunnerManager @all 2>&1
    if ($LASTEXITCODE -ne 0 -and -not $AllowFailure) { throw "runner-manager confirmation command failed with exit code $LASTEXITCODE" }
    return @($output | ForEach-Object { $_.ToString() })
}

function Assert-ContainerEvidence([string]$ContainerId, [string]$EvidenceDirectory) {
    $raw = Invoke-External docker.exe @('inspect', $ContainerId)
    $path = Join-Path $EvidenceDirectory 'container-inspect.json'
    $raw | Set-Content -LiteralPath $path -Encoding UTF8
    $doc = ($raw -join "`n") | ConvertFrom-Json
    $item = @($doc)[0]
    if ($item.HostConfig.Isolation -ne 'hyperv') { throw 'live container did not use Hyper-V isolation' }
    if ($item.Config.Image -ne $Image) { throw 'live container did not use the pinned image digest' }
    if ([int64]$item.HostConfig.NanoCpus -ne 2000000000) { throw 'live container did not receive the configured 2 CPU limit' }
    if ([int64]$item.HostConfig.Memory -ne 4294967296) { throw 'live container did not receive the configured 4096 MiB memory limit' }
    if ([string]$item.HostConfig.StorageOpt.size -ne '8192m') { throw 'live container did not receive the configured 8192 MiB disk limit' }
    if ($item.HostConfig.NetworkMode -ne 'nat') { throw 'live container did not use the expected NAT network' }
    if (@($item.Mounts).Count -ne 0 -or @($item.HostConfig.Binds).Count -ne 0) { throw 'live container exposed a host mount' }
    if (@($item.HostConfig.Devices).Count -ne 0 -or $item.HostConfig.Privileged) { throw 'live container exposed a device or privileged mode' }
    $surface = @($item.Config.Env) + @($item.Config.Cmd) + @($item.Args) + @($item.Mounts | ConvertTo-Json -Compress)
    if (($surface -join "`n") -match '(?i)(docker\.sock|ACTIONS_RUNNER_INPUT_JITCONFIG|gh[pousr]_[A-Za-z0-9_]{20,})') {
        throw 'container metadata exposed a socket or credential-shaped value'
    }
    [ordered]@{
        container_id = $ContainerId
        isolation = $item.HostConfig.Isolation
        image = $item.Config.Image
        nano_cpus = $item.HostConfig.NanoCpus
        memory = $item.HostConfig.Memory
        storage_opt = $item.HostConfig.StorageOpt
        network_mode = $item.HostConfig.NetworkMode
        mounts = @($item.Mounts).Count
        devices = @($item.HostConfig.Devices).Count
        privileged = [bool]$item.HostConfig.Privileged
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'container-attestation.json') -Encoding UTF8
}

function Find-AcceptanceRun([string]$AcceptanceId, [DateTime]$After) {
    $deadline = [DateTime]::UtcNow.AddMinutes(2)
    do {
        $json = Invoke-External gh.exe @('run', 'list', '--repo', $Repository, '--workflow', $Workflow, '--limit', '20', '--json', 'databaseId,displayTitle,createdAt,status,conclusion')
        foreach ($run in @(($json -join "`n") | ConvertFrom-Json)) {
            if ($run.displayTitle -eq "windows-hyperv-$AcceptanceId" -and [DateTime]$run.createdAt -ge $After.AddMinutes(-1)) { return $run }
        }
        Start-Sleep -Seconds 3
    } until ([DateTime]::UtcNow -ge $deadline)
    throw "could not find dispatched workflow run for acceptance id '$AcceptanceId'"
}

function Wait-ProviderContainer([string]$EvidenceDirectory, [int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $ids = Invoke-External docker.exe @('ps', '-q', '--filter', "label=$ProviderLabel") -AllowFailure
        $id = @($ids | Where-Object { $_ -match '^[0-9a-f]{12,64}$' } | Select-Object -First 1)
        if ($id.Count -gt 0) {
            Assert-ContainerEvidence $id[0] $EvidenceDirectory
            return $id[0]
        }
        Start-Sleep -Seconds 2
    } until ([DateTime]::UtcNow -ge $deadline)
    throw 'no production provider-owned Windows container appeared before timeout'
}

function Invoke-RunJob($State) {
    foreach ($flag in @(
        @($AllowReplaceService, 'AllowReplaceService', 'replacing the runner-manager service binary'),
        @($AllowServiceRestart, 'AllowServiceRestart', 'forcing a daemon crash/restart during the live job'),
        @($AllowCreatePolicy, 'AllowCreatePolicy', 'creating and enabling a temporary repository profile')
    )) { Require-OptIn ([bool]$flag[0]) $flag[1] $flag[2] }
    if ($State.acceptance_id) {
        throw "acceptance '$($State.acceptance_id)' already used this state file; finish recovery-forensics, cleanup, and rollback, then begin with a fresh audit"
    }
    if ($State.runner_service.exists -and -not $State.service_record.exists) {
        $current = Get-ServiceSnapshot 'runner-manager'
        if ($current.exists -and $current.path_name -eq $State.runner_service.path_name -and $current.executable_sha256 -eq $State.runner_service.executable_sha256) {
            $defaultRecord = Find-DefaultServiceRecord $current
            if ($defaultRecord) {
                Set-StateProperty $State service_record $defaultRecord
                Backup-ServiceRecord $State
                Save-State $State
            }
        }
        if (-not $State.service_record.exists) {
            throw 'an existing runner-manager SCM service has no verified restorable record under DataDir or the current user default paths; refusing because rollback cannot safely reconstruct it'
        }
    }
    if ($State.service_record.exists -and (-not $State.service_record.source_binary -or -not $State.service_record.restore_source_sha256 -or $State.service_record.start_mode -notin @('boot', 'login'))) {
        throw 'the prior service record lacks a restorable source binary or start mode; refusing to replace it'
    }
    if (-not (Test-Path -LiteralPath $RunnerManager -PathType Leaf)) { throw "PR binary '$RunnerManager' does not exist; build it with cargo build --release" }
    if ((Get-DockerSnapshot).server_os -ne 'windows' -or -not (Get-ImagePresent)) { throw 'verify-after-reboot has not established a Windows engine and pinned image' }
    $preexisting = Invoke-External docker.exe @('ps', '-aq', '--filter', "label=$ProviderLabel") -AllowFailure
    if (@($preexisting | Where-Object { $_ -match '^[0-9a-f]{12,64}$' }).Count -ne 0) { throw 'a provider-owned container already exists; collect recovery-forensics and resolve it before starting acceptance' }
    Invoke-External gh.exe @('auth', 'status', '--hostname', 'github.com') -DiscardOutput
    Invoke-Runner @('auth', 'status') | Out-Null
    if (-not $WorkflowRef) {
        $WorkflowRef = ((Invoke-External gh.exe @('repo', 'view', $Repository, '--json', 'defaultBranchRef', '--jq', '.defaultBranchRef.name')) -join '').Trim()
    }
    Invoke-External gh.exe @('workflow', 'view', $Workflow, '--repo', $Repository, '--ref', $WorkflowRef) -DiscardOutput
    $acceptanceId = ([DateTime]::UtcNow.ToString('yyyyMMddHHmmss') + '-' + ([Guid]::NewGuid().ToString('N').Substring(0, 8)))
    $profile = "d2-$acceptanceId"
    $label = "rm-d2-$acceptanceId"
    $evidence = Join-Path (Split-Path $StatePath -Parent) "evidence-$acceptanceId"
    Protect-StateDirectory $evidence
    Set-StateProperty $State acceptance_id $acceptanceId
    Set-StateProperty $State profile_name $profile
    Set-StateProperty $State unique_label $label
    Set-StateProperty $State evidence_dir $evidence
    Save-State $State

    if (-not $PSCmdlet.ShouldProcess('runner-manager service', "install PR binary $RunnerManager")) { return }
    Invoke-Runner @('service', 'install', '--start-at', 'boot') | Set-Content -LiteralPath (Join-Path $evidence 'service-install.txt') -Encoding UTF8
    Set-StateProperty $State replaced_service $true
    Save-State $State
    if (-not $PSCmdlet.ShouldProcess("repository profile $profile", 'create and enable isolated execution')) { return }
    Set-StateProperty $State profile_created $true
    Save-State $State
    Invoke-Runner @('repo', 'profile', 'add', $Repository, '--name', $profile, '--host-label', 'd2-acceptance', '--max-capacity', '1', '--label', 'self-hosted', '--label', 'windows', '--label', 'x64', '--label', $label, '--execution', 'isolated', '--backend', 'windows-hyper-v-container', '--image', $Image, '--cpu', '2000', '--memory', '4096', '--disk', '8192', '--enable') | Set-Content -LiteralPath (Join-Path $evidence 'profile-add.txt') -Encoding UTF8
    $dispatchAt = [DateTime]::UtcNow
    Invoke-External gh.exe @('workflow', 'run', $Workflow, '--repo', $Repository, '--ref', $WorkflowRef, '-f', "runner_label=$label", '-f', "acceptance_id=$acceptanceId", '-f', "hold_seconds=$JobHoldSeconds") -DiscardOutput
    $run = Find-AcceptanceRun $acceptanceId $dispatchAt
    Set-StateProperty $State workflow_run_id ([string]$run.databaseId)
    Save-State $State
    $container = Wait-ProviderContainer $evidence $JobTimeoutSeconds

    if ($PSCmdlet.ShouldProcess('runner-manager service process', 'force termination to exercise SCM restart and orphan adoption')) {
        $before = Get-ServiceSnapshot 'runner-manager'
        if (-not $before.exists -or $before.process_id -eq 0) { throw 'runner-manager service has no process to restart' }
        Stop-Process -Id $before.process_id -Force
        $deadline = [DateTime]::UtcNow.AddSeconds(60)
        do {
            Start-Sleep -Seconds 2
            $after = Get-ServiceSnapshot 'runner-manager'
            if ($after.exists -and $after.state -ne 'Running') { Start-Service -Name runner-manager -ErrorAction SilentlyContinue }
        } until (($after.state -eq 'Running' -and $after.process_id -ne 0 -and $after.process_id -ne $before.process_id) -or [DateTime]::UtcNow -ge $deadline)
        if ($after.state -ne 'Running' -or $after.process_id -eq $before.process_id) { throw 'service did not restart with a new process after forced termination' }
        $stillOwned = Invoke-External docker.exe @('inspect', '--format', '{{.Id}}', $container) -AllowFailure
        if ($LASTEXITCODE -ne 0) { throw 'provider container disappeared before the restarted daemon could reconcile it' }
        [ordered]@{ old_pid = $before.process_id; new_pid = $after.process_id; container_id = ($stillOwned -join '').Trim() } |
            ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence 'restart-attestation.json') -Encoding UTF8
    }

    Invoke-External gh.exe @('run', 'watch', [string]$run.databaseId, '--repo', $Repository, '--exit-status') -DiscardOutput
    $workflowLog = Invoke-External gh.exe @('run', 'view', [string]$run.databaseId, '--repo', $Repository, '--log')
    $workflowLog | Set-Content -LiteralPath (Join-Path $evidence 'workflow.log') -Encoding UTF8
    if (($workflowLog -join "`n") -notmatch 'RM_ACCEPTANCE job_object=in_job active_process_limit=256 active_process_flag=true kill_on_close=true') {
        throw 'workflow log did not contain the exact Job Object attestation'
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(120)
    do {
        $remaining = Invoke-External docker.exe @('ps', '-aq', '--filter', "label=$ProviderLabel") -AllowFailure
        if (@($remaining | Where-Object { $_ -match '^[0-9a-f]{12,64}$' }).Count -eq 0) { break }
        Start-Sleep -Seconds 2
    } until ([DateTime]::UtcNow -ge $deadline)
    if (@($remaining | Where-Object { $_ -match '^[0-9a-f]{12,64}$' }).Count -ne 0) { throw 'provider-owned orphan remained after the workflow completed' }
    $statusRaw = Invoke-Runner @('status', '--json')
    $statusRaw | Set-Content -LiteralPath (Join-Path $evidence 'runner-manager-status.json') -Encoding UTF8
    $status = ($statusRaw -join "`n") | ConvertFrom-Json
    if ([uint32]$status.host.active_ephemeral_attempts -ne 0 -or [uint32]$status.host.cleanup_blocked_ephemeral_attempts -ne 0) {
        throw 'runner-manager journal still reports an active or cleanup-blocked ephemeral attempt'
    }
    Assert-NoSecrets $evidence
    Write-Output "Acceptance run $($run.databaseId) completed. Evidence: $evidence"
}

function Assert-NoSecrets([string]$EvidenceDirectory) {
    $token = (& gh.exe auth token 2>$null | Out-String).Trim()
    try {
        foreach ($file in Get-ChildItem -LiteralPath $EvidenceDirectory -File -Recurse) {
            $text = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction SilentlyContinue
            if (-not $text) { continue }
            if (($token -and $text.Contains($token)) -or $text -match '(?im)(ACTIONS_RUNNER_INPUT_JITCONFIG\s*=|gh[pousr]_[A-Za-z0-9_]{20,})') {
                throw "credential-shaped content was found in evidence file '$($file.Name)'"
            }
        }
    } finally { $token = $null }
}

function Invoke-Forensics($State) {
    $directory = Join-Path (Split-Path $StatePath -Parent) ('forensics-' + [DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))
    Protect-StateDirectory $directory
    Get-WindowsTruth | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $directory 'windows.json') -Encoding UTF8
    Get-DockerSnapshot | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $directory 'docker.json') -Encoding UTF8
    if (Get-Command docker.exe -ErrorAction SilentlyContinue) {
        Invoke-External docker.exe @('ps', '-a', '--no-trunc', '--filter', "label=$ProviderLabel", '--format', '{{json .}}') -AllowFailure |
            Set-Content -LiteralPath (Join-Path $directory 'provider-containers.jsonl') -Encoding UTF8
    } else {
        'docker.exe is unavailable' | Set-Content -LiteralPath (Join-Path $directory 'provider-containers.txt') -Encoding UTF8
    }
    Invoke-Runner @('service', 'status') -AllowFailure | Set-Content -LiteralPath (Join-Path $directory 'service-status.txt') -Encoding UTF8
    Invoke-Runner @('status', '--json') -AllowFailure | Set-Content -LiteralPath (Join-Path $directory 'status.json') -Encoding UTF8
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = [DateTime]::UtcNow.AddHours(-4) } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'runner-manager' } | Select-Object TimeCreated, Id, LevelDisplayName, Message |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $directory 'service-events.json') -Encoding UTF8
    Assert-NoSecrets $directory
    Write-Output "Read-only forensics written to $directory"
}

function Invoke-Cleanup($State) {
    Require-OptIn $AllowCleanup 'AllowCleanup' 'disabling and removing the temporary acceptance profile'
    if ($State.cleanup_complete) { Write-Output 'Cleanup was already completed.'; return }
    if ($State.profile_created) {
        if (-not $PSCmdlet.ShouldProcess("repository profile $($State.profile_name)", 'disable, drain, and purge')) { return }
        Invoke-RunnerConfirmed @('repo', 'profile', 'set-scale', $Repository, '--profile', [string]$State.profile_name, '--enabled', 'false') -AllowFailure | Out-Null
        $deadline = [DateTime]::UtcNow.AddSeconds(120)
        do {
            $ids = Invoke-External docker.exe @('ps', '-aq', '--filter', "label=$ProviderLabel") -AllowFailure
            if (@($ids | Where-Object { $_ -match '^[0-9a-f]{12,64}$' }).Count -eq 0) { break }
            Start-Sleep -Seconds 2
        } until ([DateTime]::UtcNow -ge $deadline)
        Invoke-Runner @('repo', 'profile', 'remove', $Repository, '--profile', [string]$State.profile_name, '--purge') -AllowFailure | Out-Null
        Invoke-Runner @('repo', 'profile', 'show', $Repository, '--profile', [string]$State.profile_name) -AllowFailure | Out-Null
        if ($LASTEXITCODE -eq 0) { throw "temporary profile '$($State.profile_name)' still exists after cleanup" }
        Set-StateProperty $State profile_created $false
    }
    Set-StateProperty $State profile_name $null
    Set-StateProperty $State cleanup_complete $true
    Save-State $State
}

function Restore-ServiceState($State) {
    if (-not $State.replaced_service) { return }
    Invoke-Runner @('service', 'uninstall') -AllowFailure | Out-Null
    if ($State.service_record.exists) {
        $priorDirectory = Join-Path (Split-Path $StatePath -Parent) 'prior-service'
        $prior = Join-Path $priorDirectory (Split-Path $State.service_record.restore_source -Leaf)
        if (-not (Test-Path -LiteralPath $prior -PathType Leaf)) { throw "prior service source backup '$prior' is missing" }
        $actual = (Get-FileHash -LiteralPath $prior -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $State.service_record.restore_source_sha256) { throw 'prior service source backup hash does not match the audit record' }
        if ($State.service_record.start_mode -eq 'login' -and -not (Test-Path -LiteralPath (Join-Path $priorDirectory 'runner-manager-supervisor.exe') -PathType Leaf)) {
            throw 'prior login service supervisor backup is missing'
        }
        $mode = [string]$State.service_record.start_mode
        $restoreWithDefaultPaths = $State.service_record.PSObject.Properties.Name -contains 'restore_with_default_paths' -and $State.service_record.restore_with_default_paths
        $args = if ($restoreWithDefaultPaths) {
            @('service', 'install', '--start-at', $mode)
        } else {
            @('--data-dir', $DataDir, 'service', 'install', '--start-at', $mode)
        }
        Invoke-External $prior $args -DiscardOutput
        if (-not (Test-Path -LiteralPath $State.service_record.binary -PathType Leaf)) { throw 'restored service binary is missing from its prior path' }
        $restoredBinaryHash = (Get-FileHash -LiteralPath $State.service_record.binary -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($restoredBinaryHash -ne $State.service_record.binary_sha256) { throw 'restored service binary does not match the audited bytes' }
        Copy-Item -LiteralPath (Join-Path $priorDirectory 'service-prior.toml') -Destination $State.service_record.path -Force
        if ($mode -eq 'boot' -and $State.runner_service.state -ne 'Running') { Stop-Service -Name runner-manager -Force -ErrorAction SilentlyContinue }
        if ($mode -eq 'login' -and $State.service_record.scheduled_task_state -ne 'Running') { Stop-ScheduledTask -TaskName runner-manager -ErrorAction SilentlyContinue }
    }
}

function Restore-DockerAndFeatures($State) {
    $current = Get-DockerSnapshot
    if ($State.switched_docker -and $State.docker.server_os -eq 'linux') {
        if (-not $current.desktop_cli) { throw 'cannot restore Docker Desktop Linux mode because DockerCli.exe is unavailable' }
        Invoke-External $current.desktop_cli @('-SwitchLinuxEngine') -DiscardOutput
    }
    if ($State.pulled_image -and -not $State.image_was_present) {
        Invoke-External docker.exe @('image', 'rm', $Image) -AllowFailure -DiscardOutput
    }
    foreach ($prior in @($State.docker.services)) {
        if (-not $prior.exists) { continue }
        $service = Get-Service -Name $prior.name -ErrorAction SilentlyContinue
        if (-not $service) { continue }
        $startup = switch ([string]$prior.start_mode) { 'Auto' { 'Automatic' }; 'Manual' { 'Manual' }; 'Disabled' { 'Disabled' }; default { $null } }
        if ($startup) { Set-Service -Name $prior.name -StartupType $startup }
        if ($prior.start_mode -eq 'Auto') {
            $startToken = if ($prior.delayed_auto_start) { 'delayed-auto' } else { 'auto' }
            Invoke-External sc.exe @('config', [string]$prior.name, 'start=', $startToken) -DiscardOutput
        }
        if ($prior.state -eq 'Running' -and $service.Status -ne 'Running') { Start-Service -Name $prior.name }
        if ($prior.state -ne 'Running' -and $service.Status -eq 'Running') { Stop-Service -Name $prior.name -Force }
    }
    if ($State.prepared_containers -and [string]$State.features.containers -notin @('Enabled', 'Installed')) {
        if ($State.windows.family -eq 'server') {
            Uninstall-WindowsFeature -Name Containers -Restart:$false | Out-Null
        } else {
            Disable-WindowsOptionalFeature -Online -FeatureName Containers -NoRestart | Out-Null
        }
        Write-Output 'Containers was returned to disabled. Windows may require a manual reboot; this script did not reboot.'
    }
}

function Invoke-Rollback($State) {
    Require-OptIn $AllowRollbackChanges 'AllowRollbackChanges' 'restoring the prior service, Docker engine mode/state, image inventory, and Containers feature state'
    if ($State.rollback_complete) { Write-Output 'Rollback was already completed.'; return }
    if ($State.profile_created) {
        Require-OptIn $AllowCleanup 'AllowCleanup' 'removing the temporary acceptance profile during rollback'
        Invoke-Cleanup $State
    }
    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'restore all state recorded by the audit phase')) {
        Restore-ServiceState $State
        Restore-DockerAndFeatures $State
        Set-StateProperty $State rollback_complete $true
        Save-State $State
    }
}

Assert-Elevated
Assert-Command git.exe

switch ($Phase) {
    'audit' { Invoke-Audit }
    'prepare-before-reboot' { Enable-ContainersOnly (Load-State) }
    'verify-after-reboot' { Switch-DockerAndPull (Load-State) }
    'run-job' { Invoke-RunJob (Load-State) }
    'recovery-forensics' { Invoke-Forensics (Load-State) }
    'cleanup' { Invoke-Cleanup (Load-State) }
    'rollback' { Invoke-Rollback (Load-State) }
}
