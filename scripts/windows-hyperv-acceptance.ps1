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
    [ValidateRange(1, 2147483647)]
    [int]$PullRequestNumber = 77,
    [ValidateRange(60, 900)]
    [int]$JobHoldSeconds = 180,
    [ValidateRange(300, 3600)]
    [int]$JobTimeoutSeconds = 1200,

    [switch]$AllowEnableContainers,
    [switch]$AllowSwitchDockerToWindows,
    [switch]$AllowPullImage,
    [switch]$AllowAdoptMachineCredential,
    [switch]$AllowReplaceService,
    [switch]$AllowServiceRestart,
    [switch]$AllowCreatePolicy,
    [switch]$AllowCleanup,
    [switch]$AllowRollbackChanges
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Image = 'mcr.microsoft.com/windows/servercore@sha256:22505496dd4229dba63453ba0c6dc31c06fd3e11810e5b8e429aa6b16dab2457'
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
        [switch]$DiscardOutput,
        [string]$EvidencePath
    )
    $output = & $FilePath @ArgumentList 2>&1
    $exit = $LASTEXITCODE
    if ($EvidencePath) {
        # Evidence must survive a non-zero exit, but command diagnostics can
        # contain credentials. Persist only a small, explicit redaction surface;
        # callers that need machine-readable output continue to receive the
        # original in memory and never opt into evidence capture.
        $redacted = @($output | ForEach-Object {
            $line = $_.ToString()
            $line = [Regex]::Replace($line, '(?i)\bgh[pousr]_[A-Za-z0-9_]+\b', '<redacted-github-token>')
            $line = [Regex]::Replace($line, '(?i)(authorization\s*:\s*(?:bearer\s+)?)[^\s"'']+', '$1<redacted>')
            $line = [Regex]::Replace($line, '(?i)((?:access[_ -]?token|jit(?:config)?|secret)\s*[:=]\s*)("[^"]*"|''[^'']*''|[^\s]+)', '$1<redacted>')
            $line
        })
        $redacted | Set-Content -LiteralPath $EvidencePath -Encoding UTF8
    }
    if (($exit -ne 0) -and (-not $AllowFailure)) {
        $safe = ($ArgumentList | ForEach-Object {
            if ($_ -match '(?i)(token|jit|secret|authorization)') { '<redacted-argument>' } else { $_ }
        }) -join ' '
        $evidence = if ($EvidencePath) { "; redacted output was saved to '$EvidencePath'" } else { '' }
        throw "'$FilePath $safe' failed with exit code $exit$evidence"
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
    $manager = Get-TomlString $text 'manager'
    $startModeValue = Get-TomlString $text 'start_mode'
    $startMode = if ($startModeValue) { $startModeValue.ToLowerInvariant() } else { $null }
    $account = Get-TomlString $text 'account'
    $binary = Get-TomlString $text 'binary'
    $source = Get-TomlString $text 'source_binary'
    $restoreSource = if ($source -and (Test-Path -LiteralPath $source -PathType Leaf)) { $source } else { $binary }
    return [ordered]@{
        exists = $true
        path = $Path
        service_name = $serviceName
        manager = $manager
        start_mode = $startMode
        account = $account
        binary = $binary
        binary_sha256 = if ($binary -and (Test-Path -LiteralPath $binary -PathType Leaf)) { (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
        source_binary = $source
        restore_source = $restoreSource
        restore_source_sha256 = if ($restoreSource -and (Test-Path -LiteralPath $restoreSource -PathType Leaf)) { (Get-FileHash -LiteralPath $restoreSource -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
        scheduled_task_state = $(try { [string](Get-ScheduledTask -TaskName 'runner-manager' -ErrorAction Stop).State } catch { $null })
        config_dir = Get-TomlString $text 'config'
        state_dir = Get-TomlString $text 'state'
        runtime_dir = Get-TomlString $text 'runtime'
        logs_dir = Get-TomlString $text 'logs'
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

function Quote-ServiceArgument([string]$Value) {
    if ($Value -notmatch '[\s"]') { return $Value }
    if ($Value.Contains('"')) { throw 'the product default service path contains a quote and cannot be attested safely' }
    if ($Value.EndsWith('\')) { throw 'the product default service argument unexpectedly ends with a backslash' }
    return '"' + $Value + '"'
}

function Find-AuditedLegacyDefaultBootRecord($State) {
    $audited = $State.runner_service
    $current = Get-ServiceSnapshot 'runner-manager'
    if (-not $audited.exists -or -not $current.exists -or $audited.name -ne 'runner-manager' -or
        $audited.account -notin @('LocalSystem', 'NT AUTHORITY\SYSTEM') -or $current.account -ne $audited.account -or
        $audited.start_mode -ne 'Auto' -or $current.start_mode -ne $audited.start_mode -or
        [bool]$current.delayed_auto_start -ne [bool]$audited.delayed_auto_start -or
        -not [string]::Equals([string]$current.path_name, [string]$audited.path_name, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-SamePath $current.executable $audited.executable) -or
        -not $current.executable_sha256 -or $current.executable_sha256 -ne $audited.executable_sha256) {
        return $null
    }

    $record = Find-DefaultServiceRecord $current
    if (-not $record -or $record.start_mode -ne 'boot' -or $record.manager -ne 'the Windows Service Control Manager' -or
        $record.account -ne 'local_system') { return $null }
    $root = Join-Path $env:LOCALAPPDATA 'IvanMurzak/runner-manager'
    $config = Join-Path $root 'config'
    $state = Join-Path $root 'data/state'
    $runtime = Join-Path $root 'data/runtime'
    $logs = Join-Path $root 'data/logs'
    $binary = Join-Path $state 'bin/runner-manager.exe'
    if (-not (Test-SamePath $record.path (Join-Path $config 'service.toml')) -or
        -not (Test-SamePath $record.binary $binary) -or
        -not (Test-SamePath $record.config_dir $config) -or -not (Test-SamePath $record.state_dir $state) -or
        -not (Test-SamePath $record.runtime_dir $runtime) -or -not (Test-SamePath $record.logs_dir $logs)) {
        return $null
    }
    $arguments = @(
        $binary, 'daemon', 'run', '--service-config-dir', $config, '--service-state-dir', $state,
        '--service-runtime-dir', $runtime, '--service-logs-dir', $logs, '--windows-service-host'
    )
    $expectedCommandLine = ($arguments | ForEach-Object { Quote-ServiceArgument $_ }) -join ' '
    if (-not [string]::Equals($expectedCommandLine, [string]$current.path_name, [StringComparison]::OrdinalIgnoreCase)) {
        return $null
    }
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
        service_replacement_started = $false
        acceptance_id = $null
        profile_name = $null
        profile_selector = $null
        profile_created = $false
        unique_label = $null
        workflow_run_id = $null
        evidence_dir = $null
        pull_request_number = $null
        trigger_label = $null
        trigger_label_created = $false
        adopted_machine_credential = $null
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

function Get-MachineCredentialPaths {
    if (-not $env:ProgramData) { throw 'ProgramData is unavailable; the standard machine credential cannot be resolved' }
    return [ordered]@{
        source = Join-Path $env:ProgramData 'IvanMurzak/runner-manager/secrets/user-access-token.dpapi'
        target = Join-Path $DataDir 'secrets/machine/user-access-token.dpapi'
    }
}

function Assert-ProductMachineCredentialAcl([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "machine credential '$Path' is a reparse point" }
    if ($item.Length -le 0) { throw "machine credential '$Path' is empty" }
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) { throw "machine credential '$Path' inherits access rules" }
    $required = @('S-1-5-18', 'S-1-5-32-544', 'S-1-3-4')
    # A product renewal deliberately carries forward an explicit grant for the
    # operator that originally stored the token. On this privileged harness,
    # that may only be the identity performing the audited adoption.
    $allowed = @($required) + [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $observed = @()
    foreach ($rule in @($acl.Access)) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl -or
            $sid -notin $allowed) {
            throw "machine credential '$Path' has an unexpected access rule"
        }
        $observed += $sid
    }
    foreach ($sid in $required) {
        if ($sid -notin $observed) { throw "machine credential '$Path' is missing required protected trustee '$sid'" }
    }
}

function Protect-AdoptedCredential([string]$Path) {
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) }
    foreach ($account in @([Security.Principal.WindowsIdentity]::GetCurrent().User, [Security.Principal.SecurityIdentifier]'S-1-5-32-544', [Security.Principal.SecurityIdentifier]'S-1-5-18')) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($account, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow)
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-IsolatedCredentialPathIsPhysical {
    foreach ($path in @($DataDir, (Join-Path $DataDir 'secrets'), (Join-Path $DataDir 'secrets/machine'))) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $item = Get-Item -LiteralPath $path -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "isolated credential directory '$path' is not a physical directory"
        }
    }
}

function Adopt-MachineCredential($State) {
    Require-OptIn $AllowAdoptMachineCredential 'AllowAdoptMachineCredential' 'copying the audited same-machine boot credential into the isolated acceptance DataDir'
    $record = Find-AuditedLegacyDefaultBootRecord $State
    if (-not $record) {
        throw 'the live SCM registration does not exactly match the audited product-default LocalSystem boot record; refusing credential adoption'
    }
    # Refresh the rollback source from the record that was just bound to the
    # unchanged audited SCM registration. This also upgrades older audit state
    # that captured the legacy default-path record without its directory facts.
    Set-StateProperty $State service_record $record
    Backup-ServiceRecord $State
    Save-State $State
    $paths = Get-MachineCredentialPaths
    if (Test-SamePath $paths.source $paths.target) { throw 'source and isolated credential paths unexpectedly resolve to the same file' }
    if (-not (Test-Path -LiteralPath $paths.source -PathType Leaf)) { throw "the audited machine credential '$($paths.source)' does not exist" }
    Assert-ProductMachineCredentialAcl $paths.source
    if (Test-Path -LiteralPath $paths.target) { throw "isolated credential target '$($paths.target)' already exists; refusing ambiguous adoption" }
    Assert-IsolatedCredentialPathIsPhysical

    # Prove the standard machine store is decryptable and accepted before any
    # encrypted bytes are copied. Command output is deliberately discarded.
    Invoke-External $RunnerManager @('auth', 'status') -DiscardOutput
    $hash = (Get-FileHash -LiteralPath $paths.source -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-StateProperty $State adopted_machine_credential ([ordered]@{
        source_path = $paths.source
        target_path = $paths.target
        sha256 = $hash
        provenance = 'audited product-standard LocalSystem boot service on this machine'
    })
    Save-State $State
    Protect-StateDirectory (Split-Path $paths.target -Parent)
    try {
        $source = [IO.File]::Open($paths.source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            $target = [IO.File]::Open($paths.target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $source.CopyTo($target); $target.Flush($true) } finally { $target.Dispose() }
        } finally { $source.Dispose() }
        Protect-AdoptedCredential $paths.target
        if ((Get-FileHash -LiteralPath $paths.target -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hash) {
            throw 'the adopted encrypted credential hash does not match its audited source'
        }
    } catch {
        Remove-Item -LiteralPath $paths.target -Force -ErrorAction SilentlyContinue
        throw
    }
}

function Remove-AdoptedMachineCredential($State) {
    if ($State.PSObject.Properties.Name -notcontains 'adopted_machine_credential' -or -not $State.adopted_machine_credential) { return }
    $expected = (Get-MachineCredentialPaths).target
    $target = [string]$State.adopted_machine_credential.target_path
    if (-not (Test-SamePath $target $expected)) { throw 'recorded adopted credential target is outside the exact isolated machine store path' }
    Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $target) { throw "adopted credential '$target' remained after cleanup" }
    Set-StateProperty $State adopted_machine_credential $null
    Save-State $State
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

function Invoke-Runner([string[]]$Arguments, [switch]$AllowFailure, [string]$EvidencePath) {
    $all = @(Get-RunnerArgs) + $Arguments
    Invoke-External $RunnerManager $all -AllowFailure:$AllowFailure -EvidencePath $EvidencePath
}

function Stop-AuditedServiceForReplacement($State, [string]$EvidencePath) {
    $current = Get-ServiceSnapshot 'runner-manager'
    $audited = $State.runner_service
    if (-not $current.exists -or -not $audited.exists -or
        $current.path_name -cne $audited.path_name -or
        $current.executable_sha256 -ne $audited.executable_sha256 -or
        $current.account -ne $audited.account -or $current.start_mode -ne $audited.start_mode -or
        $current.delayed_auto_start -ne $audited.delayed_auto_start) {
        throw 'the service changed after credential adoption; refusing to stop or replace it'
    }

    # Mark the transaction before its first service mutation. Rollback must
    # restore the audited registration even when the product installer fails
    # after DeleteService but before it can write its isolated install record.
    Set-StateProperty $State service_replacement_started $true
    Save-State $State

    if ($current.state -ne 'Stopped') {
        # ServiceController.Stop only submits SERVICE_CONTROL_STOP; unlike a
        # convenience cmdlet it does not own the bounded wait below.
        $controller = Get-Service -Name 'runner-manager' -ErrorAction Stop
        try { $controller.Stop() } finally { $controller.Dispose() }
        $deadline = [DateTime]::UtcNow.AddSeconds(90)
        do {
            Start-Sleep -Milliseconds 500
            $stopped = Get-ServiceSnapshot 'runner-manager'
            if ($stopped.exists -and $stopped.state -eq 'Stopped') { break }
        } until ([DateTime]::UtcNow -ge $deadline)

        if (-not $stopped.exists -or $stopped.state -ne 'Stopped') {
            # A legacy daemon can predate the bounded SCM stop behavior. The
            # force fallback is allowed only for the unchanged audited PID and
            # executable, and only after SCM had 90 seconds to stop it cleanly.
            $stuck = Get-ServiceSnapshot 'runner-manager'
            if (-not $stuck.exists -or $stuck.process_id -eq 0 -or
                $stuck.process_id -ne $current.process_id -or
                $stuck.path_name -cne $audited.path_name -or
                $stuck.executable_sha256 -ne $audited.executable_sha256) {
                throw 'the audited service did not stop and its live identity changed; refusing force termination'
            }
            Require-OptIn $AllowServiceRestart 'AllowServiceRestart' 'force-terminating the unchanged audited legacy service after its bounded SCM stop timed out'
            Stop-Process -Id $stuck.process_id -Force -ErrorAction Stop
            $deadline = [DateTime]::UtcNow.AddSeconds(30)
            do {
                Start-Sleep -Milliseconds 500
                $stopped = Get-ServiceSnapshot 'runner-manager'
                if ($stopped.exists -and $stopped.state -eq 'Stopped') { break }
            } until ([DateTime]::UtcNow -ge $deadline)
            if (-not $stopped.exists -or $stopped.state -ne 'Stopped') {
                throw 'the audited service remained non-stopped after bounded force termination; refusing replacement'
            }
        }
    } else {
        $stopped = $current
    }

    [ordered]@{
        observed_utc = [DateTime]::UtcNow.ToString('o')
        service_name = $stopped.name
        state = $stopped.state
        account = $stopped.account
        start_mode = $stopped.start_mode
        path_name = $stopped.path_name
        executable_sha256 = $stopped.executable_sha256
        provenance = 'exact audited service stopped before reviewed replacement'
    } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $EvidencePath -Encoding UTF8
}

function Invoke-RunnerConfirmed([string[]]$Arguments, [switch]$AllowFailure) {
    $all = @(Get-RunnerArgs) + $Arguments
    $output = 'yes' | & $RunnerManager @all 2>&1
    if ($LASTEXITCODE -ne 0 -and -not $AllowFailure) { throw "runner-manager confirmation command failed with exit code $LASTEXITCODE" }
    return @($output | ForEach-Object { $_.ToString() })
}

function Remove-AcceptanceProfile($State) {
    $evidence = [string]$State.evidence_dir
    if ([string]::IsNullOrWhiteSpace($evidence)) {
        $evidence = Join-Path (Split-Path $StatePath -Parent) 'cleanup-evidence'
    }
    if (-not (Test-Path -LiteralPath $evidence -PathType Container)) {
        Protect-StateDirectory $evidence
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(120)
    $runStamp = [DateTime]::UtcNow.ToString('yyyyMMddHHmmssfff')
    $attempt = 0
    $lastCause = 'profile removal was not attempted'
    $lastEvidence = $null
    do {
        $attempt++
        $removeEvidence = Join-Path $evidence ("profile-remove-$runStamp-{0:d2}.txt" -f $attempt)
        $lastEvidence = $removeEvidence
        Invoke-Runner @('repo', 'profile', 'remove', $Repository, '--profile', [string]$State.profile_name, '--purge') -AllowFailure -EvidencePath $removeEvidence | Out-Null
        $removeExit = $LASTEXITCODE
        if ($removeExit -eq 0) {
            $showEvidence = Join-Path $evidence ("profile-remove-$runStamp-verify-{0:d2}.txt" -f $attempt)
            $lastEvidence = $showEvidence
            Invoke-Runner @('repo', 'profile', 'show', $Repository, '--profile', [string]$State.profile_name) -AllowFailure -EvidencePath $showEvidence | Out-Null
            $showExit = $LASTEXITCODE
            if ($showExit -ne 0) { return }
            $lastCause = "remove exited successfully, but profile show still found '$($State.profile_name)'"
        } else {
            $lastCause = "profile remove exited with code $removeExit"
        }
        if ([DateTime]::UtcNow -lt $deadline) { Start-Sleep -Seconds 2 }
    } until ([DateTime]::UtcNow -ge $deadline)

    throw "temporary profile '$($State.profile_name)' could not be removed within 120 seconds: $lastCause. Review the last redacted command output at '$lastEvidence' and resolve any active-attempt or local-store error before retrying cleanup."
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
    # Docker serializes absent optional collections as JSON null. PowerShell's
    # array subexpression operator counts that scalar null as one item, so
    # discard null itself while retaining every real collection entry.
    $mounts = @($item.Mounts | Where-Object { $null -ne $_ })
    $binds = @($item.HostConfig.Binds | Where-Object { $null -ne $_ })
    $devices = @($item.HostConfig.Devices | Where-Object { $null -ne $_ })
    if ($mounts.Count -ne 0 -or $binds.Count -ne 0) { throw 'live container exposed a host mount' }
    if ($devices.Count -ne 0 -or $item.HostConfig.Privileged) { throw 'live container exposed a device or privileged mode' }

    $environment = @($item.Config.Env | Where-Object { $null -ne $_ })
    $commands = @($item.Config.Cmd | Where-Object { $null -ne $_ })
    $arguments = @($item.Args | Where-Object { $null -ne $_ })
    if (@($environment | Where-Object { [string]$_ -match '(?i)^ACTIONS_RUNNER_INPUT_JITCONFIG(?:=|$)' }).Count -ne 0) {
        throw 'container metadata exposed the JIT configuration environment input'
    }
    # ConvertFrom-Json has already decoded Docker's JSON escaping. Both
    # Config.Cmd and Args repeat the reviewed bootstrap source with ordinary
    # quote characters. Require every complete call exactly once in each
    # surface before removing it; any other identifier shape remains an
    # exposure and fails closed.
    $reviewedReferences = @(
        'Environment.GetEnvironmentVariable("ACTIONS_RUNNER_INPUT_JITCONFIG", EnvironmentVariableTarget.Process)',
        'Environment.SetEnvironmentVariable("ACTIONS_RUNNER_INPUT_JITCONFIG", jitValue, EnvironmentVariableTarget.Process)',
        'Environment.SetEnvironmentVariable("ACTIONS_RUNNER_INPUT_JITCONFIG", priorJit, EnvironmentVariableTarget.Process)'
    )
    foreach ($surface in @(
        [pscustomobject]@{ Name = 'Config.Cmd'; Entries = $commands },
        [pscustomobject]@{ Name = 'Args'; Entries = $arguments }
    )) {
        $unreviewed = @($surface.Entries) -join "`n"
        foreach ($reviewedReference in $reviewedReferences) {
            if ([regex]::Matches($unreviewed, [regex]::Escape($reviewedReference)).Count -ne 1) {
                throw "container metadata exposed the JIT configuration input outside the reviewed bootstrap source in $($surface.Name)"
            }
            $unreviewed = $unreviewed.Replace($reviewedReference, '')
        }
        if ($unreviewed -match '(?i)ACTIONS_RUNNER_INPUT_JITCONFIG') {
            throw "container metadata exposed the JIT configuration input outside the reviewed bootstrap source in $($surface.Name)"
        }
    }
    $surface = $environment + $commands + $arguments + @($mounts | ConvertTo-Json -Compress)
    if (($surface -join "`n") -match '(?i)(docker\.sock|gh[pousr]_[A-Za-z0-9_]{20,}|encoded_jit_config\s*[:=]|eyJ[A-Za-z0-9_+/=-]{40,})') {
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
        mounts = $mounts.Count
        devices = $devices.Count
        privileged = [bool]$item.HostConfig.Privileged
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'container-attestation.json') -Encoding UTF8
}

function Find-AcceptanceRun([string]$TriggerSelector, [DateTime]$After) {
    $deadline = [DateTime]::UtcNow.AddMinutes(2)
    do {
        $json = Invoke-External gh.exe @('run', 'list', '--repo', $Repository, '--event', 'pull_request', '--branch', $WorkflowRef, '--limit', '30', '--json', 'databaseId,displayTitle,workflowName,createdAt,status,conclusion')
        foreach ($run in @(($json -join "`n") | ConvertFrom-Json)) {
            if ($run.workflowName -eq 'Windows Hyper-V native acceptance' -and $run.displayTitle -eq "windows-hyperv-$TriggerSelector" -and [DateTime]$run.createdAt -ge $After.AddMinutes(-1)) { return $run }
        }
        Start-Sleep -Seconds 3
    } until ([DateTime]::UtcNow -ge $deadline)
    throw "could not find pull-request workflow run for immutable profile selector '$TriggerSelector'"
}

function Resolve-AcceptanceProfileSelector($State, [string]$EvidenceDirectory) {
    $raw = Invoke-Runner @('status', '--json')
    $raw | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'profile-status.json') -Encoding UTF8
    $document = ($raw -join "`n") | ConvertFrom-Json
    $matches = @($document.policies | Where-Object {
        [string]::Equals([string]$_.target, $Repository, [StringComparison]::OrdinalIgnoreCase) -and
        [string]::Equals([string]$_.profile_name, [string]$State.profile_name, [StringComparison]::Ordinal)
    })
    if ($matches.Count -ne 1) { throw 'status did not contain exactly one newly-created acceptance profile' }
    $policy = $matches[0]
    if (-not $policy.enabled -or $policy.mode -ne 'autoscale' -or $policy.max_capacity -ne 1) {
        throw 'the newly-created acceptance profile is not the enabled single-capacity autoscale policy that was reviewed'
    }
    $labels = @($policy.routing_labels | ForEach-Object { [string]$_ })
    $known = @([string]$State.unique_label, 'self-hosted', 'windows', 'x64')
    $selector = @($labels | Where-Object { $_ -notin $known })
    if ($labels.Count -ne 5 -or @($labels | Select-Object -Unique).Count -ne 5 -or $selector.Count -ne 1) {
        throw 'status did not expose exactly one immutable selector plus the four reviewed acceptance labels'
    }
    foreach ($required in $known) {
        if ($required -notin $labels) { throw "acceptance profile routing labels omitted '$required'" }
    }
    $value = $selector[0]
    if ($value.Length -gt 50 -or
        $value -notmatch '^rm-d2-win-x64-d2-[0-9]{14}-[0-9a-f]{8}$' -or
        -not $value.EndsWith("-$($State.profile_name)", [StringComparison]::Ordinal)) {
        throw "status returned an invalid or ambiguously-bound acceptance profile selector '$value'"
    }
    Set-StateProperty $State profile_selector $value
    Set-StateProperty $State trigger_label $value
    Save-State $State
    return $value
}

function Remove-AcceptanceTrigger($State) {
    if ($State.PSObject.Properties.Name -notcontains 'trigger_label_created' -or -not $State.trigger_label_created) { return }
    $number = [string]$State.pull_request_number
    $label = [string]$State.trigger_label
    Invoke-External gh.exe @('pr', 'edit', $number, '--repo', $Repository, '--remove-label', $label) -AllowFailure -DiscardOutput
    if ($LASTEXITCODE -ne 0) { throw "could not remove one-time label '$label' from PR $number" }
    Invoke-External gh.exe @('label', 'delete', $label, '--repo', $Repository, '--yes') -AllowFailure -DiscardOutput
    if ($LASTEXITCODE -ne 0) { throw "could not delete one-time repository label '$label'" }
    Set-StateProperty $State trigger_label_created $false
    Save-State $State
}

function Wait-ProviderContainer([string]$EvidenceDirectory, [int]$TimeoutSeconds, [string]$RunId) {
    if ($RunId -notmatch '^[0-9]+$') { throw 'acceptance workflow run id is invalid' }
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $runRaw = Invoke-External gh.exe @('run', 'view', $RunId, '--repo', $Repository, '--json', 'status,conclusion,url')
        $runRaw | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'workflow-status.json') -Encoding UTF8
        $runState = ($runRaw -join "`n") | ConvertFrom-Json
        if ($runState.status -eq 'completed') {
            $conclusion = if ($runState.conclusion) { [string]$runState.conclusion } else { 'unknown' }
            throw "acceptance workflow run $RunId completed with conclusion '$conclusion' before a provider container appeared"
        }
        $ids = Invoke-External docker.exe @('ps', '-q', '--filter', "label=$ProviderLabel") -AllowFailure
        $id = @($ids | Where-Object { $_ -match '^[0-9a-f]{12,64}$' } | Select-Object -First 1)
        if ($id.Count -gt 0) {
            Assert-ContainerEvidence $id[0] $EvidenceDirectory
            return $id[0]
        }
        Start-Sleep -Seconds 3
    } until ([DateTime]::UtcNow -ge $deadline)
    throw 'no production provider-owned Windows container appeared before timeout'
}

function Invoke-RunJob($State) {
    foreach ($flag in @(
        @($AllowAdoptMachineCredential, 'AllowAdoptMachineCredential', 'copying the audited same-machine boot credential into the isolated acceptance DataDir'),
        @($AllowReplaceService, 'AllowReplaceService', 'replacing the runner-manager service binary'),
        @($AllowServiceRestart, 'AllowServiceRestart', 'forcing a daemon crash/restart during the live job'),
        @($AllowCreatePolicy, 'AllowCreatePolicy', 'creating and enabling a temporary repository profile')
    )) { Require-OptIn ([bool]$flag[0]) $flag[1] $flag[2] }
    if ($State.acceptance_id) {
        throw "acceptance '$($State.acceptance_id)' already used this state file; finish recovery-forensics, cleanup, and rollback, then begin with a fresh audit"
    }
    if ($JobHoldSeconds -ne 180) { throw 'the pull-request acceptance workflow has a fixed 180-second observation window' }
    if ($PullRequestNumber -ne 77) { throw 'this reviewed one-time acceptance workflow is pinned to PR 77' }
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
    Adopt-MachineCredential $State
    Invoke-Runner @('auth', 'status') | Out-Null
    $prRaw = Invoke-External gh.exe @('pr', 'view', [string]$PullRequestNumber, '--repo', $Repository, '--json', 'headRefName,headRepositoryOwner,headRefOid')
    $pr = ($prRaw -join "`n") | ConvertFrom-Json
    if ($pr.headRepositoryOwner.login -ne ($Repository -split '/', 2)[0]) { throw "PR $PullRequestNumber is not a same-repository pull request" }
    if ($WorkflowRef -and $WorkflowRef -ne $pr.headRefName) { throw "WorkflowRef '$WorkflowRef' is not PR $PullRequestNumber head '$($pr.headRefName)'" }
    $WorkflowRef = [string]$pr.headRefName
    $acceptanceId = ([DateTime]::UtcNow.ToString('yyyyMMddHHmmss') + '-' + ([Guid]::NewGuid().ToString('N').Substring(0, 8)))
    $profile = "d2-$acceptanceId"
    $label = "rm-d2-$acceptanceId"
    $evidence = Join-Path (Split-Path $StatePath -Parent) "evidence-$acceptanceId"
    Protect-StateDirectory $evidence
    Set-StateProperty $State acceptance_id $acceptanceId
    Set-StateProperty $State profile_name $profile
    Set-StateProperty $State unique_label $label
    Set-StateProperty $State evidence_dir $evidence
    Set-StateProperty $State pull_request_number $PullRequestNumber
    Set-StateProperty $State trigger_label $null
    Save-State $State

    if (-not $PSCmdlet.ShouldProcess('runner-manager service', "install PR binary $RunnerManager")) { return }
    Stop-AuditedServiceForReplacement $State (Join-Path $evidence 'service-replacement-preflight.json')
    Invoke-Runner @('service', 'install', '--start-at', 'boot') -EvidencePath (Join-Path $evidence 'service-install.txt') | Out-Null
    Set-StateProperty $State replaced_service $true
    Save-State $State
    if (-not $PSCmdlet.ShouldProcess("repository profile $profile", 'create and enable isolated execution')) { return }
    Set-StateProperty $State profile_created $true
    Save-State $State
    Invoke-Runner @('repo', 'profile', 'add', $Repository, '--name', $profile, '--host-label', 'd2', '--max-capacity', '1', '--label', 'self-hosted', '--label', 'windows', '--label', 'x64', '--label', $label, '--execution', 'isolated', '--backend', 'windows-hyper-v-container', '--image', $Image, '--cpu', '2000', '--memory', '4096', '--disk', '8192', '--enable') | Set-Content -LiteralPath (Join-Path $evidence 'profile-add.txt') -Encoding UTF8
    $selector = Resolve-AcceptanceProfileSelector $State $evidence
    Invoke-External gh.exe @('label', 'create', $selector, '--repo', $Repository, '--color', '8250df', '--description', "One-time d2 native acceptance trigger for PR $PullRequestNumber") -DiscardOutput
    Set-StateProperty $State trigger_label_created $true
    Save-State $State
    $dispatchAt = [DateTime]::UtcNow
    Invoke-External gh.exe @('pr', 'edit', [string]$PullRequestNumber, '--repo', $Repository, '--add-label', $selector) -DiscardOutput
    $run = Find-AcceptanceRun $selector $dispatchAt
    Set-StateProperty $State workflow_run_id ([string]$run.databaseId)
    Save-State $State
    Remove-AcceptanceTrigger $State
    $container = Wait-ProviderContainer $evidence $JobTimeoutSeconds ([string]$run.databaseId)

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
    if ($State.cleanup_complete) {
        Remove-AdoptedMachineCredential $State
        Write-Output 'Cleanup was already completed.'
        return
    }
    Remove-AcceptanceTrigger $State
    if ($State.profile_created) {
        if (-not $PSCmdlet.ShouldProcess("repository profile $($State.profile_name)", 'disable, drain, and purge')) { return }
        Invoke-RunnerConfirmed @('repo', 'profile', 'set-scale', $Repository, '--profile', [string]$State.profile_name, '--enabled', 'false') -AllowFailure | Out-Null
        $deadline = [DateTime]::UtcNow.AddSeconds(120)
        do {
            $ids = Invoke-External docker.exe @('ps', '-aq', '--filter', "label=$ProviderLabel") -AllowFailure
            if (@($ids | Where-Object { $_ -match '^[0-9a-f]{12,64}$' }).Count -eq 0) { break }
            Start-Sleep -Seconds 2
        } until ([DateTime]::UtcNow -ge $deadline)
        Remove-AcceptanceProfile $State
        Set-StateProperty $State profile_created $false
    }
    Set-StateProperty $State profile_name $null
    Remove-AdoptedMachineCredential $State
    Set-StateProperty $State cleanup_complete $true
    Save-State $State
}

function Restore-ServiceState($State) {
    $replacementStarted = $State.PSObject.Properties.Name -contains 'service_replacement_started' -and $State.service_replacement_started
    if (-not $State.replaced_service -and -not $replacementStarted) { return }
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
    Set-StateProperty $State service_replacement_started $false
    Set-StateProperty $State replaced_service $false
    Save-State $State
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
    if ($State.rollback_complete) {
        Remove-AdoptedMachineCredential $State
        Write-Output 'Rollback was already completed.'
        return
    }
    $triggerRemains = $State.PSObject.Properties.Name -contains 'trigger_label_created' -and $State.trigger_label_created
    if ($State.profile_created -or $triggerRemains) {
        Require-OptIn $AllowCleanup 'AllowCleanup' 'removing the temporary acceptance profile during rollback'
        Invoke-Cleanup $State
    }
    Remove-AdoptedMachineCredential $State
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
