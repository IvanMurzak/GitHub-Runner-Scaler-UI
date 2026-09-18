[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('prepare', 'verify-after-reboot', 'cleanup')]
    [string]$Phase,

    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$Distribution = 'Ubuntu'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this acceptance harness from an elevated PowerShell session.'
    }
}

function Invoke-Wsl {
    param([Parameter(Mandatory)][string[]]$Arguments)

    & wsl.exe @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "wsl.exe failed with exit code $LASTEXITCODE."
    }
}

function Invoke-WslText {
    param([Parameter(Mandatory)][string[]]$Arguments)

    $value = (& wsl.exe @Arguments | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $value) {
        throw "wsl.exe returned no usable value (exit code $LASTEXITCODE)."
    }
    return $value
}

function Get-WindowsBootEvidence {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $event = Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        ProviderName = 'Microsoft-Windows-Kernel-General'
        Id = 12
    } -MaxEvents 1
    if ($null -eq $os.LastBootUpTime -or $null -eq $event) {
        throw 'Windows boot evidence is unavailable.'
    }
    [ordered]@{
        lastBootUpTimeUtc = $os.LastBootUpTime.ToUniversalTime().ToString('o')
        kernelBootEventRecordId = [long]$event.RecordId
        kernelBootEventTimeUtc = $event.TimeCreated.ToUniversalTime().ToString('o')
    }
}

function Assert-BootChanged {
    param(
        [Parameter(Mandatory)]$Before,
        [Parameter(Mandatory)]$After
    )

    $asUtc = {
        param($Value)
        if ($Value -is [DateTime]) {
            return [DateTimeOffset]::new(([DateTime]$Value).ToUniversalTime())
        }
        return [DateTimeOffset]::Parse(
            [string]$Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        ).ToUniversalTime()
    }
    $beforeBoot = & $asUtc $Before.lastBootUpTimeUtc
    $afterBoot = & $asUtc $After.lastBootUpTimeUtc
    $beforeEvent = & $asUtc $Before.kernelBootEventTimeUtc
    $afterEvent = & $asUtc $After.kernelBootEventTimeUtc
    if ($afterBoot -le $beforeBoot -or $afterEvent -le $beforeEvent -or
        [long]$After.kernelBootEventRecordId -eq [long]$Before.kernelBootEventRecordId) {
        throw 'Windows boot identity and time did not both advance. Run verify-after-reboot only after a real Windows reboot.'
    }
}

function Write-State {
    param([Parameter(Mandatory)]$State)

    $temporary = "$script:StatePath.tmp"
    $State | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $temporary -Encoding utf8NoBOM
    Move-Item -LiteralPath $temporary -Destination $script:StatePath -Force
}

function Read-State {
    if (-not (Test-Path -LiteralPath $script:StatePath -PathType Leaf)) {
        return $null
    }
    $state = Get-Content -LiteralPath $script:StatePath -Raw | ConvertFrom-Json
    if ($state.schema -ne 1 -or $state.distribution -ne $Distribution -or
        $state.nonce -notmatch '^rm-reboot-nonce-[0-9a-f]{32}$') {
        throw "Refusing unrecognized acceptance state at $script:StatePath."
    }
    return $state
}

function Get-WslContext {
    $distributions = (& wsl.exe --list --quiet | Where-Object { $_ } | ForEach-Object { $_.Trim("`0 ") })
    if ($LASTEXITCODE -ne 0 -or $Distribution -notin $distributions) {
        throw "WSL distribution '$Distribution' is not installed."
    }
    $repoWindows = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $repoLinux = Invoke-WslText @('--distribution', $Distribution, '--exec', 'wslpath', '-a', $repoWindows)
    $managedUser = Invoke-WslText @('--distribution', $Distribution, '--exec', 'sh', '-lc', 'id -un')
    if ($managedUser -eq 'root') {
        throw "The default $Distribution user must be the non-root managed user."
    }
    $managedHome = Invoke-WslText @(
        '--distribution', $Distribution, '--exec', 'sh', '-lc',
        'getent passwd "$(id -un)" | cut -d: -f6'
    )
    if (-not $managedHome.StartsWith('/')) {
        throw "Could not resolve the Linux home for $managedUser."
    }
    Invoke-Wsl @(
        '--distribution', $Distribution, '--user', 'root', '--exec', 'bash', '-lc',
        'set -eu; test "$(id -u)" = 0; grep -qi microsoft /proc/sys/kernel/osrelease; for c in bash blockdev findmnt fuse-overlayfs getent mkfs.ext4 mount mountpoint podman python3 runuser sed sync; do command -v "$c" >/dev/null; done'
    )
    Invoke-Wsl @(
        '--distribution', $Distribution, '--exec', 'sh', '-lc',
        'test -x "$HOME/.cargo/bin/cargo" || command -v cargo >/dev/null'
    )
    [ordered]@{
        repoWindows = $repoWindows
        repoLinux = $repoLinux
        managedUser = $managedUser
        managedHome = $managedHome
        harness = "$repoLinux/tests/managed-wsl-oci-restart-acceptance.sh"
    }
}

function Invoke-GuestPhase {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$GuestPhase,
        [string]$Nonce = ''
    )

    $arguments = @(
        '--distribution', $Distribution, '--user', 'root', '--exec', 'bash',
        $Context.harness, $GuestPhase, $Context.repoLinux, $Context.managedUser
    )
    if ($Nonce) { $arguments += $Nonce }
    Invoke-Wsl $arguments
}

function Remove-Fixture {
    param([Parameter(Mandatory)]$Context)

    Invoke-GuestPhase -Context $Context -GuestPhase 'cleanup'
}

if ($env:OS -ne 'Windows_NT') {
    throw 'This acceptance harness requires Windows.'
}
Assert-Elevated
if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw 'wsl.exe is required.'
}

$stateDirectory = Join-Path $env:ProgramData 'RunnerManager\acceptance'
New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
$script:StatePath = Join-Path $stateDirectory "managed-wsl-reboot-$Distribution.json"
$existing = Read-State

switch ($Phase) {
    'prepare' {
        if ($null -ne $existing) {
            if ($existing.phase -ne 'prepared') {
                throw "Acceptance state is '$($existing.phase)'. Run cleanup before preparing again."
            }
            $currentBoot = Get-WindowsBootEvidence
            if ($currentBoot.lastBootUpTimeUtc -ne $existing.preparedBoot.lastBootUpTimeUtc -or
                [long]$currentBoot.kernelBootEventRecordId -ne [long]$existing.preparedBoot.kernelBootEventRecordId) {
                throw 'The prepared Windows boot has ended. Run verify-after-reboot.'
            }
            $context = Get-WslContext
            Invoke-GuestPhase -Context $context -GuestPhase 'check-seed' -Nonce $existing.nonce
            Write-Output "Already prepared. State: $script:StatePath"
            break
        }

        $context = Get-WslContext
        $nonce = 'rm-reboot-nonce-' + [guid]::NewGuid().ToString('N')
        $fixtureOwned = $false
        try {
            Invoke-Wsl @(
                '--distribution', $Distribution, '--user', 'root', '--exec', 'bash', '-c',
                'test ! -e /usr/local/libexec/runner-manager-oci-restart-acceptance && test ! -e /var/lib/runner-manager-wsl-oci-restart.ext4 && test ! -e "$1/.local/share/runner-manager-wsl-oci-restart"',
                '--', $context.managedHome
            )
            $fixtureOwned = $true
            Invoke-GuestPhase -Context $context -GuestPhase 'setup'
            Invoke-GuestPhase -Context $context -GuestPhase 'seed' -Nonce $nonce
            Invoke-GuestPhase -Context $context -GuestPhase 'check-seed' -Nonce $nonce
            $state = [ordered]@{
                schema = 1
                phase = 'prepared'
                distribution = $Distribution
                repository = $context.repoWindows
                managedUser = $context.managedUser
                nonce = $nonce
                preparedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
                preparedBoot = Get-WindowsBootEvidence
                verifiedAtUtc = $null
                verifiedBoot = $null
                result = $null
            }
            Write-State $state
            Write-Output "Prepared five bounded-provider resources and durable accounting. State: $script:StatePath"
            Write-Output 'Reboot Windows manually, then run the verify-after-reboot phase. This harness never initiates a reboot.'
        }
        catch {
            if ($fixtureOwned) {
                try { Remove-Fixture -Context $context } catch { Write-Warning "Fixture rollback failed: $_" }
            }
            throw
        }
    }

    'verify-after-reboot' {
        if ($null -eq $existing) {
            throw "No prepared acceptance state exists at $script:StatePath."
        }
        if ($existing.phase -eq 'verified') {
            Write-Output "Already verified and cleaned. Receipt: $script:StatePath"
            break
        }
        if ($existing.phase -ne 'prepared') {
            throw "Acceptance state is '$($existing.phase)'. Run cleanup before trying again."
        }
        $currentBoot = Get-WindowsBootEvidence
        Assert-BootChanged -Before $existing.preparedBoot -After $currentBoot
        $context = Get-WslContext
        $verified = $false
        $verificationError = $null
        try {
            Invoke-GuestPhase -Context $context -GuestPhase 'remount-after-host-reboot'
            Invoke-GuestPhase -Context $context -GuestPhase 'recover' -Nonce $existing.nonce
            $verified = $true
        }
        catch {
            $verificationError = $_
        }
        finally {
            try { Remove-Fixture -Context $context } catch { Write-Warning "Fixture cleanup failed: $_"; $verified = $false }
        }
        if (-not $verified) {
            $existing.phase = 'cleanup-required'
            Write-State $existing
            if ($null -ne $verificationError) {
                throw "Host-reboot verification failed: $verificationError Run cleanup to remove any remaining fixture."
            }
            throw 'Host-reboot verification cleanup failed. Run cleanup to remove any remaining fixture.'
        }
        $existing.phase = 'verified'
        $existing.verifiedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
        $existing.verifiedBoot = $currentBoot
        $existing.result = 'resources=0 capacity=0 githubRegistrations=0 nonceAbsentFromProviderDurableSurfaces=true'
        Write-State $existing
        Write-Output "Managed WSL full-Windows-reboot acceptance passed. Receipt: $script:StatePath"
    }

    'cleanup' {
        if ($null -eq $existing) {
            Write-Output 'No acceptance state or owned fixture is recorded; cleanup is already complete.'
            break
        }
        if ($existing.phase -ne 'verified') {
            $context = Get-WslContext
            Remove-Fixture -Context $context
        }
        Remove-Item -LiteralPath $script:StatePath -Force
        Write-Output 'Acceptance fixture and state receipt removed.'
    }
}
