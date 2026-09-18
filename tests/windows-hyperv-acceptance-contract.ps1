#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$harness = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts/windows-hyperv-acceptance.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($harness, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw "acceptance harness has PowerShell parse errors: $errors" }
$definition = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Assert-ContainerEvidence'
}, $true)
if (-not $definition) { throw 'Assert-ContainerEvidence was not found in the acceptance harness' }
Invoke-Expression $definition.Extent.Text

$script:InspectJson = $null
$Image = 'mcr.microsoft.com/windows/servercore@sha256:test'
function Invoke-External {
    if ($args[0] -ne 'docker.exe') { throw "unexpected mocked executable '$($args[0])'" }
    return @($script:InspectJson)
}

$script:ReviewedCommand = @('powershell.exe', '-Command', @'
Environment.GetEnvironmentVariable(\"ACTIONS_RUNNER_INPUT_JITCONFIG\", EnvironmentVariableTarget.Process);
Environment.SetEnvironmentVariable(\"ACTIONS_RUNNER_INPUT_JITCONFIG\", jitValue, EnvironmentVariableTarget.Process);
Environment.SetEnvironmentVariable(\"ACTIONS_RUNNER_INPUT_JITCONFIG\", priorJit, EnvironmentVariableTarget.Process);
'@)

function New-InspectJson {
    param(
        $Mounts = $null,
        $Binds = $null,
        $Devices = $null,
        [object[]]$Environment = @('Path=C:\Windows\System32'),
        [object[]]$Command = $script:ReviewedCommand,
        [object[]]$Arguments = @()
    )
    @([ordered]@{
        HostConfig = [ordered]@{
            Isolation = 'hyperv'
            NanoCpus = 2000000000
            Memory = 4294967296
            StorageOpt = @{ size = '8192m' }
            NetworkMode = 'nat'
            Binds = $Binds
            Devices = $Devices
            Privileged = $false
        }
        Config = [ordered]@{ Image = $Image; Env = $Environment; Cmd = $Command }
        Args = $Arguments
        Mounts = $Mounts
    }) | ConvertTo-Json -Depth 8
}

$script:OwnedFixtureDirectories = [Collections.Generic.List[string]]::new()
function Remove-OwnedFixtureDirectory([string]$Path) {
    $lastError = $null
    foreach ($attempt in 1..20) {
        try {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        } catch {
            $lastError = $_
            try {
                [IO.Directory]::Delete($Path, $true)
            } catch {
                $lastError = $_
            }
        }
        if (-not (Test-Path -LiteralPath $Path)) { return }
        if ($attempt -lt 20) { Start-Sleep -Milliseconds 250 }
    }
    throw "owned test fixture directory '$Path' remains after cleanup retries: $($lastError.Exception.Message)"
}

function Assert-Passes([string]$Name, [string]$Json, [scriptblock]$Check = {}) {
    $script:InspectJson = $Json
    $directory = Join-Path ([IO.Path]::GetTempPath()) ("runner-manager-hyperv-contract-" + [Guid]::NewGuid().ToString('N'))
    $script:OwnedFixtureDirectories.Add($directory)
    New-Item -ItemType Directory -Path $directory | Out-Null
    try {
        Assert-ContainerEvidence '0123456789abcdef' $directory
        & $Check $directory
    } catch {
        throw "expected '$Name' to pass: $($_.Exception.Message)"
    } finally {
        Remove-OwnedFixtureDirectory $directory
    }
}

function Assert-Rejected([string]$Name, [string]$Json, [string]$Message) {
    $script:InspectJson = $Json
    $directory = Join-Path ([IO.Path]::GetTempPath()) ("runner-manager-hyperv-contract-" + [Guid]::NewGuid().ToString('N'))
    $script:OwnedFixtureDirectories.Add($directory)
    New-Item -ItemType Directory -Path $directory | Out-Null
    try {
        Assert-ContainerEvidence '0123456789abcdef' $directory
        throw "expected '$Name' to be rejected"
    } catch {
        if ($_.Exception.Message -eq "expected '$Name' to be rejected") { throw }
        if ($_.Exception.Message -notlike "*$Message*") {
            throw "'$Name' failed for the wrong reason: $($_.Exception.Message)"
        }
    } finally {
        Remove-OwnedFixtureDirectory $directory
    }
}

Assert-Passes 'null optional collections and reviewed bootstrap source' (New-InspectJson) {
    param($directory)
    $attestation = Get-Content -LiteralPath (Join-Path $directory 'container-attestation.json') -Raw | ConvertFrom-Json
    if ($attestation.mounts -ne 0 -or $attestation.devices -ne 0) {
        throw 'null collections were not attested as zero'
    }
}
Assert-Rejected 'nonempty bind array' (New-InspectJson -Binds @('C:\host:C:\guest')) 'host mount'
Assert-Rejected 'nonempty device array' (New-InspectJson -Devices @(@{ PathOnHost = 'COM1' })) 'device or privileged mode'
Assert-Rejected 'JIT value in environment' (New-InspectJson -Environment @('ACTIONS_RUNNER_INPUT_JITCONFIG=secret')) 'JIT configuration environment input'
Assert-Rejected 'unreviewed JIT assignment in command metadata' (New-InspectJson -Command ($script:ReviewedCommand + @('ACTIONS_RUNNER_INPUT_JITCONFIG=secret'))) 'outside the reviewed bootstrap source'
Assert-Rejected 'unescaped reviewed JIT call in command metadata' (New-InspectJson -Command ($script:ReviewedCommand + @('Environment.GetEnvironmentVariable("ACTIONS_RUNNER_INPUT_JITCONFIG", EnvironmentVariableTarget.Process)'))) 'outside the reviewed bootstrap source'
Assert-Rejected 'duplicate reviewed JIT call in command metadata' (New-InspectJson -Command ($script:ReviewedCommand + @('Environment.GetEnvironmentVariable(\"ACTIONS_RUNNER_INPUT_JITCONFIG\", EnvironmentVariableTarget.Process)'))) 'outside the reviewed bootstrap source'
Assert-Rejected 'JIT input in argument metadata' (New-InspectJson -Arguments @('ACTIONS_RUNNER_INPUT_JITCONFIG=secret')) 'outside the reviewed bootstrap source'
Assert-Rejected 'GitHub token in command metadata' (New-InspectJson -Command ($script:ReviewedCommand + @('ghp_abcdefghijklmnopqrstuvwxyz123456'))) 'credential-shaped value'
Assert-Rejected 'JIT-shaped value in argument metadata' (New-InspectJson -Arguments @('eyJhZ2VudE5hbWUiOiJydW5uZXItbWFuYWdlciIsImVuY29kZWQiOiJhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODkrLz09In0=')) 'credential-shaped value'
Assert-Rejected 'socket path in environment metadata' (New-InspectJson -Environment @('ENDPOINT=npipe://docker.sock')) 'credential-shaped value'

$fixtureResidue = @($script:OwnedFixtureDirectories | Where-Object { Test-Path -LiteralPath $_ })
if ($fixtureResidue.Count -ne 0) {
    throw "owned test fixture directories remain after contract: $($fixtureResidue -join ', ')"
}

Write-Output 'Windows Hyper-V acceptance contract passed'
