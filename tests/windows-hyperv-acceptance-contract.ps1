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

$script:ReviewedReferences = @(
    'Environment.GetEnvironmentVariable("ACTIONS_RUNNER_INPUT_JITCONFIG", EnvironmentVariableTarget.Process)',
    'Environment.SetEnvironmentVariable("ACTIONS_RUNNER_INPUT_JITCONFIG", jitValue, EnvironmentVariableTarget.Process)',
    'Environment.SetEnvironmentVariable("ACTIONS_RUNNER_INPUT_JITCONFIG", priorJit, EnvironmentVariableTarget.Process)'
)
$script:ReviewedBootstrap = @'
Environment.GetEnvironmentVariable("ACTIONS_RUNNER_INPUT_JITCONFIG", EnvironmentVariableTarget.Process);
Environment.SetEnvironmentVariable("ACTIONS_RUNNER_INPUT_JITCONFIG", jitValue, EnvironmentVariableTarget.Process);
Environment.SetEnvironmentVariable("ACTIONS_RUNNER_INPUT_JITCONFIG", priorJit, EnvironmentVariableTarget.Process);
'@
$script:ReviewedCommand = @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', $script:ReviewedBootstrap)
$script:ReviewedArguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', $script:ReviewedBootstrap)

if ($script:ReviewedCommand.Count -ne 5 -or $script:ReviewedArguments.Count -ne 5) {
    throw 'decoded Docker command fixtures must each contain five entries'
}
if (($script:ReviewedCommand -join "`n").Contains('\')) {
    throw 'decoded Docker command fixture must contain zero backslash characters'
}
if ($script:ReviewedReferences[0].Length -ne 103 -or
    @($script:ReviewedReferences[0].ToCharArray() | Where-Object { [int]$_ -eq 34 }).Count -ne 2 -or
    @($script:ReviewedReferences[0].ToCharArray() | Where-Object { [int]$_ -eq 92 }).Count -ne 0) {
    throw 'decoded reviewed GetEnvironmentVariable reference must be 103 characters with two quotes and zero backslashes'
}

function New-InspectJson {
    param(
        $Mounts = $null,
        $Binds = $null,
        $Devices = $null,
        [object[]]$Environment = @('Path=C:\Windows\System32'),
        [object[]]$Command = $script:ReviewedCommand,
        [object[]]$Arguments = $script:ReviewedArguments
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

$decodedFixture = New-InspectJson | ConvertFrom-Json
if (@($decodedFixture[0].Config.Cmd).Count -ne 5 -or @($decodedFixture[0].Args).Count -ne 5) {
    throw 'decoded Docker fixture did not preserve the five-entry command and argument arrays'
}
foreach ($surface in @($decodedFixture[0].Config.Cmd, $decodedFixture[0].Args)) {
    if ([regex]::Matches(($surface -join "`n"), 'ACTIONS_RUNNER_INPUT_JITCONFIG').Count -ne 3) {
        throw 'decoded Docker fixture must contain three reviewed JIT references in each command surface'
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
$commandMissing = @($script:ReviewedCommand)
$commandMissing[4] = $commandMissing[4].Replace($script:ReviewedReferences[0], '')
$commandDuplicate = @($script:ReviewedCommand)
$commandDuplicate[4] += "`n$($script:ReviewedReferences[0])"
$commandUnqualified = @($script:ReviewedCommand)
$commandUnqualified[4] = $commandUnqualified[4].Replace($script:ReviewedReferences[0], 'GetEnvironmentVariable("ACTIONS_RUNNER_INPUT_JITCONFIG", EnvironmentVariableTarget.Process)')
$commandLiteralBackslash = @($script:ReviewedCommand)
$commandLiteralBackslash[4] = $commandLiteralBackslash[4].Replace($script:ReviewedReferences[0], 'Environment.GetEnvironmentVariable(\"ACTIONS_RUNNER_INPUT_JITCONFIG\", EnvironmentVariableTarget.Process)')
Assert-Rejected 'missing reviewed JIT call in command metadata' (New-InspectJson -Command $commandMissing) 'outside the reviewed bootstrap source in Config.Cmd'
Assert-Rejected 'duplicate reviewed JIT call in command metadata' (New-InspectJson -Command $commandDuplicate) 'outside the reviewed bootstrap source in Config.Cmd'
Assert-Rejected 'unqualified reviewed JIT call in command metadata' (New-InspectJson -Command $commandUnqualified) 'outside the reviewed bootstrap source in Config.Cmd'
Assert-Rejected 'literal-backslash reviewed JIT call in command metadata' (New-InspectJson -Command $commandLiteralBackslash) 'outside the reviewed bootstrap source in Config.Cmd'
Assert-Rejected 'additional JIT reference in command metadata' (New-InspectJson -Command ($script:ReviewedCommand + @('ACTIONS_RUNNER_INPUT_JITCONFIG=secret'))) 'outside the reviewed bootstrap source in Config.Cmd'

$argumentsMissing = @($script:ReviewedArguments)
$argumentsMissing[4] = $argumentsMissing[4].Replace($script:ReviewedReferences[0], '')
$argumentsDuplicate = @($script:ReviewedArguments)
$argumentsDuplicate[4] += "`n$($script:ReviewedReferences[0])"
$argumentsUnqualified = @($script:ReviewedArguments)
$argumentsUnqualified[4] = $argumentsUnqualified[4].Replace($script:ReviewedReferences[0], 'GetEnvironmentVariable("ACTIONS_RUNNER_INPUT_JITCONFIG", EnvironmentVariableTarget.Process)')
$argumentsLiteralBackslash = @($script:ReviewedArguments)
$argumentsLiteralBackslash[4] = $argumentsLiteralBackslash[4].Replace($script:ReviewedReferences[0], 'Environment.GetEnvironmentVariable(\"ACTIONS_RUNNER_INPUT_JITCONFIG\", EnvironmentVariableTarget.Process)')
Assert-Rejected 'missing reviewed JIT call in argument metadata' (New-InspectJson -Arguments $argumentsMissing) 'outside the reviewed bootstrap source in Args'
Assert-Rejected 'duplicate reviewed JIT call in argument metadata' (New-InspectJson -Arguments $argumentsDuplicate) 'outside the reviewed bootstrap source in Args'
Assert-Rejected 'unqualified reviewed JIT call in argument metadata' (New-InspectJson -Arguments $argumentsUnqualified) 'outside the reviewed bootstrap source in Args'
Assert-Rejected 'literal-backslash reviewed JIT call in argument metadata' (New-InspectJson -Arguments $argumentsLiteralBackslash) 'outside the reviewed bootstrap source in Args'
Assert-Rejected 'additional JIT reference in argument metadata' (New-InspectJson -Arguments ($script:ReviewedArguments + @('ACTIONS_RUNNER_INPUT_JITCONFIG=secret'))) 'outside the reviewed bootstrap source in Args'
Assert-Rejected 'GitHub token in command metadata' (New-InspectJson -Command ($script:ReviewedCommand + @('ghp_abcdefghijklmnopqrstuvwxyz123456'))) 'credential-shaped value'
Assert-Rejected 'JIT-shaped value in argument metadata' (New-InspectJson -Arguments ($script:ReviewedArguments + @('eyJhZ2VudE5hbWUiOiJydW5uZXItbWFuYWdlciIsImVuY29kZWQiOiJhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODkrLz09In0='))) 'credential-shaped value'
Assert-Rejected 'socket path in environment metadata' (New-InspectJson -Environment @('ENDPOINT=npipe://docker.sock')) 'credential-shaped value'

$fixtureResidue = @($script:OwnedFixtureDirectories | Where-Object { Test-Path -LiteralPath $_ })
if ($fixtureResidue.Count -ne 0) {
    throw "owned test fixture directories remain after contract: $($fixtureResidue -join ', ')"
}

Write-Output 'Windows Hyper-V acceptance contract passed'
