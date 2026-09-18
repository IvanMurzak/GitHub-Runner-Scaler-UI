[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$harness = Join-Path $PSScriptRoot 'managed-wsl-oci-reboot-acceptance.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($harness, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) {
    throw "PowerShell syntax errors:`n$($errors | Out-String)"
}

$source = Get-Content -LiteralPath $harness -Raw
foreach ($required in @(
    "[ValidateSet('prepare', 'verify-after-reboot', 'cleanup')]",
    'Assert-Elevated',
    'Get-WindowsBootEvidence',
    'Assert-BootChanged',
    "'remount-after-host-reboot'",
    "'recover'",
    "'cleanup'",
    'githubRegistrations=0',
    'capacity=0',
    'This harness never initiates a reboot.'
)) {
    if (-not $source.Contains($required)) { throw "Harness contract lost: $required" }
}
foreach ($forbidden in @('Restart-Computer', 'shutdown.exe', 'wsl.exe --terminate', 'encoded_jit_config')) {
    if ($source.Contains($forbidden)) { throw "Harness contains forbidden reboot/credential action: $forbidden" }
}

$assertBootChanged = $ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Assert-BootChanged'
}, $true)
if ($assertBootChanged.Count -ne 1) {
    throw 'Harness must define exactly one Assert-BootChanged function.'
}
Invoke-Expression $assertBootChanged[0].Extent.Text

# PowerShell 7 deserializes ISO timestamps into DateTime values while Windows
# PowerShell 5.1 leaves them as strings. Exercise the host's real receipt path,
# then force the PowerShell 7 shape so both representations stay supported.
$before = '{"lastBootUpTimeUtc":"2026-09-17T20:33:42.5000000Z","kernelBootEventRecordId":141411,"kernelBootEventTimeUtc":"2026-09-17T20:33:43.0000000Z"}' | ConvertFrom-Json
$after = [pscustomobject]@{
    lastBootUpTimeUtc = '2026-09-17T22:27:04.5000000Z'
    kernelBootEventRecordId = 141795
    kernelBootEventTimeUtc = '2026-09-17T22:27:05.0000000Z'
}
Assert-BootChanged -Before $before -After $after

$dateTimeBefore = [pscustomobject]@{
    lastBootUpTimeUtc = [DateTime]::Parse(
        '2026-09-17T20:33:42.5000000Z',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind
    )
    kernelBootEventRecordId = 141411
    kernelBootEventTimeUtc = [DateTime]::Parse(
        '2026-09-17T20:33:43.0000000Z',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind
    )
}
Assert-BootChanged -Before $dateTimeBefore -After $after

$rejectedUnchangedBoot = $false
try {
    Assert-BootChanged -Before $before -After $before
}
catch {
    $rejectedUnchangedBoot = $true
}
if (-not $rejectedUnchangedBoot) {
    throw 'Harness accepted an unchanged Windows boot identity.'
}

Write-Output 'managed WSL full-reboot harness syntax and contract passed'
