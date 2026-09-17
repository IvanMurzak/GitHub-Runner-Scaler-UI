[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$harness = Join-Path $PSScriptRoot 'managed-wsl-oci-reboot-acceptance.ps1'
$tokens = $null
$errors = $null
[void][Management.Automation.Language.Parser]::ParseFile($harness, [ref]$tokens, [ref]$errors)
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

Write-Output 'managed WSL full-reboot harness syntax and contract passed'
