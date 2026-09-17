param(
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$Distribution = 'Ubuntu'
)

$ErrorActionPreference = 'Stop'
$repoWindows = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$repoLinux = (& wsl.exe --distribution $Distribution --exec wslpath -a $repoWindows).Trim()
if ($LASTEXITCODE -ne 0 -or -not $repoLinux) {
    throw "Could not resolve the repository path inside $Distribution."
}
$managedUser = (& wsl.exe --distribution $Distribution --exec sh -lc 'id -un').Trim()
if ($LASTEXITCODE -ne 0 -or -not $managedUser -or $managedUser -eq 'root') {
    throw "The default $Distribution user must be the non-root managed user."
}
$managedPasswd = (& wsl.exe --distribution $Distribution --exec getent passwd $managedUser).Trim()
$managedHome = ($managedPasswd -split ':')[5]
if ($LASTEXITCODE -ne 0 -or -not $managedHome -or -not $managedHome.StartsWith('/')) {
    throw "Could not resolve the home directory for $managedUser in $Distribution."
}

$harness = "$repoLinux/tests/managed-wsl-oci-restart-acceptance.sh"
$fixtureOwned = $false
try {
    & wsl.exe --distribution $Distribution --user root --exec bash -c @'
test ! -e /usr/local/libexec/runner-manager-oci-restart-acceptance &&
test ! -e /var/lib/runner-manager-wsl-oci-restart.ext4 &&
test ! -e "$1/.local/share/runner-manager-wsl-oci-restart"
'@ -- $managedHome
    if ($LASTEXITCODE -ne 0) { throw 'Managed WSL restart fixture namespace is already occupied.' }
    $fixtureOwned = $true
    & wsl.exe --distribution $Distribution --user root --exec bash $harness setup $repoLinux $managedUser
    if ($LASTEXITCODE -ne 0) { throw 'Managed WSL restart fixture setup failed.' }

    & wsl.exe --distribution $Distribution --user root --exec bash $harness seed $repoLinux $managedUser
    if ($LASTEXITCODE -ne 0) { throw 'Managed WSL restart fixture seed failed.' }

    & wsl.exe --terminate $Distribution
    if ($LASTEXITCODE -ne 0) { throw "wsl --terminate $Distribution failed." }

    & wsl.exe --distribution $Distribution --user root --exec bash $harness remount $repoLinux $managedUser
    if ($LASTEXITCODE -ne 0) { throw 'Managed WSL bounded store remount failed.' }

    & wsl.exe --distribution $Distribution --user root --exec bash $harness recover $repoLinux $managedUser
    if ($LASTEXITCODE -ne 0) { throw 'Managed WSL provider recovery failed.' }

    Write-Output 'managed WSL terminate/restart acceptance passed'
}
finally {
    if ($fixtureOwned) {
        & wsl.exe --distribution $Distribution --user root --exec bash $harness cleanup $repoLinux $managedUser
        if ($LASTEXITCODE -ne 0) {
            Write-Warning 'Managed WSL restart fixture cleanup failed.'
        }
    }
}
