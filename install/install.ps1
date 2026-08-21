<#
    runner-manager installer for Windows (task a3, D11/D12/D14).

        irm https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases/latest/download/install.ps1 | iex

    ------------------------------------------------------------------------
    WHY `irm | iex` CANNOT TAKE ARGUMENTS, AND WHAT TO USE INSTEAD.
    ------------------------------------------------------------------------
    `irm | iex` pipes the script's TEXT into Invoke-Expression, so the param()
    block below never receives anything: there is no argv to bind. Anyone
    documenting `irm ... | iex --version 1.2.3` is documenting a syntax error.

    Two forms work, and both are in the README:

        # pin a version, env-var form -- works with the plain pipe above
        $env:RUNNER_MANAGER_INSTALL_VERSION = '1.2.3'
        irm <url>/install.ps1 | iex

        # pin a version, script-block form -- takes real parameters
        & ([scriptblock]::Create((irm <url>/install.ps1))) -Version 1.2.3

    ------------------------------------------------------------------------
    WINDOWS POWERSHELL 5.1 IS A SUPPORTED HOST, NOT A FALLBACK.
    ------------------------------------------------------------------------
    A clean Windows machine has Windows PowerShell 5.1 and no PowerShell 7, and
    the Definition of Done names a clean Windows host with no Node installed as
    a case this path must serve. So: no ternaries, no `??`, no `-Parallel`, and
    no assuming Invoke-WebRequest can parse without `-UseBasicParsing`. It also
    means TLS 1.2 has to be asked for explicitly, because 5.1 on an unpatched
    host still negotiates TLS 1.0 and github.com refuses that outright.

    ------------------------------------------------------------------------
    WHY IT INSTALLS TO %LOCALAPPDATA%\Programs\runner-manager.
    ------------------------------------------------------------------------
    `runner-manager service install` records the ABSOLUTE path of the binary
    (`05-infrastructure.md`, service behaviour 6). A location that moves when a
    toolchain moves -- an `npm i -g` prefix is exactly that -- leaves an
    installed service pointing at a path that no longer exists, and it surfaces
    at the next unattended boot rather than at install time. LOCALAPPDATA is
    per-user, needs no elevation, and does not move.

    ------------------------------------------------------------------------
    WHY IT REPORTS THE PATH INSTEAD OF EDITING IT.
    ------------------------------------------------------------------------
    `09-release-distribution.md` asks the script to "report how to add it to
    PATH if it is not already there", and reporting is the whole of it. A
    persistent HKCU write from a script the user piped in from the network is a
    side effect nobody asked for, it is invisible in the terminal that made it,
    and it is the one action here that outlives an uninstall. install.sh does
    not touch a shell profile for the same reason.

    ------------------------------------------------------------------------
    WHY THE CHECKSUM HAS NO -SkipVerify.
    ------------------------------------------------------------------------
    `07-security.md` lists artifact tampering in transit as a threat whose only
    control is the published SHA-256. A check that can be switched off is a
    check an attacker can ask to have switched off. If it does not match,
    nothing is installed and the exit code is non-zero.

    ------------------------------------------------------------------------
    THE SEAMS THE TEST SUITE DRIVES.
    ------------------------------------------------------------------------
    `crates/app/tests/install_scripts.rs` runs this file end to end against a
    directory of fixture assets. -BaseUrl accepts a local directory as well as
    an https:// base, which is also what an air-gapped or mirrored install
    looks like; -Arch overrides the detected architecture.
#>

[CmdletBinding()]
param(
    [string] $Version = $env:RUNNER_MANAGER_INSTALL_VERSION,
    [string] $Dir     = $env:RUNNER_MANAGER_INSTALL_DIR,
    [string] $BaseUrl = $env:RUNNER_MANAGER_INSTALL_BASE_URL,
    [string] $Arch    = $env:RUNNER_MANAGER_INSTALL_ARCH,
    [switch] $PrintPlan
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Program    = 'install.ps1'
$Repository = 'IvanMurzak/GitHub-Runner-Scaler-UI'
$BinaryName = 'runner-manager.exe'

function Write-Fail {
    param([string] $Message)
    [Console]::Error.WriteLine("${Program}: $Message")
    exit 1
}

# ---------------------------------------------------------------------------
# Arguments.
# ---------------------------------------------------------------------------

if ($Version) {
    if ($Version -match '^v') {
        Write-Fail "-Version takes 1.2.3, not v1.2.3: the 'v' belongs to the tag."
    }
    if ($Version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
        Write-Fail "-Version '$Version' is not X.Y.Z."
    }
}

if (-not $Dir) {
    $localAppData = $env:LOCALAPPDATA
    if (-not $localAppData) {
        Write-Fail 'neither -Dir nor %LOCALAPPDATA% is set, so there is nowhere to install to.'
    }
    $Dir = Join-Path $localAppData 'Programs\runner-manager'
}

# ---------------------------------------------------------------------------
# Which artifact does this host need?
# ---------------------------------------------------------------------------
# Only one Windows target is published. An ARM64 host is served by it through
# the built-in x64 emulation layer, which is stated rather than hidden: a user
# who sees "x86_64" scroll past on an ARM machine should be told why, not left
# to guess whether the wrong thing was installed.

if (-not $Arch) { $Arch = $env:PROCESSOR_ARCHITECTURE }
if (-not $Arch) { Write-Fail 'could not determine the processor architecture.' }

$target   = ''
$emulated = $false
if ($Arch -match '^(AMD64|x64|x86_64)$') {
    $target = 'x86_64-pc-windows-msvc'
} elseif ($Arch -match '^(ARM64|aarch64)$') {
    $target = 'x86_64-pc-windows-msvc'
    $emulated = $true
} else {
    Write-Fail "unsupported architecture '$Arch'. Supported: AMD64 (x64) and ARM64. Build from source with 'cargo install runner-manager'."
}

# ---------------------------------------------------------------------------
# Where the assets come from.
# ---------------------------------------------------------------------------

if (-not $BaseUrl) { $BaseUrl = "https://github.com/$Repository/releases" }

if ($BaseUrl -match '^https?://') {
    $remote = $true
    if ($Version) { $assets = "$BaseUrl/download/v$Version" }
    else          { $assets = "$BaseUrl/latest/download" }
} else {
    $remote = $false
    $assets = $BaseUrl
    if (-not (Test-Path -LiteralPath $assets -PathType Container)) {
        Write-Fail "-BaseUrl is not an http(s) URL and not a directory: $assets"
    }
}

if ($PrintPlan) {
    Write-Output 'os=windows'
    Write-Output "arch=$Arch"
    Write-Output "target=$target"
    if ($Version) { Write-Output "version=$Version" } else { Write-Output 'version=latest' }
    Write-Output "assets=$assets"
    Write-Output "install_dir=$Dir"
    Write-Output "binary=$(Join-Path $Dir $BinaryName)"
    exit 0
}

# ---------------------------------------------------------------------------
# Fetching.
# ---------------------------------------------------------------------------

if ($remote) {
    # Added rather than assigned, so an already-correct setting is widened and
    # never narrowed.
    try {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch {
        # A .NET with no Tls12 member cannot reach github.com at all; the
        # download below fails with its own message rather than this one.
        $null = $_
    }
}

# `$remote` and `$assets` are read from the enclosing scope rather than passed:
# PowerShell resolves them dynamically, which behaves the same whether this
# file is run as a script or pasted into a session by `irm | iex`. A `$script:`
# qualifier does not, because `iex` has no script scope of its own.
function Get-Asset {
    param([string] $Name, [string] $Destination)
    if (-not $remote) {
        $source = Join-Path $assets $Name
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { return $false }
        Copy-Item -LiteralPath $source -Destination $Destination -Force
        return $true
    }
    try {
        # -UseBasicParsing because 5.1 otherwise wants Internet Explorer's HTML
        # engine, which is absent on Server Core and on hosts where IE was
        # removed.
        Invoke-WebRequest -Uri "$assets/$Name" -OutFile $Destination -UseBasicParsing
        return $true
    } catch {
        $null = $_
        return $false
    }
}

$work = Join-Path ([IO.Path]::GetTempPath()) ('runner-manager-install-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null

try {
    # -----------------------------------------------------------------------
    # 1. SHA256SUMS, which names the assets and pins their digests.
    # -----------------------------------------------------------------------
    # The asset name carries the version, and "latest" is precisely the case
    # where the version is unknown, so this document is fetched first and the
    # archive name and its digest are read out of the same answer. That is why
    # this script never needs editing at release time.

    Write-Output "Resolving runner-manager for $target from $assets"

    $sums = Join-Path $work 'SHA256SUMS'
    if (-not (Get-Asset -Name 'SHA256SUMS' -Destination $sums)) {
        if ($Version) {
            Write-Fail "no release $Version found at $assets (SHA256SUMS could not be fetched)."
        }
        Write-Fail "could not fetch SHA256SUMS from $assets."
    }

    # Anchored at both ends, so `runner-manager-1.2.3-x86_64-pc-windows-msvc.zip`
    # is matched and `something-runner-manager-...zip.bak` is not.
    $pattern = '^([0-9a-f]{64})\s+(runner-manager-[0-9]+\.[0-9]+\.[0-9]+-' +
               [Regex]::Escape($target) + '\.zip)$'
    $found = New-Object System.Collections.ArrayList
    foreach ($line in (Get-Content -LiteralPath $sums)) {
        $hit = [Regex]::Match($line.Trim(), $pattern)
        if ($hit.Success) {
            $null = $found.Add(@($hit.Groups[1].Value, $hit.Groups[2].Value))
        }
    }

    # Exactly one archive per target per release. Zero means this release does
    # not publish this platform; more than one means the release is malformed,
    # and picking either would pin a digest to the wrong file.
    if ($found.Count -eq 0) {
        Write-Fail "SHA256SUMS at $assets lists no archive for $target. This release does not publish that platform."
    }
    if ($found.Count -gt 1) {
        Write-Fail "SHA256SUMS at $assets lists $($found.Count) archives for $target; refusing to guess which one is meant."
    }

    $expected = $found[0][0]
    $asset    = $found[0][1]

    $versionHit = [Regex]::Match($asset, '^runner-manager-([0-9]+\.[0-9]+\.[0-9]+)-')
    if (-not $versionHit.Success) {
        Write-Fail "could not read a version out of the asset name '$asset'."
    }
    $resolvedVersion = $versionHit.Groups[1].Value

    # With -Version, the requested version and the one that arrived must agree.
    # On the remote path a wrong version is normally a 404 above; on a local
    # mirror it is not, and a mirror serving 1.0.0 to someone who asked for
    # 1.2.3 must be a refusal rather than a surprise.
    if ($Version -and ($Version -ne $resolvedVersion)) {
        Write-Fail "asked for $Version but $assets publishes $resolvedVersion for $target."
    }

    Write-Output "Release $resolvedVersion, asset $asset"

    # -----------------------------------------------------------------------
    # 2. The archive, and the digest that decides whether it is used.
    # -----------------------------------------------------------------------

    $archive = Join-Path $work $asset
    if (-not (Get-Asset -Name $asset -Destination $archive)) {
        Write-Fail "could not fetch $asset from $assets."
    }

    $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()

    if ($actual -ne $expected) {
        [Console]::Error.WriteLine("${Program}: CHECKSUM MISMATCH -- refusing to install $asset")
        [Console]::Error.WriteLine("  expected (SHA256SUMS): $expected")
        [Console]::Error.WriteLine("  actually downloaded:   $actual")
        [Console]::Error.WriteLine('')
        [Console]::Error.WriteLine('The archive does not match the digest published beside it. That is')
        [Console]::Error.WriteLine('either a corrupted download or a tampered artifact; nothing has been')
        [Console]::Error.WriteLine('installed either way. Retry, and if it happens again report it at')
        [Console]::Error.WriteLine("https://github.com/$Repository/issues rather than installing by hand.")
        exit 1
    }

    Write-Output "SHA-256 OK: $expected"

    # -----------------------------------------------------------------------
    # 3. Unpack and install.
    # -----------------------------------------------------------------------
    # Expand-Archive ships with 5.1, and the archive was produced by
    # Compress-Archive in the release workflow, so this is the matching reader.

    $unpacked = Join-Path $work 'unpacked'
    New-Item -ItemType Directory -Path $unpacked -Force | Out-Null
    Expand-Archive -LiteralPath $archive -DestinationPath $unpacked -Force

    $stem     = "runner-manager-$resolvedVersion-$target"
    $produced = Join-Path (Join-Path $unpacked $stem) $BinaryName
    if (-not (Test-Path -LiteralPath $produced -PathType Leaf)) {
        Write-Fail "$asset does not contain $stem\$BinaryName."
    }

    if (-not (Test-Path -LiteralPath $Dir -PathType Container)) {
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    }

    # Staged and moved, so a second run replaces the binary in one step instead
    # of truncating it -- which is what makes running this script twice leave
    # exactly one working binary. Windows refuses to rename over a RUNNING
    # executable, so that case gets a sentence naming the cause rather than an
    # unexplained access-denied.
    $destination = Join-Path $Dir $BinaryName
    $staged      = Join-Path $Dir '.runner-manager.install-tmp'
    if (Test-Path -LiteralPath $staged) { Remove-Item -LiteralPath $staged -Force }
    Copy-Item -LiteralPath $produced -Destination $staged -Force
    try {
        Move-Item -LiteralPath $staged -Destination $destination -Force
    } catch {
        $null = $_
        Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
        Write-Fail "could not replace $destination. If the agent is running, stop it first: runner-manager service stop"
    }

    Write-Output ''
    Write-Output "Installed runner-manager $resolvedVersion to $destination"
    if ($emulated) {
        Write-Output ''
        Write-Output 'This is an ARM64 host and only an x64 Windows build is published;'
        Write-Output 'it runs through the built-in x64 emulation layer.'
    }

    # -----------------------------------------------------------------------
    # 4. PATH -- reported, never written.
    # -----------------------------------------------------------------------

    $onPath = $false
    if ($env:PATH) {
        foreach ($entry in ($env:PATH -split ';')) {
            if ($entry -and ($entry.TrimEnd('\') -ieq $Dir.TrimEnd('\'))) { $onPath = $true }
        }
    }

    Write-Output ''
    if ($onPath) {
        Write-Output 'Next:  runner-manager --version'
    } else {
        Write-Output "$Dir is not on your PATH. Add it for this account:"
        Write-Output ''
        Write-Output "  [Environment]::SetEnvironmentVariable('PATH', [Environment]::GetEnvironmentVariable('PATH','User') + ';$Dir', 'User')"
        Write-Output ''
        Write-Output 'then open a new terminal. Until then, run it by path:'
        Write-Output "  $destination --version"
    }

    Write-Output ''
    Write-Output 'Before you connect it to GitHub: installing the published GitHub App grants'
    Write-Output 'Repository -> Administration: Read and write, which also permits deleting,'
    Write-Output 'renaming and transferring the repository. See the README for the full'
    Write-Output 'permission set and why organization scope is the narrower option.'
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
