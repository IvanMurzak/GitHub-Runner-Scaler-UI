#!/usr/bin/env pwsh
#
# D18 spike, round 3 — WHICH permission authorized the organization call?
#
# Rounds 1 and 2 proved `POST /orgs/{org}/actions/runners/generate-jitconfig`
# returns 201. That verdict is only transferable to the *published* App if the
# App under test holds no MORE than what `07-security.md` plans to ship:
#
#     | Organization -> Self-hosted runners | Read and write |
#
# If the throwaway App happens to hold a broader organization grant, the 201
# proves nothing about the App that actually ships -- which would be the same
# class of untested assumption this task exists to close.
#
# READ-ONLY. Creates nothing, deletes nothing. Prints NO credential.

[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string] $ClientId,
  [Parameter(Mandatory)] [string] $Org,
  [string] $DeviceCodeFile,
  [int]    $AuthTimeoutSeconds = 420,
  [string] $EvidenceOut
)

$ErrorActionPreference = 'Stop'
$API = 'https://api.github.com'
$evidence = [ordered]@{}

function Note($step, $verdict, $detail) {
  $evidence[$step] = [ordered]@{ verdict = $verdict; detail = $detail }
  $c = switch ($verdict) { 'GREEN' { 'Green' } 'RED' { 'Red' } default { 'Yellow' } }
  Write-Host ("[{0,-24}] {1,-5} {2}" -f $step, $verdict, $detail) -ForegroundColor $c
}

Write-Host "`n=== device flow ===" -ForegroundColor Cyan
if ($DeviceCodeFile -and (Test-Path $DeviceCodeFile)) {
  $dc = Get-Content $DeviceCodeFile -Raw | ConvertFrom-Json
} else {
  $dc = Invoke-RestMethod -Method Post -Uri 'https://github.com/login/device/code' `
    -Headers @{ Accept = 'application/json' } -Body @{ client_id = $ClientId }
  try { Set-Clipboard -Value $dc.user_code } catch {}
  try { Start-Process $dc.verification_uri | Out-Null } catch {}
}
Write-Host "     URL :  $($dc.verification_uri)   CODE:  $($dc.user_code)" -ForegroundColor Yellow

$interval = [Math]::Max([int]$dc.interval, 5)
$deadline = (Get-Date).AddSeconds($AuthTimeoutSeconds)
$userToken = $null
while ($true) {
  if ((Get-Date) -gt $deadline) {
    Note 'device-flow' 'RED' "no authorization within ${AuthTimeoutSeconds}s -- BLOCKED"
    Write-Host "BLOCKED: URL $($dc.verification_uri) CODE $($dc.user_code)" -ForegroundColor Red
    exit 2
  }
  Start-Sleep -Seconds $interval
  $r = Invoke-RestMethod -Method Post -Uri 'https://github.com/login/oauth/access_token' `
    -Headers @{ Accept = 'application/json' } -Body @{
      client_id = $ClientId; device_code = $dc.device_code
      grant_type = 'urn:ietf:params:oauth:grant-type:device_code'
    }
  if ($r.access_token) { $userToken = $r.access_token; break }
  switch ($r.error) {
    'authorization_pending' { }
    'slow_down' { $interval = [int]$r.interval }
    default { Note 'device-flow' 'RED' "terminal error: $($r.error)"; exit 2 }
  }
}
Note 'device-flow' 'GREEN' "token family '$($userToken.Substring(0,4))'"
$gh = @{ Authorization = "Bearer $userToken"; Accept = 'application/vnd.github+json'; 'X-GitHub-Api-Version' = '2022-11-28' }

# The decisive call: what did the user actually grant, per installation?
Write-Host "`n=== installations and their granted permissions ===" -ForegroundColor Cyan
$ins = Invoke-RestMethod -Method Get -Uri "$API/user/installations" -Headers $gh
Note 'installations' 'GREEN' "total_count $($ins.total_count)"

foreach ($i in $ins.installations) {
  $perms = ($i.permissions.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" } | Sort-Object) -join ', '
  $acct = $i.account.login
  $kind = $i.account.type
  Note "install-$acct" 'GREEN' "id $($i.id) account '$acct' ($kind) app '$($i.app_slug)' repository_selection=$($i.repository_selection)"
  Write-Host "    permissions: $perms" -ForegroundColor White
  $evidence["install-$acct-permissions"] = [ordered]@{ verdict = 'INFO'; detail = $perms }

  if ($acct -eq $Org) {
    # `organization_self_hosted_runners` is the narrow grant 07-security.md ships.
    # `organization_administration` would be the broader one that must NOT be
    # what carried the 201.
    $narrow = $i.permissions.organization_self_hosted_runners
    $broad = $i.permissions.organization_administration
    if ($narrow -and -not $broad) {
      Note 'org-permission-basis' 'GREEN' "organization_self_hosted_runners=$narrow and NO organization_administration -- the narrow grant is what authorized the 201"
    } elseif ($narrow -and $broad) {
      Note 'org-permission-basis' 'AMBER' "organization_self_hosted_runners=$narrow BUT ALSO organization_administration=$broad -- cannot attribute the 201 to the narrow grant alone"
    } elseif (-not $narrow -and $broad) {
      Note 'org-permission-basis' 'AMBER' "NO organization_self_hosted_runners; organization_administration=$broad -- the 201 rode the BROADER grant; 07-security.md's narrow permission is still unproven"
    } else {
      Note 'org-permission-basis' 'AMBER' "neither organization_self_hosted_runners nor organization_administration present"
    }
  }
}

# Confirm the organization is still clean, without changing anything.
Write-Host "`n=== final organization state (read-only) ===" -ForegroundColor Cyan
$run = Invoke-RestMethod -Method Get -Uri "$API/orgs/$Org/actions/runners" -Headers $gh
Note 'final-runners' $(if ($run.total_count -eq 0) { 'GREEN' } else { 'RED' }) "total_count $($run.total_count)"
$grp = Invoke-RestMethod -Method Get -Uri "$API/orgs/$Org/actions/runner-groups" -Headers $gh
Note 'final-groups' 'GREEN' "total_count $($grp.total_count): $((@($grp.runner_groups | ForEach-Object { "id=$($_.id) '$($_.name)' default=$($_.default)" })) -join ', ')"

if ($EvidenceOut) {
  $evidence | ConvertTo-Json -Depth 6 | Set-Content $EvidenceOut -Encoding utf8
  Write-Host "evidence written to $EvidenceOut (outside the repository)"
}
