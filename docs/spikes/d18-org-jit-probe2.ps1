#!/usr/bin/env pwsh
#
# D18 spike, round 2 — sharpen two facts that round 1 (d18-org-jit-spike.ps1)
# left as assertions rather than evidence:
#
#   A. Can a non-default, non-1 runner group exist at all on this organization?
#      Round 1 found the default group IS 1, so "what happens when the default
#      is not 1" could not be observed. Establish WHY, rather than asserting it.
#   B. Round 1's 201 carried exactly the 4 requested labels and NO implicit
#      `self-hosted`. That decides what `runs-on` must contain, so: is
#      `self-hosted` accepted as an explicit label, and what is the full shape
#      of the `runner` object c4 will deserialize?
#
# Throwaway exploratory code. Creates only runners and (if permitted) one runner
# group, and deletes everything it creates. Deletes no org, repo or App.
# Prints NO credential: no token, no encoded_jit_config. Lengths only.

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
$created = @()          # runner ids to delete
$createdGroup = $null   # runner group id to delete

function Note($step, $verdict, $detail) {
  $evidence[$step] = [ordered]@{ verdict = $verdict; detail = $detail }
  $c = switch ($verdict) { 'GREEN' { 'Green' } 'RED' { 'Red' } default { 'Yellow' } }
  Write-Host ("[{0,-26}] {1,-5} {2}" -f $step, $verdict, $detail) -ForegroundColor $c
}
function Call($method, $uri, $headers, $body) {
  $p = @{ Method = $method; Uri = $uri; Headers = $headers; SkipHttpErrorCheck = $true }
  if ($null -ne $body) { $p.Body = $body; $p.ContentType = 'application/json' }
  $r = Invoke-WebRequest @p
  $parsed = $null
  if ($r.Content) { try { $parsed = $r.Content | ConvertFrom-Json } catch { $parsed = $null } }
  [pscustomobject]@{ Status = [int]$r.StatusCode; Body = $parsed; Raw = $r.Content }
}
function SafeBody($resp, $max = 400) {
  if (-not $resp.Raw) { return '<empty body>' }
  $t = ($resp.Raw -replace '\s+', ' ').Trim()
  $t = $t -replace '(gh[usop]_[A-Za-z0-9]{4})[A-Za-z0-9_]+', '$1<REDACTED>'
  $t = $t -replace '("encoded_jit_config"\s*:\s*")[^"]+', '$1<REDACTED>'
  if ($t.Length -gt $max) { $t = $t.Substring(0, $max) + '…' }
  return $t
}

# ---------------------------------------------------------------- device flow
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
    if ($EvidenceOut) { $evidence | ConvertTo-Json -Depth 6 | Set-Content $EvidenceOut -Encoding utf8 }
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
    default {
      Note 'device-flow' 'RED' "terminal error: $($r.error)"
      if ($EvidenceOut) { $evidence | ConvertTo-Json -Depth 6 | Set-Content $EvidenceOut -Encoding utf8 }
      exit 2
    }
  }
}
Note 'device-flow' 'GREEN' "token family '$($userToken.Substring(0,4))'"
$gh = @{ Authorization = "Bearer $userToken"; Accept = 'application/vnd.github+json'; 'X-GitHub-Api-Version' = '2022-11-28' }

$jitUrl = "$API/orgs/$Org/actions/runners/generate-jitconfig"
$stamp = Get-Random -Maximum 9999

try {
  # ------------------------------------------------------------- probe A
  # Can a second runner group exist here? If not, "the default is always 1 on
  # this plan" stops being an assumption.
  Write-Host "`n=== PROBE A: can a non-default runner group be created? ===" -ForegroundColor Cyan
  $mk = Call POST "$API/orgs/$Org/actions/runner-groups" $gh `
    (@{ name = "rm-d18-probe-group-$stamp"; visibility = 'all' } | ConvertTo-Json -Compress)

  if ($mk.Status -eq 201) {
    $createdGroup = $mk.Body.id
    Note 'probeA-create-group' 'GREEN' "201 group id $createdGroup name '$($mk.Body.name)' default=$($mk.Body.default)"

    # The real question: does generate-jitconfig accept a group id that is
    # neither 1 nor the default?
    $g = Call POST $jitUrl $gh (@{
        name = "rm-d18-nondefault-$stamp"; runner_group_id = $createdGroup
        labels = @('rm-d18-spike', 'linux'); work_folder = '_work'
      } | ConvertTo-Json -Compress)
    if ($g.Status -eq 201) {
      $created += $g.Body.runner.id
      Note 'probeA-jit-nondefault-group' 'GREEN' "201 runner id $($g.Body.runner.id) runner_group_id $($g.Body.runner.runner_group_id) -- a NON-1, NON-default group id is usable"
    } else {
      Note 'probeA-jit-nondefault-group' 'RED' "$($g.Status) $(SafeBody $g)"
    }
  } else {
    Note 'probeA-create-group' 'AMBER' "$($mk.Status) $(SafeBody $mk 500) -- no second group can exist here, so group 1 is necessarily the default on this org/plan"
  }

  # ------------------------------------------------------------- probe B
  # Round 1: the 201 carried exactly the requested labels. Is `self-hosted`
  # accepted explicitly, and what is the full runner object shape?
  Write-Host "`n=== PROBE B: reserved label `self-hosted`, and the runner object shape ===" -ForegroundColor Cyan
  $b = Call POST $jitUrl $gh (@{
      name = "rm-d18-selfhosted-$stamp"; runner_group_id = 1
      labels = @('self-hosted', 'rm-d18-spike', 'Windows', 'X64'); work_folder = '_work'
    } | ConvertTo-Json -Compress)
  if ($b.Status -eq 201) {
    $created += $b.Body.runner.id
    $ls = @($b.Body.runner.labels | ForEach-Object { "$($_.name)/$($_.type)" })
    Note 'probeB-selfhosted-label' 'GREEN' "201 -- 'self-hosted' IS accepted explicitly; labels: $($ls -join ', ')"
    $shape = $b.Body.runner | Select-Object * -ExcludeProperty labels
    Note 'probeB-runner-object' 'GREEN' ("fields: " + (($shape.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' | '))
    Note 'probeB-top-level' 'GREEN' ("top-level keys: " + (($b.Body.PSObject.Properties.Name) -join ', ') + "; encoded_jit_config len $($b.Body.encoded_jit_config.Length) <redacted>")
  } else {
    Note 'probeB-selfhosted-label' 'AMBER' "$($b.Status) $(SafeBody $b 500) -- 'self-hosted' is NOT accepted as an explicit label"
  }

  # ------------------------------------------------------------- probe C
  # A single-label array, the degenerate case c4 will hit for a host-scoped runner.
  Write-Host "`n=== PROBE C: single-label array ===" -ForegroundColor Cyan
  $c = Call POST $jitUrl $gh (@{
      name = "rm-d18-single-$stamp"; runner_group_id = 1
      labels = @('rm-d18-spike'); work_folder = '_work'
    } | ConvertTo-Json -Compress)
  if ($c.Status -eq 201) {
    $created += $c.Body.runner.id
    Note 'probeC-single-label' 'GREEN' "201 runner id $($c.Body.runner.id), labels: $((@($c.Body.runner.labels | ForEach-Object { $_.name })) -join ', ')"
  } else {
    Note 'probeC-single-label' 'AMBER' "$($c.Status) $(SafeBody $c 300)"
  }

  # ------------------------------------------------------------- probe D
  # Empty label array — does the service default anything in?
  $d = Call POST $jitUrl $gh (@{
      name = "rm-d18-nolabels-$stamp"; runner_group_id = 1
      labels = @(); work_folder = '_work'
    } | ConvertTo-Json -Compress)
  if ($d.Status -eq 201) {
    $created += $d.Body.runner.id
    Note 'probeD-empty-labels' 'GREEN' "201 -- accepted; labels: $((@($d.Body.runner.labels | ForEach-Object { $_.name })) -join ', ')"
  } else {
    Note 'probeD-empty-labels' 'AMBER' "$($d.Status) $(SafeBody $d 300) -- at least one label is required"
  }
}
finally {
  # Delete ONLY what this probe created: runners, then the runner group.
  # No org, no repo, no App.
  Write-Host "`n=== cleanup ===" -ForegroundColor Cyan
  foreach ($id in $created) {
    $x = Call DELETE "$API/orgs/$Org/actions/runners/$id" $gh $null
    Note "cleanup-runner-$id" $(if ($x.Status -eq 204) { 'GREEN' } else { 'RED' }) "DELETE runner $id -> $($x.Status)"
  }
  if ($createdGroup) {
    $x = Call DELETE "$API/orgs/$Org/actions/runner-groups/$createdGroup" $gh $null
    Note "cleanup-group-$createdGroup" $(if ($x.Status -eq 204) { 'GREEN' } else { 'RED' }) "DELETE runner group $createdGroup -> $($x.Status)"
  }

  $after = Call GET "$API/orgs/$Org/actions/runners" $gh $null
  Note 'final-runners' $(if ($after.Status -eq 200 -and $after.Body.total_count -eq 0) { 'GREEN' } else { 'RED' }) `
    "$($after.Status) total_count $($after.Body.total_count)"
  $ag = Call GET "$API/orgs/$Org/actions/runner-groups" $gh $null
  Note 'final-groups' $(if ($ag.Status -eq 200) { 'GREEN' } else { 'AMBER' }) `
    "$($ag.Status) total_count $($ag.Body.total_count): $((@($ag.Body.runner_groups | ForEach-Object { "id=$($_.id) '$($_.name)'" })) -join ', ')"

  if ($EvidenceOut) {
    $evidence | ConvertTo-Json -Depth 6 | Set-Content $EvidenceOut -Encoding utf8
    Write-Host "evidence written to $EvidenceOut (outside the repository)"
  }
}
