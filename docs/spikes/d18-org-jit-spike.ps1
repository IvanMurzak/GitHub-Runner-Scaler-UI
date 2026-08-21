#!/usr/bin/env pwsh
#
# D18 spike — prove ORGANIZATION-scope `generate-jitconfig`.
#
# The D17 spike proved the *repository* form
# (`POST /repos/{owner}/{repo}/actions/runners/generate-jitconfig` -> 201) and
# explicitly did not reach the organization form. Everything D18 promises at
# organization scope rests on the untested assumption that `/orgs/` behaves like
# `/repos/`. This closes that assumption before c4 builds an org code path.
#
# Throwaway exploratory code. It is not the adapter.
#
#   pwsh ./docs/spikes/d18-org-jit-spike.ps1 -ClientId Iv23xxxxxxxx -Org myorg
#   pwsh ./docs/spikes/d18-org-jit-spike.ps1 -ClientId Iv23xxxxxxxx -Org myorg -DeviceCodeFile dc.json
#
# STOP-THE-LINE (inherited from c1): if the org call is denied, record the
# status and body and stop. No fallback to repository-scope registration inside
# the organization, no retry with a broader token, no substitute endpoint.
#
# Prints NO credential: no token, no encoded_jit_config. Lengths only.
# Deletes ONLY the ephemeral runner it creates. Deletes no org, repo or App.

[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string] $ClientId,
  [Parameter(Mandatory)] [string] $Org,          # disposable organization
  [string] $DeviceCodeFile,                      # reuse an already-printed device code
  [int]    $AuthTimeoutSeconds = 480,            # stop polling and report blocked
  [string] $EvidenceOut                          # written OUTSIDE the repo
)

$ErrorActionPreference = 'Stop'
$API = 'https://api.github.com'
$evidence = [ordered]@{}
$script:runnerId = $null
$script:gh = $null

function Note($step, $verdict, $detail) {
  $evidence[$step] = [ordered]@{ verdict = $verdict; detail = $detail }
  $c = switch ($verdict) { 'GREEN' { 'Green' } 'RED' { 'Red' } default { 'Yellow' } }
  Write-Host ("[{0,-28}] {1,-5} {2}" -f $step, $verdict, $detail) -ForegroundColor $c
}

# Invoke-RestMethod throws on non-2xx and hides the body. Every point this
# spike must record needs the exact status AND the exact body, including on
# failure -- so every call goes through here.
function Call($method, $uri, $headers, $body) {
  $p = @{ Method = $method; Uri = $uri; Headers = $headers; SkipHttpErrorCheck = $true }
  if ($null -ne $body) { $p.Body = $body; $p.ContentType = 'application/json' }
  $r = Invoke-WebRequest @p
  $parsed = $null
  if ($r.Content) { try { $parsed = $r.Content | ConvertFrom-Json } catch { $parsed = $null } }
  [pscustomobject]@{ Status = [int]$r.StatusCode; Body = $parsed; Raw = $r.Content }
}

# A body may legitimately be recorded in the write-up; a token never may.
function SafeBody($resp, $max = 400) {
  if (-not $resp.Raw) { return '<empty body>' }
  $t = ($resp.Raw -replace '\s+', ' ').Trim()
  $t = $t -replace '(gh[usop]_[A-Za-z0-9]{4})[A-Za-z0-9_]+', '$1<REDACTED>'
  $t = $t -replace '("encoded_jit_config"\s*:\s*")[^"]+', '$1<REDACTED>'
  if ($t.Length -gt $max) { $t = $t.Substring(0, $max) + '…' }
  return $t
}

# ---------------------------------------------------------------- link 1
# Device flow -- identical method to d17-spike.ps1. Public client_id only.
Write-Host "`n=== LINK 1: device flow ===" -ForegroundColor Cyan

if ($DeviceCodeFile -and (Test-Path $DeviceCodeFile)) {
  $dc = Get-Content $DeviceCodeFile -Raw | ConvertFrom-Json
  Write-Host "  reusing already-printed device code" -ForegroundColor DarkGray
} else {
  $dc = Invoke-RestMethod -Method Post -Uri 'https://github.com/login/device/code' `
    -Headers @{ Accept = 'application/json' } -Body @{ client_id = $ClientId }
  try { Set-Clipboard -Value $dc.user_code } catch {}
  try { Start-Process $dc.verification_uri | Out-Null } catch {}
}

Write-Host ""
Write-Host "  ==================================================" -ForegroundColor Yellow
Write-Host "     URL :  $($dc.verification_uri)"                  -ForegroundColor Yellow
Write-Host "     CODE:  $($dc.user_code)"                         -ForegroundColor Yellow
Write-Host "  ==================================================" -ForegroundColor Yellow
Write-Host ""

$interval = [Math]::Max([int]$dc.interval, 5)
$deadline = (Get-Date).AddSeconds($AuthTimeoutSeconds)
$seen = @{}; $tick = 0; $userToken = $null

while ($true) {
  if ((Get-Date) -gt $deadline) {
    Note 'link1-device-flow' 'RED' "no authorization within ${AuthTimeoutSeconds}s -- BLOCKED on the human step"
    Write-Host "`nBLOCKED: nobody entered the code. URL $($dc.verification_uri) CODE $($dc.user_code)" -ForegroundColor Red
    if ($EvidenceOut) { $evidence | ConvertTo-Json -Depth 6 | Set-Content $EvidenceOut -Encoding utf8 }
    exit 2
  }
  Start-Sleep -Seconds $interval
  $tick++
  if ($tick % 6 -eq 0) {
    $left = [int]($deadline - (Get-Date)).TotalSeconds
    Write-Host ("  waiting for approval… {0}:{1:d2} left  (CODE {2})" -f [int]($left / 60), ($left % 60), $dc.user_code) -ForegroundColor DarkGray
  }
  $r = Invoke-RestMethod -Method Post -Uri 'https://github.com/login/oauth/access_token' `
    -Headers @{ Accept = 'application/json' } -Body @{
      client_id = $ClientId; device_code = $dc.device_code
      grant_type = 'urn:ietf:params:oauth:grant-type:device_code'
    }
  if ($r.access_token) { $userToken = $r.access_token; break }
  $seen[$r.error] = $true
  switch ($r.error) {
    'authorization_pending' { }
    'slow_down' { $interval = [int]$r.interval; Write-Host "  slow_down -> ${interval}s" -ForegroundColor DarkGray }
    default {
      Note 'link1-device-flow' 'RED' "terminal error: $($r.error) -- $($r.error_description)"
      if ($EvidenceOut) { $evidence | ConvertTo-Json -Depth 6 | Set-Content $EvidenceOut -Encoding utf8 }
      exit 2
    }
  }
}

$family = $userToken.Substring(0, 4)
Note 'link1-device-flow' 'GREEN' "token family '$family' (ghu_ = App user-to-server), error states seen: $($seen.Keys -join ',')"
if ($family -ne 'ghu_') {
  Note 'link1-token-family' 'AMBER' "expected ghu_, got '$family' -- this is NOT an App user-to-server token"
}

$script:gh = @{
  Authorization          = "Bearer $userToken"
  Accept                 = 'application/vnd.github+json'
  'X-GitHub-Api-Version' = '2022-11-28'
}
$gh = $script:gh

# ---------------------------------------------------------------- link 0
# Baseline. Point 4 claims the org is "left with zero runners"; that claim is
# only meaningful against a known starting state.
Write-Host "`n=== LINK 2: organization baseline ===" -ForegroundColor Cyan
$who = Call GET "$API/user" $gh $null
Note 'link2-identity' $(if ($who.Status -eq 200) { 'GREEN' } else { 'RED' }) "$($who.Status) login '$($who.Body.login)'"

$pre = Call GET "$API/orgs/$Org/actions/runners" $gh $null
if ($pre.Status -eq 200) {
  Note 'link2-runners-before' $(if ($pre.Body.total_count -eq 0) { 'GREEN' } else { 'AMBER' }) `
    "$($pre.Status) total_count $($pre.Body.total_count)$(if ($pre.Body.total_count -gt 0) { ' -- PRE-EXISTING, will not be touched: ' + (($pre.Body.runners | ForEach-Object { "$($_.id):$($_.name)" }) -join ',') })"
} else {
  Note 'link2-runners-before' 'RED' "$($pre.Status) $(SafeBody $pre)"
}
$preExistingIds = @()
if ($pre.Status -eq 200 -and $pre.Body.runners) { $preExistingIds = @($pre.Body.runners | ForEach-Object { $_.id }) }

# ---------------------------------------------------------------- point 2
# "Which runner_group_id is usable at organization scope, and what the response
#  is when the default group is not 1." The repository call used group 1;
# nothing establishes that the organization default matches.
Write-Host "`n=== LINK 3: runner groups at organization scope (point 2) ===" -ForegroundColor Cyan
$grp = Call GET "$API/orgs/$Org/actions/runner-groups" $gh $null
$defaultGroupId = $null
if ($grp.Status -eq 200) {
  $rows = @($grp.Body.runner_groups | ForEach-Object { "id=$($_.id) name='$($_.name)' default=$($_.default) visibility=$($_.visibility)" })
  $def = @($grp.Body.runner_groups | Where-Object { $_.default })
  if ($def.Count -gt 0) { $defaultGroupId = $def[0].id }
  Note 'link3-runner-groups' 'GREEN' "$($grp.Status) total_count $($grp.Body.total_count); $($rows -join ' | '); default group id = $defaultGroupId"
} else {
  Note 'link3-runner-groups' 'AMBER' "$($grp.Status) $(SafeBody $grp) -- group enumeration unavailable; will probe group ids directly"
}

# ---------------------------------------------------------------- point 1+3
# The call under test. Multi-label, because routing after D4 is a label set.
Write-Host "`n=== LINK 4: POST /orgs/{org}/actions/runners/generate-jitconfig (points 1 + 3) ===" -ForegroundColor Cyan

$runnerName = "rm-d18-spike-$([Environment]::MachineName.ToLower())-$(Get-Random -Maximum 9999)"
$labels = @('rm-d18-spike', 'windows', 'x64', 'self-hosted-rm')
$groupToUse = if ($null -ne $defaultGroupId) { $defaultGroupId } else { 1 }

$jitBody = @{
  name            = $runnerName
  runner_group_id = $groupToUse
  labels          = $labels
  work_folder     = '_work'
} | ConvertTo-Json -Compress

Write-Host "  POST $API/orgs/$Org/actions/runners/generate-jitconfig" -ForegroundColor White
Write-Host "  body {`"name`":`"$runnerName`",`"runner_group_id`":$groupToUse,`"labels`":[$($labels -join ', ')],`"work_folder`":`"_work`"}" -ForegroundColor White

$jit = Call POST "$API/orgs/$Org/actions/runners/generate-jitconfig" $gh $jitBody

if ($jit.Status -eq 201) {
  $script:runnerId = $jit.Body.runner.id
  $gotLabels = @($jit.Body.runner.labels | ForEach-Object { "$($_.name)/$($_.type)" })
  Note 'link4-jitconfig-org' 'GREEN' "201 runner id $($script:runnerId) name '$($jit.Body.runner.name)' group_id $($jit.Body.runner.runner_group_id) busy=$($jit.Body.runner.busy) encoded_jit_config len $($jit.Body.encoded_jit_config.Length) <redacted>"
  Note 'link4-multilabel' $(if ($gotLabels.Count -ge $labels.Count) { 'GREEN' } else { 'AMBER' }) `
    "requested $($labels.Count) labels, response carries $($gotLabels.Count): $($gotLabels -join ', ')"
} else {
  Note 'link4-jitconfig-org' 'RED' "$($jit.Status) $(SafeBody $jit)"
  Write-Host "`nSTOP-THE-LINE: organization-scope generate-jitconfig was DENIED." -ForegroundColor Red
  Write-Host "  status $($jit.Status)" -ForegroundColor Red
  Write-Host "  body   $(SafeBody $jit 2000)" -ForegroundColor Red
  Write-Host "  Not working around it. D18's organization path is blocked pending an owner decision." -ForegroundColor Red
}

# ---------------------------------------------------------------- point 2b
# The differential: what the service says when the group id is NOT the usable
# one. Without this, "group N is usable" is an assertion, not a finding.
Write-Host "`n=== LINK 5: group-id differential (point 2) ===" -ForegroundColor Cyan
foreach ($probe in @(
    @{ label = 'nonexistent-group-99999'; gid = 99999 },
    @{ label = 'group-2'; gid = 2 },
    @{ label = 'group-1'; gid = 1 })) {
  if ($probe.gid -eq $groupToUse -and $jit.Status -eq 201) {
    Note "link5-$($probe.label)" 'GREEN' "same as the group used in link 4 (201); not re-probed"
    continue
  }
  $b = @{ name = "$runnerName-probe-$($probe.gid)"; runner_group_id = $probe.gid; labels = $labels; work_folder = '_work' } | ConvertTo-Json -Compress
  $p = Call POST "$API/orgs/$Org/actions/runners/generate-jitconfig" $gh $b
  if ($p.Status -eq 201) {
    # An unexpected success still creates a runner. Record it and delete it.
    Note "link5-$($probe.label)" 'GREEN' "201 runner id $($p.Body.runner.id) group_id $($p.Body.runner.runner_group_id) -- USABLE"
    $d = Call DELETE "$API/orgs/$Org/actions/runners/$($p.Body.runner.id)" $gh $null
    Note "link5-$($probe.label)-cleanup" $(if ($d.Status -eq 204) { 'GREEN' } else { 'RED' }) "DELETE -> $($d.Status)"
  } else {
    Note "link5-$($probe.label)" 'AMBER' "$($p.Status) $(SafeBody $p 240)"
  }
}

# Omitted runner_group_id: is the field required at org scope?
$bOmit = @{ name = "$runnerName-probe-omit"; labels = $labels; work_folder = '_work' } | ConvertTo-Json -Compress
$pOmit = Call POST "$API/orgs/$Org/actions/runners/generate-jitconfig" $gh $bOmit
if ($pOmit.Status -eq 201) {
  Note 'link5-group-omitted' 'GREEN' "201 runner id $($pOmit.Body.runner.id) group_id $($pOmit.Body.runner.runner_group_id) -- field is OPTIONAL, service picked a group"
  $d = Call DELETE "$API/orgs/$Org/actions/runners/$($pOmit.Body.runner.id)" $gh $null
  Note 'link5-group-omitted-cleanup' $(if ($d.Status -eq 204) { 'GREEN' } else { 'RED' }) "DELETE -> $($d.Status)"
} else {
  Note 'link5-group-omitted' 'AMBER' "$($pOmit.Status) $(SafeBody $pOmit 240) -- field is REQUIRED"
}

# ---------------------------------------------------------------- point 4
# Delete the runner and prove the organization ends with zero.
# ONLY the runner. No org, no repo, no App.
Write-Host "`n=== LINK 6: delete the ephemeral runner, prove zero remain (point 4) ===" -ForegroundColor Cyan
if ($script:runnerId) {
  $mid = Call GET "$API/orgs/$Org/actions/runners" $gh $null
  Note 'link6-runners-during' $(if ($mid.Status -eq 200) { 'GREEN' } else { 'RED' }) `
    "$($mid.Status) total_count $($mid.Body.total_count): $((@($mid.Body.runners | ForEach-Object { "$($_.id):$($_.name):$($_.status)" })) -join ', ')"

  $del = Call DELETE "$API/orgs/$Org/actions/runners/$($script:runnerId)" $gh $null
  Note 'link6-delete-runner' $(if ($del.Status -eq 204) { 'GREEN' } else { 'RED' }) "DELETE /orgs/$Org/actions/runners/$($script:runnerId) -> $($del.Status) $(if ($del.Status -ne 204) { SafeBody $del })"
} else {
  Note 'link6-delete-runner' 'AMBER' 'no runner was created; nothing to delete'
}

$post = Call GET "$API/orgs/$Org/actions/runners" $gh $null
if ($post.Status -eq 200) {
  $leftover = @($post.Body.runners | Where-Object { $preExistingIds -notcontains $_.id })
  Note 'link6-runners-after' $(if ($leftover.Count -eq 0) { 'GREEN' } else { 'RED' }) `
    "$($post.Status) total_count $($post.Body.total_count); runners created by this spike still present: $($leftover.Count)"
} else {
  Note 'link6-runners-after' 'RED' "$($post.Status) $(SafeBody $post)"
}

# ---------------------------------------------------------------- verdict
Write-Host "`n=== D18 organization-scope verdict ===" -ForegroundColor Cyan
if ($jit.Status -eq 201) {
  Write-Host "GREEN -- POST /orgs/{org}/actions/runners/generate-jitconfig returns 201." -ForegroundColor Green
} else {
  Write-Host "RED -- organization-scope generate-jitconfig returned $($jit.Status). D18's org path is BLOCKED." -ForegroundColor Red
}

if ($EvidenceOut) {
  $evidence | ConvertTo-Json -Depth 6 | Set-Content $EvidenceOut -Encoding utf8
  Write-Host "evidence written to $EvidenceOut (outside the repository)"
}
