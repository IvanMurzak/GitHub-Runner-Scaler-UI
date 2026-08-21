#!/usr/bin/env pwsh
#
# D17 spike — prove a GitHub App *user-to-server* token drives the full
# Actions-service scale-set chain.
#
# Throwaway exploratory code. It is not the adapter; c4/c5 implement the real
# thing informed by what this learns. See d17-user-to-server-scale-set-chain.md.
#
#   pwsh ./docs/spikes/d17-spike.ps1 -ClientId Iv23xxxxxxxx -Repo owner/repo
#   pwsh ./docs/spikes/d17-spike.ps1 -ClientId Iv23xxxxxxxx -Repo owner/repo -Org myorg
#
# Prints NO credential. Cleans up the scale set and session it creates.

[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string] $ClientId,
  [Parameter(Mandatory)] [string] $Repo,      # owner/repo, disposable
  [string] $Org,                              # optional, disposable
  [string] $ScaleSetName,                     # fix the name to pre-wire a workflow's runs-on
  [int]    $MaxCapacity = 1,
  [int]    $PollSeconds = 30                  # long-poll wait for a queued job
)

$ErrorActionPreference = 'Stop'
$API = 'https://api.github.com'
$AV  = '6.0-preview'
$evidence = [ordered]@{}
$script:scaleSetId = $null
$script:sessionId  = $null
$script:tenant     = $null
$script:admin      = $null

function Note($link, $verdict, $detail) {
  $evidence[$link] = [ordered]@{ verdict = $verdict; detail = $detail }
  $c = if ($verdict -eq 'GREEN') { 'Green' } elseif ($verdict -eq 'RED') { 'Red' } else { 'Yellow' }
  Write-Host ("[{0,-22}] {1,-5} {2}" -f $link, $verdict, $detail) -ForegroundColor $c
}
function Claims($jwt) {
  $p = $jwt.Split('.')[1].Replace('-', '+').Replace('_', '/')
  $p += '=' * ((4 - $p.Length % 4) % 4)
  [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
}

# ---------------------------------------------------------------- link 1
# Device flow. Public client_id only: no secret, no redirect, no server.
Write-Host "`n=== LINK 1: device flow ===" -ForegroundColor Cyan
$dc = Invoke-RestMethod -Method Post -Uri 'https://github.com/login/device/code' `
  -Headers @{ Accept = 'application/json' } -Body @{ client_id = $ClientId }

$interval = [int]$dc.interval; $deadline = (Get-Date).AddSeconds([int]$dc.expires_in)

# The browser step is the one thing that cannot be automated -- it is the whole
# point of the device grant. Everything around it can be, so: copy the code,
# open the page, and show a live countdown instead of an inert prompt.
try { Set-Clipboard -Value $dc.user_code; $clip = ' (copied to clipboard)' } catch { $clip = '' }
try { Start-Process $dc.verification_uri | Out-Null; $opened = 'opened in your browser' } catch { $opened = $dc.verification_uri }

Write-Host ""
Write-Host "  ┌─────────────────────────────┐" -ForegroundColor DarkGray
Write-Host "  │   CODE:  $($dc.user_code)        │" -ForegroundColor Yellow
Write-Host "  └─────────────────────────────┘$clip" -ForegroundColor DarkGray
Write-Host "  $opened  ·  expires $($deadline.ToString('HH:mm:ss'))" -ForegroundColor White
Write-Host ""

$seen = @{}; $tick = 0
while ($true) {
  if ((Get-Date) -gt $deadline) { Note 'link1-device-flow' 'RED' 'device code expired before approval'; break }
  Start-Sleep -Seconds $interval
  $tick++
  if ($tick % 6 -eq 0) {
    $left = [int]($deadline - (Get-Date)).TotalSeconds
    Write-Host ("  waiting for approval… {0}:{1:d2} left" -f [int]($left/60), ($left%60)) -ForegroundColor DarkGray
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
    'slow_down'             { $interval = [int]$r.interval; Write-Host "  slow_down -> interval ${interval}s" -ForegroundColor DarkGray }
    default { Note 'link1-device-flow' 'RED' "terminal error: $($r.error)"; throw "device flow: $($r.error)" }
  }
}
$family = $userToken.Substring(0, 4)
Note 'link1-device-flow' 'GREEN' "token family '$family' (ghu_ = App user-to-server), error states seen: $($seen.Keys -join ',')"
if ($family -ne 'ghu_') {
  Note 'link1-token-family' 'AMBER' "expected ghu_, got '$family' — this is NOT an App user-to-server token; D17 is not being tested"
}

$gh = @{ Authorization = "Bearer $userToken"; Accept = 'application/vnd.github+json'; 'X-GitHub-Api-Version' = '2022-11-28' }

# ---------------------------------------------------------------- link 2/3
function Chain($scopeName, $regUrl, $configUrl) {
  # link 2 — mint a runner registration token with the user-to-server token
  try {
    $rt = (Invoke-RestMethod -Method Post -Uri $regUrl -Headers $gh).token
    Note "link2-regtoken-$scopeName" 'GREEN' "registration token minted (len $($rt.Length))"
  } catch {
    Note "link2-regtoken-$scopeName" 'RED' "$($_.Exception.Response.StatusCode.value__) $($_.ErrorDetails.Message)"
    return $null
  }
  # link 3 — exchange it for an Actions-service admin token + tenant URL
  try {
    $conn = Invoke-RestMethod -Method Post -Uri "$API/actions/runner-registration" `
      -Headers @{ Authorization = "RemoteAuth $rt"; Accept = 'application/json' } `
      -ContentType 'application/json' `
      -Body (@{ url = $configUrl; runner_event = 'register' } | ConvertTo-Json -Compress)
    $cl = Claims $conn.token
    Note "link3-admin-$scopeName" 'GREEN' "tenant $($conn.url -replace '/[^/]+/$','/…/'), schema $($conn.token_schema), scp '$($cl.scp)', ttl $([math]::Round(($cl.exp-$cl.nbf)/60,1))min"
    return $conn
  } catch {
    Note "link3-admin-$scopeName" 'RED' "$($_.Exception.Response.StatusCode.value__) $($_.ErrorDetails.Message)"
    return $null
  }
}

Write-Host "`n=== LINKS 2-3: registration token -> Actions-service admin token ===" -ForegroundColor Cyan
$owner, $name = $Repo.Split('/')
$repoConn = Chain 'repo' "$API/repos/$Repo/actions/runners/registration-token" "https://github.com/$Repo"
if ($Org) { $orgConn = Chain 'org' "$API/orgs/$Org/actions/runners/registration-token" "https://github.com/$Org" }
else      { Note 'link2-3-org' 'AMBER' 'no -Org supplied; organization scope (D18) NOT tested' }

if (-not $repoConn -and -not $orgConn) { Write-Host "`nBoth chains broken; stopping." -ForegroundColor Red; $evidence | ConvertTo-Json -Depth 6; exit 1 }

# Links 4-6 run against the ORG connection whenever one is available.
# Repository scope is already known to fail scale-set creation here, so
# pointing these links at the repo again would test nothing.
if ($orgConn) {
  $use = $orgConn; $scope = 'org'
  $script:regUrl = "$API/orgs/$Org/actions/runners/registration-token"
  $script:cfgUrl = "https://github.com/$Org"
} else {
  $use = $repoConn; $scope = 'repo'
  $script:regUrl = "$API/repos/$Repo/actions/runners/registration-token"
  $script:cfgUrl = "https://github.com/$Repo"
}
$script:tenant = $use.url; $script:admin = $use.token
$svc = @{ Authorization = "Bearer $($script:admin)"; Accept = 'application/json' }
Write-Host "`n  links 4-6 run at '$scope' scope against $($script:cfgUrl)" -ForegroundColor White

try {
  # -------------------------------------------------------------- link 4
  Write-Host "`n=== LINK 4: scale set administration + message session ===" -ForegroundColor Cyan
  $setName = if ($ScaleSetName) { $ScaleSetName } else { "rm-d17-spike-$([Environment]::MachineName.ToLower())" }
  $body = @{
    name = $setName; runnerGroupId = 1
    labels = @(@{ name = $setName; type = 'System' })
    RunnerSetting = @{ ephemeral = $true; isElastic = $true }
  } | ConvertTo-Json -Depth 5 -Compress

  $ss = Invoke-RestMethod -Method Post -Uri "$($script:tenant)_apis/runtime/runnerscalesets?api-version=$AV" `
    -Headers $svc -ContentType 'application/json' -Body $body
  $script:scaleSetId = $ss.id
  Note "link4-scaleset-create-$scope" 'GREEN' "id $($ss.id) name '$($ss.name)' group '$($ss.runnerGroupName)'"

  $sess = Invoke-RestMethod -Method Post -Uri "$($script:tenant)_apis/runtime/runnerscalesets/$($ss.id)/sessions?api-version=$AV" `
    -Headers $svc -ContentType 'application/json' `
    -Body (@{ ownerName = "d17-spike-$([Environment]::MachineName)" } | ConvertTo-Json -Compress)
  $script:sessionId = $sess.sessionId
  $mqToken = $sess.messageQueueAccessToken
  Note "link4-session-create-$scope" 'GREEN' "session $($sess.sessionId), queue token len $($mqToken.Length)"

  # -------------------------------------------------------------- link 5
  Write-Host "`n=== LINK 5: long poll -> demand -> AcquireJobs ===" -ForegroundColor Cyan
  Write-Host "  Queue a job now with:  runs-on: $setName" -ForegroundColor Yellow
  Write-Host "  Waiting ${PollSeconds}s ..." -ForegroundColor DarkGray

  $mq = @{ Authorization = "Bearer $mqToken"; Accept = 'application/json'; 'X-ScaleSetMaxCapacity' = "$MaxCapacity" }
  $uri = "$($sess.messageQueueUrl)"
  $msg = $null
  try {
    $msg = Invoke-RestMethod -Method Get -Uri $uri -Headers $mq -TimeoutSec $PollSeconds
  } catch {
    if ($_.Exception.Message -match 'timed out|timeout') { Note "link5-longpoll-$scope" 'AMBER' 'no message within the wait window (no job queued?)' }
    else { throw }
  }

  if ($msg) {
    $stats = $msg.statistics
    Note "link5-longpoll-$scope" 'GREEN' "messageId $($msg.messageId), totalAssignedJobs $($stats.totalAssignedJobs), jobAvailable $($msg.jobAvailableMessages.Count)"

    if ($msg.jobAvailableMessages.Count -gt 0) {
      $ids = @($msg.jobAvailableMessages | ForEach-Object { $_.runnerRequestId })
      $acq = Invoke-RestMethod -Method Post -Uri "$($script:tenant)_apis/runtime/runnerscalesets/$($ss.id)/acquirejobs?api-version=$AV" `
        -Headers @{ Authorization = "Bearer $mqToken"; Accept = 'application/json' } `
        -ContentType 'application/json' -Body ($ids | ConvertTo-Json -AsArray -Compress)
      Note "link5-acquirejobs-$scope" 'GREEN' "acquired $($acq.count) of $($ids.Count)"
    } else {
      Note "link5-acquirejobs-$scope" 'AMBER' 'no JobAvailable message to acquire'
    }

    # The queue URL carries a query string, so the message id goes on the PATH.
    # "$uri/$id" would produce "...?api-version=6.0-preview/42" and 404.
    $del = [UriBuilder]$uri; $del.Path = "$($del.Path)/$($msg.messageId)"
    Invoke-RestMethod -Method Delete -Uri $del.Uri.AbsoluteUri -Headers $mq | Out-Null
    Note "link5-deletemessage-$scope" 'GREEN' "acknowledged messageId $($msg.messageId)"
  }

  # -------------------------------------------------------------- link 6
  Write-Host "`n=== LINK 6: generatejitconfig ===" -ForegroundColor Cyan
  $jit = Invoke-RestMethod -Method Post -Uri "$($script:tenant)_apis/runtime/runnerscalesets/$($ss.id)/generatejitconfig?api-version=$AV" `
    -Headers $svc -ContentType 'application/json' `
    -Body (@{ name = "$setName-0"; workFolder = '_work' } | ConvertTo-Json -Compress)
  Note "link6-generatejitconfig-$scope" 'GREEN' "runner id $($jit.runner.id) name '$($jit.runner.name)', encodedJITConfig len $($jit.encodedJITConfig.Length) <redacted>"
}
finally {
  Write-Host "`n=== cleanup ===" -ForegroundColor Cyan
  # The admin JWT lives 20 minutes. A run that waited on the long poll can
  # outlive it, and an expired token here would strand a scale set on the
  # repository — so re-mint the chain before deleting anything.
  try {
    $rt2 = (Invoke-RestMethod -Method Post -Headers $gh -Uri $script:regUrl).token
    $c2 = Invoke-RestMethod -Method Post -Uri "$API/actions/runner-registration" `
      -Headers @{ Authorization = "RemoteAuth $rt2"; Accept = 'application/json' } `
      -ContentType 'application/json' `
      -Body (@{ url = $script:cfgUrl; runner_event = 'register' } | ConvertTo-Json -Compress)
    $svc = @{ Authorization = "Bearer $($c2.token)"; Accept = 'application/json' }
    $script:tenant = $c2.url
  } catch { Write-Host "  admin re-mint failed, using original token: $($_.Exception.Message)" -ForegroundColor DarkYellow }

  if ($script:sessionId -and $script:scaleSetId) {
    try { Invoke-RestMethod -Method Delete -Headers $svc -Uri "$($script:tenant)_apis/runtime/runnerscalesets/$($script:scaleSetId)/sessions/$($script:sessionId)?api-version=$AV" | Out-Null
          Write-Host "  session deleted" } catch { Write-Host "  session delete failed: $($_.Exception.Message)" -ForegroundColor Red }
  }
  if ($script:scaleSetId) {
    try { Invoke-RestMethod -Method Delete -Headers $svc -Uri "$($script:tenant)_apis/runtime/runnerscalesets/$($script:scaleSetId)?api-version=$AV" | Out-Null
          Write-Host "  scale set deleted" }
    catch { Write-Host "  scale set delete FAILED: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "  delete it by hand: scale set id $($script:scaleSetId) on $Repo" -ForegroundColor Red }
  }
}

Write-Host "`n=== D17 verdict ===" -ForegroundColor Cyan
$red   = @($evidence.GetEnumerator() | Where-Object { $_.Value.verdict -eq 'RED' })
$amber = @($evidence.GetEnumerator() | Where-Object { $_.Value.verdict -eq 'AMBER' })
if     ($red.Count)   { Write-Host "RED — D3 is reopened. Failing links: $($red.Name -join ', ')" -ForegroundColor Red }
elseif ($amber.Count) { Write-Host "PARTIAL — untested: $($amber.Name -join ', ')" -ForegroundColor Yellow }
else                  { Write-Host "GREEN — D3 holds at both scopes." -ForegroundColor Green }

$out = Join-Path $PSScriptRoot 'd17-evidence.json'
$evidence | ConvertTo-Json -Depth 6 | Set-Content $out -Encoding utf8
Write-Host "evidence written to $out"
