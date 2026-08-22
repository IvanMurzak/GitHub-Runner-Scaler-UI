#!/usr/bin/env pwsh
#
# D18b probe -- does `total_count` on the workflow-runs list endpoint count the
# rows MATCHING THE QUERY, or the repository's total run count?
#
# `c3-rest-inventory-gateway` landed an in-progress activity count that issues
# ONE request per refresh and reads `total_count` from
#
#     GET /repos/{owner}/{repo}/actions/runs?status=in_progress
#
# Nothing had ever called that endpoint. Its unit fixtures assert the
# assumption (they return a non-zero `total_count` beside an EMPTY
# `workflow_runs` array), so no test could ever have caught the assumption
# being wrong. `e1` allocates runner capacity from this number, so an inflated
# count means starting runners for jobs that do not exist.
#
# Throwaway exploratory code. It is not the adapter.
#
#   pwsh ./docs/spikes/d18b-run-count-probe.ps1
#   pwsh ./docs/spikes/d18b-run-count-probe.ps1 -Repo owner/name -PrivateRepo owner/other
#
# READ-ONLY. Every call is a GET. It creates nothing and deletes nothing: no
# runners, no workflow runs, no repositories, no organizations, no Apps.
#
# CREDENTIAL: none is required. The default fixture is a PUBLIC repository, and
# `GET /repos/{o}/{r}/actions/runs` is readable unauthenticated, so the decisive
# evidence is reproducible by anyone with no token at all. Supply -Token only to
# repeat the same probe authenticated, or to reach a private -PrivateRepo.
#
# Prints NO credential. The token is never echoed and never written to disk.

[CmdletBinding()]
param(
  [string] $Repo = 'IvanMurzak/GitHub-Runner-Scaler-UI',  # public; needs no token
  [string] $PrivateRepo,                                  # optional; needs -Token
  [string] $Token,                                        # optional
  [string] $EvidenceOut                                   # written OUTSIDE the repo
)

$ErrorActionPreference = 'Stop'
$API = 'https://api.github.com'
$evidence = [ordered]@{}

$H = @{
  Accept                 = 'application/vnd.github+json'
  'X-GitHub-Api-Version' = '2022-11-28'
  'User-Agent'           = 'd18b-run-count-probe'
}
if ($Token) { $H['Authorization'] = "Bearer $Token" }

function Note($step, $verdict, $detail) {
  $evidence[$step] = [ordered]@{ verdict = $verdict; detail = $detail }
  $c = switch ($verdict) { 'GREEN' { 'Green' } 'RED' { 'Red' } default { 'Yellow' } }
  Write-Host ("[{0,-30}] {1,-5} {2}" -f $step, $verdict, $detail) -ForegroundColor $c
}

# Invoke-RestMethod throws on non-2xx and hides the body. Every point this probe
# must record needs the exact status AND the decisive fields, including on
# failure -- so every call goes through here.
function Runs($repo, $query) {
  $uri = "$API/repos/$repo/actions/runs"
  if ($query) { $uri = "$uri`?$query" }
  $r = Invoke-WebRequest -Uri $uri -Headers $H -SkipHttpErrorCheck
  $b = $null
  if ($r.Content) { try { $b = $r.Content | ConvertFrom-Json } catch { $b = $null } }
  $len = if ($null -ne $b -and $null -ne $b.workflow_runs) { @($b.workflow_runs).Count } else { $null }
  [pscustomobject]@{
    Query   = $(if ($query) { $query } else { '<none>' })
    Status  = [int]$r.StatusCode
    Total   = $(if ($null -ne $b) { $b.total_count } else { $null })
    Len     = $len
  }
}

function Show($label, $x) {
  Write-Host ("  {0,-34} status={1} total_count={2,-6} workflow_runs.len={3}" -f `
    $label, $x.Status, $x.Total, $x.Len)
}

Write-Host "`n=== fixture: $Repo ===" -ForegroundColor Cyan

# --------------------------------------------------------------- point 1
# The filtered total_count, against BOTH the returned array length AND the
# repository's unfiltered total. If the filtered total_count equals the
# unfiltered total, the assumption is disproved.
Write-Host "`n--- POINT 1: filtered total_count vs array length vs unfiltered total ---"
$unfiltered = Runs $Repo $null
$inProgress = Runs $Repo 'status=in_progress'
Show 'unfiltered'         $unfiltered
Show 'status=in_progress' $inProgress

if ($unfiltered.Status -ne 200 -or $inProgress.Status -ne 200) {
  Note 'point1' 'RED' "non-200: unfiltered $($unfiltered.Status), filtered $($inProgress.Status)"
} elseif ($inProgress.Total -eq $unfiltered.Total -and $unfiltered.Total -gt 0) {
  Note 'point1' 'RED' "filtered total_count $($inProgress.Total) EQUALS unfiltered $($unfiltered.Total) -- total_count is NOT filtered"
} elseif ($inProgress.Total -eq $inProgress.Len) {
  Note 'point1' 'GREEN' "filtered total_count $($inProgress.Total) == array len $($inProgress.Len), and differs from unfiltered $($unfiltered.Total)"
} else {
  # Legitimate when the filtered set is larger than one page.
  Note 'point1' 'GREEN' "filtered total_count $($inProgress.Total) differs from unfiltered $($unfiltered.Total); array len $($inProgress.Len) is the page size, not the count"
}

# --------------------------------------------------------------- point 2
# A filter certain to match nothing. total_count 0 beside an empty array is
# strong evidence; a NON-ZERO total_count beside an empty array is the disproof,
# and is precisely the shape c3's own fixtures fabricate.
Write-Host "`n--- POINT 2: a filter that matches nothing ---"
$empty = $null
foreach ($probe in @('status=failure', 'status=cancelled', 'status=queued', 'status=in_progress')) {
  $x = Runs $Repo $probe
  Show $probe $x
  if ($x.Status -eq 200 -and $x.Len -eq 0) { $empty = $x; break }
}
if ($null -eq $empty) {
  Note 'point2' 'AMBER' 'no filter on this fixture returned an empty array -- point 2 not exercised here'
} elseif ($empty.Total -eq 0) {
  Note 'point2' 'GREEN' "$($empty.Query): empty array AND total_count 0, while the repository holds $($unfiltered.Total) runs"
} else {
  Note 'point2' 'RED' "$($empty.Query): EMPTY array but total_count $($empty.Total) -- total_count is not the matching count"
}

# --------------------------------------------------------------- point 3
# c3 sends `per_page=100` (PER_PAGE) alongside the filter, so whether
# total_count survives pagination is load-bearing for it specifically.
Write-Host "`n--- POINT 3: does pagination change total_count? ---"
$base = Runs $Repo 'status=completed'
$pp1  = Runs $Repo 'status=completed&per_page=1'
$pp100= Runs $Repo 'status=completed&per_page=100'
$page2= Runs $Repo 'status=completed&per_page=1&page=2'
Show 'completed'                 $base
Show 'completed&per_page=1'      $pp1
Show 'completed&per_page=100'    $pp100
Show 'completed&per_page=1&page=2' $page2

$totals = @($base.Total, $pp1.Total, $pp100.Total, $page2.Total) | Sort-Object -Unique
if ($totals.Count -eq 1) {
  Note 'point3' 'GREEN' "total_count is invariant under per_page and page: $($totals[0]) in all four; per_page=1 returned len $($pp1.Len)"
} else {
  Note 'point3' 'AMBER' "total_count varied across pagination: $($totals -join ', ') -- may be live churn on the fixture, re-run"
}

# --------------------------------------------------------------- partition
# The strongest single check: if total_count is the MATCHING count, disjoint
# filters must sum to the whole. If it were the repository total, every filter
# would report the same number.
Write-Host "`n--- PARTITION: do disjoint filters sum to the whole? ---"
$succ = Runs $Repo 'status=success'
$fail = Runs $Repo 'status=failure'
$canc = Runs $Repo 'status=cancelled'
Show 'status=success'   $succ
Show 'status=failure'   $fail
Show 'status=cancelled' $canc
$sum = [int]$succ.Total + [int]$fail.Total + [int]$canc.Total
Write-Host ("  success {0} + failure {1} + cancelled {2} = {3}   (completed reports {4})" -f `
  $succ.Total, $fail.Total, $canc.Total, $sum, $base.Total)
if ($sum -eq [int]$base.Total) {
  Note 'partition' 'GREEN' "the three conclusions partition the completed set exactly ($sum)"
} else {
  Note 'partition' 'AMBER' "sum $sum != completed $($base.Total) -- live churn between calls, or a conclusion not probed"
}

# --------------------------------------------------------------- at scale
if ($PrivateRepo) {
  Write-Host "`n=== at-scale cross-check: $PrivateRepo ===" -ForegroundColor Cyan
  $pu = Runs $PrivateRepo $null
  $pi = Runs $PrivateRepo 'status=in_progress'
  Show 'unfiltered'         $pu
  Show 'status=in_progress' $pi
  if ($pu.Status -eq 200 -and $pi.Status -eq 200) {
    if ($pi.Total -eq 0 -and $pu.Total -gt 0) {
      Note 'at-scale' 'GREEN' "in_progress total_count 0 on a repository holding $($pu.Total) runs -- an unfiltered total_count would have said $($pu.Total)"
    } elseif ($pi.Total -eq $pu.Total -and $pu.Total -gt 0) {
      Note 'at-scale' 'RED' "in_progress total_count $($pi.Total) EQUALS the repository total"
    } else {
      Note 'at-scale' 'GREEN' "in_progress total_count $($pi.Total) vs repository total $($pu.Total)"
    }
  } else {
    Note 'at-scale' 'AMBER' "unfiltered $($pu.Status), filtered $($pi.Status) -- not readable with this credential"
  }
}

# --------------------------------------------------------------- verdict
Write-Host "`n=== VERDICT ===" -ForegroundColor Cyan
$reds = @($evidence.Keys | Where-Object { $evidence[$_].verdict -eq 'RED' })
if ($reds.Count -gt 0) {
  Write-Host "RED -- total_count is NOT the filtered count. STOP: c3's activity count is wrong." -ForegroundColor Red
  Write-Host "       Failing points: $($reds -join ', ')" -ForegroundColor Red
  Write-Host "       Do not work around this. The design decision is the owner's." -ForegroundColor Red
} else {
  Write-Host "GREEN -- total_count is the count MATCHING THE QUERY." -ForegroundColor Green
  Write-Host "        c3's one-request-per-refresh activity count reads the right number." -ForegroundColor Green
}

if ($EvidenceOut) { $evidence | ConvertTo-Json -Depth 6 | Set-Content $EvidenceOut -Encoding utf8 }
