<#
.SYNOPSIS
  READ-ONLY. Searches a GitHub organization's code for this week's supply-chain indicators,
  driven by the same watchlist as the Windows hunt. Changes nothing.

.DESCRIPTION
  Several of this week's attacks live in source control, not on a laptop: fake workflow files
  that steal Actions secrets, repositories that pinned a backdoored package release, and
  references to lookalike repositories. This script runs every GitHub entry in a watchlist
  against one organization using GitHub code search.

  Check types a watchlist can use:
    WorkflowFile   Finds workflow files by name under .github/workflows.
    CodeSearch     Finds any file containing an exact string, such as a pinned bad version.

  Two ways to look:
    Tree (default)  Walks every repository's default branch, lists its workflow files and reads
                    its dependency files (requirements, pyproject, Pipfile, lock files, package.json,
                    Dockerfiles, workflow YAML). Reliable, and slower on large organizations.
    Search          Uses GitHub code search. Fast, but GitHub does not index every repository,
                    so new, small or rarely changed repositories can be silently missed.

  Both read default branches only. A clean result means "not on the default branch now", not
  "never present". For a repository with a hit, also review its Actions run history and the
  organization audit log.

.PARAMETER Org
  The GitHub organization (or user) to search.

.PARAMETER Watchlist
  Path to a watchlist .psd1. Default: the newest file in ..\..\watchlists next to this script.

.PARAMETER Method
  Tree (default) or Search. See the description.

.REQUIREMENTS
  PowerShell 7. A GitHub token that can read the organization's repositories, taken from the
  GITHUB_TOKEN environment variable or from the GitHub CLI (gh auth login). A fine-grained
  token with read-only Contents access is enough.

.EXAMPLE
  pwsh -NoProfile -File .\scripts\github\Find-GitHubSupplyChainIndicators.ps1 -Org contoso
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Org,
    [string] $Watchlist,
    [ValidateSet('Tree', 'Search')] [string] $Method = 'Tree'
)
$ErrorActionPreference = 'Stop'
$script:Findings = 0
function Red    ([string]$m) { $script:Findings++; Write-Host "[RED] $m" -ForegroundColor Red }
function Yellow ([string]$m) { Write-Host "[YELLOW] $m" -ForegroundColor Yellow }
function Plain  ([string]$m) { Write-Host "  $m" }
function Section([string]$t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }

if (-not $Watchlist) {
    $Watchlist = (Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '..\..\watchlists') -Filter '*.psd1' | Sort-Object Name -Descending | Select-Object -First 1).FullName
}
$wl = Import-PowerShellDataFile -LiteralPath $Watchlist
if (-not $wl.GitHub) { Write-Host "Watchlist $(Split-Path $Watchlist -Leaf) has no GitHub entries." ; exit 0 }

$token = $env:GITHUB_TOKEN
if (-not $token -and (Get-Command gh -ErrorAction SilentlyContinue)) { $token = (gh auth token 2>$null) }
if (-not $token) { Write-Host 'No GitHub token. Set GITHUB_TOKEN or run gh auth login.' -ForegroundColor Red; exit 1 }
$headers = @{ Authorization = "Bearer $token"; Accept = 'application/vnd.github+json'; 'X-GitHub-Api-Version' = '2022-11-28' }

function Search-Code([string]$q) {
    $items = @(); $page = 1
    do {
        $uri = "https://api.github.com/search/code?q=$([uri]::EscapeDataString($q))&per_page=100&page=$page"
        try { $r = Invoke-RestMethod -Uri $uri -Headers $headers }
        catch {
            if ($_.Exception.Response.StatusCode.value__ -in 403, 429) { Start-Sleep -Seconds 65; continue }
            throw
        }
        $items += $r.items; $page++
        Start-Sleep -Seconds 7   # code search allows about 10 requests a minute
    } while ($items.Count -lt $r.total_count -and $page -le 10)
    return $items
}

function Get-Api([string]$path) {
    try { return Invoke-RestMethod -Uri "https://api.github.com/$path" -Headers $headers -FollowRelLink }
    catch { return $null }
}

# Tree method: collect each repository's workflow names and dependency file text once.
$manifest = '(^|/)(requirements[^/]*\.txt|pyproject\.toml|Pipfile(\.lock)?|setup\.(py|cfg)|poetry\.lock|uv\.lock|package(-lock)?\.json|pnpm-lock\.yaml|yarn\.lock|Dockerfile[^/]*|docker-compose[^/]*\.ya?ml|compose\.ya?ml)$|^\.github/workflows/[^/]+\.ya?ml$'
$repoData = @()
if ($Method -eq 'Tree') {
    # Organizations list private repos to members; a user's own private repos need /user/repos.
    $me = (Get-Api 'user').login
    $list = if (Get-Api "orgs/$Org") { "orgs/$Org/repos?per_page=100&type=all" }
            elseif ($me -eq $Org) { 'user/repos?per_page=100&affiliation=owner' }
            else { "users/$Org/repos?per_page=100&type=all" }
    $repos = @(Get-Api $list | ForEach-Object { $_ } | Where-Object { -not $_.archived -and $_.size -gt 0 })
    Write-Host ("Reading {0} repositories in {1}." -f $repos.Count, $Org)
    foreach ($r in $repos) {
        $tree = Get-Api "repos/$($r.full_name)/git/trees/$($r.default_branch)?recursive=1"
        if (-not $tree) { Yellow "$($r.full_name): could not read the file tree. Check it by hand."; continue }
        if ($tree.truncated) { Yellow "$($r.full_name): file tree too large to read fully. Use -Method Search for this one." }
        $files = @($tree.tree | Where-Object { $_.type -eq 'blob' -and $_.path -match $manifest -and $_.size -lt 2MB })
        $text = @{}
        foreach ($f in $files) {
            $blob = Get-Api "repos/$($r.full_name)/git/blobs/$($f.sha)"
            if ($blob.content) { $text[$f.path] = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($blob.content -replace '\s', ''))) }
        }
        $repoData += [pscustomobject]@{ Name = $r.full_name; Workflows = @($tree.tree | Where-Object { $_.path -like '.github/workflows/*' } | ForEach-Object { $_.path }); Text = $text }
    }
}

Write-Host ("Watchlist: {0}. Organization: {1}. Method: {2}." -f $wl.Name, $Org, $Method) -ForegroundColor Cyan
foreach ($c in @($wl.GitHub)) {
    Section $c.Title
    $hits = @()
    if ($Method -eq 'Search') {
        switch ($c.Type) {
            'WorkflowFile' { foreach ($f in $c.FileNames) { $hits += Search-Code "filename:$f path:.github/workflows org:$Org" } }
            'CodeSearch'   { $hits += Search-Code "$($c.Query) org:$Org" }
        }
    } else {
        $needle = $c.Query -replace '^"|"$', ''
        foreach ($rd in $repoData) {
            switch ($c.Type) {
                'WorkflowFile' { foreach ($w in $rd.Workflows) { if ((Split-Path $w -Leaf) -in $c.FileNames) { $hits += [pscustomobject]@{ repository = @{ full_name = $rd.Name }; path = $w } } } }
                'CodeSearch'   { foreach ($k in $rd.Text.Keys) { if ($rd.Text[$k].Contains($needle)) { $hits += [pscustomobject]@{ repository = @{ full_name = $rd.Name }; path = $k } } } }
            }
        }
    }
    # Watchlists that list these indicators would match themselves; skip them.
    $hits = @($hits | Where-Object { $_.path -notmatch '(^|/)watchlists/[^/]+\.psd1$' })
    foreach ($h in $hits) { Red "$($h.repository.full_name): $($h.path). $($c.Advice)" }
    if ($hits.Count -eq 0) { Plain $(if ($Method -eq 'Search') { 'Not found in indexed default branches.' } else { 'Not found on default branches.' }) }
}

Write-Host ("`nDone. Hard findings: {0}. Nothing was changed. Results name repositories; summarize them, do not paste them into tickets or pull requests." -f $script:Findings)
