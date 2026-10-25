<#
.SYNOPSIS
  OPTIONAL, PAID. Uses DeepAPI to research this week's vulnerabilities or a customer's public
  security footprint, and writes a sourced brief. Changes nothing in any tenant or host.

.DESCRIPTION
  Every script in this repo works without this one. Use it when you want an AI-assisted,
  cited first draft instead of reading fifteen advisories by hand. It calls DeepAPI's research
  endpoint, which searches the web, reads the sources and returns an answer with links.

  Modes:
    Vulns     Give it product names, CVEs or a question. It returns fixed versions, whether
              each issue is exploited, indicators to hunt for and what the vendor says to do,
              with a source for each fact. Use the result to fill or check a watchlist for
              Find-WeeklyVulnExposure.ps1.
    Company   Give it a customer or prospect name and public domain. It returns that
              organization's public security picture: reported breaches and incidents, vendors
              and products it is publicly known to use, internet-facing services named in news
              or job posts, and recent regulatory items. It does not collect employee lists.

  Cost: each run is a paid DeepAPI request. Use -DryRun first to see the exact hold for free.
  Your key, your spend: the key comes from the DEEPAPI_API_KEY environment variable and is
  never written anywhere.

  What leaves your machine: only the text you pass in -Query, -Items, -Company and -Domain.
  Send public names and products only. Never send internal hostnames, IPs, user names, tenant
  IDs or anything a customer told you in confidence.

  Treat the output as a draft. AI research can be wrong or out of date. Check every version
  number and indicator against the linked vendor advisory before you hunt with it or put it in
  front of a customer.

.PARAMETER Mode
  Vulns or Company.

.PARAMETER Items
  Vulns mode. Products, CVEs or advisories to research, for example 'PHP','Node.js','CVE-2026-0322'.

.PARAMETER Query
  Vulns mode. A free-form question instead of, or in addition to, -Items.

.PARAMETER Company
  Company mode. The organization's public name.

.PARAMETER Domain
  Company mode. The organization's public website domain, to avoid researching the wrong
  organization with a similar name.

.PARAMETER MaxCostUsd
  Spend cap for this run in US dollars. Default 0.75. DeepAPI's minimum is 0.35.

.PARAMETER DryRun
  Validate the request and show the credit hold it would place, without running or charging.

.PARAMETER OutDir
  Where to save the brief. Default .\research-output, which git ignores.

.REQUIREMENTS
  PowerShell 7. A DeepAPI account with credits and an API key in DEEPAPI_API_KEY.
  Optional DEEPAPI_API_BASE_URL (default https://deepapi.co). Setup steps are in
  docs/research/Invoke-DeepApiResearch.md.

.EXAMPLE
  pwsh -NoProfile -File .\scripts\research\Invoke-DeepApiResearch.ps1 -Mode Vulns -Items 'PHP','Node.js','GitLab' -DryRun

.EXAMPLE
  .\Invoke-DeepApiResearch.ps1 -Mode Vulns -Query 'Which edge appliance zero-days were exploited this week and what are the fixed versions?'

.EXAMPLE
  .\Invoke-DeepApiResearch.ps1 -Mode Company -Company 'Contoso Ltd' -Domain contoso.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateSet('Vulns', 'Company')] [string] $Mode,
    [string[]] $Items,
    [string] $Query,
    [string] $Company,
    [string] $Domain,
    [ValidatePattern('^\d+(\.\d{1,6})?$')] [string] $MaxCostUsd = '0.75',
    [switch] $DryRun,
    [string] $OutDir = '.\research-output'
)
$ErrorActionPreference = 'Stop'
function Yellow ([string]$m) { Write-Host "[YELLOW] $m" -ForegroundColor Yellow }
function Plain  ([string]$m) { Write-Host "  $m" }

if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'Run this with PowerShell 7 (pwsh).' }
$key = $env:DEEPAPI_API_KEY
if (-not $key) {
    Write-Host 'DEEPAPI_API_KEY is not set. See docs/research/Invoke-DeepApiResearch.md for setup, or use the free scripts instead.' -ForegroundColor Red
    exit 1
}
$base = if ($env:DEEPAPI_API_BASE_URL) { $env:DEEPAPI_API_BASE_URL.TrimEnd('/') } else { 'https://deepapi.co' }
if ($Items) { $Items = @($Items | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim(" '`"") } | Where-Object { $_ }) }

# ---- Build the research request ---------------------------------------------------
if ($Mode -eq 'Vulns') {
    if (-not $Items -and -not $Query) { throw 'Vulns mode needs -Items, -Query or both.' }
    $topic = @()
    if ($Items) { $topic += "Items: $($Items -join '; ')." }
    if ($Query) { $topic += $Query }
    $body = @{
        query        = "For each of these vulnerabilities or affected products, what are the CVE IDs, affected and fixed versions, whether it is exploited in the wild, and the indicators of compromise? $($topic -join ' ')"
        context      = 'Audience: security analysts at a managed security provider hunting across Windows endpoints, Microsoft 365 tenants and GitHub organizations. Prefer vendor advisories, CISA KEV and primary researcher write-ups over news coverage.'
        instructions = 'One section per item. In each: CVEs with CVSS, affected versions, fixed versions for every supported branch, exploited yes/no with evidence, indicators (package names and versions, file names and paths, hashes, domains, IPs, certificate names), what a Windows host, M365 tenant or GitHub org would show, and vendor remediation steps. Copy versions and hashes exactly from the source and cite it. Say "not stated" rather than guessing.'
    }
} else {
    if (-not $Company -or -not $Domain) { throw 'Company mode needs -Company and -Domain.' }
    $body = @{
        query        = "What is the public cybersecurity picture of $Company ($Domain)? Include publicly reported breaches, ransomware or data incidents, regulatory actions, vendors and technology products it is publicly known to use, internet-facing services or platforms named in news, filings or job postings, and recent security-relevant news."
        context      = 'Purpose: a managed security provider preparing to support or assess this organization. Public sources only. Do not list employees or personal details.'
        instructions = 'Sections: Incidents and breaches (date, what happened, source). Known technology and vendors (product, how it is known, source). Exposure signals (internet-facing platforms or services named publicly). Regulatory and compliance items. Recent news. Say "nothing found" for an empty section rather than guessing. Cite every fact.'
    }
}
$body.mode = 'clean'
$body.maxCostUsd = $MaxCostUsd
if ($DryRun) { $body.dryRun = $true }

$headers = @{
    Authorization     = "Bearer $key"
    'Idempotency-Key' = [guid]::NewGuid().ToString()
}
$json = $body | ConvertTo-Json -Depth 5

# ---- Call DeepAPI and poll until done ---------------------------------------------
try {
    $r = Invoke-RestMethod -Method Post -Uri "$base/v1/research/deep" -Headers $headers -ContentType 'application/json' -Body $json -TimeoutSec 300
} catch {
    $msg = $_.ErrorDetails.Message
    if ($msg -match 'insufficient_credits') { Write-Host 'DeepAPI says the account is out of credits. Add credits at https://deepapi.co/credits.' -ForegroundColor Red }
    else { Write-Host "DeepAPI request failed: $($_.Exception.Message) $msg" -ForegroundColor Red }
    exit 1
}

if ($DryRun) {
    Write-Host 'Dry run only. Nothing was run or charged.' -ForegroundColor Cyan
    $r.estimate | Format-List | Out-String | Write-Host
    exit 0
}

$poll = 0
while ($r.next -and $r.next.method -eq 'GET' -and $poll -lt 30) {
    Start-Sleep -Seconds ([math]::Max(2, [int]$r.next.afterSecs))
    $r = Invoke-RestMethod -Uri "$base$($r.next.path)" -Headers @{ Authorization = "Bearer $key" } -TimeoutSec 120
    $poll++
}
if ($r.status -eq 'failed' -or -not $r.output) {
    Write-Host "Research did not finish. Status: $($r.status). Request ID: $($r.requestId)." -ForegroundColor Red
    exit 1
}

# ---- Save and print the brief -----------------------------------------------------
$out = $r.output
$stamp = Get-Date -Format 'yyyy-MM-dd-HHmm'
$label = if ($Mode -eq 'Company') { ($Domain -replace '[^a-z0-9.-]', '') } else { 'vulns' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$file = Join-Path $OutDir "$stamp-$label.md"

$lines = @("# DeepAPI research: $Mode", '', "Run $stamp. Request ID $($r.requestId). Draft: verify every fact against its source before use.", '', $out.answer, '', '## Sources', '')
$n = 0
foreach ($s in @($out.sources)) {
    $n++
    $t = if ($s.title) { $s.title } else { $s.url }
    $lines += "$n. [$t]($($s.url))."
}
$lines -join "`n" | Set-Content -LiteralPath $file -Encoding UTF8

Write-Host $out.answer
Write-Host ''
if ($out.completeness -and $out.completeness -ne 'complete') { Yellow "The answer stopped at the output limit ($($out.completeness)). Rerun the missing items on their own." }
Write-Host "Saved the brief and $n sources to $file. Request ID $($r.requestId). Nothing was changed." -ForegroundColor Cyan
