<#
.SYNOPSIS
  READ-ONLY. Lists what CISA added to the Known Exploited Vulnerabilities (KEV) catalog recently.
  Free, no account, no key. Changes nothing.

.DESCRIPTION
  The KEV catalog is the short list of vulnerabilities CISA has seen exploited in real attacks.
  When a week brings more advisories than anyone can patch, this is the list to rank by first.

  What it does:
    1. Downloads the public KEV feed from cisa.gov.
    2. Keeps entries added in the last -Days days, or only the vendors you name.
    3. Prints each entry with its CISA due date and whether it is tied to ransomware.
    4. Optionally writes a CSV you can sort or attach to a change request.

  Use it before a hunt to decide what to look for, and after a big Patch Tuesday to see which
  of the many fixes CISA says are already being used.

.PARAMETER Days
  How far back to look by date added. Default 7.

.PARAMETER Vendor
  Only show these vendors, matched as "contains" against the vendor and product fields.
  Example: 'Microsoft','Ivanti','Cisco'.

.PARAMETER CsvPath
  Write the results to this CSV file as well.

.PARAMETER Detail
  Also print CISA's required action and description for each entry. Off by default because the
  required action is the same boilerplate on most entries.

.REQUIREMENTS
  Windows PowerShell 5.1 or PowerShell 7. Internet access to www.cisa.gov. No modules.

.EXAMPLE
  pwsh -NoProfile -File .\scripts\research\Get-KevRecent.ps1

.EXAMPLE
  .\Get-KevRecent.ps1 -Days 14 -Vendor 'Microsoft','Ivanti','Palo Alto','Cisco','BeyondTrust' -CsvPath .\kev.csv
#>
[CmdletBinding()]
param(
    [int] $Days = 7,
    [string[]] $Vendor,
    [string] $CsvPath,
    [switch] $Detail
)
$ErrorActionPreference = 'Stop'
# pwsh -File passes "A,B" as one string; split it so both call styles work.
if ($Vendor) { $Vendor = @($Vendor | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim(" '`"") } | Where-Object { $_ }) }
$script:Findings = 0
function Red    ([string]$m) { $script:Findings++; Write-Host "[RED] $m" -ForegroundColor Red }
function Yellow ([string]$m) { Write-Host "[YELLOW] $m" -ForegroundColor Yellow }
function Plain  ([string]$m) { Write-Host "  $m" }

$feed = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    $kev = Invoke-RestMethod -Uri $feed -UseBasicParsing -TimeoutSec 60
} catch {
    Write-Host "Could not download the KEV feed from cisa.gov: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$cutoff = (Get-Date).Date.AddDays(-$Days)
$rows = @($kev.vulnerabilities | Where-Object { [datetime]$_.dateAdded -ge $cutoff })
if ($Vendor) {
    $rows = @($rows | Where-Object {
        $v = "$($_.vendorProject) $($_.product)"
        @($Vendor | Where-Object { $v -like "*$_*" }).Count -gt 0
    })
}
$rows = @($rows | Sort-Object { [datetime]$_.dateAdded } -Descending)

Write-Host ("KEV catalog version {0}, {1} entries in total. Showing {2} added since {3:yyyy-MM-dd}." -f $kev.catalogVersion, $kev.count, $rows.Count, $cutoff) -ForegroundColor Cyan

foreach ($r in $rows) {
    $line = "{0}  {1} {2}: {3}. Added {4}, CISA due {5}." -f $r.cveID, $r.vendorProject, $r.product, $r.vulnerabilityName, $r.dateAdded, $r.dueDate
    if ($r.knownRansomwareCampaignUse -eq 'Known') { Red "$line Used in ransomware campaigns." } else { Yellow $line }
    if ($Detail) { Plain $r.shortDescription; Plain "Required action: $($r.requiredAction)" }
}
if ($rows.Count -eq 0) { Plain 'Nothing added in that window for the vendors given.' }

if ($CsvPath) {
    $rows | Select-Object cveID, vendorProject, product, vulnerabilityName, dateAdded, dueDate, knownRansomwareCampaignUse, requiredAction, shortDescription |
        Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "Wrote $($rows.Count) rows to $CsvPath."
}

Write-Host ("`nDone. Entries tied to ransomware: {0}. Entries listed: {1}. Nothing was changed." -f $script:Findings, $rows.Count)
