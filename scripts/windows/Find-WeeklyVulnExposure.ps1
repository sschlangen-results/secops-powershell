<#
.SYNOPSIS
  READ-ONLY sweep of one Windows host for this week's vulnerable or backdoored software, driven
  by a watchlist file. Changes nothing.

.DESCRIPTION
  Each week brings a new list of runtimes, packages and plugins to hunt for. The checks stay the
  same; only the list changes. This script reads a watchlist (watchlists\<date>.psd1) and runs
  every Host entry in it against this machine, then prints the items that a host cannot show so
  they are not forgotten.

  Check types a watchlist can use:
    ExeVersion        Finds an executable (php.exe, node.exe, firefox.exe) on PATH, in Program
                      Files, common install folders and user AppData, reads its file version and
                      compares it with the fixed version for its branch.
    FileVersion       Finds executables by name pattern and flags known-bad versions.
    PythonPackage     Searches every site-packages folder for a package's bad versions and for
                      backdoor files dropped next to it.
    WordPressPlugin   Searches web roots for a plugin folder at a bad version and for dropped files.
    InstalledProgram  Flags installed programs whose name matches, so you know the customer runs it.

  The default watchlist is the newest file in the repo's watchlists folder. To build next week's,
  copy the latest file, change the entries and cite the advisory for every version you enter.

.PARAMETER Watchlist
  Path to a watchlist .psd1. Default: the newest file in ..\..\watchlists next to this script.

.PARAMETER WebRoots
  Extra folders to search for WordPress sites. inetpub\wwwroot, xampp, wamp and laragon folders
  are searched by default.

.PARAMETER ShowManual
  Print the watchlist items that cannot be checked from a host. On by default; use
  -ShowManual:$false from an RMM to keep output short.

.REQUIREMENTS
  Windows PowerShell 5.1 or PowerShell 7. Run elevated or as SYSTEM to see every profile.
  Works from an RMM "run PowerShell" action if you copy the watchlist next to the script and
  pass -Watchlist. No modules needed.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\Find-WeeklyVulnExposure.ps1

.EXAMPLE
  .\Find-WeeklyVulnExposure.ps1 -Watchlist .\2026-10-24.psd1 -WebRoots 'D:\Sites' -ShowManual:$false
#>
[CmdletBinding()]
param(
    [string] $Watchlist,
    [string[]] $WebRoots = @(),
    [bool] $ShowManual = $true
)
$ErrorActionPreference = 'SilentlyContinue'
$script:Findings = 0
$script:Reviews  = 0
function Red    ([string]$m) { $script:Findings++; Write-Host "[RED] $m" -ForegroundColor Red }
function Yellow ([string]$m) { $script:Reviews++;  Write-Host "[YELLOW] $m" -ForegroundColor Yellow }
function Plain  ([string]$m) { Write-Host "  $m" }
function Section([string]$t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }

# ---- Load the watchlist -----------------------------------------------------------
if (-not $Watchlist) {
    $dir = Join-Path $PSScriptRoot '..\..\watchlists'
    $Watchlist = (Get-ChildItem -LiteralPath $dir -Filter '*.psd1' | Sort-Object Name -Descending | Select-Object -First 1).FullName
}
if (-not $Watchlist -or -not (Test-Path -LiteralPath $Watchlist)) {
    Write-Host 'No watchlist found. Pass -Watchlist <path to .psd1>.' -ForegroundColor Red
    exit 1
}
$wl = Import-PowerShellDataFile -LiteralPath $Watchlist
Write-Host ("Watchlist: {0} ({1}). Host: {2}." -f $wl.Name, (Split-Path $Watchlist -Leaf), $env:COMPUTERNAME) -ForegroundColor Cyan

# ---- Where to look ----------------------------------------------------------------
$profiles = @(Get-ChildItem 'C:\Users' -Directory -Force | Where-Object { $_.Name -notin 'Public', 'Default', 'Default User', 'All Users' })
$exeRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, "$env:SystemDrive\tools", "$env:SystemDrive\php",
    "$env:SystemDrive\xampp", "$env:SystemDrive\wamp64", "$env:SystemDrive\wamp", "$env:SystemDrive\laragon",
    "$env:SystemDrive\nvm4w", "$env:ProgramData\chocolatey\lib", "$env:ProgramData\scoop") | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
foreach ($p in $profiles) {
    foreach ($sub in 'AppData\Local\Programs', 'AppData\Roaming\nvm', 'AppData\Local\nvm', 'scoop\apps', 'AppData\Local\Microsoft\WinGet\Packages', 'bin', '.local\bin') {
        $d = Join-Path $p.FullName $sub
        if (Test-Path -LiteralPath $d) { $exeRoots += $d }
    }
}

function Find-Exe([string[]]$names, [string]$pattern) {
    $hits = @{}
    foreach ($n in $names) { foreach ($c in @(Get-Command $n -All -CommandType Application)) { $hits[$c.Source.ToLower()] = $c.Source } }
    foreach ($r in $exeRoots) {
        $filters = if ($pattern) { @($pattern) } else { $names }
        foreach ($f in $filters) {
            foreach ($i in @(Get-ChildItem -LiteralPath $r -Filter $f -File -Recurse -Depth 5 -Force)) { $hits[$i.FullName.ToLower()] = $i.FullName }
        }
    }
    return @($hits.Values | Sort-Object)
}
function Get-FileVer([string]$path) {
    $vi = (Get-Item -LiteralPath $path).VersionInfo
    foreach ($s in @($vi.ProductVersion, $vi.FileVersion)) {
        if ($s -match '(\d+)\.(\d+)\.(\d+)') { return [version]("{0}.{1}.{2}" -f $Matches[1], $Matches[2], $Matches[3]) }
    }
    return $null
}
function Get-Branch([version]$v, [int]$parts) { if ($parts -ge 2) { "$($v.Major).$($v.Minor)" } else { "$($v.Major)" } }

# ---- Host checks ------------------------------------------------------------------
foreach ($c in @($wl.Host)) {
    Section $c.Title
    $n = 0
    switch ($c.Type) {

        'ExeVersion' {
            $fixed = @($c.Fixed | ForEach-Object { [version]$_ })
            $byBranch = @{}
            foreach ($f in $fixed) { $byBranch[(Get-Branch $f $c.BranchParts)] = $f }
            $lowest = ($fixed | Sort-Object | Select-Object -First 1)
            foreach ($exe in (Find-Exe $c.Names $null)) {
                $n++
                $v = Get-FileVer $exe
                if (-not $v) { Yellow "'$exe' found but its version could not be read. Check it by hand."; continue }
                $b = Get-Branch $v $c.BranchParts
                if ($byBranch.ContainsKey($b)) {
                    if ($v -lt $byBranch[$b]) {
                        $msg = "'$exe' is $v; fixed in $($byBranch[$b]). $($c.Advice)"
                        if ($c.Exploited) { Red $msg } else { Yellow $msg }
                    } else { Plain "'$exe' is $v, at or above the fix for $b." }
                } elseif ($v -lt $lowest) {
                    $msg = "'$exe' is $v, an older branch with no fix listed. $($c.Advice)"
                    if ($c.Exploited) { Red $msg } else { Yellow $msg }
                } else {
                    Yellow "'$exe' is $v, a branch the advisory does not list. Confirm it against the source: $($c.Source)"
                }
            }
        }

        'FileVersion' {
            $bad = @($c.BadVersions | ForEach-Object { [version]$_ })
            foreach ($exe in (Find-Exe @() $c.NamePattern)) {
                $n++
                $v = Get-FileVer $exe
                if (-not $v) { Yellow "'$exe' found but its version could not be read. Check it by hand. $($c.Advice)"; continue }
                if ($bad -contains $v) { Red "'$exe' is $v, a known-bad release. $($c.Advice)" }
                else { Plain "'$exe' is $v, not a listed bad release." }
            }
        }

        'PythonPackage' {
            $roots = @("$env:ProgramFiles", "${env:ProgramFiles(x86)}", "$env:SystemDrive\Python*", "$env:ProgramData") + @($profiles | ForEach-Object { $_.FullName })
            $sites = @{}
            foreach ($r in $roots) {
                foreach ($root in @(Resolve-Path $r | ForEach-Object { $_.Path })) {
                    foreach ($d in @(Get-ChildItem -LiteralPath $root -Directory -Recurse -Depth 8 -Force -Filter 'site-packages')) { $sites[$d.FullName.ToLower()] = $d.FullName }
                }
            }
            foreach ($sp in $sites.Values) {
                foreach ($di in @(Get-ChildItem -LiteralPath $sp -Directory -Filter "$($c.Package)-*.dist-info")) {
                    $n++
                    $ver = $di.Name -replace "^$([regex]::Escape($c.Package))-", '' -replace '\.dist-info$', ''
                    if ($c.BadVersions -contains $ver) { Red "$($c.Package) $ver in '$sp'. $($c.Advice)" }
                    else { Plain "$($c.Package) $ver in '$sp', not a listed bad release." }
                }
                foreach ($f in @($c.Files)) {
                    $p = Join-Path $sp $f
                    if (Test-Path -LiteralPath $p) { $n++; Red "Backdoor file '$p'. $($c.Advice)" }
                }
                foreach ($f in @($c.ReviewFiles)) {
                    $p = Join-Path $sp $f
                    if (Test-Path -LiteralPath $p) { $n++; Yellow "'$p' exists. It can be legitimate, but this backdoor used it to start itself. Read it." }
                }
            }
            if ($sites.Count -eq 0) { Plain 'No Python site-packages folders found.' }
        }

        'WordPressPlugin' {
            $roots = @("$env:SystemDrive\inetpub\wwwroot", "$env:SystemDrive\xampp\htdocs", "$env:SystemDrive\wamp64\www", "$env:SystemDrive\wamp\www", "$env:SystemDrive\laragon\www") + $WebRoots | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
            foreach ($r in $roots) {
                foreach ($cfg in @(Get-ChildItem -LiteralPath $r -Filter 'wp-config.php' -File -Recurse -Depth 4 -Force)) {
                    $site = $cfg.DirectoryName
                    foreach ($slug in @($c.Slug) + @($c.AltSlugs)) {
                        $pd = Join-Path $site "wp-content\plugins\$slug"
                        if (-not (Test-Path -LiteralPath $pd)) { continue }
                        $n++
                        $main = Get-ChildItem -LiteralPath $pd -Filter '*.php' -File | Where-Object { (Get-Content -LiteralPath $_.FullName -TotalCount 30) -match 'Plugin Name:' } | Select-Object -First 1
                        $ver = if ($main) { ((Get-Content -LiteralPath $main.FullName -TotalCount 30) -match 'Version:\s*([\d.]+)' | Select-Object -First 1) -replace '.*Version:\s*', '' } else { '' }
                        if ($c.BadVersions -contains $ver) { Red "WordPress site '$site' has $slug $ver. $($c.Advice)" }
                        else { Plain "WordPress site '$site' has $slug $(if ($ver) { $ver } else { '(version unread)' })." }
                    }
                    foreach ($f in @($c.Files)) {
                        $p = Join-Path $site $f
                        if (Test-Path -LiteralPath $p) { $n++; Red "'$p' is not a WordPress core file and matches this backdoor. $($c.Advice)" }
                    }
                }
            }
            if ($roots.Count -eq 0) { Plain 'No web roots found. Pass -WebRoots if this host serves sites from elsewhere.' }
        }

        'InstalledProgram' {
            $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
            foreach ($k in $keys) {
                foreach ($a in @(Get-ItemProperty $k | Where-Object { $_.DisplayName -match $c.Match })) {
                    $n++
                    Yellow "Installed: $($a.DisplayName) $($a.DisplayVersion). $($c.Advice)"
                }
            }
        }
    }
    if ($n -eq 0) { Plain 'Not found on this host.' }
}

# ---- What a host cannot show ------------------------------------------------------
if ($ShowManual -and $wl.Manual) {
    Section 'Check these outside this host (inventory, vendor consoles, other scripts)'
    foreach ($m in @($wl.Manual)) { Plain "- $($m.Title). $($m.Fix)" }
}
if ($wl.GitHub) { Plain "GitHub items in this watchlist: run scripts\github\Find-GitHubSupplyChainIndicators.ps1 against each organization." }

Write-Host ("`nDone on {0}. Hard findings: {1}. Items to review: {2}. Nothing was changed." -f $env:COMPUTERNAME, $script:Findings, $script:Reviews)
