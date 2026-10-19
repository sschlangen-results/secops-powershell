<#
.SYNOPSIS
  READ-ONLY sweep of one Windows host for malware that lives in user profiles and starts itself.
  Changes nothing.

.DESCRIPTION
  Built for the infostealer and loader patterns seen in 2026:
    - Fake utilities (PDF viewers, converters, document readers) that work as advertised but drop
      a backdoor into %LOCALAPPDATA%\<AppName>\ and add a scheduled task such as
      "<AppName>UpdateCheck" that runs it every hour with a --uid style argument.
    - Fake IT calls over Teams that walk a user into running a loader, which unpacks its own
      Java runtime into %APPDATA%\<random or KB-looking folder>\ and runs .java scripts.

  What it checks:
    1. Scheduled tasks whose program sits in a user-writable folder (AppData, Downloads, Temp,
       C:\Users\Public). Checks the file signature and flags hourly-style triggers.
    2. Run and RunOnce keys for the machine and every loaded user hive, plus Startup folders,
       for anything launching from a user-writable folder.
    3. Programs in each user's AppData\Local and AppData\Roaming top-level folders that were
       created recently and are not signed by a trusted publisher.
    4. Java runtimes outside Program Files, and .java or .jar files under AppData.
    5. Recent installers in Downloads whose names look like free utilities.
    6. Running processes launched from AppData, with their outbound connections.

  A valid signature is not proof of safety. Malware in this class has shipped with real code
  signing certificates that were later revoked. Signed but unknown publishers print yellow.

.PARAMETER Days
  How far back counts as recent for new folders and downloads. Default 45.

.PARAMETER TrustedPublishers
  Signer names treated as expected. Matching is "contains", so 'Microsoft' covers all
  Microsoft subsidiaries. Add your own line-of-business vendors.

.REQUIREMENTS
  Windows PowerShell 5.1 or PowerShell 7. Run elevated or as SYSTEM to see every profile and
  every task. Works from an RMM "run PowerShell" action. No modules needed.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\Find-UserProfilePersistence.ps1

.EXAMPLE
  .\Find-UserProfilePersistence.ps1 -Days 90 -TrustedPublishers 'Microsoft','Google','Contoso Software'
#>
[CmdletBinding()]
param(
    [int] $Days = 45,
    [string[]] $TrustedPublishers = @(
        'Microsoft','Google','Zoom','Slack','Adobe','Mozilla','Cisco','Citrix','Dropbox','Box, Inc',
        'LogMeIn','GoTo','RingCentral','Spotify','Discord','Apple','Intel','Dell','Lenovo','HP Inc',
        'Logitech','Notion','Grammarly','Webex','Oracle','Docker','GitHub','JetBrains','Postman'
    )
)
$ErrorActionPreference = 'SilentlyContinue'
$script:Findings = 0
$script:Reviews  = 0
$script:Printed = 0
function Out-Line([string]$m, [string]$c) {
    $script:Printed++
    if ($script:Printed -le 400) { Write-Host $m -ForegroundColor $c }
    elseif ($script:Printed -eq 401) { Write-Host '[YELLOW] Output capped at 400 lines. Run locally or raise the cap to see the rest.' -ForegroundColor Yellow }
}
function Red    ([string]$m) { $script:Findings++; Out-Line "[RED] $m" Red }
function Yellow ([string]$m) { $script:Reviews++;  Out-Line "[YELLOW] $m" Yellow }
function Plain  ([string]$m) { Write-Host "  $m" }
function Section([string]$n, [string]$t) { Write-Host "`n=== $n. $t ===" -ForegroundColor Cyan }

$cutoff = (Get-Date).AddDays(-$Days)
$userWritable = '\\Users\\[^\\]+\\(AppData|Downloads|Desktop|Documents)\\|\\Users\\Public\\|\\Windows\\Temp\\|\\AppData\\Local\\Temp\\'

function Expand-Target([string]$cmd) {
    # Pull the program path out of a command line, expanding %VARS%.
    $c = [Environment]::ExpandEnvironmentVariables($cmd).Trim()
    if ($c -match '^"([^"]+)"') { return $Matches[1] }
    if ($c -match '^(\S+\.(exe|bat|cmd|ps1|vbs|js|dll|com|scr))') { return $Matches[1] }
    return ($c -split '\s')[0]
}
function Get-SignerVerdict([string]$path) {
    if (-not $path -or -not (Test-Path -LiteralPath $path)) { return @{ Level = 'missing'; Text = 'file not found' } }
    $sig = Get-AuthenticodeSignature -LiteralPath $path
    $who = if ($sig.SignerCertificate) { ($sig.SignerCertificate.Subject -replace '^CN=("?)([^,"]+)\1.*$', '$2') } else { '' }
    if ($sig.Status -ne 'Valid') { return @{ Level = 'bad'; Text = "signature $($sig.Status)$(if ($who) { " ($who)" })" } }
    foreach ($t in $TrustedPublishers) { if ($who -like "*$t*") { return @{ Level = 'trusted'; Text = "signed by $who" } } }
    return @{ Level = 'unknown'; Text = "signed by $who, not on the trusted list" }
}
function Get-Sha256([string]$path) { if (Test-Path -LiteralPath $path) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash } }

Write-Host ("HOST {0}  {1}  running as {2}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'), [Security.Principal.WindowsIdentity]::GetCurrent().Name)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Yellow 'Not elevated. Other users'' tasks and profiles may be hidden. Run as admin or SYSTEM for full coverage.' }
$profiles = Get-ChildItem 'C:\Users' -Directory -Force | Where-Object { $_.Name -notin 'Default','Default User','All Users' }

# ---- 1. Scheduled tasks -----------------------------------------------------
Section 1 'Scheduled tasks that run from user-writable folders'
$n = 0
foreach ($t in Get-ScheduledTask) {
    foreach ($a in @($t.Actions)) {
        if (-not $a.Execute) { continue }
        $exe = Expand-Target $a.Execute
        $full = "$($a.Execute) $($a.Arguments)".Trim()
        if ($exe -notmatch $userWritable -and $full -notmatch $userWritable) { continue }
        $n++
        $v = Get-SignerVerdict $exe
        $hourly = @($t.Triggers | Where-Object { $_.Repetition.Interval -match '^PT(1H|[1-5]?\dM)$' }).Count -gt 0
        $uid = $a.Arguments -match '--?(uid|id|guid|machine-?id)[= ][0-9a-f-]{16,}'
        $desc = "Task '$($t.TaskPath)$($t.TaskName)' [$($t.State)] runs '$full'. $($v.Text)$(if ($hourly) { '. Repeats hourly or faster' })$(if ($uid) { '. Passes a per-machine ID' })"
        if ($v.Level -in 'bad','missing' -or ($v.Level -ne 'trusted' -and ($hourly -or $uid))) { Red "$desc. SHA256 $(Get-Sha256 $exe)" }
        elseif ($v.Level -eq 'unknown') { Yellow $desc }
        else { Plain $desc }
    }
}
if ($n -eq 0) { Plain 'No scheduled tasks run from user-writable folders.' }

# ---- 2. Run keys and Startup folders ------------------------------------------
Section 2 'Run keys and Startup folders'
$keys = @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
          'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')
foreach ($h in (Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) {
    $keys += "Registry::HKEY_USERS\$($h.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run"
    $keys += "Registry::HKEY_USERS\$($h.PSChildName)\Software\Microsoft\Windows\CurrentVersion\RunOnce"
}
$loaded = @(Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' }).Count
Plain "Checked machine keys and $loaded loaded user hive(s). Users who are not logged on are not covered here; their tasks in section 1 still are."
$n = 0
foreach ($k in $keys) {
    $props = Get-ItemProperty -Path $k
    if (-not $props) { continue }
    foreach ($p in $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }) {
        $val = [string]$p.Value
        if ($val -notmatch $userWritable) { continue }
        $n++
        $exe = Expand-Target $val
        $v = Get-SignerVerdict $exe
        $desc = "Run key '$($p.Name)' in $($k -replace 'Registry::','') starts '$val'. $($v.Text)"
        if ($v.Level -in 'bad','missing') { Red "$desc. SHA256 $(Get-Sha256 $exe)" } elseif ($v.Level -eq 'unknown') { Yellow $desc } else { Plain $desc }
    }
}
foreach ($pr in $profiles) {
    $sf = Join-Path $pr.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
    foreach ($f in (Get-ChildItem -LiteralPath $sf -File -Force | Where-Object { $_.Name -ne 'desktop.ini' })) {
        $n++
        $target = $f.FullName
        if ($f.Extension -eq '.lnk') { $target = (New-Object -ComObject WScript.Shell).CreateShortcut($f.FullName).TargetPath }
        $v = Get-SignerVerdict $target
        $desc = "Startup item '$($f.Name)' for profile '$($pr.Name)' starts '$target'. $($v.Text)"
        if ($v.Level -in 'bad','missing' -and $target -match $userWritable) { Red $desc } elseif ($v.Level -ne 'trusted') { Yellow $desc } else { Plain $desc }
    }
}
if ($n -eq 0) { Plain 'Nothing in Run keys or Startup folders points at a user-writable folder.' }

# ---- 3. New unsigned programs in AppData ---------------------------------------
Section 3 "Programs in AppData folders created in the last $Days days"
$n = 0
foreach ($pr in $profiles) {
    foreach ($root in 'AppData\Local','AppData\Roaming') {
        $base = Join-Path $pr.FullName $root
        foreach ($dir in (Get-ChildItem -LiteralPath $base -Directory -Force | Where-Object { $_.CreationTime -ge $cutoff -and $_.Name -notin 'Temp','Packages','Microsoft','D3DSCache','CrashDumps' })) {
            foreach ($exe in (Get-ChildItem -LiteralPath $dir.FullName -Recurse -Depth 2 -Force -File | Where-Object { $_.Extension -in '.exe','.dll' } | Select-Object -First 25)) {
                $v = Get-SignerVerdict $exe.FullName
                if ($v.Level -eq 'trusted') { continue }
                $n++
                $desc = "'$($exe.FullName)' in folder created $($dir.CreationTime.ToString('yyyy-MM-dd')). $($v.Text). SHA256 $(Get-Sha256 $exe.FullName)"
                if ($v.Level -eq 'bad') { Red $desc } else { Yellow $desc }
            }
        }
    }
}
if ($n -eq 0) { Plain 'No untrusted programs in recently created AppData folders.' }

# ---- 4. Java outside Program Files ----------------------------------------------
Section 4 'Java runtimes and scripts outside Program Files'
$n = 0
foreach ($pr in $profiles) {
    foreach ($root in 'AppData\Roaming','AppData\Local','Downloads') {
        $base = Join-Path $pr.FullName $root
        foreach ($j in (Get-ChildItem -LiteralPath $base -Recurse -Depth 4 -Force -File | Where-Object { $_.Name -in 'java.exe','javaw.exe' })) {
            $n++; Red "Java runtime at '$($j.FullName)' (created $($j.CreationTime.ToString('yyyy-MM-dd HH:mm'))). Loaders bring their own Java so they can run .java scripts. $((Get-SignerVerdict $j.FullName).Text)"
        }
        foreach ($s in (Get-ChildItem -LiteralPath $base -Recurse -Depth 4 -Force -File | Where-Object { $_.Extension -in '.java','.jar' -and $_.FullName -notmatch '\\(JetBrains|\.gradle|\.m2|Code\\User)\\' } | Select-Object -First 20)) {
            $n++; Yellow "Java file '$($s.FullName)' created $($s.CreationTime.ToString('yyyy-MM-dd HH:mm'))."
        }
    }
}
foreach ($pr in (Get-CimInstance Win32_Process | Where-Object { $_.Name -in 'java.exe','javaw.exe' -and $_.ExecutablePath -notmatch '\\Program Files' })) {
    $n++; Red "Running Java outside Program Files: pid $($pr.ProcessId) '$($pr.CommandLine)'."
}
if ($n -eq 0) { Plain 'No Java runtimes or scripts in user folders.' }

# ---- 5. Utility-looking installers in Downloads -----------------------------------
Section 5 "Free-utility installers downloaded in the last $Days days"
$n = 0
$lure = 'pdf|viewer|reader|convert|editor|document|docs?\b|manual|invoice|scan|print|zip|unzip|player|cleaner|driver|update'
foreach ($pr in $profiles) {
    foreach ($f in (Get-ChildItem -LiteralPath (Join-Path $pr.FullName 'Downloads') -Force -File -Recurse -Depth 1 | Where-Object { $_.Extension -in '.exe','.msi','.msix','.zip' -and $_.LastWriteTime -ge $cutoff -and $_.Name -match $lure })) {
        $n++
        $v = if ($f.Extension -in '.exe','.msi') { (Get-SignerVerdict $f.FullName).Text } else { 'archive, not checked' }
        Yellow "'$($f.FullName)' $([math]::Round($f.Length/1MB,1)) MB, $($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')). $v. SHA256 $(Get-Sha256 $f.FullName). Ask the user where it came from."
    }
}
if ($n -eq 0) { Plain 'No utility-looking installers in Downloads.' }

# ---- 6. Processes running from AppData ---------------------------------------------
Section 6 'Processes running from AppData, with outbound connections'
$n = 0
$conns = @(Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0)' })
foreach ($p in (Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -match '\\AppData\\' })) {
    $v = Get-SignerVerdict $p.ExecutablePath
    if ($v.Level -eq 'trusted') { continue }
    $n++
    $remote = @($conns | Where-Object { $_.OwningProcess -eq $p.ProcessId } | ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort)" }) -join ', '
    $desc = "pid $($p.ProcessId) '$($p.ExecutablePath)'. $($v.Text)$(if ($remote) { ". Connected to $remote" })"
    if ($v.Level -eq 'bad' -and $remote) { Red $desc } else { Yellow $desc }
}
if ($n -eq 0) { Plain 'No untrusted programs running from AppData.' }

Write-Host ("`nDone on {0}. Hard findings: {1}. Items to review: {2}. Nothing was changed." -f $env:COMPUTERNAME, $script:Findings, $script:Reviews)
