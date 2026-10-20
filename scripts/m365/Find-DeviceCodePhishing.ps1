<#
.SYNOPSIS
  READ-ONLY hunt for device-code phishing in one Microsoft 365 tenant. Changes nothing.

.DESCRIPTION
  Device-code phishing tricks a user into typing an attacker's code into a real Microsoft page
  ("enter this code to view the document"). The attacker's session gets the user's tokens, and
  MFA does not help because the user completed it. Current kits then register an attacker
  device in Entra ID and enroll it in Intune, which survives a password reset and token revoke.

  Six hunts, in priority order:
    1. Is there a Conditional Access policy that blocks the device code flow, is it enforced,
       and who is excluded from it?
    2. Successful device code sign-ins. Should be close to zero.
    3. Device code sign-ins blocked by Conditional Access (error 53003). Each one is a user who
       typed an attacker's code and did not report it.
    4. Microsoft Authentication Broker sign-ins from outside your known egress, grouped by IPs
       that touch more than one account.
    5. Bursts of device registrations by one account, and devices whose names match the
       firstname-lastname-domain-hex8 pattern seen in current kits.
    6. Automation user agents (python-requests, curl, Go HTTP client) in the sign-ins pulled.

  A query that fails is reported as UNKNOWN in red, never as clean.

.PARAMETER Tenant
  The customer's primary domain or tenant ID.

.PARAMETER LookbackDays
  How far back to search. Entra keeps sign-ins for 30 days on P1/P2.

.PARAMETER KnownEgress
  Optional. Start of the organization's office or VPN egress addresses, for example '203.0.113.'.
  Without it, hunt 4 lists every broker sign-in and you judge by the shared-IP view.

.REQUIREMENTS
  PowerShell 7+, Microsoft.Graph.Authentication. Entra ID P1 for sign-in logs.
  Read roles: Global Reader plus Reports Reader, or Security Reader.

.EXAMPLE
  pwsh -NoProfile -File .\Find-DeviceCodePhishing.ps1 -Tenant contoso.com

.EXAMPLE
  pwsh -NoProfile -File .\Find-DeviceCodePhishing.ps1 -Tenant contoso.com -KnownEgress '203.0.113.','198.51.100.' -LookbackDays 14
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $Tenant,
    [ValidateRange(1,30)][int] $LookbackDays = 30,
    [string[]] $KnownEgress = @(),
    [ValidateSet('Global','USGov','USGovDoD')][string] $Environment = 'Global',
    [switch] $DeviceCode,
    [int] $BurstWindowSec = 120
)
$ErrorActionPreference = 'Stop'
Import-Module Microsoft.Graph.Authentication

# ---- sign in clean and confirm the tenant -----------------------------------
Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
$scopes = 'AuditLog.Read.All','Directory.Read.All','Policy.Read.All','Device.Read.All','User.Read.All'
$conn = @{ TenantId = $Tenant; Scopes = $scopes; Environment = $Environment; NoWelcome = $true; ContextScope = 'Process' }
if ($DeviceCode) { $conn.UseDeviceCode = $true }
Connect-MgGraph @conn
$GraphBase = switch ($Environment) { 'USGov' { 'https://graph.microsoft.us' } 'USGovDoD' { 'https://dod-graph.microsoft.us' } default { 'https://graph.microsoft.com' } }
$org = (Invoke-MgGraphRequest GET "$GraphBase/v1.0/organization?`$select=id,displayName,verifiedDomains").value[0]
if ($Tenant -notin ($org.verifiedDomains | ForEach-Object { $_.name }) -and $Tenant -ne $org.id) {
    throw "Signed in to '$($org.displayName)' ($($org.id)), which does not own '$Tenant'. Stopping."
}
Write-Host ("Tenant confirmed: {0} as {1}" -f $org.displayName, (Get-MgContext).Account)

# ---- helpers -----------------------------------------------------------------
$script:Findings = 0
function Red    ([string]$m) { $script:Findings++; Write-Host "[RED] $m" -ForegroundColor Red }
function Yellow ([string]$m) { Write-Host "[YELLOW] $m" -ForegroundColor Yellow }
function Plain  ([string]$m) { Write-Host "  $m" }
function Section([string]$n,[string]$t) { Write-Host "`n=== $n. $t ===" -ForegroundColor Cyan }
function Get-GraphError($err) {
    # Graph puts the useful reason in the response body, not the exception text.
    $body = $err.ErrorDetails.Message
    if ($body) { try { $j = $body | ConvertFrom-Json; if ($j.error.message) { return "$($j.error.code): $($j.error.message)" } } catch {} ; return $body }
    $err.Exception.Message
}
function Get-All([string]$Uri, [string]$Label) {
    $out = @(); $script:Ok = $true
    try {
        while ($Uri) { $r = Invoke-MgGraphRequest GET $Uri; if ($r.value) { $out += $r.value } elseif ($r.id) { $out += $r }; $Uri = $r.'@odata.nextLink' }
    } catch { $script:Ok = $false; Red "$Label could not be read, so it is UNKNOWN, not clean: $(Get-GraphError $_)" }
    ,$out
}
function Test-Known([string]$Ip) { foreach ($p in $KnownEgress) { if ($Ip -and $Ip.StartsWith($p)) { return $true } }; $false }

$BROKER = '29d9ed98-a469-4536-ade2-f981bc1d605e'   # Microsoft Authentication Broker
# Admin command-line clients that legitimately use device code sign-in.
$adminTools = 'Microsoft Graph Command Line Tools|Microsoft Graph PowerShell|MS Teams Powershell|Exchange REST API Based Powershell|Microsoft Azure CLI|Azure PowerShell|Microsoft Exchange Online Remote PowerShell'
$since  = (Get-Date).ToUniversalTime().AddDays(-$LookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
$enc    = { param($s) [uri]::EscapeDataString($s) }

# ---- 1. Conditional Access ---------------------------------------------------
Section 1 'Conditional Access block on the device code flow'
$pols = Get-All "$GraphBase/v1.0/identity/conditionalAccess/policies" 'Conditional Access policies'
$dc = @($pols | Where-Object { $_.conditions.authenticationFlows.transferMethods -match 'deviceCodeFlow' })
if ($script:Ok -and -not $dc) { Red 'No Conditional Access policy targets the device code flow. This is the main control.' }
foreach ($p in $dc) {
    if ($p.state -eq 'enabled') { Plain "Policy '$($p.displayName)' is enforced ($($p.grantControls.builtInControls -join ','))." }
    else { Red "Policy '$($p.displayName)' is '$($p.state)'. Report-only and disabled policies do not block." }
    foreach ($groupId in @($p.conditions.users.excludeGroups | Where-Object { $_ })) {
        $grp = (Get-All "$GraphBase/v1.0/groups/$groupId`?`$select=id,displayName" 'excluded group')[0]
        $n = (Get-All "$GraphBase/v1.0/groups/$groupId/members?`$select=id&`$top=999" 'excluded group members').Count
        Yellow "Excluded group '$($grp.displayName)' has $n member(s). Exclusions that quietly grow are the usual gap."
    }
    $xu = @($p.conditions.users.excludeUsers | Where-Object { $_ }).Count
    if ($xu) { Yellow "$xu user(s) excluded directly from '$($p.displayName)'." }
}

# ---- 2 + 3. Device code sign-ins (beta: authenticationProtocol is beta only) --
Section 2 'Device code sign-ins, successful and blocked'
$f = & $enc "createdDateTime ge $since and authenticationProtocol eq 'deviceCode'"
$dcs = Get-All "$GraphBase/beta/auditLogs/signIns?`$filter=$f&`$top=999" 'device code sign-ins'
if ($script:Ok -and -not $dcs) { Plain 'None in the window. Consistent with an enforced block.' }
foreach ($s in ($dcs | Sort-Object createdDateTime -Descending)) {
    $line = "{0}  {1}  {2}  {3}" -f $s.createdDateTime, $s.userPrincipalName, $s.ipAddress, $s.appDisplayName
    switch ($s.status.errorCode) {
        0       {
            if ($s.appDisplayName -match $adminTools) { Yellow "Device code sign-in to admin tool: $line. Confirm it was your own admin session. Attackers can use the same client, and this account is not covered by the block." }
            else { Red "SUCCESSFUL device code sign-in: $line. Investigate this account now." }
        }
        53003   { Yellow "BLOCKED by Conditional Access: $line. This user typed someone else's code. Treat as a phish victim." }
        default { Plain "result $($s.status.errorCode): $line" }
    }
}

# ---- 4. Authentication Broker from outside known egress ----------------------
Section 4 'Authentication Broker sign-ins from outside known egress'
$f = & $enc "createdDateTime ge $since and appId eq '$BROKER'"
$brk = Get-All "$GraphBase/v1.0/auditLogs/signIns?`$filter=$f&`$top=999" 'broker sign-ins'
$odd = @($brk | Where-Object { -not (Test-Known $_.ipAddress) })
if ($script:Ok) {
    Plain ("{0} broker sign-in(s), {1} outside known egress{2}." -f $brk.Count, $odd.Count, $(if (-not $KnownEgress) { ' (no -KnownEgress given, so all count)' } else { '' }))
    Plain 'Remote workers on home internet show up here. The shared-IP view below is the part to read.'
    $shared = $odd | Group-Object ipAddress | Where-Object { @($_.Group.userPrincipalName | Select-Object -Unique).Count -ge 2 } |
              Sort-Object { @($_.Group.userPrincipalName | Select-Object -Unique).Count } -Descending | Select-Object -First 25
    foreach ($s in $shared) {
        $n = @($s.Group.userPrincipalName | Select-Object -Unique).Count
        Yellow ("{0} used by {1} accounts across {2} broker sign-ins. One outside IP serving several users is the phishing-kit pattern." -f $s.Name, $n, $s.Count)
    }
    if (-not $shared) { Plain 'No outside IP touched more than one account.' }
}

# ---- 5. Device registration bursts and naming pattern ------------------------
Section 5 'Device registrations: bursts and attacker naming pattern'
# Ask Graph for device events only. Pulling every audit event for 30 days on a large tenant
# runs long enough for the sign-in token to expire mid-paging.
$f = & $enc "activityDateTime ge $since and category eq 'Device'"
$devEv = @(Get-All "$GraphBase/v1.0/auditLogs/directoryAudits?`$filter=$f&`$top=999" 'device audit events')
if ($script:Ok) {
    Plain "$($devEv.Count) device-related audit event(s) in the window."
    foreach ($grp in ($devEv | Group-Object { $_.initiatedBy.user.userPrincipalName } | Where-Object Name)) {
        $ev = @($grp.Group | Sort-Object activityDateTime)
        for ($i = 0; $i -lt $ev.Count; $i++) {
            $win = @($ev | Where-Object { $d = ([datetime]$_.activityDateTime - [datetime]$ev[$i].activityDateTime).TotalSeconds; $d -ge 0 -and $d -le $BurstWindowSec })
            if ($win.Count -ge 3) { Red ("{0} made {1} device changes within {2} seconds starting {3}. Kits register devices in bursts." -f $grp.Name, $win.Count, $BurstWindowSec, $ev[$i].activityDateTime); break }
        }
    }
}
$devs = Get-All "$GraphBase/v1.0/devices?`$select=displayName,registrationDateTime,operatingSystem,isManaged&`$top=999" 'device inventory'
if ($script:Ok) {
    $pat = '^[a-z]+-[a-z]+-[a-z0-9]+-[a-z]{2,}-[a-f0-9]{8}(-p[0-9]{2})?$'
    $sus = @($devs | Where-Object { $_.displayName -match $pat })
    foreach ($d in $sus) { Red "Device '$($d.displayName)' registered $($d.registrationDateTime) matches the kit naming pattern (managed=$($d.isManaged))." }
    if (-not $sus) { Plain "No device names match the kit pattern ($($devs.Count) devices checked)." }
    $recent = @($devs | Where-Object { $_.registrationDateTime -and [datetime]$_.registrationDateTime -gt [datetime]$since })
    Plain "$($recent.Count) device(s) registered in the window. Eyeball any you cannot place."
}

# ---- 6. Automation user agents -----------------------------------------------
Section 6 'Automation user agents'
$pool = @($brk) + @($dcs)
if (-not $pool) { Yellow 'No sign-ins were pulled, so this hunt had nothing to read.' }
else {
    $auto = @($pool | Where-Object { $_.userAgent -match 'python-requests|python-urllib|go-http-client|curl/|headless' })
    foreach ($s in $auto) { Red ("{0}  {1}  {2}  user agent '{3}'" -f $s.createdDateTime, $s.userPrincipalName, $s.ipAddress, $s.userAgent) }
    if (-not $auto) { Plain "No automation user agents across $($pool.Count) sign-ins." }
}

Write-Host ("`nDone for {0}. Hard findings: {1}. Nothing was changed." -f $org.displayName, $script:Findings)
Disconnect-MgGraph | Out-Null
