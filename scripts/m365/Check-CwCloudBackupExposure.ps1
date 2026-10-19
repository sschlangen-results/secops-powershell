<#
.SYNOPSIS
  READ-ONLY exposure check for the October 2026 ConnectWise Cloud Backup / Cloud Management (SkyKick)
  supply-chain attack. Changes nothing in the tenant.

.DESCRIPTION
  Checks one Microsoft 365 tenant for:
    1. The seven ConnectWise / SkyKick app identities (service principals), plus any app named SkyKick.
    2. For any found: directory roles held, app permissions granted, credentials attached.
    3. Credentials (secrets or certificates) added to ANY app or service principal since -Since.
    4. Directory audit since -Since: role assignments, credential adds, consents, app role grants.
    5. Service principal sign-ins from the attacker IP 144.172.64.128 (beta endpoint, needs Entra ID P1).
  Expected noise in 3 and 4: your own automation, user consents, PIM activations, MSP tool refreshes.
  Anything acting as one of the seven apps, or any credential you cannot explain, is a finding.

.REQUIREMENTS
  PowerShell 7+, module Microsoft.Graph.Authentication (Install-Module Microsoft.Graph.Authentication -Scope CurrentUser).
  An account in the target tenant that can read directory and audit logs (Global Reader + Reports Reader, or Security Reader).
  Delegated scopes requested: Application.Read.All, Directory.Read.All, AuditLog.Read.All, RoleManagement.Read.Directory.

.EXAMPLE
  pwsh -NoProfile -File .\Check-CwCloudBackupExposure-Standalone.ps1 -Tenant contoso.com
  pwsh -NoProfile -File .\Check-CwCloudBackupExposure-Standalone.ps1 -Tenant contoso.com -DeviceCode
  pwsh -NoProfile -File .\Check-CwCloudBackupExposure-Standalone.ps1 -Tenant contoso.us -Environment USGov   # GCC High / DoD only

.NOTES
  Sources: BleepingComputer 2026-10-17 (updated 10/18) citing ConnectWise, Huntress, Microsoft and Todyl.
  Defang the attacker IP (144.172.64[.]128) in any ticket or note.
#>
param(
    [Parameter(Mandatory)][string] $Tenant,
    [ValidateSet('Global','USGov','USGovDoD')][string] $Environment = 'Global',
    [datetime] $Since = '2026-10-13T00:00:00Z',
    [switch] $DeviceCode
)
$ErrorActionPreference = 'Stop'
Import-Module Microsoft.Graph.Authentication

# Always start clean so a cached token for a different customer can never be reused.
Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
$scopes = 'Application.Read.All','Directory.Read.All','AuditLog.Read.All','RoleManagement.Read.Directory'
$conn = @{ TenantId = $Tenant; Scopes = $scopes; Environment = $Environment; NoWelcome = $true; ContextScope = 'Process' }
if ($DeviceCode) { $conn.UseDeviceCode = $true }
Connect-MgGraph @conn

$G = switch ($Environment) { 'USGov' { 'https://graph.microsoft.us' } 'USGovDoD' { 'https://dod-graph.microsoft.us' } default { 'https://graph.microsoft.com' } }

# Confirm we are in the tenant that was asked for before reading anything.
$org = (Invoke-MgGraphRequest GET "$G/v1.0/organization?`$select=id,displayName,verifiedDomains").value[0]
$domains = $org.verifiedDomains | ForEach-Object { $_.name }
if ($Tenant -notin $domains -and $Tenant -ne $org.id) {
    throw "Signed in to '$($org.displayName)' ($($org.id)), which does not own '$Tenant'. Stopping."
}
Write-Host ("Tenant confirmed: {0} ({1}) as {2}" -f $org.displayName, $org.id, (Get-MgContext).Account)

function Get-All([string]$Uri) {
    $out = @()
    while ($Uri) {
        $r = Invoke-MgGraphRequest -Method GET -Uri $Uri -Headers @{ ConsistencyLevel = 'eventual' }
        if ($r.value) { $out += $r.value }
        $Uri = $r.'@odata.nextLink'
    }
    $out
}

$AttackerIp = '144.172.64.128'
$CwApps = [ordered]@{
    '506e08f9-6e9a-4da4-942b-a099a03644ae' = 'ConnectWise Cloud Backup'
    '2399d300-6fca-4e6a-a686-399fefe75b83' = 'ConnectWise Cloud Management'
    '24205314-2b89-4e07-a2a4-579e898a5640' = 'Cloud Management - MS Teams'
    'b78f6a77-d4e5-46fb-87e5-d1648bd02519' = 'Cloud Management - Exchange Online'
    '0de14c77-b9b0-4137-9360-34878a929827' = 'Cloud Management - MS Graph'
    '412dcf96-176d-4b3a-a1b0-4981ad66971e' = 'Cloud Management - Partner Center'
    'b2b55f5b-7758-4719-8d8f-88ae172e6bdb' = 'Cloud Management - SharePoint Online'
}
$sinceIso = $Since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$findings = 0

Write-Host "`n=== 1. ConnectWise / SkyKick service principals ==="
$found = @()
foreach ($id in $CwApps.Keys) {
    $sp = (Get-All "$G/v1.0/servicePrincipals?`$filter=appId eq '$id'&`$select=id,appId,displayName,accountEnabled,keyCredentials,passwordCredentials") | Select-Object -First 1
    if ($sp) { $found += $sp; $findings++; Write-Host ("FOUND  {0} ({1})  '{2}'  enabled={3}" -f $CwApps[$id], $id, $sp.displayName, $sp.accountEnabled) -ForegroundColor Red }
    else { Write-Host ("absent {0} ({1})" -f $CwApps[$id], $id) }
}
foreach ($s in (Get-All "$G/v1.0/servicePrincipals?`$search=`"displayName:SkyKick`"&`$select=appId,displayName,accountEnabled")) {
    if (-not $CwApps.Contains($s.appId)) { $findings++; Write-Host ("NAME MATCH 'SkyKick': '{0}' ({1}) enabled={2}" -f $s.displayName, $s.appId, $s.accountEnabled) -ForegroundColor Yellow }
}

foreach ($sp in $found) {
    Write-Host "`n--- $($sp.displayName) ($($sp.appId)) ---"
    $roles = Get-All "$G/v1.0/servicePrincipals/$($sp.id)/memberOf" | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' }
    if ($roles) { $roles | ForEach-Object { Write-Host "  DIRECTORY ROLE: $($_.displayName)" -ForegroundColor Red } } else { Write-Host '  Directory roles: none' }
    foreach ($a in (Get-All "$G/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments")) {
        Write-Host ("  App permission on {0}: appRoleId {1} granted {2}" -f $a.resourceDisplayName, $a.appRoleId, $a.createdDateTime)
    }
    foreach ($c in @($sp.passwordCredentials) + @($sp.keyCredentials)) {
        if ($c) { Write-Host ("  Credential on SP: '{0}' start {1} end {2}" -f $c.displayName, $c.startDateTime, $c.endDateTime) }
    }
}

Write-Host "`n=== 2. Credentials added to any app or service principal since $sinceIso ==="
$hits = 0
$objs = @(Get-All "$G/v1.0/applications?`$select=displayName,appId,keyCredentials,passwordCredentials&`$top=999") +
        @(Get-All "$G/v1.0/servicePrincipals?`$select=displayName,appId,keyCredentials,passwordCredentials&`$top=999")
foreach ($o in $objs) {
    foreach ($c in @($o.passwordCredentials) + @($o.keyCredentials)) {
        if ($c -and [datetime]$c.startDateTime -ge $Since) {
            $hits++
            Write-Host ("NEW CREDENTIAL  {0} ({1})  '{2}'  start {3} UTC" -f $o.displayName, $o.appId, $c.displayName, ([datetime]$c.startDateTime).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) -ForegroundColor Yellow
        }
    }
}
if ($hits -eq 0) { Write-Host 'None.' }

Write-Host "`n=== 3. Directory audit since $sinceIso (times UTC) ==="
$acts = 'Add member to role','Add service principal credentials','Update application - Certificates and secrets management',
        'Consent to application','Add app role assignment to service principal','Add delegated permission grant'
$n = 0
foreach ($act in $acts) {
    $f = [uri]::EscapeDataString("activityDisplayName eq '$act' and activityDateTime ge $sinceIso")
    foreach ($e in (Get-All "$G/v1.0/auditLogs/directoryAudits?`$filter=$f")) {
        $actor = if ($e.initiatedBy.app.displayName) { 'APP ' + $e.initiatedBy.app.displayName } else { "$($e.initiatedBy.user.userPrincipalName) from $($e.initiatedBy.user.ipAddress)" }
        $tgt = ($e.targetResources | ForEach-Object { $_.displayName } | Where-Object { $_ }) -join ', '
        $perm = ($e.targetResources.modifiedProperties | Where-Object displayName -eq 'AppRole.Value' | ForEach-Object { $_.newValue }) -join ' '
        $line = "{0}  {1}  by {2}  target {3} {4}" -f ([datetime]$e.activityDateTime).ToUniversalTime().ToString('yyyy-MM-dd HH:mm'), $act, $actor, $tgt, $perm
        $isCw = $CwApps.Values | Where-Object { $line -match [regex]::Escape($_) }
        if ($isCw -or $line -match 'SkyKick|ConnectWise') { $findings++; Write-Host $line -ForegroundColor Red } else { Write-Host $line }
        $n++
    }
}
if ($n -eq 0) { Write-Host 'None.' }

Write-Host "`n=== 4. Service principal sign-ins from attacker IP since $sinceIso ==="
try {
    $f = [uri]::EscapeDataString("createdDateTime ge $sinceIso and ipAddress eq '$AttackerIp' and signInEventTypes/any(t: t eq 'servicePrincipal')")
    $r = Get-All "$G/beta/auditLogs/signIns?`$filter=$f&`$top=50"
    if (-not $r) { Write-Host 'None.' }
    foreach ($s in $r) { $findings++; Write-Host ("{0}  {1} ({2})  error {3}" -f $s.createdDateTime, $s.appDisplayName, $s.appId, $s.status.errorCode) -ForegroundColor Red }
} catch { Write-Host "Sign-in query failed (needs Entra ID P1 and AuditLog.Read.All): $($_.Exception.Message)" -ForegroundColor Yellow }

Write-Host ("`nDone for {0}. Hard findings: {1}. Review section 2 and 3 entries by hand. Nothing was changed." -f $org.displayName, $findings)
Disconnect-MgGraph | Out-Null
