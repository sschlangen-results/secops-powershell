<#
.SYNOPSIS
  READ-ONLY compromise review for one or more Microsoft 365 accounts. Changes nothing.

.DESCRIPTION
  The first look after "I clicked a link", a risky sign-in alert, an impossible-travel alert,
  a new-MFA-method alert or a fake IT call. For each account it answers two questions.

  Is it compromised?
    - Sign-ins where MFA was satisfied by a claim already in the token. This is the tell for
      adversary-in-the-middle phishing, where a proxy steals the session after the user
      completes MFA.
    - Sign-ins from countries outside -HomeCountries, and rare IPs seen only after -Since.
    - Legacy protocols (IMAP, POP, SMTP AUTH and similar) that skip modern MFA.
    - Entra ID Protection risk level and detections.
    - MFA methods registered or changed in the window. Attackers add their own method to stay in.
    - Device registrations, app consents and password events in the window.
    - With -IncludeMailbox: forwarding, inbox rules that forward, redirect or delete, delegates.

  What can it reach?
    - Active and PIM-eligible directory roles, flagged when privileged.
    - Groups, app role assignments, owned objects and registered devices.

  Also scores dormancy. An enabled account nobody signs in to is a standing exposure.

.PARAMETER Tenant
  The customer's primary domain or tenant ID.

.PARAMETER User
  One or more user principal names or email addresses.

.PARAMETER Since
  The date you believe exposure started, such as the click or the alert. Activity after this
  date is the focus. Defaults to 14 days ago.

.PARAMETER HomeCountries
  Two-letter country codes that are normal for this organization. Default US.

.PARAMETER IncludeMailbox
  Also check mailbox forwarding, inbox rules and delegates. Needs ExchangeOnlineManagement and
  a second sign-in.

.PARAMETER OutputPath
  Optional folder for a JSON copy of the results. The output holds customer data, so keep it
  out of tickets, chat and this repo.

.REQUIREMENTS
  PowerShell 7+, Microsoft.Graph.Authentication. ExchangeOnlineManagement for -IncludeMailbox.
  Read roles: Global Reader plus Reports Reader, or Security Reader. Entra ID P1 for sign-in
  logs, P2 for risk data.

.EXAMPLE
  pwsh -NoProfile -File .\Invoke-AccountCompromiseReview.ps1 -Tenant contoso.com -User jdoe@contoso.com

.EXAMPLE
  pwsh -NoProfile -File .\Invoke-AccountCompromiseReview.ps1 -Tenant contoso.com -User a@contoso.com,b@contoso.com -Since 2026-10-10 -IncludeMailbox
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $Tenant,
    [Parameter(Mandatory)][string[]] $User,
    [datetime] $Since = (Get-Date).AddDays(-14),
    [ValidateRange(1,30)][int] $LookbackDays = 30,
    [string[]] $HomeCountries = @('US'),
    [switch] $IncludeMailbox,
    [string] $OutputPath,
    [ValidateSet('Global','USGov','USGovDoD')][string] $Environment = 'Global',
    [switch] $DeviceCode
)
$ErrorActionPreference = 'Stop'
Import-Module Microsoft.Graph.Authentication

# ---- sign in clean and confirm the tenant -----------------------------------
Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
$scopes = 'User.Read.All','Directory.Read.All','AuditLog.Read.All','UserAuthenticationMethod.Read.All',
          'IdentityRiskyUser.Read.All','IdentityRiskEvent.Read.All','RoleManagement.Read.Directory','Device.Read.All'
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
function Enc    ([string]$s) { [uri]::EscapeDataString($s) }
function Get-GraphError($err) {
    # Graph puts the useful reason in the response body, not the exception text.
    $body = $err.ErrorDetails.Message
    if ($body) { try { $j = $body | ConvertFrom-Json; if ($j.error.message) { return "$($j.error.code): $($j.error.message)" } } catch {} ; return $body }
    $err.Exception.Message
}
function Get-All([string]$Uri, [string]$Label) {
    $out = @()
    try { while ($Uri) { $r = Invoke-MgGraphRequest GET $Uri; if ($null -ne $r.value) { $out += $r.value } else { $out += $r }; $Uri = $r.'@odata.nextLink' } }
    catch { Yellow "$Label could not be read, so treat it as UNKNOWN: $(Get-GraphError $_)" }
    ,$out
}
function Get-One([string]$Uri) { try { Invoke-MgGraphRequest GET $Uri } catch { $null } }
function CleanIp([string]$ip) { if ($ip -match '^(\d{1,3}(?:\.\d{1,3}){3}):\d+$') { $Matches[1] } else { $ip } }

$privRoles = 'Global Administrator','Privileged Role Administrator','Security Administrator','Exchange Administrator',
  'SharePoint Administrator','User Administrator','Application Administrator','Cloud Application Administrator',
  'Helpdesk Administrator','Authentication Administrator','Privileged Authentication Administrator',
  'Intune Administrator','Conditional Access Administrator','Teams Administrator','Groups Administrator'
$legacy = 'IMAP4','POP3','SMTP','Authenticated SMTP','Exchange ActiveSync','Exchange Web Services','MAPI Over HTTP','Other clients','AutoDiscover','Exchange Online PowerShell'
$lookback = (Get-Date).ToUniversalTime().AddDays(-$LookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
$sel = 'id,userPrincipalName,displayName,accountEnabled,createdDateTime,signInActivity,onPremisesSyncEnabled,lastPasswordChangeDateTime,userType'

$results = foreach ($who in $User) {
    Write-Host "`n=== $who ===" -ForegroundColor Cyan
    $u = Get-One "$GraphBase/v1.0/users/$(Enc $who)?`$select=$sel"
    if (-not $u) { $u = (Get-All "$GraphBase/v1.0/users?`$filter=$(Enc "mail eq '$who'")&`$select=$sel" 'user by mail') | Select-Object -First 1 }
    if (-not $u) { Yellow "Could not find '$who' in this tenant. Skipped."; continue }
    $id = $u.id; $upn = $u.userPrincipalName

    Plain ("Enabled {0} | {1} | created {2} | password last changed {3}" -f $u.accountEnabled, $(if ($u.onPremisesSyncEnabled) { 'synced from on-prem AD, reset it there' } else { 'cloud-only' }), $u.createdDateTime, $u.lastPasswordChangeDateTime)
    if ($u.lastPasswordChangeDateTime -and [datetime]$u.lastPasswordChangeDateTime -lt $Since) { Yellow "Password has not changed since before $($Since.ToString('yyyy-MM-dd')). If the credential was exposed, it is still live." }

    # Dormancy
    $last = @($u.signInActivity.lastSignInDateTime, $u.signInActivity.lastNonInteractiveSignInDateTime) | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1
    $days = if ($last) { [int]((Get-Date) - [datetime]$last).TotalDays } else { $null }
    if ($u.accountEnabled -and $null -eq $days) { Red 'Enabled with no sign-in on record. Nobody is watching this account.' }
    elseif ($u.accountEnabled -and $days -gt 90) { Red "Enabled but dormant for $days days. Consider deprovisioning, not just resetting." }
    elseif ($u.accountEnabled -and $days -gt 30) { Yellow "Last sign-in $days days ago." }

    # ---- Is it compromised? ----
    Write-Host "  -- compromise indicators --" -ForegroundColor DarkCyan
    $si = Get-All "$GraphBase/v1.0/auditLogs/signIns?`$filter=$(Enc "userId eq '$id' and createdDateTime ge $lookback")" 'sign-ins'
    $ok = @($si | Where-Object { $_.status.errorCode -eq 0 })
    $post = @($ok | Where-Object { [datetime]$_.createdDateTime -ge $Since })
    Plain ("Sign-ins in {0} days: {1} successful, {2} failed, {3} successful since {4}." -f $LookbackDays, $ok.Count, ($si.Count - $ok.Count), $post.Count, $Since.ToString('yyyy-MM-dd'))

    # A token claim satisfying MFA is normal for an existing session on a known device. It is the
    # stolen-session tell only when it comes from an IP the account had never used before -Since.
    $firstSeen = @{}
    foreach ($s in ($ok | Sort-Object createdDateTime)) { $k = CleanIp $s.ipAddress; if (-not $firstSeen.ContainsKey($k)) { $firstSeen[$k] = [datetime]$s.createdDateTime } }
    $aitm = @($ok | Where-Object {
        @($_.authenticationDetails.authenticationStepResultDetail) -match 'claim in the token' -and
        [datetime]$_.createdDateTime -ge $Since -and $firstSeen[(CleanIp $_.ipAddress)] -ge $Since })
    foreach ($grp in ($aitm | Group-Object { CleanIp $_.ipAddress })) {
        $s = $grp.Group[0]
        Red ("{0} sign-in(s) from new IP {1} ({2}/{3}) had MFA satisfied by a claim already in the token, with no fresh prompt. That is the stolen-session pattern from adversary-in-the-middle phishing." -f $grp.Count, $grp.Name, $s.location.city, $s.location.countryOrRegion)
    }

    $foreign = @($ok | Where-Object { $_.location.countryOrRegion -and $_.location.countryOrRegion -notin $HomeCountries })
    foreach ($grp in ($foreign | Group-Object { $_.location.countryOrRegion })) {
        Red ("{0} successful sign-in(s) from {1}, IPs {2}." -f $grp.Count, $grp.Name, ((@($grp.Group | ForEach-Object { CleanIp $_.ipAddress }) | Select-Object -Unique) -join ', '))
    }
    $byIp = $ok | Group-Object { CleanIp $_.ipAddress }
    foreach ($ip in $byIp) {
        $first = ($ip.Group | Sort-Object createdDateTime | Select-Object -First 1)
        if ([datetime]$first.createdDateTime -ge $Since -and $ip.Count -le 3 -and $first.location.countryOrRegion -in $HomeCountries) {
            Yellow ("New IP {0} first seen {1}, {2} sign-in(s), {3}/{4}, apps {5}." -f $ip.Name, $first.createdDateTime, $ip.Count, $first.location.city, $first.location.countryOrRegion, ((@($ip.Group.appDisplayName) | Select-Object -Unique) -join ', '))
        }
    }
    $leg = @($ok | Where-Object { $_.clientAppUsed -in $legacy })
    if ($leg) { Red ("{0} successful sign-in(s) over legacy protocols ({1}). These skip modern MFA." -f $leg.Count, ((@($leg.clientAppUsed) | Select-Object -Unique) -join ', ')) }

    $risky = (Get-All "$GraphBase/v1.0/identityProtection/riskyUsers?`$filter=$(Enc "id eq '$id'")" 'risky user') | Select-Object -First 1
    $det = Get-All "$GraphBase/v1.0/identityProtection/riskDetections?`$filter=$(Enc "userId eq '$id'")" 'risk detections'
    if ($risky -and $risky.riskLevel -in 'high','medium') { Red "Entra ID Protection risk: $($risky.riskLevel), state $($risky.riskState)." }
    elseif ($risky -and $risky.riskLevel -ne 'none') { Yellow "Entra ID Protection risk: $($risky.riskLevel), state $($risky.riskState)." }
    foreach ($d in ($det | Where-Object { [datetime]$_.detectedDateTime -ge $Since })) { Yellow ("Risk detection {0}: {1} ({2}) from {3}." -f $d.detectedDateTime, $d.riskEventType, $d.riskLevel, $d.ipAddress) }

    $methods = Get-All "$GraphBase/v1.0/users/$id/authentication/methods" 'MFA methods'
    $mt = @($methods | ForEach-Object { $_.'@odata.type' -replace '#microsoft\.graph\.','' -replace 'AuthenticationMethod','' })
    if (-not @($mt | Where-Object { $_ -notin 'password','email' })) { Red 'No MFA method registered beyond password.' } else { Plain "MFA methods: $($mt -join ', ')" }

    $aud = Get-All "$GraphBase/v1.0/auditLogs/directoryAudits?`$filter=$(Enc "targetResources/any(t:t/id eq '$id')")&`$top=200" 'directory audit'
    $aud = @($aud | Where-Object { [datetime]$_.activityDateTime -ge $Since })
    foreach ($e in $aud) {
        $by = if ($e.initiatedBy.user.userPrincipalName) { $e.initiatedBy.user.userPrincipalName } else { $e.initiatedBy.app.displayName }
        $line = "{0}  {1}  by {2}" -f $e.activityDateTime, $e.activityDisplayName, $by
        if ($e.activityDisplayName -match 'security info|authentication method|StrongAuthentication') { Red "MFA change: $line" }
        elseif ($e.activityDisplayName -match 'consent|permission grant|device') { Yellow $line }
        elseif ($e.activityDisplayName -match 'password') { Plain $line }
    }
    $grants = Get-All "$GraphBase/v1.0/oauth2PermissionGrants?`$filter=$(Enc "principalId eq '$id'")" 'app consents'
    foreach ($grant in $grants) { Plain "App consent: client $($grant.clientId) scopes '$($grant.scope.Trim())'" }

    # ---- What can it reach? ----
    Write-Host "  -- what it can reach --" -ForegroundColor DarkCyan
    $mo = Get-All "$GraphBase/v1.0/users/$id/memberOf?`$top=999" 'memberships'
    $roles = @($mo | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' } | ForEach-Object { $_.displayName })
    $elig = @((Get-All "$GraphBase/v1.0/roleManagement/directory/roleEligibilitySchedules?`$filter=$(Enc "principalId eq '$id'")&`$expand=roleDefinition" 'PIM eligible') | ForEach-Object { $_.roleDefinition.displayName })
    $priv = @(@($roles + $elig) | Where-Object { $_ -in $privRoles } | Select-Object -Unique)
    if ($priv) { Red "Privileged roles (active or eligible): $($priv -join ', '). Treat as an admin compromise." }
    $groups = @($mo | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' }).Count
    $dev = Get-All "$GraphBase/v1.0/users/$id/registeredDevices?`$select=displayName,operatingSystem,trustType,registrationDateTime" 'devices'
    Plain ("Roles: {0} | eligible: {1} | groups: {2} | registered devices: {3}" -f $(if ($roles) { $roles -join ', ' } else { 'none' }), $(if ($elig) { $elig -join ', ' } else { 'none' }), $groups, $dev.Count)
    foreach ($d in ($dev | Where-Object { $_.registrationDateTime -and [datetime]$_.registrationDateTime -ge $Since })) {
        Red "Device '$($d.displayName)' ($($d.operatingSystem), $($d.trustType)) registered $($d.registrationDateTime), after $($Since.ToString('yyyy-MM-dd')). Confirm the user owns it."
    }

    [pscustomobject]@{ User = $upn; Enabled = $u.accountEnabled; DormantDays = $days; SuccessfulSinceExposure = $post.Count
        TokenClaimMfa = $aitm.Count; ForeignSignIns = $foreign.Count; LegacySignIns = $leg.Count; Risk = $risky.riskLevel
        MfaMethods = $mt; PrivilegedRoles = $priv; RegisteredDevices = $dev.Count; AuditEventsSinceExposure = $aud.Count }
}

# ---- mailbox checks ------------------------------------------------------------
if ($IncludeMailbox -and $results) {
    Write-Host "`n=== Mailbox forwarding, rules and delegates ===" -ForegroundColor Cyan
    try {
        Import-Module ExchangeOnlineManagement
        Connect-ExchangeOnline -Organization $Tenant -ShowBanner:$false
        foreach ($r in $results) {
            $mbx = Get-Mailbox -Identity $r.User -ErrorAction SilentlyContinue
            if (-not $mbx) { Yellow "$($r.User): no mailbox."; continue }
            if ($mbx.ForwardingSmtpAddress -or $mbx.ForwardingAddress) { Red "$($r.User): mailbox forwards to $($mbx.ForwardingSmtpAddress)$($mbx.ForwardingAddress)." }
            foreach ($rule in @(Get-InboxRule -Mailbox $r.User -ErrorAction SilentlyContinue)) {
                if ($rule.ForwardTo -or $rule.RedirectTo -or $rule.ForwardAsAttachmentTo) { Red "$($r.User): rule '$($rule.Name)' forwards or redirects mail." }
                elseif ($rule.DeleteMessage -or $rule.MoveToFolder -match 'RSS|Archive|Conversation History|Junk') { Yellow "$($r.User): rule '$($rule.Name)' deletes or hides mail (move to '$($rule.MoveToFolder)'). Attackers use these to hide replies." }
            }
            foreach ($p in @(Get-MailboxPermission -Identity $r.User | Where-Object { -not $_.IsInherited -and $_.User -notlike 'NT AUTHORITY\*' })) {
                Yellow "$($r.User): delegate $($p.User) has $($p.AccessRights -join ',')."
            }
        }
        Disconnect-ExchangeOnline -Confirm:$false | Out-Null
    } catch { Yellow "Mailbox checks did not run: $($_.Exception.Message)" }
}

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
$results | Format-Table User, Enabled, DormantDays, SuccessfulSinceExposure, TokenClaimMfa, ForeignSignIns, LegacySignIns, Risk, RegisteredDevices -AutoSize
if ($OutputPath) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    $file = Join-Path $OutputPath ("account-review-{0:yyyyMMdd-HHmm}.json" -f (Get-Date))
    $results | ConvertTo-Json -Depth 6 | Set-Content $file
    Plain "JSON written to $file. It holds customer data. Keep it out of tickets, chat and this repo."
}
Write-Host ("Done for {0}. Hard findings: {1}. Nothing was changed." -f $org.displayName, $script:Findings)
Disconnect-MgGraph | Out-Null
