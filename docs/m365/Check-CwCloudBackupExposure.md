[← Back to all scripts](../../README.md)

# Check-CwCloudBackupExposure.ps1

**Question:** was this Microsoft 365 tenant exposed to the October 2026 ConnectWise Cloud Backup (SkyKick) supply-chain attack?

| | |
|---|---|
| Script | [`scripts/m365/Check-CwCloudBackupExposure.ps1`](../../scripts/m365/Check-CwCloudBackupExposure.ps1) |
| Changes anything | No. Read-only. |
| Module | `Microsoft.Graph.Authentication` |
| Roles you need in the tenant | Global Reader plus Reports Reader |
| Run time | About a minute on a mid-size tenant |

## Run it

```powershell
pwsh -NoProfile -File .\scripts\m365\Check-CwCloudBackupExposure.ps1 -Tenant customer.com
```

| Option | Use it when |
|---|---|
| `-DeviceCode` | You can't open a browser on this machine |
| `-Environment USGov` | The tenant is GCC High or DoD. GCC Moderate does not need it. |
| `-Since 2026-10-01` | You want to look back further than the default of 2026-10-13 |

## What happened

An attacker used the shared secret for ConnectWise Cloud Backup to sign in to customer tenants as the backup application itself. There was no user sign-in, so MFA and Conditional Access did not stop it. In some tenants the ConnectWise Cloud Management apps gave themselves admin roles, most often Exchange Administrator, and added credentials so they could come back. ConnectWise disabled its apps on 2026-10-17. That does not remove anything the attacker left inside a tenant, and tokens already issued keep working until they expire.

Only the Cloud Backup and Cloud Management products are affected. ConnectWise Manage, RMM and ScreenConnect are not named.

## What the script checks

1. Whether any of the seven ConnectWise / SkyKick apps exist in the tenant, plus anything named "SkyKick".
2. For any it finds: admin roles they hold, permissions granted, credentials attached.
3. New secrets or certificates added to **any** app since 2026-10-13.
4. Admin role changes, consents and permission grants since 2026-10-13.
5. App sign-ins from the attacker's IP address (needs Entra ID P1).

## What the colors mean here

| Color | In this script |
|---|---|
| 🔴 Red | One of the seven apps is present, one of them did something in the audit log, or a sign-in came from the attacker's IP |
| 🟡 Yellow | A new credential on any app since 10/13, or an app with "SkyKick" in its name |
| Plain | User consents, admin role activations, your own automation, MSP tool permission refreshes |

**Clean result:** zero red lines, and every yellow line has an explanation.

## If you find something

1. Stop and escalate. Do not change the tenant without approval and a ticket.
2. Once approved: disable the seven apps, remove any admin roles they hold, delete credentials added to any app since 2026-10-13, review consents and Graph activity, and revoke the apps' tokens.
3. Revoking user sessions does **not** end app access. The app itself has to be disabled and its credentials removed.

## The seven apps

| App | App ID |
|---|---|
| ConnectWise Cloud Backup | `506e08f9-6e9a-4da4-942b-a099a03644ae` |
| Cloud Management | `2399d300-6fca-4e6a-a686-399fefe75b83` |
| Cloud Management - MS Teams | `24205314-2b89-4e07-a2a4-579e898a5640` |
| Cloud Management - Exchange Online | `b78f6a77-d4e5-46fb-87e5-d1648bd02519` |
| Cloud Management - MS Graph | `0de14c77-b9b0-4137-9360-34878a929827` |
| Cloud Management - Partner Center | `412dcf96-176d-4b3a-a1b0-4981ad66971e` |
| Cloud Management - SharePoint Online | `b2b55f5b-7758-4719-8d8f-88ae172e6bdb` |

Older tenants may show them as "SkyKick Cloud Manager". Attacker IP: `144.172.64[.]128`.

## Sources

Public reporting from ConnectWise, Huntress, Microsoft and Todyl, October 2026.

[← Back to all scripts](../../README.md)
