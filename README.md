<div align="center">

# SecOps PowerShell

**Field-tested PowerShell for security analysts.** Read-only checks first, clear output, and nothing that ties back to a customer.

![PowerShell 7+](https://img.shields.io/badge/PowerShell-7%2B-5391FE?logo=powershell&logoColor=white)
![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-Authentication%20module-0078D4?logo=microsoft&logoColor=white)
![Default mode](https://img.shields.io/badge/default-read--only-2ea44f)
![PII](https://img.shields.io/badge/PII-none-critical)

</div>

---

## Scripts

| Script | Area | What it answers | Changes anything? |
|---|---|---|---|
| [`Check-CwCloudBackupExposure.ps1`](scripts/m365/Check-CwCloudBackupExposure.ps1) | Microsoft 365 / Entra ID | Was this tenant exposed to the Oct 2026 ConnectWise Cloud Backup (SkyKick) supply-chain attack? | No |

New scripts are listed here as they land.

---

## Quick start

```powershell
# One-time setup
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

# Run a check against one tenant (opens a browser sign-in)
pwsh -NoProfile -File .\scripts\m365\Check-CwCloudBackupExposure.ps1 -Tenant customer.com

# Sign in on another device instead
pwsh -NoProfile -File .\scripts\m365\Check-CwCloudBackupExposure.ps1 -Tenant customer.com -DeviceCode

# GCC High or DoD tenants only. GCC Moderate uses the default.
pwsh -NoProfile -File .\scripts\m365\Check-CwCloudBackupExposure.ps1 -Tenant customer.us -Environment USGov
```

Every Graph script signs out before it starts, confirms it landed in the tenant you named, and stops if it did not. That keeps a cached token from the last customer from answering for this one.

---

## ConnectWise Cloud Backup exposure check

<details>
<summary><b>Background</b></summary>

<br>

In October 2026 an attacker used the shared secret for ConnectWise Cloud Backup (formerly SkyKick) to sign in to customer tenants as the backup application. There was no user sign-in, so MFA and Conditional Access did not apply. In some tenants the Cloud Management service principals gave themselves directory roles, most often Exchange Administrator, and added credentials for persistence. ConnectWise disabled the seven app identities on 2026-10-17, but that does not remove anything planted inside a tenant, and tokens already issued stay valid until they expire.

Only the Cloud Backup and Cloud Management product line is named. ConnectWise Manage, RMM and ScreenConnect are not.

</details>

<details>
<summary><b>What it checks</b></summary>

<br>

1. The seven ConnectWise / SkyKick app identities, plus any app with "SkyKick" in its name
2. For any found: directory roles held, app permissions granted, credentials attached
3. Secrets or certificates added to **any** app or service principal since 2026-10-13
4. Directory audit since 2026-10-13: role assignments, credential adds, consents, app permission grants
5. Service principal sign-ins from the attacker IP (needs Entra ID P1)

</details>

<details>
<summary><b>Reading the output</b></summary>

<br>

| Color | Meaning |
|---|---|
| Red | Hard finding. One of the seven apps, activity by one of them, or a sign-in from the attacker IP. |
| Yellow | Review by hand. A new credential or a SkyKick name match. |
| Plain | Context. Usually your own automation, user consents, PIM activations or MSP tool refreshes. |

The last line prints the count of hard findings. Zero red lines plus no unexplained credentials is a clean result.

</details>

<details>
<summary><b>If you get a finding</b></summary>

<br>

Get approval and a ticket before touching the tenant. Then: disable the seven service principals, remove any directory roles they hold, remove credentials added to any app since 2026-10-13, review OAuth grants and Graph activity, and revoke the apps' tokens. Revoking user sessions does not end app access.

</details>

**Permissions:** delegated `Application.Read.All`, `Directory.Read.All`, `AuditLog.Read.All`, `RoleManagement.Read.Directory`. Global Reader plus Reports Reader is enough.

---

## Rules for this repo

These apply to every commit and every pull request.

- **No PII of any kind.** No names, emails, phone numbers, usernames, hostnames, IP addresses of customer assets, tenant IDs or customer domains. Use `contoso.com` style placeholders.
- **No customer names.** A script is about a technique, not a client.
- **No secrets.** No passwords, keys, tokens, certificates or connection strings, not even expired ones.
- **Read-only by default.** Anything that changes a tenant or host needs a `-Apply` switch, a `-WhatIf` path, and a clear warning at the top of the file.
- **Defang indicators in docs.** Write `198.51.100[.]7` and `bad[.]example`. Code may hold the live value it needs to match.
- **Stop on the wrong tenant.** Graph scripts sign out first, verify the tenant, and use process-scoped auth.
- **Comment-based help on every script.** Synopsis, description, requirements and at least one example.

---

## Layout

```
scripts/
  m365/        Microsoft 365, Entra ID, Exchange Online, Purview
.github/
  pull_request_template.md
```

New areas get their own folder under `scripts/` when the first script for them lands.

---

## Contributing

1. Branch from `main`.
2. Add the script with comment-based help and update the table at the top of this README.
3. Run it once against a tenant you are authorized to read and confirm it prints nothing identifying.
4. Open a pull request and complete the checklist.

<div align="center">
<sub>Internal use. Run only against environments you are authorized to access.</sub>
</div>
