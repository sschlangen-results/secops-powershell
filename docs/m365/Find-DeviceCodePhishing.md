[← Back to all scripts](../../README.md)

# Find-DeviceCodePhishing.ps1

**Question:** has anyone in this tenant been phished with an "enter this code" prompt, and did an attacker register a device to stay in?

| | |
|---|---|
| Script | [`scripts/m365/Find-DeviceCodePhishing.ps1`](../../scripts/m365/Find-DeviceCodePhishing.ps1) |
| Changes anything | No. Read-only. |
| Module | `Microsoft.Graph.Authentication` |
| Licensing | Entra ID P1 for sign-in logs |
| Roles you need | Global Reader plus Reports Reader, or Security Reader |
| Run time | One to five minutes, longer on very large tenants |

## Why this exists

A device-code phish sends a user a message like "enter this code to open the shared document." The page they land on is a real Microsoft page, so nothing looks wrong. When they type the code, the attacker's session receives their tokens. MFA does not help, because the user completed it themselves. Current phishing kits then register an attacker-controlled device in Entra ID, which keeps working after a password reset and a token revoke.

## Run it

```powershell
pwsh -NoProfile -File .\scripts\m365\Find-DeviceCodePhishing.ps1 -Tenant customer.com
```

| Option | Use it when |
|---|---|
| `-KnownEgress '203.0.113.','198.51.100.'` | You know the office or VPN public IP ranges. Broker sign-ins from inside them are skipped. |
| `-LookbackDays 14` | You want a shorter window. The maximum is 30. |
| `-DeviceCode` | You can't open a browser on this machine. |
| `-Environment USGov` | GCC High or DoD tenants only. |

## What it checks

1. Whether a Conditional Access policy blocks the device code flow, whether it is enforced, and who is excluded
2. Successful device code sign-ins
3. Device code sign-ins blocked by Conditional Access, error 53003
4. Microsoft Authentication Broker sign-ins from outside your known egress, grouped by any IP serving several accounts
5. Bursts of device registrations by one account, and device names that match current kit naming
6. Automation user agents such as python-requests or curl

## What the colors mean here

| Color | In this script |
|---|---|
| 🔴 Red | A successful device code sign-in to a normal app. A Conditional Access block that is missing or not enforced. A burst of device registrations. A device named like a kit device. An automation user agent. Any check that could not run. |
| 🟡 Yellow | A blocked device code attempt: that user typed a stranger's code and probably did not report it. A device code sign-in to an admin command-line tool. An outside IP shared by several accounts. Exclusions on the block policy. |
| Plain | Counts and context. |

**About admin tools.** Your own admin sessions in Graph PowerShell, Teams PowerShell or Exchange PowerShell often use device code sign-in. They show yellow, not red. Confirm each one was yours. Attackers can use the same clients.

**About shared IPs.** Office networks, hotels, carrier NAT and VPN services also put several users behind one address. A shared IP is a lead to check, not a verdict.

## If you find something

1. For a successful device code sign-in you cannot explain, run [`Invoke-AccountCompromiseReview.ps1`](Invoke-AccountCompromiseReview.md) on that account first.
2. For a blocked attempt, contact the user. They received a phish and may have entered credentials elsewhere.
3. For a suspicious device, check who registered it and when, then disable it once approved. A password reset alone does not remove a registered device.
4. Get approval and a ticket before changing the tenant.

[← Back to all scripts](../../README.md)
