[← Back to all scripts](../../README.md)

# Invoke-AccountCompromiseReview.ps1

**Question:** is this account compromised, and what could an attacker reach with it?

| | |
|---|---|
| Script | [`scripts/m365/Invoke-AccountCompromiseReview.ps1`](../../scripts/m365/Invoke-AccountCompromiseReview.ps1) |
| Changes anything | No. Read-only. |
| Modules | `Microsoft.Graph.Authentication`. Add `ExchangeOnlineManagement` for `-IncludeMailbox`. |
| Licensing | Entra ID P1 for sign-in logs, P2 for risk data |
| Roles you need | Global Reader plus Reports Reader, or Security Reader |
| Run time | Under a minute per account |

## When to run it

The first look after any of these:

- A user says they clicked a link or entered their password somewhere.
- A risky sign-in, impossible travel or unfamiliar sign-in alert.
- A new MFA method alert.
- A fake IT or help desk call over Teams or phone.
- A device code phishing hit from [`Find-DeviceCodePhishing.ps1`](Find-DeviceCodePhishing.md).

## Run it

```powershell
pwsh -NoProfile -File .\scripts\m365\Invoke-AccountCompromiseReview.ps1 -Tenant customer.com -User jdoe@customer.com -Since 2026-10-10
```

Set `-Since` to the day of the click or the alert. Anything after it gets the closest look.

| Option | Use it when |
|---|---|
| `-User a@customer.com,b@customer.com` | You want several accounts in one run. |
| `-HomeCountries US,CA` | The organization normally works from more than one country. |
| `-IncludeMailbox` | You also want forwarding, inbox rules and delegates. Signs in to Exchange Online separately. |
| `-OutputPath C:\cases\1234` | You want a JSON copy. It holds customer data, so keep it out of tickets, chat and this repo. |

## What it checks

**Is it compromised?**
- Sign-ins from a new IP where MFA was satisfied by a claim already in the token, with no fresh prompt. This is the tell for stolen-session phishing.
- Sign-ins from outside your home countries, and IPs first seen after `-Since`.
- Legacy protocols that skip modern MFA.
- Entra ID Protection risk level and detections.
- MFA methods added or changed after `-Since`.
- Device registrations, app consents and password events after `-Since`.
- With `-IncludeMailbox`: forwarding, rules that forward, redirect, delete or hide mail, and delegates.
- Dormancy: an enabled account nobody uses is an exposure on its own.

**What can it reach?**
- Active and PIM-eligible directory roles, flagged when privileged.
- Group count, registered devices and devices registered after `-Since`.

## What the colors mean here

| Color | In this script |
|---|---|
| 🔴 Red | Token-claim MFA from a new IP. Successful sign-ins from another country. Legacy protocol sign-ins. High or medium risk. A changed MFA method. A device registered after `-Since`. A privileged role. Mailbox forwarding or a forwarding rule. Dormant but enabled. |
| 🟡 Yellow | A new IP in a home country. Low risk or a risk detection. A password that predates `-Since`. App consents, device events. Rules that delete or hide mail. Delegates. Any check that could not run. |
| Plain | Counts and context. |

A privileged role shows red even on a clean account. That is deliberate: a compromise of that account is the worst case, so it gets the most care.

## If you find something

1. Get approval and a ticket before changing anything.
2. Revoke sessions, reset the password where the account is mastered (the script says cloud-only or synced from on-prem AD), and remove any MFA method or device the user cannot account for.
3. Remove forwarding and malicious rules, then check what was sent or forwarded.
4. Look for the same IPs across other accounts in the tenant.

[← Back to all scripts](../../README.md)
