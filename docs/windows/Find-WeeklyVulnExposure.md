[← Back to all scripts](../../README.md)

# Find-WeeklyVulnExposure.ps1

**Question:** does this Windows host run any of this week's vulnerable or backdoored software?

| | |
|---|---|
| Script | [`scripts/windows/Find-WeeklyVulnExposure.ps1`](../../scripts/windows/Find-WeeklyVulnExposure.ps1) |
| Watchlist | [`watchlists/2026-10-24.psd1`](../../watchlists/2026-10-24.psd1), the newest one is used by default |
| Changes anything | No. Read-only. |
| Module | None. Runs on Windows PowerShell 5.1 or PowerShell 7, so it works from an RMM. |
| Rights | Run elevated or as SYSTEM to see every user profile. |
| Run time | One to five minutes, depending on how many profiles and Python environments the host has |

## Run it

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Find-WeeklyVulnExposure.ps1
```

From an RMM, copy the script and the watchlist to the host, then pass the watchlist path:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Find-WeeklyVulnExposure.ps1 -Watchlist .\2026-10-24.psd1 -ShowManual:$false
```

| Option | Use it when |
|---|---|
| `-Watchlist <path>` | You want a specific week, or the script is not running from the repo. |
| `-WebRoots 'D:\Sites'` | The host serves WordPress sites from a folder other than inetpub, xampp, wamp or laragon. |
| `-ShowManual:$false` | You want short RMM output without the list of items a host cannot show. |

## This week's watchlist (2026-10-24)

Built from the "Your week, in one scroll" table in GRC Engineer's [This Week Was (Is) a Vulnpocalypse](https://grcengineer.com/p/this-week-was-is-a-vulnpocalypse-3-ways-grc-can-help/), with every version and indicator taken from the linked vendor advisory or write-up.

| Item | What the host check looks for | Red when |
|---|---|---|
| PHP (PHP2Shell, CVE-2026-109618 and CVE-2026-109619) | `php.exe` and `php-cgi.exe` on PATH and in common install folders | Below 8.2.35, 8.3.36, 8.4.27 or 8.5.12 for its branch, or an older branch. Exploited in the wild. |
| Node.js (October 2026 releases, 10 CVEs) | `node.exe`, including nvm and per-user installs | Below 22.23.4, 24.22.1 or 26.12.1 prints yellow. Not reported exploited. |
| Firefox (eMudhra certificates distrusted) | `firefox.exe` | Below 158.0.1, ESR 115.43.1 or ESR 153.5.1 prints yellow. |
| LiteLLM 1.107.0 (backdoored release) | `litellm-1.107.0.dist-info`, `cook.pth` and `cook.py` in every Python site-packages folder | Any of them is present. `sitecustomize.py` prints yellow. |
| OVHcloud CLI 0.11.0 to 0.15.0 (binaries swapped) | Executables named `ovhcloud*.exe` | The file version is one of the five bad releases. |
| Rank Math PRO 3.0.123 (backdoored plugin, CVE-2026-111862) | WordPress sites under the web roots | The plugin is at 3.0.123 or `wp-includes\class-wp-cache-util.php` exists. |
| BeyondTrust (CVE-2026-102764, exploited) | Installed BeyondTrust or Bomgar clients | Yellow only. The flaw is on the appliance; a client tells you the customer runs one. |

Items a host cannot show print at the end: GitLab, Ivanti, PAN-OS, Cisco Secure Email Gateway, the BeyondTrust appliance, npm Trusted Publishing, the ConnectWise app credential, Railway, Zeabur, OpenCode Console and TiDB Cloud. GitHub items are covered by [Find-GitHubSupplyChainIndicators.ps1](../github/Find-GitHubSupplyChainIndicators.md).

## What the colors mean here

| Color | In this script |
|---|---|
| 🔴 Red | A vulnerable version of something exploited in the wild, or a backdoor file or release is present. |
| 🟡 Yellow | Vulnerable but not reported exploited, a version that could not be read, a branch the advisory does not list, or a product to confirm on its appliance. |
| Plain | Found and at or above the fix, or not found. |

**Clean result:** zero red lines, and every yellow line has an owner and a date.

## If you find something

1. Stop and escalate. Don't change the host without approval and a ticket.
2. Each red line ends with the vendor's remediation steps. For LiteLLM and OVHcloud CLI, assume secrets on that host were stolen: rotate them before you clean up, not after.
3. For runtimes, patch by the CISA due date if the CVE is in the [KEV catalog](../research/Get-KevRecent.md), otherwise by your normal SLA.

## Making next week's watchlist

1. Copy the newest file in `watchlists/` and rename it to the new date.
2. Replace the entries. Each one needs a `Source` link to the advisory you took its versions from.
3. Use the check types the script supports: `ExeVersion`, `FileVersion`, `PythonPackage`, `WordPressPlugin` and `InstalledProgram`. `BranchParts = 2` compares by major.minor (PHP), `1` by major (Node.js, Firefox).
4. Short on time? The optional, paid [Invoke-DeepApiResearch.ps1](../research/Invoke-DeepApiResearch.md) drafts the versions and indicators with sources. Verify them before they go in a watchlist.

[← Back to all scripts](../../README.md)
