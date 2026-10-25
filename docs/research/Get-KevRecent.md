[← Back to all scripts](../../README.md)

# Get-KevRecent.ps1

**Question:** of everything disclosed this week, which vulnerabilities has CISA confirmed are being exploited?

| | |
|---|---|
| Script | [`scripts/research/Get-KevRecent.ps1`](../../scripts/research/Get-KevRecent.ps1) |
| Changes anything | No. Read-only. |
| Cost | Free. No account or key. |
| Module | None. Runs on Windows PowerShell 5.1 or PowerShell 7. |
| Run time | A few seconds |

## Run it

```powershell
pwsh -NoProfile -File .\scripts\research\Get-KevRecent.ps1
```

| Option | Use it when |
|---|---|
| `-Days 14` | You want a longer window than the default of 7 days. |
| `-Vendor "Microsoft,Ivanti,Cisco"` | You only care about products a customer runs. |
| `-CsvPath .\kev.csv` | You want a sortable list for a change request or a patch meeting. |
| `-Detail` | You want CISA's description and required action under each entry. |

## Why it matters

Monthly vulnerability disclosures roughly doubled during 2026, and only a small share is ever seen exploited. A flat "patch every critical in 14 days" rule gets missed at that volume, and the misses are not ranked. CISA's Known Exploited Vulnerabilities catalog is the free, public list of what attackers are actually using. Rank by it first, then hunt.

## What the colors mean here

| Color | In this script |
|---|---|
| 🔴 Red | CISA lists the entry as used in ransomware campaigns. |
| 🟡 Yellow | Exploited in the wild. Check whether any customer runs the product. |
| Plain | Description and required action, with `-Detail`. |

## Next steps

1. Match each entry against what your customers run. RMM software inventory and vulnerability scanner results are the quickest sources.
2. For anything a customer runs, hunt with [Find-WeeklyVulnExposure.ps1](../windows/Find-WeeklyVulnExposure.md) and patch by the CISA due date.
3. Want a sourced write-up of fixed versions and indicators without reading every advisory? See the optional, paid [Invoke-DeepApiResearch.ps1](Invoke-DeepApiResearch.md).

## Source

[CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), JSON feed.

[← Back to all scripts](../../README.md)
