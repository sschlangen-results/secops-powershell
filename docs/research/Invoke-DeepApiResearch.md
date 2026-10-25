[← Back to all scripts](../../README.md)

# Invoke-DeepApiResearch.ps1

> **Optional and paid.** Nothing else in this repo needs it. The free path is [Get-KevRecent.ps1](Get-KevRecent.md) plus reading the vendor advisories yourself. Use this script when a busy week makes an AI-assisted, cited first draft worth a few cents to a dollar per question.

**Question:** what are the fixed versions, exploitation status and indicators for this week's vulnerabilities, or what is a customer's public security picture?

| | |
|---|---|
| Script | [`scripts/research/Invoke-DeepApiResearch.ps1`](../../scripts/research/Invoke-DeepApiResearch.ps1) |
| Changes anything | No. It never touches a tenant or host. |
| Cost | Paid per question through your own DeepAPI account. Default cap $0.75 per run. |
| Module | None. Needs PowerShell 7. |
| Run time | About one to three minutes per question |

## Set up DeepAPI (once)

1. Create an account at [deepapi.co](https://deepapi.co) and add credits on the [credits page](https://deepapi.co/credits). Auto top-up is optional.
2. Create an API key in the DeepAPI dashboard. This project is bring-your-own-key: use your own key, never a shared one, so spend and requests trace to you.
3. Store the key as an environment variable, not in a file in this repo.

   Windows, for your user only:

   ```powershell
   [Environment]::SetEnvironmentVariable('DEEPAPI_API_KEY', '<your key>', 'User')
   ```

   Open a new PowerShell window afterwards.

   macOS or Linux, in your shell profile (`~/.zshrc` or `~/.bashrc`), or better, read it from your password manager at the start of a session:

   ```bash
   export DEEPAPI_API_KEY="$(op read 'op://<vault>/<item>/credential')"
   ```

4. Check it works without spending anything:

   ```powershell
   pwsh -NoProfile -File .\scripts\research\Invoke-DeepApiResearch.ps1 -Mode Vulns -Items PHP -DryRun
   ```

   A dry run validates the request and prints the most it could charge. Nothing runs and nothing is billed.

`DEEPAPI_API_BASE_URL` is optional and defaults to `https://deepapi.co`.

## Run it

This week's vulnerabilities:

```powershell
pwsh -NoProfile -File .\scripts\research\Invoke-DeepApiResearch.ps1 -Mode Vulns -Items "PHP,Node.js,GitLab,LiteLLM"
```

A free-form question:

```powershell
.\scripts\research\Invoke-DeepApiResearch.ps1 -Mode Vulns -Query "Which edge appliance zero-days were exploited this week, and what are the fixed versions?"
```

A customer or prospect, before onboarding or an assessment:

```powershell
.\scripts\research\Invoke-DeepApiResearch.ps1 -Mode Company -Company "Contoso Ltd" -Domain contoso.com
```

| Option | Use it when |
|---|---|
| `-DryRun` | You want to see the cost hold before running. |
| `-MaxCostUsd 1.5` | The question is broad and deserves more research depth. The minimum is 0.35. |
| `-OutDir <folder>` | You want the brief saved somewhere other than `.\research-output`. |

## What you get

A Markdown brief in `.\research-output\` with one section per item and a numbered source list. The same answer prints to the console.

Vulns mode covers CVEs, affected and fixed versions, exploited or not with evidence, indicators to hunt for, what a Windows host, Microsoft 365 tenant or GitHub organization would show, and the vendor's remediation steps.

Company mode covers publicly reported incidents and breaches, technology and vendors the organization is publicly known to use, internet-facing services named in news or job postings, regulatory items and recent news. It is told not to collect employee details.

## Automation idea: research, then hunt

1. Monday morning, run [Get-KevRecent.ps1](Get-KevRecent.md) for free to see what CISA added.
2. Feed the products your customers run into this script in Vulns mode.
3. Check the brief's versions and indicators against the linked vendor advisories, then copy them into a new watchlist for [Find-WeeklyVulnExposure.ps1](../windows/Find-WeeklyVulnExposure.md).
4. Push the hunt through your RMM.

Steps 1 and 2 can run on a schedule. Step 3 stays human, because a wrong version number in a watchlist means a missed host.

## Rules for using it

- Send public names, products and CVEs only. Never send internal hostnames, IPs, user names, tenant IDs, ticket text or anything a customer shared in confidence. Everything you pass goes to a third-party service.
- Treat the output as a draft. AI research can be wrong or stale. Verify every version, hash and indicator against its source before hunting or telling a customer.
- Briefs about a named customer stay out of git and out of pull requests. `research-output/` is already ignored.
- Check with your manager before running Company mode on a customer if your contract or their policy restricts sharing their name with outside services.

## Common problems

| Problem | Fix |
|---|---|
| `DEEPAPI_API_KEY is not set` | Step 3 of setup was skipped, or the window was opened before the variable was set. |
| `out of credits` | Add credits at [deepapi.co/credits](https://deepapi.co/credits). |
| The brief says it stopped at the output limit | Run the missing items again on their own, or raise `-MaxCostUsd`. |

[← Back to all scripts](../../README.md)
