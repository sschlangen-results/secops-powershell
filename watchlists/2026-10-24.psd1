# Week of 2026-10-24. Source list: grcengineer.com "This Week Was (Is) a Vulnpocalypse",
# "Your week, in one scroll". Versions and indicators copied from the linked vendor advisories
# and write-ups; see each entry's Source.
@{
    Name  = 'Week of 2026-10-24'
    Since = '2026-10-08'

    # ---- Checked on a Windows host by Find-WeeklyVulnExposure.ps1 ---------------------
    Host = @(
        @{
            Id = 'php'; Title = 'PHP runtime (PHP2Shell, CVE-2026-109618 and CVE-2026-109619)'
            Type = 'ExeVersion'; Names = @('php.exe', 'php-cgi.exe'); BranchParts = 2
            Fixed = @('8.2.35', '8.3.36', '8.4.27', '8.5.12'); Exploited = $true
            Advice = 'Exploited in the wild. Upgrade to the fixed release for its branch. 7.4, 8.0 and 8.1 got source backports only; treat them as needing replacement.'
            Source = 'https://www.bleepingcomputer.com/news/security/php-ships-emergency-patches-for-critical-php2shell-flaws/'
        }
        @{
            Id = 'node'; Title = 'Node.js runtime (October 2026 security releases, 10 CVEs including RCE)'
            Type = 'ExeVersion'; Names = @('node.exe'); BranchParts = 1
            Fixed = @('22.23.4', '24.22.1', '26.12.1'); Exploited = $false
            Advice = 'Upgrade to the fixed release for its major version. Majors not listed are end of life.'
            Source = 'https://nodejs.org/en/blog/vulnerability/october-2026-security-releases'
        }
        @{
            Id = 'firefox'; Title = 'Firefox (eMudhra intermediate certificates distrusted)'
            Type = 'ExeVersion'; Names = @('firefox.exe'); BranchParts = 1
            Fixed = @('115.43.1', '153.5.1', '158.0.1'); Exploited = $null
            Advice = 'Update to 158.0.1, ESR 115.43.1 or ESR 153.5.1. OneCRL normally protects current installs; old or locked-down installs miss it.'
            Source = 'https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/'
        }
        @{
            Id = 'litellm'; Title = 'LiteLLM Python package backdoored release 1.107.0'
            Type = 'PythonPackage'; Package = 'litellm'; BadVersions = @('1.107.0')
            Files = @('cook.pth', 'cook.py'); ReviewFiles = @('sitecustomize.py'); Exploited = $true
            Advice = 'Do not run pip install first. Delete cook.pth, cook.py, sitecustomize.py and their __pycache__ files from every site-packages, stop the detached python process, reinstall pinned to 1.106.2, and rotate every key the host or LiteLLM proxy held.'
            Source = 'https://docs.litellm.ai/blog/security-incident-oct-21-2026'
        }
        @{
            Id = 'ovhcloud-cli'; Title = 'OVHcloud CLI release binaries swapped for a secret stealer'
            Type = 'FileVersion'; NamePattern = 'ovhcloud*.exe'; BadVersions = @('0.11.0', '0.12.0', '0.13.0', '0.14.0', '0.15.0')
            Exploited = $true
            Advice = 'Remove it or update to 0.16.0, clean the host, and rotate every secret stored on a machine that ran 0.11.0 to 0.15.0.'
            Source = 'https://www.bleepingcomputer.com/news/security/ovhcloud-cli-releases-backdoored-on-github-to-steal-developer-secrets/'
        }
        @{
            Id = 'rank-math-pro'; Title = 'Rank Math PRO WordPress plugin backdoored (CVE-2026-111862)'
            Type = 'WordPressPlugin'; Slug = 'seo-by-rank-math-pro'; AltSlugs = @('rank-math-pro'); BadVersions = @('3.0.123')
            Files = @('wp-includes\class-wp-cache-util.php'); Exploited = $true
            Advice = 'Only copies downloaded 2026-10-15 20:02 UTC to 2026-10-16 07:12 UTC were backdoored; the version alone does not prove it. Restore from a backup before 10-15 or follow the vendor cleanup, then install 3.0.124 and rotate WordPress, database and hosting credentials.'
            Source = 'https://thehackernews.com/2026/10/popular-wordpress-seo-plugin-rank-math.html'
        }
        @{
            Id = 'beyondtrust'; Title = 'BeyondTrust Remote Support and PRA (CVE-2026-102764, exploited since August)'
            Type = 'InstalledProgram'; Match = 'BeyondTrust|Bomgar'; Exploited = $true
            Advice = 'A client on this host means the customer runs BeyondTrust. The flaw is on the Remote Support appliance (26.2.3 and earlier). Confirm the appliance is patched; Mandiant says treat an internet-facing appliance that was vulnerable during the window as possibly compromised.'
            Source = 'https://bleepingcomputer.com/news/security/beyondtrust-patches-zero-day-exploited-in-attacks-since-august'
        }
    )

    # ---- Checked in a GitHub organization by Find-GitHubSupplyChainIndicators.ps1 ------
    GitHub = @(
        @{
            Id = 'ghostaction'; Title = 'GhostAction fake workflows that steal Actions secrets'
            Type = 'WorkflowFile'; FileNames = @('security-audit.yml', 'github_actions_security.yml')
            Advice = 'Treat every secret the repository could read as stolen. Rotate them, remove the workflow, and find which account pushed it.'
            Source = 'https://thehackernews.com/2026/10/ghostaction-compromises-about-1900.html'
        }
        @{
            Id = 'litellm-pin'; Title = 'LiteLLM 1.107.0 pinned in a repository'
            Type = 'CodeSearch'; Query = '"litellm==1.107.0"'
            Advice = 'Repin to 1.106.2 and rotate anything the build or runtime environment held.'
            Source = 'https://docs.litellm.ai/blog/security-incident-oct-21-2026'
        }
        @{
            Id = 'litellm-lookalike'; Title = 'Reference to the lookalike repository Berri-AI/litellm'
            Type = 'CodeSearch'; Query = '"Berri-AI/litellm"'
            Advice = 'The real repository is BerriAI/litellm. Replace the reference and check what was pulled from the lookalike.'
            Source = 'https://docs.litellm.ai/blog/security-incident-oct-21-2026'
        }
    )

    # ---- Not visible from a host or GitHub. Check inventory and vendor consoles. -------
    Manual = @(
        @{ Title = 'GitLab self-managed, CVE-2026-110264 (CVSS 10, unauthenticated RCE) and 11 more'; Fix = 'Upgrade to 19.5.1, 19.4.3, 19.3.6, 19.2.9, 19.1.9, 19.0.10 or 18.11.13.'; Source = 'https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-1-released/' }
        @{ Title = 'Ivanti Connect Secure, CVE-2026-104935, exploited, in CISA KEV'; Fix = 'Upgrade to 22.8R2.5, 25.1.1.2, 25.1.3.0 or 25.1.3.1, and run the vendor integrity checker.'; Source = 'https://www.rapid7.com/blog/post/etr-ivanti-connect-secure-zero-day-exploited-in-the-wild-cve-2026-104935/' }
        @{ Title = 'Palo Alto PAN-OS, CVE-2026-0322, exploited, in CISA KEV'; Fix = 'Apply the fixed release from the Palo Alto advisory. The news source gave no version.'; Source = 'https://securityweek.com/palo-alto-networks-patches-pan-os-zero-day-exploited-for-remote-code-execution' }
        @{ Title = 'Cisco Secure Email Gateway, CVE-2026-76519, exploited'; Fix = 'Exposed when File Reputation is on and Content Scanner Tools is below 25.3.0.5525. Run contentscannerstatus and check for the "System Security" compromise log messages.'; Source = 'https://bleepingcomputer.com/news/security/cisco-patches-actively-exploited-secure-email-gateway-zero-day' }
        @{ Title = 'BeyondTrust Remote Support appliance, CVE-2026-102764'; Fix = 'Patch self-hosted Remote Support and PRA. SaaS was patched 2026-10-08.'; Source = 'https://bleepingcomputer.com/news/security/beyondtrust-patches-zero-day-exploited-in-attacks-since-august' }
        @{ Title = 'npm Trusted Publishing bound to renamed, moved or deleted repositories'; Fix = 'Package maintainers run npm trust list and rebind anything pointing at a repository they no longer control.'; Source = 'https://www.helpnetsecurity.com/?p=387687' }
        @{ Title = 'ConnectWise Cloud Backup app credential abused in Microsoft 365 tenants'; Fix = 'Run Check-CwCloudBackupExposure.ps1 against each tenant.'; Source = 'https://www.helpnetsecurity.com/?p=388341' }
        @{ Title = 'Railway environment variables accessed'; Fix = 'Roll every environment variable and registry credential stored in Railway.'; Source = 'https://blog.railway.com/p/security-disclosure-wednesday-october-21st' }
        @{ Title = 'Zeabur plaintext admin credentials, platform shutting down'; Fix = 'Move workloads off Zeabur and rotate every secret stored there.'; Source = 'https://bleepingcomputer.com/news/security/zeabur-shutting-down-after-second-security-breach-in-two-months' }
        @{ Title = 'OpenCode Console stored AI provider keys exposed'; Fix = 'Users notified by OpenCode revoke and replace those keys with each AI provider. The open source CLI is not affected.'; Source = 'https://techcrunch.com/2026/10/19/hackers-hit-ai-coding-tool-opencode-running-up-charges-on-users-ai-accounts/' }
        @{ Title = 'TiDB Cloud service-account credentials stolen'; Fix = 'Follow the TiDB customer actions page and rotate credentials.'; Source = 'https://www.pingcap.com/trust-hub/security/customer-actions-october-2026/' }
    )
}
