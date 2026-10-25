[← Back to all scripts](../../README.md)

# Find-GitHubSupplyChainIndicators.ps1

**Question:** does this GitHub organization hold any of this week's supply-chain indicators, such as a secret-stealing workflow or a pinned backdoored package?

| | |
|---|---|
| Script | [`scripts/github/Find-GitHubSupplyChainIndicators.ps1`](../../scripts/github/Find-GitHubSupplyChainIndicators.ps1) |
| Watchlist | The `GitHub` section of the newest file in [`watchlists/`](../../watchlists/) |
| Changes anything | No. Read-only. |
| Module | None. Needs PowerShell 7. |
| Access | A GitHub token that can read the organization's repositories: `GITHUB_TOKEN`, or a GitHub CLI login (`gh auth login`). A fine-grained token with read-only Contents access is enough. |
| Run time | A few seconds per repository with the default method |

## Run it

```powershell
pwsh -NoProfile -File .\scripts\github\Find-GitHubSupplyChainIndicators.ps1 -Org contoso
```

| Option | Use it when |
|---|---|
| `-Method Search` | The organization has hundreds of repositories and you accept that GitHub code search skips some. |
| `-Watchlist <path>` | You want a specific week. |

## How it looks

The default `Tree` method reads every active repository's default branch: the names of its workflow files, and the text of its dependency and build files (requirements files, `pyproject.toml`, Pipfiles, lock files, `package.json`, Dockerfiles, compose files and workflow YAML). It is slower but does not miss repositories.

`-Method Search` uses GitHub code search. It is fast, but GitHub does not index every repository, and in testing it returned nothing for repositories that did contain the indicator. Use it only for a first pass on a very large organization.

Both read default branches only.

## This week's checks (2026-10-24)

| Check | Red when |
|---|---|
| GhostAction workflows | A workflow file named `security-audit.yml` or `github_actions_security.yml` exists. |
| LiteLLM backdoored release | A dependency or build file contains `litellm==1.107.0`. |
| LiteLLM lookalike repository | A file references `Berri-AI/litellm` (the real one is `BerriAI/litellm`). |

## If you find something

1. Stop and escalate, and don't paste repository names into a ticket or pull request. Summarize them.
2. GhostAction: treat every secret the repository could read as stolen. Rotate them, remove the workflow, and find which account pushed it in the organization audit log.
3. LiteLLM: repin to 1.106.2, rebuild, and rotate anything the build or runtime held.
4. A clean result covers default branches as they are now. For a repository with a hit, review its Actions run history too.

[← Back to all scripts](../../README.md)
