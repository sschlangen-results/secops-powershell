[← Back to all scripts](README.md)

# Contributing

## Rules

These apply to every commit, every pull request and every guide.

- **No PII of any kind.** No names, emails, phone numbers, usernames, hostnames, customer asset IPs, tenant IDs or customer domains. Use `contoso.com` style placeholders.
- **No customer names.** A script is about a technique, not a client.
- **No secrets.** No passwords, keys, tokens, certificates or connection strings, not even expired ones.
- **Read-only by default.** Anything that changes a tenant or host needs an `-Apply` switch, a `-WhatIf` path and a warning at the top of the file.
- **Defang indicators in docs.** Write `198.51.100[.]7` and `bad[.]example`. Code may hold the live value it has to match.
- **Stop on the wrong tenant.** Graph scripts sign out first, confirm the tenant before any query, and use process-scoped sign-in.
- **Same colors everywhere.** Red for hard findings, yellow for review, plain for context, and a findings count on the last line.

## Adding a script

1. Branch from `main`.
2. Put the script under `scripts/<platform>/`, for example `scripts/m365/`. Start a new platform folder when the first script for it lands.
3. Add comment-based help: synopsis, description, requirements and at least one example.
4. Write a guide at `docs/<platform>/<ScriptName>.md`. Copy the layout of an existing guide: the question, how to run it, what it checks, what the colors mean, what to do on a finding.
5. Add one row to the table in the main [README](README.md). The README holds the table and the general steps only, never script details.
6. Run it against a tenant you are authorized to read and confirm the output prints nothing you would not want in a pull request.
7. Open a pull request and complete the checklist.

## Layout

```
scripts/<platform>/   the scripts
docs/<platform>/      one guide per script
README.md             script table and general how-to
CONTRIBUTING.md       this page
.github/              pull request checklist
```

[← Back to all scripts](README.md)
