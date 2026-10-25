[← Back to all scripts](../../README.md)

# Find-UserProfilePersistence.ps1

**Question:** is something living in a user's profile on this Windows machine and starting itself?

| | |
|---|---|
| Script | [`scripts/windows/Find-UserProfilePersistence.ps1`](../../scripts/windows/Find-UserProfilePersistence.ps1) |
| Changes anything | No. Read-only. |
| Runs on | Windows PowerShell 5.1 or PowerShell 7. No modules. |
| Run as | Administrator or SYSTEM, so it can see every profile and task |
| Run time | Usually under a minute |

## Why this exists

Two patterns keep showing up:

- **Fake free utilities.** A PDF viewer or file converter that really works, but also drops a backdoor into `%LOCALAPPDATA%\<AppName>\` and adds a scheduled task like `<AppName>UpdateCheck` that runs it every hour. Some of these ship with real code-signing certificates, so antivirus may not flag them for weeks.
- **Fake IT calls.** Someone floods a user's inbox with junk mail, then calls on Teams pretending to be the help desk and walks them into running a file. The file unpacks its own Java runtime into `%APPDATA%\` and runs `.java` scripts that scan the network.

Both hide in places every user can write to, and both need a way to start again after a reboot. This script looks in exactly those places.

## Run it

**From your RMM or ScreenConnect.** Run it as a PowerShell script. In ScreenConnect's Commands tab, put these lines above the script text:

```
#!ps
#timeout=300000
#maxlength=200000
```

**On the machine, in an elevated PowerShell window:**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Find-UserProfilePersistence.ps1
```

| Option | Use it when |
|---|---|
| `-Days 90` | You want a longer look-back for new folders and downloads. The default is 45. |
| `-TrustedPublishers 'Microsoft','Contoso Software'` | Your environment has line-of-business apps that live in AppData. Signers on this list print as context, not findings. |

## What it checks

1. Scheduled tasks that run a program from AppData, Downloads, Desktop, Documents, Temp or `C:\Users\Public`.
2. Run and RunOnce keys and Startup folders that point at those same places.
3. Programs in AppData folders created recently that are not signed by a trusted publisher.
4. Java runtimes and `.java` or `.jar` files under user profiles, and Java running from outside Program Files.
5. Recently downloaded installers with utility-sounding names, like pdf, viewer, convert or reader.
6. Untrusted programs running from AppData, with the addresses they are connected to.

Every line starts with `[RED]` or `[YELLOW]`, so the results still read correctly in an RMM console without colors.

## What the colors mean here

| Tag | In this script |
|---|---|
| `[RED]` | A task or Run key launching an unsigned or broken-signature program from a user folder. A task from a user folder that repeats hourly or passes a per-machine ID. Any Java runtime in a user profile. |
| `[YELLOW]` | Signed by a publisher that is not on the trusted list. A recent utility installer in Downloads. A Java file in a profile. |
| Plain | Signed by a trusted publisher. Normal. |

A valid signature is not proof of safety. Treat a yellow line from an unfamiliar publisher as a question to answer, not as clear.

## If you find something

1. Do not delete anything yet. Note the path, the task name and the SHA256 the script prints.
2. Isolate the machine in your EDR if a red line has a live network connection or a task that repeats.
3. Check the hash and the publisher name in your threat intel sources.
4. Ask the user what they installed and when. Their answer usually dates the infection.
5. Hunt for the same folder name, task name and hash across your other machines before you clean this one.

## Limits

- Run keys are only checked for users whose profile is loaded, which usually means users who are logged on. Their scheduled tasks are always checked.
- It looks two to four folders deep, not the whole disk.
- Tested on Windows Server through ScreenConnect as SYSTEM. A clean result there means it ran and stayed quiet, not that it has been tested against a live infection.

[← Back to all scripts](../../README.md)
