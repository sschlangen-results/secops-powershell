<div align="center">

# SecOps PowerShell

**Ready-to-run PowerShell for security analysts.**
Most scripts only read. Every one explains itself. Nothing in here names a customer.

![PowerShell 7+](https://img.shields.io/badge/PowerShell-7%2B-5391FE?logo=powershell&logoColor=white)
![Default mode](https://img.shields.io/badge/default-read--only-2ea44f)
![PII](https://img.shields.io/badge/PII-none-critical)

[Scripts](#scripts) · [How to run a script](#how-to-run-a-script) · [Reading the results](#reading-the-results) · [Contributing](CONTRIBUTING.md)

</div>

---

## Scripts

Pick the script for your question, open its guide, then follow the steps below.

| Script | Platform | Question it answers | Changes anything? | Guide |
|---|---|---|---|---|
| `Check-CwCloudBackupExposure.ps1` | Microsoft 365 | Was this tenant exposed to the ConnectWise Cloud Backup (SkyKick) supply-chain attack? | No | [Open](docs/m365/Check-CwCloudBackupExposure.md) |

---

## How to run a script

You only do steps 1 and 2 once per computer.

### 1. Install PowerShell 7

Windows PowerShell 5.1 is not enough. Check what you have:

```powershell
$PSVersionTable.PSVersion
```

If the major version is below 7, install it:

```powershell
winget install Microsoft.PowerShell      # Windows
brew install --cask powershell           # macOS
```

### 2. Install the module the script needs

Each guide lists its module. For the Microsoft 365 scripts:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

Answer **Y** if it asks to trust the PowerShell Gallery.

### 3. Get the scripts

```powershell
git clone git@github.com:sschlangen-results/secops-powershell.git
cd secops-powershell
```

No git? Use the green **Code** button on this page, choose **Download ZIP**, and unzip it. On Windows, right-click the zip, choose **Properties**, and tick **Unblock** before unzipping, or the scripts will refuse to run.

### 4. Run it

Open PowerShell 7 (`pwsh`) in the repo folder and run the script with the customer's domain:

```powershell
pwsh -NoProfile -File .\scripts\m365\Check-CwCloudBackupExposure.ps1 -Tenant customer.com
```

### 5. Sign in

A browser window opens. Sign in with **your admin account for that customer**. The script checks that you landed in the right tenant and stops if you did not.

No browser on that machine? Add `-DeviceCode`, then open the link it prints on any device and enter the code.

### 6. Read the results

The script prints its findings and a one-line summary at the end. See [Reading the results](#reading-the-results).

> **Tip:** every script has built-in help. `Get-Help .\scripts\m365\Check-CwCloudBackupExposure.ps1 -Full` shows its options and examples.

---

## Reading the results

All scripts use the same colors.

| You see | It means | What to do |
|---|---|---|
| 🔴 Red line | A hard finding | Stop and escalate. The script's guide says what to do next. |
| 🟡 Yellow line | Something to check by hand | Confirm it is expected, like your own automation or a tool update. |
| Plain line | Context | Nothing to do. |
| Last line | Count of hard findings | Zero means clean. |

Results can contain customer data. Do not paste raw output into tickets, chat or pull requests. Summarize it.

---

## Common problems

| Problem | Fix |
|---|---|
| `running scripts is disabled on this system` | Run it as shown above with `pwsh -File`, or once run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`. Unblock the zip if you downloaded one. |
| `The term 'Connect-MgGraph' is not recognized` | Step 2 was skipped. Install the module, then open a new PowerShell window. |
| `Signed in to '...' which does not own '...'` | You signed in to a different customer. Run it again and pick the right account. |
| `Insufficient privileges` or `Authorization_RequestDenied` | Your account needs read roles in that tenant. Each guide lists them. |
| Government tenant fails to sign in | GCC High and DoD need `-Environment USGov`. GCC Moderate does not. |

---

## Contributing

Adding a script? Read [CONTRIBUTING.md](CONTRIBUTING.md) first. The short version: **no PII of any kind**, no customer names, no secrets, and read-only unless a switch says otherwise.

<div align="center">
<sub>Internal use. Run scripts only against environments you are authorized to access.</sub>
</div>
