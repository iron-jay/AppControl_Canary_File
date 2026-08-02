# AppControl_Canary_File

Very simple, tiny app to test App Control is working.<br>
Ideally, you would not be able to open it (add it to a block list or something). Lets you see how permissive rules are in certain folder, etc

If it opens, it now tells you **why** it was allowed to run, which is usually the part you
actually wanted to know.

## Which build do I want?

Two binaries ship. They look and behave the same; the difference is how much they try to
explain.

| | `AppControl_Canary_File.exe` (full) | `AppControl_Canary_Lite.exe` (lite) |
|---|---|---|
| Answers | *Why* was I allowed to run? | *Was* I blocked? |
| Reads WDAC / SAC / AppLocker state | Yes | No |
| Shows path, hash, signature | Yes | Yes |
| Needs WMI and the service manager | Yes | **No** |
| Exit code when it runs | 0 / 10 / 20 / 30 by policy state | Always 5 |

**Use lite if you're not running WDAC.** Its whole point is the absence: no WMI query, no
service control manager call, nothing that can hang or throw for reasons of its own. A canary
that fails on its own account is worse than no canary, because you can't tell that apart from
a policy block. Lite has almost nothing left to go wrong.

Use the full build when you *are* running WDAC and want the verdict — especially the audit-mode
answer, which is the usual reason a canary runs when you expected a block.

Either binary works with [`tools/Test-CanaryPaths.ps1`](tools/Test-CanaryPaths.ps1), which
decides whether a location is blocked from the launch failure rather than from anything the
canary says about itself.

## Quick start

1. Grab a binary from the [latest release](../../releases/latest), or build it yourself
   (see below).
2. Add a deny rule from [`policy/`](policy/) to your policy, in audit mode first. The shipped
   rules cover both binaries.
3. Run the canary.
4. Not opening at all is the goal. If it opens: the full build's banner tells you whether
   you're in audit mode or looking at a real gap; lite just tells you it wasn't blocked.

## What's new

### 2.1 (unreleased)

- Added the **lite build** for anyone not running WDAC.

### 2.0

- The window now shows **WDAC, Smart App Control, and AppLocker enforcement state**, plus the
  canary's own path, hash, and signature — so "it opened" becomes "it opened *because*".
- **`--quiet` mode with meaningful exit codes**, so it can run unattended.
- **[`tools/Test-CanaryPaths.ps1`](tools/Test-CanaryPaths.ps1)** probes the writable-but-allowed
  directories in one shot.
- **Ready-made WDAC and AppLocker deny rules** in [`policy/`](policy/), plus published hashes
  on every release.
- Fixed: `Environment.OSVersion` reported `6.2.9200` on Windows 11 (missing app manifest);
  the window opened top-left and behind other windows; Esc didn't close it.

## What the full build reports

Launching the canary shows a window with a colour-coded verdict and the details behind it:

| Field | Why it's there |
|---|---|
| Ran from / SHA256 / Signature | Exactly what to paste into a rule, and proof of which build you ran |
| WDAC user-mode CI | Off, audit, or enforced. **Audit mode is the most common reason a canary runs when you expected a block** |
| Kernel-mode CI | Reported for completeness. Governs drivers, not this EXE, and is normally enforced |
| Smart App Control | Windows 11 only. Off, evaluation, or enforced |
| AppLocker (EXE) | Enforcement mode, plus whether `AppIDSvc` is running — rules do nothing if it isn't |
| Active WDAC policies | The `.cip` files actually loaded (needs admin to list) |

**Copy details** puts the whole report on the clipboard, so a screenshot or paste is a
complete answer rather than "it opened".

Policy state is read without elevation where Windows allows it. Run elevated for the
fullest report; the window says so when something was unreadable.

## Command line

```bash
AppControl_Canary_File.exe --quiet
```

`--quiet` prints the report instead of showing a window, so it can run unattended. `--help`
lists everything.

Exit codes — remember that the canary running at all means nothing blocked it:

| Code | Meaning |
|---|---|
| 0 | Ran; no App Control enforcement is configured |
| 10 | Ran; policy is in **audit mode** and would have blocked this |
| 20 | Ran; policy is **enforcing and failed to block it**. Real gap |
| 30 | Ran; policy state unreadable. Retry as administrator |
| 1 | Diagnostics failed |
| 5 | Ran; **lite build**, so no policy state was checked at all |

Code 5 is deliberately distinct from 0 so "nothing is configured" can never be confused with
"nothing was looked at".

A block never produces an exit code at all — the *launch* fails, surfacing as Win32 error
1260 (`ERROR_ACCESS_DISABLED_BY_POLICY`) in whatever tried to start it. That's the signal the
probe script watches for.

## Testing folder permissiveness

Broad allow rules on `C:\Windows` and `C:\Program Files` are the usual shape of a policy,
and the usual weakness: several directories underneath them are writable by standard users.

```bash
powershell -ExecutionPolicy Bypass -File tools\Test-CanaryPaths.ps1
```

It copies the canary into each candidate directory, runs it, cleans up, and reports what
happened per location. Outcomes are deliberately separated — `BLOCKED` (App Control did its
job) vs `BLOCKED-AV`, `AccessDenied`, and `CopyDenied`, which all stop the canary while
telling you nothing about your policy. Pass `-Path` for your own list, `-KeepCopies` to
leave the binaries in place for event-log correlation.

`C:\Windows\System32\spool\drivers\color` is **not** in the default list: Defender flags
writes there on sight, so it reports an AV block on every run. Pass it via `-Path` if you
want it.

## Blocking it

Ready-made rules are in [`policy/`](policy/):

- [`Deny-Canary.wdac.xml`](policy/Deny-Canary.wdac.xml) — WDAC deny by original file name
- [`Deny-Canary.applocker.xml`](policy/Deny-Canary.applocker.xml) — AppLocker deny by path, any location

Both ship in **audit mode**. Merging a deny rule straight into enforcement on a live machine
is how people lock themselves out; confirm the rule matches in the event log first, then
switch it over.

```bash
Merge-CIPolicy -PolicyPaths .\YourPolicy.xml, .\policy\Deny-Canary.wdac.xml -OutputFilePath .\Merged.xml
```

```bash
Set-AppLockerPolicy -XmlPolicy .\policy\Deny-Canary.applocker.xml -Merge
```

These match on **name, not hash, on purpose** — a hash rule pins one exact binary and
silently stops matching the moment the canary is rebuilt, which is a great way to believe
your policy works when it doesn't. Hash-pinned variants are attached to each release for
anyone who wants them.

If you do write a hash rule: WDAC and AppLocker use the **Authenticode** PE hash, not the
flat file hash. They are different values, and the flat hash produces a rule that matches
nothing. Each release publishes both, labelled.

## Where blocks show up

- WDAC: `Microsoft-Windows-CodeIntegrity/Operational` — 3076 (audit) / 3077 (enforced)
- AppLocker: `Microsoft-Windows-AppLocker/EXE and DLL`

## Building

Open the solution in Visual Studio, or:

```bash
msbuild AppControl_Canary_File.csproj /t:Rebuild /p:Configuration=Release
```

```bash
msbuild Lite\AppControl_Canary_Lite.csproj /t:Rebuild /p:Configuration=Release
```

Both projects are in the solution. They share `canary.ico` and `app.manifest` rather than
keeping copies, so the manifest fixes can't drift apart.

Targets .NET Framework 4.7.2 deliberately. It's present on every Windows 10/11 machine with
no prerequisites — a tool whose failure mode is "didn't launch" shouldn't add a runtime
dependency, or you can't tell a policy block from a missing runtime.

The app manifest requests `asInvoker`. Elevation would change which rules apply, so the
canary never prompts for UAC.

## What it doesn't do

No network access, no persistence, no writes outside what you explicitly ask the probe
script to copy. It reads policy state and shows it to you.

One EXE tests one rule. WDAC and AppLocker evaluate DLLs, MSIs, and scripts through separate
paths, and PowerShell Constrained Language Mode — arguably the most consequential thing WDAC
turns on — is invisible from here. Those need their own canaries.
