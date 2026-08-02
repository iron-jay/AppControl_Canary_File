<#
.SYNOPSIS
    Drops the App Control canary into commonly-writable directories and reports which
    ones let it run.

.DESCRIPTION
    Broad allow rules on C:\Windows and C:\Program Files are the usual shape of a WDAC or
    AppLocker policy, and the usual weakness: a handful of directories underneath them are
    writable by standard users, so anything a user can drop there inherits the allow.

    This script copies the canary into each candidate directory, runs it, and reports what
    happened. The outcome you want is Blocked.

    Copying into C:\Windows subdirectories generally needs no elevation - that is precisely
    the problem being tested - but listing active WDAC policies inside the canary does, so
    run elevated if you want the fullest report.

.PARAMETER CanaryPath
    Path to AppControl_Canary_File.exe or AppControl_Canary_Lite.exe. Defaults to whichever
    build output it finds, or a copy sitting beside this script. Either binary works: this
    script decides whether a location is blocked from the launch failure, not from anything
    the canary reports about itself.

.PARAMETER Path
    Override the default directory list.

.PARAMETER KeepCopies
    Leave the copied binaries in place instead of cleaning up. Useful when you want to
    inspect the resulting event log entries against a file that still exists.

.EXAMPLE
    .\Test-CanaryPaths.ps1

.EXAMPLE
    .\Test-CanaryPaths.ps1 -Path 'C:\Temp','D:\Share' | Export-Csv results.csv -NoTypeInformation
#>
[CmdletBinding()]
param(
    [string] $CanaryPath,

    [string[]] $Path,

    [switch] $KeepCopies
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Win32 launch failures worth telling apart. Lumping these together as "didn't run" is the
# easy mistake: only 1260 means App Control did its job, and mistaking a Defender block or
# an ACL for a policy hit is how you convince yourself a policy works when it does not.
$ErrorAccessDenied          = 5      # ACL on the file or directory, not App Control.
$ErrorVirusInfected         = 225    # Defender or another AV ate it first.
$ErrorAccessDisabledByPolicy = 1260  # WDAC / AppLocker / SRP. The outcome we want.

function Resolve-Canary {
    param([string] $Explicit)

    if ($Explicit) {
        if (-not (Test-Path -LiteralPath $Explicit)) {
            throw "Canary not found at '$Explicit'."
        }
        return (Resolve-Path -LiteralPath $Explicit).Path
    }

    # The lite build works here too - the script classifies by launch failure, not by what
    # the canary reports about itself - so fall back to it if the full build is absent.
    $root = Split-Path -Parent $PSScriptRoot
    $candidates = @(
        (Join-Path $PSScriptRoot 'AppControl_Canary_File.exe')
        (Join-Path $root 'bin\Release\AppControl_Canary_File.exe')
        (Join-Path $root 'bin\Debug\AppControl_Canary_File.exe')
        (Join-Path $PSScriptRoot 'AppControl_Canary_Lite.exe')
        (Join-Path $root 'Lite\bin\Release\AppControl_Canary_Lite.exe')
        (Join-Path $root 'Lite\bin\Debug\AppControl_Canary_Lite.exe')
    )

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    throw "Could not locate AppControl_Canary_File.exe. Pass -CanaryPath explicitly."
}

function Get-DefaultPaths {
    # Writable-by-standard-user directories that sit under the allow rules most policies
    # start from. Not exhaustive, and deliberately not a bypass list - every one of these
    # is long since public and documented by Microsoft as a reason not to allow by path.
    @(
        $env:TEMP
        "$env:WINDIR\Temp"
        "$env:WINDIR\Tasks"
        "$env:WINDIR\Tracing"
        "$env:WINDIR\Registration\CRMLog"
        # Not included: C:\Windows\System32\spool\drivers\color. Defender flags writes there
        # on sight, so it reports an AV block every run and tells you nothing about App
        # Control. Pass it via -Path if you specifically want to test it.
        "$env:WINDIR\System32\Tasks"
        "$env:ProgramData"
        "$env:LOCALAPPDATA"
        "$env:APPDATA"
        "$env:PUBLIC"
    ) | Where-Object { $_ } | Select-Object -Unique
}

function Get-NativeErrorCode {
    param([System.Exception] $Exception)

    for ($current = $Exception; $null -ne $current; $current = $current.InnerException) {
        if ($current -is [System.ComponentModel.Win32Exception]) {
            return $current.NativeErrorCode
        }
    }

    return $null
}

function Invoke-Canary {
    <#
        Deliberately not Start-Process: it discards the Win32Exception and re-throws a bare
        InvalidOperationException, so "blocked by policy" and "access denied" arrive as the
        same untyped string. Process.Start keeps NativeErrorCode, which is the whole basis
        for classifying the result.
    #>
    param([string] $FilePath)

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName               = $FilePath
    $psi.Arguments              = '--quiet'
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true

    $process = [System.Diagnostics.Process]::Start($psi)

    # Drain before waiting; a full pipe buffer would deadlock us against the child.
    $stdout = $process.StandardOutput.ReadToEnd()
    $null   = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    [pscustomobject]@{
        ExitCode = $process.ExitCode
        Output   = $stdout
    }
}

function Test-OnePath {
    param([string] $Directory, [string] $Source)

    $result = [ordered]@{
        Directory = $Directory
        Outcome   = $null
        ExitCode  = $null
        Verdict   = $null
        Detail    = $null
    }

    if (-not (Test-Path -LiteralPath $Directory)) {
        $result.Outcome = 'NoSuchDirectory'
        return [pscustomobject] $result
    }

    $target = Join-Path $Directory ([System.IO.Path]::GetFileName($Source))

    try {
        try {
            Copy-Item -LiteralPath $Source -Destination $target -Force -ErrorAction Stop
        }
        catch {
            # Not writable by this user. That is a good outcome too, just a different control.
            $result.Outcome = 'CopyDenied'
            $result.Detail  = $_.Exception.Message
            return [pscustomobject] $result
        }

        try {
            $run = Invoke-Canary -FilePath $target

            $result.Outcome  = 'RAN'
            $result.ExitCode = $run.ExitCode
            $result.Verdict  = switch ($run.ExitCode) {
                0       { 'No enforcement configured' }
                5       { 'Ran (lite build - no policy state checked)' }
                10      { 'Audit mode - would have been blocked' }
                20      { 'POLICY GAP - enforcing and ran anyway' }
                30      { 'Enforcement state unreadable (run elevated)' }
                default { "Started, but exited abnormally ($($run.ExitCode))" }
            }
        }
        catch {
            $native = Get-NativeErrorCode -Exception $_.Exception
            $result.Detail = $_.Exception.Message

            switch ($native) {
                $ErrorAccessDisabledByPolicy {
                    $result.Outcome = 'BLOCKED'
                    $result.Verdict = 'App Control blocked execution'
                }
                $ErrorVirusInfected {
                    $result.Outcome = 'BLOCKED-AV'
                    $result.Verdict = 'Antivirus blocked it, NOT App Control'
                }
                $ErrorAccessDenied {
                    $result.Outcome = 'AccessDenied'
                    $result.Verdict = 'File ACL blocked execution, NOT App Control'
                }
                default {
                    $result.Outcome = 'LaunchFailed'
                    $result.Verdict = if ($null -ne $native) { "Win32 error $native" } else { 'Unclassified failure' }
                }
            }
        }
    }
    finally {
        if (-not $KeepCopies) {
            Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue
        }
    }

    [pscustomobject] $result
}

$source = Resolve-Canary -Explicit $CanaryPath
$targets = if ($Path) { $Path } else { Get-DefaultPaths }

Write-Verbose "Using canary: $source"

$results = foreach ($directory in $targets) {
    Write-Verbose "Testing $directory"
    Test-OnePath -Directory $directory -Source $source
}

$results

$all       = @($results)
$ran       = @($all | Where-Object { $_.Outcome -eq 'RAN' })
$blocked   = @($all | Where-Object { $_.Outcome -eq 'BLOCKED' })
$otherStop = @($all | Where-Object { $_.Outcome -in 'BLOCKED-AV', 'AccessDenied', 'CopyDenied' })
$gaps      = @($ran | Where-Object { $_.ExitCode -eq 20 })

Write-Host ''
Write-Host ("Executed in {0} of {1} locations. Blocked by App Control in {2}." -f `
    $ran.Count, $all.Count, $blocked.Count)

if ($otherStop.Count -gt 0) {
    # Worth calling out separately: these look like wins on a summary line but say nothing
    # about whether App Control is working.
    Write-Host ("{0} location(s) stopped it for reasons other than App Control (AV, ACLs, or not writable)." -f `
        $otherStop.Count)
}

if ($gaps.Count -gt 0) {
    Write-Warning ("{0} location(s) executed the canary while policy was ENFORCING." -f $gaps.Count)
}
