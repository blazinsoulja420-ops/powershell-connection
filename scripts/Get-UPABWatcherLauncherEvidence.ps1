#requires -Version 5.1
<#
Stage 25 — explicit, read-only, bounded Windows launcher attribution.
Local command lines/task actions/service paths are classified only in memory.
Never print raw strings, PIDs, accounts, task names or paths.
Even no matches never proves that the legacy watcher has stopped.
Never invokes tasks, modifies startup settings, or issues permissions.
#>
[CmdletBinding()]
param(
    [switch]$InspectLocal,
    [switch]$FixtureOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($InspectLocal -and $FixtureOnly) {
    throw "Exactly one evidence mode is permitted"
}

function Measure-UPABLauncher {
    param([object[]]$Items)
    if ($Items.Count -gt 12000) { throw "Evidence collection exceeds bound" }
    $known = 0
    $ambiguous = 0
    $unreadable = 0
    $other = 0
    foreach ($entry in $Items) {
        if ($null -eq $entry -or [string]::IsNullOrWhiteSpace([string]$entry)) {
            $unreadable++
            continue
        }
        if ($entry -isnot [string] -or $entry.Length -gt 16384) {
            throw "Launcher description type or size invalid"
        }
        if ($entry -match '(?i)Start-UPAB-ExactRelay[.]ps1|upab[.]ps1|(?:^|\s)-m\s+upab\s+relay-watch(?:\s|$)') {
            $known++
        } elseif ($entry -match '(?i)upab|exact.?relay|powershell.connection') {
            $ambiguous++
        } else {
            $other++
        }
    }
    return [ordered]@{
        ItemsObserved = $Items.Count
        KnownSignatureCandidates = $known
        AmbiguousHints = $ambiguous
        Unreadable = $unreadable
        UnrelatedToKnownSignatures = $other
    }
}

$statuses = [ordered]@{
    Process = 'NOT_REQUESTED'
    ScheduledTask = 'NOT_REQUESTED'
    Service = 'NOT_REQUESTED'
}
$counts = [ordered]@{
    Process = $null
    ScheduledTask = $null
    Service = $null
}
$inspectorExcluded = $false

if ($FixtureOnly) {
    $statuses.Process = 'SYNTHETIC_FIXTURE'
    $statuses.ScheduledTask = 'SYNTHETIC_FIXTURE'
    $statuses.Service = 'SYNTHETIC_FIXTURE'
    $counts.Process = Measure-UPABLauncher @(
        'python.exe -m upab relay-watch --config public',
        'python.exe demo.py',
        'powershell.exe -File Start-UPAB-ExactRelay.ps1',
        'UPAB scratchpad', $null
    )
    $counts.ScheduledTask = Measure-UPABLauncher @(
        'NormalTask no-special-action', 'Start-UPAB-ExactRelay.ps1'
    )
    $counts.Service = Measure-UPABLauncher @(
        'GenericService', 'Other UPAB helper'
    )
} elseif ($InspectLocal) {
    try {
        # Fixed native CIM query. Do not accept user-supplied commands.
        $processes = @(Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe' OR Name='py.exe' OR Name='powershell.exe' OR Name='pwsh.exe' OR Name='cmd.exe' OR Name='upab.exe'" -ErrorAction Stop)
        if ($processes.Count -gt 12000) { throw 'Too many host processes' }
        $descriptions = @()
        foreach ($p in $processes) {
            if ($p.ProcessId -eq $PID) {
                $inspectorExcluded = $true
                continue
            }
            $descriptions += $p.CommandLine
        }
        $counts.Process = Measure-UPABLauncher $descriptions
        $statuses.Process = 'PARTIAL_OBSERVED'
    } catch {
        $statuses.Process = 'BLOCKED'
        $counts.Process = $null
    }
    try {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop)
        if ($tasks.Count -gt 12000) { throw 'Too many scheduled tasks' }
        $descriptions = @()
        foreach ($t in $tasks) {
            $description = [string]$t.TaskName + ' ' + [string]$t.TaskPath
            foreach ($a in @($t.Actions)) {
                $description += ' ' + [string]$a.Execute + ' ' + [string]$a.Arguments
                if ($description.Length -gt 16384) { throw 'Task action string too large' }
            }
            $descriptions += $description
        }
        $counts.ScheduledTask = Measure-UPABLauncher $descriptions
        $statuses.ScheduledTask = 'PARTIAL_OBSERVED'
    } catch {
        $statuses.ScheduledTask = 'BLOCKED'
        $counts.ScheduledTask = $null
    }
    try {
        $services = @(Get-CimInstance Win32_Service -ErrorAction Stop)
        if ($services.Count -gt 12000) { throw 'Too many services' }
        $descriptions = @()
        foreach ($s in $services) {
            $descriptions += ([string]$s.Name + ' ' + [string]$s.DisplayName + ' ' + [string]$s.PathName)
        }
        $counts.Service = Measure-UPABLauncher $descriptions
        $statuses.Service = 'PARTIAL_OBSERVED'
    } catch {
        $statuses.Service = 'BLOCKED'
        $counts.Service = $null
    }
}

[pscustomobject]@{
    Schema = 'upab.watcher-v3.launcher-audit-read-only.v1'
    FixtureOnly = [bool]$FixtureOnly
    LocalInspectionRequested = [bool]$InspectLocal
    InspectorHostProcessExcluded = $inspectorExcluded
    SourceStatuses = $statuses
    AggregateCounts = $counts
    RawCommandLinesReturned = $false
    TaskActionsReturned = $false
    UsernamesOrPIDsReturned = $false
    ExactWatcherIdentityProven = $false
    AllLaunchPathsCovered = $false
    OldWatcherQuiescenceProven = $false
    OwnerAuthenticated = $false
    MigrationAuthorized = $false
    RealTaskExecutionAuthorized = $false
    SystemChangesPerformed = $false
} | ConvertTo-Json -Depth 5 -Compress
