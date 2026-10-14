#requires -Version 5.1
<#
Stage 28. Read-only bounded discovery of source marker *existence*.
No arbitrary content reads, recursive drive search, commands from files,
installation, task action, credential use, service changes, or raw path export.
A marker match is only a source-layout candidate, not installed runtime proof.
#>
[CmdletBinding()]
param(
    [switch]$InspectLocal,
    [switch]$FixtureOnly
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($InspectLocal -and $FixtureOnly) {
    throw "Choose exactly one inventory mode"
}

function Measure-CandidateMarkers {
    param([object[]]$Markers)
    if ($Markers.Count -gt 1024) { throw "Unbounded source marker evidence" }
    $complete = 0
    $partial = 0
    $empty = 0
    $other = 0
    foreach ($count in $Markers) {
        if ($count -isnot [int] -or $count -lt 0 -or $count -gt 3) {
            throw "Unknown source marker summary"
        }
        if ($count -eq 3) { $complete++ }
        elseif ($count -eq 0) { $empty++ }
        else { $partial++ }
    }
    return [ordered]@{
        CandidateFoldersExamined = $Markers.Count
        ThreeMarkerSourceCandidates = $complete
        PartialMarkerCandidates = $partial
        NoMarkerFolders = $empty
        Other = $other
    }
}

$status = 'NOT_REQUESTED'
$report = $null
$readOnly = $true
if ($FixtureOnly) {
    $status = 'SYNTHETIC_FIXTURE'
    $report = Measure-CandidateMarkers @([int]3,[int]2,[int]0,[int]1)
} elseif ($InspectLocal) {
    try {
        $roots = @(
            (Join-Path $env:USERPROFILE 'Desktop'),
            (Join-Path $env:USERPROFILE 'OneDrive\Desktop'),
            (Join-Path $env:USERPROFILE 'Documents'),
            (Join-Path $env:LOCALAPPDATA 'Programs')
        )
        $seen = @{}
        $markerCounts = @()
        foreach ($root in $roots) {
            if (-not(Test-Path -LiteralPath $root -PathType Container)) { continue }
            # At most one nested level, fixed root list, with global budget.
            $candidates = @(Get-Item -LiteralPath $root -ErrorAction Stop)
            $first = @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop |
                Select-Object -First 160)
            $candidates += $first
            foreach ($sub in $first) {
                if ($markerCounts.Count -ge 1024) { break }
                # Do not descend into arbitrary deeper directories.
                $candidates += @(Get-ChildItem -LiteralPath $sub.FullName -Directory -ErrorAction SilentlyContinue |
                    Select-Object -First 30)
                if ($candidates.Count -gt 1024) { break }
            }
            foreach ($candidate in $candidates) {
                if ($markerCounts.Count -ge 1024) { break }
                if ($seen.ContainsKey($candidate.FullName)) { continue }
                $seen[$candidate.FullName] = $true
                if (($candidate.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    # Never inspect redirected roots; leave inventory partial.
                    continue
                }
                $matchCount = 0
                foreach ($name in @(
                    'scripts\Start-UPAB-ExactRelay.ps1',
                    'src\upab\relay\ledger.py',
                    'pyproject.toml'
                )) {
                    $path = Join-Path $candidate.FullName $name
                    if (Test-Path -LiteralPath $path -PathType Leaf) {
                        $file = Get-Item -LiteralPath $path -ErrorAction Stop
                        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                            throw "Redirected marker cannot be inspected"
                        }
                        if ($file.Length -gt 1048576) {
                            throw "Marker size exceeds fixed bound"
                        }
                        $matchCount++
                    }
                }
                $markerCounts += [int]$matchCount
            }
        }
        $report = Measure-CandidateMarkers $markerCounts
        $status = 'BOUNDED_PARTIAL_OBSERVATION'
    } catch {
        $status = 'BLOCKED'
        $report = $null
    }
}
[pscustomobject]@{
    Schema = 'upab.watcher-v3.bounded-discovery.v1'
    Mode = $status
    Counts = $report
    PathsOrFileContentsReturned = $false
    SourceOriginVerified = $false
    InstalledRuntimeIdentified = $false
    AllInstallationLocationsCovered = $false
    OldWatcherStoppedProven = $false
    TaskExecutionAuthorized = $false
    ChangesPerformed = $false
} | ConvertTo-Json -Depth 4 -Compress
