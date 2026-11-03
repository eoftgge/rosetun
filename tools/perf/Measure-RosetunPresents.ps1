#Requires -Version 7.0
# Counts how Rosetun's window reaches the screen while the owner drags it.
#
#   Measure  (default) runs PresentMon for rosetun-gui.exe for -Seconds after a
#            short countdown, writes its CSV to target/perf/ and prints a summary.
#   Summary  prints the summary of a CSV written earlier (-CsvPath), to compare
#            a build before and after a change; -Seconds is the length of that
#            run, since a window that presents nothing leaves no rows to time.
#
# PresentMon is not downloaded: pass the path of the console build. It reads
# ETW events, so run this from an elevated terminal or as a member of the
# "Performance Log Users" group. See README.md next to this script.

[CmdletBinding(DefaultParameterSetName = 'Measure')]
param(
    [Parameter(ParameterSetName = 'Measure', Mandatory)][string]$PresentMon,
    [Parameter(ParameterSetName = 'Measure')]
    [Parameter(ParameterSetName = 'Summary')]
    [ValidateRange(1, 600)][int]$Seconds = 15,
    [Parameter(ParameterSetName = 'Measure')][ValidateRange(0, 60)][int]$CountdownSeconds = 3,
    [Parameter(ParameterSetName = 'Measure')][ValidatePattern('^[A-Za-z0-9_-]*$')][string]$Label = '',
    [Parameter(ParameterSetName = 'Measure')][string]$ProcessName = 'rosetun-gui.exe',
    [Parameter(ParameterSetName = 'Summary', Mandatory)][string]$CsvPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-RosetunPercentile {
    param([double[]]$Sorted, [double]$Fraction)
    if ($Sorted.Count -eq 0) {
        return [double]::NaN
    }
    $rank = [math]::Ceiling($Fraction * $Sorted.Count)
    return $Sorted[[math]::Max(0, $rank - 1)]
}

function Get-RosetunColumn {
    param([object]$Row, [string[]]$Names)
    foreach ($name in $Names) {
        if ($Row.PSObject.Properties.Name -contains $name) {
            return $name
        }
    }
    return $null
}

# Milliseconds between consecutive presents of one swap chain. PresentMon 1.x and
# 2.x with --v1_metrics write MsBetweenPresents; 2.x by default writes the start
# time of each frame (CPUStartTime, in ms) instead.
function Get-RosetunIntervals {
    param([object[]]$Rows)
    $between = Get-RosetunColumn $Rows[0] @('MsBetweenPresents')
    if ($null -ne $between) {
        return @($Rows | ForEach-Object { [double]::Parse($_.$between, [cultureinfo]::InvariantCulture) })
    }
    $start = Get-RosetunColumn $Rows[0] @('CPUStartTime', 'TimeInSeconds')
    if ($null -eq $start) {
        throw 'the CSV has neither MsBetweenPresents nor CPUStartTime nor TimeInSeconds'
    }
    $scale = if ($start -eq 'TimeInSeconds') { 1000.0 } else { 1.0 }
    $intervals = [System.Collections.Generic.List[double]]::new()
    $chain = Get-RosetunColumn $Rows[0] @('SwapChainAddress')
    $groups = if ($null -ne $chain) { @($Rows | Group-Object -Property $chain) } else { @(@{ Group = $Rows }) }
    foreach ($group in $groups) {
        $times = @($group.Group | ForEach-Object { [double]::Parse($_.$start, [cultureinfo]::InvariantCulture) * $scale })
        for ($index = 1; $index -lt $times.Count; $index++) {
            $intervals.Add($times[$index] - $times[$index - 1])
        }
    }
    return @($intervals)
}

function Write-RosetunSummary {
    param([string]$Path, [string]$Application, [double]$WindowSeconds)
    $rows = @(Import-Csv -LiteralPath $Path)
    if ($rows.Count -gt 0 -and $Application -ne '') {
        $rows = @($rows | Where-Object { $_.Application -eq $Application })
    }
    Write-Host "CSV: $Path"
    if ($rows.Count -eq 0) {
        Write-Host 'Presents: 0 (the window presented nothing while measured)'
        return
    }

    $intervals = @(Get-RosetunIntervals $rows | Where-Object { $_ -ge 0 })
    $perSecond = $rows.Count / $WindowSeconds
    Write-Host ('Presents: {0} in {1:N1} s, {2:N1} per second' -f $rows.Count, $WindowSeconds, $perSecond)

    Write-Host 'PresentMode:'
    foreach ($mode in @($rows | Group-Object -Property PresentMode | Sort-Object -Property Count -Descending)) {
        Write-Host ('  {0,-45} {1,7} {2,6:N1} %' -f $mode.Name, $mode.Count, (100.0 * $mode.Count / $rows.Count))
    }

    $switches = 0
    $chain = Get-RosetunColumn $rows[0] @('SwapChainAddress')
    $groups = if ($null -ne $chain) { @($rows | Group-Object -Property $chain) } else { @(@{ Group = $rows }) }
    foreach ($group in $groups) {
        $modes = @($group.Group | ForEach-Object { $_.PresentMode })
        for ($index = 1; $index -lt $modes.Count; $index++) {
            if ($modes[$index] -ne $modes[$index - 1]) {
                $switches++
            }
        }
    }
    Write-Host "PresentMode switches: $switches"

    $sorted = [double[]]@($intervals | Sort-Object)
    Write-Host ('Between presents: median {0:N2} ms, 99th percentile {1:N2} ms ({2} intervals)' -f `
        (Get-RosetunPercentile $sorted 0.5), (Get-RosetunPercentile $sorted 0.99), $sorted.Count)
}

if ($PSCmdlet.ParameterSetName -eq 'Summary') {
    Write-RosetunSummary -Path $CsvPath -Application '' -WindowSeconds $Seconds
    return
}

if (-not (Test-Path -LiteralPath $PresentMon -PathType Leaf)) {
    throw "PresentMon not found: $PresentMon"
}
$baseName = [System.IO.Path]::GetFileNameWithoutExtension($ProcessName)
if (@(Get-Process -Name $baseName -ErrorAction SilentlyContinue).Count -eq 0) {
    throw "$ProcessName is not running; start Rosetun and show its window first"
}

$outDir = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'target/perf'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$name = if ($Label -ne '') { "presents-$Label-$stamp.csv" } else { "presents-$stamp.csv" }
$csv = Join-Path $outDir $name

for ($left = $CountdownSeconds; $left -gt 0; $left--) {
    Write-Host "Starting in $left s: take the window by its header"
    Start-Sleep -Seconds 1
}
Write-Host "Measuring for $Seconds s: drag the window fast and stop it abruptly"

$arguments = @(
    '--process_name', $ProcessName,
    '--output_file', $csv,
    '--timed', $Seconds,
    '--terminate_after_timed',
    '--stop_existing_session',
    '--no_console_stats'
)
$process = Start-Process -FilePath $PresentMon -ArgumentList $arguments -NoNewWindow -Wait -PassThru
if ($process.ExitCode -ne 0) {
    throw "PresentMon exited with $($process.ExitCode); run it elevated or as a member of Performance Log Users"
}
if (-not (Test-Path -LiteralPath $csv -PathType Leaf)) {
    Write-Host 'Presents: 0 (PresentMon wrote no CSV: the window presented nothing while measured)'
    return
}
Write-RosetunSummary -Path $csv -Application $ProcessName -WindowSeconds $Seconds
