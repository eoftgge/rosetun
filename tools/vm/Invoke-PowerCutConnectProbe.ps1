# Probes the first connect after a power cut in the Hyper-V test VM: each pass
# cuts the guest's power, starts the helper right after the boot and connects
# at once. It prints one row per pass and a summary per Lockdown mode, and
# exits with 1 if any pass failed. The owner runs it.
#
# A first connect after the matrix's power cuts timed out on sing-box
# readiness with 1.14.3 (OPEN-PROBLEMS). The probe keeps the helper log of
# every failed connect on the host, so the next pass cannot rotate it away.

param(
    [Parameter(Mandatory)][string]$SingBoxPath,
    [Parameter(Mandatory)][string]$RequestPath,
    [string]$BuildDir = (Join-Path $PSScriptRoot '..\..\target\release'),
    [switch]$RestoreCheckpoint,
    [switch]$UseHostNode,
    [string]$NodeBindInterface,
    # Builds the workspace first, so a forgotten build cannot deploy stale binaries.
    [switch]$Build,
    # Power cuts per Lockdown mode.
    [int]$Repeats = 8,
    [ValidateSet('On', 'Off', 'Both')][string]$Lockdown = 'Both',
    # Wait between `lockdown on` and the cut, as in the Lockdown matrix.
    [int]$PowerCutDelaySeconds = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RosetunVm.psm1') -Force
Assert-RosetunHostLockdownOff

$results = [System.Collections.Generic.List[object]]::new()
$guestDir = Get-RosetunGuestDir
$modes = if ($Lockdown -eq 'Both') { @('Off', 'On') } else { @($Lockdown) }

function Get-SingBoxVersion {
    param([Parameter(Mandatory)][string]$Path)
    $output = & $Path version 2>&1 | Out-String
    $global:LASTEXITCODE = 0
    if ($output -match '(?m)^sing-box version (\S+)') { $Matches[1] } else { throw "Cannot read the version of ${Path}: $output" }
}

function Assert-SingBoxSupported {
    # The service refuses any sing-box but the one it pins, so comparing
    # versions needs a local build pinned to the other one.
    $versionFile = Join-Path $PSScriptRoot '..\..\crates\rosetun-engine-singbox\src\version.rs'
    if ((Get-Content -Raw -LiteralPath $versionFile) -notmatch 'SUPPORTED_SING_BOX_VERSION: &str = "([^"]+)"') {
        throw "Cannot find SUPPORTED_SING_BOX_VERSION in $versionFile."
    }
    $supported = $Matches[1]
    $actual = Get-SingBoxVersion $SingBoxPath
    if ($actual -ne $supported) {
        throw ("$SingBoxPath is sing-box $actual, but the service accepts only $supported. For this probe set " +
            "SUPPORTED_SING_BOX_VERSION to `"$actual`" locally, run with -Build and revert the change afterwards.")
    }
    $actual
}

function Get-LockdownState {
    $status = Invoke-RosetunCli -Quiet 'status'
    if ($status.Output -match '(?m)^lockdown: (on|off)') { $Matches[1] } else { "unknown (exit $($status.ExitCode))" }
}

function Get-Readiness {
    # From the first spawn to the confirmation, so a pass that needed retries
    # counts all of them.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Log)
    $stamp = '^(\S+Z)\s'
    $spawns = @([regex]::Matches($Log, "(?m)$stamp.*spawning tunnel engine"))
    $ready = [regex]::Match($Log, "(?m)$stamp.*engine startup readiness confirmed")
    $seconds = $null
    if ($spawns.Count -gt 0 -and $ready.Success) {
        $culture = [Globalization.CultureInfo]::InvariantCulture
        $from = [DateTimeOffset]::Parse($spawns[0].Groups[1].Value, $culture)
        $to = [DateTimeOffset]::Parse($ready.Groups[1].Value, $culture)
        $seconds = [math]::Round(($to - $from).TotalSeconds, 2)
    }
    [pscustomobject]@{ Seconds = $seconds; Attempts = $spawns.Count }
}

function Get-Stages {
    # Seconds from the service's start of the connect to each step it logs,
    # so a long connect shows where the time went. ConnectSeconds minus
    # ServiceSeconds is spent outside the service (CLI start, PowerShell Direct).
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Log)
    $culture = [Globalization.CultureInfo]::InvariantCulture
    $marks = [ordered]@{
        start      = 'starting tunnel connection'
        spawn      = 'spawning tunnel engine'
        ready      = 'engine startup readiness confirmed'
        authorized = 'tunnel readiness authorization completed'
        dns        = 'DNS through the tunnel answered'
        connected  = 'current="connected"'
    }
    $times = [ordered]@{}
    foreach ($name in $marks.Keys) {
        # \W* skips a colour code's leftover escape before the time.
        $match = [regex]::Match($Log, '(?m)^\W*(\d{4}-\d\d-\d\dT[\d:.]+Z).*' + [regex]::Escape($marks[$name]))
        if ($match.Success) { $times[$name] = [DateTimeOffset]::Parse($match.Groups[1].Value, $culture) }
    }
    if (-not $times.Contains('start')) {
        return [pscustomobject]@{ ServiceSeconds = $null; Stages = 'no connect start in the log' }
    }
    $start = $times['start']
    $parts = foreach ($name in $times.Keys) {
        if ($name -ne 'start') { '{0} +{1:N1}' -f $name, ($times[$name] - $start).TotalSeconds }
    }
    $service = if ($times.Contains('connected')) {
        [math]::Round(($times['connected'] - $start).TotalSeconds, 2)
    }
    [pscustomobject]@{ ServiceSeconds = $service; Stages = $parts -join ', ' }
}

function Invoke-Pass {
    param([Parameter(Mandatory)][string]$Mode, [Parameter(Mandatory)][int]$Pass)
    $lockdownOn = $false
    $row = [pscustomobject]@{
        Lockdown = $Mode; Pass = $Pass; Result = 'FAIL'; ConnectSeconds = $null; ServiceSeconds = $null
        ReadySeconds = $null; Attempts = 0; AfterBoot = ''; Stages = ''; Note = ''
    }
    try {
        if ($Mode -eq 'On') {
            $on = Invoke-RosetunCli -Quiet 'lockdown' 'on'
            if ($on.ExitCode -ne 0) { throw "lockdown on failed: $($on.Output)" }
            $lockdownOn = $true
            Start-Sleep -Seconds $PowerCutDelaySeconds
        }
        Restart-RosetunGuest -PowerCut -Label "Lockdown $Mode #$Pass"
        Restore-RosetunGuestLease
        Start-RosetunHelper
        $row.AfterBoot = Get-LockdownState
        $mark = Get-RosetunHelperLogLength
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $connect = Connect-RosetunTunnel -Quiet
        $connected = $connect.ExitCode -eq 0 -and (Wait-RosetunState 'Connected')
        $row.ConnectSeconds = [math]::Round($clock.Elapsed.TotalSeconds, 2)
        $log = Get-RosetunHelperLogSince $mark
        $readiness = Get-Readiness $log
        $row.ReadySeconds = $readiness.Seconds
        $row.Attempts = $readiness.Attempts
        $stages = Get-Stages $log
        $row.ServiceSeconds = $stages.ServiceSeconds
        $row.Stages = $stages.Stages
        # Every pass, not only a failed one: a slow pass needs its log too.
        $kept = Join-Path $PSScriptRoot ("logs\power-cut-probe-{0:yyyyMMdd-HHmmss}-{1}-{2}.log" -f (Get-Date), $Mode, $Pass)
        [IO.File]::WriteAllText($kept, $log)
        if ($connected) {
            $row.Result = 'PASS'
        }
        else {
            $engineLines = @($log -split "`r?`n" | Where-Object { $_ -match 'engine_output' } | Select-Object -First 20)
            $row.Note = (@("exit $($connect.ExitCode): $($connect.Output)", "log: $kept") + $engineLines) -join "`n"
        }
        Invoke-RosetunCli -Quiet 'disconnect' | Out-Null
    }
    catch {
        $row.Note = "$_"
        try { Wait-RosetunGuest } catch { Write-Warning "$_" }
    }
    finally {
        if ($lockdownOn) {
            try {
                $off = Invoke-RosetunCli -Quiet 'lockdown' 'off'
                if ($off.ExitCode -ne 0) { $row.Note += "`nlockdown off failed: $($off.Output)" }
            }
            catch { $row.Note += "`nlockdown off failed: $_" }
        }
    }
    if ($row.Result -eq 'FAIL') {
        Write-Host "FAIL  Lockdown $Mode #$Pass ($($row.Note -split "`n" | Select-Object -First 1))" -ForegroundColor Red
    }
    $results.Add($row)
}

$nodeStarted = $false
$bootRecovery = $null
$runFailed = $false
$version = $null
try {
    if ($Build) {
        Write-Host 'Building...'
        & cargo build -q --release --manifest-path (Join-Path $PSScriptRoot '..\..\Cargo.toml')
        $exitCode = $LASTEXITCODE
        $global:LASTEXITCODE = 0
        if ($exitCode -ne 0) { throw "cargo build failed with exit code $exitCode." }
    }
    $version = Assert-SingBoxSupported
    if ($UseHostNode) {
        $nodeStarted = if ($NodeBindInterface) {
            Start-RosetunTestNode -SingBoxPath $SingBoxPath -BindInterface $NodeBindInterface
        }
        else {
            Start-RosetunTestNode -SingBoxPath $SingBoxPath
        }
    }
    if ($RestoreCheckpoint) {
        Write-Host 'Restoring the clean checkpoint...'
        Restore-RosetunVm
    }

    Write-Host 'Deploying binaries...'
    Stop-RosetunHelper
    Publish-Rosetun -BuildDir $BuildDir -SingBoxPath $SingBoxPath -RequestPath $RequestPath -UseHostNode:$UseHostNode
    # A Lockdown left by an interrupted run would turn every Off pass into an On one.
    $reset = Invoke-RosetunHelperMode '--reset-firewall'
    if ($reset.ExitCode -ne 0) { throw "Initial --reset-firewall failed: $($reset.Output)" }
    Register-RosetunHelper

    $bootRecovery = Disable-RosetunBootRecovery
    Restore-RosetunGuestLease
    Start-RosetunHelper
    foreach ($mode in $modes) {
        for ($pass = 1; $pass -le $Repeats; $pass++) {
            Write-Host "Lockdown $mode, power cut $pass of $Repeats..."
            Invoke-Pass -Mode $mode -Pass $pass
        }
    }
}
catch {
    Write-Host "FAIL  run ($_)" -ForegroundColor Red
    $runFailed = $true
}
finally {
    # Whatever happened: no Lockdown, the boot settings back, the guest running.
    try { Wait-RosetunGuest } catch { Write-Warning "$_" }
    if ($bootRecovery) {
        try { Restore-RosetunBootRecovery -Saved $bootRecovery }
        catch { Write-Warning "Could not restore the guest's boot recovery settings: $_" }
    }
    try { Disconnect-RosetunTunnel | Out-Null } catch { }
    try { Stop-RosetunHelper } catch { Write-Warning "Could not stop the helper: $_" }
    try {
        $reset = Invoke-RosetunHelperMode '--reset-firewall'
        if ($reset.ExitCode -ne 0) { throw $reset.Output }
    }
    catch {
        $runFailed = $true
        Write-Warning "Could not remove Lockdown; the guest may have no network. Run '$guestDir\rosetun-helper-privileged.exe --reset-firewall' in the guest as administrator: $_"
    }
    try {
        Register-RosetunHelper
        Start-RosetunHelper
    }
    catch { Write-Warning "Could not start the helper again: $_" }
    if ($nodeStarted) {
        try { Stop-RosetunTestNode } catch { Write-Warning "Could not stop the host test node: $_" }
    }
}

# Result first, so a long note cannot push it off the screen.
$results | Format-Table Result, Lockdown, Pass, ConnectSeconds, ServiceSeconds, ReadySeconds, Attempts, AfterBoot, Stages, Note -AutoSize -Wrap

Write-Host "sing-box $version, $PowerCutDelaySeconds s from lockdown on to the cut"
foreach ($mode in $modes) {
    $rows = @($results | Where-Object Lockdown -eq $mode)
    if ($rows.Count -eq 0) { continue }
    $failed = @($rows | Where-Object Result -eq 'FAIL').Count
    $ready = @($rows | Where-Object { $null -ne $_.ReadySeconds } | ForEach-Object ReadySeconds | Sort-Object)
    $summary = if ($ready.Count -gt 0) {
        $middle = [int][math]::Floor($ready.Count / 2)
        $median = if ($ready.Count % 2) { $ready[$middle] } else { ($ready[$middle - 1] + $ready[$middle]) / 2 }
        'readiness median {0:N2} s, max {1:N2} s over {2}' -f $median, $ready[-1], $ready.Count
    }
    else { 'no readiness confirmed' }
    Write-Host ("Lockdown {0}: {1} of {2} failed; {3}" -f $mode, $failed, $rows.Count, $summary)
}
Write-Host "Second cold starts when the guest did not come back: $(Get-RosetunColdStartRetries)"

if ($runFailed -or @($results | Where-Object Result -eq 'FAIL').Count -gt 0) {
    exit 1
}
exit 0
