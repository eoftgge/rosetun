# Runs the kill-switch failure matrix in the Hyper-V test VM and prints a
# PASS/FAIL table. Exits with 1 if any check fails.
#
# -UseHostNode points the request at the test node on the host, whose address
# changes with every host reboot.

param(
    [Parameter(Mandatory)][string]$SingBoxPath,
    [Parameter(Mandatory)][string]$RequestPath,
    [string]$BuildDir = (Join-Path $PSScriptRoot '..\..\target\release'),
    [switch]$RestoreCheckpoint,
    [switch]$UseHostNode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RosetunVm.psm1') -Force

$results = [System.Collections.Generic.List[object]]::new()

function Test-Step {
    param(
        [Parameter(Mandatory)][string]$Scenario,
        [Parameter(Mandatory)][string]$Expectation,
        [Parameter(Mandatory)][scriptblock]$Condition
    )
    $detail = ''
    try {
        $passed = [bool](& $Condition)
    }
    catch {
        $passed = $false
        $detail = " ($_)"
    }
    $results.Add([pscustomobject]@{
        Scenario = $Scenario
        Check    = $Expectation
        Result   = if ($passed) { 'PASS' } else { 'FAIL' }
    })
    if (-not $passed) {
        Write-Host "FAIL  $Scenario - $Expectation$detail" -ForegroundColor Red
    }
}

if ($RestoreCheckpoint) {
    Write-Host 'Restoring the clean checkpoint...'
    Restore-RosetunVm
}

Write-Host 'Deploying binaries...'
# A helper left running by a previous run keeps its executable locked.
Stop-RosetunHelper
Publish-Rosetun -BuildDir $BuildDir -SingBoxPath $SingBoxPath -RequestPath $RequestPath -UseHostNode:$UseHostNode
Register-RosetunHelper
Start-RosetunHelper

# Proves the probe itself works. Without it, every "blocked" check below would
# pass even if the probe were broken or the probe URL unreachable.
Test-Step 'baseline' 'direct egress works before connect' { Test-RosetunDirectEgress }

Write-Host 'Connect...'
Connect-RosetunTunnel | Out-Null
Test-Step 'connect' 'state is Connected' { Wait-RosetunState 'Connected' }
$egress = Wait-RosetunTunnelEgress
$detail = if ($egress.Ok) {
    "after $($egress.Seconds) s"
}
else {
    "curl $($egress.CurlExit), local '$($egress.LocalIp)', tun '$($egress.TunAddresses)': $($egress.Error)"
}
# Connected must mean usable: a tunnel that needs seconds before the first
# request gets through looks broken to the user.
Test-Step 'connect' "tunnel carries traffic within 5 s, DNS included ($detail)" {
    $egress.Ok -and $egress.Seconds -le 5
}
Test-Step 'connect' 'direct egress is blocked' { -not (Test-RosetunDirectEgress) }

Write-Host 'Engine killed...'
Stop-RosetunEngine
Test-Step 'engine killed' 'state is FailedProtected' { Wait-RosetunState 'FailedProtected' }
Test-Step 'engine killed' 'direct egress is blocked' { -not (Test-RosetunDirectEgress) }

Write-Host 'Reconnect inside protection...'
Start-RosetunEgressWatch
Connect-RosetunTunnel | Out-Null
$reconnected = Wait-RosetunState 'Connected'
$watch = Stop-RosetunEgressWatch
Test-Step 'reconnect' 'state is Connected' { $reconnected }
Test-Step 'reconnect' "no leak while reconnecting ($($watch.Probes) probes)" {
    $watch.Probes -gt 0 -and $watch.Leaks -eq 0
}

Write-Host 'Failed reconnect...'
Stop-RosetunEngine
Wait-RosetunState 'FailedProtected' | Out-Null
Set-RosetunEngineAvailable $false
Connect-RosetunTunnel | Out-Null
Test-Step 'failed reconnect' 'state stays FailedProtected' {
    Wait-RosetunState 'FailedProtected' -TimeoutSeconds 10
}
Test-Step 'failed reconnect' 'direct egress is blocked' { -not (Test-RosetunDirectEgress) }
Set-RosetunEngineAvailable $true

Write-Host 'Disconnect...'
Disconnect-RosetunTunnel | Out-Null
Test-Step 'disconnect' 'state is Disconnected' { Wait-RosetunState 'Disconnected' }
Test-Step 'disconnect' 'direct egress works again' { Test-RosetunDirectEgress }
Test-Step 'disconnect' 'tunnel adapter is gone' {
    Wait-RosetunCondition { -not (Test-RosetunTunAdapter) }
}

Write-Host 'Shutdown with the tunnel up...'
Connect-RosetunTunnel | Out-Null
Wait-RosetunState 'Connected' | Out-Null
Request-RosetunShutdown | Out-Null
Test-Step 'shutdown' 'engine stopped' { Wait-RosetunCondition { -not (Test-RosetunEngineRunning) } }
Test-Step 'shutdown' 'tunnel adapter is gone' { Wait-RosetunCondition { -not (Test-RosetunTunAdapter) } }
Test-Step 'shutdown' 'direct egress works again' { Test-RosetunDirectEgress }

# Known fail-open: the dynamic WFP session closes with the helper process, and
# the job object takes the engine down with it.
Write-Host 'Helper killed with the tunnel up...'
Start-RosetunHelper
Connect-RosetunTunnel | Out-Null
Wait-RosetunState 'Connected' | Out-Null
Stop-RosetunHelper
Test-Step 'helper killed' 'engine died with the helper' {
    Wait-RosetunCondition { -not (Test-RosetunEngineRunning) }
}
Test-Step 'helper killed' 'tunnel adapter is gone' {
    Wait-RosetunCondition { -not (Test-RosetunTunAdapter) }
}

Write-Host 'Restart after a killed helper...'
Start-RosetunHelper
Connect-RosetunTunnel | Out-Null
Test-Step 'restart' 'connect succeeds, no stale adapter' { Wait-RosetunState 'Connected' }
Disconnect-RosetunTunnel | Out-Null

$results | Format-Table -AutoSize

if ($results.Result -contains 'FAIL') {
    Write-Host '--- helper log (tail) ---'
    Get-RosetunHelperLog -Tail 60
    exit 1
}
