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
    [switch]$UseHostNode,
    # Builds the workspace first, so a forgotten build cannot deploy stale binaries.
    [switch]$Build
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RosetunVm.psm1') -Force

$results = [System.Collections.Generic.List[object]]::new()

function Test-Step {
    param(
        [Parameter(Mandatory)][string]$Scenario,
        [Parameter(Mandatory)][string]$Expectation,
        [Parameter(Mandatory)][scriptblock]$Condition,
        [string]$Note = ''
    )
    try {
        $passed = [bool](& $Condition)
    }
    catch {
        $passed = $false
        $Note = "$_"
    }
    $results.Add([pscustomobject]@{
        Result   = if ($passed) { 'PASS' } else { 'FAIL' }
        Scenario = $Scenario
        Check    = $Expectation
        Note     = $Note
    })
    if (-not $passed) {
        $suffix = if ($Note) { " ($Note)" } else { '' }
        Write-Host "FAIL  $Scenario - $Expectation$suffix" -ForegroundColor Red
    }
}

function Format-Egress {
    param([Parameter(Mandatory)]$Egress)
    if ($Egress.Ok) {
        return "after $($Egress.Seconds) s"
    }
    "curl $($Egress.CurlExit), local '$($Egress.LocalIp)', tun '$($Egress.TunAddresses)': $($Egress.Error)"
}

if ($Build) {
    Write-Host 'Building...'
    & cargo build -q --release --manifest-path (Join-Path $PSScriptRoot '..\..\Cargo.toml')
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed with exit code $LASTEXITCODE."
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
Test-Step 'baseline' 'direct DNS works before connect' { Test-RosetunDirectDns }
Test-Step 'baseline' 'direct TCP DNS works before connect' { Test-RosetunDirectDns -Tcp }
Test-Step 'baseline' 'IPv6 to the host works before connect' { Test-RosetunIpv6Egress }

Write-Host 'Connect...'
Connect-RosetunTunnel | Out-Null
Test-Step 'connect' 'state is Connected' { Wait-RosetunState 'Connected' }
$egress = Wait-RosetunTunnelEgress
# Connected must mean usable: a tunnel that needs seconds before the first
# request gets through looks broken to the user.
Test-Step 'connect' 'tunnel carries traffic within 5 s, DNS included' -Note (Format-Egress $egress) {
    $egress.Ok -and $egress.Seconds -le 5
}
Test-Step 'connect' 'direct egress is blocked' { -not (Test-RosetunDirectEgress) }
Test-Step 'connect' 'IPv6 outside the tunnel is blocked' { -not (Test-RosetunIpv6Egress) }
$probe = Invoke-RosetunCli -Quiet 'probe' 'C:\rosetun\request.json'
Test-Step 'connect' 'server check works while connected' -Note "exit $($probe.ExitCode)" {
    $probe.ExitCode -eq 0 -and $probe.Output -match '(?m)^works \d+ ms$'
}
$delay = Invoke-RosetunCli -Quiet 'delay'
Test-Step 'connect' 'tunnel delay works' -Note "exit $($delay.ExitCode)" {
    $delay.ExitCode -eq 0 -and $delay.Output -match '(?m)^works \d+ ms$'
}

# Like a Wi-Fi reconnect: the engine has to follow the network on its own,
# and the helper notices nothing.
Write-Host 'Network change with the tunnel up...'
Start-RosetunEgressWatch
$adapter = Restart-RosetunEgressAdapter
$egress = Wait-RosetunTunnelEgress -TimeoutSeconds 60
$watch = Stop-RosetunEgressWatch
Test-Step 'network change' 'adapter gets its address from DHCP again' `
    -Note "after $($adapter.Seconds) s: $($adapter.Addresses)" { $adapter.Ok }
Test-Step 'network change' 'tunnel carries traffic again within 15 s' -Note (Format-Egress $egress) {
    $egress.Ok -and $egress.Seconds -le 15
}
Test-Step 'network change' "no leak while the network changes ($($watch.Probes) probes)" {
    $watch.Probes -gt 0 -and $watch.Leaks -eq 0
}
Test-Step 'network change' 'state is still Connected' { (Get-RosetunState) -eq 'Connected' }

Write-Host 'Engine killed...'
Stop-RosetunEngine
Test-Step 'engine killed' 'state is FailedProtected' { Wait-RosetunState 'FailedProtected' }
Test-Step 'engine killed' 'direct egress is blocked' { -not (Test-RosetunDirectEgress) }
Test-Step 'engine killed' 'direct DNS is blocked' { -not (Test-RosetunDirectDns) }
# While sing-box runs, its strict route blocks IPv6 as well. Its filters die
# with it, so only here is Rosetun's own IPv6 block the one being tested.
Test-Step 'engine killed' 'IPv6 outside the tunnel is blocked' { -not (Test-RosetunIpv6Egress) }
$probe = Invoke-RosetunCli -Quiet 'probe' 'C:\rosetun\request.json'
Test-Step 'engine killed' 'server check works under protection' -Note "exit $($probe.ExitCode)" {
    $probe.ExitCode -eq 0 -and $probe.Output -match '(?m)^works \d+ ms$'
}
Test-Step 'engine killed' 'direct egress is still blocked' { -not (Test-RosetunDirectEgress) }

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
Connect-RosetunTunnel -Quiet | Out-Null
Test-Step 'failed reconnect' 'state stays FailedProtected' {
    Wait-RosetunState 'FailedProtected' -TimeoutSeconds 10
}
Test-Step 'failed reconnect' 'direct egress is blocked' { -not (Test-RosetunDirectEgress) }
Set-RosetunEngineAvailable $true

# The engine starts and the tunnel comes up, but nothing behind it answers.
Write-Host 'Reconnect to an unreachable node...'
$attempt = Connect-RosetunTunnel -RequestName 'request-unreachable.json' -Quiet
Test-Step 'unreachable reconnect' 'connect fails on the DNS check' {
    $attempt.ExitCode -ne 0 -and $attempt.Output -match 'DNS through the tunnel'
}
Test-Step 'unreachable reconnect' 'state stays FailedProtected' {
    Wait-RosetunState 'FailedProtected' -TimeoutSeconds 10
}
Test-Step 'unreachable reconnect' 'direct egress is blocked' { -not (Test-RosetunDirectEgress) }

Write-Host 'Disconnect...'
Disconnect-RosetunTunnel | Out-Null
Test-Step 'disconnect' 'state is Disconnected' { Wait-RosetunState 'Disconnected' }
Test-Step 'disconnect' 'direct egress works again' { Test-RosetunDirectEgress }
Test-Step 'disconnect' 'IPv6 works again' { Test-RosetunIpv6Egress }
Test-Step 'disconnect' 'tunnel adapter is gone' {
    Wait-RosetunCondition { -not (Test-RosetunTunAdapter) }
}

Write-Host 'Process rules...'
Connect-RosetunTunnel -RequestName 'request-process-rules.json' | Out-Null
Test-Step 'process rules' 'state is Connected' { Wait-RosetunState 'Connected' }
$egress = Wait-RosetunTunnelEgress -TimeoutSeconds 15
# The default target is block, so only the rule can let this request through.
Test-Step 'process rules' 'curl.exe goes direct by its rule' -Note (Format-Egress $egress) { $egress.Ok }
Test-Step 'process rules' 'another process hits the default block' {
    -not (Test-RosetunTunnelEgress -OtherProcess)
}
Test-Step 'process rules' 'direct egress is still blocked' { -not (Test-RosetunDirectEgress) }
Disconnect-RosetunTunnel | Out-Null
Wait-RosetunState 'Disconnected' | Out-Null

Write-Host 'Connect to an unreachable node...'
$attempt = Connect-RosetunTunnel -RequestName 'request-unreachable.json' -Quiet
Test-Step 'unreachable connect' 'connect fails on the DNS check' {
    $attempt.ExitCode -ne 0 -and $attempt.Output -match 'DNS through the tunnel'
}
Test-Step 'unreachable connect' 'state is Failed' { Wait-RosetunState 'Failed' -TimeoutSeconds 10 }
Test-Step 'unreachable connect' 'direct egress works again' { Test-RosetunDirectEgress }
Test-Step 'unreachable connect' 'tunnel adapter is gone' {
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

Write-Host 'DNS lock without the kill switch...'
Connect-RosetunTunnel -RequestName 'request-dns-lock.json' | Out-Null
Test-Step 'dns lock' 'state is Connected' { Wait-RosetunState 'Connected' }
$egress = Wait-RosetunTunnelEgress
Test-Step 'dns lock' 'tunnel carries traffic' -Note (Format-Egress $egress) { $egress.Ok }
Test-Step 'dns lock' 'direct DNS is blocked' { -not (Test-RosetunDirectDns) }
$probe = Invoke-RosetunCli -Quiet 'probe' 'C:\rosetun\request-dns-lock.json'
Test-Step 'dns lock' 'server check works with the DNS lock' -Note "exit $($probe.ExitCode)" {
    $probe.ExitCode -eq 0 -and $probe.Output -match '(?m)^works \d+ ms$'
}

Write-Host 'DNS lock during automatic restart...'
Set-RosetunEngineAvailable $false
Stop-RosetunEngine
Test-Step 'dns lock restart' 'state is Reconnecting' { Wait-RosetunState 'Reconnecting' }
Test-Step 'dns lock restart' 'direct UDP DNS is blocked' { -not (Test-RosetunDirectDns) }
Test-Step 'dns lock restart' 'direct TCP DNS is blocked' { -not (Test-RosetunDirectDns -Tcp) }
Test-Step 'dns lock restart' 'non-DNS egress still works' { Test-RosetunDirectEgress }
Set-RosetunEngineAvailable $true
Test-Step 'dns lock restart' 'state returns to Connected within 45 s' {
    Wait-RosetunState 'Connected' -TimeoutSeconds 45
}

Write-Host 'DNS lock after exhausted reconnects...'
Set-RosetunEngineAvailable $false
Stop-RosetunEngine
Test-Step 'dns lock exhausted' 'state is Failed within 90 s' {
    Wait-RosetunState 'Failed' -TimeoutSeconds 90
}
Test-Step 'dns lock exhausted' 'direct DNS works again' { Test-RosetunDirectDns }
Set-RosetunEngineAvailable $true

Write-Host 'DNS lock with automatic reconnect disabled...'
Connect-RosetunTunnel -RequestName 'request-dns-lock-manual.json' | Out-Null
Test-Step 'dns lock manual' 'state is Connected' { Wait-RosetunState 'Connected' }
Stop-RosetunEngine
Test-Step 'dns lock manual' 'state is Failed' { Wait-RosetunState 'Failed' }
Test-Step 'dns lock manual' 'direct DNS works again' { Test-RosetunDirectDns }
Disconnect-RosetunTunnel | Out-Null

Write-Host 'Disconnect with the DNS lock...'
Connect-RosetunTunnel -RequestName 'request-dns-lock.json' | Out-Null
Disconnect-RosetunTunnel | Out-Null
Test-Step 'dns lock disconnect' 'state is Disconnected' { Wait-RosetunState 'Disconnected' }
Test-Step 'dns lock disconnect' 'direct DNS works again' { Test-RosetunDirectDns }

Write-Host 'Helper killed with the DNS lock...'
Connect-RosetunTunnel -RequestName 'request-dns-lock.json' | Out-Null
Wait-RosetunState 'Connected' | Out-Null
Stop-RosetunHelper
Test-Step 'dns lock helper killed' 'direct DNS works again' {
    Wait-RosetunCondition { Test-RosetunDirectDns }
}
Start-RosetunHelper

# Result first, so a long note cannot push it off the screen.
$results | Format-Table Result, Scenario, Check, Note -AutoSize

if ($results.Result -contains 'FAIL') {
    Write-Host '--- helper log (tail) ---'
    Get-RosetunHelperLog -Tail 60
    Write-Host "All helper logs of this run: $(Save-RosetunLogs)"
    exit 1
}
