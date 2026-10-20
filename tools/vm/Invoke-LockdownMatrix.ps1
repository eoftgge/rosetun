# Runs the Lockdown matrix in the Hyper-V test VM and prints a PASS/FAIL
# table. Exits with 1 if any check fails. The owner runs it; it reboots the
# guest and cuts its power unless -SkipReboot is given.
#
# Lockdown's persistent filters survive the script and would leave the guest
# offline; `finally` runs `--reset-firewall` whatever happens. If the run is
# killed before that, see tools/vm/README.md.

param(
    [Parameter(Mandatory)][string]$SingBoxPath,
    [Parameter(Mandatory)][string]$RequestPath,
    [string]$BuildDir = (Join-Path $PSScriptRoot '..\..\target\release'),
    [switch]$RestoreCheckpoint,
    [switch]$UseHostNode,
    [string]$NodeBindInterface,
    # Builds the workspace first, so a forgotten build cannot deploy stale binaries.
    [switch]$Build,
    # Skips the reboot and the power cuts (checks 6 and 7) for a quick pass.
    [switch]$SkipReboot,
    # Each power cut pass runs this often for turning on and for turning off.
    [int]$PowerCutRepeats = 3,
    # Wait between the Lockdown change and the power cut. Without the flush a
    # cut even 60 s after the change lost it (study, run 4).
    [int]$PowerCutDelaySeconds = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RosetunVm.psm1') -Force

$results = [System.Collections.Generic.List[object]]::new()
$guestDir = Get-RosetunGuestDir
$matrixDir = Join-Path $guestDir 'lockdown-matrix'
$bootTask = 'RosetunLockdownMatrixBootCheck'
# Fixed forever in crates/rosetun-routing/src/platform/windows/lockdown.rs.
$lockdownKeys = [ordered]@{
    Provider = 'f12dbedd-f3c7-4a72-b0f8-20559c88b112'
    Sublayer = 'f829a64d-c373-4d92-9d66-e1c680f3794f'
    Outbound = '57bf2a6e-57db-4d99-bed7-ecbd2c63aa75'
    Inbound  = 'e599db5e-6aeb-4e4d-aa51-4314f1b3076c'
    Dhcp     = '98419911-30f0-4f71-9178-263b40bc7f6e'
    Cli      = '729b156a-c411-4f01-b7d9-a789c94e992b'
    # The service's DNS permit (IPv4, UDP), present whenever Lockdown is.
    ServiceDns = 'cb0f8c4b-4967-4626-a493-a4e32369e6f5'
    Lan      = 'ce01436a-65d3-48e9-b921-e0a167b05f7b'
}
$probeProviderKey = '8c9a1588-cf36-44b8-80d8-987a6b81b4d2'
# The service's dynamic provider (session.rs).
$rosetunProviderKey = '51a47ec7-6459-4b84-8854-075e1576e7f9'

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

# A finding to record, not a pass or fail.
function Add-Info {
    param([Parameter(Mandatory)][string]$Scenario, [Parameter(Mandatory)][string]$Check, [string]$Note = '')
    $results.Add([pscustomobject]@{ Result = 'INFO'; Scenario = $Scenario; Check = $Check; Note = $Note })
}

# A mark in helper.log, so a step reads only the lines it caused.
function Get-HelperLogLength {
    Invoke-RosetunGuest -ScriptBlock {
        param($dir)
        $item = Get-Item -Path "$dir\helper.log" -ErrorAction SilentlyContinue
        if ($item) { $item.Length } else { 0 }
    } -ArgumentList $guestDir
}

function Get-HelperLogSince {
    param([Parameter(Mandatory)][long]$Offset)
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $offset)
        $stream = [IO.File]::Open("$dir\helper.log", 'Open', 'Read', 'ReadWrite, Delete')
        try {
            if ($offset -le $stream.Length) { $stream.Position = $offset }
            # The console helper colours its log; the codes split `name=value`.
            [IO.StreamReader]::new($stream).ReadToEnd() -replace "\x1b\[[0-9;]*m", ''
        }
        finally { $stream.Dispose() }
    } -ArgumentList $guestDir, $Offset
}

function Test-InUseFree {
    # FWP_E_IN_USE, as the helper prints it (decimal) or as netsh does.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Log)
    $Log -notmatch '2150825994|0x8032000a|FWP_E_IN_USE'
}

function Get-LockdownObjects {
    # Which Lockdown objects exist, from one dump of the WFP state. Boot-time
    # filters are not active once BFE runs, so they are not listed.
    $present = Invoke-RosetunGuest -ScriptBlock {
        param([string[]]$keys)
        $path = Join-Path $env:TEMP ("rosetun-wfp-$([guid]::NewGuid().ToString('N')).xml")
        try {
            & netsh.exe wfp show state "file=$path" *> $null
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $path)) {
                throw 'Cannot inspect WFP state.'
            }
            $state = Get-Content -Raw -LiteralPath $path
            @($keys | ForEach-Object { $state -match [regex]::Escape($_) })
        }
        finally {
            Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue
            $global:LASTEXITCODE = 0
        }
    } -ArgumentList (, [string[]]@($lockdownKeys.Values))
    $objects = [ordered]@{}
    $index = 0
    foreach ($name in $lockdownKeys.Keys) {
        $objects[$name] = [bool]$present[$index]
        $index++
    }
    [pscustomobject]$objects
}

function Format-Objects {
    param([Parameter(Mandatory)]$Objects)
    ($Objects.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' '
}

function Test-LockdownInstalled {
    param([switch]$Lan)
    $objects = Get-LockdownObjects
    $objects.Provider -and $objects.Sublayer -and $objects.Outbound -and $objects.Inbound -and
        $objects.Dhcp -and $objects.Cli -and $objects.ServiceDns -and $objects.Lan -eq [bool]$Lan
}

function Test-LockdownAbsent {
    $objects = Get-LockdownObjects
    -not ($objects.PSObject.Properties.Value -contains $true)
}

function Get-LockdownStatusLine {
    $status = Invoke-RosetunCli -Quiet 'status'
    if ($status.Output -match '(?m)^lockdown: (on|off)') { $Matches[1] } else { "unknown (exit $($status.ExitCode))" }
}

function Invoke-Lockdown {
    # `rosetun lockdown on|off`; returns the CLI result for the caller to test.
    param([Parameter(Mandatory)][ValidateSet('on', 'off')][string]$State)
    Invoke-RosetunCli -Quiet 'lockdown' $State
}

function Invoke-GuestHelperMode {
    # Runs the service binary in one of its install modes, as the installer does.
    param([Parameter(Mandatory)][string]$Mode)
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $mode)
        $output = & (Join-Path $dir 'rosetun-helper-privileged.exe') $mode 2>&1 | ForEach-Object { "$_" }
        $exitCode = $LASTEXITCODE
        $global:LASTEXITCODE = 0
        [pscustomobject]@{ ExitCode = $exitCode; Output = ($output -join "`n") }
    } -ArgumentList $guestDir, $Mode
}

function Test-CliPathEgress {
    # The CLI's permit is by application ID, which WFP derives from the path:
    # curl copied over rosetun.exe for one request shows whether a program at
    # that path gets out. The real CLI is put back in the same call.
    $address = Get-RosetunEgressAddress
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $address, $url)
        $cli = Join-Path $dir 'rosetun.exe'
        $saved = Join-Path $dir 'rosetun.exe.matrix'
        Move-Item -LiteralPath $cli -Destination $saved -Force
        try {
            Copy-Item -LiteralPath (Get-Command -Name curl.exe -ErrorAction Stop).Source -Destination $cli -Force
            & $cli --interface $address --max-time 5 --silent --output NUL $url 2>$null
            $LASTEXITCODE -eq 0
        }
        finally {
            $global:LASTEXITCODE = 0
            Remove-Item -LiteralPath $cli -Force -ErrorAction SilentlyContinue
            Move-Item -LiteralPath $saved -Destination $cli -Force
        }
    } -ArgumentList $guestDir, $address, 'https://1.1.1.1'
}

function Start-GuestListener {
    # A TCP listener in the guest with a guest firewall rule for it, so only
    # Lockdown decides whether the host gets in. It lives in the PowerShell
    # Direct session until Stop-GuestListener.
    Invoke-RosetunGuest -ScriptBlock {
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Any, 0)
        $listener.Start(8)
        $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
        $name = "Rosetun-Lockdown-matrix-$port"
        New-NetFirewallRule -Name $name -DisplayName 'Rosetun Lockdown matrix listener' -Direction Inbound `
            -Action Allow -Protocol TCP -LocalPort $port -Profile Any | Out-Null
        $global:RosetunMatrixListener = [pscustomobject]@{ Listener = $listener; RuleName = $name; Port = $port }
        $port
    }
}

function Stop-GuestListener {
    Invoke-RosetunGuest -ScriptBlock {
        $state = Get-Variable -Name RosetunMatrixListener -Scope Global -ValueOnly -ErrorAction SilentlyContinue
        if ($state) {
            Remove-NetFirewallRule -Name $state.RuleName -ErrorAction SilentlyContinue
            $state.Listener.Stop()
            Remove-Variable -Name RosetunMatrixListener -Scope Global
        }
    }
}

function Test-InboundFromHost {
    # The host connects to the guest's Default Switch address, a private one.
    param([Parameter(Mandatory)][int]$Port)
    $address = Get-RosetunEgressAddress
    $client = [Net.Sockets.TcpClient]::new()
    try { $client.ConnectAsync($address, $Port).Wait(3000) }
    catch { $false }
    finally { $client.Dispose() }
}

function Get-GuestGateway {
    Invoke-RosetunGuest -ScriptBlock {
        (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object -Property RouteMetric | Select-Object -First 1).NextHop
    }
}

function Install-TestService {
    # The real service, so `--reset-firewall` has an SCM service to stop.
    Stop-RosetunHelper
    $install = Invoke-GuestHelperMode '--install-service'
    if ($install.ExitCode -ne 0) {
        throw "Could not install the test service: $($install.Output)"
    }
    Wait-ServicePipe
}

function Wait-ServicePipe {
    $ready = Wait-RosetunCondition {
        Invoke-RosetunGuest -ScriptBlock {
            (Get-Service -Name 'Rosetun' -ErrorAction SilentlyContinue).Status -eq 'Running' -and
                ([IO.Directory]::GetFiles('\\.\pipe\') -contains '\\.\pipe\rosetun-helper')
        }
    } -TimeoutSeconds 60
    if (-not $ready) { throw 'The Rosetun service did not open its pipe within 60 s.' }
}

function Get-ServiceState {
    Invoke-RosetunGuest -ScriptBlock { "$((Get-Service -Name 'Rosetun' -ErrorAction SilentlyContinue).Status)" }
}

function Remove-TestService {
    $remove = Invoke-GuestHelperMode '--uninstall-service'
    if ($remove.ExitCode -ne 0) {
        throw "Could not remove the test service: $($remove.Output)"
    }
}

function New-GuestRequestByName {
    # request.json with the node as node.rosetun.test. `allow_lan` matches
    # Lockdown's, since a connect moves Lockdown's LAN set to the request's.
    param([Parameter(Mandatory)][bool]$AllowLan)
    $file = if ($AllowLan) { 'request-by-name-lan.json' } else { 'request-by-name.json' }
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $file, $allowLan)
        $request = Get-Content -Raw -LiteralPath "$dir\request.json" | ConvertFrom-Json
        $request.node.server = 'node.rosetun.test'
        $request.settings | Add-Member -NotePropertyName allow_lan -NotePropertyValue $allowLan -Force
        [IO.File]::WriteAllText("$dir\$file", ($request | ConvertTo-Json -Depth 20))
    } -ArgumentList $guestDir, $file, $AllowLan
    $file
}

function Test-ByName {
    # A connect, a server check and a subscription update by name; under
    # Lockdown also that names stay closed to everything but Rosetun.
    param(
        [Parameter(Mandatory)][string]$Scenario,
        [Parameter(Mandatory)][string]$RequestName,
        [switch]$Lockdown
    )
    $mark = Get-HelperLogLength
    $connect = Connect-RosetunTunnel -RequestName $RequestName -Quiet
    Test-Step $Scenario 'connect to node.rosetun.test succeeds' { $connect.ExitCode -eq 0 } -Note $connect.Output
    Disconnect-RosetunTunnel | Out-Null
    $probe = Invoke-RosetunProbe -RequestName $RequestName
    Test-Step $Scenario 'server check of node.rosetun.test works' { $probe.Output -match '(?m)^works' } -Note $probe.Output
    $update = Invoke-RosetunCli -Quiet 'sub' 'update' $subscriptionId
    Test-Step $Scenario 'rosetun sub update from sub.rosetun.test succeeds' { $update.ExitCode -eq 0 } -Note $update.Output
    if ($Lockdown) {
        Test-Step $Scenario 'the system resolver (Dnscache) gets no answer' {
            -not (Test-RosetunGuestSystemResolver 'node.rosetun.test')
        }
        Test-Step $Scenario 'nslookup gets no answer' { -not (Test-RosetunGuestNslookup 'node.rosetun.test') }
        Test-Step $Scenario 'direct egress still closed' { -not (Test-RosetunDirectEgress) }
    }
    Test-Step $Scenario "no 'failed to resolve the VPN endpoint' in helper.log" {
        (Get-HelperLogSince $mark) -notmatch 'failed to resolve the VPN endpoint'
    }
}

function Test-BootClosed {
    # Reads the boot check of the current boot: before sign-in, a lease and a
    # route, and no attempt that reached the internet.
    param([Parameter(Mandatory)][string]$Scenario)
    $attempts = Get-RosetunBootCheck -Directory $matrixDir -BootTime (Get-RosetunGuestBootTime)
    $note = Format-RosetunBootCheck -Attempts $attempts
    $routed = @($attempts | Where-Object { $_.Route })
    Test-Step $Scenario 'boot check ran before sign-in' {
        $attempts.Count -gt 0 -and @($attempts | Where-Object { $_.User }).Count -eq 0
    } -Note $note
    Test-Step $Scenario 'a DHCP address and a default route before sign-in' {
        @($routed | Where-Object { $_.Addresses -match '/Dhcp/Preferred' }).Count -gt 0
    } -Note "$($routed.Count) of $($attempts.Count) attempts routed"
    Test-Step $Scenario 'no boot attempt reached the internet' {
        @($routed | Where-Object { $_.CurlExit -eq 0 }).Count -eq 0
    } -Note $note
}

$nodeStarted = $false
$hostLan = $null
$guestListenerPort = $null
$serviceInstalled = $false
$bootTaskRegistered = $false
$bootRecovery = $null
$ipv6Neighbors = [System.Collections.Generic.List[object]]::new()
$zone = $null
$guestResolver = $null
$subscriptionId = $null
try {
    if ($Build) {
        Write-Host 'Building...'
        & cargo build -q --release --manifest-path (Join-Path $PSScriptRoot '..\..\Cargo.toml')
        $exitCode = $LASTEXITCODE
        $global:LASTEXITCODE = 0
        if ($exitCode -ne 0) { throw "cargo build failed with exit code $exitCode." }
    }
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
    # A Lockdown left by an interrupted run would turn the baseline into a block.
    $reset = Invoke-GuestHelperMode '--reset-firewall'
    if ($reset.ExitCode -ne 0) { throw "Initial --reset-firewall failed: $($reset.Output)" }
    Register-RosetunHelper
    Start-RosetunHelper
    Invoke-RosetunCli -Quiet 'lan' 'off' | Out-Null
    Restore-RosetunGuestLease
    Set-RosetunIpv6Neighbor -Created $ipv6Neighbors
    $hostLan = Start-RosetunLanListener
    $guestListenerPort = Start-GuestListener
    $gateway = Get-GuestGateway
    # Names for scenarios 1 to 3: the guest's adapter asks the host's zone.
    $zone = Start-RosetunNameZone -SubscriptionBody "ss://aes-256-gcm:rosetun-test@192.0.2.10:8388#Lockdown%20matrix`n"
    $requestByName = New-GuestRequestByName -AllowLan $false
    $requestByNameLan = New-GuestRequestByName -AllowLan $true
    $guestResolver = Set-RosetunGuestResolver -Server $zone.DnsAddress

    # 1. Lockdown off: nothing of it exists, and the probes work.
    Test-Step '1 off' 'no Lockdown objects' { Test-LockdownAbsent } -Note (Format-Objects (Get-LockdownObjects))
    Test-Step '1 off' 'status: lockdown off' { (Get-LockdownStatusLine) -eq 'off' }
    Test-Step '1 off' 'direct egress works' { Test-RosetunDirectEgress }
    Test-Step '1 off' 'direct DNS works' { Test-RosetunDirectDns }
    Test-Step '1 off' 'IPv6 to the host works' { Test-RosetunIpv6Open -Neighbors $ipv6Neighbors }
    if ($results[$results.Count - 1].Result -eq 'FAIL') {
        throw "IPv6 to the host does not work, so every 'IPv6 closed' check would be meaningless. $(Get-RosetunIpv6NeighborReport)"
    }
    Test-Step '1 off' 'the host reaches a guest listener' { Test-InboundFromHost $guestListenerPort }
    Test-Step '1 off' 'the guest reaches a host listener' {
        Wait-RosetunCondition { Test-RosetunLanListener $hostLan } -TimeoutSeconds 10
    }
    Test-Step '1 off' 'curl at the CLI path works' { Test-CliPathEgress }
    $gatewayDns = Test-RosetunDirectDns -Server $gateway
    Add-Info '1 off' "DNS to the gateway $gateway" "answers: $gatewayDns"
    Test-Step '1 off' 'the system resolver answers node.rosetun.test' { Test-RosetunGuestSystemResolver 'node.rosetun.test' }
    if ($results[$results.Count - 1].Result -eq 'FAIL') {
        throw "The guest cannot resolve rosetun.test through $($zone.DnsAddress), so every check by name would be meaningless."
    }
    $add = Invoke-RosetunCli -Quiet 'sub' 'add' $zone.SubscriptionUrl '--name' 'Lockdown matrix'
    if ($add.Output -match '(?m)^(\S+): Lockdown matrix \|') { $subscriptionId = $Matches[1] }
    Test-Step '1 off' 'rosetun sub add from sub.rosetun.test succeeds' { $add.ExitCode -eq 0 -and $subscriptionId } -Note $add.Output
    if (-not $subscriptionId) { throw 'The subscription by name could not be added.' }
    Test-ByName '1 off' $requestByName

    # 2. On while disconnected.
    $on = Invoke-Lockdown on
    Test-Step '2 on, disconnected' 'rosetun lockdown on succeeds' { $on.ExitCode -eq 0 } -Note $on.Output
    Test-Step '2 on, disconnected' 'objects present, without LAN' { Test-LockdownInstalled } -Note (Format-Objects (Get-LockdownObjects))
    Test-Step '2 on, disconnected' 'status: lockdown on' { (Get-LockdownStatusLine) -eq 'on' }
    Test-Step '2 on, disconnected' 'direct egress closed' { -not (Test-RosetunDirectEgress) }
    Test-Step '2 on, disconnected' 'direct DNS over UDP closed' { -not (Test-RosetunDirectDns) }
    Test-Step '2 on, disconnected' 'direct DNS over TCP closed' { -not (Test-RosetunDirectDns -Tcp) }
    Test-Step '2 on, disconnected' 'IPv6 to the host closed' { -not (Test-RosetunIpv6Open -Neighbors $ipv6Neighbors) }
    Test-Step '2 on, disconnected' 'loopback open' { Test-RosetunGuestLoopback }
    Test-Step '2 on, disconnected' 'a program at the CLI path gets out (subscription update)' { Test-CliPathEgress }
    $probe = Invoke-RosetunProbe
    Test-Step '2 on, disconnected' 'server check works' { $probe.Output -match '(?m)^works' } -Note $probe.Output
    Test-Step '2 on, disconnected' 'server check left no permit behind' { -not (Test-RosetunGuestWfpKey $probeProviderKey) }
    Test-Step '2 on, disconnected' 'direct egress still closed after the check' { -not (Test-RosetunDirectEgress) }
    Test-ByName '2 on, disconnected' $requestByName -Lockdown

    # 3. Inbound and LAN.
    Test-Step '3 inbound' 'the host cannot reach a guest listener' { -not (Test-InboundFromHost $guestListenerPort) }
    Test-Step '3 inbound' 'the guest cannot reach a host listener' { -not (Test-RosetunLanListener $hostLan) }
    $lanOn = Invoke-RosetunCli -Quiet 'lan' 'on'
    Test-Step '3 lan on' 'rosetun lan on updates Lockdown' { $lanOn.ExitCode -eq 0 -and $lanOn.Output -match 'lockdown on' } -Note $lanOn.Output
    Test-Step '3 lan on' 'LAN filters present' { Test-LockdownInstalled -Lan } -Note (Format-Objects (Get-LockdownObjects))
    Test-Step '3 lan on' 'the host reaches a guest listener' { Test-InboundFromHost $guestListenerPort }
    Test-Step '3 lan on' 'the guest reaches a host listener' { Test-RosetunLanListener $hostLan }
    if ($gatewayDns) {
        Test-Step '3 lan on' 'DNS to the gateway closed' { -not (Test-RosetunDirectDns -Server $gateway) }
        Test-Step '3 lan on' 'TCP DNS to the gateway closed' { -not (Test-RosetunDirectDns -Server $gateway -Tcp) }
    }
    else {
        Add-Info '3 lan on' 'DNS to the gateway' 'not checked: the gateway did not answer DNS without Lockdown either'
    }
    Test-Step '3 lan on' 'direct egress closed' { -not (Test-RosetunDirectEgress) }
    # The zone's address is private like a router's: Rosetun's DNS permits
    # must outrank Lockdown's private-DNS block.
    Test-ByName '3 lan on' $requestByNameLan -Lockdown
    $lanOff = Invoke-RosetunCli -Quiet 'lan' 'off'
    Test-Step '3 lan off' 'rosetun lan off updates Lockdown' { $lanOff.ExitCode -eq 0 } -Note $lanOff.Output
    Test-Step '3 lan off' 'LAN filters gone' { Test-LockdownInstalled } -Note (Format-Objects (Get-LockdownObjects))
    Test-Step '3 lan off' 'the host cannot reach a guest listener' { -not (Test-InboundFromHost $guestListenerPort) }
    # The rest checks the tunnel by names the zone does not know.
    Restore-RosetunGuestResolver -Saved $guestResolver
    $guestResolver = $null

    # 4. Connect under Lockdown, then disconnect.
    $connect = Connect-RosetunTunnel -Quiet
    Test-Step '4 connected' 'connect succeeds' { $connect.ExitCode -eq 0 } -Note $connect.Output
    $tunnel = Wait-RosetunTunnelEgress -SkipRevocationCheck
    Test-Step '4 connected' 'the tunnel carries traffic' { $tunnel.Ok } -Note "$($tunnel.Seconds) s; $($tunnel.Error)"
    Test-Step '4 connected' 'direct egress closed' { -not (Test-RosetunDirectEgress) }
    Test-Step '4 connected' 'direct DNS over UDP closed' { -not (Test-RosetunDirectDns) }
    Test-Step '4 connected' 'direct DNS over TCP closed' { -not (Test-RosetunDirectDns -Tcp) }
    Test-Step '4 connected' 'IPv6 to the host closed' { -not (Test-RosetunIpv6Open -Neighbors $ipv6Neighbors) }
    Test-Step '4 connected' 'the host cannot reach a guest listener' { -not (Test-InboundFromHost $guestListenerPort) }
    Disconnect-RosetunTunnel | Out-Null
    Test-Step '4 disconnected' 'direct egress closed' { -not (Test-RosetunDirectEgress) }
    Test-Step '4 disconnected' 'no Rosetun session filters left' { -not (Test-RosetunGuestWfpKey $rosetunProviderKey) }
    Test-Step '4 disconnected' 'objects still present' { Test-LockdownInstalled }

    $unprotected = Connect-RosetunTunnel -RequestName 'request-apply-unprotected.json' -Quiet
    Test-Step '4 kill switch off' 'connect succeeds' { $unprotected.ExitCode -eq 0 } -Note $unprotected.Output
    Test-Step '4 kill switch off' 'Lockdown forces the kill switch: direct egress closed' { -not (Test-RosetunDirectEgress) }
    Disconnect-RosetunTunnel | Out-Null

    # 5. A killed service: Lockdown holds; without it, fail-open as today.
    Connect-RosetunTunnel | Out-Null
    Stop-RosetunHelper
    Test-Step '5 killed, on' 'direct egress closed' { -not (Test-RosetunDirectEgress) }
    Test-Step '5 killed, on' 'IPv6 to the host closed' { -not (Test-RosetunIpv6Open -Neighbors $ipv6Neighbors) }
    Test-Step '5 killed, on' 'the dynamic session is gone' { -not (Test-RosetunGuestWfpKey $rosetunProviderKey) }
    Test-Step '5 killed, on' 'objects still present' { Test-LockdownInstalled }
    Start-RosetunHelper
    $startLog = Get-HelperLogSince 0
    Test-Step '5 restarted, on' 'the service finds Lockdown complete' {
        $startLog -match 'Lockdown is on.*\bcomplete=true'
    } -Note (($startLog -split "`n" | Select-String -Pattern 'Lockdown') -join ' | ')
    Test-Step '5 restarted, on' 'status: lockdown on' { (Get-LockdownStatusLine) -eq 'on' }
    $off = Invoke-Lockdown off
    Test-Step '5 off' 'rosetun lockdown off succeeds' { $off.ExitCode -eq 0 } -Note $off.Output
    Connect-RosetunTunnel | Out-Null
    Stop-RosetunHelper
    Test-Step '5 killed, off' 'fails open as before Lockdown: direct egress works' { Test-RosetunDirectEgress }
    Start-RosetunHelper

    # 6. Reboot under Lockdown. The helper task has no trigger, so after the
    # boot nothing of Rosetun runs until it is started: Lockdown alone holds.
    if (-not $SkipReboot) {
        Invoke-Lockdown on | Out-Null
        # The listener and its guest firewall rule would not survive the boot cleanly.
        Stop-GuestListener
        $bootTaskRegistered = $true
        Register-RosetunBootCheck -Directory $matrixDir -TaskName $bootTask
        Restart-RosetunGuest -Label '6 reboot, on'
        Test-BootClosed '6 reboot, on'
        Test-Step '6 reboot, on' 'objects present after boot' { Test-LockdownInstalled } -Note (Format-Objects (Get-LockdownObjects))
        $lease = Get-RosetunGuestLease
        Test-Step '6 reboot, on' 'DHCP lease and default route after boot' { $lease.Leased } -Note $lease.Note
        Test-Step '6 reboot, on' 'direct egress closed after boot' { (Get-RosetunEgressAfterBoot) -ne 'open' }
        Test-Step '6 reboot, on' 'IPv6 to the host closed after boot' { -not (Test-RosetunIpv6Open -Neighbors $ipv6Neighbors) }
        $renew = Test-RosetunDhcpRenew
        Test-Step '6 reboot, on' 'ipconfig /renew keeps the lease under the inbound block' { $renew.Renewed } -Note $renew.Note
        Unregister-RosetunBootCheck -TaskName $bootTask
        $bootTaskRegistered = $false
        Start-RosetunHelper
        Test-Step '6 reboot, on' 'still closed with the service running, before Connect' { -not (Test-RosetunDirectEgress) }
        $connect = Connect-RosetunTunnel -Quiet
        $tunnel = Wait-RosetunTunnelEgress -SkipRevocationCheck
        Test-Step '6 reboot, on' 'Connect opens the tunnel' { $connect.ExitCode -eq 0 -and $tunnel.Ok } -Note "$($connect.Output) $($tunnel.Error)"
        Disconnect-RosetunTunnel | Out-Null
        Test-Step '6 reboot, on' 'closed again after Disconnect' { -not (Test-RosetunDirectEgress) }

        # 7. Power cuts right after a change: the flush must make it durable.
        $bootRecovery = Disable-RosetunBootRecovery
        Restore-RosetunGuestLease
        Start-RosetunHelper
        for ($pass = 1; $pass -le $PowerCutRepeats; $pass++) {
            $on = Invoke-Lockdown on
            Start-Sleep -Seconds $PowerCutDelaySeconds
            Restart-RosetunGuest -PowerCut -Label "7 cut after on #$pass"
            Test-Step "7 cut $PowerCutDelaySeconds s after on #$pass" 'objects present after boot' {
                $on.ExitCode -eq 0 -and (Test-LockdownInstalled)
            } -Note (Format-Objects (Get-LockdownObjects))
            Restore-RosetunGuestLease
            Start-RosetunHelper
            $off = Invoke-Lockdown off
            Start-Sleep -Seconds $PowerCutDelaySeconds
            Restart-RosetunGuest -PowerCut -Label "7 cut after off #$pass"
            Test-Step "7 cut $PowerCutDelaySeconds s after off #$pass" 'no objects after boot' {
                $off.ExitCode -eq 0 -and (Test-LockdownAbsent)
            } -Note (Format-Objects (Get-LockdownObjects))
            Restore-RosetunGuestLease
            Test-Step "7 cut $PowerCutDelaySeconds s after off #$pass" 'direct egress open' { Test-RosetunDirectEgress }
            Start-RosetunHelper
        }
        $guestListenerPort = Start-GuestListener
    }

    # 8. Off while connected and while disconnected: no FWP_E_IN_USE.
    Invoke-Lockdown on | Out-Null
    Connect-RosetunTunnel | Out-Null
    $mark = Get-HelperLogLength
    $off = Invoke-Lockdown off
    Test-Step '8 off, connected' 'rosetun lockdown off succeeds' { $off.ExitCode -eq 0 } -Note $off.Output
    Test-Step '8 off, connected' 'no objects' { Test-LockdownAbsent } -Note (Format-Objects (Get-LockdownObjects))
    $tunnel = Wait-RosetunTunnelEgress -SkipRevocationCheck
    Test-Step '8 off, connected' 'the tunnel still carries traffic' { $tunnel.Ok } -Note $tunnel.Error
    Test-Step '8 off, connected' 'the kill switch of the request stays: direct egress closed' { -not (Test-RosetunDirectEgress) }
    Test-Step '8 off, connected' 'no FWP_E_IN_USE in helper.log' { Test-InUseFree (Get-HelperLogSince $mark) }
    Disconnect-RosetunTunnel | Out-Null

    Invoke-Lockdown on | Out-Null
    Connect-RosetunTunnel -RequestName 'request-apply-unprotected.json' | Out-Null
    $off = Invoke-Lockdown off
    Test-Step '8 off, kill switch off' 'rosetun lockdown off succeeds' { $off.ExitCode -eq 0 } -Note $off.Output
    Test-Step '8 off, kill switch off' 'the forced kill switch is released: direct egress works' { Test-RosetunDirectEgress }
    $tunnel = Wait-RosetunTunnelEgress -SkipRevocationCheck
    Test-Step '8 off, kill switch off' 'the tunnel still carries traffic' { $tunnel.Ok } -Note $tunnel.Error
    Disconnect-RosetunTunnel | Out-Null

    Invoke-Lockdown on | Out-Null
    $mark = Get-HelperLogLength
    $off = Invoke-Lockdown off
    Test-Step '8 off, disconnected' 'rosetun lockdown off succeeds' { $off.ExitCode -eq 0 } -Note $off.Output
    Test-Step '8 off, disconnected' 'no objects' { Test-LockdownAbsent }
    Test-Step '8 off, disconnected' 'direct egress works' { Test-RosetunDirectEgress }
    Test-Step '8 off, disconnected' 'IPv6 to the host works' { Test-RosetunIpv6Open -Neighbors $ipv6Neighbors }
    Test-Step '8 off, disconnected' 'the host reaches a guest listener' { Test-InboundFromHost $guestListenerPort }
    $again = Invoke-Lockdown off
    Test-Step '8 off, disconnected' 'a second off succeeds' { $again.ExitCode -eq 0 } -Note $again.Output
    Test-Step '8 off, disconnected' 'no FWP_E_IN_USE in helper.log' { Test-InUseFree (Get-HelperLogSince $mark) }

    # 9. reset-firewall with the real SCM service, running and connected, then stopped.
    $serviceInstalled = $true
    Install-TestService
    Invoke-Lockdown on | Out-Null
    $connect = Connect-RosetunTunnel -Quiet
    Test-Step '9 reset, running' 'connected through the service' { $connect.ExitCode -eq 0 } -Note $connect.Output
    $reset = Invoke-GuestHelperMode '--reset-firewall'
    Test-Step '9 reset, running' '--reset-firewall succeeds' {
        $reset.ExitCode -eq 0 -and $reset.Output -match 'Lockdown removed'
    } -Note $reset.Output
    Test-Step '9 reset, running' 'no objects' { Test-LockdownAbsent } -Note (Format-Objects (Get-LockdownObjects))
    Test-Step '9 reset, running' 'the service runs again' { Wait-ServicePipe; $true }
    Test-Step '9 reset, running' 'status: lockdown off' { (Get-LockdownStatusLine) -eq 'off' }
    Test-Step '9 reset, running' 'direct egress works' { Test-RosetunDirectEgress }

    Invoke-Lockdown on | Out-Null
    Invoke-RosetunGuest -ScriptBlock { Stop-Service -Name 'Rosetun' -Force }
    Test-Step '9 reset, stopped' 'closed with the service stopped' { -not (Test-RosetunDirectEgress) }
    $reset = Invoke-RosetunCli -Quiet 'reset-firewall'
    Test-Step '9 reset, stopped' 'rosetun reset-firewall succeeds' { $reset.ExitCode -eq 0 } -Note $reset.Output
    Test-Step '9 reset, stopped' 'no objects' { Test-LockdownAbsent }
    Test-Step '9 reset, stopped' 'direct egress works' { Test-RosetunDirectEgress }
    Test-Step '9 reset, stopped' 'the service stays stopped' { (Get-ServiceState) -eq 'Stopped' }
    Invoke-RosetunGuest -ScriptBlock { Start-Service -Name 'Rosetun' }
    Test-Step '9 reset, stopped' 'the service starts and reports lockdown off' {
        Wait-ServicePipe
        (Get-LockdownStatusLine) -eq 'off'
    }

    # 10. Uninstall under Lockdown, as rosetun.iss runs it: --uninstall-service, then --reset-firewall.
    Invoke-Lockdown on | Out-Null
    Connect-RosetunTunnel | Out-Null
    $uninstall = Invoke-GuestHelperMode '--uninstall-service'
    $serviceInstalled = $uninstall.ExitCode -ne 0
    $reset = Invoke-GuestHelperMode '--reset-firewall'
    Test-Step '10 uninstall' 'both installer steps succeed' {
        $uninstall.ExitCode -eq 0 -and $reset.ExitCode -eq 0
    } -Note "$($uninstall.Output) | $($reset.Output)"
    Test-Step '10 uninstall' 'no objects' { Test-LockdownAbsent }
    Restore-RosetunGuestLease
    Test-Step '10 uninstall' 'direct egress works' { Test-RosetunDirectEgress }
    Test-Step '10 uninstall' 'IPv6 to the host works' { Test-RosetunIpv6Open -Neighbors $ipv6Neighbors }
    Register-RosetunHelper
    Start-RosetunHelper
}
catch {
    Test-Step 'run' 'completes without an error' { $false } -Note "$_"
}
finally {
    # 11. Whatever happened: no Lockdown, the console helper back as before.
    # The session may have died with the guest in a power cut.
    try { Wait-RosetunGuest } catch { Write-Warning "$_" }
    if ($guestResolver) {
        try { Restore-RosetunGuestResolver -Saved $guestResolver }
        catch { Write-Warning "Could not restore the guest's DNS servers: $_" }
    }
    if ($subscriptionId) {
        try { Invoke-RosetunCli -Quiet 'sub' 'remove' $subscriptionId | Out-Null }
        catch { Write-Warning "Could not remove the matrix subscription ${subscriptionId}: $_" }
    }
    if ($zone) {
        try { Stop-RosetunNameZone -Zone $zone } catch { Write-Warning "Could not stop the name zone: $_" }
    }
    if ($bootRecovery) {
        try { Restore-RosetunBootRecovery -Saved $bootRecovery }
        catch { Write-Warning "Could not restore the guest's boot recovery settings: $_" }
    }
    try { Disconnect-RosetunTunnel | Out-Null } catch { }
    try { Stop-GuestListener } catch { Write-Warning "Could not stop the guest listener: $_" }
    if ($hostLan) {
        try { Stop-RosetunLanListener $hostLan } catch { Write-Warning "$_" }
    }
    try { Invoke-RosetunCli -Quiet 'lan' 'off' | Out-Null } catch { }
    try { Stop-RosetunHelper } catch { Write-Warning "Could not stop the helper: $_" }
    if ($serviceInstalled) {
        try { Remove-TestService } catch { Write-Warning "$_" }
    }
    $lockdownRemoved = $false
    try {
        $reset = Invoke-GuestHelperMode '--reset-firewall'
        if ($reset.ExitCode -ne 0 -or -not (Test-LockdownAbsent)) { throw $reset.Output }
        $lockdownRemoved = $true
    }
    catch {
        Write-Warning "Could not remove Lockdown; the guest may have no network. Run '$guestDir\rosetun-helper-privileged.exe --reset-firewall' in the guest as administrator: $_"
    }
    Test-Step 'cleanup' '--reset-firewall leaves no Lockdown' { $lockdownRemoved }
    if ($bootTaskRegistered) {
        try { Unregister-RosetunBootCheck -TaskName $bootTask } catch { Write-Warning "$_" }
    }
    try {
        Invoke-RosetunGuest -ScriptBlock {
            param($dir)
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        } -ArgumentList $matrixDir
    }
    catch { Write-Warning "Could not remove ${matrixDir}: $_" }
    try {
        Register-RosetunHelper
        Start-RosetunHelper
    }
    catch { Write-Warning "Could not start the helper again: $_" }
    if ($ipv6Neighbors.Count -gt 0) {
        try { Remove-RosetunIpv6Neighbor -Created $ipv6Neighbors } catch { Write-Warning "$_" }
    }
    if ($nodeStarted) {
        try { Stop-RosetunTestNode } catch { Write-Warning "Could not stop the host test node: $_" }
    }
}

Add-Info 'run' 'second cold starts when the guest did not come back' "$(Get-RosetunColdStartRetries)"

# Result first, so a long note cannot push it off the screen.
$results | Format-Table Result, Scenario, Check, Note -AutoSize -Wrap

if ($results.Result -contains 'FAIL') {
    exit 1
}
exit 0
