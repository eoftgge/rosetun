# The Windows Local Network (LAN) matrix as an autonomous runner of the QEMU lab (stage 10d).
# Windows PowerShell 5.1, as SYSTEM.
#
# Runs all 72 checks of lan-core.tsv against the isolated lab wire, covering:
# baseline, lan-on (including long TCP session), address-change (198.51.100.10 add/remove),
# lan-rule (LAN segment overrides user rule), lan-private (10.255.255.1 behind router),
# lan-off (zero-leak, zero-allowance), switch (apply refusal and route transitions),
# lan-server (VPN node on 192.0.2.1 inside guest segment), lan-server-private, lan-reopen, and recovery.

param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]$')][string]$Medium
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib.ps1')

$plan = Get-Content -LiteralPath (Join-Path $Root 'plan.json') -Raw -Encoding UTF8 | ConvertFrom-Json
Initialize-RosetunRunner -StatusPath (Join-Path $Root 'status.json') -RunId $plan.run -WithAction

$mediumRoot = $Medium + ':\'
$bin = Join-Path $Root 'bin'
$logs = Join-Path $Root 'logs'
$work = Join-Path $Root 'lan-matrix'
$resultsDir = Join-Path $Root 'results'
$helperLogPath = Join-Path $logs 'helper.log'
$cliPath = Join-Path $bin 'rosetun.exe'
$helperPath = Join-Path $bin 'rosetun-helper-privileged.exe'
$singBoxPath = Join-Path $bin 'sing-box.exe'
$curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'
$taskName = 'RosetunHelper'

$physical = [string]$plan.addresses.client4
$gateway = [string]$plan.addresses.gateway4
$lanPeer = [string]$plan.addresses.lan_peer
$routedNode = [string]$plan.addresses.routed_node
$extraAddress = [string]$plan.addresses.extra_address
$extraPeer = [string]$plan.addresses.extra_peer
$privateBehind = [string]$plan.addresses.private_behind_router
$listenerPort = [int]$plan.addresses.listener_port
$echoPort = [int]$plan.addresses.echo_port
$holdPort = [int]$plan.addresses.hold_port
$broadcastPort = [int]$plan.addresses.broadcast_port
$mdnsGroup = [string]$plan.addresses.mdns_group
$mdnsPort = [int]$plan.addresses.mdns_port
$ssdpGroup = [string]$plan.addresses.ssdp_group
$ssdpPort = [int]$plan.addresses.ssdp_port
$target4 = [string]$plan.addresses.target4
$resolver = [string]$plan.addresses.resolver
$targetUrl = 'https://' + $target4 + '/'
$unlistedUrl = 'https://' + [string]$plan.names.unlisted + '/'
$baselineDns = [string]$plan.baseline.dns_name
$recoveryDns = 'after.' + $baselineDns
$tunAlias = [string]$plan.tun.alias
$tunAddress = ([string]$plan.request.settings.tun.ipv4 -split '/')[0]
$longSessionSeconds = [int]$plan.long_session_seconds

function Invoke-LanCli {
    param([Parameter(Mandatory)][string[]]$Arguments, [int]$Seconds = 90)
    Invoke-RosetunNative -FilePath $cliPath -Arguments $Arguments -TimeoutSeconds $Seconds
}

function Get-LanState {
    $result = Invoke-LanCli -Arguments @('status') -Seconds 20
    if ($result.Output -match '(?m)^state: (\w+)') { return $Matches[1] }
    return "unknown (exit $($result.ExitCode))"
}

function Wait-LanState {
    param([Parameter(Mandatory)][string]$Expected, [int]$TimeoutSeconds = 35)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ((Get-LanState) -eq $Expected) { return $true }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    return $false
}

function Wait-LanCondition {
    param([Parameter(Mandatory)][scriptblock]$Condition, [int]$TimeoutSeconds = 25)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (& $Condition) { return $true }
        Start-Sleep -Milliseconds 300
    } while ([DateTime]::UtcNow -lt $deadline)
    return $false
}

function Wait-HelperReady {
    param([int]$TimeoutSeconds = 90)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ($clock.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        if ((Invoke-LanCli -Arguments @('status') -Seconds 15).ExitCode -eq 0) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Test-TunAdapter {
    return ($null -ne (Get-NetAdapter -Name $tunAlias -ErrorAction SilentlyContinue))
}

function Disconnect-LanSession {
    param([int]$TimeoutSeconds = 35)
    [void](Invoke-LanCli -Arguments @('disconnect') -Seconds 30)
    return (Wait-LanCondition -TimeoutSeconds $TimeoutSeconds -Condition {
        (Get-LanState) -eq 'Disconnected' -and -not (Test-TunAdapter)
    })
}

function Connect-LanVariant {
    param([Parameter(Mandatory)][string]$RequestName)
    if ((Get-LanState) -ne 'Disconnected' -or (Test-TunAdapter)) {
        [void](Disconnect-LanSession)
    }
    $res = Invoke-LanCli -Arguments @('connect', (Join-Path $work $RequestName)) -Seconds 60
    return ($res.ExitCode -eq 0 -and (Wait-LanState 'Connected'))
}

function Get-HelperLogText {
    if (-not (Test-Path -LiteralPath $helperLogPath)) { return '' }
    try {
        $stream = [IO.File]::Open($helperLogPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try { return ((New-Object IO.StreamReader $stream).ReadToEnd() -replace "$([char]27)\[[0-9;]*m", '') }
        finally { $stream.Dispose() }
    }
    catch { return '' }
}

function Get-HelperLogLength {
    return (Get-HelperLogText).Length
}

function Get-HelperLogSince {
    param([int]$Offset)
    $text = Get-HelperLogText
    if ($Offset -le 0) { return $text }
    if ($Offset -ge $text.Length) { return '' }
    return $text.Substring($Offset)
}

function Wait-LanQuiet {
    param([int]$QuietSeconds = 8, [int]$TimeoutSeconds = 60)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $mark = Get-HelperLogLength
        Start-Sleep -Seconds $QuietSeconds
        if ((Get-HelperLogSince -Offset $mark) -notmatch 'local network changed' -and (Wait-LanState 'Connected' -TimeoutSeconds 15)) {
            return $true
        }
    }
    return $false
}

function Get-RouteInfo {
    param([Parameter(Mandatory)][string]$Address)
    $found = @(Find-NetRoute -RemoteIPAddress $Address -ErrorAction Stop)
    $source = @($found | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_NetIPAddress' }) | Select-Object -First 1
    $next = @($found | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_NetRoute' }) | Select-Object -First 1
    return [pscustomobject]@{
        InterfaceAlias = if ($next) { [string]$next.InterfaceAlias } else { '' }
        SourceAddress  = if ($source) { [string]$source.IPAddress } else { '' }
    }
}

function Get-DiscoveryRoutes {
    return @(Get-NetRoute -InterfaceAlias $tunAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.DestinationPrefix -in @('224.0.0.0/4', '255.255.255.255/32') } |
        ForEach-Object { [string]$_.DestinationPrefix })
}

function Get-BroadcastSocketSource {
    param([Parameter(Mandatory)][string]$Expected, [int]$TimeoutSeconds = 6)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $last = ''
    do {
        $socket = [Net.Sockets.Socket]::new('InterNetwork', 'Dgram', 'Udp')
        try {
            $socket.EnableBroadcast = $true
            $socket.Connect([Net.IPEndPoint]::new([Net.IPAddress]::Parse('255.255.255.255'), 9))
            $last = $socket.LocalEndPoint.Address.ToString()
        }
        catch { $last = "$($_.Exception.Message)" }
        finally { $socket.Dispose() }
        if ($last -eq $Expected) { return $last }
        Start-Sleep -Milliseconds 400
    } while ([DateTime]::UtcNow -lt $deadline)
    return $last
}

function Test-BroadcastRouteState {
    param([Parameter(Mandatory)][bool]$OnTunnel, [Parameter(Mandatory)][string]$PhysicalAlias)
    $routes = @(Get-DiscoveryRoutes)
    $expected = if ($OnTunnel) { $tunAddress } else { $physical }
    $source = Get-BroadcastSocketSource -Expected $expected
    $has224 = ($routes -contains '224.0.0.0/4')
    $has255 = ($routes -contains '255.255.255.255/32')
    if ($OnTunnel) {
        return ($has224 -and $has255 -and $source -eq $expected)
    }
    $chosen = Get-RouteInfo -Address '255.255.255.255'
    return ($has224 -and (-not $has255) -and $chosen.InterfaceAlias -eq $PhysicalAlias -and $source -eq $expected)
}

function Test-DirectEgress {
    $result = Invoke-RosetunNative -FilePath $curlPath -TimeoutSeconds 15 -Arguments @(
        '--interface', $physical, '--max-time', '5', '--silent', '--ssl-no-revoke', '--output', 'NUL', $targetUrl)
    return ($result.ExitCode -eq 0)
}

function Test-DirectDns {
    param([Parameter(Mandatory)][string]$Name)
    $query = New-RosetunQuery -Name $Name
    try {
        $reply = Invoke-RosetunUdp -Source $physical -Target $resolver -Port 53 -Request $query -Milliseconds 3000
    }
    catch { return $false }
    return ($reply.Length -ge 12 -and $reply[0] -eq 0x6a -and $reply[1] -eq 0x06 -and ($reply[2] -band 0x80) -eq 0x80)
}

function Test-TunnelEgressOnce {
    $tunAddresses = @(Get-NetIPAddress -InterfaceAlias $tunAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        ForEach-Object { $_.IPAddress })
    if ($tunAddresses.Count -eq 0) { return $false }
    $result = Invoke-RosetunNative -FilePath $curlPath -TimeoutSeconds 20 -Arguments @(
        '--max-time', '10', '--silent', '--insecure', '--ssl-no-revoke',
        '--write-out', "`nlocal=%{local_ip} remote=%{remote_ip} code=%{http_code}", $unlistedUrl)
    if ($result.ExitCode -ne 0) { return $false }
    $local = ''
    $remote = ''
    $code = ''
    if ($result.Output -match 'local=(\S*) remote=(\S*) code=(\d+)') {
        $local, $remote, $code = $Matches[1], $Matches[2], $Matches[3]
    }
    return ($tunAddresses -contains $local -and $remote -eq $target4 -and $code -eq '200' -and
        $result.Output -match 'rosetun-lab-target')
}

function Wait-TunnelEgress {
    param([int]$TimeoutSeconds = 25)
    return (Wait-LanCondition -TimeoutSeconds $TimeoutSeconds -Condition { Test-TunnelEgressOnce })
}

function Invoke-LanTcpProbe {
    param(
        [Parameter(Mandatory)][string]$Address,
        [Parameter(Mandatory)][int]$Port,
        [string]$BindAddress = '',
        [switch]$ReadBanner,
        [int]$TimeoutMs = 4000
    )
    $client = if ($BindAddress) {
        [Net.Sockets.TcpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Parse($BindAddress), 0))
    } else {
        [Net.Sockets.TcpClient]::new()
    }
    try {
        $task = $client.ConnectAsync($Address, $Port)
        if (-not $task.Wait($TimeoutMs)) {
            return [pscustomobject]@{ Connected = $false; Local = ''; Banner = ''; Error = 'TimedOut' }
        }
        $local = ([Net.IPEndPoint]$client.Client.LocalEndPoint).Address.ToString()
        $banner = ''
        if ($ReadBanner) {
            $stream = $client.GetStream()
            $stream.ReadTimeout = 4000
            $buf = [byte[]]::new(64)
            $n = $stream.Read($buf, 0, $buf.Length)
            if ($n -gt 0) { $banner = [Text.Encoding]::ASCII.GetString($buf, 0, $n).Trim() }
        }
        return [pscustomobject]@{ Connected = $true; Local = $local; Banner = $banner; Error = '' }
    }
    catch {
        $inner = $_.Exception
        while ($inner.InnerException) { $inner = $inner.InnerException }
        $code = if ($inner -is [Net.Sockets.SocketException]) { "$($inner.SocketErrorCode)" } else { $inner.GetType().Name }
        return [pscustomobject]@{ Connected = $false; Local = ''; Banner = ''; Error = $code }
    }
    finally { $client.Dispose() }
}

function Send-DiscoveryDatagram {
    param(
        [Parameter(Mandatory)][string]$Group,
        [Parameter(Mandatory)][int]$Port,
        [Parameter(Mandatory)][string]$Token,
        [string]$BindPhysical = ''
    )
    $client = [Net.Sockets.UdpClient]::new()
    try {
        $client.EnableBroadcast = $true
        if ($BindPhysical) {
            $client.Client.SetSocketOption([Net.Sockets.SocketOptionLevel]::IP,
                [Net.Sockets.SocketOptionName]::MulticastInterface,
                [Net.IPAddress]::Parse($BindPhysical).GetAddressBytes())
        }
        $bytes = [Text.Encoding]::ASCII.GetBytes("rosetun-lan-matrix $Token")
        foreach ($attempt in 1..3) {
            [void]$client.Send($bytes, $bytes.Length, $Group, $Port)
            Start-Sleep -Milliseconds 300
        }
        return 'sent'
    }
    catch {
        $inner = $_.Exception
        while ($inner.InnerException) { $inner = $inner.InnerException }
        if ($inner -is [Net.Sockets.SocketException]) { return "$($inner.SocketErrorCode)" }
        return $inner.GetType().Name
    }
    finally { $client.Dispose() }
}

function Test-LabSawToken {
    param(
        [Parameter(Mandatory)][ValidateSet('mdns', 'ssdp', 'broadcast')][string]$Kind,
        [Parameter(Mandatory)][string]$Token,
        [int]$WaitMs = 600
    )
    Start-Sleep -Milliseconds $WaitMs
    $state = Invoke-RosetunLabAction -Root $Root -Operation 'lan_state' -Parameters @{}
    $seen = @($state.$Kind)
    return ($Token -in $seen)
}

function Invoke-LongSession {
    param([Parameter(Mandatory)][int]$Seconds)
    $client = [Net.Sockets.TcpClient]::new()
    $sent = 0
    try {
        $client.Connect($lanPeer, $echoPort)
        $local = ([Net.IPEndPoint]$client.Client.LocalEndPoint).Address.ToString()
        $stream = $client.GetStream()
        $stream.ReadTimeout = 10000
        $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
        $buf = [byte[]]::new(1)
        while ([DateTime]::UtcNow -lt $deadline) {
            $stream.Write([byte[]]@(42), 0, 1)
            if ($stream.Read($buf, 0, 1) -ne 1 -or $buf[0] -ne 42) { throw 'echo mismatch or closed' }
            $sent++
            if (($sent % 6) -eq 0) {
                Set-RosetunRunnerStep -Step ("long-session-$sent")
            }
            $remaining = ($deadline - [DateTime]::UtcNow).TotalMilliseconds
            if ($remaining -gt 0) {
                Start-Sleep -Milliseconds ([int][Math]::Min(5000, $remaining))
            }
        }
        return [pscustomobject]@{ Ok = $true; Local = $local; Echoes = $sent; Error = '' }
    }
    catch {
        return [pscustomobject]@{ Ok = $false; Local = ''; Echoes = $sent; Error = "$($_.Exception.Message)" }
    }
    finally { $client.Dispose() }
}

function Get-ConnectionRows {
    param([string]$Output)
    return @($Output -split '\r?\n' | Where-Object { $_ -match '^(active|closed)\t' } | ForEach-Object {
        $c = $_ -split "`t"
        [pscustomobject]@{
            State = $c[0]
            Id = $c[1]
            Route = $c[3]
            Destination = $c[7]
        }
    })
}

function Get-LanConnectionsTo {
    # Opens exactly one TCP connection to $Address:$Port while polling `rosetun connections`,
    # so the wire sees at most one deterministic flow when routed direct.
    param(
        [Parameter(Mandatory)][string]$Address,
        [int]$Port = 80
    )
    $poller = Start-Job -ScriptBlock {
        param($cli)
        while ($true) { & $cli connections *> $null; Start-Sleep -Milliseconds 300 }
    } -ArgumentList $cliPath
    $client = [Net.Sockets.TcpClient]::new()
    try {
        Start-Sleep -Seconds 3
        $task = $client.ConnectAsync($Address, $Port)
        $raw = [Collections.Generic.List[string]]::new()
        foreach ($attempt in 1..6) {
            Start-Sleep -Milliseconds 400
            $res = Invoke-LanCli -Arguments @('connections') -Seconds 15
            if ($res.Output) { $raw.Add($res.Output) }
            $found = @(Get-ConnectionRows -Output ($raw -join "`n") | Where-Object { $_.Destination -like "$Address*" })
            if ($found.Count -gt 0 -and $attempt -ge 2) { break }
        }
        [void]$task.Wait(500)
        return @(Get-ConnectionRows -Output ($raw -join "`n") | Where-Object { $_.Destination -like "$Address*" })
    }
    finally {
        $client.Dispose()
        Stop-Job -Job $poller -ErrorAction SilentlyContinue
        Remove-Job -Job $poller -Force -ErrorAction SilentlyContinue
    }
}

function Clear-PeerNeighbor {
    Remove-NetNeighbor -IPAddress $lanPeer -Confirm:$false -ErrorAction SilentlyContinue
}

function Write-LanRequests {
    $variants = @{
        'lan-off.json'            = @{ allow = $false; private = $false; rule = $false; server = $false }
        'lan-on.json'             = @{ allow = $true;  private = $false; rule = $false; server = $false }
        'lan-private.json'        = @{ allow = $true;  private = $true;  rule = $false; server = $false }
        'lan-rule.json'           = @{ allow = $true;  private = $false; rule = $true;  server = $false }
        'lan-server.json'         = @{ allow = $true;  private = $false; rule = $false; server = $true  }
        'lan-server-private.json' = @{ allow = $true;  private = $true;  rule = $false; server = $true  }
    }
    $baseJson = ConvertTo-Json -InputObject $plan.request -Depth 30
    foreach ($name in $variants.Keys) {
        $v = $variants[$name]
        $req = $baseJson | ConvertFrom-Json
        $req.settings | Add-Member -NotePropertyName kill_switch -NotePropertyValue $true -Force
        $req.settings | Add-Member -NotePropertyName auto_reconnect -NotePropertyValue $true -Force
        $req.settings | Add-Member -NotePropertyName allow_lan -NotePropertyValue $v.allow -Force
        $req.settings | Add-Member -NotePropertyName private_networks -NotePropertyValue $v.private -Force
        $req.node.server = if ($v.server) { $gateway } else { $routedNode }
        if ($v.rule) {
            $rule = [pscustomobject]@{
                id      = 'peer-through-vpn'
                enabled = $true
                matcher = [pscustomobject]@{ ip_cidr = "$lanPeer/32" }
                target  = 'proxy'
            }
            $req.rule_set.rules = @($rule) + @($req.rule_set.rules)
        }
        [IO.File]::WriteAllText((Join-Path $work $name), (ConvertTo-Json -InputObject $req -Depth 30), (New-Object Text.UTF8Encoding $false))
    }
}

$recorder = $null
$runError = $false
$helperStarted = $false
$openWindow = $null
$extraAdded = $false
$physicalAlias = ''
$parts = [ordered]@{}

try {
    Set-RosetunRunnerState -State running -Step 'prepare'
    New-Item -ItemType Directory -Force -Path $bin, $logs, $work | Out-Null
    foreach ($file in $plan.files) {
        $source = Join-Path $mediumRoot ([string]$file.name)
        $target = Join-Path $bin ([string]$file.name)
        Copy-Item -LiteralPath $source -Destination $target -Force
        $hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hash -ne [string]$file.sha256 -or (Get-Item -LiteralPath $target).Length -ne [int64]$file.size) {
            throw "delivered file differs from the plan: $($file.name)"
        }
    }
    Add-RosetunRunnerNote -Name 'files-verified' -Value @($plan.files).Count

    $physicalNic = Get-NetIPAddress -IPAddress $physical -AddressFamily IPv4 -ErrorAction Stop | Select-Object -First 1
    $physicalAlias = [string]$physicalNic.InterfaceAlias

    $clock = [Diagnostics.Stopwatch]::StartNew()
    $version = Invoke-RosetunNative -FilePath $singBoxPath -Arguments @('version') -TimeoutSeconds 300
    Add-RosetunRunnerNote -Name 'sing-box-first-launch-seconds' -Value ([int]$clock.Elapsed.TotalSeconds)
    if ($version.ExitCode -ne 0) { throw 'sing-box does not start' }

    Set-RosetunRunnerStep -Step 'recorder'
    Import-Module (Join-Path $Root 'RosetunListResults.psm1') -Force
    $vmId = ([string](Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID).ToLowerInvariant()
    $recorder = New-RosetunListResults -Directory $resultsDir -VmId $vmId -BootId (Get-RosetunBootCounter) `
        -Suite 'windows-lan' -Catalog @($plan.catalog)
    Set-RosetunRecorder -Recorder $recorder

    Set-RosetunRunnerStep -Step 'helper'
    $command = "set ROSETUN_LOG=debug&& `"$helperPath`" > `"$helperLogPath`" 2>&1"
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c $command" -WorkingDirectory $bin
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName
    $helperStarted = $true
    if (-not (Wait-HelperReady)) { throw 'the helper did not answer status' }
    Write-LanRequests

    # Window 0: baseline (listed)
    Set-RosetunRunnerStep -Step 'baseline'
    if (Send-RosetunMarker -Plan $plan -Label 'baseline' -Word 'open') { $openWindow = 'baseline' }
    Test-Step -Id 'baseline.egress' -Scenario 'baseline' -Expectation 'direct egress works before connect' { Test-DirectEgress }
    Test-Step -Id 'baseline.dns' -Scenario 'baseline' -Expectation 'direct UDP DNS works before connect' { Test-DirectDns -Name $baselineDns }
    Start-Sleep -Seconds 2
    [void](Send-RosetunMarker -Plan $plan -Label 'baseline' -Word 'close')
    $openWindow = $null

    # Window 1: lan-on (judged)
    Set-RosetunRunnerStep -Step 'lan-on'
    if (Send-RosetunMarker -Plan $plan -Label 'lan-on' -Word 'open') { $openWindow = 'lan-on' }
    $mark = Get-HelperLogLength
    Test-Step -Id 'lan-on.connect' -Scenario 'lan-on' -Expectation 'lan-on connects' { Connect-LanVariant 'lan-on.json' }
    $segmentLog = Get-HelperLogSince -Offset $mark
    Test-Step -Id 'lan-on.log' -Scenario 'lan-on' -Expectation 'service opens guest network' {
        $segmentLog -match 'connected networks stay outside the tunnel' -and $segmentLog -notmatch 'VPN server'
    }
    $route = Get-RouteInfo -Address $lanPeer
    Test-Step -Id 'lan-on.peer-route' -Scenario 'lan-on' -Expectation 'peer route goes through physical adapter' -Note "$($route.InterfaceAlias) $($route.SourceAddress)" {
        $route.InterfaceAlias -eq $physicalAlias -and $route.SourceAddress -eq $physical
    }
    $conn = Invoke-LanTcpProbe -Address $lanPeer -Port $listenerPort -ReadBanner
    Test-Step -Id 'lan-on.peer-tcp' -Scenario 'lan-on' -Expectation 'TCP to peer connects from physical address' -Note "$($conn.Local) $($conn.Banner) $($conn.Error)" {
        $conn.Connected -and $conn.Local -eq $physical -and $conn.Banner -eq 'ROSETUN-LAN-PEER'
    }
    $dns53 = Invoke-LanTcpProbe -Address $lanPeer -Port 53
    Test-Step -Id 'lan-on.peer-dns-blocked' -Scenario 'lan-on' -Expectation 'TCP to peer port 53 is blocked' -Note $dns53.Error {
        $dns53.Error -eq 'AccessDenied'
    }
    $tok = [guid]::NewGuid().ToString('N')
    $sent = Send-DiscoveryDatagram -Group $mdnsGroup -Port $mdnsPort -Token $tok -BindPhysical $physical
    Test-Step -Id 'lan-on.mdns-physical' -Scenario 'lan-on' -Expectation 'mDNS on physical adapter reaches lab capture' -Note $sent {
        Test-LabSawToken -Kind 'mdns' -Token $tok
    }
    $tok = [guid]::NewGuid().ToString('N')
    $sent = Send-DiscoveryDatagram -Group $ssdpGroup -Port $ssdpPort -Token $tok -BindPhysical $physical
    Test-Step -Id 'lan-on.ssdp-physical' -Scenario 'lan-on' -Expectation 'SSDP on physical adapter reaches lab capture' -Note $sent {
        Test-LabSawToken -Kind 'ssdp' -Token $tok
    }
    $dRoutes = @(Get-DiscoveryRoutes)
    $bChosen = Get-RouteInfo -Address '255.255.255.255'
    $bSrc = Get-BroadcastSocketSource -Expected $physical
    Test-Step -Id 'lan-on.route-multicast-kept' -Scenario 'lan-on' -Expectation 'rosetun0 keeps 224.0.0.0/4' { $dRoutes -contains '224.0.0.0/4' }
    Test-Step -Id 'lan-on.route-broadcast-absent' -Scenario 'lan-on' -Expectation 'rosetun0 drops 255.255.255.255/32' { $dRoutes -notcontains '255.255.255.255/32' }
    Test-Step -Id 'lan-on.route-broadcast-physical' -Scenario 'lan-on' -Expectation 'Find-NetRoute sends broadcast via physical' -Note $bChosen.InterfaceAlias { $bChosen.InterfaceAlias -eq $physicalAlias }
    Test-Step -Id 'lan-on.socket-broadcast-physical' -Scenario 'lan-on' -Expectation 'broadcast socket picks physical address' -Note $bSrc { $bSrc -eq $physical }
    $tok = [guid]::NewGuid().ToString('N')
    $sent = Send-DiscoveryDatagram -Group '255.255.255.255' -Port $broadcastPort -Token $tok
    Test-Step -Id 'lan-on.broadcast-reaches' -Scenario 'lan-on' -Expectation 'limited broadcast reaches lab capture' -Note $sent {
        Test-LabSawToken -Kind 'broadcast' -Token $tok
    }
    $behind = @(Get-LanConnectionsTo -Address $privateBehind -Port 80)
    Test-Step -Id 'lan-on.behind-router-vpn' -Scenario 'lan-on' -Expectation 'private behind router goes through VPN' -Note (($behind | ForEach-Object { $_.Route }) -join ',') {
        $behind.Count -gt 0 -and @($behind | Where-Object { $_.Route -eq 'direct' }).Count -eq 0
    }
    Set-RosetunRunnerStep -Step 'long-session'
    $long = Invoke-LongSession -Seconds $longSessionSeconds
    Add-RosetunRunnerNote -Name 'long-session-echoes' -Value $long.Echoes
    Test-Step -Id 'lan-on.long-session' -Scenario 'lan-on' -Expectation 'long TCP session stays alive outside tunnel' -Note "echoes=$($long.Echoes) local=$($long.Local) $($long.Error)" {
        $long.Ok -and $long.Local -eq $physical -and $long.Echoes -gt 0
    }
    [void](Disconnect-LanSession)
    [void](Send-RosetunMarker -Plan $plan -Label 'lan-on' -Word 'close')
    $openWindow = $null

    # Window 2: address-change (judged, allowance: extra-address-arp)
    Set-RosetunRunnerStep -Step 'address-change'
    Clear-PeerNeighbor
    if (Send-RosetunMarker -Plan $plan -Label 'address-change' -Word 'open') { $openWindow = 'address-change' }
    Test-Step -Id 'address-change.connect' -Scenario 'address-change' -Expectation 'lan-on connects for address change' { Connect-LanVariant 'lan-on.json' }
    Test-Step -Id 'address-change.quiet-before' -Scenario 'address-change' -Expectation 'service settles before add' { Wait-LanQuiet }
    $mark = Get-HelperLogLength
    New-NetIPAddress -InterfaceAlias $physicalAlias -IPAddress $extraAddress -PrefixLength 26 -SkipAsSource $true | Out-Null
    $extraAdded = $true
    $newNetRegex = [regex]::Escape(($extraAddress -replace '\.\d+$', '.0/26'))
    Test-Step -Id 'address-change.follows-add' -Scenario 'address-change' -Expectation 'service follows added public network' {
        Wait-LanCondition -TimeoutSeconds 30 -Condition {
            (Get-HelperLogSince -Offset $mark) -match 'connected networks stay outside the tunnel[^\r\n]*public'
        }
    }
    Test-Step -Id 'address-change.connected-after-add' -Scenario 'address-change' -Expectation 'session remains Connected after add' { Wait-LanState 'Connected' }
    Test-Step -Id 'address-change.log-hides-network' -Scenario 'address-change' -Expectation 'helper log hides extra public CIDR' {
        (Get-HelperLogSince -Offset $mark) -notmatch $newNetRegex
    }
    $eRoute = Get-RouteInfo -Address $extraPeer
    Test-Step -Id 'address-change.extra-route-physical' -Scenario 'address-change' -Expectation 'extra peer routes via physical' -Note $eRoute.InterfaceAlias {
        $eRoute.InterfaceAlias -eq $physicalAlias
    }
    Test-Step -Id 'address-change.quiet-after-add' -Scenario 'address-change' -Expectation 'service settles on extra network' { Wait-LanQuiet }
    $mark = Get-HelperLogLength
    Remove-NetIPAddress -IPAddress $extraAddress -Confirm:$false
    $extraAdded = $false
    Test-Step -Id 'address-change.follows-remove' -Scenario 'address-change' -Expectation 'service follows removal of extra network' {
        Wait-LanCondition -TimeoutSeconds 25 -Condition {
            (Get-HelperLogSince -Offset $mark) -match 'local network changed'
        }
    }
    Test-Step -Id 'address-change.connected-after-remove' -Scenario 'address-change' -Expectation 'session remains Connected after remove' { Wait-LanState 'Connected' }
    $eRoute = Get-RouteInfo -Address $extraPeer
    Test-Step -Id 'address-change.extra-route-tunnel' -Scenario 'address-change' -Expectation 'removed extra network routes into tunnel' -Note $eRoute.InterfaceAlias {
        $eRoute.InterfaceAlias -eq $tunAlias
    }
    $dRoutes = @(Get-DiscoveryRoutes)
    $bChosen = Get-RouteInfo -Address '255.255.255.255'
    $bSrc = Get-BroadcastSocketSource -Expected $physical
    Test-Step -Id 'address-change.route-multicast-kept' -Scenario 'address-change' -Expectation 'rosetun0 keeps 224.0.0.0/4' { $dRoutes -contains '224.0.0.0/4' }
    Test-Step -Id 'address-change.route-broadcast-absent' -Scenario 'address-change' -Expectation 'rosetun0 keeps 255.255.255.255/32 absent' { $dRoutes -notcontains '255.255.255.255/32' }
    Test-Step -Id 'address-change.route-broadcast-physical' -Scenario 'address-change' -Expectation 'Find-NetRoute keeps broadcast physical' { $bChosen.InterfaceAlias -eq $physicalAlias }
    Test-Step -Id 'address-change.socket-broadcast-physical' -Scenario 'address-change' -Expectation 'broadcast socket keeps physical address' { $bSrc -eq $physical }
    [void](Disconnect-LanSession)
    [void](Send-RosetunMarker -Plan $plan -Label 'address-change' -Word 'close')
    $openWindow = $null

    # Window 3: lan-rule (judged, allowance: lan-peer-arp)
    Set-RosetunRunnerStep -Step 'lan-rule'
    if (Send-RosetunMarker -Plan $plan -Label 'lan-rule' -Word 'open') { $openWindow = 'lan-rule' }
    Test-Step -Id 'lan-rule.connect' -Scenario 'lan-rule' -Expectation 'lan-rule connects' { Connect-LanVariant 'lan-rule.json' }
    $conn = Invoke-LanTcpProbe -Address $lanPeer -Port $listenerPort -ReadBanner
    Test-Step -Id 'lan-rule.peer-direct' -Scenario 'lan-rule' -Expectation 'LAN segment wins over user proxy rule' -Note "$($conn.Local) $($conn.Banner)" {
        $conn.Connected -and $conn.Local -eq $physical -and $conn.Banner -eq 'ROSETUN-LAN-PEER'
    }
    [void](Disconnect-LanSession)
    [void](Send-RosetunMarker -Plan $plan -Label 'lan-rule' -Word 'close')
    $openWindow = $null

    # Window 4: lan-private (judged, zero allowances, expects PRIVATE_BEHIND_FLOW: 1)
    Set-RosetunRunnerStep -Step 'lan-private'
    Clear-PeerNeighbor
    if (Send-RosetunMarker -Plan $plan -Label 'lan-private' -Word 'open') { $openWindow = 'lan-private' }
    Test-Step -Id 'lan-private.connect' -Scenario 'lan-private' -Expectation 'lan-private connects' { Connect-LanVariant 'lan-private.json' }
    $behind = @(Get-LanConnectionsTo -Address $privateBehind -Port 80)
    Test-Step -Id 'lan-private.behind-router-direct' -Scenario 'lan-private' -Expectation 'private behind router goes direct' -Note (($behind | ForEach-Object { $_.Route }) -join ',') {
        $behind.Count -gt 0 -and @($behind | Where-Object { $_.Route -ne 'direct' }).Count -eq 0
    }
    [void](Disconnect-LanSession)
    [void](Send-RosetunMarker -Plan $plan -Label 'lan-private' -Word 'close')
    $openWindow = $null

    # Window 5: lan-off (judged, zero allowances, zero direct flows)
    Set-RosetunRunnerStep -Step 'lan-off'
    Clear-PeerNeighbor
    if (Send-RosetunMarker -Plan $plan -Label 'lan-off' -Word 'open') { $openWindow = 'lan-off' }
    Test-Step -Id 'lan-off.connect' -Scenario 'lan-off' -Expectation 'lan-off connects' { Connect-LanVariant 'lan-off.json' }
    $conn = Invoke-LanTcpProbe -Address $lanPeer -Port $listenerPort
    Test-Step -Id 'lan-off.peer-tcp-blocked' -Scenario 'lan-off' -Expectation 'TCP to peer does not leave physical' -Note "$($conn.Local) $($conn.Error)" {
        -not $conn.Connected -or $conn.Local -eq $tunAddress
    }
    $tok = [guid]::NewGuid().ToString('N')
    $sent = Send-DiscoveryDatagram -Group $mdnsGroup -Port $mdnsPort -Token $tok -BindPhysical $physical
    Test-Step -Id 'lan-off.mdns-physical-blocked' -Scenario 'lan-off' -Expectation 'physical mDNS blocked when LAN off' -Note $sent {
        -not (Test-LabSawToken -Kind 'mdns' -Token $tok -WaitMs 1000)
    }
    $tok = [guid]::NewGuid().ToString('N')
    $sent = Send-DiscoveryDatagram -Group $ssdpGroup -Port $ssdpPort -Token $tok -BindPhysical $physical
    Test-Step -Id 'lan-off.ssdp-physical-blocked' -Scenario 'lan-off' -Expectation 'physical SSDP blocked when LAN off' -Note $sent {
        -not (Test-LabSawToken -Kind 'ssdp' -Token $tok -WaitMs 1000)
    }
    Test-Step -Id 'lan-off.direct-egress-blocked' -Scenario 'lan-off' -Expectation 'direct egress stays blocked when LAN off' { -not (Test-DirectEgress) }
    $dRoutes = @(Get-DiscoveryRoutes)
    $bSrc = Get-BroadcastSocketSource -Expected $tunAddress
    Test-Step -Id 'lan-off.route-multicast-kept' -Scenario 'lan-off' -Expectation 'rosetun0 keeps 224.0.0.0/4' { $dRoutes -contains '224.0.0.0/4' }
    Test-Step -Id 'lan-off.route-broadcast-present' -Scenario 'lan-off' -Expectation 'rosetun0 keeps 255.255.255.255/32' { $dRoutes -contains '255.255.255.255/32' }
    Test-Step -Id 'lan-off.socket-broadcast-tunnel' -Scenario 'lan-off' -Expectation 'broadcast socket takes tunnel address' -Note $bSrc { $bSrc -eq $tunAddress }
    $tok = [guid]::NewGuid().ToString('N')
    $sent = Send-DiscoveryDatagram -Group $mdnsGroup -Port $mdnsPort -Token $tok
    Test-Step -Id 'lan-off.mdns-routed-blocked' -Scenario 'lan-off' -Expectation 'routed mDNS blocked when LAN off' -Note $sent {
        -not (Test-LabSawToken -Kind 'mdns' -Token $tok -WaitMs 1000)
    }
    $tok = [guid]::NewGuid().ToString('N')
    $sent = Send-DiscoveryDatagram -Group $ssdpGroup -Port $ssdpPort -Token $tok
    Test-Step -Id 'lan-off.ssdp-routed-blocked' -Scenario 'lan-off' -Expectation 'routed SSDP blocked when LAN off' -Note $sent {
        -not (Test-LabSawToken -Kind 'ssdp' -Token $tok -WaitMs 1000)
    }
    $tok = [guid]::NewGuid().ToString('N')
    $sent = Send-DiscoveryDatagram -Group '255.255.255.255' -Port $broadcastPort -Token $tok
    Test-Step -Id 'lan-off.broadcast-routed-blocked' -Scenario 'lan-off' -Expectation 'routed broadcast blocked when LAN off' -Note $sent {
        -not (Test-LabSawToken -Kind 'broadcast' -Token $tok -WaitMs 1000)
    }
    [void](Disconnect-LanSession)
    [void](Send-RosetunMarker -Plan $plan -Label 'lan-off' -Word 'close')
    $openWindow = $null

    # Window 6: switch (judged, allowance: lan-broadcast)
    # Run the intentional unprotected disconnect/reconnect transitions before opening the judged
    # window so OS background traffic during an intentionally disconnected gap is not misjudged
    # as a kill-switch leak; the judged window covers the reconnected lan-on session and broadcast.
    Set-RosetunRunnerStep -Step 'switch'
    Clear-PeerNeighbor
    Test-Step -Id 'switch.lan-on-connect' -Scenario 'switch' -Expectation 'lan-on connects before apply' { Connect-LanVariant 'lan-on.json' }
    Test-Step -Id 'switch.lan-on-broadcast-route' -Scenario 'switch' -Expectation 'broadcast route on physical with lan-on' {
        Test-BroadcastRouteState -OnTunnel $false -PhysicalAlias $physicalAlias
    }
    $applied = Invoke-LanCli -Arguments @('apply', (Join-Path $work 'lan-off.json')) -Seconds 30
    Test-Step -Id 'switch.apply-lan-off-refused' -Scenario 'switch' -Expectation 'apply lan-off to running session refused' -Note "exit $($applied.ExitCode)" {
        $applied.ExitCode -ne 0
    }
    Test-Step -Id 'switch.after-refusal-broadcast-route' -Scenario 'switch' -Expectation 'broadcast route remains physical after refusal' {
        Test-BroadcastRouteState -OnTunnel $false -PhysicalAlias $physicalAlias
    }
    Test-Step -Id 'switch.lan-off-connect' -Scenario 'switch' -Expectation 'lan-off connects after switch' { Connect-LanVariant 'lan-off.json' }
    Test-Step -Id 'switch.lan-off-broadcast-route' -Scenario 'switch' -Expectation 'broadcast route returns to tunnel' {
        Test-BroadcastRouteState -OnTunnel $true -PhysicalAlias $physicalAlias
    }
    [void](Disconnect-LanSession)
    if (Send-RosetunMarker -Plan $plan -Label 'switch' -Word 'open') { $openWindow = 'switch' }
    Test-Step -Id 'switch.lan-on-reconnect' -Scenario 'switch' -Expectation 'lan-on reconnects after lan-off' { Connect-LanVariant 'lan-on.json' }
    Test-Step -Id 'switch.lan-on-reconnect-broadcast-route' -Scenario 'switch' -Expectation 'broadcast route moves back to physical' {
        Test-BroadcastRouteState -OnTunnel $false -PhysicalAlias $physicalAlias
    }
    $tok = [guid]::NewGuid().ToString('N')
    $sent = Send-DiscoveryDatagram -Group '255.255.255.255' -Port $broadcastPort -Token $tok
    Test-Step -Id 'switch.broadcast-reaches-again' -Scenario 'switch' -Expectation 'limited broadcast reaches lab capture again' -Note $sent {
        Test-LabSawToken -Kind 'broadcast' -Token $tok
    }
    [void](Disconnect-LanSession)
    [void](Send-RosetunMarker -Plan $plan -Label 'switch' -Word 'close')
    $openWindow = $null

    # Window 7: lan-server (judged, allowance: lan-peer-arp, expects PEER_LISTENER_FLOW: 1)
    Set-RosetunRunnerStep -Step 'lan-server'
    if (Send-RosetunMarker -Plan $plan -Label 'lan-server' -Word 'open') { $openWindow = 'lan-server' }
    $mark = Get-HelperLogLength
    Test-Step -Id 'lan-server.connect' -Scenario 'lan-server' -Expectation 'lan-server connects with in-network VPN node' { Connect-LanVariant 'lan-server.json' }
    $serverLog = Get-HelperLogSince -Offset $mark
    Test-Step -Id 'lan-server.log' -Scenario 'lan-server' -Expectation 'service leaves out only VPN server address' {
        $serverLog -match 'open without the address of a VPN server' -and $serverLog -notmatch 'too many VPN servers'
    }
    $pRoute = Get-RouteInfo -Address $lanPeer
    Test-Step -Id 'lan-server.peer-route' -Scenario 'lan-server' -Expectation 'another peer routes via physical' -Note "$($pRoute.InterfaceAlias) $($pRoute.SourceAddress)" {
        $pRoute.InterfaceAlias -eq $physicalAlias -and $pRoute.SourceAddress -eq $physical
    }
    $conn = Invoke-LanTcpProbe -Address $lanPeer -Port $listenerPort -ReadBanner
    Test-Step -Id 'lan-server.peer-tcp' -Scenario 'lan-server' -Expectation 'TCP to another peer connects from physical' -Note "$($conn.Local) $($conn.Banner)" {
        $conn.Connected -and $conn.Local -eq $physical -and $conn.Banner -eq 'ROSETUN-LAN-PEER'
    }
    $dns53 = Invoke-LanTcpProbe -Address $lanPeer -Port 53
    Test-Step -Id 'lan-server.peer-dns-blocked' -Scenario 'lan-server' -Expectation 'TCP to another peer port 53 is blocked' -Note $dns53.Error {
        $dns53.Error -eq 'AccessDenied'
    }
    $sRoute = Get-RouteInfo -Address $gateway
    Test-Step -Id 'lan-server.server-route' -Scenario 'lan-server' -Expectation 'VPN server address routed into tunnel' -Note "$($sRoute.InterfaceAlias) $($sRoute.SourceAddress)" {
        $sRoute.InterfaceAlias -eq $tunAlias -and $sRoute.SourceAddress -eq $tunAddress
    }
    $directSrv = Invoke-LanTcpProbe -Address $gateway -Port $listenerPort -BindAddress $physical -TimeoutMs 2500
    Test-Step -Id 'lan-server.server-direct-blocked' -Scenario 'lan-server' -Expectation 'physical TCP to VPN server listener blocked' -Note $directSrv.Error {
        -not $directSrv.Connected
    }
    $tunSrv = Invoke-LanTcpProbe -Address $gateway -Port $listenerPort -ReadBanner -TimeoutMs 5000
    Test-Step -Id 'lan-server.server-through-tunnel' -Scenario 'lan-server' -Expectation 'VPN server host listener answers through tunnel' -Note "$($tunSrv.Local) $($tunSrv.Banner) $($tunSrv.Error)" {
        $tunSrv.Connected -and $tunSrv.Local -eq $tunAddress -and $tunSrv.Banner -eq 'ROSETUN-LAN-SERVER'
    }
    Test-Step -Id 'lan-server.tunnel-egress' -Scenario 'lan-server' -Expectation 'engine reaches HTTPS target via in-network server' {
        Wait-TunnelEgress
    }
    [void](Disconnect-LanSession)
    [void](Send-RosetunMarker -Plan $plan -Label 'lan-server' -Word 'close')
    $openWindow = $null

    # Window 8: lan-server-private (judged, zero allowances, expects PRIVATE_BEHIND_FLOW: 1)
    Set-RosetunRunnerStep -Step 'lan-server-private'
    Clear-PeerNeighbor
    if (Send-RosetunMarker -Plan $plan -Label 'lan-server-private' -Word 'open') { $openWindow = 'lan-server-private' }
    Test-Step -Id 'lan-server-private.connect' -Scenario 'lan-server-private' -Expectation 'lan-server-private connects' { Connect-LanVariant 'lan-server-private.json' }
    $directSrv = Invoke-LanTcpProbe -Address $gateway -Port $listenerPort -BindAddress $physical -TimeoutMs 2500
    Test-Step -Id 'lan-server-private.server-direct-blocked' -Scenario 'lan-server-private' -Expectation 'physical TCP to VPN server stays blocked' -Note $directSrv.Error {
        -not $directSrv.Connected
    }
    $sRoute = Get-RouteInfo -Address $gateway
    Test-Step -Id 'lan-server-private.server-route' -Scenario 'lan-server-private' -Expectation 'VPN server stays routed into tunnel' -Note "$($sRoute.InterfaceAlias) $($sRoute.SourceAddress)" {
        $sRoute.InterfaceAlias -eq $tunAlias -and $sRoute.SourceAddress -eq $tunAddress
    }
    $tunSrv = Invoke-LanTcpProbe -Address $gateway -Port $listenerPort -ReadBanner -TimeoutMs 5000
    Test-Step -Id 'lan-server-private.server-through-tunnel' -Scenario 'lan-server-private' -Expectation 'VPN server listener answers through tunnel' -Note "$($tunSrv.Local) $($tunSrv.Banner)" {
        $tunSrv.Connected -and $tunSrv.Local -eq $tunAddress -and $tunSrv.Banner -eq 'ROSETUN-LAN-SERVER'
    }
    $srvConns = @(Get-LanConnectionsTo -Address $gateway -Port $holdPort)
    Test-Step -Id 'lan-server-private.server-not-direct' -Scenario 'lan-server-private' -Expectation 'VPN server connection does not go direct' -Note (($srvConns | ForEach-Object { $_.Route }) -join ',') {
        $srvConns.Count -gt 0 -and @($srvConns | Where-Object { $_.Route -eq 'direct' }).Count -eq 0
    }
    $behind = @(Get-LanConnectionsTo -Address $privateBehind -Port 80)
    Test-Step -Id 'lan-server-private.behind-router-direct' -Scenario 'lan-server-private' -Expectation 'private behind router still goes direct' -Note (($behind | ForEach-Object { $_.Route }) -join ',') {
        $behind.Count -gt 0 -and @($behind | Where-Object { $_.Route -ne 'direct' }).Count -eq 0
    }
    Test-Step -Id 'lan-server-private.tunnel-egress' -Scenario 'lan-server-private' -Expectation 'engine reaches HTTPS target with lan-server-private' {
        Wait-TunnelEgress
    }
    [void](Disconnect-LanSession)
    [void](Send-RosetunMarker -Plan $plan -Label 'lan-server-private' -Word 'close')
    $openWindow = $null

    # Window 9: lan-reopen (judged, zero allowances, expects SERVER_LISTENER_FLOW: 1)
    Set-RosetunRunnerStep -Step 'lan-reopen'
    Clear-PeerNeighbor
    if (Send-RosetunMarker -Plan $plan -Label 'lan-reopen' -Word 'open') { $openWindow = 'lan-reopen' }
    Test-Step -Id 'lan-reopen.connect' -Scenario 'lan-reopen' -Expectation 'lan-on connects after lan-server' { Connect-LanVariant 'lan-on.json' }
    $conn = Invoke-LanTcpProbe -Address $gateway -Port $listenerPort -ReadBanner
    Test-Step -Id 'lan-reopen.server-direct' -Scenario 'lan-reopen' -Expectation 'former VPN server host reopens directly' -Note "$($conn.Local) $($conn.Banner) $($conn.Error)" {
        $conn.Connected -and $conn.Local -eq $physical -and $conn.Banner -eq 'ROSETUN-LAN-SERVER'
    }
    [void](Disconnect-LanSession)
    [void](Send-RosetunMarker -Plan $plan -Label 'lan-reopen' -Word 'close')
    $openWindow = $null
}
catch {
    $runError = $true
    Set-RosetunRunnerError -Place $script:RunnerStatus.step -Text ($_.Exception.GetType().Name + ': ' + $_.Exception.Message)
}
finally {
    Set-RosetunRunnerState -State cleaning -Step 'cleanup'

    if ($extraAdded -or (Get-NetIPAddress -IPAddress $extraAddress -ErrorAction SilentlyContinue)) {
        try { Remove-NetIPAddress -IPAddress $extraAddress -Confirm:$false -ErrorAction SilentlyContinue }
        catch { Set-RosetunRunnerError -Place 'cleanup' -Text 'extra-address-remove-failed' }
    }
    $cliDisconnected = $false
    if ($helperStarted -and (Test-Path -LiteralPath $cliPath)) {
        try {
            $cliDisconnected = Disconnect-LanSession -TimeoutSeconds 25
            [void](Invoke-LanCli -Arguments @('shutdown') -Seconds 15)
        }
        catch { Set-RosetunRunnerError -Place 'cleanup' -Text 'disconnect-failed' }
    }
    if ($null -ne $openWindow) {
        [void](Send-RosetunMarker -Plan $plan -Label $openWindow -Word 'close')
        $openWindow = $null
    }

    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Get-Process -Name 'rosetun-helper-privileged', 'sing-box' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500

    Remove-Item -LiteralPath $work, $bin -Recurse -Force -ErrorAction SilentlyContinue

    $parts['connection'] = if ($cliDisconnected -and -not (Get-Process -Name 'sing-box' -ErrorAction SilentlyContinue) -and -not (Test-TunAdapter)) { 'PASS' } else { 'ERROR' }
    $parts['extra_address'] = if (-not (Get-NetIPAddress -IPAddress $extraAddress -ErrorAction SilentlyContinue)) { 'PASS' } else { 'ERROR' }
    $parts['helper'] = if ($null -eq (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) -and -not (Get-Process -Name 'rosetun-helper-privileged' -ErrorAction SilentlyContinue)) { 'PASS' } else { 'ERROR' }
    $parts['files'] = if (-not (Test-Path -LiteralPath $work) -and -not (Test-Path -LiteralPath $bin)) { 'PASS' } else { 'ERROR' }

    # Window 10: recovery (listed)
    Set-RosetunRunnerStep -Step 'recovery'
    [void](Send-RosetunMarker -Plan $plan -Label 'recovery' -Word 'open')
    [void](Test-DirectEgress)
    [void](Test-DirectDns -Name $recoveryDns)
    Start-Sleep -Seconds 2
    [void](Send-RosetunMarker -Plan $plan -Label 'recovery' -Word 'close')

    $cleanupResult = if ($parts.Values -contains 'ERROR') { 'ERROR' }
        elseif ($parts.Values -contains 'UNVERIFIED') { 'UNVERIFIED' }
        else { 'PASS' }
    Set-RosetunRunnerCleanup -Result $cleanupResult -Parts $parts

    if ($null -ne $recorder) {
        try {
            Complete-RosetunListResults -Recorder $recorder -Cleanup $cleanupResult `
                -EndBootId (Get-RosetunBootCounter) -Aborted $runError
        }
        catch {
            $runError = $true
            Set-RosetunRunnerError -Place 'finalize' -Text ($_.Exception.GetType().Name + ': ' + $_.Exception.Message)
        }
    }
    Set-RosetunRunnerState -State $(if ($runError) { 'failed' } else { 'finished' }) -Step 'done'
}
