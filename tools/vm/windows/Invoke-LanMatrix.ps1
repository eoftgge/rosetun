# Runs the "Local network" matrix against the Hyper-V test VM. The owner runs it.
# The host plays a device on the guest's network: the Default Switch puts both
# in one segment. Exits with 1 if any check fails.

param(
    [Parameter(Mandatory)][string]$SingBoxPath,
    [Parameter(Mandatory)][string]$RequestPath,
    [string]$BuildDir,
    [switch]$UseHostNode,
    [string]$NodeBindInterface,
    [switch]$KeepNode,
    [switch]$Build,
    # How long the long TCP session to the host lasts.
    [int]$LongSessionSeconds = 600,
    # A private address outside the guest's segment, routed through its gateway.
    [string]$PrivateBehindRouter = '10.255.255.1',
    # A documentation network the guest is given for the address change.
    [string]$ExtraAddress = '198.51.100.10',
    [string]$ExtraPeer = '198.51.100.20'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
if (-not $BuildDir) { $BuildDir = Join-Path $RepoRoot 'target\release' }
Import-Module (Join-Path $PSScriptRoot 'RosetunVm.psm1') -Force

$results = [System.Collections.Generic.List[object]]::new()
$SwitchAlias = 'vEthernet (Default Switch)'
$TunAlias = 'rosetun0'
$TunAddress = '172.19.0.1'

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
        Result = if ($passed) { 'PASS' } else { 'FAIL' }
        Scenario = $Scenario
        Check = $Expectation
        Note = $Note
    })
    if (-not $passed) {
        Write-Host "FAIL  $Scenario - $Expectation ($Note)" -ForegroundColor Red
    }
}

function Write-RosetunLanNote {
    param([Parameter(Mandatory)][string]$Scenario, [Parameter(Mandatory)][string]$Text)
    $results.Add([pscustomobject]@{ Result = 'INFO'; Scenario = $Scenario; Check = $Text; Note = '' })
}

function New-RosetunLanRequests {
    # Request variants next to request.json in the guest: kill switch on, and
    # "Local network" off, on, on with private networks, and on with a rule
    # that sends the host through the VPN.
    param([Parameter(Mandatory)][string]$HostAddress)
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $hostAddress)
        $variants = @{
            'lan-off.json'     = @{ allow = $false; private = $false; rule = $false }
            'lan-on.json'      = @{ allow = $true; private = $false; rule = $false }
            'lan-private.json' = @{ allow = $true; private = $true; rule = $false }
            'lan-rule.json'    = @{ allow = $true; private = $false; rule = $true }
        }
        foreach ($name in $variants.Keys) {
            $variant = $variants[$name]
            $request = Get-Content -Path (Join-Path $dir 'request.json') -Raw | ConvertFrom-Json
            $request.settings | Add-Member -NotePropertyName kill_switch -NotePropertyValue $true -Force
            $request.settings | Add-Member -NotePropertyName auto_reconnect -NotePropertyValue $true -Force
            $request.settings | Add-Member -NotePropertyName allow_lan -NotePropertyValue $variant.allow -Force
            $request.settings | Add-Member -NotePropertyName private_networks -NotePropertyValue $variant.private -Force
            if ($variant.rule) {
                $rule = [pscustomobject]@{
                    id      = 'host-through-vpn'
                    enabled = $true
                    matcher = [pscustomobject]@{ ip_cidr = "$hostAddress/32" }
                    target  = 'proxy'
                }
                $request.rule_set.rules = @($rule) + @($request.rule_set.rules)
            }
            [IO.File]::WriteAllText((Join-Path $dir $name), ($request | ConvertTo-Json -Depth 30))
        }
    } -ArgumentList (Get-RosetunGuestDir), $HostAddress
}

function Connect-RosetunLan {
    param([Parameter(Mandatory)][string]$RequestName)
    Disconnect-RosetunTunnel | Out-Null
    Wait-RosetunState 'Disconnected' | Out-Null
    $result = Connect-RosetunTunnel -RequestName $RequestName
    $result.ExitCode -eq 0 -and (Wait-RosetunState 'Connected')
}

function Get-RosetunGuestRoute {
    # The adapter and source address Windows picks in the guest for $Address.
    param([Parameter(Mandatory)][string]$Address)
    Invoke-RosetunGuest -ScriptBlock {
        param($address)
        # Find-NetRoute returns the source address and the route it chose.
        $found = @(Find-NetRoute -RemoteIPAddress $address -ErrorAction Stop)
        $source = @($found | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_NetIPAddress' }) | Select-Object -First 1
        $next = @($found | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_NetRoute' }) | Select-Object -First 1
        [pscustomobject]@{
            InterfaceAlias = if ($next) { $next.InterfaceAlias } else { '' }
            SourceAddress  = if ($source) { $source.IPAddress } else { '' }
        }
    } -ArgumentList $Address
}

function Invoke-RosetunGuestConnect {
    # A TCP connect from the guest without a bound source, as an application
    # makes it. Returns the local address it used or the socket error.
    param(
        [Parameter(Mandatory)][string]$Address,
        [Parameter(Mandatory)][int]$Port,
        [int]$TimeoutMs = 3000
    )
    Invoke-RosetunGuest -ScriptBlock {
        param($address, $port, $timeout)
        $client = [Net.Sockets.TcpClient]::new()
        try {
            $task = $client.ConnectAsync($address, $port)
            if ($task.Wait($timeout)) {
                return [pscustomobject]@{
                    Connected = $true
                    Local     = ([Net.IPEndPoint]$client.Client.LocalEndPoint).Address.ToString()
                    Error     = ''
                }
            }
            [pscustomobject]@{ Connected = $false; Local = ''; Error = 'TimedOut' }
        }
        catch {
            $inner = $_.Exception
            while ($inner.InnerException) { $inner = $inner.InnerException }
            $code = if ($inner -is [Net.Sockets.SocketException]) { "$($inner.SocketErrorCode)" } else { $inner.GetType().Name }
            [pscustomobject]@{ Connected = $false; Local = ''; Error = $code }
        }
        finally { $client.Dispose() }
    } -ArgumentList $Address, $Port, $TimeoutMs
}

function Start-RosetunMulticastWatch {
    # Host listeners on the Default Switch for mDNS and SSDP. They share the
    # ports with the host's own services (ReuseAddress) and keep what arrives.
    param([Parameter(Mandatory)][string]$HostAddress)
    $watch = @()
    foreach ($target in @(@{ Group = '224.0.0.251'; Port = 5353 }, @{ Group = '239.255.255.250'; Port = 1900 })) {
        $name = "Rosetun-LAN-multicast-$($target.Port)-$([guid]::NewGuid().ToString('N'))"
        New-NetFirewallRule -Name $name -DisplayName 'Rosetun LAN matrix multicast' -Direction Inbound `
            -Action Allow -Protocol UDP -LocalPort $target.Port -InterfaceAlias $SwitchAlias -Profile Any | Out-Null
        $socket = [Net.Sockets.UdpClient]::new()
        $socket.ExclusiveAddressUse = $false
        $socket.Client.SetSocketOption([Net.Sockets.SocketOptionLevel]::Socket,
            [Net.Sockets.SocketOptionName]::ReuseAddress, $true)
        $socket.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Any, $target.Port))
        $socket.JoinMulticastGroup([Net.IPAddress]::Parse($target.Group), [Net.IPAddress]::Parse($HostAddress))
        $socket.Client.ReceiveTimeout = 500
        $watch += [pscustomobject]@{ Group = $target.Group; Port = $target.Port; Socket = $socket; RuleName = $name }
    }
    $watch
}

function Receive-RosetunMulticast {
    # Whether a datagram with $Token reached the host on the watch's group.
    param([Parameter(Mandatory)]$Watch, [Parameter(Mandatory)][string]$Token, [int]$Seconds = 5)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    $remote = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $data = $Watch.Socket.Receive([ref]$remote)
            if ([Text.Encoding]::ASCII.GetString($data).Contains($Token)) { return $true }
        }
        catch [Net.Sockets.SocketException] { }
    }
    $false
}

function Stop-RosetunMulticastWatch {
    param([Parameter(Mandatory)][object[]]$Watch)
    foreach ($entry in $Watch) {
        try { Remove-NetFirewallRule -Name $entry.RuleName -ErrorAction SilentlyContinue }
        finally { $entry.Socket.Dispose() }
    }
}

function Send-RosetunGuestMulticast {
    # Sends one datagram from the guest. -Physical picks the physical adapter,
    # as mDNS and SSDP stacks do per adapter; without it Windows routes it.
    param(
        [Parameter(Mandatory)][string]$Group,
        [Parameter(Mandatory)][int]$Port,
        [Parameter(Mandatory)][string]$Token,
        [string]$Physical = ''
    )
    Invoke-RosetunGuest -ScriptBlock {
        param($group, $port, $token, $physical)
        $client = [Net.Sockets.UdpClient]::new()
        try {
            if ($physical) {
                $client.Client.SetSocketOption([Net.Sockets.SocketOptionLevel]::IP,
                    [Net.Sockets.SocketOptionName]::MulticastInterface,
                    [Net.IPAddress]::Parse($physical).GetAddressBytes())
            }
            $bytes = [Text.Encoding]::ASCII.GetBytes("rosetun-lan-matrix $token")
            foreach ($attempt in 1..3) {
                [void]$client.Send($bytes, $bytes.Length, $group, $port)
                Start-Sleep -Milliseconds 300
            }
            'sent'
        }
        catch {
            $inner = $_.Exception
            while ($inner.InnerException) { $inner = $inner.InnerException }
            if ($inner -is [Net.Sockets.SocketException]) { "$($inner.SocketErrorCode)" } else { $inner.GetType().Name }
        }
        finally { $client.Dispose() }
    } -ArgumentList $Group, $Port, $Token, $Physical
}

function Start-RosetunEchoServer {
    # A host job that accepts one connection on the Default Switch and echoes
    # until the guest closes it.
    param([Parameter(Mandatory)][string]$HostAddress)
    $probe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse($HostAddress), 0)
    $probe.Start()
    $port = ([Net.IPEndPoint]$probe.LocalEndpoint).Port
    $probe.Stop()
    $name = "Rosetun-LAN-echo-$([guid]::NewGuid().ToString('N'))"
    New-NetFirewallRule -Name $name -DisplayName 'Rosetun LAN matrix echo' -Direction Inbound -Action Allow `
        -Protocol TCP -LocalAddress $HostAddress -LocalPort $port -InterfaceAlias $SwitchAlias -Profile Any | Out-Null
    $job = Start-Job -ScriptBlock {
        param($address, $port)
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse($address), $port)
        $listener.Start()
        try {
            $client = $listener.AcceptTcpClient()
            $stream = $client.GetStream()
            $buffer = [byte[]]::new(64)
            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $stream.Write($buffer, 0, $read)
            }
            $client.Dispose()
        }
        finally { $listener.Stop() }
    } -ArgumentList $HostAddress, $port
    Start-Sleep -Seconds 1
    [pscustomobject]@{ Port = $port; Job = $job; RuleName = $name }
}

function Stop-RosetunEchoServer {
    param([Parameter(Mandatory)]$Echo)
    Stop-Job -Job $Echo.Job -ErrorAction SilentlyContinue
    Remove-Job -Job $Echo.Job -Force -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -Name $Echo.RuleName -ErrorAction SilentlyContinue
}

function Invoke-RosetunGuestLongSession {
    # One TCP connection to the echo server, a byte every 5 s for $Seconds.
    param([Parameter(Mandatory)][string]$Address, [Parameter(Mandatory)][int]$Port, [Parameter(Mandatory)][int]$Seconds)
    Invoke-RosetunGuest -ScriptBlock {
        param($address, $port, $seconds)
        $client = [Net.Sockets.TcpClient]::new()
        $sent = 0
        try {
            $client.Connect($address, $port)
            $local = ([Net.IPEndPoint]$client.Client.LocalEndPoint).Address.ToString()
            $stream = $client.GetStream()
            $stream.ReadTimeout = 10000
            $deadline = [DateTime]::UtcNow.AddSeconds($seconds)
            $buffer = [byte[]]::new(1)
            while ([DateTime]::UtcNow -lt $deadline) {
                $stream.Write([byte[]]@(42), 0, 1)
                if ($stream.Read($buffer, 0, 1) -ne 1) { throw 'the echo stopped' }
                $sent++
                Start-Sleep -Seconds 5
            }
            [pscustomobject]@{ Ok = $true; Local = $local; Echoes = $sent; Error = '' }
        }
        catch {
            [pscustomobject]@{ Ok = $false; Local = ''; Echoes = $sent; Error = "$_" }
        }
        finally { $client.Dispose() }
    } -ArgumentList $Address, $Port, $Seconds
}

function Get-RosetunGuestConnectionsTo {
    # Tries $Address a few times while `rosetun connections` is read, and
    # returns the rows for it: the engine's route says whether "Private
    # networks behind the router" sent it direct or through the VPN.
    param([Parameter(Mandatory)][string]$Address)
    $output = Invoke-RosetunGuest -ScriptBlock {
        param($dir, $address)
        $cli = Join-Path $dir 'rosetun.exe'
        $poller = Start-Job -ScriptBlock {
            param($cli)
            while ($true) { & $cli connections *> $null }
        } -ArgumentList $cli
        try {
            Start-Sleep -Seconds 3
            $rows = @()
            foreach ($attempt in 1..4) {
                $client = [Net.Sockets.TcpClient]::new()
                try { [void]$client.ConnectAsync($address, 80).Wait(1500) }
                catch { }
                $rows += @(& $cli connections 2>&1 | ForEach-Object { "$_" })
                $client.Dispose()
            }
            $global:LASTEXITCODE = 0
            $rows -join "`n"
        }
        finally {
            Stop-Job -Job $poller -ErrorAction SilentlyContinue
            Remove-Job -Job $poller -Force -ErrorAction SilentlyContinue
        }
    } -ArgumentList (Get-RosetunGuestDir), $Address
    @(Get-RosetunConnectionRows -Output $output | Where-Object { $_.Destination -like "$Address*" })
}

function Get-RosetunGuestPhysical {
    # Alias and IPv4 address of the guest's adapter on the Default Switch.
    Invoke-RosetunGuest -ScriptBlock {
        param($tunAlias)
        $address = Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred |
            Where-Object { $_.InterfaceAlias -ne $tunAlias -and $_.IPAddress -notlike '127.*' -and
                $_.IPAddress -notlike '169.254.*' -and $_.PrefixOrigin -eq 'Dhcp' } |
            Select-Object -First 1
        [pscustomobject]@{ Alias = $address.InterfaceAlias; Address = $address.IPAddress }
    } -ArgumentList $TunAlias
}

$nodeStartedByMatrix = $false
$multicast = @()
$echo = $null
$extraAdded = $false
$physical = $null
try {
    if ($Build) {
        & cargo build -q --release --manifest-path (Join-Path $RepoRoot 'Cargo.toml')
        $exitCode = $LASTEXITCODE
        $global:LASTEXITCODE = 0
        if ($exitCode -ne 0) { throw "cargo build failed with exit code $exitCode." }
    }
    if ($UseHostNode) {
        if ($NodeBindInterface) {
            $nodeStartedByMatrix = Start-RosetunTestNode -SingBoxPath $SingBoxPath -BindInterface $NodeBindInterface
        }
        else {
            $nodeStartedByMatrix = Start-RosetunTestNode -SingBoxPath $SingBoxPath
        }
    }

    Stop-RosetunHelper
    Publish-Rosetun -BuildDir $BuildDir -SingBoxPath $SingBoxPath -RequestPath $RequestPath -UseHostNode:$UseHostNode
    Register-RosetunHelper
    Start-RosetunHelper

    $hostAddress = (Get-RosetunHostSwitchSubnet).Address
    $physical = Get-RosetunGuestPhysical
    New-RosetunLanRequests -HostAddress $hostAddress
    $lan = Start-RosetunLanListener
    $multicast = @(Start-RosetunMulticastWatch -HostAddress $hostAddress)

    try {
        # Route: with "Local network" the host is on-link through the adapter.
        Test-Step 'route' 'lan-on connects' { Connect-RosetunLan 'lan-on.json' }
        $route = Get-RosetunGuestRoute -Address $hostAddress
        Test-Step 'route' 'the host goes through the physical adapter, not rosetun0' `
            -Note "$($route.InterfaceAlias) $($route.SourceAddress)" {
            $route.InterfaceAlias -eq $physical.Alias -and $route.SourceAddress -eq $physical.Address
        }
        $connect = Invoke-RosetunGuestConnect -Address $hostAddress -Port $lan.Port
        Test-Step 'tcp' 'TCP to the host connects from the guest address' `
            -Note "$($connect.Local) $($connect.Error)" {
            $connect.Connected -and $connect.Local -eq $physical.Address -and $connect.Local -ne $TunAddress
        }
        $dns = Invoke-RosetunGuestConnect -Address $hostAddress -Port 53
        Test-Step 'dns' 'TCP to the host on port 53 is blocked' -Note $dns.Error {
            $dns.Error -eq 'AccessDenied'
        }
        foreach ($entry in $multicast) {
            foreach ($mode in @('physical', 'routed')) {
                $token = [guid]::NewGuid().ToString('N')
                $chosen = if ($mode -eq 'physical') { $physical.Address } else { '' }
                $sent = Send-RosetunGuestMulticast -Group $entry.Group -Port $entry.Port -Token $token -Physical $chosen
                Test-Step 'multicast' "$($entry.Group):$($entry.Port) $mode reaches the host" -Note $sent {
                    Receive-RosetunMulticast -Watch $entry -Token $token
                }
            }
        }
        $behind = @(Get-RosetunGuestConnectionsTo -Address $PrivateBehindRouter)
        Test-Step 'behind the router' "$PrivateBehindRouter goes through the VPN without private networks" `
            -Note (($behind | ForEach-Object { $_.Route }) -join ',') {
            $behind.Count -gt 0 -and -not ($behind | Where-Object { $_.Route -eq 'direct' })
        }

        # A long session to the host, past the engine's idle timers.
        $echo = Start-RosetunEchoServer -HostAddress $hostAddress
        $long = Invoke-RosetunGuestLongSession -Address $hostAddress -Port $echo.Port -Seconds $LongSessionSeconds
        Test-Step 'long session' "$LongSessionSeconds s to the host without a break, outside the tunnel" `
            -Note "$($long.Echoes) echoes $($long.Local) $($long.Error)" {
            $long.Ok -and $long.Local -eq $physical.Address
        }
        Stop-RosetunEchoServer $echo
        $echo = $null

        # The address change: a second network on the adapter is followed.
        $mark = Get-RosetunHelperLogLength
        Invoke-RosetunGuest -ScriptBlock {
            param($alias, $address)
            New-NetIPAddress -InterfaceAlias $alias -IPAddress $address -PrefixLength 24 -SkipAsSource $true | Out-Null
        } -ArgumentList $physical.Alias, $ExtraAddress
        $extraAdded = $true
        Test-Step 'address change' 'the service follows the new network' {
            Wait-RosetunCondition {
                (Get-RosetunHelperLogSince -Offset $mark) -match 'local network changed'
            } -TimeoutSeconds 20
        }
        Test-Step 'address change' 'the session is Connected again' { Wait-RosetunState 'Connected' }
        $route = Get-RosetunGuestRoute -Address $ExtraPeer
        Test-Step 'address change' 'the new network is on the physical adapter' -Note $route.InterfaceAlias {
            $route.InterfaceAlias -eq $physical.Alias
        }
        Test-Step 'address change' 'the new network is in the helper log' {
            (Get-RosetunHelperLogSince -Offset $mark) -match [regex]::Escape(($ExtraAddress -replace '\.\d+$', '.0/24'))
        }
        $mark = Get-RosetunHelperLogLength
        Invoke-RosetunGuest -ScriptBlock {
            param($address)
            Remove-NetIPAddress -IPAddress $address -Confirm:$false
        } -ArgumentList $ExtraAddress
        $extraAdded = $false
        Test-Step 'address change' 'the service follows the removal' {
            Wait-RosetunCondition {
                (Get-RosetunHelperLogSince -Offset $mark) -match 'local network changed'
            } -TimeoutSeconds 20
        }
        Test-Step 'address change' 'Connected after the removal' { Wait-RosetunState 'Connected' }
        $route = Get-RosetunGuestRoute -Address $ExtraPeer
        Test-Step 'address change' 'the old network is no longer outside the tunnel' -Note $route.InterfaceAlias {
            $route.InterfaceAlias -eq $TunAlias
        }

        # A user's rule sends the host through the VPN; the segment still wins.
        Test-Step 'user rule' 'lan-rule connects' { Connect-RosetunLan 'lan-rule.json' }
        $connect = Invoke-RosetunGuestConnect -Address $hostAddress -Port $lan.Port
        Test-Step 'user rule' 'the host is still reached directly' -Note "$($connect.Local) $($connect.Error)" {
            $connect.Connected -and $connect.Local -eq $physical.Address
        }

        # Private networks behind the router.
        Test-Step 'behind the router' 'lan-private connects' { Connect-RosetunLan 'lan-private.json' }
        $behind = @(Get-RosetunGuestConnectionsTo -Address $PrivateBehindRouter)
        Test-Step 'behind the router' "$PrivateBehindRouter goes direct with private networks" `
            -Note (($behind | ForEach-Object { $_.Route }) -join ',') {
            $behind.Count -gt 0 -and -not ($behind | Where-Object { $_.Route -ne 'direct' })
        }

        # Without "Local network".
        Test-Step 'off' 'lan-off connects' { Connect-RosetunLan 'lan-off.json' }
        $route = Get-RosetunGuestRoute -Address $hostAddress
        Write-RosetunLanNote 'off' "the host's route without Local network: $($route.InterfaceAlias) $($route.SourceAddress)"
        $connect = Invoke-RosetunGuestConnect -Address $hostAddress -Port $lan.Port
        Test-Step 'off' 'TCP to the host is blocked' -Note "$($connect.Local) $($connect.Error)" {
            -not $connect.Connected -or $connect.Local -eq $TunAddress
        }
        foreach ($entry in $multicast) {
            $token = [guid]::NewGuid().ToString('N')
            $sent = Send-RosetunGuestMulticast -Group $entry.Group -Port $entry.Port -Token $token -Physical $physical.Address
            Test-Step 'off' "$($entry.Group):$($entry.Port) does not reach the host" -Note $sent {
                -not (Receive-RosetunMulticast -Watch $entry -Token $token -Seconds 3)
            }
        }
        Test-Step 'off' 'direct internet is still blocked' { -not (Test-RosetunDirectEgress) }
    }
    finally {
        Disconnect-RosetunTunnel | Out-Null
        if ($physical) {
            # A static address on the adapter can switch it off DHCP; give it
            # back its lease either way.
            Invoke-RosetunGuest -ScriptBlock {
                param($alias, $address, $added)
                if ($added) {
                    Remove-NetIPAddress -IPAddress $address -Confirm:$false -ErrorAction SilentlyContinue
                }
                Set-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -Dhcp Enabled -ErrorAction SilentlyContinue
                & ipconfig.exe /renew $alias *> $null
                $global:LASTEXITCODE = 0
            } -ArgumentList $physical.Alias, $ExtraAddress, $extraAdded
        }
        if ($echo) { Stop-RosetunEchoServer $echo }
        if ($multicast.Count -gt 0) { Stop-RosetunMulticastWatch -Watch $multicast }
        try { Stop-RosetunLanListener $lan }
        catch { Write-Warning "Could not stop the LAN listener: $_" }
        Invoke-RosetunGuest -ScriptBlock {
            param($dir)
            foreach ($name in @('lan-off.json', 'lan-on.json', 'lan-private.json', 'lan-rule.json')) {
                Remove-Item -Path (Join-Path $dir $name) -Force -ErrorAction SilentlyContinue
            }
        } -ArgumentList (Get-RosetunGuestDir)
    }
}
finally {
    if ($nodeStartedByMatrix -and -not $KeepNode) {
        try { Stop-RosetunTestNode }
        catch { Write-Warning "Could not stop the test node: $_" }
    }
}

$results | Format-Table -AutoSize
if ($results.Result -contains 'FAIL') { exit 1 }
exit 0
