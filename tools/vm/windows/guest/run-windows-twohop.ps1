# The Windows Two-Hop Proxy Chain matrix as an autonomous runner of the QEMU lab (stage 10f).
# Windows PowerShell 5.1, as SYSTEM.
#
# Runs all 40 scenarios of two-hop-scenarios.tsv (20 scenarios x tun and system-proxy modes)
# against the isolated lab wire, verifying target=B and B=A attribution and zero direct leaks.

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
$work = Join-Path $Root 'twohop-matrix'
$resultsDir = Join-Path $Root 'results'
$helperLogPath = Join-Path $logs 'helper.log'
$cliPath = Join-Path $bin 'rosetun.exe'
$helperPath = Join-Path $bin 'rosetun-helper-privileged.exe'
$singBoxPath = Join-Path $bin 'sing-box.exe'
$xrayPath = Join-Path $bin 'xray.exe'
$curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'
$taskName = 'RosetunHelper'

$proxyPort = [int]$plan.proxy_port
$physical = [string]$plan.addresses.client4
$gateway = [string]$plan.addresses.gateway4
$target4 = [string]$plan.addresses.target4
$resolver = [string]$plan.addresses.resolver
$th = $plan.twohop
$b4 = [string]$th.b4
$b6 = [string]$th.b6
$lanPeer = [string]$th.lan_peer
$primaryEgress = [string]$th.primary_egress
$secondEgress4 = [string]$th.second_node_egress
$secondEgress6 = [string]$th.second_node_egress6
$domainB = [string]$th.domain_b
$targetUrl = 'https://' + $target4 + '/'
$listedName = [string]$plan.names.listed
$unlistedName = [string]$plan.names.unlisted
$listedUrl = 'https://' + $listedName + '/'
$unlistedUrl = 'https://' + $unlistedName + '/'
$baselineDns = [string]$plan.baseline.dns_name
$recoveryDns = 'after.' + $baselineDns
$tunAlias = [string]$plan.tun.alias

function Invoke-ThCli {
    param([Parameter(Mandatory)][string[]]$Arguments, [int]$Seconds = 90)
    Invoke-RosetunNative -FilePath $cliPath -Arguments $Arguments -TimeoutSeconds $Seconds
}

function Get-ThState {
    $result = Invoke-ThCli -Arguments @('status') -Seconds 20
    if ($result.Output -match '(?m)^state: (\w+)') { return $Matches[1] }
    return "unknown (exit $($result.ExitCode))"
}

function Get-ThLockdown {
    $result = Invoke-ThCli -Arguments @('status') -Seconds 20
    if ($result.ExitCode -eq 0 -and $result.Output -match '(?m)^lockdown: (on|off)\r?$') { return $Matches[1] }
    return 'unknown'
}

function Wait-ThCondition {
    param([Parameter(Mandatory)][scriptblock]$Condition, [int]$TimeoutSeconds = 30)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (& $Condition) { return $true }
        Start-Sleep -Milliseconds 300
    } while ([DateTime]::UtcNow -lt $deadline)
    return $false
}

function Wait-ThState {
    param([Parameter(Mandatory)][string]$Expected, [int]$TimeoutSeconds = 35)
    return (Wait-ThCondition -TimeoutSeconds $TimeoutSeconds -Condition { (Get-ThState) -eq $Expected })
}

function Wait-HelperReady {
    param([int]$TimeoutSeconds = 90)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ($clock.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        if ((Invoke-ThCli -Arguments @('status') -Seconds 15).ExitCode -eq 0) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Test-TunAdapter {
    return ($null -ne (Get-NetAdapter -Name $tunAlias -ErrorAction SilentlyContinue))
}

function Get-XrayPids {
    return @(Get-Process -Name 'xray' -ErrorAction SilentlyContinue | ForEach-Object { [int]$_.Id })
}

function Get-SingBoxPids {
    return @(Get-Process -Name 'sing-box' -ErrorAction SilentlyContinue | ForEach-Object { [int]$_.Id })
}

function Disconnect-ThSession {
    param([int]$TimeoutSeconds = 35)
    [void](Invoke-ThCli -Arguments @('disconnect') -Seconds 30)
    return (Wait-ThCondition -TimeoutSeconds $TimeoutSeconds -Condition {
        (Get-ThState) -eq 'Disconnected' -and -not (Test-TunAdapter) -and @(Get-XrayPids).Count -eq 0
    })
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

function Test-DirectTcpBlocked {
    param([Parameter(Mandatory)][string]$Address, [Parameter(Mandatory)][int]$Port)
    $client = [Net.Sockets.TcpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Parse($physical), 0))
    try {
        $task = $client.ConnectAsync($Address, $Port)
        if (-not $task.Wait(2500)) { return $true }
        return (-not $client.Connected)
    }
    catch { return $true }
    finally { $client.Dispose() }
}

function Test-ModeUrlOnce {
    param(
        [Parameter(Mandatory)][ValidateSet('tun', 'system-proxy')][string]$Mode,
        [Parameter(Mandatory)][string]$Url,
        [int]$MaxTime = 10
    )
    if ($Mode -eq 'system-proxy') {
        $result = Invoke-RosetunNative -FilePath $curlPath -TimeoutSeconds ($MaxTime + 10) -Arguments @(
            '--proxy', "http://127.0.0.1:$proxyPort", '--max-time', ([string]$MaxTime),
            '--silent', '--insecure', '--ssl-no-revoke', $Url)
        return ($result.ExitCode -eq 0 -and $result.Output.Trim() -eq 'rosetun-lab-target')
    }
    $tunAddresses = @(Get-NetIPAddress -InterfaceAlias $tunAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        ForEach-Object { $_.IPAddress })
    if ($tunAddresses.Count -eq 0) { return $false }
    $result = Invoke-RosetunNative -FilePath $curlPath -TimeoutSeconds ($MaxTime + 10) -Arguments @(
        '--max-time', ([string]$MaxTime), '--silent', '--insecure', '--ssl-no-revoke',
        '--write-out', "`nlocal=%{local_ip} remote=%{remote_ip} code=%{http_code}", $Url)
    if ($result.ExitCode -ne 0) { return $false }
    $local = ''; $remote = ''; $code = ''
    if ($result.Output -match 'local=(\S*) remote=(\S*) code=(\d+)') {
        $local, $remote, $code = $Matches[1], $Matches[2], $Matches[3]
    }
    return ($tunAddresses -contains $local -and $remote -eq $target4 -and $code -eq '200' -and
        $result.Output -match 'rosetun-lab-target')
}

function Wait-ModeUrl {
    param(
        [Parameter(Mandatory)][ValidateSet('tun', 'system-proxy')][string]$Mode,
        [Parameter(Mandatory)][string]$Url,
        [int]$TimeoutSeconds = 25
    )
    return (Wait-ThCondition -TimeoutSeconds $TimeoutSeconds -Condition { Test-ModeUrlOnce -Mode $Mode -Url $Url })
}

function Get-FixtureState {
    return (Invoke-RosetunLabAction -Root $Root -Operation 'fixture_state' -Parameters @{})
}

function Set-LabService {
    param(
        [Parameter(Mandatory)][ValidateSet('primary_node', 'second_node', 'xray', 'twohop_b')][string]$Service,
        [Parameter(Mandatory)][ValidateSet('start', 'stop')][string]$State
    )
    $reply = Invoke-RosetunLabAction -Root $Root -Operation 'fixture_control' -Parameters @{
        service = $Service
        state = $State
    }
    if (-not $reply.ok) { throw "fixture_control failed for $Service=$State ($($reply.reason))" }
    return $reply
}

function Get-HttpsCount {
    param($State, [Parameter(Mandatory)][string]$Source)
    if ($null -eq $State -or $null -eq $State.https -or $null -eq $State.https.by_source) { return 0 }
    $prop = $State.https.by_source.PSObject.Properties[$Source]
    if ($null -eq $prop) { return 0 }
    return [int]$prop.Value
}

function Get-TwoHopEvents {
    param($State)
    if ($null -eq $State -or $null -eq $State.twohop -or $null -eq $State.twohop.events) { return @() }
    return @($State.twohop.events)
}

function Test-HasNewTwoHopEvent {
    param(
        $AfterState,
        [int]$BeforeCount,
        [string]$Kind,
        [string]$Client = '',
        [string]$Listen = '',
        [string]$Status = 'ok'
    )
    $events = @(Get-TwoHopEvents -State $AfterState)
    if ($events.Count -le $BeforeCount) { return $false }
    for ($i = $BeforeCount; $i -lt $events.Count; $i++) {
        $ev = $events[$i]
        if ([string]$ev.kind -ne $Kind) { continue }
        if ($Status -and [string]$ev.status -ne $Status) { continue }
        if ($Client -and [string]$ev.client -ne $Client) { continue }
        if ($Listen -and [string]$ev.listen -ne $Listen) { continue }
        return $true
    }
    return $false
}

function New-ChainRequest {
    param(
        [Parameter(Mandatory)][ValidateSet('tun', 'system-proxy')][string]$Mode,
        [ValidateSet('second', 'primary', 'xray')][string]$HopA = 'second',
        [ValidateSet('http', 'https', 'socks5', 'shadowsocks', 'reality')][string]$HopBProto = 'http',
        [string]$HopBServer = $b4,
        [int]$HopBPort = 3128,
        [string]$HopBUser = '',
        [string]$HopBPass = '',
        [bool]$HopBAllowInsecure = $false,
        [bool]$AllowLan = $false,
        [string]$Engine = 'sing_box',
        [string]$Xray = 'auto',
        [bool]$TlsFragment = $false,
        [bool]$OmitA = $false,
        [bool]$AddThirdHop = $false,
        [bool]$AddTempRule = $false,
        [bool]$AddTargetIpRule = $false,
        [string]$RealityPubKey = ''
    )
    $req = (ConvertTo-Json -InputObject $plan.request -Depth 30) | ConvertFrom-Json
    $req.node.server = $gateway
    $req.settings | Add-Member -NotePropertyName engine -NotePropertyValue $Engine -Force
    $req.settings | Add-Member -NotePropertyName kill_switch -NotePropertyValue $true -Force
    $req.settings | Add-Member -NotePropertyName auto_reconnect -NotePropertyValue $true -Force
    $req.settings | Add-Member -NotePropertyName allow_lan -NotePropertyValue $AllowLan -Force
    $req.settings | Add-Member -NotePropertyName private_networks -NotePropertyValue $false -Force
    $req.settings | Add-Member -NotePropertyName xray -NotePropertyValue $Xray -Force
    if ($Mode -eq 'system-proxy') {
        $req.settings | Add-Member -NotePropertyName connection_mode -NotePropertyValue 'system_proxy' -Force
        $req.settings | Add-Member -NotePropertyName local_proxy -NotePropertyValue ([pscustomobject]@{
            port = $proxyPort; share_on_lan = $false
        }) -Force
    } else {
        $req.settings | Add-Member -NotePropertyName connection_mode -NotePropertyValue 'tun' -Force
    }
    if ($TlsFragment) {
        $req.settings | Add-Member -NotePropertyName tls_fragment -NotePropertyValue ([pscustomobject]@{
            enabled = $true; packets = 'tlshello'; length = '50-100'; interval = '10-20'
        }) -Force
    }

    # Build Hop A node
    $nodeA = (ConvertTo-Json -InputObject $req.node -Depth 20) | ConvertFrom-Json
    if ($HopA -eq 'second') {
        $nodeA.id = 'hop-a-second'
        $nodeA.name = 'hop-a-second.test'
        $nodeA.port = [int]$th.second_node_port
    } elseif ($HopA -eq 'primary') {
        $nodeA.id = 'hop-a-primary'
        $nodeA.name = 'hop-a-primary.test'
        $nodeA.port = [int]$req.node.port
    } else {
        $nodeA.id = 'hop-a-xray'
        $nodeA.name = 'hop-a-xray.test'
        $nodeA.port = [int]$th.reality_port
        $nodeA.outbound = [pscustomobject]@{
            vless = [pscustomobject]@{ uuid = [string]$th.reality_uuid; flow = 'xtls-rprx-vision' }
        }
        $nodeA.stream = [pscustomobject]@{
            transport = 'tcp'
            tls = [pscustomobject]@{
                reality = [pscustomobject]@{
                    sni = [string]$th.reality_sni
                    public_key = $RealityPubKey
                    short_id = [string]$th.reality_short_id
                    fingerprint = 'chrome'
                }
            }
        }
    }

    # Build Hop B node
    if ($HopBProto -eq 'http' -or $HopBProto -eq 'https') {
        $bOutbound = [pscustomobject]@{ http = [pscustomobject]@{ username = $HopBUser; password = $HopBPass } }
        $bTls = if ($HopBProto -eq 'https') {
            [pscustomobject]@{ tls = [pscustomobject]@{ allow_insecure = $HopBAllowInsecure } }
        } else { 'plain' }
        $bStream = [pscustomobject]@{ transport = 'tcp'; tls = $bTls }
    } elseif ($HopBProto -eq 'socks5') {
        $bOutbound = [pscustomobject]@{ socks5 = [pscustomobject]@{ username = $HopBUser; password = $HopBPass } }
        $bStream = [pscustomobject]@{ transport = 'tcp'; tls = 'plain' }
    } elseif ($HopBProto -eq 'shadowsocks') {
        $bOutbound = $req.node.outbound
        $bStream = [pscustomobject]@{ transport = 'tcp'; tls = 'plain' }
    } else {
        $bOutbound = [pscustomobject]@{
            vless = [pscustomobject]@{ uuid = [string]$th.reality_uuid; flow = 'xtls-rprx-vision' }
        }
        $bStream = [pscustomobject]@{
            transport = 'tcp'
            tls = [pscustomobject]@{
                reality = [pscustomobject]@{
                    sni = [string]$th.reality_sni
                    public_key = $RealityPubKey
                    short_id = [string]$th.reality_short_id
                    fingerprint = 'chrome'
                }
            }
        }
    }
    $nodeB = [pscustomobject]@{
        id = 'hop-b'
        name = 'hop-b.test'
        server = $HopBServer
        port = $HopBPort
        outbound = $bOutbound
        stream = $bStream
    }

    $extras = [Collections.Generic.List[object]]::new()
    if (-not $OmitA) {
        $extras.Add([pscustomobject]@{
            exit = 'exit-a'
            selection = [pscustomobject]@{ subscription = 'lab'; node = $nodeA.id }
            node = $nodeA
        })
    }
    $extras.Add([pscustomobject]@{
        exit = 'exit-b'
        via = 'exit-a'
        selection = [pscustomobject]@{ subscription = 'lab'; node = 'hop-b' }
        node = $nodeB
    })
    if ($AddThirdHop) {
        $extras.Add([pscustomobject]@{
            exit = 'exit-c'
            via = 'exit-b'
            selection = [pscustomobject]@{ subscription = 'lab'; node = 'hop-c' }
            node = $nodeB
        })
    }
    $req | Add-Member -NotePropertyName extra_nodes -NotePropertyValue $extras.ToArray() -Force

    $rules = [Collections.Generic.List[object]]::new()
    $rules.Add([pscustomobject]@{
        id = 'unlisted-primary'
        enabled = $true
        matcher = [pscustomobject]@{ domain = [pscustomobject]@{ exact = $unlistedName } }
        target = 'proxy'
    })
    $rules.Add([pscustomobject]@{
        id = 'listed-twohop'
        enabled = $true
        matcher = [pscustomobject]@{ domain = [pscustomobject]@{ exact = $listedName } }
        target = 'exit'
        exit = 'exit-b'
    })
    if ($AddTargetIpRule) {
        $rules.Add([pscustomobject]@{
            id = 'target-ip-twohop'
            enabled = $true
            matcher = [pscustomobject]@{ ip_cidr = "$target4/32" }
            target = 'exit'
            exit = 'exit-b'
        })
    }
    $req.rule_set.rules = $rules.ToArray()
    if ($AddTempRule) {
        $req | Add-Member -NotePropertyName temporary_rules -NotePropertyValue @(
            [pscustomobject]@{
                id = 'temp-twohop'
                enabled = $true
                matcher = [pscustomobject]@{ domain = [pscustomobject]@{ exact = 'temp.lab.test' } }
                target = 'exit'
                exit = 'exit-b'
            }
        ) -Force
    }
    return $req
}

function Write-ThRequest {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)]$Request)
    $path = Join-Path $work $Name
    [IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject $Request -Depth 30), (New-Object Text.UTF8Encoding $false))
    return $path
}

function Invoke-ChainApply {
    param([Parameter(Mandatory)][string]$Path)
    $res = Invoke-ThCli -Arguments @('apply', $Path) -Seconds 60
    return ($res.ExitCode -eq 0 -and (Wait-ThState 'Connected'))
}

function Test-ChainPositive {
    param(
        [Parameter(Mandatory)][ValidateSet('tun', 'system-proxy')][string]$Mode,
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][string]$ExpectedClient,
        [Parameter(Mandatory)][string]$ExpectedListen,
        [string]$ExpectedTargetSource = $b4
    )
    $before = Get-FixtureState
    $bTarget0 = Get-HttpsCount -State $before -Source $ExpectedTargetSource
    $p0 = Get-HttpsCount -State $before -Source $primaryEgress
    $ev0 = @(Get-TwoHopEvents -State $before).Count
    $listedOk = Wait-ModeUrl -Mode $Mode -Url $listedUrl -TimeoutSeconds 25
    $unlistedOk = Wait-ModeUrl -Mode $Mode -Url $unlistedUrl -TimeoutSeconds 25
    $after = Get-FixtureState
    $targetHit = (Get-HttpsCount -State $after -Source $ExpectedTargetSource) -gt $bTarget0
    $indepHit = (Get-HttpsCount -State $after -Source $primaryEgress) -gt $p0
    $bSawA = Test-HasNewTwoHopEvent -AfterState $after -BeforeCount $ev0 -Kind $Kind -Client $ExpectedClient -Listen $ExpectedListen -Status 'ok'
    $noLeak = -not (Test-DirectEgress)
    return ($listedOk -and $unlistedOk -and $targetHit -and $indepHit -and $bSawA -and $noLeak)
}

function Test-UdpBlocked {
    param([Parameter(Mandatory)][string]$TargetIp, [Parameter(Mandatory)][int]$Port)
    $udp = [Net.Sockets.UdpClient]::new()
    try {
        $udp.Client.ReceiveTimeout = 1500
        $udp.Connect($TargetIp, $Port)
        $payload = [Text.Encoding]::ASCII.GetBytes('rosetun-twohop-udp-probe')
        [void]$udp.Send($payload, $payload.Length)
        $from = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
        [void]$udp.Receive([ref]$from)
        return $false
    }
    catch { return $true }
    finally { $udp.Dispose() }
}

function Invoke-TwoHopModeSuite {
    param(
        [Parameter(Mandatory)][ValidateSet('tun', 'system-proxy')][string]$Mode,
        [Parameter(Mandatory)][string]$WindowLabel,
        [Parameter(Mandatory)][string]$RealityPubKey
    )
    Set-RosetunRunnerStep -Step $WindowLabel
    $p = $th.ports
    $prefix = $Mode.Replace('-', '_')

    $reqHttp4 = Write-ThRequest "${prefix}-http4.json" (New-ChainRequest -Mode $Mode -HopBProto 'http' -HopBServer $b4 -HopBPort ([int]$p.http))
    $reqHttp6 = Write-ThRequest "${prefix}-http6.json" (New-ChainRequest -Mode $Mode -HopBProto 'http' -HopBServer $b6 -HopBPort ([int]$p.http))
    $reqHttps4 = Write-ThRequest "${prefix}-https4.json" (New-ChainRequest -Mode $Mode -HopBProto 'https' -HopBServer $b4 -HopBPort ([int]$p.https))
    $reqHttps6 = Write-ThRequest "${prefix}-https6.json" (New-ChainRequest -Mode $Mode -HopBProto 'https' -HopBServer $b6 -HopBPort ([int]$p.https))
    $reqSocks4 = Write-ThRequest "${prefix}-socks4.json" (New-ChainRequest -Mode $Mode -HopBProto 'socks5' -HopBServer $b4 -HopBPort ([int]$p.socks5))
    $reqSocks6 = Write-ThRequest "${prefix}-socks6.json" (New-ChainRequest -Mode $Mode -HopBProto 'socks5' -HopBServer $b6 -HopBPort ([int]$p.socks5))
    $reqDomainB = Write-ThRequest "${prefix}-domain-b.json" (New-ChainRequest -Mode $Mode -HopBProto 'http' -HopBServer $domainB -HopBPort ([int]$p.http))
    $reqHttpAuthBad = Write-ThRequest "${prefix}-http-auth-bad.json" (New-ChainRequest -Mode $Mode -HopBProto 'http' -HopBServer $b4 -HopBPort ([int]$p.'http-auth') -HopBUser ([string]$th.username) -HopBPass 'wrong-password')
    $reqSocksAuthBad = Write-ThRequest "${prefix}-socks-auth-bad.json" (New-ChainRequest -Mode $Mode -HopBProto 'socks5' -HopBServer $b4 -HopBPort ([int]$p.'socks5-auth') -HopBUser ([string]$th.username) -HopBPass 'wrong-password')
    $reqHttpAuthOk = Write-ThRequest "${prefix}-http-auth-ok.json" (New-ChainRequest -Mode $Mode -HopBProto 'http' -HopBServer $b4 -HopBPort ([int]$p.'http-auth') -HopBUser ([string]$th.username) -HopBPass ([string]$th.password))
    $reqHttpsUntrusted = Write-ThRequest "${prefix}-https-untrusted.json" (New-ChainRequest -Mode $Mode -HopBProto 'https' -HopBServer $b4 -HopBPort ([int]$p.'https-untrusted'))
    $reqHttpsInsecure = Write-ThRequest "${prefix}-https-insecure.json" (New-ChainRequest -Mode $Mode -HopBProto 'https' -HopBServer $b4 -HopBPort ([int]$p.'https-untrusted') -HopBAllowInsecure $true)
    $reqUdp = Write-ThRequest "${prefix}-udp.json" (New-ChainRequest -Mode $Mode -HopBProto 'http' -HopBServer $b4 -HopBPort ([int]$p.http) -AddTargetIpRule $true)
    $reqTempA1 = Write-ThRequest "${prefix}-temp-a1.json" (New-ChainRequest -Mode $Mode -HopA 'primary' -HopBProto 'http' -HopBServer $b4 -HopBPort ([int]$p.http) -AddTempRule $true)
    $reqTempA2 = Write-ThRequest "${prefix}-temp-a2.json" (New-ChainRequest -Mode $Mode -HopA 'second' -HopBProto 'http' -HopBServer $b4 -HopBPort ([int]$p.http) -AddTempRule $true)
    $reqOmitA = Write-ThRequest "${prefix}-omit-a.json" (New-ChainRequest -Mode $Mode -HopBProto 'http' -HopBServer $b4 -HopBPort ([int]$p.http) -OmitA $true)
    $reqLanOn = Write-ThRequest "${prefix}-lan-on.json" (New-ChainRequest -Mode $Mode -HopBProto 'http' -HopBServer $lanPeer -HopBPort ([int]$p.http) -AllowLan $true)
    $reqBadProtoB = Write-ThRequest "${prefix}-bad-proto-b.json" (New-ChainRequest -Mode $Mode -HopBProto 'shadowsocks' -HopBServer $b4 -HopBPort ([int]$p.http))
    $reqThreeHop = Write-ThRequest "${prefix}-three-hop.json" (New-ChainRequest -Mode $Mode -HopBProto 'http' -HopBServer $b4 -HopBPort ([int]$p.http) -AddThirdHop $true)
    $reqXrayEngine = Write-ThRequest "${prefix}-xray-engine.json" (New-ChainRequest -Mode $Mode -Engine 'xray' -HopBProto 'http' -HopBServer $b4 -HopBPort ([int]$p.http))
    $reqTlsFrag = Write-ThRequest "${prefix}-tls-frag.json" (New-ChainRequest -Mode $Mode -TlsFragment $true -HopBProto 'http' -HopBServer $b4 -HopBPort ([int]$p.http))
    $reqXrayB = Write-ThRequest "${prefix}-xray-b.json" (New-ChainRequest -Mode $Mode -HopBProto 'reality' -HopBServer $b4 -HopBPort ([int]$th.reality_port) -RealityPubKey $RealityPubKey)
    $reqXrayA = Write-ThRequest "${prefix}-xray-a.json" (New-ChainRequest -Mode $Mode -HopA 'xray' -HopBProto 'http' -HopBServer $b4 -HopBPort ([int]$p.http) -RealityPubKey $RealityPubKey)

    if (Send-RosetunMarker -Plan $plan -Label $WindowLabel -Word 'open') { $script:openWindow = $WindowLabel }

    # 1. positive.http.ipv4
    Test-Step -Id "two-hop.positive.http.ipv4:$Mode" -Scenario $WindowLabel -Expectation 'HTTP B IPv4: target=B, B=A' {
        $conn = Invoke-ThCli -Arguments @('connect', $reqHttp4) -Seconds 60
        ($conn.ExitCode -eq 0) -and (Wait-ThState 'Connected') -and
            (Test-ChainPositive -Mode $Mode -Kind 'http' -ExpectedClient $secondEgress4 -ExpectedListen $b4)
    }
    # 2. positive.http.ipv6
    Test-Step -Id "two-hop.positive.http.ipv6:$Mode" -Scenario $WindowLabel -Expectation 'HTTP B IPv6: target=B, B=A' {
        (Invoke-ChainApply $reqHttp6) -and
            (Test-ChainPositive -Mode $Mode -Kind 'http' -ExpectedClient $secondEgress6 -ExpectedListen $b6)
    }
    # 3. positive.https.ipv4
    Test-Step -Id "two-hop.positive.https.ipv4:$Mode" -Scenario $WindowLabel -Expectation 'HTTPS B IPv4: target=B, B=A' {
        (Invoke-ChainApply $reqHttps4) -and
            (Test-ChainPositive -Mode $Mode -Kind 'https' -ExpectedClient $secondEgress4 -ExpectedListen $b4)
    }
    # 4. positive.https.ipv6
    Test-Step -Id "two-hop.positive.https.ipv6:$Mode" -Scenario $WindowLabel -Expectation 'HTTPS B IPv6: target=B, B=A' {
        (Invoke-ChainApply $reqHttps6) -and
            (Test-ChainPositive -Mode $Mode -Kind 'https' -ExpectedClient $secondEgress6 -ExpectedListen $b6)
    }
    # 5. positive.socks5.ipv4
    Test-Step -Id "two-hop.positive.socks5.ipv4:$Mode" -Scenario $WindowLabel -Expectation 'SOCKS5 B IPv4: target=B, B=A' {
        (Invoke-ChainApply $reqSocks4) -and
            (Test-ChainPositive -Mode $Mode -Kind 'socks5' -ExpectedClient $secondEgress4 -ExpectedListen $b4)
    }
    # 6. positive.socks5.ipv6
    Test-Step -Id "two-hop.positive.socks5.ipv6:$Mode" -Scenario $WindowLabel -Expectation 'SOCKS5 B IPv6: target=B, B=A' {
        (Invoke-ChainApply $reqSocks6) -and
            (Test-ChainPositive -Mode $Mode -Kind 'socks5' -ExpectedClient $secondEgress6 -ExpectedListen $b6)
    }
    # 7. domain-b
    Test-Step -Id "two-hop.domain-b:$Mode" -Scenario $WindowLabel -Expectation 'Domain B rejected before engine/protection changes' {
        $bad = Invoke-ThCli -Arguments @('apply', $reqDomainB) -Seconds 30
        ($bad.ExitCode -ne 0) -and ((Get-ThState) -eq 'Connected') -and
            (Test-ChainPositive -Mode $Mode -Kind 'socks5' -ExpectedClient $secondEgress6 -ExpectedListen $b6)
    }
    # 8. a-unavailable
    Test-Step -Id "two-hop.a-unavailable:$Mode" -Scenario $WindowLabel -Expectation 'A unavailable fails rule without direct or primary bypass' {
        if (-not (Invoke-ChainApply $reqHttp4)) { return $false }
        $ok = $false
        try {
            [void](Set-LabService -Service 'second_node' -State 'stop')
            Start-Sleep -Seconds 1
            $before = Get-FixtureState
            $p0 = Get-HttpsCount -State $before -Source $primaryEgress
            $b0 = Get-HttpsCount -State $before -Source $b4
            $c0 = Get-HttpsCount -State $before -Source $physical
            $ev0 = @(Get-TwoHopEvents -State $before).Count
            $failed = -not (Test-ModeUrlOnce -Mode $Mode -Url $listedUrl -MaxTime 6)
            $mid = Get-FixtureState
            $noBypass = ((Get-HttpsCount -State $mid -Source $primaryEgress) -eq $p0) -and
                ((Get-HttpsCount -State $mid -Source $b4) -eq $b0) -and
                ((Get-HttpsCount -State $mid -Source $physical) -eq $c0) -and
                (@(Get-TwoHopEvents -State $mid).Count -eq $ev0)
            $indep = (Wait-ModeUrl -Mode $Mode -Url $unlistedUrl -TimeoutSeconds 20) -and (-not (Test-DirectEgress))
            $ok = $failed -and $noBypass -and $indep
        }
        finally { [void](Set-LabService -Service 'second_node' -State 'start') }
        $ok -and (Wait-ModeUrl -Mode $Mode -Url $listedUrl -TimeoutSeconds 25)
    }
    # 9. b-unavailable
    Test-Step -Id "two-hop.b-unavailable:$Mode" -Scenario $WindowLabel -Expectation 'B unavailable fails rule without A or direct bypass' {
        $ok = $false
        try {
            [void](Set-LabService -Service 'twohop_b' -State 'stop')
            Start-Sleep -Seconds 1
            $before = Get-FixtureState
            $p0 = Get-HttpsCount -State $before -Source $primaryEgress
            $s0 = Get-HttpsCount -State $before -Source $secondEgress4
            $b0 = Get-HttpsCount -State $before -Source $b4
            $c0 = Get-HttpsCount -State $before -Source $physical
            $failed = -not (Test-ModeUrlOnce -Mode $Mode -Url $listedUrl -MaxTime 6)
            $mid = Get-FixtureState
            $noBypass = ((Get-HttpsCount -State $mid -Source $primaryEgress) -eq $p0) -and
                ((Get-HttpsCount -State $mid -Source $secondEgress4) -eq $s0) -and
                ((Get-HttpsCount -State $mid -Source $b4) -eq $b0) -and
                ((Get-HttpsCount -State $mid -Source $physical) -eq $c0)
            $indep = (Wait-ModeUrl -Mode $Mode -Url $unlistedUrl -TimeoutSeconds 20) -and (-not (Test-DirectEgress))
            $ok = $failed -and $noBypass -and $indep
        }
        finally { [void](Set-LabService -Service 'twohop_b' -State 'start') }
        $ok -and (Wait-ModeUrl -Mode $Mode -Url $listedUrl -TimeoutSeconds 25)
    }
    # 10. b-auth
    Test-Step -Id "two-hop.b-auth:$Mode" -Scenario $WindowLabel -Expectation 'Wrong B credentials fail without bypass; valid creds succeed' {
        if (-not (Invoke-ChainApply $reqHttpAuthBad)) { return $false }
        $st0 = Get-FixtureState
        $ev0 = @(Get-TwoHopEvents -State $st0).Count
        $b0 = Get-HttpsCount -State $st0 -Source $b4
        $httpFail = (-not (Test-ModeUrlOnce -Mode $Mode -Url $listedUrl -MaxTime 6))
        $st1 = Get-FixtureState
        $httpAuthErr = (Test-HasNewTwoHopEvent -AfterState $st1 -BeforeCount $ev0 -Kind 'http-auth' -Status 'auth_failed') -and
            ((Get-HttpsCount -State $st1 -Source $b4) -eq $b0)
        if (-not ($httpFail -and $httpAuthErr)) { return $false }

        if (-not (Invoke-ChainApply $reqSocksAuthBad)) { return $false }
        $ev1 = @(Get-TwoHopEvents -State (Get-FixtureState)).Count
        $socksFail = (-not (Test-ModeUrlOnce -Mode $Mode -Url $listedUrl -MaxTime 6))
        $st2 = Get-FixtureState
        $socksAuthErr = (Test-HasNewTwoHopEvent -AfterState $st2 -BeforeCount $ev1 -Kind 'socks5-auth' -Status 'auth_failed') -and
            ((Get-HttpsCount -State $st2 -Source $b4) -eq $b0)
        if (-not ($socksFail -and $socksAuthErr)) { return $false }

        (Invoke-ChainApply $reqHttpAuthOk) -and
            (Test-ChainPositive -Mode $Mode -Kind 'http-auth' -ExpectedClient $secondEgress4 -ExpectedListen $b4)
    }
    # 11. https-certificate
    Test-Step -Id "two-hop.https-certificate:$Mode" -Scenario $WindowLabel -Expectation 'Untrusted HTTPS B fails without bypass; allow_insecure rejected' {
        $ins = Invoke-ThCli -Arguments @('apply', $reqHttpsInsecure) -Seconds 30
        if ($ins.ExitCode -eq 0) { return $false }
        if (-not (Invoke-ChainApply $reqHttpsUntrusted)) { return $false }
        $st0 = Get-FixtureState
        $ev0 = @(Get-TwoHopEvents -State $st0).Count
        $b0 = Get-HttpsCount -State $st0 -Source $b4
        $failed = -not (Test-ModeUrlOnce -Mode $Mode -Url $listedUrl -MaxTime 6)
        $st1 = Get-FixtureState
        $tlsErr = (Test-HasNewTwoHopEvent -AfterState $st1 -BeforeCount $ev0 -Kind 'https-untrusted' -Status 'tls_error') -and
            ((Get-HttpsCount -State $st1 -Source $b4) -eq $b0)
        $failed -and $tlsErr -and (Wait-ModeUrl -Mode $Mode -Url $unlistedUrl -TimeoutSeconds 20) -and (-not (Test-DirectEgress))
    }
    # 12. udp-quic
    Test-Step -Id "two-hop.udp-quic:$Mode" -Scenario $WindowLabel -Expectation 'UDP and QUIC selected for B are blocked without bypass' {
        if (-not (Invoke-ChainApply $reqUdp)) { return $false }
        $udpBlocked = (Test-UdpBlocked -TargetIp $target4 -Port 9000) -and (Test-UdpBlocked -TargetIp $target4 -Port 443)
        $udpBlocked -and (Test-ChainPositive -Mode $Mode -Kind 'http' -ExpectedClient $secondEgress4 -ExpectedListen $b4)
    }
    # 13. apply-rollback-reconnect
    Test-Step -Id "two-hop.apply-rollback-reconnect:$Mode" -Scenario $WindowLabel -Expectation 'Apply switches A, rejects bad candidate, restores A, reconnect preserves path and temp rules' {
        if (-not (Invoke-ChainApply $reqTempA1)) { return $false }
        if (-not (Test-ChainPositive -Mode $Mode -Kind 'http' -ExpectedClient $primaryEgress -ExpectedListen $b4)) { return $false }
        $bad = Invoke-ThCli -Arguments @('apply', $reqDomainB) -Seconds 30
        if ($bad.ExitCode -eq 0 -or (Get-ThState) -ne 'Connected') { return $false }
        if (-not (Test-ChainPositive -Mode $Mode -Kind 'http' -ExpectedClient $primaryEgress -ExpectedListen $b4)) { return $false }
        if (-not (Invoke-ChainApply $reqTempA2)) { return $false }
        if (-not (Test-ChainPositive -Mode $Mode -Kind 'http' -ExpectedClient $secondEgress4 -ExpectedListen $b4)) { return $false }
        $rec = Invoke-ThCli -Arguments @('reconnect') -Seconds 60
        if ($rec.ExitCode -ne 0 -or -not (Wait-ThState 'Connected')) { return $false }
        $tmpOut = Invoke-ThCli -Arguments @('temporary') -Seconds 20
        $tmpKept = ($tmpOut.ExitCode -eq 0 -and $tmpOut.Output -match 'temp\.lab\.test')
        $tmpKept -and (Test-ChainPositive -Mode $Mode -Kind 'http' -ExpectedClient $secondEgress4 -ExpectedListen $b4)
    }
    # 14. engine-restart
    Test-Step -Id "two-hop.engine-restart:$Mode" -Scenario $WindowLabel -Expectation 'Killing engine keeps protection and restores A then B' {
        $oldPids = @(Get-SingBoxPids)
        if ($oldPids.Count -eq 0) { return $false }
        foreach ($spid in $oldPids) { Stop-Process -Id $spid -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Milliseconds 500
        $protected = -not (Test-DirectEgress)
        $restored = Wait-ThCondition -TimeoutSeconds 25 -Condition {
            $cur = @(Get-SingBoxPids)
            ($cur.Count -gt 0) -and ($cur[0] -notin $oldPids) -and ((Get-ThState) -eq 'Connected')
        }
        if (-not $restored) {
            [void](Invoke-ThCli -Arguments @('reconnect') -Seconds 60)
            $restored = (Wait-ThState 'Connected')
        }
        $protected -and $restored -and (Test-ChainPositive -Mode $Mode -Kind 'http' -ExpectedClient $secondEgress4 -ExpectedListen $b4)
    }
    # 15. dependency-removed
    Test-Step -Id "two-hop.dependency-removed:$Mode" -Scenario $WindowLabel -Expectation 'Removing A while B has via is rejected without clearing B via' {
        $bad = Invoke-ThCli -Arguments @('apply', $reqOmitA) -Seconds 30
        ($bad.ExitCode -ne 0) -and ((Get-ThState) -eq 'Connected') -and
            (Test-ChainPositive -Mode $Mode -Kind 'http' -ExpectedClient $secondEgress4 -ExpectedListen $b4)
    }
    # 16. lockdown
    Test-Step -Id "two-hop.lockdown:$Mode" -Scenario $WindowLabel -Expectation 'Lockdown on/off preserves A then B and fails closed without bypass' {
        $on = Invoke-ThCli -Arguments @('lockdown', 'on') -Seconds 30
        if ($on.ExitCode -ne 0 -or (Get-ThLockdown) -ne 'on') { return $false }
        $onOk = Test-ChainPositive -Mode $Mode -Kind 'http' -ExpectedClient $secondEgress4 -ExpectedListen $b4
        $failOk = $false
        try {
            [void](Set-LabService -Service 'twohop_b' -State 'stop')
            Start-Sleep -Seconds 1
            $b0 = Get-HttpsCount -State (Get-FixtureState) -Source $b4
            $failOk = (-not (Test-ModeUrlOnce -Mode $Mode -Url $listedUrl -MaxTime 6)) -and
                ((Get-HttpsCount -State (Get-FixtureState) -Source $b4) -eq $b0) -and
                (-not (Test-DirectEgress))
        }
        finally { [void](Set-LabService -Service 'twohop_b' -State 'start') }
        $off = Invoke-ThCli -Arguments @('lockdown', 'off') -Seconds 30
        $offOk = ($off.ExitCode -eq 0 -and (Get-ThLockdown) -eq 'off') -and
            (Test-ChainPositive -Mode $Mode -Kind 'http' -ExpectedClient $secondEgress4 -ExpectedListen $b4)
        $onOk -and $failOk -and $offOk
    }
    # 17. allow-lan
    Test-Step -Id "two-hop.allow-lan:$Mode" -Scenario $WindowLabel -Expectation 'allow_lan on/off never authorizes B (including LAN-address B) for direct client egress' {
        # Hold Lockdown across reconnects so no unprotected gap exists inside the judged window.
        $lkOn = Invoke-ThCli -Arguments @('lockdown', 'on') -Seconds 30
        if ($lkOn.ExitCode -ne 0) { return $false }
        try {
            [void](Disconnect-ThSession)
            $cLan = Invoke-ThCli -Arguments @('connect', $reqLanOn) -Seconds 60
            if ($cLan.ExitCode -ne 0 -or -not (Wait-ThState 'Connected')) { return $false }
            [void](Invoke-ThCli -Arguments @('lockdown', 'off') -Seconds 30)
            $directBlocked = (Test-DirectTcpBlocked -Address $lanPeer -Port ([int]$p.http)) -and
                (Test-DirectTcpBlocked -Address $b4 -Port ([int]$p.http))
            $viaChain = Test-ChainPositive -Mode $Mode -Kind 'lan_http' -ExpectedClient $secondEgress4 `
                -ExpectedListen $lanPeer -ExpectedTargetSource $lanPeer
            [void](Invoke-ThCli -Arguments @('lockdown', 'on') -Seconds 30)
            [void](Disconnect-ThSession)
            $cOff = Invoke-ThCli -Arguments @('connect', $reqHttp4) -Seconds 60
            if ($cOff.ExitCode -ne 0 -or -not (Wait-ThState 'Connected')) { return $false }
        }
        finally {
            [void](Invoke-ThCli -Arguments @('lockdown', 'off') -Seconds 30)
        }
        $directBlocked -and $viaChain -and
            (Test-ChainPositive -Mode $Mode -Kind 'http' -ExpectedClient $secondEgress4 -ExpectedListen $b4)
    }
    # 18. target-subscription-fallback
    Test-Step -Id "two-hop.target-subscription-fallback:$Mode" -Scenario $WindowLabel -Expectation 'Changing B target works; unsupported actual endpoints rejected before replacing session' {
        if (-not (Invoke-ChainApply $reqSocks4)) { return $false }
        if (-not (Test-ChainPositive -Mode $Mode -Kind 'socks5' -ExpectedClient $secondEgress4 -ExpectedListen $b4)) { return $false }
        $r1 = Invoke-ThCli -Arguments @('apply', $reqBadProtoB) -Seconds 30
        $r2 = Invoke-ThCli -Arguments @('apply', $reqDomainB) -Seconds 30
        $r3 = Invoke-ThCli -Arguments @('apply', $reqThreeHop) -Seconds 30
        ($r1.ExitCode -ne 0) -and ($r2.ExitCode -ne 0) -and ($r3.ExitCode -ne 0) -and
            ((Get-ThState) -eq 'Connected') -and
            (Test-ChainPositive -Mode $Mode -Kind 'socks5' -ExpectedClient $secondEgress4 -ExpectedListen $b4)
    }
    # 19. xray-fragment
    Test-Step -Id "two-hop.xray-fragment:$Mode" -Scenario $WindowLabel -Expectation 'Xray-only engine, TLS fragment and B via Xray are rejected before replacing session' {
        $r1 = Invoke-ThCli -Arguments @('apply', $reqXrayEngine) -Seconds 30
        $r2 = Invoke-ThCli -Arguments @('apply', $reqTlsFrag) -Seconds 30
        $r3 = Invoke-ThCli -Arguments @('apply', $reqXrayB) -Seconds 30
        ($r1.ExitCode -ne 0) -and ($r2.ExitCode -ne 0) -and ($r3.ExitCode -ne 0) -and
            ((Get-ThState) -eq 'Connected') -and
            (Test-ChainPositive -Mode $Mode -Kind 'socks5' -ExpectedClient $secondEgress4 -ExpectedListen $b4)
    }
    # 20. positive.xray-first-hop
    Test-Step -Id "two-hop.positive.xray-first-hop:$Mode" -Scenario $WindowLabel -Expectation 'HTTP B IPv4 with A via Xray REALITY works and stopping A fails rule without direct leak' {
        if (-not (Invoke-ChainApply $reqXrayA)) { return $false }
        if (@(Get-XrayPids).Count -eq 0) { return $false }
        $posOk = Test-ChainPositive -Mode $Mode -Kind 'http' -ExpectedClient $primaryEgress -ExpectedListen $b4
        if (-not $posOk) { return $false }
        $stopOk = $false
        try {
            [void](Set-LabService -Service 'xray' -State 'stop')
            Start-Sleep -Seconds 1
            $st0 = Get-FixtureState
            $b0 = Get-HttpsCount -State $st0 -Source $b4
            $c0 = Get-HttpsCount -State $st0 -Source $physical
            $ev0 = @(Get-TwoHopEvents -State $st0).Count
            $failed = -not (Test-ModeUrlOnce -Mode $Mode -Url $listedUrl -MaxTime 6)
            $st1 = Get-FixtureState
            $noBypass = ((Get-HttpsCount -State $st1 -Source $b4) -eq $b0) -and
                ((Get-HttpsCount -State $st1 -Source $physical) -eq $c0) -and
                (@(Get-TwoHopEvents -State $st1).Count -eq $ev0)
            $indep = (Wait-ModeUrl -Mode $Mode -Url $unlistedUrl -TimeoutSeconds 20) -and (-not (Test-DirectEgress))
            $stopOk = $failed -and $noBypass -and $indep
        }
        finally { [void](Set-LabService -Service 'xray' -State 'start') }
        $stopOk -and (Wait-ModeUrl -Mode $Mode -Url $listedUrl -TimeoutSeconds 25)
    }

    # Hold persistent Lockdown across TUN removal so Windows NCSI probes cannot fire before the close marker.
    [void](Invoke-ThCli -Arguments @('lockdown', 'on') -Seconds 30)
    [void](Disconnect-ThSession)
    Start-Sleep -Milliseconds 500
    [void](Invoke-ThCli -Arguments @('lockdown', 'off') -Seconds 30)
    [void](Send-RosetunMarker -Plan $plan -Label $WindowLabel -Word 'close')
    $script:openWindow = $null
}

$recorder = $null
$runError = $false
$helperStarted = $false
$script:openWindow = $null
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

    $clock = [Diagnostics.Stopwatch]::StartNew()
    $sbVer = Invoke-RosetunNative -FilePath $singBoxPath -Arguments @('version') -TimeoutSeconds 300
    Add-RosetunRunnerNote -Name 'sing-box-first-launch-seconds' -Value ([int]$clock.Elapsed.TotalSeconds)
    if ($sbVer.ExitCode -ne 0) { throw 'sing-box does not start' }

    $clock.Restart()
    $xrVer = Invoke-RosetunNative -FilePath $xrayPath -Arguments @('version') -TimeoutSeconds 300
    Add-RosetunRunnerNote -Name 'xray-first-launch-seconds' -Value ([int]$clock.Elapsed.TotalSeconds)
    if ($xrVer.ExitCode -ne 0) { throw 'xray does not start' }

    Set-RosetunRunnerStep -Step 'recorder'
    Import-Module (Join-Path $Root 'RosetunListResults.psm1') -Force
    $vmId = ([string](Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID).ToLowerInvariant()
    $recorder = New-RosetunListResults -Directory $resultsDir -VmId $vmId -BootId (Get-RosetunBootCounter) `
        -Suite 'windows-twohop' -Catalog @($plan.catalog)
    Set-RosetunRecorder -Recorder $recorder

    Set-RosetunRunnerStep -Step 'fixture-state'
    $initialState = Get-FixtureState
    $realityPubKey = [string]$initialState.reality_public_key
    if (-not $realityPubKey) { throw 'missing-reality-public-key' }

    Set-RosetunRunnerStep -Step 'helper'
    $command = "set ROSETUN_LOG=debug&& `"$helperPath`" > `"$helperLogPath`" 2>&1"
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c $command" -WorkingDirectory $bin
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName
    $helperStarted = $true
    if (-not (Wait-HelperReady)) { throw 'the helper did not answer status' }

    # Window 0: baseline (listed)
    Set-RosetunRunnerStep -Step 'baseline'
    if (Send-RosetunMarker -Plan $plan -Label 'baseline' -Word 'open') { $script:openWindow = 'baseline' }
    [void](Test-DirectEgress)
    [void](Test-DirectDns -Name $baselineDns)
    Start-Sleep -Seconds 2
    [void](Send-RosetunMarker -Plan $plan -Label 'baseline' -Word 'close')
    $script:openWindow = $null

    # Window 1: twohop-tun (20 scenarios)
    Invoke-TwoHopModeSuite -Mode 'tun' -WindowLabel 'twohop-tun' -RealityPubKey $realityPubKey
    # Let Windows NCSI's ~4s post-TUN-removal probe burst complete outside judged windows.
    Start-Sleep -Seconds 8

    # Window 2: twohop-proxy (20 scenarios)
    Invoke-TwoHopModeSuite -Mode 'system-proxy' -WindowLabel 'twohop-proxy' -RealityPubKey $realityPubKey
}
catch {
    $runError = $true
    Set-RosetunRunnerError -Place $script:RunnerStatus.step -Text ($_.Exception.GetType().Name + ': ' + $_.Exception.Message)
}
finally {
    Set-RosetunRunnerState -State cleaning -Step 'cleanup'

    $cliDisconnected = $false
    if ($helperStarted -and (Test-Path -LiteralPath $cliPath)) {
        try {
            [void](Invoke-ThCli -Arguments @('lockdown', 'off') -Seconds 20)
            $cliDisconnected = Disconnect-ThSession -TimeoutSeconds 25
            [void](Invoke-ThCli -Arguments @('shutdown') -Seconds 15)
        }
        catch { Set-RosetunRunnerError -Place 'cleanup' -Text 'disconnect-failed' }
    }
    if ($null -ne $script:openWindow) {
        [void](Send-RosetunMarker -Plan $plan -Label $script:openWindow -Word 'close')
        $script:openWindow = $null
    }

    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Get-Process -Name 'rosetun-helper-privileged', 'sing-box', 'xray' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    if (Test-Path -LiteralPath $helperPath) {
        [void](Invoke-RosetunNative -FilePath $helperPath -Arguments @('--reset-firewall') -TimeoutSeconds 20)
    }

    Remove-Item -LiteralPath $work, $bin -Recurse -Force -ErrorAction SilentlyContinue

    $parts['connection'] = if ($cliDisconnected -and @(Get-SingBoxPids).Count -eq 0 -and @(Get-XrayPids).Count -eq 0 -and -not (Test-TunAdapter)) { 'PASS' } else { 'ERROR' }
    $parts['helper'] = if ($null -eq (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) -and -not (Get-Process -Name 'rosetun-helper-privileged' -ErrorAction SilentlyContinue)) { 'PASS' } else { 'ERROR' }
    $parts['files'] = if (-not (Test-Path -LiteralPath $work) -and -not (Test-Path -LiteralPath $bin)) { 'PASS' } else { 'ERROR' }

    # Window 3: recovery (listed)
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
