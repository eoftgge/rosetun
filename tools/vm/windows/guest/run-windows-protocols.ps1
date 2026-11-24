# The Windows Protocols and Extensions matrix as an autonomous runner of the QEMU lab (stage 10f).
# Windows PowerShell 5.1, as SYSTEM.
#
# Runs all 17 checks of protocols-checks.tsv against the isolated lab wire, covering:
# baseline, hysteria2, tuic (with outage/recovery), anytls, xray-reality (off/auto/child-killed/apply/helper-killed),
# xray-xhttp (off/auto/apply), second-node (rule-exit/outage/apply-node), dhcp (renew under kill switch), and recovery.

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
$work = Join-Path $Root 'protocols-matrix'
$resultsDir = Join-Path $Root 'results'
$helperLogPath = Join-Path $logs 'helper.log'
$cliPath = Join-Path $bin 'rosetun.exe'
$helperPath = Join-Path $bin 'rosetun-helper-privileged.exe'
$singBoxPath = Join-Path $bin 'sing-box.exe'
$xrayPath = Join-Path $bin 'xray.exe'
$curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'
$netshPath = Join-Path $env:SystemRoot 'System32\netsh.exe'
$ipconfigPath = Join-Path $env:SystemRoot 'System32\ipconfig.exe'
$taskName = 'RosetunHelper'

$physical = [string]$plan.addresses.client4
$gateway = [string]$plan.addresses.gateway4
$target4 = [string]$plan.addresses.target4
$resolver = [string]$plan.addresses.resolver
$primaryEgress = [string]$plan.protocols.primary_egress
$secondEgress = [string]$plan.protocols.second_node_egress
$targetUrl = 'https://' + $target4 + '/'
$listedUrl = 'https://' + [string]$plan.names.listed + '/'
$unlistedUrl = 'https://' + [string]$plan.names.unlisted + '/'
$baselineDns = [string]$plan.baseline.dns_name
$recoveryDns = 'after.' + $baselineDns
$tunAlias = [string]$plan.tun.alias

function Invoke-ProtoCli {
    param([Parameter(Mandatory)][string[]]$Arguments, [int]$Seconds = 90)
    Invoke-RosetunNative -FilePath $cliPath -Arguments $Arguments -TimeoutSeconds $Seconds
}

function Get-ProtoState {
    $result = Invoke-ProtoCli -Arguments @('status') -Seconds 20
    if ($result.Output -match '(?m)^state: (\w+)') { return $Matches[1] }
    return "unknown (exit $($result.ExitCode))"
}

function Wait-ProtoCondition {
    param([Parameter(Mandatory)][scriptblock]$Condition, [int]$TimeoutSeconds = 30)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (& $Condition) { return $true }
        Start-Sleep -Milliseconds 300
    } while ([DateTime]::UtcNow -lt $deadline)
    return $false
}

function Wait-ProtoState {
    param([Parameter(Mandatory)][string]$Expected, [int]$TimeoutSeconds = 35)
    return (Wait-ProtoCondition -TimeoutSeconds $TimeoutSeconds -Condition { (Get-ProtoState) -eq $Expected })
}

function Wait-HelperReady {
    param([int]$TimeoutSeconds = 90)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ($clock.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        if ((Invoke-ProtoCli -Arguments @('status') -Seconds 15).ExitCode -eq 0) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Start-ProtoHelper {
    if (Get-Process -Name 'rosetun-helper-privileged' -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Get-Process -Name 'rosetun-helper-privileged', 'sing-box', 'xray' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 300
    }
    $command = "set ROSETUN_LOG=debug&& `"$helperPath`" >> `"$helperLogPath`" 2>&1"
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c $command" -WorkingDirectory $bin
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName
    if (-not (Wait-HelperReady)) { throw 'the helper did not answer status' }
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

function Test-XrayRunning {
    return (@(Get-XrayPids).Count -gt 0)
}

function Disconnect-ProtoSession {
    param([int]$TimeoutSeconds = 35)
    [void](Invoke-ProtoCli -Arguments @('disconnect') -Seconds 30)
    return (Wait-ProtoCondition -TimeoutSeconds $TimeoutSeconds -Condition {
        (Get-ProtoState) -eq 'Disconnected' -and -not (Test-TunAdapter) -and -not (Test-XrayRunning)
    })
}

function Connect-ProtoVariant {
    param([Parameter(Mandatory)][string]$RequestName, [switch]$AlreadyDisconnected)
    if (-not $AlreadyDisconnected -and ((Get-ProtoState) -ne 'Disconnected' -or (Test-TunAdapter))) {
        [void](Disconnect-ProtoSession)
    }
    $res = Invoke-ProtoCli -Arguments @('connect', (Join-Path $work $RequestName)) -Seconds 60
    return ($res.ExitCode -eq 0 -and (Wait-ProtoState 'Connected'))
}

function Close-ProtoWindow {
    param([Parameter(Mandatory)][string]$Label, [switch]$LockdownAlreadyOn)
    # Hold persistent Lockdown across TUN removal so Windows NCSI probes cannot fire before the close marker.
    if (-not $LockdownAlreadyOn) {
        [void](Invoke-ProtoCli -Arguments @('lockdown', 'on') -Seconds 30)
    }
    [void](Disconnect-ProtoSession)
    Start-Sleep -Milliseconds 500
    [void](Invoke-ProtoCli -Arguments @('lockdown', 'off') -Seconds 30)
    [void](Send-RosetunMarker -Plan $plan -Label $Label -Word 'close')
    $script:openWindow = $null
    # Let any Windows background burst triggered by opening the firewall finish outside judged windows.
    Start-Sleep -Seconds 3
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

function Test-TunnelUrlOnce {
    param([string]$Url = $unlistedUrl, [int]$MaxTime = 10)
    $tunAddresses = @(Get-NetIPAddress -InterfaceAlias $tunAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        ForEach-Object { $_.IPAddress })
    if ($tunAddresses.Count -eq 0) { return $false }
    $result = Invoke-RosetunNative -FilePath $curlPath -TimeoutSeconds ($MaxTime + 10) -Arguments @(
        '--max-time', ([string]$MaxTime), '--silent', '--insecure', '--ssl-no-revoke',
        '--write-out', "`nlocal=%{local_ip} remote=%{remote_ip} code=%{http_code}", $Url)
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

function Wait-TunnelUrl {
    param([string]$Url = $unlistedUrl, [int]$TimeoutSeconds = 30)
    return (Wait-ProtoCondition -TimeoutSeconds $TimeoutSeconds -Condition { Test-TunnelUrlOnce -Url $Url })
}

function Get-FixtureState {
    return (Invoke-RosetunLabAction -Root $Root -Operation 'fixture_state' -Parameters @{})
}

function Set-LabService {
    param(
        [Parameter(Mandatory)][ValidateSet('primary_node', 'second_node', 'xray')][string]$Service,
        [Parameter(Mandatory)][ValidateSet('start', 'stop')][string]$State
    )
    $reply = Invoke-RosetunLabAction -Root $Root -Operation 'fixture_control' -Parameters @{
        service = $Service
        state = $State
    }
    if (-not $reply.ok) { throw "fixture_control failed for $Service=$State ($($reply.reason))" }
    return $reply
}

function Get-HttpsSourceCount {
    param($State, [Parameter(Mandatory)][string]$Source)
    if ($null -eq $State -or $null -eq $State.https -or $null -eq $State.https.by_source) { return 0 }
    $prop = $State.https.by_source.PSObject.Properties[$Source]
    if ($null -eq $prop) { return 0 }
    return [int]$prop.Value
}

function Restore-StaticIpv4 {
    param([Parameter(Mandatory)][string]$Alias)
    [void](Invoke-RosetunNative -FilePath $netshPath -TimeoutSeconds 20 -Arguments @(
        'interface', 'ipv4', 'set', 'address', "name=$Alias", 'source=static',
        "addr=$physical", 'mask=255.255.255.0', "gateway=$gateway"))
    [void](Invoke-RosetunNative -FilePath $netshPath -TimeoutSeconds 20 -Arguments @(
        'interface', 'ipv4', 'set', 'dnsservers', "name=$Alias", 'source=static',
        "addr=$resolver", 'register=none'))
    [void](Wait-ProtoCondition -TimeoutSeconds 20 -Condition {
        $addr = Get-NetIPAddress -InterfaceAlias $Alias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -eq $physical } | Select-Object -First 1
        ($null -ne $addr -and [string]$addr.PrefixOrigin -eq 'Manual')
    })
}

function Write-JsonFile {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)]$Object)
    [IO.File]::WriteAllText((Join-Path $work $Name), (ConvertTo-Json -InputObject $Object -Depth 30), (New-Object Text.UTF8Encoding $false))
}

function New-BaseRequest {
    param([string]$Xray = 'auto')
    $req = (ConvertTo-Json -InputObject $plan.request -Depth 30) | ConvertFrom-Json
    $req.settings | Add-Member -NotePropertyName kill_switch -NotePropertyValue $true -Force
    $req.settings | Add-Member -NotePropertyName auto_reconnect -NotePropertyValue $true -Force
    $req.settings | Add-Member -NotePropertyName allow_lan -NotePropertyValue $false -Force
    $req.settings | Add-Member -NotePropertyName private_networks -NotePropertyValue $false -Force
    $req.settings | Add-Member -NotePropertyName xray -NotePropertyValue $Xray -Force
    $req.node.server = $gateway
    return $req
}

function Write-ProtocolRequests {
    param([Parameter(Mandatory)][string]$RealityPubKey)
    $p = $plan.protocols

    # Shadowsocks primary node (baseline for apply transitions and DHCP)
    $ss = New-BaseRequest -Xray 'auto'
    Write-JsonFile -Name 'ss.json' -Object $ss

    # Hysteria2 UDP
    $hy2 = New-BaseRequest -Xray 'off'
    $hy2.node.id = 'lab-hysteria2'
    $hy2.node.name = 'lab-hysteria2.test'
    $hy2.node.port = [int]$p.hysteria2_port
    $hy2.node.outbound = [pscustomobject]@{ hysteria2 = [pscustomobject]@{ password = [string]$p.password } }
    $hy2.node.stream = [pscustomobject]@{
        transport = 'tcp'
        tls = [pscustomobject]@{ tls = [pscustomobject]@{ sni = [string]$p.sni; allow_insecure = $false } }
    }
    Write-JsonFile -Name 'hysteria2.json' -Object $hy2

    # TUIC v5 UDP
    $tuic = New-BaseRequest -Xray 'off'
    $tuic.node.id = 'lab-tuic'
    $tuic.node.name = 'lab-tuic.test'
    $tuic.node.port = [int]$p.tuic_port
    $tuic.node.outbound = [pscustomobject]@{
        tuic = [pscustomobject]@{
            uuid = [string]$p.tuic_uuid
            password = [string]$p.password
            congestion_control = 'bbr'
            udp_relay_mode = 'native'
        }
    }
    $tuic.node.stream = [pscustomobject]@{
        transport = 'tcp'
        tls = [pscustomobject]@{ tls = [pscustomobject]@{ sni = [string]$p.sni; alpn = @('h3'); allow_insecure = $false } }
    }
    Write-JsonFile -Name 'tuic.json' -Object $tuic

    # AnyTLS TCP
    $anytls = New-BaseRequest -Xray 'off'
    $anytls.node.id = 'lab-anytls'
    $anytls.node.name = 'lab-anytls.test'
    $anytls.node.port = [int]$p.anytls_port
    $anytls.node.outbound = [pscustomobject]@{ anytls = [pscustomobject]@{ password = [string]$p.password } }
    $anytls.node.stream = [pscustomobject]@{
        transport = 'tcp'
        tls = [pscustomobject]@{ tls = [pscustomobject]@{ sni = [string]$p.sni; allow_insecure = $false } }
    }
    Write-JsonFile -Name 'anytls.json' -Object $anytls

    # VLESS REALITY + Vision (xray off / auto)
    foreach ($mode in @('off', 'auto')) {
        $vr = New-BaseRequest -Xray $mode
        $vr.node.id = "lab-reality-$mode"
        $vr.node.name = 'lab-reality.test'
        $vr.node.port = [int]$p.reality_port
        $vr.node.outbound = [pscustomobject]@{
            vless = [pscustomobject]@{ uuid = [string]$p.reality_uuid; flow = 'xtls-rprx-vision' }
        }
        $vr.node.stream = [pscustomobject]@{
            transport = 'tcp'
            tls = [pscustomobject]@{
                reality = [pscustomobject]@{
                    sni = [string]$p.reality_sni
                    public_key = $RealityPubKey
                    short_id = [string]$p.reality_short_id
                    fingerprint = 'chrome'
                }
            }
        }
        Write-JsonFile -Name "reality-$mode.json" -Object $vr
    }

    # VLESS XHTTP + REALITY (xray off / auto)
    foreach ($mode in @('off', 'auto')) {
        $vx = New-BaseRequest -Xray $mode
        $vx.node.id = "lab-xhttp-$mode"
        $vx.node.name = 'lab-xhttp.test'
        $vx.node.port = [int]$p.xhttp_port
        $vx.node.outbound = [pscustomobject]@{
            vless = [pscustomobject]@{ uuid = [string]$p.reality_uuid }
        }
        $vx.node.stream = [pscustomobject]@{
            transport = [pscustomobject]@{ xhttp = [pscustomobject]@{ path = [string]$p.xhttp_path; mode = 'auto' } }
            tls = [pscustomobject]@{
                reality = [pscustomobject]@{
                    sni = [string]$p.reality_sni
                    public_key = $RealityPubKey
                    short_id = [string]$p.reality_short_id
                    fingerprint = 'chrome'
                }
            }
        }
        Write-JsonFile -Name "xhttp-$mode.json" -Object $vx
    }

    # Second node rule-exit (listed.lab.test -> exit-second; unlisted.lab.test -> proxy)
    $sec = New-BaseRequest -Xray 'auto'
    $secondNode = (ConvertTo-Json -InputObject $sec.node -Depth 20) | ConvertFrom-Json
    $secondNode.id = 'second-node'
    $secondNode.name = 'second-node.test'
    $secondNode.port = [int]$p.second_node_port
    $sec | Add-Member -NotePropertyName extra_nodes -NotePropertyValue @(
        [pscustomobject]@{
            exit = 'exit-second'
            selection = [pscustomobject]@{ subscription = 'lab'; node = 'second-node' }
            node = $secondNode
        }
    ) -Force
    $sec.rule_set.rules = @(
        [pscustomobject]@{
            id = 'listed-via-second'
            enabled = $true
            matcher = [pscustomobject]@{ domain = [pscustomobject]@{ exact = [string]$plan.names.listed } }
            target = 'exit'
            exit = 'exit-second'
        }
    )
    Write-JsonFile -Name 'second-node.json' -Object $sec

    # Primary node rule for listed.lab.test (used by second-node.apply-node)
    $secPrimary = New-BaseRequest -Xray 'auto'
    $secPrimary.rule_set.rules = @(
        [pscustomobject]@{
            id = 'listed-via-primary'
            enabled = $true
            matcher = [pscustomobject]@{ domain = [pscustomobject]@{ exact = [string]$plan.names.listed } }
            target = 'proxy'
        }
    )
    Write-JsonFile -Name 'listed-primary.json' -Object $secPrimary
}

$recorder = $null
$runError = $false
$helperStarted = $false
$script:openWindow = $null
$physicalAlias = ''
$dhcpSwitched = $false
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
        -Suite 'windows-protocols' -Catalog @($plan.catalog)
    Set-RosetunRecorder -Recorder $recorder

    Set-RosetunRunnerStep -Step 'fixture-state'
    $initialState = Get-FixtureState
    $realityPubKey = [string]$initialState.reality_public_key
    if (-not $realityPubKey) { throw 'missing-reality-public-key' }

    Set-RosetunRunnerStep -Step 'helper'
    Start-ProtoHelper
    $helperStarted = $true
    Write-ProtocolRequests -RealityPubKey $realityPubKey

    # Window 0: baseline (listed)
    Set-RosetunRunnerStep -Step 'baseline'
    if (Send-RosetunMarker -Plan $plan -Label 'baseline' -Word 'open') { $script:openWindow = 'baseline' }
    Test-Step -Id 'baseline.egress' -Scenario 'baseline' -Expectation 'direct HTTPS succeeds before connect' { Test-DirectEgress }
    Test-Step -Id 'baseline.dns' -Scenario 'baseline' -Expectation 'direct UDP DNS succeeds before connect' { Test-DirectDns -Name $baselineDns }
    Start-Sleep -Seconds 2
    [void](Send-RosetunMarker -Plan $plan -Label 'baseline' -Word 'close')
    $script:openWindow = $null

    # Window 1: hysteria2 (judged)
    Set-RosetunRunnerStep -Step 'hysteria2'
    if (Send-RosetunMarker -Plan $plan -Label 'hysteria2' -Word 'open') { $script:openWindow = 'hysteria2' }
    Test-Step -Id 'proto.hysteria2' -Scenario 'hysteria2' -Expectation 'Hysteria2 connects, carries HTTPS and blocks direct' {
        $ok = (Connect-ProtoVariant 'hysteria2.json' -AlreadyDisconnected) -and (Wait-TunnelUrl) -and (-not (Test-DirectEgress))
        $ok
    }
    Close-ProtoWindow -Label 'hysteria2'

    # Window 2: tuic (judged)
    Set-RosetunRunnerStep -Step 'tuic'
    if (Send-RosetunMarker -Plan $plan -Label 'tuic' -Word 'open') { $script:openWindow = 'tuic' }
    Test-Step -Id 'proto.tuic' -Scenario 'tuic' -Expectation 'TUIC connects, fails closed on outage and recovers' {
        $connOk = (Connect-ProtoVariant 'tuic.json' -AlreadyDisconnected) -and (Wait-TunnelUrl) -and (-not (Test-DirectEgress))
        if (-not $connOk) { return $false }
        try {
            [void](Set-LabService -Service 'primary_node' -State 'stop')
            Start-Sleep -Seconds 1
            $failClosed = (-not (Test-TunnelUrlOnce -MaxTime 5)) -and (-not (Test-DirectEgress))
        }
        finally {
            [void](Set-LabService -Service 'primary_node' -State 'start')
        }
        if (-not $failClosed) { return $false }
        $recovered = Wait-TunnelUrl -TimeoutSeconds 20
        if (-not $recovered) {
            [void](Invoke-ProtoCli -Arguments @('reconnect') -Seconds 60)
            $recovered = (Wait-ProtoState 'Connected') -and (Wait-TunnelUrl -TimeoutSeconds 25)
        }
        $recovered -and (-not (Test-DirectEgress))
    }
    Close-ProtoWindow -Label 'tuic'

    # Window 3: anytls (judged)
    Set-RosetunRunnerStep -Step 'anytls'
    if (Send-RosetunMarker -Plan $plan -Label 'anytls' -Word 'open') { $script:openWindow = 'anytls' }
    Test-Step -Id 'proto.anytls' -Scenario 'anytls' -Expectation 'AnyTLS connects, carries HTTPS and blocks direct' {
        (Connect-ProtoVariant 'anytls.json' -AlreadyDisconnected) -and (Wait-TunnelUrl) -and (-not (Test-DirectEgress))
    }
    Close-ProtoWindow -Label 'anytls'

    # Window 4: xray-reality (judged)
    Set-RosetunRunnerStep -Step 'xray-reality'
    if (Send-RosetunMarker -Plan $plan -Label 'xray-reality' -Word 'open') { $script:openWindow = 'xray-reality' }
    Test-Step -Id 'xray.reality.off' -Scenario 'xray-reality' -Expectation 'REALITY with xray off never spawns xray.exe and never leaks' {
        $res = Invoke-ProtoCli -Arguments @('connect', (Join-Path $work 'reality-off.json')) -Seconds 45
        Start-Sleep -Seconds 1
        $noXray = -not (Test-XrayRunning)
        $noLeak = $true
        if ($res.ExitCode -eq 0 -and (Get-ProtoState) -eq 'Connected') {
            $noLeak = -not (Test-DirectEgress)
        }
        else {
            [void](Disconnect-ProtoSession)
        }
        $noXray -and $noLeak
    }
    Test-Step -Id 'xray.reality.auto' -Scenario 'xray-reality' -Expectation 'REALITY + Vision with xray auto starts xray.exe and carries HTTPS' {
        $started = if ((Get-ProtoState) -eq 'Connected') {
            $ap = Invoke-ProtoCli -Arguments @('apply', (Join-Path $work 'reality-auto.json')) -Seconds 60
            ($ap.ExitCode -eq 0) -and (Wait-ProtoState 'Connected')
        }
        else {
            Connect-ProtoVariant 'reality-auto.json'
        }
        $started -and (Test-XrayRunning) -and (Wait-TunnelUrl) -and (-not (Test-DirectEgress))
    }
    Test-Step -Id 'xray.reality.child-killed' -Scenario 'xray-reality' -Expectation 'Killing xray.exe keeps protection active and reconnect restores Xray' {
        $oldPids = @(Get-XrayPids)
        if ($oldPids.Count -eq 0) { return $false }
        foreach ($xpid in $oldPids) { Stop-Process -Id $xpid -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Milliseconds 500
        $protected = -not (Test-DirectEgress)
        $restored = Wait-ProtoCondition -TimeoutSeconds 25 -Condition {
            $cur = @(Get-XrayPids)
            ($cur.Count -gt 0) -and ($cur[0] -notin $oldPids) -and ((Get-ProtoState) -eq 'Connected')
        }
        if (-not $restored) {
            [void](Invoke-ProtoCli -Arguments @('reconnect') -Seconds 60)
            $restored = (Wait-ProtoState 'Connected') -and (Test-XrayRunning)
        }
        $protected -and $restored -and (Wait-TunnelUrl) -and (-not (Test-DirectEgress))
    }
    Test-Step -Id 'xray.reality.apply' -Scenario 'xray-reality' -Expectation 'Apply switches cleanly between REALITY and Shadowsocks' {
        $toSs = Invoke-ProtoCli -Arguments @('apply', (Join-Path $work 'ss.json')) -Seconds 60
        $ssOk = ($toSs.ExitCode -eq 0) -and (Wait-ProtoState 'Connected') -and
            (Wait-ProtoCondition -TimeoutSeconds 15 -Condition { -not (Test-XrayRunning) }) -and
            (Wait-TunnelUrl) -and (-not (Test-DirectEgress))
        if (-not $ssOk) { return $false }
        $toReal = Invoke-ProtoCli -Arguments @('apply', (Join-Path $work 'reality-auto.json')) -Seconds 60
        ($toReal.ExitCode -eq 0) -and (Wait-ProtoState 'Connected') -and
            (Wait-ProtoCondition -TimeoutSeconds 15 -Condition { Test-XrayRunning }) -and
            (Wait-TunnelUrl) -and (-not (Test-DirectEgress))
    }
    Close-ProtoWindow -Label 'xray-reality'

    # Run forced helper kill outside judged windows (dynamic WFP drops on process kill by design;
    # keeping Lockdown off lets Windows reset the lab 8390 TCP sockets cleanly with no orphan FIN retries).
    Test-Step -Id 'xray.reality.helper-killed' -Scenario 'xray-reality' -Expectation 'Killing helper terminates both sing-box.exe and xray.exe via job' {
        if (-not (Connect-ProtoVariant 'reality-auto.json')) { return $false }
        if (-not (Test-XrayRunning) -or @(Get-SingBoxPids).Count -eq 0) { return $false }
        Get-Process -Name 'rosetun-helper-privileged' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Wait-ProtoCondition -TimeoutSeconds 15 -Condition {
            (@(Get-SingBoxPids).Count -eq 0) -and (@(Get-XrayPids).Count -eq 0) -and
            (-not (Get-Process -Name 'rosetun-helper-privileged' -ErrorAction SilentlyContinue))
        }
    }
    [void](Invoke-RosetunNative -FilePath $helperPath -Arguments @('--reset-firewall') -TimeoutSeconds 20)
    [void](Wait-ProtoCondition -TimeoutSeconds 15 -Condition { -not (Test-TunAdapter) })
    Start-ProtoHelper
    # Let Windows NCSI's ~4s post-TUN-removal probe burst complete outside judged windows.
    Start-Sleep -Seconds 8

    # Window 5: xray-xhttp (judged)
    Set-RosetunRunnerStep -Step 'xray-xhttp'
    if (Send-RosetunMarker -Plan $plan -Label 'xray-xhttp' -Word 'open') { $script:openWindow = 'xray-xhttp' }
    # Hold Lockdown across the refused xhttp-off connect so Windows background probes cannot leak while disconnected.
    [void](Invoke-ProtoCli -Arguments @('lockdown', 'on') -Seconds 30)
    Test-Step -Id 'xray.xhttp.off' -Scenario 'xray-xhttp' -Expectation 'XHTTP with xray off is refused cleanly without starting xray.exe' {
        $res = Invoke-ProtoCli -Arguments @('connect', (Join-Path $work 'xhttp-off.json')) -Seconds 30
        $st = Get-ProtoState
        ($res.ExitCode -ne 0) -and (-not (Test-XrayRunning)) -and (-not (Test-TunAdapter)) -and
            (@('Disconnected', 'Failed', 'FailedProtected') -contains $st)
    }
    Test-Step -Id 'xray.xhttp.auto' -Scenario 'xray-xhttp' -Expectation 'XHTTP + REALITY with xray auto starts xray.exe and carries HTTPS' {
        (Connect-ProtoVariant 'xhttp-auto.json') -and (Test-XrayRunning) -and (Wait-TunnelUrl) -and (-not (Test-DirectEgress))
    }
    Test-Step -Id 'xray.xhttp.apply' -Scenario 'xray-xhttp' -Expectation 'Apply switches cleanly between XHTTP and Shadowsocks' {
        $toSs = Invoke-ProtoCli -Arguments @('apply', (Join-Path $work 'ss.json')) -Seconds 60
        $ssOk = ($toSs.ExitCode -eq 0) -and (Wait-ProtoState 'Connected') -and
            (Wait-ProtoCondition -TimeoutSeconds 15 -Condition { -not (Test-XrayRunning) }) -and
            (Wait-TunnelUrl) -and (-not (Test-DirectEgress))
        if (-not $ssOk) { return $false }
        $toXhttp = Invoke-ProtoCli -Arguments @('apply', (Join-Path $work 'xhttp-auto.json')) -Seconds 60
        ($toXhttp.ExitCode -eq 0) -and (Wait-ProtoState 'Connected') -and
            (Wait-ProtoCondition -TimeoutSeconds 15 -Condition { Test-XrayRunning }) -and
            (Wait-TunnelUrl) -and (-not (Test-DirectEgress))
    }
    Close-ProtoWindow -Label 'xray-xhttp' -LockdownAlreadyOn

    # Window 6: second-node (judged)
    Set-RosetunRunnerStep -Step 'second-node'
    if (Send-RosetunMarker -Plan $plan -Label 'second-node' -Word 'open') { $script:openWindow = 'second-node' }
    Test-Step -Id 'second-node.rule-exit' -Scenario 'second-node' -Expectation 'Rule exit routes listed via second node and unlisted via primary' {
        if (-not (Connect-ProtoVariant 'second-node.json' -AlreadyDisconnected)) { return $false }
        $before = Get-FixtureState
        $p0 = Get-HttpsSourceCount -State $before -Source $primaryEgress
        $s0 = Get-HttpsSourceCount -State $before -Source $secondEgress
        $listedOk = Wait-TunnelUrl -Url $listedUrl -TimeoutSeconds 25
        $unlistedOk = Wait-TunnelUrl -Url $unlistedUrl -TimeoutSeconds 25
        $after = Get-FixtureState
        $p1 = Get-HttpsSourceCount -State $after -Source $primaryEgress
        $s1 = Get-HttpsSourceCount -State $after -Source $secondEgress
        $listedOk -and $unlistedOk -and ($s1 -gt $s0) -and ($p1 -gt $p0) -and (-not (Test-DirectEgress))
    }
    Test-Step -Id 'second-node.outage' -Scenario 'second-node' -Expectation 'Stopping second node fails its rule without fallback while primary works' {
        try {
            [void](Set-LabService -Service 'second_node' -State 'stop')
            Start-Sleep -Seconds 1
            $before = Get-FixtureState
            $p0 = Get-HttpsSourceCount -State $before -Source $primaryEgress
            $c0 = Get-HttpsSourceCount -State $before -Source $physical
            $listedFailed = -not (Test-TunnelUrlOnce -Url $listedUrl -MaxTime 6)
            $mid = Get-FixtureState
            $noFallback = ((Get-HttpsSourceCount -State $mid -Source $primaryEgress) -eq $p0) -and
                ((Get-HttpsSourceCount -State $mid -Source $physical) -eq $c0)
            $primaryWorks = (Wait-TunnelUrl -Url $unlistedUrl -TimeoutSeconds 20) -and
                ((Get-HttpsSourceCount -State (Get-FixtureState) -Source $primaryEgress) -gt $p0)
            $noLeak = -not (Test-DirectEgress)
            $outageOk = $listedFailed -and $noFallback -and $primaryWorks -and $noLeak
        }
        finally {
            [void](Set-LabService -Service 'second_node' -State 'start')
        }
        $outageOk -and (Wait-TunnelUrl -Url $listedUrl -TimeoutSeconds 25)
    }
    Test-Step -Id 'second-node.apply-node' -Scenario 'second-node' -Expectation 'Apply moves rule between second node and primary without reconnect' {
        $toPrimary = Invoke-ProtoCli -Arguments @('apply', (Join-Path $work 'listed-primary.json')) -Seconds 60
        if ($toPrimary.ExitCode -ne 0 -or -not (Wait-ProtoState 'Connected')) { return $false }
        $b1 = Get-FixtureState
        $p0 = Get-HttpsSourceCount -State $b1 -Source $primaryEgress
        $s0 = Get-HttpsSourceCount -State $b1 -Source $secondEgress
        if (-not (Wait-TunnelUrl -Url $listedUrl -TimeoutSeconds 25)) { return $false }
        $a1 = Get-FixtureState
        if ((Get-HttpsSourceCount -State $a1 -Source $primaryEgress) -le $p0 -or
            (Get-HttpsSourceCount -State $a1 -Source $secondEgress) -ne $s0) { return $false }
        $toSecond = Invoke-ProtoCli -Arguments @('apply', (Join-Path $work 'second-node.json')) -Seconds 60
        if ($toSecond.ExitCode -ne 0 -or -not (Wait-ProtoState 'Connected')) { return $false }
        $b2 = Get-FixtureState
        $s2 = Get-HttpsSourceCount -State $b2 -Source $secondEgress
        if (-not (Wait-TunnelUrl -Url $listedUrl -TimeoutSeconds 25)) { return $false }
        $a2 = Get-FixtureState
        ((Get-HttpsSourceCount -State $a2 -Source $secondEgress) -gt $s2) -and (-not (Test-DirectEgress))
    }
    Close-ProtoWindow -Label 'second-node'

    # Window 7: dhcp (judged, allowances: dhcpv4, arp-probe, arp-announcement)
    Set-RosetunRunnerStep -Step 'dhcp'
    if (Send-RosetunMarker -Plan $plan -Label 'dhcp' -Word 'open') { $script:openWindow = 'dhcp' }
    Test-Step -Id 'dhcp.renew-under-kill-switch' -Scenario 'dhcp' -Expectation 'DHCPv4 acquisition and renewal succeed under kill switch' {
        if (-not (Connect-ProtoVariant 'ss.json' -AlreadyDisconnected)) { return $false }
        if (-not (Wait-TunnelUrl) -or (Test-DirectEgress)) { return $false }
        $before = Get-FixtureState
        $ackBefore = @($before.dhcp.events | Where-Object { $_.reply -eq 'ack' }).Count
        $dhcpSwitched = $true
        [void](Invoke-RosetunNative -FilePath $netshPath -TimeoutSeconds 20 -Arguments @(
            'interface', 'ipv4', 'set', 'address', "name=$physicalAlias", 'source=dhcp'))
        [void](Invoke-RosetunNative -FilePath $netshPath -TimeoutSeconds 20 -Arguments @(
            'interface', 'ipv4', 'set', 'dnsservers', "name=$physicalAlias", 'source=dhcp'))
        $gotLease = Wait-ProtoCondition -TimeoutSeconds 30 -Condition {
            $addr = Get-NetIPAddress -InterfaceAlias $physicalAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -eq $physical } | Select-Object -First 1
            ($null -ne $addr -and [string]$addr.PrefixOrigin -eq 'Dhcp')
        }
        if (-not $gotLease) { return $false }
        $mid = Get-FixtureState
        $ackMid = @($mid.dhcp.events | Where-Object { $_.reply -eq 'ack' }).Count
        $renew = Invoke-RosetunNative -FilePath $ipconfigPath -TimeoutSeconds 30 -Arguments @('/renew', $physicalAlias)
        Start-Sleep -Seconds 1
        $after = Get-FixtureState
        $ackAfter = @($after.dhcp.events | Where-Object { $_.reply -eq 'ack' }).Count
        Add-RosetunRunnerNote -Name 'dhcp-acks' -Value ($ackAfter - $ackBefore)
        ($renew.ExitCode -eq 0) -and ($ackMid -gt $ackBefore) -and ($ackAfter -gt $ackMid) -and
            (-not (Test-DirectEgress)) -and (Wait-TunnelUrl -TimeoutSeconds 25)
    }
    Close-ProtoWindow -Label 'dhcp'
    if ($dhcpSwitched -and $physicalAlias) {
        Restore-StaticIpv4 -Alias $physicalAlias
        $dhcpSwitched = $false
    }
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
            [void](Invoke-ProtoCli -Arguments @('lockdown', 'off') -Seconds 20)
            $cliDisconnected = Disconnect-ProtoSession -TimeoutSeconds 25
            [void](Invoke-ProtoCli -Arguments @('shutdown') -Seconds 15)
        }
        catch { Set-RosetunRunnerError -Place 'cleanup' -Text 'disconnect-failed' }
    }
    if ($null -ne $script:openWindow) {
        [void](Send-RosetunMarker -Plan $plan -Label $script:openWindow -Word 'close')
        $script:openWindow = $null
    }
    if ($physicalAlias) {
        $curAddr = Get-NetIPAddress -InterfaceAlias $physicalAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -eq $physical } | Select-Object -First 1
        if ($dhcpSwitched -or $null -eq $curAddr -or [string]$curAddr.PrefixOrigin -ne 'Manual') {
            try { Restore-StaticIpv4 -Alias $physicalAlias }
            catch { Set-RosetunRunnerError -Place 'cleanup' -Text 'static-ipv4-restore-failed' }
        }
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

    # Window 8: recovery (listed)
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
