# Runs the system proxy matrix against the Hyper-V test VM. The owner runs it.
# The host plays another device on the guest's network: the Default Switch puts
# both in one segment. Exits with 1 if any check fails.

param(
    [Parameter(Mandatory)][string]$SingBoxPath,
    [Parameter(Mandatory)][string]$RequestPath,
    [string]$BuildDir,
    [switch]$UseHostNode,
    [string]$NodeBindInterface,
    [switch]$KeepNode,
    [switch]$Build,
    [string]$ResultDirectory,
    # The local proxy's port in every request of this matrix.
    [int]$ProxyPort = 10808,
    # Answers through the proxy; a name, so the engine has to resolve it.
    [string]$ProbeUrl = 'https://cp.cloudflare.com/generate_204'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
if (-not $BuildDir) { $BuildDir = Join-Path $RepoRoot 'target\release' }
Import-Module (Join-Path $PSScriptRoot 'RosetunVm.psm1') -Force

$recorder = $null
$nodeIdentity = $null
$nodeStartedByMatrix = $false
$runError = $false
$components = @{}
if ($ResultDirectory) {
    Import-Module (Join-Path $PSScriptRoot 'RosetunProxyResults.psm1') -Force
    $recorder = New-RosetunProxyResults -Directory $ResultDirectory `
        -VmId ((Get-VM -Name (Get-RosetunVmName) -ErrorAction Stop).Id.ToString()) `
        -BootId (Get-RosetunGuestBootTime) -UseHostNode ([bool]$UseHostNode) -KeepNode ([bool]$KeepNode) -ProxyPort $ProxyPort
}
$results = [System.Collections.Generic.List[object]]::new()
$RequestNames = @('proxy-plain.json', 'proxy-strict.json', 'proxy-share.json', 'proxy-share-strict.json', 'proxy-share-lan.json', 'tun-strict.json')
$DesktopTool = 'desktop_proxy.exe'
$RecordName = 'desktop-proxy-matrix.json'

function Test-Step {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Scenario,
        [Parameter(Mandatory)][string]$Expectation,
        [Parameter(Mandatory)][scriptblock]$Condition,
        [string]$Note = ''
    )
    if ($recorder) { $Note = '' }
    $reason = 'condition-false'
    try {
        $passed = [bool](& $Condition)
    }
    catch {
        $reason = 'condition-exception'
        $passed = $false
        $Note = if ($recorder) { 'condition-exception' } else { "$_" }
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
    if ($recorder) {
        Add-RosetunListResult $recorder $Id $(if ($passed) { 'PASS' } else { 'FAIL' }) $(if ($passed) { 'checked' } else { $reason })
    }
}

function Restore-RosetunProxyDesktop {
    param($Original, $Expected)
    try {
        $current = Get-RosetunGuestDesktopProxy
        if (-not (Compare-RosetunProxySettings $current $Expected)) { return 'UNVERIFIED' }
        Set-RosetunGuestDesktopProxy -Enabled $Original.Enabled -Server $Original.Server -Script $Original.Script
        if (Compare-RosetunProxySettings (Get-RosetunGuestDesktopProxy) $Original) { return 'PASS' }
        return 'ERROR'
    }
    catch { Add-RosetunListError $recorder cleanup; return 'UNVERIFIED' }
}

function Get-RosetunProxyLockdownCleanup {
    # PASS covers CLI off and the active WFP dump only. Boot-time filters hidden
    # after BFE startup are outside this observation, as in the Lockdown matrix.
    $state = 'UNVERIFIED'
    try {
        $status = Invoke-RosetunCli -Quiet 'status'
        if ($status.ExitCode -is [int] -and $status.ExitCode -eq 0 -and $status.Output -is [string]) {
            $lines = @([regex]::Matches($status.Output, '(?m)^lockdown: (on|off)\r?$'))
            if ($lines.Count -eq 1 -and @([regex]::Matches($status.Output, '(?m)^lockdown:')).Count -eq 1) { $state = if ($lines[0].Groups[1].Value -eq 'off') { 'PASS' } else { 'ERROR' } }
        }
    }
    catch { }
    $objects = 'UNVERIFIED'
    try {
        $observation = @(Invoke-RosetunGuest -ScriptBlock {
            $path = Join-Path $env:TEMP ("rosetun-wfp-$([guid]::NewGuid().ToString('N')).xml")
            try {
                & netsh.exe wfp show state "file=$path" *> $null
                if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $path)) { return 'UNVERIFIED' }
                $settings = [Xml.XmlReaderSettings]::new()
                $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
                $settings.ConformanceLevel = [Xml.ConformanceLevel]::Fragment
                $settings.XmlResolver = $null
                $reader = [Xml.XmlReader]::Create($path, $settings)
                try {
                    $xml = [Xml.XmlDocument]::new()
                    $xml.XmlResolver = $null
                    # netsh may append firewallState after wfpstate. Parse the
                    # entire stream, rather than truncating at a closing tag.
                    $roots = [Collections.Generic.List[Xml.XmlNode]]::new()
                    $declaration = $false
                    while (-not $reader.EOF) {
                        if ($reader.ReadState -eq [Xml.ReadState]::Initial) { $null = $reader.Read(); continue }
                        if ($reader.NodeType -eq [Xml.XmlNodeType]::Element) {
                            $roots.Add($xml.ReadNode($reader))
                            if ($roots.Count -gt 2) { return 'UNVERIFIED' }
                            continue
                        }
                        if ($reader.NodeType -eq [Xml.XmlNodeType]::XmlDeclaration) {
                            if ($declaration -or $roots.Count -ne 0) { return 'UNVERIFIED' }
                            $declaration = $true
                        }
                        elseif ($reader.NodeType -notin @([Xml.XmlNodeType]::Whitespace, [Xml.XmlNodeType]::SignificantWhitespace, [Xml.XmlNodeType]::Comment)) { return 'UNVERIFIED' }
                        $null = $reader.Read()
                    }
                    if ($roots.Count -eq 0 -or $roots[0].Name -cne 'wfpstate') { return 'UNVERIFIED' }
                    if ($roots.Count -eq 2) {
                        $tail = $roots[1]
                        # Only the observed empty metadata collection is supported.
                        # Populated or unfamiliar metadata remains UNVERIFIED.
                        if ($tail.Name -cne 'firewallState' -or $tail.Attributes.Count -ne 0) { return 'UNVERIFIED' }
                        $children = @($tail.SelectNodes('*'))
                        if ($children.Count -ne 1 -or $children[0].Name -cne 'dynamicKeywordAddresses' -or
                            $children[0].Attributes.Count -ne 0 -or @($children[0].SelectNodes('*')).Count -ne 0 -or
                            -not [string]::IsNullOrWhiteSpace($tail.InnerText)) { return 'UNVERIFIED' }
                    }
                    $null = $xml.AppendChild($roots[0])
                }
                finally { $reader.Dispose() }
                if ($xml.DocumentElement.LocalName -cne 'wfpstate') { return 'UNVERIFIED' }
                if (@($xml.SelectNodes('//*[namespace-uri() != ""]')).Count -ne 0) { return 'UNVERIFIED' }
                # Include the provider and sublayer references on filters, so all
                # LAN slots and program permits are covered, not only fixed filter IDs.
                $lockdownKeys = @(
                    'f12dbedd-f3c7-4a72-b0f8-20559c88b112', 'f829a64d-c373-4d92-9d66-e1c680f3794f',
                    '57bf2a6e-57db-4d99-bed7-ecbd2c63aa75', 'e599db5e-6aeb-4e4d-aa51-4314f1b3076c',
                    '98419911-30f0-4f71-9178-263b40bc7f6e', 'cb0f8c4b-4967-4626-a493-a4e32369e6f5',
                    'f6a5849d-943f-4d77-917c-8811e9a70000', 'e0222624-bc2f-43a6-8058-b939a77ddd4b',
                    '982cc554-9f41-4c9a-833f-87cc5149725f', '729b156a-c411-4f01-b7d9-a789c94e992b',
                    '05b9da42-ea8e-4b28-a2b8-2404db01e0d1')
                foreach ($node in @($xml.SelectNodes('/wfpstate//providerKey | /wfpstate//subLayerKey | /wfpstate//filterKey'))) {
                    $key = [guid]::Empty
                    if ([guid]::TryParse($node.InnerText, [ref]$key) -and $key.ToString() -in $lockdownKeys) { return 'ERROR' }
                }
                # State dumps group filters by layer. Missing collections or
                # inconsistent declared counts cannot prove absence.
                $collections = @(@('/wfpstate/providers', 'providerKey', 'PROVIDER'),
                    @('/wfpstate/subLayers', 'subLayerKey', 'SUBLAYER'),
                    @('/wfpstate/layers', 'layer/layerKey', 'LAYER'))
                $layers = @($xml.SelectNodes('/wfpstate/layers/item'))
                if ($layers.Count -eq 0) { return 'UNVERIFIED' }
                foreach ($layer in $layers) {
                    if (@($layer.SelectNodes('filters')).Count -ne 1) { return 'UNVERIFIED' }
                }
                $collections += ,@('/wfpstate/layers/item/filters', 'filterKey', 'FILTER')
                foreach ($collection in $collections) {
                    $containers = @($xml.SelectNodes($collection[0]))
                    if ($containers.Count -eq 0) { return 'UNVERIFIED' }
                    if ($collection[2] -ne 'FILTER' -and $containers.Count -ne 1) { return 'UNVERIFIED' }
                    foreach ($container in $containers) {
                        $items = @($container.SelectNodes('*'))
                        $count = 0
                        if ($container.HasAttribute('numItems') -and
                            (-not [int]::TryParse($container.GetAttribute('numItems'), [ref]$count) -or $count -ne $items.Count)) { return 'UNVERIFIED' }
                        foreach ($item in $items) {
                            if ($item.LocalName -cne 'item') { return 'UNVERIFIED' }
                            $keys = @($item.SelectNodes($collection[1]))
                            $key = [guid]::Empty
                            if ($keys.Count -ne 1 -or @($keys[0].SelectNodes('*')).Count -ne 0) { return 'UNVERIFIED' }
                            if (-not [guid]::TryParse($keys[0].InnerText, [ref]$key) -and
                                $keys[0].InnerText -cnotmatch ('^FWPM_' + $collection[2] + '_[A-Z0-9_]+$')) { return 'UNVERIFIED' }
                        }
                    }
                }
                foreach ($filter in @($xml.SelectNodes('/wfpstate/layers/item/filters/item'))) {
                    foreach ($reference in @(@('providerKey', 'PROVIDER'), @('subLayerKey', 'SUBLAYER'))) {
                        $keys = @($filter.SelectNodes($reference[0]))
                        # A provider is optional; the sublayer must be unambiguous.
                        if ($keys.Count -gt 1 -or ($reference[1] -eq 'SUBLAYER' -and $keys.Count -ne 1)) { return 'UNVERIFIED' }
                        if ($keys.Count -eq 0) { continue }
                        if (@($keys[0].SelectNodes('*')).Count -ne 0) { return 'UNVERIFIED' }
                        $value = $keys[0].InnerText
                        if ($reference[1] -eq 'PROVIDER' -and [string]::IsNullOrWhiteSpace($value)) { continue }
                        $key = [guid]::Empty
                        if (-not [guid]::TryParse($value, [ref]$key) -and
                            $value -cnotmatch ('^FWPM_' + $reference[1] + '_[A-Z0-9_]+$')) { return 'UNVERIFIED' }
                    }
                }
                return 'PASS'
            }
            catch { return 'UNVERIFIED' }
            finally {
                Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue
                $global:LASTEXITCODE = 0
            }
        })
        if ($observation.Count -eq 1 -and $observation[0] -is [string] -and $observation[0] -in @('PASS', 'ERROR', 'UNVERIFIED')) { $objects = $observation[0] }
    }
    catch { }
    if ($state -eq 'ERROR' -or $objects -eq 'ERROR') { return 'ERROR' }
    if ($state -eq 'PASS' -and $objects -eq 'PASS') { return 'PASS' }
    return 'UNVERIFIED'
}

function Complete-RosetunProxyCleanup {
    param($Components)
    foreach ($name in @('node', 'lan', 'watch', 'listener', 'connection', 'lockdown', 'desktop', 'files')) {
        if (-not $Components.ContainsKey($name)) { $Components[$name] = 'NOT_CREATED' }
    }
    # Read back only resources already targeted by the legacy cleanup.
    foreach ($name in @('lan', 'watch', 'listener', 'connection', 'files')) {
        if ($Components[$name] -ne 'UNVERIFIED') { continue }
        try {
            $confirmed = switch ($name) {
                'lan' {
                    if (Get-Variable lanDevice -Scope Script -ErrorAction SilentlyContinue) {
                        @(Get-NetIPAddress -ErrorAction Stop | Where-Object { $_.IPAddress -eq $script:lanDevice.Address }).Count -eq 0 -and
                        @(Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.Name -eq $script:lanDevice.RuleName }).Count -eq 0 -and
                        -not $script:lanDevice.Listener.Server.IsBound
                    } else { $null }
                }
                'watch' {
                    Invoke-RosetunGuest -ScriptBlock {
                        param($dir)
                        -not (Test-Path -LiteralPath (Join-Path $dir 'rosetun-egress-watch.txt') -ErrorAction Stop) -and
                        @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -eq 'RosetunEgressWatch' }).Count -eq 0 -and
                        @(Get-CimInstance Win32_Process -Filter "Name = 'curl.exe' OR Name = 'cmd.exe'" -ErrorAction Stop |
                            Where-Object { $_.CommandLine -like '*rosetun-egress-probe=*' }).Count -eq 0
                    } -ArgumentList (Get-RosetunGuestDir)
                }
                'listener' {
                    if (Get-Variable holder -ErrorAction SilentlyContinue) {
                        Invoke-RosetunGuest -ScriptBlock {
                            param($processId)
                            @(Get-Process -ErrorAction Stop | Where-Object { $_.Id -eq $processId }).Count -eq 0
                        } -ArgumentList $holder
                    } else { $null }
                }
                'connection' { (Get-RosetunState) -eq 'Disconnected' }
                'files' {
                    Invoke-RosetunGuest -ScriptBlock {
                        param($dir, [string[]]$names)
                        @($names | Where-Object { Test-Path -LiteralPath (Join-Path $dir $_) -ErrorAction Stop }).Count -eq 0
                    } -ArgumentList (Get-RosetunGuestDir), (@($RequestNames) + @($RecordName, $DesktopTool))
                }
            }
            if ($null -ne $confirmed) { $Components[$name] = if ($confirmed -eq $true) { 'PASS' } else { 'ERROR' } }
        }
        catch { $Components[$name] = 'UNVERIFIED'; Add-RosetunListError $recorder cleanup }
    }
    if ($Components.lockdown -eq 'UNVERIFIED') { $Components.lockdown = Get-RosetunProxyLockdownCleanup }
}

function New-RosetunProxyRequests {
    # Variants next to request.json in the guest. `tun-strict.json` is the way
    # into the mode change: the same kill switch, with the adapter.
    param([Parameter(Mandatory)][int]$Port)
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $port)
        $variants = @{
            'proxy-plain.json'        = @{ mode = 'system_proxy'; kill = $false; share = $false }
            'proxy-strict.json'       = @{ mode = 'system_proxy'; kill = $true; share = $false }
            'proxy-share.json'        = @{ mode = 'system_proxy'; kill = $false; share = $true }
            'proxy-share-strict.json' = @{ mode = 'system_proxy'; kill = $true; share = $true }
            'proxy-share-lan.json'    = @{ mode = 'system_proxy'; kill = $false; share = $true; lan = $true }
            'tun-strict.json'         = @{ mode = 'tun'; kill = $true; share = $false }
        }
        foreach ($name in $variants.Keys) {
            $variant = $variants[$name]
            $request = Get-Content -Path (Join-Path $dir 'request.json') -Raw | ConvertFrom-Json
            $settings = $request.settings
            $settings | Add-Member -NotePropertyName connection_mode -NotePropertyValue $variant.mode -Force
            $settings | Add-Member -NotePropertyName kill_switch -NotePropertyValue $variant.kill -Force
            $settings | Add-Member -NotePropertyName auto_reconnect -NotePropertyValue $true -Force
            $settings | Add-Member -NotePropertyName allow_lan -NotePropertyValue ([bool]$variant.lan) -Force
            $settings | Add-Member -NotePropertyName local_proxy -Force -NotePropertyValue ([pscustomobject]@{
                    port = $port
                    share_on_lan = $variant.share
                })
            [IO.File]::WriteAllText((Join-Path $dir $name), ($request | ConvertTo-Json -Depth 30))
        }
    } -ArgumentList (Get-RosetunGuestDir), $Port
}

function Connect-RosetunProxy {
    param([Parameter(Mandatory)][string]$RequestName)
    Disconnect-RosetunTunnel | Out-Null
    Wait-RosetunState 'Disconnected' | Out-Null
    $result = Connect-RosetunTunnel -RequestName $RequestName
    $result.ExitCode -eq 0 -and (Wait-RosetunState 'Connected')
}

function Get-RosetunGuestProxyCode {
    # curl's exit code for a request through the local proxy in the guest.
    param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][int]$Port)
    Invoke-RosetunGuest -ScriptBlock {
        param($url, $port)
        & curl.exe --proxy "http://127.0.0.1:$port" --max-time 20 --silent --ssl-no-revoke --output NUL $url 2>$null
        $code = $LASTEXITCODE
        $global:LASTEXITCODE = 0
        $code
    } -ArgumentList $Url, $Port
}

function Test-RosetunProxyCarries {
    # The request answered, and the test node logged a connection for it: it went
    # through the VPN, not out by itself. Without the node only the answer counts.
    param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][int]$Port)
    $before = if ($UseHostNode) { Get-RosetunTestNodeConnections } else { 0 }
    if ((Get-RosetunGuestProxyCode -Url $Url -Port $Port) -ne 0) { return $false }
    if (-not $UseHostNode) { return $true }
    Wait-RosetunCondition { (Get-RosetunTestNodeConnections) -gt $before }
}

function Get-RosetunGuestDesktopProxy {
    # What the desktop's settings say right now, from the registry WinINet keeps.
    Invoke-RosetunGuest -ScriptBlock {
        $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        # The guest runs Windows PowerShell, and a value may be missing.
        $values = Get-ItemProperty -Path $key
        [pscustomobject]@{
            Enabled = [int]$values.ProxyEnable
            Server = [string]$values.ProxyServer
            Script = [string]$values.AutoConfigURL
        }
    }
}

function Set-RosetunGuestDesktopProxy {
    # Puts settings of the user's own in place, as if set by hand.
    param([int]$Enabled, [string]$Server, [string]$Script)
    Invoke-RosetunGuest -ScriptBlock {
        param($enabled, $server, $pac)
        $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        Set-ItemProperty -Path $key -Name ProxyEnable -Value $enabled -Type DWord
        Set-ItemProperty -Path $key -Name ProxyServer -Value $server -Type String
        if ($pac) {
            Set-ItemProperty -Path $key -Name AutoConfigURL -Value $pac -Type String
        }
        else {
            Remove-ItemProperty -Path $key -Name AutoConfigURL -ErrorAction SilentlyContinue
        }
    } -ArgumentList $Enabled, $Server, $Script
    if ($recorder) { $script:desktopExpected = [pscustomobject]@{ Enabled = $Enabled; Server = $Server; Script = $Script } }
}

function Invoke-RosetunGuestDesktopTool {
    # The module the GUI uses, for a guest where the GUI cannot run.
    param([Parameter(Mandatory)][string[]]$Arguments)
    $answer = Invoke-RosetunGuest -ScriptBlock {
        param($dir, $tool, $record, [string[]]$toolArgs)
        $path = Join-Path $dir $tool
        $recordPath = Join-Path $dir $record
        $command = @($toolArgs[0], $recordPath) + @($toolArgs | Select-Object -Skip 1)
        $output = & $path @command 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE
        $global:LASTEXITCODE = 0
        [pscustomobject]@{ ExitCode = $code; Output = ($output -join ' ') }
    } -ArgumentList (Get-RosetunGuestDir), $DesktopTool, $RecordName, $Arguments
    if ($recorder -and $answer.ExitCode -eq 0) {
        if ($Arguments[0] -eq 'set') { $script:desktopExpected = [pscustomobject]@{ Enabled = 1; Server = "127.0.0.1:$ProxyPort"; Script = '' } }
        elseif ($answer.Output -match 'Restored' -and (Get-Variable own -ErrorAction SilentlyContinue)) { $script:desktopExpected = $own }
    }
    return $answer
}

function Test-RosetunGuestRecord {
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $record)
        Test-Path -Path (Join-Path $dir $record)
    } -ArgumentList (Get-RosetunGuestDir), $RecordName
}

function Test-RosetunHostThroughGuestProxy {
    # A request through the guest's proxy from another device on the guest's network:
    # the host, from an address of its own. The host's usual address is the test node's,
    # and a shared proxy leaves the VPN servers' addresses out on purpose. With
    # -FromServer it is that address. curl's exit code 0 is an answer.
    param(
        [Parameter(Mandatory)][string]$GuestAddress,
        [Parameter(Mandatory)][int]$Port,
        [Parameter(Mandatory)][string]$Url,
        [switch]$FromServer
    )
    $source = if ($FromServer) { @() } else { @('--interface', $script:lanDevice.Address) }
    & curl.exe @source --proxy "http://${GuestAddress}:$Port" --max-time 15 --silent --ssl-no-revoke --output NUL $Url 2>$null
    $code = $LASTEXITCODE
    $global:LASTEXITCODE = 0
    $code -eq 0
}

try {
    if ($Build) {
        & cargo build -q --release --manifest-path (Join-Path $RepoRoot 'Cargo.toml')
        $exitCode = $LASTEXITCODE
        $global:LASTEXITCODE = 0
        if ($exitCode -ne 0) { throw "cargo build failed with exit code $exitCode." }
        & cargo build -q --release -p rosetun-shell --example desktop_proxy --manifest-path (Join-Path $RepoRoot 'Cargo.toml')
        $exitCode = $LASTEXITCODE
        $global:LASTEXITCODE = 0
        if ($exitCode -ne 0) { throw "cargo build of the desktop proxy tool failed with exit code $exitCode." }
    }
    if ($UseHostNode) {
        if ($NodeBindInterface) {
            $nodeStartedByMatrix = Start-RosetunTestNode -ProcessIdentity ([ref]$nodeIdentity) -SingBoxPath $SingBoxPath -BindInterface $NodeBindInterface
        }
        else {
            $nodeStartedByMatrix = Start-RosetunTestNode -ProcessIdentity ([ref]$nodeIdentity) -SingBoxPath $SingBoxPath
        }
    }

    $components.connection = 'UNVERIFIED'
    $components.files = 'UNVERIFIED'
    Stop-RosetunHelper
    Publish-Rosetun -BuildDir $BuildDir -SingBoxPath $SingBoxPath -RequestPath $RequestPath -UseHostNode:$UseHostNode
    Copy-Item -ToSession (Connect-RosetunVm) -Force `
        -Path (Join-Path $BuildDir "examples\$DesktopTool") `
        -Destination (Join-Path (Get-RosetunGuestDir) $DesktopTool)
    Register-RosetunHelper
    Start-RosetunHelper
    New-RosetunProxyRequests -Port $ProxyPort
    $guestAddress = @(Get-RosetunGuestIpv4)[0]
    $components.lan = 'UNVERIFIED'
    $script:lanDevice = Start-RosetunLanDevice

    # The proxy carries what is sent to it; what is not stays outside the VPN.
    Test-Step -Id 'plain.connect' 'plain' 'the proxy mode connects without a kill switch' { Connect-RosetunProxy 'proxy-plain.json' }
    Test-Step -Id 'plain.adapter' 'plain' 'no adapter comes up' { -not (Test-RosetunTunAdapter) }
    Test-Step -Id 'plain.proxy' 'plain' 'a request through the proxy goes through the VPN' {
        Test-RosetunProxyCarries -Url $ProbeUrl -Port $ProxyPort
    }
    Test-Step -Id 'plain.direct' 'plain' 'a request around the proxy goes out by itself' { Test-RosetunDirectEgress }
    Test-Step -Id 'plain.unshared' 'plain' 'other devices do not reach an unshared proxy' {
        -not (Test-RosetunHostThroughGuestProxy -GuestAddress $guestAddress -Port $ProxyPort -Url $ProbeUrl)
    }

    # The port is checked before the engine and any protection start.
    Disconnect-RosetunTunnel | Out-Null
    Wait-RosetunState 'Disconnected' | Out-Null
    $components.listener = 'UNVERIFIED'
    $holder = Invoke-RosetunGuest -ScriptBlock {
        param($port)
        $process = Start-Process -FilePath 'powershell.exe' -PassThru -WindowStyle Hidden -ArgumentList @(
            '-NoProfile', '-Command',
            "`$l=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,$port);`$l.Start();Start-Sleep 120")
        # A fixed wait lost on a cold guest: the service found the port free, and the
        # engine then failed on it with no word of the port.
        $deadline = (Get-Date).AddSeconds(45)
        while ((Get-Date) -lt $deadline -and
            -not (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)) {
            Start-Sleep -Milliseconds 200
        }
        $process.Id
    } -ArgumentList $ProxyPort
    try {
        $busy = Connect-RosetunTunnel -RequestName 'proxy-strict.json' -Quiet
        Test-Step -Id 'busy.reject' 'busy port' 'the connect fails naming the port' -Note $busy.Output {
            $busy.ExitCode -ne 0 -and $busy.Output -match "\b$ProxyPort\b"
        }
        Test-Step -Id 'busy.engine' 'busy port' 'no engine started and no filter stayed' { -not (Test-RosetunEngineRunning) }
        Test-Step -Id 'busy.direct' 'busy port' 'the network stays open' { Test-RosetunDirectEgress }
    }
    finally {
        try {
            Invoke-RosetunGuest -ScriptBlock {
                param($id)
                Stop-Process -Id $id -Force -ErrorAction SilentlyContinue
            } -ArgumentList $holder
        }
        catch { if ($recorder) { $components.listener = 'ERROR'; Add-RosetunListError $recorder cleanup }; throw }
    }
    Wait-RosetunState 'Failed' | Out-Null
    Disconnect-RosetunTunnel | Out-Null

    # The strict kill switch: the first phase for as long as the session lasts.
    Test-Step -Id 'strict.connect' 'strict' 'the proxy mode connects with the kill switch' { Connect-RosetunProxy 'proxy-strict.json' }
    Test-Step -Id 'strict.proxy' 'strict' 'a request through the proxy goes through the VPN' {
        Test-RosetunProxyCarries -Url $ProbeUrl -Port $ProxyPort
    }
    Test-Step -Id 'strict.direct' 'strict' 'a request around the proxy is blocked' { -not (Test-RosetunDirectEgress) }
    Test-Step -Id 'strict.dns' 'strict' 'DNS around the proxy is blocked' { -not (Test-RosetunDirectDns) }

    # The engine dies: its restart must not open anything.
    $components.watch = 'UNVERIFIED'
    Start-RosetunEgressWatch
    $egressWatchActive = $true
    try {
        Stop-RosetunEngine
        Test-Step -Id 'strict.restart' 'strict' 'a killed engine comes back' { Wait-RosetunState 'Connected' }
    }
    finally {
        try { $watch = Stop-RosetunEgressWatch }
        catch { if ($recorder) { $components.watch = 'ERROR'; Add-RosetunListError $recorder cleanup }; throw }
        $egressWatchActive = $false
    }
    Test-Step -Id 'strict.watch' 'strict' "nothing leaves directly while it restarts ($($watch.Probes) probes)" {
        $watch.Probes -gt 0 -and $watch.Leaks -eq 0
    }

    # The mode changes under the standing kill switch, both ways.
    Test-Step -Id 'mode.tun' 'mode change' 'TUN with the kill switch connects' { Connect-RosetunProxy 'tun-strict.json' }
    $components.watch = 'UNVERIFIED'
    Start-RosetunEgressWatch
    $egressWatchActive = $true
    try {
        $toProxy = Invoke-RosetunApply -RequestName 'proxy-strict.json'
        Test-Step -Id 'mode.to-proxy' 'mode change' 'TUN to the proxy applies' -Note $toProxy.Output { $toProxy.ExitCode -eq 0 }
        Test-Step -Id 'mode.adapter-gone' 'mode change' 'the adapter is gone' {
            Wait-RosetunCondition { -not (Test-RosetunTunAdapter) }
        }
        Test-Step -Id 'mode.proxy' 'mode change' 'the proxy carries traffic' { Test-RosetunProxyCarries -Url $ProbeUrl -Port $ProxyPort }
        $toTun = Invoke-RosetunApply -RequestName 'tun-strict.json'
        Test-Step -Id 'mode.to-tun' 'mode change' 'the proxy back to TUN applies' -Note $toTun.Output { $toTun.ExitCode -eq 0 }
        Test-Step -Id 'mode.tunnel' 'mode change' 'the adapter is back and carries traffic' { Test-RosetunTunnelEgress }
    }
    finally {
        try { $watch = Stop-RosetunEgressWatch }
        catch { if ($recorder) { $components.watch = 'ERROR'; Add-RosetunListError $recorder cleanup }; throw }
        $egressWatchActive = $false
    }
    Test-Step -Id 'mode.watch' 'mode change' "nothing leaves directly during the changes ($($watch.Probes) probes)" {
        $watch.Probes -gt 0 -and $watch.Leaks -eq 0
    }

    # Other devices on the guest's network, and no one else.
    foreach ($requestName in @('proxy-share.json', 'proxy-share-strict.json')) {
        $variant = if ($requestName -eq 'proxy-share.json') { 'plain' } else { 'strict' }
        Test-Step -Id "sharing.$variant.connect" 'sharing' "$requestName connects" { Connect-RosetunProxy $requestName }
        Test-Step -Id "sharing.$variant.host" 'sharing' "$requestName`: the host on the guest's network uses the proxy" {
            Test-RosetunHostThroughGuestProxy -GuestAddress $guestAddress -Port $ProxyPort -Url $ProbeUrl
        }
        if ($UseHostNode) {
            Test-Step -Id "sharing.$variant.server" 'sharing' "$requestName`: the VPN server's own address does not get in" {
                -not (Test-RosetunHostThroughGuestProxy -GuestAddress $guestAddress -Port $ProxyPort -Url $ProbeUrl -FromServer)
            }
        }
        if (-not $UseHostNode -and $recorder) {
            Add-RosetunListResult $recorder "sharing.$variant.server" SKIP host-node-disabled
        }
        Test-Step -Id "sharing.$variant.loopback" 'sharing' "$requestName`: the proxy still answers on loopback" {
            Test-RosetunProxyCarries -Url $ProbeUrl -Port $ProxyPort
        }
    }
    Test-Step -Id 'sharing.off' 'sharing' 'with the switch off the host does not get in' {
        Connect-RosetunProxy 'proxy-plain.json'
        -not (Test-RosetunHostThroughGuestProxy -GuestAddress $guestAddress -Port $ProxyPort -Url $ProbeUrl)
    }
    Disconnect-RosetunTunnel | Out-Null
    Wait-RosetunState 'Disconnected' | Out-Null
    Test-Step -Id 'sharing.disconnected' 'sharing' 'after a disconnect the host does not get in' {
        -not (Test-RosetunHostThroughGuestProxy -GuestAddress $guestAddress -Port $ProxyPort -Url $ProbeUrl)
    }

    # The desktop's settings, through the module the GUI uses.
    $components.desktop = 'UNVERIFIED'
    $original = Get-RosetunGuestDesktopProxy
    $script:desktopChanged = $true
    Set-RosetunGuestDesktopProxy -Enabled 0 -Server '' -Script 'http://proxy.example.com/wpad.dat'
    $own = Get-RosetunGuestDesktopProxy
    $set = Invoke-RosetunGuestDesktopTool @('set', "$ProxyPort")
    Test-Step -Id 'desktop.set' 'desktop' 'the settings point at the local proxy' -Note $set.Output {
        $now = Get-RosetunGuestDesktopProxy
        $set.ExitCode -eq 0 -and $now.Enabled -eq 1 -and $now.Server -eq "127.0.0.1:$ProxyPort" -and -not $now.Script
    }
    Test-Step -Id 'desktop.record' 'desktop' 'the record of the user''s settings is there' { Test-RosetunGuestRecord }
    $back = Invoke-RosetunGuestDesktopTool @('restore')
    Test-Step -Id 'desktop.restore' 'desktop' 'after a disconnect the settings are back, script included' -Note $back.Output {
        $now = Get-RosetunGuestDesktopProxy
        $back.Output -match 'Restored' -and $now.Enabled -eq $own.Enabled -and $now.Script -eq $own.Script
    }
    Test-Step -Id 'desktop.record-gone' 'desktop' 'the record is gone' { -not (Test-RosetunGuestRecord) }

    # The tool exits without restoring: what killing the GUI leaves behind.
    Invoke-RosetunGuestDesktopTool @('set', "$ProxyPort") | Out-Null
    Test-Step -Id 'crash.persist' 'crash' 'the proxy and the record outlive the process' {
        (Get-RosetunGuestDesktopProxy).Server -eq "127.0.0.1:$ProxyPort" -and (Test-RosetunGuestRecord)
    }
    $back = Invoke-RosetunGuestDesktopTool @('restore')
    Test-Step -Id 'crash.restore' 'crash' 'the next start restores them' -Note $back.Output {
        $back.Output -match 'Restored' -and (Get-RosetunGuestDesktopProxy).Script -eq $own.Script
    }

    # Someone else changed them: not ours to touch.
    Invoke-RosetunGuestDesktopTool @('set', "$ProxyPort") | Out-Null
    Set-RosetunGuestDesktopProxy -Enabled 1 -Server 'proxy.example.com:3128' -Script ''
    $back = Invoke-RosetunGuestDesktopTool @('restore')
    Test-Step -Id 'foreign.preserve' 'foreign' 'settings changed since stay as they are' -Note $back.Output {
        $now = Get-RosetunGuestDesktopProxy
        $back.Output -match 'LeftAsTheyAre' -and $now.Server -eq 'proxy.example.com:3128' -and
            -not (Test-RosetunGuestRecord)
    }

    # Lockdown keeps its rules: closed inbound without its "Local network".
    $components.lockdown = 'UNVERIFIED'
    $lockdown = Invoke-RosetunCli -Quiet 'lockdown' 'on' '--lan' 'off'
    Test-Step -Id 'lockdown.on' 'lockdown' 'Lockdown goes on without its local network' -Note $lockdown.Output { $lockdown.ExitCode -eq 0 }
    try {
        Test-Step -Id 'lockdown.connect' 'lockdown' 'a shared proxy connects under it' { Connect-RosetunProxy 'proxy-share.json' }
        Test-Step -Id 'lockdown.proxy' 'lockdown' 'the proxy carries traffic' { Test-RosetunProxyCarries -Url $ProbeUrl -Port $ProxyPort }
        Test-Step -Id 'lockdown.direct' 'lockdown' 'a request around the proxy is blocked' { -not (Test-RosetunDirectEgress) }
        Test-Step -Id 'lockdown.host-blocked' 'lockdown' 'the host does not get in' {
            -not (Test-RosetunHostThroughGuestProxy -GuestAddress $guestAddress -Port $ProxyPort -Url $ProbeUrl)
        }
        Disconnect-RosetunTunnel | Out-Null
        Wait-RosetunState 'Disconnected' | Out-Null

        $lockdown = Invoke-RosetunCli -Quiet 'lockdown' 'on' '--lan' 'on'
        Test-Step -Id 'lockdown.lan-on' 'lockdown' 'Lockdown takes its local network' -Note $lockdown.Output { $lockdown.ExitCode -eq 0 }
        # With "Local network" on too: an administrator's connect makes Lockdown's local
        # network follow the request, and this matrix's CLI runs as one.
        Test-Step -Id 'lockdown.lan-connect' 'lockdown' 'a shared proxy connects' { Connect-RosetunProxy 'proxy-share-lan.json' }
        Test-Step -Id 'lockdown.host-allowed' 'lockdown' 'with its local network the host gets in' {
            Test-RosetunHostThroughGuestProxy -GuestAddress $guestAddress -Port $ProxyPort -Url $ProbeUrl
        }
    }
    finally {
        Disconnect-RosetunTunnel | Out-Null
        Wait-RosetunState 'Disconnected' | Out-Null
        try {
            $lockdownOff = Invoke-RosetunCli -Quiet 'lockdown' 'off'
            if ($recorder -and $lockdownOff.ExitCode -ne 0) { $components.lockdown = 'ERROR'; Add-RosetunListError $recorder cleanup }
        }
        catch { if ($recorder) { $components.lockdown = 'ERROR'; Add-RosetunListError $recorder cleanup }; throw }
    }
}
catch {
    $runError = $true
    if ($recorder) { throw 'Proxy matrix infrastructure error.' }
    throw
}
finally {
    if (Get-Variable -Name lanDevice -Scope Script -ValueOnly -ErrorAction SilentlyContinue) {
        try { Stop-RosetunLanDevice $script:lanDevice }
        catch { if ($recorder) { $components.lan = 'ERROR'; Add-RosetunListError $recorder cleanup }; Write-Warning $(if ($recorder) { 'Proxy cleanup infrastructure error.' } else { "Could not remove the temporary LAN device: $_" }) }
    }
    if (Get-Variable -Name egressWatchActive -ValueOnly -ErrorAction SilentlyContinue) {
        try { Stop-RosetunEgressWatch | Out-Null }
        catch { if ($recorder) { $components.watch = 'ERROR'; Add-RosetunListError $recorder cleanup }; Write-Warning $(if ($recorder) { 'Proxy cleanup infrastructure error.' } else { "Could not stop the egress watch: $_" }) }
    }
    $cleanupPart = 'connection'
    try {
        Disconnect-RosetunTunnel | Out-Null
        $cleanupPart = 'desktop'
        if (Get-Variable -Name desktopChanged -Scope Script -ValueOnly -ErrorAction SilentlyContinue) {
            if (-not $recorder) {
                Set-RosetunGuestDesktopProxy -Enabled $original.Enabled -Server $original.Server -Script $original.Script
            }
            else {
                $components.desktop = Restore-RosetunProxyDesktop -Original $original -Expected $(if (Get-Variable desktopExpected -ErrorAction SilentlyContinue) { $desktopExpected } else { $null })
            }
        }
        $cleanupPart = 'files'
        Invoke-RosetunGuest -ScriptBlock {
            param($dir, [string[]]$names)
            foreach ($name in $names) {
                Remove-Item -Path (Join-Path $dir $name) -Force -ErrorAction SilentlyContinue
            }
        } -ArgumentList (Get-RosetunGuestDir), (@($RequestNames) + @($RecordName, $DesktopTool))
    }
    catch { if ($recorder) { $components[$cleanupPart] = 'ERROR'; Add-RosetunListError $recorder cleanup }; Write-Warning $(if ($recorder) { 'Proxy cleanup infrastructure error.' } else { "Could not clean the guest: $_" }) }
    if (($nodeStartedByMatrix -or $null -ne $nodeIdentity) -and -not $KeepNode) {
        try { Stop-RosetunTestNode -ProcessIdentity $nodeIdentity }
        catch { if ($recorder) { $components.node = 'ERROR'; Add-RosetunListError $recorder cleanup }; Write-Warning $(if ($recorder) { 'Proxy cleanup infrastructure error.' } else { "Could not stop the test node: $_" }) }
    }
    if ($recorder) {
        if ($null -ne $nodeIdentity -or $nodeStartedByMatrix) {
            if (-not $components.ContainsKey('node')) { $components.node = if ($KeepNode) { 'RETAINED' } else { Get-RosetunListNodeCleanup $nodeIdentity } }
        }
        else { $components.node = 'NOT_CREATED' }
        Complete-RosetunProxyCleanup -Components $components
        $endBoot = ''
        try { $endBoot = Get-RosetunGuestBootTime } catch { Add-RosetunListError $recorder execution }
        if ($endBoot -ne $recorder.Plan.identity.boot_id) { Add-RosetunListError $recorder execution }
        Complete-RosetunListResults $recorder (Get-RosetunProxyCleanupStatus $components) $endBoot $runError -Components $components
    }
}

$results | Format-Table -AutoSize
if ($recorder -and ((Get-RosetunProxyCleanupStatus $components) -ne 'PASS' -or $recorder.Errors.Count -gt 0)) { exit 1 }
if ($results.Result -contains 'FAIL') { exit 1 }
exit 0
