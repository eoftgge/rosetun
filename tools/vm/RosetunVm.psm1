# Drives the Hyper-V test VM over PowerShell Direct. The channel is VMBus, not
# the network, so it keeps working while the guest kill switch blocks traffic.

Set-StrictMode -Version Latest

# Preference variables of the calling script do not reach into a module, so
# without this a failed cmdlet here would continue silently and the next step
# would fail with a misleading error instead.
$ErrorActionPreference = 'Stop'

$script:Config = @{
    VmName   = 'rosetun-test'
    CredPath = Join-Path $env:USERPROFILE '.rosetun-vm-credential.xml'
    GuestDir = 'C:\rosetun'
    TaskName = 'RosetunHelper'
    TunAlias = 'rosetun0'
    PipeName = 'rosetun-helper'
    # Must be reachable from the guest without the tunnel; the baseline check
    # in the matrix fails loudly if it is not.
    ProbeUrl = 'https://1.1.1.1'
    # Must answer DNS from the guest without the tunnel; the baseline check
    # fails loudly if it does not.
    DnsProbeServer = '1.1.1.1'
    # Fetched through the tunnel, so it must be reachable from the test node's
    # exit, which is the developer's own network. Cloudflare-hosted sites such as
    # www.example.com fail the TLS handshake there when the node bypasses the
    # host VPN.
    TunnelProbeUrl = 'https://ya.ru'
    # Routed through the second test node by an Exit rule; like TunnelProbeUrl it
    # must be reachable from the node's exit, and on another host than it.
    ExitRuleUrl = 'https://yandex.ru'
    # Downloaded at a limited rate through the tunnel and closed midway, so it
    # must be far larger than a minute at that rate (tens of MB) and, like
    # TunnelProbeUrl, reachable from the node's exit.
    LongTransferUrl = 'https://mirror.yandex.ru/debian/dists/bookworm/main/Contents-amd64.gz'
}
$script:Session = $null
# Second cold starts Restart-RosetunGuest needed in this session of the module.
$script:ColdStartRetries = 0

function Install-RosetunSingBox {
    # Downloads the pinned sing-box build into tools\ and checks it, so the
    # 80 MB binary does not have to live in git. Update both values together
    # with SUPPORTED_SING_BOX_VERSION in rosetun-engine-singbox.
    param([string]$Destination = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\sing-box.exe')))

    $version = '1.14.3'
    $expectedHash = '5C19BB3F8C12D4E85B3D47FE63123A7624B314B58DD7A8E32F51004F1C4D2FAF'

    if ((Test-Path -Path $Destination) -and
        (Get-FileHash -Path $Destination -Algorithm SHA256).Hash -eq $expectedHash) {
        Write-Host "sing-box $version is already at $Destination"
        return
    }

    $name = "sing-box-$version-windows-amd64"
    $url = "https://github.com/SagerNet/sing-box/releases/download/v$version/$name.zip"
    $zip = Join-Path $env:TEMP "$name.zip"
    $unpacked = Join-Path $env:TEMP $name

    & curl.exe --fail --silent --show-error --location --output $zip $url
    $exitCode = $LASTEXITCODE
    $global:LASTEXITCODE = 0
    if ($exitCode -ne 0) {
        throw "Downloading $url failed with curl exit code $exitCode."
    }
    try {
        Expand-Archive -Path $zip -DestinationPath $env:TEMP -Force
        $binary = Join-Path $unpacked 'sing-box.exe'
        $hash = (Get-FileHash -Path $binary -Algorithm SHA256).Hash
        if ($hash -ne $expectedHash) {
            throw "sing-box.exe from $url has SHA-256 $hash, expected $expectedHash."
        }
        Copy-Item -Path $binary -Destination $Destination -Force
    }
    finally {
        Remove-Item -Path $zip, $unpacked -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host "sing-box $version installed to $Destination"
}

function Install-RosetunXray {
    $version = '26.10.21'
    $expectedHash = 'FC58C39EE2F2717B4C54D28D374362389E5319B20AE44AEA76EA45A5243EC827'
    $installer = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\installer\build.ps1') -Raw
    if ($installer -notmatch ('(?m)^\$xrayVersion = ''{0}''\r?$' -f $version) -or
        $installer -notmatch ('(?m)^\$xrayArchiveHash = ''{0}''\r?$' -f $expectedHash)) {
        throw 'The VM Xray archive pin differs from installer/build.ps1.'
    }

    $logDir = Join-Path $PSScriptRoot 'logs'
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    $archive = Join-Path $logDir "Xray-windows-64-$version.zip"
    if (-not (Test-Path -LiteralPath $archive)) {
        $download = "$archive.download"
        $url = "https://github.com/XTLS/Xray-core/releases/download/v$version/Xray-windows-64.zip"
        try {
            & curl.exe --fail --silent --show-error --location --output $download $url
            $exitCode = $LASTEXITCODE
            $global:LASTEXITCODE = 0
            if ($exitCode -ne 0) { throw "Downloading $url failed with curl exit code $exitCode." }
            $hash = (Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash
            if ($hash -ne $expectedHash) { throw "Xray archive has SHA-256 $hash, expected $expectedHash." }
            Move-Item -LiteralPath $download -Destination $archive
        }
        finally { Remove-Item -LiteralPath $download -Force -ErrorAction SilentlyContinue }
    }
    $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
    if ($hash -ne $expectedHash) { throw "Xray archive has SHA-256 $hash, expected $expectedHash." }

    $unpacked = Join-Path $logDir "xray-$([guid]::NewGuid().ToString('N'))"
    try {
        Expand-Archive -LiteralPath $archive -DestinationPath $unpacked
        $binary = Join-Path $unpacked 'xray.exe'
        if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
            throw 'The pinned Xray archive does not contain xray.exe.'
        }
        return [pscustomobject]@{ Binary = $binary; Directory = $unpacked }
    }
    catch {
        Remove-Item -LiteralPath $unpacked -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }
}

function Start-RosetunXrayTestNode {
    param([Parameter(Mandatory)][string]$CoverSite, [string]$BindInterface)

    if ($CoverSite -notmatch '^(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+$') {
        throw 'The REALITY cover site must be a DNS name without a scheme or port.'
    }
    $config = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'test-node.json') -Raw | ConvertFrom-Json
    $port = [int](($config.inbounds | Where-Object { $_.type -eq 'shadowsocks' }).listen_port) + 2
    # The exit node takes the port in between.
    $xhttpPort = $port + 2
    $xhttpPath = '/rosetun-xhttp'
    foreach ($listenPort in @($port, $xhttpPort)) {
        if (Get-NetTCPConnection -LocalPort $listenPort -State Listen -ErrorAction SilentlyContinue) {
            throw "TCP $listenPort is already in use; refusing to start the REALITY test node."
        }
    }
    $hostIp = (Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' -AddressFamily IPv4).IPAddress
    $installation = Install-RosetunXray
    $configPath = Join-Path $installation.Directory 'server.json'
    $node = $null
    try {
        $pair = (& $installation.Binary x25519 2>&1) -join "`n"
        $exitCode = $LASTEXITCODE
        $global:LASTEXITCODE = 0
        if ($exitCode -ne 0) { throw "Xray could not generate an X25519 key pair (exit $exitCode)." }
        $private = [regex]::Match($pair, '(?m)^PrivateKey:[ \t]*([A-Za-z0-9_-]{43})\r?$').Groups[1].Value
        $public = [regex]::Match($pair, '(?m)^Password \(PublicKey\):[ \t]*([A-Za-z0-9_-]{43})\r?$').Groups[1].Value
        if (-not $private -or -not $public) { throw 'Xray x25519 returned an unexpected key format.' }
        [byte[]]$shortIdBytes = New-Object byte[] 8
        $random = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $random.GetBytes($shortIdBytes) }
        finally { $random.Dispose() }
        $shortId = [BitConverter]::ToString($shortIdBytes).Replace('-', '').ToLowerInvariant()
        $realitySettings = @{
            dest = "${CoverSite}:443"
            serverNames = @($CoverSite)
            privateKey = $private
            shortIds = @($shortId)
        }
        $server = @{
            log = @{ loglevel = 'warning' }
            inbounds = @(
                @{
                    listen = $hostIp
                    port = $port
                    protocol = 'vless'
                    settings = @{ clients = @(@{ id = 'dd963d73-4229-4d4b-86af-c21d38dc3c25'; flow = 'xtls-rprx-vision' }); decryption = 'none' }
                    streamSettings = @{
                        network = 'tcp'
                        security = 'reality'
                        realitySettings = $realitySettings
                    }
                },
                # Vision does not run over XHTTP, so this client has no flow.
                @{
                    listen = $hostIp
                    port = $xhttpPort
                    protocol = 'vless'
                    settings = @{ clients = @(@{ id = 'dd963d73-4229-4d4b-86af-c21d38dc3c25' }); decryption = 'none' }
                    streamSettings = @{
                        network = 'xhttp'
                        xhttpSettings = @{ path = $xhttpPath; mode = 'auto' }
                        security = 'reality'
                        realitySettings = $realitySettings
                    }
                }
            )
            outbounds = @(@{ protocol = 'freedom' })
        }
        if ($BindInterface) {
            $server.outbounds[0].streamSettings = @{ sockopt = @{ interface = $BindInterface } }
        }
        [IO.File]::WriteAllText($configPath, ($server | ConvertTo-Json -Depth 12))
        $node = Start-Process -FilePath $installation.Binary -ArgumentList 'run', '-config', $configPath `
            -WindowStyle Hidden -PassThru
        $deadline = (Get-Date).AddSeconds(15)
        do {
            $ready = @($port, $xhttpPort | Where-Object {
                $listeners = @(Get-NetTCPConnection -LocalAddress $hostIp -LocalPort $_ -State Listen -ErrorAction SilentlyContinue)
                $listeners.Count -gt 0 -and -not ($listeners | Where-Object { $_.OwningProcess -ne $node.Id })
            })
            if (-not $node.HasExited -and $ready.Count -eq 2) { break }
            if ($node.HasExited -or (Get-Date) -gt $deadline) {
                throw "The REALITY test node did not start on TCP $port and $xhttpPort."
            }
            Start-Sleep -Milliseconds 200
        } while ($true)
        Remove-Item -LiteralPath $configPath -Force
        Write-Host "REALITY test node listening on TCP $port, XHTTP + REALITY on TCP $xhttpPort"
        return [pscustomobject]@{
            Process = $node
            Binary = $installation.Binary
            Directory = $installation.Directory
            Port = $port
            XhttpPort = $xhttpPort
            XhttpPath = $xhttpPath
            PublicKey = $public
            ShortId = $shortId
            CoverSite = $CoverSite
        }
    }
    catch {
        if ($node -and -not $node.HasExited) {
            Stop-Process -InputObject $node -Force -ErrorAction SilentlyContinue
            Wait-Process -InputObject $node -Timeout 5 -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $installation.Directory -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }
}

function Stop-RosetunXrayTestNode {
    param([Parameter(Mandatory)]$Node)

    try {
        if (-not $Node.Process.HasExited) {
            Stop-Process -InputObject $Node.Process -Force
            Wait-Process -InputObject $Node.Process -Timeout 5 -ErrorAction SilentlyContinue
        }
    }
    finally {
        if ($Node.Process.HasExited) {
            Remove-Item -LiteralPath $Node.Directory -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Start-RosetunTestNode {
    # Runs the TCP and UDP test nodes on the host with a log kept under vm\logs.
    param(
        [string]$SingBoxPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\sing-box.exe')),
        # Sends the node's own traffic out of this adapter, past a VPN client
        # running in TUN mode on the host. Such a client accepts TCP itself and
        # can leave the node with open connections that never carry data.
        [string]$BindInterface,
        [switch]$CloudflareBlocked,
        # A second plain node for rules that leave through another server.
        [switch]$ExitNode
    )

    $config = Get-Content -Path (Join-Path $PSScriptRoot 'test-node.json') -Raw | ConvertFrom-Json
    $tcpPort = Get-RosetunTestNodePort -CloudflareBlocked:$CloudflareBlocked -ExitNode:$ExitNode
    $udpPort = ($config.inbounds | Where-Object { $_.type -eq 'hysteria2' }).listen_port
    $tcpOnly = $CloudflareBlocked -or $ExitNode
    $suffix = if ($CloudflareBlocked) { '-cloudflare-blocked' } elseif ($ExitNode) { '-exit' } else { '' }
    if ($tcpOnly) {
        $udpPort = $null
        $config.inbounds = @($config.inbounds | Where-Object { $_.type -eq 'shadowsocks' })
        $config.inbounds[0].listen_port = $tcpPort
    }
    if ($CloudflareBlocked) {
        $config | Add-Member -NotePropertyName route -NotePropertyValue ([pscustomobject]@{
            rules = @(
                [pscustomobject]@{ action = 'sniff' }
                [pscustomobject]@{ domain = @('cp.cloudflare.com'); action = 'reject' }
                [pscustomobject]@{
                    ip_cidr = @('1.1.1.1/32', '1.0.0.1/32')
                    action = 'reject'
                }
            )
            final = 'direct'
        })
    }
    $tcpListening = Get-NetTCPConnection -LocalPort $tcpPort -State Listen -ErrorAction SilentlyContinue
    $udpListening = if ($null -ne $udpPort) {
        Get-NetUDPEndpoint -LocalPort $udpPort -ErrorAction SilentlyContinue
    } else { $null }
    $ports = if ($tcpOnly) { "TCP $tcpPort" } else { "TCP $tcpPort and UDP $udpPort" }
    if ($tcpListening -and ($tcpOnly -or $udpListening)) {
        Write-Host "Test node already listens on $ports."
        return $false
    }
    if ($tcpListening -or $udpListening) {
        throw 'One test port is already in use; stop the existing node before starting both inbounds.'
    }
    if ($BindInterface) {
        $config.outbounds | Where-Object { $_.type -eq 'direct' } | ForEach-Object {
            $_ | Add-Member -NotePropertyName bind_interface -NotePropertyValue $BindInterface -Force
        }
    }

    $logDir = Join-Path $PSScriptRoot 'logs'
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    if (-not $tcpOnly) {
        $keyPath = Join-Path $logDir 'test-node.key'
        $certPath = Join-Path $logDir 'test-node.crt'
        if ((Test-Path $keyPath) -ne (Test-Path $certPath)) {
            throw 'The test certificate or key is missing; remove both and restart the test node.'
        }
        if (-not (Test-Path $keyPath)) {
            $pair = (& $SingBoxPath generate tls-keypair rosetun-test.invalid 2>&1) -join "`n"
            $exitCode = $LASTEXITCODE
            $global:LASTEXITCODE = 0
            if ($exitCode -ne 0) {
                throw "Could not generate the test TLS certificate (exit $exitCode)."
            }
            $key = [regex]::Match($pair, '(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----')
            $cert = [regex]::Match($pair, '(?s)-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----')
            if (-not $key.Success -or -not $cert.Success) {
                throw 'The certificate generator returned an unexpected format.'
            }
            [IO.File]::WriteAllText($keyPath, ($key.Value + "`n"))
            [IO.File]::WriteAllText($certPath, ($cert.Value + "`n"))
        }
        ($config.inbounds | Where-Object { $_.type -eq 'hysteria2' }).tls | ForEach-Object {
            $_ | Add-Member -NotePropertyName key_path -NotePropertyValue $keyPath -Force
            $_ | Add-Member -NotePropertyName certificate_path -NotePropertyValue $certPath -Force
        }
    }
    $config.log = [pscustomobject]@{
        level     = 'debug'
        timestamp = $true
        output    = Join-Path $logDir "test-node$suffix.log"
    }
    $configPath = Join-Path $env:TEMP "rosetun-test-node$suffix.json"
    [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 10))

    $node = Start-Process -FilePath $SingBoxPath -ArgumentList 'run', '--disable-color', '-c', $configPath `
        -WindowStyle Hidden -PassThru
    $deadline = (Get-Date).AddSeconds(15)
    while ($true) {
        $tcpListening = @(Get-NetTCPConnection -LocalPort $tcpPort -State Listen -ErrorAction SilentlyContinue)
        $udpListening = @(if ($null -ne $udpPort) {
            Get-NetUDPEndpoint -LocalPort $udpPort -ErrorAction SilentlyContinue
        })
        if (-not $node.HasExited -and $tcpListening.Count -gt 0 -and
            ($tcpOnly -or $udpListening.Count -gt 0) -and
            -not ($tcpListening | Where-Object { $_.OwningProcess -ne $node.Id }) -and
            ($tcpOnly -or -not ($udpListening | Where-Object { $_.OwningProcess -ne $node.Id }))) {
            break
        }
        if ($node.HasExited -or (Get-Date) -gt $deadline) {
            if (-not $node.HasExited) {
                Stop-Process -InputObject $node -Force -ErrorAction SilentlyContinue
                Wait-Process -InputObject $node -Timeout 5 -ErrorAction SilentlyContinue
            }
            throw "The test node did not start on $ports; see $($config.log.output)."
        }
        Start-Sleep -Milliseconds 200
    }
    Write-Host "Test node listening on $ports, log: $($config.log.output)"
    return $true
}

function Get-RosetunTestNodePort {
    # TCP port of a host test node: the main node, the Cloudflare-blocked node
    # next to it, and the exit node after the REALITY node's port (+2).
    param([switch]$CloudflareBlocked, [switch]$ExitNode)

    if ($CloudflareBlocked -and $ExitNode) {
        throw 'Choose one of -CloudflareBlocked and -ExitNode.'
    }
    $config = Get-Content -Path (Join-Path $PSScriptRoot 'test-node.json') -Raw | ConvertFrom-Json
    $port = ($config.inbounds | Where-Object { $_.type -eq 'shadowsocks' }).listen_port
    if ($CloudflareBlocked) { return $port + 1 }
    if ($ExitNode) { return $port + 3 }
    return $port
}

function Get-RosetunTestNodeConnections {
    # How many proxied connections a host test node has logged so far.
    param([switch]$ExitNode)

    $name = if ($ExitNode) { 'test-node-exit.log' } else { 'test-node.log' }
    $log = Join-Path (Join-Path $PSScriptRoot 'logs') $name
    if (-not (Test-Path $log)) {
        return 0
    }
    # The node keeps its log open for writing.
    $stream = [IO.File]::Open($log, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    try {
        $reader = [IO.StreamReader]::new($stream)
        $count = 0
        while ($null -ne ($line = $reader.ReadLine())) {
            if ($line -like '*inbound connection to*') { $count++ }
        }
        return $count
    }
    finally { $stream.Dispose() }
}

function Stop-RosetunTestNode {
    param([switch]$CloudflareBlocked, [switch]$ExitNode)

    $config = Get-Content -Path (Join-Path $PSScriptRoot 'test-node.json') -Raw | ConvertFrom-Json
    $tcpPort = Get-RosetunTestNodePort -CloudflareBlocked:$CloudflareBlocked -ExitNode:$ExitNode
    $udpPort = ($config.inbounds | Where-Object { $_.type -eq 'hysteria2' }).listen_port
    $tcpOnly = $CloudflareBlocked -or $ExitNode
    if ($tcpOnly) {
        $udpPort = $null
    }
    $ports = if ($tcpOnly) { "TCP $tcpPort" } else { "TCP $tcpPort and UDP $udpPort" }
    $tcpListening = @(Get-NetTCPConnection -LocalPort $tcpPort -State Listen -ErrorAction SilentlyContinue)
    $udpListening = @(if ($null -ne $udpPort) {
        Get-NetUDPEndpoint -LocalPort $udpPort -ErrorAction SilentlyContinue
    })
    if ($tcpListening.Count -eq 0 -or (-not $tcpOnly -and $udpListening.Count -eq 0)) {
        Write-Warning "No complete test node listens on $ports; nothing stopped."
        return
    }
    $tcpOwners = @($tcpListening | Select-Object -ExpandProperty OwningProcess -Unique)
    # @() keeps a single owner an array; Set-StrictMode has no .Count on a bare integer.
    $udpOwners = @(if ($tcpOnly) { $tcpOwners } else {
        $udpListening | Select-Object -ExpandProperty OwningProcess -Unique
    })
    if ($tcpOwners.Count -ne 1 -or $udpOwners.Count -ne 1 -or $tcpOwners[0] -ne $udpOwners[0]) {
        Write-Warning "$ports do not have one common owner; nothing stopped."
        return
    }
    $node = Get-Process -Id $tcpOwners[0] -ErrorAction SilentlyContinue
    if (-not $node -or $node.ProcessName -ne 'sing-box') {
        Write-Warning "The process on TCP $tcpPort and UDP $udpPort is not sing-box.exe; nothing stopped."
        return
    }
    $tcpListening = @(Get-NetTCPConnection -LocalPort $tcpPort -State Listen -ErrorAction SilentlyContinue)
    $udpListening = @(if ($null -ne $udpPort) {
        Get-NetUDPEndpoint -LocalPort $udpPort -ErrorAction SilentlyContinue
    })
    if ($tcpListening.Count -eq 0 -or (-not $tcpOnly -and $udpListening.Count -eq 0) -or
        @($tcpListening | Where-Object { $_.OwningProcess -ne $node.Id }).Count -gt 0 -or
        @($udpListening | Where-Object { $_.OwningProcess -ne $node.Id }).Count -gt 0) {
        Write-Warning "Test node port ownership changed; nothing stopped."
        return
    }
    Stop-Process -InputObject $node -Force
}

function Connect-RosetunVm {
    if ($null -ne $script:Session -and $script:Session.State -eq 'Opened') {
        return $script:Session
    }

    $credential = Import-Clixml -Path $script:Config.CredPath
    $script:Session = New-PSSession -VMName $script:Config.VmName -Credential $credential

    # Registering a SYSTEM task and running the helper need a full admin token.
    $elevated = Invoke-Command -Session $script:Session -ScriptBlock {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    if (-not $elevated) {
        Disconnect-RosetunVm
        throw 'The guest session is not elevated. See LocalAccountTokenFilterPolicy in the setup notes.'
    }

    return $script:Session
}

function Disconnect-RosetunVm {
    if ($null -ne $script:Session) {
        Remove-PSSession -Session $script:Session
        $script:Session = $null
    }
}

function Invoke-RosetunGuest {
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @()
    )
    Invoke-Command -Session (Connect-RosetunVm) -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
}

function Restore-RosetunVm {
    param([string]$CheckpointName = 'clean')

    # The checkpoint resets the guest, so any open session is dead afterwards.
    Disconnect-RosetunVm

    # Several checkpoints may share a name; the newest is the one that counts.
    $checkpoint = Get-VMCheckpoint -VMName $script:Config.VmName -Name $CheckpointName |
        Sort-Object -Property CreationTime -Descending |
        Select-Object -First 1
    if ($null -eq $checkpoint) {
        throw "Checkpoint '$CheckpointName' was not found for $($script:Config.VmName)."
    }
    $checkpoint | Restore-VMCheckpoint -Confirm:$false
    if ((Get-VM -Name $script:Config.VmName).State -ne 'Running') {
        Start-VM -Name $script:Config.VmName
    }

    $deadline = (Get-Date).AddMinutes(3)
    while ($true) {
        try {
            Connect-RosetunVm | Out-Null
            return
        }
        catch {
            if ((Get-Date) -gt $deadline) {
                throw "The guest did not accept PowerShell Direct within 3 minutes: $_"
            }
            Start-Sleep -Seconds 3
        }
    }
}

function Publish-Rosetun {
    param(
        [Parameter(Mandatory)][string]$BuildDir,
        [Parameter(Mandatory)][string]$SingBoxPath,
        [Parameter(Mandatory)][string]$RequestPath,
        # Points the node at the test node on the host. The Default Switch
        # subnet changes with every host reboot, and the address with it.
        [switch]$UseHostNode,
        $XrayNode
    )

    $session = Connect-RosetunVm
    $dir = $script:Config.GuestDir

    $request = Get-Content -Path $RequestPath -Raw | ConvertFrom-Json
    # The matrix deliberately kills the engine and checks FailedProtected before manual reconnect.
    $request.settings | Add-Member -NotePropertyName auto_reconnect -NotePropertyValue $false -Force
    if ($UseHostNode) {
        $hostIp = (Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' -AddressFamily IPv4).IPAddress
        # Without the node the tunnel still comes up, and only the traffic
        # check fails, with nothing in the logs to say why.
        if (-not (Get-NetTCPConnection -LocalPort $request.node.port -State Listen -ErrorAction SilentlyContinue)) {
            throw "Nothing listens on port $($request.node.port) on the host. Start the test node first."
        }
        $request.node.server = $hostIp
        Write-Host "Node server set to $hostIp"
    }
    $temporaryRequest = Join-Path $env:TEMP 'rosetun-request.json'
    # Set-Content -Encoding utf8 on Windows PowerShell writes a BOM, which serde_json rejects.
    [IO.File]::WriteAllText($temporaryRequest, ($request | ConvertTo-Json -Depth 20))
    $RequestPath = $temporaryRequest
    $derived = [ordered]@{}

    $hysteriaPort = (Get-Content -Path (Join-Path $PSScriptRoot 'test-node.json') -Raw | ConvertFrom-Json).inbounds |
        Where-Object { $_.type -eq 'hysteria2' } | Select-Object -ExpandProperty listen_port
    if (-not (Get-NetUDPEndpoint -LocalPort $hysteriaPort -ErrorAction SilentlyContinue)) {
        throw "Nothing listens on UDP $hysteriaPort on the host. Start the test node first."
    }
    $hysteria = $request | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $hysteria.node.id = 'home-hysteria2'
    $hysteria.node.name = 'Test Hysteria2'
    $hysteria.node.server = (Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' -AddressFamily IPv4).IPAddress
    $hysteria.node.port = $hysteriaPort
    $hysteria.node.outbound = [pscustomobject]@{
        hysteria2 = [pscustomobject]@{ password = 'rosetun-test' }
    }
    $hysteria.node.stream = [pscustomobject]@{
        transport = 'tcp'
        tls       = [pscustomobject]@{
            tls = [pscustomobject]@{
                sni            = 'rosetun-test.invalid'
                allow_insecure = $true
            }
        }
    }
    $hysteria.selection.node = $hysteria.node.id
    $hysteria.settings.kill_switch = $true
    $derived['request-hysteria2.json'] = $hysteria

    $cloudflareBlocked = $request | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $cloudflareBlocked.node.id = 'home-cloudflare-blocked'
    $cloudflareBlocked.node.name = 'Cloudflare-blocked test node'
    $blockedNodeConfig = Get-Content -Path (Join-Path $PSScriptRoot 'test-node.json') -Raw | ConvertFrom-Json
    $cloudflareBlocked.node.port = ($blockedNodeConfig.inbounds |
        Where-Object { $_.type -eq 'shadowsocks' }).listen_port + 1
    $cloudflareBlocked.selection.node = $cloudflareBlocked.node.id
    $cloudflareBlocked.settings.kill_switch = $true
    $cloudflareBlocked.settings.dns = [pscustomobject]@{
        server      = '8.8.8.8'
        server_name = 'dns.google'
    }
    $derived['request-cloudflare-blocked.json'] = $cloudflareBlocked

    $ruleExit = $request | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $ruleExit.settings.kill_switch = $true
    $exitNode = $request.node | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $exitNode.id = 'home-exit'
    $exitNode.name = 'Exit test node'
    $exitNode.port = Get-RosetunTestNodePort -ExitNode
    $ruleExit | Add-Member -NotePropertyName extra_nodes -Force -NotePropertyValue @(
        [pscustomobject]@{
            exit      = 'second-node'
            selection = [pscustomobject]@{
                subscription = $request.selection.subscription
                node         = $exitNode.id
            }
            node      = $exitNode
        }
    )
    $ruleExit.rule_set.rules = @(
        [pscustomobject]@{
            id      = 'exit-domain'
            enabled = $true
            matcher = [pscustomobject]@{
                domain = [pscustomobject]@{ exact = ([uri]$script:Config.ExitRuleUrl).Host }
            }
            target  = 'exit'
            exit    = 'second-node'
        }
    ) + @($ruleExit.rule_set.rules)
    $derived['request-rule-exit.json'] = $ruleExit

    if ($XrayNode) {
        $reality = $request | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $reality.node.id = 'home-reality'
        $reality.node.name = 'REALITY test node'
        $reality.node.server = (Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' -AddressFamily IPv4).IPAddress
        $reality.node.port = $XrayNode.Port
        $reality.node.outbound = [pscustomobject]@{
            vless = [pscustomobject]@{
                uuid = 'dd963d73-4229-4d4b-86af-c21d38dc3c25'
                flow = 'xtls-rprx-vision'
            }
        }
        $reality.node.stream = [pscustomobject]@{
            transport = 'tcp'
            tls = [pscustomobject]@{
                reality = [pscustomobject]@{
                    sni = $XrayNode.CoverSite
                    public_key = $XrayNode.PublicKey
                    short_id = $XrayNode.ShortId
                    fingerprint = 'chrome'
                }
            }
        }
        $reality.selection.node = $reality.node.id
        $reality.settings.kill_switch = $true
        $reality.settings.auto_reconnect = $true
        $reality.settings | Add-Member -NotePropertyName xray -NotePropertyValue 'auto' -Force
        $derived['request-reality.json'] = $reality

        $realityOff = $reality | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $realityOff.settings.xray = 'off'
        $realityOff.settings.auto_reconnect = $false
        $derived['request-reality-xray-off.json'] = $realityOff

        $xhttp = $reality | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $xhttp.node.id = 'home-xhttp'
        $xhttp.node.name = 'XHTTP test node'
        $xhttp.node.port = $XrayNode.XhttpPort
        $xhttp.node.outbound.vless.PSObject.Properties.Remove('flow')
        $xhttp.node.stream.transport = [pscustomobject]@{
            xhttp = [pscustomobject]@{ path = $XrayNode.XhttpPath; mode = 'auto' }
        }
        $xhttp.selection.node = $xhttp.node.id
        $derived['request-xhttp.json'] = $xhttp

        $xhttpOff = $xhttp | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $xhttpOff.settings.xray = 'off'
        $xhttpOff.settings.auto_reconnect = $false
        $derived['request-xhttp-xray-off.json'] = $xhttpOff

        $applyFromReality = $request | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $applyFromReality.settings.kill_switch = $true
        $applyFromReality.settings.auto_reconnect = $true
        $applyFromReality.settings | Add-Member -NotePropertyName xray -NotePropertyValue 'auto' -Force
        $derived['request-reality-apply-back.json'] = $applyFromReality
    }

    # The same request with a node that never answers: 192.0.2.1 is TEST-NET-1,
    # reserved and unroutable. The engine starts, but DNS through the tunnel
    # cannot work, so the helper's DNS check must fail the connect.
    $unreachable = Get-Content -Path $RequestPath -Raw | ConvertFrom-Json
    $unreachable.node.server = '192.0.2.1'
    $derived['request-unreachable.json'] = $unreachable

    $deadServer = Get-Content -Path $RequestPath -Raw | ConvertFrom-Json
    $deadServer.node.server = '203.0.113.10'
    $derived['request-dead-server.json'] = $deadServer

    # The same request with a single process rule: curl.exe goes direct and
    # everything else hits the default block. A request that gets through then
    # proves both that the rule matched and that direct traffic from the
    # engine passes the kill switch.
    $processRules = Get-Content -Path $RequestPath -Raw | ConvertFrom-Json
    $processRules.rule_set = [pscustomobject]@{
        id             = $processRules.rule_set.id
        name           = 'Process rule test'
        rules          = @(
            [pscustomobject]@{
                id      = 'curl-direct'
                enabled = $true
                matcher = [pscustomobject]@{ process = [pscustomobject]@{ name = 'curl.exe' } }
                target  = 'direct'
            }
        )
        default_target = 'block'
    }
    $derived['request-process-rules.json'] = $processRules

    foreach ($allowLan in @($true, $false)) {
        $lan = Get-Content -Path $RequestPath -Raw | ConvertFrom-Json
        $lan.settings | Add-Member -NotePropertyName kill_switch -NotePropertyValue $true -Force
        $lan.settings | Add-Member -NotePropertyName allow_lan -NotePropertyValue $allowLan -Force
        $name = if ($allowLan) { 'request-lan-allowed.json' } else { 'request-lan-blocked.json' }
        $derived[$name] = $lan
    }

    $autoReconnect = Get-Content -Path $RequestPath -Raw | ConvertFrom-Json
    $autoReconnect.settings.auto_reconnect = $true
    $derived['request-auto-reconnect.json'] = $autoReconnect

    $dnsLock = Get-Content -Path $RequestPath -Raw | ConvertFrom-Json
    $dnsLock.settings.kill_switch = $false
    $dnsLock.settings.auto_reconnect = $true
    $derived['request-dns-lock.json'] = $dnsLock

    $dnsLockManual = Get-Content -Path $RequestPath -Raw | ConvertFrom-Json
    $dnsLockManual.settings.kill_switch = $false
    $dnsLockManual.settings.auto_reconnect = $false
    $derived['request-dns-lock-manual.json'] = $dnsLockManual

    $applyRules = Get-Content -Path $RequestPath -Raw | ConvertFrom-Json
    $applyRules.rule_set.rules = @($applyRules.rule_set.rules | Where-Object { $_.id -ne 'direct-domain' })
    if ($applyRules.rule_set.rules.Count -eq $request.rule_set.rules.Count) {
        throw 'The request has no direct-domain rule for the apply scenarios.'
    }
    $derived['request-apply-rules.json'] = $applyRules

    $applyNode = $applyRules | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $applyNode.node.id = 'home-server-2'
    $applyNode.selection.node = 'home-server-2'
    $derived['request-apply-node.json'] = $applyNode

    $applyUnreachable = $applyNode | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $applyUnreachable.node.port = 9
    $derived['request-apply-unreachable.json'] = $applyUnreachable

    $applyUnprotected = $applyNode | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $applyUnprotected.settings.kill_switch = $false
    $derived['request-apply-unprotected.json'] = $applyUnprotected

    $temporary = $applyNode | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $temporary.rule_set.default_target = 'block'
    $temporary.settings.auto_reconnect = $true
    $temporaryRules = @($request.rule_set.rules | Where-Object { $_.id -eq 'direct-domain' })
    if ($temporaryRules.Count -ne 1) {
        throw 'The request must have exactly one direct-domain rule for the temporary scenario.'
    }
    $temporary | Add-Member -NotePropertyName temporary_rules -NotePropertyValue $temporaryRules -Force
    $derived['request-temporary.json'] = $temporary

    $dnsLockApply = $dnsLock | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $dnsLockApply.rule_set.rules = @($dnsLockApply.rule_set.rules | Where-Object { $_.id -ne 'direct-domain' })
    $derived['request-dns-lock-apply.json'] = $dnsLockApply

    $derivedDir = Join-Path $env:TEMP 'rosetun-derived-requests'
    New-Item -ItemType Directory -Force -Path $derivedDir | Out-Null

    Invoke-RosetunGuest -ScriptBlock {
        param($dir)
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        # The process rule scenario needs the same curl under another process name.
        Copy-Item -Path "$env:SystemRoot\System32\curl.exe" -Destination "$dir\curl-other.exe" -Force
    } -ArgumentList $dir

    # The helper looks for sing-box.exe next to itself, so names are fixed here.
    $copies = [ordered]@{
        (Join-Path $BuildDir 'rosetun-helper-privileged.exe') = 'rosetun-helper-privileged.exe'
        (Join-Path $BuildDir 'rosetun.exe')                   = 'rosetun.exe'
        $SingBoxPath                                          = 'sing-box.exe'
        $RequestPath                                          = 'request.json'
    }
    if ($XrayNode) {
        $copies[$XrayNode.Binary] = 'xray.exe'
    }
    foreach ($name in $derived.Keys) {
        $path = Join-Path $derivedDir $name
        [IO.File]::WriteAllText($path, ($derived[$name] | ConvertTo-Json -Depth 20))
        $copies[$path] = $name
    }
    try {
        foreach ($source in $copies.Keys) {
            Copy-Item -ToSession $session -Path $source -Destination (Join-Path $dir $copies[$source]) -Force
        }
    }
    finally {
        Remove-Item -Path $derivedDir -Recurse -Force
        if ($null -ne $temporaryRequest) {
            Remove-Item -Path $temporaryRequest
        }
    }

    # Defender scans a new executable on its first launch, which in a fresh
    # guest outlasts the helper's version-check timeout. One untimed launch
    # here keeps that scan out of the scenarios.
    $seconds = Invoke-RosetunGuest -ScriptBlock {
        param($dir)
        $watch = [Diagnostics.Stopwatch]::StartNew()
        & "$dir\sing-box.exe" version | Out-Null
        [int]$watch.Elapsed.TotalSeconds
    } -ArgumentList $dir
    Write-Host "sing-box first launch took $seconds s"
}

function Update-Rosetun {
    # Redeploys a build into the running guest without restoring the
    # checkpoint: faster than the matrix when iterating on one scenario.
    param(
        [Parameter(Mandatory)][string]$SingBoxPath,
        [Parameter(Mandatory)][string]$RequestPath,
        [string]$BuildDir = (Join-Path $PSScriptRoot '..\..\target\release'),
        [switch]$UseHostNode,
        [switch]$Build
    )
    if ($Build) {
        & cargo build --release --manifest-path (Join-Path $PSScriptRoot '..\..\Cargo.toml')
        $exitCode = $LASTEXITCODE
        $global:LASTEXITCODE = 0
        if ($exitCode -ne 0) {
            throw "cargo build failed with exit code $exitCode."
        }
    }
    # A running helper keeps its executable locked.
    Stop-RosetunHelper
    Publish-Rosetun -BuildDir $BuildDir -SingBoxPath $SingBoxPath -RequestPath $RequestPath -UseHostNode:$UseHostNode
    Register-RosetunHelper
    Start-RosetunHelper
}

function Register-RosetunHelper {
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $task)
        # SYSTEM is closest to how the helper will run as a service. Stdout and
        # stderr go to a file so the log survives the session.
        $command = "set ROSETUN_LOG=debug&& `"$dir\rosetun-helper-privileged.exe`" > `"$dir\helper.log`" 2>&1"
        $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c $command" -WorkingDirectory $dir
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName $task -Action $action -Principal $principal `
            -Settings $settings -Force | Out-Null
    } -ArgumentList $script:Config.GuestDir, $script:Config.TaskName
}

function Start-RosetunHelper {
    # The first start after a deploy waits for Defender to scan the new
    # binary, which takes well over 15 seconds in a freshly restored guest.
    param([int]$TimeoutSeconds = 60)
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $task, $pipeName, $timeout)

        # The default IgnoreNew policy silently drops a start issued while a
        # previous instance is still winding down, so wait it out first.
        $deadline = (Get-Date).AddSeconds($timeout)
        while ((Get-ScheduledTask -TaskName $task).State -eq 'Running') {
            if ((Get-Date) -gt $deadline) {
                throw 'A previous helper task instance is still running.'
            }
            Start-Sleep -Milliseconds 200
        }

        # Keep every earlier run's log: after a killed helper or a failed
        # scenario it is the evidence, and the matrix restarts the helper.
        if (Test-Path -Path "$dir\helper.log") {
            $stamp = (Get-Item -Path "$dir\helper.log").LastWriteTime.ToString('yyyyMMdd-HHmmss-fff')
            Move-Item -Path "$dir\helper.log" -Destination "$dir\helper-$stamp.log" -Force
        }
        Start-ScheduledTask -TaskName $task

        # Enumerating the pipe directory does not connect to the pipe, unlike
        # Test-Path, so it never consumes a listener instance.
        $deadline = (Get-Date).AddSeconds($timeout)
        while (-not ([IO.Directory]::GetFiles('\\.\pipe\') -contains "\\.\pipe\$pipeName")) {
            if ((Get-Date) -gt $deadline) {
                $state = (Get-ScheduledTask -TaskName $task).State
                $result = (Get-ScheduledTaskInfo -TaskName $task).LastTaskResult
                $running = [bool](Get-Process -Name 'rosetun-helper-privileged' -ErrorAction SilentlyContinue)
                $message = ('The helper did not open its pipe within {3} seconds. ' +
                    'Task state: {0}; last result: 0x{1:X8}; helper process running: {2}.') -f $state, $result, $running, $timeout
                $tail = Get-Content -Path "$dir\helper.log" -Tail 20 -ErrorAction SilentlyContinue
                if ($tail) {
                    $message += "`n" + ($tail -join "`n")
                }
                throw $message
            }
            Start-Sleep -Milliseconds 200
        }
    } -ArgumentList $script:Config.GuestDir, $script:Config.TaskName, $script:Config.PipeName, $TimeoutSeconds
}

function Stop-RosetunHelper {
    # A hard kill on purpose: it simulates a helper crash. Stopping only the
    # task could leave the helper running as a child of cmd.exe.
    Invoke-RosetunGuest -ScriptBlock {
        param($task)
        Stop-Process -Name 'rosetun-helper-privileged' -Force -ErrorAction SilentlyContinue
        Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue

        # Stop-ScheduledTask returns before the instance is gone.
        $deadline = (Get-Date).AddSeconds(15)
        # The task does not exist yet on a fresh guest.
        while ((Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue).State -eq 'Running' -or
            (Get-Process -Name 'rosetun-helper-privileged' -ErrorAction SilentlyContinue)) {
            if ((Get-Date) -gt $deadline) {
                throw 'The helper did not stop within 15 seconds.'
            }
            Start-Sleep -Milliseconds 200
        }
    } -ArgumentList $script:Config.TaskName
}

function Invoke-RosetunCli {
    param(
        # Status is polled in loops where failures are expected; keep it silent.
        [switch]$Quiet,
        [Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$Arguments
    )
    $result = Invoke-RosetunGuest -ScriptBlock {
        param($dir, [string[]]$cliArgs)
        $output = & "$dir\rosetun.exe" @cliArgs 2>&1 | ForEach-Object { "$_" }
        $exitCode = $LASTEXITCODE
        $global:LASTEXITCODE = 0
        [pscustomobject]@{ ExitCode = $exitCode; Output = ($output -join "`n") }
    } -ArgumentList $script:Config.GuestDir, $Arguments

    # Callers usually discard the result, so a failure must be visible here.
    if (-not $Quiet -and $result.ExitCode -ne 0) {
        Write-Warning "rosetun $($Arguments -join ' ') exited with $($result.ExitCode):`n$($result.Output)"
    }
    return $result
}

function Connect-RosetunTunnel {
    param(
        [string]$RequestName = 'request.json',
        # For connects that are expected to fail; the caller checks the result.
        [switch]$Quiet
    )
    Invoke-RosetunCli -Quiet:$Quiet 'connect' (Join-Path $script:Config.GuestDir $RequestName)
}

function Invoke-RosetunProbe {
    param([string]$RequestName = 'request.json')
    Invoke-RosetunCli -Quiet 'probe' (Join-Path $script:Config.GuestDir $RequestName)
}

function Invoke-RosetunApply {
    param(
        [string]$RequestName = 'request.json',
        [switch]$Quiet
    )
    Invoke-RosetunCli -Quiet:$Quiet 'apply' (Join-Path $script:Config.GuestDir $RequestName)
}

function Disconnect-RosetunTunnel {
    Invoke-RosetunCli 'disconnect'
}

function Request-RosetunShutdown {
    Invoke-RosetunCli 'shutdown'
}

function Get-RosetunGuestDir {
    return $script:Config.GuestDir
}

function Get-RosetunVmName {
    return $script:Config.VmName
}

function Get-RosetunTunnelProbeUrl {
    return $script:Config.TunnelProbeUrl
}

function Get-RosetunExitRuleUrl {
    return $script:Config.ExitRuleUrl
}

function Get-RosetunLongTransferUrl {
    return $script:Config.LongTransferUrl
}

function Get-RosetunStatus {
    param([Parameter(Mandatory)][int]$ProtocolVersion)

    Invoke-RosetunGuest -ScriptBlock {
        param($protocolVersion)
        $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'rosetun-helper', [IO.Pipes.PipeDirection]::InOut)
        try {
            $pipe.Connect(5000)
            $writer = [IO.StreamWriter]::new($pipe, [Text.UTF8Encoding]::new($false))
            $writer.NewLine = "`n"
            $writer.AutoFlush = $true
            $reader = [IO.StreamReader]::new($pipe, [Text.UTF8Encoding]::new($false))
            foreach ($request in @(
                ('{"request":{"id":1,"body":{"hello":{"client":"rosetun-matrix","protocol_version":' + $protocolVersion + '}}}}'),
                '{"request":{"id":2,"body":"status"}}'
            )) {
                $writer.WriteLine($request)
                $id = if ($request -match '"id":1') { 1 } else { 2 }
                do {
                    $read = $reader.ReadLineAsync()
                    if (-not $read.Wait(5000)) { throw 'Timed out waiting for helper status.' }
                    if ($null -eq $read.Result) { throw 'Helper closed the status pipe.' }
                    $frame = $read.Result | ConvertFrom-Json
                } while ($frame.PSObject.Properties.Name -notcontains 'response' -or $frame.response.id -ne $id)
                if ($id -eq 1 -and -not $frame.response.body.hello) {
                    throw 'Helper rejected the status handshake.'
                }
            }
            if (-not $frame.response.body.status) { throw 'Helper did not return a status.' }
            $frame.response.body.status
        }
        finally { $pipe.Dispose() }
    } -ArgumentList $ProtocolVersion
}

function Get-RosetunState {
    $result = Invoke-RosetunCli -Quiet 'status'
    if ($result.Output -match '(?m)^state: (\w+)') {
        return $Matches[1]
    }
    return "unknown (exit $($result.ExitCode))"
}

function Wait-RosetunState {
    param(
        [Parameter(Mandatory)][string]$Expected,
        [int]$TimeoutSeconds = 30
    )
    # Polling status is also what makes the helper notice a dead engine.
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        if ((Get-RosetunState) -eq $Expected) {
            return $true
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Wait-RosetunCondition {
    param(
        [Parameter(Mandatory)][scriptblock]$Condition,
        [int]$TimeoutSeconds = 10
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        if (& $Condition) {
            return $true
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Get-RosetunEgressInterface {
    # Interface index and IPv4 address of the physical adapter that carries
    # the default route outside the tunnel.
    Invoke-RosetunGuest -ScriptBlock {
        param($tunAlias)
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceAlias -ne $tunAlias } |
            Sort-Object -Property RouteMetric |
            Select-Object -First 1
        if ($null -eq $route) {
            throw 'No default route outside the tunnel.'
        }
        [pscustomobject]@{
            Index   = $route.InterfaceIndex
            Address = (Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 |
                Select-Object -First 1).IPAddress
        }
    } -ArgumentList $script:Config.TunAlias
}

function Get-RosetunEgressAddress {
    (Get-RosetunEgressInterface).Address
}

function Start-RosetunLanListener {
    $address = Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' -AddressFamily IPv4 -AddressState Preferred -ErrorAction Stop |
        Where-Object { $_.IPAddress -notlike '169.254.*' } |
        Select-Object -First 1 -ExpandProperty IPAddress
    if (-not $address) {
        throw 'The Default Switch has no usable IPv4 gateway address.'
    }
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse($address), 0)
    $name = "Rosetun-LAN-matrix-$([guid]::NewGuid().ToString('N'))"
    try {
        $listener.Start(8)
        $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
        New-NetFirewallRule -Name $name -DisplayName 'Rosetun LAN matrix listener' -Direction Inbound `
            -Action Allow -Protocol TCP -LocalAddress $address -LocalPort $port `
            -InterfaceAlias 'vEthernet (Default Switch)' -Profile Any -ErrorAction Stop | Out-Null
        return [pscustomobject]@{ Address = $address; Port = $port; Listener = $listener; RuleName = $name }
    }
    catch {
        Remove-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
        $listener.Stop()
        throw
    }
}

function Stop-RosetunLanListener {
    param([Parameter(Mandatory)]$Lan)
    try { Remove-NetFirewallRule -Name $Lan.RuleName -ErrorAction Stop }
    finally { $Lan.Listener.Stop() }
}

function Test-RosetunUdpInternet {
    # True when an NTP reply comes back to the guest. A public server is used on
    # purpose: the host's LAN address is on-link for the guest, so datagrams to it
    # bypass the TUN and say nothing about the tunnel. NTP is not hijacked by the
    # engine and port 123 is not filtered by VLESS Vision.
    param([string]$Server = '162.159.200.1')
    Invoke-RosetunGuest -ScriptBlock {
        param($server)
        $client = [Net.Sockets.UdpClient]::new()
        try {
            $client.Client.ReceiveTimeout = 3000
            $request = [byte[]]::new(48)
            $request[0] = 0x1B
            $remote = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
            for ($attempt = 0; $attempt -lt 3; $attempt++) {
                [void]$client.Send($request, $request.Length, $server, 123)
                try {
                    $reply = $client.Receive([ref]$remote)
                    if ($reply.Length -ge 48) { return $true }
                }
                catch [Net.Sockets.SocketException] { }
            }
            return $false
        }
        finally { $client.Dispose() }
    } -ArgumentList $Server
}

function Test-RosetunLanListener {
    param([Parameter(Mandatory)]$Lan)
    $localAddress = Get-RosetunEgressAddress
    Invoke-RosetunGuest -ScriptBlock {
        param($localAddress, $hostAddress, $port)
        $endpoint = [Net.IPEndPoint]::new([Net.IPAddress]::Parse($localAddress), 0)
        $client = [Net.Sockets.TcpClient]::new($endpoint)
        try { return $client.ConnectAsync($hostAddress, $port).Wait(2000) }
        catch { return $false }
        finally { $client.Dispose() }
    } -ArgumentList $localAddress, $Lan.Address, $Lan.Port
}

function Test-RosetunDirectEgress {
    # True when a process other than the engine reaches the internet through
    # the physical adapter. Under an active kill switch this must be false.
    $address = Get-RosetunEgressAddress
    Invoke-RosetunGuest -ScriptBlock {
        param($address, $url)
        & curl.exe --interface $address --max-time 5 --silent --output NUL $url 2>$null
        $LASTEXITCODE -eq 0
    } -ArgumentList $address, $script:Config.ProbeUrl
}

function Test-RosetunDirectDns {
    param(
        # Resolvers fall back to TCP for long answers; the lock must cover it too.
        [switch]$Tcp,
        # Another resolver than DnsProbeServer, such as the guest's gateway.
        [string]$Server = $script:Config.DnsProbeServer
    )
    # A non-engine guest process probes port 53 through the physical adapter.
    $address = Get-RosetunEgressAddress
    Invoke-RosetunGuest -ScriptBlock {
        param($address, $server, $tcp)
        $local = [Net.IPEndPoint]::new([Net.IPAddress]::Parse($address), 0)
        if ($tcp) {
            $client = [Net.Sockets.TcpClient]::new($local)
            try { return $client.ConnectAsync($server, 53).Wait(3000) }
            catch { return $false }
            finally { $client.Dispose() }
        }
        # A standard query for example.com, type A, recursion desired.
        $ascii = [Text.Encoding]::ASCII
        [byte[]]$query = @(0x52, 0x53, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 7) +
            $ascii.GetBytes('example') + @(3) + $ascii.GetBytes('com') + @(0, 0, 1, 0, 1)
        $client = [Net.Sockets.UdpClient]::new($local)
        try {
            $client.Client.ReceiveTimeout = 3000
            [void]$client.Send($query, $query.Length, $server, 53)
            $from = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
            $reply = $client.Receive([ref]$from)
            return $reply.Length -ge 12 -and $reply[0] -eq 0x52 -and $reply[1] -eq 0x53
        }
        catch { return $false }
        finally { $client.Dispose() }
    } -ArgumentList $address, $Server, [bool]$Tcp
}

function Get-RosetunIpv6NeighborTarget {
    # Both ends of the Default Switch link. The switch does not pass IPv6
    # neighbor discovery, so each side needs the other's MAC pinned.
    $hostAdapter = Get-NetAdapter -Name 'vEthernet (Default Switch)' -ErrorAction Stop
    $hostAddress = Get-NetIPAddress -InterfaceIndex $hostAdapter.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -like 'fe80::*' } |
        Select-Object -First 1
    if ($null -eq $hostAddress) {
        throw 'The host has no link-local IPv6 address on the Default Switch.'
    }
    # The VM's MAC may be dynamic, so it is read on every run.
    $vmAdapters = @(Get-VMNetworkAdapter -VMName $script:Config.VmName -ErrorAction Stop |
        Where-Object { $_.SwitchName -eq 'Default Switch' })
    if ($vmAdapters.Count -ne 1) {
        throw "Expected one network adapter of $($script:Config.VmName) on the Default Switch, found $($vmAdapters.Count)."
    }
    $egress = Get-RosetunEgressInterface
    $guest = Invoke-RosetunGuest -ScriptBlock {
        param($index)
        [pscustomobject]@{
            Address = Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv6 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -like 'fe80::*' } |
                Select-Object -First 1 -ExpandProperty IPAddress
            Mac     = (Get-NetAdapter -InterfaceIndex $index -ErrorAction Stop).MacAddress
        }
    } -ArgumentList $egress.Index
    if (-not $guest.Address) {
        throw 'The guest has no link-local IPv6 address on its egress adapter.'
    }
    $vmMac = $vmAdapters[0].MacAddress -replace '[^0-9A-Fa-f]', ''
    if (($guest.Mac -replace '[^0-9A-Fa-f]', '') -ne $vmMac) {
        throw "The guest egress adapter ($($guest.Mac)) is not the VM's Default Switch adapter ($vmMac)."
    }
    [pscustomobject]@{
        HostIndex    = $hostAdapter.ifIndex
        HostAddress  = $hostAddress.IPAddress -replace '%.*$', ''
        HostMac      = $hostAdapter.MacAddress
        GuestIndex   = $egress.Index
        GuestAddress = $guest.Address -replace '%.*$', ''
        GuestMac     = $vmMac
    }
}

function Set-RosetunIpv6Neighbor {
    # Pins the host in the guest and the guest on the host, in ActiveStore
    # only, so nothing survives a reboot of either side. An exact Permanent
    # entry is left alone; any other is replaced. Every entry this call creates
    # is appended to $Created at once, so an interrupted run can still remove it.
    # Safe to call again after the guest adapter restarts.
    param([Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Created)
    $pin = {
        param($index, $address, $mac)
        $wanted = ($mac -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
        $neighbor = Get-NetNeighbor -InterfaceIndex $index -IPAddress $address -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($null -ne $neighbor -and $neighbor.State -eq 'Permanent' -and
            ($neighbor.LinkLayerAddress -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() -eq $wanted) {
            return $false
        }
        if ($null -ne $neighbor) {
            Remove-NetNeighbor -InterfaceIndex $index -IPAddress $address -PolicyStore ActiveStore -Confirm:$false -ErrorAction Stop
        }
        New-NetNeighbor -InterfaceIndex $index -IPAddress $address -LinkLayerAddress (($wanted -split '(..)' -ne '') -join '-') `
            -State Permanent -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
        $true
    }
    $target = Get-RosetunIpv6NeighborTarget
    $sides = @(
        [pscustomobject]@{ Side = 'guest'; Index = $target.GuestIndex; Address = $target.HostAddress; Mac = $target.HostMac }
        [pscustomobject]@{ Side = 'host'; Index = $target.HostIndex; Address = $target.GuestAddress; Mac = $target.GuestMac }
    )
    foreach ($side in $sides) {
        try {
            $createdNow = if ($side.Side -eq 'guest') {
                Invoke-RosetunGuest -ScriptBlock $pin -ArgumentList $side.Index, $side.Address, $side.Mac
            }
            else {
                & $pin $side.Index $side.Address $side.Mac
            }
        }
        catch {
            throw "Could not pin the IPv6 neighbor $($side.Address) on the $($side.Side): $_"
        }
        $known = $Created | Where-Object {
            $_.Side -eq $side.Side -and $_.Index -eq $side.Index -and $_.Address -eq $side.Address
        }
        if ($createdNow -and -not $known) {
            $Created.Add([pscustomobject]@{ Side = $side.Side; Index = $side.Index; Address = $side.Address })
        }
    }
}

function Remove-RosetunIpv6Neighbor {
    # Removes the entries Set-RosetunIpv6Neighbor created. Tries every entry
    # and reports all failures at the end.
    param([Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Created)
    $unpin = {
        param($index, $address)
        if (Get-NetNeighbor -InterfaceIndex $index -IPAddress $address -PolicyStore ActiveStore -ErrorAction SilentlyContinue) {
            Remove-NetNeighbor -InterfaceIndex $index -IPAddress $address -PolicyStore ActiveStore -Confirm:$false -ErrorAction Stop
        }
    }
    $failures = @()
    foreach ($entry in @($Created)) {
        try {
            if ($entry.Side -eq 'guest') {
                Invoke-RosetunGuest -ScriptBlock $unpin -ArgumentList $entry.Index, $entry.Address
            }
            else {
                & $unpin $entry.Index $entry.Address
            }
            [void]$Created.Remove($entry)
        }
        catch {
            $failures += "$($entry.Address) on the $($entry.Side): $_"
        }
    }
    if ($failures) {
        throw "Could not remove IPv6 neighbors: $($failures -join '; ')"
    }
}

function Get-RosetunIpv6NeighborReport {
    # What each side holds for the other's link-local address, for the error
    # that stops the matrix after a failed IPv6 baseline. Never throws.
    try {
        $target = Get-RosetunIpv6NeighborTarget
    }
    catch {
        return "Neighbor entries unavailable: $_"
    }
    $describe = {
        param($index, $address)
        $entries = foreach ($store in 'ActiveStore', 'PersistentStore') {
            Get-NetNeighbor -InterfaceIndex $index -IPAddress $address -PolicyStore $store -ErrorAction SilentlyContinue |
                ForEach-Object { "$store $($_.State) $($_.LinkLayerAddress)" }
        }
        if ($entries) { $entries -join ', ' } else { 'none' }
    }
    $hostEntry = & $describe $target.HostIndex $target.GuestAddress
    try {
        $guestEntry = Invoke-RosetunGuest -ScriptBlock $describe -ArgumentList $target.GuestIndex, $target.HostAddress
    }
    catch {
        $guestEntry = "unavailable: $_"
    }
    "Host neighbor $($target.GuestAddress) (expected $($target.GuestMac)): $hostEntry. " +
        "Guest neighbor $($target.HostAddress) (expected $($target.HostMac)): $guestEntry."
}

function Assert-RosetunHostLockdownOff {
    # Lockdown on the host leaves Hyper-V guests offline: the host serves the
    # Default Switch itself (DHCP, DNS, NAT), which is inbound traffic for it,
    # and the guest's first DHCP request comes from 0.0.0.0. Every guest check
    # would then fail for a reason that is not the guest's. BFE keeps
    # persistent providers under this key (both value and subkey names are
    # checked); Lockdown's provider key is fixed
    # (crates/rosetun-routing/src/platform/windows/lockdown.rs).
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\Persistent\Provider'
    $lockdownProvider = '{f12dbedd-f3c7-4a72-b0f8-20559c88b112}'
    try {
        $item = Get-Item -LiteralPath $key -ErrorAction Stop
        $names = @($item.GetValueNames()) + @($item.GetSubKeyNames())
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        return
    }
    catch {
        Write-Warning "Cannot tell whether Lockdown is on on this host: $($_.Exception.Message)"
        return
    }
    if ($names | Where-Object { $_ -ieq $lockdownProvider }) {
        throw ('Rosetun Lockdown is on on this host, so Hyper-V guests get no network. ' +
            'Turn Lockdown off (or run rosetun reset-firewall as administrator) and start again.')
    }
}

function Assert-RosetunIpv6Neighbor {
    # Without both pins the guest cannot reach the host over IPv6 at all, and
    # every "IPv6 blocked" check would pass without proving anything. A guest
    # adapter restart can drop the guest's ActiveStore entry.
    $target = Get-RosetunIpv6NeighborTarget
    $isPinned = {
        param($index, $address, $mac)
        $wanted = ($mac -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
        $neighbor = Get-NetNeighbor -InterfaceIndex $index -IPAddress $address -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Select-Object -First 1
        $null -ne $neighbor -and $neighbor.State -eq 'Permanent' -and
            ($neighbor.LinkLayerAddress -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() -eq $wanted
    }
    $hostPinned = & $isPinned $target.HostIndex $target.GuestAddress $target.GuestMac
    $guestPinned = Invoke-RosetunGuest -ScriptBlock $isPinned -ArgumentList $target.GuestIndex, $target.HostAddress, $target.HostMac
    if (-not ($hostPinned -and $guestPinned)) {
        throw "The IPv6 neighbor pins are missing, so this IPv6 check would prove nothing. $(Get-RosetunIpv6NeighborReport)"
    }
}

function Test-RosetunIpv6Egress {
    # True when a guest process opens a TCP connection over IPv6 outside the
    # tunnel. Neither the guest nor the developer's network has global IPv6, so
    # the target is the test node on the host's link-local address. The connect
    # passes the same WFP IPv6 layer a real leak would.
    $hostAddress = Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' -AddressFamily IPv6 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -like 'fe80::*' } |
        Select-Object -First 1
    if ($null -eq $hostAddress) {
        throw 'The host has no link-local IPv6 address on the Default Switch.'
    }
    $port = (Get-Content -Path (Join-Path $PSScriptRoot 'test-node.json') -Raw | ConvertFrom-Json).inbounds[0].listen_port
    # Without a listener every "blocked" check would pass with a broken probe.
    if (-not (Get-NetTCPConnection -LocalAddress '::' -LocalPort $port -State Listen -ErrorAction SilentlyContinue)) {
        throw "The test node does not listen on IPv6 port $port. Restart it with Stop-RosetunTestNode and Start-RosetunTestNode."
    }
    Assert-RosetunIpv6Neighbor
    $egress = Get-RosetunEgressInterface

    Invoke-RosetunGuest -ScriptBlock {
        param($address, $index, $port)
        $client = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetworkV6)
        try {
            $client.ConnectAsync([Net.IPAddress]::Parse("$address%$index"), $port).Wait(3000)
        }
        catch {
            $false
        }
        finally {
            $client.Dispose()
        }
    } -ArgumentList ($hostAddress.IPAddress -replace '%.*$', ''), $egress.Index, $port
}

function Test-RosetunTunnelEgress {
    param(
        [string]$Url = $script:Config.TunnelProbeUrl,
        # Runs the probe from a copy of curl under another process name, for
        # checking process rules.
        [switch]$OtherProcess,
        [switch]$Detailed,
        [switch]$SkipRevocationCheck
    )
    $curl = if ($OtherProcess) { Join-Path $script:Config.GuestDir 'curl-other.exe' } else { 'curl.exe' }
    # A hostname on purpose: this also exercises the hijacked DNS path. The
    # local address proves the connection went through the tunnel; without the
    # kill switch a connection that bypasses it succeeds as well.
    $result = Invoke-RosetunGuest -ScriptBlock {
        param($url, $tunAlias, $curl, $skipRevocationCheck)
        # A missing binary would fail the probe and pass a "blocked" check.
        if (-not (Get-Command -Name $curl -ErrorAction SilentlyContinue)) {
            throw "$curl was not found in the guest."
        }
        $tunAddresses = @(Get-NetIPAddress -InterfaceAlias $tunAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            ForEach-Object { $_.IPAddress })
        $flags = @('--max-time', '10', '--silent', '--show-error', '--output', 'NUL', '--write-out', 'local=%{local_ip}')
        if ($skipRevocationCheck) {
            # The kill switch blocks Windows certificate revocation lookups outside the tunnel.
            $flags += '--ssl-no-revoke'
        }
        $output = @(& $curl @flags $url 2>&1 | ForEach-Object { "$_" })
        $exitCode = $LASTEXITCODE
        $localIp = ($output | Where-Object { $_ -like 'local=*' } | Select-Object -First 1) -replace '^local=', ''
        [pscustomobject]@{
            Ok           = $exitCode -eq 0 -and $tunAddresses -contains $localIp
            CurlExit     = $exitCode
            LocalIp      = $localIp
            TunAddresses = $tunAddresses -join ','
            Error        = ($output | Where-Object { $_ -notlike 'local=*' -and $_ }) -join ' '
        }
    } -ArgumentList $Url, $script:Config.TunAlias, $curl, [bool]$SkipRevocationCheck

    if ($Detailed) {
        return $result
    }
    return $result.Ok
}

function Wait-RosetunTunnelEgress {
    # Reports how long the first request took to get through, so a tunnel
    # that needs time after Connected shows up as a number, not a failure.
    param(
        [string]$Url = $script:Config.TunnelProbeUrl,
        [int]$TimeoutSeconds = 30,
        [switch]$SkipRevocationCheck
    )
    $watch = [Diagnostics.Stopwatch]::StartNew()
    do {
        $last = Test-RosetunTunnelEgress -Url $Url -Detailed -SkipRevocationCheck:$SkipRevocationCheck
        if ($last.Ok) {
            break
        }
        Start-Sleep -Milliseconds 500
    } while ($watch.Elapsed.TotalSeconds -lt $TimeoutSeconds)
    $last | Add-Member -NotePropertyName Seconds -NotePropertyValue ([int]$watch.Elapsed.TotalSeconds) -PassThru
}

function Measure-RosetunTunnelWarmup {
    # Probes from inside the guest right after Connected, to show which part
    # of the tunnel comes up late: TCP without DNS, the tunnel's own DNS
    # server, or DNS through the Windows resolver.
    param(
        [int]$Seconds = 30,
        [string]$HostName = 'www.example.com',
        # An address of $HostName, so the TCP probe needs no DNS.
        [string]$Address = '8.47.69.6'
    )
    Invoke-RosetunGuest -ScriptBlock {
        param($seconds, $hostName, $address, $tunAlias)
        $tunDns = (Get-DnsClientServerAddress -InterfaceAlias $tunAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses |
            Select-Object -First 1
        if (-not $tunDns) {
            $tunDns = '172.19.0.2'
        }
        $watch = [Diagnostics.Stopwatch]::StartNew()
        while ($watch.Elapsed.TotalSeconds -lt $seconds) {
            $at = [int]$watch.Elapsed.TotalSeconds
            & curl.exe --max-time 2 --silent --output NUL --resolve "${hostName}:443:$address" "https://$hostName" 2>$null
            $tcp = $LASTEXITCODE -eq 0
            $tunnelDns = [bool](Resolve-DnsName $hostName -Type A -Server $tunDns -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue |
                Where-Object { $_.Type -eq 'A' })
            $systemDns = [bool](Resolve-DnsName $hostName -Type A -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue |
                Where-Object { $_.Type -eq 'A' })
            '{0,3}s  tcp={1}  tunnel-dns={2}  system-dns={3}' -f $at, $tcp, $tunnelDns, $systemDns
            Start-Sleep -Milliseconds 500
        }
    } -ArgumentList $Seconds, $HostName, $Address, $script:Config.TunAlias
}

function Start-RosetunEgressWatch {
    # A scheduled task outlives the PowerShell Direct session that must close
    # before Save-VM. It uses the same 200 ms physical-egress probe throughout.
    $address = Get-RosetunEgressAddress
    Invoke-RosetunGuest -ScriptBlock {
        param($address, $url, $dir)
        $task = 'RosetunEgressWatch'
        $path = Join-Path $dir 'rosetun-egress-watch.txt'
        $scriptPath = Join-Path $dir 'rosetun-egress-watch.ps1'
        if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
            Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
            $deadline = (Get-Date).AddSeconds(10)
            while ((Get-ScheduledTask -TaskName $task).State -eq 'Running') {
                if ((Get-Date) -gt $deadline) { throw 'A previous egress watch did not stop.' }
                Start-Sleep -Milliseconds 200
            }
            Unregister-ScheduledTask -TaskName $task -Confirm:$false
        }
        Remove-Item -Path $path, "$path.tmp", "$path.error" -ErrorAction SilentlyContinue
        $probe = {
            param($address, $url, $path)
            $ErrorActionPreference = 'Stop'
            $probes = 0
            $leaks = 0
            try {
                while ($true) {
                    & curl.exe --interface $address --max-time 2 --silent --output NUL $url 2>$null
                    $probes++
                    if ($LASTEXITCODE -eq 0) { $leaks++ }
                    # Stop-ScheduledTask kills this process at any moment: write a
                    # temporary file and swap it in, so the counts are never empty.
                    # A reader holding the file blocks the swap; the next round retries.
                    [IO.File]::WriteAllText("$path.tmp", "$probes $leaks")
                    try { Move-Item -LiteralPath "$path.tmp" -Destination $path -Force }
                    catch { }
                    Start-Sleep -Milliseconds 200
                }
            }
            catch {
                [IO.File]::WriteAllText("$path.error", "$_")
                exit 1
            }
        }
        [IO.File]::WriteAllText($scriptPath, $probe.ToString())
        # SYSTEM does not inherit the PowerShell Direct session's execution policy.
        $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" "{1}" "{2}" "{3}"' -f `
            $scriptPath, $address, $url, $path
        $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
            -Argument $arguments -WorkingDirectory $dir
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        try {
            Register-ScheduledTask -TaskName $task -Action $action -Principal $principal `
                -Settings $settings -Force | Out-Null
            Start-ScheduledTask -TaskName $task

            # Starting a task can take longer than a reconnect; wait for its first probe.
            $deadline = (Get-Date).AddSeconds(30)
            while (-not (Test-Path -Path $path)) {
                if ((Get-Date) -gt $deadline) {
                    $state = (Get-ScheduledTask -TaskName $task).State
                    $result = (Get-ScheduledTaskInfo -TaskName $task).LastTaskResult
                    $errorText = Get-Content -Path "$path.error" -Raw -ErrorAction SilentlyContinue
                    throw "The egress watch did not record a probe within 30 seconds: task $state, result $result, script error '$errorText'."
                }
                Start-Sleep -Milliseconds 200
            }
        }
        catch {
            Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
            Remove-Item -Path $path, "$path.error", $scriptPath -ErrorAction SilentlyContinue
            throw
        }
    } -ArgumentList $address, $script:Config.ProbeUrl, $script:Config.GuestDir
}

function Stop-RosetunEgressWatch {
    Invoke-RosetunGuest -ScriptBlock {
        param($dir)
        $task = 'RosetunEgressWatch'
        $path = Join-Path $dir 'rosetun-egress-watch.txt'
        try {
            Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
            $deadline = (Get-Date).AddSeconds(10)
            while ((Get-ScheduledTask -TaskName $task).State -eq 'Running') {
                if ((Get-Date) -gt $deadline) {
                    throw 'The egress watch did not stop within 10 seconds.'
                }
                Start-Sleep -Milliseconds 200
            }
            # Move-Item -Force deletes the old counts before it moves the new ones
            # in, so a stop in between leaves only the temporary file; a process
            # that is still exiting can also hold the file for a moment.
            $counts = @()
            $deadline = (Get-Date).AddSeconds(3)
            while ($counts.Count -lt 2) {
                foreach ($candidate in $path, "$path.tmp") {
                    try { $text = [IO.File]::ReadAllText($candidate) }
                    catch { continue }
                    $counts = @($text.Trim() -split ' ')
                    if ($counts.Count -ge 2) { break }
                }
                if ($counts.Count -ge 2 -or (Get-Date) -gt $deadline) { break }
                Start-Sleep -Milliseconds 200
            }
            if ($counts.Count -lt 2) {
                $failure = Get-Content -Path "$path.error" -Raw -ErrorAction SilentlyContinue
                if ($failure) { Write-Warning "The egress watch failed: $failure" }
                else { Write-Warning 'The egress watch left no readable counts.' }
                return [pscustomobject]@{ Probes = 0; Leaks = 0 }
            }
            [pscustomobject]@{ Probes = [int]$counts[0]; Leaks = [int]$counts[1] }
        }
        finally {
            Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
            Remove-Item -Path $path, "$path.tmp", "$path.error", (Join-Path $dir 'rosetun-egress-watch.ps1') `
                -ErrorAction SilentlyContinue
        }
    } -ArgumentList $script:Config.GuestDir
}

function Restart-RosetunEgressAdapter {
    # Takes the guest's physical adapter down and up again, like a Wi-Fi
    # reconnect, and waits for DHCP to assign its IPv4 address again. Under the
    # kill switch that needs the DHCP permit to work.
    param(
        [int]$DownSeconds = 5,
        [int]$TimeoutSeconds = 60
    )
    $egress = Get-RosetunEgressInterface
    Invoke-RosetunGuest -ScriptBlock {
        param($index, $downSeconds, $timeout)
        Get-NetAdapter -InterfaceIndex $index | Disable-NetAdapter -Confirm:$false
        Start-Sleep -Seconds $downSeconds
        Get-NetAdapter -InterfaceIndex $index | Enable-NetAdapter -Confirm:$false

        $watch = [Diagnostics.Stopwatch]::StartNew()
        do {
            # An APIPA address (169.254.x.x) has the WellKnown origin, not Dhcp.
            $address = Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.PrefixOrigin -eq 'Dhcp' -and $_.AddressState -eq 'Preferred' } |
                Select-Object -First 1
            if ($null -ne $address) {
                break
            }
            Start-Sleep -Milliseconds 500
        } while ($watch.Elapsed.TotalSeconds -lt $timeout)

        $current = @(Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            ForEach-Object { "$($_.IPAddress) ($($_.PrefixOrigin), $($_.AddressState))" })
        [pscustomobject]@{
            Ok        = $null -ne $address
            Seconds   = [int]$watch.Elapsed.TotalSeconds
            Addresses = $current -join ', '
        }
    } -ArgumentList $egress.Index, $DownSeconds, $TimeoutSeconds
}

function Stop-RosetunEngine {
    Invoke-RosetunGuest -ScriptBlock {
        Stop-Process -Name 'sing-box' -Force -ErrorAction SilentlyContinue
    }
}

function Set-RosetunEngineAvailable {
    param([Parameter(Mandatory)][bool]$Available)
    # Hiding the binary is the simplest way to make the next engine start fail.
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $available)
        if ($available) {
            if (Test-Path "$dir\sing-box.exe.off") { Rename-Item "$dir\sing-box.exe.off" 'sing-box.exe' }
        }
        elseif (Test-Path "$dir\sing-box.exe") {
            Rename-Item "$dir\sing-box.exe" 'sing-box.exe.off'
        }
    } -ArgumentList $script:Config.GuestDir, $Available
}

function Test-RosetunEngineRunning {
    Invoke-RosetunGuest -ScriptBlock {
        [bool](Get-Process -Name 'sing-box' -ErrorAction SilentlyContinue)
    }
}

function Test-RosetunXrayRunning {
    Invoke-RosetunGuest -ScriptBlock {
        [bool](Get-Process -Name 'xray' -ErrorAction SilentlyContinue)
    }
}

function Stop-RosetunXrayEngine {
    Invoke-RosetunGuest -ScriptBlock {
        Stop-Process -Name 'xray' -Force -ErrorAction SilentlyContinue
    }
}

function Test-RosetunTunAdapter {
    Invoke-RosetunGuest -ScriptBlock {
        param($alias)
        [bool](Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue)
    } -ArgumentList $script:Config.TunAlias
}

function Test-RosetunProxyPath {
    # Runs the proxy outbound from the helper's last rendered config in a
    # standalone sing-box: no TUN, no WFP, no DNS hijack. Run it while
    # disconnected, otherwise the tunnel captures this traffic as well.
    param(
        [string]$Url = 'http://www.example.com',
        [string]$WriteOut = 'HTTP %{http_code}',
        [int]$Port = 2080
    )
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $url, $writeOut, $port)
        $rendered = 'C:\rosetun\data\run\sing-box\config.json'
        $proxy = (Get-Content -Path $rendered -Raw | ConvertFrom-Json).outbounds |
            Where-Object { $_.tag -eq 'proxy' }
        $config = [ordered]@{
            log       = [ordered]@{ level = 'debug'; timestamp = $true }
            inbounds  = @([ordered]@{ type = 'mixed'; listen = '127.0.0.1'; listen_port = $port })
            outbounds = @($proxy)
            route     = @{ final = 'proxy' }
        }
        $configPath = "$dir\proxy-test.json"
        $logPath = "$dir\proxy-test.log"
        # Set-Content -Encoding utf8 on PowerShell 5.1 writes a BOM, which sing-box rejects.
        [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 20))

        $engine = Start-Process -FilePath "$dir\sing-box.exe" -PassThru -NoNewWindow `
            -ArgumentList 'run', '--disable-color', '-c', $configPath `
            -RedirectStandardError $logPath -RedirectStandardOutput "$dir\proxy-test.out"
        try {
            $deadline = (Get-Date).AddSeconds(15)
            while (-not (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)) {
                if ($engine.HasExited -or (Get-Date) -gt $deadline) {
                    break
                }
                Start-Sleep -Milliseconds 200
            }
            $curl = 'sing-box did not start'
            $curlExit = $null
            if (-not $engine.HasExited) {
                # A reachability probe, not a certificate check.
                $curl = & curl.exe --max-time 15 --silent --show-error --insecure --output NUL `
                    --write-out $writeOut --proxy "socks5h://127.0.0.1:$port" $url 2>&1 |
                    ForEach-Object { "$_" }
                $curlExit = $LASTEXITCODE
            }
        }
        finally {
            # Lets sing-box log why the connection failed before it is killed.
            Start-Sleep -Seconds 1
            Stop-Process -Id $engine.Id -Force -ErrorAction SilentlyContinue
            $engine.WaitForExit(5000) | Out-Null
            Remove-Item -Path $configPath -ErrorAction SilentlyContinue
        }
        [pscustomobject]@{
            CurlExit = $curlExit
            Curl     = $curl -join "`n"
            Log      = (Get-Content -Path $logPath -Tail 30 -ErrorAction SilentlyContinue) -join "`n"
        }
    } -ArgumentList $script:Config.GuestDir, $Url, $WriteOut, $Port
}

function Save-RosetunLogs {
    # Copies every helper log from the guest, the current one and those of
    # earlier helper runs, into a fresh folder on the host.
    param([string]$Destination = (Join-Path $PSScriptRoot ("logs\" + (Get-Date -Format 'yyyyMMdd-HHmmss'))))

    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    # The running helper keeps helper.log open, so Copy-Item cannot read it
    # directly. Snapshot every log on the guest with shared read access first.
    $snapshot = Invoke-RosetunGuest -ScriptBlock {
        param($dir)
        $snapshot = Join-Path $env:TEMP ('rosetun-logs-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $snapshot | Out-Null
        foreach ($log in Get-ChildItem -Path $dir -Filter 'helper*.log' -File) {
            try {
                $source = [IO.File]::Open($log.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read,
                    [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
                try {
                    $target = [IO.File]::Create((Join-Path $snapshot $log.Name))
                    try { $source.CopyTo($target) } finally { $target.Dispose() }
                }
                finally { $source.Dispose() }
            }
            catch {
                Write-Warning "Could not copy $($log.Name): $($_.Exception.Message)"
            }
        }
        $snapshot
    } -ArgumentList $script:Config.GuestDir
    try {
        Copy-Item -FromSession (Connect-RosetunVm) -Path (Join-Path $snapshot '*.log') `
            -Destination $Destination -ErrorAction Continue
    }
    finally {
        Invoke-RosetunGuest -ScriptBlock {
            param($snapshot)
            Remove-Item -Path $snapshot -Recurse -Force -ErrorAction SilentlyContinue
        } -ArgumentList $snapshot
    }
    # The host-side node log, written when the node runs via Start-RosetunTestNode.
    Copy-Item -Path (Join-Path $PSScriptRoot 'logs\test-node.log') -Destination $Destination -ErrorAction SilentlyContinue
    return $Destination
}

function Get-RosetunHelperLog {
    param([int]$Tail = 40)
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $tail)
        Get-Content -Path "$dir\helper.log" -Tail $tail -ErrorAction SilentlyContinue
    } -ArgumentList $script:Config.GuestDir, $Tail
}

function Invoke-RosetunConnectionsDuring {
    # The service collects the connection list only while it is read and keeps
    # a closed connection only if it was read before it closed, so a poller
    # reads the list during the whole request. The service polls the engine
    # four times a second: a single quick request can open and close between
    # two polls and never be seen, so curl fetches the page twelve times, two
    # a second, at a limited rate, over one kept-alive connection that lives
    # about six seconds. The CLI prints what it reads 1.5 s after it starts.
    # Returns the `rosetun connections` output read in the middle of the
    # request, where the connection is active, followed by the one read after
    # it ended, where it is closed. -ConfigPath is the configuration the CLI
    # explains routes with (its RULE column).
    param(
        [Parameter(Mandatory)][string]$Url,
        [switch]$SkipRevocationCheck,
        [string]$ConfigPath
    )
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $url, $skipRevocationCheck, $configPath)
        # Set before the poller starts, so its process inherits it too.
        if ($configPath) {
            $env:ROSETUN_CONFIG = $configPath
        }
        $cli = Join-Path $dir 'rosetun.exe'
        $poller = Start-Job -ScriptBlock {
            param($cli)
            while ($true) { & $cli connections *> $null }
        } -ArgumentList $cli
        $curl = $null
        try {
            Start-Sleep -Seconds 3
            $flags = @('--max-time', '10', '--silent', '--rate', '2/s', '--limit-rate', '20k')
            if ($skipRevocationCheck) {
                $flags += '--ssl-no-revoke'
            }
            foreach ($fetch in 1..12) {
                $flags += @('--output', 'NUL', $url)
            }
            $start = [Diagnostics.ProcessStartInfo]::new((Get-Command -Name curl.exe -ErrorAction Stop).Source,
                ($flags -join ' '))
            $start.UseShellExecute = $false
            $curl = [Diagnostics.Process]::Start($start)
            Start-Sleep -Seconds 1
            $during = @(& $cli connections 2>&1 | ForEach-Object { "$_" })
            $duringExit = $LASTEXITCODE
            if (-not $curl.WaitForExit(60000)) {
                $curl.Kill()
                $curl.WaitForExit()
            }
            $curlExit = $curl.ExitCode
            Start-Sleep -Seconds 2
            $after = @(& $cli connections 2>&1 | ForEach-Object { "$_" })
            $exitCode = if ($duringExit -ne 0) { $duringExit } else { $LASTEXITCODE }
            $output = $during + $after
        }
        finally {
            if ($curl) {
                $curl.Dispose()
            }
            Stop-Job -Job $poller -ErrorAction SilentlyContinue
            Remove-Job -Job $poller -Force -ErrorAction SilentlyContinue
            Remove-Item Env:ROSETUN_CONFIG -ErrorAction SilentlyContinue
        }
        $global:LASTEXITCODE = 0
        [pscustomobject]@{ CurlExit = $curlExit; ExitCode = $exitCode; Output = ($output -join "`n") }
    } -ArgumentList $script:Config.GuestDir, $Url, [bool]$SkipRevocationCheck, $ConfigPath
}

function Get-RosetunConnectionRows {
    # Rows of `rosetun connections`: STATE ID NET ROUTE DOWN UP SECONDS DESTINATION PROGRAM RULE.
    param([string]$Output)
    @($Output -split '\r?\n' | Where-Object { $_ -match '^(active|closed)\t' } | ForEach-Object {
            $columns = $_ -split "`t"
            [pscustomobject]@{
                State = $columns[0]
                Id = $columns[1]
                Route = $columns[3]
                Destination = $columns[7]
                Program = $columns[8]
                Rule = if ($columns.Count -gt 9) { $columns[9] } else { $null }
            }
        })
}

function Invoke-RosetunConnectionClose {
    # Starts one long download through the tunnel at a limited rate, finds it
    # in `rosetun connections` by host (curl's own row when the engine named
    # the program) and closes it with `rosetun connections close <id>`. A
    # poller keeps the list collected the whole time, so the closed connection
    # is kept. Without the close curl would stop only at --max-time (exit 28).
    # Returns the id, the close command's result, curl's exit code and run
    # time, and the list read after curl ended.
    param([Parameter(Mandatory)][string]$Url)
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $url)
        $cli = Join-Path $dir 'rosetun.exe'
        $hostName = ([uri]$url).Host
        $poller = Start-Job -ScriptBlock {
            param($cli)
            while ($true) { & $cli connections *> $null }
        } -ArgumentList $cli
        $curl = $null
        $id = ''
        $closeExit = $null
        $closeOutput = ''
        $curlExit = $null
        $seconds = $null
        $after = @()
        try {
            Start-Sleep -Seconds 3
            $flags = @('--max-time', '60', '--silent', '--limit-rate', '100k', '--output', 'NUL', $url)
            $start = [Diagnostics.ProcessStartInfo]::new((Get-Command -Name curl.exe -ErrorAction Stop).Source,
                ($flags -join ' '))
            $start.UseShellExecute = $false
            $watch = [Diagnostics.Stopwatch]::StartNew()
            $curl = [Diagnostics.Process]::Start($start)
            Start-Sleep -Seconds 3
            $during = @(& $cli connections 2>&1 | ForEach-Object { "$_" })
            $rows = @(foreach ($line in $during) {
                    $columns = $line -split "`t"
                    if ($columns.Count -ge 9 -and $columns[0] -eq 'active' -and
                        $columns[7] -like "${hostName}:*" -and $columns[1] -ne '-') {
                        [pscustomobject]@{ Id = $columns[1]; Program = $columns[8] }
                    }
                })
            $row = @($rows | Where-Object { $_.Program -like '*\curl.exe' }) + $rows | Select-Object -First 1
            if ($row) {
                $id = $row.Id
                $closeOutput = @(& $cli connections close $id 2>&1 | ForEach-Object { "$_" }) -join "`n"
                $closeExit = $LASTEXITCODE
            }
            else {
                $closeOutput = "no active row for ${hostName}: " + (($during | Select-Object -First 10) -join ' | ')
            }
            if (-not $curl.WaitForExit(90000)) {
                $curl.Kill()
                $curl.WaitForExit()
            }
            $seconds = [math]::Round($watch.Elapsed.TotalSeconds, 1)
            $curlExit = $curl.ExitCode
            Start-Sleep -Seconds 2
            $after = @(& $cli connections 2>&1 | ForEach-Object { "$_" })
        }
        finally {
            if ($curl) {
                if (-not $curl.HasExited) { $curl.Kill() }
                $curl.Dispose()
            }
            Stop-Job -Job $poller -ErrorAction SilentlyContinue
            Remove-Job -Job $poller -Force -ErrorAction SilentlyContinue
        }
        $global:LASTEXITCODE = 0
        [pscustomobject]@{
            Id = $id
            CloseExit = $closeExit
            CloseOutput = $closeOutput
            CurlExit = $curlExit
            CurlSeconds = $seconds
            After = ($after -join "`n")
        }
    } -ArgumentList $script:Config.GuestDir, $Url
}

function Find-RosetunLogText {
    # Every helper log of the guest, console runs and the service's data folder,
    # searched for $Text as a whole host name, or anywhere with -Anywhere (for
    # the start of an id). Returns the names of matching files, with -WithLine
    # as name:line of the first match (never the line itself, which may be the leak).
    # -SinceUtcTicks (guest clock) skips logs last written before it, such as earlier runs'.
    param(
        [Parameter(Mandatory)][string]$Text,
        [switch]$Anywhere,
        [switch]$WithLine,
        [Nullable[long]]$SinceUtcTicks
    )
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $text, $anywhere, $withLine, $sinceUtcTicks)
        $pattern = if ($anywhere) {
            '(?i)' + [regex]::Escape($text)
        }
        else {
            '(?i)(?<![a-z0-9.-])' + [regex]::Escape($text) + '(?![a-z0-9-])'
        }
        $logs = @(Get-ChildItem -Path $dir -Filter 'helper*.log' -File -ErrorAction SilentlyContinue) +
            @(Get-ChildItem -Path (Join-Path $dir 'data\logs') -File -ErrorAction SilentlyContinue)
        foreach ($log in $logs) {
            if ($sinceUtcTicks -and $log.LastWriteTimeUtc.Ticks -lt $sinceUtcTicks) {
                continue
            }
            $stream = [IO.File]::Open($log.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read,
                [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
            try {
                $content = [IO.StreamReader]::new($stream).ReadToEnd()
            }
            finally { $stream.Dispose() }
            $match = [regex]::Match($content, $pattern)
            if (-not $match.Success) {
                continue
            }
            if ($withLine) {
                $line = [regex]::Matches($content.Substring(0, $match.Index), "`n").Count + 1
                "$($log.Name):$line"
            }
            else {
                $log.Name
            }
        }
    } -ArgumentList $script:Config.GuestDir, $Text, [bool]$Anywhere, [bool]$WithLine, $SinceUtcTicks
}

function Test-RosetunGuestLoopback {
    # Loopback must keep working under a Lockdown block: local services use it.
    Invoke-RosetunGuest -ScriptBlock {
        $results = foreach ($address in [Net.IPAddress]::Loopback, [Net.IPAddress]::IPv6Loopback) {
            $listener = [Net.Sockets.TcpListener]::new($address, 0)
            $client = [Net.Sockets.TcpClient]::new($address.AddressFamily)
            try {
                $listener.Start()
                $client.ConnectAsync($address, ([Net.IPEndPoint]$listener.LocalEndpoint).Port).Wait(3000)
            }
            catch { $false }
            finally {
                $client.Dispose()
                $listener.Stop()
            }
        }
        -not ($results -contains $false)
    }
}

function Get-RosetunGuestLease {
    # The DHCP address and default route of the guest, or why there is none.
    Invoke-RosetunGuest -ScriptBlock {
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1
        $addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceAlias -notlike 'Loopback*' })
        $dhcp = $addresses | Where-Object { $_.PrefixOrigin -eq 'Dhcp' -and $_.IPAddress -notlike '169.254.*' } |
            Select-Object -First 1
        [pscustomobject]@{
            Leased = [bool]($route -and $dhcp)
            Note   = "route=$([bool]$route) ipv4=$(($addresses | ForEach-Object { "$($_.IPAddress)/$($_.PrefixOrigin)" }) -join ',')"
        }
    }
}

function Restore-RosetunGuestLease {
    # A boot under a boot-time block lost the DHCP lease on the VM, and the
    # DHCP client only retries every few minutes on its own.
    Invoke-RosetunGuest -ScriptBlock {
        if (-not (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)) {
            & ipconfig.exe /renew *> $null
            $global:LASTEXITCODE = 0
        }
    }
    $leased = Wait-RosetunCondition {
        [bool](Invoke-RosetunGuest -ScriptBlock { Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue })
    } -TimeoutSeconds 90
    if (-not $leased) {
        throw 'The guest got no default route back within 90 s.'
    }
}

function Test-RosetunDhcpRenew {
    # Renews the lease of the default-route adapter; under a block without a
    # DHCP permit this loses the address.
    Invoke-RosetunGuest -ScriptBlock {
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object -Property RouteMetric | Select-Object -First 1
        $alias = $route.InterfaceAlias
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $output = (& ipconfig.exe /renew $alias 2>&1 | Out-String).Trim() -replace '\s+', ' '
        $exitCode = $LASTEXITCODE
        $global:LASTEXITCODE = 0
        $lease = Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.PrefixOrigin -eq 'Dhcp' } | Select-Object -First 1
        [pscustomobject]@{
            Renewed = $exitCode -eq 0 -and [bool]$lease
            Note    = "renew exit $exitCode after $([int]$watch.Elapsed.TotalSeconds) s, DHCP address kept: $([bool]$lease); $output"
        }
    }
}

function Test-RosetunIpv6Open {
    # Re-pins first: a reboot drops the guest's ActiveStore entry.
    param([Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Neighbors)
    Set-RosetunIpv6Neighbor -Created $Neighbors
    Test-RosetunIpv6Egress
}

function Test-RosetunGuestWfpKey {
    # Whether a WFP object with this key (provider, sublayer or filter) exists.
    param([Parameter(Mandatory)][string]$Key)
    Invoke-RosetunGuest -ScriptBlock {
        param($key)
        $path = Join-Path $env:TEMP ("rosetun-wfp-$([guid]::NewGuid().ToString('N')).xml")
        try {
            & netsh.exe wfp show state "file=$path" *> $null
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $path)) {
                throw 'Cannot inspect WFP state.'
            }
            (Get-Content -Raw -LiteralPath $path) -match [regex]::Escape($key)
        }
        finally {
            Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue
            $global:LASTEXITCODE = 0
        }
    } -ArgumentList $Key
}

function Get-RosetunGuestBootTime {
    # A string, so the boot check in the guest can write the same value.
    Invoke-RosetunGuest -ScriptBlock {
        (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
    }
}

function Restart-RosetunGuest {
    # -PowerCut turns the VM off instead, as a power cut would. -Label names
    # the step in the warning when the guest does not come back.
    param([switch]$PowerCut, [string]$Label = 'restart')
    $before = Get-RosetunGuestBootTime
    if ($PowerCut) {
        Disconnect-RosetunVm
        Stop-VM -Name $script:Config.VmName -TurnOff -Force
        Start-VM -Name $script:Config.VmName
    }
    else {
        try { Invoke-RosetunGuest -ScriptBlock { Restart-Computer -Force } }
        catch { }
        Disconnect-RosetunVm
    }
    # Connecting too early would reach the guest before it went down.
    $back = {
        $deadline = (Get-Date).AddMinutes(5)
        while ((Get-Date) -lt $deadline) {
            try {
                if ((Get-RosetunGuestBootTime) -ne $before) { return $true }
            }
            catch {
                try { Disconnect-RosetunVm } catch { }
            }
            Start-Sleep -Seconds 5
        }
        $false
    }
    if (& $back) { return }
    if (-not $PowerCut) {
        throw 'The guest did not come back within 5 minutes.'
    }
    # Several cuts in a row left the guest stuck at boot without a single
    # System event; a second cold start brought it back. The screen is the
    # only evidence of where it stopped.
    $screenshot = try { Save-RosetunGuestScreenshot } catch { "no screenshot: $_" }
    $script:ColdStartRetries++
    Write-Warning "${Label}: the guest did not come back within 5 minutes; turning it off and on once more. Screen: $screenshot"
    Disconnect-RosetunVm
    Stop-VM -Name $script:Config.VmName -TurnOff -Force
    Start-VM -Name $script:Config.VmName
    if (-not (& $back)) {
        throw 'The guest did not come back within 5 minutes, also after a second cold start.'
    }
}

function Get-RosetunColdStartRetries {
    $script:ColdStartRetries
}

function Save-RosetunGuestScreenshot {
    # Saves what the VM's screen shows as tools/vm/logs/guest-stuck-<time>.png
    # and returns the path.
    param([int]$Width = 1024, [int]$Height = 768)
    $namespace = 'root\virtualization\v2'
    $vm = Get-CimInstance -Namespace $namespace -ClassName Msvm_ComputerSystem `
        -Filter "ElementName='$($script:Config.VmName)'"
    $settings = Get-CimAssociatedInstance -InputObject $vm -ResultClassName Msvm_VirtualSystemSettingData |
        Where-Object { $_.VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized' } |
        Select-Object -First 1
    $service = Get-CimInstance -Namespace $namespace -ClassName Msvm_VirtualSystemManagementService
    $thumbnail = Invoke-CimMethod -InputObject $service -MethodName GetVirtualSystemThumbnailImage -Arguments @{
        TargetSystem = $settings
        WidthPixels  = [uint16]$Width
        HeightPixels = [uint16]$Height
    }
    if ($thumbnail.ReturnValue -ne 0 -or -not $thumbnail.ImageData) {
        throw "GetVirtualSystemThumbnailImage returned $($thumbnail.ReturnValue)."
    }
    # The image is RGB565, two bytes a pixel, rows without padding.
    [byte[]]$pixels = $thumbnail.ImageData
    Add-Type -AssemblyName System.Drawing
    $format = [Drawing.Imaging.PixelFormat]::Format16bppRgb565
    $bitmap = [Drawing.Bitmap]::new($Width, $Height, $format)
    try {
        $data = $bitmap.LockBits([Drawing.Rectangle]::new(0, 0, $Width, $Height),
            [Drawing.Imaging.ImageLockMode]::WriteOnly, $format)
        try {
            for ($row = 0; $row -lt $Height; $row++) {
                [Runtime.InteropServices.Marshal]::Copy($pixels, $row * $Width * 2,
                    [IntPtr]::Add($data.Scan0, $row * $data.Stride), $Width * 2)
            }
        }
        finally { $bitmap.UnlockBits($data) }
        $dir = Join-Path $PSScriptRoot 'logs'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $path = Join-Path $dir "guest-stuck-$(Get-Date -Format 'yyyyMMdd-HHmmss').png"
        $bitmap.Save($path, [Drawing.Imaging.ImageFormat]::Png)
        $path
    }
    finally { $bitmap.Dispose() }
}

function Wait-RosetunGuest {
    # Drops a session that may have died with the guest, starts a VM that is
    # off and waits until the guest answers again.
    param([int]$TimeoutSeconds = 300)
    try { Disconnect-RosetunVm } catch { }
    if ((Get-VM -Name $script:Config.VmName).State -ne 'Running') {
        Start-VM -Name $script:Config.VmName
    }
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        try {
            Invoke-RosetunGuest -ScriptBlock { $true } | Out-Null
            return
        }
        catch {
            try { Disconnect-RosetunVm } catch { }
            if ((Get-Date) -gt $deadline) {
                throw "The guest did not answer within $TimeoutSeconds s: $_"
            }
        }
        Start-Sleep -Seconds 5
    }
}

function Disable-RosetunBootRecovery {
    # After several power cuts in a row Windows stops at a recovery screen
    # instead of booting. Returns the previous values for
    # Restore-RosetunBootRecovery; an absent value is $null.
    # The BCD store is a registry hive with the same lazy flush as BFE's
    # policy: a power cut soon after bcdedit can lose the change, and the guest
    # still stopped at Automatic Repair. A clean restart writes it to disk;
    # the caller starts the helper again afterwards.
    $saved = Invoke-RosetunGuest -ScriptBlock {
        $current = (& bcdedit.exe /enum '{current}' | Out-String) -split "`r?`n"
        $saved = @{}
        foreach ($name in 'bootstatuspolicy', 'recoveryenabled') {
            $line = $current | Where-Object { $_ -match "^$name\s+(\S+)" } | Select-Object -First 1
            $saved[$name] = if ($line -and $line -match "^$name\s+(\S+)") { $Matches[1] } else { $null }
        }
        foreach ($pair in @(@('bootstatuspolicy', 'ignoreallfailures'), @('recoveryenabled', 'no'))) {
            & bcdedit.exe /set '{current}' $pair[0] $pair[1] | Out-Null
            $exitCode = $LASTEXITCODE
            $global:LASTEXITCODE = 0
            if ($exitCode -ne 0) { throw "bcdedit /set $($pair[0]) failed with exit code $exitCode." }
        }
        [pscustomobject]$saved
    }
    Restart-RosetunGuest -Label 'boot recovery off'
    $saved
}

function Restore-RosetunBootRecovery {
    param([Parameter(Mandatory)]$Saved)
    Invoke-RosetunGuest -ScriptBlock {
        param($policy, $recovery)
        # bcdedit prints booleans in the display language.
        $recovery = switch -Regex ($recovery) {
            '^(yes|\u0434\u0430)$' { 'yes' }
            '^(no|\u043d\u0435\u0442)$' { 'no' }
            default { $recovery }
        }
        foreach ($pair in @(@('bootstatuspolicy', $policy), @('recoveryenabled', $recovery))) {
            if ($pair[1]) {
                & bcdedit.exe /set '{current}' $pair[0] $pair[1] | Out-Null
            }
            else {
                & bcdedit.exe /deletevalue '{current}' $pair[0] | Out-Null
            }
        }
        $global:LASTEXITCODE = 0
    } -ArgumentList $Saved.bootstatuspolicy, $Saved.recoveryenabled
}

function Register-RosetunBootCheck {
    # Runs as SYSTEM at startup, before anyone signs in: an AtLogOn task would
    # never fire, because PowerShell Direct is not an interactive sign-in. It
    # records for up to 150 s whether the guest has a route and whether curl
    # reaches -Url; Get-RosetunBootCheck reads the result.
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$TaskName,
        [string]$Url = $script:Config.ProbeUrl
    )
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $task, $url)
        $script = @'
param($result, $url)
$bootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$attempts = [System.Collections.Generic.List[object]]::new()
$deadline = (Get-Date).AddSeconds(150)
$withRoute = 0
while ((Get-Date) -lt $deadline -and $withRoute -lt 3) {
    $uptime = [int]((Get-Date) - $bootTime).TotalSeconds
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1
    $address = if ($route) {
        Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.AddressState -eq 'Preferred' } | Select-Object -First 1
    }
    $curlExit = $null
    $curlError = ''
    if ($address) {
        $withRoute++
        $curlError = (& curl.exe --max-time 5 --silent --show-error --output NUL $url 2>&1 | ForEach-Object { "$_" }) -join ' '
        $curlExit = $LASTEXITCODE
    }
    $attempts.Add([pscustomobject]@{
        Uptime    = $uptime
        Route     = [bool]$address
        CurlExit  = $curlExit
        CurlError = $curlError
        User      = "$((Get-CimInstance Win32_ComputerSystem).UserName)"
        Bfe       = "$((Get-Service -Name BFE).Status)"
        Addresses = (@(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceAlias -notlike 'Loopback*' } |
            ForEach-Object { "$($_.IPAddress)/$($_.PrefixOrigin)/$($_.AddressState)" }) -join ',')
    })
    if ($withRoute -lt 3) { Start-Sleep -Seconds 3 }
}
# Tagged with the boot it belongs to: a power cut can undo the deletion of the
# previous result, which the scenario must not mistake for this one. Written
# to a temporary file first, so a reader never sees half of it.
$record = [pscustomobject]@{ BootTime = $bootTime.ToUniversalTime().ToString('o'); Attempts = $attempts }
$record | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath "$result.tmp" -Encoding UTF8
Move-Item -LiteralPath "$result.tmp" -Destination $result -Force
'@
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $scriptPath = Join-Path $dir 'boot-check.ps1'
        $resultPath = Join-Path $dir 'boot-check.json'
        Set-Content -LiteralPath $scriptPath -Value $script -Encoding UTF8
        Remove-Item -LiteralPath $resultPath -ErrorAction SilentlyContinue
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -result `"$resultPath`" -url `"$url`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(5)) `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $principal `
            -Settings $settings -Force | Out-Null
    } -ArgumentList $Directory, $TaskName, $Url
}

function Unregister-RosetunBootCheck {
    param([Parameter(Mandatory)][string]$TaskName)
    Invoke-RosetunGuest -ScriptBlock {
        param($task)
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
    } -ArgumentList $TaskName
}

function Get-RosetunBootCheck {
    # The boot check's attempts of the boot that started at -BootTime.
    param([Parameter(Mandatory)][string]$Directory, [Parameter(Mandatory)][string]$BootTime)
    $deadline = (Get-Date).AddMinutes(4)
    $stale = $false
    while ((Get-Date) -lt $deadline) {
        $json = Invoke-RosetunGuest -ScriptBlock {
            param($path)
            if (Test-Path -LiteralPath $path) { Get-Content -Raw -LiteralPath $path }
        } -ArgumentList (Join-Path $Directory 'boot-check.json')
        if ($json) {
            $record = $json | ConvertFrom-Json
            if ($record.BootTime -eq $BootTime) { return @($record.Attempts) }
            $stale = $true
        }
        Start-Sleep -Seconds 5
    }
    if ($stale) {
        throw "The boot check left only a result of an earlier boot (current boot $BootTime): the task did not run or its result was lost."
    }
    throw 'The boot check wrote no result within 4 minutes.'
}

function Format-RosetunBootCheck {
    param([Parameter(Mandatory)][object[]]$Attempts)
    ($Attempts | ForEach-Object {
        "t=$($_.Uptime)s route=$($_.Route) curl=$($_.CurlExit) user='$($_.User)' bfe=$($_.Bfe) ipv4=$($_.Addresses) $($_.CurlError)"
    }) -join '; '
}

function Get-RosetunEgressAfterBoot {
    try {
        if (Test-RosetunDirectEgress) { 'open' } else { 'closed' }
    }
    catch {
        if ("$_" -notmatch 'No default route') { throw }
        'no default route'
    }
}

function Find-RosetunFreeAddress {
    # An unused address near the top of the Default Switch subnet: the switch's
    # DHCP hands out addresses from the bottom.
    param([Parameter(Mandatory)][string]$Address, [Parameter(Mandatory)][int]$PrefixLength)
    $bytes = [Net.IPAddress]::Parse($Address).GetAddressBytes()
    [Array]::Reverse($bytes)
    $value = [BitConverter]::ToUInt32($bytes, 0)
    $hostBits = 32 - $PrefixLength
    $network = [uint32](($value -shr $hostBits) -shl $hostBits)
    $broadcast = [uint32]($network + [math]::Pow(2, $hostBits) - 1)
    $ping = [Net.NetworkInformation.Ping]::new()
    try {
        for ($candidate = $broadcast - 1; $candidate -gt $broadcast - 20; $candidate--) {
            $octets = [BitConverter]::GetBytes([uint32]$candidate)
            [Array]::Reverse($octets)
            $text = ([Net.IPAddress]::new($octets)).ToString()
            if ($text -eq $Address -or (Get-NetIPAddress -IPAddress $text -ErrorAction SilentlyContinue)) { continue }
            if ($ping.Send($text, 500).Status -eq 'Success') { continue }
            return $text
        }
    }
    finally { $ping.Dispose() }
    throw "No free address near the top of the Default Switch subnet of $Address/$PrefixLength."
}

function Start-RosetunNameZone {
    # A DNS responder for the zone rosetun.test (`.test` is reserved, RFC 2606)
    # and an HTTP server for one subscription file, both on the host, so the
    # guest reaches the test node and a subscription by name. node.rosetun.test
    # and sub.rosetun.test point to the host's Default Switch address; other
    # names in the zone get NXDOMAIN and names outside it REFUSED. TTL 0, so
    # no resolver caches an answer from one scenario into the next.
    param([Parameter(Mandatory)][string]$SubscriptionBody)

    $alias = 'vEthernet (Default Switch)'
    $ip = Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -AddressState Preferred -ErrorAction Stop |
        Where-Object { $_.IPAddress -notlike '169.254.*' } |
        Select-Object -First 1
    if (-not $ip) { throw 'The Default Switch has no usable IPv4 address.' }
    $zone = [pscustomobject]@{
        HostAddress     = $ip.IPAddress
        DnsAddress      = $ip.IPAddress
        AddedAddress    = $null
        HttpPort        = 0
        SubscriptionUrl = $null
        RuleNames       = [System.Collections.Generic.List[string]]::new()
        Job             = $null
    }
    try {
        # Internet Connection Sharing answers DNS for the Default Switch on the
        # host's own address, so 53 there is usually taken. The responder then
        # gets a second address on the same adapter; the guest reaches it on-link.
        $free = try {
            [Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Parse($zone.HostAddress), 53)).Close()
            $true
        }
        catch { $false }
        if (-not $free) {
            $zone.DnsAddress = Find-RosetunFreeAddress -Address $zone.HostAddress -PrefixLength $ip.PrefixLength
            New-NetIPAddress -InterfaceAlias $alias -IPAddress $zone.DnsAddress -PrefixLength $ip.PrefixLength `
                -SkipAsSource $true -ErrorAction Stop | Out-Null
            $zone.AddedAddress = $zone.DnsAddress
            $ready = Wait-RosetunCondition {
                (Get-NetIPAddress -IPAddress $zone.DnsAddress -ErrorAction SilentlyContinue).AddressState -eq 'Preferred'
            } -TimeoutSeconds 15
            if (-not $ready) { throw "The second address $($zone.DnsAddress) did not become usable." }
            Write-Host "Port 53 on $($zone.HostAddress) is taken (ICS); the name zone answers on $($zone.DnsAddress)."
        }

        $probe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse($zone.HostAddress), 0)
        $probe.Start()
        $zone.HttpPort = ([Net.IPEndPoint]$probe.LocalEndpoint).Port
        $probe.Stop()
        $zone.SubscriptionUrl = "http://sub.rosetun.test:$($zone.HttpPort)/sub"

        foreach ($rule in @(
                @{ Protocol = 'UDP'; Address = $zone.DnsAddress; Port = 53 },
                @{ Protocol = 'TCP'; Address = $zone.HostAddress; Port = $zone.HttpPort })) {
            $name = "Rosetun-name-zone-$([guid]::NewGuid().ToString('N'))"
            New-NetFirewallRule -Name $name -DisplayName 'Rosetun name zone' -Direction Inbound -Action Allow `
                -Protocol $rule.Protocol -LocalAddress $rule.Address -LocalPort $rule.Port `
                -InterfaceAlias $alias -Profile Any -ErrorAction Stop | Out-Null
            $zone.RuleNames.Add($name)
        }

        $zone.Job = Start-Job -ArgumentList $zone.DnsAddress, $zone.HostAddress, $zone.HttpPort, $SubscriptionBody -ScriptBlock {
            param($dnsAddress, $hostAddress, $httpPort, $body)
            $ErrorActionPreference = 'Stop'
            $hostBytes = [Net.IPAddress]::Parse($hostAddress).GetAddressBytes()
            $content = [Text.Encoding]::UTF8.GetBytes($body)
            $udp = [Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Parse($dnsAddress), 53))
            # SIO_UDP_CONNRESET off: a reply to a port already closed would
            # otherwise fail the next receive with WSAECONNRESET.
            [void]$udp.Client.IOControl(-1744830452, [byte[]]@(0, 0, 0, 0), $null)
            $http = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse($hostAddress), $httpPort)
            $http.Start()
            'ready'
            $receive = $udp.ReceiveAsync()
            $accept = $http.AcceptTcpClientAsync()
            while ($true) {
                $index = [Threading.Tasks.Task]::WaitAny([Threading.Tasks.Task[]]@($receive, $accept))
                if ($index -eq 0) {
                    $received = $receive
                    $receive = $udp.ReceiveAsync()
                    if ($received.IsFaulted) {
                        "receive failed: $($received.Exception.InnerException.Message)"
                        continue
                    }
                    $packet = $received.Result.Buffer
                    $peer = $received.Result.RemoteEndPoint
                    $offset = 12
                    $labels = @()
                    while ($offset -lt $packet.Length -and $packet[$offset] -ne 0 -and
                        $offset + 1 + $packet[$offset] -le $packet.Length) {
                        $labels += [Text.Encoding]::ASCII.GetString($packet, $offset + 1, $packet[$offset])
                        $offset += 1 + $packet[$offset]
                    }
                    if ($offset + 5 -gt $packet.Length) { continue }
                    $name = ($labels -join '.').ToLowerInvariant()
                    $type = $packet[$offset + 1] * 256 + $packet[$offset + 2]
                    $answers = 0
                    $rcode = 0
                    if ($name -in @('node.rosetun.test', 'sub.rosetun.test')) {
                        if ($type -eq 1) { $answers = 1 }
                    }
                    elseif ($name -eq 'rosetun.test' -or $name.EndsWith('.rosetun.test')) { $rcode = 3 }
                    else { $rcode = 5 }
                    [byte[]]$reply = @($packet[0], $packet[1], 0x81, (0x80 -bor $rcode), 0, 1, 0, $answers, 0, 0, 0, 0) +
                        $packet[12..($offset + 4)]
                    if ($answers) {
                        # The question's name by pointer, type A, class IN, TTL 0.
                        $reply += [byte[]]@(0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4) + $hostBytes
                    }
                    [void]$udp.Send($reply, $reply.Length, $peer)
                }
                else {
                    $client = $accept.Result
                    $accept = $http.AcceptTcpClientAsync()
                    try {
                        $client.ReceiveTimeout = 3000
                        $stream = $client.GetStream()
                        $buffer = [byte[]]::new(8192)
                        $read = 0
                        do {
                            $count = $stream.Read($buffer, $read, $buffer.Length - $read)
                            $read += $count
                        } while ($count -gt 0 -and $read -lt $buffer.Length -and
                            -not [Text.Encoding]::ASCII.GetString($buffer, 0, $read).Contains("`r`n`r`n"))
                        $head = [Text.Encoding]::ASCII.GetBytes(
                            "HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nContent-Length: $($content.Length)`r`nConnection: close`r`n`r`n")
                        $stream.Write($head, 0, $head.Length)
                        $stream.Write($content, 0, $content.Length)
                    }
                    catch { }
                    finally { $client.Close() }
                }
            }
        }
        $ready = Wait-RosetunCondition {
            $zone.Job.State -ne 'Running' -or (@(Receive-Job -Job $zone.Job -Keep) -contains 'ready')
        } -TimeoutSeconds 30
        if (-not $ready -or $zone.Job.State -ne 'Running') {
            $reason = try { Receive-Job -Job $zone.Job -Keep 2>&1 | Out-String } catch { "$_" }
            throw "The name zone did not start: $reason"
        }
        Write-Host "Name zone rosetun.test on $($zone.DnsAddress):53, subscription at $($zone.SubscriptionUrl)"
        return $zone
    }
    catch {
        Stop-RosetunNameZone -Zone $zone
        throw
    }
}

function Stop-RosetunNameZone {
    param([Parameter(Mandatory)]$Zone)
    if ($Zone.Job) {
        Stop-Job -Job $Zone.Job -ErrorAction SilentlyContinue
        Remove-Job -Job $Zone.Job -Force -ErrorAction SilentlyContinue
    }
    foreach ($name in $Zone.RuleNames) {
        Remove-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
    }
    if ($Zone.AddedAddress) {
        Remove-NetIPAddress -IPAddress $Zone.AddedAddress -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Set-RosetunGuestResolver {
    # Points the guest's physical adapter at one IPv4 DNS server and returns
    # what to restore.
    param([Parameter(Mandatory)][string]$Server)
    $index = (Get-RosetunEgressInterface).Index
    Invoke-RosetunGuest -ScriptBlock {
        param($index, $server)
        $saved = @((Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv4).ServerAddresses)
        Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $server
        Clear-DnsClientCache
        [pscustomobject]@{ Index = $index; Servers = $saved }
    } -ArgumentList $index, $Server
}

function Restore-RosetunGuestResolver {
    # Back to the DHCP servers, or to the static ones the adapter had.
    param([Parameter(Mandatory)]$Saved)
    Invoke-RosetunGuest -ScriptBlock {
        param($index, [string[]]$servers)
        Set-DnsClientServerAddress -InterfaceIndex $index -ResetServerAddresses
        $now = @((Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv4).ServerAddresses)
        if ($servers.Count -gt 0 -and (Compare-Object -ReferenceObject $now -DifferenceObject $servers)) {
            Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $servers
        }
        Clear-DnsClientCache
    } -ArgumentList $Saved.Index, ([string[]]@($Saved.Servers))
}

function Test-RosetunGuestSystemResolver {
    # True when the system resolver (the Dnscache service) answers $Name.
    param([Parameter(Mandatory)][string]$Name)
    Invoke-RosetunGuest -ScriptBlock {
        param($name)
        Clear-DnsClientCache
        try {
            @(Resolve-DnsName -Name $name -Type A -DnsOnly -QuickTimeout -ErrorAction Stop |
                Where-Object { $_.PSObject.Properties['IPAddress'] -and $_.IPAddress }).Count -gt 0
        }
        catch { $false }
    } -ArgumentList $Name
}

function Test-RosetunGuestNslookup {
    # True when nslookup, which sends its own queries, gets an answer for $Name.
    param([Parameter(Mandatory)][string]$Name)
    Invoke-RosetunGuest -ScriptBlock {
        param($name)
        $output = (& nslookup.exe -timeout=2 -retry=1 $name 2>&1 | ForEach-Object { "$_" }) -join "`n"
        $global:LASTEXITCODE = 0
        $output -match "Name:\s+$([regex]::Escape($name))"
    } -ArgumentList $Name
}

Export-ModuleMember -Function *-Rosetun*
