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
}
$script:Session = $null

function Install-RosetunSingBox {
    # Downloads the pinned sing-box build into tools\ and checks it, so the
    # 80 MB binary does not have to live in git. Update both values together
    # with SUPPORTED_SING_BOX_VERSION in rosetun-engine-singbox.
    param([string]$Destination = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\sing-box.exe')))

    $version = '1.14.1'
    $expectedHash = 'B838DE45BD0B2E6DDBED1977E4745622F7DFFAB3B293807FF4C6B1B640FED909'

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
    if ($LASTEXITCODE -ne 0) {
        throw "Downloading $url failed with curl exit code $LASTEXITCODE."
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

function Start-RosetunTestNode {
    # Runs the Shadowsocks test node on the host in the background with a
    # debug log in vm\logs, so a failed run keeps the node's side as well.
    param(
        [string]$SingBoxPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\sing-box.exe')),
        # Sends the node's own traffic out of this adapter, past a VPN client
        # running in TUN mode on the host. Such a client accepts TCP itself and
        # can leave the node with open connections that never carry data.
        [string]$BindInterface
    )

    $config = Get-Content -Path (Join-Path $PSScriptRoot 'test-node.json') -Raw | ConvertFrom-Json
    $port = $config.inbounds[0].listen_port
    if ($BindInterface) {
        $config.outbounds | Where-Object { $_.type -eq 'direct' } | ForEach-Object {
            $_ | Add-Member -NotePropertyName bind_interface -NotePropertyValue $BindInterface -Force
        }
    }
    if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
        Write-Host "Something already listens on port $port; leaving it running."
        return
    }

    $logDir = Join-Path $PSScriptRoot 'logs'
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    $config.log = [pscustomobject]@{
        level     = 'debug'
        timestamp = $true
        output    = Join-Path $logDir 'test-node.log'
    }
    $configPath = Join-Path $env:TEMP 'rosetun-test-node.json'
    [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 10))

    $node = Start-Process -FilePath $SingBoxPath -ArgumentList 'run', '--disable-color', '-c', $configPath `
        -WindowStyle Hidden -PassThru
    $deadline = (Get-Date).AddSeconds(15)
    while (-not (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)) {
        if ($node.HasExited -or (Get-Date) -gt $deadline) {
            throw "The test node did not start listening on port $port; see $logDir\test-node.log."
        }
        Start-Sleep -Milliseconds 200
    }
    Write-Host "Test node listening on port $port, log: $logDir\test-node.log"
}

function Stop-RosetunTestNode {
    $config = Get-Content -Path (Join-Path $PSScriptRoot 'test-node.json') -Raw | ConvertFrom-Json
    Get-NetTCPConnection -LocalPort $config.inbounds[0].listen_port -State Listen -ErrorAction SilentlyContinue |
        ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
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
        [switch]$UseHostNode
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

    # The same request with a node that never answers: 192.0.2.1 is TEST-NET-1,
    # reserved and unroutable. The engine starts, but DNS through the tunnel
    # cannot work, so the helper's DNS check must fail the connect.
    $unreachable = Get-Content -Path $RequestPath -Raw | ConvertFrom-Json
    $unreachable.node.server = '192.0.2.1'
    $derived['request-unreachable.json'] = $unreachable

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
        if ($LASTEXITCODE -ne 0) {
            throw "cargo build failed with exit code $LASTEXITCODE."
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
        [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($output -join "`n") }
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
        [switch]$Tcp
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
    } -ArgumentList $address, $script:Config.DnsProbeServer, [bool]$Tcp
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
        [switch]$Detailed
    )
    $curl = if ($OtherProcess) { Join-Path $script:Config.GuestDir 'curl-other.exe' } else { 'curl.exe' }
    # A hostname on purpose: this also exercises the hijacked DNS path. The
    # local address proves the connection went through the tunnel; without the
    # kill switch a connection that bypasses it succeeds as well.
    $result = Invoke-RosetunGuest -ScriptBlock {
        param($url, $tunAlias, $curl)
        # A missing binary would fail the probe and pass a "blocked" check.
        if (-not (Get-Command -Name $curl -ErrorAction SilentlyContinue)) {
            throw "$curl was not found in the guest."
        }
        $tunAddresses = @(Get-NetIPAddress -InterfaceAlias $tunAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            ForEach-Object { $_.IPAddress })
        $output = @(& $curl --max-time 10 --silent --show-error --output NUL --write-out 'local=%{local_ip}' $url 2>&1 |
            ForEach-Object { "$_" })
        $exitCode = $LASTEXITCODE
        $localIp = ($output | Where-Object { $_ -like 'local=*' } | Select-Object -First 1) -replace '^local=', ''
        [pscustomobject]@{
            Ok           = $exitCode -eq 0 -and $tunAddresses -contains $localIp
            CurlExit     = $exitCode
            LocalIp      = $localIp
            TunAddresses = $tunAddresses -join ','
            Error        = ($output | Where-Object { $_ -notlike 'local=*' -and $_ }) -join ' '
        }
    } -ArgumentList $Url, $script:Config.TunAlias, $curl

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
        [int]$TimeoutSeconds = 30
    )
    $watch = [Diagnostics.Stopwatch]::StartNew()
    do {
        $last = Test-RosetunTunnelEgress -Url $Url -Detailed
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
    # Probes direct egress every 200 ms in the background, to catch leaks that
    # last only a fraction of a second, such as during a reconnect.
    $address = Get-RosetunEgressAddress
    Invoke-RosetunGuest -ScriptBlock {
        param($address, $url)
        Remove-Item -Path "$env:TEMP\rosetun-egress-watch.txt" -ErrorAction SilentlyContinue
        Start-Job -Name 'rosetun-egress-watch' -ArgumentList $address, $url -ScriptBlock {
            param($address, $url)
            $probes = 0
            $leaks = 0
            while ($true) {
                & curl.exe --interface $address --max-time 2 --silent --output NUL $url 2>$null
                $probes++
                if ($LASTEXITCODE -eq 0) { $leaks++ }
                Set-Content -Path "$env:TEMP\rosetun-egress-watch.txt" -Value "$probes $leaks"
                Start-Sleep -Milliseconds 200
            }
        } | Out-Null

        # A job takes seconds to start, longer than a reconnect now lasts.
        # Without this wait the watch can miss the whole reconnect.
        $deadline = (Get-Date).AddSeconds(30)
        while (-not (Test-Path -Path "$env:TEMP\rosetun-egress-watch.txt")) {
            if ((Get-Date) -gt $deadline) {
                throw 'The egress watch did not record a probe within 30 seconds.'
            }
            Start-Sleep -Milliseconds 200
        }
    } -ArgumentList $address, $script:Config.ProbeUrl
}

function Stop-RosetunEgressWatch {
    Invoke-RosetunGuest -ScriptBlock {
        Stop-Job -Name 'rosetun-egress-watch'
        Remove-Job -Name 'rosetun-egress-watch'
        $counts = (Get-Content -Path "$env:TEMP\rosetun-egress-watch.txt" -ErrorAction SilentlyContinue) -split ' '
        if ($counts.Count -lt 2) {
            return [pscustomobject]@{ Probes = 0; Leaks = 0 }
        }
        [pscustomobject]@{ Probes = [int]$counts[0]; Leaks = [int]$counts[1] }
    }
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
    Copy-Item -FromSession (Connect-RosetunVm) -Path (Join-Path $script:Config.GuestDir 'helper*.log') `
        -Destination $Destination
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

Export-ModuleMember -Function *-Rosetun*
