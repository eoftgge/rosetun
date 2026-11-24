# Probes and guest actions of the Windows Failure runner (stage 10b). Windows PowerShell 5.1, as SYSTEM.
#
# Sourced by `run-windows-failure.ps1` after `lib.ps1` and the runner's path variables (`$plan`, `$cliPath`,
# `$helperPath`, `$curlPath`, `$work`, `$taskName`, `$physical`, `$targetUrl`). Every direct probe binds to the
# guest's own physical address so that it tests the WFP rules on the physical adapter and appears on the lab wire
# whenever it is allowed out.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-FailureCli {
    param([Parameter(Mandatory)][string[]]$Arguments, [int]$Seconds = 90)
    Invoke-RosetunNative -FilePath $cliPath -Arguments $Arguments -TimeoutSeconds $Seconds
}

function Get-FailureState {
    $result = Invoke-FailureCli -Arguments @('status') -Seconds 20
    if ($result.Output -match '(?m)^state: (\w+)') { return $Matches[1] }
    return "unknown (exit $($result.ExitCode))"
}

function Get-FailureProtection {
    $result = Invoke-FailureCli -Arguments @('status') -Seconds 20
    if ($result.Output -match '(?m)^protection: (.+?)\s*$') { return $Matches[1] }
    return 'unknown'
}

function Wait-FailureState {
    param([Parameter(Mandatory)][string]$Expected, [int]$TimeoutSeconds = 30)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ((Get-FailureState) -eq $Expected) { return $true }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    return $false
}

function Wait-FailureCondition {
    param([Parameter(Mandatory)][scriptblock]$Condition, [int]$TimeoutSeconds = 15)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (& $Condition) { return $true }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    return $false
}

function Wait-HelperReady {
    param([int]$TimeoutSeconds = 90)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ($clock.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        if ((Invoke-FailureCli -Arguments @('status') -Seconds 15).ExitCode -eq 0) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Get-DirectEgressCode {
    $result = Invoke-RosetunNative -FilePath $curlPath -TimeoutSeconds 15 -Arguments @(
        '--interface', $physical, '--max-time', '5', '--silent', '--ssl-no-revoke', '--output', 'NUL', $targetUrl)
    return $result.ExitCode
}

function Test-DirectEgress {
    return ((Get-DirectEgressCode) -eq 0)
}

function Test-DirectDns {
    param([string]$Name = [string]$plan.baseline.dns_name)
    $query = New-RosetunQuery -Name $Name
    try {
        $reply = Invoke-RosetunUdp -Source $physical -Target ([string]$plan.addresses.resolver) -Port 53 -Request $query -Milliseconds 3000
    }
    catch { return $false }
    return ($reply.Length -ge 12 -and $reply[0] -eq 0x6a -and $reply[1] -eq 0x06 -and ($reply[2] -band 0x80) -eq 0x80)
}

function Test-DirectTcpDns {
    # Resolvers fall back to TCP for long answers; the lab's DNS service records a TCP row only after it reads the
    # two-byte length and the question, so the probe sends the whole message and checks the answer's header.
    param([string]$Name = [string]$plan.baseline.dns_name)
    $query = New-RosetunQuery -Name $Name
    $client = New-Object Net.Sockets.TcpClient -ArgumentList (Get-RosetunEndPoint $physical 0)
    try {
        $client.ReceiveTimeout = 3000
        $client.SendTimeout = 3000
        if (-not $client.ConnectAsync([string]$plan.addresses.resolver, 53).Wait(3000)) { return $false }
        $stream = $client.GetStream()
        $prefix = [byte[]](([byte]($query.Length -shr 8)), ([byte]($query.Length -band 255)))
        $stream.Write($prefix, 0, 2)
        $stream.Write($query, 0, $query.Length)
        $head = New-Object byte[] 2
        if ($stream.Read($head, 0, 2) -ne 2) { return $false }
        $size = ([int]$head[0] -shl 8) -bor [int]$head[1]
        $reply = New-Object byte[] $size
        $offset = 0
        while ($offset -lt $size) {
            $got = $stream.Read($reply, $offset, $size - $offset)
            if ($got -le 0) { break }
            $offset += $got
        }
        return ($offset -eq $size -and $size -ge 12 -and $reply[0] -eq 0x6a -and $reply[1] -eq 0x06 -and
            ($reply[2] -band 0x80) -eq 0x80)
    }
    catch { return $false }
    finally { $client.Close() }
}

function Test-Ipv6Egress {
    # A TCP connection over IPv6 outside the tunnel to the lab's IPv6 HTTP target. Under the kill switch or sing-box's
    # strict route it is blocked before any packet leaves; in the baseline and recovery windows the handshake completes
    # on the wire and calibrates the observer's IPv6 control flow.
    $client = New-Object Net.Sockets.TcpClient -ArgumentList (Get-RosetunEndPoint ([string]$plan.addresses.client6) 0)
    try {
        $client.ReceiveTimeout = 3000
        $client.SendTimeout = 3000
        return $client.ConnectAsync([Net.IPAddress]::Parse([string]$plan.addresses.target6), ([int]$plan.addresses.http_port)).Wait(3000)
    }
    catch { return $false }
    finally { $client.Close() }
}

function Test-TunnelEgress {
    param([Parameter(Mandatory)][string]$Url)
    $tunAddresses = @(Get-NetIPAddress -InterfaceAlias ([string]$plan.tun.alias) -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            ForEach-Object { $_.IPAddress })
    $result = Invoke-RosetunNative -FilePath $curlPath -TimeoutSeconds 20 -Arguments @(
        '--max-time', '10', '--silent', '--show-error', '--insecure', '--ssl-no-revoke', '--output', 'NUL',
        '--write-out', 'local=%{local_ip} remote=%{remote_ip} code=%{http_code}', $Url)
    $local = ''
    $remote = ''
    $code = ''
    if ($result.Output -match 'local=(\S*) remote=(\S*) code=(\d+)') { $local, $remote, $code = $Matches[1], $Matches[2], $Matches[3] }
    return [pscustomobject]@{
        Ok = ($result.ExitCode -eq 0 -and $tunAddresses -contains $local -and $remote -eq [string]$plan.addresses.target4 -and $code -eq '200')
        CurlExit = $result.ExitCode
    }
}

function Wait-TunnelEgress {
    param([Parameter(Mandatory)][string]$Url, [int]$TimeoutSeconds = 30)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    do {
        $last = Test-TunnelEgress -Url $Url
        if ($last.Ok) { break }
        Start-Sleep -Milliseconds 500
    } while ($clock.Elapsed.TotalSeconds -lt $TimeoutSeconds)
    $clock.Stop()
    return [pscustomobject]@{
        Ok = $last.Ok
        CurlExit = $last.CurlExit
        Seconds = [math]::Round($clock.Elapsed.TotalSeconds, 2)
    }
}

function Test-WfpFilters {
    # Both the dynamic session provider (`51a47ec7-...`) and the persistent sublayer (`4955e6a4-...`) belong to Rosetun.
    $path = Join-Path $env:TEMP ("rosetun-wfp-$([guid]::NewGuid().ToString('N')).xml")
    try {
        $dump = Invoke-RosetunNative -FilePath (Join-Path $env:SystemRoot 'System32\netsh.exe') -TimeoutSeconds 30 -Arguments @(
            'wfp', 'show', 'state', "file=$path")
        if ($dump.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $path)) {
            throw 'cannot inspect WFP state'
        }
        $raw = Get-Content -Raw -LiteralPath $path
        return ($raw -match '51a47ec7-6459-4b84-8854-075e1576e7f9' -or $raw -match '4955e6a4-b1d2-4f95-9b63-2e8b25a9f0c2')
    }
    finally {
        Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue
    }
}

function Test-TunAdapter {
    return ($null -ne (Get-NetAdapter -Name ([string]$plan.tun.alias) -ErrorAction SilentlyContinue))
}

function Test-EngineRunning {
    return (@(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'sing-box.exe'" -ErrorAction SilentlyContinue |
                Where-Object { -not $_.CommandLine -or $_.CommandLine -match '\srun(\s|$)' }).Count -gt 0)
}

function Stop-FailureEngine {
    Stop-Process -Name 'sing-box' -Force -ErrorAction SilentlyContinue
}

function Stop-FailureHelper {
    # Hard kill of the helper process and its scheduled task, simulating an unexpected helper crash.
    Stop-Process -Name 'rosetun-helper-privileged' -Force -ErrorAction SilentlyContinue
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ($clock.Elapsed.TotalSeconds -lt 15 -and ((Get-Process -Name 'rosetun-helper-privileged' -ErrorAction SilentlyContinue) -or
            (@(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Running' }).Count -gt 0))) {
        Start-Sleep -Milliseconds 200
    }
}

function Get-PhysicalInterfaceIndex {
    $address = Get-NetIPAddress -IPAddress $physical -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $address) { return [int]$address.InterfaceIndex }
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -ne [string]$plan.tun.alias } |
        Sort-Object -Property RouteMetric | Select-Object -First 1
    if ($null -eq $route) { throw 'no physical adapter found' }
    return [int]$route.InterfaceIndex
}

function Wait-PhysicalRoute {
    param([Parameter(Mandatory)][int]$Index, [int]$TimeoutSeconds = 60)
    Wait-FailureCondition -TimeoutSeconds $TimeoutSeconds -Condition {
        $v4 = Get-NetIPAddress -InterfaceIndex $Index -IPAddress $physical -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.AddressState -eq 'Preferred' } | Select-Object -First 1
        $v6 = Get-NetIPAddress -InterfaceIndex $Index -IPAddress ([string]$plan.addresses.client6) -AddressFamily IPv6 -ErrorAction SilentlyContinue |
            Where-Object { $_.AddressState -eq 'Preferred' } | Select-Object -First 1
        $route4 = Get-NetRoute -InterfaceIndex $Index -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1
        $route6 = Get-NetRoute -InterfaceIndex $Index -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Select-Object -First 1
        return ($null -ne $v4 -and $null -ne $v6 -and $null -ne $route4 -and $null -ne $route6)
    }
}

function Start-FailureEgressWatch {
    # One background curl loops over a URL range bound to the physical address while a session restarts, recording one
    # exit code per line (0 would be an answer from the target, a leak). Under the kill switch WFP blocks the connect
    # inside the guest before any frame reaches the wire.
    param([int]$FirstProbeTimeoutSeconds = 30)
    $watchTask = 'RosetunEgressWatch'
    $watchPath = Join-Path $work 'rosetun-egress-watch.txt'
    $marker = 'rosetun-egress-probe='
    Stop-FailureEgressWatch -Quiet | Out-Null
    $range = $targetUrl.TrimEnd('/') + "/?$marker[1-10000000]"
    $arguments = ('/d /c ""{0}" --interface {1} --max-time 2 --rate 300/m --silent --ssl-no-revoke --output NUL ' +
        '--write-out "%{{stderr}}%{{exitcode}}\n" "{2}" 2> "{3}""') -f $curlPath, $physical, $range, $watchPath
    $action = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\cmd.exe') -Argument $arguments -WorkingDirectory $work
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $watchTask -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $watchTask
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ($clock.Elapsed.TotalSeconds -lt $FirstProbeTimeoutSeconds) {
        $text = ''
        try {
            $stream = [IO.File]::Open($watchPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
            try { $text = (New-Object IO.StreamReader $stream).ReadToEnd() } finally { $stream.Dispose() }
        }
        catch { }
        if ($text.Contains("`n")) { return }
        Start-Sleep -Milliseconds 200
    }
    Stop-FailureEgressWatch -Quiet | Out-Null
    throw "egress watch did not record a probe within $FirstProbeTimeoutSeconds s"
}

function Stop-FailureEgressWatch {
    param([switch]$Quiet)
    $watchTask = 'RosetunEgressWatch'
    $watchPath = Join-Path $work 'rosetun-egress-watch.txt'
    $marker = 'rosetun-egress-probe='
    try {
        Stop-ScheduledTask -TaskName $watchTask -ErrorAction SilentlyContinue
        $clock = [Diagnostics.Stopwatch]::StartNew()
        while ($clock.Elapsed.TotalSeconds -lt 10 -and
            (@(Get-ScheduledTask -TaskName $watchTask -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Running' }).Count -gt 0)) {
            Start-Sleep -Milliseconds 200
        }
        $clock.Restart()
        while ($clock.Elapsed.TotalSeconds -lt 10) {
            $curls = @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'curl.exe'" -ErrorAction SilentlyContinue |
                    Where-Object { $_.CommandLine -like "*$marker*" })
            if ($curls.Count -eq 0) { break }
            foreach ($process in $curls) { Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue }
            Start-Sleep -Milliseconds 200
        }
        $text = $null
        if (Test-Path -LiteralPath $watchPath) {
            try { $text = [IO.File]::ReadAllText($watchPath) } catch { }
        }
        if ([string]::IsNullOrEmpty($text) -or -not $text.Contains("`n")) {
            return [pscustomobject]@{ Probes = 0; Leaks = 0 }
        }
        $lines = @($text.Substring(0, $text.LastIndexOf("`n") + 1) -split "`r?`n" | Where-Object { $_ -match '^\d+$' })
        return [pscustomobject]@{
            Probes = $lines.Count
            Leaks = @($lines | Where-Object { $_ -eq '0' }).Count
        }
    }
    finally {
        Unregister-ScheduledTask -TaskName $watchTask -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $watchPath -Force -ErrorAction SilentlyContinue
    }
}

function Write-FailureRequest {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)]$Request)
    $path = Join-Path $work $Name
    [IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject $Request -Depth 30), (New-Object Text.UTF8Encoding $false))
    return $path
}

function Copy-FailureRequest {
    param([Parameter(Mandatory)]$Request)
    return (ConvertTo-Json -InputObject $Request -Depth 30 | ConvertFrom-Json)
}

function Invoke-RecoveryControlProbes {
    # Both ends of the run calibrate the four physical paths on the wire (HTTPS target, IPv6 HTTP target, UDP DNS and
    # TCP DNS for `after.<baseline>`). Cases whose own checks do not already run all four call the missing ones here.
    param(
        [bool]$NeedEgress = $true,
        [bool]$NeedIpv6 = $true,
        [bool]$NeedUdpDns = $true,
        [bool]$NeedTcpDns = $true
    )
    $afterDns = 'after.' + [string]$plan.baseline.dns_name
    if ($NeedEgress) { [void](Test-DirectEgress) }
    if ($NeedUdpDns) { [void](Test-DirectDns -Name $afterDns) }
    if ($NeedTcpDns) { [void](Test-DirectTcpDns -Name $afterDns) }
    if ($NeedIpv6) { [void](Test-Ipv6Egress) }
}
