# The Windows Proxy matrix as an autonomous runner of the QEMU lab (stage 10d).
# Windows PowerShell 5.1, as SYSTEM.
#
# Runs all 46 checks of proxy-checks.json in exact catalog order against the isolated lab wire,
# where the lab router plays both the VPN node (192.0.2.1) and the LAN peer (192.0.2.254).
# Marks five windows: baseline (listed), strict (judged), sharing-strict (judged),
# lockdown (judged), and recovery (listed).

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
$work = Join-Path $Root 'proxy-matrix'
$resultsDir = Join-Path $Root 'results'
$cliPath = Join-Path $bin 'rosetun.exe'
$helperPath = Join-Path $bin 'rosetun-helper-privileged.exe'
$singBoxPath = Join-Path $bin 'sing-box.exe'
$desktopToolPath = Join-Path $bin 'desktop_proxy.exe'
$curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'
$taskName = 'RosetunHelper'
$watchTaskName = 'RosetunEgressWatch'
$watchLogPath = Join-Path $work 'rosetun-egress-watch.txt'
$proxyUser = 'RosetunProxyUser'
$desktopTaskName = 'RosetunProxyDesktop'
$proxyUserDir = 'C:\rosetun-proxy-user'

$proxyPort = [int]$plan.proxy_port
$physical = [string]$plan.addresses.client4
$gateway = [string]$plan.addresses.gateway4
$lanPeer = [string]$plan.addresses.lan_peer
$target4 = [string]$plan.addresses.target4
$resolver = [string]$plan.addresses.resolver
$targetUrl = 'https://' + $target4 + '/'
$listed = [string]$plan.names.listed
$probeUrl = 'https://' + $listed + '/'
$baselineDns = [string]$plan.baseline.dns_name
$recoveryDns = 'after.' + $baselineDns
$tunAlias = [string]$plan.tun.alias

$lockdownKeys = @(
    'f12dbedd-f3c7-4a72-b0f8-20559c88b112', 'f829a64d-c373-4d92-9d66-e1c680f3794f',
    '57bf2a6e-57db-4d99-bed7-ecbd2c63aa75', 'e599db5e-6aeb-4e4d-aa51-4314f1b3076c',
    '98419911-30f0-4f71-9178-263b40bc7f6e', 'cb0f8c4b-4967-4626-a493-a4e32369e6f5',
    'f6a5849d-943f-4d77-917c-8811e9a70000', 'e0222624-bc2f-43a6-8058-b939a77ddd4b',
    '982cc554-9f41-4c9a-833f-87cc5149725f', '729b156a-c411-4f01-b7d9-a789c94e992b',
    '05b9da42-ea8e-4b28-a2b8-2404db01e0d1'
)

function Invoke-ProxyCli {
    param([Parameter(Mandatory)][string[]]$Arguments, [int]$Seconds = 90)
    Invoke-RosetunNative -FilePath $cliPath -Arguments $Arguments -TimeoutSeconds $Seconds
}

function Get-ProxyState {
    $result = Invoke-ProxyCli -Arguments @('status') -Seconds 20
    if ($result.Output -match '(?m)^state: (\w+)') { return $Matches[1] }
    return "unknown (exit $($result.ExitCode))"
}

function Get-ProxyLockdownLine {
    $result = Invoke-ProxyCli -Arguments @('status') -Seconds 20
    if ($result.ExitCode -eq 0 -and $result.Output -match '(?m)^lockdown: (on|off)\r?$') {
        return $Matches[1]
    }
    return 'unknown'
}

function Wait-ProxyState {
    param([Parameter(Mandatory)][string]$Expected, [int]$TimeoutSeconds = 30)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ((Get-ProxyState) -eq $Expected) { return $true }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    return $false
}

function Wait-ProxyCondition {
    param([Parameter(Mandatory)][scriptblock]$Condition, [int]$TimeoutSeconds = 20)
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
        if ((Invoke-ProxyCli -Arguments @('status') -Seconds 15).ExitCode -eq 0) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Test-TunAdapter {
    return ($null -ne (Get-NetAdapter -Name $tunAlias -ErrorAction SilentlyContinue))
}

function Test-EngineRunning {
    $procs = @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'sing-box.exe'" -ErrorAction SilentlyContinue |
        Where-Object { -not $_.CommandLine -or $_.CommandLine -match '\srun(\s|$)' })
    return ($procs.Count -gt 0)
}

function Get-EnginePids {
    return @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'sing-box.exe'" -ErrorAction SilentlyContinue |
        Where-Object { -not $_.CommandLine -or $_.CommandLine -match '\srun(\s|$)' } |
        ForEach-Object { [int]$_.ProcessId })
}

function Disconnect-ProxySession {
    param([int]$TimeoutSeconds = 30)
    [void](Invoke-ProxyCli -Arguments @('disconnect') -Seconds 30)
    $ok = Wait-ProxyCondition -TimeoutSeconds $TimeoutSeconds -Condition {
        (Get-ProxyState) -eq 'Disconnected' -and -not (Test-TunAdapter)
    }
    return $ok
}

function Connect-ProxyVariant {
    param([Parameter(Mandatory)][string]$RequestName)
    [void](Disconnect-ProxySession)
    $res = Invoke-ProxyCli -Arguments @('connect', (Join-Path $work $RequestName)) -Seconds 60
    return ($res.ExitCode -eq 0 -and (Wait-ProxyState 'Connected'))
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

function Test-ProxyCarriesOnce {
    $result = Invoke-RosetunNative -FilePath $curlPath -TimeoutSeconds 20 -Arguments @(
        '--proxy', "http://127.0.0.1:$proxyPort", '--max-time', '15', '--silent', '--insecure', '--ssl-no-revoke', $probeUrl)
    return ($result.ExitCode -eq 0 -and $result.Output.Trim() -eq 'rosetun-lab-target')
}

function Wait-ProxyCarries {
    param([int]$TimeoutSeconds = 20)
    return (Wait-ProxyCondition -TimeoutSeconds $TimeoutSeconds -Condition { Test-ProxyCarriesOnce })
}

function Test-TunnelEgressOnce {
    $tunAddresses = @(Get-NetIPAddress -InterfaceAlias $tunAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        ForEach-Object { $_.IPAddress })
    if ($tunAddresses.Count -eq 0) { return $false }
    $result = Invoke-RosetunNative -FilePath $curlPath -TimeoutSeconds 20 -Arguments @(
        '--max-time', '10', '--silent', '--insecure', '--ssl-no-revoke',
        '--write-out', "`nlocal=%{local_ip} remote=%{remote_ip} code=%{http_code}", $probeUrl)
    $script:TunnelCurlExit = [int]$result.ExitCode
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

function Record-NativeCounters {
    param([Parameter(Mandatory)][string]$Prefix)
    $counterLine = Select-String -LiteralPath (Join-Path $logs 'helper.log') -Pattern 'native packet pump counters' |
        Select-Object -Last 1
    if ($null -eq $counterLine) { return }
    $plain = $counterLine.Line -replace '\x1b\[[0-9;]*m', ''
    foreach ($name in @('frames', 'bad_checksum', 'tcp', 'written', 'write_errors', 'accepted')) {
        if ($plain -match "(?:^|\s)$name=(\d+)") {
            Add-RosetunRunnerNote -Name "$Prefix-$name" -Value ([long]$Matches[1])
        }
    }
}

function Wait-TunnelEgress {
    param([int]$TimeoutSeconds = 25)
    return (Wait-ProxyCondition -TimeoutSeconds $TimeoutSeconds -Condition { Test-TunnelEgressOnce })
}

function Invoke-LabProxyProbe {
    param([switch]$FromServer)
    $src = if ($FromServer) { $gateway } else { $lanPeer }
    $reply = Invoke-RosetunLabAction -Root $Root -Operation 'probe_proxy' -Parameters @{
        source = $src
        port = $proxyPort
        mode = 'http_proxy'
    }
    return ([bool]$reply.ok)
}

function Stop-WatchCurlProcesses {
    Get-CimInstance -ClassName Win32_Process -Filter "Name = 'curl.exe' OR Name = 'cmd.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like '*rosetun-egress-probe=*' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

function Start-ProxyEgressWatch {
    param([int]$FirstProbeTimeoutSeconds = 30)
    $marker = 'rosetun-egress-probe='
    if (Get-ScheduledTask -TaskName $watchTaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $watchTaskName -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 300
        Unregister-ScheduledTask -TaskName $watchTaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    Stop-WatchCurlProcesses
    Remove-Item -LiteralPath $watchLogPath -Force -ErrorAction SilentlyContinue
    $range = $targetUrl.TrimEnd('/') + "/?$marker[1-10000000]"
    $arguments = ('/d /c curl.exe --interface {0} --max-time 2 --rate 300/m --silent --ssl-no-revoke --output NUL ' +
        '--write-out "%{{stderr}}%{{exitcode}}\n" "{1}" 2> "{2}"') -f $physical, $range, $watchLogPath
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument $arguments -WorkingDirectory $work
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $watchTaskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $watchTaskName
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ($clock.Elapsed.TotalSeconds -lt $FirstProbeTimeoutSeconds) {
        $text = ''
        try {
            $stream = [IO.File]::Open($watchLogPath, 'Open', 'Read', 'ReadWrite, Delete')
            try { $text = [IO.StreamReader]::new($stream).ReadToEnd() } finally { $stream.Dispose() }
        }
        catch { }
        if ($text.Contains("`n")) { return }
        Start-Sleep -Milliseconds 200
    }
    Stop-ProxyEgressWatch | Out-Null
    throw 'egress watch did not record a first probe'
}

function Stop-ProxyEgressWatch {
    try {
        Stop-ScheduledTask -TaskName $watchTaskName -ErrorAction SilentlyContinue
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        while ((Get-ScheduledTask -TaskName $watchTaskName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty State) -eq 'Running') {
            if ([DateTime]::UtcNow -gt $deadline) { break }
            Start-Sleep -Milliseconds 200
        }
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        while ([DateTime]::UtcNow -lt $deadline) {
            $alive = @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'curl.exe' OR Name = 'cmd.exe'" -ErrorAction SilentlyContinue |
                Where-Object { $_.CommandLine -like '*rosetun-egress-probe=*' })
            if ($alive.Count -eq 0) { break }
            foreach ($p in $alive) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
            Start-Sleep -Milliseconds 200
        }
        $text = $null
        try { $text = [IO.File]::ReadAllText($watchLogPath) } catch { }
        if ($null -eq $text) { return [pscustomobject]@{ Probes = 0; Leaks = 0 } }
        $lastNl = $text.LastIndexOf("`n")
        if ($lastNl -lt 0) { return [pscustomobject]@{ Probes = 0; Leaks = 0 } }
        $lines = @($text.Substring(0, $lastNl + 1) -split "`r?`n" | Where-Object { $_ -match '^\d+$' })
        return [pscustomobject]@{ Probes = $lines.Count; Leaks = @($lines | Where-Object { $_ -eq '0' }).Count }
    }
    finally {
        Unregister-ScheduledTask -TaskName $watchTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $watchLogPath -Force -ErrorAction SilentlyContinue
    }
}

function Remove-ProxyDesktopAccount {
    Unregister-ScheduledTask -TaskName $desktopTaskName -Confirm:$false -ErrorAction SilentlyContinue
    Get-Process -Name 'desktop_proxy' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    $user = Get-LocalUser -Name $proxyUser -ErrorAction SilentlyContinue
    if ($user) {
        Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue |
            Where-Object { $_.SID -eq $user.SID.Value } |
            Remove-CimInstance -ErrorAction SilentlyContinue
        Remove-LocalUser -Name $proxyUser -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $proxyUserDir -Recurse -Force -ErrorAction SilentlyContinue
}

function Invoke-DesktopProxySuite {
    Remove-ProxyDesktopAccount
    $password = 'Rp1!' + [guid]::NewGuid().ToString('N')
    $secure = ConvertTo-SecureString -String $password -AsPlainText -Force
    New-LocalUser -Name $proxyUser -Password $secure -PasswordNeverExpires -AccountNeverExpires `
        -Description 'Rosetun Proxy matrix' | Out-Null
    foreach ($group in 'S-1-5-32-545', 'S-1-5-32-559') {
        try { Add-LocalGroupMember -SID $group -Member $proxyUser -ErrorAction Stop }
        catch [Microsoft.PowerShell.Commands.MemberExistsException] { }
    }
    New-Item -ItemType Directory -Path $proxyUserDir -Force | Out-Null
    [void](Invoke-RosetunNative -FilePath (Join-Path $env:SystemRoot 'System32\icacls.exe') -TimeoutSeconds 20 -Arguments @(
        $proxyUserDir, '/grant', "${proxyUser}:(OI)(CI)M"))
    Copy-Item -LiteralPath $desktopToolPath -Destination (Join-Path $proxyUserDir 'desktop_proxy.exe') -Force

    $desktopScriptPath = Join-Path $proxyUserDir 'desktop-checks.ps1'
    $desktopResultPath = Join-Path $proxyUserDir 'desktop-results.json'
    $desktopScript = @'
param([string]$Dir, [int]$Port, [string]$OutPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$tool = Join-Path $Dir 'desktop_proxy.exe'
$record = Join-Path $Dir 'desktop-proxy-matrix.json'

function Get-Settings {
    $v = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    $enabled = if ($v -and ($v.PSObject.Properties.Name -contains 'ProxyEnable')) { [int]$v.ProxyEnable } else { 0 }
    $server = if ($v -and ($v.PSObject.Properties.Name -contains 'ProxyServer')) { [string]$v.ProxyServer } else { '' }
    $pac = if ($v -and ($v.PSObject.Properties.Name -contains 'AutoConfigURL')) { [string]$v.AutoConfigURL } else { '' }
    return [pscustomobject]@{ Enabled = $enabled; Server = $server; Script = $pac }
}

Add-Type -TypeDefinition '
using System;
using System.Runtime.InteropServices;

public static class RosetunWinInet {
    private const uint INTERNET_OPTION_REFRESH = 37;
    private const uint INTERNET_OPTION_SETTINGS_CHANGED = 39;
    private const uint INTERNET_OPTION_PER_CONNECTION_OPTION = 75;
    private const uint INTERNET_PER_CONN_FLAGS = 1;
    private const uint INTERNET_PER_CONN_PROXY_SERVER = 2;
    private const uint INTERNET_PER_CONN_PROXY_BYPASS = 3;
    private const uint INTERNET_PER_CONN_AUTOCONFIG_URL = 4;
    private const uint PROXY_TYPE_DIRECT = 0x1;
    private const uint PROXY_TYPE_PROXY = 0x2;
    private const uint PROXY_TYPE_AUTO_PROXY_URL = 0x4;

    [StructLayout(LayoutKind.Explicit)]
    private struct OptionValue {
        [FieldOffset(0)] public uint dwValue;
        [FieldOffset(0)] public IntPtr pszValue;
        [FieldOffset(0)] public long ftValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PerConnOption {
        public uint dwOption;
        public OptionValue Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PerConnOptionList {
        public uint dwSize;
        public IntPtr pszConnection;
        public uint dwOptionCount;
        public uint dwOptionError;
        public IntPtr pOptions;
    }

    [DllImport("wininet.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool InternetSetOptionW(IntPtr hInternet, uint dwOption, IntPtr lpBuffer, uint dwBufferLength);

    public static void SetProxy(int enabled, string server, string pac) {
        uint flags = PROXY_TYPE_DIRECT;
        if (enabled != 0) flags |= PROXY_TYPE_PROXY;
        if (!string.IsNullOrEmpty(pac)) flags |= PROXY_TYPE_AUTO_PROXY_URL;
        IntPtr pServer = Marshal.StringToHGlobalUni(server ?? "");
        IntPtr pBypass = Marshal.StringToHGlobalUni("");
        IntPtr pPac = Marshal.StringToHGlobalUni(pac ?? "");
        int optSize = Marshal.SizeOf(typeof(PerConnOption));
        IntPtr pOpts = Marshal.AllocHGlobal(optSize * 4);
        IntPtr pList = IntPtr.Zero;
        try {
            PerConnOption[] opts = new PerConnOption[4];
            opts[0].dwOption = INTERNET_PER_CONN_FLAGS;
            opts[0].Value.dwValue = flags;
            opts[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
            opts[1].Value.pszValue = pServer;
            opts[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
            opts[2].Value.pszValue = pBypass;
            opts[3].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
            opts[3].Value.pszValue = pPac;
            for (int i = 0; i < 4; i++) {
                Marshal.StructureToPtr(opts[i], IntPtr.Add(pOpts, i * optSize), false);
            }
            PerConnOptionList list = new PerConnOptionList();
            list.dwSize = (uint)Marshal.SizeOf(typeof(PerConnOptionList));
            list.pszConnection = IntPtr.Zero;
            list.dwOptionCount = 4;
            list.dwOptionError = 0;
            list.pOptions = pOpts;
            pList = Marshal.AllocHGlobal((int)list.dwSize);
            Marshal.StructureToPtr(list, pList, false);
            if (!InternetSetOptionW(IntPtr.Zero, INTERNET_OPTION_PER_CONNECTION_OPTION, pList, list.dwSize)) {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
            InternetSetOptionW(IntPtr.Zero, INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
            InternetSetOptionW(IntPtr.Zero, INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);
        } finally {
            if (pList != IntPtr.Zero) Marshal.FreeHGlobal(pList);
            Marshal.FreeHGlobal(pOpts);
            Marshal.FreeHGlobal(pServer);
            Marshal.FreeHGlobal(pBypass);
            Marshal.FreeHGlobal(pPac);
        }
    }
}
'

function Set-Settings([int]$Enabled, [string]$Server, [string]$Pac) {
    if (-not (Test-Path -Path $key)) { New-Item -Path $key -Force | Out-Null }
    [RosetunWinInet]::SetProxy($Enabled, $Server, $Pac)
}

function Run-Tool([string[]]$ToolArgs) {
    $cmd = @($ToolArgs[0], $record) + @($ToolArgs | Select-Object -Skip 1)
    $out = & $tool @cmd 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
    $global:LASTEXITCODE = 0
    return [pscustomobject]@{ ExitCode = $code; Output = ($out -join ' ') }
}

$original = Get-Settings
$res = [ordered]@{
    desktop_set = $false; desktop_record = $false; desktop_restore = $false; desktop_record_gone = $false
    crash_persist = $false; crash_restore = $false; foreign_preserve = $false
    desktop_restore_note = ''; crash_restore_note = ''
    cleanup = 'ERROR'; error = ''
}
try {
    Set-Settings -Enabled 0 -Server '' -Pac 'http://proxy.invalid/wpad.dat'
    $own = Get-Settings

    $set = Run-Tool @('set', "$Port")
    $now = Get-Settings
    $res.desktop_set = ($set.ExitCode -eq 0 -and $now.Enabled -eq 1 -and $now.Server -eq "127.0.0.1:$Port" -and -not $now.Script)
    $res.desktop_record = (Test-Path -LiteralPath $record)

    $back = Run-Tool @('restore')
    $now = Get-Settings
    $res.desktop_restore_note = "exit=$($back.ExitCode) out=$($back.Output) en=$($now.Enabled)/$($own.Enabled) pac=$($now.Script)/$($own.Script)"
    $res.desktop_restore = ($back.ExitCode -eq 0 -and $back.Output -match 'Restored' -and $now.Enabled -eq $own.Enabled -and $now.Script -eq $own.Script)
    $res.desktop_record_gone = (-not (Test-Path -LiteralPath $record))

    [void](Run-Tool @('set', "$Port"))
    $res.crash_persist = ((Get-Settings).Server -eq "127.0.0.1:$Port" -and (Test-Path -LiteralPath $record))
    $back = Run-Tool @('restore')
    $now = Get-Settings
    $res.crash_restore_note = "exit=$($back.ExitCode) out=$($back.Output) pac=$($now.Script)/$($own.Script)"
    $res.crash_restore = ($back.ExitCode -eq 0 -and $back.Output -match 'Restored' -and $now.Script -eq $own.Script)

    [void](Run-Tool @('set', "$Port"))
    Set-Settings -Enabled 1 -Server 'proxy.invalid:3128' -Pac ''
    $back = Run-Tool @('restore')
    $now = Get-Settings
    $res.foreign_preserve = ($back.ExitCode -eq 0 -and $back.Output -match 'LeftAsTheyAre' -and $now.Server -eq 'proxy.invalid:3128' -and -not (Test-Path -LiteralPath $record))
}
catch {
    $res.error = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
}
finally {
    try {
        Set-Settings -Enabled $original.Enabled -Server $original.Server -Pac $original.Script
        $after = Get-Settings
        if ($after.Enabled -eq $original.Enabled -and $after.Server -eq $original.Server -and $after.Script -eq $original.Script -and -not (Test-Path -LiteralPath $record)) {
            $res.cleanup = 'PASS'
        }
    }
    catch { $res.cleanup = 'ERROR' }
    [IO.File]::WriteAllText($OutPath, (ConvertTo-Json -InputObject $res -Compress), (New-Object Text.UTF8Encoding $false))
}
'@
    [IO.File]::WriteAllText($desktopScriptPath, $desktopScript, (New-Object Text.UTF8Encoding $false))
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$desktopScriptPath`" -Dir `"$proxyUserDir`" -Port $proxyPort -OutPath `"$desktopResultPath`"" `
        -WorkingDirectory $proxyUserDir
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(2)) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $desktopTaskName -Action $action -Settings $settings -User $proxyUser -Password $password -RunLevel Limited | Out-Null
    Start-ScheduledTask -TaskName $desktopTaskName
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    while (-not (Test-Path -LiteralPath $desktopResultPath) -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 250
    }
    if (-not (Test-Path -LiteralPath $desktopResultPath)) {
        throw 'desktop proxy task did not finish'
    }
    return ([IO.File]::ReadAllText($desktopResultPath, [Text.Encoding]::UTF8) | ConvertFrom-Json)
}

function Test-WfpLockdownClean {
    $path = Join-Path $env:TEMP ("rosetun-wfp-$([guid]::NewGuid().ToString('N')).xml")
    try {
        $dump = Invoke-RosetunNative -FilePath (Join-Path $env:SystemRoot 'System32\netsh.exe') -TimeoutSeconds 30 -Arguments @(
            'wfp', 'show', 'state', "file=$path")
        if ($dump.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $path)) { return 'UNVERIFIED' }
        $raw = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)
        if ($raw -notmatch '<wfpstate>' -or $raw -notmatch '</wfpstate>' -or $raw -notmatch '<providerKey>' -or $raw -notmatch '<subLayerKey>') {
            return 'UNVERIFIED'
        }
        foreach ($guid in $lockdownKeys) {
            if ($raw -match [regex]::Escape($guid)) { return 'ERROR' }
        }
        return 'PASS'
    }
    catch { return 'UNVERIFIED' }
    finally { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
}

function Write-ProxyRequests {
    $variants = @{
        'proxy-plain.json'        = @{ mode = 'system_proxy'; kill = $false; share = $false; lan = $false }
        'proxy-strict.json'       = @{ mode = 'system_proxy'; kill = $true;  share = $false; lan = $false }
        'proxy-share.json'        = @{ mode = 'system_proxy'; kill = $false; share = $true;  lan = $false }
        'proxy-share-strict.json' = @{ mode = 'system_proxy'; kill = $true;  share = $true;  lan = $false }
        'proxy-share-lan.json'    = @{ mode = 'system_proxy'; kill = $false; share = $true;  lan = $true  }
        'tun-strict.json'         = @{ mode = 'tun';          kill = $true;  share = $false; lan = $false }
    }
    $baseJson = ConvertTo-Json -InputObject $plan.request -Depth 30
    foreach ($name in $variants.Keys) {
        $v = $variants[$name]
        $req = $baseJson | ConvertFrom-Json
        $req.settings | Add-Member -NotePropertyName connection_mode -NotePropertyValue $v.mode -Force
        $req.settings.tun | Add-Member -NotePropertyName backend -NotePropertyValue 'native_mixed' -Force
        $req.settings | Add-Member -NotePropertyName kill_switch -NotePropertyValue $v.kill -Force
        $req.settings | Add-Member -NotePropertyName auto_reconnect -NotePropertyValue $true -Force
        $req.settings | Add-Member -NotePropertyName allow_lan -NotePropertyValue $v.lan -Force
        $req.settings | Add-Member -NotePropertyName private_networks -NotePropertyValue $false -Force
        $req.settings | Add-Member -NotePropertyName local_proxy -Force -NotePropertyValue ([pscustomobject]@{
            port = $proxyPort
            share_on_lan = $v.share
        })
        [IO.File]::WriteAllText((Join-Path $work $name), (ConvertTo-Json -InputObject $req -Depth 30), (New-Object Text.UTF8Encoding $false))
    }
}

function Install-LabWintun {
    $length = 427552
    $expected = 'E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE'
    $engineBytes = [IO.File]::ReadAllBytes($singBoxPath)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $offset = [Array]::IndexOf($engineBytes, [byte]0x4D, 0)
        while ($offset -ge 0 -and $offset -le $engineBytes.Length - $length) {
            if ($engineBytes[$offset + 1] -eq 0x5A) {
                $hash = [BitConverter]::ToString($sha256.ComputeHash($engineBytes, $offset, $length)).Replace('-', '')
                if ($hash -eq $expected) {
                    $dll = [byte[]]::new($length)
                    [Array]::Copy($engineBytes, $offset, $dll, 0, $length)
                    [IO.File]::WriteAllBytes((Join-Path $bin 'wintun.dll'), $dll)
                    return
                }
            }
            $offset = [Array]::IndexOf($engineBytes, [byte]0x4D, $offset + 1)
        }
    }
    finally {
        $sha256.Dispose()
    }
    throw 'the supplied sing-box does not contain the pinned Wintun DLL'
}

$recorder = $null
$runError = $false
$helperStarted = $false
$egressWatchActive = $false
$holderPid = $null
$desktopRunCleanup = 'UNVERIFIED'
$openWindow = $null
$components = [ordered]@{
    node = 'NOT_CREATED'
    lan = 'UNVERIFIED'
    watch = 'NOT_CREATED'
    listener = 'NOT_CREATED'
    connection = 'UNVERIFIED'
    lockdown = 'NOT_CREATED'
    desktop = 'NOT_CREATED'
    files = 'UNVERIFIED'
}
$cliDisconnectedAtCleanup = $false
$cliLockdownOffAtCleanup = $false

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
    $version = Invoke-RosetunNative -FilePath $singBoxPath -Arguments @('version') -TimeoutSeconds 300
    Add-RosetunRunnerNote -Name 'sing-box-first-launch-seconds' -Value ([int]$clock.Elapsed.TotalSeconds)
    if ($version.ExitCode -ne 0) { throw 'sing-box does not start' }

    Set-RosetunRunnerStep -Step 'recorder'
    Import-Module (Join-Path $Root 'RosetunListResults.psm1') -Force
    $rawCatalog = Get-Content -LiteralPath (Join-Path $Root 'proxy-checks.json') -Encoding UTF8 -Raw | ConvertFrom-Json
    $catalog = @()
    foreach ($entry in $rawCatalog) {
        $entry.required = $true
        $catalog += $entry
    }
    $vmId = ([string](Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID).ToLowerInvariant()
    $params = @{ use_host_node = $true; keep_node = $false; proxy_port = $proxyPort }
    $recorder = New-RosetunListResults -Directory $resultsDir -VmId $vmId -BootId (Get-RosetunBootCounter) `
        -Suite 'windows-proxy' -Catalog $catalog -Parameters $params
    Set-RosetunRecorder -Recorder $recorder

    Set-RosetunRunnerStep -Step 'helper'
    Install-LabWintun
    $command = "set ROSETUN_LOG=debug&& `"$helperPath`" > `"$(Join-Path $logs 'helper.log')`" 2>&1"
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c $command" -WorkingDirectory $bin
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName
    $helperStarted = $true
    if (-not (Wait-HelperReady)) { throw 'the helper did not answer status' }
    Write-ProxyRequests

    # Window 0: baseline (listed)
    Set-RosetunRunnerStep -Step 'baseline'
    if (Send-RosetunMarker -Plan $plan -Label 'baseline' -Word 'open') { $openWindow = 'baseline' }
    [void](Test-DirectEgress)
    [void](Test-DirectDns -Name $baselineDns)
    Start-Sleep -Seconds 2
    [void](Send-RosetunMarker -Plan $plan -Label 'baseline' -Word 'close')
    $openWindow = $null

    # Plain checks (outside judged windows)
    Set-RosetunRunnerStep -Step 'plain'
    Test-Step -Id 'plain.connect' -Scenario 'plain' -Expectation 'connect without kill switch' { Connect-ProxyVariant 'proxy-plain.json' }
    Test-Step -Id 'plain.adapter' -Scenario 'plain' -Expectation 'no TUN adapter' { -not (Test-TunAdapter) }
    Test-Step -Id 'plain.proxy' -Scenario 'plain' -Expectation 'proxy carries traffic' { Wait-ProxyCarries }
    Test-Step -Id 'plain.direct' -Scenario 'plain' -Expectation 'direct egress works' { Test-DirectEgress }
    Test-Step -Id 'plain.unshared' -Scenario 'plain' -Expectation 'unshared proxy rejects LAN' { -not (Invoke-LabProxyProbe) }

    # Busy port checks (outside judged windows)
    Set-RosetunRunnerStep -Step 'busy'
    [void](Disconnect-ProxySession)
    $components.listener = 'UNVERIFIED'
    $holderProc = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -PassThru -WindowStyle Hidden -ArgumentList @(
        '-NoProfile', '-Command',
        "`$l=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,$proxyPort);`$l.Start();Start-Sleep 120")
    $holderPid = $holderProc.Id
    [void](Wait-ProxyCondition -TimeoutSeconds 45 -Condition {
        @(Get-NetTCPConnection -LocalPort $proxyPort -State Listen -ErrorAction SilentlyContinue).Count -gt 0
    })
    try {
        $busy = Invoke-ProxyCli -Arguments @('connect', (Join-Path $work 'proxy-strict.json')) -Seconds 30
        Test-Step -Id 'busy.reject' -Scenario 'busy' -Expectation 'busy port rejects connect naming port' -Note "exit $($busy.ExitCode)" {
            $busy.ExitCode -ne 0 -and $busy.Output -match "\b$proxyPort\b"
        }
        Test-Step -Id 'busy.engine' -Scenario 'busy' -Expectation 'no engine after busy port' { -not (Test-EngineRunning) }
        Test-Step -Id 'busy.direct' -Scenario 'busy' -Expectation 'network remains open after busy port' { Test-DirectEgress }
    }
    finally {
        Stop-Process -Id $holderPid -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 300
    }
    [void](Wait-ProxyState 'Failed' -TimeoutSeconds 10)
    [void](Disconnect-ProxySession)

    # Flush cached ARP neighbor for LAN peer before opening strict zero-allowance window.
    Remove-NetNeighbor -IPAddress $lanPeer -Confirm:$false -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    # Window 1: strict (judged, zero allowances)
    Set-RosetunRunnerStep -Step 'strict'
    if (Send-RosetunMarker -Plan $plan -Label 'strict' -Word 'open') { $openWindow = 'strict' }
    Test-Step -Id 'strict.connect' -Scenario 'strict' -Expectation 'connect with kill switch' { Connect-ProxyVariant 'proxy-strict.json' }
    Test-Step -Id 'strict.proxy' -Scenario 'strict' -Expectation 'strict proxy carries traffic' { Wait-ProxyCarries }
    Test-Step -Id 'strict.direct' -Scenario 'strict' -Expectation 'strict direct egress blocked' { -not (Test-DirectEgress) }
    Test-Step -Id 'strict.dns' -Scenario 'strict' -Expectation 'strict direct DNS blocked' { -not (Test-DirectDns -Name $baselineDns) }

    $components.watch = 'UNVERIFIED'
    Start-ProxyEgressWatch
    $egressWatchActive = $true
    $watch = [pscustomobject]@{ Probes = 0; Leaks = 0 }
    try {
        $oldPids = @(Get-EnginePids)
        Stop-Process -Name 'sing-box' -Force -ErrorAction SilentlyContinue
        Test-Step -Id 'strict.restart' -Scenario 'strict' -Expectation 'killed engine reconnects' {
            $restarted = Wait-ProxyCondition -TimeoutSeconds 45 -Condition {
                $now = @(Get-EnginePids)
                @($now | Where-Object { $_ -notin $oldPids }).Count -gt 0 -and (Get-ProxyState) -eq 'Connected'
            }
            $restarted -and (Wait-ProxyCarries -TimeoutSeconds 15)
        }
    }
    finally {
        $watch = Stop-ProxyEgressWatch
        $egressWatchActive = $false
    }
    Add-RosetunRunnerNote -Name 'strict-watch-probes' -Value $watch.Probes
    Test-Step -Id 'strict.watch' -Scenario 'strict' -Expectation 'no direct egress during engine restart' -Note "probes=$($watch.Probes) leaks=$($watch.Leaks)" {
        $watch.Probes -gt 0 -and $watch.Leaks -eq 0
    }

    Set-RosetunRunnerStep -Step 'mode'
    $script:TunnelCurlExit = -1
    Test-Step -Id 'mode.tun' -Scenario 'mode' -Expectation 'connect NativeMixed with kill switch' {
        (Connect-ProxyVariant 'tun-strict.json') -and (Wait-TunnelEgress)
    }
    Add-RosetunRunnerNote -Name 'mode-native-curl-exit' -Value $script:TunnelCurlExit
    Start-ProxyEgressWatch
    $egressWatchActive = $true
    $watch = [pscustomobject]@{ Probes = 0; Leaks = 0 }
    try {
        $toProxy = Invoke-ProxyCli -Arguments @('apply', (Join-Path $work 'proxy-strict.json')) -Seconds 60
        Record-NativeCounters -Prefix 'mode-native'
        Test-Step -Id 'mode.to-proxy' -Scenario 'mode' -Expectation 'apply TUN to proxy' -Note "exit $($toProxy.ExitCode)" { $toProxy.ExitCode -eq 0 }
        Test-Step -Id 'mode.adapter-gone' -Scenario 'mode' -Expectation 'TUN adapter removed' {
            Wait-ProxyCondition -TimeoutSeconds 20 -Condition { -not (Test-TunAdapter) }
        }
        Test-Step -Id 'mode.proxy' -Scenario 'mode' -Expectation 'proxy carries traffic after apply' { Wait-ProxyCarries }
        $toTun = Invoke-ProxyCli -Arguments @('apply', (Join-Path $work 'tun-strict.json')) -Seconds 60
        Test-Step -Id 'mode.to-tun' -Scenario 'mode' -Expectation 'apply proxy to TUN' -Note "exit $($toTun.ExitCode)" { $toTun.ExitCode -eq 0 }
        $script:TunnelCurlExit = -1
        Test-Step -Id 'mode.tunnel' -Scenario 'mode' -Expectation 'TUN adapter returns and carries traffic' { Wait-TunnelEgress }
        Add-RosetunRunnerNote -Name 'mode-native-reconnect-curl-exit' -Value $script:TunnelCurlExit
    }
    finally {
        $watch = Stop-ProxyEgressWatch
        $egressWatchActive = $false
    }
    Add-RosetunRunnerNote -Name 'mode-watch-probes' -Value $watch.Probes
    Test-Step -Id 'mode.watch' -Scenario 'mode' -Expectation 'no direct egress during mode changes' -Note "probes=$($watch.Probes) leaks=$($watch.Leaks)" {
        $watch.Probes -gt 0 -and $watch.Leaks -eq 0
    }
    [void](Disconnect-ProxySession)
    Record-NativeCounters -Prefix 'mode-native-reconnect'
    [void](Send-RosetunMarker -Plan $plan -Label 'strict' -Word 'close')
    $openWindow = $null

    # Sharing plain (outside judged windows)
    Set-RosetunRunnerStep -Step 'sharing-plain'
    Test-Step -Id 'sharing.plain.connect' -Scenario 'sharing' -Expectation 'sharing plain connect' { Connect-ProxyVariant 'proxy-share.json' }
    Test-Step -Id 'sharing.plain.host' -Scenario 'sharing' -Expectation 'sharing plain host' { Invoke-LabProxyProbe }
    Test-Step -Id 'sharing.plain.server' -Scenario 'sharing' -Expectation 'sharing plain server' { -not (Invoke-LabProxyProbe -FromServer) }
    Test-Step -Id 'sharing.plain.loopback' -Scenario 'sharing' -Expectation 'sharing plain loopback' { Wait-ProxyCarries }
    [void](Disconnect-ProxySession)

    # Window 2: sharing-strict (judged, allowances: lan-peer-arp, shared-proxy-peer, shared-proxy-server)
    Set-RosetunRunnerStep -Step 'sharing-strict'
    if (Send-RosetunMarker -Plan $plan -Label 'sharing-strict' -Word 'open') { $openWindow = 'sharing-strict' }
    Test-Step -Id 'sharing.strict.connect' -Scenario 'sharing' -Expectation 'sharing strict connect' { Connect-ProxyVariant 'proxy-share-strict.json' }
    Test-Step -Id 'sharing.strict.host' -Scenario 'sharing' -Expectation 'sharing strict host' { Invoke-LabProxyProbe }
    Test-Step -Id 'sharing.strict.server' -Scenario 'sharing' -Expectation 'sharing strict server' { -not (Invoke-LabProxyProbe -FromServer) }
    Test-Step -Id 'sharing.strict.loopback' -Scenario 'sharing' -Expectation 'sharing strict loopback' { Wait-ProxyCarries }
    [void](Disconnect-ProxySession)
    [void](Send-RosetunMarker -Plan $plan -Label 'sharing-strict' -Word 'close')
    $openWindow = $null

    # Sharing off / disconnected (outside judged windows)
    Set-RosetunRunnerStep -Step 'sharing-off'
    Test-Step -Id 'sharing.off' -Scenario 'sharing' -Expectation 'sharing off' {
        (Connect-ProxyVariant 'proxy-plain.json') -and (-not (Invoke-LabProxyProbe))
    }
    [void](Disconnect-ProxySession)
    Test-Step -Id 'sharing.disconnected' -Scenario 'sharing' -Expectation 'sharing disconnected' { -not (Invoke-LabProxyProbe) }

    # Desktop / crash / foreign (outside judged windows, under temporary local user)
    Set-RosetunRunnerStep -Step 'desktop'
    $components.desktop = 'UNVERIFIED'
    $desk = $null
    try {
        $desk = Invoke-DesktopProxySuite
        $desktopRunCleanup = [string]$desk.cleanup
    }
    finally {
        Remove-ProxyDesktopAccount
    }
    $deskErr = if ($null -ne $desk -and $desk.error) { "err=$($desk.error)" } else { '' }
    $deskRestoreNote = if ($null -ne $desk -and $desk.desktop_restore_note) { [string]$desk.desktop_restore_note } else { $deskErr }
    $crashRestoreNote = if ($null -ne $desk -and $desk.crash_restore_note) { [string]$desk.crash_restore_note } else { $deskErr }
    Test-Step -Id 'desktop.set' -Scenario 'desktop' -Expectation 'desktop set' -Note $deskErr { $null -ne $desk -and [bool]$desk.desktop_set }
    Test-Step -Id 'desktop.record' -Scenario 'desktop' -Expectation 'desktop record' { $null -ne $desk -and [bool]$desk.desktop_record }
    Test-Step -Id 'desktop.restore' -Scenario 'desktop' -Expectation 'desktop restore' -Note $deskRestoreNote { $null -ne $desk -and [bool]$desk.desktop_restore }
    Test-Step -Id 'desktop.record-gone' -Scenario 'desktop' -Expectation 'desktop record-gone' { $null -ne $desk -and [bool]$desk.desktop_record_gone }
    Test-Step -Id 'crash.persist' -Scenario 'crash' -Expectation 'crash persist' { $null -ne $desk -and [bool]$desk.crash_persist }
    Test-Step -Id 'crash.restore' -Scenario 'crash' -Expectation 'crash restore' -Note $crashRestoreNote { $null -ne $desk -and [bool]$desk.crash_restore }
    Test-Step -Id 'foreign.preserve' -Scenario 'foreign' -Expectation 'foreign preserve' { $null -ne $desk -and [bool]$desk.foreign_preserve }

    # Window 3: lockdown (judged, allowances: lan-peer-arp, shared-proxy-peer)
    Set-RosetunRunnerStep -Step 'lockdown'
    $components.lockdown = 'UNVERIFIED'
    if (Send-RosetunMarker -Plan $plan -Label 'lockdown' -Word 'open') { $openWindow = 'lockdown' }
    try {
        $ldOn = Invoke-ProxyCli -Arguments @('lockdown', 'on', '--lan', 'off') -Seconds 60
        Test-Step -Id 'lockdown.on' -Scenario 'lockdown' -Expectation 'lockdown on' -Note "exit $($ldOn.ExitCode)" { $ldOn.ExitCode -eq 0 }
        Test-Step -Id 'lockdown.connect' -Scenario 'lockdown' -Expectation 'lockdown connect' { Connect-ProxyVariant 'proxy-share.json' }
        Test-Step -Id 'lockdown.proxy' -Scenario 'lockdown' -Expectation 'lockdown proxy' { Wait-ProxyCarries }
        Test-Step -Id 'lockdown.direct' -Scenario 'lockdown' -Expectation 'lockdown direct' { -not (Test-DirectEgress) }
        Test-Step -Id 'lockdown.host-blocked' -Scenario 'lockdown' -Expectation 'lockdown host-blocked' { -not (Invoke-LabProxyProbe) }
        [void](Disconnect-ProxySession)

        $ldLan = Invoke-ProxyCli -Arguments @('lockdown', 'on', '--lan', 'on') -Seconds 60
        Test-Step -Id 'lockdown.lan-on' -Scenario 'lockdown' -Expectation 'lockdown lan-on' -Note "exit $($ldLan.ExitCode)" { $ldLan.ExitCode -eq 0 }
        Test-Step -Id 'lockdown.lan-connect' -Scenario 'lockdown' -Expectation 'lockdown lan-connect' { Connect-ProxyVariant 'proxy-share-lan.json' }
        Test-Step -Id 'lockdown.host-allowed' -Scenario 'lockdown' -Expectation 'lockdown host-allowed' { Invoke-LabProxyProbe }
    }
    finally {
        [void](Disconnect-ProxySession)
        $ldOff = Invoke-ProxyCli -Arguments @('lockdown', 'off') -Seconds 60
        if ($ldOff.ExitCode -ne 0) { $components.lockdown = 'ERROR' }
        [void](Send-RosetunMarker -Plan $plan -Label 'lockdown' -Word 'close')
        $openWindow = $null
    }
}
catch {
    $runError = $true
    Set-RosetunRunnerError -Place $script:RunnerStatus.step -Text ($_.Exception.GetType().Name + ': ' + $_.Exception.Message)
}
finally {
    Set-RosetunRunnerState -State cleaning -Step 'cleanup'

    if ($egressWatchActive) {
        try { [void](Stop-ProxyEgressWatch) } catch { $components.watch = 'ERROR' }
    }
    if ($null -ne $holderPid) {
        Stop-Process -Id $holderPid -Force -ErrorAction SilentlyContinue
    }
    Remove-ProxyDesktopAccount

    if ($helperStarted -and (Test-Path -LiteralPath $cliPath)) {
        try {
            [void](Disconnect-ProxySession -TimeoutSeconds 25)
            if ((Get-ProxyLockdownLine) -eq 'on') {
                [void](Invoke-ProxyCli -Arguments @('lockdown', 'off') -Seconds 60)
            }
            $cliDisconnectedAtCleanup = ((Get-ProxyState) -eq 'Disconnected')
            $cliLockdownOffAtCleanup = ((Get-ProxyLockdownLine) -eq 'off')
        }
        catch {
            Set-RosetunRunnerError -Place 'cleanup' -Text 'disconnect-or-lockdown-off-failed'
        }
        try { [void](Invoke-ProxyCli -Arguments @('shutdown') -Seconds 15) } catch { }
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

    # Verify all 8 components for windows_proxy.py contract.
    $components.lan = if (@(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $physical }).Count -eq 1) { 'PASS' } else { 'ERROR' }
    if ($components.watch -ne 'NOT_CREATED') {
        $watchClean = (-not (Test-Path -LiteralPath $watchLogPath) -and
            $null -eq (Get-ScheduledTask -TaskName $watchTaskName -ErrorAction SilentlyContinue) -and
            @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'curl.exe' OR Name = 'cmd.exe'" -ErrorAction SilentlyContinue |
                Where-Object { $_.CommandLine -like '*rosetun-egress-probe=*' }).Count -eq 0)
        $components.watch = if ($watchClean) { 'PASS' } else { 'ERROR' }
    }
    if ($components.listener -ne 'NOT_CREATED') {
        $listenerClean = ($null -eq (Get-Process -Id $holderPid -ErrorAction SilentlyContinue) -and
            @(Get-NetTCPConnection -LocalPort $proxyPort -State Listen -ErrorAction SilentlyContinue).Count -eq 0)
        $components.listener = if ($listenerClean) { 'PASS' } else { 'ERROR' }
    }
    $connClean = ($cliDisconnectedAtCleanup -and
        -not (Get-Process -Name 'sing-box' -ErrorAction SilentlyContinue) -and
        -not (Test-TunAdapter))
    $components.connection = if ($connClean) { 'PASS' } else { 'ERROR' }
    if ($components.lockdown -ne 'NOT_CREATED') {
        $wfpClean = Test-WfpLockdownClean
        if ($components.lockdown -eq 'ERROR' -or $wfpClean -eq 'ERROR') { $components.lockdown = 'ERROR' }
        elseif ($cliLockdownOffAtCleanup -and $wfpClean -eq 'PASS') { $components.lockdown = 'PASS' }
        else { $components.lockdown = 'UNVERIFIED' }
    }
    if ($components.desktop -ne 'NOT_CREATED') {
        $deskClean = ($desktopRunCleanup -eq 'PASS' -and
            $null -eq (Get-LocalUser -Name $proxyUser -ErrorAction SilentlyContinue) -and
            $null -eq (Get-ScheduledTask -TaskName $desktopTaskName -ErrorAction SilentlyContinue) -and
            -not (Test-Path -LiteralPath $proxyUserDir) -and
            -not (Get-Process -Name 'desktop_proxy' -ErrorAction SilentlyContinue))
        $components.desktop = if ($deskClean) { 'PASS' } else { 'ERROR' }
    }
    $filesClean = (-not (Test-Path -LiteralPath $work) -and -not (Test-Path -LiteralPath $bin) -and
        $null -eq (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) -and
        -not (Get-Process -Name 'rosetun-helper-privileged' -ErrorAction SilentlyContinue))
    $components.files = if ($filesClean) { 'PASS' } else { 'ERROR' }

    # Window 4: recovery (listed) — after cleanup, proving the network is back.
    Set-RosetunRunnerStep -Step 'recovery'
    [void](Send-RosetunMarker -Plan $plan -Label 'recovery' -Word 'open')
    [void](Test-DirectEgress)
    [void](Test-DirectDns -Name $recoveryDns)
    Start-Sleep -Seconds 2
    [void](Send-RosetunMarker -Plan $plan -Label 'recovery' -Word 'close')

    $cleanupAggregate = if ($components.Values -contains 'ERROR') { 'ERROR' }
        elseif ($components.Values -contains 'UNVERIFIED') { 'UNVERIFIED' }
        else { 'PASS' }
    $statusParts = [ordered]@{}
    foreach ($k in $components.Keys) {
        if ($components[$k] -in @('PASS', 'ERROR', 'UNVERIFIED')) {
            $statusParts[$k] = $components[$k]
        }
    }
    Set-RosetunRunnerCleanup -Result $cleanupAggregate -Parts $statusParts

    if ($null -ne $recorder) {
        try {
            Complete-RosetunListResults -Recorder $recorder -Cleanup $cleanupAggregate `
                -EndBootId (Get-RosetunBootCounter) -Aborted $runError -Components $components
        }
        catch {
            $runError = $true
            Set-RosetunRunnerError -Place 'finalize' -Text ($_.Exception.GetType().Name + ': ' + $_.Exception.Message)
        }
    }
    Set-RosetunRunnerState -State $(if ($runError) { 'failed' } else { 'finished' }) -Step 'done'
}
