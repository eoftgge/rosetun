# Runs the kill-switch failure matrix in the Hyper-V test VM and prints a
# PASS/FAIL table. Exits with 1 if any check fails.
#
# -UseHostNode points the request at the test node on the host, whose address
# changes with every host reboot.

param(
    [Parameter(Mandatory)][string]$SingBoxPath,
    [Parameter(Mandatory)][string]$RequestPath,
    [string]$BuildDir = (Join-Path $PSScriptRoot '..\..\target\release'),
    [switch]$RestoreCheckpoint,
    [switch]$UseHostNode,
    [string]$NodeBindInterface,
    [string]$RealityCoverSite,
    [switch]$KeepNode,
    # Builds the workspace first, so a forgotten build cannot deploy stale binaries.
    [switch]$Build
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RosetunVm.psm1') -Force
Assert-RosetunHostLockdownOff

$results = [System.Collections.Generic.List[object]]::new()

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
    } -ArgumentList (Get-RosetunGuestDir)
}

function Get-HelperLogSince {
    param([Parameter(Mandatory)][long]$Offset)
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $offset)
        $stream = [IO.File]::Open("$dir\helper.log", 'Open', 'Read', 'ReadWrite, Delete')
        try {
            # A rotated log is shorter than the mark: read it whole.
            if ($offset -le $stream.Length) { $stream.Position = $offset }
            [IO.StreamReader]::new($stream).ReadToEnd()
        }
        finally { $stream.Dispose() }
    } -ArgumentList (Get-RosetunGuestDir), $Offset
}

function Format-Egress {
    param([Parameter(Mandatory)]$Egress)
    if ($Egress.Ok) {
        return "after $($Egress.Seconds) s"
    }
    "curl $($Egress.CurlExit), local '$($Egress.LocalIp)', tun '$($Egress.TunAddresses)': $($Egress.Error)"
}

function Set-GuestEgressAdapter {
    param([Parameter(Mandatory)][int]$Index, [Parameter(Mandatory)][bool]$Enabled)
    Invoke-RosetunGuest -ScriptBlock {
        param($index, $enabled)
        $adapter = Get-NetAdapter -InterfaceIndex $index -ErrorAction Stop
        if ($enabled) {
            $adapter | Enable-NetAdapter -Confirm:$false
        }
        else {
            $adapter | Disable-NetAdapter -Confirm:$false
        }
    } -ArgumentList $Index, $Enabled
}

function Wait-GuestEgressRoute {
    param([Parameter(Mandatory)][int]$Index)
    Wait-RosetunCondition {
        Invoke-RosetunGuest -ScriptBlock {
            param($index)
            $address = Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.PrefixOrigin -eq 'Dhcp' -and $_.AddressState -eq 'Preferred' } |
                Select-Object -First 1
            $route = Get-NetRoute -InterfaceIndex $index -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                Select-Object -First 1
            [bool]($address -and $route)
        } -ArgumentList $Index
    } -TimeoutSeconds 60
}

function Test-RosetunWfpFilters {
    Invoke-RosetunGuest -ScriptBlock {
        $path = Join-Path $env:TEMP ("rosetun-wfp-$([guid]::NewGuid().ToString('N')).xml")
        try {
            & netsh.exe wfp show state "file=$path" *> $null
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $path)) {
                throw 'Cannot inspect WFP state.'
            }
            (Get-Content -Raw -LiteralPath $path) -match '51a47ec7-6459-4b84-8854-075e1576e7f9'
        }
        finally {
            Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue
        }
    }
}

function Get-NetworkWaitNote {
    param($Status)
    if ($null -eq $Status) {
        return 'last state: unavailable; reconnect_failure_kind: unavailable'
    }
    $stateName = if ($Status.state -is [string]) {
        $Status.state
    }
    else {
        $Status.state.PSObject.Properties.Name | Select-Object -First 1
    }
    $kind = if ($Status.PSObject.Properties.Name -contains 'reconnect_failure_kind') {
        $Status.reconnect_failure_kind
    }
    else {
        'none'
    }
    "last state: $stateName; reconnect_failure_kind: $kind"
}

function Format-ConnectionsNote {
    # Under Set-StrictMode, `$rows.Route` on an empty list throws and ends the
    # whole run; with no matching row the CLI's own lines are the evidence.
    param($Listed, [object[]]$Rows)
    $routes = @($Rows | ForEach-Object { $_.Route } | Sort-Object -Unique) -join ','
    $note = "curl $($Listed.CurlExit), exit $($Listed.ExitCode), routes $routes"
    if (@($Rows).Count -eq 0) {
        $head = @(($Listed.Output -replace "\x1b\[[0-9;?]*[A-Za-z]", '') -split '\r?\n' |
            Where-Object { $_.Trim() } | Select-Object -First 10) -join ' | '
        $note += "; output: $head"
    }
    $note
}

function Invoke-SettingsCli {
    param(
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter(Mandatory)][ValidateSet('connect', 'apply', 'exits')][string]$Action
    )
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $configPath, $action)
        $env:ROSETUN_CONFIG = $configPath
        try {
            $output = & "$dir\rosetun.exe" $action 2>&1 | ForEach-Object { "$_" }
            $exitCode = $LASTEXITCODE
            $global:LASTEXITCODE = 0
            [pscustomobject]@{ ExitCode = $exitCode; Output = ($output -join "`n") }
        }
        finally {
            Remove-Item Env:ROSETUN_CONFIG -ErrorAction SilentlyContinue
        }
    } -ArgumentList (Get-RosetunGuestDir), $ConfigPath, $Action
}

function Invoke-XraySetting {
    param([Parameter(Mandatory)][ValidateSet('auto', 'off')][string]$Setting)

    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $setting)
        $env:ROSETUN_CONFIG = Join-Path $dir 'matrix-xray-settings.json'
        try {
            $output = & "$dir\rosetun.exe" xray $setting 2>&1 | ForEach-Object { "$_" }
            $exitCode = $LASTEXITCODE
            $global:LASTEXITCODE = 0
            [pscustomobject]@{ ExitCode = $exitCode; Output = ($output -join "`n") }
        }
        finally {
            Remove-Item Env:ROSETUN_CONFIG -ErrorAction SilentlyContinue
        }
    } -ArgumentList (Get-RosetunGuestDir), $Setting
}

function Test-RealityTunnelDns {
    Invoke-RosetunGuest -ScriptBlock {
        $dns = (Get-DnsClientServerAddress -InterfaceAlias 'rosetun0' -AddressFamily IPv4).ServerAddresses |
            Select-Object -First 1
        if (-not $dns) { return $false }
        [bool](Resolve-DnsName 'example.com' -Type A -Server $dns -DnsOnly -QuickTimeout `
            -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 'A' })
    }
}

function Install-OtherAccountService {
    param([string]$GuestDir)
    Invoke-RosetunGuest -ScriptBlock {
        param($dir)
        $output = & (Join-Path $dir 'rosetun-helper-privileged.exe') --install-service 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Could not start the test service: $($output -join ' ')"
        }
        $global:LASTEXITCODE = 0
        $deadline = (Get-Date).AddSeconds(60)
        while ((Get-Service -Name 'Rosetun' -ErrorAction Stop).Status -ne 'Running' -or
            -not ([IO.Directory]::GetFiles('\\.\pipe\') -contains '\\.\pipe\rosetun-helper')) {
            if ((Get-Date) -gt $deadline) {
                throw 'The test service did not open its pipe within 60 seconds.'
            }
            Start-Sleep -Milliseconds 200
        }
    } -ArgumentList $GuestDir
}

function Remove-OtherAccountService {
    param([string]$GuestDir)
    Invoke-RosetunGuest -ScriptBlock {
        param($dir)
        $output = & (Join-Path $dir 'rosetun-helper-privileged.exe') --uninstall-service 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Could not remove the test service: $($output -join ' ')"
        }
        $global:LASTEXITCODE = 0
    } -ArgumentList $GuestDir
}

function Remove-OtherAccount {
    param([string]$Name)
    if (-not $Name) { return }
    Invoke-RosetunGuest -ScriptBlock {
        param($name)
        $user = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
        if ($user) {
            $sid = $user.SID.Value
            try { Remove-LocalUser -Name $name -ErrorAction Stop }
            catch { Write-Warning "Could not remove the other-account test user: $_" }
            Get-CimInstance -ClassName Win32_UserProfile -Filter "SID = '$sid'" -ErrorAction SilentlyContinue |
                Remove-CimInstance -ErrorAction SilentlyContinue
        }
    } -ArgumentList $Name
}

function New-OtherAccount {
    param([string]$Name)
    Invoke-RosetunGuest -ScriptBlock {
        param($name)
        $bytes = New-Object byte[] 24
        $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $random.GetBytes($bytes) }
        finally { $random.Dispose() }
        $password = 'Rt1!' + [Convert]::ToBase64String($bytes)
        $secure = ConvertTo-SecureString -String $password -AsPlainText -Force
        New-LocalUser -Name $name -Password $secure -PasswordNeverExpires | Out-Null
        $password
    } -ArgumentList $Name
}

# Sends requests to the service pipe as another, standard local account.
# A process started with that account's credentials fails inside PowerShell
# Direct (no window station: STATUS_DLL_INIT_FAILED), and a scheduled task as a
# fresh account did not finish, so the guest impersonates the account on its
# own thread while it opens the pipe; the service sees that account's token.
# This checks the service's decision; the CLI's wording is covered by unit tests.
function Invoke-OtherAccountRequests {
    param([string]$Name, [string]$Password, [string]$GuestDir, [int]$ProtocolVersion,
        [string[]]$Commands)
    Invoke-RosetunGuest -ScriptBlock {
        param($name, $password, $dir, $protocolVersion, [string[]]$commands)

        function Read-Reply {
            param($Reader, [int]$Id, [int]$TimeoutSeconds = 15)
            $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
            while ($true) {
                $remaining = [int]($deadline - (Get-Date)).TotalMilliseconds
                if ($remaining -le 0) { throw 'timed out waiting for the service' }
                $read = $Reader.ReadLineAsync()
                if (-not $read.Wait($remaining)) { throw 'timed out waiting for the service' }
                if ($null -eq $read.Result) { throw 'the service closed the connection' }
                $frame = $read.Result | ConvertFrom-Json
                if ($frame.PSObject.Properties.Name -contains 'response' -and
                    $frame.response.id -eq $Id) {
                    return $frame.response.body
                }
            }
        }

        if (-not ('RosetunOtherLogon' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class RosetunOtherLogon {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LogonUserW(string user, string domain, string password,
        int logonType, int provider, out IntPtr token);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);

    // LOGON32_LOGON_INTERACTIVE with the default provider: the account's own,
    // non-elevated token. Users may log on locally by default.
    public static IntPtr Logon(string user, string password) {
        IntPtr token;
        if (!LogonUserW(user, ".", password, 2, 0, out token)) {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        return token;
    }
}
'@
        }

        $requestJson = (Get-Content -LiteralPath (Join-Path $dir 'request.json') -Raw) -replace '[\r\n]+', ' '
        $bodies = [ordered]@{
            status = '"status"'
            disconnect = '"disconnect"'
            temporary = '"temporary_rules"'
            connections = '"connections"'
            # Ownership is checked before the id is looked at, so any id will do.
            close = '{"close_connection":{"id":"' + [guid]::NewGuid().ToString() + '"}}'
            apply ='{"apply":' + $requestJson + '}'
            connect = '{"connect":' + $requestJson + '}'
        }
        $cli = Join-Path $dir 'rosetun.exe'
        $token = [IntPtr]::Zero
        $identity = $null
        $logonError = $null
        try {
            $token = [RosetunOtherLogon]::Logon($name, $password)
            $identity = [System.Security.Principal.WindowsIdentity]::new($token)
        }
        catch { $logonError = "logon as the test account failed: $($_.Exception.Message)" }
        try {
            foreach ($command in $commands) {
                $reply = $null
                $pipe = $null
                try {
                    if ($logonError) { throw $logonError }
                    $pipe = [System.IO.Pipes.NamedPipeClientStream]::new('.', 'rosetun-helper',
                        [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None,
                        [System.Security.Principal.TokenImpersonationLevel]::Identification)
                    $context = $identity.Impersonate()
                    try { $pipe.Connect(5000) }
                    finally { $context.Undo() }
                    $writer = [System.IO.StreamWriter]::new($pipe, [System.Text.UTF8Encoding]::new($false))
                    $writer.NewLine = "`n"
                    $writer.AutoFlush = $true
                    $reader = [System.IO.StreamReader]::new($pipe, [System.Text.UTF8Encoding]::new($false))
                    $writer.WriteLine('{"request":{"id":1,"body":{"hello":{"client":"rosetun-matrix","protocol_version":' +
                        $protocolVersion + '}}}}')
                    $hello = Read-Reply -Reader $reader -Id 1
                    if (-not $hello.hello) {
                        throw "the handshake was refused: $($hello | ConvertTo-Json -Compress -Depth 8)"
                    }
                    $writer.WriteLine('{"request":{"id":2,"body":' + $bodies[$command] + '}}')
                    $timeout = if ($command -eq 'connect') { 60 } else { 15 }
                    $body = Read-Reply -Reader $reader -Id 2 -TimeoutSeconds $timeout
                    $code = ''
                    $state = ''
                    $succeeded = $false
                    if ($body -is [string]) {
                        $reply = $body
                        $succeeded = $body -eq 'ok'
                    }
                    elseif ($body.PSObject.Properties.Name -contains 'error') {
                        $code = [string]$body.error.code
                        $reply = "error ${code}: $($body.error.message)"
                    }
                    elseif ($body.PSObject.Properties.Name -contains 'status') {
                        $state = [string]$body.status.state
                        $reply = "status $state"
                        $succeeded = $true
                    }
                    else {
                        $reply = $body | ConvertTo-Json -Compress -Depth 8
                        $succeeded = $body.PSObject.Properties.Name -contains 'temporary_rules' -or
                            $body.PSObject.Properties.Name -contains 'connections'
                    }
                }
                catch {
                    $reply = "failed: $($_.Exception.Message)"
                    $code = ''
                    $state = ''
                    $succeeded = $false
                }
                finally {
                    if ($pipe) { $pipe.Dispose() }
                }
                $adminStatus = & $cli status 2>&1 | ForEach-Object { "$_" }
                $adminExit = $LASTEXITCODE
                $global:LASTEXITCODE = 0
                [pscustomobject]@{
                    Command = $command
                    Reply = $reply
                    Code = $code
                    State = $state
                    Succeeded = $succeeded
                    StillConnected = ($adminExit -eq 0 -and
                        ($adminStatus -join "`n") -match '(?m)^state: Connected\r?$')
                }
            }
        }
        finally {
            if ($identity) { $identity.Dispose() }
            if ($token -ne [IntPtr]::Zero) { [RosetunOtherLogon]::CloseHandle($token) | Out-Null }
        }
    } -ArgumentList $Name, $Password, $GuestDir, $ProtocolVersion, $Commands
}

$nodeStartedByMatrix = $false
$blockedNodeStartedByMatrix = $false
$xrayNode = $null
$lanListener = $null
$egressWatchActive = $false
$otherAccountName = $null
$serviceAttempted = $false
$consoleStoppedForOther = $false
$ipv6Neighbors = [System.Collections.Generic.List[object]]::new()
try {
if ($Build) {
    Write-Host 'Building...'
    & cargo build -q --release --manifest-path (Join-Path $PSScriptRoot '..\..\Cargo.toml')
    $exitCode = $LASTEXITCODE
    $global:LASTEXITCODE = 0
    if ($exitCode -ne 0) {
        throw "cargo build failed with exit code $exitCode."
    }
}

if ($UseHostNode) {
    if (-not $RealityCoverSite) {
        throw '-RealityCoverSite is required with -UseHostNode.'
    }
    if ($NodeBindInterface) {
        $nodeStartedByMatrix = Start-RosetunTestNode -SingBoxPath $SingBoxPath -BindInterface $NodeBindInterface
    }
    else {
        $nodeStartedByMatrix = Start-RosetunTestNode -SingBoxPath $SingBoxPath
    }
    if ($NodeBindInterface) {
        $blockedNodeStartedByMatrix = Start-RosetunTestNode -SingBoxPath $SingBoxPath `
            -BindInterface $NodeBindInterface -CloudflareBlocked
    }
    else {
        $blockedNodeStartedByMatrix = Start-RosetunTestNode -SingBoxPath $SingBoxPath -CloudflareBlocked
    }
    $xrayNode = Start-RosetunXrayTestNode -CoverSite $RealityCoverSite -BindInterface $NodeBindInterface
}

if ($RestoreCheckpoint) {
    Write-Host 'Restoring the clean checkpoint...'
    Restore-RosetunVm
}

Write-Host 'Deploying binaries...'
# A helper left running by a previous run keeps its executable locked.
Stop-RosetunHelper
Publish-Rosetun -BuildDir $BuildDir -SingBoxPath $SingBoxPath -RequestPath $RequestPath `
    -UseHostNode:$UseHostNode -XrayNode $xrayNode
Register-RosetunHelper
Start-RosetunHelper
$lanListener = Start-RosetunLanListener

Set-RosetunIpv6Neighbor -Created $ipv6Neighbors
$protocolSource = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '..\..\crates\rosetun-ipc\src\protocol.rs')
if (-not ($protocolSource -match 'pub const PROTOCOL_VERSION: u32 = (\d+);')) {
    throw 'Could not read PROTOCOL_VERSION from rosetun-ipc.'
}
$protocolVersion = [int]$Matches[1]

# Proves the probe itself works. Without it, every "blocked" check below would
# pass even if the probe were broken or the probe URL unreachable.
Test-Step 'baseline' 'direct egress works before connect' { Test-RosetunDirectEgress }
Test-Step 'baseline' 'direct DNS works before connect' { Test-RosetunDirectDns }
Test-Step 'baseline' 'direct TCP DNS works before connect' { Test-RosetunDirectDns -Tcp }
Test-Step 'baseline' 'IPv6 to the host works before connect' { Test-RosetunIpv6Egress }
if ($results[$results.Count - 1].Result -eq 'FAIL') {
    throw "IPv6 to the host does not work, so every 'IPv6 outside the tunnel is blocked' check would be meaningless. $(Get-RosetunIpv6NeighborReport)"
}
# The new firewall rule can take a moment to accept guest connections.
Test-Step 'baseline' 'LAN listener is reachable before connect' {
    Wait-RosetunCondition { Test-RosetunLanListener $lanListener } -TimeoutSeconds 10
}

Write-Host 'No network before connect...'
$networkAdapter = Get-RosetunEgressInterface
try {
    Set-GuestEgressAdapter -Index $networkAdapter.Index -Enabled $false
    $networkTimer = [Diagnostics.Stopwatch]::StartNew()
    $attempt = Connect-RosetunTunnel -Quiet
    $failed = Wait-RosetunState 'Failed' -TimeoutSeconds 10
    $networkTimer.Stop()
    $status = Get-RosetunStatus -ProtocolVersion $protocolVersion
    Test-Step 'no network' 'Failed with no network within 10 s' `
        -Note "exit $($attempt.ExitCode); after $($networkTimer.Elapsed.TotalSeconds) s" {
        $attempt.ExitCode -ne 0 -and $failed -and $networkTimer.Elapsed.TotalSeconds -le 10 -and
            $status.state.failed.failure_kind -eq 'no_network' -and
            $attempt.Output -match 'NoNetwork'
    }
    Test-Step 'no network' 'no WFP filters were installed' { -not (Test-RosetunWfpFilters) }
    Test-Step 'no network' 'no TUN adapter was created' { -not (Test-RosetunTunAdapter) }
    Test-Step 'no network' 'engine did not start' { -not (Test-RosetunEngineRunning) }
}
finally {
    Set-GuestEgressAdapter -Index $networkAdapter.Index -Enabled $true
}
$routeRestored = Wait-GuestEgressRoute -Index $networkAdapter.Index
Test-Step 'no network' 'physical route returns after adapter enable' { $routeRestored }
if (-not $routeRestored) { throw 'The guest physical route did not return after adapter enable.' }
# An ActiveStore neighbor entry may not survive the adapter restart.
Set-RosetunIpv6Neighbor -Created $ipv6Neighbors

Write-Host 'Connect...'
Connect-RosetunTunnel | Out-Null
Test-Step 'connect' 'state is Connected' { Wait-RosetunState 'Connected' }
$egress = Wait-RosetunTunnelEgress
# Connected must mean usable: a tunnel that needs seconds before the first
# request gets through looks broken to the user.
Test-Step 'connect' 'tunnel carries traffic within 5 s, DNS included' -Note (Format-Egress $egress) {
    $egress.Ok -and $egress.Seconds -le 5
}
Test-Step 'connect' 'direct egress is blocked' { -not (Test-RosetunDirectEgress) }
Test-Step 'connect' 'IPv6 outside the tunnel is blocked' { -not (Test-RosetunIpv6Egress) }
$probe = Invoke-RosetunProbe
Test-Step 'connect' 'server check works while connected' -Note "exit $($probe.ExitCode)" {
    $probe.ExitCode -eq 0 -and $probe.Output -match '(?m)^works \d+ ms$'
}
$delay = Invoke-RosetunCli -Quiet 'delay'
Test-Step 'connect' 'tunnel delay works' -Note "exit $($delay.ExitCode)" {
    $delay.ExitCode -eq 0 -and $delay.Output -match '(?m)^works \d+ ms$'
}
# The same check as through Xray: if it fails here too, the test or the lab is at fault.
Test-Step 'connect' 'UDP reaches the internet through the node (NTP)' { Test-RosetunUdpInternet }
$connectionsHost = ([uri](Get-RosetunTunnelProbeUrl)).Host
$listed = Invoke-RosetunConnectionsDuring -Url (Get-RosetunTunnelProbeUrl)
$rows = @(Get-RosetunConnectionRows $listed.Output | Where-Object { $_.Destination -like "${connectionsHost}:*" })
Test-Step 'connections' "a request to $connectionsHost is listed through the VPN" `
    -Note (Format-ConnectionsNote $listed $rows) {
    $listed.CurlExit -eq 0 -and $listed.ExitCode -eq 0 -and $rows.Count -gt 0 -and
        @($rows | Where-Object Route -ne 'proxy').Count -eq 0
}
$longTransferHost = ([uri](Get-RosetunLongTransferUrl)).Host
$closing = Invoke-RosetunConnectionClose -Url (Get-RosetunLongTransferUrl)
$closedId = $closing.Id
$closedRows = @(Get-RosetunConnectionRows $closing.After | Where-Object { $closedId -and $_.Id -eq $closedId })
# curl exits 28 only at --max-time, which the download reaches unless it is closed.
Test-Step 'connections' "closing a download from $longTransferHost by its id ends it early" `
    -Note "close exit $($closing.CloseExit): $($closing.CloseOutput); curl $($closing.CurlExit) after $($closing.CurlSeconds) s" {
    $closedId -and $closing.CloseExit -eq 0 -and $null -ne $closing.CurlExit -and
        $closing.CurlExit -notin @(0, 28) -and $closing.CurlSeconds -lt 30
}
Test-Step 'connections' 'the closed download moves to the closed list' `
    -Note "states: $(@($closedRows | ForEach-Object { $_.State }) -join ',')" {
    $closedRows.Count -gt 0 -and @($closedRows | Where-Object State -ne 'closed').Count -eq 0
}
Test-Step 'no network' 'connect succeeds after the route returns' { (Get-RosetunState) -eq 'Connected' }
Test-Step 'no network' 'direct egress is blocked after the route returns' { -not (Test-RosetunDirectEgress) }

Write-Host 'No network during a protected session...'
Disconnect-RosetunTunnel | Out-Null
$autoConnect = Connect-RosetunTunnel -RequestName 'request-auto-reconnect.json' -Quiet
Test-Step 'no network session' 'auto-reconnect request is Connected' -Note "exit $($autoConnect.ExitCode)" {
    $autoConnect.ExitCode -eq 0 -and (Wait-RosetunState 'Connected')
}
Test-Step 'no network session' 'direct egress is blocked before network loss' {
    -not (Test-RosetunDirectEgress)
}
Start-RosetunEgressWatch
$egressWatchActive = $true
$watch = $null
$returnTimer = $null
try {
    try {
        Set-GuestEgressAdapter -Index $networkAdapter.Index -Enabled $false
        $script:lastNetworkStatus = $null
        $networkLost = Wait-RosetunCondition {
            $script:lastNetworkStatus = Get-RosetunStatus -ProtocolVersion $protocolVersion
            $script:lastNetworkStatus.state -eq 'reconnecting' -and
                $script:lastNetworkStatus.PSObject.Properties.Name -contains 'reconnect_failure_kind' -and
                $script:lastNetworkStatus.reconnect_failure_kind -eq 'no_network'
        } -TimeoutSeconds 10
        $networkLostNote = if ($networkLost) { '' } else { Get-NetworkWaitNote $script:lastNetworkStatus }
        Test-Step 'no network session' 'status reports no network while waiting' -Note $networkLostNote {
            $networkLost
        }
        Test-Step 'no network session' 'WFP filters stay installed' { Test-RosetunWfpFilters }
    }
    finally {
        $returnTimer = [Diagnostics.Stopwatch]::StartNew()
        Set-GuestEgressAdapter -Index $networkAdapter.Index -Enabled $true
    }
    $routeRestored = Wait-GuestEgressRoute -Index $networkAdapter.Index
    Test-Step 'no network session' 'physical route returns' { $routeRestored }
    $connected = Wait-RosetunState 'Connected' -TimeoutSeconds 60
    $returnTimer.Stop()
    $reconnectNote = "after $($returnTimer.Elapsed.TotalSeconds) s"
    if (-not $connected) {
        $reconnectNote += "; $(Get-NetworkWaitNote (Get-RosetunStatus -ProtocolVersion $protocolVersion))"
    }
    Test-Step 'no network session' 'reconnected within 60 s of adapter enable' `
        -Note $reconnectNote {
        $routeRestored -and $connected -and $returnTimer.Elapsed.TotalSeconds -le 60
    }
    # After the timed reconnect, so the pin does not count against it.
    if ($routeRestored) { Set-RosetunIpv6Neighbor -Created $ipv6Neighbors }
    Test-Step 'no network session' 'direct egress stays blocked after recovery' {
        -not (Test-RosetunDirectEgress)
    }
}
finally {
    $watch = Stop-RosetunEgressWatch
    $egressWatchActive = $false
}
Test-Step 'no network session' "no direct leak through loss and recovery ($($watch.Probes) probes)" {
    $watch.Probes -gt 0 -and $watch.Leaks -eq 0
}
Disconnect-RosetunTunnel | Out-Null
$baseConnect = Connect-RosetunTunnel -Quiet
Test-Step 'no network session' 'base request is restored' -Note "exit $($baseConnect.ExitCode)" {
    $baseConnect.ExitCode -eq 0 -and (Wait-RosetunState 'Connected') -and
        -not (Test-RosetunDirectEgress)
}

# Not the first connect of the run: the first adapter creation in a fresh VM
# can leave the tunnel silent for a while, which this scenario must not measure.
Disconnect-RosetunTunnel | Out-Null
if ($UseHostNode) {
    Write-Host 'Connect through the node whose exit cannot reach Cloudflare...'
    $blockedConnect = Connect-RosetunTunnel -RequestName 'request-cloudflare-blocked.json' -Quiet
    Test-Step 'Cloudflare blocked at exit' 'connect succeeds' -Note "exit $($blockedConnect.ExitCode)" {
        $blockedConnect.ExitCode -eq 0
    }
    Test-Step 'Cloudflare blocked at exit' 'state is Connected' { Wait-RosetunState 'Connected' }
    $probe = Invoke-RosetunProbe 'request-cloudflare-blocked.json'
    Test-Step 'Cloudflare blocked at exit' 'server check works' -Note "exit $($probe.ExitCode)" {
        $probe.ExitCode -eq 0 -and $probe.Output -match '(?m)^works \d+ ms$'
    }
    $delay = Invoke-RosetunCli -Quiet 'delay'
    Test-Step 'Cloudflare blocked at exit' 'tunnel delay works' -Note "exit $($delay.ExitCode)" {
        $delay.ExitCode -eq 0 -and $delay.Output -match '(?m)^works \d+ ms$'
    }
    Test-Step 'Cloudflare blocked at exit' 'direct egress stays blocked' {
        -not (Test-RosetunDirectEgress)
    }
    Disconnect-RosetunTunnel | Out-Null
    Test-Step 'Cloudflare blocked at exit' 'direct egress works after disconnect' {
        Test-RosetunDirectEgress
    }

    Write-Host 'Route one domain through a second node...'
    $exitNodeStartedByMatrix = $false
    $exitConfigPath = Join-Path (Get-RosetunGuestDir) 'exit-matrix\config.json'
    try {
        $exitNodeStartedByMatrix = if ($NodeBindInterface) {
            Start-RosetunTestNode -SingBoxPath $SingBoxPath -BindInterface $NodeBindInterface -ExitNode
        }
        else {
            Start-RosetunTestNode -SingBoxPath $SingBoxPath -ExitNode
        }
        $exitRuleUrl = Get-RosetunExitRuleUrl
        $exitConnect = Connect-RosetunTunnel -RequestName 'request-rule-exit.json' -Quiet
        Test-Step 'Rule through another server' 'connect succeeds' -Note "exit $($exitConnect.ExitCode)" {
            $exitConnect.ExitCode -eq 0
        }
        Test-Step 'Rule through another server' 'state is Connected' { Wait-RosetunState 'Connected' }
        $exitSince = (Get-RosetunStatus -ProtocolVersion $protocolVersion).since_unix

        # Each node logs a line per proxied connection, so the counts show
        # which node carried a request. Only the rule's domain goes to the second.
        $secondBefore = Get-RosetunTestNodeConnections -ExitNode
        $egress = Wait-RosetunTunnelEgress -Url $exitRuleUrl -SkipRevocationCheck
        Start-Sleep -Seconds 1
        $secondAfterRule = Get-RosetunTestNodeConnections -ExitNode
        Test-Step 'Rule through another server' 'rule domain goes through the second node' `
            -Note "$(Format-Egress $egress); second node +$($secondAfterRule - $secondBefore)" {
            $egress.Ok -and $secondAfterRule -gt $secondBefore
        }
        $firstBefore = Get-RosetunTestNodeConnections
        $egress = Wait-RosetunTunnelEgress
        Start-Sleep -Seconds 1
        $firstAfter = Get-RosetunTestNodeConnections
        $secondAfterOther = Get-RosetunTestNodeConnections -ExitNode
        Test-Step 'Rule through another server' 'other traffic goes through the first node' `
            -Note "$(Format-Egress $egress); first node +$($firstAfter - $firstBefore), second node +$($secondAfterOther - $secondAfterRule)" {
            $egress.Ok -and $firstAfter -gt $firstBefore -and $secondAfterOther -eq $secondAfterRule
        }
        $delay = Invoke-RosetunCli -Quiet 'delay'
        Test-Step 'Rule through another server' 'delay shows the second node answering' `
            -Note "exit $($delay.ExitCode)" {
            $delay.ExitCode -eq 0 -and $delay.Output -match '(?m)^works \d+ ms$' -and
                $delay.Output -match '(?m)^  second-node\tworks \d+ ms$'
        }

        # A settings apply must keep the exit on the session's node. The config
        # lists an unreachable Dutch decoy first, which an unpinned resolution
        # would pick for the country exit.
        Invoke-RosetunGuest -ScriptBlock {
            param($dir, $configPath)
            New-Item -Path (Split-Path -Parent $configPath) -ItemType Directory -Force | Out-Null
            $request = Get-Content -Path (Join-Path $dir 'request-rule-exit.json') -Raw | ConvertFrom-Json
            $flag = [char]::ConvertFromUtf32(0x1F1F3) + [char]::ConvertFromUtf32(0x1F1F1)
            $exitNode = $request.extra_nodes[0].node
            $exitNode.name = "$flag Exit test node"
            $decoy = $exitNode | ConvertTo-Json -Depth 20 | ConvertFrom-Json
            $decoy.id = 'home-exit-decoy'
            $decoy.name = "$flag Decoy node"
            $decoy.server = '192.0.2.1'
            $config = @{
                version = 5
                settings = $request.settings
                subscriptions = @(@{
                    id = $request.selection.subscription
                    name = 'Test node'
                    url = 'https://example.invalid/subscription'
                    nodes = @($request.node, $decoy, $exitNode)
                })
                active = $request.selection
                active_rule_set = $request.rule_set.id
                rule_sets = @($request.rule_set)
                exits = @(@{
                    id = 'second-node'
                    name = 'Second node'
                    target = @{ country = 'NL' }
                })
            }
            [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 30))
        } -ArgumentList (Get-RosetunGuestDir), $exitConfigPath
        $exitApply = Invoke-SettingsCli -ConfigPath $exitConfigPath -Action apply
        Test-Step 'Rule through another server' 'apply in the session succeeds' `
            -Note "exit $($exitApply.ExitCode)" {
            $exitApply.ExitCode -eq 0 -and (Wait-RosetunState 'Connected')
        }
        $exitList = Invoke-SettingsCli -ConfigPath $exitConfigPath -Action exits
        Test-Step 'Rule through another server' 'exits lists the session node' `
            -Note "exit $($exitList.ExitCode)" {
            $exitList.ExitCode -eq 0 -and
                $exitList.Output -match '(?m)^  second-node\tSecond node\tcountry NL\t[^\t]*Exit test node\t1$' -and
                $exitList.Output -notmatch '192\.0\.2\.1\b'
        }
        $secondBefore = Get-RosetunTestNodeConnections -ExitNode
        $egress = Wait-RosetunTunnelEgress -Url $exitRuleUrl -SkipRevocationCheck
        Start-Sleep -Seconds 1
        $secondAfterApply = Get-RosetunTestNodeConnections -ExitNode
        Test-Step 'Rule through another server' 'apply keeps the exit node' `
            -Note "$(Format-Egress $egress); second node +$($secondAfterApply - $secondBefore)" {
            $egress.Ok -and $secondAfterApply -gt $secondBefore
        }
        $exitSince = (Get-RosetunStatus -ProtocolVersion $protocolVersion).since_unix

        Stop-RosetunTestNode -ExitNode
        $exitNodeStartedByMatrix = $false
        Test-Step 'Rule through another server' 'rule domain fails without the second node' {
            -not (Test-RosetunTunnelEgress -Url $exitRuleUrl -SkipRevocationCheck)
        }
        $delay = Invoke-RosetunCli -Quiet 'delay'
        Test-Step 'Rule through another server' 'delay shows the second node not answering' `
            -Note "exit $($delay.ExitCode)" {
            $delay.ExitCode -eq 0 -and $delay.Output -match '(?m)^works \d+ ms$' -and
                $delay.Output -match '(?m)^  second-node\tnot answering$'
        }
        $egress = Wait-RosetunTunnelEgress
        Test-Step 'Rule through another server' 'other traffic still works' -Note (Format-Egress $egress) {
            $egress.Ok
        }
        # Longer than the watchdog interval: a dead second node must not restart the session.
        Start-Sleep -Seconds 35
        $exitStatus = Get-RosetunStatus -ProtocolVersion $protocolVersion
        Test-Step 'Rule through another server' 'session stays Connected without a restart' {
            $exitStatus.state -eq 'connected' -and $exitStatus.since_unix -eq $exitSince
        }
        Test-Step 'Rule through another server' 'direct egress stays blocked' {
            -not (Test-RosetunDirectEgress)
        }
    }
    finally {
        if ($exitNodeStartedByMatrix -and -not $KeepNode) {
            try { Stop-RosetunTestNode -ExitNode }
            catch { Write-Warning "Could not stop the exit test node: $_" }
        }
        Invoke-RosetunGuest -ScriptBlock {
            param($configPath)
            Remove-Item -Path (Split-Path -Parent $configPath) -Recurse -Force -ErrorAction SilentlyContinue
        } -ArgumentList $exitConfigPath
    }
    Disconnect-RosetunTunnel | Out-Null
    $baseConnect = Connect-RosetunTunnel -Quiet
    Test-Step 'Rule through another server' 'base request is restored' -Note "exit $($baseConnect.ExitCode)" {
        $baseConnect.ExitCode -eq 0 -and (Wait-RosetunState 'Connected') -and
            -not (Test-RosetunDirectEgress)
    }
    Disconnect-RosetunTunnel | Out-Null

    Write-Host 'Connect to a new Xray REALITY server in automatic mode...'
    $realityConnect = Connect-RosetunTunnel -RequestName 'request-reality.json' -Quiet
    Test-Step 'REALITY auto' 'connect succeeds' -Note "exit $($realityConnect.ExitCode)" {
        $realityConnect.ExitCode -eq 0
    }
    Test-Step 'REALITY auto' 'state is Connected' { Wait-RosetunState 'Connected' }
    $realityStatus = Get-RosetunStatus -ProtocolVersion $protocolVersion
    Test-Step 'REALITY auto' 'Xray is active in automatic mode' {
        $realityStatus.xray -and $realityStatus.xray_use -eq 'auto'
    }
    $egress = Wait-RosetunTunnelEgress
    Test-Step 'REALITY auto' 'tunnel carries traffic and resolves DNS' -Note (Format-Egress $egress) {
        $egress.Ok
    }
    Test-Step 'REALITY auto' 'UDP DNS resolves inside the tunnel' { Test-RealityTunnelDns }
    Test-Step 'REALITY auto' 'UDP reaches the internet through Xray (NTP)' { Test-RosetunUdpInternet }
    Test-Step 'REALITY auto' 'direct egress is blocked' { -not (Test-RosetunDirectEgress) }
    Test-Step 'REALITY auto' 'direct UDP DNS is blocked' { -not (Test-RosetunDirectDns) }
    $probe = Invoke-RosetunProbe 'request-reality.json'
    Test-Step 'REALITY auto' 'server check works' -Note "exit $($probe.ExitCode)" {
        $probe.ExitCode -eq 0 -and $probe.Output -match '(?m)^works \d+ ms$'
    }
    $delay = Invoke-RosetunCli -Quiet 'delay'
    Test-Step 'REALITY auto' 'tunnel delay works' -Note "exit $($delay.ExitCode)" {
        $delay.ExitCode -eq 0 -and $delay.Output -match '(?m)^works \d+ ms$'
    }
    Disconnect-RosetunTunnel | Out-Null

    Write-Host 'The same REALITY server without Xray...'
    try {
        $setting = Invoke-XraySetting -Setting off
        Test-Step 'REALITY off' 'rosetun xray off succeeds' -Note "exit $($setting.ExitCode)" {
            $setting.ExitCode -eq 0
        }
        # Explicit request files bypass the CLI store, so mirror the off setting in the request.
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $rejected = Connect-RosetunTunnel -RequestName 'request-reality-xray-off.json' -Quiet
        $timer.Stop()
        Test-Step 'REALITY off' 'connect is rejected by REALITY within 60 s' `
            -Note "exit $($rejected.ExitCode) after $([int]$timer.Elapsed.TotalSeconds) s" {
            $rejected.ExitCode -ne 0 -and $timer.Elapsed.TotalSeconds -le 60 -and
                $rejected.Output -match 'ServerRejected'
        }
        # A failed first connect releases protection, as in 'unreachable connect'.
        Test-Step 'REALITY off' 'state is Failed' { Wait-RosetunState 'Failed' -TimeoutSeconds 10 }
        Test-Step 'REALITY off' 'direct egress works again' { Test-RosetunDirectEgress }
        Test-Step 'REALITY off' 'tunnel adapter is gone' {
            Wait-RosetunCondition { -not (Test-RosetunTunAdapter) }
        }
    }
    finally {
        $setting = Invoke-XraySetting -Setting auto
        Test-Step 'REALITY off' 'rosetun xray auto restores the setting' -Note "exit $($setting.ExitCode)" {
            $setting.ExitCode -eq 0
        }
        Invoke-RosetunGuest -ScriptBlock {
            param($dir)
            Remove-Item -LiteralPath (Join-Path $dir 'matrix-xray-settings.json') -Force -ErrorAction SilentlyContinue
        } -ArgumentList (Get-RosetunGuestDir)
    }
    Disconnect-RosetunTunnel | Out-Null

    Write-Host 'Kill the Xray child during a protected session...'
    Connect-RosetunTunnel -RequestName 'request-reality.json' | Out-Null
    Test-Step 'REALITY child killed' 'state is Connected before the kill' { Wait-RosetunState 'Connected' }
    Start-RosetunEgressWatch
    $egressWatchActive = $true
    try {
        Stop-RosetunXrayEngine
        $xrayStopped = Wait-RosetunCondition {
            (Get-RosetunStatus -ProtocolVersion $protocolVersion).xray_stopped
        } -TimeoutSeconds 20
        $xrayReconnected = Wait-RosetunState 'Connected' -TimeoutSeconds 90
    }
    finally {
        $watch = Stop-RosetunEgressWatch
        $egressWatchActive = $false
    }
    Test-Step 'REALITY child killed' 'status reports Xray stopped' { $xrayStopped }
    Test-Step 'REALITY child killed' 'helper reconnects with Xray' {
        $xrayReconnected -and (Test-RosetunXrayRunning) -and
            (Get-RosetunStatus -ProtocolVersion $protocolVersion).xray
    }
    Test-Step 'REALITY child killed' "no direct leak ($($watch.Probes) probes)" {
        $watch.Probes -gt 0 -and $watch.Leaks -eq 0
    }
    Test-Step 'REALITY child killed' 'direct egress remains blocked' { -not (Test-RosetunDirectEgress) }
    Disconnect-RosetunTunnel | Out-Null

    Write-Host 'Apply Shadowsocks to REALITY and back under protection...'
    Connect-RosetunTunnel -RequestName 'request-reality-apply-back.json' | Out-Null
    Start-RosetunEgressWatch
    $egressWatchActive = $true
    try {
        $apply = Invoke-RosetunApply 'request-reality.json' -Quiet
        Test-Step 'REALITY apply' 'Shadowsocks to REALITY succeeds' -Note "exit $($apply.ExitCode)" {
            $apply.ExitCode -eq 0 -and (Get-RosetunState) -eq 'Connected'
        }
        $egress = Wait-RosetunTunnelEgress
        Test-Step 'REALITY apply' 'REALITY carries traffic' -Note (Format-Egress $egress) { $egress.Ok }
        Test-Step 'REALITY apply' 'direct egress is blocked on REALITY' { -not (Test-RosetunDirectEgress) }
        $apply = Invoke-RosetunApply 'request-reality-apply-back.json' -Quiet
        Test-Step 'REALITY apply' 'REALITY to Shadowsocks succeeds' -Note "exit $($apply.ExitCode)" {
            $apply.ExitCode -eq 0 -and (Get-RosetunState) -eq 'Connected'
        }
        $egress = Wait-RosetunTunnelEgress
        Test-Step 'REALITY apply' 'Shadowsocks carries traffic again' -Note (Format-Egress $egress) {
            $egress.Ok
        }
        Test-Step 'REALITY apply' 'direct egress stays blocked' { -not (Test-RosetunDirectEgress) }
    }
    finally {
        $watch = Stop-RosetunEgressWatch
        $egressWatchActive = $false
    }
    Test-Step 'REALITY apply' "no direct leak ($($watch.Probes) probes)" {
        $watch.Probes -gt 0 -and $watch.Leaks -eq 0
    }
    Disconnect-RosetunTunnel | Out-Null

    Write-Host 'Kill the helper during a REALITY session...'
    Connect-RosetunTunnel -RequestName 'request-reality.json' | Out-Null
    Test-Step 'REALITY helper killed' 'both children run before the kill' {
        (Test-RosetunEngineRunning) -and (Test-RosetunXrayRunning)
    }
    Stop-RosetunHelper
    Test-Step 'REALITY helper killed' 'sing-box and Xray stop with the helper' {
        Wait-RosetunCondition { -not (Test-RosetunEngineRunning) -and -not (Test-RosetunXrayRunning) } `
            -TimeoutSeconds 20
    }
    Test-Step 'REALITY helper killed' 'tunnel adapter is removed' {
        Wait-RosetunCondition { -not (Test-RosetunTunAdapter) } -TimeoutSeconds 20
    }
    Start-RosetunHelper
}

Write-Host 'Another Windows account cannot control the tunnel...'
$serviceAlreadyInstalled = Invoke-RosetunGuest -ScriptBlock {
    [bool](Get-Service -Name 'Rosetun' -ErrorAction SilentlyContinue)
}
if ($serviceAlreadyInstalled) {
    throw 'A Rosetun service is already installed in the guest; refusing to change it.'
}
Disconnect-RosetunTunnel | Out-Null
Stop-RosetunHelper
$consoleStoppedForOther = $true
$serviceAttempted = $true
Install-OtherAccountService -GuestDir (Get-RosetunGuestDir)
$serviceConnect = Connect-RosetunTunnel -Quiet
Test-Step 'other account' 'administrator connects through the service' -Note "exit $($serviceConnect.ExitCode)" {
    $serviceConnect.ExitCode -eq 0 -and (Get-RosetunState) -eq 'Connected'
}
$otherSuffix = [guid]::NewGuid().ToString('N').Substring(0, 10)
$otherAccountName = "rt-$otherSuffix"
$otherPassword = New-OtherAccount -Name $otherAccountName
try {
    $otherResults = @(Invoke-OtherAccountRequests -Name $otherAccountName -Password $otherPassword `
        -GuestDir (Get-RosetunGuestDir) -ProtocolVersion $protocolVersion `
        -Commands @('status', 'disconnect', 'temporary', 'connections', 'close', 'apply'))
    foreach ($command in @('status', 'disconnect', 'temporary', 'connections', 'close', 'apply')) {
        $result = $otherResults | Where-Object Command -eq $command | Select-Object -First 1
        $note = if ($result) { $result.Reply } else { 'no result' }
        if ($command -eq 'status') {
            Test-Step 'other account' 'status reports Connected' -Note $note {
                $result -and $result.State -eq 'connected'
            }
        }
        else {
            Test-Step 'other account' "$command is denied" -Note $note {
                $result -and $result.Code -eq 'access_denied'
            }
        }
        Test-Step 'other account' "tunnel remains Connected after $command" {
            $result -and $result.StillConnected
        }
    }
    $adminDisconnect = Disconnect-RosetunTunnel
    Test-Step 'other account' 'administrator disconnects the tunnel' `
        -Note "exit $($adminDisconnect.ExitCode)" {
        $adminDisconnect.ExitCode -eq 0 -and (Wait-RosetunState 'Disconnected')
    }

    $otherResults = @(Invoke-OtherAccountRequests -Name $otherAccountName -Password $otherPassword `
        -GuestDir (Get-RosetunGuestDir) -ProtocolVersion $protocolVersion `
        -Commands @('connect', 'temporary'))
    $ownerConnect = $otherResults | Where-Object Command -eq 'connect' | Select-Object -First 1
    $note = if ($ownerConnect) { $ownerConnect.Reply } else { 'no result' }
    Test-Step 'other account' 'standard account connects its own tunnel' -Note $note {
        $ownerConnect -and $ownerConnect.Succeeded -and $ownerConnect.StillConnected
    }
    $ownerTemporary = $otherResults | Where-Object Command -eq 'temporary' | Select-Object -First 1
    $note = if ($ownerTemporary) { $ownerTemporary.Reply } else { 'no result' }
    Test-Step 'other account' 'standard account can read its temporary rules' -Note $note {
        $ownerTemporary -and $ownerTemporary.Succeeded -and
            $ownerTemporary.Code -ne 'access_denied' -and $ownerTemporary.StillConnected
    }
    # The list is the owner's browsing history: unlike control, an
    # administrator of another account may not read it.
    $adminConnections = Invoke-RosetunCli -Quiet 'connections'
    Test-Step 'other account' 'administrator cannot read the other account connections' `
        -Note "exit $($adminConnections.ExitCode): $($adminConnections.Output)" {
        $adminConnections.ExitCode -ne 0 -and
            $adminConnections.Output -match 'only that account can read its connections' -and
            @(Get-RosetunConnectionRows $adminConnections.Output).Count -eq 0
    }
    # A full id goes to the service as typed, without reading the list first.
    $adminClose = Invoke-RosetunCli -Quiet 'connections' 'close' ([guid]::NewGuid().ToString())
    Test-Step 'other account' 'administrator cannot close the other account connections' `
        -Note "exit $($adminClose.ExitCode): $($adminClose.Output)" {
        $adminClose.ExitCode -ne 0 -and
            $adminClose.Output -match 'only that account can close its connections'
    }
    $adminApply = Invoke-RosetunApply 'request.json' -Quiet
    Test-Step 'other account' 'administrator applies the other account tunnel' `
        -Note "exit $($adminApply.ExitCode)" {
        $adminApply.ExitCode -eq 0 -and (Wait-RosetunState 'Connected')
    }
    $adminDisconnect = Disconnect-RosetunTunnel
    Test-Step 'other account' 'administrator disconnects the other account tunnel' `
        -Note "exit $($adminDisconnect.ExitCode)" {
        $adminDisconnect.ExitCode -eq 0 -and (Wait-RosetunState 'Disconnected')
    }
}
finally {
    try {
        $cleanup = Invoke-RosetunCli -Quiet 'disconnect'
        if ($cleanup.ExitCode -ne 0 -and (Get-RosetunState) -ne 'Disconnected') {
            Write-Warning "Could not disconnect the other account tunnel: $($cleanup.Output)"
        }
    }
    catch { Write-Warning "Could not disconnect the other account tunnel: $_" }
    Remove-OtherAccount -Name $otherAccountName
}
Remove-OtherAccountService -GuestDir (Get-RosetunGuestDir)
$serviceAttempted = $false
Start-RosetunHelper
$consoleStoppedForOther = $false
Connect-RosetunTunnel | Out-Null
Test-Step 'other account' 'administrator reconnects for the remaining matrix' {
    Wait-RosetunState 'Connected'
}

$initialNodeId = (Get-Content -Path $RequestPath -Raw | ConvertFrom-Json).node.id
Write-Host 'Apply session changes under the kill switch...'
$apply = Invoke-RosetunApply 'request-apply-rules.json' -Quiet
Test-Step 'apply rules' 'apply succeeds' -Note "exit $($apply.ExitCode)" { $apply.ExitCode -eq 0 }
Test-Step 'apply rules' 'state is Connected' { (Get-RosetunState) -eq 'Connected' }
$status = Invoke-RosetunCli -Quiet 'status'
Test-Step 'apply rules' 'node is unchanged' {
    $status.ExitCode -eq 0 -and $status.Output -match ('(?m)^node: {0}$' -f [regex]::Escape($initialNodeId))
}
$egress = Wait-RosetunTunnelEgress
Test-Step 'apply rules' 'tunnel carries traffic' -Note (Format-Egress $egress) { $egress.Ok }
Test-Step 'apply rules' 'direct egress is blocked' { -not (Test-RosetunDirectEgress) }
Test-Step 'apply rules' 'IPv6 outside the tunnel is blocked' { -not (Test-RosetunIpv6Egress) }

$apply = Invoke-RosetunApply 'request-apply-node.json' -Quiet
Test-Step 'apply node' 'apply succeeds' -Note "exit $($apply.ExitCode)" { $apply.ExitCode -eq 0 }
Test-Step 'apply node' 'state is Connected' { (Get-RosetunState) -eq 'Connected' }
$status = Invoke-RosetunCli -Quiet 'status'
Test-Step 'apply node' 'new node is reported' {
    $status.ExitCode -eq 0 -and $status.Output -match '(?m)^node: home-server-2$'
}
$egress = Wait-RosetunTunnelEgress
Test-Step 'apply node' 'tunnel carries traffic' -Note (Format-Egress $egress) { $egress.Ok }

$watch = [Diagnostics.Stopwatch]::StartNew()
$apply = Invoke-RosetunApply 'request-apply-unreachable.json' -Quiet
$watch.Stop()
Test-Step 'apply unreachable' 'apply fails within 60 s' `
    -Note "exit $($apply.ExitCode) after $([int]$watch.Elapsed.TotalSeconds) s" {
    $apply.ExitCode -ne 0 -and $watch.Elapsed.TotalSeconds -le 60
}
Test-Step 'apply unreachable' 'state is Connected' { (Get-RosetunState) -eq 'Connected' }
$status = Invoke-RosetunCli -Quiet 'status'
Test-Step 'apply unreachable' 'previous node is reported' {
    $status.ExitCode -eq 0 -and $status.Output -match '(?m)^node: home-server-2$'
}
$egress = Wait-RosetunTunnelEgress
Test-Step 'apply unreachable' 'tunnel carries traffic' -Note (Format-Egress $egress) { $egress.Ok }
Test-Step 'apply unreachable' 'direct egress is blocked' { -not (Test-RosetunDirectEgress) }

$apply = Invoke-RosetunApply 'request-apply-unprotected.json' -Quiet
Test-Step 'apply protection' 'apply fails' -Note "exit $($apply.ExitCode)" { $apply.ExitCode -ne 0 }
Test-Step 'apply protection' 'state is Connected' { (Get-RosetunState) -eq 'Connected' }
Test-Step 'apply protection' 'direct egress stays blocked' { -not (Test-RosetunDirectEgress) }

Write-Host 'Temporary rule under the kill switch...'
$temporaryDomainUrl = 'https://2ip.io'
$permanentDomainUrl = Get-RosetunTunnelProbeUrl
$apply = Invoke-RosetunApply 'request-temporary.json' -Quiet
Test-Step 'temporary' 'apply succeeds' -Note "exit $($apply.ExitCode)" { $apply.ExitCode -eq 0 }
Test-Step 'temporary' 'state is Connected' { (Get-RosetunState) -eq 'Connected' }
$status = Invoke-RosetunCli -Quiet 'status'
Test-Step 'temporary' 'one rule is reported' {
    $status.ExitCode -eq 0 -and $status.Output -match '(?m)^temporary rules: 1$'
}
$rules = Invoke-RosetunCli -Quiet 'temporary'
Test-Step 'temporary' 'rule is returned' {
    $rules.ExitCode -eq 0 -and $rules.Output -match '(?m)^direct: domain exact 2ip\.io$'
}
$egress = Wait-RosetunTunnelEgress -Url $temporaryDomainUrl -TimeoutSeconds 15 -SkipRevocationCheck
# The base default is block, so this domain can pass only through the temporary direct rule.
Test-Step 'temporary' 'domain goes direct' -Note (Format-Egress $egress) { $egress.Ok }
$temporaryHost = ([uri]$temporaryDomainUrl).Host
$listed = Invoke-RosetunConnectionsDuring -Url $temporaryDomainUrl -SkipRevocationCheck
$rows = @(Get-RosetunConnectionRows $listed.Output | Where-Object { $_.Destination -like "${temporaryHost}:*" })
Test-Step 'connections' "a request to $temporaryHost is listed as direct" `
    -Note (Format-ConnectionsNote $listed $rows) {
    $listed.CurlExit -eq 0 -and $listed.ExitCode -eq 0 -and $rows.Count -gt 0 -and
        @($rows | Where-Object Route -ne 'direct').Count -eq 0
}
Test-Step 'temporary' 'unmatched domain is blocked' {
    -not (Test-RosetunTunnelEgress -Url $permanentDomainUrl)
}
Test-Step 'temporary' 'physical egress stays blocked' { -not (Test-RosetunDirectEgress) }

Stop-RosetunEngine
Test-Step 'temporary restart' 'state returns to Connected' {
    Wait-RosetunState 'Connected' -TimeoutSeconds 90
}
# Right after the restart the service may still hold the session for a moment
# and answer "unavailable while the service is busy"; the GUI retries the same way.
$status = $null
$reported = Wait-RosetunCondition {
    $script:status = Invoke-RosetunCli -Quiet 'status'
    $script:status.ExitCode -eq 0 -and $script:status.Output -match '(?m)^temporary rules: 1$'
}
Test-Step 'temporary restart' 'one rule is reported' `
    -Note ("exit {0}: {1}" -f $status.ExitCode, (@($status.Output -split '\r?\n' | Where-Object { $_ -match '^temporary rules' }) -join ' | ')) {
    $reported
}
$egress = Wait-RosetunTunnelEgress -Url $temporaryDomainUrl -TimeoutSeconds 15 -SkipRevocationCheck
Test-Step 'temporary restart' 'domain still goes direct' -Note (Format-Egress $egress) { $egress.Ok }
Test-Step 'temporary restart' 'physical egress stays blocked' { -not (Test-RosetunDirectEgress) }

Write-Host 'Sleep with the tunnel up (saved Hyper-V VM)...'
Start-RosetunEgressWatch
$egressWatchActive = $true
$watch = $null
try {
    $beforeProbes = Invoke-RosetunGuest -ScriptBlock {
        param($dir)
        [int]((Get-Content -Path (Join-Path $dir 'rosetun-egress-watch.txt')) -split ' ')[0]
    } -ArgumentList (Get-RosetunGuestDir)
    $guestBefore = Invoke-RosetunGuest -ScriptBlock { [DateTime]::UtcNow }
    $hostBefore = [DateTime]::UtcNow
    Disconnect-RosetunVm
    $vmName = Get-RosetunVmName
    $sleepWatch = [Diagnostics.Stopwatch]::StartNew()
    $resumeWatch = $null
    try {
        Save-VM -Name $vmName | Out-Null
        if ((Get-VM -Name $vmName).State -ne 'Saved') {
            throw 'The VM did not enter the Saved state.'
        }
        $savedAt = [DateTime]::UtcNow
        Start-Sleep -Seconds 40
    }
    finally {
        if ((Get-VM -Name $vmName).State -eq 'Saved') {
            $resumeAt = [DateTime]::UtcNow
            $resumeWatch = [Diagnostics.Stopwatch]::StartNew()
            Start-VM -Name $vmName | Out-Null
        }
    }
    $deadline = (Get-Date).AddSeconds(45)
    while ($true) {
        try {
            Connect-RosetunVm | Out-Null
            break
        }
        catch {
            if ((Get-Date) -gt $deadline) {
                throw "The saved guest did not accept PowerShell Direct within 45 seconds: $_"
            }
            Start-Sleep -Seconds 2
        }
    }
    $guestAfter = Invoke-RosetunGuest -ScriptBlock { [DateTime]::UtcNow }
    $hostAfter = [DateTime]::UtcNow
    $savedSeconds = ($resumeAt - $savedAt).TotalSeconds
    $runningSeconds = ($hostAfter - $hostBefore).TotalSeconds - $savedSeconds
    $clockJump = ($guestAfter - $guestBefore).TotalSeconds - $runningSeconds
    Test-Step 'sleep' 'guest clock jumped by more than 30 s while saved' `
        -Note ("saved {0:N1} s, inferred jump {1:N1} s; check Hyper-V time synchronization if it did not jump" -f `
            $savedSeconds, $clockJump) {
        $savedSeconds -gt 30 -and $clockJump -gt 30
    }
    $connected = Wait-RosetunState 'Connected' -TimeoutSeconds 30
    $connectedAt = $resumeWatch.Elapsed.TotalSeconds
    Test-Step 'sleep' 'state is Connected within 30 s of Start-VM' `
        -Note ("{0} after {1:N1} s" -f (Get-RosetunState), $connectedAt) {
        $connected -and $connectedAt -le 30
    }
    $egress = Wait-RosetunTunnelEgress -Url $temporaryDomainUrl -TimeoutSeconds 30 -SkipRevocationCheck
    $resumeWatch.Stop()
    Test-Step 'sleep' 'tunnel carries traffic within 30 s of Start-VM' `
        -Note ("{0}; after {1:N1} s" -f (Format-Egress $egress), $resumeWatch.Elapsed.TotalSeconds) {
        $egress.Ok -and $resumeWatch.Elapsed.TotalSeconds -le 30
    }
    Test-Step 'sleep' 'helper logged the resume reconnect' {
        Wait-RosetunCondition {
            @(Get-RosetunHelperLog -Tail 200 | Where-Object { $_ -match 'resumed from sleep; reconnecting tunnel' }).Count -gt 0
        }
    }
    Write-Host ("Saved-VM sleep scenario took {0:N1} s" -f $sleepWatch.Elapsed.TotalSeconds)
}
finally {
    try {
        $watch = Stop-RosetunEgressWatch
        $egressWatchActive = $false
    }
    catch {
        Test-Step 'sleep' 'egress watch stopped' -Note "$_" { $false }
    }
}
$probeCount = if ($watch) { $watch.Probes } else { 0 }
$leakCount = if ($watch) { $watch.Leaks } else { 'unknown' }
Test-Step 'sleep' "no direct leak after Start-VM ($probeCount probes)" `
    -Note "before save: $beforeProbes probes; leaks: $leakCount" {
    $watch -and $probeCount -gt $beforeProbes -and $leakCount -eq 0
}

Disconnect-RosetunTunnel | Out-Null
$connect = Connect-RosetunTunnel -Quiet
Test-Step 'temporary disconnect' 'original request connects' -Note "exit $($connect.ExitCode)" {
    $connect.ExitCode -eq 0 -and (Get-RosetunState) -eq 'Connected'
}
$status = Invoke-RosetunCli -Quiet 'status'
Test-Step 'temporary disconnect' 'no temporary rules remain' {
    $status.ExitCode -eq 0 -and $status.Output -match '(?m)^temporary rules: 0$'
}
$rules = Invoke-RosetunCli -Quiet 'temporary'
Test-Step 'temporary disconnect' 'rule list is empty' {
    $rules.ExitCode -eq 0 -and $rules.Output -match '(?m)^none$'
}

Write-Host 'Temporary rules across a CLI apply from settings...'
$configPath = Join-Path (Get-RosetunGuestDir) 'settings-matrix\config.json'
try {
    Disconnect-RosetunTunnel | Out-Null
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $configPath)
        New-Item -Path (Split-Path -Parent $configPath) -ItemType Directory -Force | Out-Null
        $request = Get-Content -Path (Join-Path $dir 'request-temporary.json') -Raw | ConvertFrom-Json
        $config = @{
            version = 3
            settings = $request.settings
            subscriptions = @(@{
                id = $request.selection.subscription
                name = 'Test node'
                url = 'https://example.invalid/subscription'
                nodes = @($request.node)
            })
            active = $request.selection
            active_rule_set = $request.rule_set.id
            rule_sets = @($request.rule_set)
        }
        [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 30))
    } -ArgumentList (Get-RosetunGuestDir), $configPath

    $connect = Invoke-SettingsCli -ConfigPath $configPath -Action connect
    Test-Step 'settings apply' 'connect uses the isolated config' -Note "exit $($connect.ExitCode)" {
        $connect.ExitCode -eq 0 -and (Wait-RosetunState 'Connected')
    }
    $apply = Invoke-RosetunApply 'request-temporary.json' -Quiet
    Test-Step 'settings apply' 'temporary rule is added' -Note "exit $($apply.ExitCode)" {
        $apply.ExitCode -eq 0 -and (Get-RosetunState) -eq 'Connected'
    }
    $temporaryBefore = Invoke-RosetunCli -Quiet 'temporary'
    $temporaryLine = 'direct: domain exact ' + ([Uri]$temporaryDomainUrl).Host
    Test-Step 'settings apply' 'temporary rule is returned before apply' {
        $temporaryBefore.ExitCode -eq 0 -and
            $temporaryBefore.Output -match ('(?m)^{0}$' -f [regex]::Escape($temporaryLine))
    }
    Test-Step 'settings apply' 'permanent domain is blocked before apply' {
        -not (Test-RosetunTunnelEgress -Url $permanentDomainUrl)
    }

    Invoke-RosetunGuest -ScriptBlock {
        param($configPath, $domain)
        $config = Get-Content -Path $configPath -Raw | ConvertFrom-Json
        $config.rule_sets[0].rules = @($config.rule_sets[0].rules) + @([pscustomobject]@{
            id = 'settings-direct'
            enabled = $true
            matcher = @{ domain = @{ exact = $domain } }
            target = 'direct'
        })
        [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 30))
    } -ArgumentList $configPath, ([Uri]$permanentDomainUrl).Host
    $apply = Invoke-SettingsCli -ConfigPath $configPath -Action apply
    Test-Step 'settings apply' 'CLI apply without a request succeeds' -Note "exit $($apply.ExitCode)" {
        $apply.ExitCode -eq 0 -and (Wait-RosetunState 'Connected')
    }
    $temporaryAfter = Invoke-RosetunCli -Quiet 'temporary'
    # The CLI also prints log lines, possibly with ANSI colour codes before the
    # timestamp; keep only the rule lines ("direct: domain exact ...") and "none".
    $ruleLines = {
        param([string]$Text)
        @($Text -split '\r?\n' | Where-Object { $_ -match '^((proxy|direct|block): |none$)' }) -join ' | '
    }
    $rulesBefore = & $ruleLines $temporaryBefore.Output
    $rulesAfter = & $ruleLines $temporaryAfter.Output
    Test-Step 'settings apply' 'temporary rule remains after apply' `
        -Note ("exit {0}; before: {1}; after: {2}" -f $temporaryAfter.ExitCode, $rulesBefore, $rulesAfter) {
        $temporaryAfter.ExitCode -eq 0 -and $rulesAfter -eq $rulesBefore -and
            $temporaryAfter.Output -match ('(?m)^{0}$' -f [regex]::Escape($temporaryLine))
    }
    $egress = Wait-RosetunTunnelEgress -Url $temporaryDomainUrl -TimeoutSeconds 15 -SkipRevocationCheck
    Test-Step 'settings apply' 'temporary domain still goes direct' -Note (Format-Egress $egress) {
        $egress.Ok
    }
    $egress = Wait-RosetunTunnelEgress -Url $permanentDomainUrl -TimeoutSeconds 15 -SkipRevocationCheck
    Test-Step 'settings apply' 'new permanent domain goes direct' -Note (Format-Egress $egress) {
        $egress.Ok
    }
    Test-Step 'settings apply' 'physical egress stays blocked' { -not (Test-RosetunDirectEgress) }
}
finally {
    try { Disconnect-RosetunTunnel | Out-Null }
    finally {
        Invoke-RosetunGuest -ScriptBlock {
            param($configPath)
            Remove-Item -Path (Split-Path -Parent $configPath) -Recurse -Force -ErrorAction SilentlyContinue
        } -ArgumentList $configPath
    }
}
# Each apply kills sing-box and starts a new one at once; on some Windows 10
# machines the old Wintun adapter is then still being removed and the helper
# has to retry the start instead of rolling the change back.
Write-Host 'Twenty settings applies in a row...'
$seriesConfigPath = Join-Path (Get-RosetunGuestDir) 'apply-series\config.json'
$seriesWatchActive = $false
try {
    $killSwitch = Invoke-RosetunGuest -ScriptBlock {
        param($dir, $configPath)
        New-Item -Path (Split-Path -Parent $configPath) -ItemType Directory -Force | Out-Null
        $request = Get-Content -Path (Join-Path $dir 'request.json') -Raw | ConvertFrom-Json
        $config = @{
            version = 3
            settings = $request.settings
            subscriptions = @(@{
                id = $request.selection.subscription
                name = 'Test node'
                url = 'https://example.invalid/subscription'
                nodes = @($request.node)
            })
            active = $request.selection
            active_rule_set = $request.rule_set.id
            rule_sets = @($request.rule_set)
        }
        [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 30))
        [bool]$request.settings.kill_switch
    } -ArgumentList (Get-RosetunGuestDir), $seriesConfigPath

    $seriesLogMark = Get-HelperLogLength
    $connect = Invoke-SettingsCli -ConfigPath $seriesConfigPath -Action connect
    Test-Step 'apply series' 'connect uses the isolated config' -Note "exit $($connect.ExitCode)" {
        $connect.ExitCode -eq 0 -and (Wait-RosetunState 'Connected')
    }
    Start-RosetunEgressWatch
    $seriesWatchActive = $true
    $failedApplies = [System.Collections.Generic.List[string]]::new()
    for ($round = 1; $round -le 20; $round++) {
        Invoke-RosetunGuest -ScriptBlock {
            param($configPath, $round)
            $config = Get-Content -Path $configPath -Raw | ConvertFrom-Json
            $rules = @($config.rule_sets[0].rules | Where-Object { $_.id -ne 'apply-series' })
            $config.rule_sets[0].rules = $rules + @([pscustomobject]@{
                id = 'apply-series'
                enabled = $true
                matcher = @{ domain = @{ exact = "series-$round.example.com" } }
                target = 'direct'
            })
            [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 30))
        } -ArgumentList $seriesConfigPath, $round
        $apply = Invoke-SettingsCli -ConfigPath $seriesConfigPath -Action apply
        $state = Get-RosetunState
        if ($apply.ExitCode -ne 0 -or $state -ne 'Connected') {
            # The CLI's last line names the helper's error; without it a
            # failed apply leaves nothing to go on.
            $reason = (($apply.Output -replace "\x1b\[[0-9;]*m", '') -split "`n" |
                Where-Object { $_.Trim() } | Select-Object -Last 1)
            $failedApplies.Add("#${round}: exit $($apply.ExitCode), $state, $reason")
        }
    }
    $watch = Stop-RosetunEgressWatch
    $seriesWatchActive = $false
    Test-Step 'apply series' 'all 20 applies succeed and stay Connected' `
        -Note ($failedApplies -join '; ') { $failedApplies.Count -eq 0 }
    $seriesLog = Get-HelperLogSince $seriesLogMark
    if ($failedApplies.Count -gt 0) {
        $seriesLogPath = Join-Path $PSScriptRoot ("logs\apply-series-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
        New-Item -ItemType Directory -Force -Path (Split-Path $seriesLogPath) | Out-Null
        Set-Content -Path $seriesLogPath -Value $seriesLog -Encoding UTF8
        Write-Host "apply series helper log: $seriesLogPath"
    }
    $retries = ([regex]::Matches($seriesLog, 'retrying the engine start')).Count
    $busy = ([regex]::Matches($seriesLog, 'already exists')).Count
    $timeoutKills = ([regex]::Matches($seriesLog, 'sing-box did not stop in time')).Count
    $seriesNote = "$($watch.Probes) probes; helper log: $retries retries, $busy 'already exists' lines"
    Test-Step 'apply series' 'no sing-box is killed after the graceful stop timeout' `
        -Note "$timeoutKills kills" { $timeoutKills -eq 0 }
    # A retry is how the old race showed; clean Windows 11 never raced, so it is reported, not failed.
    if ($retries -eq 0) {
        Test-Step 'apply series' 'no engine start is retried' -Note "$busy 'already exists' lines" { $true }
    }
    else {
        Add-Info 'apply series' 'engine start retries' "$retries retries, $busy 'already exists' lines"
    }
    if ($killSwitch) {
        Test-Step 'apply series' 'direct egress stays blocked throughout' -Note $seriesNote {
            $watch.Probes -gt 0 -and $watch.Leaks -eq 0
        }
    }
    else {
        Write-Host "apply series without kill switch: $seriesNote"
    }
}
finally {
    try {
        if ($seriesWatchActive) { Stop-RosetunEgressWatch | Out-Null }
    }
    finally {
        try { Disconnect-RosetunTunnel | Out-Null }
        finally {
            Invoke-RosetunGuest -ScriptBlock {
                param($configPath)
                Remove-Item -Path (Split-Path -Parent $configPath) -Recurse -Force -ErrorAction SilentlyContinue
            } -ArgumentList $seriesConfigPath
        }
    }
}

$connect = Connect-RosetunTunnel -Quiet
Test-Step 'settings apply' 'original request reconnects for the remaining matrix' `
    -Note "exit $($connect.ExitCode)" {
    $connect.ExitCode -eq 0 -and (Wait-RosetunState 'Connected')
}

# Like a Wi-Fi reconnect: the engine has to follow the network on its own,
# and the helper notices nothing.
Write-Host 'Network change with the tunnel up...'
Start-RosetunEgressWatch
$egressWatchActive = $true
$adapter = Restart-RosetunEgressAdapter
$egress = Wait-RosetunTunnelEgress -TimeoutSeconds 60
$watch = Stop-RosetunEgressWatch
$egressWatchActive = $false
Test-Step 'network change' 'adapter gets its address from DHCP again' `
    -Note "after $($adapter.Seconds) s: $($adapter.Addresses)" { $adapter.Ok }
$networkChangeNote = Format-Egress $egress
if (-not $egress.Ok -or $egress.Seconds -gt 15) {
    $networkChangeNote += "; $(Get-NetworkWaitNote (Get-RosetunStatus -ProtocolVersion $protocolVersion))"
}
Test-Step 'network change' 'tunnel carries traffic again within 15 s' -Note $networkChangeNote {
    $egress.Ok -and $egress.Seconds -le 15
}
Test-Step 'network change' "no leak while the network changes ($($watch.Probes) probes)" {
    $watch.Probes -gt 0 -and $watch.Leaks -eq 0
}
Test-Step 'network change' 'state is still Connected' { (Get-RosetunState) -eq 'Connected' }
# The adapter restart can drop the guest's ActiveStore neighbor entry.
Set-RosetunIpv6Neighbor -Created $ipv6Neighbors

Write-Host 'Engine killed...'
Stop-RosetunEngine
Test-Step 'engine killed' 'state is FailedProtected' { Wait-RosetunState 'FailedProtected' }
Test-Step 'engine killed' 'direct egress is blocked' { -not (Test-RosetunDirectEgress) }
Test-Step 'engine killed' 'direct DNS is blocked' { -not (Test-RosetunDirectDns) }
# While sing-box runs, its strict route blocks IPv6 as well. Its filters die
# with it, so only here is Rosetun's own IPv6 block the one being tested.
Test-Step 'engine killed' 'IPv6 outside the tunnel is blocked' { -not (Test-RosetunIpv6Egress) }
$probe = Invoke-RosetunProbe
Test-Step 'engine killed' 'server check works under protection' -Note "exit $($probe.ExitCode)" {
    $probe.ExitCode -eq 0 -and $probe.Output -match '(?m)^works \d+ ms$'
}
Test-Step 'engine killed' 'direct egress is still blocked' { -not (Test-RosetunDirectEgress) }

Write-Host 'Reconnect inside protection...'
Start-RosetunEgressWatch
$egressWatchActive = $true
Connect-RosetunTunnel | Out-Null
$reconnected = Wait-RosetunState 'Connected'
$watch = Stop-RosetunEgressWatch
$egressWatchActive = $false
Test-Step 'reconnect' 'state is Connected' { $reconnected }
Test-Step 'reconnect' "no leak while reconnecting ($($watch.Probes) probes)" {
    $watch.Probes -gt 0 -and $watch.Leaks -eq 0
}

Write-Host 'Failed reconnect...'
Stop-RosetunEngine
Wait-RosetunState 'FailedProtected' | Out-Null
Set-RosetunEngineAvailable $false
Connect-RosetunTunnel -Quiet | Out-Null
Test-Step 'failed reconnect' 'state stays FailedProtected' {
    Wait-RosetunState 'FailedProtected' -TimeoutSeconds 10
}
Test-Step 'failed reconnect' 'direct egress is blocked' { -not (Test-RosetunDirectEgress) }
Set-RosetunEngineAvailable $true

# The engine starts and the tunnel comes up, but nothing behind it answers.
Write-Host 'Reconnect to an unreachable node...'
$attempt = Connect-RosetunTunnel -RequestName 'request-unreachable.json' -Quiet
Test-Step 'unreachable reconnect' 'connect fails before it can be used' {
    $attempt.ExitCode -ne 0 -and $attempt.Output -match 'ServerUnreachable|DnsTimeout|DNS through the tunnel'
}
Test-Step 'unreachable reconnect' 'state stays FailedProtected' {
    Wait-RosetunState 'FailedProtected' -TimeoutSeconds 10
}
Test-Step 'unreachable reconnect' 'direct egress is blocked' { -not (Test-RosetunDirectEgress) }

Write-Host 'Disconnect...'
Disconnect-RosetunTunnel | Out-Null
Test-Step 'disconnect' 'state is Disconnected' { Wait-RosetunState 'Disconnected' }
Test-Step 'disconnect' 'direct egress works again' { Test-RosetunDirectEgress }
Test-Step 'disconnect' 'IPv6 works again' { Test-RosetunIpv6Egress }
Test-Step 'disconnect' 'tunnel adapter is gone' {
    Wait-RosetunCondition { -not (Test-RosetunTunAdapter) }
}

# The disconnect above follows a failed reconnect, which has already stopped
# sing-box: connect once more, so this disconnect stops a live one.
Write-Host 'Graceful disconnect...'
$attempt = Connect-RosetunTunnel -Quiet
Test-Step 'graceful disconnect' 'connects' -Note "exit $($attempt.ExitCode)" {
    $attempt.ExitCode -eq 0 -and (Get-RosetunState) -eq 'Connected'
}
$logMark = Get-HelperLogLength
Disconnect-RosetunTunnel | Out-Null
# Measured from when the disconnect call returned, inside the guest.
$adapterGoneMs = Invoke-RosetunGuest -ScriptBlock {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while (Get-NetAdapter -Name 'rosetun0' -ErrorAction SilentlyContinue) {
        if ($watch.Elapsed.TotalSeconds -ge 2) { return $null }
        Start-Sleep -Milliseconds 100
    }
    $watch.ElapsedMilliseconds
}
Test-Step 'graceful disconnect' 'adapter rosetun0 is gone within 2 s' -Note "$adapterGoneMs ms" {
    $null -ne $adapterGoneMs
}
$stopLine = [regex]::Match((Get-HelperLogSince $logMark), 'sing-box (stopped gracefully|did not stop in time|killed).*').Value
Test-Step 'graceful disconnect' 'helper log shows a graceful sing-box stop' -Note $stopLine.Trim() {
    $stopLine -match 'stopped gracefully'
}
$afterDisconnect = Invoke-RosetunCli -Quiet 'connections'
Test-Step 'connections' 'the list is empty after a disconnect' `
    -Note "exit $($afterDisconnect.ExitCode): $($afterDisconnect.Output)" {
    $afterDisconnect.Output -match 'not connected' -and
        @(Get-RosetunConnectionRows $afterDisconnect.Output).Count -eq 0
}

Write-Host 'Five immediate disconnect/reconnect cycles...'
for ($cycle = 1; $cycle -le 5; $cycle++) {
    $attempt = Connect-RosetunTunnel -Quiet
    Test-Step 'rapid reconnect' "cycle $cycle connects" -Note "exit $($attempt.ExitCode)" {
        $attempt.ExitCode -eq 0 -and (Get-RosetunState) -eq 'Connected'
    }
    $attempt = Disconnect-RosetunTunnel
    Test-Step 'rapid reconnect' "cycle $cycle disconnects" -Note "exit $($attempt.ExitCode)" {
        $attempt.ExitCode -eq 0 -and (Get-RosetunState) -eq 'Disconnected'
    }
}
Test-Step 'rapid reconnect' 'direct egress works afterwards' { Test-RosetunDirectEgress }
$adapterWaits = @(Get-RosetunHelperLog -Tail 200 | Select-String 'waiting for Windows to remove the previous tunnel adapter').Count
Write-Host "Adapter-removal waits visible in the recent helper log: $adapterWaits"

Write-Host 'Process rules...'
Connect-RosetunTunnel -RequestName 'request-process-rules.json' | Out-Null
Test-Step 'process rules' 'state is Connected' { Wait-RosetunState 'Connected' }
$egress = Wait-RosetunTunnelEgress -TimeoutSeconds 15
# The default target is block, so only the rule can let this request through.
Test-Step 'process rules' 'curl.exe goes direct by its rule' -Note (Format-Egress $egress) { $egress.Ok }
Test-Step 'process rules' 'another process hits the default block' {
    -not (Test-RosetunTunnelEgress -OtherProcess)
}
Test-Step 'process rules' 'direct egress is still blocked' { -not (Test-RosetunDirectEgress) }
Disconnect-RosetunTunnel | Out-Null
Wait-RosetunState 'Disconnected' | Out-Null

Write-Host 'LAN with kill switch...'
Connect-RosetunTunnel -RequestName 'request-lan-allowed.json' | Out-Null
Test-Step 'allow LAN' 'state is Connected' { Wait-RosetunState 'Connected' }
Test-Step 'allow LAN' 'host LAN listener is reachable' { Test-RosetunLanListener $lanListener }
Test-Step 'allow LAN' 'direct internet is still blocked' { -not (Test-RosetunDirectEgress) }
Disconnect-RosetunTunnel | Out-Null
Test-Step 'allow LAN' 'state is Disconnected' { Wait-RosetunState 'Disconnected' }

Connect-RosetunTunnel -RequestName 'request-lan-blocked.json' | Out-Null
Test-Step 'block LAN' 'state is Connected' { Wait-RosetunState 'Connected' }
Test-Step 'block LAN' 'host LAN listener is blocked' { -not (Test-RosetunLanListener $lanListener) }
Test-Step 'block LAN' 'direct internet is still blocked' { -not (Test-RosetunDirectEgress) }
Disconnect-RosetunTunnel | Out-Null
Test-Step 'block LAN' 'state is Disconnected' { Wait-RosetunState 'Disconnected' }
Test-Step 'block LAN' 'direct internet works afterwards' { Test-RosetunDirectEgress }

Write-Host 'Connect to an unreachable node...'
$attempt = Connect-RosetunTunnel -RequestName 'request-unreachable.json' -Quiet
Test-Step 'unreachable connect' 'connect fails before it can be used' {
    $attempt.ExitCode -ne 0 -and $attempt.Output -match 'ServerUnreachable|DnsTimeout|DNS through the tunnel'
}
Test-Step 'unreachable connect' 'state is Failed' { Wait-RosetunState 'Failed' -TimeoutSeconds 10 }
Test-Step 'unreachable connect' 'direct egress works again' { Test-RosetunDirectEgress }
Test-Step 'unreachable connect' 'tunnel adapter is gone' {
    Wait-RosetunCondition { -not (Test-RosetunTunAdapter) }
}

Write-Host 'Cancel a connection to a dead server after three seconds...'
$cancel = Invoke-RosetunGuest -ScriptBlock {
    param($dir)
    $cli = Join-Path $dir 'rosetun.exe'
    $request = Join-Path $dir 'request-dead-server.json'
    $prefix = Join-Path $dir ('cancel-' + [guid]::NewGuid().ToString('N'))
    $stdout = "$prefix.out"
    $stderr = "$prefix.err"
    function Read-TunnelState {
        param($exe)
        $output = & $exe status 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
        $global:LASTEXITCODE = 0
        if ($exitCode -eq 0 -and $output -match '(?m)^state: (\w+)') { return $Matches[1] }
        return 'unknown'
    }
    $process = Start-Process -FilePath $cli -ArgumentList @('connect', "`"$request`"") `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden
    try {
        $deadline = (Get-Date).AddSeconds(10)
        $started = $false
        do {
            $started = (Read-TunnelState $cli) -eq 'Connecting'
            if ($started) { break }
            Start-Sleep -Milliseconds 100
        } while ((Get-Date) -lt $deadline)
        if ($started) { Start-Sleep -Seconds 3 }
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $output = & $cli disconnect 2>&1 | Out-String
        $exit = $LASTEXITCODE
        $global:LASTEXITCODE = 0
        $state = Read-TunnelState $cli
        while ($state -ne 'Disconnected' -and $watch.Elapsed.TotalSeconds -lt 2) {
            Start-Sleep -Milliseconds 50
            $state = Read-TunnelState $cli
        }
        $watch.Stop()
        [pscustomobject]@{
            Started        = $started
            DisconnectExit = $exit
            State          = $state
            Seconds        = $watch.Elapsed.TotalSeconds
        }
    }
    finally {
        if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
        Remove-Item $stdout, $stderr -Force -ErrorAction SilentlyContinue
    }
} -ArgumentList (Get-RosetunGuestDir)
Test-Step 'cancel connect' 'reached Connecting before cancellation' { $cancel.Started }
Test-Step 'cancel connect' 'disconnect succeeds' -Note "exit $($cancel.DisconnectExit)" {
    $cancel.DisconnectExit -eq 0
}
Test-Step 'cancel connect' 'state becomes Disconnected in under one second' `
    -Note "$($cancel.State) after $([math]::Round($cancel.Seconds, 2)) s" {
    $cancel.State -eq 'Disconnected' -and $cancel.Seconds -lt 1
}
Test-Step 'cancel connect' 'direct egress works again' { Test-RosetunDirectEgress }
Test-Step 'cancel connect' 'tunnel adapter is gone' {
    Wait-RosetunCondition { -not (Test-RosetunTunAdapter) }
}

Write-Host 'Classify a dead server without waiting for the DNS deadline...'
$watch = [Diagnostics.Stopwatch]::StartNew()
$attempt = Connect-RosetunTunnel -RequestName 'request-dead-server.json' -Quiet
$watch.Stop()
$deadServerClassified = $attempt.Output -match 'ServerUnreachable'
Test-Step 'dead server' 'failure is ServerUnreachable within 20 s' `
    -Note ("exit {0} after {1:N1} s, classified: {2}" -f $attempt.ExitCode, $watch.Elapsed.TotalSeconds, $deadServerClassified) {
    $attempt.ExitCode -ne 0 -and $attempt.Output -match 'ServerUnreachable' -and
        $watch.Elapsed.TotalSeconds -le 20
}
Test-Step 'dead server' 'state is Failed' { Wait-RosetunState 'Failed' -TimeoutSeconds 5 }
Test-Step 'dead server' 'direct egress works again' { Test-RosetunDirectEgress }

Write-Host 'Shutdown with the tunnel up...'
Connect-RosetunTunnel | Out-Null
Wait-RosetunState 'Connected' | Out-Null
Request-RosetunShutdown | Out-Null
Test-Step 'shutdown' 'engine stopped' { Wait-RosetunCondition { -not (Test-RosetunEngineRunning) } }
Test-Step 'shutdown' 'tunnel adapter is gone' { Wait-RosetunCondition { -not (Test-RosetunTunAdapter) } }
Test-Step 'shutdown' 'direct egress works again' { Test-RosetunDirectEgress }

# Known fail-open: the dynamic WFP session closes with the helper process, and
# the job object takes the engine down with it.
Write-Host 'Helper killed with the tunnel up...'
Start-RosetunHelper
Connect-RosetunTunnel | Out-Null
Wait-RosetunState 'Connected' | Out-Null
Stop-RosetunHelper
Test-Step 'helper killed' 'engine died with the helper' {
    Wait-RosetunCondition { -not (Test-RosetunEngineRunning) }
}
Test-Step 'helper killed' 'tunnel adapter is gone' {
    Wait-RosetunCondition { -not (Test-RosetunTunAdapter) }
}
Test-Step 'helper killed' 'direct egress works again' {
    Wait-RosetunCondition { Test-RosetunDirectEgress }
}
Test-Step 'helper killed' 'direct DNS works again' {
    Wait-RosetunCondition { Test-RosetunDirectDns }
}

Write-Host 'Restart after a killed helper...'
Start-RosetunHelper
Connect-RosetunTunnel | Out-Null
Test-Step 'restart' 'connect succeeds, no stale adapter' { Wait-RosetunState 'Connected' }
Disconnect-RosetunTunnel | Out-Null

Write-Host 'DNS lock without the kill switch...'
Connect-RosetunTunnel -RequestName 'request-dns-lock.json' | Out-Null
Test-Step 'dns lock' 'state is Connected' { Wait-RosetunState 'Connected' }
$egress = Wait-RosetunTunnelEgress
Test-Step 'dns lock' 'tunnel carries traffic' -Note (Format-Egress $egress) { $egress.Ok }
Test-Step 'dns lock' 'direct DNS is blocked' { -not (Test-RosetunDirectDns) }
# Without the kill switch only sing-box's strict route blocks IPv6: the TUN
# has no IPv6 address, so sing-tun blocks every IPv6 connect (rules/ENGINE.md).
Test-Step 'dns lock' 'IPv6 outside the tunnel is blocked without the kill switch' {
    -not (Test-RosetunIpv6Egress)
}
$apply = Invoke-RosetunApply 'request-dns-lock-apply.json' -Quiet
Test-Step 'dns lock apply' 'apply succeeds' -Note "exit $($apply.ExitCode)" { $apply.ExitCode -eq 0 }
Test-Step 'dns lock apply' 'state is Connected' { (Get-RosetunState) -eq 'Connected' }
Test-Step 'dns lock apply' 'direct DNS is blocked' { -not (Test-RosetunDirectDns) }
$egress = Wait-RosetunTunnelEgress
Test-Step 'dns lock apply' 'tunnel carries traffic' -Note (Format-Egress $egress) { $egress.Ok }
$probe = Invoke-RosetunProbe 'request-dns-lock.json'
Test-Step 'dns lock' 'server check works with the DNS lock' -Note "exit $($probe.ExitCode)" {
    $probe.ExitCode -eq 0 -and $probe.Output -match '(?m)^works \d+ ms$'
}

Write-Host 'DNS lock during automatic restart...'
Set-RosetunEngineAvailable $false
Stop-RosetunEngine
Test-Step 'dns lock restart' 'state is Reconnecting' { Wait-RosetunState 'Reconnecting' }
Test-Step 'dns lock restart' 'direct UDP DNS is blocked' { -not (Test-RosetunDirectDns) }
Test-Step 'dns lock restart' 'direct TCP DNS is blocked' { -not (Test-RosetunDirectDns -Tcp) }
Test-Step 'dns lock restart' 'non-DNS egress still works' { Test-RosetunDirectEgress }
Set-RosetunEngineAvailable $true
Test-Step 'dns lock restart' 'state returns to Connected within 45 s' {
    Wait-RosetunState 'Connected' -TimeoutSeconds 45
}

Write-Host 'DNS lock after exhausted reconnects...'
Set-RosetunEngineAvailable $false
Stop-RosetunEngine
Test-Step 'dns lock exhausted' 'state is Failed within 90 s' {
    Wait-RosetunState 'Failed' -TimeoutSeconds 90
}
Test-Step 'dns lock exhausted' 'direct DNS works again' { Test-RosetunDirectDns }
Set-RosetunEngineAvailable $true

Write-Host 'DNS lock with automatic reconnect disabled...'
Connect-RosetunTunnel -RequestName 'request-dns-lock-manual.json' | Out-Null
Test-Step 'dns lock manual' 'state is Connected' { Wait-RosetunState 'Connected' }
Stop-RosetunEngine
Test-Step 'dns lock manual' 'state is Failed' { Wait-RosetunState 'Failed' }
Test-Step 'dns lock manual' 'direct DNS works again' { Test-RosetunDirectDns }
Disconnect-RosetunTunnel | Out-Null

Write-Host 'Disconnect with the DNS lock...'
Connect-RosetunTunnel -RequestName 'request-dns-lock.json' | Out-Null
Disconnect-RosetunTunnel | Out-Null
Test-Step 'dns lock disconnect' 'state is Disconnected' { Wait-RosetunState 'Disconnected' }
Test-Step 'dns lock disconnect' 'direct DNS works again' { Test-RosetunDirectDns }
Test-Step 'dns lock disconnect' 'IPv6 works again' { Test-RosetunIpv6Egress }

Write-Host 'Helper killed with the DNS lock...'
Connect-RosetunTunnel -RequestName 'request-dns-lock.json' | Out-Null
Wait-RosetunState 'Connected' | Out-Null
Stop-RosetunHelper
Test-Step 'dns lock helper killed' 'direct DNS works again' {
    Wait-RosetunCondition { Test-RosetunDirectDns }
}
Start-RosetunHelper

Write-Host 'Hysteria2 through the kill switch...'
$connect = Connect-RosetunTunnel -RequestName 'request-hysteria2.json' -Quiet
Test-Step 'hysteria2' 'connect succeeds' -Note "exit $($connect.ExitCode)" {
    $connect.ExitCode -eq 0
}
Test-Step 'hysteria2' 'state is Connected' { Wait-RosetunState 'Connected' }
$egress = Wait-RosetunTunnelEgress
Test-Step 'hysteria2' 'tunnel carries traffic' -Note (Format-Egress $egress) { $egress.Ok }
Test-Step 'hysteria2' 'direct egress is blocked' { -not (Test-RosetunDirectEgress) }
Test-Step 'hysteria2' 'IPv6 outside the tunnel is blocked' { -not (Test-RosetunIpv6Egress) }
$probe = Invoke-RosetunProbe 'request-hysteria2.json'
Test-Step 'hysteria2' 'server check works under protection' -Note "exit $($probe.ExitCode)" {
    $probe.ExitCode -eq 0 -and $probe.Output -match '(?m)^works \d+ ms$'
}
Disconnect-RosetunTunnel | Out-Null
Test-Step 'hysteria2' 'state is Disconnected' { Wait-RosetunState 'Disconnected' }
Test-Step 'hysteria2' 'direct egress works again' { Test-RosetunDirectEgress }
Test-Step 'hysteria2' 'IPv6 works again' { Test-RosetunIpv6Egress }

$namedIn = @(Find-RosetunLogText $connectionsHost)
Test-Step 'connections' "no service log names $connectionsHost" -Note ($namedIn -join ', ') {
    $namedIn.Count -eq 0
}
$namedIn = @(Find-RosetunLogText $longTransferHost)
Test-Step 'connections' "no service log names the closed download's $longTransferHost" `
    -Note ($namedIn -join ', ') {
    $namedIn.Count -eq 0
}
$closeLogged = @(Find-RosetunLogText 'closed a connection on request' -Anywhere)
$namedIn = if ($closedId) { @(Find-RosetunLogText $closedId -Anywhere) } else { @() }
Test-Step 'connections' 'the close is logged without the connection id' `
    -Note "logged in: $($closeLogged -join ', '); id in: $($namedIn -join ', ')" {
    $closedId -and $closeLogged.Count -gt 0 -and $namedIn.Count -eq 0
}

}
finally {
    if ($ipv6Neighbors.Count -gt 0) {
        try { Remove-RosetunIpv6Neighbor -Created $ipv6Neighbors }
        catch { Write-Warning "Could not remove the IPv6 neighbors pinned by the matrix: $_" }
    }
    if ($egressWatchActive) {
        try { Stop-RosetunEgressWatch | Out-Null }
        catch { Write-Warning "Could not remove the egress watch: $_" }
    }
    if ($otherAccountName) {
        try {
            Remove-OtherAccount -Name $otherAccountName
        }
        catch { Write-Warning "Could not finish other-account cleanup: $_" }
    }
    if ($serviceAttempted) {
        try { Remove-OtherAccountService -GuestDir (Get-RosetunGuestDir) }
        catch { Write-Warning "Could not remove the temporary Rosetun service: $_" }
    }
    if ($consoleStoppedForOther) {
        try { Start-RosetunHelper }
        catch { Write-Warning "Could not restore the console helper: $_" }
    }
    if ($null -ne $lanListener) {
        try { Stop-RosetunLanListener $lanListener }
        catch { Write-Warning "Could not remove the LAN listener or firewall rule: $_" }
    }
    if ($xrayNode) {
        try { Stop-RosetunXrayTestNode -Node $xrayNode }
        catch { Write-Warning "Could not stop the REALITY test node: $_" }
    }
    if ($blockedNodeStartedByMatrix -and -not $KeepNode) {
        try { Stop-RosetunTestNode -CloudflareBlocked }
        catch { Write-Warning "Could not stop the Cloudflare-blocked test node: $_" }
    }
    if ($nodeStartedByMatrix -and -not $KeepNode) {
        try { Stop-RosetunTestNode }
        catch { Write-Warning "Could not stop the test node: $_" }
    }
}

# Result first, so a long note cannot push it off the screen.
$results | Format-Table Result, Scenario, Check, Note -AutoSize

if ($results.Result -contains 'FAIL') {
    Write-Host '--- helper log (tail) ---'
    Get-RosetunHelperLog -Tail 60
    Write-Host "All helper logs of this run: $(Save-RosetunLogs)"
    exit 1
}
exit 0
