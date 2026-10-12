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
    [switch]$KeepNode,
    # Builds the workspace first, so a forgotten build cannot deploy stale binaries.
    [switch]$Build
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RosetunVm.psm1') -Force

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

function Format-Egress {
    param([Parameter(Mandatory)]$Egress)
    if ($Egress.Ok) {
        return "after $($Egress.Seconds) s"
    }
    "curl $($Egress.CurlExit), local '$($Egress.LocalIp)', tun '$($Egress.TunAddresses)': $($Egress.Error)"
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

# Sends requests to the service pipe as another, standard local account.
# A process started with that account's credentials fails inside PowerShell
# Direct (no window station: STATUS_DLL_INIT_FAILED), and a scheduled task as a
# fresh account did not finish, so the guest impersonates the account on its
# own thread while it opens the pipe; the service sees that account's token.
# This checks the service's decision; the CLI's wording is covered by unit tests.
function Invoke-OtherAccountRequests {
    param([string]$Name, [string]$GuestDir, [int]$ProtocolVersion)
    try {
        Invoke-RosetunGuest -ScriptBlock {
            param($name, $dir, $protocolVersion)

            function Read-Reply {
                param($Reader, [int]$Id)
                $deadline = (Get-Date).AddSeconds(15)
                while ($true) {
                    $remaining = [int]($deadline - (Get-Date)).TotalMilliseconds
                    if ($remaining -le 0) { throw 'timed out waiting for the service' }
                    $read = $Reader.ReadLineAsync()
                    if (-not $read.Wait($remaining)) { throw 'timed out waiting for the service' }
                    if ($null -eq $read.Result) { throw 'the service closed the connection' }
                    $frame = $read.Result | ConvertFrom-Json
                    if ($frame.response -and $frame.response.id -eq $Id) {
                        return $frame.response.body
                    }
                }
            }

            $bytes = New-Object byte[] 24
            $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            try { $random.GetBytes($bytes) }
            finally { $random.Dispose() }
            $password = 'Rt1!' + [Convert]::ToBase64String($bytes)
            $secure = ConvertTo-SecureString -String $password -AsPlainText -Force
            New-LocalUser -Name $name -Password $secure -PasswordNeverExpires | Out-Null

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
                apply = '{"apply":' + $requestJson + '}'
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
                foreach ($command in $bodies.Keys) {
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
                        $body = Read-Reply -Reader $reader -Id 2
                        $reply = if ($body.error) {
                            "error $($body.error.code): $($body.error.message)"
                        }
                        elseif ($body.status) { "status $($body.status.state)" }
                        else { $body | ConvertTo-Json -Compress -Depth 8 }
                        $code = if ($body.error) { [string]$body.error.code } else { '' }
                        $state = if ($body.status) { [string]$body.status.state } else { '' }
                    }
                    catch {
                        $reply = "failed: $($_.Exception.Message)"
                        $code = ''
                        $state = ''
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
                        StillConnected = ($adminExit -eq 0 -and
                            ($adminStatus -join "`n") -match '(?m)^state: Connected\r?$')
                    }
                }
            }
            finally {
                if ($identity) { $identity.Dispose() }
                if ($token -ne [IntPtr]::Zero) { [RosetunOtherLogon]::CloseHandle($token) | Out-Null }
            }
        } -ArgumentList $Name, $GuestDir, $ProtocolVersion
    }
    finally {
        try { Remove-OtherAccount -Name $Name }
        catch { Write-Warning "Could not clean up the other-account test: $_" }
    }
}

$nodeStartedByMatrix = $false
$lanListener = $null
$otherAccountName = $null
$serviceAttempted = $false
$consoleStoppedForOther = $false
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
    if ($NodeBindInterface) {
        $nodeStartedByMatrix = Start-RosetunTestNode -SingBoxPath $SingBoxPath -BindInterface $NodeBindInterface
    }
    else {
        $nodeStartedByMatrix = Start-RosetunTestNode -SingBoxPath $SingBoxPath
    }
}

if ($RestoreCheckpoint) {
    Write-Host 'Restoring the clean checkpoint...'
    Restore-RosetunVm
}

Write-Host 'Deploying binaries...'
# A helper left running by a previous run keeps its executable locked.
Stop-RosetunHelper
Publish-Rosetun -BuildDir $BuildDir -SingBoxPath $SingBoxPath -RequestPath $RequestPath -UseHostNode:$UseHostNode
Register-RosetunHelper
Start-RosetunHelper
$lanListener = Start-RosetunLanListener

$ipv6NeighborCreated = Initialize-RosetunIpv6Neighbor

# Proves the probe itself works. Without it, every "blocked" check below would
# pass even if the probe were broken or the probe URL unreachable.
Test-Step 'baseline' 'direct egress works before connect' { Test-RosetunDirectEgress }
Test-Step 'baseline' 'direct DNS works before connect' { Test-RosetunDirectDns }
Test-Step 'baseline' 'direct TCP DNS works before connect' { Test-RosetunDirectDns -Tcp }
Test-Step 'baseline' 'IPv6 to the host works before connect' { Test-RosetunIpv6Egress }
# The new firewall rule can take a moment to accept guest connections.
Test-Step 'baseline' 'LAN listener is reachable before connect' {
    Wait-RosetunCondition { Test-RosetunLanListener $lanListener } -TimeoutSeconds 10
}

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
$protocolSource = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '..\..\crates\rosetun-ipc\src\protocol.rs')
if (-not ($protocolSource -match 'pub const PROTOCOL_VERSION: u32 = (\d+);')) {
    throw 'Could not read PROTOCOL_VERSION from rosetun-ipc.'
}
$protocolVersion = [int]$Matches[1]
$otherResults = @(Invoke-OtherAccountRequests -Name $otherAccountName `
    -GuestDir (Get-RosetunGuestDir) -ProtocolVersion $protocolVersion)
foreach ($command in @('status', 'disconnect', 'temporary', 'apply')) {
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
Disconnect-RosetunTunnel | Out-Null
Test-Step 'other account' 'administrator disconnects the tunnel' {
    Wait-RosetunState 'Disconnected'
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
Test-Step 'temporary' 'unmatched domain is blocked' {
    -not (Test-RosetunTunnelEgress -Url 'https://ya.ru')
}
Test-Step 'temporary' 'physical egress stays blocked' { -not (Test-RosetunDirectEgress) }

Stop-RosetunEngine
Test-Step 'temporary restart' 'state returns to Connected' {
    Wait-RosetunState 'Connected' -TimeoutSeconds 90
}
$status = Invoke-RosetunCli -Quiet 'status'
Test-Step 'temporary restart' 'one rule is reported' {
    $status.ExitCode -eq 0 -and $status.Output -match '(?m)^temporary rules: 1$'
}
$egress = Wait-RosetunTunnelEgress -Url $temporaryDomainUrl -TimeoutSeconds 15 -SkipRevocationCheck
Test-Step 'temporary restart' 'domain still goes direct' -Note (Format-Egress $egress) { $egress.Ok }
Test-Step 'temporary restart' 'physical egress stays blocked' { -not (Test-RosetunDirectEgress) }

Write-Host 'Sleep with the tunnel up (saved Hyper-V VM)...'
Start-RosetunEgressWatch
$watch = $null
try {
    $beforeProbes = Invoke-RosetunGuest -ScriptBlock {
        [int]((Get-Content -Path "$env:TEMP\rosetun-egress-watch.txt") -split ' ')[0]
    }
    $guestBefore = Invoke-RosetunGuest -ScriptBlock { [DateTime]::UtcNow }
    Disconnect-RosetunVm
    $vmName = Get-RosetunVmName
    $sleepWatch = [Diagnostics.Stopwatch]::StartNew()
    $resumeWatch = $null
    try {
        Save-VM -Name $vmName | Out-Null
        Start-Sleep -Seconds 35
    }
    finally {
        if ((Get-VM -Name $vmName).State -eq 'Saved') {
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
    $guestGap = ($guestAfter - $guestBefore).TotalSeconds
    Test-Step 'sleep' 'guest clock jumped by more than 30 s' `
        -Note ("guest {0:N1} s, host {1:N1} s; check Hyper-V time synchronization if it did not jump" -f `
            $guestGap, $sleepWatch.Elapsed.TotalSeconds) {
        $guestGap -gt 30
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
    try { $watch = Stop-RosetunEgressWatch }
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

# Like a Wi-Fi reconnect: the engine has to follow the network on its own,
# and the helper notices nothing.
Write-Host 'Network change with the tunnel up...'
Start-RosetunEgressWatch
$adapter = Restart-RosetunEgressAdapter
$egress = Wait-RosetunTunnelEgress -TimeoutSeconds 60
$watch = Stop-RosetunEgressWatch
Test-Step 'network change' 'adapter gets its address from DHCP again' `
    -Note "after $($adapter.Seconds) s: $($adapter.Addresses)" { $adapter.Ok }
Test-Step 'network change' 'tunnel carries traffic again within 15 s' -Note (Format-Egress $egress) {
    $egress.Ok -and $egress.Seconds -le 15
}
Test-Step 'network change' "no leak while the network changes ($($watch.Probes) probes)" {
    $watch.Probes -gt 0 -and $watch.Leaks -eq 0
}
Test-Step 'network change' 'state is still Connected' { (Get-RosetunState) -eq 'Connected' }

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
Connect-RosetunTunnel | Out-Null
$reconnected = Wait-RosetunState 'Connected'
$watch = Stop-RosetunEgressWatch
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

if ($ipv6NeighborCreated) {
    Test-Step 'cleanup' 'created IPv6 neighbor is removed' {
        $hostAddress = Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' -AddressFamily IPv6 -ErrorAction Stop |
            Where-Object { $_.IPAddress -like 'fe80::*' } |
            Select-Object -First 1
        if ($null -eq $hostAddress) {
            throw 'The host has no link-local IPv6 address on the Default Switch.'
        }
        $egress = Get-RosetunEgressInterface
        Invoke-RosetunGuest -ScriptBlock {
            param($address, $index)
            Remove-NetNeighbor -InterfaceIndex $index -IPAddress $address -Confirm:$false -ErrorAction Stop
            $true
        } -ArgumentList ($hostAddress.IPAddress -replace '%.*$', ''), $egress.Index
    }
}

}
finally {
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
