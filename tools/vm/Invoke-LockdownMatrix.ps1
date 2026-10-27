# Runs the Lockdown matrix in the Hyper-V test VM and prints a PASS/FAIL
# table. Exits with 1 if any check fails. The owner runs it; it reboots the
# guest and cuts its power unless -SkipReboot is given.
#
# Lockdown's persistent filters survive the script and would leave the guest
# offline; `finally` runs `--reset-firewall` whatever happens. If the run is
# killed before that, see tools/vm/README.md.

param(
    [Parameter(Mandatory)][string]$SingBoxPath,
    [Parameter(Mandatory)][string]$RequestPath,
    [string]$BuildDir = (Join-Path $PSScriptRoot '..\..\target\release'),
    [switch]$RestoreCheckpoint,
    [switch]$UseHostNode,
    [string]$NodeBindInterface,
    # Builds the workspace first, so a forgotten build cannot deploy stale binaries.
    [switch]$Build,
    # Skips the reboot and the power cuts (checks 6 and 7) for a quick pass.
    [switch]$SkipReboot,
    # Each power cut pass runs this often for turning on and for turning off.
    [int]$PowerCutRepeats = 3,
    # Wait between the Lockdown change and the power cut. Without the flush a
    # cut even 60 s after the change lost it (study, run 4).
    [int]$PowerCutDelaySeconds = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RosetunVm.psm1') -Force
Assert-RosetunHostLockdownOff

$results = [System.Collections.Generic.List[object]]::new()
$guestDir = Get-RosetunGuestDir
$matrixDir = Join-Path $guestDir 'lockdown-matrix'
$bootTask = 'RosetunLockdownMatrixBootCheck'
# Fixed forever in crates/rosetun-routing/src/platform/windows/lockdown.rs.
$lockdownKeys = [ordered]@{
    Provider = 'f12dbedd-f3c7-4a72-b0f8-20559c88b112'
    Sublayer = 'f829a64d-c373-4d92-9d66-e1c680f3794f'
    Outbound = '57bf2a6e-57db-4d99-bed7-ecbd2c63aa75'
    Inbound  = 'e599db5e-6aeb-4e4d-aa51-4314f1b3076c'
    Dhcp     = '98419911-30f0-4f71-9178-263b40bc7f6e'
    # The service's DNS permit (IPv4, UDP), present whenever Lockdown is.
    ServiceDns = 'cb0f8c4b-4967-4626-a493-a4e32369e6f5'
    Lan      = 'ce01436a-65d3-48e9-b921-e0a167b05f7b'
    # The CLI's permits (IPv4: TCP 443, UDP DNS) exist only while no session
    # runs. The GUI is not deployed, so it has none.
    CliWeb   = '05b9da42-ea8e-4b28-a2b8-2404db01e0d1'
    CliDns   = '982cc554-9f41-4c9a-833f-87cc5149725f'
    # Retired in 0.4 (the CLI to any port); never present again.
    RetiredCli = '729b156a-c411-4f01-b7d9-a789c94e992b'
}
# A local account outside Administrators, created for this run.
$standardUser = 'RosetunMatrixUser'
$standardDir = 'C:\rosetun-matrix-user'
$probeProviderKey = '8c9a1588-cf36-44b8-80d8-987a6b81b4d2'
# The service's dynamic provider (session.rs).
$rosetunProviderKey = '51a47ec7-6459-4b84-8854-075e1576e7f9'

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

function Test-InUseFree {
    # FWP_E_IN_USE, as the helper prints it (decimal) or as netsh does.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Log)
    $Log -notmatch '2150825994|0x8032000a|FWP_E_IN_USE'
}

function Get-LockdownObjects {
    # Which Lockdown objects exist, from one dump of the WFP state. Boot-time
    # filters are not active once BFE runs, so they are not listed.
    $present = Invoke-RosetunGuest -ScriptBlock {
        param([string[]]$keys)
        $path = Join-Path $env:TEMP ("rosetun-wfp-$([guid]::NewGuid().ToString('N')).xml")
        try {
            & netsh.exe wfp show state "file=$path" *> $null
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $path)) {
                throw 'Cannot inspect WFP state.'
            }
            $state = Get-Content -Raw -LiteralPath $path
            @($keys | ForEach-Object { $state -match [regex]::Escape($_) })
        }
        finally {
            Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue
            $global:LASTEXITCODE = 0
        }
    } -ArgumentList (, [string[]]@($lockdownKeys.Values))
    $objects = [ordered]@{}
    $index = 0
    foreach ($name in $lockdownKeys.Keys) {
        $objects[$name] = [bool]$present[$index]
        $index++
    }
    [pscustomobject]$objects
}

function Format-Objects {
    param([Parameter(Mandatory)]$Objects)
    ($Objects.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' '
}

function Test-LockdownInstalled {
    # The program permits come and go with sessions; Test-ProgramPermits
    # checks them.
    param([switch]$Lan)
    $objects = Get-LockdownObjects
    $objects.Provider -and $objects.Sublayer -and $objects.Outbound -and $objects.Inbound -and
        $objects.Dhcp -and $objects.ServiceDns -and $objects.Lan -eq [bool]$Lan -and -not $objects.RetiredCli
}

function Test-ProgramPermits {
    # Whether the CLI's Lockdown permits are present (`-Present`) or absent.
    param([switch]$Present)
    $objects = Get-LockdownObjects
    if ($objects.RetiredCli) { return $false }
    if ($Present) { $objects.CliWeb -and $objects.CliDns } else { -not $objects.CliWeb -and -not $objects.CliDns }
}

function New-StandardAccount {
    # Its password lives only in this run. The account gets a folder of its
    # own for the runner scripts and their output.
    $password = 'Rm1!' + [guid]::NewGuid().ToString('N')
    Invoke-RosetunGuest -ScriptBlock {
        param($name, $password, $dir)
        Get-LocalUser -Name $name -ErrorAction SilentlyContinue | Remove-LocalUser
        $secure = ConvertTo-SecureString -String $password -AsPlainText -Force
        New-LocalUser -Name $name -Password $secure -PasswordNeverExpires -AccountNeverExpires `
            -Description 'Rosetun Lockdown matrix' | Out-Null
        # Users, and Performance Log Users for "Log on as a batch job", which
        # a task with a stored password needs (the failure matrix's task as
        # a fresh account never finished). Neither gives administrator
        # rights. By SID, since group names are localized.
        foreach ($group in 'S-1-5-32-545', 'S-1-5-32-559') {
            try { Add-LocalGroupMember -SID $group -Member $name -ErrorAction Stop }
            catch [Microsoft.PowerShell.Commands.MemberExistsException] { }
        }
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        & icacls.exe $dir /grant "${name}:(OI)(CI)M" | Out-Null
        $global:LASTEXITCODE = 0
    } -ArgumentList $standardUser, $password, $standardDir
    $password
}

function Remove-StandardAccount {
    Invoke-RosetunGuest -ScriptBlock {
        param($name, $dir)
        $user = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
        if ($user) {
            Get-CimInstance -ClassName Win32_UserProfile |
                Where-Object { $_.SID -eq $user.SID.Value } |
                Remove-CimInstance -ErrorAction SilentlyContinue
            Remove-LocalUser -Name $name
        }
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    } -ArgumentList $standardUser, $standardDir
}

function Invoke-AsStandardUser {
    # Runs a program as the standard account through a one-off scheduled task
    # with its password: the token has no administrator rights and no
    # elevation. Arguments must not contain spaces or quotes.
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [int]$TimeoutSeconds = 30
    )
    Invoke-RosetunGuest -ScriptBlock {
        param($name, $password, $dir, $file, $arguments, $timeout)
        $id = [guid]::NewGuid().ToString('N')
        $runner = Join-Path $dir "run-$id.ps1"
        $out = Join-Path $dir "out-$id.txt"
        $err = Join-Path $dir "err-$id.txt"
        $code = Join-Path $dir "code-$id.txt"
        $task = "RosetunMatrixUser-$id"
        $quote = { param($value) "'" + ($value -replace "'", "''") + "'" }
        $script = @(
            "`$process = Start-Process -FilePath $(& $quote $file) -ArgumentList $(& $quote $arguments) " +
                "-WorkingDirectory $(& $quote $dir) -NoNewWindow -PassThru " +
                "-RedirectStandardOutput $(& $quote $out) -RedirectStandardError $(& $quote $err)"
            # Without reading the handle first, ExitCode stays empty.
            '$null = $process.Handle'
            "if (`$process.WaitForExit($($timeout * 1000))) { `$result = `$process.ExitCode } else { `$process.Kill(); `$result = 'timeout' }"
            "Set-Content -LiteralPath $(& $quote $code) -Value `$result"
        ) -join "`r`n"
        [IO.File]::WriteAllText($runner, $script)
        $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
            -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$runner`"" -WorkingDirectory $dir
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(2)) `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName $task -Action $action -Settings $settings -User $name `
            -Password $password -RunLevel Limited | Out-Null
        try {
            Start-ScheduledTask -TaskName $task
            $deadline = (Get-Date).AddSeconds($timeout + 30)
            while (-not (Test-Path -LiteralPath $code) -and (Get-Date) -lt $deadline) {
                Start-Sleep -Milliseconds 250
            }
            if (-not (Test-Path -LiteralPath $code)) {
                # 0x80070569: the account lacks "Log on as a batch job".
                $last = (Get-ScheduledTaskInfo -TaskName $task).LastTaskResult
                throw ("The task as {0} did not finish; last result 0x{1:X8}." -f $name, $last)
            }
            $text = (Get-Content -Raw -LiteralPath $code).Trim()
            $output = @($out, $err | Where-Object { Test-Path -LiteralPath $_ } |
                ForEach-Object { Get-Content -Raw -LiteralPath $_ }) -join "`n"
            [pscustomobject]@{
                ExitCode = if ($text -match '^-?\d+$') { [int]$text } else { $text }
                Output   = $output.Trim()
            }
        }
        finally {
            Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $runner, $out, $err, $code -ErrorAction SilentlyContinue
        }
    } -ArgumentList $standardUser, $script:standardPassword, $standardDir, $FilePath, ($Arguments -join ' '), $TimeoutSeconds
}

function Invoke-StandardFetch {
    # Rosetun's own sing-box.exe started by the standard account, with no
    # node config: plain (the default route, so into the tunnel while one is
    # up) or bound to the physical adapter's address (outside the tunnel).
    # `Ok` is true when the fetch succeeded, false when it failed and $null
    # when the account could not run it, which no check counts as a pass.
    param([switch]$Physical)
    $arguments = @('tools', 'fetch', 'https://1.1.1.1')
    if ($Physical) {
        $config = Join-Path $standardDir 'physical.json'
        $address = Get-RosetunEgressAddress
        Invoke-RosetunGuest -ScriptBlock {
            param($path, $address)
            $outbound = [ordered]@{ type = 'direct'; tag = 'direct'; inet4_bind_address = $address }
            $json = [ordered]@{ log = @{ level = 'error' }; outbounds = @($outbound) } | ConvertTo-Json -Depth 5
            [IO.File]::WriteAllText($path, $json)
        } -ArgumentList $config, $address
        $arguments = @('-c', $config) + $arguments
    }
    try {
        $run = Invoke-AsStandardUser -FilePath (Join-Path $guestDir 'sing-box.exe') -Arguments $arguments
        [pscustomobject]@{ Ok = $run.ExitCode -eq 0; Note = "exit $($run.ExitCode): $($run.Output)" }
    }
    catch {
        [pscustomobject]@{ Ok = $null; Note = "not run: $_" }
    }
}

function Test-StandardFetchBlocked {
    # Both fetches fail: without a session Lockdown holds, and the engine
    # permits match only the service's account.
    param([Parameter(Mandatory)][string]$Scenario)
    $plain = Invoke-StandardFetch
    Test-Step $Scenario 'sing-box.exe tools fetch from a standard account fails' {
        $standardFetchWorks -and $plain.Ok -eq $false
    } -Note (Get-StandardFetchNote $plain)
    $physical = Invoke-StandardFetch -Physical
    Test-Step $Scenario 'the same, bound to the physical adapter, fails' {
        $standardFetchWorks -and $physical.Ok -eq $false
    } -Note (Get-StandardFetchNote $physical)
}

function Get-StandardFetchNote {
    # A failure proves nothing unless the same fetch worked without Lockdown.
    param([Parameter(Mandatory)]$Fetch)
    if ($standardFetchWorks) { $Fetch.Note } else { "not meaningful: the fetch failed in '1 off' too; $($Fetch.Note)" }
}

function Test-StandardLockdownOff {
    # `rosetun lockdown off` from the standard account is refused with the
    # hint and Lockdown stays.
    param([Parameter(Mandatory)][string]$Scenario)
    try {
        $off = Invoke-AsStandardUser -FilePath (Join-Path $guestDir 'rosetun.exe') -Arguments @('lockdown', 'off')
    }
    catch {
        $off = [pscustomobject]@{ ExitCode = 'not run'; Output = "$_" }
    }
    Test-Step $Scenario 'rosetun lockdown off from a standard account is refused' {
        $off.ExitCode -is [int] -and $off.ExitCode -ne 0 -and $off.Output -match 'administrator'
    } -Note "exit $($off.ExitCode): $($off.Output)"
    Test-Step $Scenario 'Lockdown stays after the refusal' {
        (Get-LockdownStatusLine) -eq 'on' -and (Test-LockdownInstalled)
    } -Note (Format-Objects (Get-LockdownObjects))
}

function Test-LockdownAbsent {
    $objects = Get-LockdownObjects
    -not ($objects.PSObject.Properties.Value -contains $true)
}

function Get-LockdownStatusLine {
    $status = Invoke-RosetunCli -Quiet 'status'
    if ($status.Output -match '(?m)^lockdown: (on|off)') { $Matches[1] } else { "unknown (exit $($status.ExitCode))" }
}

function Invoke-Lockdown {
    # `rosetun lockdown on|off`; returns the CLI result for the caller to test.
    param([Parameter(Mandatory)][ValidateSet('on', 'off')][string]$State)
    Invoke-RosetunCli -Quiet 'lockdown' $State
}

function Test-CliPathEgress {
    # The CLI's permit is by application ID, which WFP derives from the path:
    # curl copied over rosetun.exe for one request shows whether a program at
    # that path gets out. The real CLI is put back in the same call.
    $address = Get-RosetunEgressAddress
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $address, $url)
        $cli = Join-Path $dir 'rosetun.exe'
        $saved = Join-Path $dir 'rosetun.exe.matrix'
        Move-Item -LiteralPath $cli -Destination $saved -Force
        try {
            Copy-Item -LiteralPath (Get-Command -Name curl.exe -ErrorAction Stop).Source -Destination $cli -Force
            & $cli --interface $address --max-time 5 --silent --output NUL $url 2>$null
            $LASTEXITCODE -eq 0
        }
        finally {
            $global:LASTEXITCODE = 0
            Remove-Item -LiteralPath $cli -Force -ErrorAction SilentlyContinue
            Move-Item -LiteralPath $saved -Destination $cli -Force
        }
    } -ArgumentList $guestDir, $address, 'https://1.1.1.1'
}

function Start-GuestListener {
    # A TCP listener in the guest with a guest firewall rule for it, so only
    # Lockdown decides whether the host gets in. It lives in the PowerShell
    # Direct session until Stop-GuestListener.
    Invoke-RosetunGuest -ScriptBlock {
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Any, 0)
        $listener.Start(8)
        $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
        $name = "Rosetun-Lockdown-matrix-$port"
        New-NetFirewallRule -Name $name -DisplayName 'Rosetun Lockdown matrix listener' -Direction Inbound `
            -Action Allow -Protocol TCP -LocalPort $port -Profile Any | Out-Null
        $global:RosetunMatrixListener = [pscustomobject]@{ Listener = $listener; RuleName = $name; Port = $port }
        $port
    }
}

function Stop-GuestListener {
    Invoke-RosetunGuest -ScriptBlock {
        $state = Get-Variable -Name RosetunMatrixListener -Scope Global -ValueOnly -ErrorAction SilentlyContinue
        if ($state) {
            Remove-NetFirewallRule -Name $state.RuleName -ErrorAction SilentlyContinue
            $state.Listener.Stop()
            Remove-Variable -Name RosetunMatrixListener -Scope Global
        }
    }
}

function Test-InboundFromHost {
    # The host connects to the guest's Default Switch address, a private one.
    param([Parameter(Mandatory)][int]$Port)
    $address = Get-RosetunEgressAddress
    $client = [Net.Sockets.TcpClient]::new()
    try { $client.ConnectAsync($address, $Port).Wait(3000) }
    catch { $false }
    finally { $client.Dispose() }
}

function Test-LockdownErrorFree {
    # The service's errors about Lockdown or the kill switch it forces.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Log)
    -not ($Log -split "`n" | Where-Object { $_ -match '\bERROR\b' -and $_ -match '(?i)lockdown|kill switch' })
}

function Test-SleepClockJump {
    param([Parameter(Mandatory)][string]$Scenario, [Parameter(Mandatory)]$Sleep)
    Test-Step $Scenario 'guest clock jumped by more than 30 s while saved' `
        -Note ("saved {0:N1} s, inferred jump {1:N1} s; check Hyper-V time synchronization if it did not jump" -f `
            $Sleep.SavedSeconds, $Sleep.ClockJump) {
        $Sleep.SavedSeconds -gt 30 -and $Sleep.ClockJump -gt 30
    }
}

function Get-GuestGateway {
    Invoke-RosetunGuest -ScriptBlock {
        (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object -Property RouteMetric | Select-Object -First 1).NextHop
    }
}

function Install-TestService {
    # The real service, so `--reset-firewall` has an SCM service to stop.
    Stop-RosetunHelper
    $install = Invoke-RosetunHelperMode '--install-service'
    if ($install.ExitCode -ne 0) {
        throw "Could not install the test service: $($install.Output)"
    }
    Wait-ServicePipe
}

function Wait-ServicePipe {
    $ready = Wait-RosetunCondition {
        Invoke-RosetunGuest -ScriptBlock {
            (Get-Service -Name 'Rosetun' -ErrorAction SilentlyContinue).Status -eq 'Running' -and
                ([IO.Directory]::GetFiles('\\.\pipe\') -contains '\\.\pipe\rosetun-helper')
        }
    } -TimeoutSeconds 60
    if (-not $ready) { throw 'The Rosetun service did not open its pipe within 60 s.' }
}

function Get-ServiceState {
    Invoke-RosetunGuest -ScriptBlock { "$((Get-Service -Name 'Rosetun' -ErrorAction SilentlyContinue).Status)" }
}

function Remove-TestService {
    $remove = Invoke-RosetunHelperMode '--uninstall-service'
    if ($remove.ExitCode -ne 0) {
        throw "Could not remove the test service: $($remove.Output)"
    }
}

function New-GuestRequestByName {
    # request.json with the node as node.rosetun.test. `allow_lan` matches
    # Lockdown's, since a connect moves Lockdown's LAN set to the request's.
    param([Parameter(Mandatory)][bool]$AllowLan)
    $file = if ($AllowLan) { 'request-by-name-lan.json' } else { 'request-by-name.json' }
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $file, $allowLan)
        $request = Get-Content -Raw -LiteralPath "$dir\request.json" | ConvertFrom-Json
        $request.node.server = 'node.rosetun.test'
        $request.settings | Add-Member -NotePropertyName allow_lan -NotePropertyValue $allowLan -Force
        [IO.File]::WriteAllText("$dir\$file", ($request | ConvertTo-Json -Depth 20))
    } -ArgumentList $guestDir, $file, $AllowLan
    $file
}

function Test-ByName {
    # A connect, a server check and a subscription update by name; under
    # Lockdown also that names stay closed to everything but Rosetun.
    param(
        [Parameter(Mandatory)][string]$Scenario,
        [Parameter(Mandatory)][string]$RequestName,
        [switch]$Lockdown
    )
    $mark = Get-RosetunHelperLogLength
    $connect = Connect-RosetunTunnel -RequestName $RequestName -Quiet
    Test-Step $Scenario 'connect to node.rosetun.test succeeds' { $connect.ExitCode -eq 0 } -Note $connect.Output
    Disconnect-RosetunTunnel | Out-Null
    $probe = Invoke-RosetunProbe -RequestName $RequestName
    Test-Step $Scenario 'server check of node.rosetun.test works' { $probe.Output -match '(?m)^works' } -Note $probe.Output
    $update = Invoke-RosetunCli -Quiet 'sub' 'update' $subscriptionId
    Test-Step $Scenario 'rosetun sub update from sub.rosetun.test succeeds' { $update.ExitCode -eq 0 } -Note $update.Output
    if ($Lockdown) {
        Test-Step $Scenario 'the system resolver (Dnscache) gets no answer' {
            -not (Test-RosetunGuestSystemResolver 'node.rosetun.test')
        }
        Test-Step $Scenario 'nslookup gets no answer' { -not (Test-RosetunGuestNslookup 'node.rosetun.test') }
        Test-Step $Scenario 'direct egress still closed' { -not (Test-RosetunDirectEgress) }
    }
    Test-Step $Scenario "no 'failed to resolve the VPN endpoint' in helper.log" {
        (Get-RosetunHelperLogSince $mark) -notmatch 'failed to resolve the VPN endpoint'
    }
}

function Test-BootClosed {
    # Reads the boot check of the current boot: before sign-in, a lease and a
    # route, and no attempt that reached the internet.
    param([Parameter(Mandatory)][string]$Scenario)
    $attempts = Get-RosetunBootCheck -Directory $matrixDir -BootTime (Get-RosetunGuestBootTime)
    $note = Format-RosetunBootCheck -Attempts $attempts
    $routed = @($attempts | Where-Object { $_.Route })
    Test-Step $Scenario 'boot check ran before sign-in' {
        $attempts.Count -gt 0 -and @($attempts | Where-Object { $_.User }).Count -eq 0
    } -Note $note
    Test-Step $Scenario 'a DHCP address and a default route before sign-in' {
        @($routed | Where-Object { $_.Addresses -match '/Dhcp/Preferred' }).Count -gt 0
    } -Note "$($routed.Count) of $($attempts.Count) attempts routed"
    Test-Step $Scenario 'no boot attempt reached the internet' {
        @($routed | Where-Object { $_.CurlExit -eq 0 }).Count -eq 0
    } -Note $note
}

$nodeStarted = $false
$hostLan = $null
$guestListenerPort = $null
$serviceInstalled = $false
$bootTaskRegistered = $false
$bootRecovery = $null
$ipv6Neighbors = [System.Collections.Generic.List[object]]::new()
$zone = $null
$guestResolver = $null
$subscriptionId = $null
$egressWatchActive = $false
$standardPassword = $null
$standardFetchWorks = $false
try {
    if ($Build) {
        Write-Host 'Building...'
        & cargo build -q --release --manifest-path (Join-Path $PSScriptRoot '..\..\Cargo.toml')
        $exitCode = $LASTEXITCODE
        $global:LASTEXITCODE = 0
        if ($exitCode -ne 0) { throw "cargo build failed with exit code $exitCode." }
    }
    if ($UseHostNode) {
        $nodeStarted = if ($NodeBindInterface) {
            Start-RosetunTestNode -SingBoxPath $SingBoxPath -BindInterface $NodeBindInterface
        }
        else {
            Start-RosetunTestNode -SingBoxPath $SingBoxPath
        }
    }
    if ($RestoreCheckpoint) {
        Write-Host 'Restoring the clean checkpoint...'
        Restore-RosetunVm
    }

    Write-Host "Checking the guest's network..."
    Restore-RosetunGuestLease

    Write-Host 'Deploying binaries...'
    Stop-RosetunHelper
    Publish-Rosetun -BuildDir $BuildDir -SingBoxPath $SingBoxPath -RequestPath $RequestPath -UseHostNode:$UseHostNode
    # A Lockdown left by an interrupted run would turn the baseline into a block.
    $reset = Invoke-RosetunHelperMode '--reset-firewall'
    if ($reset.ExitCode -ne 0) { throw "Initial --reset-firewall failed: $($reset.Output)" }
    Register-RosetunHelper
    Start-RosetunHelper
    Invoke-RosetunCli -Quiet 'lan' 'off' | Out-Null
    Restore-RosetunGuestLease
    Set-RosetunIpv6Neighbor -Created $ipv6Neighbors
    $hostLan = Start-RosetunLanListener
    $guestListenerPort = Start-GuestListener
    $gateway = Get-GuestGateway
    # Names for scenarios 1 to 3: the guest's adapter asks the host's zone.
    $zone = Start-RosetunNameZone -SubscriptionBody "ss://aes-256-gcm:rosetun-test@192.0.2.10:8388#Lockdown%20matrix`n"
    $requestByName = New-GuestRequestByName -AllowLan $false
    $requestByNameLan = New-GuestRequestByName -AllowLan $true
    $guestResolver = Set-RosetunGuestResolver -Server $zone.DnsAddress

    # 1. Lockdown off: nothing of it exists, and the probes work.
    Test-Step '1 off' 'no Lockdown objects' { Test-LockdownAbsent } -Note (Format-Objects (Get-LockdownObjects))
    Test-Step '1 off' 'status: lockdown off' { (Get-LockdownStatusLine) -eq 'off' }
    Test-Step '1 off' 'direct egress works' { Test-RosetunDirectEgress }
    Test-Step '1 off' 'direct DNS works' { Test-RosetunDirectDns }
    Test-Step '1 off' 'IPv6 to the host works' { Test-RosetunIpv6Open -Neighbors $ipv6Neighbors }
    if ($results[$results.Count - 1].Result -eq 'FAIL') {
        throw "IPv6 to the host does not work, so every 'IPv6 closed' check would be meaningless. $(Get-RosetunIpv6NeighborReport)"
    }
    Test-Step '1 off' 'the host reaches a guest listener' { Test-InboundFromHost $guestListenerPort }
    Test-Step '1 off' 'the guest reaches a host listener' {
        Wait-RosetunCondition { Test-RosetunLanListener $hostLan } -TimeoutSeconds 10
    }
    Test-Step '1 off' 'curl at the CLI path works' { Test-CliPathEgress }
    $gatewayDns = Test-RosetunDirectDns -Server $gateway
    Add-Info '1 off' "DNS to the gateway $gateway" "answers: $gatewayDns"
    Test-Step '1 off' 'the system resolver answers node.rosetun.test' { Test-RosetunGuestSystemResolver 'node.rosetun.test' }
    if ($results[$results.Count - 1].Result -eq 'FAIL') {
        throw "The guest cannot resolve rosetun.test through $($zone.DnsAddress), so every check by name would be meaningless."
    }
    $add = Invoke-RosetunCli -Quiet 'sub' 'add' $zone.SubscriptionUrl '--name' 'Lockdown matrix'
    if ($add.Output -match '(?m)^(\S+): Lockdown matrix \|') { $subscriptionId = $Matches[1] }
    Test-Step '1 off' 'rosetun sub add from sub.rosetun.test succeeds' { $add.ExitCode -eq 0 -and $subscriptionId } -Note $add.Output
    if (-not $subscriptionId) { throw 'The subscription by name could not be added.' }
    Test-ByName '1 off' $requestByName
    # The standard account's fetches must work here, or every "fails" check
    # below proves nothing; those then fail as not meaningful.
    try { $standardPassword = New-StandardAccount }
    catch { Test-Step '1 off' 'a standard account is created' { $false } -Note "$_" }
    $plain = Invoke-StandardFetch
    $physical = Invoke-StandardFetch -Physical
    Test-Step '1 off' 'sing-box.exe tools fetch from a standard account works' { $plain.Ok } -Note $plain.Note
    Test-Step '1 off' 'the same, bound to the physical adapter, works' { $physical.Ok } -Note $physical.Note
    $standardFetchWorks = [bool]($plain.Ok -and $physical.Ok)

    # 2. On while disconnected.
    $on = Invoke-Lockdown on
    Test-Step '2 on, disconnected' 'rosetun lockdown on succeeds' { $on.ExitCode -eq 0 } -Note $on.Output
    Test-Step '2 on, disconnected' 'objects present, without LAN' { Test-LockdownInstalled } -Note (Format-Objects (Get-LockdownObjects))
    Test-Step '2 on, disconnected' 'status: lockdown on' { (Get-LockdownStatusLine) -eq 'on' }
    Test-Step '2 on, disconnected' 'CLI permits present, the retired one absent' { Test-ProgramPermits -Present } `
        -Note (Format-Objects (Get-LockdownObjects))
    Test-StandardLockdownOff '2 standard account'
    Test-StandardFetchBlocked '2 standard account'
    Test-Step '2 on, disconnected' 'direct egress closed' { -not (Test-RosetunDirectEgress) }
    Test-Step '2 on, disconnected' 'direct DNS over UDP closed' { -not (Test-RosetunDirectDns) }
    Test-Step '2 on, disconnected' 'direct DNS over TCP closed' { -not (Test-RosetunDirectDns -Tcp) }
    Test-Step '2 on, disconnected' 'IPv6 to the host closed' { -not (Test-RosetunIpv6Open -Neighbors $ipv6Neighbors) }
    Test-Step '2 on, disconnected' 'loopback open' { Test-RosetunGuestLoopback }
    Test-Step '2 on, disconnected' 'a program at the CLI path gets out (subscription update)' { Test-CliPathEgress }
    $probe = Invoke-RosetunProbe
    Test-Step '2 on, disconnected' 'server check works' { $probe.Output -match '(?m)^works' } -Note $probe.Output
    Test-Step '2 on, disconnected' 'server check left no permit behind' { -not (Test-RosetunGuestWfpKey $probeProviderKey) }
    Test-Step '2 on, disconnected' 'direct egress still closed after the check' { -not (Test-RosetunDirectEgress) }
    Test-ByName '2 on, disconnected' $requestByName -Lockdown

    # 3. Inbound and LAN.
    Test-Step '3 inbound' 'the host cannot reach a guest listener' { -not (Test-InboundFromHost $guestListenerPort) }
    Test-Step '3 inbound' 'the guest cannot reach a host listener' { -not (Test-RosetunLanListener $hostLan) }
    $lanOn = Invoke-RosetunCli -Quiet 'lan' 'on'
    Test-Step '3 lan on' 'rosetun lan on updates Lockdown' { $lanOn.ExitCode -eq 0 -and $lanOn.Output -match 'lockdown on' } -Note $lanOn.Output
    Test-Step '3 lan on' 'LAN filters present' { Test-LockdownInstalled -Lan } -Note (Format-Objects (Get-LockdownObjects))
    Test-Step '3 lan on' 'the host reaches a guest listener' { Test-InboundFromHost $guestListenerPort }
    Test-Step '3 lan on' 'the guest reaches a host listener' { Test-RosetunLanListener $hostLan }
    if ($gatewayDns) {
        Test-Step '3 lan on' 'DNS to the gateway closed' { -not (Test-RosetunDirectDns -Server $gateway) }
        Test-Step '3 lan on' 'TCP DNS to the gateway closed' { -not (Test-RosetunDirectDns -Server $gateway -Tcp) }
    }
    else {
        Add-Info '3 lan on' 'DNS to the gateway' 'not checked: the gateway did not answer DNS without Lockdown either'
    }
    Test-Step '3 lan on' 'direct egress closed' { -not (Test-RosetunDirectEgress) }
    # The zone's address is private like a router's: Rosetun's DNS permits
    # must outrank Lockdown's private-DNS block.
    Test-ByName '3 lan on' $requestByNameLan -Lockdown
    $lanOff = Invoke-RosetunCli -Quiet 'lan' 'off'
    Test-Step '3 lan off' 'rosetun lan off updates Lockdown' { $lanOff.ExitCode -eq 0 } -Note $lanOff.Output
    Test-Step '3 lan off' 'LAN filters gone' { Test-LockdownInstalled } -Note (Format-Objects (Get-LockdownObjects))
    Test-Step '3 lan off' 'the host cannot reach a guest listener' { -not (Test-InboundFromHost $guestListenerPort) }
    # The rest checks the tunnel by names the zone does not know.
    Restore-RosetunGuestResolver -Saved $guestResolver
    $guestResolver = $null

    # 4. Connect under Lockdown, then disconnect.
    $connect = Connect-RosetunTunnel -Quiet
    Test-Step '4 connected' 'connect succeeds' { $connect.ExitCode -eq 0 } -Note $connect.Output
    $tunnel = Wait-RosetunTunnelEgress -SkipRevocationCheck
    Test-Step '4 connected' 'the tunnel carries traffic' { $tunnel.Ok } -Note "$($tunnel.Seconds) s; $($tunnel.Error)"
    Test-Step '4 connected' 'direct egress closed' { -not (Test-RosetunDirectEgress) }
    Test-Step '4 connected' 'direct DNS over UDP closed' { -not (Test-RosetunDirectDns) }
    Test-Step '4 connected' 'direct DNS over TCP closed' { -not (Test-RosetunDirectDns -Tcp) }
    Test-Step '4 connected' 'IPv6 to the host closed' { -not (Test-RosetunIpv6Open -Neighbors $ipv6Neighbors) }
    Test-Step '4 connected' 'the host cannot reach a guest listener' { -not (Test-InboundFromHost $guestListenerPort) }
    Test-Step '4 connected' 'CLI permits removed for the session' { Test-ProgramPermits } -Note (Format-Objects (Get-LockdownObjects))
    Test-Step '4 connected' 'a program at the CLI path stays closed outside the tunnel' { -not (Test-CliPathEgress) }
    Test-StandardLockdownOff '4 standard account, connected'
    # Without binding, the fetch follows the default route into the tunnel:
    # not a leak, so only recorded.
    $plain = Invoke-StandardFetch
    Add-Info '4 standard account, connected' 'plain sing-box.exe tools fetch (through the tunnel)' "ok: $($plain.Ok); $($plain.Note)"
    $physical = Invoke-StandardFetch -Physical
    Test-Step '4 standard account, connected' 'sing-box.exe tools fetch bound to the physical adapter fails' {
        $standardFetchWorks -and $physical.Ok -eq $false
    } -Note (Get-StandardFetchNote $physical)
    Disconnect-RosetunTunnel | Out-Null
    Test-Step '4 disconnected' 'direct egress closed' { -not (Test-RosetunDirectEgress) }
    Test-Step '4 disconnected' 'no Rosetun session filters left' { -not (Test-RosetunGuestWfpKey $rosetunProviderKey) }
    Test-Step '4 disconnected' 'objects still present' { Test-LockdownInstalled }
    Test-Step '4 disconnected' 'CLI permits back' { Test-ProgramPermits -Present } -Note (Format-Objects (Get-LockdownObjects))
    Test-StandardFetchBlocked '4 standard account, disconnected'

    $unprotected = Connect-RosetunTunnel -RequestName 'request-apply-unprotected.json' -Quiet
    Test-Step '4 kill switch off' 'connect succeeds' { $unprotected.ExitCode -eq 0 } -Note $unprotected.Output
    Test-Step '4 kill switch off' 'Lockdown forces the kill switch: direct egress closed' { -not (Test-RosetunDirectEgress) }
    Disconnect-RosetunTunnel | Out-Null

    # 5. A killed service: Lockdown holds; without it, fail-open as today.
    Connect-RosetunTunnel | Out-Null
    Stop-RosetunHelper
    Test-Step '5 killed, on' 'direct egress closed' { -not (Test-RosetunDirectEgress) }
    Test-Step '5 killed, on' 'IPv6 to the host closed' { -not (Test-RosetunIpv6Open -Neighbors $ipv6Neighbors) }
    Test-Step '5 killed, on' 'the dynamic session is gone' { -not (Test-RosetunGuestWfpKey $rosetunProviderKey) }
    Test-Step '5 killed, on' 'objects still present' { Test-LockdownInstalled }
    # The session removed them for good; only the service puts them back.
    Test-Step '5 killed, on' 'CLI permits still absent' { Test-ProgramPermits } -Note (Format-Objects (Get-LockdownObjects))
    Start-RosetunHelper
    $startLog = Get-RosetunHelperLogSince 0
    Test-Step '5 restarted, on' 'the service finds Lockdown complete' {
        $startLog -match 'Lockdown is on.*\bcomplete=true'
    } -Note (($startLog -split "`n" | Select-String -Pattern 'Lockdown') -join ' | ')
    Test-Step '5 restarted, on' 'status: lockdown on' { (Get-LockdownStatusLine) -eq 'on' }
    Test-Step '5 restarted, on' 'CLI permits back without a session' { Test-ProgramPermits -Present } `
        -Note (Format-Objects (Get-LockdownObjects))
    $off = Invoke-Lockdown off
    Test-Step '5 off' 'rosetun lockdown off succeeds' { $off.ExitCode -eq 0 } -Note $off.Output
    Connect-RosetunTunnel | Out-Null
    Stop-RosetunHelper
    Test-Step '5 killed, off' 'fails open as before Lockdown: direct egress works' { Test-RosetunDirectEgress }
    Start-RosetunHelper

    # 5b. Sleep and resume under Lockdown (a saved VM), disconnected and
    # connected. The listener lives in the PowerShell Direct session, which
    # closes before Save-VM.
    $on = Invoke-Lockdown on
    Test-Step '5b sleep' 'rosetun lockdown on succeeds' { $on.ExitCode -eq 0 } -Note $on.Output
    $mark = Get-RosetunHelperLogLength
    Stop-GuestListener
    $guestListenerPort = $null
    $sleep = Suspend-RosetunGuest -Seconds 40
    $guestListenerPort = Start-GuestListener
    Test-SleepClockJump '5b sleep, disconnected' $sleep
    Test-Step '5b sleep, disconnected' 'objects present' { Test-LockdownInstalled } -Note (Format-Objects (Get-LockdownObjects))
    Test-Step '5b sleep, disconnected' 'status: lockdown on' { (Get-LockdownStatusLine) -eq 'on' }
    Test-Step '5b sleep, disconnected' 'direct egress closed' { -not (Test-RosetunDirectEgress) }
    Test-Step '5b sleep, disconnected' 'IPv6 to the host closed' { -not (Test-RosetunIpv6Open -Neighbors $ipv6Neighbors) }
    Test-Step '5b sleep, disconnected' 'the host cannot reach a guest listener' { -not (Test-InboundFromHost $guestListenerPort) }
    $connect = Connect-RosetunTunnel -Quiet
    $tunnel = Wait-RosetunTunnelEgress -SkipRevocationCheck
    Test-Step '5b sleep, disconnected' 'connect opens the tunnel' {
        $connect.ExitCode -eq 0 -and $tunnel.Ok
    } -Note "$($connect.Output) $($tunnel.Error)"

    Start-RosetunEgressWatch
    $egressWatchActive = $true
    $watch = $null
    $beforeProbes = 0
    try {
        $beforeProbes = Get-RosetunEgressWatchProbes
        Stop-GuestListener
        $guestListenerPort = $null
        $sleep = Suspend-RosetunGuest -Seconds 40
        $guestListenerPort = Start-GuestListener
        Test-SleepClockJump '5b sleep, connected' $sleep
        $connected = Wait-RosetunState 'Connected' -TimeoutSeconds 30
        $connectedAt = $sleep.ResumeWatch.Elapsed.TotalSeconds
        Test-Step '5b sleep, connected' 'state is Connected within 30 s of Start-VM' `
            -Note ("{0} after {1:N1} s" -f (Get-RosetunState), $connectedAt) {
            $connected -and $connectedAt -le 30
        }
        $tunnel = Wait-RosetunTunnelEgress -TimeoutSeconds 30 -SkipRevocationCheck
        $sleep.ResumeWatch.Stop()
        Test-Step '5b sleep, connected' 'tunnel carries traffic within 30 s of Start-VM' `
            -Note ("{0} s; {1}; after {2:N1} s" -f $tunnel.Seconds, $tunnel.Error, $sleep.ResumeWatch.Elapsed.TotalSeconds) {
            $tunnel.Ok -and $sleep.ResumeWatch.Elapsed.TotalSeconds -le 30
        }
        Test-Step '5b sleep, connected' 'objects present' { Test-LockdownInstalled } -Note (Format-Objects (Get-LockdownObjects))
    }
    finally {
        try {
            $watch = Stop-RosetunEgressWatch
            $egressWatchActive = $false
        }
        catch {
            Test-Step '5b sleep, connected' 'egress watch stopped' -Note "$_" { $false }
        }
    }
    $probeCount = if ($watch) { $watch.Probes } else { 0 }
    $leakCount = if ($watch) { $watch.Leaks } else { 'unknown' }
    Test-Step '5b sleep, connected' "no direct leak across the sleep ($probeCount probes)" `
        -Note "before save: $beforeProbes probes; leaks: $leakCount" {
        $watch -and $probeCount -gt $beforeProbes -and $leakCount -eq 0
    }
    Disconnect-RosetunTunnel | Out-Null
    $sleepLog = Get-RosetunHelperLogSince $mark
    Test-Step '5b sleep' 'no FWP_E_IN_USE in helper.log' { Test-InUseFree $sleepLog }
    Test-Step '5b sleep' 'no Lockdown errors in helper.log' { Test-LockdownErrorFree $sleepLog } -Note (
        ($sleepLog -split "`n" | Where-Object { $_ -match '\bERROR\b' } | Select-Object -First 3) -join ' | ')
    $off = Invoke-Lockdown off
    Test-Step '5b sleep' 'rosetun lockdown off succeeds' { $off.ExitCode -eq 0 } -Note $off.Output

    # 6. Reboot under Lockdown. The helper task has no trigger, so after the
    # boot nothing of Rosetun runs until it is started: Lockdown alone holds.
    if (-not $SkipReboot) {
        Invoke-Lockdown on | Out-Null
        # The listener and its guest firewall rule would not survive the boot cleanly.
        Stop-GuestListener
        $bootTaskRegistered = $true
        Register-RosetunBootCheck -Directory $matrixDir -TaskName $bootTask
        Restart-RosetunGuest -Label '6 reboot, on'
        Test-BootClosed '6 reboot, on'
        Test-Step '6 reboot, on' 'objects present after boot' { Test-LockdownInstalled } -Note (Format-Objects (Get-LockdownObjects))
        $lease = Get-RosetunGuestLease
        Test-Step '6 reboot, on' 'DHCP lease and default route after boot' { $lease.Leased } -Note $lease.Note
        Test-Step '6 reboot, on' 'direct egress closed after boot' { (Get-RosetunEgressAfterBoot) -ne 'open' }
        Test-Step '6 reboot, on' 'IPv6 to the host closed after boot' { -not (Test-RosetunIpv6Open -Neighbors $ipv6Neighbors) }
        $renew = Test-RosetunDhcpRenew
        Test-Step '6 reboot, on' 'ipconfig /renew keeps the lease under the inbound block' { $renew.Renewed } -Note $renew.Note
        Unregister-RosetunBootCheck -TaskName $bootTask
        $bootTaskRegistered = $false
        Start-RosetunHelper
        Test-Step '6 reboot, on' 'still closed with the service running, before Connect' { -not (Test-RosetunDirectEgress) }
        $connect = Connect-RosetunTunnel -Quiet
        $tunnel = Wait-RosetunTunnelEgress -SkipRevocationCheck
        Test-Step '6 reboot, on' 'Connect opens the tunnel' { $connect.ExitCode -eq 0 -and $tunnel.Ok } -Note "$($connect.Output) $($tunnel.Error)"
        Disconnect-RosetunTunnel | Out-Null
        Test-Step '6 reboot, on' 'closed again after Disconnect' { -not (Test-RosetunDirectEgress) }

        # 7. Power cuts right after a change: the flush must make it durable.
        $bootRecovery = Disable-RosetunBootRecovery
        Restore-RosetunGuestLease
        Start-RosetunHelper
        for ($pass = 1; $pass -le $PowerCutRepeats; $pass++) {
            $on = Invoke-Lockdown on
            Start-Sleep -Seconds $PowerCutDelaySeconds
            Restart-RosetunGuest -PowerCut -Label "7 cut after on #$pass"
            Test-Step "7 cut $PowerCutDelaySeconds s after on #$pass" 'objects present after boot' {
                $on.ExitCode -eq 0 -and (Test-LockdownInstalled)
            } -Note (Format-Objects (Get-LockdownObjects))
            Restore-RosetunGuestLease
            Start-RosetunHelper
            $off = Invoke-Lockdown off
            Start-Sleep -Seconds $PowerCutDelaySeconds
            Restart-RosetunGuest -PowerCut -Label "7 cut after off #$pass"
            Test-Step "7 cut $PowerCutDelaySeconds s after off #$pass" 'no objects after boot' {
                $off.ExitCode -eq 0 -and (Test-LockdownAbsent)
            } -Note (Format-Objects (Get-LockdownObjects))
            Restore-RosetunGuestLease
            Test-Step "7 cut $PowerCutDelaySeconds s after off #$pass" 'direct egress open' { Test-RosetunDirectEgress }
            Start-RosetunHelper
        }
        $guestListenerPort = Start-GuestListener
    }

    # 8. Off while connected and while disconnected: no FWP_E_IN_USE.
    Invoke-Lockdown on | Out-Null
    # The first connect after the power cuts has twice timed out on sing-box
    # readiness; helper.log is rewritten by later helper starts, so keep the
    # lines of a failed connect on the host before they are gone.
    $connectMark = Get-RosetunHelperLogLength
    $connect = Connect-RosetunTunnel
    if ($connect.ExitCode -ne 0) {
        $kept = Join-Path $PSScriptRoot ("logs\lockdown-first-connect-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
        Get-RosetunHelperLogSince $connectMark | Set-Content -LiteralPath $kept -Encoding UTF8
        Add-Info '8 off, connected' 'the first connect after the power cuts failed; helper log kept' -Note $kept
    }
    $mark = Get-RosetunHelperLogLength
    $off = Invoke-Lockdown off
    Test-Step '8 off, connected' 'rosetun lockdown off succeeds' { $off.ExitCode -eq 0 } -Note $off.Output
    Test-Step '8 off, connected' 'no objects' { Test-LockdownAbsent } -Note (Format-Objects (Get-LockdownObjects))
    $tunnel = Wait-RosetunTunnelEgress -SkipRevocationCheck
    Test-Step '8 off, connected' 'the tunnel still carries traffic' { $tunnel.Ok } -Note $tunnel.Error
    Test-Step '8 off, connected' 'the kill switch of the request stays: direct egress closed' { -not (Test-RosetunDirectEgress) }
    Test-Step '8 off, connected' 'no FWP_E_IN_USE in helper.log' { Test-InUseFree (Get-RosetunHelperLogSince $mark) }
    Disconnect-RosetunTunnel | Out-Null

    Invoke-Lockdown on | Out-Null
    Connect-RosetunTunnel -RequestName 'request-apply-unprotected.json' | Out-Null
    $off = Invoke-Lockdown off
    Test-Step '8 off, kill switch off' 'rosetun lockdown off succeeds' { $off.ExitCode -eq 0 } -Note $off.Output
    Test-Step '8 off, kill switch off' 'the forced kill switch is released: direct egress works' { Test-RosetunDirectEgress }
    $tunnel = Wait-RosetunTunnelEgress -SkipRevocationCheck
    Test-Step '8 off, kill switch off' 'the tunnel still carries traffic' { $tunnel.Ok } -Note $tunnel.Error
    Disconnect-RosetunTunnel | Out-Null

    Invoke-Lockdown on | Out-Null
    $mark = Get-RosetunHelperLogLength
    $off = Invoke-Lockdown off
    Test-Step '8 off, disconnected' 'rosetun lockdown off succeeds' { $off.ExitCode -eq 0 } -Note $off.Output
    Test-Step '8 off, disconnected' 'no objects' { Test-LockdownAbsent }
    Test-Step '8 off, disconnected' 'direct egress works' { Test-RosetunDirectEgress }
    Test-Step '8 off, disconnected' 'IPv6 to the host works' { Test-RosetunIpv6Open -Neighbors $ipv6Neighbors }
    Test-Step '8 off, disconnected' 'the host reaches a guest listener' { Test-InboundFromHost $guestListenerPort }
    $again = Invoke-Lockdown off
    Test-Step '8 off, disconnected' 'a second off succeeds' { $again.ExitCode -eq 0 } -Note $again.Output
    Test-Step '8 off, disconnected' 'no FWP_E_IN_USE in helper.log' { Test-InUseFree (Get-RosetunHelperLogSince $mark) }

    # 9. reset-firewall with the real SCM service, running and connected, then stopped.
    $serviceInstalled = $true
    Install-TestService
    Invoke-Lockdown on | Out-Null
    $connect = Connect-RosetunTunnel -Quiet
    Test-Step '9 reset, running' 'connected through the service' { $connect.ExitCode -eq 0 } -Note $connect.Output
    $reset = Invoke-RosetunHelperMode '--reset-firewall'
    Test-Step '9 reset, running' '--reset-firewall succeeds' {
        $reset.ExitCode -eq 0 -and $reset.Output -match 'Lockdown removed'
    } -Note $reset.Output
    Test-Step '9 reset, running' 'no objects' { Test-LockdownAbsent } -Note (Format-Objects (Get-LockdownObjects))
    Test-Step '9 reset, running' 'the service runs again' { Wait-ServicePipe; $true }
    Test-Step '9 reset, running' 'status: lockdown off' { (Get-LockdownStatusLine) -eq 'off' }
    Test-Step '9 reset, running' 'direct egress works' { Test-RosetunDirectEgress }

    Invoke-Lockdown on | Out-Null
    Invoke-RosetunGuest -ScriptBlock { Stop-Service -Name 'Rosetun' -Force }
    Test-Step '9 reset, stopped' 'closed with the service stopped' { -not (Test-RosetunDirectEgress) }
    $reset = Invoke-RosetunCli -Quiet 'reset-firewall'
    Test-Step '9 reset, stopped' 'rosetun reset-firewall succeeds' { $reset.ExitCode -eq 0 } -Note $reset.Output
    Test-Step '9 reset, stopped' 'no objects' { Test-LockdownAbsent }
    Test-Step '9 reset, stopped' 'direct egress works' { Test-RosetunDirectEgress }
    Test-Step '9 reset, stopped' 'the service stays stopped' { (Get-ServiceState) -eq 'Stopped' }
    Invoke-RosetunGuest -ScriptBlock { Start-Service -Name 'Rosetun' }
    Test-Step '9 reset, stopped' 'the service starts and reports lockdown off' {
        Wait-ServicePipe
        (Get-LockdownStatusLine) -eq 'off'
    }

    # 10. Uninstall under Lockdown, as rosetun.iss runs it: --uninstall-service, then --reset-firewall.
    Invoke-Lockdown on | Out-Null
    Connect-RosetunTunnel | Out-Null
    $uninstall = Invoke-RosetunHelperMode '--uninstall-service'
    $serviceInstalled = $uninstall.ExitCode -ne 0
    $reset = Invoke-RosetunHelperMode '--reset-firewall'
    Test-Step '10 uninstall' 'both installer steps succeed' {
        $uninstall.ExitCode -eq 0 -and $reset.ExitCode -eq 0
    } -Note "$($uninstall.Output) | $($reset.Output)"
    Test-Step '10 uninstall' 'no objects' { Test-LockdownAbsent }
    Restore-RosetunGuestLease
    Test-Step '10 uninstall' 'direct egress works' { Test-RosetunDirectEgress }
    Test-Step '10 uninstall' 'IPv6 to the host works' { Test-RosetunIpv6Open -Neighbors $ipv6Neighbors }
    Register-RosetunHelper
    Start-RosetunHelper
}
catch {
    Test-Step 'run' 'completes without an error' { $false } -Note "$_"
}
finally {
    # 11. Whatever happened: no Lockdown, the console helper back as before.
    # The session may have died with the guest in a power cut.
    try { Wait-RosetunGuest } catch { Write-Warning "$_" }
    if ($guestResolver) {
        try { Restore-RosetunGuestResolver -Saved $guestResolver }
        catch { Write-Warning "Could not restore the guest's DNS servers: $_" }
    }
    if ($subscriptionId) {
        try { Invoke-RosetunCli -Quiet 'sub' 'remove' $subscriptionId | Out-Null }
        catch { Write-Warning "Could not remove the matrix subscription ${subscriptionId}: $_" }
    }
    if ($zone) {
        try { Stop-RosetunNameZone -Zone $zone } catch { Write-Warning "Could not stop the name zone: $_" }
    }
    if ($bootRecovery) {
        try { Restore-RosetunBootRecovery -Saved $bootRecovery }
        catch { Write-Warning "Could not restore the guest's boot recovery settings: $_" }
    }
    if ($egressWatchActive) {
        try { Stop-RosetunEgressWatch | Out-Null } catch { Write-Warning "Could not stop the egress watch: $_" }
    }
    try { Disconnect-RosetunTunnel | Out-Null } catch { }
    try { Stop-GuestListener } catch { Write-Warning "Could not stop the guest listener: $_" }
    if ($hostLan) {
        try { Stop-RosetunLanListener $hostLan } catch { Write-Warning "$_" }
    }
    try { Invoke-RosetunCli -Quiet 'lan' 'off' | Out-Null } catch { }
    try { Stop-RosetunHelper } catch { Write-Warning "Could not stop the helper: $_" }
    if ($serviceInstalled) {
        try { Remove-TestService } catch { Write-Warning "$_" }
    }
    $lockdownRemoved = $false
    try {
        $reset = Invoke-RosetunHelperMode '--reset-firewall'
        if ($reset.ExitCode -ne 0 -or -not (Test-LockdownAbsent)) { throw $reset.Output }
        $lockdownRemoved = $true
    }
    catch {
        Write-Warning "Could not remove Lockdown; the guest may have no network. Run '$guestDir\rosetun-helper-privileged.exe --reset-firewall' in the guest as administrator: $_"
    }
    Test-Step 'cleanup' '--reset-firewall leaves no Lockdown' { $lockdownRemoved }
    if ($bootTaskRegistered) {
        try { Unregister-RosetunBootCheck -TaskName $bootTask } catch { Write-Warning "$_" }
    }
    try { Remove-StandardAccount } catch { Write-Warning "Could not remove the account ${standardUser}: $_" }
    try {
        Invoke-RosetunGuest -ScriptBlock {
            param($dir)
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        } -ArgumentList $matrixDir
    }
    catch { Write-Warning "Could not remove ${matrixDir}: $_" }
    try {
        Register-RosetunHelper
        Start-RosetunHelper
    }
    catch { Write-Warning "Could not start the helper again: $_" }
    if ($ipv6Neighbors.Count -gt 0) {
        try { Remove-RosetunIpv6Neighbor -Created $ipv6Neighbors } catch { Write-Warning "$_" }
    }
    if ($nodeStarted) {
        try { Stop-RosetunTestNode } catch { Write-Warning "Could not stop the host test node: $_" }
    }
}

Add-Info 'run' 'second cold starts when the guest did not come back' "$(Get-RosetunColdStartRetries)"

# Result first, so a long note cannot push it off the screen.
$results | Format-Table Result, Scenario, Check, Note -AutoSize -Wrap

if ($results.Result -contains 'FAIL') {
    exit 1
}
exit 0
