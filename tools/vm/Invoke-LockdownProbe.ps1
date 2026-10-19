# Probes WFP sublayer arbitration for Lockdown in the Hyper-V test VM with the
# lockdown_probe example and prints a PASS/FAIL table. Exits with 1 if any
# check fails. The owner runs it, with Rosetun disconnected in the guest.
#
# The probe's persistent objects survive the script; `finally` removes them
# whatever happens. If the run is killed before that, see tools/vm/README.md.

param(
    [string]$ProbePath = (Join-Path $PSScriptRoot '..\..\target\release\examples\lockdown_probe.exe'),
    # Builds the example first, so a forgotten build cannot deploy a stale probe.
    [switch]$Build,
    # Step 7 reboots the guest three or four times; skip it for a quick pass.
    [switch]$SkipReboot,
    # Adds a reboot by turning the VM off, as after a power cut, with the
    # boot-time filters installed.
    [switch]$PowerCut,
    # Must match ProbeUrl in RosetunVm.psm1: reachable from the guest directly.
    [string]$ProbeUrl = 'https://1.1.1.1'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RosetunVm.psm1') -Force

$results = [System.Collections.Generic.List[object]]::new()
$probeDir = Join-Path (Get-RosetunGuestDir) 'lockdown-probe'
$probeExe = Join-Path $probeDir 'lockdown_probe.exe'
$bootTask = 'RosetunLockdownBootCheck'
# Keys from crates/rosetun-routing/examples/lockdown_probe.rs.
$permitProviderKey = '1ddf6dff-5a79-4f1a-a453-a39aba5c23fe'
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

# A finding to record, not a pass or fail: the study needs the answer either way.
function Add-Info {
    param([Parameter(Mandatory)][string]$Scenario, [Parameter(Mandatory)][string]$Check, [string]$Note = '')
    $results.Add([pscustomobject]@{ Result = 'INFO'; Scenario = $Scenario; Check = $Check; Note = $Note })
}

function Invoke-Probe {
    param([Parameter(Mandatory)][string[]]$Arguments)
    Invoke-RosetunGuest -ScriptBlock {
        param($exe, $arguments)
        $output = & $exe @arguments 2>&1 | ForEach-Object { "$_" }
        $exitCode = $LASTEXITCODE
        $global:LASTEXITCODE = 0
        [pscustomobject]@{ ExitCode = $exitCode; Output = ($output -join "`n") }
    } -ArgumentList $probeExe, $Arguments
}

function Get-ProbeStatus {
    $status = Invoke-Probe -Arguments @('persistent', 'status')
    if ($status.ExitCode -ne 0 -or $status.Output -notmatch 'summary: provider=(\w+) sublayer=(\w+) persistent_filters=(\d)/2 boottime_filters=(\d)/2') {
        throw "persistent status failed: $($status.Output)"
    }
    [pscustomobject]@{
        Provider   = $Matches[1] -eq 'present'
        Sublayer   = $Matches[2] -eq 'present'
        Persistent = [int]$Matches[3]
        Boottime   = [int]$Matches[4]
        Output     = $status.Output
    }
}

function Test-ProbeInstalled {
    param([switch]$Boottime)
    $status = Get-ProbeStatus
    $status.Provider -and $status.Sublayer -and $status.Persistent -eq 2 -and
        $status.Boottime -eq $(if ($Boottime) { 2 } else { 0 })
}

function Test-ProbeEmpty {
    $status = Get-ProbeStatus
    -not $status.Provider -and -not $status.Sublayer -and $status.Persistent -eq 0 -and $status.Boottime -eq 0
}

function Install-Probe {
    param([switch]$Boottime)
    $arguments = @('persistent', 'install')
    if ($Boottime) { $arguments += '--boottime' }
    $install = Invoke-Probe -Arguments $arguments
    if ($install.ExitCode -ne 0) {
        throw "persistent install failed: $($install.Output)"
    }
}

function Remove-Probe {
    $remove = Invoke-Probe -Arguments @('persistent', 'remove')
    if ($remove.ExitCode -ne 0) {
        throw "persistent remove failed: $($remove.Output)"
    }
    $remove.Output
}

function Start-Permit {
    # The soft permit at the default weight passes no options at all.
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Arguments)
    $permit = Invoke-RosetunGuest -ScriptBlock {
        param($exe, $dir, $arguments)
        $name = "permit-$([guid]::NewGuid().ToString('N'))"
        $stdin = Join-Path $dir 'empty-stdin.txt'
        $stdout = Join-Path $dir "$name.out.txt"
        $stderr = Join-Path $dir "$name.err.txt"
        [IO.File]::WriteAllText($stdin, '')
        $curl = (Get-Command -Name curl.exe -ErrorAction Stop).Source
        # Remoting may deliver an empty array as $null, which would add an empty argument.
        $all = @('permit', '--program', "`"$curl`"") + @($arguments | Where-Object { $_ })
        # Stdin at EOF: the probe then holds the permit until it is killed.
        $process = Start-Process -FilePath $exe -ArgumentList $all -PassThru -WindowStyle Hidden `
            -RedirectStandardInput $stdin -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        $deadline = (Get-Date).AddSeconds(15)
        while ((Get-Date) -lt $deadline) {
            if ((Test-Path -LiteralPath $stdout) -and ((Get-Content -Raw -LiteralPath $stdout) -match '(?m)^ready')) {
                return [pscustomobject]@{ Id = $process.Id; Output = (Get-Content -Raw -LiteralPath $stdout).Trim() }
            }
            if ($process.HasExited) { break }
            Start-Sleep -Milliseconds 200
        }
        $errorText = if (Test-Path -LiteralPath $stderr) { (Get-Content -Raw -LiteralPath $stderr) } else { '' }
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        throw "permit did not become ready: $errorText"
    } -ArgumentList $probeExe, $probeDir, $Arguments
    $permit
}

function Stop-Permit {
    param([Parameter(Mandatory)][int]$Id)
    Invoke-RosetunGuest -ScriptBlock {
        param($id)
        # A kill, not Enter: the dynamic session must clean up after a crash too.
        Stop-Process -Id $id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $id -Timeout 10 -ErrorAction SilentlyContinue
    } -ArgumentList $Id
}

function Test-GuestWfpKey {
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
        }
    } -ArgumentList $Key
}

function Test-OtherProgramEgress {
    # A renamed copy of curl has another app ID, so it shows whether a permit
    # for curl.exe leaked to the rest of the guest.
    $address = Get-RosetunEgressAddress
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $address, $url)
        & (Join-Path $dir 'curl-other.exe') --interface $address --max-time 5 --silent --output NUL $url 2>$null
        $LASTEXITCODE -eq 0
    } -ArgumentList $probeDir, $address, $ProbeUrl
}

function Get-GuestBootTime {
    Invoke-RosetunGuest -ScriptBlock { (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime }
}

function Restart-Guest {
    param([switch]$PowerCut)
    $before = Get-GuestBootTime
    if ($PowerCut) {
        Disconnect-RosetunVm
        Stop-VM -Name (Get-RosetunVmName) -TurnOff -Force
        Start-VM -Name (Get-RosetunVmName)
    }
    else {
        try { Invoke-RosetunGuest -ScriptBlock { Restart-Computer -Force } }
        catch { }
        Disconnect-RosetunVm
    }
    # Connecting too early would reach the guest before it went down.
    $deadline = (Get-Date).AddMinutes(5)
    while ($true) {
        try {
            if ((Get-GuestBootTime) -ne $before) { return }
        }
        catch {
            try { Disconnect-RosetunVm } catch { }
        }
        if ((Get-Date) -gt $deadline) {
            throw 'The guest did not come back within 5 minutes.'
        }
        Start-Sleep -Seconds 5
    }
}

function Register-BootCheck {
    # Runs as SYSTEM at startup, before anyone signs in: an AtLogOn task would
    # never fire, because PowerShell Direct is not an interactive sign-in.
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $task, $url)
        $script = @'
param($result, $url)
$attempts = [System.Collections.Generic.List[object]]::new()
$deadline = (Get-Date).AddSeconds(150)
$withRoute = 0
while ((Get-Date) -lt $deadline -and $withRoute -lt 3) {
    $uptime = [int]((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalSeconds
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1
    $address = if ($route) {
        Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.AddressState -eq 'Preferred' } | Select-Object -First 1
    }
    $curlExit = $null
    $curlError = ''
    if ($address) {
        $withRoute++
        $curlError = (& curl.exe --max-time 5 --silent --show-error --output NUL $url 2>&1 | Out-String).Trim()
        $curlExit = $LASTEXITCODE
    }
    $attempts.Add([pscustomobject]@{
        Uptime    = $uptime
        Route     = [bool]$address
        CurlExit  = $curlExit
        CurlError = $curlError
        User      = "$((Get-CimInstance Win32_ComputerSystem).UserName)"
        Bfe       = "$((Get-Service -Name BFE).Status)"
    })
    if ($withRoute -lt 3) { Start-Sleep -Seconds 3 }
}
$attempts | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $result -Encoding UTF8
'@
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
    } -ArgumentList $probeDir, $bootTask, $ProbeUrl
}

function Get-BootCheck {
    $deadline = (Get-Date).AddMinutes(4)
    while ((Get-Date) -lt $deadline) {
        $json = Invoke-RosetunGuest -ScriptBlock {
            param($path)
            if (Test-Path -LiteralPath $path) { Get-Content -Raw -LiteralPath $path }
        } -ArgumentList (Join-Path $probeDir 'boot-check.json')
        if ($json) { return @($json | ConvertFrom-Json) }
        Start-Sleep -Seconds 5
    }
    throw 'The boot check wrote no result within 4 minutes.'
}

function Format-BootCheck {
    param([Parameter(Mandatory)][object[]]$Attempts)
    ($Attempts | ForEach-Object {
        "t=$($_.Uptime)s route=$($_.Route) curl=$($_.CurlExit) user='$($_.User)' bfe=$($_.Bfe) $($_.CurlError)"
    }) -join '; '
}

function Invoke-RebootPass {
    param(
        [Parameter(Mandatory)][string]$Scenario,
        [ValidateSet('none', 'persistent', 'boottime')][string]$Lockdown,
        [switch]$PowerCut
    )
    Remove-Probe | Out-Null
    if ($Lockdown -ne 'none') {
        Install-Probe -Boottime:($Lockdown -eq 'boottime')
    }
    Register-BootCheck
    Restart-Guest -PowerCut:$PowerCut
    $attempts = Get-BootCheck
    $note = Format-BootCheck -Attempts $attempts
    $routed = @($attempts | Where-Object { $_.Route })
    $beforeSignIn = @($attempts | Where-Object { $_.User }).Count -eq 0

    if ($Lockdown -eq 'none') {
        # The control: without it a "blocked" result could mean "no network yet".
        Test-Step $Scenario 'boot check reaches the internet without Lockdown' {
            @($routed | Where-Object { $_.CurlExit -eq 0 }).Count -gt 0
        } -Note $note
        return
    }
    Test-Step $Scenario 'boot check ran with a route, before sign-in' {
        $routed.Count -gt 0 -and $beforeSignIn
    } -Note $note
    Test-Step $Scenario 'egress closed at every routed boot attempt' {
        $routed.Count -gt 0 -and @($routed | Where-Object { $_.CurlExit -eq 0 }).Count -eq 0
    } -Note $note
    Test-Step $Scenario 'status shows the objects after boot' {
        Test-ProbeInstalled -Boottime:($Lockdown -eq 'boottime')
    } -Note (Get-ProbeStatus).Output
    Test-Step $Scenario 'egress closed after boot' { -not (Test-RosetunDirectEgress) }
}

if ($Build) {
    & cargo build -q --release -p rosetun-routing --example lockdown_probe
    if ($LASTEXITCODE -ne 0) { throw 'Building lockdown_probe failed.' }
}
$ProbePath = (Resolve-Path -LiteralPath $ProbePath).Path

$bootTaskRegistered = $false
try {
    $session = Connect-RosetunVm
    Invoke-RosetunGuest -ScriptBlock {
        param($dir)
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        Copy-Item -LiteralPath (Get-Command -Name curl.exe -ErrorAction Stop).Source `
            -Destination (Join-Path $dir 'curl-other.exe') -Force
    } -ArgumentList $probeDir
    Copy-Item -ToSession $session -Path $ProbePath -Destination $probeExe -Force

    # A leftover from an interrupted run would turn the baseline into a block.
    Remove-Probe | Out-Null

    # 1. Baseline.
    Test-Step 'baseline' 'no Rosetun WFP session in the guest' { -not (Test-GuestWfpKey $rosetunProviderKey) }
    Test-Step 'baseline' 'probe objects absent' { Test-ProbeEmpty }
    Test-Step 'baseline' 'curl reaches the internet directly' { Test-RosetunDirectEgress }
    Test-Step 'baseline' 'another program reaches the internet directly' { Test-OtherProgramEgress }

    # 2. Persistent block-all.
    Install-Probe
    Test-Step 'install' 'status: provider, sublayer, 2 persistent filters' { Test-ProbeInstalled } -Note (Get-ProbeStatus).Output
    Test-Step 'install' 'curl egress closed' { -not (Test-RosetunDirectEgress) }
    Test-Step 'install' 'direct DNS over UDP closed' { -not (Test-RosetunDirectDns) }
    Test-Step 'install' 'direct DNS over TCP closed' { -not (Test-RosetunDirectDns -Tcp) }
    $resolver = Invoke-RosetunGuest -ScriptBlock {
        Clear-DnsClientCache
        try {
            Resolve-DnsName -Name 'example.org' -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null
            'resolved'
        }
        catch { "failed: $($_.Exception.Message)" }
    }
    Add-Info 'install' 'system resolver (Dnscache) after a cache flush' $resolver

    # 3-5. A permit for curl.exe from a dynamic session, against the persistent block.
    $cases = @(
        @{ Name = 'soft, sublayer 0x8000 (above)'; Args = @(); Open = $false },
        @{ Name = 'hard, sublayer 0x8000 (above)'; Args = @('--hard'); Open = $true },
        @{ Name = 'soft, sublayer 0x2000 (below)'; Args = @('--sublayer-weight', '0x2000'); Open = $false },
        @{ Name = 'hard, sublayer 0x2000 (below)'; Args = @('--sublayer-weight', '0x2000', '--hard'); Open = $false },
        @{ Name = 'soft, in the Lockdown sublayer'; Args = @('--lockdown-sublayer'); Open = $true },
        @{ Name = 'hard, in the Lockdown sublayer'; Args = @('--lockdown-sublayer', '--hard'); Open = $true }
    )
    foreach ($case in $cases) {
        $scenario = "permit $($case.Name)"
        $permit = $null
        try {
            $permit = Start-Permit -Arguments $case.Args
            $expected = if ($case.Open) { 'open' } else { 'closed' }
            $actual = Test-RosetunDirectEgress
            Test-Step $scenario "curl egress $expected" { $actual -eq $case.Open } -Note "egress open: $actual"
            Test-Step $scenario 'another program stays closed' { -not (Test-OtherProgramEgress) }
            if ($case.Args -contains '--lockdown-sublayer' -and -not ($case.Args -contains '--hard')) {
                $remove = Invoke-Probe -Arguments @('persistent', 'remove')
                Test-Step $scenario 'remove refused while the permit uses the sublayer' {
                    $remove.ExitCode -ne 0 -and $remove.Output -match 'FWP_E_IN_USE'
                } -Note $remove.Output
                Test-Step $scenario 'refused remove changed nothing' { Test-ProbeInstalled }
            }
        }
        catch {
            Test-Step $scenario 'permit starts' { $false } -Note "$_"
        }
        finally {
            if ($permit) { Stop-Permit -Id $permit.Id }
        }
    }
    # Equal sublayer weights have no documented order, so this is a finding only.
    foreach ($hard in @($false, $true)) {
        $arguments = @('--sublayer-weight', '0x4000')
        if ($hard) { $arguments += '--hard' }
        $permit = $null
        $scenario = "permit $(if ($hard) { 'hard' } else { 'soft' }), sublayer 0x4000 (equal)"
        try {
            $permit = Start-Permit -Arguments $arguments
            Add-Info $scenario 'curl egress' "open: $(Test-RosetunDirectEgress)"
        }
        catch { Add-Info $scenario 'permit starts' "$_" }
        finally {
            if ($permit) { Stop-Permit -Id $permit.Id }
        }
    }

    # 6. The permit process is killed while Lockdown stays.
    $permit = Start-Permit -Arguments @('--hard')
    Test-Step 'permit killed' 'hard permit opened curl first' { Test-RosetunDirectEgress }
    Stop-Permit -Id $permit.Id
    Test-Step 'permit killed' 'dynamic permit objects gone' { -not (Test-GuestWfpKey $permitProviderKey) }
    Test-Step 'permit killed' 'curl egress closed again' { -not (Test-RosetunDirectEgress) }
    Test-Step 'permit killed' 'persistent objects still in place' { Test-ProbeInstalled }

    # 7. Reboots. The control pass first proves the boot check can see an open network.
    if (-not $SkipReboot) {
        $bootTaskRegistered = $true
        Invoke-RebootPass -Scenario 'reboot, no Lockdown' -Lockdown none
        Invoke-RebootPass -Scenario 'reboot, persistent' -Lockdown persistent
        Invoke-RebootPass -Scenario 'reboot, persistent + boot-time' -Lockdown boottime
        if ($PowerCut) {
            Invoke-RebootPass -Scenario 'power cut, persistent + boot-time' -Lockdown boottime -PowerCut
        }
    }

    # Last while locked: a failed renewal could cost the lease the checks above need.
    $dhcp = Invoke-RosetunGuest -ScriptBlock {
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object -Property RouteMetric | Select-Object -First 1
        $alias = $route.InterfaceAlias
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $output = (& ipconfig.exe /renew $alias 2>&1 | Out-String).Trim() -replace '\s+', ' '
        $exitCode = $LASTEXITCODE
        $global:LASTEXITCODE = 0
        $lease = Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.PrefixOrigin -eq 'Dhcp' } | Select-Object -First 1
        "renew exit $exitCode after $([int]$watch.Elapsed.TotalSeconds) s, DHCP address kept: $([bool]$lease); $output"
    }
    Add-Info 'locked' 'DHCP lease renewal (ipconfig /renew)' $dhcp

    # 8. Remove.
    Remove-Probe | Out-Null
    Test-Step 'remove' 'status empty' { Test-ProbeEmpty } -Note (Get-ProbeStatus).Output
    Test-Step 'remove' 'curl egress open again' { Test-RosetunDirectEgress }
    Test-Step 'remove' 'second remove succeeds and removes nothing' { (Remove-Probe) -match 'removed: nothing' }
}
catch {
    Test-Step 'run' 'completes without an error' { $false } -Note "$_"
}
finally {
    # 9. Cleanup, whatever happened above.
    try {
        Invoke-RosetunGuest -ScriptBlock {
            Get-Process -Name lockdown_probe -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        }
    }
    catch { Write-Warning "Could not stop a running permit: $_" }
    $probeRemoved = $false
    try {
        Remove-Probe | Out-Null
        if (-not (Test-ProbeEmpty)) { throw (Get-ProbeStatus).Output }
        $probeRemoved = $true
    }
    catch {
        Write-Warning "Could not remove the Lockdown probe objects; the guest may have no network. Run '$probeExe persistent remove' in the guest as administrator: $_"
    }
    if ($bootTaskRegistered) {
        try {
            Invoke-RosetunGuest -ScriptBlock {
                param($task)
                Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
            } -ArgumentList $bootTask
        }
        catch { Write-Warning "Could not remove the scheduled task ${bootTask}: $_" }
    }
    # The probe stays in the guest when its objects could not be removed, so
    # the manual remove in the warning above still has a binary to run.
    if ($probeRemoved) {
        try {
            Invoke-RosetunGuest -ScriptBlock {
                param($dir)
                Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction Stop
            } -ArgumentList $probeDir
        }
        catch { Write-Warning "Could not remove ${probeDir}: $_" }
    }
}

# Result first, so a long note cannot push it off the screen.
$results | Format-Table Result, Scenario, Check, Note -AutoSize -Wrap

if ($results.Result -contains 'FAIL') {
    exit 1
}
exit 0
