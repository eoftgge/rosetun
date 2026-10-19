# Probes WFP sublayer arbitration for Lockdown in the Hyper-V test VM with the
# lockdown_probe example and prints a PASS/FAIL table. Exits with 1 if any
# check fails. The owner runs it, with Rosetun disconnected in the guest.
# Unless -SkipIpv6, it starts the host test node for the IPv6 checks and pins
# the IPv6 neighbors on both sides like the failure matrix.
#
# The probe's persistent objects survive the script; `finally` removes them
# whatever happens. If the run is killed before that, see tools/vm/README.md.

param(
    [string]$ProbePath = (Join-Path $PSScriptRoot '..\..\target\release\examples\lockdown_probe.exe'),
    # Builds the example first, so a forgotten build cannot deploy a stale probe.
    [switch]$Build,
    # Step 7 reboots the guest three times, more with -PowerCut; skip it for a
    # quick pass.
    [switch]$SkipReboot,
    # Adds reboots by turning the VM off, as after a power cut, with the
    # boot-time filters installed: one per delay below, plus one with a flush.
    [switch]$PowerCut,
    # Waits between installing and cutting the power, to find the shortest one
    # the objects survive. A cut a few seconds after the install lost every
    # probe object on the VM (2026-10-20).
    [int[]]$PowerCutDelaySeconds = @(5, 15, 30, 60),
    # Wait after `install --flush` before the cut of the flush pass.
    [int]$PowerCutFlushDelaySeconds = 2,
    # Wait after registering the boot check and before the install, so the
    # task itself reaches the disk and only the probe's objects are at stake.
    [int]$PowerCutSettleSeconds = 60,
    # The Lockdown sublayer weight passed to `persistent install`.
    [string]$LockdownWeight = '0xC000',
    # The host test node whose IPv6 port the IPv6 checks connect to.
    [string]$SingBoxPath = (Join-Path $PSScriptRoot '..\sing-box.exe'),
    [switch]$SkipIpv6,
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
    $pattern = 'summary: provider=(\w+) sublayer=(\w+) persistent_filters=(\d+)/(\d+) boottime_filters=(\d+)/(\d+) same_weight_sublayers=(\d+)'
    if ($status.ExitCode -ne 0 -or $status.Output -notmatch $pattern) {
        throw "persistent status failed: $($status.Output)"
    }
    $summary = $Matches
    # BFE may store another weight than the one requested (0x4001 for 0x4000 seen).
    $weight = if ($status.Output -match 'sublayer present flags=\S+ weight=(0x[0-9a-f]+)') { $Matches[1] } else { $null }
    [pscustomobject]@{
        Provider        = $summary[1] -eq 'present'
        Sublayer        = $summary[2] -eq 'present'
        Weight          = $weight
        Persistent      = [int]$summary[3]
        PersistentTotal = [int]$summary[4]
        Boottime        = [int]$summary[5]
        BoottimeTotal   = [int]$summary[6]
        SameWeight      = [int]$summary[7]
        Output          = $status.Output
    }
}

function Test-ProbeInstalled {
    param([switch]$Boottime)
    $status = Get-ProbeStatus
    $status.Provider -and $status.Sublayer -and $status.Persistent -eq $status.PersistentTotal -and
        $status.Boottime -eq $(if ($Boottime) { $status.BoottimeTotal } else { 0 })
}

function Test-ProbeEmpty {
    $status = Get-ProbeStatus
    -not $status.Provider -and -not $status.Sublayer -and $status.Persistent -eq 0 -and $status.Boottime -eq 0
}

function Install-Probe {
    param([switch]$Boottime, [switch]$Flush, [string]$Weight = $LockdownWeight)
    $arguments = @('persistent', 'install', '--sublayer-weight', $Weight)
    if ($Boottime) { $arguments += '--boottime' }
    if ($Flush) { $arguments += '--flush' }
    $install = Invoke-Probe -Arguments $arguments
    if ($install.ExitCode -ne 0) {
        throw "persistent install failed: $($install.Output)"
    }
    $install.Output
}

function Format-Weight {
    param([Parameter(Mandatory)][int]$Weight)
    '0x{0:x4}' -f $Weight
}

function Remove-Probe {
    $remove = Invoke-Probe -Arguments @('persistent', 'remove')
    if ($remove.ExitCode -ne 0) {
        throw "persistent remove failed: $($remove.Output)"
    }
    $remove.Output
}

function Start-Permit {
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Arguments)
    $permit = Invoke-RosetunGuest -ScriptBlock {
        param($exe, $dir, $arguments)
        $name = "permit-$([guid]::NewGuid().ToString('N'))"
        # One stdin file per permit: a killed permit's handle can outlive it briefly.
        $stdin = Join-Path $dir "$name.in.txt"
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
        $stopError = ''
        try { Stop-Process -Id $id -Force -ErrorAction Stop }
        catch { $stopError = "$_" }
        # The Process object from Start-Process keeps a handle, so the exited
        # permit stays listed as a zombie until it is collected: test HasExited,
        # not presence.
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        $deadline = (Get-Date).AddSeconds(15)
        do {
            $alive = Get-Process -Id $id -ErrorAction SilentlyContinue | Where-Object { -not $_.HasExited }
            if (-not $alive) { return }
            Start-Sleep -Milliseconds 300
        } while ((Get-Date) -lt $deadline)
        throw "permit process $id is still running after 15 s; Stop-Process: '$stopError'"
    } -ArgumentList $Id
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

function Invoke-RebootPass {
    param(
        [Parameter(Mandatory)][string]$Scenario,
        [ValidateSet('none', 'persistent', 'boottime')][string]$Lockdown
    )
    Remove-Probe | Out-Null
    Restore-RosetunGuestLease
    if ($Lockdown -ne 'none') {
        Install-Probe -Boottime:($Lockdown -eq 'boottime') | Out-Null
    }
    Register-RosetunBootCheck -Directory $probeDir -TaskName $bootTask -Url $ProbeUrl
    Restart-RosetunGuest
    $attempts = Get-RosetunBootCheck -Directory $probeDir -BootTime (Get-RosetunGuestBootTime)
    $note = Format-RosetunBootCheck -Attempts $attempts
    $routed = @($attempts | Where-Object { $_.Route })
    $beforeSignIn = @($attempts | Where-Object { $_.User }).Count -eq 0

    if ($Lockdown -eq 'none') {
        # The control: without it a "blocked" result could mean "no network yet".
        Test-Step $Scenario 'boot check reaches the internet without Lockdown' {
            @($routed | Where-Object { $_.CurlExit -eq 0 }).Count -gt 0
        } -Note $note
        return
    }
    Test-Step $Scenario 'boot check ran before sign-in' { $attempts.Count -gt 0 -and $beforeSignIn } -Note $note
    # With the DHCPv4 permit in both sets the lease must survive the boot;
    # without it the boot-time pass lost it (VM run 3). A routed attempt also
    # makes the curl check below mean something.
    Test-Step $Scenario 'a DHCP address and a default route before sign-in' {
        @($routed | Where-Object { $_.Addresses -match '/Dhcp/Preferred' }).Count -gt 0
    } -Note "$($routed.Count) of $($attempts.Count) attempts routed"
    Test-Step $Scenario 'no boot attempt reached the internet' {
        @($routed | Where-Object { $_.CurlExit -eq 0 }).Count -eq 0
    } -Note $note
    Test-Step $Scenario 'status shows the objects after boot' {
        Test-ProbeInstalled -Boottime:($Lockdown -eq 'boottime')
    } -Note (Get-ProbeStatus).Output
    $lease = Get-RosetunGuestLease
    Test-Step $Scenario 'DHCP lease and default route after boot' { $lease.Leased } -Note $lease.Note
    $after = Get-RosetunEgressAfterBoot
    Test-Step $Scenario 'egress closed after boot' { $after -ne 'open' } -Note $after
    if (-not $SkipIpv6 -and $lease.Leased) {
        Test-Step $Scenario 'IPv6 to the host closed after boot' { -not (Test-RosetunIpv6Open -Neighbors $ipv6Neighbors) }
    }
}

function Invoke-PowerCutPass {
    # Measures whether the objects reach the disk within $Delay seconds of the
    # install. Losing them is a finding about the delay, not a failure of the
    # probe, so the outcome is returned and recorded as INFO.
    param([Parameter(Mandatory)][int]$Delay, [switch]$Flush)
    $scenario = "power cut $Delay s after install$(if ($Flush) { ' --flush' })"
    # Everything but $survived goes to Out-Null: the caller tests the output.
    Remove-Probe | Out-Null
    Restore-RosetunGuestLease | Out-Null
    Register-RosetunBootCheck -Directory $probeDir -TaskName $bootTask -Url $ProbeUrl | Out-Null
    Start-Sleep -Seconds $PowerCutSettleSeconds
    $install = Install-Probe -Boottime -Flush:$Flush
    if ($Flush) { Add-Info $scenario 'install --flush output' ($install -replace '\s*\n\s*', '; ') }
    Start-Sleep -Seconds $Delay
    Restart-RosetunGuest -PowerCut | Out-Null
    $bootTime = Get-RosetunGuestBootTime
    $survived = Test-ProbeInstalled -Boottime
    $status = Get-ProbeStatus
    $bootNote = try { Format-RosetunBootCheck -Attempts (Get-RosetunBootCheck -Directory $probeDir -BootTime $bootTime) }
    catch { "boot check lost: $_" }
    $after = Get-RosetunEgressAfterBoot
    Add-Info $scenario 'objects survived the cut' "survived: $survived; egress after boot: $after; $bootNote"
    if ($survived) {
        Test-Step $scenario 'egress closed after boot' { $after -ne 'open' } -Note $after
    }
    elseif ($status.Provider -or $status.Sublayer -or $status.Persistent -or $status.Boottime) {
        # Part of one transaction on disk would mean BFE's storage is not atomic.
        Add-Info $scenario 'partial objects after the cut' ($status.Output -replace '\s*\n\s*', '; ')
    }
    $survived
}

if ($Build) {
    & cargo build -q --release -p rosetun-routing --example lockdown_probe
    if ($LASTEXITCODE -ne 0) { throw 'Building lockdown_probe failed.' }
}
$ProbePath = (Resolve-Path -LiteralPath $ProbePath).Path

$lockdownValue = [int]$LockdownWeight
# Relative to the Lockdown weight, so the arbitration cases stay the same
# question at any weight; at 0xC000 "below" is the product's 0x8000.
$aboveWeight = Format-Weight ([Math]::Min($lockdownValue + 0x2000, 0xFFFE))
$belowWeight = Format-Weight ([Math]::Max($lockdownValue - 0x4000, 0x1000))

$bootTaskRegistered = $false
$ipv6Neighbors = [System.Collections.Generic.List[object]]::new()
$nodeStarted = $false
try {
    if (-not $SkipIpv6) {
        $nodeStarted = Start-RosetunTestNode -SingBoxPath ([IO.Path]::GetFullPath($SingBoxPath))
    }
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
    Test-Step 'baseline' 'no Rosetun WFP session in the guest' { -not (Test-RosetunGuestWfpKey $rosetunProviderKey) }
    Test-Step 'baseline' 'probe objects absent' { Test-ProbeEmpty }
    Test-Step 'baseline' 'curl reaches the internet directly' { Test-RosetunDirectEgress }
    Test-Step 'baseline' 'another program reaches the internet directly' { Test-OtherProgramEgress }
    Test-Step 'baseline' 'loopback works' { Test-RosetunGuestLoopback }
    if (-not $SkipIpv6) {
        # Without a working baseline every "IPv6 closed" below proves nothing.
        Test-Step 'baseline' 'IPv6 to the host works' { Test-RosetunIpv6Open -Neighbors $ipv6Neighbors }
    }

    # Why run 1 stored 0x4000 as 0x4001: who else sits there.
    $sublayers = Invoke-Probe -Arguments @('persistent', 'sublayers')
    Add-Info 'sublayers' 'all sublayers before install' ($sublayers.Output -replace '\s*\n\s*', '; ')
    Install-Probe -Weight '0x4000' | Out-Null
    $status = Get-ProbeStatus
    Add-Info 'weight 0x4000' 'stored weight and other sublayers on it' "stored $($status.Weight), same weight: $($status.SameWeight); $((($status.Output -split "`n") -match '^same weight') -join '; ')"
    Remove-Probe | Out-Null

    # 2. Persistent block-all with the loopback and DHCPv4 permits.
    Install-Probe | Out-Null
    $status = Get-ProbeStatus
    Test-Step 'install' 'status: provider, sublayer, all persistent filters' { Test-ProbeInstalled } -Note $status.Output
    Add-Info 'install' "Lockdown sublayer weight stored by BFE (requested $LockdownWeight)" "stored $($status.Weight), other sublayers on it: $($status.SameWeight)"
    $flush = Invoke-Probe -Arguments @('persistent', 'flush')
    Add-Info 'install' 'BFE policy in the registry (persistent flush)' "exit $($flush.ExitCode); $($flush.Output -replace '\s*\n\s*', '; ')"
    Test-Step 'install' 'curl egress closed' { -not (Test-RosetunDirectEgress) }
    Test-Step 'install' 'loopback stays open' { Test-RosetunGuestLoopback }
    if (-not $SkipIpv6) {
        Test-Step 'install' 'IPv6 to the host closed' { -not (Test-RosetunIpv6Open -Neighbors $ipv6Neighbors) }
    }
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
        @{ Name = "soft, sublayer $aboveWeight (above)"; Args = @('--sublayer-weight', $aboveWeight); Open = $false },
        @{ Name = "hard, sublayer $aboveWeight (above)"; Args = @('--sublayer-weight', $aboveWeight, '--hard'); Open = $true },
        @{ Name = "soft, sublayer $belowWeight (below)"; Args = @('--sublayer-weight', $belowWeight); Open = $false },
        @{ Name = "hard, sublayer $belowWeight (below)"; Args = @('--sublayer-weight', $belowWeight, '--hard'); Open = $false },
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
    # The weight BFE stored, not the requested one: they differed on the VM.
    $lockdownWeight = (Get-ProbeStatus).Weight
    foreach ($hard in @($false, $true)) {
        $arguments = @('--sublayer-weight', $lockdownWeight)
        if ($hard) { $arguments += '--hard' }
        $permit = $null
        $scenario = "permit $(if ($hard) { 'hard' } else { 'soft' }), sublayer $lockdownWeight (equal)"
        try {
            $permit = Start-Permit -Arguments $arguments
            Add-Info $scenario 'curl egress' "open: $(Test-RosetunDirectEgress); $($permit.Output -replace '\s+', ' ')"
        }
        catch { Add-Info $scenario 'permit starts' "$_" }
        finally {
            if ($permit) { Stop-Permit -Id $permit.Id }
        }
    }

    # 6. The permit process is killed while Lockdown stays.
    $permit = Start-Permit -Arguments @('--sublayer-weight', $aboveWeight, '--hard')
    Test-Step 'permit killed' 'hard permit opened curl first' { Test-RosetunDirectEgress }
    Stop-Permit -Id $permit.Id
    Test-Step 'permit killed' 'dynamic permit objects gone' { -not (Test-RosetunGuestWfpKey $permitProviderKey) }
    Test-Step 'permit killed' 'curl egress closed again' { -not (Test-RosetunDirectEgress) }
    Test-Step 'permit killed' 'persistent objects still in place' { Test-ProbeInstalled }

    # 7. Reboots. The control pass first proves the boot check can see an open network.
    if (-not $SkipReboot) {
        $bootTaskRegistered = $true
        Invoke-RebootPass -Scenario 'reboot, no Lockdown' -Lockdown none
        Invoke-RebootPass -Scenario 'reboot, persistent' -Lockdown persistent
        Invoke-RebootPass -Scenario 'reboot, persistent + boot-time' -Lockdown boottime
        if ($PowerCut) {
            $longest = ($PowerCutDelaySeconds | Measure-Object -Maximum).Maximum
            foreach ($delay in ($PowerCutDelaySeconds | Sort-Object)) {
                $survived = Invoke-PowerCutPass -Delay $delay
                if ($delay -eq $longest) {
                    Test-Step "power cut $delay s after install" 'objects survive the longest delay' { $survived }
                }
            }
            # The flush pass reports separately: it answers whether a flush
            # makes the install durable at once.
            Invoke-PowerCutPass -Delay $PowerCutFlushDelaySeconds -Flush | Out-Null
        }
    }

    # Last while locked: a failed renewal could cost the lease the checks above
    # need. A known state first, since the reboot passes may leave another.
    Remove-Probe | Out-Null
    Restore-RosetunGuestLease
    Install-Probe | Out-Null
    $dhcp = Test-RosetunDhcpRenew
    # The DHCPv4 permit makes this a check; before it, run 3 only recorded it.
    Test-Step 'locked, persistent only' 'ipconfig /renew keeps the DHCP lease' { $dhcp.Renewed } -Note $dhcp.Note

    # 8. Remove.
    Remove-Probe | Out-Null
    Test-Step 'remove' 'status empty' { Test-ProbeEmpty } -Note (Get-ProbeStatus).Output
    Restore-RosetunGuestLease
    Test-Step 'remove' 'curl egress open again' { Test-RosetunDirectEgress }
    if (-not $SkipIpv6) {
        Test-Step 'remove' 'IPv6 to the host works again' { Test-RosetunIpv6Open -Neighbors $ipv6Neighbors }
    }
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
        try { Unregister-RosetunBootCheck -TaskName $bootTask }
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
    if ($ipv6Neighbors.Count -gt 0) {
        try { Remove-RosetunIpv6Neighbor -Created $ipv6Neighbors }
        catch { Write-Warning "$_" }
    }
    if ($nodeStarted) {
        try { Stop-RosetunTestNode }
        catch { Write-Warning "Could not stop the host test node: $_" }
    }
}

# Result first, so a long note cannot push it off the screen.
$results | Format-Table Result, Scenario, Check, Note -AutoSize -Wrap

if ($results.Result -contains 'FAIL') {
    exit 1
}
exit 0
