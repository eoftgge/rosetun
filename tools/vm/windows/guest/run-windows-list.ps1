# The List rule-set matrix as an autonomous runner of the QEMU lab (stage 10a). Windows PowerShell 5.1, as SYSTEM.
#
# The same eleven checks as Invoke-ListMatrix.ps1, with the same ids, against the lab's targets: the controller names
# them in plan.json, copies nothing but starts this script and reads status.json while it runs. The guest has no network
# but the lab's wire, so the Rosetun binaries and the pinned sing-box came on a read-only medium, and the script checks
# their hashes before it uses them. It marks the two windows the observer judges (`baseline`, before the session, and
# `session`, from just before the connect to just after the protection is gone) and cleans up whatever happens.

param(
    # Where the controller put the runner, its plan and its status, and the letter of the drive of the read-only medium
    # (a path with a trailing backslash would end its quote on a command line).
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]$')][string]$Medium
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib.ps1')

$plan = Get-Content -LiteralPath (Join-Path $Root 'plan.json') -Raw -Encoding UTF8 | ConvertFrom-Json
Initialize-RosetunRunner -StatusPath (Join-Path $Root 'status.json') -RunId $plan.run

$mediumRoot = $Medium + ':\'
$bin = Join-Path $Root 'bin'
$logs = Join-Path $Root 'logs'
$work = Join-Path $Root 'list-matrix'
$configPath = Join-Path $work 'config.json'
$cliPath = Join-Path $bin 'rosetun.exe'
$helperPath = Join-Path $bin 'rosetun-helper-privileged.exe'
$singBoxPath = Join-Path $bin 'sing-box.exe'
$curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'
$taskName = 'RosetunHelper'
$listed = [string]$plan.names.listed
$unlisted = [string]$plan.names.unlisted
$physical = [string]$plan.addresses.client4
$targetUrl = 'https://' + [string]$plan.addresses.target4 + '/'

function Invoke-ListCli {
    param([Parameter(Mandatory)][string[]]$Arguments, [int]$Seconds = 90)
    Invoke-RosetunNative -FilePath $cliPath -Arguments $Arguments -TimeoutSeconds $Seconds -Environment @{ ROSETUN_CONFIG = $configPath }
}

function Get-ListState {
    $result = Invoke-ListCli -Arguments @('status') -Seconds 20
    if ($result.Output -match '(?m)^state: (\w+)') { return $Matches[1] }
    return "unknown (exit $($result.ExitCode))"
}

function Get-ListProtection {
    $result = Invoke-ListCli -Arguments @('status') -Seconds 20
    if ($result.Output -match '(?m)^protection: (.+?)\s*$') { return $Matches[1] }
    return 'unknown'
}

function Wait-ListState {
    param([Parameter(Mandatory)][string]$Expected, [int]$TimeoutSeconds = 30)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ((Get-ListState) -eq $Expected) { return $true }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    return $false
}

function Get-DirectEgressCode {
    # curl's exit code of a request that leaves from the physical address: 0 when it got out. The lab's CA is in the
    # machine store, so the certificate of the target is checked; no revocation lookup, which the lab cannot answer.
    $result = Invoke-RosetunNative -FilePath $curlPath -TimeoutSeconds 15 -Arguments @(
        '--interface', $physical, '--max-time', '5', '--silent', '--ssl-no-revoke', '--output', 'NUL', $targetUrl)
    return $result.ExitCode
}

function Test-DirectEgress {
    return ((Get-DirectEgressCode) -eq 0)
}

function Test-DirectDns {
    # A question to the lab's resolver from the physical address, as the Hyper-V matrix asks 1.1.1.1.
    $query = New-RosetunQuery -Name ([string]$plan.baseline.dns_name)
    try {
        $reply = Invoke-RosetunUdp -Source $physical -Target ([string]$plan.addresses.resolver) -Port 53 -Request $query -Milliseconds 3000
    }
    catch { return $false }
    return ($reply.Length -ge 12 -and $reply[0] -eq 0x6a -and $reply[1] -eq 0x06 -and ($reply[2] -band 0x80) -eq 0x80)
}

function Test-TunnelEgress {
    # A request by name, so that the hijacked DNS is part of it. The local address proves that it went into the tunnel;
    # the target's certificate has an address and no name, so the name is not checked against it (`--insecure`), and the
    # answer must come from the target.
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
    return $last
}

function Wait-HelperReady {
    param([int]$TimeoutSeconds = 90)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ($clock.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        if ((Invoke-ListCli -Arguments @('status') -Seconds 15).ExitCode -eq 0) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Write-ListConfig {
    param($Config)
    [IO.File]::WriteAllText($configPath, (ConvertTo-Json -InputObject $Config -Depth 30), (New-Object Text.UTF8Encoding $false))
}

$recorder = $null
$cleanup = 'UNVERIFIED'
$parts = [ordered]@{}
$runError = $false
$baselineOpen = $false
$sessionOpen = $false
$helperStarted = $false
$filesVerified = $false

try {
    Set-RosetunRunnerState -State running -Step 'prepare'

    # The medium holds the files; what runs is a copy whose hash is the one the plan names.
    New-Item -ItemType Directory -Force -Path $bin, $logs, $work, (Join-Path $work 'lists') | Out-Null
    foreach ($file in $plan.files) {
        $source = Join-Path $mediumRoot ([string]$file.name)
        $target = Join-Path $bin ([string]$file.name)
        Copy-Item -LiteralPath $source -Destination $target -Force
        $hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hash -ne [string]$file.sha256 -or (Get-Item -LiteralPath $target).Length -ne [int64]$file.size) {
            throw "delivered file differs from the plan: $($file.name)"
        }
    }
    $filesVerified = $true
    Add-RosetunRunnerNote -Name 'files-verified' -Value @($plan.files).Count

    # Defender scans a new executable on its first launch, which outlasts the helper's own version check.
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $version = Invoke-RosetunNative -FilePath $singBoxPath -Arguments @('version') -TimeoutSeconds 300
    Add-RosetunRunnerNote -Name 'sing-box-first-launch-seconds' -Value ([int]$clock.Elapsed.TotalSeconds)
    if ($version.ExitCode -ne 0) { throw 'sing-box does not start' }

    Set-RosetunRunnerStep -Step 'recorder'
    Import-Module (Join-Path $Root 'RosetunListResults.psm1') -Force
    # The machine and the boot as the guest itself knows them: the controller holds them against its own.
    $vmId = ([string](Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID).ToLowerInvariant()
    $recorder = New-RosetunListResults -Directory (Join-Path $Root 'results') -VmId $vmId -BootId (Get-RosetunBootCounter)
    Set-RosetunRecorder -Recorder $recorder

    Set-RosetunRunnerStep -Step 'helper'
    $command = "set ROSETUN_LOG=debug&& `"$helperPath`" > `"$(Join-Path $logs 'helper.log')`" 2>&1"
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c $command" -WorkingDirectory $bin
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName
    $helperStarted = $true

    # The configuration of the matrix: the node of the lab, one rule on one list, and the list itself.
    $config = $plan.config
    $listsDirectory = Join-Path $work 'lists'
    $textBytes = [Text.Encoding]::UTF8.GetBytes($listed + "`n")
    $listPath = Join-Path $listsDirectory '1.txt'
    [IO.File]::WriteAllBytes($listPath, $textBytes)
    $config.lists[0].size = [uint64]$textBytes.Length
    $config.lists[0].sha256 = (Get-FileHash -LiteralPath $listPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-ListConfig -Config $config

    if (-not (Wait-HelperReady)) { throw 'the helper did not answer status' }

    Set-RosetunRunnerStep -Step 'baseline'
    $baselineOpen = Send-RosetunMarker -Plan $plan -Label 'baseline' -Word 'open'
    Test-Step 'baseline' 'direct egress works before connect' -Id 'baseline.egress' { Test-DirectEgress }
    Test-Step 'baseline' 'direct DNS works before connect' -Id 'baseline.dns' { Test-DirectDns }
    # The target closes the probe's connection a moment after the guest did. That frame belongs to this window, not to
    # the session that opens right after it: the windows are told apart by their markers, and the wire is not instant.
    Start-Sleep -Seconds 3
    [void](Send-RosetunMarker -Plan $plan -Label 'baseline' -Word 'close')
    $baselineOpen = $false

    Set-RosetunRunnerStep -Step 'text'
    # The marker goes before anything of the session, while the network is still the machine's own.
    $sessionOpen = Send-RosetunMarker -Plan $plan -Label 'session' -Word 'open'
    $connect = Invoke-ListCli -Arguments @('connect')
    Test-Step 'text block' 'connect uploads the list' -Id 'text.connect' -Note "exit $($connect.ExitCode)" {
        $connect.ExitCode -eq 0 -and (Wait-ListState 'Connected')
    }
    $opened = Wait-TunnelEgress -Url "https://$unlisted/"
    Test-Step 'text block' 'the unlisted name opens through the tunnel' -Id 'text.tunnel' -Note "curl $($opened.CurlExit)" {
        $opened.Ok
    }
    Test-Step 'text block' 'the listed name is blocked' -Id 'text.block' {
        -not (Test-TunnelEgress -Url "https://$listed/").Ok
    }
    Test-Step 'text block' 'physical egress remains blocked' -Id 'text.physical' {
        -not (Test-DirectEgress)
    }

    Set-RosetunRunnerStep -Step 'binary'
    $source = Join-Path $work 'listed.json'
    $binary = Join-Path $listsDirectory '1.srs'
    [IO.File]::WriteAllText($source, ('{"version":3,"rules":[{"domain_suffix":["' + $listed + '"]}]}'), (New-Object Text.UTF8Encoding $false))
    $compiled = Invoke-RosetunNative -FilePath $singBoxPath -Arguments @('rule-set', 'compile', '--output', $binary, $source) -TimeoutSeconds 60
    if ($compiled.ExitCode -eq 0) {
        $config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $config.lists[0].format = 'sing_box_binary'
        $config.lists[0].source.file.original_name = 'listed.srs'
        $config.lists[0].size = [uint64](Get-Item -LiteralPath $binary).Length
        $config.lists[0].sha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
        $config.rule_sets[0].default_target = 'block'
        $config.rule_sets[0].rules[0].target = 'direct'
        Write-ListConfig -Config $config
    }
    Test-Step 'binary direct' 'sing-box compiles a local SRS' -Id 'binary.compile' -Note "exit $($compiled.ExitCode)" {
        $compiled.ExitCode -eq 0
    }
    if ($compiled.ExitCode -eq 0) {
        $apply = Invoke-ListCli -Arguments @('apply')
        Test-Step 'binary direct' 'apply uploads the compiled list' -Id 'binary.apply' -Note "exit $($apply.ExitCode)" {
            $apply.ExitCode -eq 0 -and (Wait-ListState 'Connected')
        }
        $opened = Wait-TunnelEgress -Url "https://$listed/"
        Test-Step 'binary direct' 'the listed name opens with the direct rule' -Id 'binary.direct' -Note "curl $($opened.CurlExit)" {
            $opened.Ok
        }
        Test-Step 'binary direct' 'the unlisted name follows the block default' -Id 'binary.default' {
            -not (Test-TunnelEgress -Url "https://$unlisted/").Ok
        }
        Test-Step 'binary direct' 'physical egress remains blocked' -Id 'binary.physical' {
            -not (Test-DirectEgress)
        }
    }
    else {
        foreach ($id in @('binary.apply', 'binary.direct', 'binary.default', 'binary.physical')) {
            Skip-RosetunStep -Id $id -Reason 'srs-compile-failed' -Scenario 'binary direct'
        }
    }
}
catch {
    $runError = $true
    Set-RosetunRunnerError -Place 'execution' -Text "$($_.Exception.GetType().Name): $($_.Exception.Message)"
}
finally {
    try {
        Set-RosetunRunnerState -State cleaning -Step 'disconnect'
        $disconnected = $false
        if ($helperStarted -and (Test-Path -LiteralPath $cliPath)) {
            [void](Invoke-ListCli -Arguments @('disconnect'))
            # The protection is gone when the state is Disconnected and nothing is installed: only then is the network
            # the machine's own again and the closing marker may be sent.
            $clock = [Diagnostics.Stopwatch]::StartNew()
            while ($clock.Elapsed.TotalSeconds -lt 40) {
                if ((Get-ListState) -eq 'Disconnected' -and (Get-ListProtection) -eq 'none') { $disconnected = $true; break }
                Start-Sleep -Milliseconds 500
            }
        }
        $parts['disconnected'] = if ($disconnected) { 'PASS' } elseif ($helperStarted) { 'ERROR' } else { 'UNVERIFIED' }
        if ($sessionOpen -and $disconnected) {
            [void](Send-RosetunMarker -Plan $plan -Label 'session' -Word 'close')
            $sessionOpen = $false
        }
        if ($baselineOpen) {
            [void](Send-RosetunMarker -Plan $plan -Label 'baseline' -Word 'close')
            $baselineOpen = $false
        }

        Set-RosetunRunnerStep -Step 'cleanup'
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
        $parts['list_directory'] = if (-not (Test-Path -LiteralPath $work)) { 'PASS' } else { 'ERROR' }

        # A hard stop, as the Hyper-V matrix does: stopping the task alone could leave the helper under cmd.exe.
        Stop-Process -Name 'rosetun-helper-privileged' -Force -ErrorAction SilentlyContinue
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        $clock = [Diagnostics.Stopwatch]::StartNew()
        while ($clock.Elapsed.TotalSeconds -lt 20 -and ((Get-Process -Name 'rosetun-helper-privileged' -ErrorAction SilentlyContinue) -or
                (@(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Running' }).Count -gt 0))) {
            Start-Sleep -Milliseconds 200
        }
        $parts['helper'] = if (-not (Get-Process -Name 'rosetun-helper-privileged' -ErrorAction SilentlyContinue)) { 'PASS' } else { 'ERROR' }

        # A failed delivery can leave an unchecked executable in the directory being cleaned.
        if ($filesVerified -and (Test-Path -LiteralPath $helperPath)) {
            $reset = Invoke-RosetunNative -FilePath $helperPath -Arguments @('--reset-firewall') -TimeoutSeconds 60
            $parts['firewall'] = if ($reset.ExitCode -eq 0) { 'PASS' } else { 'ERROR' }
        }
        else { $parts['firewall'] = 'UNVERIFIED' }

        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        $parts['task'] = if ($null -eq (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) { 'PASS' } else { 'ERROR' }

        $clock = [Diagnostics.Stopwatch]::StartNew()
        while ($clock.Elapsed.TotalSeconds -lt 20 -and (Get-NetAdapter -Name ([string]$plan.tun.alias) -ErrorAction SilentlyContinue)) {
            Start-Sleep -Milliseconds 500
        }
        $parts['adapter'] = if ($null -eq (Get-NetAdapter -Name ([string]$plan.tun.alias) -ErrorAction SilentlyContinue)) { 'PASS' } else { 'ERROR' }

        Remove-Item -LiteralPath $bin -Recurse -Force -ErrorAction SilentlyContinue
        $parts['binaries'] = if (-not (Test-Path -LiteralPath $bin)) { 'PASS' } else { 'ERROR' }

        $cleanup = if (@($parts.Values) -contains 'ERROR') { 'ERROR' }
        elseif (@($parts.Values | Where-Object { $_ -ne 'PASS' }).Count -gt 0) { 'UNVERIFIED' }
        else { 'PASS' }
    }
    catch {
        $cleanup = 'ERROR'
        Set-RosetunRunnerError -Place 'cleanup' -Text "$($_.Exception.GetType().Name): $($_.Exception.Message)"
    }
    Set-RosetunRunnerCleanup -Result $cleanup -Parts $parts

    if ($recorder) {
        try {
            $endBoot = ''
            try { $endBoot = Get-RosetunBootCounter } catch { Add-RosetunListError -Recorder $recorder -Place execution }
            if ($endBoot -ne $recorder.Plan.identity.boot_id) { Add-RosetunListError -Recorder $recorder -Place execution }
            if ($cleanup -eq 'ERROR') { Add-RosetunListError -Recorder $recorder -Place cleanup }
            Complete-RosetunListResults -Recorder $recorder -Cleanup $cleanup -EndBootId $endBoot -Aborted $runError
        }
        catch {
            Set-RosetunRunnerError -Place 'export' -Text "$($_.Exception.GetType().Name): $($_.Exception.Message)"
        }
    }
    if ($runError -or $null -eq $recorder) { Set-RosetunRunnerState -State failed -Step 'done' }
    else { Set-RosetunRunnerState -State finished -Step 'done' }
}
