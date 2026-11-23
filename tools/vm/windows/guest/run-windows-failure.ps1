# The Windows Failure core matrix as an autonomous runner of the QEMU lab (stage 10b). Windows PowerShell 5.1, as SYSTEM.
#
# Each run executes one selected case of the Failure core (`engine-killed`, `helper-killed`, `no-network`,
# `apply-rules`, `reconnect`, `temporary` or `dns-lock`) on a fresh disposable guest against the lab's targets.
# The runner verifies the hashes of the delivered binaries, marks the three windows the observer judges (`baseline`,
# `session` and `recovery`), records every check in the order of the case's catalog into `status.json` and the
# `RosetunListResults.psm1` recorder, and cleans up whatever happens.

param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]$')][string]$Medium
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib.ps1')

$plan = Get-Content -LiteralPath (Join-Path $Root 'plan.json') -Raw -Encoding UTF8 | ConvertFrom-Json
Initialize-RosetunRunner -StatusPath (Join-Path $Root 'status.json') -RunId ([string]$plan.run)

$mediumRoot = $Medium + ':\'
$bin = Join-Path $Root 'bin'
$logs = Join-Path $Root 'logs'
$work = Join-Path $Root 'list-matrix'
$cliPath = Join-Path $bin 'rosetun.exe'
$helperPath = Join-Path $bin 'rosetun-helper-privileged.exe'
$singBoxPath = Join-Path $bin 'sing-box.exe'
$curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'
$taskName = 'RosetunHelper'
$caseName = [string]$plan.case
$listed = [string]$plan.names.listed
$unlisted = [string]$plan.names.unlisted
$physical = [string]$plan.addresses.client4
$targetUrl = 'https://' + [string]$plan.addresses.target4 + '/'
$baselineDns = [string]$plan.baseline.dns_name
$recoveryDns = 'after.' + $baselineDns

. (Join-Path $PSScriptRoot 'failure-probes.ps1')

function Disconnect-FailureSession {
    param([int]$TimeoutSeconds = 40)
    [void](Invoke-FailureCli -Arguments @('disconnect'))
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ($clock.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        if ((Get-FailureState) -eq 'Disconnected' -and (Get-FailureProtection) -eq 'none') {
            return $true
        }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Invoke-ConnectChecks {
    param([Parameter(Mandatory)][string]$RequestPath)
    $connect = Invoke-FailureCli -Arguments @('connect', $RequestPath)
    Test-Step -Id 'connect.state-is-connected' -Scenario 'connect' -Expectation 'state is Connected' -Note "exit $($connect.ExitCode)" {
        $connect.ExitCode -eq 0 -and (Wait-FailureState 'Connected')
    }
    $egress = Wait-TunnelEgress -Url "https://$unlisted/"
    Test-Step -Id 'connect.tunnel-carries-traffic-within-5-s-dns-included' -Scenario 'connect' -Expectation 'tunnel carries traffic within 5 s, DNS included' -Note "curl $($egress.CurlExit) $($egress.Seconds)s" {
        $egress.Ok -and $egress.Seconds -le 5
    }
    Test-Step -Id 'connect.direct-egress-is-blocked' -Scenario 'connect' -Expectation 'direct egress is blocked' {
        -not (Test-DirectEgress)
    }
    Test-Step -Id 'connect.ipv6-outside-the-tunnel-is-blocked' -Scenario 'connect' -Expectation 'IPv6 outside the tunnel is blocked' {
        -not (Test-Ipv6Egress)
    }
}

$recorder = $null
$cleanup = 'UNVERIFIED'
$parts = [ordered]@{}
$runError = $false
$baselineOpen = $false
$sessionOpen = $false
$recoveryOpen = $false
$helperStarted = $false
$filesVerified = $false

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
    $filesVerified = $true
    Add-RosetunRunnerNote -Name 'files-verified' -Value @($plan.files).Count

    $clock = [Diagnostics.Stopwatch]::StartNew()
    $version = Invoke-RosetunNative -FilePath $singBoxPath -Arguments @('version') -TimeoutSeconds 300
    Add-RosetunRunnerNote -Name 'sing-box-first-launch-seconds' -Value ([int]$clock.Elapsed.TotalSeconds)
    if ($version.ExitCode -ne 0) { throw 'sing-box does not start' }

    Set-RosetunRunnerStep -Step 'recorder'
    Import-Module (Join-Path $Root 'RosetunListResults.psm1') -Force
    $vmId = ([string](Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID).ToLowerInvariant()
    $catalogRows = @($plan.catalog | ForEach-Object { $_ })
    $recorder = New-RosetunListResults -Directory (Join-Path $Root 'results') -VmId $vmId -BootId (Get-RosetunBootCounter) -Suite 'windows-failure' -Catalog $catalogRows
    Set-RosetunRecorder -Recorder $recorder

    Set-RosetunRunnerStep -Step 'helper'
    $command = "set ROSETUN_LOG=debug&& `"$helperPath`" > `"$(Join-Path $logs 'helper.log')`" 2>&1"
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c $command" -WorkingDirectory $bin
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName
    $helperStarted = $true

    if (-not (Wait-HelperReady)) { throw 'the helper did not answer status' }

    $baseRequest = Copy-FailureRequest -Request $plan.request
    $baseRequest.settings.kill_switch = $true
    $baseRequestPath = Write-FailureRequest -Name 'request.json' -Request $baseRequest
    $planRequestPath = Write-FailureRequest -Name 'request-plan.json' -Request $plan.request
    $initialNodeId = [string]$baseRequest.node.id

    Set-RosetunRunnerStep -Step 'baseline'
    $baselineOpen = Send-RosetunMarker -Plan $plan -Label 'baseline' -Word 'open'
    Test-Step -Id 'baseline.direct-egress-works-before-connect' -Scenario 'baseline' -Expectation 'direct egress works before connect' {
        Test-DirectEgress
    }
    Test-Step -Id 'baseline.direct-dns-works-before-connect' -Scenario 'baseline' -Expectation 'direct DNS works before connect' {
        Test-DirectDns -Name $baselineDns
    }
    Test-Step -Id 'baseline.direct-tcp-dns-works-before-connect' -Scenario 'baseline' -Expectation 'direct TCP DNS works before connect' {
        Test-DirectTcpDns -Name $baselineDns
    }
    Test-Step -Id 'baseline.ipv6-to-the-host-works-before-connect' -Scenario 'baseline' -Expectation 'IPv6 to the host works before connect' {
        Test-Ipv6Egress
    }

    if ($caseName -eq 'no-network') {
        Set-RosetunRunnerStep -Step 'no-network'
        $adapterIndex = Get-PhysicalInterfaceIndex
        $routeRestored = $false
        try {
            Disable-NetAdapter -InterfaceIndex $adapterIndex -Confirm:$false
            $networkTimer = [Diagnostics.Stopwatch]::StartNew()
            $attempt = Invoke-FailureCli -Arguments @('connect', $baseRequestPath) -Seconds 30
            $failed = Wait-FailureState -Expected 'Failed' -TimeoutSeconds 10
            $networkTimer.Stop()
            $status = Invoke-FailureCli -Arguments @('status') -Seconds 15
            Test-Step -Id 'no-network.failed-with-no-network-within-10-s' -Scenario 'no network' -Expectation 'Failed with no network within 10 s' -Note "exit $($attempt.ExitCode)" {
                $attempt.ExitCode -ne 0 -and $failed -and $networkTimer.Elapsed.TotalSeconds -le 10 -and
                    ($attempt.Output -match 'NoNetwork|no_network' -or $status.Output -match 'NoNetwork|no_network')
            }
            Test-Step -Id 'no-network.no-wfp-filters-were-installed' -Scenario 'no network' -Expectation 'no WFP filters were installed' {
                -not (Test-WfpFilters)
            }
            Test-Step -Id 'no-network.no-tun-adapter-was-created' -Scenario 'no network' -Expectation 'no TUN adapter was created' {
                -not (Test-TunAdapter)
            }
            Test-Step -Id 'no-network.engine-did-not-start' -Scenario 'no network' -Expectation 'engine did not start' {
                -not (Test-EngineRunning)
            }
        }
        finally {
            Enable-NetAdapter -InterfaceIndex $adapterIndex -Confirm:$false
        }
        $routeRestored = Wait-PhysicalRoute -Index $adapterIndex -TimeoutSeconds 60
        Test-Step -Id 'no-network.physical-route-returns-after-adapter-enable' -Scenario 'no network' -Expectation 'physical route returns after adapter enable' {
            $routeRestored
        }
        if (-not $routeRestored) { throw 'physical route did not return after adapter enable' }
    }

    Start-Sleep -Seconds 3
    [void](Send-RosetunMarker -Plan $plan -Label 'baseline' -Word 'close')
    $baselineOpen = $false

    Set-RosetunRunnerStep -Step 'session'
    $sessionOpen = Send-RosetunMarker -Plan $plan -Label 'session' -Word 'open'
    Invoke-ConnectChecks -RequestPath $baseRequestPath

    switch ($caseName) {
        'no-network' {
            Test-Step -Id 'no-network.connect-succeeds-after-the-route-returns' -Scenario 'no network' -Expectation 'connect succeeds after the route returns' {
                (Get-FailureState) -eq 'Connected'
            }
            Test-Step -Id 'no-network.direct-egress-is-blocked-after-the-route-returns' -Scenario 'no network' -Expectation 'direct egress is blocked after the route returns' {
                -not (Test-DirectEgress)
            }
            if (-not (Disconnect-FailureSession)) { throw 'session did not disconnect cleanly' }
        }
        'engine-killed' {
            Stop-FailureEngine
            Test-Step -Id 'engine-killed.state-is-failedprotected' -Scenario 'engine killed' -Expectation 'state is FailedProtected' {
                Wait-FailureState 'FailedProtected'
            }
            Test-Step -Id 'engine-killed.direct-egress-is-blocked' -Scenario 'engine killed' -Expectation 'direct egress is blocked' {
                -not (Test-DirectEgress)
            }
            Test-Step -Id 'engine-killed.direct-dns-is-blocked' -Scenario 'engine killed' -Expectation 'direct DNS is blocked' {
                -not (Test-DirectDns -Name $baselineDns)
            }
            Test-Step -Id 'engine-killed.ipv6-outside-the-tunnel-is-blocked' -Scenario 'engine killed' -Expectation 'IPv6 outside the tunnel is blocked' {
                -not (Test-Ipv6Egress)
            }
            Test-Step -Id 'engine-killed.direct-egress-is-still-blocked' -Scenario 'engine killed' -Expectation 'direct egress is still blocked' {
                -not (Test-DirectEgress)
            }
            if (-not (Disconnect-FailureSession)) { throw 'session did not disconnect cleanly' }
        }
        'helper-killed' {
            Stop-FailureHelper
            Test-Step -Id 'helper-killed.engine-died-with-the-helper' -Scenario 'helper killed' -Expectation 'engine died with the helper' {
                Wait-FailureCondition { -not (Test-EngineRunning) }
            }
            Test-Step -Id 'helper-killed.tunnel-adapter-is-gone' -Scenario 'helper killed' -Expectation 'tunnel adapter is gone' {
                Wait-FailureCondition { -not (Test-TunAdapter) }
            }
            [void](Wait-FailureCondition -TimeoutSeconds 20 -Condition { -not (Test-WfpFilters) })
        }
        'apply-rules' {
            $applyRequest = Copy-FailureRequest -Request $baseRequest
            $applyRequest.rule_set.rules = @([ordered]@{
                    id = 'block-listed'
                    enabled = $true
                    matcher = [ordered]@{ domain = [ordered]@{ exact = $listed } }
                    target = 'block'
                })
            $applyPath = Write-FailureRequest -Name 'request-apply-rules.json' -Request $applyRequest
            $apply = Invoke-FailureCli -Arguments @('apply', $applyPath)
            Test-Step -Id 'apply-rules.apply-succeeds' -Scenario 'apply rules' -Expectation 'apply succeeds' -Note "exit $($apply.ExitCode)" {
                $apply.ExitCode -eq 0
            }
            Test-Step -Id 'apply-rules.state-is-connected' -Scenario 'apply rules' -Expectation 'state is Connected' {
                (Get-FailureState) -eq 'Connected'
            }
            $status = Invoke-FailureCli -Arguments @('status') -Seconds 20
            Test-Step -Id 'apply-rules.node-is-unchanged' -Scenario 'apply rules' -Expectation 'node is unchanged' {
                $status.ExitCode -eq 0 -and $status.Output -match ('(?m)^node: {0}\r?$' -f [regex]::Escape($initialNodeId))
            }
            $egress = Wait-TunnelEgress -Url "https://$unlisted/"
            Test-Step -Id 'apply-rules.tunnel-carries-traffic' -Scenario 'apply rules' -Expectation 'tunnel carries traffic' -Note "curl $($egress.CurlExit)" {
                $egress.Ok
            }
            Test-Step -Id 'apply-rules.direct-egress-is-blocked' -Scenario 'apply rules' -Expectation 'direct egress is blocked' {
                -not (Test-DirectEgress)
            }
            Test-Step -Id 'apply-rules.ipv6-outside-the-tunnel-is-blocked' -Scenario 'apply rules' -Expectation 'IPv6 outside the tunnel is blocked' {
                -not (Test-Ipv6Egress)
            }
            if (-not (Disconnect-FailureSession)) { throw 'session did not disconnect cleanly' }
        }
        'reconnect' {
            Start-FailureEgressWatch
            $watch = [pscustomobject]@{ Probes = 0; Leaks = 1 }
            try {
                $reconnect = Invoke-FailureCli -Arguments @('reconnect')
                Test-Step -Id 'reconnect.reconnect-succeeds' -Scenario 'reconnect' -Expectation 'reconnect succeeds' -Note "exit $($reconnect.ExitCode)" {
                    $reconnect.ExitCode -eq 0
                }
                Test-Step -Id 'reconnect.state-is-connected' -Scenario 'reconnect' -Expectation 'state is Connected' {
                    (Get-FailureState) -eq 'Connected'
                }
                Test-Step -Id 'reconnect.wfp-filters-stay-installed' -Scenario 'reconnect' -Expectation 'WFP filters stay installed' {
                    Test-WfpFilters
                }
                Test-Step -Id 'reconnect.direct-egress-is-blocked' -Scenario 'reconnect' -Expectation 'direct egress is blocked' {
                    -not (Test-DirectEgress)
                }
                Test-Step -Id 'reconnect.ipv6-outside-the-tunnel-is-blocked' -Scenario 'reconnect' -Expectation 'IPv6 outside the tunnel is blocked' {
                    -not (Test-Ipv6Egress)
                }
            }
            finally {
                $watch = Stop-FailureEgressWatch
            }
            Test-Step -Id 'reconnect.no-direct-leak-through-the-restart' -Scenario 'reconnect' -Expectation 'no direct leak through the restart' -Note "probes $($watch.Probes)" {
                $watch.Probes -gt 0 -and $watch.Leaks -eq 0
            }
            $status = Invoke-FailureCli -Arguments @('status') -Seconds 20
            Test-Step -Id 'reconnect.node-is-unchanged' -Scenario 'reconnect' -Expectation 'node is unchanged' {
                $status.ExitCode -eq 0 -and $status.Output -match ('(?m)^node: {0}\r?$' -f [regex]::Escape($initialNodeId))
            }
            $egress = Wait-TunnelEgress -Url "https://$unlisted/"
            Test-Step -Id 'reconnect.tunnel-carries-traffic' -Scenario 'reconnect' -Expectation 'tunnel carries traffic' -Note "curl $($egress.CurlExit)" {
                $egress.Ok
            }
            if (-not (Disconnect-FailureSession)) { throw 'session did not disconnect cleanly' }
        }
        'temporary' {
            $temporaryRequest = Copy-FailureRequest -Request $baseRequest
            $temporaryRequest.rule_set.default_target = 'block'
            $temporaryRequest.rule_set.rules = @()
            $temporaryRule = [ordered]@{
                id = 'direct-domain'
                enabled = $true
                matcher = [ordered]@{ domain = [ordered]@{ exact = $listed } }
                target = 'direct'
            }
            $temporaryRequest | Add-Member -NotePropertyName 'temporary_rules' -NotePropertyValue @($temporaryRule) -Force
            $temporaryPath = Write-FailureRequest -Name 'request-temporary.json' -Request $temporaryRequest
            $apply = Invoke-FailureCli -Arguments @('apply', $temporaryPath)
            Test-Step -Id 'temporary.apply-succeeds' -Scenario 'temporary' -Expectation 'apply succeeds' -Note "exit $($apply.ExitCode)" {
                $apply.ExitCode -eq 0
            }
            Test-Step -Id 'temporary.state-is-connected' -Scenario 'temporary' -Expectation 'state is Connected' {
                (Get-FailureState) -eq 'Connected'
            }
            $status = Invoke-FailureCli -Arguments @('status') -Seconds 20
            Test-Step -Id 'temporary.one-rule-is-reported' -Scenario 'temporary' -Expectation 'one rule is reported' {
                $status.ExitCode -eq 0 -and $status.Output -match '(?m)^temporary rules: 1\r?$'
            }
            $rules = Invoke-FailureCli -Arguments @('temporary') -Seconds 20
            Test-Step -Id 'temporary.rule-is-returned' -Scenario 'temporary' -Expectation 'rule is returned' {
                $rules.ExitCode -eq 0 -and $rules.Output -match ('(?m)^direct: domain exact {0}\r?$' -f [regex]::Escape($listed))
            }
            $egress = Wait-TunnelEgress -Url "https://$listed/"
            Test-Step -Id 'temporary.domain-goes-direct' -Scenario 'temporary' -Expectation 'domain goes direct' -Note "curl $($egress.CurlExit)" {
                $egress.Ok
            }
            Test-Step -Id 'temporary.unmatched-domain-is-blocked' -Scenario 'temporary' -Expectation 'unmatched domain is blocked' {
                -not (Test-TunnelEgress -Url "https://$unlisted/").Ok
            }
            Test-Step -Id 'temporary.physical-egress-stays-blocked' -Scenario 'temporary' -Expectation 'physical egress stays blocked' {
                -not (Test-DirectEgress)
            }
            if (-not (Disconnect-FailureSession)) { throw 'temporary session did not disconnect cleanly' }
            $reconnect = Invoke-FailureCli -Arguments @('connect', $baseRequestPath)
            Test-Step -Id 'temporary-disconnect.original-request-connects' -Scenario 'temporary disconnect' -Expectation 'original request connects' -Note "exit $($reconnect.ExitCode)" {
                $reconnect.ExitCode -eq 0 -and (Wait-FailureState 'Connected')
            }
            $statusAfter = Invoke-FailureCli -Arguments @('status') -Seconds 20
            Test-Step -Id 'temporary-disconnect.no-temporary-rules-remain' -Scenario 'temporary disconnect' -Expectation 'no temporary rules remain' {
                $statusAfter.ExitCode -eq 0 -and $statusAfter.Output -match '(?m)^temporary rules: 0\r?$'
            }
            $rulesAfter = Invoke-FailureCli -Arguments @('temporary') -Seconds 20
            Test-Step -Id 'temporary-disconnect.rule-list-is-empty' -Scenario 'temporary disconnect' -Expectation 'rule list is empty' {
                $rulesAfter.ExitCode -eq 0 -and $rulesAfter.Output -match '(?m)^none\r?$'
            }
            if (-not (Disconnect-FailureSession)) { throw 'session did not disconnect cleanly' }
        }
        'dns-lock' {
            if (-not (Disconnect-FailureSession)) { throw 'initial session did not disconnect before dns-lock' }
            $dnsConnect = Invoke-FailureCli -Arguments @('connect', $planRequestPath)
            Test-Step -Id 'dns-lock.state-is-connected' -Scenario 'dns lock' -Expectation 'state is Connected' -Note "exit $($dnsConnect.ExitCode)" {
                $dnsConnect.ExitCode -eq 0 -and (Wait-FailureState 'Connected')
            }
            $egress = Wait-TunnelEgress -Url "https://$unlisted/"
            Test-Step -Id 'dns-lock.tunnel-carries-traffic' -Scenario 'dns lock' -Expectation 'tunnel carries traffic' -Note "curl $($egress.CurlExit)" {
                $egress.Ok
            }
            Test-Step -Id 'dns-lock.direct-dns-is-blocked' -Scenario 'dns lock' -Expectation 'direct DNS is blocked' {
                -not (Test-DirectDns -Name $baselineDns)
            }
            Test-Step -Id 'dns-lock.ipv6-outside-the-tunnel-is-blocked-without-the-kill-switch' -Scenario 'dns lock' -Expectation 'IPv6 outside the tunnel is blocked without the kill switch' {
                -not (Test-Ipv6Egress)
            }
            if (-not (Disconnect-FailureSession)) { throw 'dns-lock session did not disconnect cleanly' }
        }
    }

    Start-Sleep -Seconds 3
    [void](Send-RosetunMarker -Plan $plan -Label 'session' -Word 'close')
    $sessionOpen = $false

    Set-RosetunRunnerStep -Step 'recovery'
    $recoveryOpen = Send-RosetunMarker -Plan $plan -Label 'recovery' -Word 'open'
    switch ($caseName) {
        'engine-killed' {
            Test-Step -Id 'disconnect.state-is-disconnected' -Scenario 'disconnect' -Expectation 'state is Disconnected' {
                Wait-FailureState 'Disconnected'
            }
            Test-Step -Id 'disconnect.direct-egress-works-again' -Scenario 'disconnect' -Expectation 'direct egress works again' {
                Test-DirectEgress
            }
            Test-Step -Id 'disconnect.ipv6-works-again' -Scenario 'disconnect' -Expectation 'IPv6 works again' {
                Test-Ipv6Egress
            }
            Test-Step -Id 'disconnect.tunnel-adapter-is-gone' -Scenario 'disconnect' -Expectation 'tunnel adapter is gone' {
                Wait-FailureCondition { -not (Test-TunAdapter) }
            }
            Invoke-RecoveryControlProbes -NeedEgress $false -NeedIpv6 $false -NeedUdpDns $true -NeedTcpDns $true
        }
        'helper-killed' {
            Test-Step -Id 'helper-killed.direct-egress-works-again' -Scenario 'helper killed' -Expectation 'direct egress works again' {
                Wait-FailureCondition { Test-DirectEgress }
            }
            Test-Step -Id 'helper-killed.direct-dns-works-again' -Scenario 'helper killed' -Expectation 'direct DNS works again' {
                Wait-FailureCondition { Test-DirectDns -Name $recoveryDns }
            }
            Invoke-RecoveryControlProbes -NeedEgress $false -NeedIpv6 $true -NeedUdpDns $false -NeedTcpDns $true
        }
        default {
            Invoke-RecoveryControlProbes -NeedEgress $true -NeedIpv6 $true -NeedUdpDns $true -NeedTcpDns $true
        }
    }
    Start-Sleep -Seconds 3
    [void](Send-RosetunMarker -Plan $plan -Label 'recovery' -Word 'close')
    $recoveryOpen = $false
}
catch {
    $runError = $true
    Set-RosetunRunnerError -Place 'execution' -Text "$($_.Exception.GetType().Name): $($_.Exception.Message)"
}
finally {
    try {
        Set-RosetunRunnerState -State cleaning -Step 'disconnect'
        Stop-FailureEgressWatch -Quiet | Out-Null
        $disconnected = $false
        if ($helperStarted -and (Test-Path -LiteralPath $cliPath)) {
            if ($caseName -eq 'helper-killed' -and -not (Get-Process -Name 'rosetun-helper-privileged' -ErrorAction SilentlyContinue)) {
                $disconnected = (-not (Test-EngineRunning) -and -not (Test-TunAdapter) -and -not (Test-WfpFilters))
            }
            else {
                $disconnected = Disconnect-FailureSession -TimeoutSeconds 40
            }
        }
        $parts['disconnected'] = if ($disconnected) { 'PASS' } elseif ($helperStarted) { 'ERROR' } else { 'UNVERIFIED' }
        if ($recoveryOpen) {
            [void](Send-RosetunMarker -Plan $plan -Label 'recovery' -Word 'close')
            $recoveryOpen = $false
        }
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

        Stop-Process -Name 'rosetun-helper-privileged' -Force -ErrorAction SilentlyContinue
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        $clock = [Diagnostics.Stopwatch]::StartNew()
        while ($clock.Elapsed.TotalSeconds -lt 20 -and ((Get-Process -Name 'rosetun-helper-privileged' -ErrorAction SilentlyContinue) -or
                (@(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Running' }).Count -gt 0))) {
            Start-Sleep -Milliseconds 200
        }
        $parts['helper'] = if (-not (Get-Process -Name 'rosetun-helper-privileged' -ErrorAction SilentlyContinue)) { 'PASS' } else { 'ERROR' }

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
