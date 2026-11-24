# Runs the four Windows Upgrade scenarios on the isolated lab as SYSTEM.
# Requires Windows PowerShell 5.1.
param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]$')][string]$Medium
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib.ps1')

$plan = Get-Content -LiteralPath (Join-Path $Root 'plan.json') -Raw -Encoding UTF8 | ConvertFrom-Json
Initialize-RosetunRunner -StatusPath (Join-Path $Root 'status.json') -RunId $plan.run

$bin = Join-Path $Root 'bin'
$logs = Join-Path $Root 'logs'
$work = Join-Path $Root 'upgrade-matrix'
$installDir = Join-Path $env:ProgramFiles 'Rosetun'
$installedCli = Join-Path $installDir 'rosetun.exe'
$installedHelper = Join-Path $installDir 'rosetun-helper-privileged.exe'
$uninstaller = Join-Path $installDir 'unins000.exe'
$cliPath = Join-Path $bin 'rosetun.exe'
$helperPath = Join-Path $bin 'rosetun-helper-privileged.exe'
$curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'
$uninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{833B7718-C11A-4F97-9ABC-6967646F9DBB}_is1'
$urlClass = 'HKLM:\SOFTWARE\Classes\rosetun'
$profileDirectories = @((Join-Path $env:APPDATA 'Rosetun'), (Join-Path $env:LOCALAPPDATA 'Rosetun'))
$physical = [string]$plan.addresses.client4
$target4 = [string]$plan.addresses.target4
$targetUrl = 'https://' + $target4 + '/'
$unlistedUrl = 'https://' + [string]$plan.names.unlisted + '/'
$baselineDns = [string]$plan.baseline.dns_name
$recoveryDns = 'after.' + $baselineDns
$tunAlias = [string]$plan.tun.alias
$setupTimeout = [int]$plan.setup_timeout_seconds
$protectedRequest = Join-Path $work 'protected.json'
$openRequest = Join-Path $work 'open.json'

function Wait-RosetunUpgradeCondition {
    param([Parameter(Mandatory)][scriptblock]$Condition, [int]$TimeoutSeconds = 45)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    do {
        if (& $Condition) { return $true }
        Start-Sleep -Milliseconds 250
    } while ($clock.Elapsed.TotalSeconds -lt $TimeoutSeconds)
    return $false
}

function Invoke-RosetunInstalledCli {
    param([Parameter(Mandatory)][string[]]$Arguments, [int]$TimeoutSeconds = 60)
    Invoke-RosetunNative -FilePath $installedCli -Arguments $Arguments -TimeoutSeconds $TimeoutSeconds
}

function Get-RosetunInstalledStatus {
    $service = Get-Service -Name 'Rosetun' -ErrorAction SilentlyContinue
    if ($null -eq $service -or $service.Status -ne 'Running' -or -not [IO.File]::Exists($installedCli)) {
        return ''
    }
    $result = Invoke-RosetunInstalledCli -Arguments @('status') -TimeoutSeconds 10
    if ($result.ExitCode -eq 0) { return [string]$result.Output }
    return ''
}

function Test-RosetunInstalledService {
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name = 'Rosetun'"
    if ($null -eq $service -or $service.State -ne 'Running') { return $false }
    $expectedPath = [regex]::Escape($installedHelper)
    return ($service.PathName -match ('^"?' + $expectedPath + '(?:"|\s|$)') -and
        (Get-RosetunInstalledStatus) -match '(?m)^state: \w+\s*$')
}

function Connect-RosetunInstalled {
    param([Parameter(Mandatory)][string]$Request)
    $result = Invoke-RosetunInstalledCli -Arguments @('connect', $Request)
    return ($result.ExitCode -eq 0 -and (Wait-RosetunUpgradeCondition -Condition {
        (Get-RosetunInstalledStatus) -match '(?m)^state: Connected\s*$'
    }))
}

function Test-RosetunUpgradeDirectEgress {
    $result = Invoke-RosetunNative -FilePath $curlPath -TimeoutSeconds 10 -Arguments @(
        '--noproxy', '*', '--interface', $physical, '--max-time', '4', '--silent', '--fail', '--ssl-no-revoke',
        '--write-out', "`nlocal=%{local_ip} remote=%{remote_ip}", $targetUrl)
    return ($result.ExitCode -eq 0 -and $result.Output -match 'rosetun-lab-target' -and
        $result.Output -match ('local=' + [regex]::Escape($physical) + ' remote=' + [regex]::Escape($target4) + '\s*$'))
}

function Test-RosetunUpgradeDirectDns {
    param([Parameter(Mandatory)][string]$Name)
    try {
        $reply = Invoke-RosetunUdp -Source $physical -Target ([string]$plan.addresses.resolver) -Port 53 `
            -Request (New-RosetunQuery -Name $Name) -Milliseconds 3000
    }
    catch { return $false }
    return ($reply.Length -ge 12 -and $reply[0] -eq 0x6a -and $reply[1] -eq 0x06 -and ($reply[2] -band 0x80) -eq 0x80)
}

function Test-RosetunUpgradeTunnel {
    $tunAddresses = @(Get-NetIPAddress -InterfaceAlias $tunAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        ForEach-Object { $_.IPAddress })
    if ($tunAddresses.Count -eq 0) { return $false }
    $result = Invoke-RosetunNative -FilePath $curlPath -TimeoutSeconds 15 -Arguments @(
        '--noproxy', '*', '--max-time', '8', '--silent', '--fail', '--insecure', '--ssl-no-revoke',
        '--write-out', "`nlocal=%{local_ip} remote=%{remote_ip}", $unlistedUrl)
    return ($result.ExitCode -eq 0 -and $result.Output -match 'rosetun-lab-target' -and
        $result.Output -match 'local=(\S+) remote=(\S+)\s*$' -and
        $tunAddresses -contains $Matches[1] -and $Matches[2] -eq $target4)
}

function Get-RosetunUpgradeWfp {
    $path = Join-Path $work 'wfp.xml'
    try {
        $result = Invoke-RosetunNative -FilePath (Join-Path $env:SystemRoot 'System32\netsh.exe') `
            -TimeoutSeconds 20 -Arguments @('wfp', 'show', 'state', "file=$path")
        if ($result.ExitCode -ne 0 -or -not [IO.File]::Exists($path)) { throw 'cannot inspect WFP state' }
        $raw = [IO.File]::ReadAllText($path)
        if ($raw -notmatch '<wfpstate>' -or $raw -notmatch '</wfpstate>') { throw 'incomplete WFP state' }
        return [pscustomobject]@{
            Lockdown = $raw -match '<providerKey>\s*\{?f12dbedd-f3c7-4a72-b0f8-20559c88b112\}?\s*</providerKey>'
            LockdownSublayer = $raw -match '<subLayerKey>\s*\{?f829a64d-c373-4d92-9d66-e1c680f3794f\}?\s*</subLayerKey>'
            Hold = $raw -match '<providerKey>\s*\{?496d09fa-1d9a-451b-871f-35ba72197795\}?\s*</providerKey>'
            Session = $raw -match '<providerKey>\s*\{?51a47ec7-6459-4b84-8854-075e1576e7f9\}?\s*</providerKey>' -or
                $raw -match '<subLayerKey>\s*\{?0c035ef5-4c5c-4583-ad9c-179791360f5e\}?\s*</subLayerKey>'
        }
    }
    finally { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
}

function Test-RosetunNoUpgradeHold {
    $state = Get-RosetunUpgradeWfp
    return (-not ($state.Hold -or $state.Lockdown -or $state.LockdownSublayer))
}

function Get-RosetunUpgradeLog {
    param([Parameter(Mandatory)][string]$Path)
    if (-not [IO.File]::Exists($Path)) { return '' }
    $stream = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite, Delete')
    try {
        $reader = [IO.StreamReader]::new($stream)
        try { return $reader.ReadToEnd() }
        finally { $reader.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Start-RosetunUpgradeProcess {
    param([Parameter(Mandatory)][string]$FilePath, [Parameter(Mandatory)][string]$Arguments)
    $start = [Diagnostics.ProcessStartInfo]::new($FilePath, $Arguments)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.WorkingDirectory = $work
    return [Diagnostics.Process]::Start($start)
}

function Stop-RosetunUpgradeProcess {
    param([Parameter(Mandatory)][Diagnostics.Process]$Process)
    if (-not $Process.HasExited) {
        try { $Process.Kill() }
        catch [InvalidOperationException] { if (-not $Process.HasExited) { throw } }
        if (-not $Process.WaitForExit(5000)) { throw "process $($Process.Id) did not exit" }
    }
}

function Stop-RosetunSetupProcesses {
    $names = @('old-setup', 'new-setup', 'old-setup.tmp', 'new-setup.tmp', 'rosetun-install-check', 'unins000*', '_unins*')
    foreach ($process in @(Get-Process -Name $names -ErrorAction SilentlyContinue)) {
        Stop-RosetunUpgradeProcess -Process $process
    }
}

function Invoke-RosetunUpgradeSetup {
    param(
        [Parameter(Mandatory)][ValidateSet('old', 'new')][string]$Build,
        [Parameter(Mandatory)][string]$Scenario,
        [switch]$Interrupt
    )
    $log = Join-Path $logs "$Scenario-$Build.log"
    $setup = Join-Path $bin "$Build-setup.exe"
    $process = Start-RosetunUpgradeProcess -FilePath $setup `
        -Arguments "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LANG=english /LOG=`"$log`""
    $clock = [Diagnostics.Stopwatch]::StartNew()
    try {
        if ($Interrupt) {
            $wizard = $null
            $service = [ServiceProcess.ServiceController]::new('Rosetun')
            try {
                # Keep the wizard's handle before polling the service. Fetching WFP state here can let Setup finish first.
                while (-not $process.HasExited -and $clock.Elapsed.TotalSeconds -lt $setupTimeout) {
                    if ($null -eq $wizard) {
                        $wizard = Get-CimInstance -ClassName Win32_Process `
                            -Filter "ParentProcessId = $($process.Id) AND Name = '$Build-setup.tmp'" |
                            ForEach-Object { Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue } |
                            Select-Object -First 1
                        if ($null -eq $wizard) {
                            Start-Sleep -Milliseconds 50
                            continue
                        }
                        [void]$wizard.Handle
                    }
                    $service.Refresh()
                    if ($wizard.HasExited) { break }
                    if ($service.Status -eq 'Stopped') {
                        Stop-RosetunUpgradeProcess -Process $wizard
                        Stop-RosetunUpgradeProcess -Process $process
                        $text = Get-RosetunUpgradeLog -Path $log
                        $state = Get-RosetunUpgradeWfp
                        $service.Refresh()
                        return [pscustomobject]@{
                            Interrupted = $service.Status -eq 'Stopped' -and $state.Hold -and $state.Lockdown -and
                                $text -match 'The network is held closed for the upgrade|upgrade hold placed' -and
                                $text -notmatch 'Installation process succeeded'
                            Seconds = [int]$clock.Elapsed.TotalSeconds
                        }
                    }
                    Start-Sleep -Milliseconds 25
                }
            }
            finally {
                $service.Dispose()
                if ($null -ne $wizard) { $wizard.Dispose() }
            }
            return [pscustomobject]@{ Interrupted = $false; Seconds = [int]$clock.Elapsed.TotalSeconds }
        }

        if (-not $process.WaitForExit($setupTimeout * 1000)) { throw "$Scenario $Build setup timed out" }
        $text = Get-RosetunUpgradeLog -Path $log
        while ($text -notmatch 'Log closed\.' -and $clock.Elapsed.TotalSeconds -lt $setupTimeout) {
            Start-Sleep -Milliseconds 250
            $text = Get-RosetunUpgradeLog -Path $log
        }
        $code = $process.ExitCode
        $version = ([string](Get-Item -LiteralPath $setup).VersionInfo.ProductVersion).Trim()
        $installedVersion = if (Test-Path -LiteralPath $uninstallKey) {
            [string](Get-ItemProperty -LiteralPath $uninstallKey -Name 'DisplayVersion').DisplayVersion
        }
        $succeeded = $code -eq 0 -and $text -match 'Log closed\.' -and $text -match 'Installation process succeeded' -and
            $version -and $version -eq $installedVersion
        # The previous setup starts an unprotected service. Let its background traffic settle before opening the window.
        if ($Build -eq 'old' -and $succeeded) { Start-Sleep -Seconds 5 }
        return [pscustomobject]@{
            Succeeded = $succeeded; ExitCode = $code; Log = $text; Seconds = [int]$clock.Elapsed.TotalSeconds
            Version = $installedVersion
        }
    }
    finally { $process.Dispose() }
}

function Stop-RosetunUpgradeGui {
    Get-Process -Name 'rosetun-gui' -ErrorAction SilentlyContinue | ForEach-Object { Stop-RosetunUpgradeProcess -Process $_ }
}

function Test-RosetunInstallationAbsent {
    return (-not (Test-Path -LiteralPath $installDir) -and -not (Get-Service -Name 'Rosetun' -ErrorAction SilentlyContinue) -and
        -not (Test-Path -LiteralPath $uninstallKey) -and -not (Test-Path -LiteralPath $urlClass))
}

function Uninstall-RosetunUpgradeBuild {
    param([Parameter(Mandatory)][string]$Scenario)
    Stop-RosetunUpgradeGui
    if ([IO.File]::Exists($uninstaller)) {
        # Reset-firewall in the uninstaller can restart a service it found running.
        $service = Get-Service -Name 'Rosetun' -ErrorAction SilentlyContinue
        if ($null -ne $service) {
            try {
                if ($service.Status -ne 'Stopped') { Stop-Service -InputObject $service }
                $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
            }
            finally { $service.Dispose() }
        }
        $path = Join-Path $logs "$Scenario-uninstall.log"
        $process = Start-RosetunUpgradeProcess -FilePath $uninstaller `
            -Arguments "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG=`"$path`""
        try {
            if (-not $process.WaitForExit($setupTimeout * 1000)) { throw 'uninstaller process timed out' }
            if ($process.ExitCode -ne 0) { throw "uninstaller exited with code $($process.ExitCode)" }
            if (-not (Wait-RosetunUpgradeCondition -TimeoutSeconds $setupTimeout -Condition {
                -not [IO.File]::Exists($uninstaller) -and
                    -not (Get-Process -Name '_unins*', 'unins000*' -ErrorAction SilentlyContinue) -and
                    (Get-RosetunUpgradeLog -Path $path) -match 'Uninstallation process succeeded\.[\s\S]*Log closed\.'
            })) { throw 'uninstaller did not finish removing Rosetun' }
            if (Get-Service -Name 'Rosetun' -ErrorAction SilentlyContinue) { throw 'uninstaller left the Rosetun service' }
            # The install helper creates the directory before Inno copies its files.
            if ([IO.Directory]::Exists($installDir)) { [IO.Directory]::Delete($installDir) }
        }
        finally { $process.Dispose() }
    }
    if (-not (Test-RosetunInstallationAbsent)) { throw 'installed state remains after uninstall' }
}

function Start-RosetunUpgradeWatch {
    param([Parameter(Mandatory)][string]$Scenario)
    $script:watchLog = Join-Path $logs "$Scenario-watch.log"
    $range = $targetUrl + '?rosetun-egress-probe=[1-10000000]'
    $arguments = ('--noproxy "*" --interface {0} --max-time 2 --rate 300/m --silent --ssl-no-revoke --output NUL ' +
        '--write-out "%{{stderr}}%{{exitcode}}\n" "{1}"') -f $physical, $range
    $start = [Diagnostics.ProcessStartInfo]::new($curlPath, $arguments)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardError = $true
    $script:watchFile = [IO.FileStream]::new($script:watchLog, 'Create', 'Write', 'Read', 1)
    $script:watchProcess = [Diagnostics.Process]::Start($start)
    $script:watchDrain = $script:watchProcess.StandardError.BaseStream.CopyToAsync($script:watchFile)
    if (-not (Wait-RosetunUpgradeCondition -TimeoutSeconds 15 -Condition {
        (Get-RosetunUpgradeWatch).Probes -gt 0 -and -not $script:watchProcess.HasExited
    })) { throw 'egress watch did not record a probe' }
}

function Get-RosetunUpgradeWatch {
    $text = Get-RosetunUpgradeLog -Path $script:watchLog
    $lastNl = $text.LastIndexOf("`n")
    if ($lastNl -lt 0) { return [pscustomobject]@{ Probes = 0; Leaks = 0 } }
    $lines = @($text.Substring(0, $lastNl + 1) -split "`r?`n" | Where-Object { $_ -match '^\d+$' })
    return [pscustomobject]@{ Probes = $lines.Count; Leaks = @($lines | Where-Object { $_ -eq '0' }).Count }
}

function Stop-RosetunUpgradeWatch {
    try {
        if ($null -ne $script:watchProcess) {
            Stop-RosetunUpgradeProcess -Process $script:watchProcess
            if ($null -ne $script:watchDrain) { [void]$script:watchDrain.Wait(5000) }
        }
    }
    finally {
        if ($null -ne $script:watchProcess) { $script:watchProcess.Dispose(); $script:watchProcess = $null }
        if ($null -ne $script:watchFile) { $script:watchFile.Dispose(); $script:watchFile = $null }
        $script:watchDrain = $null
    }
}

function Open-RosetunUpgradeWindow {
    param([Parameter(Mandatory)][string]$Label)
    Set-RosetunRunnerStep -Step $Label
    $script:openWindow = $Label
    if (-not (Send-RosetunMarker -Plan $plan -Label $Label -Word 'open')) { throw 'opening marker did not reach the lab' }
}

function Close-RosetunUpgradeWindow {
    $label = $script:openWindow
    $script:openWindow = $null
    if (-not (Send-RosetunMarker -Plan $plan -Label $label -Word 'close')) { throw 'closing marker did not reach the lab' }
}

function Write-RosetunUpgradeRequests {
    $base = ConvertTo-Json -InputObject $plan.request -Depth 30
    foreach ($variant in @(@{ Path = $protectedRequest; KillSwitch = $true }, @{ Path = $openRequest; KillSwitch = $false })) {
        $request = $base | ConvertFrom-Json
        $request.settings | Add-Member -NotePropertyName kill_switch -NotePropertyValue $variant.KillSwitch -Force
        $request.settings | Add-Member -NotePropertyName allow_lan -NotePropertyValue $false -Force
        $request.settings | Add-Member -NotePropertyName auto_reconnect -NotePropertyValue $false -Force
        [IO.File]::WriteAllText($variant.Path, (ConvertTo-Json -InputObject $request -Depth 30))
    }
}

$recorder = $null
$runError = $false
$ownsInstallation = $false
$script:watchProcess = $null
$script:watchDrain = $null
$script:watchFile = $null
$script:watchLog = ''
$script:openWindow = $null
$parts = [ordered]@{}

try {
    Set-RosetunRunnerState -State running -Step 'prepare'
    New-Item -ItemType Directory -Force -Path $bin, $logs, $work | Out-Null
    $mediumRoot = $Medium + ':\'
    foreach ($file in $plan.files) {
        $name = [string]$file.name
        $target = Join-Path $bin $name
        Copy-Item -LiteralPath (Join-Path $mediumRoot $name) -Destination $target -Force
        if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne [string]$file.sha256 -or
            (Get-Item -LiteralPath $target).Length -ne [int64]$file.size) { throw "delivered file differs from the plan: $name" }
    }
    Add-RosetunRunnerNote -Name 'files-verified' -Value @($plan.files).Count
    $wfp = Get-RosetunUpgradeWfp
    if (-not (Test-RosetunInstallationAbsent) -or @($profileDirectories | Where-Object { Test-Path -LiteralPath $_ }).Count -or
        $wfp.Lockdown -or $wfp.LockdownSublayer -or $wfp.Hold -or $wfp.Session) {
        throw 'a previous installation or its state exists on the base image'
    }
    $ownsInstallation = $true
    Write-RosetunUpgradeRequests

    Import-Module (Join-Path $Root 'RosetunListResults.psm1') -Force
    $vmId = ([string](Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID).ToLowerInvariant()
    $recorder = New-RosetunListResults -Directory (Join-Path $Root 'results') -VmId $vmId `
        -BootId (Get-RosetunBootCounter) -Suite 'windows-upgrade' -Catalog @($plan.catalog)
    Set-RosetunRecorder -Recorder $recorder

    Open-RosetunUpgradeWindow 'baseline'
    Test-Step -Id 'baseline.egress' -Scenario 'baseline' -Expectation 'physical HTTPS reaches the lab target' {
        Test-RosetunUpgradeDirectEgress
    }
    Test-Step -Id 'baseline.dns' -Scenario 'baseline' -Expectation 'physical UDP DNS reaches the lab resolver' {
        Test-RosetunUpgradeDirectDns -Name $baselineDns
    }
    Close-RosetunUpgradeWindow

Set-RosetunRunnerStep -Step 'lockdown-old'
    $old = Invoke-RosetunUpgradeSetup -Build old -Scenario 'lockdown'
    Test-Step -Id 'lockdown.old-installed' -Scenario 'lockdown' -Expectation 'the old setup installs and serves requests' `
        -Note "exit $($old.ExitCode), seconds $($old.Seconds), version $($old.Version)" {
            $old.Succeeded -and (Wait-RosetunUpgradeCondition -Condition { Test-RosetunInstalledService })
        }
    Open-RosetunUpgradeWindow 'lockdown'
    $on = Invoke-RosetunInstalledCli -Arguments @('lockdown', 'on')
    Test-Step -Id 'lockdown.before-closed' -Scenario 'lockdown' -Expectation 'disconnected Lockdown blocks physical egress' {
        $on.ExitCode -eq 0 -and (Get-RosetunInstalledStatus) -match '(?m)^state: Disconnected\s*$' -and
            (Get-RosetunUpgradeWfp).Lockdown -and -not (Test-RosetunUpgradeDirectEgress)
    }
    Start-RosetunUpgradeWatch 'lockdown'
    $new = Invoke-RosetunUpgradeSetup -Build new -Scenario 'lockdown'
    Test-Step -Id 'lockdown.new-installed' -Scenario 'lockdown' -Expectation 'the new setup installs and serves requests' `
        -Note "exit $($new.ExitCode), seconds $($new.Seconds), version $($new.Version)" {
            $new.Succeeded -and $new.Version -ne $old.Version -and
                (Wait-RosetunUpgradeCondition -Condition { Test-RosetunInstalledService })
        }
    Test-Step -Id 'lockdown.setup-saw-lockdown' -Scenario 'lockdown' -Expectation 'setup detects Lockdown and adds no hold' {
        $new.Log -match 'The network is not held for the upgrade \(code 4\)|Lockdown is on and holds the network'
    }
    Test-Step -Id 'lockdown.status' -Scenario 'lockdown' -Expectation 'new service reports Lockdown without an upgrade hold' {
        $status = Get-RosetunInstalledStatus
        $status -match '(?m)^lockdown: on\s*$' -and $status -notmatch '(?m)^network: held closed'
    }
    Test-Step -Id 'lockdown.wfp' -Scenario 'lockdown' -Expectation 'Lockdown remains and the hold marker is absent' {
        $state = Get-RosetunUpgradeWfp
        $state.Lockdown -and $state.LockdownSublayer -and -not $state.Hold
    }
    Test-Step -Id 'lockdown.after-closed' -Scenario 'lockdown' -Expectation 'physical egress stays closed after upgrade' {
        -not (Test-RosetunUpgradeDirectEgress)
    }
    Stop-RosetunUpgradeWatch
    $watch = Get-RosetunUpgradeWatch
    Test-Step -Id 'lockdown.watch-closed' -Scenario 'lockdown' -Expectation 'no watch probes escape during upgrade' `
        -Note "$($watch.Leaks) of $($watch.Probes) escaped" { $watch.Probes -gt 0 -and $watch.Leaks -eq 0 }
    $off = Invoke-RosetunInstalledCli -Arguments @('lockdown', 'off')
    Close-RosetunUpgradeWindow
    # Re-enable Lockdown so uninstall still has to remove it.
    $on = Invoke-RosetunInstalledCli -Arguments @('lockdown', 'on')
    $beforeUninstall = Get-RosetunUpgradeWfp
    Uninstall-RosetunUpgradeBuild 'lockdown'
    Test-Step -Id 'lockdown.uninstall-clears' -Scenario 'lockdown' -Expectation 'uninstall removes persistent Lockdown objects' {
        $off.ExitCode -eq 0 -and $on.ExitCode -eq 0 -and $beforeUninstall.Lockdown -and (Test-RosetunNoUpgradeHold)
    }

    Set-RosetunRunnerStep -Step 'kill-switch-old'
    $old = Invoke-RosetunUpgradeSetup -Build old -Scenario 'kill-switch'
    Test-Step -Id 'kill-switch.old-installed' -Scenario 'kill switch' -Expectation 'the old setup installs and serves requests' `
        -Note "exit $($old.ExitCode), seconds $($old.Seconds), version $($old.Version)" {
            $old.Succeeded -and (Wait-RosetunUpgradeCondition -Condition { Test-RosetunInstalledService })
        }
    Open-RosetunUpgradeWindow 'kill-switch'
    Test-Step -Id 'kill-switch.before-connected' -Scenario 'kill switch' -Expectation 'the old service connects with kill switch on' {
        Connect-RosetunInstalled -Request $protectedRequest
    }
    Test-Step -Id 'kill-switch.before-closed' -Scenario 'kill switch' -Expectation 'physical egress is blocked before upgrade' {
        -not (Test-RosetunUpgradeDirectEgress)
    }
    Start-RosetunUpgradeWatch 'kill-switch'
    $new = Invoke-RosetunUpgradeSetup -Build new -Scenario 'kill-switch'
    Stop-RosetunUpgradeGui
    Test-Step -Id 'kill-switch.new-installed' -Scenario 'kill switch' -Expectation 'the new setup installs and serves requests' `
        -Note "exit $($new.ExitCode), seconds $($new.Seconds), version $($new.Version)" {
            $new.Succeeded -and $new.Version -ne $old.Version -and
                (Wait-RosetunUpgradeCondition -Condition { Test-RosetunInstalledService })
        }
    Test-Step -Id 'kill-switch.setup-placed-hold' -Scenario 'kill switch' -Expectation 'setup reports placing the hold' {
        $new.Log -match 'The network is held closed for the upgrade|upgrade hold placed'
    }
    Test-Step -Id 'kill-switch.gui-reconnect-launch' -Scenario 'kill switch' -Expectation 'setup launches the GUI to reconnect' {
        $new.Log -match 'Started the GUI to reconnect after the upgrade'
    }
    Test-Step -Id 'kill-switch.hold-status' -Scenario 'kill switch' -Expectation 'the new service reports hold without Lockdown' {
        $status = Get-RosetunInstalledStatus
        $status -match '(?m)^lockdown: off\s*$' -and $status -match '(?m)^network: held closed'
    }
    Test-Step -Id 'kill-switch.hold-wfp' -Scenario 'kill switch' -Expectation 'the persistent upgrade hold marker exists' {
        $state = Get-RosetunUpgradeWfp
        $state.Hold -and $state.Lockdown -and $state.LockdownSublayer
    }
    Test-Step -Id 'kill-switch.after-closed' -Scenario 'kill switch' -Expectation 'physical egress is blocked by the hold' {
        -not (Test-RosetunUpgradeDirectEgress)
    }
    $watchBeforeReconnect = Get-RosetunUpgradeWatch
    Test-Step -Id 'kill-switch.upgrade-closed' -Scenario 'kill switch' -Expectation 'no watch probes escape during setup' `
        -Note "$($watchBeforeReconnect.Leaks) of $($watchBeforeReconnect.Probes) escaped" {
            $watchBeforeReconnect.Probes -gt 0 -and $watchBeforeReconnect.Leaks -eq 0
        }
    Test-Step -Id 'kill-switch.reconnect' -Scenario 'kill switch' -Expectation 'the new service reconnects with the kill switch' {
        Connect-RosetunInstalled -Request $protectedRequest
    }
    Test-Step -Id 'kill-switch.tunnel' -Scenario 'kill switch' -Expectation 'the new tunnel carries lab traffic' {
        Wait-RosetunUpgradeCondition -TimeoutSeconds 25 -Condition { Test-RosetunUpgradeTunnel }
    }
    Test-Step -Id 'kill-switch.hold-lifted' -Scenario 'kill switch' -Expectation 'reconnect lifts the hold without turning on Lockdown' {
        $status = Get-RosetunInstalledStatus
        $status -match '(?m)^lockdown: off\s*$' -and $status -notmatch '(?m)^network: held closed' -and
            (Test-RosetunNoUpgradeHold)
    }
    Test-Step -Id 'kill-switch.reconnect-direct-closed' -Scenario 'kill switch' -Expectation 'the reconnected kill switch blocks physical egress' {
        -not (Test-RosetunUpgradeDirectEgress)
    }
    Stop-RosetunUpgradeWatch
    $watch = Get-RosetunUpgradeWatch
    Test-Step -Id 'kill-switch.reconnect-closed' -Scenario 'kill switch' -Expectation 'no watch probes escape while reconnecting' `
        -Note "$($watch.Leaks) of $($watch.Probes) escaped across setup and reconnect" {
            $watch.Probes -gt $watchBeforeReconnect.Probes -and $watch.Leaks -eq 0
        }
    $disconnect = Invoke-RosetunInstalledCli -Arguments @('disconnect')
    Close-RosetunUpgradeWindow
    Test-Step -Id 'kill-switch.disconnect-opens' -Scenario 'kill switch' -Expectation 'disconnect restores direct egress' {
        $disconnect.ExitCode -eq 0 -and (Wait-RosetunUpgradeCondition -TimeoutSeconds 15 -Condition {
            Test-RosetunUpgradeDirectEgress
        })
    }
    Uninstall-RosetunUpgradeBuild 'kill-switch'

Set-RosetunRunnerStep -Step 'no-kill-switch-old'
    $old = Invoke-RosetunUpgradeSetup -Build old -Scenario 'no-kill-switch'
    Test-Step -Id 'no-kill-switch.old-installed' -Scenario 'no kill switch' -Expectation 'the old setup installs and serves requests' `
        -Note "exit $($old.ExitCode), seconds $($old.Seconds), version $($old.Version)" {
            $old.Succeeded -and (Wait-RosetunUpgradeCondition -Condition { Test-RosetunInstalledService })
        }
    Open-RosetunUpgradeWindow 'no-kill-switch'
    Test-Step -Id 'no-kill-switch.before-connected' -Scenario 'no kill switch' -Expectation 'the old service connects without a kill switch' {
        Connect-RosetunInstalled -Request $openRequest
    }
    $new = Invoke-RosetunUpgradeSetup -Build new -Scenario 'no-kill-switch'
    Test-Step -Id 'no-kill-switch.direct-open' -Scenario 'no kill switch' -Expectation 'direct egress is open after setup' {
        Test-RosetunUpgradeDirectEgress
    }
    Close-RosetunUpgradeWindow
    Test-Step -Id 'no-kill-switch.new-installed' -Scenario 'no kill switch' -Expectation 'the new setup installs and serves requests' `
        -Note "exit $($new.ExitCode), seconds $($new.Seconds), version $($new.Version)" {
            $new.Succeeded -and $new.Version -ne $old.Version -and
                (Wait-RosetunUpgradeCondition -Condition { Test-RosetunInstalledService })
        }
    Test-Step -Id 'no-kill-switch.setup-skips-hold' -Scenario 'no kill switch' -Expectation 'setup reports no hold without kill switch' {
        $new.Log -match 'The network is not held for the upgrade \(code 3\)|no kill switch is on; the network is not held'
    }
    Test-Step -Id 'no-kill-switch.no-reconnect-launch' -Scenario 'no kill switch' -Expectation 'setup does not try to launch the GUI to reconnect' {
        $new.Log -notmatch 'the GUI (?:to reconnect|after the upgrade)' -and
            -not (Get-Process -Name 'rosetun-gui' -ErrorAction SilentlyContinue)
    }
    Test-Step -Id 'no-kill-switch.no-protection' -Scenario 'no kill switch' -Expectation 'new service and WFP report neither Lockdown nor hold' {
        $status = Get-RosetunInstalledStatus
        $status -match '(?m)^lockdown: off\s*$' -and $status -notmatch '(?m)^network: held closed' -and (Test-RosetunNoUpgradeHold)
    }
    Uninstall-RosetunUpgradeBuild 'no-kill-switch'

    Set-RosetunRunnerStep -Step 'broken-old'
    $old = Invoke-RosetunUpgradeSetup -Build old -Scenario 'broken'
    Test-Step -Id 'broken.old-installed' -Scenario 'broken' -Expectation 'the old setup installs and serves requests' `
        -Note "exit $($old.ExitCode), seconds $($old.Seconds), version $($old.Version)" {
            $old.Succeeded -and (Wait-RosetunUpgradeCondition -Condition { Test-RosetunInstalledService })
        }
    Open-RosetunUpgradeWindow 'broken'
    Test-Step -Id 'broken.before-connected' -Scenario 'broken' -Expectation 'the old service connects with a kill switch' {
        Connect-RosetunInstalled -Request $protectedRequest
    }
    Test-Step -Id 'broken.before-closed' -Scenario 'broken' -Expectation 'the kill switch blocks egress before setup' {
        -not (Test-RosetunUpgradeDirectEgress)
    }
    Start-RosetunUpgradeWatch 'broken'
    $broken = Invoke-RosetunUpgradeSetup -Build new -Scenario 'broken' -Interrupt
    Test-Step -Id 'broken.interrupted-held' -Scenario 'broken' -Expectation 'setup is interrupted after placing the hold and stopping the old service' `
        -Note "seconds $($broken.Seconds)" { $broken.Interrupted }
    Start-Sleep -Seconds 20
    Test-Step -Id 'broken.after-closed' -Scenario 'broken' -Expectation 'physical egress stays closed after interrupted setup' {
        -not (Test-RosetunUpgradeDirectEgress)
    }
    Stop-RosetunUpgradeWatch
    $watch = Get-RosetunUpgradeWatch
    Test-Step -Id 'broken.watch-closed' -Scenario 'broken' -Expectation 'no watch probes escape during or after interrupted setup' `
        -Note "$($watch.Leaks) of $($watch.Probes) escaped" { $watch.Probes -gt 0 -and $watch.Leaks -eq 0 }
    Stop-RosetunSetupProcesses
    $reset = Invoke-RosetunNative -FilePath $cliPath -Arguments @('reset-firewall') -TimeoutSeconds 30
    Close-RosetunUpgradeWindow
    Test-Step -Id 'broken.reset-succeeds' -Scenario 'broken' -Expectation 'the external CLI reset-firewall succeeds' `
        -Note "exit $($reset.ExitCode)" { $reset.ExitCode -eq 0 }
    Test-Step -Id 'broken.reset-clears' -Scenario 'broken' -Expectation 'reset removes the upgrade hold and Lockdown WFP objects' {
        Test-RosetunNoUpgradeHold
    }
    Test-Step -Id 'broken.reset-opens' -Scenario 'broken' -Expectation 'reset restores direct egress' {
        Wait-RosetunUpgradeCondition -TimeoutSeconds 25 -Condition { Test-RosetunUpgradeDirectEgress }
    }
    Uninstall-RosetunUpgradeBuild 'broken'
}
catch {
    $runError = $true
    Set-RosetunRunnerError -Place $script:RunnerStatus.step -Text ($_.Exception.GetType().Name + ': ' + $_.Exception.Message)
}
finally {
    Set-RosetunRunnerState -State cleaning -Step 'cleanup'
    if ($ownsInstallation) {
        $parts['processes'] = 'ERROR'
        try {
            Stop-RosetunUpgradeWatch
            Stop-RosetunSetupProcesses
            Stop-RosetunUpgradeGui
            $parts['processes'] = 'PASS'
        }
        catch { Set-RosetunRunnerError -Place 'cleanup' -Text "stopping setup processes failed: $_" }

        $parts['firewall'] = 'ERROR'
        try {
            $reset = Invoke-RosetunNative -FilePath $helperPath -Arguments @('--reset-firewall') -TimeoutSeconds 30
            if ($null -ne $script:openWindow) { Close-RosetunUpgradeWindow }
            if ($reset.ExitCode -eq 0 -and (Test-RosetunNoUpgradeHold) -and -not (Get-RosetunUpgradeWfp).Session) {
                $parts['firewall'] = 'PASS'
            }
        }
        catch { Set-RosetunRunnerError -Place 'cleanup' -Text "firewall reset failed: $_" }

        $parts['installation'] = 'ERROR'
        try {
            Uninstall-RosetunUpgradeBuild 'cleanup'
            if (-not (Get-Process -Name 'rosetun-helper-privileged', 'sing-box', 'xray' -ErrorAction SilentlyContinue) -and
                -not (Get-NetAdapter -Name $tunAlias -ErrorAction SilentlyContinue)) { $parts['installation'] = 'PASS' }
        }
        catch { Set-RosetunRunnerError -Place 'cleanup' -Text "uninstall failed: $_" }

        $parts['profile'] = 'ERROR'
        try {
            foreach ($directory in $profileDirectories) {
                if (Test-Path -LiteralPath $directory) { Remove-Item -LiteralPath $directory -Recurse -Force }
            }
            $parts['profile'] = 'PASS'
        }
        catch { Set-RosetunRunnerError -Place 'cleanup' -Text "remove setup profile state failed: $_" }
    }
    else { $parts['installation'] = 'UNVERIFIED' }

    if (-not $runError) {
        try {
            Open-RosetunUpgradeWindow 'recovery'
            Test-Step -Id 'recovery.egress' -Scenario 'recovery' -Expectation 'physical HTTPS works after cleanup' {
                Test-RosetunUpgradeDirectEgress
            }
            Test-Step -Id 'recovery.dns' -Scenario 'recovery' -Expectation 'physical UDP DNS works after cleanup' {
                Test-RosetunUpgradeDirectDns -Name $recoveryDns
            }
            Close-RosetunUpgradeWindow
        }
        catch {
            $runError = $true
            Set-RosetunRunnerError -Place 'recovery' -Text ($_.Exception.GetType().Name + ': ' + $_.Exception.Message)
        }
    }
    Remove-Item -LiteralPath $work, $bin -Recurse -Force -ErrorAction SilentlyContinue
    $parts['files'] = if ((Test-Path -LiteralPath $work) -or (Test-Path -LiteralPath $bin)) { 'ERROR' } else { 'PASS' }
    $cleanupResult = if ($parts.Values -contains 'ERROR') { 'ERROR' }
        elseif ($parts.Values -contains 'UNVERIFIED') { 'UNVERIFIED' }
        else { 'PASS' }
    Set-RosetunRunnerCleanup -Result $cleanupResult -Parts $parts
    if ($null -ne $recorder) {
        try {
            Complete-RosetunListResults -Recorder $recorder -Cleanup $cleanupResult `
                -EndBootId (Get-RosetunBootCounter) -Aborted $runError
        }
        catch {
            $runError = $true
            Set-RosetunRunnerError -Place 'finalize' -Text ($_.Exception.GetType().Name + ': ' + $_.Exception.Message)
        }
    }
    Set-RosetunRunnerState -State $(if ($runError) { 'failed' } else { 'finished' }) -Step 'done'
}
