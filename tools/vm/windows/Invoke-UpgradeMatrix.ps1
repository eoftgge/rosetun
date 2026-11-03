# Runs the upgrade matrix in the Hyper-V test VM and prints a PASS/FAIL
# table: setup of the current build over the previous one, silently, under
# Lockdown, under the kill switch, without it, and an upgrade that breaks
# off. Exits with 1 if any check fails. The owner runs it.
#
# Each scenario installs the previous build, sets up its state with that
# build's CLI, starts the egress watch (curl bound to the physical adapter
# every 200 ms; any answer is a leak), runs the current setup and checks
# the result. The GUI the setup starts with --after-upgrade is recorded and
# stopped: the matrix reconnects with the CLI. `finally` uninstalls and runs
# `--reset-firewall`; if the run is killed before that, see README.md.

param(
    # Setups built by installer\build.ps1: the previous release and HEAD.
    [Parameter(Mandatory)][string]$PreviousSetup,
    [Parameter(Mandatory)][string]$CurrentSetup,
    [Parameter(Mandatory)][string]$SingBoxPath,
    [Parameter(Mandatory)][string]$RequestPath,
    [string]$BuildDir,
    [switch]$RestoreCheckpoint,
    [switch]$UseHostNode,
    [string]$NodeBindInterface,
    # Builds the workspace first: the CLI and helper in the guest's working
    # folder, used for requests and for `reset-firewall` after a broken upgrade.
    [switch]$Build,
    [int]$SetupTimeoutSeconds = 600
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
if (-not $BuildDir) { $BuildDir = Join-Path $RepoRoot 'target\release' }
Import-Module (Join-Path $PSScriptRoot 'RosetunVm.psm1') -Force
Assert-RosetunHostLockdownOff

foreach ($setup in $PreviousSetup, $CurrentSetup) {
    if (-not (Test-Path -LiteralPath $setup -PathType Leaf)) { throw "No setup at $setup." }
}

$results = [System.Collections.Generic.List[object]]::new()
$guestDir = Get-RosetunGuestDir
$upgradeDir = Join-Path $guestDir 'upgrade'
# Fixed forever in crates/rosetun-routing/src/platform/windows/lockdown.rs.
$lockdownProviderKey = 'f12dbedd-f3c7-4a72-b0f8-20559c88b112'
$holdProviderKey = '496d09fa-1d9a-451b-871f-35ba72197795'
# The status fields read here exist from this protocol on.
$protocolVersion = 16

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

function Copy-Setups {
    $session = Connect-RosetunVm
    Invoke-RosetunGuest -ScriptBlock {
        param($dir)
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    } -ArgumentList $upgradeDir
    Copy-Item -ToSession $session -Path $PreviousSetup -Destination (Join-Path $upgradeDir 'previous-setup.exe') -Force
    Copy-Item -ToSession $session -Path $CurrentSetup -Destination (Join-Path $upgradeDir 'current-setup.exe') -Force
}

function New-UpgradeRequests {
    # request.json with the kill switch on and off; auto-reconnect stays off,
    # as Publish-Rosetun sets it. Built on the host by the function
    # tests\Test-RosetunUpgradeRequests.ps1 checks without a VM.
    $source = [string](Invoke-RosetunGuest -ScriptBlock {
            param($path)
            Get-Content -Raw -LiteralPath $path
        } -ArgumentList (Join-Path $guestDir 'request.json'))
    foreach ($killSwitch in $true, $false) {
        $name = if ($killSwitch) { 'request-upgrade-kill-switch.json' } else { 'request-upgrade-open.json' }
        $json = New-RosetunUpgradeRequest -Json $source -KillSwitch $killSwitch
        Invoke-RosetunGuest -ScriptBlock {
            param($path, $json)
            # Without a BOM: serde_json rejects one.
            [IO.File]::WriteAllText($path, $json)
        } -ArgumentList (Join-Path $guestDir $name), $json
    }
}

function Invoke-Setup {
    # Runs a setup silently and waits for it. -Background returns at once
    # with the process, for the broken upgrade.
    param(
        [Parameter(Mandatory)][ValidateSet('previous', 'current')][string]$Build,
        [Parameter(Mandatory)][string]$LogName,
        [switch]$Background
    )
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $build, $logName, $background, $timeout)
        $setup = Join-Path $dir "$build-setup.exe"
        $log = Join-Path $dir "$logName.log"
        Remove-Item -LiteralPath $log -ErrorAction SilentlyContinue
        $process = Start-Process -FilePath $setup -PassThru `
            -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/LOG=`"$log`""
        if ($background) { return [pscustomobject]@{ Id = $process.Id; ExitCode = $null } }
        if (-not $process.WaitForExit($timeout * 1000)) {
            throw "$build setup did not finish within $timeout s."
        }
        [pscustomobject]@{ Id = $process.Id; ExitCode = $process.ExitCode }
    } -ArgumentList $upgradeDir, $Build, $LogName, [bool]$Background, $SetupTimeoutSeconds
}

function Get-SetupLog {
    param([Parameter(Mandatory)][string]$LogName)
    Invoke-RosetunGuest -ScriptBlock {
        param($path)
        Get-Content -Raw -LiteralPath $path -ErrorAction SilentlyContinue
    } -ArgumentList (Join-Path $upgradeDir "$LogName.log")
}

function Invoke-InstalledCli {
    # The CLI of whichever build is installed, which speaks its service's protocol.
    param([Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$Arguments)
    Invoke-RosetunGuest -ScriptBlock {
        param([string[]]$cliArgs)
        $encoding = [Console]::OutputEncoding
        [Console]::OutputEncoding = [Text.Encoding]::UTF8
        try {
            $output = & "$env:ProgramFiles\Rosetun\rosetun.exe" @cliArgs 2>&1 | ForEach-Object { "$_" }
            $exitCode = $LASTEXITCODE
            $global:LASTEXITCODE = 0
            [pscustomobject]@{ ExitCode = $exitCode; Output = ($output -join "`n") }
        }
        finally {
            [Console]::OutputEncoding = $encoding
        }
    } -ArgumentList (, $Arguments)
}

function Get-InstalledState {
    $result = Invoke-InstalledCli 'status'
    if ($result.Output -match '(?m)^state: (\w+)') { return $Matches[1] }
    "unknown (exit $($result.ExitCode))"
}

function Wait-InstalledState {
    param([Parameter(Mandatory)][string]$Expected, [int]$TimeoutSeconds = 60)
    Wait-RosetunCondition { (Get-InstalledState) -eq $Expected } -TimeoutSeconds $TimeoutSeconds
}

function Connect-Installed {
    param([Parameter(Mandatory)][string]$RequestName)
    $result = Invoke-InstalledCli 'connect' (Join-Path $guestDir $RequestName)
    if ($result.ExitCode -ne 0) { throw "connect failed: $($result.Output)" }
}

function Wait-InstalledService {
    Invoke-RosetunGuest -ScriptBlock {
        $deadline = (Get-Date).AddSeconds(60)
        while ((Get-Date) -lt $deadline) {
            $service = Get-Service -Name 'Rosetun' -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq 'Running' -and (Test-Path '\\.\pipe\rosetun-helper')) {
                return $true
            }
            Start-Sleep -Milliseconds 500
        }
        $false
    }
}

function Get-UpgradeGui {
    # The command line of a GUI the setup started, or $null.
    Invoke-RosetunGuest -ScriptBlock {
        $gui = @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'rosetun-gui.exe'")
        if ($gui.Count -gt 0) { $gui[0].CommandLine } else { $null }
    }
}

function Stop-UpgradeGui {
    Invoke-RosetunGuest -ScriptBlock {
        Stop-Process -Name 'rosetun-gui' -Force -ErrorAction SilentlyContinue
    }
}

function Wait-UpgradeGui {
    # [Run] starts it with nowait, so it may come a moment after setup exits.
    $commandLine = $null
    $deadline = (Get-Date).AddSeconds(15)
    while (-not $commandLine -and (Get-Date) -lt $deadline) {
        $commandLine = Get-UpgradeGui
        if (-not $commandLine) { Start-Sleep -Milliseconds 500 }
    }
    $commandLine
}

function Uninstall-Rosetun {
    # The uninstaller runs --reset-firewall itself; a broken install may have
    # none, so the working folder's helper cleans up after it.
    Invoke-RosetunGuest -ScriptBlock {
        $uninstaller = "$env:ProgramFiles\Rosetun\unins000.exe"
        if (Test-Path -LiteralPath $uninstaller) {
            $process = Start-Process -FilePath $uninstaller -PassThru `
                -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART'
            if (-not $process.WaitForExit(300000)) { throw 'The uninstaller did not finish within 300 s.' }
            # The uninstaller copies itself to TEMP and returns before that copy ends.
            $deadline = (Get-Date).AddSeconds(120)
            while ((Test-Path -LiteralPath $uninstaller) -and (Get-Date) -lt $deadline) {
                Start-Sleep -Milliseconds 500
            }
        }
        Stop-Process -Name 'rosetun-gui' -Force -ErrorAction SilentlyContinue
    }
    $reset = Invoke-RosetunHelperMode '--reset-firewall'
    if ($reset.ExitCode -ne 0) { throw "--reset-firewall after uninstall failed: $($reset.Output)" }
}

function Get-HoldStatus {
    Get-RosetunStatus -ProtocolVersion $protocolVersion
}

function Start-Watch {
    Start-RosetunEgressWatch
    $script:watchActive = $true
}

function Stop-Watch {
    $script:watchActive = $false
    Stop-RosetunEgressWatch
}

function Format-Watch {
    param([Parameter(Mandatory)]$Watch)
    "$($Watch.Leaks) of $($Watch.Probes) probes got out"
}

$nodeStarted = $false
$watchActive = $false
try {
    if ($Build) {
        Write-Host 'Building...'
        & cargo build -q --release --manifest-path (Join-Path $RepoRoot 'Cargo.toml')
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

    Write-Host 'Deploying the working folder and the setups...'
    # The console helper would take the service's pipe; the installed service runs instead.
    Stop-RosetunHelper
    Publish-Rosetun -BuildDir $BuildDir -SingBoxPath $SingBoxPath -RequestPath $RequestPath -UseHostNode:$UseHostNode
    $reset = Invoke-RosetunHelperMode '--reset-firewall'
    if ($reset.ExitCode -ne 0) { throw "Initial --reset-firewall failed: $($reset.Output)" }
    Copy-Setups
    New-UpgradeRequests
    Restore-RosetunGuestLease
    Test-Step '0 baseline' 'direct egress works' { Test-RosetunDirectEgress }

    # 1. Lockdown on, disconnected: Lockdown holds the network itself.
    $scenario = '1 Lockdown'
    $previous = Invoke-Setup -Build previous -LogName 'lockdown-previous'
    Test-Step $scenario 'the previous build installs' { $previous.ExitCode -eq 0 } -Note "exit $($previous.ExitCode)"
    Test-Step $scenario 'its service runs' { Wait-InstalledService }
    $lockdown = Invoke-InstalledCli 'lockdown' 'on'
    Test-Step $scenario 'Lockdown turns on' { $lockdown.ExitCode -eq 0 } -Note $lockdown.Output
    Test-Step $scenario 'direct egress is blocked before the upgrade' { -not (Test-RosetunDirectEgress) }
    Start-Watch
    $current = Invoke-Setup -Build current -LogName 'lockdown-current'
    $watch = Stop-Watch
    Stop-UpgradeGui
    Test-Step $scenario 'the current build installs over it' { $current.ExitCode -eq 0 } -Note "exit $($current.ExitCode)"
    Test-Step $scenario 'nothing got out during the upgrade' {
        $watch.Probes -gt 0 -and $watch.Leaks -eq 0
    } -Note (Format-Watch $watch)
    Test-Step $scenario 'setup saw Lockdown and placed no hold' {
        (Get-SetupLog 'lockdown-current') -match 'Lockdown is on and holds the network'
    }
    Test-Step $scenario 'its service runs' { Wait-InstalledService }
    $status = Get-HoldStatus
    Test-Step $scenario 'Lockdown is still on, and no hold' {
        $status.lockdown -and -not $status.upgrade_hold
    } -Note "lockdown=$($status.lockdown) upgrade_hold=$($status.upgrade_hold)"
    Test-Step $scenario 'no hold marker' { -not (Test-RosetunGuestWfpKey -Key $holdProviderKey) }
    Test-Step $scenario 'direct egress is still blocked' { -not (Test-RosetunDirectEgress) }
    Uninstall-Rosetun
    Test-Step $scenario 'uninstall removes Lockdown' { -not (Test-RosetunGuestWfpKey -Key $lockdownProviderKey) }

    # 2. Connected with the kill switch, no Lockdown: the hold closes the gap
    # between the old service stopping and the new one connecting.
    $scenario = '2 kill switch'
    $previous = Invoke-Setup -Build previous -LogName 'kill-switch-previous'
    Test-Step $scenario 'the previous build installs' { $previous.ExitCode -eq 0 } -Note "exit $($previous.ExitCode)"
    Test-Step $scenario 'its service runs' { Wait-InstalledService }
    Connect-Installed 'request-upgrade-kill-switch.json'
    Test-Step $scenario 'connected before the upgrade' { Wait-InstalledState 'connected' }
    Test-Step $scenario 'direct egress is blocked before the upgrade' { -not (Test-RosetunDirectEgress) }
    Start-Watch
    $current = Invoke-Setup -Build current -LogName 'kill-switch-current'
    $gui = Wait-UpgradeGui
    $watch = Stop-Watch
    Stop-UpgradeGui
    Test-Step $scenario 'the current build installs over it' { $current.ExitCode -eq 0 } -Note "exit $($current.ExitCode)"
    Test-Step $scenario 'nothing got out during the upgrade' {
        $watch.Probes -gt 0 -and $watch.Leaks -eq 0
    } -Note (Format-Watch $watch)
    Test-Step $scenario 'setup placed the hold' {
        (Get-SetupLog 'kill-switch-current') -match 'upgrade hold placed'
    }
    Test-Step $scenario 'setup starts the GUI with --after-upgrade' { "$gui" -match '--after-upgrade' } -Note "$gui"
    Test-Step $scenario 'its service runs' { Wait-InstalledService }
    $status = Get-HoldStatus
    Test-Step $scenario 'the service reports the hold, not Lockdown' {
        $status.upgrade_hold -and -not $status.lockdown
    } -Note "lockdown=$($status.lockdown) upgrade_hold=$($status.upgrade_hold)"
    Test-Step $scenario 'the hold marker exists' { Test-RosetunGuestWfpKey -Key $holdProviderKey }
    Test-Step $scenario 'direct egress is blocked after the upgrade' { -not (Test-RosetunDirectEgress) }
    Start-Watch
    Connect-Installed 'request-upgrade-kill-switch.json'
    Test-Step $scenario 'connected again' { Wait-InstalledState 'connected' }
    Test-Step $scenario 'traffic goes through the tunnel' { Test-RosetunTunnelEgress -SkipRevocationCheck }
    $watch = Stop-Watch
    Test-Step $scenario 'nothing got out while the hold was lifted' {
        $watch.Probes -gt 0 -and $watch.Leaks -eq 0
    } -Note (Format-Watch $watch)
    $status = Get-HoldStatus
    Test-Step $scenario 'the hold is lifted' {
        -not $status.upgrade_hold -and -not $status.lockdown
    } -Note "lockdown=$($status.lockdown) upgrade_hold=$($status.upgrade_hold)"
    Test-Step $scenario 'no hold marker and no Lockdown objects' {
        -not (Test-RosetunGuestWfpKey -Key $holdProviderKey) -and
        -not (Test-RosetunGuestWfpKey -Key $lockdownProviderKey)
    }
    Test-Step $scenario 'direct egress is still blocked by the kill switch' { -not (Test-RosetunDirectEgress) }
    Invoke-InstalledCli 'disconnect' | Out-Null
    Test-Step $scenario 'direct egress works after a disconnect' {
        Wait-RosetunCondition { Test-RosetunDirectEgress } -TimeoutSeconds 15
    }
    Uninstall-Rosetun

    # 3. Connected without the kill switch: nothing was closed, so nothing is
    # held. The upgrade's window is the expected leak, recorded, not failed.
    $scenario = '3 no kill switch'
    $previous = Invoke-Setup -Build previous -LogName 'open-previous'
    Test-Step $scenario 'the previous build installs' { $previous.ExitCode -eq 0 } -Note "exit $($previous.ExitCode)"
    Test-Step $scenario 'its service runs' { Wait-InstalledService }
    Connect-Installed 'request-upgrade-open.json'
    Test-Step $scenario 'connected before the upgrade' { Wait-InstalledState 'connected' }
    Start-Watch
    $current = Invoke-Setup -Build current -LogName 'open-current'
    $gui = Get-UpgradeGui
    $watch = Stop-Watch
    Stop-UpgradeGui
    Test-Step $scenario 'the current build installs over it' { $current.ExitCode -eq 0 } -Note "exit $($current.ExitCode)"
    Add-Info $scenario 'direct egress during the upgrade (expected without the kill switch)' (Format-Watch $watch)
    Test-Step $scenario 'setup placed no hold' {
        (Get-SetupLog 'open-current') -match 'no kill switch is on; the network is not held'
    }
    Test-Step $scenario 'no GUI with --after-upgrade' { "$gui" -notmatch '--after-upgrade' } -Note "$gui"
    Test-Step $scenario 'its service runs' { Wait-InstalledService }
    $status = Get-HoldStatus
    Test-Step $scenario 'no hold and no Lockdown' {
        -not $status.upgrade_hold -and -not $status.lockdown
    } -Note "lockdown=$($status.lockdown) upgrade_hold=$($status.upgrade_hold)"
    Test-Step $scenario 'direct egress works' { Test-RosetunDirectEgress }
    Uninstall-Rosetun

    # 4. Connected with the kill switch, and the upgrade breaks off once the
    # hold is placed and the old service is gone: closed, and reset-firewall
    # opens it.
    $scenario = '4 broken upgrade'
    $previous = Invoke-Setup -Build previous -LogName 'broken-previous'
    Test-Step $scenario 'the previous build installs' { $previous.ExitCode -eq 0 } -Note "exit $($previous.ExitCode)"
    Test-Step $scenario 'its service runs' { Wait-InstalledService }
    Connect-Installed 'request-upgrade-kill-switch.json'
    Test-Step $scenario 'connected before the upgrade' { Wait-InstalledState 'connected' }
    Start-Watch
    $current = Invoke-Setup -Build current -LogName 'broken-current' -Background
    $broken = Invoke-RosetunGuest -ScriptBlock {
        param($setupId, $holdKey)
        $path = Join-Path $env:TEMP 'rosetun-upgrade-wfp.xml'
        $deadline = (Get-Date).AddSeconds(120)
        $held = $false
        while (-not $held -and (Get-Date) -lt $deadline) {
            $service = Get-Service -Name 'Rosetun' -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq 'Stopped') {
                & netsh.exe wfp show state "file=$path" *> $null
                $held = (Get-Content -Raw -LiteralPath $path -ErrorAction SilentlyContinue) -match [regex]::Escape($holdKey)
                $global:LASTEXITCODE = 0
            }
            if (-not $held) { Start-Sleep -Milliseconds 200 }
        }
        Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue
        # Setup runs its wizard in a child process; both go.
        $children = @(Get-CimInstance -ClassName Win32_Process -Filter "ParentProcessId = $setupId")
        Stop-Process -Id $setupId -Force -ErrorAction SilentlyContinue
        foreach ($child in $children) { Stop-Process -Id $child.ProcessId -Force -ErrorAction SilentlyContinue }
        $held
    } -ArgumentList $current.Id, $holdProviderKey
    Test-Step $scenario 'setup placed the hold and stopped the service before it broke off' { $broken }
    # A while closed, not only at the moment the setup died.
    Start-Sleep -Seconds 20
    $watch = Stop-Watch
    Test-Step $scenario 'nothing got out during and after the broken upgrade' {
        $watch.Probes -gt 0 -and $watch.Leaks -eq 0
    } -Note (Format-Watch $watch)
    Test-Step $scenario 'direct egress is blocked' { -not (Test-RosetunDirectEgress) }
    $reset = Invoke-RosetunCli -Quiet 'reset-firewall'
    Test-Step $scenario 'rosetun reset-firewall succeeds' { $reset.ExitCode -eq 0 } -Note $reset.Output
    Test-Step $scenario 'no hold marker and no Lockdown objects' {
        -not (Test-RosetunGuestWfpKey -Key $holdProviderKey) -and
        -not (Test-RosetunGuestWfpKey -Key $lockdownProviderKey)
    }
    Test-Step $scenario 'direct egress works again' {
        Wait-RosetunCondition { Test-RosetunDirectEgress } -TimeoutSeconds 30
    }
    Uninstall-Rosetun
}
catch {
    Test-Step 'run' 'completes without an error' { $false } -Note "$_"
}
finally {
    if ($watchActive) {
        try { Stop-Watch | Out-Null } catch { Write-Warning "Could not stop the egress watch: $_" }
    }
    try {
        Invoke-RosetunGuest -ScriptBlock {
            # The setup and the wizard it runs from TEMP (`<name>.tmp`).
            Stop-Process -Name 'previous-setup*', 'current-setup*' -Force -ErrorAction SilentlyContinue
        }
    }
    catch { Write-Warning "Could not stop a setup: $_" }
    try { Uninstall-Rosetun } catch { Write-Warning "Could not uninstall Rosetun: $_" }
    $clean = $false
    try {
        $clean = -not (Test-RosetunGuestWfpKey -Key $lockdownProviderKey) -and
            -not (Test-RosetunGuestWfpKey -Key $holdProviderKey)
    }
    catch { Write-Warning "$_" }
    Test-Step 'cleanup' 'no Lockdown objects and no hold marker are left' { $clean }
    if (-not $clean) {
        Write-Warning "The guest may have no network. Run '$guestDir\rosetun-helper-privileged.exe --reset-firewall' in the guest as administrator."
    }
    try {
        Invoke-RosetunGuest -ScriptBlock {
            param($dir)
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        } -ArgumentList $upgradeDir
    }
    catch { Write-Warning "Could not remove ${upgradeDir}: $_" }
    try {
        Register-RosetunHelper
        Start-RosetunHelper
    }
    catch { Write-Warning "Could not start the helper again: $_" }
    if ($nodeStarted) {
        try { Stop-RosetunTestNode } catch { Write-Warning "Could not stop the host test node: $_" }
    }
}

# Result first, so a long note cannot push it off the screen.
$results | Format-Table Result, Scenario, Check, Note -AutoSize -Wrap

if ($results.Result -contains 'FAIL') {
    exit 1
}
exit 0
