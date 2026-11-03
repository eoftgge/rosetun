#Requires -Version 7.0
# Linux L2 stand, host side. The owner runs it; the agent only prepares it.
#
#   Stage   (default) builds HEAD in WSL (or takes -ArtifactDir), checks the selected
#                     VM and guest, copies the run to the guest and starts it through
#                     the installed launcher, or prints the one command the owner
#                     runs there with sudo when the launcher cannot.
#   Collect           reads the status and report of a run back and judges it.
#   InitKnownHosts    pins the guest's host key once, after the owner compared its
#                     fingerprint with the VM console.
#   PrepareLauncher   copies the launcher and its installer into the guest for the
#                     one-time installation the owner runs there with sudo.
#
# The stand's values come from stand.local.psd1 next to this script (or -Settings);
# a parameter given on the command line wins over the file.
#
# Nothing here restores a checkpoint unless -RestoreCheckpoint names one, installs
# packages or creates accounts. The only privileged step is the launcher the owner
# installed (guest/launch.sh), started with sudo -n. See README.md.

[CmdletBinding(DefaultParameterSetName = 'Stage')]
param(
    [string]$Settings,
    [string]$VmName,
    [guid]$VmId,
    [string]$SshHost,
    [string]$SshUser,
    [string]$KnownHostsPath,
    [string]$IdentityFile,
    [string]$StandId,
    [ValidateRange(1, 65535)][int]$SshPort = 22,
    [string]$UserA,
    [string]$UserB,

    [Parameter(ParameterSetName = 'Stage')][string]$ArtifactDir,
    [Parameter(ParameterSetName = 'Stage')][string]$WslDistro,
    [Parameter(ParameterSetName = 'Stage')][string]$RestoreCheckpoint,
    [Parameter(ParameterSetName = 'Stage')][string]$RepoRoot = (Join-Path $PSScriptRoot '..\..\..'),
    [Parameter(ParameterSetName = 'Stage')][ValidateRange(10, 3600)][int]$ScenarioTimeoutSeconds = 30,
    [Parameter(ParameterSetName = 'Stage')][ValidateRange(10, 3600)][int]$UnitTimeoutSeconds = 180,
    [Parameter(ParameterSetName = 'Stage')][ValidateRange(60, 7200)][int]$JobTimeoutSeconds = 900,

    [Parameter(ParameterSetName = 'Collect', Mandatory)][switch]$Collect,
    [Parameter(ParameterSetName = 'Collect', Mandatory)][string]$RunId,
    [Parameter(ParameterSetName = 'Collect')][ValidateRange(0, 7200)][int]$WaitSeconds = 0,

    [Parameter(ParameterSetName = 'InitKnownHosts', Mandatory)][switch]$InitKnownHosts,

    [Parameter(ParameterSetName = 'PrepareLauncher', Mandatory)][switch]$PrepareLauncher,

    [string]$LogRoot = (Join-Path $PSScriptRoot 'logs')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RosetunLinuxVm.psm1') -Force

$guestBase = '/var/lib/rosetun-l2'

# ------------------------------------------------------------------ settings

$settingsPath = if ($PSBoundParameters.ContainsKey('Settings')) { $Settings }
else {
    $default = Join-Path $PSScriptRoot 'stand.local.psd1'
    if (Test-Path -LiteralPath $default -PathType Leaf) { $default } else { $null }
}
$fileSettings = if ($settingsPath) { Read-RosetunLinuxStandSettings -Path $settingsPath } else { @{} }
$explicit = @{}
foreach ($name in @('VmName', 'StandId', 'SshUser', 'SshHost', 'SshPort', 'KnownHostsPath', 'IdentityFile', 'UserA', 'UserB', 'WslDistro')) {
    if ($PSBoundParameters.ContainsKey($name)) { $explicit[$name] = $PSBoundParameters[$name] }
}
$stand = Resolve-RosetunLinuxStandSettings -Settings $fileSettings -Explicit $explicit
Assert-RosetunLinuxStandSettings -Stand $stand -SettingsPath $settingsPath `
    -Names @('VmName', 'StandId', 'SshUser', 'KnownHostsPath', 'IdentityFile')

function Read-GuestJson {
    param($Target, [string]$Path)
    $text = Read-RosetunLinuxGuestFile -Target $Target -Path $Path
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    try { $text | ConvertFrom-Json -ErrorAction Stop } catch { $null }
}

# The VM id is read from Hyper-V unless the caller pins it; the stand id file,
# BIOS GUID and boot id still prove which guest answers.
$vmIdGiven = $PSBoundParameters.ContainsKey('VmId')
function Get-StandIdentity {
    $expected = if ($vmIdGiven) { $VmId } else { @(Get-VM -Name $stand.VmName -ErrorAction Stop)[0].VMId }
    Get-RosetunLinuxVmIdentity -VmName $stand.VmName -VmId $expected
}

# The address comes from SshHost or, after the VM is up, from Hyper-V.
function New-StandTarget {
    param([switch]$AllowMissingKnownHosts)
    $address = if ($stand.SshHost) { $stand.SshHost } else { Resolve-RosetunLinuxGuestAddress -VmName $stand.VmName -TimeoutSeconds 180 }
    New-RosetunLinuxTarget -HostName $address -User $stand.SshUser -KnownHostsPath $stand.KnownHostsPath `
        -IdentityFile $stand.IdentityFile -HostKeyAlias $stand.StandId -Port $stand.SshPort -AllowMissingKnownHosts:$AllowMissingKnownHosts
}

if ($PSCmdlet.ParameterSetName -eq 'InitKnownHosts') {
    $identity = Get-StandIdentity
    if ($identity.State -ne 'Running') { throw "VM '$($stand.VmName)' is $($identity.State). Start it first." }
    Initialize-RosetunLinuxKnownHosts -Target (New-StandTarget -AllowMissingKnownHosts)
    exit 0
}

Test-RosetunLinuxHostKeyPinned -KnownHostsPath $stand.KnownHostsPath -HostKeyAlias $stand.StandId

function Get-GuestHome {
    param($Target)
    $guestHome = (Invoke-RosetunLinuxSsh -Target $Target -Command 'printf %s "$HOME"' -TimeoutSeconds 20).Output.Trim()
    if ($guestHome -notmatch '^/[A-Za-z0-9._/-]+$') { throw 'Could not determine the guest home directory.' }
    $guestHome
}

function Show-LauncherInstall {
    param([string]$Folder)
    $vm = $stand.VmName
    $checkpoint = $stand.Checkpoint
    Write-Host '  1. On the host, restore the clean checkpoint and copy the launcher:'
    Write-Host "       Restore-VMCheckpoint -VMName $vm -Name $checkpoint -Confirm:`$false; Start-VM -Name $vm"
    Write-Host '       .\tools\vm\linux\Invoke-LinuxL2Matrix.ps1 -PrepareLauncher'
    Write-Host "  2. In the guest, as $($stand.SshUser):"
    Write-Host "       $(Get-RosetunLinuxInstallCommand -Folder $Folder -UserA $stand.UserA -UserB $stand.UserB)"
    Write-Host '  3. On the host, make the clean checkpoint again (a restore would bring the old launcher back):'
    Write-Host "       Remove-VMCheckpoint -VMName $vm -Name $checkpoint; Checkpoint-VM -Name $vm -SnapshotName $checkpoint"
}

if ($PSCmdlet.ParameterSetName -eq 'PrepareLauncher') {
    Assert-RosetunLinuxStandSettings -Stand $stand -SettingsPath $settingsPath -Names @('UserA', 'UserB')
    $identity = Get-StandIdentity
    if ($identity.State -ne 'Running') { throw "VM '$($stand.VmName)' is $($identity.State). Start it first." }
    $target = New-StandTarget
    Wait-RosetunLinuxSsh -Target $target -TimeoutSeconds 120
    $copied = Copy-RosetunLinuxLauncherToGuest -Target $target -GuestHome (Get-GuestHome $target)
    Write-Host "Copied the launcher to $($copied.Folder) (sha256 $($copied.LauncherHash))."
    Write-Host "In the guest, as $($stand.SshUser), run:"
    Write-Host ''
    Write-Host "  $(Get-RosetunLinuxInstallCommand -Folder $copied.Folder -UserA $stand.UserA -UserB $stand.UserB)"
    Write-Host ''
    Write-Host 'Then make the clean checkpoint again (see the stand guide).'
    exit 0
}

if ($PSCmdlet.ParameterSetName -eq 'Stage') {
    Assert-RosetunLinuxStandSettings -Stand $stand -SettingsPath $settingsPath -Names @('UserA', 'UserB')
    $runId = New-RosetunLinuxRunId
    $runLog = Join-Path $LogRoot $runId
    $null = New-Item -ItemType Directory -Path $runLog

    # The build comes first, so a failed build leaves the VM untouched.
    $repo = (Resolve-Path -LiteralPath $RepoRoot).ProviderPath
    $source = Get-RosetunLinuxSource -RepoRoot $repo
    if ($ArtifactDir) {
        $artifactDir = $ArtifactDir
        $artifacts = Get-RosetunLinuxArtifacts -ArtifactDir $artifactDir -Source $source
        if (-not $artifacts.Confirmed) {
            Write-Warning "Artifact origin is NOT confirmed: $($artifacts.Note). The report will say so."
        }
    }
    else {
        Write-Host "Building $($source.Sha.Substring(0, 12)) in WSL '$($stand.WslDistro)'..."
        $artifactDir = Invoke-RosetunLinuxBuild -RepoRoot $repo -Source $source -RunId $runId -WslDistro $stand.WslDistro `
            -Heartbeat { param($elapsed) Write-Host ('  still building, {0:mm\:ss}' -f $elapsed) }
        $after = Get-RosetunLinuxSource -RepoRoot $repo
        if ($after.Sha -ne $source.Sha -or $after.Dirty) { throw 'The checkout changed during the build. Nothing was staged; start again.' }
        $artifacts = Get-RosetunLinuxArtifacts -ArtifactDir $artifactDir -Source $source
        if (-not $artifacts.Confirmed) { throw "The build does not match HEAD: $($artifacts.Note). Nothing was staged." }
        Write-Host "Artifacts: $artifactDir"
    }

    $identity = Get-StandIdentity
    if ($RestoreCheckpoint) {
        Write-Host "Restoring checkpoint '$RestoreCheckpoint' of '$($stand.VmName)' (requested explicitly)."
        Restore-RosetunLinuxCheckpoint -VmName $stand.VmName -CheckpointName $RestoreCheckpoint
    }
    elseif ($identity.State -ne 'Running') {
        throw "VM '$($stand.VmName)' is $($identity.State). Start it yourself; the stand starts and restores nothing without -RestoreCheckpoint."
    }
    $target = New-StandTarget
    Wait-RosetunLinuxSsh -Target $target -TimeoutSeconds 300

    $standRead = Invoke-RosetunLinuxSsh -Target $target -Command 'cat /etc/rosetun-l2-stand-id' -TimeoutSeconds 20
    if ($standRead.ExitCode -ne 0 -or $standRead.Output.Trim() -ne $stand.StandId) {
        throw "The guest does not carry stand id '$($stand.StandId)' in /etc/rosetun-l2-stand-id. Wrong machine; nothing was copied."
    }
    $bootRead = Invoke-RosetunLinuxSsh -Target $target -Command 'cat /proc/sys/kernel/random/boot_id' -TimeoutSeconds 20
    $bootId = $bootRead.Output.Trim()
    if ($bootRead.ExitCode -ne 0 -or $bootId -notmatch '^[0-9a-f-]{36}$') { throw 'Could not read the guest boot id.' }

    $jobEnv = New-RosetunLinuxJobEnv -RunId $runId -StandId $stand.StandId -BootId $bootId -UserA $stand.UserA -UserB $stand.UserB `
        -BiosGuid $identity.BiosGuid -ScenarioTimeoutSeconds $ScenarioTimeoutSeconds `
        -UnitTimeoutSeconds $UnitTimeoutSeconds -JobTimeoutSeconds $JobTimeoutSeconds
    $stage = New-RosetunLinuxStage -StageRoot (Join-Path $runLog 'stage') -RunId $runId -ArtifactDir $artifactDir -JobEnv $jobEnv

    $remoteParent = "$(Get-GuestHome $target)/rosetun-l2-stage"
    $made = Invoke-RosetunLinuxSsh -Target $target -TimeoutSeconds 20 `
        -Command "umask 077 && mkdir -p -m 700 -- $remoteParent && test ! -e $remoteParent/$runId"
    if ($made.ExitCode -ne 0) { throw "Could not prepare $remoteParent on the guest (or the run id exists): $($made.Error.Trim())" }
    Copy-RosetunLinuxToGuest -Target $target -LocalDirectory $stage.Directory -RemoteParent $remoteParent
    $fix = Invoke-RosetunLinuxSsh -Target $target -TimeoutSeconds 20 -Command "chmod 700 -- $remoteParent/$runId && chmod 755 -- $remoteParent/$runId/guest/*.sh $remoteParent/$runId/artifacts/*"
    if ($fix.ExitCode -ne 0) { throw "Could not set modes on the staged run: $($fix.Error.Trim())" }

    $record = [ordered]@{
        schema = 1; run_id = $runId; created = [DateTime]::UtcNow.ToString('o')
        vm = [ordered]@{ name = $identity.Name; id = $identity.VmId }
        stand_id = $stand.StandId; boot_id = $bootId; manifest_sha256 = $stage.ManifestHash
        source = [ordered]@{ sha = $source.Sha; dirty = $source.Dirty; dirty_entries = $source.DirtyEntries; dirty_paths = @($source.DirtyPaths); dirty_digest = $source.DirtyDigest }
        artifacts = [ordered]@{ hashes = $artifacts.Hashes; origin_confirmed = $artifacts.Confirmed; origin_note = $artifacts.Note; toolchain = $artifacts.Toolchain; built_on = $artifacts.BuiltOn }
        checkpoint_restored = [bool]$RestoreCheckpoint
    }
    [IO.File]::WriteAllText((Join-Path $runLog 'stage.json'), ($record | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))

    $start = Start-RosetunLinuxJob -Target $target -StageDir "$remoteParent/$runId" -RunId $runId -ManifestHash $stage.ManifestHash `
        -ExpectedLauncherHash (Get-RosetunLinuxFileSha256 (Join-Path $stage.Directory 'guest/launch.sh'))
    Write-Host ''
    if ($start.Started) {
        Write-Host "Run $runId started through the launcher:"
        Write-Host "  $($start.Output.Replace("`n", "`n  "))"
    }
    else {
        Write-Host "Run $runId is staged on the guest. It was not started: $($start.Reason)."
        if ($start.Reinstall) {
            Write-Host 'Reinstall the launcher before the next run:'
            Show-LauncherInstall -Folder "$(Get-GuestHome $target)/rosetun-l2-launcher"
        }
        Write-Host 'For this run, in the guest, as the account that owns the stage directory, run exactly:'
        Write-Host ''
        Write-Host "  $($start.ManualCommand)"
    }
    Write-Host ''
    Write-Host 'Then, from this host:'
    Write-Host ''
    Write-Host "  .\tools\vm\linux\Invoke-LinuxL2Matrix.ps1 -Collect -RunId $runId -WaitSeconds 1200"
    exit 0
}

# Collect
if (-not (Test-RosetunLinuxRunId $RunId)) { throw "Invalid run id '$RunId'." }
$runLog = Join-Path $LogRoot $RunId
$stagePath = Join-Path $runLog 'stage.json'
if (-not (Test-Path -LiteralPath $stagePath)) { throw "No stage record for run $RunId under '$LogRoot'. This host did not stage it." }
$record = Get-Content -LiteralPath $stagePath -Raw | ConvertFrom-Json
$identity = Get-StandIdentity
if ($record.run_id -ne $RunId -or $record.stand_id -ne $stand.StandId -or $record.vm.id -ne $identity.VmId -or $record.vm.name -ne $stand.VmName) {
    throw 'The stage record belongs to another VM or stand. Nothing was read.'
}
$target = New-StandTarget

$stageInfo = [pscustomobject]@{
    RunId = $RunId; BootId = $record.boot_id
    Source = [pscustomobject]@{
        Sha = $record.source.sha; Dirty = $record.source.dirty; DirtyEntries = $record.source.dirty_entries
        DirtyPaths = @(Get-RosetunLinuxMember -Object $record.source -Name 'dirty_paths' | Where-Object { $null -ne $_ })
    }
    Artifacts = [pscustomobject]@{
        Confirmed = [bool]$record.artifacts.origin_confirmed; Note = $record.artifacts.origin_note
        Hashes = [ordered]@{}
    }
}
foreach ($property in $record.artifacts.hashes.PSObject.Properties) { $stageInfo.Artifacts.Hashes[$property.Name] = $property.Value }

$scenarios = @(Get-RosetunLinuxScenarios)
$deadline = [DateTime]::UtcNow.AddSeconds($WaitSeconds)
do {
    $status = $null
    $report = $null
    try {
        Wait-RosetunLinuxSsh -Target $target -TimeoutSeconds 60
        $status = Read-GuestJson -Target $target -Path "$guestBase/$RunId/report/status.json"
        $report = Read-GuestJson -Target $target -Path "$guestBase/$RunId/report/report.json"
    }
    catch {
        Write-Warning "Could not reach the guest: $_"
    }
    $finished = ($null -ne $report) -and ($null -ne $status) -and ($status.state -eq 'finished')
    if ($finished -or [DateTime]::UtcNow -ge $deadline) { break }
    Start-Sleep -Seconds 10
} while ($true)

$judgement = Test-RosetunLinuxReport -Report $report -Status $status -Stage $stageInfo -Scenarios $scenarios
$text = Format-RosetunLinuxReport -Judgement $judgement -Stage $stageInfo
[IO.File]::WriteAllText((Join-Path $runLog 'report.txt'), $text, [Text.UTF8Encoding]::new($false))
$hostReport = [ordered]@{
    schema = 1; run_id = $RunId; collected = [DateTime]::UtcNow.ToString('o')
    verdict = $judgement.Verdict; coverage = $judgement.Coverage; cleanup = $judgement.CleanupStatus
    problems = $judgement.Problems; counts = $judgement.Counts
    source = $record.source; artifacts = $record.artifacts; boot_id = $record.boot_id
    guest = if ($null -ne $report) { $report.guest } else { $null }
    scenarios = $judgement.Rows
}
[IO.File]::WriteAllText((Join-Path $runLog 'report.json'), ($hostReport | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))

Write-Host $text
Write-Host "Reports: $runLog"
if ($judgement.Verdict -eq 'PASS') { exit 0 }
exit 1
