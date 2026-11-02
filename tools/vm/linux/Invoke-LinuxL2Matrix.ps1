#Requires -Version 7.0
# Linux L2 stand, host side. The owner runs it; the agent only prepares it.
#
#   Stage   (default) checks the selected VM and guest, copies the run to the guest
#                     and prints the one command the owner runs there with sudo.
#   Collect           reads the status and report of a run back and judges it.
#
# Nothing here restores a checkpoint unless -RestoreCheckpoint names one, installs
# packages, creates accounts, or starts anything privileged. The privileged job is
# started in the guest by the owner (guest/start.sh). See Linux-Stand.md.

[CmdletBinding(DefaultParameterSetName = 'Stage')]
param(
    [Parameter(Mandatory)][string]$VmName,
    [Parameter(Mandatory)][guid]$VmId,
    [Parameter(Mandatory)][string]$SshHost,
    [Parameter(Mandatory)][string]$SshUser,
    [Parameter(Mandatory)][string]$KnownHostsPath,
    [Parameter(Mandatory)][string]$IdentityFile,
    [Parameter(Mandatory)][string]$StandId,
    [ValidateRange(1, 65535)][int]$SshPort = 22,

    [Parameter(ParameterSetName = 'Stage', Mandatory)][string]$ArtifactDir,
    [Parameter(ParameterSetName = 'Stage', Mandatory)][string]$UserA,
    [Parameter(ParameterSetName = 'Stage', Mandatory)][string]$UserB,
    [Parameter(ParameterSetName = 'Stage')][string]$RestoreCheckpoint,
    [Parameter(ParameterSetName = 'Stage')][string]$RepoRoot = (Join-Path $PSScriptRoot '..\..\..'),
    [Parameter(ParameterSetName = 'Stage')][ValidateRange(10, 3600)][int]$ScenarioTimeoutSeconds = 30,
    [Parameter(ParameterSetName = 'Stage')][ValidateRange(10, 3600)][int]$UnitTimeoutSeconds = 180,
    [Parameter(ParameterSetName = 'Stage')][ValidateRange(60, 7200)][int]$JobTimeoutSeconds = 900,

    [Parameter(ParameterSetName = 'Collect', Mandatory)][switch]$Collect,
    [Parameter(ParameterSetName = 'Collect', Mandatory)][string]$RunId,
    [Parameter(ParameterSetName = 'Collect')][ValidateRange(0, 7200)][int]$WaitSeconds = 0,

    [string]$LogRoot = (Join-Path $PSScriptRoot 'logs')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RosetunLinuxVm.psm1') -Force

$guestBase = '/var/lib/rosetun-l2'

function Read-GuestJson {
    param($Target, [string]$Path)
    $text = Read-RosetunLinuxGuestFile -Target $Target -Path $Path
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    try { $text | ConvertFrom-Json -ErrorAction Stop } catch { $null }
}

$target = New-RosetunLinuxTarget -HostName $SshHost -User $SshUser -KnownHostsPath $KnownHostsPath `
    -IdentityFile $IdentityFile -Port $SshPort
Test-RosetunLinuxHostKeyPinned -Target $target

if ($PSCmdlet.ParameterSetName -eq 'Stage') {
    $runId = New-RosetunLinuxRunId
    $runLog = Join-Path $LogRoot $runId
    $null = New-Item -ItemType Directory -Path $runLog

    $identity = Get-RosetunLinuxVmIdentity -VmName $VmName -VmId $VmId
    if ($RestoreCheckpoint) {
        Write-Host "Restoring checkpoint '$RestoreCheckpoint' of '$VmName' (requested explicitly)."
        Restore-RosetunLinuxCheckpoint -VmName $VmName -CheckpointName $RestoreCheckpoint
    }
    elseif ($identity.State -ne 'Running') {
        throw "VM '$VmName' is $($identity.State). Start it yourself; the stand starts and restores nothing without -RestoreCheckpoint."
    }
    Wait-RosetunLinuxSsh -Target $target -TimeoutSeconds 300

    $standRead = Invoke-RosetunLinuxSsh -Target $target -Command 'cat /etc/rosetun-l2-stand-id' -TimeoutSeconds 20
    if ($standRead.ExitCode -ne 0 -or $standRead.Output.Trim() -ne $StandId) {
        throw "The guest does not carry stand id '$StandId' in /etc/rosetun-l2-stand-id. Wrong machine; nothing was copied."
    }
    $bootRead = Invoke-RosetunLinuxSsh -Target $target -Command 'cat /proc/sys/kernel/random/boot_id' -TimeoutSeconds 20
    $bootId = $bootRead.Output.Trim()
    if ($bootRead.ExitCode -ne 0 -or $bootId -notmatch '^[0-9a-f-]{36}$') { throw 'Could not read the guest boot id.' }

    $source = Get-RosetunLinuxSource -RepoRoot (Resolve-Path -LiteralPath $RepoRoot).ProviderPath
    $artifacts = Get-RosetunLinuxArtifacts -ArtifactDir $ArtifactDir -Source $source
    if (-not $artifacts.Confirmed) {
        Write-Warning "Artifact origin is NOT confirmed: $($artifacts.Note). The report will say so."
    }

    $jobEnv = New-RosetunLinuxJobEnv -RunId $runId -StandId $StandId -BootId $bootId -UserA $UserA -UserB $UserB `
        -BiosGuid $identity.BiosGuid -ScenarioTimeoutSeconds $ScenarioTimeoutSeconds `
        -UnitTimeoutSeconds $UnitTimeoutSeconds -JobTimeoutSeconds $JobTimeoutSeconds
    $stage = New-RosetunLinuxStage -StageRoot (Join-Path $runLog 'stage') -RunId $runId -ArtifactDir $ArtifactDir -JobEnv $jobEnv

    $guestHome = (Invoke-RosetunLinuxSsh -Target $target -Command 'printf %s "$HOME"' -TimeoutSeconds 20).Output.Trim()
    if ($guestHome -notmatch '^/[A-Za-z0-9._/-]+$') { throw 'Could not determine the guest home directory.' }
    $remoteParent = "$guestHome/rosetun-l2-stage"
    $made = Invoke-RosetunLinuxSsh -Target $target -TimeoutSeconds 20 `
        -Command "umask 077 && mkdir -p -m 700 -- $remoteParent && test ! -e $remoteParent/$runId"
    if ($made.ExitCode -ne 0) { throw "Could not prepare $remoteParent on the guest (or the run id exists): $($made.Error.Trim())" }
    Copy-RosetunLinuxToGuest -Target $target -LocalDirectory $stage.Directory -RemoteParent $remoteParent
    $fix = Invoke-RosetunLinuxSsh -Target $target -TimeoutSeconds 20 -Command "chmod 700 -- $remoteParent/$runId && chmod 755 -- $remoteParent/$runId/guest/*.sh $remoteParent/$runId/artifacts/*"
    if ($fix.ExitCode -ne 0) { throw "Could not set modes on the staged run: $($fix.Error.Trim())" }

    $record = [ordered]@{
        schema = 1; run_id = $runId; created = [DateTime]::UtcNow.ToString('o')
        vm = [ordered]@{ name = $identity.Name; id = $identity.VmId }
        stand_id = $StandId; boot_id = $bootId; manifest_sha256 = $stage.ManifestHash
        source = [ordered]@{ sha = $source.Sha; dirty = $source.Dirty; dirty_entries = $source.DirtyEntries; dirty_digest = $source.DirtyDigest }
        artifacts = [ordered]@{ hashes = $artifacts.Hashes; origin_confirmed = $artifacts.Confirmed; origin_note = $artifacts.Note; toolchain = $artifacts.Toolchain; built_on = $artifacts.BuiltOn }
        checkpoint_restored = [bool]$RestoreCheckpoint
    }
    [IO.File]::WriteAllText((Join-Path $runLog 'stage.json'), ($record | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))

    Write-Host ''
    Write-Host "Run $runId is staged on the guest. Nothing privileged has started."
    Write-Host 'In the guest, as the account that owns the stage directory, run exactly:'
    Write-Host ''
    Write-Host "  sudo bash $remoteParent/$runId/guest/start.sh $runId $remoteParent/$runId $($stage.ManifestHash)"
    Write-Host ''
    Write-Host 'Then, from this host:'
    Write-Host ''
    Write-Host "  .\tools\vm\linux\Invoke-LinuxL2Matrix.ps1 -Collect -RunId $runId -WaitSeconds 1200 <same VM, SSH and stand parameters>"
    exit 0
}

# Collect
if (-not (Test-RosetunLinuxRunId $RunId)) { throw "Invalid run id '$RunId'." }
$runLog = Join-Path $LogRoot $RunId
$stagePath = Join-Path $runLog 'stage.json'
if (-not (Test-Path -LiteralPath $stagePath)) { throw "No stage record for run $RunId under '$LogRoot'. This host did not stage it." }
$record = Get-Content -LiteralPath $stagePath -Raw | ConvertFrom-Json
if ($record.run_id -ne $RunId -or $record.stand_id -ne $StandId -or $record.vm.id -ne $VmId.ToString() -or $record.vm.name -ne $VmName) {
    throw 'The stage record belongs to another VM or stand. Nothing was read.'
}
$null = Get-RosetunLinuxVmIdentity -VmName $VmName -VmId $VmId

$stageInfo = [pscustomobject]@{
    RunId = $RunId; BootId = $record.boot_id
    Source = [pscustomobject]@{ Sha = $record.source.sha; Dirty = $record.source.dirty; DirtyEntries = $record.source.dirty_entries }
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
