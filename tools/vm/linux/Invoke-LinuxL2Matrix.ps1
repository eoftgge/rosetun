#Requires -Version 7.0
# Linux L2 stand, host side. The owner runs it; the agent only prepares it.
#
#   Run               the one command: builds HEAD in WSL, restores the clean
#                     checkpoint, checks the guest, stages the run, starts it through
#                     the installed launcher, waits for the job and judges the report.
#                     Exits 0 only on PASS.
#   Stage   (default) builds HEAD in WSL (or takes -ArtifactDir), checks the selected
#                     VM and guest, copies the run to the guest and starts it through
#                     the installed launcher, or prints the one command the owner
#                     runs there with sudo when the launcher cannot.
#   Collect           reads the status and report of a run back and judges it; use it
#                     to reconnect to a run.
#   InitKnownHosts    pins the guest's host key once, after the owner compared its
#                     fingerprint with the VM console.
#   PrepareLauncher   copies the launcher and its installer into the guest for the
#                     one-time installation the owner runs there with sudo.
#
# The stand's values come from stand.local.psd1 next to this script (or -Settings);
# a parameter given on the command line wins over the file.
#
# Only -Run and -RestoreCheckpoint restore a checkpoint. Nothing here installs
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

    [Parameter(ParameterSetName = 'Run', Mandatory)][switch]$Run,
    [Parameter(ParameterSetName = 'Run')][string]$Checkpoint,
    # L3: the real service with its nftables kill switch, against the host's test node.
    # L4: Lockdown on the real service, with two reboots of the guest. The
    # parameters marked "L3 only" apply to L4 as well.
    [Parameter(ParameterSetName = 'Run')][ValidateSet('L2', 'L3', 'L4')][string]$Stage = 'L2',
    # L3 only: the Windows sing-box.exe that runs the test node on the host.
    [Parameter(ParameterSetName = 'Run')][string]$SingBoxPath,
    # L3 only: the Linux sing-box binary installed in the guest (the version the
    # helper pins; checked against its release checksum by the owner).
    [Parameter(ParameterSetName = 'Run')][string]$SingBoxLinuxPath,
    # L3 only: the connect request whose node and settings the matrix uses.
    [Parameter(ParameterSetName = 'Run')][string]$RequestPath,
    # L3 only: sends the test node's own traffic out of this host adapter.
    [Parameter(ParameterSetName = 'Run')][string]$NodeBindInterface,
    # L3 only: a public address that answers HTTPS and DNS, probed directly and
    # through the tunnel.
    [Parameter(ParameterSetName = 'Run')][string]$ProbeAddress = '1.1.1.1',
    # L3 only: where the DNS-lock check sends its UDP 53 datagram; it need not
    # answer. By default the request's DNS server when it is an IPv4 address,
    # else -ProbeAddress.
    [Parameter(ParameterSetName = 'Run')][string]$DnsProbeAddress,

    [Parameter(ParameterSetName = 'Stage')][Parameter(ParameterSetName = 'Run')][string]$ArtifactDir,
    [Parameter(ParameterSetName = 'Stage')][Parameter(ParameterSetName = 'Run')][string]$WslDistro,
    [Parameter(ParameterSetName = 'Stage')][string]$RestoreCheckpoint,
    [Parameter(ParameterSetName = 'Stage')][Parameter(ParameterSetName = 'Run')][string]$RepoRoot = (Join-Path $PSScriptRoot '..\..\..'),
    [Parameter(ParameterSetName = 'Stage')][Parameter(ParameterSetName = 'Run')][ValidateRange(10, 3600)][int]$ScenarioTimeoutSeconds = 30,
    [Parameter(ParameterSetName = 'Stage')][Parameter(ParameterSetName = 'Run')][ValidateRange(10, 3600)][int]$UnitTimeoutSeconds = 180,
    [Parameter(ParameterSetName = 'Stage')][Parameter(ParameterSetName = 'Run')][ValidateRange(60, 7200)][int]$JobTimeoutSeconds = 900,

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
$mode = $PSCmdlet.ParameterSetName

# ------------------------------------------------------------------ settings

if (-not (Test-RosetunLinuxElevated)) {
    throw 'Hyper-V needs administrator rights. Open Windows PowerShell as administrator, start pwsh in that window and run this again.'
}
if ($null -eq (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
    throw 'The Hyper-V PowerShell module is missing. Enable "Hyper-V Module for Windows PowerShell" in Windows features.'
}

$settingsPath = if ($PSBoundParameters.ContainsKey('Settings')) { $Settings }
else {
    $default = Join-Path $PSScriptRoot 'stand.local.psd1'
    if (Test-Path -LiteralPath $default -PathType Leaf) { $default } else { $null }
}
if ($mode -eq 'Run' -and $null -eq $settingsPath) {
    throw "No stand settings. Copy tools\vm\linux\stand.example.psd1 to tools\vm\linux\stand.local.psd1 and fill it in."
}
$fileSettings = if ($settingsPath) { Read-RosetunLinuxStandSettings -Path $settingsPath } else { @{} }
$explicit = @{}
foreach ($name in @('VmName', 'StandId', 'SshUser', 'SshHost', 'SshPort', 'KnownHostsPath', 'IdentityFile', 'UserA', 'UserB',
        'Checkpoint', 'WslDistro')) {
    if ($PSBoundParameters.ContainsKey($name)) { $explicit[$name] = $PSBoundParameters[$name] }
}
$stand = Resolve-RosetunLinuxStandSettings -Settings $fileSettings -Explicit $explicit
Assert-RosetunLinuxStandSettings -Stand $stand -SettingsPath $settingsPath `
    -Names @('VmName', 'StandId', 'SshUser', 'KnownHostsPath', 'IdentityFile')
if (-not (Test-Path -LiteralPath $stand.IdentityFile -PathType Leaf)) {
    throw "The SSH key '$($stand.IdentityFile)' does not exist. Make it as the stand guide shows, or fix IdentityFile."
}

# ------------------------------------------------------------------ helpers

$clock = [Diagnostics.Stopwatch]::StartNew()

# One line per stage of the run, with the time since the start.
function Write-Step {
    param([string]$Text)
    Write-Host ("[{0}] {1}" -f (Format-RosetunLinuxElapsed $clock.Elapsed), $Text)
}

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

# The address comes from SshHost or, once the VM is up, from Hyper-V.
function New-StandTarget {
    param([switch]$AllowMissingKnownHosts, [int]$AddressTimeoutSeconds = 180)
    $address = if ($stand.SshHost) { $stand.SshHost } else { Resolve-RosetunLinuxGuestAddress -VmName $stand.VmName -TimeoutSeconds $AddressTimeoutSeconds }
    New-RosetunLinuxTarget -HostName $address -User $stand.SshUser -KnownHostsPath $stand.KnownHostsPath `
        -IdentityFile $stand.IdentityFile -HostKeyAlias $stand.StandId -Port $stand.SshPort -AllowMissingKnownHosts:$AllowMissingKnownHosts
}

# Waits until the guest answers over SSH, reading the address again on every try:
# after a restore Hyper-V may report the old lease for a while.
function Wait-StandTarget {
    param([int]$TimeoutSeconds = 300)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $last = ''
    $address = $null
    do {
        try {
            $target = New-StandTarget -AddressTimeoutSeconds 30
            $address = $target.HostName
            Wait-RosetunLinuxSsh -Target $target -TimeoutSeconds 30
            return $target
        }
        catch {
            if ("$_" -match 'host key verification failed') { throw }
            $last = "$_" -replace '^.*Last answer: ', ''
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    $source = if ($stand.SshHost) { 'SshHost' } else { 'Hyper-V' }
    throw (Format-RosetunLinuxSshSilence -TimeoutSeconds $TimeoutSeconds -Address $address -AddressSource $source `
            -HostSubnets @(Get-RosetunLinuxHostSwitchSubnets) -LastAnswer $last)
}

function Get-GuestHome {
    param($Target)
    $guestHome = (Invoke-RosetunLinuxSsh -Target $Target -Command 'printf %s "$HOME"' -TimeoutSeconds 20).Output.Trim()
    if ($guestHome -notmatch '^/[A-Za-z0-9._/-]+$') { throw 'Could not determine the guest home directory.' }
    $guestHome
}

function Show-LauncherInstall {
    param([string]$Folder)
    $vm = $stand.VmName
    $point = $stand.Checkpoint
    Write-Host '  1. On the host, restore the clean checkpoint and copy the launcher:'
    Write-Host "       Restore-VMCheckpoint -VMName $vm -Name $point -Confirm:`$false; Start-VM -Name $vm"
    Write-Host '       .\tools\vm\linux\Invoke-LinuxL2Matrix.ps1 -PrepareLauncher'
    Write-Host "  2. In the guest, as $($stand.SshUser):"
    Write-Host "       $(Get-RosetunLinuxInstallCommand -Folder $Folder -UserA $stand.UserA -UserB $stand.UserB)"
    Write-Host '  3. On the host, make the clean checkpoint again from the powered-off VM (a restore would bring the old launcher back):'
    Write-Host "       Stop-VM -Name $vm; Remove-VMCheckpoint -VMName $vm -Name $point; Checkpoint-VM -Name $vm -SnapshotName $point"
}

# Builds HEAD in WSL, or checks a given artifact folder. A host build must match
# HEAD exactly; a given folder may be unconfirmed, and the report says so.
function Invoke-StandBuild {
    param([string]$RunId, [string]$BuildStage = 'L2')
    $repo = (Resolve-Path -LiteralPath $RepoRoot).ProviderPath
    $source = Get-RosetunLinuxSource -RepoRoot $repo
    if ($ArtifactDir) {
        Write-Step "Using the artifacts in $ArtifactDir"
        $artifacts = Get-RosetunLinuxArtifacts -ArtifactDir $ArtifactDir -Source $source -Stage $BuildStage
        if (-not $artifacts.Confirmed) { Write-Warning "Artifact origin is NOT confirmed: $($artifacts.Note). The report will say so." }
        return [pscustomobject]@{ Directory = $ArtifactDir; Source = $source; Artifacts = $artifacts }
    }
    Assert-RosetunLinuxCleanSource -Source $source
    Write-Step "Building $($source.Sha.Substring(0, 12)) in WSL '$($stand.WslDistro)'"
    $directory = Invoke-RosetunLinuxBuild -RepoRoot $repo -Source $source -RunId $RunId -WslDistro $stand.WslDistro -Stage $BuildStage `
        -Heartbeat { param($elapsed) Write-Host "    building, $(Format-RosetunLinuxElapsed $elapsed)" } -HeartbeatSeconds 60
    $after = Get-RosetunLinuxSource -RepoRoot $repo
    if ($after.Sha -ne $source.Sha -or $after.Dirty) { throw 'The checkout changed during the build. Nothing was staged; start again.' }
    $artifacts = Get-RosetunLinuxArtifacts -ArtifactDir $directory -Source $source -Stage $BuildStage
    if (-not $artifacts.Confirmed) { throw "The build does not match HEAD: $($artifacts.Note). Nothing was staged." }
    Write-Host "    $directory"
    [pscustomobject]@{ Directory = $directory; Source = $source; Artifacts = $artifacts }
}

# Checks which guest answers, stages the run there and records it on the host.
function Invoke-StandStage {
    param(
        [string]$RunId, [string]$RunLog, $Build, $Identity, [string]$Restored,
        [string]$StageName = 'L2',
        # L3: the engine and the requests staged next to the build, and the job's
        # host node values.
        [Collections.IDictionary]$ExtraFiles = [ordered]@{},
        [Collections.IDictionary]$ExtraJob = [ordered]@{}
    )
    $target = Wait-StandTarget -TimeoutSeconds 300
    Write-Step "Checking the guest at $($target.HostName)"
    $standRead = Invoke-RosetunLinuxSsh -Target $target -Command 'cat /etc/rosetun-l2-stand-id' -TimeoutSeconds 20
    if ($standRead.ExitCode -ne 0 -or $standRead.Output.Trim() -ne $stand.StandId) {
        throw "The guest does not carry stand id '$($stand.StandId)' in /etc/rosetun-l2-stand-id. Wrong machine; nothing was copied."
    }
    $bootRead = Invoke-RosetunLinuxSsh -Target $target -Command 'cat /proc/sys/kernel/random/boot_id' -TimeoutSeconds 20
    $bootId = $bootRead.Output.Trim()
    if ($bootRead.ExitCode -ne 0 -or $bootId -notmatch '^[0-9a-f-]{36}$') { throw 'Could not read the guest boot id.' }

    Write-Step "Staging run $RunId"
    $jobEnv = New-RosetunLinuxJobEnv -RunId $RunId -StandId $stand.StandId -BootId $bootId -UserA $stand.UserA -UserB $stand.UserB `
        -BiosGuid $Identity.BiosGuid -ScenarioTimeoutSeconds $ScenarioTimeoutSeconds `
        -UnitTimeoutSeconds $UnitTimeoutSeconds -JobTimeoutSeconds $JobTimeoutSeconds -Extra $ExtraJob
    $stage = New-RosetunLinuxStage -StageRoot (Join-Path $RunLog 'stage') -RunId $RunId -ArtifactDir $Build.Directory -JobEnv $jobEnv `
        -Stage $StageName -Extra $ExtraFiles
    $remoteParent = "$(Get-GuestHome $target)/rosetun-l2-stage"
    $made = Invoke-RosetunLinuxSsh -Target $target -TimeoutSeconds 20 `
        -Command "umask 077 && mkdir -p -m 700 -- $remoteParent && test ! -e $remoteParent/$RunId"
    if ($made.ExitCode -ne 0) { throw "Could not prepare $remoteParent on the guest (or the run id exists): $($made.Error.Trim())" }
    Copy-RosetunLinuxToGuest -Target $target -LocalDirectory $stage.Directory -RemoteParent $remoteParent
    $fix = Invoke-RosetunLinuxSsh -Target $target -TimeoutSeconds 20 -Command "chmod 700 -- $remoteParent/$RunId && chmod 755 -- $remoteParent/$RunId/guest/*.sh $remoteParent/$RunId/artifacts/*"
    if ($fix.ExitCode -ne 0) { throw "Could not set modes on the staged run: $($fix.Error.Trim())" }

    $source = $Build.Source
    $artifacts = $Build.Artifacts
    $extraHashes = [ordered]@{}
    foreach ($name in @($ExtraFiles.Keys)) { $extraHashes[$name] = Get-RosetunLinuxFileSha256 $ExtraFiles[$name] }
    $record = [ordered]@{
        schema = 1; run_id = $RunId; stage = $StageName; created = [DateTime]::UtcNow.ToString('o')
        staged_files = $extraHashes
        vm = [ordered]@{ name = $Identity.Name; id = $Identity.VmId }
        stand_id = $stand.StandId; boot_id = $bootId; manifest_sha256 = $stage.ManifestHash
        source = [ordered]@{ sha = $source.Sha; dirty = $source.Dirty; dirty_entries = $source.DirtyEntries; dirty_paths = @($source.DirtyPaths); dirty_digest = $source.DirtyDigest }
        artifacts = [ordered]@{ hashes = $artifacts.Hashes; origin_confirmed = $artifacts.Confirmed; origin_note = $artifacts.Note; toolchain = $artifacts.Toolchain; built_on = $artifacts.BuiltOn }
        checkpoint_restored = [bool]$Restored
    }
    [IO.File]::WriteAllText((Join-Path $RunLog 'stage.json'), ($record | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    [pscustomobject]@{ Target = $target; StageDir = "$remoteParent/$RunId"; Stage = $stage }
}

function Invoke-StandStart {
    param([string]$RunId, $Staged)
    $start = Start-RosetunLinuxJob -Target $Staged.Target -StageDir $Staged.StageDir -RunId $RunId -ManifestHash $Staged.Stage.ManifestHash `
        -ExpectedLauncherHash (Get-RosetunLinuxFileSha256 (Join-Path $Staged.Stage.Directory 'guest/launch.sh'))
    if ($start.Started) {
        Write-Step 'Started the job through the launcher (no password)'
        return $start
    }
    Write-Step "The job was not started: $($start.Reason)"
    if ($start.Reinstall) {
        Write-Host 'Reinstall the launcher before the next run:'
        Show-LauncherInstall -Folder "$(Get-GuestHome $Staged.Target)/rosetun-l2-launcher"
    }
    Write-Host 'For this run, in the guest, as the account that owns the stage directory, run exactly:'
    Write-Host ''
    Write-Host "  $($start.ManualCommand)"
    Write-Host ''
    $start
}

# Reads the run back, waiting up to WaitSeconds for it to finish, judges it and
# writes report.txt and report.json. Returns the verdict.
function Invoke-StandCollect {
    param([string]$RunId, [int]$WaitSeconds, [switch]$Progress)
    if (-not (Test-RosetunLinuxRunId $RunId)) { throw "Invalid run id '$RunId'." }
    $runLog = Join-Path $LogRoot $RunId
    $stagePath = Join-Path $runLog 'stage.json'
    if (-not (Test-Path -LiteralPath $stagePath)) { throw "No stage record for run $RunId under '$LogRoot'. This host did not stage it." }
    $record = Get-Content -LiteralPath $stagePath -Raw | ConvertFrom-Json
    $identity = Get-StandIdentity
    if ($record.run_id -ne $RunId -or $record.stand_id -ne $stand.StandId -or $record.vm.id -ne $identity.VmId -or $record.vm.name -ne $stand.VmName) {
        throw 'The stage record belongs to another VM or stand. Nothing was read.'
    }

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

    $recordedStage = [string](Get-RosetunLinuxMember -Object $record -Name 'stage')
    if ([string]::IsNullOrEmpty($recordedStage)) { $recordedStage = 'L2' }
    if ($recordedStage -notin @('L2', 'L3', 'L4')) { throw "The stage record names an unknown stage '$recordedStage'." }
    $scenarios = @(Get-RosetunLinuxScenarios -Stage $recordedStage)
    $waitClock = [Diagnostics.Stopwatch]::StartNew()
    $lastLine = ''
    $lastShown = [TimeSpan]::Zero
    do {
        $status = $null
        $report = $null
        try {
            $target = Wait-StandTarget -TimeoutSeconds 60
            $status = Read-GuestJson -Target $target -Path "$guestBase/$RunId/report/status.json"
            $report = Read-GuestJson -Target $target -Path "$guestBase/$RunId/report/report.json"
        }
        catch {
            Write-Warning "Could not reach the guest: $_"
        }
        $finished = ($null -ne $report) -and ($null -ne $status) -and ($status.state -eq 'finished')
        if ($finished -or $waitClock.Elapsed.TotalSeconds -ge $WaitSeconds) { break }
        if ($Progress) {
            $line = Format-RosetunLinuxJobProgress -Status $status
            if ($line -ne $lastLine -or ($waitClock.Elapsed - $lastShown).TotalSeconds -ge 120) {
                Write-Host "    $line, $(Format-RosetunLinuxElapsed $waitClock.Elapsed)"
                $lastLine = $line
                $lastShown = $waitClock.Elapsed
            }
        }
        Start-Sleep -Seconds 10
    } while ($true)

    $planned = (Get-RosetunLinuxStageProfile $recordedStage)['Reboots']
    $judgement = Test-RosetunLinuxReport -Report $report -Status $status -Stage $stageInfo -Scenarios $scenarios `
        -PlannedReboots ([int]$(if ($null -eq $planned) { 0 } else { $planned }))
    $text = Format-RosetunLinuxReport -Judgement $judgement -Stage $stageInfo
    $reportPath = Join-Path $runLog 'report.txt'
    [IO.File]::WriteAllText($reportPath, $text, [Text.UTF8Encoding]::new($false))
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
    Write-Host "Report: $reportPath"
    $judgement.Verdict
}

# ------------------------------------------------------------------ modes

if ($mode -eq 'InitKnownHosts') {
    $identity = Get-StandIdentity
    if ($identity.State -ne 'Running') { throw "VM '$($stand.VmName)' is $($identity.State). Start it first." }
    Initialize-RosetunLinuxKnownHosts -Target (New-StandTarget -AllowMissingKnownHosts)
    exit 0
}

Test-RosetunLinuxHostKeyPinned -KnownHostsPath $stand.KnownHostsPath -HostKeyAlias $stand.StandId

if ($mode -eq 'PrepareLauncher') {
    Assert-RosetunLinuxStandSettings -Stand $stand -SettingsPath $settingsPath -Names @('UserA', 'UserB')
    $identity = Get-StandIdentity
    if ($identity.State -ne 'Running') { throw "VM '$($stand.VmName)' is $($identity.State). Start it first." }
    $target = Wait-StandTarget -TimeoutSeconds 120
    $copied = Copy-RosetunLinuxLauncherToGuest -Target $target -GuestHome (Get-GuestHome $target)
    Write-Host "Copied the launcher to $($copied.Folder) (sha256 $($copied.LauncherHash))."
    Write-Host "In the guest, as $($stand.SshUser), run:"
    Write-Host ''
    Write-Host "  $(Get-RosetunLinuxInstallCommand -Folder $copied.Folder -UserA $stand.UserA -UserB $stand.UserB)"
    Write-Host ''
    Write-Host 'Then make the clean checkpoint again (see the stand guide).'
    exit 0
}

if ($mode -eq 'Collect') {
    $verdict = Invoke-StandCollect -RunId $RunId -WaitSeconds $WaitSeconds -Progress:($WaitSeconds -gt 0)
    if ($verdict -eq 'PASS') { exit 0 }
    exit 1
}

Assert-RosetunLinuxStandSettings -Stand $stand -SettingsPath $settingsPath -Names @('UserA', 'UserB')
$newRunId = New-RosetunLinuxRunId
$runLog = Join-Path $LogRoot $newRunId

if ($mode -eq 'Run') {
    Assert-RosetunLinuxStandSettings -Stand $stand -SettingsPath $settingsPath -Names @('Checkpoint')
    # Everything that can fail fast is checked before the build takes minutes.
    $identity = Get-StandIdentity
    $points = @(Get-VMCheckpoint -VMName $stand.VmName -Name $stand.Checkpoint -ErrorAction SilentlyContinue)
    if ($points.Count -ne 1) {
        throw "VM '$($stand.VmName)' has $($points.Count) checkpoints named '$($stand.Checkpoint)'; the run needs exactly one (see the stand guide)."
    }
    if (-not $ArtifactDir) { $null = ConvertTo-RosetunLinuxWslPath -WslDistro $stand.WslDistro -Path $PSScriptRoot }
    $extraFiles = [ordered]@{}
    $extraJob = [ordered]@{}
    $nodeStarted = $false
    if ($Stage -in @('L3', 'L4')) {
        # Everything that can fail fast, before the build.
        if (-not $SingBoxLinuxPath) { throw '-Stage L3 needs -SingBoxLinuxPath: the Linux sing-box binary for the guest (see the stand guide, L3).' }
        $elf = Test-RosetunLinuxElf $SingBoxLinuxPath
        if (-not $elf.Ok) { throw "-SingBoxLinuxPath '$SingBoxLinuxPath': $($elf.Reason)." }
        if (-not $SingBoxPath) { $SingBoxPath = Join-Path $RepoRoot 'tools\sing-box.exe' }
        if (-not (Test-Path -LiteralPath $SingBoxPath -PathType Leaf)) { throw "-SingBoxPath '$SingBoxPath' does not exist: the host test node needs the Windows sing-box.exe." }
        if (-not $RequestPath) { $RequestPath = Join-Path $RepoRoot 'tools\vm\windows\request-local.json' }
        if (-not (Test-Path -LiteralPath $RequestPath -PathType Leaf)) { throw "-RequestPath '$RequestPath' does not exist." }
        $probe = $null
        if (-not [Net.IPAddress]::TryParse($ProbeAddress, [ref]$probe) -or $probe.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
            throw "-ProbeAddress '$ProbeAddress' is not an IPv4 address."
        }
        $hostAddress = @(Get-RosetunLinuxHostSwitchSubnets | Select-Object -First 1)
        if ($hostAddress.Count -eq 0) { throw "The host has no IPv4 address on 'vEthernet (Default Switch)'." }
        $hostAddress = $hostAddress[0].Address
        # L4: two reboots, and the phases after them under the same limit each.
        if (-not $PSBoundParameters.ContainsKey('JobTimeoutSeconds')) { $JobTimeoutSeconds = if ($Stage -eq 'L4') { 3000 } else { 1800 } }
        # The test node of the Windows matrices, on the host's Default Switch address.
        Import-Module (Join-Path $PSScriptRoot '..\windows\RosetunVm.psm1') -Force
        $nodePort = Get-RosetunTestNodePort
        $dnsProbe = Select-RosetunLinuxDnsProbe -Explicit $DnsProbeAddress -RequestPath $RequestPath -ProbeAddress $probe.ToString()
        Write-Step "Probes: HTTPS $($probe), DNS $dnsProbe"
        $extraJob = [ordered]@{ HOST_ADDRESS = $hostAddress; NODE_PORT = "$nodePort"; PROBE_ADDRESS = $probe.ToString(); DNS_PROBE_ADDRESS = $dnsProbe }
    }
    $null = New-Item -ItemType Directory -Path $runLog
    Write-Step "Run $newRunId ($Stage) on '$($stand.VmName)'"

    try {
        $build = Invoke-StandBuild -RunId $newRunId -BuildStage $Stage
        if ($Stage -in @('L3', 'L4')) {
            if (-not (Get-NetTCPConnection -LocalPort $nodePort -State Listen -ErrorAction SilentlyContinue)) {
                Write-Step "Starting the test node on $($hostAddress):$nodePort"
                $nodeArguments = @{ SingBoxPath = (Resolve-Path -LiteralPath $SingBoxPath).ProviderPath }
                if ($NodeBindInterface) { $nodeArguments.BindInterface = $NodeBindInterface }
                Start-RosetunTestNode @nodeArguments
                $nodeStarted = $true
            }
            else {
                Write-Step "Using the test node already listening on port $nodePort"
            }
            $requestDir = Join-Path $runLog 'requests'
            $null = New-Item -ItemType Directory -Path $requestDir
            $extraFiles = New-RosetunLinuxL3Requests -RequestPath $RequestPath -HostAddress $hostAddress -NodePort $nodePort -OutDir $requestDir
            $extraFiles['sing-box'] = (Resolve-Path -LiteralPath $SingBoxLinuxPath).ProviderPath
            $extraFiles['rosetun-helper.service'] = Join-Path $RepoRoot 'packaging\linux\rosetun-helper.service'
            if ($Stage -eq 'L4') {
                $extraFiles['rosetun-lockdown.service'] = Join-Path $RepoRoot 'packaging\linux\rosetun-lockdown.service'
            }
        }
        Write-Step "Restoring checkpoint '$($stand.Checkpoint)'"
        Restore-RosetunLinuxCheckpoint -VmName $stand.VmName -CheckpointName $stand.Checkpoint
        Write-Step 'Waiting for the guest'
        $staged = Invoke-StandStage -RunId $newRunId -RunLog $runLog -Build $build -Identity $identity -Restored $stand.Checkpoint `
            -StageName $Stage -ExtraFiles $extraFiles -ExtraJob $extraJob
        $start = Invoke-StandStart -RunId $newRunId -Staged $staged
        $wait = Get-RosetunLinuxRunWaitSeconds -JobTimeoutSeconds $JobTimeoutSeconds -Manual:(-not $start.Started)
        Write-Step "Waiting for the job (at most $(Format-RosetunLinuxElapsed ([TimeSpan]::FromSeconds($wait))))"
        $verdict = Invoke-StandCollect -RunId $newRunId -WaitSeconds $wait -Progress
        Write-Step "Result: $verdict"
        if ($Stage -in @('L3', 'L4')) {
            # The restore below removes the guest's copy; the journal explains a failure.
            try {
                $journal = Read-RosetunLinuxGuestFile -Target (Wait-StandTarget -TimeoutSeconds 60) -Path "$guestBase/$newRunId/report/helper-journal.txt"
                if ($null -ne $journal) {
                    $journalPath = Join-Path $runLog 'helper-journal.txt'
                    [IO.File]::WriteAllText($journalPath, $journal, [Text.UTF8Encoding]::new($false))
                    Write-Host "Helper journal: $journalPath"
                }
            }
            catch { Write-Warning "Could not read the helper journal: $_" }
        }
    }
    finally {
        if ($Stage -in @('L3', 'L4')) {
            # The service must never stay in a checkpoint or a running guest.
            if (Test-Path -LiteralPath (Join-Path $runLog 'stage.json')) {
                Write-Step "Restoring checkpoint '$($stand.Checkpoint)' after the run"
                try { Restore-RosetunLinuxCheckpoint -VmName $stand.VmName -CheckpointName $stand.Checkpoint -NoStart }
                catch { Write-Warning "Could not restore '$($stand.Checkpoint)' after the run: $_" }
            }
            if ($nodeStarted) {
                try { Stop-RosetunTestNode } catch { Write-Warning "Could not stop the test node: $_" }
            }
        }
    }
    if ($verdict -eq 'PASS') { exit 0 }
    if ($Stage -eq 'L2') {
        Write-Host "Reconnect later with: .\tools\vm\linux\Invoke-LinuxL2Matrix.ps1 -Collect -RunId $newRunId -WaitSeconds 1200"
    }
    exit 1
}

# Stage
$null = New-Item -ItemType Directory -Path $runLog
$build = Invoke-StandBuild -RunId $newRunId
$identity = Get-StandIdentity
if ($RestoreCheckpoint) {
    Write-Step "Restoring checkpoint '$RestoreCheckpoint' (requested explicitly)"
    Restore-RosetunLinuxCheckpoint -VmName $stand.VmName -CheckpointName $RestoreCheckpoint
}
elseif ($identity.State -ne 'Running') {
    throw "VM '$($stand.VmName)' is $($identity.State). Start it yourself; the stand starts and restores nothing without -RestoreCheckpoint."
}
$staged = Invoke-StandStage -RunId $newRunId -RunLog $runLog -Build $build -Identity $identity -Restored $RestoreCheckpoint
$null = Invoke-StandStart -RunId $newRunId -Staged $staged
Write-Host 'Then, from this host:'
Write-Host ''
Write-Host "  .\tools\vm\linux\Invoke-LinuxL2Matrix.ps1 -Collect -RunId $newRunId -WaitSeconds 1200"
exit 0
