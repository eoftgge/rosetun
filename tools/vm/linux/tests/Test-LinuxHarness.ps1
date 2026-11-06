#Requires -Version 7.0
# Unprivileged self-test of the Linux stand's host side. It needs no Hyper-V, no
# SSH and no guest. It proves report judgement, timeouts and artifact checks; it is
# not a Hyper-V run and proves nothing about the Linux guest.
#
#   pwsh -NoProfile -File tools/vm/linux/tests/Test-LinuxHarness.ps1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\RosetunLinuxVm.psm1') -Force

$script:Passed = 0
$script:Failed = 0
function Assert-That {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { $script:Passed++ }
    else { $script:Failed++; Write-Host "FAIL  $Name $Detail" -ForegroundColor Red }
}

$runId = '20261101T220100Z-0123abcd'
$bootId = '11111111-2222-3333-4444-555555555555'
$scenarios = @(Get-RosetunLinuxScenarios)
$stage = [pscustomobject]@{ RunId = $runId; BootId = $bootId }

function New-GoodReport {
    $lines = foreach ($s in $scenarios) {
        $result = if ($s.Evidence -eq 'not-run') { 'SKIP' } else { 'PASS' }
        [pscustomobject]@{ id = $s.Id; evidence = $s.Evidence; result = $result; reason = 'ok'; duration_ms = 5; expectation = $s.Title; group = $s.Group }
    }
    $pass = @($lines | Where-Object result -EQ 'PASS').Count
    $skip = @($lines | Where-Object result -EQ 'SKIP').Count
    [pscustomobject]@{
        schema = 1; run_id = $runId
        guest = [pscustomobject]@{ boot_id = $bootId; boot_id_at_end = $bootId }
        summary = [pscustomobject]@{ overall = 'PASS'; pass = $pass; fail = 0; error = 0; skip = $skip; total = $lines.Count }
        cleanup = [pscustomobject]@{ status = 'PASS'; actions = ''; problems = ''; duration_ms = 3 }
        scenarios = @($lines)
    }
}
$finished = [pscustomobject]@{ run_id = $runId; state = 'finished'; current = '' }

# --- a complete, matching report passes, with partial coverage for the one SKIP
$judgement = Test-RosetunLinuxReport -Report (New-GoodReport) -Status $finished -Stage $stage -Scenarios $scenarios
Assert-That 'a complete report passes' ($judgement.Verdict -eq 'PASS') ($judgement.Problems -join '; ')
Assert-That 'the skipped optional scenario makes coverage partial' ($judgement.Coverage -eq 'partial')

# --- missing, unreadable or unfinished reports never pass
$judgement = Test-RosetunLinuxReport -Report $null -Status $finished -Stage $stage -Scenarios $scenarios
Assert-That 'a missing report is an error' ($judgement.Verdict -eq 'ERROR')
$judgement = Test-RosetunLinuxReport -Report $null -Status $null -Stage $stage -Scenarios $scenarios
Assert-That 'a missing report and status is an error' ($judgement.Verdict -eq 'ERROR')
$running = [pscustomobject]@{ run_id = $runId; state = 'running'; current = 'stale.restart-refused' }
$judgement = Test-RosetunLinuxReport -Report (New-GoodReport) -Status $running -Stage $stage -Scenarios $scenarios
Assert-That 'an unfinished job is an error even with a full report' ($judgement.Verdict -eq 'ERROR')

# --- a report of another run or boot is foreign
$foreign = New-GoodReport
$foreign.run_id = '20261101T220100Z-ffffffff'
$judgement = Test-RosetunLinuxReport -Report $foreign -Status $finished -Stage $stage -Scenarios $scenarios
Assert-That 'a report of another run is an error' ($judgement.Verdict -eq 'ERROR')
$foreignStatus = [pscustomobject]@{ run_id = '20261101T220100Z-ffffffff'; state = 'finished'; current = '' }
$judgement = Test-RosetunLinuxReport -Report (New-GoodReport) -Status $foreignStatus -Stage $stage -Scenarios $scenarios
Assert-That 'a status of another run is an error' ($judgement.Verdict -eq 'ERROR')
$rebooted = New-GoodReport
$rebooted.guest.boot_id = '99999999-2222-3333-4444-555555555555'
$judgement = Test-RosetunLinuxReport -Report $rebooted -Status $finished -Stage $stage -Scenarios $scenarios
Assert-That 'a different boot id is an error' ($judgement.Verdict -eq 'ERROR')
$rebootedEnd = New-GoodReport
$rebootedEnd.guest.boot_id_at_end = '99999999-2222-3333-4444-555555555555'
$judgement = Test-RosetunLinuxReport -Report $rebootedEnd -Status $finished -Stage $stage -Scenarios $scenarios
Assert-That 'a reboot during the run is an error' ($judgement.Verdict -eq 'ERROR')

# --- L4 reboots on purpose: listed boots, the staged one first, no more than planned
$second = '22222222-2222-3333-4444-555555555555'
$third = '33333333-2222-3333-4444-555555555555'
function New-RebootedReport([string[]]$Boots, [string]$AtEnd) {
    $report = New-GoodReport
    $report.guest = [pscustomobject]@{ boot_id = $bootId; boot_id_at_end = $AtEnd; boot_ids = @($Boots) }
    $report
}
$judgement = Test-RosetunLinuxReport -Report (New-RebootedReport @($bootId, $second, $third) $third) -Status $finished -Stage $stage -Scenarios $scenarios -PlannedReboots 2
Assert-That 'planned reboots listed in order pass' ($judgement.Verdict -eq 'PASS') ($judgement.Problems -join '; ')
$judgement = Test-RosetunLinuxReport -Report (New-RebootedReport @($bootId, $second) $second) -Status $finished -Stage $stage -Scenarios $scenarios -PlannedReboots 2
Assert-That 'a run that ended before its last reboot is judged by its scenarios' ($judgement.Verdict -eq 'PASS') ($judgement.Problems -join '; ')
$judgement = Test-RosetunLinuxReport -Report (New-RebootedReport @($bootId, $second, $third, '44444444-2222-3333-4444-555555555555') '44444444-2222-3333-4444-555555555555') -Status $finished -Stage $stage -Scenarios $scenarios -PlannedReboots 2
Assert-That 'more boots than planned are an error' ($judgement.Verdict -eq 'ERROR')
$judgement = Test-RosetunLinuxReport -Report (New-RebootedReport @($second, $third) $third) -Status $finished -Stage $stage -Scenarios $scenarios -PlannedReboots 2
Assert-That 'a boot list without the staged boot first is an error' ($judgement.Verdict -eq 'ERROR')
$judgement = Test-RosetunLinuxReport -Report (New-RebootedReport @($bootId, $second) $third) -Status $finished -Stage $stage -Scenarios $scenarios -PlannedReboots 2
Assert-That 'a boot outside the list is an error' ($judgement.Verdict -eq 'ERROR')
$judgement = Test-RosetunLinuxReport -Report (New-RebootedReport @($bootId, $second, $second) $second) -Status $finished -Stage $stage -Scenarios $scenarios -PlannedReboots 2
Assert-That 'a boot listed twice is an error' ($judgement.Verdict -eq 'ERROR')
$judgement = Test-RosetunLinuxReport -Report (New-RebootedReport @($bootId, $second) $second) -Status $finished -Stage $stage -Scenarios $scenarios
Assert-That 'without planned reboots any reboot is an error' ($judgement.Verdict -eq 'ERROR')

# --- the L4 stage: its own scenarios, two reboots, the L3 build
$l4 = Get-RosetunLinuxStageProfile 'L4'
Assert-That 'L4 plans two reboots' ($l4['Reboots'] -eq 2)
Assert-That 'L4 runs its own job' ($l4.Scripts -contains 'run-l4.sh' -and $l4.Scripts -notcontains 'run-l3.sh')
$l4Scenarios = @(Get-RosetunLinuxScenarios -Stage 'L4')
Assert-That 'L4 scenarios load' ($l4Scenarios.Count -ge 20) "$($l4Scenarios.Count)"
Assert-That 'every L4 scenario is required' (@($l4Scenarios | Where-Object { -not $_.Required }).Count -eq 0)

# --- the L5 stage: packages instead of programs, no reboot
$l5 = Get-RosetunLinuxStageProfile 'L5'
Assert-That 'L5 stages packages' ($l5['Packages'] -and $l5.Artifacts -contains 'rosetun-old.deb' -and $l5.Artifacts -contains 'rosetun-new.deb')
Assert-That 'L5 runs its own job' ($l5.Scripts -contains 'run-l5.sh' -and $l5.Scripts -notcontains 'run-l3.sh')
$l5Scenarios = @(Get-RosetunLinuxScenarios -Stage 'L5')
Assert-That 'L5 scenarios load' ($l5Scenarios.Count -ge 15) "$($l5Scenarios.Count)"
Assert-That 'every L5 scenario is required' (@($l5Scenarios | Where-Object { -not $_.Required }).Count -eq 0)
$notDeb = Join-Path ([IO.Path]::GetTempPath()) "rosetun-not-deb-$PID"
[IO.File]::WriteAllBytes($notDeb, [Text.Encoding]::ASCII.GetBytes("!<arch>`nsomething-else--------"))
Assert-That 'another ar archive is not a package' (-not (Test-RosetunLinuxDeb $notDeb))
[IO.File]::WriteAllBytes($notDeb, [Text.Encoding]::ASCII.GetBytes("!<arch>`ndebian-binary   0"))
Assert-That 'a package is recognised by its first member' (Test-RosetunLinuxDeb $notDeb)
Remove-Item -LiteralPath $notDeb

# --- required scenarios cannot be dropped, skipped or invented
$dropped = New-GoodReport
$dropped.scenarios = @($dropped.scenarios | Where-Object id -NE 'stale.restart-refused')
$judgement = Test-RosetunLinuxReport -Report $dropped -Status $finished -Stage $stage -Scenarios $scenarios
Assert-That 'a dropped scenario is an error' ($judgement.Verdict -eq 'ERROR')
$skipped = New-GoodReport
($skipped.scenarios | Where-Object id -EQ 'credentials.owner-uid').result = 'SKIP'
$judgement = Test-RosetunLinuxReport -Report $skipped -Status $finished -Stage $stage -Scenarios $scenarios
Assert-That 'a skipped required scenario is an error' ($judgement.Verdict -eq 'ERROR')
$fake = New-GoodReport
($fake.scenarios | Where-Object id -EQ 'missing-group.refusal').result = 'PASS'
$judgement = Test-RosetunLinuxReport -Report $fake -Status $finished -Stage $stage -Scenarios $scenarios
Assert-That 'a PASS for a scenario with no check is an error' ($judgement.Verdict -eq 'ERROR')
$extra = New-GoodReport
$extra.scenarios = @($extra.scenarios) + [pscustomobject]@{ id = 'invented.scenario'; evidence = 'transport-fixture'; result = 'PASS'; reason = ''; duration_ms = 1 }
$judgement = Test-RosetunLinuxReport -Report $extra -Status $finished -Stage $stage -Scenarios $scenarios
Assert-That 'an unknown scenario is an error' ($judgement.Verdict -eq 'ERROR')
$evidence = New-GoodReport
($evidence.scenarios | Where-Object id -EQ 'unit.helper-uid-policies').evidence = 'transport-fixture'
$judgement = Test-RosetunLinuxReport -Report $evidence -Status $finished -Stage $stage -Scenarios $scenarios
Assert-That 'relabelled evidence is an error' ($judgement.Verdict -eq 'ERROR')

# --- failures and the guest's own claims
$failing = New-GoodReport
($failing.scenarios | Where-Object id -EQ 'credentials.spoofed-hello').result = 'FAIL'
$failing.summary.pass--; $failing.summary.fail++
$judgement = Test-RosetunLinuxReport -Report $failing -Status $finished -Stage $stage -Scenarios $scenarios
Assert-That 'a failed scenario fails the run' ($judgement.Verdict -eq 'FAIL' -or $judgement.Verdict -eq 'ERROR')
Assert-That 'a failed run claims no coverage' ($judgement.Coverage -eq 'none')
$lying = New-GoodReport
($lying.scenarios | Where-Object id -EQ 'credentials.spoofed-hello').result = 'FAIL'
$judgement = Test-RosetunLinuxReport -Report $lying -Status $finished -Stage $stage -Scenarios $scenarios
Assert-That 'a summary that disagrees with the lines is an error' ($judgement.Verdict -eq 'ERROR')

# --- cleanup is judged separately and its failure stops the run from passing
$dirty = New-GoodReport
$dirty.cleanup.status = 'ERROR'
$dirty.cleanup.problems = 'socket is not the recorded object; left untouched'
$judgement = Test-RosetunLinuxReport -Report $dirty -Status $finished -Stage $stage -Scenarios $scenarios
Assert-That 'a cleanup error is an error' ($judgement.Verdict -eq 'ERROR')
Assert-That 'the cleanup status is reported' ($judgement.CleanupStatus -eq 'ERROR')
$nocleanup = New-GoodReport
$nocleanup.PSObject.Properties.Remove('cleanup')
$judgement = Test-RosetunLinuxReport -Report $nocleanup -Status $finished -Stage $stage -Scenarios $scenarios
Assert-That 'a report without a cleanup section is an error' ($judgement.Verdict -eq 'ERROR')

$badSchema = New-GoodReport
$badSchema.schema = 7
$judgement = Test-RosetunLinuxReport -Report $badSchema -Status $finished -Stage $stage -Scenarios $scenarios
Assert-That 'an unknown schema is an error' ($judgement.Verdict -eq 'ERROR')

# --- timeouts of native programs
$pwsh = (Get-Process -Id $PID).Path
$threw = $false
$started = [DateTime]::UtcNow
try { $null = Invoke-RosetunLinuxProcess -FilePath $pwsh -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 60') -TimeoutSeconds 2 }
catch { $threw = "$_" -match 'TIMEOUT' }
Assert-That 'a hanging program is killed and reported as a timeout' $threw
Assert-That 'the timeout fires on time' (([DateTime]::UtcNow - $started).TotalSeconds -lt 20)
$ok = Invoke-RosetunLinuxProcess -FilePath $pwsh -ArgumentList @('-NoProfile', '-Command', 'Write-Output hello; exit 3') -TimeoutSeconds 30
Assert-That 'exit code and output are returned' ($ok.ExitCode -eq 3 -and $ok.Output.Trim() -eq 'hello')
$script:Beats = 0
$null = Invoke-RosetunLinuxProcess -FilePath $pwsh -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 3') -TimeoutSeconds 30 `
    -Heartbeat { param($elapsed) $script:Beats++ } -HeartbeatSeconds 1
Assert-That 'a long program reports its elapsed time' ($script:Beats -ge 1)

# --- dirty working trees: a host build refuses them and names the paths
$listed = ConvertFrom-RosetunLinuxGitStatus " M tools/vm/linux/README.md`n?? notes/`r`nA  crates/x.rs`n"
Assert-That 'changed paths are read from git status' (($listed -join '|') -eq 'tools/vm/linux/README.md|notes/|crates/x.rs')
Assert-That 'a clean status lists nothing' (@(ConvertFrom-RosetunLinuxGitStatus '').Count -eq 0)
$dirtySource = [pscustomobject]@{ Sha = 'c' * 40; Dirty = $true; DirtyEntries = 2; DirtyPaths = @('tools/vm/linux/README.md', 'notes/'); DirtyDigest = 'd' * 64 }
$refusedBuild = ''
try { Assert-RosetunLinuxCleanSource -Source $dirtySource } catch { $refusedBuild = "$_" }
Assert-That 'a dirty tree stops the host build' ($refusedBuild -match 'differs from HEAD')
Assert-That 'the refusal names every changed path' ($refusedBuild -match 'tools/vm/linux/README\.md' -and $refusedBuild -match 'notes/')
$many = @(1..40 | ForEach-Object { "file$_.txt" })
Assert-That 'a long path list is cut with a count' ((Format-RosetunLinuxPathList $many) -match 'and 10 more')
Assert-That 'a clean tree passes' ($null -eq (Assert-RosetunLinuxCleanSource -Source ([pscustomobject]@{ Sha = 'c' * 40; Dirty = $false; DirtyPaths = @() })))
$dirtyStage = [pscustomobject]@{
    RunId = $runId; BootId = $bootId; Source = $dirtySource
    Artifacts = [pscustomobject]@{ Confirmed = $false; Note = 'x'; Hashes = [ordered]@{} }
}
$dirtyText = Format-RosetunLinuxReport -Judgement (Test-RosetunLinuxReport -Report (New-GoodReport) -Status $finished -Stage $stage -Scenarios $scenarios) -Stage $dirtyStage
Assert-That 'the report names the changed paths of a dirty source' ($dirtyText -match 'dirty=True' -and $dirtyText -match '- notes/')
$oldStage = [pscustomobject]@{
    RunId = $runId; BootId = $bootId; Source = [pscustomobject]@{ Sha = 'c' * 40; Dirty = $true; DirtyEntries = 1 }
    Artifacts = [pscustomobject]@{ Confirmed = $false; Note = 'x'; Hashes = [ordered]@{} }
}
$oldText = Format-RosetunLinuxReport -Judgement (Test-RosetunLinuxReport -Report (New-GoodReport) -Status $finished -Stage $stage -Scenarios $scenarios) -Stage $oldStage
Assert-That 'a stage record from before path lists still formats' ($oldText -match 'dirty=True')

# --- ELF detection
$tmp = Join-Path ([IO.Path]::GetTempPath()) "rosetun-l2-selftest-$([guid]::NewGuid().ToString('N'))"
$null = New-Item -ItemType Directory -Path $tmp
try {
    function New-Header { param([byte[]]$Bytes) $b = [byte[]]::new(64); $Bytes.CopyTo($b, 0); $b }
    $elf = New-Header @(0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0x3E, 0)
    [IO.File]::WriteAllBytes((Join-Path $tmp 'good'), $elf)
    Assert-That 'an x86-64 PIE ELF is accepted' ((Test-RosetunLinuxElf (Join-Path $tmp 'good')).Ok)
    $arm = New-Header @(0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0xB7, 0)
    [IO.File]::WriteAllBytes((Join-Path $tmp 'arm'), $arm)
    Assert-That 'an ARM64 ELF is refused' (-not (Test-RosetunLinuxElf (Join-Path $tmp 'arm')).Ok)
    $pe = New-Header @(0x4D, 0x5A, 0x90, 0)
    [IO.File]::WriteAllBytes((Join-Path $tmp 'pe'), $pe)
    $peResult = Test-RosetunLinuxElf (Join-Path $tmp 'pe')
    Assert-That 'a Windows PE file is refused' ((-not $peResult.Ok) -and $peResult.Reason -match 'Windows')
    [IO.File]::WriteAllText((Join-Path $tmp 'script'), "#!/bin/sh`necho hi`n")
    Assert-That 'a script is refused' (-not (Test-RosetunLinuxElf (Join-Path $tmp 'script')).Ok)
    Assert-That 'a missing file is refused' (-not (Test-RosetunLinuxElf (Join-Path $tmp 'nothing')).Ok)
    # A path relative to PowerShell's location, which is not the process's directory.
    Push-Location -LiteralPath $tmp
    try { Assert-That 'a relative path is read from the current location' ((Test-RosetunLinuxElf '.\good').Ok) }
    finally { Pop-Location }

    # --- artifact provenance
    $dir = Join-Path $tmp 'artifacts'
    $null = New-Item -ItemType Directory -Path $dir
    $hashes = [ordered]@{}
    foreach ($name in @('l2_transport_fixture', 'rosetun_helper_privileged_tests', 'rosetun_ipc_tests')) {
        $bytes = New-Header @(0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0x3E, 0)
        $bytes[40] = [byte]$hashes.Count
        [IO.File]::WriteAllBytes((Join-Path $dir $name), $bytes)
        $hashes[$name] = @{ sha256 = Get-RosetunLinuxFileSha256 (Join-Path $dir $name) }
    }
    $sha = 'a' * 40
    $source = [pscustomobject]@{ Sha = $sha; Dirty = $false; DirtyEntries = 0; DirtyDigest = 'd' * 64 }
    function Write-Provenance {
        param([string]$BuildSha, $Dirty, [string]$Digest)
        $value = [ordered]@{ schema = 1; target = 'x86_64-unknown-linux-gnu'; source_sha = $BuildSha; source_dirty = $Dirty; source_dirty_digest = $Digest
            toolchain = @{ rustc = 'rustc 1.96.0' }; built_on = @{ os = 'Debian' }; artifacts = $hashes }
        [IO.File]::WriteAllText((Join-Path $dir 'provenance.json'), ($value | ConvertTo-Json -Depth 6))
    }
    Write-Provenance -BuildSha $sha -Dirty $false -Digest ('d' * 64)
    $artifacts = Get-RosetunLinuxArtifacts -ArtifactDir $dir -Source $source
    Assert-That 'matching provenance confirms the origin' $artifacts.Confirmed
    Write-Provenance -BuildSha ('b' * 40) -Dirty $false -Digest ('d' * 64)
    $artifacts = Get-RosetunLinuxArtifacts -ArtifactDir $dir -Source $source
    Assert-That 'a different build commit leaves the origin unconfirmed' (-not $artifacts.Confirmed)
    Write-Provenance -BuildSha 'unknown' -Dirty 'unknown' -Digest 'unknown'
    $artifacts = Get-RosetunLinuxArtifacts -ArtifactDir $dir -Source $source
    Assert-That 'an unknown build commit leaves the origin unconfirmed' (-not $artifacts.Confirmed)
    Write-Provenance -BuildSha $sha -Dirty $false -Digest ('e' * 64)
    $artifacts = Get-RosetunLinuxArtifacts -ArtifactDir $dir -Source $source
    Assert-That 'a different working tree leaves the origin unconfirmed' (-not $artifacts.Confirmed)
    Write-Provenance -BuildSha $sha -Dirty $false -Digest ('d' * 64)
    [IO.File]::AppendAllText((Join-Path $dir 'rosetun_ipc_tests'), 'x')
    $replaced = $false
    try { $null = Get-RosetunLinuxArtifacts -ArtifactDir $dir -Source $source } catch { $replaced = "$_" -match 'does not match' }
    Assert-That 'an artifact changed after the build is refused' $replaced

    # --- staging manifest
    $stageRoot = Join-Path $tmp 'stage'
    [IO.File]::WriteAllBytes((Join-Path $dir 'rosetun_ipc_tests'), (New-Header @(0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0x3E, 0)))
    $jobEnv = New-RosetunLinuxJobEnv -RunId $runId -StandId 'stand-1' -BootId $bootId -UserA 'ipc_owner' -UserB 'ipc_other' -BiosGuid '00112233-4455-6677-8899-aabbccddeeff'
    $staged = New-RosetunLinuxStage -StageRoot $stageRoot -RunId $runId -ArtifactDir $dir -JobEnv $jobEnv
    $manifest = Get-Content -LiteralPath (Join-Path $staged.Directory 'manifest.sha256')
    Assert-That 'the manifest lists the guest scripts' (@($manifest | Where-Object { $_ -match 'guest/start\.sh$' }).Count -eq 1)
    Assert-That 'the manifest lists the artifacts' (@($manifest | Where-Object { $_ -match 'artifacts/l2_transport_fixture$' }).Count -eq 1)
    Assert-That 'the manifest does not list itself' (@($manifest | Where-Object { $_ -match 'manifest\.sha256$' }).Count -eq 0)
    $crlf = [IO.File]::ReadAllText((Join-Path $staged.Directory 'guest/run-l2.sh')).Contains("`r")
    Assert-That 'staged scripts use LF endings' (-not $crlf)
    $again = $false
    try { $null = New-RosetunLinuxStage -StageRoot $stageRoot -RunId $runId -ArtifactDir $dir -JobEnv $jobEnv } catch { $again = "$_" -match 'already exists' }
    Assert-That 'a run id cannot be staged twice' $again
    Assert-That 'the stage carries the launcher for a manual start' (@($manifest | Where-Object { $_ -match '  guest/launch\.sh$' }).Count -eq 1)
    Assert-That 'the installer stays out of the stage' (@($manifest | Where-Object { $_ -match 'install-launcher' }).Count -eq 0)
    $startText = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\guest\start.sh') -Raw
    $requiredMatch = [regex]::Match($startText, '(?s)L2_START_REQUIRED=\((.*?)\)')
    $required = @($requiredMatch.Groups[1].Value -split '\s+' | Where-Object { $_ -ne '' } | Sort-Object -CaseSensitive)
    $stagedFiles = @($staged.Files | Sort-Object -CaseSensitive)
    Assert-That 'the host stages exactly the files start.sh requires' (($required -join ',') -ceq ($stagedFiles -join ','))
    Assert-That 'the staged launcher is byte-equal to guest/launch.sh in LF' (
        (Get-RosetunLinuxFileSha256 (Join-Path $staged.Directory 'guest/launch.sh')) -eq
        (Get-RosetunLinuxTextSha256 ((Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\guest\launch.sh') -Raw).Replace("`r`n", "`n"))))
}
finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# --- job description and SSH hygiene
$unsafe = $false
try { $null = New-RosetunLinuxJobEnv -RunId $runId -StandId 'a;b' -BootId $bootId -UserA 'x' -UserB 'y' -BiosGuid 'g' } catch { $unsafe = $true }
Assert-That 'a job value with shell syntax is refused' $unsafe
$same = $false
try { $null = New-RosetunLinuxJobEnv -RunId $runId -StandId 's' -BootId $bootId -UserA 'x' -UserB 'x' -BiosGuid 'g' } catch { $same = $true }
Assert-That 'two identical test accounts are refused' $same
$badRun = $false
try { $null = New-RosetunLinuxJobEnv -RunId '../x' -StandId 's' -BootId $bootId -UserA 'x' -UserB 'y' -BiosGuid 'g' } catch { $badRun = $true }
Assert-That 'a run id with a path is refused' $badRun

$windows = $false
try { $null = Get-RosetunLinuxVmIdentity -VmName 'rosetun-test' -VmId ([guid]::NewGuid()) } catch { $windows = "$_" -match 'Windows test VM' }
Assert-That 'the Windows test VM is never accepted as a Linux stand' $windows

$known = Join-Path ([IO.Path]::GetTempPath()) "kh-$([guid]::NewGuid().ToString('N'))"
$key = Join-Path ([IO.Path]::GetTempPath()) "id-$([guid]::NewGuid().ToString('N'))"
try {
    [IO.File]::WriteAllText($known, "example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderPlaceholderPlaceholder00`n")
    [IO.File]::WriteAllText($key, "placeholder`n")
    $target = New-RosetunLinuxTarget -HostName '192.0.2.10' -User 'tester' -KnownHostsPath $known -IdentityFile $key -HostKeyAlias 'stand-1'
    $optionList = @(Get-RosetunLinuxSshOptions $target)
    $options = $optionList -join ' '
    Assert-That 'host keys are verified strictly' ($options -match 'StrictHostKeyChecking=yes')
    Assert-That 'host key checking is never disabled' ($options -notmatch 'StrictHostKeyChecking=(no|accept-new)')
    Assert-That 'the host key is looked up by stand id, not by address' ($optionList -contains 'HostKeyAlias=stand-1')
    Assert-That 'the address is never checked against known_hosts' ($optionList -contains 'CheckHostIP=no')
    Assert-That 'ssh never rewrites the pinned file' ($optionList -contains 'UpdateHostKeys=no')
    Assert-That 'passwords are never prompted for' ($options -match 'PasswordAuthentication=no' -and $options -match 'BatchMode=yes')
    Assert-That 'agent forwarding is off' ($options -match 'ForwardAgent=no')
    $pendingOptions = @(Get-RosetunLinuxSshOptions $target -AcceptNewKeyInto 'C:\x\kh.pending')
    Assert-That 'a first key goes only into the pending file' (($pendingOptions -contains 'UserKnownHostsFile=C:/x/kh.pending') -and
        ($pendingOptions -contains 'StrictHostKeyChecking=accept-new') -and -not ($pendingOptions -match [regex]::Escape($known.Replace('\', '/'))))
    $noKnown = $false
    try { $null = New-RosetunLinuxTarget -HostName 'example.invalid' -User 'tester' -KnownHostsPath (Join-Path $env:TEMP 'nothing-here') -IdentityFile $key -HostKeyAlias 'stand-1' } catch { $noKnown = "$_" -match 'InitKnownHosts' }
    Assert-That 'a missing known_hosts file is refused with a hint' $noKnown
    $badHost = $false
    try { $null = New-RosetunLinuxTarget -HostName 'a b;c' -User 'tester' -KnownHostsPath $known -IdentityFile $key -HostKeyAlias 'stand-1' } catch { $badHost = $true }
    Assert-That 'an unsafe host name is refused' $badHost
    $badAlias = $false
    try { $null = New-RosetunLinuxTarget -HostName 'example.invalid' -User 'tester' -KnownHostsPath $known -IdentityFile $key -HostKeyAlias 'a b' } catch { $badAlias = $true }
    Assert-That 'an unsafe stand id is refused as alias' $badAlias
    $pendingTarget = $false
    try { $null = New-RosetunLinuxTarget -HostName 'example.invalid' -User 'tester' -KnownHostsPath "$known.pending" -IdentityFile $key -HostKeyAlias 'stand-1' -AllowMissingKnownHosts } catch { $pendingTarget = "$_" -match 'never confirmed' }
    Assert-That 'an unconfirmed pending file is never used as known_hosts' $pendingTarget
}
finally {
    Remove-Item -LiteralPath $known, $key -Force -ErrorAction SilentlyContinue
}

# --- first host key: kept only after the owner answers yes
$khDir = Join-Path ([IO.Path]::GetTempPath()) "kh-init-$([guid]::NewGuid().ToString('N'))"
$null = New-Item -ItemType Directory -Path $khDir
try {
    $line = "stand-1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderPlaceholderPlaceholder00`n"
    $pending = Join-Path $khDir 'kh.pending'
    $pinned = Join-Path $khDir 'kh'
    [IO.File]::WriteAllText($pending, $line)
    Assert-That 'a single ed25519 key under the stand id is a valid pending key' (Test-RosetunLinuxPendingHostKey -Path $pending -HostKeyAlias 'stand-1')
    Assert-That 'a pending key under another name is refused' (-not (Test-RosetunLinuxPendingHostKey -Path $pending -HostKeyAlias 'stand-2'))
    [IO.File]::WriteAllText($pending, $line + $line.Replace('stand-1', 'stand-1'))
    Assert-That 'a pending file with two keys is refused' (-not (Test-RosetunLinuxPendingHostKey -Path $pending -HostKeyAlias 'stand-1'))
    [IO.File]::WriteAllText($pending, $line.Replace('ssh-ed25519', 'ssh-rsa'))
    Assert-That 'a pending key of another type is refused' (-not (Test-RosetunLinuxPendingHostKey -Path $pending -HostKeyAlias 'stand-1'))

    [IO.File]::WriteAllText($pending, $line)
    $kept = Complete-RosetunLinuxKnownHosts -PendingPath $pending -KnownHostsPath $pinned -Answer 'no'
    Assert-That 'an answer other than yes keeps nothing' ((-not $kept) -and -not (Test-Path $pinned) -and -not (Test-Path $pending))
    [IO.File]::WriteAllText($pending, $line)
    $kept = Complete-RosetunLinuxKnownHosts -PendingPath $pending -KnownHostsPath $pinned -Answer 'YES please'
    Assert-That 'only the exact answer yes confirms' ((-not $kept) -and -not (Test-Path $pinned))
    [IO.File]::WriteAllText($pending, $line)
    [IO.File]::WriteAllText($pinned, '')
    $kept = Complete-RosetunLinuxKnownHosts -PendingPath $pending -KnownHostsPath $pinned -Answer 'yes'
    Assert-That 'a confirmed key replaces an empty file' ($kept -and (Get-Content -LiteralPath $pinned -Raw) -eq $line -and -not (Test-Path $pending))
    $refused = $false
    try { Assert-RosetunLinuxKnownHostsInitAllowed -KnownHostsPath $pinned } catch { $refused = "$_" -match 'never replaces' }
    Assert-That 'an existing pinned key is never replaced by -InitKnownHosts' $refused
}
finally {
    Remove-Item -LiteralPath $khDir -Recurse -Force -ErrorAction SilentlyContinue
}

# --- settings file and parameter precedence
$settingsDir = Join-Path ([IO.Path]::GetTempPath()) "stand-$([guid]::NewGuid().ToString('N'))"
$null = New-Item -ItemType Directory -Path $settingsDir
try {
    $file = Join-Path $settingsDir 'stand.local.psd1'
    [IO.File]::WriteAllText($file, "@{ VmName = 'vm-a'; StandId = 'stand-1'; SshUser = 'l2admin'; KnownHostsPath = '~\kh'; IdentityFile = '%ROSETUN_L2_SELFTEST%\id'; UserA = 'ipc_owner'; SshHost = '' }")
    $env:ROSETUN_L2_SELFTEST = 'C:\example'
    $fromFile = Read-RosetunLinuxStandSettings -Path $file
    $resolved = Resolve-RosetunLinuxStandSettings -Settings $fromFile -Explicit @{ VmName = 'vm-b'; UserB = 'ipc_other' }
    Assert-That 'an explicit parameter wins over the file' ($resolved.VmName -eq 'vm-b')
    Assert-That 'the file fills what the command line leaves out' ($resolved.StandId -eq 'stand-1' -and $resolved.UserA -eq 'ipc_owner' -and $resolved.UserB -eq 'ipc_other')
    Assert-That 'defaults fill what neither sets' ($resolved.Checkpoint -eq 'l2-clean' -and $resolved.WslDistro -eq 'Debian' -and $resolved.SshPort -eq 22)
    Assert-That 'an empty SshHost counts as not set' ($null -eq $resolved.SshHost)
    Assert-That 'paths expand ~ and environment variables' ($resolved.KnownHostsPath -eq "$HOME\kh" -and $resolved.IdentityFile -eq 'C:\example\id')
    [IO.File]::WriteAllText($file, "@{ VmNmae = 'vm-a' }")
    $typo = $false
    try { $null = Read-RosetunLinuxStandSettings -Path $file } catch { $typo = "$_" -match "Unknown setting 'VmNmae'" }
    Assert-That 'an unknown setting is refused' $typo
    [IO.File]::WriteAllText($file, "@{ SshPort = '22' }")
    $port = $false
    try { $null = Read-RosetunLinuxStandSettings -Path $file } catch { $port = $true }
    Assert-That 'a port given as text is refused' $port
    $missing = $false
    try { Assert-RosetunLinuxStandSettings -Stand $resolved -Names @('VmName', 'SshHost') -SettingsPath $file } catch { $missing = "$_" -match 'SshHost' }
    Assert-That 'a missing setting is named' $missing
    $absent = $false
    try { $null = Read-RosetunLinuxStandSettings -Path (Join-Path $settingsDir 'none.psd1') } catch { $absent = "$_" -match 'stand.example.psd1' }
    Assert-That 'a missing settings file points to the example' $absent
}
finally {
    Remove-Item Env:\ROSETUN_L2_SELFTEST -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $settingsDir -Recurse -Force -ErrorAction SilentlyContinue
}

# --- automatic or manual start of the job
$good = 'a' * 64
$choice = Select-RosetunLinuxStartMode -InstalledHash $good -ExpectedHash $good -SudoExitCode 0
Assert-That 'the current launcher with its sudo rule starts the job automatically' ($choice.Mode -eq 'auto')
$choice = Select-RosetunLinuxStartMode -InstalledHash 'missing' -ExpectedHash $good -SudoExitCode 1
Assert-That 'a missing launcher falls back to the manual command' ($choice.Mode -eq 'manual' -and -not $choice.Reinstall -and $choice.Reason -match 'not installed')
$choice = Select-RosetunLinuxStartMode -InstalledHash ('b' * 64) -ExpectedHash $good -SudoExitCode 0
Assert-That 'an old launcher falls back and asks for a reinstall' ($choice.Mode -eq 'manual' -and $choice.Reinstall)
$choice = Select-RosetunLinuxStartMode -InstalledHash $good -ExpectedHash $good -SudoExitCode 1
Assert-That 'a launcher without the NOPASSWD rule falls back' ($choice.Mode -eq 'manual' -and $choice.Reason -match 'sudo -n')
$choice = Select-RosetunLinuxStartMode -InstalledHash 'sha256sum: permission denied' -ExpectedHash $good -SudoExitCode 0
Assert-That 'an unreadable launcher falls back' ($choice.Mode -eq 'manual')
$stageDir = '/home/l2admin/rosetun-l2-stage/' + $runId
Assert-That 'the manual command runs the staged launcher with sudo' (
    (Get-RosetunLinuxManualStartCommand -StageDir $stageDir -RunId $runId -ManifestHash $good) -ceq "sudo bash $stageDir/guest/launch.sh $runId $stageDir $good")
Assert-That 'the automatic command never asks for a password' (
    (Get-RosetunLinuxLauncherStartCommand -StageDir $stageDir -RunId $runId -ManifestHash $good) -ceq "sudo -n /usr/local/libexec/rosetun-l2/launch $runId $stageDir $good")
$launchText = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\guest\launch.sh') -Raw
Assert-That 'the host and the launcher agree on the installed path' ($launchText -match "(?m)^L2_LAUNCH_INSTALLED=$([regex]::Escape((Get-RosetunLinuxLauncherPath)))$")
Assert-That 'the install command passes both test accounts' (
    (Get-RosetunLinuxInstallCommand -Folder '/home/l2admin/rosetun-l2-launcher' -UserA 'ipc_owner' -UserB 'ipc_other') -ceq
    'sudo bash /home/l2admin/rosetun-l2-launcher/install-launcher.sh ipc_owner ipc_other')

# --- the entry script calls module functions only with parameters they have
$entryPath = Join-Path $PSScriptRoot '..\Invoke-LinuxL2Matrix.ps1'
$entryAst = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $entryPath).ProviderPath, [ref]$null, [ref]$null)
$moduleCommands = @{}
foreach ($command in @(Get-Command -Module RosetunLinuxVm)) { $moduleCommands[$command.Name] = $command }
$badCalls = [System.Collections.Generic.List[string]]::new()
$checkedCalls = 0
foreach ($call in $entryAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)) {
    $name = $call.GetCommandName()
    if ($null -eq $name -or -not $moduleCommands.ContainsKey($name)) { continue }
    $checkedCalls++
    $known = $moduleCommands[$name].Parameters.Keys
    foreach ($element in $call.CommandElements) {
        if ($element -isnot [System.Management.Automation.Language.CommandParameterAst]) { continue }
        $matched = @($known | Where-Object { $_ -like "$($element.ParameterName)*" })
        if ($matched.Count -eq 0) { $badCalls.Add("$name -$($element.ParameterName) (line $($element.Extent.StartLineNumber))") }
    }
}
Assert-That 'the entry script calls module functions' ($checkedCalls -gt 20)
Assert-That 'every parameter the entry script passes exists' ($badCalls.Count -eq 0) ($badCalls -join '; ')

# --- progress of a one-command run
Assert-That 'elapsed time reads as minutes and seconds' ((Format-RosetunLinuxElapsed ([TimeSpan]::FromSeconds(3725))) -eq '62:05')
Assert-That 'a job without status is waiting to start' ((Format-RosetunLinuxJobProgress -Status $null) -eq 'waiting for the job to start')
Assert-That 'a running job names its scenario' ((Format-RosetunLinuxJobProgress -Status $running) -eq 'job running, stale.restart-refused')
$noisy = [pscustomobject]@{ state = 'running'; current = "x`e[31m" + ('y' * 200) }
$noisyLine = Format-RosetunLinuxJobProgress -Status $noisy
Assert-That 'guest text in progress lines is printable and short' ($noisyLine -notmatch "`e" -and $noisyLine.Length -le 100)
Assert-That 'the automatic run waits for the job limit plus cleanup' ((Get-RosetunLinuxRunWaitSeconds -JobTimeoutSeconds 900) -eq 1200)
Assert-That 'a manual start leaves time to paste the command' ((Get-RosetunLinuxRunWaitSeconds -JobTimeoutSeconds 900 -Manual) -gt 1200)

# --- guest address from the adapter's list
Assert-That 'the first usable IPv4 address is chosen' ((Select-RosetunLinuxGuestAddress @('fe80::1', '169.254.10.20', '2001:db8::5', '192.0.2.10', '198.51.100.7')) -eq '192.0.2.10')
Assert-That 'IPv6 and link-local addresses alone give no address' ($null -eq (Select-RosetunLinuxGuestAddress @('fe80::1', '169.254.1.1', '2001:db8::1')))
Assert-That 'an empty adapter list gives no address' ($null -eq (Select-RosetunLinuxGuestAddress @()))
Assert-That 'loopback and junk are skipped' ((Select-RosetunLinuxGuestAddress @('127.0.0.1', 'not-an-address', '203.0.113.4')) -eq '203.0.113.4')

# --- subnet of the guest address against the host's Default Switch
Assert-That 'the prefix length counts' (-not (Test-RosetunLinuxSameSubnet -Address '192.0.2.77' -Network '192.0.2.1' -PrefixLength 28))
Assert-That 'an address inside a /24 is in the same subnet' (Test-RosetunLinuxSameSubnet -Address '192.0.2.77' -Network '192.0.2.1' -PrefixLength 24)
Assert-That 'an address of another subnet is not' (-not (Test-RosetunLinuxSameSubnet -Address '198.51.100.7' -Network '192.0.2.1' -PrefixLength 20))
Assert-That 'a /0 contains everything' (Test-RosetunLinuxSameSubnet -Address '203.0.113.9' -Network '192.0.2.1' -PrefixLength 0)
Assert-That 'junk is never in the subnet' (-not (Test-RosetunLinuxSameSubnet -Address 'not-an-address' -Network '192.0.2.1' -PrefixLength 24))
Assert-That 'IPv6 is never in an IPv4 subnet' (-not (Test-RosetunLinuxSameSubnet -Address '2001:db8::1' -Network '192.0.2.1' -PrefixLength 24))

$switch = @([pscustomobject]@{ Address = '192.0.2.1'; PrefixLength = 24 })
$stale = Format-RosetunLinuxSshSilence -TimeoutSeconds 300 -Address '198.51.100.7' -HostSubnets $switch -LastAnswer ''
Assert-That 'the silence names the Hyper-V address' ($stale -match '198\.51\.100\.7, from Hyper-V')
Assert-That 'the silence names the host subnet' ($stale -match '192\.0\.2\.1/24')
Assert-That 'a stale subnet is called out' ($stale -match 'Same subnet: no')
Assert-That 'an empty last answer is never printed empty' ($stale -match 'Last answer: no attempt finished')
Assert-That 'without SshHost there is no SshHost warning' ($stale -notmatch 'SshHost is set')
$reachable = Format-RosetunLinuxSshSilence -TimeoutSeconds 300 -Address '192.0.2.50' -HostSubnets $switch -LastAnswer 'connection refused'
Assert-That 'a reachable address points at the guest' ($reachable -match 'Same subnet: yes')
$pinned = Format-RosetunLinuxSshSilence -TimeoutSeconds 300 -Address '198.51.100.7' -AddressSource SshHost -HostSubnets $switch -LastAnswer 'x'
Assert-That 'a set SshHost is warned about' ($pinned -match 'SshHost is set' -and $pinned -match 'from SshHost')
$noSwitch = Format-RosetunLinuxSshSilence -TimeoutSeconds 300 -Address '' -HostSubnets @() -LastAnswer 'x'
Assert-That 'a missing address and switch are both said' ($noSwitch -match 'Guest address: none' -and $noSwitch -match 'has no IPv4 address')

# --- one failed ssh attempt in words
Assert-That 'an empty ssh failure is described' ((ConvertTo-RosetunLinuxSshAnswer -ExitCode 255 -ErrorText '' -HostName '192.0.2.5') -match 'printed nothing.*192\.0\.2\.5:22')
Assert-That 'a timeout is named' ((ConvertTo-RosetunLinuxSshAnswer -ExitCode 255 -ErrorText 'ssh: connect to host 192.0.2.5 port 22: Connection timed out' -HostName '192.0.2.5') -match '^connection timeout')
Assert-That 'a killed ssh is a timeout' ((ConvertTo-RosetunLinuxSshAnswer -ExitCode -1 -ErrorText 'TIMEOUT: ssh.exe did not finish within 25 s' -HostName '192.0.2.5') -match '^no answer')
Assert-That 'a refusal is named' ((ConvertTo-RosetunLinuxSshAnswer -ExitCode 255 -ErrorText 'connect to host 192.0.2.5 port 22: Connection refused' -HostName '192.0.2.5') -match '^connection refused')
Assert-That 'a refused key is named' ((ConvertTo-RosetunLinuxSshAnswer -ExitCode 255 -ErrorText 'l2admin@192.0.2.5: Permission denied (publickey).' -HostName '192.0.2.5') -match '^the key was refused')
Assert-That 'no route is named' ((ConvertTo-RosetunLinuxSshAnswer -ExitCode 255 -ErrorText 'connect to host 192.0.2.5 port 22: No route to host' -HostName '192.0.2.5') -match '^no route')

# --- the state a restore leaves tells what the checkpoint holds
Assert-That 'a powered-off checkpoint is accepted' ($null -eq (Get-RosetunLinuxRestoredStateProblem -VmName 'rosetun-linux-l2' -CheckpointName 'l2-clean' -State 'Off'))
$memory = Get-RosetunLinuxRestoredStateProblem -VmName 'rosetun-linux-l2' -CheckpointName 'l2-clean' -State 'Saved'
Assert-That 'a checkpoint with memory is refused' ($null -ne $memory -and $memory -match 'memory of a running guest')
foreach ($command in @(Get-RosetunLinuxCheckpointRemake -VmName 'rosetun-linux-l2' -CheckpointName 'l2-clean')) {
    Assert-That "the refusal carries '$command'" ($memory.Contains($command))
}
Assert-That 'the remake stops the VM before the checkpoint' (
    $memory.IndexOf('Stop-VM -Name rosetun-linux-l2') -lt $memory.IndexOf('Checkpoint-VM -Name rosetun-linux-l2'))
$odd = Get-RosetunLinuxRestoredStateProblem -VmName 'rosetun-linux-l2' -CheckpointName 'l2-clean' -State 'Paused'
Assert-That 'any other state is refused too' ($null -ne $odd -and $odd -match "'Paused'")

# --- the proxy stage: its own job and scenarios
$proxyStage = Get-RosetunLinuxStageProfile 'Proxy'
Assert-That 'the proxy stage runs its own job' ($proxyStage.Scripts -contains 'run-proxy.sh' -and $proxyStage.Scripts -notcontains 'run-l3.sh')
Assert-That 'the proxy stage carries the desktop tool' ($proxyStage.Artifacts -contains 'desktop_proxy')
$proxyScenarios = @(Get-RosetunLinuxScenarios -Stage Proxy)
Assert-That 'the proxy scenarios cover the strict kill switch, sharing, Lockdown and the desktop' (@($proxyScenarios | Where-Object { $_.Id -in @('strict.around-blocked', 'share.peer-refused', 'lockdown.share-closed', 'desktop.crash') }).Count -eq 4)

# --- L3: scenarios, requests, the stage's composition
$l3 = @(Get-RosetunLinuxScenarios -Stage L3)
Assert-That 'the L3 scenarios load' ($l3.Count -ge 15)
Assert-That 'every L3 scenario but the IPv6 neighbor (no IPv6 router on the Default Switch) is required' ((@($l3 | Where-Object { -not $_.Required } | ForEach-Object { $_.Id }) -join ',') -ceq 'ipv6.neighbor')
Assert-That 'the L3 list covers the crash and the stop' (@($l3 | Where-Object { $_.Id -in @('crash.helper-killed', 'crash.open-network', 'stop.removes-table') }).Count -eq 3)
Assert-That 'the L3 list covers a DNS-lock crash, inbound answers and forwarding' (@($l3 | Where-Object { $_.Id -in @('crash.dns-lock-killed', 'inbound.reply', 'forward.blocked') }).Count -eq 3)
Assert-That 'L2 keeps its own list' (@(Get-RosetunLinuxScenarios -Stage L2 | Where-Object { $_.Id -like 'killswitch.*' }).Count -eq 0)

$l3tmp = Join-Path ([IO.Path]::GetTempPath()) "rosetun-l3-selftest-$([guid]::NewGuid().ToString('N'))"
$null = New-Item -ItemType Directory -Path $l3tmp
try {
    $template = [ordered]@{
        node     = [ordered]@{ id = 'n'; server = 'node.example.com'; port = 1 }
        settings = [ordered]@{ kill_switch = $false; allow_lan = $true; auto_reconnect = $false }
    }
    $templatePath = Join-Path $l3tmp 'template.json'
    [IO.File]::WriteAllText($templatePath, ($template | ConvertTo-Json -Depth 5))
    $requestDir = Join-Path $l3tmp 'requests'
    $null = New-Item -ItemType Directory -Path $requestDir
    $requests = New-RosetunLinuxL3Requests -RequestPath $templatePath -HostAddress '192.0.2.1' -NodePort 8388 -OutDir $requestDir
    $read = { param($name) Get-Content -LiteralPath $requests[$name] -Raw | ConvertFrom-Json }
    $ks = & $read 'request-kill-switch.json'
    $lan = & $read 'request-lan.json'
    $dns = & $read 'request-dns-lock.json'
    Assert-That 'the requests point at the host node' ($ks.node.server -eq '192.0.2.1' -and $ks.node.port -eq 8388 -and $dns.node.server -eq '192.0.2.1')
    Assert-That 'the kill-switch request has the kill switch and no LAN' ($ks.settings.kill_switch -and -not $ks.settings.allow_lan)
    Assert-That 'the LAN request has both' ($lan.settings.kill_switch -and $lan.settings.allow_lan)
    Assert-That 'the DNS-lock request has no kill switch' (-not $dns.settings.kill_switch)
    Assert-That 'every request reconnects by itself' ($ks.settings.auto_reconnect -and $lan.settings.auto_reconnect -and $dns.settings.auto_reconnect)
    $withDns = [ordered]@{ node = $template.node; settings = [ordered]@{ kill_switch = $true; dns = [ordered]@{ server = '203.0.113.53'; server_name = 'dns.example.com' } } }
    $withDnsPath = Join-Path $l3tmp 'with-dns.json'
    [IO.File]::WriteAllText($withDnsPath, ($withDns | ConvertTo-Json -Depth 5))
    Assert-That "the DNS probe is the request's resolver" ((Select-RosetunLinuxDnsProbe -RequestPath $withDnsPath -ProbeAddress '198.51.100.1') -eq '203.0.113.53')
    Assert-That 'the DNS probe given wins' ((Select-RosetunLinuxDnsProbe -Explicit '192.0.2.53' -RequestPath $withDnsPath -ProbeAddress '198.51.100.1') -eq '192.0.2.53')
    Assert-That 'without a resolver address the DNS probe is the HTTPS probe' ((Select-RosetunLinuxDnsProbe -RequestPath $templatePath -ProbeAddress '198.51.100.1') -eq '198.51.100.1')
    $namedDns = [ordered]@{ node = $template.node; settings = [ordered]@{ dns = [ordered]@{ server = 'dns.example.com' } } }
    $namedPath = Join-Path $l3tmp 'named-dns.json'
    [IO.File]::WriteAllText($namedPath, ($namedDns | ConvertTo-Json -Depth 5))
    Assert-That 'a resolver by name is not a DNS probe' ((Select-RosetunLinuxDnsProbe -RequestPath $namedPath -ProbeAddress '198.51.100.1') -eq '198.51.100.1')
    $badDns = $false
    try { $null = Select-RosetunLinuxDnsProbe -Explicit 'x;y' -RequestPath $templatePath -ProbeAddress '198.51.100.1' } catch { $badDns = $true }
    Assert-That 'an invalid DNS probe is refused' $badDns
    $badHost = $false
    try { $null = New-RosetunLinuxL3Requests -RequestPath $templatePath -HostAddress '2001:db8::1' -NodePort 8388 -OutDir $requestDir } catch { $badHost = $true }
    Assert-That 'an IPv6 host address is refused' $badHost

    $l3build = Join-Path $l3tmp 'build'
    $null = New-Item -ItemType Directory -Path $l3build
    $elfHeader = [byte[]]@(0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0x3E, 0) + [byte[]]::new(44)
    $buildHashes = [ordered]@{}
    foreach ($name in @('rosetun-helper-privileged', 'rosetun')) {
        [IO.File]::WriteAllBytes((Join-Path $l3build $name), $elfHeader)
        $buildHashes[$name] = @{ sha256 = Get-RosetunLinuxFileSha256 (Join-Path $l3build $name) }
    }
    $l3source = [pscustomobject]@{ Sha = 'a' * 40; Dirty = $false; DirtyEntries = 0; DirtyDigest = 'd' * 64 }
    [IO.File]::WriteAllText((Join-Path $l3build 'provenance.json'), ([ordered]@{
                schema = 1; stage = 'l3'; target = 'x86_64-unknown-linux-gnu'; source_sha = 'a' * 40; source_dirty = $false
                source_dirty_digest = 'd' * 64; toolchain = @{}; built_on = @{}; artifacts = $buildHashes
            } | ConvertTo-Json -Depth 5))
    Assert-That 'an L3 build is checked against its own artifacts' (Get-RosetunLinuxArtifacts -ArtifactDir $l3build -Source $l3source -Stage L3).Confirmed
    $l2refused = $false
    try { $null = Get-RosetunLinuxArtifacts -ArtifactDir $l3build -Source $l3source -Stage L2 } catch { $l2refused = $true }
    Assert-That 'an L3 build is not an L2 build' $l2refused

    $engine = Join-Path $l3tmp 'sing-box'
    [IO.File]::WriteAllBytes($engine, $elfHeader)
    $extra = [ordered]@{}
    foreach ($name in $requests.Keys) { $extra[$name] = $requests[$name] }
    $extra['sing-box'] = $engine
    $extra['rosetun-helper.service'] = Join-Path $PSScriptRoot '..\..\..\..\packaging\linux\rosetun-helper.service'
    $jobExtra = [ordered]@{ HOST_ADDRESS = '192.0.2.1'; NODE_PORT = '8388'; PROBE_ADDRESS = '198.51.100.1'; DNS_PROBE_ADDRESS = '203.0.113.53' }
    $l3env = New-RosetunLinuxJobEnv -RunId $runId -StandId 'stand-1' -BootId $bootId -UserA 'ipc_owner' -UserB 'ipc_other' `
        -BiosGuid '00112233-4455-6677-8899-aabbccddeeff' -Extra $jobExtra
    Assert-That 'the L3 job carries the host node' ($l3env -match '(?m)^HOST_ADDRESS=192\.0\.2\.1$' -and $l3env -match '(?m)^NODE_PORT=8388$')
    $l3staged = New-RosetunLinuxStage -StageRoot (Join-Path $l3tmp 'stage') -RunId $runId -ArtifactDir $l3build -JobEnv $l3env -Stage L3 -Extra $extra
    $startText = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\guest\start.sh') -Raw
    $l3required = @([regex]::Match($startText, '(?s)L3_START_REQUIRED=\((.*?)\)').Groups[1].Value -split '\s+' | Where-Object { $_ -ne '' } | Sort-Object -CaseSensitive)
    Assert-That 'the host stages exactly the files start.sh requires for L3' (($l3required -join ',') -ceq (@($l3staged.Files | Sort-Object -CaseSensitive) -join ','))

    $unsafeExtra = $false
    try { $null = New-RosetunLinuxJobEnv -RunId $runId -StandId 's' -BootId $bootId -UserA 'a' -UserB 'b' -BiosGuid 'g' -Extra @{ HOST_ADDRESS = '1;reboot' } } catch { $unsafeExtra = $true }
    Assert-That 'an unsafe extra job value is refused' $unsafeExtra
    $unsafeKey = $false
    try { $null = New-RosetunLinuxJobEnv -RunId $runId -StandId 's' -BootId $bootId -UserA 'a' -UserB 'b' -BiosGuid 'g' -Extra @{ 'path' = 'x' } } catch { $unsafeKey = $true }
    Assert-That 'a lowercase extra job key is refused' $unsafeKey
}
finally {
    Remove-Item -LiteralPath $l3tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# --- timeout runs programs: a job's shell function after it only fails in the guest
foreach ($job in @('run-l2.sh', 'run-l3.sh', 'run-l4.sh', 'run-l5.sh')) {
    $text = Get-Content -LiteralPath (Join-Path $PSScriptRoot "..\guest\$job") -Raw
    $functions = @([regex]::Matches($text, '(?m)^\s*([a-z_][a-z0-9_]*)\(\) \{') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
    $commands = @([regex]::Matches($text, '\btimeout(?: --?[a-z-]+(?:=\S+)?)* +\S+ +([a-z_][a-z0-9_]*)(?=\s)') | ForEach-Object { $_.Groups[1].Value })
    $wrong = @($commands | Where-Object { $_ -in $functions })
    Assert-That "$job gives timeout no shell function" ($wrong.Count -eq 0) ($wrong -join ', ')
    Assert-That "$job has functions to check against" ($functions.Count -gt 0)
}
$probe = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\guest\run-l4.sh') -Raw
Assert-That 'the check catches the mistake it is for' ('timeout --kill-after=3 60 as_user /usr/bin/x' -match '\btimeout(?: --?[a-z-]+(?:=\S+)?)* +\S+ +([a-z_][a-z0-9_]*)(?=\s)' -and $Matches[1] -eq 'as_user')
$unguarded = [regex]::Matches($probe, '(?m)^\s*scope_probe [a-z-]+\s*$').Count
Assert-That 'every L4 scope probe stops on a scope that did not run' ($unguarded -eq 0) "$unguarded unguarded"

Write-Host "Test-LinuxHarness: $script:Passed passed, $script:Failed failed"
if ($script:Failed -gt 0) { exit 1 }
exit 0
