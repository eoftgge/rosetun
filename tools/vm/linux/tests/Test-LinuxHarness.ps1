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
    $target = New-RosetunLinuxTarget -HostName 'example.invalid' -User 'tester' -KnownHostsPath $known -IdentityFile $key
    $options = (Get-RosetunLinuxSshOptions $target) -join ' '
    Assert-That 'host keys are verified strictly' ($options -match 'StrictHostKeyChecking=yes')
    Assert-That 'host key checking is never disabled' ($options -notmatch 'StrictHostKeyChecking=(no|accept-new)')
    Assert-That 'passwords are never prompted for' ($options -match 'PasswordAuthentication=no' -and $options -match 'BatchMode=yes')
    Assert-That 'agent forwarding is off' ($options -match 'ForwardAgent=no')
    $noKnown = $false
    try { $null = New-RosetunLinuxTarget -HostName 'example.invalid' -User 'tester' -KnownHostsPath (Join-Path $env:TEMP 'nothing-here') -IdentityFile $key } catch { $noKnown = $true }
    Assert-That 'a missing known_hosts file is refused' $noKnown
    $badHost = $false
    try { $null = New-RosetunLinuxTarget -HostName 'a b;c' -User 'tester' -KnownHostsPath $known -IdentityFile $key } catch { $badHost = $true }
    Assert-That 'an unsafe host name is refused' $badHost
}
finally {
    Remove-Item -LiteralPath $known, $key -Force -ErrorAction SilentlyContinue
}

Write-Host "Test-LinuxHarness: $script:Passed passed, $script:Failed failed"
if ($script:Failed -gt 0) { exit 1 }
exit 0
