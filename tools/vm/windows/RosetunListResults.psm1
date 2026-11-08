# Opt-in recorder for the List matrix only. No VM operations belong here.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-RosetunListJson {
    param($Recorder, [string]$Name, $Value)
    $temporary = Join-Path $Recorder.Directory ($Name + '.tmp')
    try {
        $json = ConvertTo-Json -InputObject $Value -Depth 20 -Compress
        [IO.File]::WriteAllText($temporary, $json + "`n", [Text.UTF8Encoding]::new($false))
        [IO.File]::Move($temporary, (Join-Path $Recorder.Directory $Name))
    }
    catch { $Recorder.Broken = $true; throw 'List result write failed.' }
}

function New-RosetunListResults {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$VmId,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$BootId
    )
    $rows = @(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'list-checks.json') -Raw | ConvertFrom-Json)
    # New-Item without Force refuses an existing run directory, even an empty one.
    $null = New-Item -Path $Directory -ItemType Directory -ErrorAction Stop
    $identity = @{ run_id = [guid]::NewGuid().ToString(); vm_id = $VmId; boot_id = $BootId }
    $plan = @{ schema = 'rosetun.windows-list.plan.v1'; suite = 'windows-list'; profile = 'exploratory'
        policy = @{ mode = 'exploratory' }; identity = $identity; catalog = $rows }
    $recorder = [pscustomobject]@{ Directory = [IO.Path]::GetFullPath($Directory); Plan = $plan
        Events = [Collections.Generic.List[object]]::new(); Errors = [Collections.Generic.List[object]]::new()
        Broken = $false; Finished = $false }
    Write-RosetunListJson $recorder 'plan.json' $plan
    [IO.File]::WriteAllText((Join-Path $recorder.Directory 'events.jsonl'), '', [Text.UTF8Encoding]::new($false))
    return $recorder
}

function Add-RosetunListResult {
    param($Recorder, [string]$Id, [ValidateSet('PASS', 'FAIL', 'SKIP')][string]$Result,
        [ValidateSet('checked', 'condition-false', 'condition-exception', 'srs-compile-failed', 'interrupted')][string]$Reason)
    if ($Recorder.Finished -or $Id -notin $Recorder.Plan.catalog.id -or $Id -in @($Recorder.Events | ForEach-Object { $_.id })) {
        $Recorder.Broken = $true
        throw 'Invalid List result transition.'
    }
    $event = @{ schema = 'rosetun.windows-list.event.v1'; run_id = $Recorder.Plan.identity.run_id
        sequence = $Recorder.Events.Count + 1; id = $Id; result = $Result; reason = $Reason }
    $Recorder.Events.Add($event)
    try {
        [IO.File]::AppendAllText((Join-Path $Recorder.Directory 'events.jsonl'),
            (ConvertTo-Json -InputObject $event -Compress) + "`n", [Text.UTF8Encoding]::new($false))
    }
    catch { $Recorder.Broken = $true; throw 'List event write failed.' }
}

function Add-RosetunListError {
    param($Recorder, [ValidateSet('execution', 'cleanup', 'export')][string]$Place)
    $Recorder.Errors.Add(@{ reason = 'infrastructure-error'; place = $Place })
}

function Complete-RosetunListResults {
    param($Recorder, [ValidateSet('PASS', 'ERROR', 'UNVERIFIED')][string]$Cleanup,
        [string]$EndBootId, [bool]$Aborted = $false)
    if ($Recorder.Finished) { throw 'List results already finalized.' }
    if ($Aborted) { Add-RosetunListError $Recorder execution }
    if ($Recorder.Broken) { Add-RosetunListError $Recorder export }
    foreach ($row in $Recorder.Plan.catalog) {
        if ($row.id -notin @($Recorder.Events | ForEach-Object { $_.id })) {
            Add-RosetunListResult $Recorder $row.id SKIP interrupted
        }
    }
    $summary = @{ total = $Recorder.Events.Count }
    foreach ($name in @('PASS', 'FAIL', 'SKIP')) {
        $summary[$name.ToLowerInvariant()] = @($Recorder.Events | Where-Object { $_.result -eq $name }).Count
    }
    $report = @{ schema = 'rosetun.windows-list.report.v1'; identity = $Recorder.Plan.identity
        boot_id_at_end = $EndBootId; checks = $Recorder.Events.ToArray(); summary = $summary
        cleanup = @{ status = $Cleanup }; errors = $Recorder.Errors.ToArray() }
    Write-RosetunListJson $Recorder 'report.json' $report
    Write-RosetunListJson $Recorder 'status.json' @{
        schema = 'rosetun.windows-list.status.v1'; identity = $Recorder.Plan.identity
        state = 'finished'; event_count = $Recorder.Events.Count
    }
    $Recorder.Finished = $true
    if ($Recorder.Broken) { throw 'List result export failed.' }
}

Export-ModuleMember -Function New-RosetunListResults, Add-RosetunListResult, Add-RosetunListError, Complete-RosetunListResults
