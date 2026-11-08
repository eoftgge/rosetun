# Opt-in recorder for the List matrix only. No VM operations belong here.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-RosetunListCanonicalString {
    param([AllowEmptyString()][string]$Value)
    $text = [Text.StringBuilder]::new()
    $null = $text.Append('"')
    foreach ($unit in $Value.ToCharArray()) {
        $code = [int]$unit
        $escaped = switch ($code) {
            8 { '\b' }; 9 { '\t' }; 10 { '\n' }; 12 { '\f' }; 13 { '\r' }
            34 { '\"' }; 92 { '\\' }
            default {
                if ($code -lt 32 -or $code -gt 126) { '\u' + $code.ToString('x4') }
                else { [string]$unit }
            }
        }
        $null = $text.Append($escaped)
    }
    $null = $text.Append('"')
    return $text.ToString()
}

function Get-RosetunListCatalogDigest {
    param([object[]]$Rows)
    # Fixed ordinal key order for the six-field catalog contract, with no whitespace.
    $items = foreach ($row in $Rows) {
        $fields = foreach ($key in @('detail', 'evidence', 'group', 'id', 'required', 'title')) {
            $value = if ($key -eq 'required') {
                if ($row.required -isnot [bool]) { throw 'Catalog required must be boolean.' }
                if ($row.required) { 'true' } else { 'false' }
            } else { ConvertTo-RosetunListCanonicalString $row.$key }
            '"' + $key + '":' + $value
        }
        '{' + ($fields -join ',') + '}'
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes('[' + ($items -join ',') + ']')
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-RosetunListNodeCleanup {
    param($ProcessIdentity)
    if ($null -eq $ProcessIdentity -or $null -eq $ProcessIdentity.CreationTicks) { return 'UNVERIFIED' }
    try {
        $process = Get-Process -Id $ProcessIdentity.Id -ErrorAction Stop
        $null = $process.Handle
        if ($process.StartTime.ToUniversalTime().Ticks -ne $ProcessIdentity.CreationTicks) {
            # PID reuse proves that the original process ended, not ownership of the replacement.
            return 'PASS'
        }
        if ($process.WaitForExit(5000)) { return 'PASS' }
        return 'ERROR'
    }
    catch [Microsoft.PowerShell.Commands.ProcessCommandException] {
        if ($_.FullyQualifiedErrorId -like 'NoProcessFoundForGivenId*') { return 'PASS' }
        return 'UNVERIFIED'
    }
    catch { return 'UNVERIFIED' }
}

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
    $rows = @(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'list-checks.json') -Encoding UTF8 -Raw | ConvertFrom-Json | ForEach-Object { $_ })
    # New-Item without Force refuses an existing run directory, even an empty one.
    $null = New-Item -Path $Directory -ItemType Directory -ErrorAction Stop
    $identity = @{ run_id = [guid]::NewGuid().ToString(); vm_id = $VmId; boot_id = $BootId }
    $plan = @{ schema = 'rosetun.windows-list.plan.v2'; suite = 'windows-list'; profile = 'exploratory'
        policy = @{ mode = 'exploratory' }; identity = $identity; catalog = $rows; catalog_digest = Get-RosetunListCatalogDigest $rows }
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

Export-ModuleMember -Function New-RosetunListResults, Add-RosetunListResult, Add-RosetunListError, Complete-RosetunListResults, Get-RosetunListNodeCleanup, Get-RosetunListCatalogDigest
