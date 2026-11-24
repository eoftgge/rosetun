# Synthetic producer and recorder self-tests. Never imports the VM module.
param([Parameter(Mandatory)][string]$Directory,
    [ValidateSet('success', 'fail', 'abort', 'srs', 'cleanup', 'fail-abort', 'write', 'reuse')][string]$Case = 'success')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\RosetunListResults.psm1') -Force
# Load only Test-Step's AST, without executing the matrix or importing Hyper-V.
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot '..\Invoke-ListMatrix.ps1'), [ref]$null, [ref]$parseErrors)
if (@($parseErrors).Count) { throw 'Matrix does not parse.' }
$step = $ast.Find({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Test-Step'
}, $false)
. ([scriptblock]::Create($step.Extent.Text))
$results = [Collections.Generic.List[object]]::new()
$r = New-RosetunListResults -Directory $Directory -VmId 'synthetic-vm' -BootId 'synthetic-boot'
if ($Case -eq 'reuse') {
    try { $null = New-RosetunListResults -Directory $Directory -VmId 'other' -BootId 'other' }
    catch { Write-Host 'PASS directory reuse rejected'; exit 0 }
    throw 'Directory reused.'
}
$recorder = $r
foreach ($row in $r.Plan.catalog) {
    if ($Case -in @('abort', 'fail-abort') -and $r.Events.Count -eq 2) { break }
    $result = 'PASS'; $reason = 'checked'
    if (($Case -in @('fail', 'fail-abort') -and $r.Events.Count -eq 0) -or
        ($Case -eq 'srs' -and $row.id -eq 'binary.compile')) {
        $result = 'FAIL'; $reason = 'condition-exception'
    }
    if ($Case -eq 'srs' -and $row.detail -eq 'binary.compile') {
        $result = 'SKIP'; $reason = 'srs-compile-failed'
    }
    if ($result -eq 'SKIP') {
        Add-RosetunListResult $r $row.id $result $reason
    }
    elseif ($reason -eq 'condition-exception') {
        Test-Step 'synthetic' 'throws' -Id $row.id { throw 'private diagnostic marker' }
    }
    else {
        Test-Step 'synthetic' 'condition' -Id $row.id { $result -eq 'PASS' }
    }
    # An event must be on disk before finalization.
    $lines = @(Get-Content -LiteralPath (Join-Path $Directory 'events.jsonl'))
    if ($lines.Count -ne $r.Events.Count) { throw 'Event not flushed.' }
}
if ($Case -eq 'write') {
    # A directory at the temporary file path deterministically refuses writes.
    $null = New-Item -ItemType Directory -Path (Join-Path $Directory 'report.json.tmp')
    try { Complete-RosetunListResults $r PASS synthetic-boot }
    catch {
        if (Test-Path (Join-Path $Directory 'status.json')) { throw 'False completion.' }
        Write-Host 'PASS report write failure rejected'; exit 0
    }
    throw 'Write failure ignored.'
}
$cleanup = if ($Case -eq 'cleanup') { 'ERROR' } else { 'PASS' }
if ($Case -eq 'cleanup') { Add-RosetunListError $r cleanup }
Complete-RosetunListResults $r $cleanup synthetic-boot ($Case -in @('abort', 'fail-abort'))
Write-Host "PASS synthetic $Case"
