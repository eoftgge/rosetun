param([Parameter(Mandatory)][string]$Directory, [string]$Case = 'success', [bool]$UseHostNode = $true, [string]$Location)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Location) { Set-Location -LiteralPath $Location }
Import-Module (Join-Path $PSScriptRoot '..\RosetunProxyResults.psm1') -Force
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot '..\Invoke-ProxyMatrix.ps1'), [ref]$null, [ref]$parseErrors)
if (@($parseErrors).Count) { throw 'Matrix does not parse.' }
foreach ($name in @('Test-Step', 'Complete-RosetunProxyCleanup')) {
    $function = $ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $false)
    . ([scriptblock]::Create($function.Extent.Text))
}
if ($Case -eq 'no-host') { $UseHostNode = $false }
$recorder = New-RosetunProxyResults -Directory $Directory -VmId synthetic-vm -BootId synthetic-boot -UseHostNode $UseHostNode
# Enumerate actual commands, including expandable strings and both quote styles.
$commands = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Test-Step' }, $true))
$sharingLoop = $ast.Find({ param($n) $n -is [Management.Automation.Language.ForEachStatementAst] -and $n.Variable.VariablePath.UserPath -eq 'requestName' }, $true)
$requests = @($sharingLoop.Condition.PipelineElements[0].Expression.SafeGetValue())
if ($requests.Count -ne 2 -or $requests[0] -ne 'proxy-share.json' -or $requests[1] -ne 'proxy-share-strict.json') { throw 'Sharing variants changed; review catalog.' }
$actual = [Collections.Generic.List[string]]::new()
foreach ($command in $commands) {
    $parts = $command.CommandElements
    $id = $parts[2].Value
    if ($id.Contains('$variant')) {
        foreach ($variant in @('plain', 'strict')) { $actual.Add($id.Replace('$variant', $variant)) }
    } else { $actual.Add($id) }
}
if (@(Compare-Object @($actual | Sort-Object) @($recorder.Plan.catalog.id | Sort-Object)).Count) { throw 'Call site/catalog mismatch.' }
if ($actual.Count -ne @($actual | Sort-Object -Unique).Count) { throw 'Duplicate call site ID.' }
$results = [Collections.Generic.List[object]]::new()
foreach ($row in $recorder.Plan.catalog) {
    if ($Case -in @('abort', 'fail-abort') -and $recorder.Events.Count -eq 25) { break }
    if (-not $row.required) { Add-RosetunListResult $recorder $row.id SKIP host-node-disabled }
    elseif ($Case -like 'fail*' -and $recorder.Events.Count -eq 0) {
        Test-Step -Id $row.id synthetic throws { throw 'SECRET-EXCEPTION' }
    } else { Test-Step -Id $row.id synthetic passes { $true } }
    if (@(Get-Content -LiteralPath (Join-Path $recorder.Directory 'events.jsonl')).Count -ne $recorder.Events.Count) { throw 'Event not flushed.' }
}
$components = @{}
foreach ($name in @('node', 'lan', 'watch', 'listener', 'connection', 'lockdown', 'desktop', 'files')) { $components[$name] = 'PASS' }
if (-not $UseHostNode) { $components.node = 'NOT_CREATED' }
if ($Case -eq 'fail-cleanup') { $components.desktop = 'ERROR'; Add-RosetunListError $recorder cleanup }
if ($Case -eq 'fail-export') {
    $null = New-Item -ItemType Directory -Path (Join-Path $recorder.Directory 'report.json.tmp')
    try { Complete-RosetunListResults $recorder PASS synthetic-boot -Components $components }
    catch {
        if (Test-Path (Join-Path $recorder.Directory 'status.json')) { throw 'False completion.' }
        exit 0
    }
    throw 'Export error ignored.'
}
Complete-RosetunListResults $recorder (Get-RosetunProxyCleanupStatus $components) synthetic-boot ($Case -in @('abort', 'fail-abort')) -Components $components
