# Exercise the recorder without VM operations and with distinct PowerShell/.NET locations.
param([Parameter(Mandatory)][string]$Directory)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\RosetunListResults.psm1') -Force
$null = New-Item -Path $Directory -ItemType Directory -ErrorAction Stop
$shellDirectory = (New-Item -Path (Join-Path $Directory 'ps location') -ItemType Directory).FullName
$processDirectory = (New-Item -Path (Join-Path $Directory 'io location') -ItemType Directory).FullName
$previousLocation = Get-Location
$previousDirectory = [Environment]::CurrentDirectory
try {
    Set-Location -LiteralPath $shellDirectory
    $shellDirectory = (Get-Location).ProviderPath
    $processDirectory = Join-Path (Split-Path -Parent $shellDirectory) 'io location'
    [Environment]::CurrentDirectory = $processDirectory
    $relative = 'nested/run [literal]'
    $expected = Join-Path (Join-Path $shellDirectory 'nested') 'run [literal]'
    $r = New-RosetunListResults -Directory $relative -VmId synthetic-vm -BootId synthetic-boot
    if ($r.Directory -ne $expected) { throw 'Recorder resolved the wrong directory.' }
    # Further shell location changes must not redirect events or final artifacts.
    Set-Location -LiteralPath $processDirectory
    foreach ($row in $r.Plan.catalog) { Add-RosetunListResult $r $row.id PASS checked }
    Complete-RosetunListResults $r PASS synthetic-boot
    foreach ($name in @('plan.json', 'events.jsonl', 'report.json', 'status.json')) {
        if (-not (Test-Path -LiteralPath (Join-Path $expected $name))) { throw 'Artifact missing.' }
        if (Test-Path -LiteralPath (Join-Path (Join-Path $processDirectory $relative) $name)) {
            throw 'Artifact written relative to the process directory.'
        }
    }
    try { $null = New-RosetunListResults -Directory $expected -VmId synthetic-vm -BootId synthetic-boot }
    catch { Write-Host 'PASS relative recorder paths and directory reuse rejection'; return }
    throw 'Existing result directory was reused.'
}
finally {
    [Environment]::CurrentDirectory = $previousDirectory
    Set-Location -LiteralPath $previousLocation
}
