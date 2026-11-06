# Checks, without a VM, how the Lockdown matrix tells the boot check's result of this
# boot from an earlier one's. Run it in PowerShell 7 and in Windows PowerShell: their
# ConvertFrom-Json differ on dates. Exits with 1 if any check fails.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\RosetunVm.psm1') -Force

$failures = 0
$boot = '2026-11-06T23:32:42.3060880Z'
$record = [pscustomobject]@{ BootTime = $boot; Attempts = @() } | ConvertTo-Json -Depth 4

foreach ($check in @(
        @{ Name = "this boot's result"; Time = $boot; Expected = $true },
        @{ Name = "another boot's result"; Time = '2026-11-06T23:20:00.0000000Z'; Expected = $false }
    )) {
    $actual = Test-RosetunBootCheckRecord -Json $record -BootTime $check.Time
    if ($actual -eq $check.Expected) {
        Write-Host "PASS  $($check.Name)"
    }
    else {
        Write-Host "FAIL  $($check.Name): $actual" -ForegroundColor Red
        $failures++
    }
}
if ($failures -gt 0) {
    exit 1
}
exit 0
