# Run the real recorder against a supplied module copy and catalog fixture.
param([Parameter(Mandatory)][string]$Directory, [Parameter(Mandatory)][string]$ModulePath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module $ModulePath -Force
$r = New-RosetunListResults -Directory $Directory -VmId synthetic-vm -BootId synthetic-boot
foreach ($row in $r.Plan.catalog) { Add-RosetunListResult $r $row.id PASS checked }
Complete-RosetunListResults $r PASS synthetic-boot
