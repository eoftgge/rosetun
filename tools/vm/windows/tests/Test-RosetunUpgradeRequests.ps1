# Builds the upgrade matrix's requests on the host, without a VM, from the
# request the matrix is run with and from variants of it that lack the
# fields the matrix sets. Exits with 1 if any check fails.

param(
    [string]$RequestPath = (Join-Path $PSScriptRoot '..\request-local.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\RosetunVm.psm1') -Force

$failures = 0

function Assert-RosetunCheck {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][scriptblock]$Condition)
    try {
        $passed = [bool](& $Condition)
        $note = ''
    }
    catch {
        $passed = $false
        $note = " ($_)"
    }
    if ($passed) {
        Write-Host "PASS  $Name"
    }
    else {
        Write-Host "FAIL  $Name$note" -ForegroundColor Red
        $script:failures++
    }
}

function Get-RosetunComparable {
    # The request without the fields the matrix sets, for comparing the rest.
    param([Parameter(Mandatory)][string]$Json)
    $request = $Json | ConvertFrom-Json
    $request.settings.PSObject.Properties.Remove('kill_switch')
    $request.settings.PSObject.Properties.Remove('allow_lan')
    $request | ConvertTo-Json -Depth 20 -Compress
}

$source = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $RequestPath))
$variants = [ordered]@{ 'as given' = $source }
# Publish-Rosetun adds auto_reconnect before the matrix reads request.json.
$published = $source | ConvertFrom-Json
$published.settings | Add-Member -NotePropertyName auto_reconnect -NotePropertyValue $false -Force
$variants['as published'] = $published | ConvertTo-Json -Depth 20
foreach ($field in 'kill_switch', 'allow_lan') {
    $without = $source | ConvertFrom-Json
    $without.settings.PSObject.Properties.Remove($field)
    $variants["without $field"] = $without | ConvertTo-Json -Depth 20
}

foreach ($variant in $variants.Keys) {
    $json = $variants[$variant]
    foreach ($killSwitch in $true, $false) {
        $name = "$variant, kill switch $($killSwitch.ToString().ToLowerInvariant())"
        $built = $null
        Assert-RosetunCheck "$name - builds" {
            $script:built = New-RosetunUpgradeRequest -Json $json -KillSwitch $killSwitch
            $true
        }
        if ($null -eq $built) { continue }
        $settings = ($built | ConvertFrom-Json).settings
        Assert-RosetunCheck "$name - kill_switch is set" {
            $settings.kill_switch -is [bool] -and $settings.kill_switch -eq $killSwitch
        }
        Assert-RosetunCheck "$name - allow_lan is off" {
            $settings.allow_lan -is [bool] -and -not $settings.allow_lan
        }
        Assert-RosetunCheck "$name - nothing else changes" {
            (Get-RosetunComparable $built) -eq (Get-RosetunComparable $json)
        }
    }
}

if ($failures -gt 0) {
    Write-Host "$failures check(s) failed" -ForegroundColor Red
    exit 1
}
exit 0
