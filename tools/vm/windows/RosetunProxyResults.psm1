# Proxy policy over the shared, VM-independent journal primitives.
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'RosetunListResults.psm1')

function New-RosetunProxyResults {
    param([string]$Directory, [string]$VmId, [string]$BootId,
        [bool]$UseHostNode, [bool]$KeepNode = $false, [int]$ProxyPort = 10808)
    $rows = @(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'proxy-checks.json') -Raw | ConvertFrom-Json | ForEach-Object { $_ })
    foreach ($row in $rows) {
        if ($row.detail -eq 'host-node') { $row.required = $UseHostNode }
    }
    New-RosetunListResults -Directory $Directory -VmId $VmId -BootId $BootId -Suite windows-proxy -Catalog $rows `
        -Parameters @{ use_host_node = $UseHostNode; keep_node = $KeepNode; proxy_port = $ProxyPort }
}

function Compare-RosetunProxySettings {
    param($Left, $Right)
    return $null -ne $Left -and $null -ne $Right -and $Left.Enabled -eq $Right.Enabled -and
        $Left.Server -ceq $Right.Server -and $Left.Script -ceq $Right.Script
}

function Get-RosetunProxyCleanupStatus {
    param($Components)
    $values = @($Components.Values)
    if ($values -contains 'ERROR') { return 'ERROR' }
    if ($values -contains 'UNVERIFIED') { return 'UNVERIFIED' }
    if (@($values | Where-Object { $_ -notin @('PASS', 'NOT_CREATED', 'RETAINED') }).Count) { return 'ERROR' }
    return 'PASS'
}

Export-ModuleMember -Function New-RosetunProxyResults, Compare-RosetunProxySettings, Get-RosetunProxyCleanupStatus,
    Add-RosetunListResult, Add-RosetunListError, Complete-RosetunListResults, Get-RosetunListNodeCleanup
