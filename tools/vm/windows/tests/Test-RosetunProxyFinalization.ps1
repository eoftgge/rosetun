# Run the real nested/outer finally AST with synthetic resource acquisitions.
# Only external operations are replaced; no VM module or matrix body is executed.
param([Parameter(Mandatory)][string]$Directory, [string]$Case = 'success')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\RosetunProxyResults.psm1') -Force
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '..\Invoke-ProxyMatrix.ps1'), [ref]$null, [ref]$errors)
if (@($errors).Count) { throw 'Parse failed.' }
foreach ($name in @('Test-Step', 'Restore-RosetunProxyDesktop', 'Get-RosetunProxyLockdownCleanup', 'Complete-RosetunProxyCleanup')) {
    $f = $ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $false)
    . ([scriptblock]::Create($f.Extent.Text))
}
$outer = @($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] })
if ($outer.Count -ne 1) { throw 'Outer finalization changed.' }
$outer = $outer[0]
$inner = @($outer.Body.FindAll({ param($n) $n -is [Management.Automation.Language.TryStatementAst] -and $null -ne $n.Finally -and $n.Finally.Extent.Text.Contains('$lockdownOff') }, $false))
if ($inner.Count -ne 1) { throw 'Lockdown finalization changed.' }
$UseHostNode = $Case -ne 'no-host'
$KeepNode = $false
$nodeStartedByMatrix = $UseHostNode
$nodeIdentity = if ($UseHostNode) { [pscustomobject]@{ Id=123; CreationTicks=456 } } else { $null }
$runError = $false
$results = [Collections.Generic.List[object]]::new()
$recorder = New-RosetunProxyResults $Directory synthetic-vm synthetic-boot $UseHostNode
$guestDir = Join-Path $recorder.Directory 'guest'
$null = New-Item -ItemType Directory -Path $guestDir
# Take actual cleanup names from the matrix, including all request variants.
foreach ($name in @('RequestNames', 'RecordName', 'DesktopTool')) {
    $assignment = $ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -eq ('$' + $name) }
    . ([scriptblock]::Create($assignment.Extent.Text))
}
foreach ($name in @($RequestNames) + @($RecordName, $DesktopTool)) { [IO.File]::WriteAllText((Join-Path $guestDir $name), '') }
$components = @{}
foreach ($name in @('lan', 'watch', 'listener', 'connection', 'desktop', 'files')) { $components[$name] = 'UNVERIFIED' }
if ($Case -ne 'not-started') { $components.lockdown = 'UNVERIFIED' }
if ($Case -eq 'prior-error') { $components.lockdown = 'ERROR' }
$script:lanDevice = [pscustomobject]@{ Address='192.0.2.10'; RuleName='synthetic'; Listener=[pscustomobject]@{ Server=[pscustomobject]@{ IsBound=$true } } }
$script:desktopChanged = $true
$original = [pscustomobject]@{ Enabled=0; Server=''; Script='' }
$script:desktopExpected = [pscustomobject]@{ Enabled=1; Server='proxy.example.com:3128'; Script='' }
$script:current = $script:desktopExpected
$egressWatchActive = $true
$holder = 234
$script:lanRemoved = $false; $script:watchStopped = $false; $script:nodeStopped = $false; $script:disconnected = $false
$script:offCalled = $false; $script:dumpCalled = $false
function Stop-RosetunLanDevice { param($Device) $script:lanRemoved=$true; $Device.Listener.Server.IsBound=$false }
function Get-NetIPAddress { if (-not $script:lanRemoved) { [pscustomobject]@{ IPAddress='192.0.2.10' } } }
function Get-NetFirewallRule { if (-not $script:lanRemoved) { [pscustomobject]@{ Name='synthetic' } } }
function Stop-RosetunEgressWatch { $script:watchStopped=$true }
function Get-ScheduledTask { if (-not $script:watchStopped) { [pscustomobject]@{ TaskName='RosetunEgressWatch' } } }
function Get-CimInstance { }
function Get-Process { }
function Disconnect-RosetunTunnel { $script:disconnected=$true }
function Wait-RosetunState { $true }
function Get-RosetunState { if ($script:disconnected) { 'Disconnected' } else { 'Connected' } }
function Get-RosetunGuestDesktopProxy { return $script:current }
function Set-RosetunGuestDesktopProxy { param($Enabled,$Server,$Script) $script:current=[pscustomobject]@{ Enabled=$Enabled; Server=$Server; Script=$Script } }
function Get-RosetunGuestDir { $guestDir }
function Get-RosetunGuestBootTime { 'synthetic-boot' }
$nodeProcess = [pscustomobject]@{ Id=123; Handle=0; Exited=$false; StartTime=[datetime]::new(456, [DateTimeKind]::Utc) }
$nodeProcess | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($timeout) return $this.Exited }
# Keep the real process-identity verifier; substitute only its process observation.
$listModule = Get-Module RosetunListResults -All | Select-Object -First 1
& $listModule {
    param($process)
    $script:finalizationProcess = $process
    function script:Get-Process { param($Id) return $script:finalizationProcess }
} $nodeProcess
function Stop-RosetunTestNode {
    param($ProcessIdentity)
    if ($ProcessIdentity.CreationTicks -ne 456) { throw 'Identity lost.' }
    $script:nodeStopped=$true
    $nodeProcess.Exited=$true
}
function Invoke-RosetunCli {
    param([switch]$Quiet)
    if ($args[0] -eq 'lockdown') {
        if ($args[1] -ne 'off') { throw 'Destructive operation outside cleanup.' }
        if (Test-Path (Join-Path $recorder.Directory 'status.json')) { throw 'Premature completion.' }
        $script:offCalled=$true
        if ($Case -eq 'off-throws') { throw 'SECRET-OFF' }
        return [pscustomobject]@{ ExitCode=$(if ($Case -in @('off-fails', 'fail-cleanup')) { 1 } else { 0 }); Output='' }
    }
    if ($args[0] -ne 'status' -or -not $script:offCalled) { throw 'Unexpected CLI observation.' }
    if ($Case -eq 'status-throws') { throw 'SECRET-STATUS' }
    $output = switch ($Case) {
        'on' { "lockdown: on`n" }
        'status-empty' { '' }
        'status-bad' { "lockdown: offline`n" }
        'status-conflict' { "lockdown: off`nlockdown: on`n" }
        default { "state: Disconnected`nlockdown: off`n" }
    }
    [pscustomobject]@{ ExitCode=$(if ($Case -eq 'status-fails') { 1 } else { 0 }); Output=$output }
}
# The real guest observation/parser runs locally against fake netsh output.
function netsh.exe {
    $script:dumpCalled=$true
    if (-not $script:offCalled) { throw 'Dump before off.' }
    if ($Case -eq 'dump-fails') { $global:LASTEXITCODE=1; return }
    if ($Case -eq 'missing-file') { $global:LASTEXITCODE=0; return }
    $path = ($args | Where-Object { $_ -like 'file=*' }).Substring(5)
    $xml = '<wfpstate><providers numItems="1"><item><providerKey>FWPM_PROVIDER_MPSSVC_WF</providerKey></item></providers><subLayers numItems="1"><item><subLayerKey>FWPM_SUBLAYER_MPSSVC_WF</subLayerKey></item></subLayers><layers numItems="1"><item><layer><layerKey>FWPM_LAYER_ALE_AUTH_CONNECT_V4</layerKey></layer><filters numItems="0"/></item></layers></wfpstate>'
    if ($Case -eq 'objects') { $xml = $xml.Replace('<filters numItems="0"/>', '<filters numItems="1"><item><filterKey>{00000000-0000-0000-0000-000000000001}</filterKey><providerKey>{F12DBEDD-F3C7-4A72-B0F8-20559C88B112}</providerKey></item></filters>') }
    if ($Case -in @('clean-filter', 'bad-reference', 'duplicate-reference', 'bad-sublayer', 'missing-sublayer', 'namespaced-reference')) {
        $reference = if ($Case -eq 'bad-reference') { 'damaged-provider-key' } else { 'FWPM_PROVIDER_MPSSVC_WF' }
        $filter = '<item><filterKey>{00000000-0000-0000-0000-000000000001}</filterKey><providerKey>' + $reference + '</providerKey><subLayerKey>FWPM_SUBLAYER_MPSSVC_WF</subLayerKey></item>'
        if ($Case -eq 'duplicate-reference') { $filter = $filter.Replace('</item>', '<providerKey>FWPM_PROVIDER_MPSSVC_WF</providerKey></item>') }
        if ($Case -eq 'bad-sublayer') { $filter = $filter.Replace('FWPM_SUBLAYER_MPSSVC_WF', 'damaged-sublayer-key') }
        if ($Case -eq 'missing-sublayer') { $filter = $filter.Replace('<subLayerKey>FWPM_SUBLAYER_MPSSVC_WF</subLayerKey>', '') }
        if ($Case -eq 'namespaced-reference') { $filter = $filter.Replace('<providerKey>', '<providerKey xmlns="urn:invalid">') }
        $xml = $xml.Replace('<filters numItems="0"/>', '<filters numItems="1">' + $filter + '</filters>')
    }
    if ($Case -eq 'count-mismatch') { $xml = $xml.Replace('<filters numItems="0"/>', '<filters numItems="1"/>') }
    switch ($Case) {
        'empty-dump' { $xml='' }
        'bad-xml' { $xml='<wfpstate>' }
        'missing-section' { $xml='<wfpstate><providers/><filters/></wfpstate>' }
        'bad-item' { $xml=$xml.Replace('<providerKey>FWPM_PROVIDER_MPSSVC_WF</providerKey>', '') }

        'dtd' { $xml='<!DOCTYPE wfpstate [<!ENTITY x "SECRET">]><wfpstate><providers/><subLayers/><filters/></wfpstate>' }
    }
    $tail = "<firewallState>`r`n`t<dynamicKeywordAddresses/>`r`n</firewallState>"
    switch ($Case) {
        'firewall-tail' { $xml = '<?xml version="1.0" encoding="utf-8"?>' + $xml + $tail }
        'firewall-tail-objects' { $xml = $xml.Replace('<filters numItems="0"/>', '<filters numItems="1"><item><filterKey>{57bf2a6e-57db-4d99-bed7-ecbd2c63aa75}</filterKey></item></filters>') + $tail }
        'unknown-tail' { $xml += '<unknown/>' }
        'duplicate-wfp' { $xml += $xml }
        'truncated-tail' { $xml += '<firewallState><dynamicKeywordAddresses/>' }
        'extra-root' { $xml += $tail + '<extra/>' }
        'trailing-text' { $xml += $tail + 'unexpected' }
        'tail-dtd' { $xml += '<!DOCTYPE firewallState [<!ENTITY x "SECRET">]>' + $tail }
        'tail-declaration' { $xml += '<?xml version="1.0"?>' + $tail }
        'tail-populated' { $xml += '<firewallState><dynamicKeywordAddresses><item/></dynamicKeywordAddresses></firewallState>' }
        'tail-namespace' { $xml += '<firewallState xmlns="urn:invalid"><dynamicKeywordAddresses/></firewallState>' }
        'tail-attribute' { $xml += '<firewallState unknown="1"><dynamicKeywordAddresses/></firewallState>' }
    }
    [IO.File]::WriteAllText($path, $xml)
    $global:LASTEXITCODE=0
}
function Invoke-RosetunGuest {
    param($ScriptBlock,$ArgumentList)
    if ($Case -eq 'read-denied' -and $ScriptBlock.ToString().Contains('netsh.exe')) { throw 'SECRET-READ-DENIED' }
    if ($Case -eq 'bad-envelope' -and $ScriptBlock.ToString().Contains('netsh.exe')) { return @('PASS', 'PASS') }
    & $ScriptBlock @ArgumentList
}
$produce = {
    foreach ($row in $recorder.Plan.catalog) {
        if ($Case -eq 'not-started' -and $row.group -eq 'lockdown') { break }
        if (-not $row.required) { Add-RosetunListResult $recorder $row.id SKIP host-node-disabled }
        else { Test-Step -Id $row.id synthetic condition { -not ($Case -like 'fail-*' -and $row.id -eq 'plain.connect') } }
    }
    if ($Case -eq 'fail-export') { $null = New-Item -ItemType Directory -Path (Join-Path $recorder.Directory 'report.json.tmp') }
    if ($Case -eq 'fail-infrastructure') { throw 'SECRET-INFRASTRUCTURE' }
}
$innerBody = if ($Case -eq 'fail-lockdown-body') { "throw 'SECRET-INNER'" } else { '' }
$innerText = if ($Case -eq 'not-started') { '' } else { 'try { ' + $innerBody + ' } finally ' + $inner[0].Finally.Extent.Text }
$code = 'try { & $produce; ' + $innerText + ' } ' + ($outer.CatchClauses.Extent.Text -join ' ') + ' finally ' + $outer.Finally.Extent.Text
try { . ([scriptblock]::Create($code)) }
catch { if ($Case -notin @('off-throws', 'fail-export', 'fail-infrastructure', 'fail-lockdown-body')) { throw } }
if ($Case -eq 'fail-export') {
    if (Test-Path (Join-Path $recorder.Directory 'status.json')) { throw 'False completion.' }
} elseif (-not (Test-Path (Join-Path $recorder.Directory 'status.json'))) { throw 'No completion.' }
if (-not $script:lanRemoved -or -not $script:watchStopped -or -not $script:disconnected -or ($UseHostNode -and -not $script:nodeStopped)) { throw 'Cleanup path was not executed.' }
if ($Case -eq 'not-started' -and ($script:offCalled -or $script:dumpCalled -or $components.lockdown -ne 'NOT_CREATED')) { throw 'Unacquired Lockdown touched.' }
if ($Case -in @('success', 'no-host') -and (-not $script:offCalled -or -not $script:dumpCalled)) { throw 'Observation path missing.' }

if ($Case -in @('prior-error', 'off-fails', 'off-throws', 'fail-cleanup') -and $script:dumpCalled) { throw 'Established error was re-observed.' }
