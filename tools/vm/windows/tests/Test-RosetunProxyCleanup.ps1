# Extract integration functions only; never import Hyper-V or execute the matrix body.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\RosetunProxyResults.psm1') -Force
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '..\Invoke-ProxyMatrix.ps1'), [ref]$null, [ref]$errors)
if (@($errors).Count) { throw 'Parse failed.' }
foreach ($name in @('Restore-RosetunProxyDesktop', 'Complete-RosetunProxyCleanup')) {
    $f = $ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $false)
    . ([scriptblock]::Create($f.Extent.Text))
}
$recorder = [pscustomobject]@{ Errors = [Collections.Generic.List[object]]::new() }
$RequestNames = @('synthetic.json'); $RecordName = 'synthetic-record'; $DesktopTool = 'synthetic-tool'
$holder = 123
function Get-RosetunGuestDir { 'synthetic' }
function Invoke-RosetunGuest { param($ScriptBlock, $ArgumentList) if ($script:refuse) { throw 'SECRET' }; return $script:confirmed }
function Get-RosetunState { if ($script:confirmed) { 'Disconnected' } else { 'Connected' } }
$script:refuse = $false
$script:lanDevice = [pscustomobject]@{ Address='192.0.2.10'; RuleName='synthetic-rule'; Listener=[pscustomobject]@{ Server=[pscustomobject]@{ IsBound=$false } } }
function Get-NetIPAddress { if (-not $script:confirmed) { [pscustomobject]@{ IPAddress='192.0.2.10' } } }
function Get-NetFirewallRule { if (-not $script:confirmed) { [pscustomobject]@{ Name='synthetic-rule' } } }
foreach ($component in @('lan', 'watch', 'listener', 'connection', 'files')) {
    foreach ($confirmed in @($true, $false)) {
        $script:confirmed = $confirmed
        $parts = @{ desktop = 'ERROR' }; $parts[$component] = 'UNVERIFIED'
        Complete-RosetunProxyCleanup $parts
        $expected = if ($confirmed) { 'PASS' } else { 'ERROR' }
        if ($parts[$component] -ne $expected -or (Get-RosetunProxyCleanupStatus $parts) -ne 'ERROR') { throw 'Component aggregation failed.' }
    }
}
$script:refuse = $true
$parts = @{ files = 'UNVERIFIED' }
Complete-RosetunProxyCleanup $parts
if ($parts.files -ne 'UNVERIFIED') { throw 'Read refusal passed.' }
function Get-RosetunGuestDesktopProxy { if ($script:refuse) { throw 'SECRET-DESKTOP-SETTINGS' }; return $script:current }
function Set-RosetunGuestDesktopProxy { param($Enabled,$Server,$Script) $script:writes++; $script:current = [pscustomobject]@{ Enabled=$Enabled; Server=$Server; Script=$Script } }
$original = [pscustomobject]@{ Enabled=0; Server=''; Script='' }
$expected = [pscustomobject]@{ Enabled=1; Server='proxy.example.com:3128'; Script='' }
$script:writes = 0
if ((Restore-RosetunProxyDesktop $original $expected) -ne 'UNVERIFIED' -or $script:writes -ne 0) { throw 'Desktop refusal failed.' }
$script:refuse = $false; $script:current = $original
if ((Restore-RosetunProxyDesktop $original $expected) -ne 'UNVERIFIED' -or $script:writes -ne 0) { throw 'Foreign settings overwritten.' }
$script:current = $expected
if ((Restore-RosetunProxyDesktop $original $expected) -ne 'PASS' -or $script:writes -ne 1) { throw 'Desktop restore failed.' }
foreach ($component in @('node', 'lan', 'watch', 'listener', 'connection', 'lockdown', 'desktop', 'files')) {
    foreach ($state in @('PASS', 'ERROR', 'UNVERIFIED')) {
        $parts = @{ other='PASS' }; $parts[$component]=$state
        if ((Get-RosetunProxyCleanupStatus $parts) -ne $state) { throw 'Aggregate mismatch.' }
    }
}
if ((Get-RosetunProxyCleanupStatus @{ node='RETAINED'; files='NOT_CREATED' }) -ne 'PASS') { throw 'Scope mismatch.' }
Write-Host 'PASS Proxy cleanup integration'
