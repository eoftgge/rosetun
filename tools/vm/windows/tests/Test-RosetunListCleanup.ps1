# Autonomous cleanup aggregation tests. Extract functions without VM module initialization.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\RosetunListResults.psm1') -Force
function Import-TestFunction {
    param([string]$File, [string]$Name)
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($File, [ref]$null, [ref]$errors)
    if (@($errors).Count) { throw "Parse failed: $File" }
    $definition = $ast.Find({ param($n)
        $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name
    }, $false)
    return [scriptblock]::Create($definition.Extent.Text.Replace('$PSScriptRoot', "'" + (Split-Path -Parent $File).Replace("'", "''") + "'"))
}
. (Import-TestFunction (Join-Path $PSScriptRoot '..\Invoke-ListMatrix.ps1') 'Complete-ListNodeCleanup')
. (Import-TestFunction (Join-Path $PSScriptRoot '..\RosetunListResults.psm1') 'Get-RosetunListNodeCleanup')
. (Import-TestFunction (Join-Path $PSScriptRoot '..\RosetunVm.psm1') 'Stop-RosetunTestNode')
$originalStop = ${function:Stop-RosetunTestNode}
# Exercise real Get-Process absence classification before replacing it below.
if ((Get-RosetunListNodeCleanup ([pscustomobject]@{ Id = [int]::MaxValue; CreationTicks = 1 })) -ne 'PASS') {
    throw 'Real process absence was not confirmed.'
}
$created = [datetime]'2026-01-01T00:00:00Z'
$identity = [pscustomobject]@{ Id = 12345; CreationTicks = $created.ToUniversalTime().Ticks }
function Get-Process {
    param($Id, $ErrorAction)
    if ($script:state -eq 'unavailable') { throw 'Access unavailable' }
    if ($script:state -eq 'absent') {
        $errorRecord = [Management.Automation.ErrorRecord]::new(
            [Microsoft.PowerShell.Commands.ProcessCommandException]::new('Process absent'),
            'NoProcessFoundForGivenId', [Management.Automation.ErrorCategory]::ObjectNotFound, $Id)
        throw $errorRecord
    }
    $time = if ($script:state -eq 'reused') { $created.AddSeconds(1) } else { $created }
    $process = [pscustomobject]@{ Id = $Id; StartTime = $time; Handle = 1; ProcessName = 'sing-box' }
    $process | Add-Member ScriptMethod WaitForExit { param($Timeout) $script:state -eq 'exited' }
    return $process
}
function Stop-RosetunTestNode {
    param($ProcessIdentity)
    $script:stops++
    if ($script:stopThrows) { throw 'Stop unavailable' }
}
$matrixAst = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot '..\Invoke-ListMatrix.ps1'), [ref]$null, [ref]$null)
$outerTry = $matrixAst.Find({ param($n)
    $n -is [Management.Automation.Language.TryStatementAst] -and $null -ne $n.Finally -and
        $n.Finally.Extent.Text.Contains('Complete-RosetunListResults')
}, $false)
$body = $outerTry.Finally.Extent.Text
$finalize = [scriptblock]::Create($body.Substring(1, $body.Length - 2))
function Get-RosetunGuestBootTime { 'synthetic-boot' }
function Add-RosetunListError { param($Recorder, $Place) $Recorder.Errors.Add($Place) }
function Complete-RosetunListResults {
    param($Recorder, $Cleanup, $EndBootId, $Aborted)
    $script:reported = $Cleanup
}
$cases = @(
    @('exited', $true, $false, 'PASS', 'PASS', 1),
    @('absent', $true, $false, 'PASS', 'PASS', 1),
    @('alive', $true, $false, 'PASS', 'ERROR', 1),
    @('unavailable', $true, $false, 'PASS', 'UNVERIFIED', 1),
    @('reused', $true, $false, 'PASS', 'PASS', 1),
    @('alive', $false, $false, 'PASS', 'PASS', 0),
    @('alive', $true, $true, 'PASS', 'PASS', 0),
    @('exited', $true, $false, 'ERROR', 'ERROR', 1),
    @('exited', $true, $false, 'UNVERIFIED', 'UNVERIFIED', 1)
)
$script:stopThrows = $false
foreach ($case in $cases) {
    $script:state, $started, $keep, $guest, $expected, $stopCount = $case
    $script:stops = 0
    $owned = if ($started) { $identity } else { $null }
    $actual = Complete-ListNodeCleanup $guest $started $owned $keep
    if ($actual -ne $expected -or $script:stops -ne $stopCount) {
        throw "Aggregation $case returned $actual, stops $script:stops"
    }
    $nodeStartedByMatrix = $started; $nodeIdentity = $owned; $KeepNode = $keep
    $cleanup = $guest; $runError = $false; $script:stops = 0
    $recorder = [pscustomobject]@{ Plan = @{ identity = @{ boot_id = 'synthetic-boot' } }
        Errors = [Collections.Generic.List[object]]::new() }
    . $finalize
    if ($script:reported -ne $expected -or $script:stops -ne $stopCount) {
        throw "Matrix finalization $case returned $script:reported"
    }
}
$script:state = 'exited'; $script:stopThrows = $true
if ((Complete-ListNodeCleanup PASS $true $identity $false) -ne 'ERROR') { throw 'Stop error lost.' }
$script:stopThrows = $false
$unknown = [pscustomobject]@{ Id = 12345; CreationTicks = $null }
if ((Complete-ListNodeCleanup PASS $true $unknown $false) -ne 'UNVERIFIED') { throw 'Unknown identity accepted.' }
# Exercise the real guarded stop body with substituted listeners and process operations.
${function:Stop-RosetunTestNode} = $originalStop
function Get-RosetunTestNodePort { return 12345 }
function Get-NetTCPConnection { [pscustomobject]@{ OwningProcess = 12345 } }
function Get-NetUDPEndpoint { [pscustomobject]@{ OwningProcess = 12345 } }
function Stop-Process { param($InputObject, [switch]$Force) $script:kills++ }
# The extracted function's PSScriptRoot is the test directory.
function Get-Content { param($Path, [switch]$Raw) '{"inbounds":[{"type":"hysteria2","listen_port":12345}]}' }
foreach ($state in @('alive', 'reused')) {
    $script:state = $state; $script:kills = 0
    Stop-RosetunTestNode -ProcessIdentity $identity
    $expected = if ($state -eq 'alive') { 1 } else { 0 }
    if ($script:kills -ne $expected) { throw "Stop identity guard failed: $state" }
}
Write-Host 'PASS autonomous List cleanup aggregation and stop identity guard'
