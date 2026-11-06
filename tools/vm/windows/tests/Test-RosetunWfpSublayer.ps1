# Checks, on the host and without a VM, what the failure matrix uses to take the
# session's sublayer key. It never names the service's key to WFP: the live part uses
# a random key, so it cannot touch a running Rosetun. Without elevation WFP refuses
# the add, which still proves the entry points and the marshalling; as an administrator
# it goes through the whole cycle, and the empty sublayer is gone again at the end.
# Exits with 1 if any check fails.

param(
    [string]$SessionSource = (Join-Path $PSScriptRoot '..\..\..\..\crates\rosetun-routing\src\platform\windows\session.rs'),
    [string]$LockdownSource = (Join-Path $PSScriptRoot '..\..\..\..\crates\rosetun-routing\src\platform\windows\lockdown.rs'),
    [string]$Matrix = (Join-Path $PSScriptRoot '..\Invoke-FailureMatrix.ps1')
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

function ConvertFrom-RosetunGuidFields {
    # `GUID { data1: 0x0c03_5ef5, data2: ..., data3: ..., data4: [...] }` as text.
    param([Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$Name)
    $pattern = "const $Name`: GUID = GUID \{\s*data1: 0x([0-9a-f_]+),\s*data2: 0x([0-9a-f_]+),\s*data3: 0x([0-9a-f_]+),\s*data4: \[([^\]]+)\]"
    $match = [regex]::Match($Source, $pattern)
    if (-not $match.Success) { throw "$Name not found" }
    $bytes = @($match.Groups[4].Value -split ',' | ForEach-Object { $_.Trim() -replace '^0x', '' })
    '{0}-{1}-{2}-{3}-{4}' -f ($match.Groups[1].Value -replace '_', ''), $match.Groups[2].Value, $match.Groups[3].Value,
        (-join $bytes[0..1]), (-join $bytes[2..7])
}

$key = Get-RosetunSessionSublayerKey

Assert-RosetunCheck "the key is the service's sublayer key" {
    (ConvertFrom-RosetunGuidFields -Source (Get-Content -LiteralPath $SessionSource -Raw) -Name 'SUBLAYER_KEY') -ieq $key
}
Assert-RosetunCheck "the key is not Lockdown's" {
    $source = Get-Content -LiteralPath $LockdownSource -Raw
    $match = [regex]::Match($source, 'const SUBLAYER_KEY: GUID = GUID::from_u128\(0x([0-9a-f_]+)\)')
    $match.Success -and ($match.Groups[1].Value -replace '_', '') -ine ($key -replace '-', '')
}
Assert-RosetunCheck 'the matrix does not try to stop BFE, which Windows refuses' {
    (Get-Content -LiteralPath $Matrix -Raw) -notmatch "Stop-Service[^\r\n]*'BFE'"
}

# As Invoke-Command -Session runs a block: in the runspace's global scope, where what
# it leaves is there for the next block.
$runspace = [runspacefactory]::CreateRunspace()
$runspace.Open()
try {
    $session = [powershell]::Create()
    $session.Runspace = $runspace
    [void]$session.AddScript((Get-RosetunWfpSublayerCall).ToString(), $false).
        AddArgument('Remove').AddArgument([guid]::NewGuid().ToString())
    [void]$session.Invoke()
    $session.Commands.Clear()
    $session.Streams.Error.Clear()
    [void]$session.AddScript('$action = [pscustomobject]@{ task = 1 }; $key = 1; $status = 1', $false)
    [void]$session.Invoke()
    Assert-RosetunCheck "the block leaves a session's later variables alone" {
        $session.Streams.Error.Count -eq 0
    }
    $session.Dispose()
}
finally {
    $runspace.Dispose()
}

$probe = [guid]::NewGuid().ToString()
$first = [uint32](Invoke-RosetunLocalWfpSublayer -Action Add -Key $probe)
Assert-RosetunCheck 'FWPM_SUBLAYER0 has its 64-bit size' { [RosetunStand.WfpSublayer]::StructSize() -eq 72 }
$accessDenied = [uint32]5
if ($first -eq $accessDenied) {
    Write-Host 'Not elevated: WFP refused the add, so the entry points answer; the cycle is not run.'
    Assert-RosetunCheck 'a refused delete also comes back as a status' {
        ([uint32](Invoke-RosetunLocalWfpSublayer -Action Remove -Key $probe)) -in @([uint32]5, [uint32]'0x80320007')
    }
}
else {
    Assert-RosetunCheck 'the sublayer is added' { $first -eq 0 }
    Assert-RosetunCheck 'a second add finds the key taken, as the service will' {
        ([uint32](Invoke-RosetunLocalWfpSublayer -Action Add -Key $probe)) -eq [uint32]'0x80320009'
    }
    Assert-RosetunCheck 'the sublayer is removed' {
        ([uint32](Invoke-RosetunLocalWfpSublayer -Action Remove -Key $probe)) -eq 0
    }
    Assert-RosetunCheck 'a second remove finds nothing, which the matrix accepts' {
        ([uint32](Invoke-RosetunLocalWfpSublayer -Action Remove -Key $probe)) -eq [uint32]'0x80320007'
    }
}

if ($failures -gt 0) {
    Write-Host "$failures check(s) failed" -ForegroundColor Red
    exit 1
}
exit 0
