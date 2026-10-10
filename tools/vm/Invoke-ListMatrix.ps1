# Runs the list rule-set matrix against the Hyper-V test VM. The owner runs it.
# Exits with 1 if any check fails; no guest credentials or generated files are committed.

param(
    [Parameter(Mandatory)][string]$SingBoxPath,
    [Parameter(Mandatory)][string]$RequestPath,
    [string]$BuildDir = (Join-Path $PSScriptRoot '..\..\target\release'),
    [switch]$UseHostNode,
    [string]$NodeBindInterface,
    [switch]$KeepNode,
    [switch]$Build
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RosetunVm.psm1') -Force

$results = [System.Collections.Generic.List[object]]::new()

function Test-Step {
    param(
        [Parameter(Mandatory)][string]$Scenario,
        [Parameter(Mandatory)][string]$Expectation,
        [Parameter(Mandatory)][scriptblock]$Condition,
        [string]$Note = ''
    )
    try {
        $passed = [bool](& $Condition)
    }
    catch {
        $passed = $false
        $Note = "$_"
    }
    $results.Add([pscustomobject]@{
        Result = if ($passed) { 'PASS' } else { 'FAIL' }
        Scenario = $Scenario
        Check = $Expectation
        Note = $Note
    })
    if (-not $passed) {
        Write-Host "FAIL  $Scenario - $Expectation ($Note)" -ForegroundColor Red
    }
}

function Invoke-ListCli {
    param(
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter(Mandatory)][ValidateSet('connect', 'apply')][string]$Action
    )
    Invoke-RosetunGuest -ScriptBlock {
        param($dir, $configPath, $action)
        $env:ROSETUN_CONFIG = $configPath
        try {
            $output = & "$dir\rosetun.exe" $action 2>&1 | ForEach-Object { "$_" }
            $exitCode = $LASTEXITCODE
            $global:LASTEXITCODE = 0
            [pscustomobject]@{ ExitCode = $exitCode; Output = ($output -join "`n") }
        }
        finally {
            Remove-Item Env:ROSETUN_CONFIG -ErrorAction SilentlyContinue
        }
    } -ArgumentList (Get-RosetunGuestDir), $ConfigPath, $Action
}

$nodeStartedByMatrix = $false
try {
if ($Build) {
    & cargo build -q --release --manifest-path (Join-Path $PSScriptRoot '..\..\Cargo.toml')
    $exitCode = $LASTEXITCODE
    $global:LASTEXITCODE = 0
    if ($exitCode -ne 0) {
        throw "cargo build failed with exit code $exitCode."
    }
}

if ($UseHostNode) {
    if ($NodeBindInterface) {
        $nodeStartedByMatrix = Start-RosetunTestNode -SingBoxPath $SingBoxPath -BindInterface $NodeBindInterface
    }
    else {
        $nodeStartedByMatrix = Start-RosetunTestNode -SingBoxPath $SingBoxPath
    }
}

Stop-RosetunHelper
Publish-Rosetun -BuildDir $BuildDir -SingBoxPath $SingBoxPath -RequestPath $RequestPath -UseHostNode:$UseHostNode
Register-RosetunHelper
Start-RosetunHelper

$guestDir = Get-RosetunGuestDir
$configPath = Join-Path $guestDir 'list-matrix\config.json'
try {
    Test-Step 'baseline' 'direct egress works before connect' { Test-RosetunDirectEgress }
    Test-Step 'baseline' 'direct DNS works before connect' { Test-RosetunDirectDns }

    $configPath = Invoke-RosetunGuest -ScriptBlock {
        param($dir)
        $root = Join-Path $dir 'list-matrix'
        $lists = Join-Path $root 'lists'
        New-Item -Path $lists -ItemType Directory -Force | Out-Null
        $request = Get-Content -Path (Join-Path $dir 'request.json') -Raw | ConvertFrom-Json
        $text = [Text.Encoding]::UTF8.GetBytes("example.com`n")
        $path = Join-Path $lists '1.txt'
        [IO.File]::WriteAllBytes($path, $text)
        $digest = (Get-FileHash -Path $path -Algorithm SHA256).Hash.ToLowerInvariant()
        $ruleSet = @{
            id = 'list-matrix'
            name = 'List matrix'
            default_target = 'proxy'
            rules = @(@{
                id = 'example-list'
                enabled = $true
                matcher = @{ list = @{ list = '1'; category = $null } }
                target = 'block'
            })
        }
        $config = @{
            version = 3
            settings = $request.settings
            subscriptions = @(@{
                id = $request.selection.subscription
                name = 'Test node'
                url = 'https://example.invalid/subscription'
                nodes = @($request.node)
            })
            active = $request.selection
            active_rule_set = $ruleSet.id
            rule_sets = @($ruleSet)
            lists = @(@{
                id = '1'
                name = 'Example list'
                source = @{ file = @{ original_name = 'example.txt' } }
                format = 'text'
                size = [uint64]$text.Length
                sha256 = $digest
                categories = @()
            })
        }
        $configPath = Join-Path $root 'config.json'
        [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 30))
        $configPath
    } -ArgumentList $guestDir

    $connect = Invoke-ListCli -ConfigPath $configPath -Action connect
    Test-Step 'text block' 'connect uploads the list' -Note "exit $($connect.ExitCode)" {
        $connect.ExitCode -eq 0 -and (Wait-RosetunState 'Connected')
    }
    $opened = Wait-RosetunTunnelEgress -Url 'https://example.org' -SkipRevocationCheck
    Test-Step 'text block' 'example.org opens through the tunnel' -Note "curl $($opened.CurlExit)" {
        $opened.Ok
    }
    Test-Step 'text block' 'example.com is blocked' {
        -not (Test-RosetunTunnelEgress -Url 'https://example.com' -SkipRevocationCheck)
    }
    Test-Step 'text block' 'physical egress remains blocked' {
        -not (Test-RosetunDirectEgress)
    }

    $compiled = Invoke-RosetunGuest -ScriptBlock {
        param($dir, $configPath)
        $root = Split-Path -Parent $configPath
        $source = Join-Path $root 'example.json'
        $binary = Join-Path $root 'lists\1.srs'
        [IO.File]::WriteAllText($source, '{"version":3,"rules":[{"domain_suffix":["example.com"]}]}')
        $output = & "$dir\sing-box.exe" rule-set compile --output $binary $source 2>&1 |
            ForEach-Object { "$_" }
        $exitCode = $LASTEXITCODE
        $global:LASTEXITCODE = 0
        if ($exitCode -eq 0) {
            $config = Get-Content -Path $configPath -Raw | ConvertFrom-Json
            $config.lists[0].format = 'sing_box_binary'
            $config.lists[0].source.file.original_name = 'example.srs'
            $config.lists[0].size = [uint64](Get-Item $binary).Length
            $config.lists[0].sha256 = (Get-FileHash -Path $binary -Algorithm SHA256).Hash.ToLowerInvariant()
            $config.rule_sets[0].default_target = 'block'
            $config.rule_sets[0].rules[0].target = 'direct'
            [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 30))
        }
        [pscustomobject]@{ ExitCode = $exitCode; Output = ($output -join "`n") }
    } -ArgumentList $guestDir, $configPath
    Test-Step 'binary direct' 'sing-box compiles a local SRS' -Note "exit $($compiled.ExitCode)" {
        $compiled.ExitCode -eq 0
    }

    if ($compiled.ExitCode -eq 0) {
        $apply = Invoke-ListCli -ConfigPath $configPath -Action apply
        Test-Step 'binary direct' 'apply uploads the compiled list' -Note "exit $($apply.ExitCode)" {
            $apply.ExitCode -eq 0 -and (Wait-RosetunState 'Connected')
        }
        $opened = Wait-RosetunTunnelEgress -Url 'https://example.com' -SkipRevocationCheck
        Test-Step 'binary direct' 'example.com opens with the direct rule' -Note "curl $($opened.CurlExit)" {
            $opened.Ok
        }
        Test-Step 'binary direct' 'unmatched example.org follows the block default' {
            -not (Test-RosetunTunnelEgress -Url 'https://example.org' -SkipRevocationCheck)
        }
        Test-Step 'binary direct' 'physical egress remains blocked' {
            -not (Test-RosetunDirectEgress)
        }
    }
}
finally {
    Disconnect-RosetunTunnel | Out-Null
    Invoke-RosetunGuest -ScriptBlock {
        param($configPath)
        Remove-Item -Path (Split-Path -Parent $configPath) -Recurse -Force -ErrorAction SilentlyContinue
    } -ArgumentList $configPath
}
}
finally {
    if ($nodeStartedByMatrix -and -not $KeepNode) {
        try { Stop-RosetunTestNode }
        catch { Write-Warning "Could not stop the test node: $_" }
    }
}

$results | Format-Table -AutoSize
if ($results.Result -contains 'FAIL') { exit 1 }
exit 0
