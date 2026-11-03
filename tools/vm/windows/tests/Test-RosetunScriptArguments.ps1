# Finds command arguments written as casts, such as
# `-ArgumentList $a, [bool]$Flag`. In argument mode that is not a cast but
# the string '[bool]False', which is true wherever it is tested: a guest
# script block then takes the branch for the flag being set. Parenthesise
# it: `([bool]$Flag)`. Parses every PowerShell file under tools\vm without
# running anything. Exits with 1 if any is found.

param(
    [string]$Root = (Join-Path $PSScriptRoot '..\..')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$found = 0
$files = @(Get-ChildItem -Path $Root -Recurse -File -Include '*.ps1', '*.psm1')
foreach ($file in $files) {
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$errors)
    if (@($errors).Count -gt 0) {
        Write-Host "FAIL  $($file.FullName): does not parse: $($errors[0].Message)" -ForegroundColor Red
        $found++
        continue
    }
    $bareCasts = $ast.FindAll({
            param($node)
            ($node -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -or
                $node -is [System.Management.Automation.Language.StringConstantExpressionAst]) -and
            $node.StringConstantType -eq [System.Management.Automation.Language.StringConstantType]::BareWord -and
            $node.Extent.Text -match '^\[[\w.]+\]\S'
        }, $true)
    foreach ($node in $bareCasts) {
        Write-Host ("FAIL  {0}:{1}: '{2}' is a string here, not a cast; write ({2})" -f
            $file.FullName, $node.Extent.StartLineNumber, $node.Extent.Text) -ForegroundColor Red
        $found++
    }
}

if ($found -gt 0) {
    Write-Host "$found finding(s) in $($files.Count) files" -ForegroundColor Red
    exit 1
}
Write-Host "PASS  no cast-like command arguments in $($files.Count) files"
exit 0
