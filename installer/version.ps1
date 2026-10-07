function Get-RosetunVersion {
    $root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    $manifest = Get-Content -LiteralPath (Join-Path $root 'Cargo.toml') -Raw
    $workspacePackage = [regex]::Match($manifest, '(?ms)^\[workspace\.package\]\r?\n(?<section>.*?)(?=^\[|\z)')
    if (-not $workspacePackage.Success) {
        throw 'Missing [workspace.package] in Cargo.toml.'
    }
    $versionMatch = [regex]::Match($workspacePackage.Groups['section'].Value, '(?m)^version\s*=\s*"(?<version>[^"]+)"\s*$')
    if (-not $versionMatch.Success) {
        throw 'Missing version in [workspace.package] in Cargo.toml.'
    }
    $version = $versionMatch.Groups['version'].Value
    $fileVersion = $version -replace '-.*$', ''
    if ($fileVersion -notmatch '^\d+\.\d+\.\d+$') {
        throw "Invalid numeric installer file version $fileVersion from $version."
    }
    [pscustomobject]@{
        Version = $version
        FileVersion = $fileVersion
        Prerelease = $version.Contains('-')
    }
}
