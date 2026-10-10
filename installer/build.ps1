param([switch]$Release)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
. (Join-Path $PSScriptRoot 'version.ps1')
$releaseVersion = Get-RosetunVersion
$version = $releaseVersion.Version
$fileVersion = $releaseVersion.FileVersion
# Keep this version in sync with the cargo-about cache key in .github/workflows/release.yml.
$cargoAboutVersion = '0.9.2'
$installedCargoAbout = & cargo about --version 2>$null
if ($LASTEXITCODE -ne 0 -or ($installedCargoAbout | Out-String).Trim() -ne "cargo-about $cargoAboutVersion") {
    if (-not $Release) {
        throw "cargo-about $cargoAboutVersion is required. Install it with: cargo install cargo-about --locked --version $cargoAboutVersion --features cli --force"
    }
    & cargo install cargo-about --locked --version $cargoAboutVersion --features cli --force
    if ($LASTEXITCODE -ne 0) {
        throw "Installing cargo-about $cargoAboutVersion failed with cargo exit code $LASTEXITCODE."
    }
    $installedCargoAbout = & cargo about --version 2>$null
    if ($LASTEXITCODE -ne 0 -or ($installedCargoAbout | Out-String).Trim() -ne "cargo-about $cargoAboutVersion") {
        throw "cargo-about $cargoAboutVersion is unavailable after installation."
    }
}

# Update these together with Install-RosetunSingBox and SUPPORTED_SING_BOX_VERSION.
$singBoxVersion = '1.14.1'
$expectedHash = 'B838DE45BD0B2E6DDBED1977E4745622F7DFFAB3B293807FF4C6B1B640FED909'
$wintunVersion = '0.14.1'
$wintunDllLength = 427552
$wintunDllHash = 'E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE'
$versionFile = Get-Content -LiteralPath (Join-Path $root 'crates/rosetun-engine-singbox/src/version.rs') -Raw
$supportedVersion = [regex]::Match($versionFile, '(?m)^pub const SUPPORTED_SING_BOX_VERSION:\s*&str\s*=\s*"([^"]+)"\s*;')
if (-not $supportedVersion.Success) {
    throw 'Cannot read SUPPORTED_SING_BOX_VERSION from version.rs.'
}
if ($singBoxVersion -ne $supportedVersion.Groups[1].Value) {
    throw "Installer sing-box $singBoxVersion differs from SUPPORTED_SING_BOX_VERSION $($supportedVersion.Groups[1].Value)."
}

$buildDir = Join-Path $root 'target/release'
$outputDir = Join-Path $root 'target/installer'
$licensesDir = Join-Path $outputDir 'licenses'
$singBoxDir = Join-Path $outputDir 'sing-box'
$binary = Join-Path $singBoxDir 'sing-box.exe'
$license = Join-Path $singBoxDir 'LICENSE'

if (Test-Path -LiteralPath $licensesDir) {
    Remove-Item -LiteralPath $licensesDir -Recurse -Force
}
New-Item -ItemType Directory -Path $licensesDir -Force | Out-Null

Push-Location $root
try {
    & cargo build -q --release --locked -p rosetun-gui -p rosetun-helper-privileged -p rosetun
    if ($LASTEXITCODE -ne 0) {
        throw "Building release binaries failed with cargo exit code $LASTEXITCODE."
    }
    & cargo -q about generate --fail --locked installer/third-party.hbs -o (Join-Path $licensesDir 'third-party.html')
    if ($LASTEXITCODE -ne 0) {
        throw "Generating Rust crate licenses failed with cargo-about exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}

if (-not ((Test-Path -LiteralPath $binary -PathType Leaf) -and
           (Test-Path -LiteralPath $license -PathType Leaf) -and
           (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash -eq $expectedHash)) {
    $name = "sing-box-$singBoxVersion-windows-amd64"
    $url = "https://github.com/SagerNet/sing-box/releases/download/v$singBoxVersion/$name.zip"
    $tempDir = Join-Path ([IO.Path]::GetTempPath()) ("rosetun-installer-" + [guid]::NewGuid().ToString('N'))
    $archive = Join-Path $tempDir "$name.zip"
    $unpacked = Join-Path $tempDir 'unpacked'
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    try {
        & curl.exe --fail --silent --show-error --location --output $archive $url
        if ($LASTEXITCODE -ne 0) {
            throw "Downloading $url failed with curl exit code $LASTEXITCODE."
        }
        Expand-Archive -LiteralPath $archive -DestinationPath $unpacked
        $downloadedBinary = Join-Path $unpacked "$name/sing-box.exe"
        $downloadedLicense = Join-Path $unpacked "$name/LICENSE"
        if (-not (Test-Path -LiteralPath $downloadedLicense -PathType Leaf)) {
            throw "Archive $url does not contain LICENSE."
        }
        $hash = (Get-FileHash -LiteralPath $downloadedBinary -Algorithm SHA256).Hash
        if ($hash -ne $expectedHash) {
            throw "sing-box.exe from $url has SHA-256 $hash, expected $expectedHash."
        }
        New-Item -ItemType Directory -Path $singBoxDir -Force | Out-Null
        Copy-Item -LiteralPath $downloadedBinary -Destination $binary -Force
        Copy-Item -LiteralPath $downloadedLicense -Destination $license -Force
    }
    finally {
        Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Verify the embedded DLL without extracting or modifying the official executable.
$singBoxBytes = [IO.File]::ReadAllBytes($binary)
$wintunFound = $false
$sha256 = [Security.Cryptography.SHA256]::Create()
try {
    $offset = [Array]::IndexOf($singBoxBytes, [byte]0x4D, 0)
    while ($offset -ge 0 -and $offset -le $singBoxBytes.Length - $wintunDllLength) {
        if ($singBoxBytes[$offset + 1] -eq 0x5A) {
            $candidateHash = [BitConverter]::ToString($sha256.ComputeHash($singBoxBytes, $offset, $wintunDllLength)).Replace('-', '')
            if ($candidateHash -eq $wintunDllHash) {
                $wintunFound = $true
                break
            }
        }
        $offset = [Array]::IndexOf($singBoxBytes, [byte]0x4D, $offset + 1)
    }
}
finally {
    $sha256.Dispose()
}
if (-not $wintunFound) {
    throw "Wintun notice verification failed: sing-box.exe does not contain the pinned Wintun $wintunVersion amd64 DLL (SHA-256 $wintunDllHash). Review the Wintun version, DLL pin and license notices before packaging."
}

Copy-Item -LiteralPath (Join-Path $root 'LICENSE') -Destination (Join-Path $licensesDir 'rosetun.txt')
Copy-Item -LiteralPath $license -Destination (Join-Path $licensesDir 'sing-box.txt')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'third-party/wintun-prebuilt-binaries-license.txt') -Destination $licensesDir
$wintunNotice = @"
The unmodified official sing-box $singBoxVersion executable embeds Wintun $wintunVersion.
The prebuilt Wintun DLL is copyrighted by WireGuard LLC and is distributed
under the Wintun Prebuilt Binaries License; see wintun-prebuilt-binaries-license.txt.

Upstream binary distribution:
https://www.wintun.net/builds/wintun-$wintunVersion.zip
Embedded amd64 DLL: $wintunDllLength bytes, SHA-256 $wintunDllHash.

Wintun source code (GPL-2.0):
https://git.zx2c4.com/wintun/tree/?h=$wintunVersion

Rosetun is not affiliated with WireGuard LLC.

License source:
https://git.zx2c4.com/wintun/plain/prebuilt-binaries-license.txt?h=$wintunVersion
"@
Set-Content -LiteralPath (Join-Path $licensesDir 'wintun.txt') -Value $wintunNotice -Encoding utf8
Copy-Item -Path (Join-Path $root 'crates/rosetun-gui/assets/fonts/OFL-*.txt') -Destination $licensesDir
$sourceNotice = @"
sing-box $singBoxVersion is licensed under the GNU General Public License,
version 3 or later (see sing-box.txt). Rosetun ships the unmodified official
build sing-box-$singBoxVersion-windows-amd64, sing-box.exe SHA-256 $expectedHash.

Corresponding source:
https://github.com/SagerNet/sing-box/tree/v$singBoxVersion
https://github.com/SagerNet/sing-box/archive/refs/tags/v$singBoxVersion.tar.gz

Every Rosetun release on GitHub also carries a copy of that source archive.
"@
Set-Content -LiteralPath (Join-Path $licensesDir 'sing-box-source.txt') -Value $sourceNotice -Encoding utf8

if ($env:ISCC) {
    $iscc = $env:ISCC
}
else {
    $iscc = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
}
if (-not $iscc -or -not (Test-Path -LiteralPath $iscc -PathType Leaf)) {
    throw 'Inno Setup 6.3 or later is required: https://jrsoftware.org/isdl.php (or set ISCC)'
}

New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
$issPath = Join-Path $PSScriptRoot 'rosetun.iss'
& $iscc /Qp "/DAppVersion=$version" "/DFileVersion=$fileVersion" "/DBuildDir=$buildDir" "/DSingBoxDir=$singBoxDir" "/DLicensesDir=$licensesDir" "/O$outputDir" $issPath
if ($LASTEXITCODE -ne 0) {
    throw "Compiling $issPath failed with ISCC exit code $LASTEXITCODE."
}
$setup = Join-Path $outputDir "rosetun-$version-setup.exe"
if (-not (Test-Path -LiteralPath $setup -PathType Leaf)) {
    throw "ISCC did not produce $setup."
}
Write-Host "Installer: $setup"
Write-Host "SHA-256: $((Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash)"

if ($Release) {
    $sourceArchive = Join-Path $outputDir "sing-box-$singBoxVersion-source.tar.gz"
    $partialArchive = "$sourceArchive.download"
    $sourceUrl = "https://github.com/SagerNet/sing-box/archive/refs/tags/v$singBoxVersion.tar.gz"
    try {
        & curl.exe --fail --location --silent --show-error --output $partialArchive $sourceUrl
        if ($LASTEXITCODE -ne 0) {
            throw "Downloading $sourceUrl failed with curl exit code $LASTEXITCODE."
        }
        Move-Item -LiteralPath $partialArchive -Destination $sourceArchive -Force
    }
    finally {
        if (Test-Path -LiteralPath $partialArchive) {
            Remove-Item -LiteralPath $partialArchive -Force
        }
    }

    $setupHash = (Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash.ToLowerInvariant()
    $sourceHash = (Get-FileHash -LiteralPath $sourceArchive -Algorithm SHA256).Hash.ToLowerInvariant()
    $checksums = @(
        "$setupHash  $([IO.Path]::GetFileName($setup))"
        "$sourceHash  $([IO.Path]::GetFileName($sourceArchive))"
    )
    $utf8 = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText((Join-Path $outputDir 'SHA256SUMS.txt'), ($checksums -join "`n") + "`n", $utf8)

    $notes = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'release-notes.md'), [Text.Encoding]::UTF8)
    $notes = $notes.Replace('{{version}}', $version)
    $notes = $notes.Replace('{{setup}}', [IO.Path]::GetFileName($setup))
    $notes = $notes.Replace('{{sha256}}', $setupHash)
    $notes = $notes.Replace('{{sing_box_version}}', $singBoxVersion)
    $notes = $notes.Replace('{{wintun_version}}', $wintunVersion)
    [IO.File]::WriteAllText((Join-Path $outputDir 'release-notes.md'), $notes, $utf8)

    if ($env:GITHUB_OUTPUT) {
        $outputs = "version=$version`nprerelease=$($releaseVersion.Prerelease.ToString().ToLowerInvariant())`nsetup=$setup`n"
        [IO.File]::AppendAllText($env:GITHUB_OUTPUT, $outputs, $utf8)
    }
    Write-Host "Source archive: $sourceArchive"
}
