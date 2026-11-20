# Signs the SHA256SUMS.txt of a draft GitHub release with minisign and uploads
# the signature. Run it on the owner's machine: the secret key is read only by
# minisign, which asks for its password on the console. The script never
# copies, prints or stores the key, and it does not publish unless asked.
#
#   .\tools\release\Sign-RosetunRelease.ps1 -Version 0.7.0 -SecretKey D:\keys\rosetun.key
#
# The trusted comment is `rosetun <version>`. The client refuses an update
# whose comment does not match the release it came from.

param(
    # The release version without the leading "v", as in Cargo.toml.
    [Parameter(Mandatory)][string]$Version,
    # Path to the minisign secret key file.
    [Parameter(Mandatory)][string]$SecretKey,
    [string]$Repository = 'eoftgge/rosetun',
    # The public key the signature is checked against. Defaults to the one
    # committed in the repository.
    [string]$PublicKey,
    # Publishes the draft after the signature is uploaded.
    [switch]$Publish
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-RosetunCommand {
    param([Parameter(Mandatory)][string]$Name)

    if (-not (Get-Command -Name $Name -CommandType Application -ErrorAction SilentlyContinue)) {
        throw "'$Name' was not found on PATH. Install it and try again."
    }
}

function Assert-RosetunExitCode {
    param([Parameter(Mandatory)][string]$Action)

    if ($LASTEXITCODE -ne 0) {
        throw "$Action failed (exit code $LASTEXITCODE)."
    }
}

if ($Version -notmatch '^\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$') {
    throw "Version '$Version' is not a version such as 0.7.0 or 0.7.0-beta.1. Do not add a leading 'v'."
}

if (-not $PublicKey) {
    $repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).ProviderPath
    $PublicKey = Join-Path $repositoryRoot 'crates\rosetun-core\keys\minisign.pub'
}
if (-not (Test-Path -LiteralPath $PublicKey -PathType Leaf)) {
    throw "The public key file was not found: $PublicKey"
}
if (-not (Test-Path -LiteralPath $SecretKey -PathType Leaf)) {
    throw 'The secret key file was not found. Pass the path to the minisign secret key with -SecretKey.'
}
$secretKeyPath = (Resolve-Path -LiteralPath $SecretKey).ProviderPath
$publicKeyPath = (Resolve-Path -LiteralPath $PublicKey).ProviderPath

Assert-RosetunCommand -Name 'gh'
Assert-RosetunCommand -Name 'minisign'

$tag = "v$Version"
$trustedComment = "rosetun $Version"

$releaseJson = & gh release view $tag --repo $Repository --json isDraft,tagName
Assert-RosetunExitCode -Action "Looking up release $tag in $Repository"
$release = ($releaseJson | Out-String) | ConvertFrom-Json
if ($release.tagName -ne $tag) {
    throw "GitHub returned release '$($release.tagName)' instead of $tag."
}
if (-not $release.isDraft) {
    throw "Release $tag is already published. Sign a draft, before it is published."
}

$workDirectory = Join-Path ([IO.Path]::GetTempPath()) ("rosetun-sign-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workDirectory | Out-Null
try {
    & gh release download $tag --repo $Repository --pattern 'SHA256SUMS.txt' --dir $workDirectory
    Assert-RosetunExitCode -Action 'Downloading SHA256SUMS.txt'
    $sums = Join-Path $workDirectory 'SHA256SUMS.txt'
    if (-not (Test-Path -LiteralPath $sums -PathType Leaf)) {
        throw "Release $tag has no SHA256SUMS.txt."
    }
    $signature = "$sums.minisig"

    Write-Host "Signing SHA256SUMS.txt of $tag. minisign asks for the key password."
    & minisign -S -s $secretKeyPath -m $sums -t $trustedComment
    Assert-RosetunExitCode -Action 'Signing'
    if (-not (Test-Path -LiteralPath $signature -PathType Leaf)) {
        throw 'minisign did not write a signature file.'
    }

    & minisign -V -p $publicKeyPath -m $sums
    Assert-RosetunExitCode -Action 'Verifying the signature with the public key'
    $comments = @(Get-Content -LiteralPath $signature | Where-Object { $_ -like 'trusted comment:*' })
    if ($comments.Count -ne 1 -or $comments[0] -cne "trusted comment: $trustedComment") {
        throw "The trusted comment of the signature is not exactly 'trusted comment: $trustedComment'."
    }

    & gh release upload $tag $signature --repo $Repository --clobber
    Assert-RosetunExitCode -Action 'Uploading SHA256SUMS.txt.minisig'
    Write-Host "Uploaded SHA256SUMS.txt.minisig to the draft $tag."

    if ($Publish) {
        & gh release edit $tag --draft=false --repo $Repository
        Assert-RosetunExitCode -Action 'Publishing the release'
        Write-Host "Published $tag."
    }
    else {
        Write-Host 'The release is still a draft. After a final look, publish it:'
        Write-Host "  gh release edit $tag --draft=false --repo $Repository"
        Write-Host 'or run this script again with -Publish.'
    }
}
finally {
    Remove-Item -LiteralPath $workDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
