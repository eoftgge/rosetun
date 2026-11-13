"""Copy the site and fill release markers from GitHub, only during publication."""

import argparse
import html
import json
import os
from pathlib import Path
import re
import shutil
import tomllib
import urllib.request

REPOSITORY = 'eoftgge/rosetun'
API = f'https://api.github.com/repos/{REPOSITORY}'
RELEASES = f'https://github.com/{REPOSITORY}/releases/download/'
MARKERS = {'VERSION', 'INSTALLER', 'DOWNLOAD_URL', 'CHECKSUM_URL', 'SHA256_LINE'}
# What a page says about Linux depends on whether the stable release has a package.
LINUX_MARKERS = {'DEB', 'DEB_URL'}
LINUX_READY = re.compile(r'<!-- linux-ready (.*?) -->', re.DOTALL)
LINUX_SOON = re.compile(r'<!-- linux-soon -->(.*?)<!-- /linux-soon -->', re.DOTALL)
DOC_VERSION = re.compile(r'<!-- docs-version -->(.*?)<!-- /docs-version -->', re.DOTALL)


def workspace_version(manifest):
    """The workspace is the sole source of the site's release version."""
    with manifest.open('rb') as source:
        version = tomllib.load(source)['workspace']['package']['version']
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('the site requires a stable workspace version')
    return version


def fetch(url, api=False):
    headers = {'User-Agent': 'Rosetun-Pages', 'Accept': 'application/vnd.github+json' if api else 'text/plain'}
    if api and os.environ.get('GH_TOKEN'):
        headers['Authorization'] = f'Bearer {os.environ["GH_TOKEN"]}'
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        body = response.read(2 * 1024 * 1024 + 1)
    if len(body) > 2 * 1024 * 1024:
        raise ValueError('release response exceeds 2 MiB')
    return body


def replacements(release, sums):
    if release.get('draft') or release.get('prerelease'):
        raise ValueError('a stable published release is required')
    tag = release['tag_name']
    if not re.fullmatch(r'v?\d+\.\d+\.\d+', tag):
        raise ValueError('unexpected stable release tag')
    version = tag.removeprefix('v')
    installer = f'rosetun-{version}-setup.exe'
    assets = release['assets']

    def asset_url(name):
        matches = [a['browser_download_url'] for a in assets if a['name'] == name]
        if matches != [f'{RELEASES}{tag}/{name}']:
            raise ValueError(f'missing, duplicated or unexpected asset: {name}')
        return matches[0]

    download = asset_url(installer)
    checksums = asset_url('SHA256SUMS.txt')
    matching = []
    for line in sums.splitlines():
        match = re.fullmatch(r'([0-9a-fA-F]{64}) [ *](.+)', line)
        if match and match[2] == installer:
            matching.append(line)
    if len(matching) != 1:
        raise ValueError('expected exactly one installer checksum')
    deb = f'rosetun_{version}_amd64.deb'
    deb_url = ''
    if any(a['name'] == deb for a in assets):
        deb_url = asset_url(deb)
        if not any(re.fullmatch(r'[0-9a-fA-F]{64} [ *]' + re.escape(deb), line) for line in sums.splitlines()):
            raise ValueError('expected a checksum of the Debian package')
    return dict(VERSION=version, INSTALLER=installer, DOWNLOAD_URL=download,
                CHECKSUM_URL=checksums, SHA256_LINE=matching[0], DEB=deb if deb_url else '', DEB_URL=deb_url)


def render(source, output, values):
    if set(values) != MARKERS | LINUX_MARKERS:
        raise ValueError('incomplete release data')
    if output.exists():
        raise ValueError('output must be a new directory')
    shutil.copytree(source, output)
    for path in output.rglob('*.html'):
        text = path.read_text(encoding='utf-8')
        if tuple(map(int, values['VERSION'].split('.'))) >= (0, 5, 0):
            english = path.relative_to(output).parts[0] == 'en'
            label = 'Stable release' if english else 'Стабильный выпуск'
            platforms = 'Windows and Linux' if english else 'Windows и Linux'
            if not values['DEB_URL']:
                platforms = 'Windows'
            def stable_banner(match):
                return f'<p class="note">{label}: {html.escape(values["VERSION"])} · {platforms}.</p>'
            text = DOC_VERSION.sub(stable_banner, text)
        else:
            english = path.relative_to(output).parts[0] == 'en'
            label = 'Stable release' if english else 'Стабильный выпуск'
            baseline = 'Documentation: 0.5' if english else 'Документация: 0.5'
            text = DOC_VERSION.sub(
                lambda match: f'<p class="note">{label}: {html.escape(values["VERSION"])} · Windows. {baseline}.</p>',
                text,
            )
        if values['DEB_URL']:
            text = LINUX_SOON.sub('', text)
            text = LINUX_READY.sub(lambda match: match[1], text)
            for key in LINUX_MARKERS:
                text = text.replace(f'@@{key}@@', html.escape(values[key], quote=True))
        else:
            text = LINUX_READY.sub('', text)
            text = LINUX_SOON.sub(lambda match: match[1], text)
        found = set(re.findall(r'@@([A-Z0-9_]+)@@', text))
        if unknown := found - MARKERS:
            raise ValueError(f'unknown release markers in {path}: {sorted(unknown)}')
        for key in MARKERS:
            text = text.replace(f'@@{key}@@', html.escape(values[key], quote=True))
        text = re.sub(r'href="[^"]*"\s+data-release-href="([^"]*)"',
                      lambda match: f'href="{match[1]}"', text)
        text = re.sub(r'<(span|code)([^>]*?)\s+data-release-text="([^"]*)"\s*>.*?</\1\s*>',
                      lambda match: f'<{match[1]}{match[2].rstrip()}>{match[3]}</{match[1]}>',
                      text, flags=re.DOTALL)
        if '@@' in text:
            raise ValueError(f'unresolved marker in {path}')
        path.write_text(text, encoding='utf-8', newline='\n')


def preview_values(version, linux):
    """Use synthetic checksums only for a local, offline release preview."""
    names = [f'rosetun-{version}-setup.exe', 'SHA256SUMS.txt']
    if linux:
        names.append(f'rosetun_{version}_amd64.deb')
    release = dict(tag_name=f'v{version}', draft=False, prerelease=False, assets=[
        dict(name=name, browser_download_url=f'{RELEASES}v{version}/{name}') for name in names
    ])
    return replacements(release, '\n'.join('0' * 64 + '  ' + name for name in names))


def published_values(manifest):
    version = workspace_version(manifest)
    release = json.loads(fetch(f'{API}/releases/tags/v{version}', api=True))
    if release['tag_name'] != f'v{version}':
        raise ValueError('release tag does not match the workspace version')
    # Validate asset URLs before making any release download request.
    provisional = replacements(release, '\n'.join(
        '0' * 64 + '  ' + name for name in (f'rosetun-{version}-setup.exe', f'rosetun_{version}_amd64.deb')
    ))
    sums = fetch(provisional['CHECKSUM_URL']).decode('utf-8-sig')
    return replacements(release, sums)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--preview', action='store_true', help='offline preview of the workspace version; never publish')
    parser.add_argument('--preview-version', help='offline preview with synthetic checksums; never publish')
    parser.add_argument('--preview-deb', action='store_true', help='include a Debian package in the preview')
    args = parser.parse_args()
    if args.preview_deb and not (args.preview or args.preview_version):
        parser.error('--preview-deb requires --preview or --preview-version')
    if args.preview or args.preview_version:
        version = args.preview_version or workspace_version(Path('Cargo.toml'))
        render(Path('site'), args.output, preview_values(version, args.preview_deb))
        print('Local preview only: checksums are synthetic. Do not publish this directory.')
        raise SystemExit(0)
    render(Path('site'), args.output, published_values(Path('Cargo.toml')))
