"""Copy the site and fill release markers from GitHub, only during publication."""

import argparse
import html
import json
import os
from pathlib import Path
import re
import shutil
import urllib.request

REPOSITORY = 'eoftgge/rosetun'
API = f'https://api.github.com/repos/{REPOSITORY}'
RELEASES = f'https://github.com/{REPOSITORY}/releases/download/'
MARKERS = {'VERSION', 'INSTALLER', 'DOWNLOAD_URL', 'CHECKSUM_URL', 'SHA256_LINE'}


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
    return dict(VERSION=version, INSTALLER=installer, DOWNLOAD_URL=download,
                CHECKSUM_URL=checksums, SHA256_LINE=matching[0])


def render(source, output, values):
    if set(values) != MARKERS:
        raise ValueError('incomplete release data')
    if output.exists():
        raise ValueError('output must be a new directory')
    shutil.copytree(source, output)
    for path in output.rglob('*.html'):
        text = path.read_text(encoding='utf-8')
        found = set(re.findall(r'@@([A-Z0-9_]+)@@', text))
        if found and found != MARKERS:
            raise ValueError(f'incomplete markers in {path}')
        for key, value in values.items():
            text = text.replace(f'@@{key}@@', html.escape(value, quote=True))
        text = re.sub(r'href="[^"]*" data-release-href="([^"]*)"',
                      lambda match: f'href="{match[1]}"', text)
        text = re.sub(r'<(span|code)([^>]*?) data-release-text="([^"]*)">.*?</\1>',
                      lambda match: f'<{match[1]}{match[2]}>{match[3]}</{match[1]}>', text)
        if '@@' in text:
            raise ValueError(f'unresolved marker in {path}')
        path.write_text(text, encoding='utf-8', newline='\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    release = json.loads(fetch(f'{API}/releases/latest', api=True))
    # Validate asset URLs before making any release download request.
    provisional = replacements(release, '0' * 64 + '  rosetun-' + release['tag_name'].removeprefix('v') + '-setup.exe')
    sums = fetch(provisional['CHECKSUM_URL']).decode('utf-8-sig')
    render(Path('site'), args.output, replacements(release, sums))
