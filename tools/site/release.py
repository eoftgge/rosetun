"""Write the release data the site reads, only during publication.

The pages show neutral text until `site/data/release.json` exists; Zola reads the file through
`load_data`. The workspace version in Cargo.toml selects the release: exactly its `v<version>` tag.
"""

import argparse
import json
import os
from pathlib import Path
import re
import tomllib
import urllib.request

REPOSITORY = 'eoftgge/rosetun'
API = f'https://api.github.com/repos/{REPOSITORY}'
RELEASES = f'https://github.com/{REPOSITORY}/releases/download/'
DATA = Path('site/data/release.json')
KEYS = {'version', 'installer', 'download_url', 'checksum_url', 'sha256_line', 'deb', 'deb_url', 'banner'}


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


def banner(version, linux):
    """The documentation banner of each language, from the stable version and its platforms."""
    release = tuple(map(int, version.split('.')))
    result = {}
    for lang, label, platforms, baseline in (
        ('ru', 'Стабильный выпуск', 'Windows и Linux', 'Документация: 0.6'),
        ('en', 'Stable release', 'Windows and Linux', 'Documentation: 0.6'),
    ):
        supported = platforms if linux and release >= (0, 5, 0) else 'Windows'
        result[lang] = f'{label}: {version} · {supported}.'
        if release < (0, 6, 0):
            result[lang] += f' {baseline}.'
    return result


def replacements(release, sums):
    """The data of one published release; it refuses anything but a complete stable release."""
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
    return dict(version=version, installer=installer, download_url=download, checksum_url=checksums,
                sha256_line=matching[0], deb=deb if deb_url else '', deb_url=deb_url,
                banner=banner(version, bool(deb_url)))


def write(output, values):
    """Writes the data file that the Zola templates and pages read through `load_data`."""
    if set(values) != KEYS:
        raise ValueError('incomplete release data')
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(values, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')


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
    sums = fetch(provisional['checksum_url']).decode('utf-8-sig')
    return replacements(release, sums)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=DATA, help=f'data file, {DATA} by default')
    parser.add_argument('--preview', action='store_true', help='offline preview of the workspace version; never publish')
    parser.add_argument('--preview-version', help='offline preview with synthetic checksums; never publish')
    parser.add_argument('--preview-deb', action='store_true', help='include a Debian package in the preview')
    args = parser.parse_args()
    if args.preview_deb and not (args.preview or args.preview_version):
        parser.error('--preview-deb requires --preview or --preview-version')
    if args.preview or args.preview_version:
        version = args.preview_version or workspace_version(Path('Cargo.toml'))
        write(args.output, preview_values(version, args.preview_deb))
        print('Local preview only: checksums are synthetic. Do not publish this build.')
        raise SystemExit(0)
    write(args.output, published_values(Path('Cargo.toml')))
