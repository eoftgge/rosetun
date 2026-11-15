"""Install the pinned Zola release (tools/site/zola.toml) for Linux or Windows, x86-64.

The archive comes from the GitHub release of that exact version and its SHA-256 is checked before
anything is unpacked. Only the `zola` executable is extracted.
"""

import argparse
import hashlib
from pathlib import Path
import platform
import stat
import tarfile
import tomllib
import urllib.request
import zipfile
from io import BytesIO

PIN = Path(__file__).with_name('zola.toml')
LIMIT = 100 * 1024 * 1024


def pinned():
    return tomllib.loads(PIN.read_text(encoding='utf-8'))


def archive(pin, system):
    """The archive name and the pin entry for a platform."""
    entry = pin[system]
    extension = 'tar.gz' if system == 'linux' else 'zip'
    return f'zola-v{pin["version"]}-{entry["triple"]}.{extension}', entry


def current_system():
    machine = platform.machine().lower()
    system = platform.system().lower()
    if system in ('linux', 'windows') and machine in ('x86_64', 'amd64'):
        return system
    raise SystemExit(f'no pinned Zola for {platform.system()} {platform.machine()}')


def verify(data, expected):
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected:
        raise ValueError(f'SHA-256 mismatch: expected {expected}, got {digest}')


def unpack(data, system, directory):
    """Extract only the executable, after the hash has been verified."""
    name = 'zola.exe' if system == 'windows' else 'zola'
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / name
    if system == 'windows':
        with zipfile.ZipFile(BytesIO(data)) as source:
            target.write_bytes(source.read(name))
    else:
        with tarfile.open(fileobj=BytesIO(data), mode='r:gz') as source:
            member = source.getmember(name)
            if not member.isfile():
                raise ValueError(f'{name} is not a regular file in the archive')
            target.write_bytes(source.extractfile(member).read())
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return target


def install(directory, system=None):
    pin = pinned()
    system = system or current_system()
    name, entry = archive(pin, system)
    url = f'https://github.com/getzola/zola/releases/download/v{pin["version"]}/{name}'
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError('the Zola archive exceeds 100 MiB')
    verify(data, entry['sha256'])
    return unpack(data, system, directory)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=Path('target/zola'), help='where to put the executable')
    args = parser.parse_args()
    print(install(args.directory))
