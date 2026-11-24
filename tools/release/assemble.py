"""Release validation and asset assembly for .github/workflows/release.yml.

Subcommands:
  check-tag   Verify that a pushed tag matches Cargo.toml, sits on master (or
              dev for an alpha/beta of the next minor/major version), and has
              no existing GitHub release (including drafts).
  assemble    Combine Windows, Linux, and macOS release artifacts in one
              directory, update SHA256SUMS.txt and release-notes.md, verify no
              unexpanded placeholders remain, and emit GITHUB_OUTPUT entries.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib


def read_workspace_version(manifest: Path) -> str:
    with manifest.open('rb') as handle:
        data = tomllib.load(handle)
    version = data['workspace']['package']['version']
    numeric = version.split('-', 1)[0]
    if not re.fullmatch(r'\d+\.\d+\.\d+', numeric):
        raise ValueError(f'invalid workspace version: {version}')
    return version


def is_next_minor_prerelease(master_version: str, tag_version: str) -> bool:
    master_match = re.match(r'^(\d+)\.(\d+)\.\d+', master_version)
    tag_match = re.match(r'^(\d+)\.(\d+)\.\d+-(alpha|beta)\.', tag_version)
    if not master_match or not tag_match:
        return False
    master_pair = (int(master_match[1]), int(master_match[2]))
    tag_pair = (int(tag_match[1]), int(tag_match[2]))
    return tag_pair > master_pair


def validate_tag_rules(
    *,
    tag: str,
    version: str,
    on_master: bool,
    on_dev: bool,
    master_version: str,
    existing_tags: list[str],
) -> None:
    if tag != f'v{version}':
        raise ValueError(f'Tag {tag} does not match Cargo.toml version {version}.')
    allowed = on_master or (on_dev and is_next_minor_prerelease(master_version, version))
    if not allowed:
        raise ValueError(
            f'Tag {tag} must point to a commit on master, or on dev for an alpha or beta of the next version.'
        )
    if tag in existing_tags:
        raise ValueError(f'Release {tag} already exists.')


def git_is_ancestor(commit: str, ref: str) -> bool:
    result = subprocess.run(
        ['git', 'merge-base', '--is-ancestor', commit, ref],
        check=False,
        capture_output=True,
    )
    return result.returncode == 0


def read_git_manifest_version(ref: str) -> str:
    raw = subprocess.check_output(['git', 'show', f'{ref}:Cargo.toml'])
    return tomllib.loads(raw.decode('utf-8'))['workspace']['package']['version']


def list_existing_release_tags() -> list[str]:
    # `gh release view` ignores draft releases; listing all releases sees drafts too.
    raw = subprocess.check_output(['gh', 'release', 'list', '--limit', '1000', '--json', 'tagName'])
    return [entry['tagName'] for entry in json.loads(raw.decode('utf-8'))]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest().lower()


def find_single(directory: Path, pattern: str, label: str) -> Path:
    matches = sorted(p for p in directory.glob(pattern) if p.is_file())
    if len(matches) != 1:
        raise ValueError(f'Expected exactly one {label} matching {pattern}, found {len(matches)}.')
    return matches[0]


def assemble_release(directory: Path, manifest: Path) -> dict[str, str]:
    version = read_workspace_version(manifest)
    prerelease = 'true' if '-' in version else 'false'

    setup = find_single(directory, 'rosetun-*-setup.exe', 'Windows installer')
    deb = find_single(directory, 'rosetun_*_amd64.deb', 'Debian package')
    archive = find_single(directory, 'rosetun-*-linux-amd64.tar.gz', 'Linux archive')
    macos = find_single(directory, 'rosetun-*-macos-arm64-experimental.pkg', 'macOS package')
    sing_box_source = find_single(directory, 'sing-box-*-source.tar.gz', 'sing-box source archive')
    xray_source = find_single(directory, 'xray-*-source.tar.gz', 'Xray source archive')

    # GitHub turns "~" in an asset name into ".", which would part it from
    # SHA256SUMS.txt. The package's internal Debian version keeps "~".
    clean_deb_name = deb.name.replace('~', '-')
    if clean_deb_name != deb.name:
        target_deb = directory / clean_deb_name
        deb.rename(target_deb)
        deb = target_deb

    deb_hash = sha256_file(deb)
    archive_hash = sha256_file(archive)
    macos_hash = sha256_file(macos)

    sums_path = directory / 'SHA256SUMS.txt'
    sums_text = sums_path.read_text(encoding='utf-8')
    if sums_text and not sums_text.endswith('\n'):
        sums_text += '\n'
    sums_text += (
        f'{deb_hash}  {deb.name}\n'
        f'{archive_hash}  {archive.name}\n'
        f'{macos_hash}  {macos.name}\n'
    )
    sums_path.write_text(sums_text, encoding='utf-8', newline='\n')

    notes_path = directory / 'release-notes.md'
    notes = notes_path.read_text(encoding='utf-8')
    replacements = {
        '{{deb}}': deb.name,
        '{{deb_sha256}}': deb_hash,
        '{{linux_archive}}': archive.name,
        '{{linux_archive_sha256}}': archive_hash,
        '{{macos_pkg}}': macos.name,
        '{{macos_pkg_sha256}}': macos_hash,
    }
    for placeholder, value in replacements.items():
        if placeholder not in notes:
            raise ValueError(f'Missing placeholder {placeholder} in {notes_path}.')
        notes = notes.replace(placeholder, value)

    leftover = sorted(set(re.findall(r'\{\{[^{}]+\}\}', notes)))
    if leftover:
        raise ValueError(f'Unexpanded placeholders in {notes_path}: {", ".join(leftover)}')
    notes_path.write_text(notes, encoding='utf-8', newline='\n')

    return {
        'version': version,
        'prerelease': prerelease,
        'setup': setup.as_posix(),
        'deb': deb.as_posix(),
        'archive': archive.as_posix(),
        'macos': macos.as_posix(),
        'sing_box_source': sing_box_source.as_posix(),
        'xray_source': xray_source.as_posix(),
        'sums': sums_path.as_posix(),
        'notes': notes_path.as_posix(),
    }


def write_github_outputs(outputs: dict[str, str], output_file: Path | None) -> None:
    if output_file is None:
        return
    with output_file.open('a', encoding='utf-8', newline='\n') as handle:
        for key, value in outputs.items():
            handle.write(f'{key}={value}\n')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest='command', required=True)

    check = subparsers.add_parser('check-tag', help='Validate release tag rules and availability')
    check.add_argument('--tag', required=True)
    check.add_argument('--sha', required=True)
    check.add_argument('--manifest', type=Path, default=Path('Cargo.toml'))

    assemble = subparsers.add_parser('assemble', help='Assemble release checksums and notes')
    assemble.add_argument('--dir', type=Path, required=True)
    assemble.add_argument('--manifest', type=Path, default=Path('Cargo.toml'))

    args = parser.parse_args(argv)
    github_output = Path(os.environ['GITHUB_OUTPUT']) if os.environ.get('GITHUB_OUTPUT') else None

    if args.command == 'check-tag':
        version = read_workspace_version(args.manifest)
        validate_tag_rules(
            tag=args.tag,
            version=version,
            on_master=git_is_ancestor(args.sha, 'origin/master'),
            on_dev=git_is_ancestor(args.sha, 'origin/dev'),
            master_version=read_git_manifest_version('origin/master'),
            existing_tags=list_existing_release_tags(),
        )
        print(f'Tag {args.tag} is valid for Rosetun {version}.')
        return 0

    outputs = assemble_release(args.dir, args.manifest)
    write_github_outputs(outputs, github_output)
    for key, value in outputs.items():
        print(f'{key}={value}')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(f'assemble.py: {error}', file=sys.stderr)
        raise SystemExit(1)
