#!/usr/bin/env python3
"""Signs SHA256SUMS.txt of a draft GitHub release with minisign and uploads it.

Run this on the owner's machine (Windows or Linux): the secret key is read only
by minisign, which asks for its password on the terminal. This script never
reads, copies, prints, or stores the secret key, and does not publish unless
--publish is passed.

  python3 tools/release/sign.py --version 0.7.0 --secret-key /path/to/rosetun.key

The trusted comment is `rosetun <version>`. The updater refuses a release whose
signature is legacy (`Ed`) or whose trusted comment does not match the release.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from collections.abc import Callable, Sequence
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

DEFAULT_REPOSITORY = 'eoftgge/rosetun'
VERSION_RE = re.compile(r'^\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$')


class SignError(RuntimeError):
    """Raised when release signing preconditions or verification fail."""


def default_public_key() -> Path:
    return Path(__file__).resolve().parents[2] / 'crates' / 'rosetun-core' / 'keys' / 'minisign.pub'


def validate_version(version: str) -> str:
    if not VERSION_RE.fullmatch(version):
        raise SignError(
            f"Version '{version}' is not a version such as 0.7.0 or 0.7.0-beta.1. "
            "Do not add a leading 'v'."
        )
    return version


def require_command(name: str, *, which: Callable[[str], str | None] = shutil.which) -> str:
    resolved = which(name)
    if not resolved:
        raise SignError(f"'{name}' was not found on PATH. Install it and try again.")
    return resolved


def validate_release_metadata(release: object, expected_tag: str) -> None:
    if not isinstance(release, dict):
        raise SignError(f'Unexpected JSON from gh release view for {expected_tag}.')
    tag_name = release.get('tagName')
    if tag_name != expected_tag:
        raise SignError(f"GitHub returned release '{tag_name}' instead of {expected_tag}.")
    if release.get('isDraft') is not True:
        raise SignError(f'Release {expected_tag} is already published. Sign a draft, before it is published.')


def verify_signature_file(signature_path: Path, expected_trusted_comment: str) -> None:
    if not signature_path.is_file():
        raise SignError('minisign did not write a signature file.')

    try:
        lines = signature_path.read_text(encoding='utf-8').splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise SignError(f'Could not read the signature file: {error}') from error

    if len(lines) < 4:
        raise SignError('The signature file is incomplete.')

    try:
        signature_bytes = base64.b64decode(lines[1].strip(), validate=True)
    except (ValueError, binascii.Error) as error:
        raise SignError(f'The signature payload is not valid base64: {error}') from error

    if len(signature_bytes) < 2 or signature_bytes[:2] != b'ED':
        raise SignError('The signature is not prehashed (ED); the updater refuses legacy (Ed) signatures.')

    expected_line = f'trusted comment: {expected_trusted_comment}'
    comments = [line for line in lines if line.startswith('trusted comment:')]
    if len(comments) != 1 or comments[0] != expected_line:
        raise SignError(f"The trusted comment of the signature is not exactly '{expected_line}'.")


def _run_checked(
    args: Sequence[str],
    action: str,
    *,
    run: Callable[..., subprocess.CompletedProcess[str]],
    capture_stdout: bool = False,
) -> str:
    kwargs: dict[str, object] = {'check': False}
    if capture_stdout:
        kwargs['stdout'] = subprocess.PIPE
        kwargs['text'] = True
        kwargs['encoding'] = 'utf-8'
    result = run(list(args), **kwargs)
    if result.returncode != 0:
        raise SignError(f'{action} failed (exit code {result.returncode}).')
    return result.stdout if capture_stdout else ''


def sign_release(
    *,
    version: str,
    secret_key: Path,
    repository: str = DEFAULT_REPOSITORY,
    public_key: Path | None = None,
    publish: bool = False,
    which: Callable[[str], str | None] = shutil.which,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    validate_version(version)

    resolved_public_key = public_key if public_key is not None else default_public_key()
    if not resolved_public_key.is_file():
        raise SignError(f'The public key file was not found: {resolved_public_key}')
    if not secret_key.is_file():
        raise SignError('The secret key file was not found. Pass the path to the minisign secret key with --secret-key.')

    secret_key_path = str(secret_key.resolve())
    public_key_path = str(resolved_public_key.resolve())

    gh = require_command('gh', which=which)
    minisign = require_command('minisign', which=which)

    tag = f'v{version}'
    trusted_comment = f'rosetun {version}'

    release_raw = _run_checked(
        [gh, 'release', 'view', tag, '--repo', repository, '--json', 'isDraft,tagName'],
        f'Looking up release {tag} in {repository}',
        run=run,
        capture_stdout=True,
    )
    try:
        release = json.loads(release_raw)
    except json.JSONDecodeError as error:
        raise SignError(f'Could not parse release metadata for {tag}: {error}') from error
    validate_release_metadata(release, tag)

    with tempfile.TemporaryDirectory(prefix='rosetun-sign-') as work_dir_str:
        work_dir = Path(work_dir_str)
        _run_checked(
            [gh, 'release', 'download', tag, '--repo', repository, '--pattern', 'SHA256SUMS.txt', '--dir', str(work_dir)],
            'Downloading SHA256SUMS.txt',
            run=run,
        )
        sums_path = work_dir / 'SHA256SUMS.txt'
        if not sums_path.is_file():
            raise SignError(f'Release {tag} has no SHA256SUMS.txt.')
        signature_path = work_dir / 'SHA256SUMS.txt.minisig'

        print(f'Signing SHA256SUMS.txt of {tag}. minisign asks for the key password.', flush=True)
        # -H forces a prehashed ("ED") signature on older minisign builds (such as 0.8);
        # the updater verifies with allow_legacy = false and rejects legacy ("Ed") signatures.
        _run_checked(
            [minisign, '-S', '-H', '-s', secret_key_path, '-m', str(sums_path), '-t', trusted_comment],
            'Signing',
            run=run,
        )
        if not signature_path.is_file():
            raise SignError('minisign did not write a signature file.')

        _run_checked(
            [minisign, '-V', '-p', public_key_path, '-m', str(sums_path)],
            'Verifying the signature with the public key',
            run=run,
        )
        verify_signature_file(signature_path, trusted_comment)

        _run_checked(
            [gh, 'release', 'upload', tag, str(signature_path), '--repo', repository, '--clobber'],
            'Uploading SHA256SUMS.txt.minisig',
            run=run,
        )
        print(f'Uploaded SHA256SUMS.txt.minisig to the draft {tag}.')

        if publish:
            _run_checked(
                [gh, 'release', 'edit', tag, '--draft=false', '--repo', repository],
                'Publishing the release',
                run=run,
            )
            print(f'Published {tag}.')
        else:
            print('The release is still a draft. After a final look, publish it:')
            print(f'  gh release edit {tag} --draft=false --repo {repository}')
            print('or run this script again with --publish.')


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Sign SHA256SUMS.txt of a draft GitHub release with minisign and upload the signature.',
    )
    parser.add_argument(
        '--version',
        required=True,
        help='Release version without the leading "v", as in Cargo.toml (e.g. 0.7.0 or 0.7.0-beta.1).',
    )
    parser.add_argument(
        '--secret-key',
        required=True,
        type=Path,
        help='Path to the minisign secret key file.',
    )
    parser.add_argument(
        '--repo',
        default=DEFAULT_REPOSITORY,
        help=f'GitHub repository in owner/name form (default: {DEFAULT_REPOSITORY}).',
    )
    parser.add_argument(
        '--public-key',
        type=Path,
        default=None,
        help='Path to the minisign public key (default: crates/rosetun-core/keys/minisign.pub).',
    )
    parser.add_argument(
        '--publish',
        action='store_true',
        help='Publish the draft release after uploading the verified signature.',
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    sign_release(
        version=args.version,
        secret_key=args.secret_key,
        repository=args.repo,
        public_key=args.public_key,
        publish=args.publish,
    )
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except SignError as error:
        print(f'sign.py: {error}', file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print('sign.py: interrupted.', file=sys.stderr)
        raise SystemExit(130)
