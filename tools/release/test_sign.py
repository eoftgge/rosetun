"""Unit tests for tools/release/sign.py."""

import base64
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from sign import (
    SignError,
    default_public_key,
    sign_release,
    validate_release_metadata,
    validate_version,
    verify_signature_file,
)


def make_minisig(prefix: bytes, trusted_comment: str, *, extra_comment: str | None = None) -> str:
    payload = base64.b64encode(prefix + b'\x00' * 72).decode('ascii')
    global_sig = base64.b64encode(b'\x01' * 64).decode('ascii')
    lines = [
        'untrusted comment: signature from minisign secret key',
        payload,
        f'trusted comment: {trusted_comment}',
    ]
    if extra_comment is not None:
        lines.append(extra_comment)
    lines.append(global_sig)
    return '\n'.join(lines) + '\n'


class ReleaseSigningTests(unittest.TestCase):
    def test_default_public_key_exists_in_repo(self):
        key_path = default_public_key()
        self.assertTrue(key_path.is_file())
        self.assertEqual(key_path.name, 'minisign.pub')

    def test_validate_version_accepts_semver_and_rejects_v_prefix(self):
        self.assertEqual(validate_version('0.7.0'), '0.7.0')
        self.assertEqual(validate_version('0.7.0-beta.2'), '0.7.0-beta.2')
        self.assertEqual(validate_version('1.2.3+build.1'), '1.2.3+build.1')

        for invalid in ('v0.7.0', '0.7', '0.7.0 beta', '', 'not-a-version'):
            with self.assertRaises(SignError):
                validate_version(invalid)

    def test_validate_release_metadata_requires_matching_draft(self):
        validate_release_metadata({'tagName': 'v0.7.0', 'isDraft': True}, 'v0.7.0')

        with self.assertRaisesRegex(SignError, 'already published'):
            validate_release_metadata({'tagName': 'v0.7.0', 'isDraft': False}, 'v0.7.0')

        with self.assertRaisesRegex(SignError, 'instead of v0.7.0'):
            validate_release_metadata({'tagName': 'v0.6.0', 'isDraft': True}, 'v0.7.0')

        with self.assertRaises(SignError):
            validate_release_metadata(['not', 'a', 'dict'], 'v0.7.0')

    def test_verify_signature_file_enforces_prehashed_ed_and_trusted_comment(self):
        with tempfile.TemporaryDirectory() as directory:
            sig = Path(directory) / 'SHA256SUMS.txt.minisig'

            sig.write_text(make_minisig(b'ED', 'rosetun 0.7.0'), encoding='utf-8')
            verify_signature_file(sig, 'rosetun 0.7.0')

            # Reject legacy (Ed) signatures.
            sig.write_text(make_minisig(b'Ed', 'rosetun 0.7.0'), encoding='utf-8')
            with self.assertRaisesRegex(SignError, 'prehashed'):
                verify_signature_file(sig, 'rosetun 0.7.0')

            # Reject mismatched trusted comment.
            sig.write_text(make_minisig(b'ED', 'rosetun 0.6.0'), encoding='utf-8')
            with self.assertRaisesRegex(SignError, 'trusted comment'):
                verify_signature_file(sig, 'rosetun 0.7.0')

            # Reject duplicate trusted comment lines.
            sig.write_text(
                make_minisig(b'ED', 'rosetun 0.7.0', extra_comment='trusted comment: rosetun 0.7.0'),
                encoding='utf-8',
            )
            with self.assertRaisesRegex(SignError, 'trusted comment'):
                verify_signature_file(sig, 'rosetun 0.7.0')

            # Reject incomplete files and invalid base64.
            sig.write_text('untrusted comment: short\n', encoding='utf-8')
            with self.assertRaisesRegex(SignError, 'incomplete'):
                verify_signature_file(sig, 'rosetun 0.7.0')

            sig.write_text('untrusted comment: x\n!!!not-base64!!!\ntrusted comment: rosetun 0.7.0\nsig\n', encoding='utf-8')
            with self.assertRaisesRegex(SignError, 'base64'):
                verify_signature_file(sig, 'rosetun 0.7.0')

    def test_sign_release_draft_and_publish_flows(self):
        for publish in (False, True):
            with self.subTest(publish=publish), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                secret_key = root / 'dummy.key'
                secret_key.write_text('do-not-read', encoding='utf-8')
                public_key = root / 'dummy.pub'
                public_key.write_text('public', encoding='utf-8')

                recorded: list[tuple[list[str], dict[str, object]]] = []
                seen_work_dirs: list[Path] = []

                def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                    recorded.append((args, kwargs))
                    if args[1:3] == ['release', 'view']:
                        return subprocess.CompletedProcess(
                            args, 0, stdout=json.dumps({'tagName': 'v0.7.0', 'isDraft': True})
                        )
                    if args[1:3] == ['release', 'download']:
                        work_dir = Path(args[args.index('--dir') + 1])
                        seen_work_dirs.append(work_dir)
                        (work_dir / 'SHA256SUMS.txt').write_text('0' * 64 + '  asset\n', encoding='utf-8')
                        return subprocess.CompletedProcess(args, 0, stdout='')
                    if args[0] == '/usr/bin/minisign' and '-S' in args:
                        # Signing must run interactively without capturing stdout.
                        self.assertNotIn('stdout', kwargs)
                        sums = Path(args[args.index('-m') + 1])
                        comment = args[args.index('-t') + 1]
                        (sums.parent / f'{sums.name}.minisig').write_text(
                            make_minisig(b'ED', comment),
                            encoding='utf-8',
                        )
                        return subprocess.CompletedProcess(args, 0, stdout='')
                    return subprocess.CompletedProcess(args, 0, stdout='')

                stdout_capture = io.StringIO()
                with patch('sys.stdout', stdout_capture):
                    sign_release(
                        version='0.7.0',
                        secret_key=secret_key,
                        repository='owner/repo',
                        public_key=public_key,
                        publish=publish,
                        which=lambda name: f'/usr/bin/{name}',
                        run=fake_run,
                    )

                commands = [args for args, _ in recorded]
                self.assertEqual(commands[0][:4], ['/usr/bin/gh', 'release', 'view', 'v0.7.0'])
                self.assertEqual(commands[1][:4], ['/usr/bin/gh', 'release', 'download', 'v0.7.0'])
                self.assertEqual(commands[2][:4], ['/usr/bin/minisign', '-S', '-H', '-s'])
                self.assertEqual(commands[2][4], str(secret_key.resolve()))
                self.assertEqual(commands[3][:4], ['/usr/bin/minisign', '-V', '-p', str(public_key.resolve())])
                self.assertEqual(commands[4][:4], ['/usr/bin/gh', 'release', 'upload', 'v0.7.0'])
                self.assertIn('--clobber', commands[4])

                if publish:
                    self.assertEqual(len(commands), 6)
                    self.assertEqual(
                        commands[5],
                        ['/usr/bin/gh', 'release', 'edit', 'v0.7.0', '--draft=false', '--repo', 'owner/repo'],
                    )
                else:
                    self.assertEqual(len(commands), 5)
                    self.assertIn('--publish', stdout_capture.getvalue())

                # Temporary working directory must be cleaned up.
                self.assertEqual(len(seen_work_dirs), 1)
                self.assertFalse(seen_work_dirs[0].exists())

    def test_sign_release_cleans_up_tempdir_and_stops_on_legacy_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret_key = root / 'dummy.key'
            secret_key.write_text('do-not-read', encoding='utf-8')
            public_key = root / 'dummy.pub'
            public_key.write_text('public', encoding='utf-8')

            seen_work_dirs: list[Path] = []
            uploaded = False

            def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                nonlocal uploaded
                if args[1:3] == ['release', 'view']:
                    return subprocess.CompletedProcess(
                        args, 0, stdout=json.dumps({'tagName': 'v0.7.0', 'isDraft': True})
                    )
                if args[1:3] == ['release', 'download']:
                    work_dir = Path(args[args.index('--dir') + 1])
                    seen_work_dirs.append(work_dir)
                    (work_dir / 'SHA256SUMS.txt').write_text('0' * 64 + '  asset\n', encoding='utf-8')
                    return subprocess.CompletedProcess(args, 0, stdout='')
                if args[0] == '/usr/bin/minisign' and '-S' in args:
                    sums = Path(args[args.index('-m') + 1])
                    (sums.parent / f'{sums.name}.minisig').write_text(
                        make_minisig(b'Ed', 'rosetun 0.7.0'),
                        encoding='utf-8',
                    )
                    return subprocess.CompletedProcess(args, 0, stdout='')
                if args[1:3] == ['release', 'upload']:
                    uploaded = True
                return subprocess.CompletedProcess(args, 0, stdout='')

            with patch('sys.stdout', io.StringIO()), self.assertRaisesRegex(SignError, 'prehashed'):
                sign_release(
                    version='0.7.0',
                    secret_key=secret_key,
                    public_key=public_key,
                    which=lambda name: f'/usr/bin/{name}',
                    run=fake_run,
                )

            self.assertFalse(uploaded)
            self.assertEqual(len(seen_work_dirs), 1)
            self.assertFalse(seen_work_dirs[0].exists())

    def test_sign_release_checks_keys_and_tools_before_running(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret_key = root / 'dummy.key'
            secret_key.write_text('x', encoding='utf-8')
            public_key = root / 'dummy.pub'
            public_key.write_text('x', encoding='utf-8')

            with self.assertRaisesRegex(SignError, 'secret key'):
                sign_release(version='0.7.0', secret_key=root / 'missing.key', public_key=public_key)

            with self.assertRaisesRegex(SignError, 'public key'):
                sign_release(version='0.7.0', secret_key=secret_key, public_key=root / 'missing.pub')

            with self.assertRaisesRegex(SignError, "'minisign' was not found"):
                sign_release(
                    version='0.7.0',
                    secret_key=secret_key,
                    public_key=public_key,
                    which=lambda name: '/usr/bin/gh' if name == 'gh' else None,
                )


if __name__ == '__main__':
    unittest.main()
