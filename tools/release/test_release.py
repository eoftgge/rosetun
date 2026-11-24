"""Unit tests for tools/release/assemble.py."""

import hashlib
from pathlib import Path
import tempfile
import unittest

from assemble import (
    assemble_release,
    is_next_minor_prerelease,
    read_workspace_version,
    validate_tag_rules,
)


class ReleaseAssemblyTests(unittest.TestCase):
    def test_workspace_version_reads_stable_and_prerelease(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / 'Cargo.toml'
            manifest.write_text('[workspace.package]\nversion = "0.7.0-beta.1"\n', encoding='utf-8')
            self.assertEqual(read_workspace_version(manifest), '0.7.0-beta.1')
            manifest.write_text('[workspace.package]\nversion = "0.7.0"\n', encoding='utf-8')
            self.assertEqual(read_workspace_version(manifest), '0.7.0')
            manifest.write_text('[workspace.package]\nversion = "bad"\n', encoding='utf-8')
            with self.assertRaises(ValueError):
                read_workspace_version(manifest)

    def test_tag_validation_enforces_branch_and_uniqueness_rules(self):
        self.assertTrue(is_next_minor_prerelease('0.6.1', '0.7.0-beta.1'))
        self.assertTrue(is_next_minor_prerelease('0.6.1', '1.0.0-alpha.1'))
        self.assertFalse(is_next_minor_prerelease('0.6.1', '0.6.2-beta.1'))
        self.assertFalse(is_next_minor_prerelease('0.6.1', '0.7.0'))

        # Stable tag on master passes.
        validate_tag_rules(
            tag='v0.7.0',
            version='0.7.0',
            on_master=True,
            on_dev=False,
            master_version='0.6.0',
            existing_tags=['v0.6.0'],
        )
        # Next-minor beta on dev passes.
        validate_tag_rules(
            tag='v0.7.0-beta.1',
            version='0.7.0-beta.1',
            on_master=False,
            on_dev=True,
            master_version='0.6.0',
            existing_tags=['v0.6.0'],
        )
        # Stable tag on dev only fails.
        with self.assertRaisesRegex(ValueError, 'master'):
            validate_tag_rules(
                tag='v0.7.0',
                version='0.7.0',
                on_master=False,
                on_dev=True,
                master_version='0.6.0',
                existing_tags=[],
            )
        # Existing tag (including draft) fails.
        with self.assertRaisesRegex(ValueError, 'already exists'):
            validate_tag_rules(
                tag='v0.7.0',
                version='0.7.0',
                on_master=True,
                on_dev=True,
                master_version='0.7.0',
                existing_tags=['v0.7.0'],
            )
        # Mismatched tag fails.
        with self.assertRaisesRegex(ValueError, 'does not match'):
            validate_tag_rules(
                tag='v0.7.1',
                version='0.7.0',
                on_master=True,
                on_dev=True,
                master_version='0.6.0',
                existing_tags=[],
            )

    def test_assemble_renames_tilde_deb_appends_hashes_and_fills_notes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / 'Cargo.toml'
            manifest.write_text('[workspace.package]\nversion = "0.7.0-beta.1"\n', encoding='utf-8')
            assets = root / 'installer'
            assets.mkdir()

            files = {
                'rosetun-0.7.0-beta.1-setup.exe': b'win-setup',
                'rosetun_0.7.0~beta.1_amd64.deb': b'debian-pkg',
                'rosetun-0.7.0-beta.1-linux-amd64.tar.gz': b'linux-tar',
                'rosetun-0.7.0-beta.1-macos-arm64-experimental.pkg': b'macos-pkg',
                'sing-box-1.14.3-source.tar.gz': b'sing-box-src',
                'xray-26.11.9-source.tar.gz': b'xray-src',
            }
            for name, payload in files.items():
                (assets / name).write_bytes(payload)

            setup_hash = hashlib.sha256(b'win-setup').hexdigest()
            (assets / 'SHA256SUMS.txt').write_text(
                f'{setup_hash}  rosetun-0.7.0-beta.1-setup.exe\n',
                encoding='utf-8',
            )
            (assets / 'release-notes.md').write_text(
                'deb={{deb}} {{deb_sha256}}\n'
                'linux={{linux_archive}} {{linux_archive_sha256}}\n'
                'macos={{macos_pkg}} {{macos_pkg_sha256}}\n',
                encoding='utf-8',
            )

            outputs = assemble_release(assets, manifest)
            self.assertEqual(outputs['version'], '0.7.0-beta.1')
            self.assertEqual(outputs['prerelease'], 'true')
            self.assertTrue(outputs['deb'].endswith('rosetun_0.7.0-beta.1_amd64.deb'))
            self.assertFalse((assets / 'rosetun_0.7.0~beta.1_amd64.deb').exists())
            self.assertTrue((assets / 'rosetun_0.7.0-beta.1_amd64.deb').exists())

            deb_hash = hashlib.sha256(b'debian-pkg').hexdigest()
            linux_hash = hashlib.sha256(b'linux-tar').hexdigest()
            macos_hash = hashlib.sha256(b'macos-pkg').hexdigest()

            sums = (assets / 'SHA256SUMS.txt').read_text(encoding='utf-8')
            self.assertIn(f'{deb_hash}  rosetun_0.7.0-beta.1_amd64.deb\n', sums)
            self.assertIn(f'{linux_hash}  rosetun-0.7.0-beta.1-linux-amd64.tar.gz\n', sums)
            self.assertIn(f'{macos_hash}  rosetun-0.7.0-beta.1-macos-arm64-experimental.pkg\n', sums)

            notes = (assets / 'release-notes.md').read_text(encoding='utf-8')
            self.assertIn(f'deb=rosetun_0.7.0-beta.1_amd64.deb {deb_hash}', notes)
            self.assertIn(f'linux=rosetun-0.7.0-beta.1-linux-amd64.tar.gz {linux_hash}', notes)
            self.assertIn(f'macos=rosetun-0.7.0-beta.1-macos-arm64-experimental.pkg {macos_hash}', notes)

    def test_assemble_rejects_unexpanded_placeholders(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / 'Cargo.toml'
            manifest.write_text('[workspace.package]\nversion = "0.7.0"\n', encoding='utf-8')
            assets = root / 'installer'
            assets.mkdir()
            for name in (
                'rosetun-0.7.0-setup.exe',
                'rosetun_0.7.0_amd64.deb',
                'rosetun-0.7.0-linux-amd64.tar.gz',
                'rosetun-0.7.0-macos-arm64-experimental.pkg',
                'sing-box-1.14.3-source.tar.gz',
                'xray-26.11.9-source.tar.gz',
            ):
                (assets / name).write_bytes(b'x')
            (assets / 'SHA256SUMS.txt').write_text('', encoding='utf-8')
            (assets / 'release-notes.md').write_text(
                '{{deb}} {{deb_sha256}} {{linux_archive}} {{linux_archive_sha256}} '
                '{{macos_pkg}} {{macos_pkg_sha256}} {{forgotten}}',
                encoding='utf-8',
            )
            with self.assertRaisesRegex(ValueError, 'forgotten'):
                assemble_release(assets, manifest)

    def test_real_release_notes_template_has_no_unhandled_placeholders(self):
        repo_root = Path(__file__).resolve().parents[2]
        template = (repo_root / 'installer' / 'release-notes.md').read_text(encoding='utf-8')
        # Simulate the substitutions performed by installer/windows/build.ps1 -Release.
        simulated = (
            template.replace('{{version}}', '0.7.0')
            .replace('{{setup}}', 'rosetun-0.7.0-setup.exe')
            .replace('{{sha256}}', '0' * 64)
            .replace('{{sing_box_version}}', '1.14.3')
            .replace('{{xray_version}}', '26.11.9')
            .replace('{{wintun_version}}', '0.14.1')
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / 'Cargo.toml'
            manifest.write_text('[workspace.package]\nversion = "0.7.0"\n', encoding='utf-8')
            assets = root / 'installer'
            assets.mkdir()
            for name in (
                'rosetun-0.7.0-setup.exe',
                'rosetun_0.7.0_amd64.deb',
                'rosetun-0.7.0-linux-amd64.tar.gz',
                'rosetun-0.7.0-macos-arm64-experimental.pkg',
                'sing-box-1.14.3-source.tar.gz',
                'xray-26.11.9-source.tar.gz',
            ):
                (assets / name).write_bytes(b'payload')
            (assets / 'SHA256SUMS.txt').write_text(f'{"0" * 64}  rosetun-0.7.0-setup.exe\n', encoding='utf-8')
            (assets / 'release-notes.md').write_text(simulated, encoding='utf-8')

            outputs = assemble_release(assets, manifest)
            self.assertEqual(outputs['version'], '0.7.0')
            self.assertEqual(outputs['prerelease'], 'false')
            final_notes = (assets / 'release-notes.md').read_text(encoding='utf-8')
            self.assertNotIn('{{', final_notes)
            self.assertIn('rosetun-0.7.0-macos-arm64-experimental.pkg', final_notes)


if __name__ == '__main__':
    unittest.main()
