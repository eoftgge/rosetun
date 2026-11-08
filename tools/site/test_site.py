"""Regression checks for release validation and the offline site gate."""

from contextlib import redirect_stdout
import copy
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import call, patch

from check import check
from release import API, RELEASES, preview_values, published_values, render, replacements, workspace_version


class SiteChecks(unittest.TestCase):
    def test_cargo_version_updates_both_languages_without_editing_pages(self):
        for version in ('2.7.19', '3.12.4'):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                manifest = Path(directory) / 'Cargo.toml'
                manifest.write_text(f'[workspace.package]\nversion = "{version}"\n', encoding='utf-8')
                names = (f'rosetun-{version}-setup.exe', f'rosetun_{version}_amd64.deb', 'SHA256SUMS.txt')
                release = dict(tag_name=f'v{version}', draft=False, prerelease=False, assets=[
                    dict(name=name, browser_download_url=f'{RELEASES}v{version}/{name}') for name in names
                ])
                sums = '\n'.join('a' * 64 + '  ' + name for name in names[:2])
                with patch('release.fetch', side_effect=[json.dumps(release).encode(), sums.encode()]) as fetch:
                    values = published_values(manifest)
                self.assertEqual(fetch.call_args_list, [
                    call(f'{API}/releases/tags/v{version}', api=True),
                    call(f'{RELEASES}v{version}/SHA256SUMS.txt'),
                ])
                output = Path(directory) / 'site'
                render(Path('site'), output, values)
                with redirect_stdout(io.StringIO()):
                    check(output, rendered=True)
                for lang in ('en', 'ru'):
                    for page in (output / lang).rglob('*.html'):
                        source = Path('site') / page.relative_to(output)
                        text = page.read_text(encoding='utf-8')
                        if '<!-- docs-version -->' in source.read_text(encoding='utf-8'):
                            self.assertIn(f'{version} · Windows', text)
                        self.assertNotIn('0.5.1', text)
                        self.assertNotIn('data-release-', text)
                        self.assertNotIn('@@', text)
                    install = (output / lang / 'docs/install/index.html').read_text(encoding='utf-8')
                    for command in (
                        f'sudo apt install ./rosetun_{version}_amd64.deb',
                        f'git clone --branch v{version} https://github.com/eoftgge/rosetun.git',
                        f'bash tools/arch/update-pkgbuild.sh v{version}',
                        f'Get-FileHash .\\rosetun-{version}-setup.exe -Algorithm SHA256',
                        f'gh attestation verify .\\rosetun-{version}-setup.exe',
                        f'gh attestation verify rosetun_{version}_amd64.deb',
                    ):
                        self.assertIn(command, install)
                    for name in names[:2]:
                        self.assertIn(f'href="{RELEASES}v{version}/{name}"', install)
                    history = (output / lang / 'docs/index.html').read_text(encoding='utf-8')
                    self.assertIn('blob/v0.4.0/', history)

    def test_workspace_publication_rejects_previews_and_a_different_release(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / 'Cargo.toml'
            manifest.write_text('[workspace.package]\nversion = "2.7.19-beta.1"\n', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'stable workspace version'):
                workspace_version(manifest)
            manifest.write_text('[workspace.package]\nversion = "2.7.19"\n', encoding='utf-8')
            with patch('release.fetch', return_value=json.dumps(self.release).encode()) as fetch:
                with self.assertRaisesRegex(ValueError, 'does not match'):
                    published_values(manifest)
                self.assertEqual(fetch.call_count, 1)

    def test_a_page_can_use_one_marker_but_unknown_markers_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source'
            source.mkdir()
            page = source / 'index.html'
            page.write_text('<code data-release-text="@@VERSION@@">release</code>', encoding='utf-8')
            output = Path(directory) / 'valid'
            render(source, output, preview_values('2.7.19', False))
            self.assertEqual((output / 'index.html').read_text(encoding='utf-8'), '<code>2.7.19</code>')
            page.write_text('@@VERSOIN@@', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'unknown release markers'):
                render(source, Path(directory) / 'invalid', preview_values('2.7.19', False))

    def test_install_commands_do_not_advertise_a_missing_debian_package(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'site'
            render(Path('site'), output, preview_values('2.7.19', False))
            for lang in ('en', 'ru'):
                page = (output / lang / 'docs/install/index.html').read_text(encoding='utf-8')
                self.assertNotIn('sudo apt install ./', page)
                self.assertNotIn('gh attestation verify rosetun_', page)
                self.assertNotIn('rosetun_2.7.19_amd64.deb', page)

    def setUp(self):
        self.release = dict(tag_name='v1.2.3', draft=False, prerelease=False, assets=[
            dict(name=name, browser_download_url=f'{RELEASES}v1.2.3/{name}')
            for name in ('rosetun-1.2.3-setup.exe', 'SHA256SUMS.txt')
        ])
        self.sums = 'a' * 64 + '  rosetun-1.2.3-setup.exe\n'

    def test_release_rejects_unpublished_preliminary_and_incomplete_assets(self):
        for change in ({'draft': True}, {'prerelease': True}, {'tag_name': 'v1.2.3-beta.1'}, {'assets': []}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                replacements(self.release | change, self.sums)
        changed = copy.deepcopy(self.release)
        changed['assets'][0]['browser_download_url'] = 'https://example.com/setup.exe'
        with self.assertRaises(ValueError):
            replacements(changed, self.sums)

    def test_checksum_must_match_exactly_once(self):
        for sums in ('', self.sums * 2, self.sums.replace('1.2.3', '1.2.4'), 'bad  rosetun-1.2.3-setup.exe'):
            with self.subTest(sums=sums), self.assertRaises(ValueError):
                replacements(self.release, sums)
        binary = self.sums.replace('  rosetun', ' *rosetun')
        self.assertEqual(replacements(self.release, binary)['SHA256_LINE'], binary.strip())

    def rendered_front_page(self, release, sums):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'site'
            render(Path('site'), output, replacements(release, sums))
            with redirect_stdout(io.StringIO()):
                check(output, rendered=True)
            return (output / 'en/index.html').read_text(encoding='utf-8')

    def test_linux_falls_back_to_releases_without_a_stable_package(self):
        page = self.rendered_front_page(self.release, self.sums)
        self.assertNotIn('linux-', page)
        self.assertNotIn('.deb', page)

    def test_a_stable_release_with_a_package_links_it(self):
        name = 'rosetun_1.2.3_amd64.deb'
        release = copy.deepcopy(self.release)
        release['assets'].append(dict(name=name, browser_download_url=f'{RELEASES}v1.2.3/{name}'))
        with self.assertRaises(ValueError):
            replacements(release, self.sums)
        page = self.rendered_front_page(release, self.sums + 'b' * 64 + f'  {name}\n')
        self.assertNotIn('linux-', page)

    def test_rendered_site_passes_and_gate_rejects_bad_links_and_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'site'
            render(Path('site'), output, replacements(self.release, self.sums))
            with redirect_stdout(io.StringIO()):
                check(output, rendered=True)
            page = output / 'en/index.html'
            original = page.read_text(encoding='utf-8')
            self.assertNotIn('data-release-', original)
            self.assertIn(f'href="{RELEASES}v1.2.3/rosetun-1.2.3-setup.exe"', original)
            self.assertIn('<span>Version 1.2.3</span>', original)
            self.assertIn('Get-FileHash .\\rosetun-1.2.3-setup.exe', original)
            for extra in (
                '<a href="missing/">Missing</a>',
                '<a href="#missing">Missing</a>',
                '<img src="https://example.com/image.png" alt="">',
                '<link rel="preconnect" href="https://example.com">',
                '<a href="/en/">Root path</a>',
            ):
                page.write_text(original + extra, encoding='utf-8')
                with self.subTest(extra=extra), self.assertRaises(AssertionError):
                    check(output, rendered=True)
            page.write_text(original, encoding='utf-8')
            css = output / 'assets/site.css'
            original_css = css.read_text(encoding='utf-8')
            css.write_text(original_css + 'body{background:url(https://example.com/image.png)}', encoding='utf-8')
            with self.assertRaises(AssertionError):
                check(output, rendered=True)

            css.write_text(original_css, encoding='utf-8')
            svg = output / 'assets/rose.svg'
            original_svg = svg.read_text(encoding='utf-8')
            svg.write_text(original_svg.replace('</svg>', '<image href="https://example.com/image.png"/></svg>'), encoding='utf-8')
            with self.assertRaises(AssertionError):
                check(output, rendered=True)
            svg.write_text(original_svg, encoding='utf-8')
            page.unlink()
            with self.assertRaises(AssertionError):
                check(output, rendered=True)

    def test_documentation_banner_tracks_the_stable_version_and_keeps_the_baseline(self):
        for version, preview in (('0.4.0', True), ('0.5.0', False)):
            release = copy.deepcopy(self.release)
            release['tag_name'] = 'v' + version
            for asset in release['assets']:
                asset['name'] = asset['name'].replace('1.2.3', version)
                asset['browser_download_url'] = asset['browser_download_url'].replace('1.2.3', version)
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'site'
                render(Path('site'), output, replacements(release, self.sums.replace('1.2.3', version)))
                for lang, warning in (('en', '0.5 is not stable yet'), ('ru', 'стабильная 0.5 ещё не вышла')):
                    page = (output / lang / 'docs/index.html').read_text(encoding='utf-8')
                    self.assertNotIn(warning, page)
                    self.assertIn(f'{version} · Windows', page)
                    if preview:
                        self.assertIn('Documentation: 0.5' if lang == 'en' else 'Документация: 0.5', page)
                    self.assertNotIn('docs-version', page)
                    self.assertIn(f'blob/v0.4.0/README{".ru" if lang == "ru" else ""}.md', page)
                    if not preview:
                        self.assertNotIn("0.4 reference</a>.</p>", page)

    def test_documentation_rejects_broken_navigation(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'site'
            render(Path('site'), output, replacements(self.release, self.sums))
            page = output / 'en/docs/install/index.html'
            original = page.read_text(encoding='utf-8')
            for old, new in (
                ('rel="next"', 'rel="other"'),
                ('../../../ru/docs/install/', '../../../ru/docs/rules/'),
                ('aria-label="On this page"', 'aria-label="Other"'),
                ('../../../assets/rose.svg', 'https://example.com/rose.svg'),
            ):
                with self.subTest(old=old):
                    page.write_text(original.replace(old, new), encoding='utf-8')
                    with self.assertRaises(AssertionError):
                        check(output, rendered=True)

    def test_stable_05_preview_switches_every_documentation_banner_and_linux_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'site'
            render(Path('site'), output, preview_values('0.5.0', True))
            with redirect_stdout(io.StringIO()):
                check(output, rendered=True)
            for lang in ('en', 'ru'):
                for page in (output / lang / 'docs').rglob('*.html'):
                    text = page.read_text(encoding='utf-8')
                    self.assertIn('0.5.0 · Windows', text)
                    self.assertNotIn('0.5 is not stable yet', text)
                    self.assertNotIn('стабильная 0.5 ещё не вышла', text)
                    self.assertNotIn('<!-- linux-', text)
                    if page.parent != output / lang / 'docs':
                        self.assertNotIn('blob/v0.4.0/', text)

    def test_headers_reject_missing_or_reordered_navigation_items(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'site'
            render(Path('site'), output, preview_values('0.5.0', True))
            for lang in ('en', 'ru'):
                for suffix in ('providers/index.html', 'docs/rules/index.html'):
                    page = output / lang / suffix
                    original = page.read_text(encoding='utf-8')
                    nav = re.search(r'<nav aria-label="(?:Navigation|Навигация)">.*?</nav>',
                                    original, re.DOTALL)[0]
                    links = re.findall(r'<a\b.*?</a>', nav, re.DOTALL)
                    swapped = (nav.replace(links[2], 'SWAPPED_SECTION')
                               .replace(links[3], links[2]).replace('SWAPPED_SECTION', links[3]))
                    for changed in (swapped, nav.replace(links[0], '')):
                        with self.subTest(lang=lang, page=suffix, navigation=changed):
                            page.write_text(original.replace(nav, changed), encoding='utf-8')
                            with self.assertRaisesRegex(AssertionError, 'inconsistent header'):
                                check(output, rendered=True)
                    page.write_text(original, encoding='utf-8')


if __name__ == '__main__':
    unittest.main()
