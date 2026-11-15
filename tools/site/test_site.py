"""Regression checks for release data, the Zola build and the offline site gate.

The build tests need the pinned Zola: `python tools/site/install_zola.py` puts it in `target/zola`.
"""

from contextlib import redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import call, patch

from check import check
from release import API, RELEASES, banner, preview_values, published_values, replacements, workspace_version, write

ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / 'site'


def zola():
    """The Zola executable: $ZOLA, the one on PATH or the one install_zola.py put in target/zola."""
    if os.environ.get('ZOLA'):
        return os.environ['ZOLA']
    found = shutil.which('zola') or next(
        (str(path) for path in (ROOT / 'target/zola').glob('zola*') if path.suffix in ('', '.exe')), None)
    return found


def build(directory, values=None):
    """Builds a copy of the site, with release data when given, and returns the output directory."""
    source = Path(directory) / 'source'
    shutil.copytree(SITE, source, ignore=shutil.ignore_patterns('release.json'))
    if values is not None:
        write(source / 'data/release.json', values)
    output = Path(directory) / 'output'
    subprocess.run([zola(), '--root', str(source), 'build', '--output-dir', str(output)],
                   check=True, capture_output=True, text=True)
    return output


def pages(output, prefix):
    """The pages of one language: English in `en/`, Russian in the root without `en/` and the redirects."""
    if prefix:
        return list((output / prefix).rglob('index.html'))
    return [page for page in output.rglob('index.html') if page.relative_to(output).parts[0] not in {'en', 'ru'}]


def quiet_check(output, rendered=False):
    with redirect_stdout(io.StringIO()):
        check(output, rendered=rendered)


def read(output, relative):
    return (output / relative).read_text(encoding='utf-8')


class ReleaseData(unittest.TestCase):
    def setUp(self):
        self.release = dict(tag_name='v1.2.3', draft=False, prerelease=False, assets=[
            dict(name=name, browser_download_url=f'{RELEASES}v1.2.3/{name}')
            for name in ('rosetun-1.2.3-setup.exe', 'SHA256SUMS.txt')
        ])
        self.sums = 'a' * 64 + '  rosetun-1.2.3-setup.exe\n'

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
        self.assertEqual(replacements(self.release, binary)['sha256_line'], binary.strip())

    def test_a_package_needs_its_own_checksum(self):
        name = 'rosetun_1.2.3_amd64.deb'
        release = copy.deepcopy(self.release)
        release['assets'].append(dict(name=name, browser_download_url=f'{RELEASES}v1.2.3/{name}'))
        with self.assertRaises(ValueError):
            replacements(release, self.sums)
        values = replacements(release, self.sums + 'b' * 64 + f'  {name}\n')
        self.assertEqual(values['deb'], name)
        self.assertEqual(values['deb_url'], f'{RELEASES}v1.2.3/{name}')

    def test_the_data_file_is_complete_and_never_rewrites_a_release(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'data/release.json'
            with self.assertRaisesRegex(ValueError, 'incomplete'):
                write(target, {'version': '1.2.3'})
            write(target, preview_values('2.7.19', True))
            data = json.loads(target.read_text(encoding='utf-8'))
            self.assertEqual(data['version'], '2.7.19')
            self.assertEqual(data['installer'], 'rosetun-2.7.19-setup.exe')

    def test_the_banner_names_the_stable_version_and_its_platforms(self):
        self.assertEqual(banner('0.5.0', True), {'ru': 'Стабильный выпуск: 0.5.0 · Windows и Linux.',
                                                 'en': 'Stable release: 0.5.0 · Windows and Linux.'})
        self.assertEqual(banner('0.5.0', False)['en'], 'Stable release: 0.5.0 · Windows.')
        self.assertEqual(banner('0.4.0', True)['en'], 'Stable release: 0.4.0 · Windows. Documentation: 0.5.')
        self.assertEqual(banner('0.4.0', False)['ru'], 'Стабильный выпуск: 0.4.0 · Windows. Документация: 0.5.')


@unittest.skipUnless(zola(), 'Zola is not installed; run tools/site/install_zola.py')
class SiteBuild(unittest.TestCase):
    def setUp(self):
        self.release = dict(tag_name='v1.2.3', draft=False, prerelease=False, assets=[
            dict(name=name, browser_download_url=f'{RELEASES}v1.2.3/{name}')
            for name in ('rosetun-1.2.3-setup.exe', 'SHA256SUMS.txt')
        ])
        self.sums = 'a' * 64 + '  rosetun-1.2.3-setup.exe\n'
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def built(self, values=None):
        return build(self.directory.name, values if values is not None else replacements(self.release, self.sums))

    def test_the_site_builds_and_passes_without_release_data(self):
        output = build(self.directory.name)
        quiet_check(output)
        with self.assertRaisesRegex(AssertionError, 'release data missing'):
            check(output, rendered=True)
        home = read(output, 'index.html')
        self.assertIn('https://github.com/eoftgge/rosetun/releases/latest', home)
        self.assertIn('Стабильный выпуск: см. загрузки.', home)
        self.assertIn('rosetun-VERSION-setup.exe', home)
        self.assertIn('В этом выпуске нет пакета Debian', read(output, 'docs/install/index.html'))

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
                output = build(directory, values)
                quiet_check(output, rendered=True)
                for prefix in ('en/', ''):
                    for page in pages(output, prefix):
                        text = page.read_text(encoding='utf-8')
                        if page.parent.name != 'providers':
                            self.assertIn(f'{version} · Windows', text)
                        self.assertNotIn('0.5.1', text)
                        self.assertNotIn('data-release-', text)
                        self.assertNotIn('@@', text)
                    install = read(output, f'{prefix}docs/install/index.html')
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
                    self.assertIn('blob/v0.4.0/', read(output, f'{prefix}docs/index.html'))

    def test_install_commands_do_not_advertise_a_missing_debian_package(self):
        output = build(self.directory.name, preview_values('2.7.19', False))
        for prefix in ('en/', ''):
            page = read(output, f'{prefix}docs/install/index.html')
            self.assertNotIn('sudo apt install ./', page)
            self.assertNotIn('gh attestation verify rosetun_', page)
            self.assertNotIn('rosetun_2.7.19_amd64.deb', page)

    def test_linux_falls_back_to_releases_without_a_stable_package(self):
        output = self.built()
        quiet_check(output, rendered=True)
        page = read(output, 'en/index.html')
        self.assertNotIn('linux-', page)
        self.assertNotIn('.deb', page)

    def test_a_stable_release_with_a_package_links_it(self):
        name = 'rosetun_1.2.3_amd64.deb'
        release = copy.deepcopy(self.release)
        release['assets'].append(dict(name=name, browser_download_url=f'{RELEASES}v1.2.3/{name}'))
        output = build(self.directory.name, replacements(release, self.sums + 'b' * 64 + f'  {name}\n'))
        quiet_check(output, rendered=True)
        self.assertNotIn('linux-', read(output, 'en/index.html'))
        self.assertIn(f'href="{RELEASES}v1.2.3/{name}"', read(output, 'en/docs/install/index.html'))

    def test_rendered_site_passes_and_gate_rejects_bad_links_and_resources(self):
        output = self.built()
        quiet_check(output, rendered=True)
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
            '<script>alert(1)</script>',
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

    def test_each_page_checks_its_policy_and_scripts(self):
        output = self.built()
        for relative, old, new in (
            ('en/docs/install/index.html', "default-src 'none';", "default-src 'self';"),
            ('docs/install/index.html', '<main', '<script src="../../assets/script.js"></script><main'),
            ('en/index.html', 'script-src', 'script-src https://example.com'),
        ):
            page = output / relative
            original = page.read_text(encoding='utf-8')
            self.assertIn(old, original)
            page.write_text(original.replace(old, new, 1), encoding='utf-8')
            with self.subTest(relative=relative), self.assertRaises(AssertionError):
                check(output, rendered=True)
            page.write_text(original, encoding='utf-8')

    def test_documentation_banner_tracks_the_stable_version_and_keeps_the_baseline(self):
        for version, preview in (('0.4.0', True), ('0.5.0', False)):
            release = copy.deepcopy(self.release)
            release['tag_name'] = 'v' + version
            for asset in release['assets']:
                asset['name'] = asset['name'].replace('1.2.3', version)
                asset['browser_download_url'] = asset['browser_download_url'].replace('1.2.3', version)
            with tempfile.TemporaryDirectory() as directory:
                output = build(directory, replacements(release, self.sums.replace('1.2.3', version)))
                for lang, warning, prefix in (('en', '0.5 is not stable yet', 'en/'),
                                              ('ru', 'стабильная 0.5 ещё не вышла', '')):
                    page = read(output, f'{prefix}docs/index.html')
                    self.assertNotIn(warning, page)
                    self.assertIn(f'{version} · Windows', page)
                    if preview:
                        self.assertIn('Documentation: 0.5' if lang == 'en' else 'Документация: 0.5', page)
                    self.assertNotIn('docs-version', page)
                    self.assertIn(f'blob/v0.4.0/README{".ru" if lang == "ru" else ""}.md', page)

    def test_documentation_rejects_broken_navigation(self):
        output = self.built()
        page = output / 'en/docs/install/index.html'
        original = page.read_text(encoding='utf-8')
        for old, new in (
            ('rel="next"', 'rel="other"'),
            ('../../../docs/install/', '../../../docs/rules/'),
            ('aria-label="On this page"', 'aria-label="Other"'),
            ('../../../assets/rose.svg', 'https://example.com/rose.svg'),
        ):
            with self.subTest(old=old):
                self.assertIn(old, original)
                page.write_text(original.replace(old, new), encoding='utf-8')
                with self.assertRaises(AssertionError):
                    check(output, rendered=True)

    def test_stable_05_preview_switches_every_documentation_banner_and_linux_copy(self):
        output = build(self.directory.name, preview_values('0.5.0', True))
        quiet_check(output, rendered=True)
        for prefix in ('en/', ''):
            for page in (output / prefix / 'docs').rglob('index.html'):
                text = page.read_text(encoding='utf-8')
                self.assertIn('0.5.0 · Windows', text)
                self.assertNotIn('0.5 is not stable yet', text)
                self.assertNotIn('стабильная 0.5 ещё не вышла', text)
                self.assertNotIn('<!-- linux-', text)
                if page.parent != output / prefix / 'docs':
                    self.assertNotIn('blob/v0.4.0/', text)

    def test_headers_reject_missing_or_reordered_navigation_items(self):
        output = self.built(preview_values('0.5.0', True))
        for prefix in ('en/', ''):
            for suffix in ('providers/index.html', 'docs/rules/index.html'):
                page = output / prefix / suffix
                original = page.read_text(encoding='utf-8')
                nav = re.search(r'<nav aria-label="(?:Navigation|Навигация)">.*?</nav>', original, re.DOTALL)[0]
                links = re.findall(r'<a\b.*?</a>', nav, re.DOTALL)
                swapped = (nav.replace(links[2], 'SWAPPED_SECTION')
                           .replace(links[3], links[2]).replace('SWAPPED_SECTION', links[3]))
                for changed in (swapped, nav.replace(links[0], '')):
                    with self.subTest(prefix=prefix, page=suffix, navigation=changed):
                        page.write_text(original.replace(nav, changed), encoding='utf-8')
                        with self.assertRaisesRegex(AssertionError, 'inconsistent header'):
                            check(output, rendered=True)
                page.write_text(original, encoding='utf-8')

    def test_old_russian_addresses_redirect_to_the_pages_that_replaced_them(self):
        output = self.built()
        for old, new in (('ru/index.html', 'index.html'), ('ru/docs/rules/index.html', 'docs/rules/index.html'),
                         ('ru/docs/index.html', 'docs/index.html'), ('ru/providers/index.html', 'providers/index.html'),
                         ('ru/help/index.html', 'help/index.html')):
            with self.subTest(old=old):
                text = read(output, old)
                depth = len(Path(old).parent.parts)
                self.assertIn(f'url={"../" * depth}{new.removesuffix("index.html")}', text)
        self.assertNotIn('en/', read(output, 'ru/docs/rules/index.html'))
        alias = output / 'ru/docs/rules/index.html'
        original = alias.read_text(encoding='utf-8')
        alias.write_text(original.replace('docs/rules/', 'docs/modes/'), encoding='utf-8')
        with self.assertRaisesRegex(AssertionError, 'redirect leads to'):
            check(output, rendered=True)
        alias.unlink()
        with self.assertRaisesRegex(AssertionError, 'missing redirect'):
            check(output, rendered=True)

    def test_the_404_page_links_to_both_home_pages_and_loads_no_script(self):
        output = self.built()
        page = output / '404.html'
        original = page.read_text(encoding='utf-8')
        self.assertIn('href="/rosetun/"', original)
        self.assertIn('href="/rosetun/en/"', original)
        self.assertNotIn('<script', original)
        for old, new in (
            ('href="/rosetun/en/" hreflang="en">Home', 'href="/rosetun/de/" hreflang="en">Home'),
            ('</head>', '<script src="/rosetun/assets/script.js"></script></head>'),
            ('/rosetun/assets/site.css', 'assets/site.css'),
        ):
            with self.subTest(old=old):
                self.assertIn(old, original)
                page.write_text(original.replace(old, new, 1), encoding='utf-8')
                with self.assertRaises(AssertionError):
                    check(output, rendered=True)
        page.write_text(original, encoding='utf-8')
        quiet_check(output, rendered=True)

    def test_a_link_to_the_own_site_must_be_relative(self):
        output = self.built()
        page = output / 'en/index.html'
        original = page.read_text(encoding='utf-8')
        page.write_text(original + '<a href="https://eoftgge.github.io/rosetun/en/docs/">Docs</a>', encoding='utf-8')
        with self.assertRaisesRegex(AssertionError, 'own site'):
            check(output, rendered=True)

    def test_an_alias_that_is_not_an_old_russian_address_is_refused(self):
        source = Path(self.directory.name) / 'source'
        shutil.copytree(SITE, source, ignore=shutil.ignore_patterns('release.json'))
        help_page = source / 'content/help.md'
        text = help_page.read_text(encoding='utf-8')
        help_page.write_text(text.replace('aliases = ["/ru/help/"]', 'aliases = ["/ru/help/", "/old/help/"]'),
                             encoding='utf-8')
        output = Path(self.directory.name) / 'output'
        subprocess.run([zola(), '--root', str(source), 'build', '--output-dir', str(output)],
                       check=True, capture_output=True, text=True)
        with self.assertRaisesRegex(AssertionError, 'unexpected redirect'):
            check(output)

    def test_a_build_for_another_address_keeps_every_link_relative(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source'
            shutil.copytree(SITE, source, ignore=shutil.ignore_patterns('release.json'))
            output = Path(directory) / 'rosetun'
            subprocess.run([zola(), '--root', str(source), 'build', '--base-url', 'http://localhost:8000/rosetun',
                            '--output-dir', str(output)], check=True, capture_output=True, text=True)
            quiet_check(output)
            for page in output.rglob('*.html'):
                self.assertNotIn('localhost', page.read_text(encoding='utf-8'), page)


if __name__ == '__main__':
    unittest.main()
