"""Regression checks for release validation and the offline site gate."""

from contextlib import redirect_stdout
import copy
import io
from pathlib import Path
import tempfile
import unittest

from check import check
from release import RELEASES, render, replacements


class SiteChecks(unittest.TestCase):
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

    def test_linux_stays_coming_soon_until_the_stable_release_has_a_package(self):
        page = self.rendered_front_page(self.release, self.sums)
        self.assertIn('Linux: coming soon.', page)
        self.assertNotIn('linux-', page)
        self.assertNotIn('.deb', page)

    def test_a_stable_release_with_a_package_links_it(self):
        name = 'rosetun_1.2.3_amd64.deb'
        release = copy.deepcopy(self.release)
        release['assets'].append(dict(name=name, browser_download_url=f'{RELEASES}v1.2.3/{name}'))
        with self.assertRaises(ValueError):
            replacements(release, self.sums)
        page = self.rendered_front_page(release, self.sums + 'b' * 64 + f'  {name}\n')
        self.assertIn(f'href="{RELEASES}v1.2.3/{name}"', page)
        self.assertNotIn('coming soon', page)
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
                '<script>alert(1)</script>',
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

    def test_documentation_preview_banner_tracks_the_stable_version(self):
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
                    self.assertEqual(warning in page, preview)
                    self.assertNotIn('docs-version', page)
                    self.assertIn(f'blob/v0.4.0/README{".ru" if lang == "ru" else ""}.md', page)

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


if __name__ == '__main__':
    unittest.main()
