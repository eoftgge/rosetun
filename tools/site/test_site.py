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


if __name__ == '__main__':
    unittest.main()
