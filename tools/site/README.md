# Static site maintenance

The source is plain HTML and CSS in `site/`. Both languages are edited directly.
Documentation lives in `site/{en,ru}/docs/`, with matching page paths, an on-page
contents list, a visible language switch and previous/next links. Handwritten
HTML shares the existing styles and offline checks without adding a converter
or a build dependency. Edit it directly; the README is only a short entry point.
Keep the release markers in both landing pages; the Pages job fills them at
publication time using the latest stable GitHub release, its installer asset and
the matching line in `SHA256SUMS.txt`. No API calls run in a visitor's browser.
Release markers live in `data-release-href` and `data-release-text` attributes.
The source pages show readable fallback text and link to the latest release;
publication replaces the fallback links and text and removes those attributes.

Run from the repository root:

```sh
python tools/site/check.py site
python -m unittest discover -s tools/site -p 'test_*.py'
python tools/site/release.py --output target/site-preview
python tools/site/check.py target/site-preview --rendered
python -m http.server 8000 --directory target/site-preview
```

The preview output directory must not already exist. Release preparation needs
network access; source validation and tests do not. A missing stable release,
asset or unique checksum stops publication. The checksum is copied, not a claim
that the CI job downloaded and hashed the installer.

For a subdirectory preview, put the prepared copy under a directory named
`rosetun` and serve its parent. Open `/rosetun/`. All local URLs are relative.
Review at 360, 768 and 1280 CSS pixels, in both color schemes, with JavaScript
disabled. Screenshots must use documentation-only data.

The workflow checks `dev` pushes without deploying. Deployment uses `master`
for release events and successful Release workflow completions. The latter is
needed because a release created with `GITHUB_TOKEN` does not trigger another
workflow through `release: published`. A completed preview release can therefore
refresh the site from `master` with the unchanged latest stable download.
Manual deployment must select `master`. The workflow does not enable Pages;
the owner must first choose GitHub Actions in Settings → Pages.

Deployment takes `master`, so copy edited on `dev` reaches visitors when `master`
moves forward. Text that depends on the stable release having a Debian package
sits in `<!-- linux-ready ... -->` and `<!-- linux-soon -->...<!-- /linux-soon -->`
markers: publication keeps one and drops the other.

The latest stable release is the documentation baseline. Until 0.5 is stable,
each documentation page lists its 0.5 additions and links to the immutable 0.4
reference. The guarantee matrix and network inventory explicitly describe the
0.5 preview. `<!-- docs-version -->...<!-- /docs-version -->` wraps the current
stable/preview banner: release preparation replaces it with the actual stable
version from 0.5 onward. Keep the individual "since 0.5" notes as history.

The same source validator runs locally and in Pages. It checks every HTML page,
internal links and fragments, both language counterparts, documentation language
switches and pagers, and local-only resources including CSS and SVG. Source
checks and unit tests require no network or browser. To review unprepared HTML,
serve `site` directly with `python -m http.server 8000 --directory site`.
