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

Every localized page shares one header and footer. The header order is Home,
Documentation, For providers, Help, then the matching page in the other language.
The current section is marked without moving or removing links. After adding a
page or changing the shared navigation, run `python tools/site/navigation.py --write`.
This updates the committed HTML; publication needs no extra generation step.
The normal site check rejects headers and footers that differ from this template.

The preview output directory must not already exist. Release preparation needs
network access; source validation and tests do not. A missing stable release,
asset or unique checksum stops publication. The checksum is copied, not a claim
that the CI job downloaded and hashed the installer.

Preview the site as it will read after stable 0.5, without network access:

```sh
python tools/site/release.py --preview-version 0.5.0 --preview-deb --output target/site-preview-0.5
python tools/site/check.py target/site-preview-0.5 --rendered
python -m http.server 8000 --directory target/site-preview-0.5
```

This preview uses synthetic checksums; do not publish its output. The Pages job
continues to fetch the actual latest stable release and checksums. From 0.5,
documentation banners name the stable version and its available platforms.
The 0.4 reference lives in the documentation index history rather than every
banner. Individual "since 0.5" notes stay as muted history, without a warning border.

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

The source documentation baseline is stable 0.5 for Windows and Linux. The
0.4 reference remains in the documentation index history; individual "since 0.5"
notes remain as history too. `<!-- docs-version -->...<!-- /docs-version -->`
wraps the baseline banner. Publication fills it with the actual latest stable
version and available platforms. If that release is still older than 0.5, the
banner names both the older download and the 0.5 documentation baseline.
The Linux fallback links to the release list; a stable Debian asset replaces
it with the exact package link. Source pages do not promise an unpublished file.

The same source validator runs locally and in Pages. It checks every HTML page,
internal links and fragments, both language counterparts, documentation language
switches and pagers, and local-only resources including CSS and SVG. Source
checks and unit tests require no network or browser. To review unprepared HTML,
serve `site` directly with `python -m http.server 8000 --directory site`.
