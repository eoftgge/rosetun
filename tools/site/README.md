# Static site maintenance

The source is plain HTML and CSS in `site/`. Both languages are edited directly.
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

Add the public site link to both READMEs only after the owner enables Pages and
verifies the deployment. Do not replace stable-release copy with unreleased
features when editing the site on `dev`.
