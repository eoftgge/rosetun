# Site maintenance

The site is built by [Zola](https://www.getzola.org/) from Markdown and one set of
templates. The generated HTML is never committed. Russian is the default language and
lives in the root (`/docs/install/`); English lives in `/en/` (`/en/docs/install/`). The
old Russian addresses `/ru/...` stay as redirect pages, because releases and READMEs
link to them.

```
site/
  config.toml          language, translations, Content-Security-Policy per kind of page
  content/             Markdown: name.md is Russian, name.en.md its English twin
  templates/           base.html, index.html (home), docs.html, doc.html, help.html,
                       providers.html, components.html, internal/alias.html (redirects)
  static/assets/       styles, fonts, images, script.js (home only), redirect.js (redirects only)
  data/release.json    written by release.py during publication; not in git
```

## Zola

The version and the SHA-256 of both archives are pinned in `tools/site/zola.toml`, and
nowhere else. `install_zola.py` downloads exactly that release from GitHub, checks the
hash before it unpacks anything and extracts only the executable. The Pages workflow
uses the same script.

```sh
python tools/site/install_zola.py              # target/zola/zola (zola.exe on Windows)
export PATH="$PWD/target/zola:$PATH"           # Linux, macOS shells
$env:PATH = "$PWD\target\zola;$env:PATH"       # PowerShell
```

To update Zola, change the version and both hashes in `zola.toml` together (the hashes
are in the release's asset list on GitHub), then run the checks below.

## Checks

Run from the repository root:

```sh
zola --root site build --output-dir target/site --force
python tools/site/check.py target/site
zola --root site check --skip-external-links
python -m unittest discover -s tools/site -p 'test_*.py'
```

`check.py` validates the built directory: forbidden elements and attributes, internal
links and fragments, both language versions of every page, the language switch, the
contents list and the pager of the documentation, local resources only (HTML, CSS, SVG),
the Content-Security-Policy and scripts of each kind of page, the shared header and
footer with the current section marked, and that every old `/ru/...` address redirects
to its page. Neither it nor the tests need the network or a browser. The tests build the
site with the Zola from `$ZOLA`, `PATH` or `target/zola`, and skip the build tests when
there is none.

## Preview

```sh
zola --root site serve                     # live preview with neutral release text
python tools/site/release.py --preview --preview-deb   # then build or serve with release data
```

Every address on a page is relative to that page, so a build works from any directory.
To review the site under a subdirectory, as GitHub Pages serves it, build into a
directory named `rosetun` and serve its parent:

```sh
zola --root site build --output-dir target/preview/rosetun --force
python -m http.server 8000 --directory target/preview     # open /rosetun/
```

Review at 360, 768 and 1280 CSS pixels, in both color schemes, with JavaScript disabled.
Screenshots must use documentation-only data.

## Release data

Without `site/data/release.json` every page shows neutral text and links to the list of
releases. Do not put the current release number in the text. `release.py` writes the
file; the templates and the home and install pages read it with `load_data`, and the
Pages job then builds the site with it.

Python 3.11+ reads `[workspace.package].version` from the root `Cargo.toml`; the Pages
job fetches exactly that published stable tag (`v<version>`), its assets and the matching
lines of `SHA256SUMS.txt`. It never falls back to the latest release, and a prerelease
workspace version, a missing release, asset or unique checksum stops publication. The
checksum is copied; the job does not download and hash the installer. No API calls run in
a visitor's browser.

```sh
python tools/site/release.py                                  # publication (needs the network)
python tools/site/release.py --preview --preview-deb          # offline, synthetic checksums
python tools/site/release.py --preview-version 2.7.19         # another version, synthetic
zola --root site build --output-dir target/site-release --force
python tools/site/check.py target/site-release --rendered
```

A preview uses synthetic checksums; do not publish its output. Delete
`site/data/release.json` to see the neutral text again.

What depends on the release:

- the banner under the title of every documentation page and on the home page
  names the stable version and its platforms. When the release predates 0.6,
  it also identifies 0.6 as the version described by the documentation.
- installation and download commands, links and checksum lines (`r?.installer`,
  `r?.download_url`, ...), each with a neutral fallback after `or`;
- the Linux text: `{% if r?.deb_url %}` shows the package instructions, `{% else %}` the
  note that the release has none. Source pages never promise an unpublished file.

The documentation describes 0.6. The index links to the 0.5.1 release notes
and the 0.4 reference.

## Editing

- **A page.** Add `content/docs/name.md` (Russian) and `name.en.md` (English) with the
  same `weight`, which sets the order of the documentation, the index and the pager. The
  Russian page needs `aliases = ["/ru/docs/name/"]`. Give each page an
  `[extra] group`, the heading of its group in the contents, in the page's language. The contents of the
  documentation index is built from the pages of the section, in the order of `weight`,
  grouped by consecutive `group`; the pager follows the same order.
- **Headings** need an explicit id (`## Title {#id}`) when the anchor must not change;
  Cyrillic headings always do. The "On this page" list is the page's `h2` headings. A
  different label goes into `[extra.toc_labels]` as `id = "Label"`. Front matter
  `overview = "Label"` wraps the page in `<section id="details">` and puts that label
  first in the list.
- **Links between pages** use `../name/`. Zola rewrites a relative link that does not
  begin with `../`, `/` or `#` into an absolute one with `base_url`, which breaks a
  preview, so the home page keeps its links as plain HTML. Do not use `@/` links.
- **Templated content.** Every Markdown file is a Tera template. Wrap a literal `{{`,
  `{%` or `{#` in `{% raw %}`. HTML stays in Markdown only where Markdown cannot say it:
  the diagram, a note paragraph, the table with row headers on the provider page, headings
  that must not get an id, and the home page links.
- **The 404 page** (`templates/404.html`) is served at any missing address, so its links
  start from the directory of the site (`/rosetun/...`) instead of being relative to the page.
  It loads no script and links to the home page of both languages.
- **The header, the footer and the language switch** are in `templates/base.html`; their
  labels are in `config.toml`. `check.py` fails when a page's header or footer differs
  from what its location requires.

## Deployment

The workflow checks `dev` pushes without deploying. Deployment uses `master` for release
events and successful Release workflow completions. The latter is needed because a release
created with `GITHUB_TOKEN` does not trigger another workflow through `release: published`.
A completed preview release can therefore refresh the site from `master` using the version
in master's Cargo.toml. Manual deployment must select `master`. The workflow does not
enable Pages; the owner must first choose GitHub Actions in Settings → Pages.

Deployment takes `master`, so copy edited on `dev` reaches visitors when `master` moves
forward.
