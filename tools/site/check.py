"""Validate the built site without third-party dependencies or network access.

Run it on the output of `zola build`. Russian is the default language and lives in the root;
English lives in `en/`. The old `/ru/...` addresses are redirect pages that this check follows.
"""

import argparse
from html.parser import HTMLParser
from pathlib import Path
import re
import tomllib
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET

CONFIG = Path(__file__).resolve().parents[2] / 'site' / 'config.toml'
OWN_HOST = urlsplit(tomllib.loads(CONFIG.read_text(encoding='utf-8'))['base_url']).hostname
LABELS = {
    'ru': dict(items=('Главная', 'Документация', 'Для провайдеров', 'Помощь'), switch='English',
               licenses='Лицензии', security='Сообщить об уязвимости', toc='На этой странице'),
    'en': dict(items=('Home', 'Documentation', 'For providers', 'Help'), switch='Русский',
               licenses='Licenses', security='Report a vulnerability', toc='On this page'),
}
SECTIONS = ('', 'docs', 'providers', 'help')


class Document(HTMLParser):
    def __init__(self, path):
        super().__init__(convert_charrefs=True)
        self.path = path
        self.ids = set()
        self.links = []
        self.alternates = {}
        self.lang = None
        self.pager = set()
        self.language_links = {}
        self.toc_links = []
        self.in_toc = False
        self.redirect = None
        self.csp = None
        self.scripts = []
        self.chrome = {'header': [], 'footer': []}
        self.region = None
        self.link = None
        self.main = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'nav':
            self.in_toc = attrs.get('aria-label') in {'On this page', 'На этой странице'}
        if tag == 'a' and self.in_toc:
            self.toc_links.append(attrs.get('href', ''))
        if tag == 'html':
            self.lang = attrs.get('lang')
        if tag == 'main':
            self.main = True
        if tag in ('header', 'footer'):
            self.region = tag
        if tag == 'a' and self.region:
            self.link = dict(href=attrs.get('href', ''), text='', current=attrs.get('aria-current'),
                             lang=attrs.get('hreflang'))
            self.chrome[self.region].append(self.link)
        if 'id' in attrs:
            assert attrs['id'] not in self.ids, f'{self.path}: duplicate id'
            self.ids.add(attrs['id'])
        assert tag not in {'style', 'iframe', 'object', 'embed', 'base', 'form'}, (
            f'{self.path}: unexpected active element {tag}'
        )
        assert not any(k.startswith('on') or k in {'style', 'srcset', 'ping'} for k in attrs), (
            f'{self.path}: unexpected active attribute'
        )
        if tag == 'script':
            assert 'src' in attrs, f'{self.path}: inline script'
            self.scripts.append(attrs['src'])
        if tag == 'link' and attrs.get('rel') == 'alternate':
            self.alternates[attrs.get('hreflang')] = attrs.get('href')
        if tag == 'a' and attrs.get('rel') in {'prev', 'next'}:
            self.pager.add(attrs['rel'])
        if tag == 'a' and attrs.get('hreflang'):
            self.language_links[attrs['hreflang']] = attrs.get('href')
        for key in ('href', 'src', 'poster', 'data'):
            if key in attrs:
                self.links.append((attrs[key], tag != 'a'))
        if tag == 'meta' and attrs.get('http-equiv', '').lower() == 'content-security-policy':
            self.csp = re.sub(r'\s+', ' ', attrs.get('content', '')).strip()
        if tag == 'meta' and attrs.get('http-equiv', '').lower() == 'refresh':
            match = re.fullmatch(r'0;\s*url=(.+)', attrs.get('content', ''))
            assert match, f'{self.path}: unexpected redirect'
            self.redirect = match[1]
            self.links.append((match[1], True))

    def handle_data(self, data):
        if self.link is not None:
            self.link['text'] += data

    def handle_endtag(self, tag):
        if tag == 'nav':
            self.in_toc = False
        if tag == 'a':
            self.link = None
        if tag in ('header', 'footer'):
            self.region = None


def local_target(root, source, url, resource=False):
    parts = urlsplit(url)
    if parts.scheme or parts.netloc:
        assert not resource, f'{source}: external resource {url}'
        assert parts.hostname != OWN_HOST, f'{source}: absolute link to the own site {url}; use a relative one'
        assert parts.scheme == 'https', f'{source}: unsafe link {url}'
        return None
    assert not parts.path.startswith(('/', '\\')), f'{source}: root-relative URL {url}'
    target = (source.parent / unquote(parts.path)).resolve() if parts.path else source
    assert target.is_relative_to(root), f'{source}: URL escapes the site: {url}'
    if target.is_dir():
        target /= 'index.html'
    assert target.is_file(), f'{source}: missing target {url}'
    return target, unquote(parts.fragment)


def page_language(relative):
    """The language and the path inside the language of a built page."""
    if relative.parts[0] == 'en':
        return 'en', Path(*relative.parts[1:])
    return 'ru', relative


def expected_chrome(path, root, lang, inner):
    """The header and the footer links of a page: (text, target, aria-current, hreflang)."""
    other = 'ru' if lang == 'en' else 'en'
    texts = LABELS[lang]
    base = root / 'en' if lang == 'en' else root
    switch = (root if other == 'ru' else root / 'en') / inner
    top = inner.parts[0] if len(inner.parts) > 1 else ''
    current = 'page' if len(inner.parts) <= 2 else 'location'
    header = [('Rosetun', base / 'index.html', None, None)]
    for section, label in zip(SECTIONS, texts['items']):
        header.append((label, base / section / 'index.html', current if section == top else None, None))
    header.append((texts['switch'], switch, None, other))
    footer = [
        ('GitHub', 'https://github.com/eoftgge/rosetun', None, None),
        (texts['licenses'], base / 'docs/licenses/index.html', None, None),
        ('GPL-3.0-or-later', 'https://github.com/eoftgge/rosetun/blob/master/LICENSE', None, None),
        (texts['security'], 'https://github.com/eoftgge/rosetun/security/policy', None, None),
        (texts['switch'], switch, None, other),
    ]
    return header, footer


def check_chrome(path, root, doc, lang, inner):
    """Every page shares one header and footer, with the current section marked."""
    expected = expected_chrome(path, root, lang, inner)
    for region, wanted in zip(('header', 'footer'), expected):
        actual = []
        for link in doc.chrome[region]:
            target = local_target(root, path, link['href'])
            actual.append((link['text'].strip(), target[0] if target else link['href'],
                           link['current'], link['lang']))
        assert actual == wanted, f'{path}: inconsistent {region}'


def check_alias(root, path, doc, documents):
    """An old `/ru/...` address redirects to the page that replaced it."""
    assert doc.redirect, f'{path}: not a redirect'
    assert path.name == 'index.html', f'{path}: a redirect must be a directory index'
    target, _ = local_target(root, path, doc.redirect)
    relative = path.relative_to(root / 'ru')
    assert target == root / relative, f'{path}: redirect leads to {doc.redirect}'
    scripts = {local_target(root, path, src, True)[0] for src in doc.scripts}
    assert scripts == {root / 'assets/redirect.js'}, f'{path}: unexpected scripts {doc.scripts}'
    assert target in documents, f'{path}: redirect to a missing page'


def check_not_found(root, path, doc, csp):
    """The 404 page is served at any address, so its links start from the site's directory."""
    assert doc.lang == 'ru', f'{path}: wrong language'
    assert doc.csp == csp, f'{path}: unexpected Content-Security-Policy'
    assert not doc.scripts, f'{path}: the 404 page must not load scripts'
    style = next((url for url, _ in doc.links if url.endswith('assets/site.css')), None)
    assert style and style.startswith('/'), f'{path}: expected the style sheet from the site directory'
    prefix = style.removesuffix('assets/site.css')
    for url, resource in doc.links:
        if url.startswith('#'):
            continue
        if urlsplit(url).scheme:
            local_target(root, path, url, resource)
            continue
        assert url.startswith(prefix), f'{path}: address outside the site directory {url}'
        target = root / unquote(urlsplit(url).path)[len(prefix):]
        assert (target / 'index.html' if target.is_dir() else target).is_file(), f'{path}: missing target {url}'
    assert {prefix, prefix + 'en/'} <= {url for url, _ in doc.links}, f'{path}: missing links to both home pages'


def check(directory, rendered=False):
    root = Path(directory).resolve()
    csp = tomllib.loads(CONFIG.read_text(encoding='utf-8'))['extra']
    documents = {}
    for path in root.rglob('*.html'):
        source = path.read_text(encoding='utf-8')
        assert '—' not in source, f'{path}: em dash'
        doc = Document(path)
        doc.feed(source)
        documents[path] = doc
    assert documents, 'no HTML documents'
    aliases = {path for path in documents if path.relative_to(root).parts[0] == 'ru'}
    not_found = root / '404.html'
    assert not_found in documents, '404.html is missing'
    check_not_found(root, not_found, documents[not_found], csp['csp'])
    pages = {path: doc for path, doc in documents.items() if path not in aliases and path != not_found}
    for path, doc in pages.items():
        assert not doc.redirect, f'{path}: unexpected redirect; only /ru/ aliases are supported'
        relative = path.relative_to(root)
        lang, inner = page_language(relative)
        assert doc.lang == lang, f'{path}: wrong language'
        assert set(doc.alternates) == {'ru', 'en'}, f'{path}: missing hreflang'
        for other, counterpart in (('ru', root / inner), ('en', root / 'en' / inner)):
            assert counterpart in pages, f'{path}: missing translation {other}'
            actual, _ = local_target(root, path, doc.alternates[other])
            assert actual == counterpart, f'{path}: incorrect alternate {other}'
        home = inner == Path('index.html')
        assert doc.csp == csp['csp_home' if home else 'csp'], f'{path}: unexpected Content-Security-Policy'
        scripts = {local_target(root, path, src, True)[0] for src in doc.scripts}
        assert scripts == ({root / 'assets/script.js'} if home else set()), f'{path}: unexpected scripts {doc.scripts}'
        check_chrome(path, root, doc, lang, inner)
        if 'docs' in inner.parts:
            other = 'ru' if lang == 'en' else 'en'
            assert other in doc.language_links, f'{path}: missing language switch'
            actual, _ = local_target(root, path, doc.language_links[other])
            assert actual == (root if other == 'ru' else root / 'en') / inner, f'{path}: incorrect language switch'
            assert doc.toc_links and all(url.startswith('#') and url != '#main' for url in doc.toc_links), (
                f'{path}: missing table of contents'
            )
            if len(inner.parts) > 2:
                assert doc.pager == {'prev', 'next'}, f'{path}: missing documentation pager'
        if rendered:
            assert not any(url.endswith('/releases/latest') for url, _ in doc.links), (
                f'{path}: release data missing: a link still points to the latest release'
            )
        if lang == 'ru':
            alias = root / 'ru' / inner
            assert alias in aliases, f'{path}: missing redirect from the old address {alias.relative_to(root)}'
            check_alias(root, alias, documents[alias], pages)
    stray = aliases - {root / 'ru' / path.relative_to(root) for path in pages
                       if page_language(path.relative_to(root))[0] == 'ru'}
    assert not stray, f'redirect without a page: {sorted(p.relative_to(root).as_posix() for p in stray)}'
    for path, doc in documents.items():
        if path == not_found:
            continue
        for url, resource in doc.links:
            resolved = local_target(root, path, url, resource)
            if resolved:
                target, fragment = resolved
                if fragment:
                    assert target in documents and fragment in documents[target].ids, (
                        f'{path}: missing fragment {url}'
                    )
    for path in root.rglob('*.css'):
        css = path.read_text(encoding='utf-8')
        assert not re.search(r'@import|expression\s*\(|image-set\s*\(|\\', css, re.I), (
            f'{path}: unsupported CSS resource syntax'
        )
        for match in re.finditer(r'url\(\s*([^)]+?)\s*\)', css, re.I):
            local_target(root, path, match[1].strip('\"\''), True)
    for path in root.rglob('*.svg'):
        svg = path.read_text(encoding='utf-8')
        tree = ET.fromstring(svg)
        ids = {element.get('id') for element in tree.iter() if element.get('id')}
        assert not re.search(r'@import|image-set\s*\(|\\', svg, re.I), f'{path}: unsafe SVG CSS'
        for element in tree.iter():
            assert element.tag.split('}')[-1] not in {'script', 'foreignObject'}, f'{path}: active SVG'
            for key, value in element.attrib.items():
                name = key.split('}')[-1]
                assert not name.lower().startswith('on'), f'{path}: SVG event handler'
                if name in {'href', 'src'}:
                    assert value.startswith('#') and value[1:] in ids, f'{path}: external SVG resource'
        for match in re.finditer(r'url\(\s*([^)]+?)\s*\)', svg, re.I):
            value = match[1].strip('\"\'')
            assert value.startswith('#') and value[1:] in ids, f'{path}: external SVG resource'
    size = sum(p.stat().st_size for p in root.rglob('*') if p.is_file() and 'screens' not in p.parts)
    assert size < 1_000_000, f'site exceeds 1 MB: {size} bytes'
    print(f'OK: {len(pages)} HTML pages and {len(aliases)} redirects; links, translations, local resources; {size} bytes')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', nargs='?', default='target/site')
    parser.add_argument('--rendered', action='store_true', help='the build had release data')
    args = parser.parse_args()
    check(args.directory, args.rendered)
