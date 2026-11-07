"""Validate the static site without third-party dependencies or network access."""

import argparse
from html.parser import HTMLParser
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET


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

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'nav':
            self.in_toc = attrs.get('aria-label') in {'On this page', 'На этой странице'}
        if tag == 'a' and self.in_toc:
            self.toc_links.append(attrs.get('href', ''))
        if tag == 'html':
            self.lang = attrs.get('lang')
        if 'id' in attrs:
            assert attrs['id'] not in self.ids, f'{self.path}: duplicate id'
            self.ids.add(attrs['id'])
        assert tag not in {'script', 'style', 'iframe', 'object', 'embed', 'base', 'form'}, (
            f'{self.path}: unexpected active element {tag}'
        )
        assert not any(k.startswith('on') or k in {'style', 'srcset', 'ping'} for k in attrs), (
            f'{self.path}: unexpected active attribute'
        )
        if tag == 'link' and attrs.get('rel') == 'alternate':
            self.alternates[attrs.get('hreflang')] = attrs.get('href')
        if tag == 'a' and attrs.get('rel') in {'prev', 'next'}:
            self.pager.add(attrs['rel'])
        if tag == 'a' and attrs.get('hreflang'):
            self.language_links[attrs['hreflang']] = attrs.get('href')
        for key in ('href', 'src', 'poster', 'data'):
            if key in attrs:
                self.links.append((attrs[key], tag != 'a'))
        if tag == 'meta' and attrs.get('http-equiv', '').lower() == 'refresh':
            match = re.fullmatch(r'0;\s*url=(.+)', attrs.get('content', ''))
            assert match, f'{self.path}: unexpected redirect'
            self.links.append((match[1], True))

    def handle_endtag(self, tag):
        if tag == 'nav':
            self.in_toc = False


def local_target(root, source, url, resource=False):
    parts = urlsplit(url)
    if parts.scheme or parts.netloc:
        assert not resource, f'{source}: external resource {url}'
        assert parts.scheme == 'https', f'{source}: unsafe link {url}'
        return None
    assert not parts.path.startswith(('/', '\\')), f'{source}: root-relative URL {url}'
    target = (source.parent / unquote(parts.path)).resolve() if parts.path else source
    assert target.is_relative_to(root), f'{source}: URL escapes the site: {url}'
    if target.is_dir():
        target /= 'index.html'
    assert target.is_file(), f'{source}: missing target {url}'
    return target, unquote(parts.fragment)


def check(directory, rendered=False):
    root = Path(directory).resolve()
    documents = {}
    for path in root.rglob('*.html'):
        source = path.read_text(encoding='utf-8')
        if rendered:
            assert not re.search(r'@@[A-Z0-9_]+@@', source), f'{path}: unresolved release marker'
        assert '\u2014' not in source, f'{path}: em dash'
        doc = Document(path)
        doc.feed(source)
        documents[path] = doc
    assert documents, 'no HTML documents'
    for path, doc in documents.items():
        relative = path.relative_to(root)
        expected_lang = relative.parts[0] if len(relative.parts) > 1 else 'ru'
        assert doc.lang == expected_lang, f'{path}: wrong language'
        assert set(doc.alternates) == {'ru', 'en'}, f'{path}: missing hreflang'
        suffix = Path(*relative.parts[1:]) if len(relative.parts) > 1 else Path('index.html')
        for lang in ('ru', 'en'):
            counterpart = root / lang / suffix
            assert counterpart in documents, f'{path}: missing translation {lang}'
            actual, _ = local_target(root, path, doc.alternates[lang])
            assert actual == counterpart, f'{path}: incorrect alternate {lang}'
        if 'docs' in relative.parts:
            other = 'ru' if doc.lang == 'en' else 'en'
            assert other in doc.language_links, f'{path}: missing language switch'
            actual, _ = local_target(root, path, doc.language_links[other])
            assert actual == root / other / suffix, f'{path}: incorrect language switch'
            assert doc.toc_links and all(url.startswith('#') and url != '#main' for url in doc.toc_links), (
                f'{path}: missing table of contents'
            )
            if len(relative.parts) > 3:
                assert doc.pager == {'prev', 'next'}, f'{path}: missing documentation pager'
        for url, resource in doc.links:
            if not rendered and re.fullmatch(r'@@(?:DOWNLOAD_URL|CHECKSUM_URL)@@', url):
                continue
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
    print(f'OK: {len(documents)} HTML pages; links, translations, local resources; {size} bytes')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', nargs='?', default='site')
    parser.add_argument('--rendered', action='store_true')
    args = parser.parse_args()
    check(args.directory, args.rendered)
