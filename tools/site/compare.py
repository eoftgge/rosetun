"""Compare a built site with the pages of an earlier commit: visible text of `main`, ids and `<head>`.

The pages before the move to Zola were handwritten HTML under `site/{ru,en}/`. The move must not
change a word, so the check reads those pages from git and compares them with the built site, where
the Russian pages live in the root. Run it against a build made without release data, which has
the same neutral text as the old source pages.
"""

import argparse
from html.parser import HTMLParser
from pathlib import PurePosixPath
import posixpath
import re
import subprocess
import sys

BLOCKS = {
    'address', 'article', 'aside', 'blockquote', 'body', 'dd', 'details', 'dialog', 'div', 'dl', 'dt',
    'figcaption', 'figure', 'footer', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header', 'hr', 'li', 'main',
    'ol', 'p', 'pre', 'section', 'table', 'tbody', 'td', 'tfoot', 'th', 'thead', 'tr', 'ul', 'button',
}
SKIP = {'script', 'style', 'title'}


class Page(HTMLParser):
    """The text of `main`, the ids of the document and the parts of `<head>` that matter."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.chrome = {'header': [], 'footer': [], 'skip': []}
        self.ids = []
        self.head = {'alternate': {}}
        self.stack = []
        self.title = ''

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if 'id' in attrs:
            self.ids.append(attrs['id'])
        if tag in ('meta', 'link'):
            self.void(tag, attrs)
            return
        self.stack.append(tag)
        if tag == 'a' and attrs.get('class') == 'skip':
            self.stack.append('skip')
        for area in self.areas():
            self.chrome[area].append(' ')
        if tag in BLOCKS and 'main' in self.stack:
            self.text.append(' ')

    def void(self, tag, attrs):
        if tag == 'meta':
            if attrs.get('name') == 'description':
                self.head['description'] = attrs.get('content')
            if attrs.get('http-equiv', '').lower() == 'content-security-policy':
                self.head['csp'] = re.sub(r'\s+', ' ', attrs.get('content', '')).strip()
            if attrs.get('name') == 'referrer':
                self.head['referrer'] = attrs.get('content')
        elif attrs.get('rel') == 'alternate':
            self.head['alternate'][attrs.get('hreflang')] = attrs.get('href')
        elif attrs.get('rel') == 'stylesheet':
            self.head['stylesheet'] = attrs.get('href')

    def handle_endtag(self, tag):
        if tag in ('meta', 'link'):
            return
        if tag in BLOCKS and 'main' in self.stack:
            self.text.append(' ')
        while self.stack:
            if self.stack.pop() == tag:
                break

    def areas(self):
        return [area for area in ('header', 'footer', 'skip') if area in self.stack]

    def handle_data(self, data):
        if 'title' in self.stack:
            self.title += data
            return
        if any(tag in SKIP for tag in self.stack):
            return
        for area in self.areas():
            self.chrome[area].append(data)
        if 'main' in self.stack:
            self.text.append(data)

    def visible(self):
        return re.sub(r'\s+', ' ', ''.join(self.text)).strip()


def parse(source):
    page = Page()
    page.feed(source)
    page.head['title'] = re.sub(r'\s+', ' ', page.title).strip()
    for area, parts in page.chrome.items():
        page.chrome[area] = re.sub(r'\s+', ' ', ''.join(parts)).strip()
    return page


def git(*args):
    return subprocess.run(['git', *args], capture_output=True, check=True).stdout.decode('utf-8')


def new_name(old):
    """Where a page of the old site lives in the built one: `ru/x/` moved to the root."""
    return old[3:] if old.startswith('ru/') else old


def canonical(directory, href):
    """The site path an alternate link leads to, in the new layout."""
    target = posixpath.normpath(posixpath.join(posixpath.dirname(directory), href))
    target = '' if target == '.' else target.rstrip('/') + '/'
    return target[3:] if target.startswith('ru/') else ('' if target == 'ru/' else target)


def compare(old_ref, built, names=None):
    """Returns the list of differences; empty means the pages match."""
    from pathlib import Path
    root = Path(built)
    pages = [line for line in git('ls-tree', '-r', '--name-only', old_ref, 'site').splitlines()
             if re.fullmatch(r'site/(?:ru|en)/(?:.+/)?index\.html', line)]
    problems = []
    checked = 0
    for path in sorted(pages):
        old = path[len('site/'):]
        directory = old[:-len('index.html')]
        new = root / new_name(old)
        if not new.is_file():
            problems.append(f'{old}: missing in the built site ({new_name(old)})')
            continue
        before = parse(git('show', f'{old_ref}:{path}'))
        after = parse(new.read_text(encoding='utf-8'))
        checked += 1
        label = old
        if before.visible() != after.visible():
            problems.append(f'{label}: visible text of main differs\n  old: {describe(before.visible(), after.visible())}\n'
                            f'  new: {describe(after.visible(), before.visible())}')
        if before.ids != after.ids:
            problems.append(f'{label}: ids differ: removed {sorted(set(before.ids) - set(after.ids))}, '
                            f'added {sorted(set(after.ids) - set(before.ids))}'
                            + ('' if sorted(before.ids) != sorted(after.ids) else ' (order only)'))
        for key in ('title', 'description', 'csp', 'referrer'):
            if before.head.get(key) != after.head.get(key):
                problems.append(f'{label}: head {key} differs: {before.head.get(key)!r} != {after.head.get(key)!r}')
        for lang in ('ru', 'en'):
            was = canonical(directory, before.head['alternate'][lang])
            now = canonical(new_name(directory), after.head['alternate'][lang])
            if was != now:
                problems.append(f'{label}: alternate {lang} differs: {was!r} != {now!r}')
        for area in ('header', 'footer', 'skip'):
            if before.chrome[area] != after.chrome[area]:
                problems.append(f'{label}: {area} text differs: {before.chrome[area]!r} != {after.chrome[area]!r}')
    return checked, problems


def describe(text, other):
    """The first place where two normalized texts diverge, with some context."""
    index = next((i for i, (a, b) in enumerate(zip(text, other)) if a != b), min(len(text), len(other)))
    return f'...{text[max(0, index - 40):index + 80]!r}'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('built', help='directory of a build made without release data')
    parser.add_argument('--old-ref', default='HEAD', help='git revision that still has site/{ru,en}/**/index.html')
    args = parser.parse_args()
    checked, problems = compare(args.old_ref, args.built)
    for problem in problems:
        print(problem)
    print(f'{checked} pages compared, {len(problems)} differences')
    sys.exit(1 if problems else 0)
