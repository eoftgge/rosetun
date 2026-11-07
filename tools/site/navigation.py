"""Keep the committed static page headers and footers consistent."""

import argparse
from html import escape
import os
from pathlib import Path
import re
from textwrap import indent


def page_chrome(path, root):
    relative = path.relative_to(root)
    lang = relative.parts[0]
    english = lang == 'en'
    other = 'ru' if english else 'en'
    section = relative.parts[1] if len(relative.parts) > 2 else ''

    def url(target, directory=False):
        result = Path(os.path.relpath(target, path.parent)).as_posix()
        return escape(result + ('/' if directory else ''), quote=True)

    def local(section):
        return url(root / lang / section, directory=True)

    other_url = url(root / other / Path(*relative.parts[1:]).parent, directory=True)
    language = 'Русский' if english else 'English'
    switch = f'<a href="{other_url}" lang="{other}" hreflang="{other}">{language}</a>'
    items = [
        ('', 'Home' if english else 'Главная'),
        ('docs', 'Documentation' if english else 'Документация'),
        ('providers', 'For providers' if english else 'Для провайдеров'),
        ('help', 'Help' if english else 'Помощь'),
    ]
    links = []
    for target, label in items:
        current = ''
        if target == section:
            value = 'page' if len(relative.parts) <= 3 else 'location'
            current = f' aria-current="{value}"'
        links.append(f'        <a href="{local(target)}"{current}>{label}</a>')
    links.append('        ' + switch)
    navigation = '\n'.join(links)
    nav_label = 'Navigation' if english else 'Навигация'
    logo = url(root / 'assets/rose.svg')
    header = f'''<header class="wrap">
    <div class="header-brand">
        <a class="brand" href="{local('')}"><img src="{logo}" width="40" height="40" alt="" />Rosetun</a>
        <p class="platform-label">WINDOWS <span aria-hidden="true">·</span> LINUX <span aria-hidden="true">·</span> OPEN SOURCE</p>
    </div>
    <nav aria-label="{nav_label}">
{navigation}
    </nav>
</header>'''
    licenses = 'Licenses' if english else 'Лицензии'
    security = 'Report a vulnerability' if english else 'Сообщить об уязвимости'
    footer = f'''<footer class="wrap">
    <span>Rosetun</span>
    <a href="https://github.com/eoftgge/rosetun">GitHub</a>
    <a href="{local('docs/licenses')}">{licenses}</a>
    <a href="https://github.com/eoftgge/rosetun/blob/master/LICENSE">GPL-3.0-or-later</a>
    <a href="https://github.com/eoftgge/rosetun/security/policy">{security}</a>
    {switch}
</footer>'''
    return indent(header, '        '), indent(footer, '        ')


def check_chrome(path, root, source):
    for tag, expected in zip(('header', 'footer'), page_chrome(path, root)):
        actual = re.search(rf'        <{tag} class="wrap">.*?</{tag}>', source, re.DOTALL)
        assert actual and actual[0] == expected, (
            f'{path}: inconsistent {tag}; run python tools/site/navigation.py --write'
        )


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', nargs='?', default='site', type=Path)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    for lang in ('en', 'ru'):
        for path in (args.directory / lang).rglob('*.html'):
            source = path.read_text(encoding='utf-8')
            if args.write:
                for tag, replacement in zip(('header', 'footer'), page_chrome(path, args.directory)):
                    source, count = re.subn(rf'        <{tag} class="wrap">.*?</{tag}>',
                                           lambda match: replacement, source, flags=re.DOTALL)
                    assert count == 1, f'{path}: expected one {tag}'
                path.write_text(source, encoding='utf-8', newline='\n')
            check_chrome(path, args.directory, source)
