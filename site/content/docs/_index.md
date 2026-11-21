+++
title = "Документация"
sort_by = "weight"
template = "docs.html"
page_template = "doc.html"
aliases = ["/ru/docs/"]

[extra]
toc_labels = { "history" = "История" }
+++

## Новое в 0.7 {#new-in-07}

- Перед переходом с 0.6 скопируйте настройки. Rosetun 0.7 сохраняет их в формате 12 и оставляет копию `config.v9.json`. [Обновление и возврат](../docs/install/#update)
- Появились редактируемые [группы правил и каталог шаблонов](../docs/rules/#groups), а поиск и [проверка адреса](../docs/rules/#test) объединены в одном поле.
- Добавлены протоколы TUIC v5, AnyTLS и WireGuard (включая `.conf` и байты `reserved` для Cloudflare WARP), а в отчёте импорта подписок теперь указаны названия пропущенных протоколов. [Подписки и серверы](../docs/subscriptions/)
- Файл `SHA256SUMS.txt` подписывается ключом выпуска, а на Windows приложение умеет [скачивать и проверять обновления](../docs/install/#windows). Добавлены флаги или коды стран и встроенный Noto Color Emoji. [На каждый день](../docs/everyday/)
- Доступна экспериментальная сборка для [macOS (Apple Silicon)](../docs/macos/) в формате `.pkg` для macOS 14+ (без kill switch и Lockdown).

## История документации {#history}

- [Заметки к выпуску 0.6.0](https://github.com/eoftgge/rosetun/releases/tag/v0.6.0)
- [Заметки к выпуску 0.5.1](https://github.com/eoftgge/rosetun/releases/tag/v0.5.1)
- [Документация 0.4 (Windows)](https://github.com/eoftgge/rosetun/blob/v0.4.0/README.ru.md)
