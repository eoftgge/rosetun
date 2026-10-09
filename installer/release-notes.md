# Rosetun {{version}}

This is an alpha release. Bugs are expected. Report them in [Issues](https://github.com/eoftgge/rosetun/issues); report vulnerabilities privately through [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

## What's new

- **Hysteria2.** Subscriptions can now carry Hysteria2 servers, as links or in sing-box JSON, with Salamander obfuscation and port hopping. Hysteria2 runs over UDP, so **TCP ping** does not apply to it; use **URL test**.
- **New version notice.** Rosetun asks GitHub for its list of releases at launch, if a day has passed since the last check, and then once a day. A new version shows under **Settings → About**, with a dot on the Settings tab, **Open release page** and **Skip this version**. Nothing is downloaded or installed. **Check now** checks at once; **Check for updates** turns automatic checks off.
- **TLS fingerprint.** TLS servers that do not set a fingerprint now present Chrome's, as most clients do, instead of Go's own.
- **Settings survive upgrades.** The settings file now carries a format version. The first time it saves settings (also after the first update check), Rosetun 0.1.0-alpha.4 moves the file to the new format and keeps the previous one next to it as `config.v1.json`; it contains the same subscription links.
- Server checks are now called **TCP ping** and **URL test**. Links use the rose accent colour.

Settings, subscriptions and rules from 0.1.0-alpha.3 are kept. Going back to 0.1.0-alpha.3 after the settings were saved in the new format: the older version refuses to open the new file and leaves it untouched; replace `config.json` with `config.v1.json` to use it.

## Install

Windows 10 or 11, x64. Download `{{setup}}` from this release. The installer is not code-signed yet: if SmartScreen says "Windows protected your PC", select **More info** and then **Run anyway**.

## Verify

Run `Get-FileHash .\{{setup}} -Algorithm SHA256` and compare the result with `{{sha256}}` (also in `SHA256SUMS.txt`). Verify its provenance with `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

## Included

Rosetun includes the unmodified official sing-box {{sing_box_version}} build, licensed under GPL-3.0-or-later. The corresponding source is attached as `sing-box-{{sing_box_version}}-source.tar.gz`.

## Русский

Это альфа-версия. Ошибки возможны. Сообщайте о них в [Issues](https://github.com/eoftgge/rosetun/issues), а об уязвимостях сообщайте приватно через [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

### Что нового

- **Hysteria2.** Подписки теперь могут содержать серверы Hysteria2, ссылками или в JSON sing-box, с обфускацией Salamander и сменой портов. Hysteria2 работает по UDP, поэтому **Пинг TCP** к нему неприменим; используйте **Проверку URL**.
- **Сообщение о новой версии.** Rosetun запрашивает у GitHub список релизов при запуске, если с прошлой проверки прошли сутки, и затем раз в сутки. Новая версия появляется в **Настройки → О программе**, с точкой на вкладке настроек и кнопками **Открыть страницу релиза** и **Пропустить эту версию**. Ничего не скачивается и не устанавливается. **Проверить сейчас** проверяет сразу; **Проверять обновления** выключает автоматическую проверку.
- **Отпечаток TLS.** TLS-серверы, у которых отпечаток не задан, теперь представляются как Chrome, как в большинстве клиентов, а не собственным отпечатком Go.
- **Настройки переживают обновления.** У файла настроек появилась версия формата. При первом сохранении настроек (в том числе после первой проверки обновлений) Rosetun 0.1.0-alpha.4 переводит файл на новый формат и оставляет прежний рядом как `config.v1.json`; в нём те же ссылки подписок.
- Проверки серверов теперь называются **Пинг TCP** и **Проверка URL**. Ссылки окрашены в розовый цвет оформления.

Настройки, подписки и правила из 0.1.0-alpha.3 сохраняются. Если вернуться на 0.1.0-alpha.3 после того, как настройки сохранены в новом формате, старая версия откажется открывать новый файл и не изменит его; чтобы пользоваться ею, замените `config.json` файлом `config.v1.json`.

### Установка

Windows 10 или 11, x64. Скачайте `{{setup}}` из этого релиза. Установщик пока не подписан: если SmartScreen показывает «Windows protected your PC», нажмите **More info**, затем **Run anyway**.

### Проверка

Выполните `Get-FileHash .\{{setup}} -Algorithm SHA256` и сравните результат с `{{sha256}}` (он также указан в `SHA256SUMS.txt`). Проверьте происхождение командой `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

### Состав

Rosetun включает официальную сборку sing-box {{sing_box_version}} без изменений, лицензия GPL-3.0-or-later. Соответствующие исходники приложены в архиве `sing-box-{{sing_box_version}}-source.tar.gz`.
