# Rosetun {{version}}

This is an alpha release, the last one of 0.1: from here 0.1 only gets fixes, in betas, before 0.1.0. Bugs are expected. Report them in [Issues](https://github.com/eoftgge/rosetun/issues); report vulnerabilities privately through [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

## What's new

- **Your own lists of sites and addresses.** **Rules** has a new **Lists** tab. Add a list by link or from a file: sing-box rule sets (`.srs` and `.json`), Xray `geosite.dat` and `geoip.dat`, or plain text with one domain or address per line. Files up to 128 MiB are accepted. Lists from links update together with subscriptions.
- **Rules by list.** In the new rule dialog, **List** routes a whole list, or for `geosite.dat` and `geoip.dat` the categories you tick, through the VPN, directly, or blocks them. Tick several categories to add a rule for each at once; a category with an attribute, such as `google@cn`, can be typed into the search.
- **When a list loses a category.** If an updated `.dat` file no longer has a category a rule uses, the rule keeps working with the last version of that category, and Rosetun warns in the rule row, on the list and on the connection screen. If there is no earlier version, the rule is skipped and the warning says so.
- **List updates while connected.** A list you update by hand applies when you leave the tab, like a rule edit. An automatic update does not restart the tunnel: the list shows "Updated · takes effect on the next connection".
- **Rule dialog.** **Only until disconnect** moved into **Advanced**, which now opens below its heading; when it is on and **Advanced** is closed, the heading says so. When **Add rule** is unavailable, the dialog says why. Unavailable main buttons across the app are easier to see.
- **Rules screen.** The rule set selector moved up, next to the **Rules · Lists** switch.
- **Program rules ignore letter case.** A rule for `telegram.exe` now also matches `Telegram.exe`, as Windows does with file names.
- **Edits are not lost on quit.** Quitting from the tray while connected applies pending rule and DNS edits first.
- **The command line and the app agree.** `rosetun apply` keeps temporary rules added in the app, and settings changed in the app and in `rosetun` at the same time are both kept.
- **Security.**
  - The app checks that it talks to the real Rosetun service, and other accounts on the computer can no longer pose as it.
  - The service limits how many connections it accepts at once and checks every request more strictly.
  - VLESS and VMess credentials no longer appear in debug output.
  - Messages from the network library that may carry secrets are no longer logged.
  - If the service fails unexpectedly, it no longer leaves the network blocked.

Settings, subscriptions and rules from 0.1.0-alpha.5 are kept: the settings move to format 3 on the first start, and the previous file is saved as `config.v2.json` next to `config.json` in `%APPDATA%\Rosetun`. To go back to 0.1.0-alpha.5, put that copy back as `config.json`; lists and list rules are then lost.

## Install

Windows 10 or 11, x64. Download `{{setup}}` from this release. The installer is not code-signed yet: if SmartScreen says "Windows protected your PC", select **More info** and then **Run anyway**.

## Verify

Run `Get-FileHash .\{{setup}} -Algorithm SHA256` and compare the result with `{{sha256}}` (also in `SHA256SUMS.txt`). Verify its provenance with `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

## Included

Rosetun includes the unmodified official sing-box {{sing_box_version}} build, licensed under GPL-3.0-or-later. The corresponding source is attached as `sing-box-{{sing_box_version}}-source.tar.gz`.

The executable embeds Wintun {{wintun_version}}, distributed under the Wintun Prebuilt Binaries License; the license and notice are installed in `licenses/wintun-prebuilt-binaries-license.txt` and `licenses/wintun.txt`.

## Русский

Это альфа-версия, последняя для 0.1: дальше 0.1 получает только исправления, в бета-версиях, до выхода 0.1.0. Ошибки возможны. Сообщайте о них в [Issues](https://github.com/eoftgge/rosetun/issues), а об уязвимостях сообщайте приватно через [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

### Что нового

- **Свои списки сайтов и адресов.** На вкладке **Правила** появился раздел **Списки**. Список можно добавить по ссылке или из файла: наборы правил sing-box (`.srs` и `.json`), `geosite.dat` и `geoip.dat` от Xray или обычный текст, один домен или адрес на строку. Файлы до 128 МиБ. Списки по ссылке обновляются вместе с подписками.
- **Правила по списку.** В окне нового правила вариант **Список** направляет весь список, а для `geosite.dat` и `geoip.dat` отмеченные категории, через VPN, напрямую или блокирует их. Можно отметить несколько категорий, и на каждую появится своё правило; категорию с атрибутом, например `google@cn`, можно ввести в поиск.
- **Если из списка пропала категория.** Если в обновлённом `.dat` больше нет категории, которую использует правило, правило работает по прошлой версии этой категории, а Rosetun предупреждает об этом в строке правила, в карточке списка и на экране подключения. Если прошлой версии нет, правило не работает, и предупреждение говорит об этом.
- **Обновление списков при подключении.** Список, обновлённый вручную, применяется, когда вы уходите с вкладки, как правка правил. Автоматическое обновление не перезапускает туннель: у списка видно «Обновлён · применится при следующем подключении».
- **Окно правила.** **Только до отключения** переехало в раздел **Дополнительно**, который теперь раскрывается под своим заголовком; если оно включено, а раздел свёрнут, это видно у заголовка. Если **Добавить правило** недоступно, окно пишет почему. Недоступные основные кнопки во всей программе стали заметнее.
- **Экран правил.** Выбор набора правил переехал наверх, к переключателю **Правила · Списки**.
- **Правила для программ без учёта регистра.** Правило для `telegram.exe` теперь срабатывает и для `Telegram.exe`, как и принято в Windows для имён файлов.
- **Правки не теряются при выходе.** Выход из трея при подключении сначала применяет непримененные правки правил и DNS.
- **Командная строка и программа заодно.** `rosetun apply` сохраняет временные правила, добавленные в программе, а настройки, измененные одновременно в программе и в `rosetun`, сохраняются обе.
- **Безопасность.**
  - Программа проверяет, что говорит с настоящей службой Rosetun, и другие учётные записи компьютера больше не могут выдать себя за неё.
  - Служба ограничивает число одновременных подключений и строже проверяет каждый запрос.
  - Учётные данные VLESS и VMess больше не попадают в отладочный вывод.
  - Сообщения сетевой библиотеки, в которых могут быть секреты, больше не пишутся в журнал.
  - Если служба неожиданно падает, она больше не оставляет сеть заблокированной.

Настройки, подписки и правила из 0.1.0-alpha.5 сохраняются: при первом запуске настройки переходят на формат 3, а прежний файл сохраняется как `config.v2.json` рядом с `config.json` в `%APPDATA%\Rosetun`. Чтобы вернуться на 0.1.0-alpha.5, верните эту копию под именем `config.json`; списки и правила по спискам при этом пропадут.

### Установка

Windows 10 или 11, x64. Скачайте `{{setup}}` из этого релиза. Установщик пока не подписан: если SmartScreen показывает «Windows protected your PC», нажмите **More info**, затем **Run anyway**.

### Проверка

Выполните `Get-FileHash .\{{setup}} -Algorithm SHA256` и сравните результат с `{{sha256}}` (он также указан в `SHA256SUMS.txt`). Проверьте происхождение командой `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

### Состав

Rosetun включает официальную сборку sing-box {{sing_box_version}} без изменений, лицензия GPL-3.0-or-later. Соответствующие исходники приложены в архиве `sing-box-{{sing_box_version}}-source.tar.gz`.

Исполняемый файл содержит Wintun {{wintun_version}}, который распространяется по лицензии Wintun Prebuilt Binaries License; текст лицензии и уведомление устанавливаются в `licenses/wintun-prebuilt-binaries-license.txt` и `licenses/wintun.txt`.
