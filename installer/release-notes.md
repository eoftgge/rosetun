# Rosetun {{version}}

The second alpha of 0.2: small visible improvements on top of the Xray support from 0.2.0-alpha.1. It is for people who are ready to test; if you want the steady version, stay on the 0.1 beta, which keeps getting fixes (0.1.0-beta.2 and later do not offer it; 0.1.0-beta.1 and 0.2.0-alpha.1 do). Please report what breaks in [Issues](https://github.com/eoftgge/rosetun/issues); report vulnerabilities privately through [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

**Going back to 0.1 takes a manual step.** 0.2 upgrades the settings file to a new format, and 0.1 refuses a file from a newer version instead of overwriting it. Rosetun keeps your previous settings next to it as `%APPDATA%\Rosetun\config.v3.json`: to return to the beta, install it and rename that file to `config.json`. Changes made in 0.2 are not carried back.

## What's changed

- **The tray icon shows the state by shape, not only by colour.** The rose is in colour only while connected; otherwise it is grey with a corner badge: an arc while connecting, a lock when the kill switch keeps the internet closed, "!" when connecting failed, "×" when the Rosetun service is not running. The tooltip for the last one says "Service unavailable".
- **One rose everywhere.** The header and Settings › About show the same rose as the app icon and the tray.
- **Settings › Connection › Local network.** Your router, printer and other devices on your network are reached directly, past the tunnel; DNS on the local network stays closed. Off by default; turn it off on public networks. A change while connected applies at the next connection. From the command line: `rosetun lan on` or `rosetun lan off`.
- **Rules by IP address.** The rule dialog has an "IP address" tab: IPv4 and IPv6 addresses or subnets, one per line. A subnet written with host bits (such as `192.0.2.5/24`) gets a **Fix** button, and addresses of the local network get a hint that points to the new Local network setting.
- **Lists are not downloaded again when they have not changed.** Rosetun asks the server first (`ETag` / `Last-Modified`), so updating subscriptions no longer fetches large lists such as `geosite.dat` every time.
- **Names in Task Manager.** The app shows as "Rosetun" and the service as "Rosetun Service"; the files also carry their version. sing-box and Xray keep their own names.

## Known issues

- If you switch between networks (for example Wi-Fi and cable) while connected through Xray, the connection may stop until Rosetun reconnects.

## Install

Windows 10 or 11, x64. Download `{{setup}}` from this release. The installer is not code-signed yet: if SmartScreen says "Windows protected your PC", select **More info** and then **Run anyway**.

## Verify

Run `Get-FileHash .\{{setup}} -Algorithm SHA256` and compare the result with `{{sha256}}` (also in `SHA256SUMS.txt`). Verify its provenance with `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

## Included

Rosetun includes the unmodified official sing-box {{sing_box_version}} build, licensed under GPL-3.0-or-later. The corresponding source is attached as `sing-box-{{sing_box_version}}-source.tar.gz`.

Rosetun includes the unmodified official Xray-core {{xray_version}} build, licensed under MPL-2.0. The corresponding source is attached as `xray-{{xray_version}}-source.tar.gz`; the license is installed in `licenses/`. Xray's `geoip.dat` and `geosite.dat` are not installed.

The executable embeds Wintun {{wintun_version}}, distributed under the Wintun Prebuilt Binaries License; the license and notice are installed in `licenses/wintun-prebuilt-binaries-license.txt` and `licenses/wintun.txt`.

## Русский

Вторая альфа-версия 0.2: небольшие заметные улучшения поверх поддержки Xray из 0.2.0-alpha.1. Она для тех, кто готов тестировать; если нужна спокойная версия, оставайтесь на бете 0.1: она продолжает получать исправления (0.1.0-beta.2 и новее её не предлагают; 0.1.0-beta.1 и 0.2.0-alpha.1 предлагают). Сообщайте о проблемах в [Issues](https://github.com/eoftgge/rosetun/issues), а об уязвимостях приватно через [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

**Вернуться на 0.1 можно только вручную.** 0.2 переводит файл настроек на новый формат, а 0.1 отказывается читать файл более новой версии и не перезаписывает его. Прежние настройки Rosetun сохраняет рядом, в `%APPDATA%\Rosetun\config.v3.json`: чтобы вернуться на бету, установите её и переименуйте этот файл в `config.json`. Изменения, сделанные в 0.2, при этом не переносятся.

### Что изменилось

- **Значок в трее показывает состояние формой, а не только цветом.** Роза цветная только при подключении; в остальных состояниях она серая, а в углу значок: дуга при подключении, замок, когда kill switch держит интернет закрытым, «!», когда подключиться не удалось, «×», когда служба Rosetun не запущена. Подсказка в последнем случае: «Служба недоступна».
- **Одна роза везде.** В шапке и в «Настройки › О программе» та же роза, что на значке программы и в трее.
- **Настройки › Подключение › Локальная сеть.** Роутер, принтер и другие устройства в вашей сети доступны напрямую, мимо туннеля; DNS в локальной сети остаётся закрытым. По умолчанию выключено; в общественных сетях лучше выключить. Если изменить во время подключения, применится при следующем подключении. Из командной строки: `rosetun lan on` или `rosetun lan off`.
- **Правила по IP-адресам.** В окне правила появилась вкладка «IP-адрес»: адреса или подсети IPv4 и IPv6, по одному на строку. Для подсети с битами хоста (например, `192.0.2.5/24`) есть кнопка **Исправить**, а для адресов локальной сети подсказка со ссылкой на новую настройку «Локальная сеть».
- **Неизменившиеся списки больше не скачиваются заново.** Rosetun сначала спрашивает сервер (`ETag` / `Last-Modified`), поэтому обновление подписок не качает каждый раз большие списки вроде `geosite.dat`.
- **Названия в диспетчере задач.** Программа видна как «Rosetun», служба как «Rosetun Service»; у файлов также указана версия. sing-box и Xray остаются под своими именами.

### Известные проблемы

- Если во время подключения через Xray сменить сеть (например, Wi-Fi на кабель), соединение может прерваться, пока Rosetun не переподключится.

### Установка

Windows 10 или 11, x64. Скачайте `{{setup}}` из этого релиза. Установщик пока не подписан: если SmartScreen показывает «Windows protected your PC», нажмите **More info**, затем **Run anyway**.

### Проверка

Выполните `Get-FileHash .\{{setup}} -Algorithm SHA256` и сравните результат с `{{sha256}}` (он также указан в `SHA256SUMS.txt`). Проверьте происхождение командой `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

### Состав

Rosetun включает официальную сборку sing-box {{sing_box_version}} без изменений, лицензия GPL-3.0-or-later. Соответствующие исходники приложены в архиве `sing-box-{{sing_box_version}}-source.tar.gz`.

Rosetun включает официальную сборку Xray-core {{xray_version}} без изменений, лицензия MPL-2.0. Соответствующие исходники приложены в архиве `xray-{{xray_version}}-source.tar.gz`; текст лицензии устанавливается в `licenses/`. Файлы Xray `geoip.dat` и `geosite.dat` не устанавливаются.

Исполняемый файл содержит Wintun {{wintun_version}}, который распространяется по лицензии Wintun Prebuilt Binaries License; текст лицензии и уведомление устанавливаются в `licenses/wintun-prebuilt-binaries-license.txt` и `licenses/wintun.txt`.
