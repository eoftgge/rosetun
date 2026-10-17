# Rosetun {{version}}

The first release of Rosetun: a VPN client for Windows with rules for what goes through the tunnel, a kill switch and a Windows service, on sing-box. It is a young project with one developer: please report what breaks in [Issues](https://github.com/eoftgge/rosetun/issues); report vulnerabilities privately through [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

## What's changed since 0.1.0-beta.2

- **REALITY rejections are recognised in every case.** When a REALITY server refused the connection while only DNS was passing, sing-box reported it without the outbound's name and Rosetun did not count it; now it does, so the connection stops with the explanation instead of waiting for the timeout.
- **The README and the security policy** say what is supported: the latest 0.1.x release, not test versions of the next one. The kill switch works while the Rosetun service is running; the README says so next to it.

Everything from 0.1.0-beta.1 and beta.2 is included.

## Known issues

- **REALITY servers on Xray 26.9.8 and newer** refuse connections from sing-box, the engine Rosetun uses ([SagerNet/sing-box#4520](https://github.com/SagerNet/sing-box/issues/4520)). Rosetun then says the server rejected the connection and explains why. Try another server or ask your provider. Rosetun 0.2 connects these servers through Xray.
- **"Apply" while connected failed once with an engine error** on an early test version, and the cause was not found. If it happens to you, please open an issue with the lines of `%ProgramFiles%\Rosetun\data\logs\helper*.log` around the error (remove server addresses first).

## Help wanted: IPv6

If your provider gives you IPv6, connect and open [test-ipv6.com](https://test-ipv6.com). It should show no IPv6 address. Please report what it shows in [Issues](https://github.com/eoftgge/rosetun/issues).

Settings, subscriptions, lists and rules from the betas are kept as they are; older versions are upgraded on the first start as before. The app and the service are updated together by the installer.

## Install

Windows 10 or 11, x64. Download `{{setup}}` from this release. The installer is not code-signed yet: if SmartScreen says "Windows protected your PC", select **More info** and then **Run anyway**.

## Verify

Run `Get-FileHash .\{{setup}} -Algorithm SHA256` and compare the result with `{{sha256}}` (also in `SHA256SUMS.txt`). Verify its provenance with `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

## Included

Rosetun includes the unmodified official sing-box {{sing_box_version}} build, licensed under GPL-3.0-or-later. The corresponding source is attached as `sing-box-{{sing_box_version}}-source.tar.gz`.

The executable embeds Wintun {{wintun_version}}, distributed under the Wintun Prebuilt Binaries License; the license and notice are installed in `licenses/wintun-prebuilt-binaries-license.txt` and `licenses/wintun.txt`.

## Русский

Первый выпуск Rosetun: VPN-клиент для Windows с правилами, что идёт через туннель, с kill switch и службой Windows, на sing-box. Проект молодой, его ведёт один разработчик: сообщайте о проблемах в [Issues](https://github.com/eoftgge/rosetun/issues), а об уязвимостях приватно через [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

### Что изменилось после 0.1.0-beta.2

- **Отказ сервера REALITY распознаётся всегда.** Если сервер REALITY отклонял подключение, пока шёл только DNS, sing-box сообщал об этом без имени выхода, и Rosetun это не учитывал; теперь учитывает, и подключение останавливается с объяснением, а не ждёт тайм-аута.
- **README и политика безопасности** говорят, что поддерживается: последний выпуск 0.1.x, а не тестовые версии следующего. Kill switch работает, пока запущена служба Rosetun; README говорит об этом рядом с ним.

Всё из 0.1.0-beta.1 и beta.2 входит в этот выпуск.

### Известные проблемы

- **Серверы REALITY на Xray 26.9.8 и новее** не принимают подключения от sing-box, на котором работает Rosetun ([SagerNet/sing-box#4520](https://github.com/SagerNet/sing-box/issues/4520)). Rosetun в этом случае пишет, что сервер отклонил подключение, и объясняет почему. Попробуйте другой сервер или напишите провайдеру. Rosetun 0.2 подключает такие серверы через Xray.
- **«Применить» при подключении однажды не сработало** с ошибкой ядра на ранней тестовой версии, причину найти не удалось. Если это случится у вас, откройте Issue и приложите строки из `%ProgramFiles%\Rosetun\data\logs\helper*.log` рядом с ошибкой (сначала уберите адреса серверов).

### Нужна помощь: IPv6

Если провайдер даёт вам IPv6, подключитесь и откройте [test-ipv6.com](https://test-ipv6.com). Адреса IPv6 там быть не должно. Пожалуйста, сообщите, что показала страница, в [Issues](https://github.com/eoftgge/rosetun/issues).

Настройки, подписки, списки и правила из бета-версий сохраняются как есть; более старые версии, как и раньше, обновляются при первом запуске. Программу и службу установщик обновляет вместе.

### Установка

Windows 10 или 11, x64. Скачайте `{{setup}}` из этого релиза. Установщик пока не подписан: если SmartScreen показывает «Windows protected your PC», нажмите **More info**, затем **Run anyway**.

### Проверка

Выполните `Get-FileHash .\{{setup}} -Algorithm SHA256` и сравните результат с `{{sha256}}` (он также указан в `SHA256SUMS.txt`). Проверьте происхождение командой `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

### Состав

Rosetun включает официальную сборку sing-box {{sing_box_version}} без изменений, лицензия GPL-3.0-or-later. Соответствующие исходники приложены в архиве `sing-box-{{sing_box_version}}-source.tar.gz`.

Исполняемый файл содержит Wintun {{wintun_version}}, который распространяется по лицензии Wintun Prebuilt Binaries License; текст лицензии и уведомление устанавливаются в `licenses/wintun-prebuilt-binaries-license.txt` и `licenses/wintun.txt`.
