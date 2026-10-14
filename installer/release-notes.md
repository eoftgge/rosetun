# Rosetun {{version}}

This is the second beta of 0.1: fixes only. Please keep using it every day and report what breaks in [Issues](https://github.com/eoftgge/rosetun/issues); report vulnerabilities privately through [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

## What's changed

- **The country in the header is the server's.** With the default "Direct" rule the header could show the country of your own connection instead of the server's. The lookup now always goes through the tunnel.
- **The main screen no longer shows the server address.** It often ends up in screenshots, and published server addresses get blocked. The address is still in the server list.
- **First connection after installing.** When Windows was slow to set up the tunnel adapter, a single failed server check right after the waiting time could still stop the connection. Checks that failed while the adapter was being set up no longer count.
- **Update notices follow your version.** A beta now offers newer betas and the release, not test versions of the next release. A release offers releases only.
- **`rosetun connect`** prints `connected` when the tunnel is up.

## Known issue: REALITY servers on Xray 26.9.8 and newer

VLESS + REALITY servers updated to Xray 26.9.8 or newer refuse connections from sing-box, the engine Rosetun uses ([SagerNet/sing-box#4520](https://github.com/SagerNet/sing-box/issues/4520)). Rosetun then says the server rejected the connection and explains why. Try another server or ask your provider. Rosetun 0.2 will connect these servers through Xray.

## Help wanted: IPv6

If your provider gives you IPv6, connect and open [test-ipv6.com](https://test-ipv6.com). It should show no IPv6 address. Please report what it shows in [Issues](https://github.com/eoftgge/rosetun/issues).

Settings, subscriptions, lists and rules from 0.1.0-beta.1 are kept as they are; older versions are upgraded on the first start as before. The app and the service are updated together by the installer.

## Install

Windows 10 or 11, x64. Download `{{setup}}` from this release. The installer is not code-signed yet: if SmartScreen says "Windows protected your PC", select **More info** and then **Run anyway**.

## Verify

Run `Get-FileHash .\{{setup}} -Algorithm SHA256` and compare the result with `{{sha256}}` (also in `SHA256SUMS.txt`). Verify its provenance with `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

## Included

Rosetun includes the unmodified official sing-box {{sing_box_version}} build, licensed under GPL-3.0-or-later. The corresponding source is attached as `sing-box-{{sing_box_version}}-source.tar.gz`.

The executable embeds Wintun {{wintun_version}}, distributed under the Wintun Prebuilt Binaries License; the license and notice are installed in `licenses/wintun-prebuilt-binaries-license.txt` and `licenses/wintun.txt`.

## Русский

Это вторая бета-версия 0.1, только исправления. Пользуйтесь ей каждый день и сообщайте о проблемах в [Issues](https://github.com/eoftgge/rosetun/issues), а об уязвимостях сообщайте приватно через [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

### Что изменилось

- **Страна в шапке теперь страна сервера.** С правилом по умолчанию «Напрямую» шапка могла показывать страну вашего собственного подключения, а не сервера. Теперь запрос всегда идёт через туннель.
- **Главный экран больше не показывает адрес сервера.** Он часто попадает на снимки экрана, а опубликованные адреса серверов блокируют. Адрес по-прежнему есть в списке серверов.
- **Первое подключение после установки.** Если Windows долго настраивала адаптер туннеля, одна неудачная проверка сервера сразу после ожидания всё ещё могла прервать подключение. Проверки, которые не прошли, пока адаптер настраивался, больше не учитываются.
- **Уведомления об обновлениях учитывают вашу версию.** Бета предлагает более новые беты и выпуск, но не тестовые версии следующего выпуска. Выпуск предлагает только выпуски.
- **`rosetun connect`** пишет `connected`, когда туннель поднят.

### Известная проблема: серверы REALITY на Xray 26.9.8 и новее

Серверы VLESS + REALITY, обновлённые до Xray 26.9.8 или новее, не принимают подключения от sing-box, на котором работает Rosetun ([SagerNet/sing-box#4520](https://github.com/SagerNet/sing-box/issues/4520)). Rosetun в этом случае пишет, что сервер отклонил подключение, и объясняет почему. Попробуйте другой сервер или напишите провайдеру. Rosetun 0.2 будет подключать такие серверы через Xray.

### Нужна помощь: IPv6

Если провайдер даёт вам IPv6, подключитесь и откройте [test-ipv6.com](https://test-ipv6.com). Адреса IPv6 там быть не должно. Пожалуйста, сообщите, что показала страница, в [Issues](https://github.com/eoftgge/rosetun/issues).

Настройки, подписки, списки и правила из 0.1.0-beta.1 сохраняются как есть; более старые версии, как и раньше, обновляются при первом запуске. Программу и службу установщик обновляет вместе.

### Установка

Windows 10 или 11, x64. Скачайте `{{setup}}` из этого релиза. Установщик пока не подписан: если SmartScreen показывает «Windows protected your PC», нажмите **More info**, затем **Run anyway**.

### Проверка

Выполните `Get-FileHash .\{{setup}} -Algorithm SHA256` и сравните результат с `{{sha256}}` (он также указан в `SHA256SUMS.txt`). Проверьте происхождение командой `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

### Состав

Rosetun включает официальную сборку sing-box {{sing_box_version}} без изменений, лицензия GPL-3.0-or-later. Соответствующие исходники приложены в архиве `sing-box-{{sing_box_version}}-source.tar.gz`.

Исполняемый файл содержит Wintun {{wintun_version}}, который распространяется по лицензии Wintun Prebuilt Binaries License; текст лицензии и уведомление устанавливаются в `licenses/wintun-prebuilt-binaries-license.txt` и `licenses/wintun.txt`.
