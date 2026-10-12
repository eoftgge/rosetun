# Rosetun {{version}}

This is the first beta of 0.1. From here 0.1 only gets fixes, in further betas, until 0.1.0. Please use it every day and report what breaks in [Issues](https://github.com/eoftgge/rosetun/issues); report vulnerabilities privately through [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

## What's changed

- **Security.**
  - Another Windows account on the same computer can no longer disconnect your tunnel, change it or read its temporary rules. Only the account that connected it, or an administrator, can.
  - The service no longer lets programs that connect to it and then stay silent lock out the app and `rosetun`.
- **First connection after installing.** When Windows takes long to set up the tunnel adapter, Rosetun no longer gives up with "server unreachable" too early.
- **Server checks do not depend on one company.** The full check, the tunnel delay and the checks while connecting ask Cloudflare and Google at the same time, so a server whose exit cannot reach one of them still works. The DNS watchdog does the same.
- **Servers near the time limit** are no longer shown as not working by "Check servers" and "Delay".
- **The TCP ping** runs only when the tunnel is known to be down. Right after start it could show the same time for every server.
- **Lists.** Connecting with large lists is faster: each list is verified once. A damaged saved copy of a category no longer stops the connection; the rule is skipped with a warning.
- **Small windows and large scaling.** At 125 and 150 % the header shows tab icons, and the rules toolbar wraps to two rows instead of squeezing the action filter.
- **Layout fixes** in the list card and the category picker.

## Known issue: REALITY servers on Xray 26.9.8 and newer

VLESS + REALITY servers updated to Xray 26.9.8 or newer refuse connections from sing-box, the engine Rosetun uses ([SagerNet/sing-box#4520](https://github.com/SagerNet/sing-box/issues/4520)). Rosetun then says the server rejected the connection and explains why. Try another server or ask your provider. A fix is planned.

## Help wanted: IPv6

If your provider gives you IPv6, connect and open [test-ipv6.com](https://test-ipv6.com). It should show no IPv6 address. Please report what it shows in [Issues](https://github.com/eoftgge/rosetun/issues).

Settings, subscriptions, lists and rules from 0.1.0-alpha.6 are kept as they are; older versions are upgraded on the first start as before. The app and the service are updated together by the installer.

## Install

Windows 10 or 11, x64. Download `{{setup}}` from this release. The installer is not code-signed yet: if SmartScreen says "Windows protected your PC", select **More info** and then **Run anyway**.

## Verify

Run `Get-FileHash .\{{setup}} -Algorithm SHA256` and compare the result with `{{sha256}}` (also in `SHA256SUMS.txt`). Verify its provenance with `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

## Included

Rosetun includes the unmodified official sing-box {{sing_box_version}} build, licensed under GPL-3.0-or-later. The corresponding source is attached as `sing-box-{{sing_box_version}}-source.tar.gz`.

The executable embeds Wintun {{wintun_version}}, distributed under the Wintun Prebuilt Binaries License; the license and notice are installed in `licenses/wintun-prebuilt-binaries-license.txt` and `licenses/wintun.txt`.

## Русский

Это первая бета-версия 0.1. Дальше 0.1 получает только исправления, в следующих бетах, до выхода 0.1.0. Пользуйтесь ей каждый день и сообщайте о проблемах в [Issues](https://github.com/eoftgge/rosetun/issues), а об уязвимостях сообщайте приватно через [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

### Что изменилось

- **Безопасность.**
  - Другая учётная запись Windows на этом компьютере больше не может отключить ваш туннель, изменить его или прочитать его временные правила. Это может только учётная запись, которая его подключила, или администратор.
  - Программы, которые подключаются к службе и молчат, больше не могут заблокировать доступ к ней для приложения и `rosetun`.
- **Первое подключение после установки.** Если Windows долго настраивает адаптер туннеля, Rosetun больше не сдаётся раньше времени с ошибкой «сервер недоступен».
- **Проверка серверов не зависит от одной компании.** Полная проверка, задержка туннеля и проверки при подключении обращаются одновременно к Cloudflare и Google, поэтому сервер, выход которого не достаёт до одного из них, всё равно работает. Сторож DNS делает так же.
- **Серверы у предела времени ожидания** больше не показываются как неработающие в «Проверить серверы» и «Задержка».
- **TCP-пинг** запускается, только когда известно, что туннель выключен. Сразу после запуска он мог показывать одинаковое время у всех серверов.
- **Списки.** Подключение с большими списками быстрее: каждый список проверяется один раз. Повреждённая сохранённая копия категории больше не мешает подключиться; правило пропускается с предупреждением.
- **Маленькое окно и крупный масштаб.** При 125 и 150 % в шапке остаются значки вкладок, а панель правил переносится на две строки вместо того, чтобы сжимать фильтр действий.
- **Исправлена вёрстка** карточки списка и выбора категорий.

### Известная проблема: серверы REALITY на Xray 26.9.8 и новее

Серверы VLESS + REALITY, обновлённые до Xray 26.9.8 или новее, не принимают подключения от sing-box, на котором работает Rosetun ([SagerNet/sing-box#4520](https://github.com/SagerNet/sing-box/issues/4520)). Rosetun в этом случае пишет, что сервер отклонил подключение, и объясняет почему. Попробуйте другой сервер или напишите провайдеру. Исправление запланировано.

### Нужна помощь: IPv6

Если провайдер даёт вам IPv6, подключитесь и откройте [test-ipv6.com](https://test-ipv6.com). Адреса IPv6 там быть не должно. Пожалуйста, сообщите, что показала страница, в [Issues](https://github.com/eoftgge/rosetun/issues).

Настройки, подписки, списки и правила из 0.1.0-alpha.6 сохраняются как есть; более старые версии, как и раньше, обновляются при первом запуске. Программу и службу установщик обновляет вместе.

### Установка

Windows 10 или 11, x64. Скачайте `{{setup}}` из этого релиза. Установщик пока не подписан: если SmartScreen показывает «Windows protected your PC», нажмите **More info**, затем **Run anyway**.

### Проверка

Выполните `Get-FileHash .\{{setup}} -Algorithm SHA256` и сравните результат с `{{sha256}}` (он также указан в `SHA256SUMS.txt`). Проверьте происхождение командой `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

### Состав

Rosetun включает официальную сборку sing-box {{sing_box_version}} без изменений, лицензия GPL-3.0-or-later. Соответствующие исходники приложены в архиве `sing-box-{{sing_box_version}}-source.tar.gz`.

Исполняемый файл содержит Wintun {{wintun_version}}, который распространяется по лицензии Wintun Prebuilt Binaries License; текст лицензии и уведомление устанавливаются в `licenses/wintun-prebuilt-binaries-license.txt` и `licenses/wintun.txt`.
