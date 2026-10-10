# Rosetun {{version}}

This is an alpha release. Bugs are expected. Report them in [Issues](https://github.com/eoftgge/rosetun/issues); report vulnerabilities privately through [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

## What's new

- **Clearer connection failures.** While connecting, Rosetun shows the current step and how long it has taken, and **Cancel** stops the attempt. When a connection fails, it says why: the server is not responding, rejected the connection, closed it, or did not respond in time, or the engine did not start in time. If another VPN is enabled, or a program that filters traffic (`winws.exe` or `goodbyedpi.exe`) is running, the error names it and says what to do.
- **More reliable connects.** Rosetun waits for Windows to remove the previous tunnel adapter before starting again; a reconnect right after a failure could hang before. It allows more time when Windows creates the adapter slowly. The connection check through the server waits up to a minute for a slow server, but gives up early when the server clearly fails.
- **Rule and DNS edits apply when you leave the tab.** While connected, edits no longer wait for a button: they apply when you leave **Rules** or **Settings**, or hide the window. **Apply now** applies them at once. If they cannot be applied, Rosetun brings back the previous rules and DNS, both in the tunnel and in the settings, and **Restore my edits** returns your edits so you can fix them.
- **Select several rules.** Ctrl+click and Shift+click select several rules, Ctrl+A selects all shown. Selected rules can be dragged together, moved with **Move to top** and **Move to end**, or deleted with **Delete selected**. Esc clears the selection; Delete asks to delete the selected rules.
- **Install folder.** On a first install you can choose another folder on a local drive. The installer checks that standard users cannot change it or the folders above it, because the service runs from it with SYSTEM rights, and names the folder that fails the check. Upgrades keep the previous folder.
- **Delete your data on uninstall.** The uninstaller offers **Also delete settings, subscriptions and rules**. Other users' data on the computer stays.
- **Privacy.** Engine messages in the log no longer contain site addresses unless **Verbose log** is on.
- The connect button now blooms in layers when connected. The petals in the header are fainter.

Settings, subscriptions and rules from 0.1.0-alpha.4 are kept. The settings format has not changed, so going back to 0.1.0-alpha.4 keeps them too.

## Install

Windows 10 or 11, x64. Download `{{setup}}` from this release. The installer is not code-signed yet: if SmartScreen says "Windows protected your PC", select **More info** and then **Run anyway**.

## Verify

Run `Get-FileHash .\{{setup}} -Algorithm SHA256` and compare the result with `{{sha256}}` (also in `SHA256SUMS.txt`). Verify its provenance with `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

## Included

Rosetun includes the unmodified official sing-box {{sing_box_version}} build, licensed under GPL-3.0-or-later. The corresponding source is attached as `sing-box-{{sing_box_version}}-source.tar.gz`.

## Русский

Это альфа-версия. Ошибки возможны. Сообщайте о них в [Issues](https://github.com/eoftgge/rosetun/issues), а об уязвимостях сообщайте приватно через [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

### Что нового

- **Понятные ошибки подключения.** Во время подключения Rosetun показывает текущий шаг и сколько он длится, а **Отменить** останавливает попытку. Если подключиться не удалось, Rosetun пишет почему: сервер не отвечает, отклонил подключение, закрыл соединение или не ответил вовремя, или ядро не успело запуститься. Если включён другой VPN или запущена программа, которая фильтрует трафик (`winws.exe` или `goodbyedpi.exe`), в ошибке названа она и сказано, что сделать.
- **Надёжнее подключение.** Перед новым запуском Rosetun ждёт, пока Windows уберёт прошлый адаптер туннеля; раньше переподключение сразу после ошибки могло зависнуть. Если Windows создаёт адаптер медленно, Rosetun ждёт дольше. Проверка связи через сервер ждёт медленный сервер до минуты, но заканчивается раньше, если сервер явно не работает.
- **Правки правил и DNS применяются, когда вы уходите с вкладки.** При подключении правки больше не ждут кнопки: они применяются, когда вы уходите с вкладки **Правила** или **Настройки** или скрываете окно. **Применить сейчас** применяет их сразу. Если применить не получилось, Rosetun возвращает прежние правила и DNS и в туннеле, и в настройках, а **Вернуть мои правки** возвращает ваши правки, чтобы их можно было исправить.
- **Выделение нескольких правил.** Ctrl+щелчок и Shift+щелчок выделяют несколько правил, Ctrl+A выделяет все показанные. Выделенные правила можно перетащить вместе, переместить кнопками **В начало** и **В конец** или удалить кнопкой **Удалить выбранные**. Esc снимает выделение, Delete предлагает удалить выделенные.
- **Папка установки.** При первой установке можно выбрать другую папку на локальном диске. Установщик проверяет, что обычные пользователи не могут менять её и папки выше, потому что служба запускается из неё с правами SYSTEM, и называет папку, которая не прошла проверку. При обновлении папка остаётся прежней.
- **Удаление данных вместе с программой.** При удалении Rosetun предлагает **Также удалить настройки, подписки и правила**. Данные других пользователей компьютера остаются.
- **Приватность.** Сообщения ядра в журнале больше не содержат адресов сайтов, если не включён **Подробный журнал**.
- Кнопка подключения теперь раскрывается слоями, как роза. Лепестки в заголовке стали бледнее.

Настройки, подписки и правила из 0.1.0-alpha.4 сохраняются. Формат настроек не изменился, поэтому при возврате на 0.1.0-alpha.4 они тоже сохранятся.

### Установка

Windows 10 или 11, x64. Скачайте `{{setup}}` из этого релиза. Установщик пока не подписан: если SmartScreen показывает «Windows protected your PC», нажмите **More info**, затем **Run anyway**.

### Проверка

Выполните `Get-FileHash .\{{setup}} -Algorithm SHA256` и сравните результат с `{{sha256}}` (он также указан в `SHA256SUMS.txt`). Проверьте происхождение командой `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

### Состав

Rosetun включает официальную сборку sing-box {{sing_box_version}} без изменений, лицензия GPL-3.0-or-later. Соответствующие исходники приложены в архиве `sing-box-{{sing_box_version}}-source.tar.gz`.
