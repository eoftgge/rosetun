# Rosetun {{version}}

An early test build of Rosetun 0.3. Its main feature, **Lockdown**, is ready to try: no internet without the tunnel, also while disconnected, after a restart and if the Rosetun service stops. This is an alpha for testing; **0.2.0 stays the supported release**, and Rosetun 0.2.0 does not offer this build as an update.

Settings keep their format, so nothing is converted. Please report what breaks in [Issues](https://github.com/eoftgge/rosetun/issues); report vulnerabilities privately through [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

**Turn Lockdown off before going back to 0.2.0.** 0.2.0 does not know Lockdown: it can neither remove it nor connect while it is on, and the computer stays offline. If you already went back, install this build again and turn Lockdown off, or run `rosetun reset-firewall` from it as administrator. Uninstalling this build removes Lockdown too.

## What's new in 0.3 so far

- **Lockdown** (the **Protection** card on the connection screen, and Settings › Connection). Rosetun keeps its own Windows firewall filters that block everything outside the tunnel: while disconnected, after a restart (from boot, before you sign in to Windows) and if the service stops or crashes. Without Lockdown the kill switch still works as before, only while the service runs.
  - While Lockdown is on, the **Kill switch** is always on, and incoming connections are blocked too, except from your network when **Local network** is on.
  - Without a connection, Rosetun itself can still update subscriptions and lists, check servers and connect; other programs cannot. Rosetun then looks up names with its own DNS queries to your network's DNS servers, so the lookups of other programs stay closed. Your subscription provider sees your real IP address, as without Lockdown.
  - Turning it on and off asks for confirmation; the dialog for turning it on says how to get out.
  - **The way out:** turn Lockdown off in Rosetun. If Rosetun does not open or work, run `rosetun reset-firewall` in a terminal as administrator. Uninstalling Rosetun removes Lockdown; if it cannot, the uninstaller stops and keeps Rosetun, so you are never left offline without a way back. Updating Rosetun keeps Lockdown on.
  - From the command line: `rosetun lockdown on`, `rosetun lockdown off`, `rosetun reset-firewall`.
  - The tray shows "blocked" while Lockdown keeps a disconnected computer offline, and **Collect report** includes whether Lockdown is on.
- **Disconnecting removes the tunnel adapter at once.** Rosetun now stops sing-box gracefully instead of killing it, so Windows no longer has to clean up a leftover adapter, and the next connection does not wait for it.
- **The first connection after starting Windows** no longer fails when Windows Defender is slow to check sing-box.
- **"Server name not found"** instead of "could not set up routing" when the server's address cannot be looked up; it no longer suggests turning off another VPN.
- **Dialog buttons are on the right**, the main one last, in every dialog.

## Known issues

- If you switch between networks (for example Wi-Fi and cable) while connected through Xray, the connection may stop until Rosetun reconnects.
- **Lockdown is new and has been tested on Windows 11 only**, on a clean system and on one everyday computer. Not tested yet: Windows 10, other firewalls or antivirus programs with their own network filters, and sleep or hibernation with Lockdown on.
- **With Lockdown on, Wi-Fi with a sign-in page** (a hotel or a café) cannot open its page, and **Windows cannot set the clock** without the tunnel. Turn Lockdown off for a moment, sign in or correct the clock, connect, and turn it on again.

## Install

Windows 10 or 11, x64. Download `{{setup}}` from this release. [Code signing policy](https://github.com/eoftgge/rosetun/blob/master/CODE_SIGNING_POLICY.md): the installer is not code-signed yet; if SmartScreen says "Windows protected your PC", select **More info** and then **Run anyway**.

## Verify

Run `Get-FileHash .\{{setup}} -Algorithm SHA256` and compare the result with `{{sha256}}` (also in `SHA256SUMS.txt`). Verify its provenance with `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

## Included

Rosetun includes the unmodified official sing-box {{sing_box_version}} build, licensed under GPL-3.0-or-later. The corresponding source is attached as `sing-box-{{sing_box_version}}-source.tar.gz`.

Rosetun includes the unmodified official Xray-core {{xray_version}} build, licensed under MPL-2.0. The corresponding source is attached as `xray-{{xray_version}}-source.tar.gz`; the license is installed in `licenses/`. Xray's `geoip.dat` and `geosite.dat` are not installed.

The executable embeds Wintun {{wintun_version}}, distributed under the Wintun Prebuilt Binaries License; the license and notice are installed in `licenses/wintun-prebuilt-binaries-license.txt` and `licenses/wintun.txt`.

## Русский

Ранняя тестовая сборка Rosetun 0.3. Её главную функцию, **Lockdown**, уже можно попробовать: без туннеля интернета нет, и без подключения, и после перезагрузки, и если служба Rosetun остановится. Это альфа для тестирования; **поддерживаемый выпуск по-прежнему 0.2.0**, и Rosetun 0.2.0 не предлагает эту сборку как обновление.

Формат настроек не изменился, ничего не преобразуется. Сообщайте о проблемах в [Issues](https://github.com/eoftgge/rosetun/issues), а об уязвимостях приватно через [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

**Перед возвратом на 0.2.0 выключите Lockdown.** 0.2.0 не знает про Lockdown: она не может ни снять его, ни подключиться, пока он включён, и компьютер остаётся без сети. Если вы уже вернулись, установите эту сборку снова и выключите Lockdown или выполните её `rosetun reset-firewall` от имени администратора. Удаление этой сборки тоже снимает Lockdown.

### Что нового в 0.3 на сейчас

- **Lockdown** (карточка **Защита** на экране подключения и «Настройки › Подключение»). Rosetun держит собственные фильтры брандмауэра Windows, которые закрывают всё мимо туннеля: без подключения, после перезагрузки (с загрузки, ещё до входа в Windows) и если служба остановится или упадёт. Без Lockdown kill switch работает как раньше, только пока работает служба.
  - Пока Lockdown включён, **Kill switch** включён всегда, а входящие соединения тоже закрыты, кроме вашей сети при включённой **Локальной сети**.
  - Без подключения сам Rosetun по-прежнему может обновлять подписки и списки, проверять серверы и подключаться; другие программы нет. Имена Rosetun тогда ищет сам, своими запросами к DNS-серверам вашей сети, поэтому запросы других программ остаются закрыты. Провайдер подписки видит ваш настоящий IP-адрес, как и без Lockdown.
  - Включение и выключение требуют подтверждения; в окне включения написано, как выйти.
  - **Как выйти:** выключите Lockdown в Rosetun. Если Rosetun не открывается или не работает, выполните `rosetun reset-firewall` в терминале от имени администратора. Удаление Rosetun снимает Lockdown; если снять не удалось, удаление останавливается и оставляет Rosetun, так что вы не останетесь без сети и без выхода. Обновление Rosetun Lockdown не снимает.
  - Из командной строки: `rosetun lockdown on`, `rosetun lockdown off`, `rosetun reset-firewall`.
  - Значок в трее показывает «заблокировано», пока Lockdown держит отключённый компьютер без сети, а **Собрать отчёт** указывает, включён ли Lockdown.
- **Отключение сразу убирает адаптер туннеля.** Теперь Rosetun останавливает sing-box штатно, а не убивает его, поэтому Windows не приходится убирать оставшийся адаптер, и следующее подключение его не ждёт.
- **Первое подключение после запуска Windows** больше не срывается, когда Защитник Windows долго проверяет sing-box.
- **«Не удалось найти адрес сервера»** вместо «не удалось настроить маршрутизацию», когда адрес сервера не находится; совета выключить другой VPN при этом больше нет.
- **Кнопки окон справа**, основная крайняя, во всех окнах.

### Известные проблемы

- Если во время подключения через Xray сменить сеть (например, Wi-Fi на кабель), соединение может прерваться, пока Rosetun не переподключится.
- **Lockdown новый и проверен только на Windows 11**, на чистой системе и на одном рабочем компьютере. Ещё не проверены: Windows 10, другие брандмауэры и антивирусы со своими сетевыми фильтрами, сон и гибернация с включённым Lockdown.
- **При включённом Lockdown Wi-Fi со входом через страницу** (гостиница, кафе) не откроет свою страницу, а **Windows не сможет выставить время** без туннеля. Выключите Lockdown на время, войдите или поправьте часы, подключитесь и включите его снова.

### Установка

Windows 10 или 11, x64. Скачайте `{{setup}}` из этого релиза. [Политика подписи кода](https://github.com/eoftgge/rosetun/blob/master/CODE_SIGNING_POLICY.md) (Code signing policy): установщик пока не подписан; если SmartScreen показывает «Windows protected your PC», нажмите **More info**, затем **Run anyway**.

### Проверка

Выполните `Get-FileHash .\{{setup}} -Algorithm SHA256` и сравните результат с `{{sha256}}` (он также указан в `SHA256SUMS.txt`). Проверьте происхождение командой `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

### Состав

Rosetun включает официальную сборку sing-box {{sing_box_version}} без изменений, лицензия GPL-3.0-or-later. Соответствующие исходники приложены в архиве `sing-box-{{sing_box_version}}-source.tar.gz`.

Rosetun включает официальную сборку Xray-core {{xray_version}} без изменений, лицензия MPL-2.0. Соответствующие исходники приложены в архиве `xray-{{xray_version}}-source.tar.gz`; текст лицензии устанавливается в `licenses/`. Файлы Xray `geoip.dat` и `geosite.dat` не устанавливаются.

Исполняемый файл содержит Wintun {{wintun_version}}, который распространяется по лицензии Wintun Prebuilt Binaries License; текст лицензии и уведомление устанавливаются в `licenses/wintun-prebuilt-binaries-license.txt` и `licenses/wintun.txt`.
