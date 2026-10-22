# Rosetun {{version}}

An early test build of Rosetun 0.3. Its two main features are ready to try: **Lockdown**, no internet without the tunnel, also while disconnected, after a restart and if the Rosetun service stops; and the **Traffic** tab with the live list of connections, where each one goes and why. This is an alpha for testing; **0.2.0 stays the supported release**, and Rosetun 0.2.0 does not offer this build as an update.

Settings move to a new format (see What's new); 0.2.0 cannot read the new one. Please report what breaks in [Issues](https://github.com/eoftgge/rosetun/issues); report vulnerabilities privately through [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

**Turn Lockdown off before going back to 0.2.0.** 0.2.0 does not know Lockdown: it can neither remove it nor connect while it is on, and the computer stays offline. If you already went back, install this build again and turn Lockdown off, or run `rosetun reset-firewall` from it as administrator. Uninstalling this build removes Lockdown too. **Your settings:** 0.2.0 cannot read settings saved by this build. The previous file is kept next to them as `%APPDATA%\Rosetun\config.v5.json`; to go back, close Rosetun and rename it to `config.json` (changes made in this build are lost).

## What's new in 0.3 so far

- **Lockdown**, experimental (the **Protection** card on the connection screen, and Settings › Connection; tested on Windows 11 only, see Known issues). Rosetun keeps its own Windows firewall filters that block everything outside the tunnel: while disconnected, after a restart (from boot, before you sign in to Windows) and if the service stops or crashes. Without Lockdown the kill switch still works as before, only while the service runs.
  - While Lockdown is on, the **Kill switch** is always on, and incoming connections are blocked too, except from your network when **Local network** is on.
  - Without a connection, Rosetun itself can still update subscriptions and lists, check servers and connect; other programs cannot. Rosetun then looks up names with its own DNS queries to your network's DNS servers, so the lookups of other programs stay closed. Your subscription provider sees your real IP address, as without Lockdown.
  - Turning it on and off asks for confirmation; the dialog for turning it on says how to get out.
  - **The way out:** turn Lockdown off in Rosetun. If Rosetun does not open or work, run `rosetun reset-firewall` in a terminal as administrator. Uninstalling Rosetun removes Lockdown; if it cannot, the uninstaller stops and keeps Rosetun, so you are never left offline without a way back. Updating Rosetun keeps Lockdown on.
  - From the command line: `rosetun lockdown on`, `rosetun lockdown off`, `rosetun reset-firewall`.
  - The tray shows "blocked" while Lockdown keeps a disconnected computer offline, and **Collect report** includes whether Lockdown is on.
- **Connections on the Traffic tab.** While you are connected, the tab lists what your programs connect to right now and what closed while the tab was open.
  - **By program** (named as the program names itself, for example "Google Chrome") or **all connections**; a filter by route (through the VPN, direct, or one of your exits) and a search by program or address.
  - Select a connection for its details: route, **why it took that route** (which rule, template or list matched, or that no rule did and the default applied), address, program, start time, data and speed.
  - From there: **create a rule** for that site or program in one click, or **close the connection** (the program usually opens it again at once).
  - The list is kept only in memory, only for the Windows account that connected, and is cleared when you disconnect. It is never written to disk or to the log and is not part of **Collect report**. Connections that rules block are not shown, and very short ones can be missed.
  - From the command line: `rosetun connections` and `rosetun connections close <id>`.
- **Failure details.** Under a connection error, **Details** shows the technical reason with a **Copy** button. Server and site addresses are removed from it, so it is safe to paste into an issue.
- **Clearer states.** "Connecting…" and "Reconnecting…" show that Rosetun is waiting. When the Rosetun service is not running, the connection screen says "Connection unavailable" in red instead of a grey "State unknown".
- **The tray rose** has a thin dark outline, so it stays visible on a red or light taskbar, and is drawn at the taskbar's own size, so it is sharp at any display scale. In the taskbar, Start and Alt+Tab the rose sits on a dark plate.
- **Privacy fixes.** Some sing-box error lines put site addresses into the Rosetun service log even with the detailed log off; now every public address is hidden there. **Collect report** now also hides an address that is followed by a colon, as in error messages.
- **sing-box {{sing_box_version}} and Xray {{xray_version}}.** The Xray project withdrew the release that 0.3.0-alpha.1 included.
- **Disconnecting removes the tunnel adapter at once.** Rosetun now stops sing-box gracefully instead of killing it, so Windows no longer has to clean up a leftover adapter, and the next connection does not wait for it.
- **The first connection after starting Windows** no longer fails when Windows Defender is slow to check sing-box, also after a power loss. While Rosetun waits for that check, the connection screen and the tray say so.
- **"Server name not found"** instead of "could not set up routing" when the server's address cannot be looked up; it no longer suggests turning off another VPN.
- **Dialog buttons are on the right**, the main one last, in every dialog.
- **XHTTP servers** (also known as SplitHTTP) connect through Xray, also for server checks; with "Connection through Xray" set to "Without Xray", Rosetun says before connecting that such a server needs Xray and offers **Connect through Xray**. Servers with a separate download server are still skipped and named in the subscription report.
- **Settings format 6.** Settings are converted when this build first saves them, and the previous file stays as `config.v5.json`; an older Rosetun, 0.2.0 included, refuses to read the new format and does not overwrite it.

## Known issues

- If you switch between networks (for example Wi-Fi and cable) while connected through Xray, the connection may stop until Rosetun reconnects.
- **Lockdown is new and has been tested on Windows 11 only**, on a clean system and on one everyday computer. Not tested yet: Windows 10, other firewalls or antivirus programs with their own network filters, and sleep or hibernation with Lockdown on.
- **With Lockdown on, Wi-Fi with a sign-in page** (a hotel or a café) cannot open its page, and **Windows cannot set the clock** without the tunnel. Turn Lockdown off for a moment, sign in or correct the clock, connect, and turn it on again.
- **Lockdown leaves Hyper-V virtual machines on this computer without network**, and most likely WSL2, Docker Desktop, Windows Sandbox and Mobile hotspot too. Turn Lockdown off while you need them.

## Install

Windows 10 or 11, x64. Download `{{setup}}` from this release. [Code signing policy](https://github.com/eoftgge/rosetun/blob/master/CODE_SIGNING_POLICY.md): the installer is not code-signed yet; if SmartScreen says "Windows protected your PC", select **More info** and then **Run anyway**.

## Verify

Run `Get-FileHash .\{{setup}} -Algorithm SHA256` and compare the result with `{{sha256}}` (also in `SHA256SUMS.txt`). Verify its provenance with `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

## Included

Rosetun includes the unmodified official sing-box {{sing_box_version}} build, licensed under GPL-3.0-or-later. The corresponding source is attached as `sing-box-{{sing_box_version}}-source.tar.gz`.

Rosetun includes the unmodified official Xray-core {{xray_version}} build, licensed under MPL-2.0. The corresponding source is attached as `xray-{{xray_version}}-source.tar.gz`; the license is installed in `licenses/`. Xray's `geoip.dat` and `geosite.dat` are not installed.

The executable embeds Wintun {{wintun_version}}, distributed under the Wintun Prebuilt Binaries License; the license and notice are installed in `licenses/wintun-prebuilt-binaries-license.txt` and `licenses/wintun.txt`.

## Русский

Ранняя тестовая сборка Rosetun 0.3. Две её главные функции уже можно попробовать. **Lockdown**: без туннеля интернета нет, и без подключения, и после перезагрузки, и если служба Rosetun остановится. Вкладка **Трафик** с живым списком соединений: куда идёт каждое и почему. Это альфа для тестирования; **поддерживаемый выпуск по-прежнему 0.2.0**, и Rosetun 0.2.0 не предлагает эту сборку как обновление.

Настройки переходят на новый формат (см. «Что нового»); 0.2.0 его прочитать не сможет. Сообщайте о проблемах в [Issues](https://github.com/eoftgge/rosetun/issues), а об уязвимостях приватно через [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

**Перед возвратом на 0.2.0 выключите Lockdown.** 0.2.0 не знает про Lockdown: она не может ни снять его, ни подключиться, пока он включён, и компьютер остаётся без сети. Если вы уже вернулись, установите эту сборку снова и выключите Lockdown или выполните её `rosetun reset-firewall` от имени администратора. Удаление этой сборки тоже снимает Lockdown. **Настройки:** 0.2.0 не читает настройки, сохранённые этой сборкой. Прежний файл лежит рядом как `%APPDATA%\Rosetun\config.v5.json`; чтобы вернуться, закройте Rosetun и переименуйте его в `config.json` (изменения, сделанные в этой сборке, пропадут).

### Что нового в 0.3 на сейчас

- **Lockdown**, экспериментальный (карточка **Защита** на экране подключения и «Настройки › Подключение»; проверен только на Windows 11, см. «Известные проблемы»). Rosetun держит собственные фильтры брандмауэра Windows, которые закрывают всё мимо туннеля: без подключения, после перезагрузки (с загрузки, ещё до входа в Windows) и если служба остановится или упадёт. Без Lockdown kill switch работает как раньше, только пока работает служба.
  - Пока Lockdown включён, **Kill switch** включён всегда, а входящие соединения тоже закрыты, кроме вашей сети при включённой **Локальной сети**.
  - Без подключения сам Rosetun по-прежнему может обновлять подписки и списки, проверять серверы и подключаться; другие программы нет. Имена Rosetun тогда ищет сам, своими запросами к DNS-серверам вашей сети, поэтому запросы других программ остаются закрыты. Провайдер подписки видит ваш настоящий IP-адрес, как и без Lockdown.
  - Включение и выключение требуют подтверждения; в окне включения написано, как выйти.
  - **Как выйти:** выключите Lockdown в Rosetun. Если Rosetun не открывается или не работает, выполните `rosetun reset-firewall` в терминале от имени администратора. Удаление Rosetun снимает Lockdown; если снять не удалось, удаление останавливается и оставляет Rosetun, так что вы не останетесь без сети и без выхода. Обновление Rosetun Lockdown не снимает.
  - Из командной строки: `rosetun lockdown on`, `rosetun lockdown off`, `rosetun reset-firewall`.
  - Значок в трее показывает «заблокировано», пока Lockdown держит отключённый компьютер без сети, а **Собрать отчёт** указывает, включён ли Lockdown.
- **Соединения на вкладке «Трафик».** Пока вы подключены, вкладка показывает, куда сейчас подключаются ваши программы и что закрылось, пока вкладка была открыта.
  - **По приложениям** (с именем, как программа называет себя сама, например «Google Chrome») или **все соединения**; фильтр по маршруту (через VPN, напрямую или одно из ваших направлений) и поиск по программе или адресу.
  - Нажмите на соединение, чтобы увидеть подробности: маршрут, **почему он такой** (какое правило, шаблон или список подошёл, или что не подошло ни одно и сработало правило по умолчанию), адрес, программа, время начала, объём и скорость.
  - Оттуда же: **создать правило** для этого сайта или программы в одно нажатие или **закрыть соединение** (программа обычно сразу открывает его заново).
  - Список хранится только в памяти, только для учётной записи Windows, которая подключилась, и очищается при отключении. Он не пишется ни на диск, ни в журнал и не входит в **Собрать отчёт**. Соединения, заблокированные правилами, не показываются, а очень короткие могут не попасть в список.
  - Из командной строки: `rosetun connections` и `rosetun connections close <id>`.
- **Подробности ошибки.** Под ошибкой подключения **Подробнее** показывает технический текст с кнопкой **Копировать**. Адреса серверов и сайтов из него убраны, его можно вставлять в issue.
- **Понятнее состояния.** «Подключение…» и «Переподключение…» показывают, что Rosetun ждёт. Когда служба Rosetun не запущена, экран подключения пишет красное «Подключение недоступно» вместо серого «Состояние неизвестно».
- **Роза в трее** получила тонкий тёмный контур, чтобы её было видно на красной и светлой панели задач, и рисуется в размере самой панели, поэтому чёткая при любом масштабе. На панели задач, в «Пуске» и в Alt+Tab роза лежит на тёмной подложке.
- **Исправления приватности.** Некоторые строки ошибок sing-box попадали в журнал службы Rosetun с адресами сайтов даже при выключенном подробном журнале; теперь там скрыт любой публичный адрес. **Собрать отчёт** теперь скрывает и адрес, за которым идёт двоеточие, как в текстах ошибок.
- **sing-box {{sing_box_version}} и Xray {{xray_version}}.** Проект Xray отозвал выпуск, который был в 0.3.0-alpha.1.
- **Отключение сразу убирает адаптер туннеля.** Теперь Rosetun останавливает sing-box штатно, а не убивает его, поэтому Windows не приходится убирать оставшийся адаптер, и следующее подключение его не ждёт.
- **Первое подключение после запуска Windows** больше не срывается, когда Защитник Windows долго проверяет sing-box.
- **«Не удалось найти адрес сервера»** вместо «не удалось настроить маршрутизацию», когда адрес сервера не находится; совета выключить другой VPN при этом больше нет.
- **Кнопки окон справа**, основная крайняя, во всех окнах.
- **Серверы XHTTP** (он же SplitHTTP) подключаются через Xray, проверка серверов тоже; при «Без Xray» в «Подключение через Xray» Rosetun ещё до подключения говорит, что такому серверу нужен Xray, и предлагает **Подключить через Xray**. Серверы с отдельным сервером загрузки пока пропускаются и называются в отчёте о подписке.
- **Формат настроек 6.** Настройки преобразуются, когда эта сборка впервые их сохраняет, а прежний файл остаётся как `config.v5.json`; более старый Rosetun, в том числе 0.2.0, новый формат читать откажется и не перезапишет его.

### Известные проблемы

- Если во время подключения через Xray сменить сеть (например, Wi-Fi на кабель), соединение может прерваться, пока Rosetun не переподключится.
- **Lockdown новый и проверен только на Windows 11**, на чистой системе и на одном рабочем компьютере. Ещё не проверены: Windows 10, другие брандмауэры и антивирусы со своими сетевыми фильтрами, сон и гибернация с включённым Lockdown.
- **При включённом Lockdown Wi-Fi со входом через страницу** (гостиница, кафе) не откроет свою страницу, а **Windows не сможет выставить время** без туннеля. Выключите Lockdown на время, войдите или поправьте часы, подключитесь и включите его снова.
- **Lockdown оставляет без сети виртуальные машины Hyper-V на этом компьютере**, а скорее всего и WSL2, Docker Desktop, «Песочницу Windows» и мобильный хот-спот. Выключите Lockdown, пока они нужны.

### Установка

Windows 10 или 11, x64. Скачайте `{{setup}}` из этого релиза. [Политика подписи кода](https://github.com/eoftgge/rosetun/blob/master/CODE_SIGNING_POLICY.md) (Code signing policy): установщик пока не подписан; если SmartScreen показывает «Windows protected your PC», нажмите **More info**, затем **Run anyway**.

### Проверка

Выполните `Get-FileHash .\{{setup}} -Algorithm SHA256` и сравните результат с `{{sha256}}` (он также указан в `SHA256SUMS.txt`). Проверьте происхождение командой `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

### Состав

Rosetun включает официальную сборку sing-box {{sing_box_version}} без изменений, лицензия GPL-3.0-or-later. Соответствующие исходники приложены в архиве `sing-box-{{sing_box_version}}-source.tar.gz`.

Rosetun включает официальную сборку Xray-core {{xray_version}} без изменений, лицензия MPL-2.0. Соответствующие исходники приложены в архиве `xray-{{xray_version}}-source.tar.gz`; текст лицензии устанавливается в `licenses/`. Файлы Xray `geoip.dat` и `geosite.dat` не устанавливаются.

Исполняемый файл содержит Wintun {{wintun_version}}, который распространяется по лицензии Wintun Prebuilt Binaries License; текст лицензии и уведомление устанавливаются в `licenses/wintun-prebuilt-binaries-license.txt` и `licenses/wintun.txt`.
