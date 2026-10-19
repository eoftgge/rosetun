# Rosetun {{version}}

Rosetun 0.2. Its goal: connect everywhere, and show what is going on. REALITY servers on new Xray connect again, a rule can send its sites or programs through another country or server, and Rosetun explains more of what goes wrong.

Rosetun 0.1.0 offers this release as an update. Settings from 0.1 are upgraded on the first start; settings from the 0.2 betas are kept as they are. Please report what breaks in [Issues](https://github.com/eoftgge/rosetun/issues); report vulnerabilities privately through [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

**Going back to 0.1 takes a manual step.** 0.2 upgrades the settings file to a new format, and 0.1 refuses a file from a newer version instead of overwriting it. Rosetun keeps your previous settings next to it as `%APPDATA%\Rosetun\config.v3.json`: to return to 0.1.0, install it and rename that file to `config.json`. Changes made in 0.2 are not carried back.

## What's new in 0.2

- **REALITY servers on Xray 26.9.8 and newer connect again.** sing-box cannot talk to them ([SagerNet/sing-box#4520](https://github.com/SagerNet/sing-box/issues/4520)), so Rosetun now connects VLESS + REALITY servers through Xray. sing-box still runs the tunnel, the rules, DNS and the kill switch; Xray only carries the connection to the server.
- **Settings › Advanced › Connection through Xray:**
  - **Automatically** (default): Xray for VLESS servers with REALITY, sing-box for the rest.
  - **Without Xray**: sing-box for everything, as in 0.1. If a REALITY server rejects sing-box, Rosetun says so and offers to switch to Automatically and connect.
  - **Xray for all servers**: every supported server except Hysteria2 goes through Xray.
- **You can see what is going on.** The server list marks servers that go through Xray, and the main screen shows "sing-box + Xray" while connected through it.
- **Switching servers while connected** works between ordinary and REALITY servers; the kill switch stays on during the switch.
- **Server checks and delay** go through the same chain as the connection.
- **If Xray stops** while connected, the kill switch keeps the internet closed and Rosetun reconnects. If `xray.exe` is missing or damaged, Rosetun says so and links to the release page.
- **The tray icon shows the state by shape, not only by colour.** The rose is in colour only while connected; otherwise it is grey with a corner badge: an arc while connecting, a lock when the kill switch keeps the internet closed, "!" when connecting failed, "×" when the Rosetun service is not running. The tooltip for the last one says "Service unavailable".
- **A new rose, one everywhere.** The app icon, the header, Settings › About and the tray share one new rose, drawn to stay clear down to 16 pixels.
- **Settings › Connection › Local network.** Your router, printer and other devices on your network are reached directly, past the tunnel; DNS on the local network stays closed. Off by default; turn it off on public networks. A change while connected applies at the next connection. From the command line: `rosetun lan on` or `rosetun lan off`.
- **Rules by IP address.** The rule dialog has an "IP address" tab: IPv4 and IPv6 addresses or subnets, one per line. A subnet written with host bits (such as `192.0.2.5/24`) gets a **Fix** button, and addresses of the local network get a hint that points to the new Local network setting.
- **Lists are not downloaded again when they have not changed.** Rosetun asks the server first (`ETag` / `Last-Modified`), so updating subscriptions no longer fetches large lists such as `geosite.dat` every time.
- **Names in Task Manager.** The app shows as "Rosetun" and the service as "Rosetun Service"; the files also carry their version. sing-box and Xray keep their own names.
- **Settings › Service and log › System check** looks for common causes of VPN trouble: a wrong clock (TLS and REALITY need it), a system proxy left by another program, Zapret or WinDivert intercepting packets, and other VPN clients or their adapters. It runs by itself after a failed connection and shows the first finding under the error. It only reports; it changes nothing.
- **"No network connection" instead of blaming the server.** With no network, connecting fails at once with its own message. While connected, a short network change (switching Wi-Fi, replugging the cable) no longer breaks the session. With **Reconnect automatically** on, a longer outage shows "No network connection", Rosetun waits for the network and reconnects when it returns; the kill switch keeps the internet closed meanwhile.
- **Collect report** (Settings › Service and log) saves one text file for a bug report: versions, settings without secrets, the connection state, the system check and the logs. IP addresses, links, domains, keys, server and subscription names and your Windows account name are removed; open the file to see exactly what you send. The service log is given only to the Windows account that started the session.
- **Clearer errors:** when the engine fails to start, Rosetun says so in plain words instead of internal details, and the "Restore my edits" link fits on one line.
- **Rules through another server.** A rule can send its sites or programs through another country or a specific server, while the rest goes through the server on the main screen. In the rule dialog, **Where** is one field: Through VPN, Direct, Block, your exits, another country or a specific server. Picking a country or a server creates an **exit** on its own; the new **Exits** tab next to Rules and Lists changes its server, turns on a fallback ("any server of this country if this one disappears") and shows which server is used now.
  - A country exit picks the fastest server of that country at connect and keeps it until you disconnect: servers of one country may leave to the internet from different addresses.
  - If an exit's server disappears from the subscription, its rules block (never go direct) and the rule list warns.
  - The connection screen lists the exits in use with the server and its delay. From the command line: `rosetun exits`; `rosetun delay` shows each exit's delay.
- **A window hidden in the tray stays idle.** It no longer redraws every second and wakes only when something is due, such as a subscription update.
- **"Apply" and reconnecting no longer fail with "engine exited with code 1"** when Windows is slow to remove the previous tunnel adapter. This was the cause of the rare engine error on "Apply" known since 0.1; it also delayed reconnecting after a network loss. Rosetun now recognises it and starts the engine again a couple of seconds later, with the protection kept in place, and "Apply" keeps your change instead of rolling it back.
- **The buttons on a subscription card** (expand, update, more) no longer start dragging the card or show the drag cursor. Drag a subscription by its name.
- **A subscription link copied without `https://`** is accepted: Rosetun adds `https://` and shows the link as it will be added, without its token. It never assumes `http://`.
- **All fixes from 0.1.0** are included.
- **Since 0.2.0-beta.2,** only the subscription link without `https://` is new.

## Known issues

- If you switch between networks (for example Wi-Fi and cable) while connected through Xray, the connection may stop until Rosetun reconnects.

## Install

Windows 10 or 11, x64. Download `{{setup}}` from this release. [Code signing policy](https://github.com/eoftgge/rosetun/blob/master/CODE_SIGNING_POLICY.md): the installer is not code-signed yet; if SmartScreen says "Windows protected your PC", select **More info** and then **Run anyway**.

## Verify

Run `Get-FileHash .\{{setup}} -Algorithm SHA256` and compare the result with `{{sha256}}` (also in `SHA256SUMS.txt`). Verify its provenance with `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

## Included

Rosetun includes the unmodified official sing-box {{sing_box_version}} build, licensed under GPL-3.0-or-later. The corresponding source is attached as `sing-box-{{sing_box_version}}-source.tar.gz`.

Rosetun includes the unmodified official Xray-core {{xray_version}} build, licensed under MPL-2.0. The corresponding source is attached as `xray-{{xray_version}}-source.tar.gz`; the license is installed in `licenses/`. Xray's `geoip.dat` and `geosite.dat` are not installed.

The executable embeds Wintun {{wintun_version}}, distributed under the Wintun Prebuilt Binaries License; the license and notice are installed in `licenses/wintun-prebuilt-binaries-license.txt` and `licenses/wintun.txt`.

## Русский

Rosetun 0.2. Её цель: подключаться везде и показывать, что происходит. Серверы REALITY на новом Xray снова подключаются, правило может вести свои сайты или программы через другую страну или сервер, а Rosetun понятнее объясняет, что пошло не так.

Rosetun 0.1.0 предлагает этот выпуск как обновление. Настройки из 0.1 обновляются при первом запуске, настройки бет 0.2 сохраняются как есть. Сообщайте о проблемах в [Issues](https://github.com/eoftgge/rosetun/issues), а об уязвимостях приватно через [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

**Вернуться на 0.1 можно только вручную.** 0.2 переводит файл настроек на новый формат, а 0.1 отказывается читать файл более новой версии и не перезаписывает его. Прежние настройки Rosetun сохраняет рядом, в `%APPDATA%\Rosetun\config.v3.json`: чтобы вернуться на 0.1.0, установите её и переименуйте этот файл в `config.json`. Изменения, сделанные в 0.2, при этом не переносятся.

### Что нового в 0.2

- **Серверы REALITY на Xray 26.9.8 и новее снова подключаются.** sing-box с ними работать не может ([SagerNet/sing-box#4520](https://github.com/SagerNet/sing-box/issues/4520)), поэтому серверы VLESS + REALITY Rosetun теперь подключает через Xray. Туннель, правила, DNS и kill switch по-прежнему работают на sing-box; Xray только ведёт соединение с сервером.
- **Настройки › Дополнительно › Подключение через Xray:**
  - **Автоматически** (по умолчанию): Xray для серверов VLESS с REALITY, sing-box для остальных.
  - **Без Xray**: всё через sing-box, как в 0.1. Если сервер REALITY не примет sing-box, Rosetun скажет об этом и предложит включить «Автоматически» и подключиться.
  - **Xray для всех серверов**: все поддерживаемые серверы, кроме Hysteria2, идут через Xray.
- **Видно, что происходит.** В списке серверов отмечены те, что пойдут через Xray, а на главном экране во время подключения через него написано «sing-box + Xray».
- **Смена сервера во время подключения** работает между обычными серверами и серверами REALITY; kill switch при этом не выключается.
- **Проверка серверов и задержка** идут через ту же цепочку, что и подключение.
- **Если Xray остановится** во время подключения, kill switch держит интернет закрытым, а Rosetun переподключается. Если `xray.exe` пропал или повреждён, Rosetun скажет об этом и даст ссылку на страницу выпуска.
- **Значок в трее показывает состояние формой, а не только цветом.** Роза цветная только при подключении; в остальных состояниях она серая, а в углу значок: дуга при подключении, замок, когда kill switch держит интернет закрытым, «!», когда подключиться не удалось, «×», когда служба Rosetun не запущена. Подсказка в последнем случае: «Служба недоступна».
- **Новая роза, одна везде.** Значок программы, шапка, «Настройки › О программе» и трей показывают одну новую розу, которая читается даже на 16 пикселях.
- **Настройки › Подключение › Локальная сеть.** Роутер, принтер и другие устройства в вашей сети доступны напрямую, мимо туннеля; DNS в локальной сети остаётся закрытым. По умолчанию выключено; в общественных сетях лучше выключить. Если изменить во время подключения, применится при следующем подключении. Из командной строки: `rosetun lan on` или `rosetun lan off`.
- **Правила по IP-адресам.** В окне правила появилась вкладка «IP-адрес»: адреса или подсети IPv4 и IPv6, по одному на строку. Для подсети с битами хоста (например, `192.0.2.5/24`) есть кнопка **Исправить**, а для адресов локальной сети подсказка со ссылкой на новую настройку «Локальная сеть».
- **Неизменившиеся списки больше не скачиваются заново.** Rosetun сначала спрашивает сервер (`ETag` / `Last-Modified`), поэтому обновление подписок не качает каждый раз большие списки вроде `geosite.dat`.
- **Названия в диспетчере задач.** Программа видна как «Rosetun», служба как «Rosetun Service»; у файлов также указана версия. sing-box и Xray остаются под своими именами.
- **Настройки › Служба и журнал › Проверка системы** ищет частые причины сбоев VPN: неверные часы (без них не работают TLS и REALITY), системный прокси, оставленный другой программой, Zapret или WinDivert, перехватывающие пакеты, другие VPN-клиенты и их адаптеры. После неудачного подключения проверка запускается сама и показывает первую находку под ошибкой. Она только сообщает и ничего не меняет.
- **«Нет подключения к сети» вместо «сервер не отвечает».** Без сети подключение сразу заканчивается своим сообщением. Во время подключения короткая смена сети (другой Wi-Fi, переподключённый кабель) больше не обрывает сессию. При включённом **Переподключаться при обрыве** долгая пропажа сети показывается как «Нет подключения к сети»: Rosetun ждёт сеть и подключается, когда она вернётся, а kill switch всё это время держит интернет закрытым.
- **Собрать отчёт** (Настройки › Служба и журнал) сохраняет один текстовый файл для сообщения об ошибке: версии, настройки без секретов, состояние подключения, проверку системы и журналы. IP-адреса, ссылки, домены, ключи, имена серверов и подписок, имя учётной записи Windows вычищаются; откройте файл и посмотрите, что именно отправляете. Журнал службы выдаётся только учётной записи, которая запускала подключение.
- **Понятнее ошибки:** если ядро не запустилось, Rosetun говорит об этом простыми словами вместо внутренних подробностей, а ссылка «Вернуть мои правки» помещается в одну строку.
- **Правила через другой сервер.** Правило может вести свои сайты или программы через другую страну или конкретный сервер, а остальное идёт через сервер с главного экрана. В диалоге правила **Куда направить** стало одним полем: «Через VPN», «Напрямую», «Блокировать», ваши направления, другая страна или конкретный узел. Выбор страны или узла сам создаёт **направление**; новая вкладка **Направления** рядом с «Правила · Списки» меняет его сервер, включает запасной («любой узел этой страны, если этого не станет») и показывает, какой сервер используется сейчас.
  - Направление на страну выбирает самый быстрый сервер страны при подключении и держит его до отключения: серверы одной страны могут выходить в интернет с разных адресов.
  - Если сервер направления пропал из подписки, его правила блокируют (никогда не идут напрямую), а список правил предупреждает.
  - Экран подключения показывает используемые направления с сервером и задержкой. Из командной строки: `rosetun exits`; `rosetun delay` показывает задержку каждого направления.
- **Окно, свёрнутое в трей, не нагружает компьютер.** Оно больше не перерисовывается каждую секунду и просыпается, только когда пора что-то сделать, например обновить подписку.
- **«Применить» и переподключение больше не падают с «engine exited with code 1»**, когда Windows долго удаляет прежний адаптер туннеля. Это и была причина редкой ошибки ядра при «Применить», известной с 0.1; из-за неё же затягивалось переподключение после пропажи сети. Теперь Rosetun распознаёт её и через пару секунд запускает ядро снова, не снимая защиту, а «Применить» сохраняет ваше изменение вместо отката.
- **Кнопки на карточке подписки** (развернуть, обновить, ещё) больше не начинают перетаскивание карточки и не показывают курсор перетаскивания. Подписку перетаскивают за название.
- **Ссылку подписки без `https://`** можно вставить как есть: Rosetun допишет `https://` и покажет, как ссылка будет добавлена, без токена. `http://` он не подставляет никогда.
- **Все исправления из 0.1.0** входят в эту версию.
- **С 0.2.0-beta.2** нового только ссылка подписки без `https://`.

### Известные проблемы

- Если во время подключения через Xray сменить сеть (например, Wi-Fi на кабель), соединение может прерваться, пока Rosetun не переподключится.

### Установка

Windows 10 или 11, x64. Скачайте `{{setup}}` из этого релиза. [Политика подписи кода](https://github.com/eoftgge/rosetun/blob/master/CODE_SIGNING_POLICY.md) (Code signing policy): установщик пока не подписан; если SmartScreen показывает «Windows protected your PC», нажмите **More info**, затем **Run anyway**.

### Проверка

Выполните `Get-FileHash .\{{setup}} -Algorithm SHA256` и сравните результат с `{{sha256}}` (он также указан в `SHA256SUMS.txt`). Проверьте происхождение командой `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

### Состав

Rosetun включает официальную сборку sing-box {{sing_box_version}} без изменений, лицензия GPL-3.0-or-later. Соответствующие исходники приложены в архиве `sing-box-{{sing_box_version}}-source.tar.gz`.

Rosetun включает официальную сборку Xray-core {{xray_version}} без изменений, лицензия MPL-2.0. Соответствующие исходники приложены в архиве `xray-{{xray_version}}-source.tar.gz`; текст лицензии устанавливается в `licenses/`. Файлы Xray `geoip.dat` и `geosite.dat` не устанавливаются.

Исполняемый файл содержит Wintun {{wintun_version}}, который распространяется по лицензии Wintun Prebuilt Binaries License; текст лицензии и уведомление устанавливаются в `licenses/wintun-prebuilt-binaries-license.txt` и `licenses/wintun.txt`.
