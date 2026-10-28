# Rosetun {{version}}

**A beta of Rosetun 0.4.** It brings colour themes, a more useful tray, `rosetun://` subscription links, a device ID per provider, program icons, a smoother interface, update offers you can actually see, and a harder Lockdown. Both test matrices (failures and Lockdown) pass on this build; still, expect rough edges and please report them in [Issues](https://github.com/eoftgge/rosetun/issues), and vulnerabilities privately through [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

Install it over 0.3.x; settings and Lockdown are carried over. Rosetun 0.3.1 and 0.3.0 do not offer a beta as an update, so download it here; Rosetun 0.3.0-beta.1 and the 0.2.0 betas do offer it.

**Going back to 0.3.** Turn Lockdown off in 0.4 first: 0.4 changes its filters, and 0.3 does not know the new ones. 0.3 also cannot read settings saved by 0.4. The previous file is kept as `%APPDATA%\Rosetun\config.v6.json`; close Rosetun and rename it to `config.json` (changes made in 0.4 are lost).

## What's new in 0.4

- **Colour themes** in Settings › General: Rose, Graphite rose, Cocoa, Lilac, Teal and Amber. "Connected" is shown in the theme's pale accent, so it is easy to tell from a failure.
- **A more useful tray menu.**
  - The state comes first ("Connected · Japan", "Traffic blocked"), then **Connect · Japan** or **Disconnect**.
  - **Servers**: your five most recent servers, the current one checked, and **All servers…**. A click switches the server while connected, under protection, or connects to it while disconnected.
  - One item opens or hides the window.
  - **Notifications** when the VPN drops, comes back or cannot connect, without server names, since Windows shows them on the lock screen. None while the Rosetun window is in front or when you disconnect yourself. Turn them off in Settings › General › **Notifications**.
- **New versions are hard to miss.** A strip on the connection screen with **Download** and **Skip**, an **Update to …** item in the tray and one notification per version. A found version is remembered across restarts; before, it showed only as a small dot in Settings and was forgotten when Rosetun restarted. When GitHub's API limit is used up, which happens behind a shared VPN address, Rosetun reads GitHub's releases feed instead. Versions before 0.4 still show an update only as that dot.
- **`rosetun://` subscription links.** A button on a provider's page can open Rosetun with the subscription filled in: `rosetun://add/<subscription link>`, optionally with `#name`. Rosetun only shows **Add subscription** with the link, its name and the provider's host; nothing is downloaded or added until you click **Add**. The installer registers the scheme.
- **A device ID per provider.** With **Send device ID** on (the default), new subscriptions get a device ID of their own for each subscription server, so different providers cannot match your device. Subscriptions added before 0.4 keep their ID, so a provider that limits devices does not count you twice.
- **Program icons** on the Traffic tab, in the new rule dialog and in the rules table, taken from programs on local disks only; a program on a network drive keeps its coloured tile, so Windows never connects to another computer to fetch an icon.
- **Traffic tab.** The program list holds its order while the pointer is on it, so a row does not move away from under the cursor. The chart moves smoothly instead of jumping each second.
- **A smoother interface.** Subscriptions and programs open with an animation, screens and tabs fade in, dialogs appear softly, and the header's petals drift while connected. Continuous animations run at up to 60 frames per second while the window is in focus and 30 when it is not, and none while it is hidden. **Reduce motion** turns all of it off. Settings no longer flicker while they save, and quick changes in a row are all kept.
- **Lockdown hardening.**
  - Turning Lockdown on or off, and changing its local network access, now need administrator rights (UAC); `rosetun lockdown` needs a terminal opened as administrator.
  - **Fixed a way around the tunnel.** While connected, any account on the computer could start Rosetun's `sing-box.exe` and reach the internet outside the tunnel, even with Lockdown on: sing-box's own firewall permit for its executable overrode Rosetun's blocks. The service now runs sing-box from a copy in `data\engines` that only SYSTEM and Administrators can open, and permits the engines only for the service's own account.
  - Rosetun itself (the app and the `rosetun` command) gets out without a connection only over TCP and DNS, and only while not connected. Any TCP port is allowed, so subscriptions on ports other than 443 update under Lockdown too.
  - `rosetun` started from a scheduled task can now check the Rosetun service; before, it could not tell that the service was genuine.
- **Supply chain.** Dependencies are checked with cargo-deny in CI and again before each release, engine source archives are pinned by SHA-256, and rustls and related crates are updated.
- **Settings format 7.** Settings are converted when 0.4 first saves them, and the previous file stays as `config.v6.json`; 0.3 refuses to read the new format and does not overwrite it.
- **sing-box {{sing_box_version}} and Xray {{xray_version}}**, the same as in 0.3.1.

## Known issues

- **This is a beta.** The changes above passed both test matrices in a virtual machine and daily use on one computer, but not wide use yet.
- **Windows 10 has not been tested**, only Windows 11. Rosetun may work on Windows 10; if something does not, please report it.
- If you switch between networks (for example Wi-Fi and cable) while connected through Xray, the connection may stop until Rosetun reconnects.
- **Lockdown is experimental**: tested on Windows 11 only, on a clean system and on one everyday computer, with restarts, power cuts and sleep in a virtual machine. Not tested yet: other firewalls or antivirus programs with their own network filters, hibernation and sleep on real hardware.
- **With Lockdown on, Wi-Fi with a sign-in page** (a hotel or a café) cannot open its page, and **Windows cannot set the clock** without the tunnel. Turn Lockdown off for a moment, sign in or correct the clock, connect, and turn it on again.
- **Lockdown leaves Hyper-V virtual machines on this computer without network**, and most likely WSL2, Docker Desktop, Windows Sandbox and Mobile hotspot too. Turn Lockdown off while you need them.

## Install

Windows 11, x64 (Windows 10 is not tested). Download `{{setup}}` from this release. [Code signing policy](https://github.com/eoftgge/rosetun/blob/master/CODE_SIGNING_POLICY.md): the installer is not code-signed yet; if SmartScreen says "Windows protected your PC", select **More info** and then **Run anyway**.

## Verify

Run `Get-FileHash .\{{setup}} -Algorithm SHA256` and compare the result with `{{sha256}}` (also in `SHA256SUMS.txt`). Verify its provenance with `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

## Included

Rosetun includes the unmodified official sing-box {{sing_box_version}} build, licensed under GPL-3.0-or-later. The corresponding source is attached as `sing-box-{{sing_box_version}}-source.tar.gz`.

Rosetun includes the unmodified official Xray-core {{xray_version}} build, licensed under MPL-2.0. The corresponding source is attached as `xray-{{xray_version}}-source.tar.gz`; the license is installed in `licenses/`. Xray's `geoip.dat` and `geosite.dat` are not installed.

The executable embeds Wintun {{wintun_version}}, distributed under the Wintun Prebuilt Binaries License; the license and notice are installed in `licenses/wintun-prebuilt-binaries-license.txt` and `licenses/wintun.txt`.

## Русский

**Бета Rosetun 0.4.** В ней цветовые темы, полезный трей, ссылки `rosetun://` для подписок, свой ID устройства для каждого провайдера, значки программ, плавный интерфейс, заметные предложения обновиться и более строгий Lockdown. Обе тестовые матрицы (отказов и Lockdown) на этой сборке проходят; и всё же возможны шероховатости, сообщайте о них в [Issues](https://github.com/eoftgge/rosetun/issues), а об уязвимостях приватно через [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

Устанавливайте поверх 0.3.x; настройки и Lockdown сохраняются. Rosetun 0.3.1 и 0.3.0 не предлагают бету как обновление, скачайте её здесь; 0.3.0-beta.1 и беты 0.2.0 её предложат.

**Возврат на 0.3.** Сначала выключите Lockdown в 0.4: 0.4 меняет его фильтры, а 0.3 не знает новых. Кроме того, 0.3 не читает настройки, сохранённые 0.4. Прежний файл лежит как `%APPDATA%\Rosetun\config.v6.json`; закройте Rosetun и переименуйте его в `config.json` (изменения, сделанные в 0.4, пропадут).

### Что нового в 0.4

- **Цветовые темы** в «Настройки › Основные»: Роза, Графитовая роза, Какао, Сирень, Бирюза и Янтарь. «Подключено» показывается бледным оттенком акцента темы, поэтому его легко отличить от ошибки.
- **Полезное меню трея.**
  - Сверху состояние («Подключено · Япония», «Трафик заблокирован»), затем **Подключиться · Япония** или **Отключиться**.
  - **Серверы**: пять последних серверов, у текущего галочка, и **Все серверы…**. Щелчок при подключении переключает сервер под защитой, при отключении сразу подключает.
  - Один пункт открывает или скрывает окно.
  - **Уведомления**, когда VPN отключается, подключается снова или не может подключиться, без имён серверов: Windows показывает их на экране блокировки. Их нет, пока окно Rosetun на переднем плане, и когда вы отключаетесь сами. Выключаются в «Настройки › Основные › **Уведомления**».
- **Новую версию трудно пропустить.** Полоса на экране подключения с кнопками **Скачать** и **Пропустить**, пункт **Обновить до …** в трее и одно уведомление на версию. Найденная версия запоминается и после перезапуска; раньше она показывалась только маленькой точкой в настройках и забывалась при перезапуске Rosetun. Когда лимит API GitHub исчерпан (так бывает за общим адресом VPN), Rosetun читает ленту релизов GitHub. Версии до 0.4 по-прежнему показывают обновление только той точкой.
- **Ссылки `rosetun://` для подписок.** Кнопка на странице провайдера может открыть Rosetun с уже вписанной подпиской: `rosetun://add/<ссылка подписки>`, по желанию с `#имя`. Rosetun только показывает окно **Добавить подписку** со ссылкой, именем и адресом провайдера; ничего не скачивается и не добавляется, пока вы не нажмёте **Добавить**. Схему регистрирует установщик.
- **Свой ID устройства для каждого провайдера.** Когда включено **Отправлять ID устройства** (по умолчанию) новые подписки получают свой ID для каждого сервера подписок, и разные провайдеры не могут сопоставить ваше устройство. Подписки, добавленные до 0.4, сохраняют прежний ID, чтобы провайдер с лимитом устройств не посчитал вас дважды.
- **Значки программ** на вкладке «Трафик», в окне нового правила и в таблице правил; только для программ на локальных дисках. Программа на сетевом диске остаётся с цветной плиткой, чтобы Windows не обращалась к чужому компьютеру за значком.
- **Вкладка «Трафик».** Список программ не перестраивается, пока на нём указатель, и строка не уезжает из-под курсора. График движется плавно, а не скачет каждую секунду.
- **Плавный интерфейс.** Подписки и программы раскрываются с анимацией, экраны и вкладки мягко проявляются, окна поверх появляются плавно, а лепестки в шапке дрейфуют при подключении. Непрерывные анимации идут не чаще 60 кадров в секунду, пока окно в фокусе, 30 без фокуса и не идут вовсе, пока окно скрыто. **Уменьшить анимацию** выключает всё это. Настройки больше не мигают при сохранении, а быстрые изменения подряд не теряются.
- **Lockdown строже.**
  - Включение и выключение Lockdown и изменение его доступа к локальной сети теперь требуют прав администратора (UAC); `rosetun lockdown` нужно запускать в терминале от имени администратора.
  - **Закрыт обход туннеля.** Пока туннель был подключён, любая учётная запись на компьютере могла запустить `sing-box.exe` из Rosetun и выйти в интернет мимо туннеля, даже с Lockdown: собственное разрешение sing-box в брандмауэре для его файла перебивало блокировки Rosetun. Теперь служба запускает sing-box из копии в `data\engines`, которую могут открыть только SYSTEM и администраторы, и разрешает движкам выход только от учётной записи службы.
  - Сам Rosetun (приложение и команда `rosetun`) без подключения выходит только по TCP и DNS и только пока туннель не подключён. Разрешён любой порт TCP, так что подписки не на 443-м порту тоже обновляются под Lockdown.
  - `rosetun`, запущенный задачей планировщика, теперь может проверить службу Rosetun; раньше он не мог убедиться, что служба настоящая.
- **Цепочка поставки.** Зависимости проверяются cargo-deny в CI и ещё раз перед каждым выпуском, архивы исходников движков закреплены по SHA-256, rustls и связанные крейты обновлены.
- **Формат настроек 7.** Настройки преобразуются при первом сохранении в 0.4, прежний файл остаётся как `config.v6.json`; 0.3 отказывается читать новый формат и не перезаписывает его.
- **sing-box {{sing_box_version}} и Xray {{xray_version}}**, те же, что в 0.3.1.

### Известные проблемы

- **Это бета.** Изменения выше прошли обе тестовые матрицы в виртуальной машине и повседневную работу на одном компьютере, но ещё не широкое использование.
- **Windows 10 не проверялась**, только Windows 11. Rosetun может работать на Windows 10; если что-то не работает, сообщите.
- Если переключать сети (например, Wi-Fi и кабель) при подключении через Xray, соединение может остановиться, пока Rosetun не переподключится.
- **Lockdown экспериментальный**: проверен только на Windows 11, на чистой системе и на одном рабочем компьютере, с перезагрузками, отключениями питания и сном в виртуальной машине. Ещё не проверены: другие брандмауэры и антивирусы со своими сетевыми фильтрами, гибернация и сон на реальном железе.
- **С включённым Lockdown Wi-Fi со страницей входа** (в гостинице или кафе) не может открыть эту страницу, а **Windows не может выставить время** без туннеля. Выключите Lockdown на минуту, войдите или поправьте время, подключитесь и включите его снова.
- **Lockdown оставляет без сети виртуальные машины Hyper-V на этом компьютере**, и, скорее всего, WSL2, Docker Desktop, Windows Sandbox и мобильный хот-спот. Выключайте Lockdown, пока они нужны.

### Установка

Windows 11, x64 (Windows 10 не проверялась). Скачайте `{{setup}}` из этого релиза. [Политика подписи кода](https://github.com/eoftgge/rosetun/blob/master/CODE_SIGNING_POLICY.md) (Code signing policy): установщик пока не подписан; если SmartScreen показывает «Windows protected your PC», нажмите **More info**, затем **Run anyway**.

### Проверка

Выполните `Get-FileHash .\{{setup}} -Algorithm SHA256` и сравните результат с `{{sha256}}` (он также указан в `SHA256SUMS.txt`). Проверьте происхождение командой `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

### Состав

Rosetun включает официальную сборку sing-box {{sing_box_version}} без изменений, лицензия GPL-3.0-or-later. Соответствующие исходники приложены в архиве `sing-box-{{sing_box_version}}-source.tar.gz`.

Rosetun включает официальную сборку Xray-core {{xray_version}} без изменений, лицензия MPL-2.0. Соответствующие исходники приложены в архиве `xray-{{xray_version}}-source.tar.gz`; текст лицензии устанавливается в `licenses/`. Файлы Xray `geoip.dat` и `geosite.dat` не устанавливаются.

Исполняемый файл содержит Wintun {{wintun_version}}, который распространяется по лицензии Wintun Prebuilt Binaries License; текст лицензии и уведомление устанавливаются в `licenses/wintun-prebuilt-binaries-license.txt` и `licenses/wintun.txt`.
