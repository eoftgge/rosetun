# Rosetun {{version}}

Rosetun 0.5.1 fixes an Arch Linux compatibility issue in the nftables preflight check. On systems where `/usr/sbin` is a symbolic link to `/usr/bin`, Rosetun rejected the trusted `nft` executable and reported the kill switch and DNS lock as unavailable. This release accepts the standard Arch Linux executable location without relaxing the ownership and permission checks.

Settings and Lockdown are unchanged from 0.5.0. See **What's new in 0.5** below for the previous release's features and known limitations.

## Fixed in 0.5.1

- **Arch Linux: kill switch and DNS lock.** The nftables executable check now supports the `/usr/bin/nft` layout used by Arch Linux, where `/usr/sbin` points to `/usr/bin`. The kill switch and DNS lock are no longer disabled solely because of this directory layout.

## What's new in 0.5

Details are in the [README](https://eoftgge.github.io/rosetun/en/docs/).

- **Linux:** Debian 13, amd64, as a `.deb` package. Kill switch, DNS lock and Lockdown on nftables, engines without root, tray, notifications, autostart and `rosetun://` links. Checked by hand on GNOME, not yet on KDE Plasma; see [Requirements](https://eoftgge.github.io/rosetun/en/docs/install/#requirements).
- **System proxy mode**, beside TUN: a local proxy your desktop's settings point at, with a strict kill switch and access from your network. See [TUN and System proxy](https://eoftgge.github.io/rosetun/en/docs/modes/).
- **The protection in place** shows in the window and in `rosetun status`, with what is missing and whether it stays if the service crashes.
- **The network stays closed through an update** while the kill switch is on. See [Protection guarantees](https://eoftgge.github.io/rosetun/en/docs/guarantees/).
- **Local network** on Windows opens only your own network, each on its own adapter, and finding devices works. **Private networks behind the router** is the old, wider behaviour, as a separate setting. See [Local network](https://eoftgge.github.io/rosetun/en/docs/local-network/).
- **Reconnect** in the tray and `rosetun reconnect` restart the tunnel without dropping protection.
- **Your own HTTP, HTTPS and SOCKS5 proxies**, on a tab of the add dialog.
- **TLS fragmentation** of the connection to the server, through Xray.
- **Rules:** undo with Ctrl+Z, **Revert** to the applied rules, Del for the selected rule, and a new **New rule** dialog that adds several programs or addresses at once.
- **Names in other scripts**, drawn with system fonts, and input in them.
- **Windows:** the window draws with Direct3D 12, and autostart moves to a scheduled task at sign-in.
- **sing-box {{sing_box_version}} and Xray {{xray_version}}.**

## Updating from 0.4

Install it over 0.4; settings and Lockdown are carried over.

- **Settings format 8.** Settings are converted when 0.5 first saves them, and the previous file stays as `config.v7.json`. 0.4 refuses to read the new format and does not overwrite it.
- **Lockdown stays on** through the update.
- **With the kill switch on, the network stays closed** through the update. The app starts and connects again; if it cannot, the connection screen offers **Connect** and **Open network**, and `rosetun open-network` does the same. Without the kill switch the update has a moment with nothing closed, as before.

## Going back to 0.4

Not tested.

1. In 0.5, disconnect, so your own proxy settings come back.
2. Uninstall 0.5 and keep your settings. This removes Lockdown, an update's hold and the sign-in task.
3. Install 0.4.
4. Close Rosetun. If `%APPDATA%\Rosetun\config.v7.json` exists, rename it to `config.json` over the newer file; changes made in 0.5 are lost.
5. Turn on **Start with Windows** and Lockdown again if you use them.

## Known limitations

- **Windows: multicast without a chosen adapter goes into the tunnel.** mDNS or SSDP from a program that leaves the choice to Windows does not reach your network, also with **Local network** on. Programs that pick the adapter are fine, as is broadcast to 255.255.255.255.
- **Linux: Local network is wider than on Windows.** The firewall opens every private range on any interface, not only your own network, and VPN servers' addresses are not left out.
- **Linux: rules by program have a price.** A session with such a rule gives its engine `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`, nearly root for anything that takes the engine over. A sing-box error sometimes attributes a connection to the wrong program ([#4501](https://github.com/SagerNet/sing-box/issues/4501), open), so a **Direct** rule for a program can now and then let another program's connection past the tunnel. If this matters, use rules by site and IP, with **Through VPN** as the default and no **Direct** rule by program.
- **Linux:** no file dialogs, no **Collect report** and no system proxy or packet interception checks.
- **Lockdown is experimental.** Not tested: Windows 10, other firewalls or antivirus programs with their own network filters, firewalld on Linux, hibernation, sleep on real hardware (on Linux, sleep at all) and a power cut on Linux.
- **With Lockdown on, Wi-Fi with a sign-in page** cannot open its page, and **the system cannot set the clock** without the tunnel. Turn Lockdown off for a moment, sign in or correct the clock, connect, and turn it on again.
- **Lockdown leaves virtual machines on this computer without network**: Hyper-V on Windows, and most likely WSL2, Docker Desktop, Windows Sandbox and Mobile hotspot. On Linux, virtual machines and containers, without a Rosetun connection. Turn Lockdown off while you need them.
- **Desktops.** KDE Plasma has not been checked on a real desktop yet. On GNOME, without an extension that provides a tray, closing the window closes the program.
- **The Windows installer is not code-signed yet.**
- If you switch between networks (for example Wi-Fi and cable) while connected through Xray, the connection may stop until Rosetun reconnects.

## Install

**Windows 11, x64.** Windows 10 runs on one tester's computer; the failure tests have not run on it. Download `{{setup}}` from this release. [Code signing policy](https://github.com/eoftgge/rosetun/blob/dev/CODE_SIGNING_POLICY.md): if SmartScreen says "Windows protected your PC", select **More info** and then **Run anyway**.

**Debian 13, amd64.** Download `{{deb}}`, then:

```sh
sudo apt install ./{{deb}}
sudo usermod -aG rosetun "$USER"
```

Then restart the computer: logging out is not enough.

## Verify

Compare the hash with this release's `SHA256SUMS.txt`, and verify the provenance. An attestation says which workflow built the file; it is not a code signature.

- Windows: `Get-FileHash .\{{setup}} -Algorithm SHA256` gives `{{sha256}}`. Then `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.
- Linux archive: `{{linux_archive}}`, SHA-256 `{{linux_archive_sha256}}`; verify with `gh attestation verify {{linux_archive}} --repo eoftgge/rosetun`.
- Debian: `sha256sum {{deb}}` gives `{{deb_sha256}}`. Then `gh attestation verify {{deb}} --repo eoftgge/rosetun`.

## Report a problem

[Issues](https://github.com/eoftgge/rosetun/issues), with the steps and the error text. On Windows attach **Collect report**; on Linux see [Troubleshooting](https://eoftgge.github.io/rosetun/en/docs/troubleshooting/). Report a vulnerability privately through [Security](https://github.com/eoftgge/rosetun/security/advisories/new), without subscription links or credentials.

## Included

Rosetun includes the unmodified official sing-box {{sing_box_version}} build, licensed under GPL-3.0-or-later. The corresponding source is attached as `sing-box-{{sing_box_version}}-source.tar.gz`.

Rosetun includes the unmodified official Xray-core {{xray_version}} build, licensed under MPL-2.0. The corresponding source is attached as `xray-{{xray_version}}-source.tar.gz`; the license is installed in `licenses/` on Windows and in `/usr/share/doc/rosetun/licenses` on Linux. Xray's `geoip.dat` and `geosite.dat` are not installed.

On Windows, the sing-box executable embeds Wintun {{wintun_version}}, distributed under the Wintun Prebuilt Binaries License; the license and notice are installed in `licenses/wintun-prebuilt-binaries-license.txt` and `licenses/wintun.txt`.

## Русский

### Исправлено в 0.5.1

Rosetun 0.5.1 исправляет несовместимость проверки nftables с Arch Linux. Когда `/usr/sbin` является символической ссылкой на `/usr/bin`, Rosetun отклонял исполняемый файл `nft` и сообщал, что kill switch и замок DNS недоступны. Теперь стандартное расположение `nft` в Arch Linux поддерживается без ослабления проверок владельца и прав доступа.

- **Arch Linux: kill switch и замок DNS.** Проверка nftables принимает `/usr/bin/nft`, если путь проходит проверку безопасности. Защита больше не становится недоступной только из-за устройства каталогов Arch Linux.

Настройки и Lockdown не изменились по сравнению с 0.5.0. Возможности предыдущего выпуска и известные ограничения описаны ниже.

### Что нового в 0.5

Подробности в [README](https://eoftgge.github.io/rosetun/ru/docs/).

- **Linux:** Debian 13, amd64, пакетом `.deb`. Kill switch, замок DNS и Lockdown на nftables, ядра без root, трей, уведомления, автозапуск и ссылки `rosetun://`. Вручную проверено на GNOME, на KDE Plasma пока нет; см. [Требования](https://eoftgge.github.io/rosetun/ru/docs/install/#requirements).
- **Режим «Системный прокси»** рядом с TUN: локальный прокси, на который указывают настройки системы, со строгим kill switch и доступом из вашей сети. См. [TUN и системный прокси](https://eoftgge.github.io/rosetun/ru/docs/modes/).
- **Действующая защита** видна в окне и в `rosetun status`, вместе с тем, чего не хватает и останется ли защита при падении службы.
- **Сеть остаётся закрытой при обновлении**, если включён kill switch. См. [Гарантии защиты](https://eoftgge.github.io/rosetun/ru/docs/guarantees/).
- **Локальная сеть** на Windows открывает только вашу сеть, каждую на своём адаптере, и поиск устройств работает. **Частные сети за роутером** это прежнее, более широкое поведение отдельной настройкой. См. [Локальная сеть](https://eoftgge.github.io/rosetun/ru/docs/local-network/).
- **Переподключиться** в трее и `rosetun reconnect` перезапускают туннель, не снимая защиту.
- **Собственные прокси HTTP, HTTPS и SOCKS5** на вкладке окна добавления.
- **Фрагментация TLS** соединения с сервером, через Xray.
- **Правила:** Ctrl+Z, **Вернуть** к применённым правилам, Del для выделенного правила и новое окно **Новое правило**, которое добавляет сразу несколько программ или адресов.
- **Имена на других письменностях**, которые рисуют системные шрифты, и ввод на них.
- **Windows:** окно рисуется через Direct3D 12, а автозапуск переходит на задачу планировщика при входе в систему.
- **sing-box {{sing_box_version}} и Xray {{xray_version}}.**

### Обновление с 0.4

Устанавливайте поверх 0.4; настройки и Lockdown сохраняются.

- **Формат настроек 8.** Настройки преобразуются при первом сохранении в 0.5, прежний файл остаётся как `config.v7.json`. 0.4 отказывается читать новый формат и не перезаписывает его.
- **Lockdown остаётся включённым** при обновлении.
- **Если включён kill switch, сеть при обновлении остаётся закрытой.** Приложение запускается и подключается снова; если не удалось, экран подключения предлагает **Подключиться** и **Открыть сеть**, то же делает `rosetun open-network`. Без kill switch при обновлении, как и раньше, есть момент, когда ничего не закрыто.

### Возврат на 0.4

Не проверено.

1. В 0.5 отключитесь, чтобы вернулись ваши настройки прокси.
2. Удалите 0.5, сохранив настройки. Это снимает Lockdown, удержание после обновления и задачу запуска при входе.
3. Установите 0.4.
4. Закройте Rosetun. Если есть `%APPDATA%\Rosetun\config.v7.json`, переименуйте его в `config.json` поверх нового файла; изменения, сделанные в 0.5, пропадут.
5. Снова включите **Запускать вместе с Windows** и Lockdown, если они нужны.

### Известные ограничения

- **Windows: multicast без выбранного адаптера уходит в туннель.** mDNS или SSDP от программы, которая оставляет выбор Windows, до вашей сети не доходит, в том числе при включённой **Локальной сети**. У программ, которые выбирают адаптер, всё работает, как и широковещательные запросы на 255.255.255.255.
- **Linux: «Локальная сеть» шире, чем на Windows.** Брандмауэр открывает все частные диапазоны на любом интерфейсе, а не только вашу сеть, и адреса VPN-серверов не вырезаются.
- **Linux: у правил по программам есть цена.** Сеанс с таким правилом даёт своему ядру `CAP_SYS_PTRACE` и `CAP_DAC_READ_SEARCH`, почти root для того, кто захватит ядро. Ошибка sing-box иногда приписывает соединение не той программе ([#4501](https://github.com/SagerNet/sing-box/issues/4501), открыта), поэтому правило «Напрямую» для программы может изредка пропустить мимо туннеля чужое соединение. Если это важно, используйте правила по сайтам и IP, а по умолчанию оставьте «Через VPN» без правил «Напрямую» по программам.
- **Linux:** нет диалогов выбора файла, **Собрать отчёт** и проверок системного прокси и перехвата пакетов.
- **Lockdown экспериментальный.** Не проверены: Windows 10, другие брандмауэры и антивирусы со своими сетевыми фильтрами, firewalld на Linux, гибернация, сон на настоящем компьютере (на Linux сон вообще) и отключение питания на Linux.
- **С включённым Lockdown Wi-Fi со страницей входа** не может открыть эту страницу, а **система не может выставить время** без туннеля. Выключите Lockdown на минуту, войдите или поправьте время, подключитесь и включите его снова.
- **Lockdown оставляет без сети виртуальные машины на этом компьютере**: Hyper-V на Windows и, скорее всего, WSL2, Docker Desktop, Windows Sandbox и мобильный хот-спот. На Linux виртуальные машины и контейнеры, пока нет подключения Rosetun. Выключайте Lockdown, пока они нужны.
- **Рабочие столы.** KDE Plasma на настоящем рабочем столе пока не проверен. На GNOME без расширения, которое даёт трей, закрытие окна закрывает программу.
- **Установщик Windows пока не подписан.**
- Если переключать сети (например, Wi-Fi и кабель) при подключении через Xray, соединение может остановиться, пока Rosetun не переподключится.

### Установка

**Windows 11, x64.** Windows 10 работает на компьютере одного тестировщика; проверки отказов на ней не прогонялись. Скачайте `{{setup}}` из этого выпуска. [Политика подписи кода](https://github.com/eoftgge/rosetun/blob/dev/CODE_SIGNING_POLICY.md) (Code signing policy): если SmartScreen показывает «Windows protected your PC», нажмите **More info**, затем **Run anyway**.

**Debian 13, amd64.** Скачайте `{{deb}}`, затем:

```sh
sudo apt install ./{{deb}}
sudo usermod -aG rosetun "$USER"
```

Затем перезагрузите компьютер: выхода из системы мало.

### Проверка

Сравните хеш с `SHA256SUMS.txt` этого выпуска и проверьте происхождение. Аттестация говорит, какой workflow собрал файл; это не подпись кода.

- Windows: `Get-FileHash .\{{setup}} -Algorithm SHA256` даёт `{{sha256}}`. Затем `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.
- Linux archive: `{{linux_archive}}`, SHA-256 `{{linux_archive_sha256}}`; verify with `gh attestation verify {{linux_archive}} --repo eoftgge/rosetun`.
- Debian: `sha256sum {{deb}}` даёт `{{deb_sha256}}`. Затем `gh attestation verify {{deb}} --repo eoftgge/rosetun`.

### Сообщить о проблеме

[Issues](https://github.com/eoftgge/rosetun/issues), с шагами и текстом ошибки. На Windows приложите **Собрать отчёт**; для Linux см. [Устранение неполадок](https://eoftgge.github.io/rosetun/ru/docs/troubleshooting/). Об уязвимостях сообщайте приватно через [Security](https://github.com/eoftgge/rosetun/security/advisories/new), без ссылок подписок и паролей.

### Состав

Rosetun включает официальную сборку sing-box {{sing_box_version}} без изменений, лицензия GPL-3.0-or-later. Соответствующие исходники приложены в архиве `sing-box-{{sing_box_version}}-source.tar.gz`.

Rosetun включает официальную сборку Xray-core {{xray_version}} без изменений, лицензия MPL-2.0. Соответствующие исходники приложены в архиве `xray-{{xray_version}}-source.tar.gz`; текст лицензии устанавливается в `licenses/` на Windows и в `/usr/share/doc/rosetun/licenses` на Linux. Файлы Xray `geoip.dat` и `geosite.dat` не устанавливаются.

На Windows исполняемый файл sing-box содержит Wintun {{wintun_version}}, который распространяется по лицензии Wintun Prebuilt Binaries License; текст лицензии и уведомление устанавливаются в `licenses/wintun-prebuilt-binaries-license.txt` и `licenses/wintun.txt`.
