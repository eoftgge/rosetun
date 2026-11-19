# Rosetun {{version}}

Rosetun 0.6 adds rule sharing, experimental two-hop exits and subscription updates through the VPN. On Linux, **Local network** now opens only the networks directly attached to your computer.

## What’s new

- **Import and export rules.** Open the menu beside a rule set to exchange a JSON file or use the clipboard. Import previews the rules, skips duplicates when adding and can create a new set. The default rule has its own checkbox. Ctrl+Z undoes the import. Export includes list links only after you approve the displayed hosts. The CLI offers `rosetun rules export` and `rosetun rules import`. [Rules](https://eoftgge.github.io/rosetun/en/docs/rules/#exchange)
- **Check where a rule sends an address or program.** Use the check field on the Rules tab or `rosetun rules test`. The check sends no network requests and tells you when it lacks enough information for a definite answer. [Rule check](https://eoftgge.github.io/rosetun/en/docs/rules/)
- **Two-hop exits (experimental).** In exit B, select exit A under **Connect through** and point a rule at B. A can use Xray. B must be an HTTP, HTTPS or SOCKS5 proxy at an IP address. The path carries TCP. UDP, including QUIC, is blocked, and a failed hop never falls back to a shorter path. [Setup and limits](https://eoftgge.github.io/rosetun/en/docs/rules/#two-hop)
- **Update subscriptions through VPN.** On by default, this sends subscription downloads and updates through the main VPN server while connected, even when a rule sends the provider’s site directly. A failed VPN request stops with an error. When disconnected, updates use the ordinary path. [Subscriptions](https://eoftgge.github.io/rosetun/en/docs/subscriptions/#updates)
- **Tunnel bypass warning.** With a TUN connection and the kill switch off, Rosetun reports a persistent route outside the tunnel on the connection screen and in the tray. You can enable the kill switch for the next connection from the warning. [Connection and protection](https://eoftgge.github.io/rosetun/en/docs/protection/#bypass-warning)
- **Choose how to measure delay.** In **Settings → Connection**, choose **Full request** or **Repeated request**. The latter is the default and measures the second request over an open connection. [Everyday use](https://eoftgge.github.io/rosetun/en/docs/everyday/)
- **Linux desktop and local network.** Rule files use the desktop’s file dialog. **Collect report**, folder buttons and system checks are available, and Rosetun verifies the system proxy settings it writes on GNOME. Window size and maximized state are restored on Wayland and X11. X11 also restores the position when the monitor is still available. **Private networks behind the router** remains a separate option for wider access. [Linux support](https://eoftgge.github.io/rosetun/en/docs/linux/) · [Local network](https://eoftgge.github.io/rosetun/en/docs/local-network/)
- **Windows startup.** Rosetun allows extra time for a new TUN adapter. If Windows still holds a tunnel address from the previous session, Rosetun asks you to restart the computer.

## Engines and security

Includes sing-box {{sing_box_version}} and [Xray-core {{xray_version}}](https://github.com/XTLS/Xray-core/releases/tag/v{{xray_version}}). Xray updates its default Chrome fingerprint and disables Multipath TCP by default on its TCP listeners. Updates for [CVE-2026-98432 in the Linux kernel](https://security-tracker.debian.org/tracker/CVE-2026-98432) come from your OS distribution. Building Rosetun from source requires Rust 1.99 or later.

## Updating from 0.5

Back up your settings before installing. The settings folder is `%APPDATA%\Rosetun` on Windows and `~/.config/rosetun` on Linux. Install over 0.5 to keep your settings and Lockdown. The first save in 0.6 writes **settings format 9** and keeps the format 8 file as `config.v8.json`. Rosetun 0.5 refuses to open a format 9 file and leaves it intact.

**Returning to 0.5.1.** Disconnect and uninstall 0.6 while keeping your settings. Install 0.5.1, close it and restore your backup or copy `config.v8.json` over `config.json`. You lose settings changes made in 0.6. Re-enable autostart and Lockdown if you used them. [Install, update and roll back](https://eoftgge.github.io/rosetun/en/docs/install/)

## Download and verify

- **Windows 11 x64:** `{{setup}}`, SHA-256 `{{sha256}}`. The installer is unsigned. [Code signing policy](https://github.com/eoftgge/rosetun/blob/master/CODE_SIGNING_POLICY.md)
- **Debian 13 amd64:** `{{deb}}`, SHA-256 `{{deb_sha256}}`. Install with `sudo apt install ./{{deb}}`, run `sudo usermod -aG rosetun "$USER"` and restart the computer. See the guide for compatible distributions. [Linux installation](https://eoftgge.github.io/rosetun/en/docs/install/#debian-13)
- **Arch Linux:** build `rosetun-bin` from the repository recipe. It uses the Linux archive `{{linux_archive}}`, SHA-256 `{{linux_archive_sha256}}`. [Arch installation](https://eoftgge.github.io/rosetun/en/docs/install/#arch-linux)

Compare the file’s hash with `SHA256SUMS.txt`. To verify build provenance, run `gh attestation verify <file> --repo eoftgge/rosetun` with the downloaded filename. [Verification instructions](https://eoftgge.github.io/rosetun/en/docs/install/#verify-the-download)

Lockdown and two-hop exits remain experimental. For desktop support and portal requirements see [Linux support](https://eoftgge.github.io/rosetun/en/docs/linux/). For tested protection and its limits see [Protection guarantees](https://eoftgge.github.io/rosetun/en/docs/guarantees/).

Report problems in [Issues](https://github.com/eoftgge/rosetun/issues). For vulnerabilities, use [private reporting](https://github.com/eoftgge/rosetun/security/advisories/new). Review the file from **Settings → Service and log → Collect report** before sharing it. Leave out credentials and subscription links.

Rosetun bundles the official sing-box and Xray-core builds. Their corresponding sources are attached as `sing-box-{{sing_box_version}}-source.tar.gz` (GPL-3.0-or-later) and `xray-{{xray_version}}-source.tar.gz` (MPL-2.0). On Windows, sing-box includes Wintun {{wintun_version}} under the Wintun Prebuilt Binaries License. [Component notices](https://eoftgge.github.io/rosetun/en/docs/licenses/)

---

## По-русски

Rosetun {{version}} добавляет обмен правилами, экспериментальные двухзвенные направления и обновление подписок через VPN. На Linux **Локальная сеть** теперь открывает только сети, к которым компьютер подключён напрямую.

### Что нового

- **Импорт и экспорт правил.** Откройте меню рядом с набором правил, чтобы выбрать JSON-файл или буфер обмена. Импорт показывает предпросмотр, пропускает дубликаты при добавлении и позволяет создать новый набор. Для правила по умолчанию есть отдельный флажок. Весь импорт отменяется через Ctrl+Z. Ссылки на списки попадают в экспорт после подтверждения показанных доменов. В командной строке есть `rosetun rules export` и `rosetun rules import`. [Правила](https://eoftgge.github.io/rosetun/docs/rules/#exchange)
- **Проверка адреса или программы по правилам.** Воспользуйтесь полем на вкладке **Правила** или командой `rosetun rules test`. Проверка обходится без сетевых запросов и сообщает, если данных для точного ответа не хватает. [Проверка правил](https://eoftgge.github.io/rosetun/docs/rules/)
- **Двухзвенные направления (экспериментально).** В направлении B выберите A в поле **Подключаться через** и направьте правило в B. A может работать через Xray. Для B нужен HTTP-, HTTPS- или SOCKS5-прокси с IP-адресом. Цепочка пропускает TCP. UDP, в том числе QUIC, блокируется, а при сбое звена более короткий маршрут не используется. [Настройка и ограничения](https://eoftgge.github.io/rosetun/docs/rules/#two-hop)
- **Обновление подписок через VPN.** По умолчанию при подключении загрузка и обновление подписок идут через основной VPN-сервер, даже если правило отправляет сайт провайдера напрямую. При сбое запрос завершается ошибкой. Без подключения подписка обновляется обычным путём. [Подписки](https://eoftgge.github.io/rosetun/docs/subscriptions/#updates)
- **Предупреждение об обходе туннеля.** Если при активном TUN и выключенном kill switch появится устойчивый маршрут в обход туннеля, Rosetun сообщит об этом на экране подключения и в трее. Из предупреждения можно включить kill switch для следующего подключения. [Подключение и защита](https://eoftgge.github.io/rosetun/docs/protection/#bypass-warning)
- **Два способа измерить задержку.** В разделе **Настройки → Подключение** можно выбрать **Полный запрос** или **Повторный запрос**. По умолчанию работает второй способ, который измеряет запрос по уже открытому соединению. [Повседневное использование](https://eoftgge.github.io/rosetun/docs/everyday/)
- **Рабочий стол и локальная сеть на Linux.** Файлы правил открываются через системный диалог. Доступны сбор отчёта, открытие папок и проверка системы. На GNOME Rosetun проверяет, что настройки системного прокси применились. Размер окна и состояние развёртывания восстанавливаются на Wayland и X11. На X11 восстанавливается и положение, если монитор по-прежнему доступен. Более широкий доступ к локальным адресам можно включить отдельно через **Частные сети за роутером**. [Поддержка Linux](https://eoftgge.github.io/rosetun/docs/linux/) · [Локальная сеть](https://eoftgge.github.io/rosetun/docs/local-network/)
- **Запуск на Windows.** Rosetun даёт новому адаптеру TUN больше времени на запуск. Если Windows ещё держит адрес туннеля прошлого сеанса, Rosetun предлагает перезагрузить компьютер.

### Движки и безопасность

В комплекте sing-box {{sing_box_version}} и [Xray-core {{xray_version}}](https://github.com/XTLS/Xray-core/releases/tag/v{{xray_version}}). В Xray обновлён отпечаток Chrome по умолчанию, а на слушающих TCP-сокетах по умолчанию выключен Multipath TCP. Исправление [CVE-2026-98432 в ядре Linux](https://security-tracker.debian.org/tracker/CVE-2026-98432) поставляется с обновлением ядра от вашего дистрибутива. Для сборки Rosetun из исходников нужен Rust 1.99 или новее.

### Переход с 0.5

Перед установкой сделайте копию настроек. На Windows они находятся в `%APPDATA%\Rosetun`, на Linux в `~/.config/rosetun`. Установите 0.6 поверх 0.5, чтобы сохранить настройки и Lockdown. При первом сохранении 0.6 записывает **формат 9** и оставляет файл формата 8 как `config.v8.json`. Rosetun 0.5 отказывается открывать файл формата 9 и оставляет его целым.

**Возврат к 0.5.1.** Отключитесь и удалите 0.6, сохранив настройки. Установите 0.5.1, закройте приложение и восстановите резервную копию или скопируйте `config.v8.json` поверх `config.json`. Изменения настроек в 0.6 пропадут. Включите автозапуск и Lockdown заново, если пользовались ими. [Установка, обновление и возврат](https://eoftgge.github.io/rosetun/docs/install/)

### Загрузка и проверка

- **Windows 11 x64:** `{{setup}}`, SHA-256 `{{sha256}}`. Установщик без подписи. [Политика подписи кода](https://github.com/eoftgge/rosetun/blob/master/CODE_SIGNING_POLICY.md)
- **Debian 13 amd64:** `{{deb}}`, SHA-256 `{{deb_sha256}}`. Установите пакет через `sudo apt install ./{{deb}}`, выполните `sudo usermod -aG rosetun "$USER"` и перезагрузите компьютер. Совместимые дистрибутивы перечислены в руководстве. [Установка на Linux](https://eoftgge.github.io/rosetun/docs/install/#debian-13)
- **Arch Linux:** соберите `rosetun-bin` по рецепту из репозитория. Он использует архив `{{linux_archive}}`, SHA-256 `{{linux_archive_sha256}}`. [Установка на Arch](https://eoftgge.github.io/rosetun/docs/install/#arch-linux)

Сравните хеш файла с `SHA256SUMS.txt`. Чтобы проверить происхождение сборки, выполните `gh attestation verify <файл> --repo eoftgge/rosetun`, подставив имя скачанного файла. [Инструкция по проверке](https://eoftgge.github.io/rosetun/docs/install/#verify-the-download)

Lockdown и двухзвенные направления остаются экспериментальными. Поддержка рабочих столов и требования к порталу описаны на странице [Поддержка Linux](https://eoftgge.github.io/rosetun/docs/linux/). Проверки защиты и их границы описаны на странице [Гарантии защиты](https://eoftgge.github.io/rosetun/docs/guarantees/).

О проблемах пишите в [Issues](https://github.com/eoftgge/rosetun/issues), об уязвимостях сообщайте [приватно](https://github.com/eoftgge/rosetun/security/advisories/new). Перед отправкой просмотрите файл из **Настройки → Служба и журнал → Собрать отчёт**. Исключите пароли и ссылки подписок.

В комплект входят официальные сборки sing-box и Xray-core. Соответствующие исходники приложены в архивах `sing-box-{{sing_box_version}}-source.tar.gz` (GPL-3.0-or-later) и `xray-{{xray_version}}-source.tar.gz` (MPL-2.0). На Windows sing-box включает Wintun {{wintun_version}} по лицензии Wintun Prebuilt Binaries License. [Компоненты и лицензии](https://eoftgge.github.io/rosetun/docs/licenses/)
