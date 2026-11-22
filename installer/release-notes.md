# Rosetun {{version}}

## What’s new

- **Rule groups and templates catalog.** Combine websites, apps, IP addresses and lists into an editable group with one toggle and route. Expand groups inline in the table, add or reorder conditions inside the group editor, group or move rules from the right-click menu, undo with Ctrl+Z and export or import groups. Pick from 8 ready-made presets in **Templates**. [Rules](https://eoftgge.github.io/rosetun/en/docs/rules/#groups)
- **Search and address check in one field.** Search your rules and test where a site, IP or program goes from the same input, with compact square-icon controls on narrow windows. Temporary rules now appear beside the active rule set on the connection screen. [Check an address](https://eoftgge.github.io/rosetun/en/docs/rules/#test)
- **TUIC v5, AnyTLS and WireGuard.** Added `tuic://`, `anytls://`, `wireguard://`, `wg://`, WireGuard `.conf` and sing-box/Xray JSON support (including Cloudflare WARP `reserved` bytes), all carried by sing-box. Subscription import reports now name skipped unsupported protocols. [Subscriptions](https://eoftgge.github.io/rosetun/en/docs/subscriptions/)
- **Verified in-app updates on Windows.** `SHA256SUMS.txt` is now signed with the release key (`SHA256SUMS.txt.minisig`). On Windows, the update notice can download, verify and launch the installer right from the app. Updating stays manual on Linux and macOS. [Install and verify](https://eoftgge.github.io/rosetun/en/docs/install/#windows)
- **macOS (Apple Silicon) · experimental build.** `.pkg` installer with `Rosetun.app`, CLI, `launchd` service, sing-box and Xray for macOS 14+ (`arm64`). Kill switch and Lockdown are unavailable on macOS: traffic may go direct if the tunnel drops. [macOS support](https://eoftgge.github.io/rosetun/en/docs/macos/)
- **Black and White themes.** Added a light porcelain **White** theme with the signature rose accent and a deep OLED **Black** theme with a calm steel-graphite accent in **Settings → General → Color themes**.
- **Country flags or codes and color emoji.** Choose how countries appear in **Settings → General → Country display**. Bundled Noto Color Emoji renders server names consistently on Windows, Linux and macOS.
- **Clearer two-hop setup and smoother program list.** **Connect through** shows only usable exits and explains when TLS fragmentation blocks chaining; loading running programs and icons no longer stalls the traffic chart. [Two-hop exits](https://eoftgge.github.io/rosetun/en/docs/rules/#two-hop)

Includes sing-box {{sing_box_version}} and [Xray-core {{xray_version}}](https://github.com/XTLS/Xray-core/releases/tag/v{{xray_version}}). Building from source requires Rust 1.99+.

## Upgrading from 0.6

Back up your settings before installing (`%APPDATA%\Rosetun` on Windows, `~/.config/rosetun` on Linux). Install 0.7 over 0.6 to keep your settings and Lockdown. On first save, 0.7 writes **format 12** and leaves the format 9 file beside it as `config.v9.json`. Rosetun 0.6 refuses to open a format 12 file and leaves it intact.

**Going back to 0.6.** Disconnect and uninstall 0.7 keeping your settings. Install 0.6, close the app and restore your backup or copy `config.v9.json` over `config.json`. Changes made in 0.7 will not carry back. Re-enable autostart and Lockdown if you used them. [Install, update and rollback](https://eoftgge.github.io/rosetun/en/docs/install/#update)

## Download and verify

- **Windows 11 x64:** `{{setup}}`, SHA-256 `{{sha256}}` (unsigned; [code signing policy](https://github.com/eoftgge/rosetun/blob/master/CODE_SIGNING_POLICY.md)).
- **Debian 13 amd64:** `{{deb}}`, SHA-256 `{{deb_sha256}}` (`sudo apt install ./{{deb}}`, `sudo usermod -aG rosetun "$USER"`, reboot; [Linux guide](https://eoftgge.github.io/rosetun/en/docs/install/#debian-13)).
- **Arch Linux:** `rosetun-bin` recipe using `{{linux_archive}}`, SHA-256 `{{linux_archive_sha256}}` ([Arch guide](https://eoftgge.github.io/rosetun/en/docs/install/#arch-linux)).
- **macOS (Apple Silicon) · experimental build:** `{{macos_pkg}}`, SHA-256 `{{macos_pkg_sha256}}` (macOS 14+, `arm64`; no kill switch or Lockdown; [macOS guide](https://eoftgge.github.io/rosetun/en/docs/install/#macos)).

Verify `SHA256SUMS.txt` with `SHA256SUMS.txt.minisig` (`minisign`), compare hashes and check provenance with `gh attestation verify <file> --repo eoftgge/rosetun` ([details](https://eoftgge.github.io/rosetun/en/docs/install/#verify-the-download)).

Lockdown, two-hop exits and the macOS Apple Silicon build are experimental ([Linux](https://eoftgge.github.io/rosetun/en/docs/linux/) · [macOS](https://eoftgge.github.io/rosetun/en/docs/macos/) · [Protection guarantees](https://eoftgge.github.io/rosetun/en/docs/guarantees/)). Report bugs in [Issues](https://github.com/eoftgge/rosetun/issues) and vulnerabilities [privately](https://github.com/eoftgge/rosetun/security/advisories/new).

Engine sources: `sing-box-{{sing_box_version}}-source.tar.gz` (GPL-3.0-or-later) and `xray-{{xray_version}}-source.tar.gz` (MPL-2.0). On Windows, sing-box includes Wintun {{wintun_version}} under the Wintun Prebuilt Binaries License. [Licenses](https://eoftgge.github.io/rosetun/en/docs/licenses/)

---

## По-русски

### Что нового

- **Группы правил и каталог шаблонов.** Объединяйте сайты, программы, IP-адреса и списки в редактируемую группу с одним переключателем и маршрутом. Группы раскрываются прямо в таблице, условия внутри редактора группы можно добавлять по вкладкам и менять местами, правила объединяются и добавляются в группу через контекстное меню, изменения отменяются по Ctrl+Z и поддерживаются при экспорте и импорте. В окне **Шаблоны** доступны 8 готовых пресетов. [Правила](https://eoftgge.github.io/rosetun/docs/rules/#groups)
- **Поиск и проверка адреса в одном поле.** Поиск по правилам и проверка маршрута для сайта, IP или программы теперь в одной строке, а на узких окнах панель сжимается до компактных иконок. Временные правила отображаются рядом с активным набором на экране подключения. [Проверка адреса](https://eoftgge.github.io/rosetun/docs/rules/#test)
- **TUIC v5, AnyTLS и WireGuard.** Добавлена поддержка `tuic://`, `anytls://`, `wireguard://`, `wg://`, файлов WireGuard `.conf` и sing-box/Xray JSON (включая байты `reserved` для Cloudflare WARP), все через sing-box. В отчёте импорта подписок теперь указаны названия пропущенных неподдерживаемых протоколов. [Подписки](https://eoftgge.github.io/rosetun/docs/subscriptions/)
- **Обновление из приложения на Windows.** Файл `SHA256SUMS.txt` подписывается ключом выпуска (`SHA256SUMS.txt.minisig`). На Windows уведомление о новой версии скачивает, проверяет и запускает установщик прямо из приложения. На Linux и macOS обновление остаётся ручным. [Установка и проверка](https://eoftgge.github.io/rosetun/docs/install/#windows)
- **macOS (Apple Silicon) · экспериментальная сборка.** Установщик `.pkg` с `Rosetun.app`, CLI, службой `launchd`, sing-box и Xray для macOS 14+ (`arm64`). Kill switch и Lockdown на macOS недоступны: при обрыве туннеля трафик может пойти напрямую. [Поддержка macOS](https://eoftgge.github.io/rosetun/docs/macos/)
- **Чёрная и Белая темы.** В **Настройки → Основные → Цветовые темы** добавлены светлая фарфоровая **Белая** тема с фирменным акцентом розы и глубокая OLED **Чёрная** тема со спокойным стально-графитовым акцентом.
- **Флаги или коды стран и цветные эмодзи.** Выбор отображения стран в **Настройки → Основные → Отображение страны**. Встроенный Noto Color Emoji одинаково рисует эмодзи на Windows, Linux и macOS.
- **Понятнее настройка двух звеньев и плавнее список программ.** **Подключаться через** показывает только подходящие направления и поясняет ограничение фрагментации TLS; загрузка процессов и значков больше не тормозит график трафика. [Двухзвенные направления](https://eoftgge.github.io/rosetun/docs/rules/#two-hop)

В комплекте sing-box {{sing_box_version}} и [Xray-core {{xray_version}}](https://github.com/XTLS/Xray-core/releases/tag/v{{xray_version}}). Для сборки из исходников нужен Rust 1.99+.

### Переход с 0.6

Перед установкой сделайте копию настроек (`%APPDATA%\Rosetun` на Windows, `~/.config/rosetun` на Linux). Установите 0.7 поверх 0.6, чтобы сохранить настройки и Lockdown. При первом сохранении 0.7 записывает **формат 12** и оставляет файл формата 9 рядом как `config.v9.json`. Rosetun 0.6 отказывается открывать файл формата 12 и оставляет его целым.

**Возврат к 0.6.** Отключитесь и удалите 0.7, сохранив настройки. Установите 0.6, закройте приложение и восстановите резервную копию или скопируйте `config.v9.json` поверх `config.json`. Изменения настроек в 0.7 не перенесутся. Включите автозапуск и Lockdown заново, если пользовались ими. [Установка, обновление и возврат](https://eoftgge.github.io/rosetun/docs/install/#update)

### Загрузка и проверка

- **Windows 11 x64:** `{{setup}}`, SHA-256 `{{sha256}}` (без подписи; [политика подписи кода](https://github.com/eoftgge/rosetun/blob/master/CODE_SIGNING_POLICY.md)).
- **Debian 13 amd64:** `{{deb}}`, SHA-256 `{{deb_sha256}}` (`sudo apt install ./{{deb}}`, `sudo usermod -aG rosetun "$USER"`, перезагрузка; [установка на Linux](https://eoftgge.github.io/rosetun/docs/install/#debian-13)).
- **Arch Linux:** рецепт `rosetun-bin` с архивом `{{linux_archive}}`, SHA-256 `{{linux_archive_sha256}}` ([установка на Arch](https://eoftgge.github.io/rosetun/docs/install/#arch-linux)).
- **macOS (Apple Silicon) · экспериментальная сборка:** `{{macos_pkg}}`, SHA-256 `{{macos_pkg_sha256}}` (macOS 14+, `arm64`; без kill switch и Lockdown; [установка на macOS](https://eoftgge.github.io/rosetun/docs/install/#macos)).

Проверяйте подпись `SHA256SUMS.txt` через `SHA256SUMS.txt.minisig` (`minisign`), сверяйте хеши и проверяйте происхождение через `gh attestation verify <файл> --repo eoftgge/rosetun` ([инструкция](https://eoftgge.github.io/rosetun/docs/install/#verify-the-download)).

Lockdown, двухзвенные направления и сборка для macOS на Apple Silicon остаются экспериментальными ([Linux](https://eoftgge.github.io/rosetun/docs/linux/) · [macOS](https://eoftgge.github.io/rosetun/docs/macos/) · [Гарантии защиты](https://eoftgge.github.io/rosetun/docs/guarantees/)). О проблемах пишите в [Issues](https://github.com/eoftgge/rosetun/issues), об уязвимостях сообщайте [приватно](https://github.com/eoftgge/rosetun/security/advisories/new).

Исходники ядер: `sing-box-{{sing_box_version}}-source.tar.gz` (GPL-3.0-or-later) и `xray-{{xray_version}}-source.tar.gz` (MPL-2.0). На Windows sing-box включает Wintun {{wintun_version}} по Wintun Prebuilt Binaries License. [Лицензии](https://eoftgge.github.io/rosetun/docs/licenses/)
