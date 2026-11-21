# Rosetun {{version}}

## What’s new

- **Country flags or codes.** Choose how countries appear in **Settings → General → Country display**.
- **Color emoji.** Bundled Noto Color Emoji renders server names consistently on Windows, Linux and macOS.
- **Clearer two-hop setup.** **Connect through** shows only usable exits and explains when TLS fragmentation blocks chaining. [Rules](https://eoftgge.github.io/rosetun/en/docs/rules/#two-hop)
- **Smoother program list.** Loading running programs and icons no longer stalls the traffic chart.
- **macOS (Apple Silicon) · experimental build.** `.pkg` installer with `Rosetun.app`, CLI, `launchd` service, sing-box and Xray. Kill switch and Lockdown are unavailable on macOS: traffic may go direct if the tunnel drops. [macOS support](https://eoftgge.github.io/rosetun/en/docs/macos/)

Includes sing-box {{sing_box_version}} and [Xray-core {{xray_version}}](https://github.com/XTLS/Xray-core/releases/tag/v{{xray_version}}). Building from source requires Rust 1.99+.

## Download and verify

- **Windows 11 x64:** `{{setup}}`, SHA-256 `{{sha256}}` (unsigned; [code signing policy](https://github.com/eoftgge/rosetun/blob/master/CODE_SIGNING_POLICY.md)).
- **Debian 13 amd64:** `{{deb}}`, SHA-256 `{{deb_sha256}}` (`sudo apt install ./{{deb}}`, `sudo usermod -aG rosetun "$USER"`, reboot; [Linux guide](https://eoftgge.github.io/rosetun/en/docs/install/#debian-13)).
- **Arch Linux:** `rosetun-bin` recipe using `{{linux_archive}}`, SHA-256 `{{linux_archive_sha256}}` ([Arch guide](https://eoftgge.github.io/rosetun/en/docs/install/#arch-linux)).
- **macOS (Apple Silicon) · experimental build:** `{{macos_pkg}}`, SHA-256 `{{macos_pkg_sha256}}` (macOS 14+, `arm64`; no kill switch or Lockdown; [macOS guide](https://eoftgge.github.io/rosetun/en/docs/install/#macos)).

Verify hashes against `SHA256SUMS.txt` and provenance with `gh attestation verify <file> --repo eoftgge/rosetun` ([details](https://eoftgge.github.io/rosetun/en/docs/install/#verify-the-download)).

Lockdown, two-hop exits and the macOS Apple Silicon build are experimental ([Linux](https://eoftgge.github.io/rosetun/en/docs/linux/) · [macOS](https://eoftgge.github.io/rosetun/en/docs/macos/) · [Protection guarantees](https://eoftgge.github.io/rosetun/en/docs/guarantees/)). Report bugs in [Issues](https://github.com/eoftgge/rosetun/issues) and vulnerabilities [privately](https://github.com/eoftgge/rosetun/security/advisories/new).

Engine sources: `sing-box-{{sing_box_version}}-source.tar.gz` (GPL-3.0-or-later) and `xray-{{xray_version}}-source.tar.gz` (MPL-2.0). On Windows, sing-box includes Wintun {{wintun_version}} under the Wintun Prebuilt Binaries License. [Licenses](https://eoftgge.github.io/rosetun/en/docs/licenses/)

---

## По-русски

### Что нового

- **Флаги или коды стран.** Выбор отображения стран в **Настройки → Основные → Отображение страны**.
- **Цветные эмодзи.** Встроенный Noto Color Emoji одинаково рисует эмодзи на Windows, Linux и macOS.
- **Понятнее настройка двух звеньев.** **Подключаться через** показывает только подходящие направления и поясняет ограничение фрагментации TLS. [Правила](https://eoftgge.github.io/rosetun/docs/rules/#two-hop)
- **Плавнее список программ.** Загрузка процессов и значков больше не тормозит график трафика.
- **macOS (Apple Silicon) · экспериментальная сборка.** Установщик `.pkg` с `Rosetun.app`, CLI, службой `launchd`, sing-box и Xray. Kill switch и Lockdown на macOS недоступны: при обрыве туннеля трафик может пойти напрямую. [Поддержка macOS](https://eoftgge.github.io/rosetun/docs/macos/)

В комплекте sing-box {{sing_box_version}} и [Xray-core {{xray_version}}](https://github.com/XTLS/Xray-core/releases/tag/v{{xray_version}}). Для сборки из исходников нужен Rust 1.99+.

### Загрузка и проверка

- **Windows 11 x64:** `{{setup}}`, SHA-256 `{{sha256}}` (без подписи; [политика подписи кода](https://github.com/eoftgge/rosetun/blob/master/CODE_SIGNING_POLICY.md)).
- **Debian 13 amd64:** `{{deb}}`, SHA-256 `{{deb_sha256}}` (`sudo apt install ./{{deb}}`, `sudo usermod -aG rosetun "$USER"`, перезагрузка; [установка на Linux](https://eoftgge.github.io/rosetun/docs/install/#debian-13)).
- **Arch Linux:** рецепт `rosetun-bin` с архивом `{{linux_archive}}`, SHA-256 `{{linux_archive_sha256}}` ([установка на Arch](https://eoftgge.github.io/rosetun/docs/install/#arch-linux)).
- **macOS (Apple Silicon) · экспериментальная сборка:** `{{macos_pkg}}`, SHA-256 `{{macos_pkg_sha256}}` (macOS 14+, `arm64`; без kill switch и Lockdown; [установка на macOS](https://eoftgge.github.io/rosetun/docs/install/#macos)).

Проверяйте хеши по `SHA256SUMS.txt` и происхождение через `gh attestation verify <файл> --repo eoftgge/rosetun` ([инструкция](https://eoftgge.github.io/rosetun/docs/install/#verify-the-download)).

Lockdown, двухзвенные направления и сборка для macOS на Apple Silicon остаются экспериментальными ([Linux](https://eoftgge.github.io/rosetun/docs/linux/) · [macOS](https://eoftgge.github.io/rosetun/docs/macos/) · [Гарантии защиты](https://eoftgge.github.io/rosetun/docs/guarantees/)). О проблемах пишите в [Issues](https://github.com/eoftgge/rosetun/issues), об уязвимостях сообщайте [приватно](https://github.com/eoftgge/rosetun/security/advisories/new).

Исходники ядер: `sing-box-{{sing_box_version}}-source.tar.gz` (GPL-3.0-or-later) и `xray-{{xray_version}}-source.tar.gz` (MPL-2.0). На Windows sing-box включает Wintun {{wintun_version}} по Wintun Prebuilt Binaries License. [Лицензии](https://eoftgge.github.io/rosetun/docs/licenses/)
