# Rosetun {{version}}

Rosetun 0.7 shows countries as flags or codes and draws emoji the same on every system.

## What’s new

- **Country flags or codes.** Exits, servers and rule destinations show the country as a flag or as a two-letter code. Choose in **Settings → General → Country display**.
- **Color emoji.** Rosetun bundles the Noto Color Emoji font, so emoji in server names look the same on Windows and Linux. The download is about 5 MB larger.
- **Clearer two-hop setup.** **Connect through** appears only when another exit can carry the path. If TLS fragmentation is the only obstacle, the exit editor says so. [Rules](https://eoftgge.github.io/rosetun/en/docs/rules/#two-hop)
- **Smoother program list.** Loading running programs and their icons no longer stalls the traffic chart.

## Engines and security

Includes sing-box {{sing_box_version}} and [Xray-core {{xray_version}}](https://github.com/XTLS/Xray-core/releases/tag/v{{xray_version}}). Building Rosetun from source requires Rust 1.99 or later.

## Updating from 0.6

Back up your settings before installing. The settings folder is `%APPDATA%\Rosetun` on Windows and `~/.config/rosetun` on Linux. Install over 0.6 to keep your settings and Lockdown. The first save in 0.7 writes **settings format 10** and keeps the format 9 file as `config.v9.json`. Rosetun 0.6 refuses to open a format 10 file and leaves it intact.

**Returning to 0.6.** Disconnect and uninstall 0.7 while keeping your settings. Install 0.6, close it and restore your backup or copy `config.v9.json` over `config.json`. You lose settings changes made in 0.7. Re-enable autostart and Lockdown if you used them. [Install, update and roll back](https://eoftgge.github.io/rosetun/en/docs/install/)

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

Rosetun {{version}} показывает страны флагами или кодами и одинаково рисует эмодзи на всех системах.

### Что нового

- **Флаги или коды стран.** Направления, серверы и цели правил показывают страну флагом или двухбуквенным кодом. Выбор в разделе **Настройки → Основные → Отображение страны**.
- **Цветные эмодзи.** В Rosetun встроен шрифт Noto Color Emoji, поэтому эмодзи в названиях серверов выглядят одинаково на Windows и Linux. Загрузка стала примерно на 5 МБ больше.
- **Понятнее настройка двух звеньев.** Поле **Подключаться через** появляется, только когда путь может пройти через другое направление. Если мешает только фрагментация TLS, редактор направления об этом скажет. [Правила](https://eoftgge.github.io/rosetun/docs/rules/#two-hop)
- **Плавнее список программ.** Загрузка запущенных программ и их значков больше не останавливает график трафика.

### Движки и безопасность

В комплекте sing-box {{sing_box_version}} и [Xray-core {{xray_version}}](https://github.com/XTLS/Xray-core/releases/tag/v{{xray_version}}). Для сборки Rosetun из исходников нужен Rust 1.99 или новее.

### Переход с 0.6

Перед установкой сделайте копию настроек. На Windows они находятся в `%APPDATA%\Rosetun`, на Linux в `~/.config/rosetun`. Установите 0.7 поверх 0.6, чтобы сохранить настройки и Lockdown. При первом сохранении 0.7 записывает **формат 10** и оставляет файл формата 9 как `config.v9.json`. Rosetun 0.6 отказывается открывать файл формата 10 и оставляет его целым.

**Возврат к 0.6.** Отключитесь и удалите 0.7, сохранив настройки. Установите 0.6, закройте приложение и восстановите резервную копию или скопируйте `config.v9.json` поверх `config.json`. Изменения настроек в 0.7 пропадут. Включите автозапуск и Lockdown заново, если пользовались ими. [Установка, обновление и возврат](https://eoftgge.github.io/rosetun/docs/install/)

### Загрузка и проверка

- **Windows 11 x64:** `{{setup}}`, SHA-256 `{{sha256}}`. Установщик без подписи. [Политика подписи кода](https://github.com/eoftgge/rosetun/blob/master/CODE_SIGNING_POLICY.md)
- **Debian 13 amd64:** `{{deb}}`, SHA-256 `{{deb_sha256}}`. Установите пакет через `sudo apt install ./{{deb}}`, выполните `sudo usermod -aG rosetun "$USER"` и перезагрузите компьютер. Совместимые дистрибутивы перечислены в руководстве. [Установка на Linux](https://eoftgge.github.io/rosetun/docs/install/#debian-13)
- **Arch Linux:** соберите `rosetun-bin` по рецепту из репозитория. Он использует архив `{{linux_archive}}`, SHA-256 `{{linux_archive_sha256}}`. [Установка на Arch](https://eoftgge.github.io/rosetun/docs/install/#arch-linux)

Сравните хеш файла с `SHA256SUMS.txt`. Чтобы проверить происхождение сборки, выполните `gh attestation verify <файл> --repo eoftgge/rosetun`, подставив имя скачанного файла. [Инструкция по проверке](https://eoftgge.github.io/rosetun/docs/install/#verify-the-download)

Lockdown и двухзвенные направления остаются экспериментальными. Поддержка рабочих столов и требования к порталу описаны на странице [Поддержка Linux](https://eoftgge.github.io/rosetun/docs/linux/). Проверки защиты и их границы описаны на странице [Гарантии защиты](https://eoftgge.github.io/rosetun/docs/guarantees/).

О проблемах пишите в [Issues](https://github.com/eoftgge/rosetun/issues), об уязвимостях сообщайте [приватно](https://github.com/eoftgge/rosetun/security/advisories/new). Перед отправкой просмотрите файл из **Настройки → Служба и журнал → Собрать отчёт**. Исключите пароли и ссылки подписок.

В комплект входят официальные сборки sing-box и Xray-core. Соответствующие исходники приложены в архивах `sing-box-{{sing_box_version}}-source.tar.gz` (GPL-3.0-or-later) и `xray-{{xray_version}}-source.tar.gz` (MPL-2.0). На Windows sing-box включает Wintun {{wintun_version}} по лицензии Wintun Prebuilt Binaries License. [Компоненты и лицензии](https://eoftgge.github.io/rosetun/docs/licenses/)
