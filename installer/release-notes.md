# Rosetun {{version}}

This 0.2 alpha adds Xray as a server-facing helper behind sing-box. Please report issues in [Issues](https://github.com/eoftgge/rosetun/issues); report vulnerabilities privately through [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

## What's changed

- VLESS + REALITY nodes use Xray automatically while [sing-box#4520](https://github.com/SagerNet/sing-box/issues/4520) is unresolved. sing-box still owns the TUN, rules, DNS and kill switch.
- Advanced settings let you disable Xray or use it for all supported nodes. Hysteria2 stays on sing-box.
- The server list shows which nodes use Xray; the connection screen shows the running chain. Server checks and delay tests use the same chain as the connection.
- Settings from earlier versions migrate to format 4. The former, unavailable `engine: "xray"` setting is replaced with `engine: "sing-box"` and the new Xray choice.

## Install and verify

Windows 10 or 11, x64. Download `{{setup}}`. Run `Get-FileHash .\{{setup}} -Algorithm SHA256` and compare with `{{sha256}}` (also in `SHA256SUMS.txt`). Verify provenance with `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

## Included components

Rosetun includes the unmodified official sing-box {{sing_box_version}} build, licensed under GPL-3.0-or-later; its corresponding source is attached as `sing-box-{{sing_box_version}}-source.tar.gz`. The executable embeds Wintun {{wintun_version}} under the Wintun Prebuilt Binaries License; notices are installed in `licenses/`.

Rosetun also includes the unmodified official Xray-core {{xray_version}} build, licensed under MPL-2.0; its corresponding source is attached as `xray-{{xray_version}}-source.tar.gz`. The MPL text and source notice are installed in `licenses/`. Xray `geoip.dat` and `geosite.dat` are not installed.

## Русский

В этой альфа-версии 0.2 Xray подключает сервер за sing-box. О проблемах сообщайте в [Issues](https://github.com/eoftgge/rosetun/issues), об уязвимостях приватно через [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

### Что изменилось

- Узлы VLESS + REALITY автоматически подключаются через Xray, пока не исправлена [sing-box#4520](https://github.com/SagerNet/sing-box/issues/4520). Туннель, правила, DNS и kill switch по-прежнему работают на sing-box.
- В дополнительных настройках можно выключить Xray или включить его для всех поддерживаемых узлов. Hysteria2 остаётся на sing-box.
- В списке серверов отмечено, какие узлы пойдут через Xray, а на главном экране показана активная цепочка. Проверка серверов и задержки работает через неё же.
- Старые настройки переходят на формат 4. Заглушка `engine: "xray"` заменяется на `engine: "sing-box"` и новый выбор Xray.

### Установка и проверка

Windows 10 или 11, x64. Скачайте `{{setup}}`. Выполните `Get-FileHash .\{{setup}} -Algorithm SHA256` и сравните результат с `{{sha256}}` (также в `SHA256SUMS.txt`). Проверьте происхождение командой `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

### Состав

Rosetun включает официальную сборку sing-box {{sing_box_version}} без изменений под лицензией GPL-3.0-or-later. Исходники приложены как `sing-box-{{sing_box_version}}-source.tar.gz`. В исполняемом файле содержится Wintun {{wintun_version}}; лицензии и уведомления установлены в `licenses/`.

Также включена официальная сборка Xray-core {{xray_version}} без изменений под лицензией MPL-2.0. Исходники приложены как `xray-{{xray_version}}-source.tar.gz`, текст MPL и уведомление установлены в `licenses/`. Файлы Xray `geoip.dat` и `geosite.dat` не устанавливаются.
