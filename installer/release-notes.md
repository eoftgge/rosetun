# Rosetun {{version}}

This is an alpha release. Bugs are expected. Report them in [Issues](https://github.com/eoftgge/rosetun/issues); report vulnerabilities privately through [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

## What's new

- **Change the server, rules or DNS while connected.** Choosing another server or rule set applies at once; after editing rules or DNS, select **Apply**. The tunnel restarts for a second or two without disconnecting, and the kill switch keeps traffic blocked meanwhile. If the new server does not work, Rosetun returns to the previous one.
- **Temporary rules.** Mark a new rule **Temporary** to keep it only until you disconnect. It applies at once, is never saved, and survives automatic reconnects. **Keep permanently** in the rule's menu turns it into an ordinary rule.
- **Traffic tab.** Download and upload speed, session totals and a chart over 1, 5 or 15 minutes. The connection screen keeps one line with the current speed.
- Server checks are now called **Ping** and **Real delay**.

When you switch to a server given by name while connected, its address is resolved through the current tunnel. Settings and subscriptions from 0.1.0-alpha.2 are kept.

## Install

Windows 10 or 11, x64. Download `{{setup}}` from this release. The installer is not code-signed yet: if SmartScreen says "Windows protected your PC", select **More info** and then **Run anyway**.

## Verify

Run `Get-FileHash .\{{setup}} -Algorithm SHA256` and compare the result with `{{sha256}}` (also in `SHA256SUMS.txt`). Verify its provenance with `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

## Included

Rosetun includes the unmodified official sing-box {{sing_box_version}} build, licensed under GPL-3.0-or-later. The corresponding source is attached as `sing-box-{{sing_box_version}}-source.tar.gz`.

## Русский

Это альфа-версия. Ошибки возможны. Сообщайте о них в [Issues](https://github.com/eoftgge/rosetun/issues), а об уязвимостях сообщайте приватно через [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

### Что нового

- **Смена сервера, правил и DNS при подключении.** Другой сервер или набор правил применяется сразу; после правки правил или DNS нажмите **Применить**. Туннель перезапускается на секунду или две без отключения, а kill switch в это время держит трафик заблокированным. Если новый сервер не работает, Rosetun вернётся к прежнему.
- **Временные правила.** Отметьте новое правило как **Временное**, и оно будет действовать только до отключения. Правило применяется сразу, никуда не сохраняется и переживает автоматическое переподключение. **Сохранить навсегда** в меню правила превращает его в обычное.
- **Вкладка «Трафик».** Скорость загрузки и отдачи, итоги за сеанс и график за 1, 5 или 15 минут. На экране подключения осталась одна строка с текущей скоростью.
- Проверки серверов теперь называются **Пинг** и **Реальная задержка**.

Если при подключении переключиться на сервер, заданный именем, его адрес определяется через текущий туннель. Настройки и подписки из 0.1.0-alpha.2 сохраняются.

### Установка

Windows 10 или 11, x64. Скачайте `{{setup}}` из этого релиза. Установщик пока не подписан: если SmartScreen показывает «Windows protected your PC», нажмите **More info**, затем **Run anyway**.

### Проверка

Выполните `Get-FileHash .\{{setup}} -Algorithm SHA256` и сравните результат с `{{sha256}}` (он также указан в `SHA256SUMS.txt`). Проверьте происхождение командой `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

### Состав

Rosetun включает официальную сборку sing-box {{sing_box_version}} без изменений, лицензия GPL-3.0-or-later. Соответствующие исходники приложены в архиве `sing-box-{{sing_box_version}}-source.tar.gz`.
