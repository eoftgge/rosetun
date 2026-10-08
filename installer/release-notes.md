# Rosetun {{version}}

This is an alpha release. Bugs are expected. Report them in [Issues](https://github.com/eoftgge/rosetun/issues); report vulnerabilities privately through [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

## What's new

- **Server checks.** The **Check** menu on a subscription card offers a **Quick check** (TCP connection time, available when disconnected) and a **Full check** (an HTTPS request through each server, available while connected). A server that accepts a TCP connection but fails the full check is marked "not working". Right-click a server to check just that one.
- **Delay** of the current server on the connection screen, measured a few seconds after connecting; click it to measure again.
- A compact rule set menu on the connection screen.
- **Open** and **All processes** tabs in the add-rule dialog.
- Drag subscriptions by their header; the card shows time remaining before expiry (amber in the last 7 days, red once expired).
- "Applies on next connect" appears only after a setting really changed.

Each full check sends one HTTPS request to `https://cp.cloudflare.com/generate_204` through each checked server; measuring delay sends one through the current server. Settings and subscriptions from 0.1.0-alpha.1 are kept.

## Install

Windows 10 or 11, x64. Download `{{setup}}` from this release. The installer is not code-signed yet: if SmartScreen says "Windows protected your PC", select **More info** and then **Run anyway**.

## Verify

Run `Get-FileHash .\{{setup}} -Algorithm SHA256` and compare the result with `{{sha256}}` (also in `SHA256SUMS.txt`). Verify its provenance with `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

## Included

Rosetun includes the unmodified official sing-box {{sing_box_version}} build, licensed under GPL-3.0-or-later. The corresponding source is attached as `sing-box-{{sing_box_version}}-source.tar.gz`.

## Русский

Это альфа-версия. Ошибки возможны. Сообщайте о них в [Issues](https://github.com/eoftgge/rosetun/issues), а об уязвимостях сообщайте приватно через [Security](https://github.com/eoftgge/rosetun/security/advisories/new).

### Что нового

- **Проверка серверов.** Меню **Проверить** в карточке подписки предлагает **Быструю проверку** (время установки TCP-соединения, доступна без подключения) и **Полную проверку** (HTTPS-запрос через каждый сервер, работает и при подключении). Если TCP-соединение установлено, но запрос через сервер не прошёл, полная проверка покажет «не работает». Чтобы проверить один сервер, нажмите на него правой кнопкой.
- **Задержка** текущего сервера на главном экране: измеряется через несколько секунд после подключения, по клику измеряется заново.
- Компактное меню набора правил на главном экране.
- Вкладки **Открытые** и **Все процессы** в окне добавления правила.
- Подписки перетаскиваются за заголовок; карточка показывает, сколько времени осталось до окончания подписки (жёлтым в последние 7 дней, красным после истечения).
- «Применится при следующем подключении» появляется, только если настройка действительно изменилась.

Полная проверка отправляет по одному HTTPS-запросу к `https://cp.cloudflare.com/generate_204` через каждый проверяемый сервер; замер задержки — один через текущий сервер. Настройки и подписки из 0.1.0-alpha.1 сохраняются.

### Установка

Windows 10 или 11, x64. Скачайте `{{setup}}` из этого релиза. Установщик пока не подписан: если SmartScreen показывает «Windows protected your PC», нажмите **More info**, затем **Run anyway**.

### Проверка

Выполните `Get-FileHash .\{{setup}} -Algorithm SHA256` и сравните результат с `{{sha256}}` (он также указан в `SHA256SUMS.txt`). Проверьте происхождение командой `gh attestation verify .\{{setup}} --repo eoftgge/rosetun`.

### Состав

Rosetun включает официальную сборку sing-box {{sing_box_version}} без изменений, лицензия GPL-3.0-or-later. Соответствующие исходники приложены в архиве `sing-box-{{sing_box_version}}-source.tar.gz`.
