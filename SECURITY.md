# Security policy

## Supported versions

| Version | Security fixes |
| --- | --- |
| 0.6.x | Yes. Use the latest stable release. |
| Pre-releases | For testing. Reports are welcome. |
| 0.5.x and older | No. Upgrade to 0.6. |

## Report a vulnerability privately

Submit the report privately through GitHub. Include your Rosetun version, operating system, connection mode, protection settings and steps to reproduce. **Collect report** (Settings → Service and log) prepares a redacted report. Review it before attaching it, and leave out subscription links, server links, credentials and raw logs. [Report a vulnerability](https://github.com/eoftgge/rosetun/security/advisories/new)

## What is in scope

Report traffic outside the tunnel when the kill switch, DNS lock or Lockdown should have blocked it. Also report exposed credentials or private traffic data, actions on external input before confirmation, and unauthorized access to the service, its pipe or socket, or its files. This includes rule imports that take effect before confirmation and subscription updates that retry directly after a failed VPN request while **Update subscriptions through VPN** is enabled.

The security model describes the scope on Windows, Linux and the experimental Apple Silicon macOS build (where kill switch and Lockdown are unavailable, so traffic may go direct if the tunnel drops), including what the VPN provider can see and where to report bugs in bundled components. [Security model](https://eoftgge.github.io/rosetun/en/docs/security/)

## How reports are handled

The maintainer reviews reports privately and publishes an advisory for confirmed vulnerabilities after a fix is available, with credit if you want it. Rosetun has one maintainer, no external security review and no guaranteed response or fix deadline.

## По-русски

**Поддерживаемые версии.** Исправления безопасности выходят в ветке 0.6.x. Используйте её последний стабильный выпуск. О проблемах в предварительных версиях тоже можно сообщать. Если вы на 0.5.x или более ранней версии, обновитесь до 0.6.

**Как сообщить.** Отправьте приватный отчёт через GitHub. Укажите версию Rosetun, систему, режим подключения, настройки защиты и шаги воспроизведения. **Собрать отчёт** (Настройки → Служба и журнал) готовит отчёт со скрытыми чувствительными данными. Просмотрите его перед отправкой. Исключите ссылки подписок и серверов, пароли и исходные журналы. [Сообщить об уязвимости](https://github.com/eoftgge/rosetun/security/advisories/new)

**Что входит.** Сообщайте о трафике мимо туннеля, когда его должен блокировать kill switch, замок DNS или Lockdown, об утечках паролей и данных о трафике, о действиях с внешними данными до подтверждения и о доступе к службе, её каналу, сокету или файлам без нужных прав. Сюда относятся импорт правил до подтверждения и прямой повтор запроса после сбоя при включённом **Обновлении подписок через VPN**. Границы защиты на Windows, Linux и в экспериментальной сборке для macOS на Apple Silicon (где kill switch и Lockdown недоступны, и при обрыве туннеля трафик может пойти напрямую), видимость данных для провайдера и порядок сообщений об ошибках компонентов описаны в [модели безопасности](https://eoftgge.github.io/rosetun/docs/security/).

**Как обрабатываются сообщения.** Разработчик рассматривает отчёты приватно. Для подтверждённой уязвимости он публикует уведомление после выхода исправления и указывает автора отчёта по его желанию. Rosetun ведёт один разработчик. Внешнего аудита безопасности не было, сроки ответа и исправления не гарантируются.
