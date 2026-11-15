# Security policy

## Supported versions

| Version | Security fixes |
| --- | --- |
| 0.5.x (latest: 0.5.1) | Yes |
| Pre-releases of the next version | For testing; reports are welcome, fixes go into the next one |
| 0.4 and older | No |

## Report a vulnerability privately

Use [Security → Report a vulnerability](https://github.com/eoftgge/rosetun/security/advisories/new). **Do not open a public Issue** for a vulnerability, and do not include subscription links, server links, credentials or unredacted logs in a report: such links can contain passwords. **Collect report** (Settings → Service and log) removes them and is safe to attach.

## What is in scope

Traffic outside the tunnel despite the kill switch, the DNS lock or Lockdown; leaks of subscription links, credentials, server addresses or visited sites; input from outside that is acted on before you confirm it; and, on Windows and Linux, the privileges of the service, its pipe or socket, its files and its installation. Out of scope: malware already running under your account or as administrator, an administrator or root changing Rosetun, what your VPN server or provider sees by design, and bugs in sing-box, Xray or Wintun themselves.

The full list for each system is on the [security model page](https://eoftgge.github.io/rosetun/en/docs/security/).

## How reports are handled

A report is acknowledged, fixed in the next release or beta, and published as a GitHub security advisory once a fixed version is out, with credit if you want it. Rosetun is a young project maintained by one developer and has not had an external security review. A response is intended, but no response or fix deadline is guaranteed.

## По-русски

**Поддерживаемые версии.** Исправления безопасности получает 0.5.x (последний выпуск 0.5.1). Предварительные выпуски следующей версии предназначены для проверки: сообщения о них приветствуются, исправления идут в следующий выпуск. 0.4 и старше не поддерживаются.

**Как сообщить.** Приватно, через [Security → Report a vulnerability](https://github.com/eoftgge/rosetun/security/advisories/new), не через публичный Issue. Не прикладывайте ссылки подписок и серверов, пароли и непроверенные журналы: в ссылках бывают пароли. **Собрать отчёт** (Настройки → Служба и журнал) их вычищает, его прикладывать можно.

**Что входит.** Трафик мимо туннеля при включённых kill switch, замке DNS или Lockdown; утечки ссылок подписок, паролей, адресов серверов и посещённых сайтов; данные извне, к которым Rosetun применяет действие до вашего подтверждения; права службы, её канала или сокета, файлов и установки на Windows и Linux. Не входит: вредоносная программа под вашей учётной записью или от имени администратора, администратор или root, меняющий Rosetun, то, что видят VPN-сервер или провайдер по своей природе, и ошибки самих sing-box, Xray и Wintun. Полный список по системам: [модель безопасности](https://eoftgge.github.io/rosetun/docs/security/).

**Как обрабатываются сообщения.** Сообщение подтверждается, исправление выходит в следующем выпуске или бете, после выхода исправленной версии публикуется GitHub security advisory, с упоминанием автора сообщения, если вы этого хотите. Проект молодой, его ведёт один разработчик, внешней проверки безопасности не было; срок ответа и исправления не гарантирован.
