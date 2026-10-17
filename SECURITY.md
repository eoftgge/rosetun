# Security policy

## Supported versions

Only the latest release of the current line (0.1.x) is supported. Pre-releases of the next version are for testing and are not supported; older releases do not receive security fixes.

## Report a vulnerability privately

Use [Security → Report a vulnerability](https://github.com/eoftgge/rosetun/security/advisories/new). **Do not open a public Issue** for a vulnerability or include subscription links, server links, credentials or unredacted logs in a report. Such links can contain passwords.

In particular, please report problems involving the SYSTEM-privileged service or its named pipe, including ways for a standard user to change the installation directory or its ancestors and replace an executable run by the service. Also report bypasses of the kill switch or DNS lock, and leaks of subscription links, passwords or site addresses into logs or the interface.

Install-folder checks inspect current ownership and ACLs. They cannot detect access handles opened while a folder or file was writable in the past: changing its ACL does not revoke those handles. If an installation was ever writable by an untrusted account, do not execute its binaries or treat an in-place upgrade as a repair. Disable the affected service using trusted administrative tools before rebooting to clear old handles, then reinstall into a fresh protected folder.

Rosetun is a young project maintained by one developer and has not had an external security review. A response is intended, but no response or fix deadline is guaranteed.

## По-русски

Поддерживается только последний выпуск текущей линии (0.1.x); предварительные версии следующего выпуска предназначены для тестирования и не поддерживаются. Сообщайте об уязвимостях приватно через [Security → Report a vulnerability](https://github.com/eoftgge/rosetun/security/advisories/new), не через публичный Issue. Не прикладывайте ссылки подписок и серверов, пароли или непроверенные журналы. Проверка папки установки не обнаруживает дескрипторы, открытые до исправления прав: если обычный пользователь когда-либо мог менять файлы программы, не запускайте файлы прежней установки. Сначала отключите службу доверенными системными средствами, затем перезагрузите компьютер и установите программу заново в новую защищённую папку, а не обновляйте поверх. Проект молодой, его ведёт один разработчик, внешней проверки безопасности не было; срок ответа и исправления не гарантирован.
