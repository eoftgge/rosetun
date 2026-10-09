# Security policy

## Supported versions

Only the latest alpha release is supported. Older alphas may not receive security fixes.

## Report a vulnerability privately

Use [Security → Report a vulnerability](https://github.com/eoftgge/rosetun/security/advisories/new). **Do not open a public Issue** for a vulnerability or include subscription links, server links, credentials or unredacted logs in a report. Such links can contain passwords.

In particular, please report problems involving the SYSTEM-privileged service or its named pipe, including ways for a standard user to change the installation directory or its ancestors and replace an executable run by the service. Also report bypasses of the kill switch or DNS lock, and leaks of subscription links, passwords or site addresses into logs or the interface.

Install-folder checks inspect current ownership and ACLs. They cannot detect access handles opened while a folder or file was writable in the past: changing its ACL does not revoke those handles. If an installation was ever writable by an untrusted account, do not treat an in-place upgrade as a repair; reboot to clear old handles and reinstall into a fresh protected folder.

This is an alpha project maintained by one developer. A response is intended, but no response or fix deadline is guaranteed.

## По-русски

Поддерживается только последняя альфа-версия. Сообщайте об уязвимостях приватно через [Security → Report a vulnerability](https://github.com/eoftgge/rosetun/security/advisories/new), не через публичный Issue. Не прикладывайте ссылки подписок и серверов, пароли или непроверенные журналы. Проверка папки установки не обнаруживает дескрипторы, открытые до исправления прав: если обычный пользователь когда-либо мог менять файлы программы, перезагрузите компьютер и переустановите её в новую защищённую папку, а не обновляйте поверх. Срок ответа и исправления в альфа-версии не гарантирован.
