# Security policy

## Supported versions

| Version | Security fixes |
| --- | --- |
| 0.3.x (latest: 0.3.1) | Yes, until 0.4.0 is released |
| 0.4 betas | For testing; reports are welcome, fixes go into the next beta |
| 0.2.x and older | No |

Once 0.4.0 is released, only the latest 0.4.x release is supported.

## Report a vulnerability privately

Use [Security → Report a vulnerability](https://github.com/eoftgge/rosetun/security/advisories/new). **Do not open a public Issue** for a vulnerability, and do not include subscription links, server links, credentials or unredacted logs in a report: such links can contain passwords. **Collect report** (Settings → Service and log) removes them and is safe to attach.

## What to report

- **The SYSTEM service and its named pipe:** a standard account controlling another account's tunnel, changing Lockdown without administrator rights, or a program posing as the service to the app or the `rosetun` command.
- **The installation:** ways for a standard account to change the installation folder or its ancestors, `data` or `data\engines`, and so replace or start a program the service runs.
- **Traffic outside the tunnel:** a way around the kill switch, the DNS lock or Lockdown, including from another Windows account on the same computer while connected.
- **Leaks:** subscription links, credentials, server addresses or visited sites in logs, in **Collect report**, in notifications or in the interface where they should be hidden.
- **Input from outside:** a `rosetun://` link that adds or downloads anything before you confirm; a subscription or list that makes Rosetun write outside its folders or run anything; an update offer that points anywhere but this repository's releases; a program icon read from a network path.

## Out of scope

- Malware already running under your account or as administrator. Lockdown stops accidental leaks, not a program you run yourself (see [How it works](README.md#how-it-works)).
- An administrator changing Rosetun, its service or its firewall filters.
- What your VPN server or subscription provider can see by design: the traffic the server carries, and your real IP address when Rosetun updates a subscription without a connection.
- Bugs in sing-box, Xray or Wintun themselves: please report them to those projects. Do report to us when the way Rosetun runs them opens a hole. In 0.4 one such case was fixed: while connected, sing-box's own firewall permit let any account on the computer start Rosetun's `sing-box.exe` and get around the tunnel.

## How reports are handled

A report is acknowledged, fixed in the next release or beta, and published as a GitHub security advisory once a fixed version is out, with credit if you want it. Rosetun is a young project maintained by one developer and has not had an external security review. A response is intended, but no response or fix deadline is guaranteed.

## A folder that was ever writable

Install-folder checks inspect current ownership and ACLs. They cannot detect access handles opened while a folder or file was writable in the past: changing its ACL does not revoke those handles. If an installation was ever writable by an untrusted account, do not execute its binaries or treat an in-place upgrade as a repair. Disable the affected service using trusted administrative tools before rebooting to clear old handles, then reinstall into a fresh protected folder.

## Verify a download

Compare the installer's SHA-256 with `SHA256SUMS.txt` in the release, and verify its provenance with `gh attestation verify .\rosetun-<version>-setup.exe --repo eoftgge/rosetun`. The installer is not code-signed yet; see the [code signing policy](CODE_SIGNING_POLICY.md).

## По-русски

**Поддерживаемые версии.** Исправления безопасности получает 0.3.x (последний выпуск 0.3.1) до выхода 0.4.0; беты 0.4 предназначены для проверки, сообщения о них приветствуются, а исправления идут в следующую бету; 0.2.x и старше не поддерживаются. После выхода 0.4.0 поддерживается только последний выпуск 0.4.x.

**Как сообщить.** Приватно, через [Security → Report a vulnerability](https://github.com/eoftgge/rosetun/security/advisories/new), не через публичный Issue. Не прикладывайте ссылки подписок и серверов, пароли и непроверенные журналы: в ссылках бывают пароли. **Собрать отчёт** (Настройки → Служба и журнал) их вычищает, его прикладывать можно.

**О чём сообщать:**
- служба SYSTEM и её именованный канал: обычная учётная запись управляет чужим туннелем, меняет Lockdown без прав администратора, или программа выдаёт себя за службу перед приложением или командой `rosetun`;
- установка: обычная учётная запись может изменить папку установки или её родителей, `data` или `data\engines` и так подменить или запустить программу, которую запускает служба;
- трафик мимо туннеля: обход kill switch, замка DNS или Lockdown, в том числе из другой учётной записи Windows на том же компьютере во время подключения;
- утечки: ссылки подписок, пароли, адреса серверов или посещённые сайты в журналах, в **Собрать отчёт**, в уведомлениях или в интерфейсе там, где они должны быть скрыты;
- данные извне: ссылка `rosetun://`, которая что-то добавляет или скачивает до подтверждения; подписка или список, из-за которых Rosetun пишет за пределы своих папок или что-то запускает; предложение обновиться, ведущее не на релизы этого репозитория; значок программы, прочитанный с сетевого пути.

**Вне рамок:** вредоносная программа, уже запущенная под вашей учётной записью или от имени администратора (Lockdown защищает от случайных утечек, а не от программ, которые вы запустили сами, см. [Как это устроено](README.ru.md#как-это-устроено)); администратор, меняющий Rosetun, его службу или фильтры; то, что VPN-сервер или провайдер подписки видят по своей природе; ошибки самих sing-box, Xray и Wintun, о них сообщайте этим проектам. Но если уязвимость открывает именно то, как Rosetun их запускает, сообщайте нам: в 0.4 исправлен такой случай, когда во время подключения собственное разрешение sing-box в брандмауэре позволяло любой учётной записи на компьютере запустить `sing-box.exe` из Rosetun и выйти мимо туннеля.

**Как обрабатываются сообщения.** Сообщение подтверждается, исправление выходит в следующем выпуске или бете, после выхода исправленной версии публикуется GitHub security advisory, с упоминанием автора сообщения, если вы этого хотите. Проект молодой, его ведёт один разработчик, внешней проверки безопасности не было; срок ответа и исправления не гарантирован.

**Если папка установки когда-то была доступна на запись.** Проверка папки установки не обнаруживает дескрипторы, открытые до исправления прав: если обычный пользователь когда-либо мог менять файлы программы, не запускайте файлы прежней установки. Сначала отключите службу доверенными системными средствами, затем перезагрузите компьютер и установите программу заново в новую защищённую папку, а не обновляйте поверх.

**Проверка загрузки.** Сравните SHA-256 установщика с `SHA256SUMS.txt` из релиза и проверьте происхождение командой `gh attestation verify .\rosetun-<version>-setup.exe --repo eoftgge/rosetun`. Установщик пока не подписан, см. [политику подписи кода](CODE_SIGNING_POLICY.md).
