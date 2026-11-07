# Security policy

## Supported versions

| Version | Security fixes |
| --- | --- |
| 0.4.x (latest: 0.4.0) | Yes, until 0.5.0 is released |
| 0.5 betas | For testing; reports are welcome, fixes go into the next beta |
| 0.3.x and older | No |

Once 0.5.0 is released, only the latest 0.5.x release is supported.

## Report a vulnerability privately

Use [Security → Report a vulnerability](https://github.com/eoftgge/rosetun/security/advisories/new). **Do not open a public Issue** for a vulnerability, and do not include subscription links, server links, credentials or unredacted logs in a report: such links can contain passwords. **Collect report** (Settings → Service and log, Windows) removes them and is safe to attach. On Linux nothing cleans the logs for you: remove them by hand.

## What to report

- **Traffic outside the tunnel:** a way around the kill switch, the DNS lock or Lockdown, including from another account on the same computer while connected.
- **Leaks:** subscription links, credentials, server addresses or visited sites in logs, in **Collect report**, in notifications or in the interface where they should be hidden.
- **Input from outside:** a `rosetun://` link that adds or downloads anything before you confirm; a subscription or list that makes Rosetun write outside its folders or run anything; an update offer that points anywhere but this repository's releases; a program icon read from a network path.

**On Windows:**

- **The SYSTEM service and its named pipe:** a standard account controlling another account's tunnel, changing Lockdown without administrator rights, or a program posing as the service to the app or the `rosetun` command.
- **The installation:** ways for a standard account to change the installation folder or its ancestors, `data` or `data\engines`, and so replace or start a program the service runs.
- **The proxy mode's filters:** with **Access from the local network** on, a device outside this computer's own networks reaching the proxy, or the proxy reachable after the session ended.
- **The update's hold:** traffic leaving while the installer holds the network closed.

**On Linux:**

- **The service's socket and the group `rosetun`** (`/run/rosetun/helper.sock`, mode 0660): an account outside the group reaching the service, a member controlling another account's tunnel or changing Lockdown without root, or a program posing as the service, which the client checks runs as root.
- **polkit:** the action `io.github.eoftgge.rosetun.lockdown` running anything but `/usr/lib/rosetun/rosetun`, or running without an administrator's password; the rule for `rosetun-engine` giving more than the DNS settings of a link in systemd-resolved.
- **The account `rosetun-engine`:** an engine getting more than `CAP_NET_ADMIN`, `CAP_NET_RAW` and `CAP_NET_BIND_SERVICE`, another group, or a way into the service; the service running an engine from a file that is not root's. The exception is a session with an enabled rule by program: its sing-box also holds `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`, which is nearly root, so taking over that sing-box is taking over the computer. Those two reaching any other engine or session is a vulnerability.
- **The nftables table `inet rosetun`:** an account without root changing it, or a change the service does not notice or put back; a program outside the engines' cgroup getting the engines' permit, or outside the app's and the command's scopes getting theirs under Lockdown.
- **`/var/lib/rosetun`:** the folder, Lockdown's record or the lists readable or writable without root; a damaged record that leaves the network open.
- **The `.deb` package:** a maintainer script that opens the network during an upgrade, removes the way out before Lockdown is gone, or leaves a file others can write; an upgrade marker in `/run/rosetun` that an ordinary account can set.
- **`rosetun://` links through the socket** in `$XDG_RUNTIME_DIR`: another account delivering a link to your Rosetun, or the `.desktop` handler running anything but `rosetun-gui --open-url`.

## Out of scope

- Malware already running under your account or as administrator. Lockdown stops accidental leaks, not a program you run yourself (see [How it works](https://eoftgge.github.io/rosetun/en/docs/how-it-works/)).
- An administrator or root changing Rosetun, its service or its firewall rules.
- What your VPN server or subscription provider can see by design: the traffic the server carries, and your real IP address when Rosetun updates a subscription without a connection.
- Bugs in sing-box, Xray or Wintun themselves: please report them to those projects. Do report to us when the way Rosetun runs them opens a hole. In 0.4 one such case was fixed: while connected, sing-box's own firewall permit let any account on the computer start Rosetun's `sing-box.exe` and get around the tunnel.

## How reports are handled

A report is acknowledged, fixed in the next release or beta, and published as a GitHub security advisory once a fixed version is out, with credit if you want it. Rosetun is a young project maintained by one developer and has not had an external security review. A response is intended, but no response or fix deadline is guaranteed.

## A folder that was ever writable

Install-folder checks inspect current ownership and ACLs. They cannot detect access handles opened while a folder or file was writable in the past: changing its ACL does not revoke those handles. If an installation was ever writable by an untrusted account, do not execute its binaries or treat an in-place upgrade as a repair. Disable the affected service using trusted administrative tools before rebooting to clear old handles, then reinstall into a fresh protected folder.

## Verify a download

Compare the file's SHA-256 with `SHA256SUMS.txt` in the release, and verify its provenance with `gh attestation verify .\rosetun-<version>-setup.exe --repo eoftgge/rosetun` or `gh attestation verify rosetun_<version>_amd64.deb --repo eoftgge/rosetun`. The installer is not code-signed yet; see the [code signing policy](CODE_SIGNING_POLICY.md).

## По-русски

**Поддерживаемые версии.** Исправления безопасности получает 0.4.x (последний выпуск 0.4.0) до выхода 0.5.0; беты 0.5 предназначены для проверки, сообщения о них приветствуются, а исправления идут в следующую бету; 0.3.x и старше не поддерживаются. После выхода 0.5.0 поддерживается только последний выпуск 0.5.x.

**Как сообщить.** Приватно, через [Security → Report a vulnerability](https://github.com/eoftgge/rosetun/security/advisories/new), не через публичный Issue. Не прикладывайте ссылки подписок и серверов, пароли и непроверенные журналы: в ссылках бывают пароли. **Собрать отчёт** (Настройки → Служба и журнал, Windows) их вычищает, его прикладывать можно. На Linux журналы за вас никто не очищает: уберите это вручную.

**О чём сообщать:**
- трафик мимо туннеля: обход kill switch, замка DNS или Lockdown, в том числе из другой учётной записи на том же компьютере во время подключения;
- утечки: ссылки подписок, пароли, адреса серверов или посещённые сайты в журналах, в **Собрать отчёт**, в уведомлениях или в интерфейсе там, где они должны быть скрыты;
- данные извне: ссылка `rosetun://`, которая что-то добавляет или скачивает до подтверждения; подписка или список, из-за которых Rosetun пишет за пределы своих папок или что-то запускает; предложение обновиться, ведущее не на релизы этого репозитория; значок программы, прочитанный с сетевого пути.

**На Windows:**
- служба SYSTEM и её именованный канал: обычная учётная запись управляет чужим туннелем, меняет Lockdown без прав администратора, или программа выдаёт себя за службу перед приложением или командой `rosetun`;
- установка: обычная учётная запись может изменить папку установки или её родителей, `data` или `data\engines` и так подменить или запустить программу, которую запускает служба;
- фильтры режима прокси: при включённом **Доступе из локальной сети** к прокси проходит устройство не из сетей этого компьютера, или прокси доступен после конца сеанса;
- удержание при обновлении: трафик выходит, пока установщик держит сеть закрытой.

**На Linux:**
- сокет службы и группа `rosetun` (`/run/rosetun/helper.sock`, режим 0660): к службе проходит учётная запись не из группы, участник управляет чужим туннелем или меняет Lockdown без root, или программа выдаёт себя за службу (клиент проверяет, что служба работает от root);
- polkit: действие `io.github.eoftgge.rosetun.lockdown` запускает что-то кроме `/usr/lib/rosetun/rosetun` или работает без пароля администратора; правило для `rosetun-engine` даёт больше, чем настройки DNS интерфейса в systemd-resolved;
- учётная запись `rosetun-engine`: ядро получает больше, чем `CAP_NET_ADMIN`, `CAP_NET_RAW` и `CAP_NET_BIND_SERVICE`, другую группу или путь в службу; служба запускает ядро из файла, который не принадлежит root. Исключение: сеанс с включённым правилом по программе, его sing-box держит ещё `CAP_SYS_PTRACE` и `CAP_DAC_READ_SEARCH`, это почти root, и захват такого sing-box означает захват компьютера. Если эти два права попали к другому ядру или сеансу, это уязвимость;
- таблица nftables `inet rosetun`: учётная запись без root её меняет, или служба не замечает изменение и не возвращает её; программа вне cgroup ядер получает разрешение ядер, а вне областей приложения и команды их разрешение под Lockdown;
- `/var/lib/rosetun`: папка, запись Lockdown или списки доступны без root; повреждённая запись оставляет сеть открытой;
- пакет `.deb`: сценарий сопровождающего открывает сеть при обновлении, убирает путь выхода раньше Lockdown или оставляет файл, который могут менять другие; метка обновления в `/run/rosetun`, которую может поставить обычная учётная запись;
- ссылки `rosetun://` через сокет в `$XDG_RUNTIME_DIR`: другая учётная запись передаёт ссылку вашему Rosetun, или обработчик `.desktop` запускает что-то кроме `rosetun-gui --open-url`.

**Вне рамок:** вредоносная программа, уже запущенная под вашей учётной записью или от имени администратора (Lockdown защищает от случайных утечек, а не от программ, которые вы запустили сами, см. [Как это устроено](https://eoftgge.github.io/rosetun/ru/docs/how-it-works/)); администратор или root, меняющий Rosetun, его службу или правила брандмауэра; то, что VPN-сервер или провайдер подписки видят по своей природе; ошибки самих sing-box, Xray и Wintun, о них сообщайте этим проектам. Но если уязвимость открывает именно то, как Rosetun их запускает, сообщайте нам: в 0.4 исправлен такой случай, когда во время подключения собственное разрешение sing-box в брандмауэре позволяло любой учётной записи на компьютере запустить `sing-box.exe` из Rosetun и выйти мимо туннеля.

**Как обрабатываются сообщения.** Сообщение подтверждается, исправление выходит в следующем выпуске или бете, после выхода исправленной версии публикуется GitHub security advisory, с упоминанием автора сообщения, если вы этого хотите. Проект молодой, его ведёт один разработчик, внешней проверки безопасности не было; срок ответа и исправления не гарантирован.

**Если папка установки когда-то была доступна на запись.** Проверка папки установки не обнаруживает дескрипторы, открытые до исправления прав: если обычный пользователь когда-либо мог менять файлы программы, не запускайте файлы прежней установки. Сначала отключите службу доверенными системными средствами, затем перезагрузите компьютер и установите программу заново в новую защищённую папку, а не обновляйте поверх.

**Проверка загрузки.** Сравните SHA-256 файла с `SHA256SUMS.txt` из релиза и проверьте происхождение командой `gh attestation verify .\rosetun-<version>-setup.exe --repo eoftgge/rosetun` или `gh attestation verify rosetun_<version>_amd64.deb --repo eoftgge/rosetun`. Установщик пока не подписан, см. [политику подписи кода](CODE_SIGNING_POLICY.md).
