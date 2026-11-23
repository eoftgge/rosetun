+++
title = "Установка"
weight = 1
aliases = ["/ru/docs/install/"]

[extra]
group = "Начало"
toc_labels = { "debian-13" = "Debian 13", "macos" = "macOS (Apple Silicon)" }
+++

{%- set r = load_data(path="data/release.json", required=false) -%}
## Требования {#requirements}

**Windows:** Windows 11, x64. Windows 10 работает на компьютере одного тестировщика; проверки отказов на ней не прогонялись.

**Linux:** amd64 с systemd, nftables и cgroup v2. Проверки проходят на Debian 13. С polkit (`pkexec`, `polkitd`) можно менять Lockdown в приложении. В терминале для этого есть `sudo rosetun lockdown on` и `sudo rosetun lockdown off`.

**macOS (Apple Silicon) · экспериментальная сборка:** macOS 14 Sonoma или новее на процессоре Apple Silicon (`arm64`). Intel Mac не поддерживаются. Kill switch и Lockdown на macOS недоступны.

## Windows {#windows}

Скачайте `{{ r?.installer or "rosetun-<версия>-setup.exe" }}` на странице [Releases]({{ r?.download_url or "https://github.com/eoftgge/rosetun/releases" }}). Установщик пока не подписан: если SmartScreen показывает «Windows protected your PC», нажмите **More info**, затем **Run anyway**. См. [политику подписи кода](https://github.com/eoftgge/rosetun/blob/master/CODE_SIGNING_POLICY.md) (на английском).

Папку установки можно выбрать, но не внутри профиля пользователя и не там, где её могут менять обычные пользователи: служба работает с правами SYSTEM. При удалении настройки в `%APPDATA%\Rosetun` по умолчанию остаются; при желании можно удалить настройки, подписки и правила.

**Обновление:** запустите новый установщик поверх старой версии. Если включён kill switch, сеть на время обновления остаётся закрытой, а приложение запускается и подключается снова. Если подключиться не удалось, экран подключения предлагает **Подключиться** и **Открыть сеть**; то же делает `rosetun open-network`. Lockdown остаётся включённым.

С 0.7 на Windows уведомление о новой версии предлагает **Скачать**: программа скачивает установщик и проверяет его, затем кнопка меняется на **Установить и перезапустить**. Установка просит права администратора. Есть также **Открыть на GitHub** и **Пропустить эту версию**. На Linux и macOS обновление остаётся ручным.

{% if not r?.deb_url %}

В этом выпуске нет пакета Debian. См. GitHub Releases.

{% endif %}

## Debian / Ubuntu / Linux Mint {#debian-13}

**Дистрибутивы (amd64, glibc 2.36 или новее):** Debian 13 проверен системными матрицами. На Ubuntu 24.04+, Linux Mint 22+ и других производных Debian/Ubuntu с этой или более новой glibc, systemd, nftables и polkit должен работать тот же `.deb`; ручная проверка Ubuntu ещё впереди.

Системы без systemd и пакеты Flatpak, Snap и AppImage не поддерживаются: Rosetun нужны привилегированная системная служба и доступ к файрволу и TUN-устройству хоста.

{% if r?.deb_url %}

Скачайте `{{ r?.deb or "rosetun_<версия>_amd64.deb" }}` со страницы [Releases]({{ r?.deb_url or "https://github.com/eoftgge/rosetun/releases" }}), [проверьте его](../install/#verify-the-download), установите и добавьте себя в группу, которой доступна служба:

```
sudo apt install ./{{ r?.deb or "rosetun_<версия>_amd64.deb" }}
sudo usermod -aG rosetun "$USER"
```

{% endif %}

Затем **перезагрузите компьютер**. Выхода из системы мало: пользовательский менеджер systemd может пережить выход и передавать запущенным программам старые группы. Если пропустить последнюю команду, окно предложит то же самое кнопкой **Добавить меня**.

**Обновление:** установите новый пакет так же. Если kill switch включён, сеть на время обновления остаётся закрытой: открытое окно перезапустится само и подключится снова. Без окна `rosetun status` покажет `network: held closed`, `rosetun connect` подключит, а `rosetun open-network` откроет сеть. Lockdown остаётся включённым.

**Удаление:** `sudo apt remove rosetun` сначала снимает Lockdown. Если снять не удалось, удаление останавливается и Rosetun остаётся, чтобы сеть можно было открыть.

**Полное удаление:** `sudo apt purge rosetun` удаляет ещё списки и состояние в `/var/lib/rosetun`. Настройки и запись автозапуска в домашней папке (`~/.config/rosetun`) и группа `rosetun` остаются.

## Arch Linux {#arch-linux}

Рецепт `rosetun-bin` находится в репозитории Rosetun. Просмотрите рецепт для нужного выпуска перед сборкой пакета на Arch.

```
git clone --branch v{{ r?.version or "VERSION" }} https://github.com/eoftgge/rosetun.git
cd rosetun
bash tools/arch/update-pkgbuild.sh v{{ r?.version or "VERSION" }}
cd packaging/arch
makepkg -si
sudo systemctl enable --now rosetun-helper rosetun-lockdown
sudo usermod -aG rosetun "$USER"
sudo reboot
```

Пакет устанавливает файлы выпуска вместе с соответствующими сборками sing-box и Xray.

### Системный DNS в режиме TUN {#arch-dns}

Включите `systemd-resolved`, чтобы sing-box мог зарегистрировать DNS-сервер туннеля в системе.

```sh
sudo systemctl enable --now systemd-resolved.service
```

Если Rosetun уже подключён, отключитесь и подключитесь снова. Затем проверьте DNS на интерфейсе туннеля и выполните системный запрос.

```sh
resolvectl status rosetun0
timeout 5s getent ahosts example.org
```

В строке **DNS Servers** должен появиться сервер туннеля. Если он есть, а запрос по-прежнему не проходит, проверьте, использует ли система `systemd-resolved`. Для его локального DNS рекомендуемая настройка `/etc/resolv.conf` представляет собой символическую ссылку на `/run/systemd/resolve/stub-resolv.conf`. [Справка systemd-resolved](https://man.archlinux.org/man/systemd-resolved.service.8.en)

**Обновление:** обновите пакет и выполните `sudo rosetun-helper-privileged --restart-for-upgrade`. Обычный `systemctl restart` при kill switch открывает сеть. Специальная команда сохраняет удержание до подключения или `rosetun open-network`. Службы включает пользователь, а не пакет.

**Удаление:** `sudo pacman -R rosetun-bin`. Хук транзакции снимает Lockdown до удаления файлов и прерывает удаление при ошибке. Для аварийного выхода: `sudo rosetun reset-firewall`. Настройки пользователя и группа остаются.

**Статус проверки.** Интерфейс проверяли вручную на Arch. Автоматические системные матрицы Linux охватывают Debian 13.

## macOS (Apple Silicon) · экспериментальная сборка {#macos}

Экспериментальная сборка предназначена только для Mac на Apple Silicon (`arm64`) с macOS 14 или новее. **Kill switch и Lockdown на macOS недоступны:** при обрыве туннеля трафик может пойти напрямую. Подробности и ограничения описаны на странице [Поддержка macOS](../macos/).

{% if r?.macos_url %}

Скачайте `{{ r.macos }}` со страницы [Releases]({{ r.macos_url }}), [проверьте его](../install/#verify-the-download) и откройте установщик `.pkg` (или установите из терминала):

```
sudo installer -pkg ./{{ r.macos }} -target /
```

{% else %}

В этом стабильном выпуске нет экспериментального пакета macOS. См. [GitHub Releases](https://github.com/eoftgge/rosetun/releases).

{% endif %}

Установщик ставит `/Applications/Rosetun.app`, команду `/usr/local/bin/rosetun`, вспомогательные бинарники и ядра в `/usr/local/libexec/rosetun` (принадлежат `root:wheel`) и запускает системную службу `launchd` (`/Library/LaunchDaemons/io.github.eoftgge.rosetun.helper.plist`). Настройки пользователя хранятся в `~/.config/rosetun`.

Если пакет `.pkg` в выпуске не подписан Apple Developer ID, macOS Gatekeeper может заблокировать открытие двойным щелчком: проверьте контрольную сумму и аттестацию ниже, затем откройте пакет через контекстное меню (**Открыть**) или установите командой `sudo installer`.

**Обновление:** запустите новый `.pkg` поверх установленного. Сценарий установки аккуратно останавливает службу, обновляет файлы и запускает её снова. Настройки в `~/.config/rosetun` сохраняются.

**Удаление:** выполните в терминале:

```
sudo /usr/local/libexec/rosetun/uninstall.sh
```

Скрипт останавливает службу `launchd`, удаляет `Rosetun.app`, CLI, службу, ядра, сокет, журнал `/private/var/log/rosetun-helper.log` и запись `pkgutil`. Настройки в `~/.config/rosetun` остаются. Добавьте `--purge`, чтобы дополнительно удалить состояние службы и списки из `/Library/Application Support/Rosetun`.

## Переход с 0.6 {#update}

Перед обновлением скопируйте папку настроек. На Windows настройки по умолчанию находятся в `%APPDATA%\Rosetun`. На Linux они находятся в `~/.config/rosetun`. В копии остаются ссылки подписок, поэтому храните её у себя.

Обновитесь по инструкции для своей системы выше, чтобы сохранить настройки и Lockdown. При первом сохранении 0.7 переводит настройки из формата 9 в **формат 13** и оставляет прежний файл рядом (`config.v9.json` после 0.6 или `config.v12.json` после 0.7.0-beta.1). Rosetun 0.6 и 0.7.0-beta.1 отказываются открывать файл формата 13 и оставляют его целым.

## Возврат к 0.6 {#rollback}

1. Отключитесь в 0.7, чтобы восстановить свои настройки прокси.
2. Удалите 0.7, сохранив настройки. На Debian используйте `apt remove`, чтобы сохранить данные, которые удаляет `apt purge`.
3. Установите 0.6 и закройте Rosetun.
4. Если настройки были сохранены в формате 13, восстановите `config.json` из копии, сделанной перед обновлением. Если в папке настроек есть `config.v9.json`, можно скопировать его под именем `config.json`. Чтобы сохранить изменения из 0.7, сделайте отдельную копию файла формата 13.
5. Включите заново автозапуск и Lockdown, если пользовались ими.

## Проверка загрузки {#verify-the-download}

В `SHA256SUMS.txt` каждого выпуска есть установщики и пакеты. Для выпуска, собранного по тегу, на GitHub есть ещё аттестация происхождения файлов. Аттестация говорит, какой workflow собрал файл; это не подпись кода.

Начиная с 0.7 `SHA256SUMS.txt` подписан ключом выпуска. Скачайте `SHA256SUMS.txt` и `SHA256SUMS.txt.minisig` со страницы выпуска и проверьте подпись с помощью [minisign](https://jedisct1.github.io/minisign/):

```
minisign -Vm SHA256SUMS.txt -P RWSDO2nJ1GqGnPiNy6v88Pz2L8A8Ru/1XSux4rHWdO9FIcLudiCYltbQ
```

Тот же публичный ключ лежит в репозитории: [`minisign.pub`](https://github.com/eoftgge/rosetun/blob/master/crates/rosetun-core/keys/minisign.pub). Выпуски до 0.7 не подписаны.

Windows:

```
Get-FileHash .\{{ r?.installer or "rosetun-<версия>-setup.exe" }} -Algorithm SHA256
gh attestation verify .\{{ r?.installer or "rosetun-<версия>-setup.exe" }} --repo eoftgge/rosetun
```

{% if r?.deb_url %}

Debian:

```
sha256sum --check --ignore-missing SHA256SUMS.txt
gh attestation verify {{ r?.deb or "rosetun_<версия>_amd64.deb" }} --repo eoftgge/rosetun
```

{% endif %}

{% if r?.macos_url %}

macOS (Apple Silicon):

```
shasum -a 256 {{ r.macos }}
gh attestation verify {{ r.macos }} --repo eoftgge/rosetun
```

{% endif %}
