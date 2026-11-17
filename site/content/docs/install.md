+++
title = "Установка"
weight = 1
aliases = ["/ru/docs/install/"]

[extra]
group = "Начало"
toc_labels = { "debian-13" = "Debian 13" }
+++

{%- set r = load_data(path="data/release.json", required=false) -%}
## Требования {#requirements}

**Windows:** Windows 11, x64. Windows 10 работает на компьютере одного тестировщика; проверки отказов на ней не прогонялись.

**Linux:** amd64 с systemd, nftables и cgroup v2. Проверки проходят на Debian 13. С polkit (`pkexec`, `polkitd`) можно менять Lockdown в приложении. В терминале для этого есть `sudo rosetun lockdown on` и `sudo rosetun lockdown off`.

## Windows {#windows}

Скачайте `{{ r?.installer or "rosetun-<версия>-setup.exe" }}` на странице [Releases]({{ r?.download_url or "https://github.com/eoftgge/rosetun/releases" }}). Установщик пока не подписан: если SmartScreen показывает «Windows protected your PC», нажмите **More info**, затем **Run anyway**. См. [политику подписи кода](https://github.com/eoftgge/rosetun/blob/master/CODE_SIGNING_POLICY.md) (на английском).

Папку установки можно выбрать, но не внутри профиля пользователя и не там, где её могут менять обычные пользователи: служба работает с правами SYSTEM. При удалении настройки в `%APPDATA%\Rosetun` по умолчанию остаются; при желании можно удалить настройки, подписки и правила.

**Обновление:** запустите новый установщик поверх старой версии. Если включён kill switch, сеть на время обновления остаётся закрытой, а приложение запускается и подключается снова. Если подключиться не удалось, экран подключения предлагает **Подключиться** и **Открыть сеть**; то же делает `rosetun open-network`. Lockdown остаётся включённым.

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

**Обновление:** обновите пакет и выполните `sudo rosetun-helper-privileged --restart-for-upgrade`. Обычный `systemctl restart` при kill switch открывает сеть. Специальная команда сохраняет удержание до подключения или `rosetun open-network`. Службы включает пользователь, а не пакет.

**Удаление:** `sudo pacman -R rosetun-bin`. Хук транзакции снимает Lockdown до удаления файлов и прерывает удаление при ошибке. Для аварийного выхода: `sudo rosetun reset-firewall`. Настройки пользователя и группа остаются.

**Статус проверки.** Интерфейс проверяли вручную на Arch. Автоматические системные матрицы Linux охватывают Debian 13.

## Переход с 0.5 {#update}

Перед обновлением скопируйте папку настроек. На Windows настройки по умолчанию находятся в `%APPDATA%\Rosetun`. На Linux они находятся в `~/.config/rosetun`. В копии остаются ссылки подписок, поэтому храните её у себя.

Обновитесь по инструкции для своей системы выше, чтобы сохранить настройки и Lockdown. При первом сохранении 0.6 переводит настройки из формата 8 в **формат 9** и оставляет прежний файл рядом под именем `config.v8.json`. Бета 0.6 уже использует формат 9. Rosetun 0.5 отказывается открывать файл формата 9 и оставляет его целым.

## Возврат к 0.5.1 {#rollback}

1. Отключитесь в 0.6, чтобы восстановить свои настройки прокси.
2. Удалите 0.6, сохранив настройки. На Debian используйте `apt remove`, чтобы сохранить данные, которые удаляет `apt purge`.
3. Установите 0.5.1 и закройте Rosetun.
4. Если настройки были сохранены в формате 9, восстановите `config.json` из копии, сделанной перед обновлением. Если в папке настроек есть `config.v8.json`, можно скопировать его под именем `config.json`. Чтобы сохранить изменения из 0.6, сделайте отдельную копию файла формата 9.
5. Включите заново автозапуск и Lockdown, если пользовались ими.

## Проверка загрузки {#verify-the-download}

В `SHA256SUMS.txt` каждого выпуска есть установщик и пакет. Для выпуска, собранного по тегу, на GitHub есть ещё аттестация происхождения обоих файлов. Аттестация говорит, какой workflow собрал файл; это не подпись кода.

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
