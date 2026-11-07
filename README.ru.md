[English](README.md) | Русский


Arch Linux: рецепт AUR `rosetun-bin` подготовлен к 0.5.0; см. [установку и безопасное обновление](https://eoftgge.github.io/rosetun/ru/docs/install/#arch-linux).
<p align="center"><img src=".github/assets/banner.svg" alt="Rosetun: VPN-клиент для Windows и Linux" width="100%"></p>

<p align="center">
  <a href="https://eoftgge.github.io/rosetun/ru/"><img src="https://img.shields.io/badge/%D0%A1%D0%B0%D0%B9%D1%82%20%D0%BF%D1%80%D0%BE%D0%B5%D0%BA%D1%82%D0%B0-8C2338?style=for-the-badge" alt="Сайт проекта"></a>
  <a href="https://eoftgge.github.io/rosetun/ru/docs/"><img src="https://img.shields.io/badge/%D0%94%D0%BE%D0%BA%D1%83%D0%BC%D0%B5%D0%BD%D1%82%D0%B0%D1%86%D0%B8%D1%8F-432D36?style=for-the-badge" alt="Документация"></a>
  <a href="https://eoftgge.github.io/rosetun/ru/help/"><img src="https://img.shields.io/badge/%D0%9F%D0%BE%D0%BC%D0%BE%D1%89%D1%8C-432D36?style=for-the-badge" alt="Помощь"></a>
  <a href="https://eoftgge.github.io/rosetun/ru/providers/"><img src="https://img.shields.io/badge/%D0%94%D0%BB%D1%8F%20%D0%BF%D1%80%D0%BE%D0%B2%D0%B0%D0%B9%D0%B4%D0%B5%D1%80%D0%BE%D0%B2-432D36?style=for-the-badge" alt="Для провайдеров"></a>
</p>

<p align="center">
<img alt="CI" src="https://img.shields.io/github/actions/workflow/status/eoftgge/rosetun/ci.yml?style=for-the-badge&logo=rust">
<img alt="GitHub issues by-label" src="https://img.shields.io/github/issues/eoftgge/rosetun/bug?style=for-the-badge&logo=github">
</p>

<p align="center">
  <a href="https://github.com/eoftgge/rosetun/releases"><img src=".github/assets/download-ru.svg" alt="Скачать Rosetun для Windows" height="56"></a>
  <a href="https://github.com/eoftgge/rosetun/releases"><img src=".github/assets/download-linux-ru.svg" alt="Скачать Rosetun для Debian 13" height="56"></a>
</p>

Rosetun: VPN-клиент для Windows и Linux на sing-box и Xray.
Системная служба защищает от утечек независимо от ядра.

**Молодой проект:** один разработчик с помощью ИИ-агентов, пока мало пользователей. О проблемах пишите в [Issues](https://github.com/eoftgge/rosetun/issues).

## Главное

- Kill switch и защита системного DNS.
- Экспериментальный Lockdown: защита и без подключения.
- TUN и системный прокси (с 0.5).
- Правила по программам, сайтам, IP и спискам; отдельные выходы.
- Подписки провайдеров, QR-коды и ссылки `rosetun://`.
- Локальная сеть и переподключение при обрыве.
- Трей, уведомления, командная строка; русский и английский интерфейсы.

## Установка

Windows 11 x64: скачайте установщик выше и запустите. [Проверка загрузки и установка](https://eoftgge.github.io/rosetun/ru/docs/install/).

Linux amd64 (с предварительной 0.5): проверено на Debian 13; должно работать на Ubuntu 24.04+, Linux Mint 22+ и производных Debian/Ubuntu с glibc >= 2.36, systemd, nftables и polkit. Arch: рецепт AUR подготовлен, работа пока не проверена. Системы без systemd и Flatpak/Snap/AppImage не поддерживаются, поскольку нужна привилегированная служба хоста. [Поддержка Linux](https://eoftgge.github.io/rosetun/ru/docs/linux/). Скачайте `.deb` и выполните:

```sh
sudo apt install ./rosetun_<версия>_amd64.deb
```

[Добавьте себя в группу `rosetun` и перезагрузите компьютер](https://eoftgge.github.io/rosetun/ru/docs/install/#debian-13).

## Документация

[Руководство](https://eoftgge.github.io/rosetun/ru/docs/) · [Помощь](https://eoftgge.github.io/rosetun/ru/help/) · [Для провайдеров](https://eoftgge.github.io/rosetun/ru/providers/).

[Сборка из исходников](https://eoftgge.github.io/rosetun/ru/docs/build/) · [Безопасность](SECURITY.md).

Стабильная версия: 0.4 для Windows. Возможности 0.5 в документации помечены отдельно.

## Устранение неполадок

[Инструкции для Windows и Linux, выход из Lockdown и журналы](https://eoftgge.github.io/rosetun/ru/docs/troubleshooting/).

### Debian 13

[Установка, обновление и удаление](https://eoftgge.github.io/rosetun/ru/docs/install/#debian-13).

## Лицензии

Rosetun: **GPL-3.0-or-later**, © 2026 Sandaar. [LICENSE](LICENSE).
sing-box: GPL-3.0-or-later; Xray-core: MPL-2.0; Wintun: [Prebuilt Binaries License](installer/third-party/wintun-prebuilt-binaries-license.txt); шрифты: OFL-1.1.
[Полные уведомления, исходники компонентов и установленные лицензии](https://eoftgge.github.io/rosetun/ru/docs/licenses/).
Rosetun не связан с sing-box, SagerNet или Project X.
