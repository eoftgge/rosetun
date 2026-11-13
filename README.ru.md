[English](README.md) | Русский

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
  <a href="https://github.com/eoftgge/rosetun/releases/latest"><img src=".github/assets/download.svg" alt="Download" height="56"></a>
</p>

Rosetun: VPN-клиент для Windows и Linux на sing-box и Xray.
Системная служба защищает от утечек независимо от ядра.

**Стабильный выпуск: 0.5.1 · Windows и Linux.**

**Молодой проект:** один разработчик с помощью ИИ-агентов, пока мало пользователей. О проблемах пишите в [Issues](https://github.com/eoftgge/rosetun/issues).

## Главное

- Kill switch и защита системного DNS.
- Экспериментальный Lockdown: защита и без подключения.
- TUN и системный прокси.
- Правила по программам, сайтам, IP и спискам; отдельные выходы.
- Подписки провайдеров, QR-коды и ссылки `rosetun://`.
- Локальная сеть и переподключение при обрыве.
- Трей, уведомления, командная строка; русский и английский интерфейсы.

## Установка

Выберите файл на странице выпуска по кнопке выше:

- **Windows 11 x64:** запустите `rosetun-0.5.1-setup.exe`.
- **Debian / Ubuntu / Linux Mint, amd64:** установите `rosetun_0.5.1_amd64.deb`, добавьте себя в группу службы и перезагрузите компьютер:

```sh
sudo apt install ./rosetun_0.5.1_amd64.deb
sudo usermod -aG rosetun "$USER"
sudo reboot
```

Debian 13 проверен. Ubuntu 24.04+, Linux Mint 22+ и совместимые производные должны работать; см. [поддержку Linux и требования](https://eoftgge.github.io/rosetun/ru/docs/linux/).

**Arch Linux:** соберите бинарный пакет по рецепту из этого репозитория; публикация в AUR и проверка работы пока не выполнены. [Установка и безопасное обновление](https://eoftgge.github.io/rosetun/ru/docs/install/#arch-linux).

[Проверка загрузки, обновление, удаление и выход из Lockdown](https://eoftgge.github.io/rosetun/ru/docs/install/).

## Документация

[Руководство](https://eoftgge.github.io/rosetun/ru/docs/) · [Помощь](https://eoftgge.github.io/rosetun/ru/help/) · [Для провайдеров](https://eoftgge.github.io/rosetun/ru/providers/).

[Сборка из исходников](https://eoftgge.github.io/rosetun/ru/docs/build/) · [Безопасность](SECURITY.md).

## Устранение неполадок

[Инструкции для Windows и Linux, выход из Lockdown и журналы](https://eoftgge.github.io/rosetun/ru/docs/troubleshooting/).

## Лицензии

Rosetun: **GPL-3.0-or-later**, © 2026 Sandaar. [LICENSE](LICENSE).
sing-box: GPL-3.0-or-later; Xray-core: MPL-2.0; Wintun: [Prebuilt Binaries License](installer/third-party/wintun-prebuilt-binaries-license.txt); шрифты: OFL-1.1.
[Полные уведомления, исходники компонентов и установленные лицензии](https://eoftgge.github.io/rosetun/ru/docs/licenses/).
Rosetun не связан с sing-box, SagerNet или Project X.
