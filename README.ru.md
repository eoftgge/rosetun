[English](README.md) | Русский

<p align="center"><img src="site/static/assets/banner.svg" alt="Rosetun: VPN-клиент для Windows и Linux" width="100%"></p>

<p align="center">
  <a href="https://eoftgge.github.io/rosetun/"><img src="https://img.shields.io/badge/%D0%A1%D0%B0%D0%B9%D1%82%20%D0%BF%D1%80%D0%BE%D0%B5%D0%BA%D1%82%D0%B0-8C2338?style=for-the-badge" alt="Сайт проекта"></a>
  <a href="https://eoftgge.github.io/rosetun/docs/"><img src="https://img.shields.io/badge/%D0%94%D0%BE%D0%BA%D1%83%D0%BC%D0%B5%D0%BD%D1%82%D0%B0%D1%86%D0%B8%D1%8F-432D36?style=for-the-badge" alt="Документация"></a>
  <a href="https://eoftgge.github.io/rosetun/help/"><img src="https://img.shields.io/badge/%D0%9F%D0%BE%D0%BC%D0%BE%D1%89%D1%8C-432D36?style=for-the-badge" alt="Помощь"></a>
  <a href="https://eoftgge.github.io/rosetun/providers/"><img src="https://img.shields.io/badge/%D0%94%D0%BB%D1%8F%20%D0%BF%D1%80%D0%BE%D0%B2%D0%B0%D0%B9%D0%B4%D0%B5%D1%80%D0%BE%D0%B2-432D36?style=for-the-badge" alt="Для провайдеров"></a>
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

Rosetun ведёт один разработчик с помощью агентов для кода. О проблемах пишите в [Issues](https://github.com/eoftgge/rosetun/issues).

## Главное

- Kill switch и защита системного DNS.
- Экспериментальный Lockdown: защита и без подключения.
- TUN и системный прокси.
- Правила по программам, сайтам, IP и спискам; отдельные выходы.
- Подписки провайдеров, QR-коды и ссылки `rosetun://`.
- Локальная сеть и переподключение при обрыве.
- Трей, уведомления, командная строка; русский и английский интерфейсы.

## Установка

- **Windows 11 x64.** Скачайте установщик `-setup.exe` со страницы выпуска по кнопке выше. [Установка на Windows](https://eoftgge.github.io/rosetun/docs/install/#windows)
- **Debian 13 amd64.** Установите пакет `.deb`, добавьте свою учётную запись в группу `rosetun` и перезагрузите компьютер. Требования для Ubuntu и Linux Mint перечислены в руководстве. [Установка на Debian](https://eoftgge.github.io/rosetun/docs/install/#debian-13)
- **Arch Linux.** Соберите `rosetun-bin` по рецепту в этом репозитории. [Установка на Arch](https://eoftgge.github.io/rosetun/docs/install/#arch-linux)

## Документация

- [Руководство](https://eoftgge.github.io/rosetun/docs/)
- [Помощь и устранение неполадок](https://eoftgge.github.io/rosetun/help/)
- [Для провайдеров](https://eoftgge.github.io/rosetun/providers/)
- [Сборка из исходников](https://eoftgge.github.io/rosetun/docs/build/)
- [Политика безопасности и приватные сообщения](SECURITY.md)
- [Модель безопасности](https://eoftgge.github.io/rosetun/docs/security/)

## Лицензии

Rosetun: **GPL-3.0-or-later**, © 2026 Sandaar. [LICENSE](LICENSE).
sing-box: GPL-3.0-or-later; Xray-core: MPL-2.0; Wintun: [Prebuilt Binaries License](installer/third-party/wintun-prebuilt-binaries-license.txt); шрифты: OFL-1.1; флаги стран: MIT.
[Полные уведомления, исходники компонентов и установленные лицензии](https://eoftgge.github.io/rosetun/docs/licenses/).
Rosetun не связан с sing-box, SagerNet или Project X.
