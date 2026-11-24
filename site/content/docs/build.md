+++
title = "Сборка из исходников"
weight = 14
aliases = ["/ru/docs/build/"]

[extra]
group = "Справка"
overview = "Сборка из исходников"
+++

Нужен Rust 1.99 или новее, под Windows с MSVC. `cargo build --release` собирает программы, `cargo test --workspace` запускает тесты.

- **Установщик Windows:** `./installer/windows/build.ps1` собирает `target/installer/rosetun-<версия>-setup.exe`. См. [инструкцию к установщику](https://github.com/eoftgge/rosetun/blob/master/installer/README.md).
- **Пакеты выпуска для Linux:** `installer/linux/build-deb.sh --release` собирает пакет Debian и архив Linux из одних бинарников. Сборка выпуска идёт от обычного пользователя в закреплённом контейнере Debian 12. Для проверок на локальном стенде Debian 13 используется отдельная сборка. [Инструкция по упаковке](https://github.com/eoftgge/rosetun/blob/master/installer/README.md#debian-package)
- **Пакет macOS (Apple Silicon, экспериментально):** `installer/macos/build-pkg.sh --release --allow-unsigned` собирает `target/macos/rosetun-<версия>-macos-arm64-experimental.pkg` на Mac с Apple Silicon; с переменными Developer ID скрипт также подписывает и нотаризирует пакет. [Инструкция по упаковке macOS](https://github.com/eoftgge/rosetun/blob/master/installer/README.md#macos-package-apple-silicon-experimental)
- **Проверка отказов** на виртуальных машинах: [описание стенда VM](https://github.com/eoftgge/rosetun/blob/master/tools/README.md).

Перед первым коммитом один раз выполните `git config core.hooksPath tools/hooks`. Хуки не пропускают подписи ИИ и сообщения не по Conventional Commits, файлы патчей, настоящие адреса серверов и имя вашей учётной записи Windows в добавленных строках, а при push неотформатированный код. CI повторяет проверки сообщений и добавленных строк.
