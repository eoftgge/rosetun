+++
title = "Rosetun"
description = 'Rosetun. VPN-клиент. Подписки, правила и защита соединения.'
template = "index.html"
aliases = ["/ru/"]

[extra]
skip = 'К содержанию'
headline = 'Ваш трафик. Ваши правила.'
lead = 'VPN-клиент для Windows и Linux: подписки, правила, kill switch и Lockdown.'
download_windows = 'Скачать для Windows'
download_linux = 'Скачать для Linux'
all_releases = 'Все выпуски'
verify_download = 'Проверить загрузку'
features_eyebrow = 'ПОД ВАШИ ЗАДАЧИ'
features_title = 'Одно подключение. Больше выбора.'
note = 'Rosetun защищает от случайных утечек, а не от вредоносных программ под вашей учётной записью. Без Lockdown падение службы снимает блокировку на Windows, а на Linux kill switch остаётся. Lockdown экспериментальный: сторонние брандмауэры, антивирусы, гибернация и сон на настоящем компьютере не проверены. <a href="docs/privacy/">Сетевые обращения и модель защиты</a>'
screens_title = 'Знакомство с интерфейсом'
screens_lead = 'Основные возможности Rosetun в одном интерфейсе.'
lightbox_label = 'Просмотр скриншота'
lightbox_close = 'Закрыть'

[[extra.features]]
title = 'Подключение под защитой'
text = 'Kill switch блокирует трафик при потере туннеля и держит сеть закрытой при обновлении. Без него замок DNS держит системный DNS в туннеле. Окно и rosetun status показывают, что установлено и чего не хватает. Экспериментальный Lockdown сохраняет блокировку без подключения и после перезагрузки.'

[[extra.features]]
title = 'Ваши правила'
text = 'Отправляйте программы, сайты и IP через VPN, напрямую или блокируйте. Используйте GeoIP, GeoSite и свои списки. Отменяйте изменения по Ctrl+Z. Временные правила действуют до отключения. Правила по программам работают на Windows и Linux. См. <a href="docs/rules/">ограничения Linux</a>.'

[[extra.features]]
title = 'Несколько направлений'
text = 'Выберите другую страну или сервер для отдельного правила. Если сервер направления исчезнет, его трафик блокируется и не выходит напрямую.'

[[extra.features]]
title = 'Подписки под рукой'
text = 'Добавляйте подписку ссылкой, QR-кодом или кнопкой rosetun:// на сайте провайдера, а также свой прокси HTTP, HTTPS или SOCKS5. Отправку ID устройства можно выключить для каждой подписки.'

[[extra.features]]
title = 'Выбор соединения'
text = 'VLESS, VMess, Trojan, Shadowsocks и Hysteria2. Ядра sing-box и Xray, REALITY и XHTTP, фрагментация TLS. Доступные транспорты и ограничения описаны на странице для провайдеров.'

[[extra.features]]
title = 'Приватность без обещаний'
text = 'Нет телеметрии. Приложение обращается к провайдеру, серверам, DNS, спискам, GitHub и сервисам проверки сети. Соединения хранятся в памяти до отключения, без записи на диск.'

[[extra.features]]
title = 'TUN или системный прокси'
text = 'TUN берёт весь трафик компьютера. Системный прокси касается программ, которые его используют, когда TUN мешает; по желанию со строгим kill switch и доступом из вашей сети.'

[[extra.features]]
title = 'Ваша локальная сеть'
text = 'Принтер, NAS и стриминг игр мимо туннеля. На Windows открывается только ваша сеть, если не открыть ещё и частные сети за роутером. На Linux открываются все частные диапазоны.'

[[extra.screens]]
image = 'main'
alt = 'Rosetun: подключение и защита'
caption = 'Подключение и защита'

[[extra.screens]]
image = 'traffic'
alt = 'Rosetun: трафик и соединения'
caption = 'Трафик и соединения'

[[extra.screens]]
image = 'rules'
alt = 'Rosetun: правила маршрутизации'
caption = 'Правила'

[[extra.screens]]
image = 'lists'
alt = 'Rosetun: списки'
caption = 'Списки: SRS, Xray geosite и geoip'

[[extra.screens]]
image = 'exits'
alt = 'Rosetun: направления'
caption = 'Направления'

[[extra.screens]]
image = 'settings'
alt = 'Rosetun: настройки защиты'
caption = 'Настройки защиты'
+++

{%- set r = load_data(path="data/release.json", required=false) -%}
<p class="release-detail"><span>{% if r %}Версия {{ r.version }}{% else %}Стабильный выпуск. Файлы и контрольные суммы на GitHub Releases.{% endif %}</span></p>
<p class="eyebrow">ЗАГРУЗКА</p>

<h2>Проверьте установщик</h2>

Установщик пока не подписан сертификатом Windows. Сравните SHA-256 файла со строкой ниже и с SHA256SUMS.txt из выпуска.

```
Get-FileHash .\{{ r?.installer or "rosetun-VERSION-setup.exe" }} -Algorithm SHA256
```

[SHA256SUMS.txt]({{ r?.checksum_url or "https://github.com/eoftgge/rosetun/releases/latest" }})

```
{{ r?.sha256_line or "SHA256SUMS.txt: сумма указана в файле выпуска" }}
```

Для публичных выпусков по тегу workflow создаёт аттестацию происхождения установщика. Проверьте её через GitHub CLI. Это проверка происхождения сборки, а не подпись Windows.

```
gh attestation verify .\{{ r?.installer or "rosetun-VERSION-setup.exe" }} --repo eoftgge/rosetun
```

<p>Пакет Debian тоже есть в SHA256SUMS.txt и имеет аттестацию: <a href="docs/install/#debian-13">Debian 13</a>.</p>

<p><a href="help/">Установка и первый запуск</a></p>
