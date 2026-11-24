+++
title = "Everyday use"
weight = 4

[extra]
group = "Getting started"
overview = "Everyday use"
+++

- **Start at sign-in:** on Windows a scheduled task, on Linux an autostart entry in your home folder. The option is in Settings.
- The **tray icon** shows the state by shape: the rose is in colour only while connected; otherwise it is grey with a badge for connecting, traffic blocked, a failed connection and the service not running. Its menu shows the state, connects or disconnects, reconnects, switches between your five most recent servers and opens the window.
- **Notifications** say when the VPN drops, comes back or cannot connect; they name no server, since they can show on the lock screen. Turn them off in Settings › General.
- **Quitting** Rosetun while connected asks whether to disconnect or keep the VPN, which the service holds without the window; the answer can be remembered (Settings › General › **When quitting Rosetun**).
- **New versions** are offered on the connection screen, in the tray menu and by one notification per version, until you update or skip that version. Nothing is downloaded or installed automatically. From 0.7 on Windows, the notice lets you download and verify the installer against the signed `SHA256SUMS.txt` and start the update with **Install and restart**; on Linux and macOS, updating stays manual.
- English and Russian interfaces, eight colour themes, configurable **Country display** (flags or two-letter codes) and **Reduce motion**. Bundled Noto Color Emoji renders emoji consistently in server names, while other scripts use system fonts: the Windows fonts folder, fontconfig on Linux or macOS system fonts. Right-to-left text shows without shaping.
- **Delay** on the connection screen has two ways, chosen in **Settings → Connection** and saved at once; the hint on the number says which one is in use. **Repeated request**, the default, times a second request over a connection that is already open, so it is close to a ping. **Full request** opens a site from scratch, with the connection and encryption to the server and to the site, so it takes several round trips and reads higher than a ping. `rosetun delay --mode full|repeated` asks in either way and uses the saved one without `--mode`.
- **System check** (Settings → Service and log) looks for a wrong clock, other VPN clients or their adapters and a network that replaces DNS answers, and on Windows for a system proxy and for Zapret or WinDivert intercepting packets. It runs by itself after a failed connection and changes nothing.
- **Collect report** (Settings → Service and log) saves one text file for a bug report: versions, settings without secrets, the connection state, the system check and the logs. IP addresses, links, domains, email addresses, keys and passwords, server, subscription, list and rule set names, and your account name are removed. On Linux the file is chosen in the desktop's own dialog; without one it is saved next to the settings.
- Command line: `rosetun status`, `temporary`, `connect`, `apply`, `probe`, `delay`, `exits`, `select`, `sub add|update|list|remove`, `rules test|export|import`, `nodes`, `config`, `connections`, `connections close`, `xray auto|off|always`, `lan on|off`, `lockdown on|off`, `reconnect`, `open-network`, `reset-firewall`, `disconnect`, `shutdown`.
