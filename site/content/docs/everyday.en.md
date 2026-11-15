+++
title = "Everyday use"
weight = 13

[extra]
overview = "Everyday use"
+++

- **Start at sign-in:** on Windows a scheduled task, on Linux an autostart entry in your home folder. The option is in Settings.
- The **tray icon** shows the state by shape: the rose is in colour only while connected; otherwise it is grey with a badge for connecting, traffic blocked, a failed connection and the service not running. Its menu shows the state, connects or disconnects, reconnects, switches between your five most recent servers and opens the window.
- **Notifications** say when the VPN drops, comes back or cannot connect; they name no server, since they can show on the lock screen. Turn them off in Settings › General.
- **Quitting** Rosetun while connected asks whether to disconnect or keep the VPN, which the service holds without the window; the answer can be remembered (Settings › General › **When quitting Rosetun**).
- **New versions** are offered on the connection screen, in the tray menu and by one notification per version, until you update or skip that version. Nothing is downloaded or installed by itself.
- English and Russian interfaces, six colour themes and **Reduce motion**. Server names and your own input can be in other scripts, drawn with system fonts: the Windows fonts folder, or fontconfig on Linux. Right-to-left text shows without shaping.
- **System check** (Settings → Service and log) looks for a wrong clock, other VPN clients or their adapters and a network that replaces DNS answers, and on Windows for a system proxy and for Zapret or WinDivert intercepting packets. It runs by itself after a failed connection and changes nothing.
- **Collect report** (Settings → Service and log) saves one text file for a bug report: versions, settings without secrets, the connection state, the system check and the logs. IP addresses, links, domains, email addresses, keys and passwords, server, subscription, list and rule set names, and your account name are removed. On Linux the file is chosen in the desktop's own dialog; without one it is saved next to the settings.
- Command line: `rosetun status`, `temporary`, `connect`, `apply`, `probe`, `delay`, `exits`, `select`, `sub add|update|list|remove`, `nodes`, `config`, `connections`, `connections close`, `xray auto|off|always`, `lan on|off`, `lockdown on|off`, `reconnect`, `open-network`, `reset-firewall`, `disconnect`, `shutdown`.
