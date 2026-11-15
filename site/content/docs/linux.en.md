+++
title = "Linux support"
weight = 13

[extra]
group = "Reference"
overview = "Linux support"
+++

**Distributions (amd64, glibc 2.36 or newer):** Debian 13 is verified by the system test matrices. Ubuntu 24.04+, Linux Mint 22+ and other Debian/Ubuntu derivatives with this glibc or newer, systemd, nftables and polkit are expected to work with the same `.deb`; manual Ubuntu verification is pending.

The Arch Linux binary recipe `rosetun-bin` is available in the repository; AUR publication and runtime verification are pending. See [installation and updates](../install/#arch-linux).

Systems without systemd and Flatpak, Snap and AppImage packages are unsupported: Rosetun needs a privileged system service and access to the host firewall and TUN device.

| Desktop | Tray | System proxy settings |
|---|---|---|
| KDE Plasma, Wayland and X11 | Yes | Changed by Rosetun (`kioslaverc`) |
| GNOME | Only with an extension that provides a tray. Without a tray, closing the window closes the program | Changed by Rosetun (`gsettings`) |
| Others | Where a tray host answers; not tested | Rosetun shows the address to enter yourself |

The table says what the code does. Rosetun was checked by hand on GNOME, and not yet on KDE Plasma.

Linux behaves as Windows does wherever the system allows it. Local network, file dialogs (the desktop's own, through the portal), **Collect report**, the buttons that open a folder, the checks in **System check** (the system proxy, programs and firewall rules that redirect traffic) and the remembered window work on both. What the system itself limits:

- Wayland lets a program choose a window's size but not where it goes, so only the size and the maximized state come back there; on X11 the position does too, if a monitor still shows it;
- a file dialog needs a desktop portal (`xdg-desktop-portal` with a backend for your desktop); without one you type the full path of a list file and the report is saved next to the settings;
- the service log in the report comes from the system journal and needs an account in the `systemd-journal` or `adm` group; otherwise the report says so;
- the firewall check sees nftables, including iptables-nft, and not legacy iptables;
- a QR code is read from a file or the clipboard; there is no screen capture;
- multicast from a program that picks no interface: on Windows it goes into the tunnel; on Linux this has not been measured.
