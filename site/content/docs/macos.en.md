+++
title = "macOS support"
weight = 15

[extra]
group = "Reference"
overview = "macOS support"
+++

**macOS (Apple Silicon) · experimental build.** The `.pkg` installer targets Apple Silicon (`arm64`) and requires macOS 14 Sonoma or later. Intel Macs are not supported. The build passes macOS CI tests, but has not gone through an automated real-hardware failure matrix yet; report issues in [Issues](https://github.com/eoftgge/rosetun/issues).

## What works {#what-works}

- **TUN tunnel (`utun`)** powered by bundled sing-box and Xray (VLESS, VMess, Trojan, Shadowsocks, Hysteria2, REALITY, XHTTP, TLS fragmentation, two-hop exits).
- **`launchd` system daemon** (`io.github.eoftgge.rosetun.helper` in `/Library/LaunchDaemons/`) running the privileged helper and engines as `root`.
- **Desktop app and CLI:** `Rosetun.app` in `/Applications/` and `rosetun` in `/usr/local/bin/rosetun`.
- **Routing rules:** by domain, IP, GeoIP/GeoSite, lists and running programs.
- **Reconnect:** automatic tunnel reconnect when the active physical interface changes (for example, between Wi-Fi and Ethernet).
- **Subscriptions and UI:** Russian and English following the system locale, bundled Noto Color Emoji, macOS system font fallback and opening folders in Finder.

## Protection limits {#protection-limits}

- **Kill switch and Lockdown are unavailable on macOS.** Rosetun does not configure `pf` or another host firewall on macOS.
- **If the tunnel drops or an engine restarts, traffic may go direct.** The connection screen, Settings and `rosetun status` state this explicitly.
- If you need leak blocking when the tunnel drops or before sign-in, use Rosetun on Windows or Linux. See [Protection guarantees](../guarantees/).

## Platform notes {#platform-notes}

- **Rules by program:** running processes are read through `libproc`. On macOS, applications often send network traffic from helper or XPC subprocesses with a different executable name than the main app. You may need to match that helper process directly; path matching on macOS is case-sensitive.
- **Menu bar and deep links:** a menu bar icon, native notifications and the `rosetun://` URL handler are not implemented in this experimental build yet. Add subscriptions by link, from the clipboard or from a QR code image.
- **Files and paths:** user settings live in `~/.config/rosetun`, helper state and lists in `/Library/Application Support/Rosetun`, the service socket in `/private/var/run/rosetun/helper.sock`, and the service log in `/private/var/log/rosetun-helper.log`.
- **Install and uninstall:** see [macOS installation](../install/#macos). To remove Rosetun, run `sudo /usr/local/libexec/rosetun/uninstall.sh`.
