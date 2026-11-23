+++
title = "Troubleshooting"
weight = 12

[extra]
group = "Reference"
overview = "Troubleshooting"
+++

- Run **System check** (Settings → Service and log) first. It also runs by itself after a failed connection and shows the first finding under the error.
- **No network at all with Lockdown on, and Rosetun does not open.** This removes Lockdown without the service. In a terminal opened as administrator on Windows:
  ```
  & 'C:\Program Files\Rosetun\rosetun.exe' reset-firewall
  ```
  Use your own folder if you chose another. On Linux:
  ```
  sudo rosetun reset-firewall
  ```
  Uninstalling Rosetun removes Lockdown too.
- **The network is closed after an update or a crash**, and `rosetun status` says `network: held closed`. Connect, or open it: **Open network** on the connection screen, or `rosetun open-network`. Without a working service, use `reset-firewall` as above.
- **A site does not open right after connecting:** browsers keep their own DNS cache. Rosetun clears the Windows DNS cache when it connects and disconnects, but not theirs. Restart the browser.
- **Another VPN client** in TUN mode can prevent the tunnel from starting. Disconnect it and retry. A program that changes traffic, such as zapret, can disrupt the connection to the server: exclude the server addresses in its settings.
- **Windows: "Windows still holds the tunnel of the last session".** Windows kept the adapter of the previous session, which can happen after fast startup. Restart the computer and connect again.
- **Linux: No access to the Rosetun service.** Your account is not in the `rosetun` group yet, or your session started before it joined. Press **Add me**, or run `sudo usermod -aG rosetun "$USER"`, and restart the computer.
- **Linux: the tunnel DNS is missing from systemd-resolved.** Check that the service is running, then reconnect. With the tunnel connected, `resolvectl status rosetun0` should show a DNS server for the link. [Set up system DNS on Arch](../install/#arch-dns)
- **Linux: Rosetun says another program changed the firewall rules.** `nftables.service` and firewalld can start with `flush ruleset`, which removes Rosetun's table. The service puts it back within seconds and `rosetun status` says when. If it says `firewall rules: cannot be checked or put back`, treat the network as unprotected and reconnect.
- **Linux: KDE programs do not use the proxy.** Check that `~/.config/kioslaverc` has `ProxyType=1` under `[Proxy Settings]` and that `XDG_CURRENT_DESKTOP` contains `KDE`; otherwise Rosetun shows the address to enter yourself. KDE programs read the settings again by a signal and Chromium watches the file; restart other programs. The `rosetun` command never changes these settings.
- **Linux: Without a connection subscriptions do not update under Lockdown.** Rosetun started outside your desktop session, as the window says. Restart it from the desktop.
- **A subscription update through VPN fails while connected.** Check that the main server works and try the update again. Rosetun stops after a failed VPN request. [Subscription updates](../subscriptions/#updates)
- **Linux: the file dialog fails to open.** Check that `xdg-desktop-portal` and a backend for your desktop are installed. You can import and export rules through the clipboard. [Linux support](../linux/)
- **TLS fragmentation** works only for servers that Xray carries (VLESS, VMess, Trojan, Shadowsocks without TCP `finalmask`) and helps with some providers only. Hysteria2, TUIC, AnyTLS, WireGuard, HTTP or SOCKS5 servers and streams with `finalmask` connect without it, and it is unavailable while **Without Xray** is selected.
- **No network connection** means the system has no working network, so the server is not to blame. Connecting fails at once. While connected, a short network change does not break the session; with **Reconnect automatically** on, Rosetun waits for the network and reconnects when it returns, and the kill switch keeps the internet closed meanwhile.
- **Wi-Fi with a sign-in page** (a hotel or a café) or **a wrong clock** with **Lockdown** on: the sign-in page cannot open and the system cannot set the time without the tunnel, and the tunnel cannot start without them. Turn Lockdown off for a moment, sign in or correct the clock, connect, and turn Lockdown on again.
- **Lockdown leaves virtual machines without network.** Confirmed for Hyper-V on Windows, and most likely WSL2, Docker Desktop, Windows Sandbox and Mobile hotspot as well; on Linux, virtual machines and containers on this computer lose network without a Rosetun connection. Turn Lockdown off while you need them.
- **Windows: the window fails to open or draws incorrectly after an update:** quit Rosetun from the tray, then run `$env:ROSETUN_RENDERER='glow'; & 'C:\Program Files\Rosetun\rosetun-gui.exe'` in PowerShell (adjust the path if needed). Use **Collect report** and send the report with a description of the problem.
- **Windows: setup stops because standard users can change a folder under `C:\Program Files\Rosetun`.** This usually follows **Continue** in File Explorer, which gives your account permanent access to a protected Rosetun folder such as `data`. Uninstall Rosetun and install it again. To read the service log, use **Collect report** or an editor run as administrator instead.

**Report a problem** in [Issues](https://github.com/eoftgge/rosetun/issues), with the steps and the error text. Attach **Collect report** (Settings → Service and log). On Linux the report includes the service log from the system journal when your account may read it (the groups `adm` and `systemd-journal` on Debian); otherwise it says so and asks for nothing as root. Then add the output below by hand, removing addresses, links and names first: unlike the report, these logs are not cleaned.

```
rosetun status
sudo journalctl -u rosetun-helper -b --no-pager
cat ~/.config/rosetun/rosetun-gui.log
```

Report a vulnerability privately: see [SECURITY.md](https://github.com/eoftgge/rosetun/blob/master/SECURITY.md).
