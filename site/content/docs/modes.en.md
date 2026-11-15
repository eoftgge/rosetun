+++
title = "TUN and System proxy"
weight = 3

[extra]
overview = "TUN and System proxy"
+++

Changing the connection mode saves it for the next connection, including a connection from the tray or on startup. The current session keeps its mode. Select **Reconnect now** beside the pending note to use the saved mode immediately; protection stays in place during the restart.

**Connection mode** (Settings → Connection) chooses how traffic reaches the VPN. **TUN**, the default, takes all of this computer's traffic. **System proxy** starts a local proxy (HTTP and SOCKS5 on one port, 10808 unless you change it) and points your desktop's proxy settings at it, for when TUN gets in the way of another VPN, an anti-cheat or an antivirus, or when you only need the browser.

- **What goes through the VPN:** only programs that use the system proxy, which means browsers and most applications. Rules by site, address, list and program work as in TUN.
- **What does not:** programs that ignore the system proxy, such as games, many console programs and Windows services (WinHTTP is left as it is). Without the kill switch they go direct, and so does their DNS: this mode has no DNS lock, since it has no adapter. Point console programs at the proxy yourself (`curl -x http://127.0.0.1:10808 ...`); Rosetun does not set `http_proxy` and other variables, which running programs would not read anyway.
- **Kill switch** here is strict: only Rosetun's engine and this computer's loopback reach the network, while you are connected too, so everything that does not use the proxy stays without network. Off by default, and it asks before it goes on.
- **Access from the local network** (off by default) lets a phone or a TV on your network use the proxy: Settings shows the address to enter. On Windows only the networks this computer's adapters are connected to get in, without the VPN servers' own addresses, for as long as the session lasts. On Linux the proxy listens only on the private addresses of physical interfaces. Under **Lockdown** it needs **Local network** too, and otherwise stays closed to other devices.
- **Your own settings come back:** what you had before, an automatic configuration script or a proxy of your own included, is saved next to the configuration and restored when you disconnect, quit or change the mode, and at the next start after a crash or a power cut. If you changed the proxy yourself meanwhile, Rosetun leaves your change alone.
- The `rosetun` command starts the proxy but does not change the desktop's settings: only the app does that.
