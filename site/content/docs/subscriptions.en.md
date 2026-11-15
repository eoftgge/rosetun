+++
title = "Subscriptions and servers"
weight = 6

[extra]
overview = "Subscriptions and servers"
+++

- Provider subscriptions in plain or base64-encoded link lists, Xray JSON and sing-box JSON. Add one from its link, from a QR code (an image file, the clipboard or a part of the screen on Windows, the clipboard on Linux) or from a provider's `rosetun://` link.
- HTTP, HTTPS and SOCKS5 proxies of your own, on the **Proxy** tab of the add dialog.
- **Send device ID** (HWID) is on by default: panels that limit devices answer "subscription not found" without it. Turn it off for a subscription in the add dialog (`--no-hwid` in the CLI). See [Privacy and network access](../privacy/).
- VLESS, VMess, Trojan, Shadowsocks and Hysteria2 nodes (Salamander obfuscation and port hopping); TCP, WebSocket, gRPC and HTTPUpgrade transports for TCP-based nodes, and XHTTP (SplitHTTP) through Xray; plain, TLS and Reality security modes. Hysteria2 uses QUIC over UDP. Not supported yet, so such servers are skipped: XHTTP with a separate download server, mKCP, QUIC and HTTP/2 transports, VLESS encryption, Shadowsocks plugins and other protocols.
- **Connection through Xray** (Settings → Advanced): **Automatically** (default) uses Xray for VLESS servers with REALITY and for XHTTP, and sing-box for the rest; **Without Xray** connects to every server with sing-box alone; **Xray for all servers** sends every supported server except Hysteria2 through Xray. The server list marks servers that go through Xray.
- **TLS fragmentation** (Settings → Advanced): splits the first packets to the server, which helps when a provider cuts the connection by its first packet. Servers that Xray carries go through Xray while it is on; the connection screen says whether it applies to the current server.
- **DNS through the tunnel** via a configurable DNS-over-HTTPS resolver.
- **Server checks:** a TCP ping and a URL test that sends a request through each server, even while connected, through the same chain as the connection.
