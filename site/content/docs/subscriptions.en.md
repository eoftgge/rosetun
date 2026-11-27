+++
title = "Subscriptions and servers"
weight = 7

[extra]
group = "Setup"
overview = "Subscriptions and servers"
+++

- Provider subscriptions in plain or base64-encoded link lists, Xray JSON, sing-box JSON and WireGuard `.conf` files. Add one by URL, from a QR code in a file or on the clipboard, or through a provider's `rosetun://` link. Windows can also read a QR code from a selected region of the screen. On Linux, opening an image file uses the [desktop portal](../linux/).
- HTTP, HTTPS and SOCKS5 proxies of your own, on the **Proxy** tab of the add dialog.
- **Send device ID** (HWID) is on by default: panels that limit devices answer "subscription not found" without it. Turn it off for a subscription in the add dialog (`--no-hwid` in the CLI). See [Privacy and network access](../privacy/).
- **User-Agent** is chosen per subscription when adding or in **Edit subscription**: **Rosetun (default)**, **Happ** (`Happ/4.0.0`), or **Custom**. This is useful when a provider returns different configs depending on the client name.
- VLESS, VMess, Trojan, Shadowsocks, Hysteria2 (Salamander obfuscation and port hopping), TUIC v5, AnyTLS and WireGuard nodes; TCP, WebSocket, gRPC and HTTPUpgrade transports for TCP-based nodes, and XHTTP (SplitHTTP) through Xray; plain, TLS (including `enableSessionResumption`) and Reality security modes. Xray JSON subscriptions also support `routing.balancers` (`random`, `roundRobin`, `leastPing`, `leastLoad` and `fallbackTag`) with `observatory` / `burstObservatory`, and `streamSettings.finalmask.tcp` (`header-custom`). Hysteria2 and TUIC v5 use QUIC over UDP and AnyTLS uses TCP over TLS or Reality (all three work from subscription links `hysteria2://`, `tuic://`, `anytls://` and sing-box JSON); WireGuard uses UDP and works from `wireguard://` and `wg://` links, sing-box JSON, Xray JSON and `.conf` files, including Cloudflare WARP `reserved` bytes. Not supported yet, so such servers are skipped and named by protocol in the update report: XHTTP with a separate download server, UDP `finalmask` and `finalmask` types other than TCP `header-custom`, mKCP, QUIC and HTTP/2 transports, VLESS encryption, Shadowsocks plugins and other protocols (such as AmneziaWG).
- **Connection through Xray** (Settings → Advanced): **Automatically** (default) uses Xray directly for every protocol it supports (VLESS, VMess with `alterId = 0`, Trojan, Shadowsocks, XHTTP, Xray balancers and TCP `finalmask`) without spawning sing-box; sing-box handles Hysteria2, TUIC, AnyTLS, WireGuard, external HTTP/SOCKS5 proxies and legacy VMess; **Without Xray** connects to every server with sing-box alone (servers using XHTTP, Xray balancers or `finalmask` cannot connect in this mode); **Xray for all servers** likewise routes every supported protocol through Xray except Hysteria2, TUIC, AnyTLS and WireGuard (those always use sing-box). The server list marks servers that go through Xray.
- **TLS fragmentation** (Settings → Advanced): splits the first packets to the server, which helps when a provider cuts the connection by its first packet. Servers that Xray carries (without TCP `finalmask`) go through Xray while it is on; the connection screen says whether it applies to the current server.
- **DNS through the tunnel** via a configurable DNS-over-HTTPS resolver.
- **Server checks:** a TCP ping and a URL test that sends a request through each server, even while connected, through the same chain as the connection.

## Updates through VPN {#updates}

**Settings → Connection → Update subscriptions through VPN** is on by default.
While connected, subscription downloads and updates use the main VPN server,
even when a rule sends the provider's site directly. This works in TUN and
system proxy mode, in the app and in `rosetun sub update`.

A failed VPN request shows an error and is never retried directly. Without a
connection, or with the setting off, the ordinary path is used; in TUN it
follows your rules. If the service is unavailable and the connection state is
unknown, the enabled setting stops the update with an error. Turn it off only
when you want to use the ordinary path. Lists and app update checks are not
changed by this setting.
