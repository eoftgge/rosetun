English | [Русский](README.ru.md)

<p align="center"><img src=".github/assets/banner.svg" alt="Rosetun: VPN client for Windows" width="100%"></p>

<p align="center">
  <a href="https://github.com/eoftgge/rosetun/releases/latest"><img src=".github/assets/download.svg" alt="Download Rosetun for Windows" height="56"></a>
</p>

<p align="center">
<img alt="CI" src="https://img.shields.io/github/actions/workflow/status/eoftgge/rosetun/ci.yml?style=for-the-badge&logo=rust">
<img alt="GitHub issues by-label" src="https://img.shields.io/github/issues/eoftgge/rosetun/bug?style=for-the-badge&logo=github">
</p>

Rosetun is a Windows VPN client powered by sing-box, which runs the tunnel, rules and DNS; for VLESS + REALITY servers, Xray behind sing-box carries the connection to the server. A Windows service maintains the kill switch and DNS lock; routing rules split traffic by app, website and IP address, and provider subscriptions supply servers.

**Young project:** one developer maintains it with AI coding agents, and it has few users yet. Please report what breaks in [Issues](https://github.com/eoftgge/rosetun/issues).

## Features

- A **Kill switch** blocks traffic when the tunnel drops, as long as the Rosetun service is running (see [How it works](#how-it-works)). Without it, a DNS lock keeps system DNS from leaking outside the tunnel throughout the session, including while the engine restarts.
- *Experimental:* **Lockdown** (the **Protection** card on the connection screen) closes the internet to everything outside the tunnel, not only while connected: also while disconnected, after a restart (from boot, before you sign in to Windows) and if the Rosetun service stops or crashes. While it is on, the **Kill switch** is always on. Incoming connections are blocked too, except from your network when **Local network** is on. Turning it on and off asks for confirmation. It has been tested on Windows 11 only; other firewalls and antivirus programs, sleep and hibernation are not tested yet, so the **Kill switch** stays the main protection.
- **Routing rules** for apps, websites, IP addresses and subnets, and lists, with **Quick templates** and actions **Through VPN**, **Direct** and **Block**.
- **Exits:** a rule can send its traffic through another country or a specific server while the rest goes through the server on the main screen. Picking a country or a server in the rule creates an exit on the **Exits** tab, where you can change its server and turn on a fallback to any server of the same country. If an exit's server disappears, its rules block traffic; they never go direct.
- **Lists:** GeoIP and GeoSite (Xray `.dat` files, sing-box rule sets) and your own text lists, from a file or a link. A list from a link is downloaded again only when it has changed (`ETag` / `Last-Modified`).
- Provider subscriptions in plain or base64-encoded link lists, Xray JSON and sing-box JSON. **Send device ID** (HWID) is optional for providers that require it.
- VLESS, VMess, Trojan, Shadowsocks and Hysteria2 nodes (Salamander obfuscation and port hopping); TCP, WebSocket, gRPC and HTTPUpgrade transports for TCP-based nodes; plain, TLS and Reality security modes. Hysteria2 uses QUIC over UDP. Not supported yet, so such servers are skipped: XHTTP, SplitHTTP, mKCP, QUIC and HTTP/2 transports, VLESS encryption, Shadowsocks plugins and other protocols.
- **Connection through Xray** (Settings → Advanced): **Automatically** (default) uses Xray for VLESS servers with REALITY and sing-box for the rest; **Without Xray** connects to every server with sing-box alone; **Xray for all servers** sends every supported server except Hysteria2 through Xray. The server list marks servers that go through Xray.
- **DNS through the tunnel** via a configurable DNS-over-HTTPS resolver.
- **Local network** (Settings → Connection): your router, printer and other devices on your network are reached directly, past the tunnel. Off by default; turn it off on public networks.
- Change the server, rules or DNS while connected: Rosetun restarts the tunnel in a second or two without disconnecting, and the kill switch keeps traffic blocked meanwhile.
- **Temporary rules:** add a rule only until disconnect; it applies at once and is never saved.
- **Reconnect automatically** after sleep, a network outage or an engine failure, with a DNS watchdog while connected.
- **Server checks:** a TCP ping and a URL test that sends a request through each server, even while connected, through the same chain as the connection.
- **System check** (Settings → Service and log) looks for a wrong clock, a system proxy, Zapret or WinDivert intercepting packets, and other VPN clients or their adapters. It runs by itself after a failed connection and changes nothing.
- **Collect report** (Settings → Service and log) saves one text file for a bug report: versions, settings without secrets, the connection state, the system check and the logs. IP addresses, links, domains, email addresses, keys and passwords, server, subscription, list and rule set names, and your Windows account name are removed.
- The tray icon shows the state by shape: the rose is in colour only while connected; otherwise it is grey with a badge for connecting, traffic blocked (by the kill switch, or by Lockdown while disconnected), a failed connection and the service not running.
- Command line: `rosetun status`, `temporary`, `connect`, `apply`, `probe`, `delay`, `exits`, `select`, `sub add|update|list|remove`, `nodes`, `config`, `xray auto|off|always`, `lan on|off`, `lockdown on|off`, `reset-firewall`, `disconnect`, `shutdown`.
- **Start with Windows**, and English and Russian interfaces.

## Install

Download the installer from [Releases](https://github.com/eoftgge/rosetun/releases). Windows 10 or 11, x64, is required. The installer is not code-signed yet; if SmartScreen says "Windows protected your PC", select **More info** and then **Run anyway**.

Rosetun plans to apply again to [SignPath Foundation](https://signpath.org) for free code signing once the project is better known; see the [code signing policy](CODE_SIGNING_POLICY.md) for the planned process. Current releases remain unsigned.

You can choose an installation folder, but not inside a user profile or where standard users can change it; the SYSTEM service requires a protected folder. Uninstalling keeps your configuration in `%APPDATA%\Rosetun` by default, or you can choose to delete your settings, subscriptions and rules.
When the configuration format is upgraded, Rosetun keeps a copy of the previous file beside it (such as `config.v1.json`); the copy contains the same subscription URLs.

### Verify the download

Compare `Get-FileHash .\rosetun-<version>-setup.exe -Algorithm SHA256` with the entry in the release's `SHA256SUMS.txt`. For a public tagged release, verify provenance with `gh attestation verify .\rosetun-<version>-setup.exe --repo eoftgge/rosetun`.

## Privacy and network access

Rosetun makes these network requests:

- To the VPN server for the tunnel; **TCP ping** also makes a TCP connection attempt to each server being checked while the tunnel is down.
- **URL test** and the delay on the connection screen send two HTTPS requests at once, to `https://cp.cloudflare.com/generate_204` and `https://www.gstatic.com/generate_204`, through the server being checked, the current server or each exit's server. URL test connects directly to each server, outside the tunnel. While connecting and while connected, the service sends the same requests through the current server to check that it works; this cannot be turned off.
- To your subscription provider to fetch or update subscriptions, using `User-Agent: Rosetun/<version>` by default. When **Send device ID** is on, the request also includes `x-hwid`, `x-device-os`, `x-ver-os` and `x-device-model`. Subscription URLs may contain credentials; an HTTP subscription sends its token without encryption.
- To the addresses of lists, given by you or by a subscription, when a list is added or updated and with subscription updates (turn them off under **Update subscriptions automatically**). Rosetun sends `ETag` / `Last-Modified` from the previous download, so an unchanged list is not downloaded again. The request goes through the tunnel when connected.
- To the configured DNS-over-HTTPS resolver through the tunnel. The service also checks DNS by querying `example.com` during connection and random names beneath `example.com` while the tunnel is up.
- To `https://1.1.1.1/cdn-cgi/trace` for the public IP and country shown on the connection screen: through the current server when connected, and directly when disconnected, after a failed connection or when the service is unavailable. The IP is hidden by default and is not written to the log. Exits make no requests of their own: their country comes from the server name.
- To `https://api.github.com/repos/eoftgge/rosetun/releases` for the release list at launch if it has never been checked or the last successful check was over a day ago, then once a day, and when you click **Check now**. The request goes through the tunnel when connected. Automatic checks are on by default; turn them off under **Settings → About → Check for updates**. The last successful check time and any skipped version are saved in the settings file. Nothing is downloaded or installed automatically.
- **System check** sends an HTTP `HEAD` request to `http://cp.cloudflare.com/`, unencrypted, to compare your clock with its `Date` header. It runs when you click **Check**, by itself after a failed connection and in **Collect report**; it goes directly without a tunnel and through the tunnel when connected.
- If DNS stalls, the watchdog sends HTTP `HEAD` requests to `1.1.1.1:80` and to `connectivitycheck.gstatic.com/generate_204` through the tunnel to distinguish a DNS failure from a lost path. The second name is resolved through the tunnel's DNS when the connection starts.
- Before connecting, system DNS resolves the VPN server name; provider and ping hostnames may also be resolved by the operating system.
- When changing servers while connected, the new server's name is resolved through the current tunnel.

The engine's control API and the link from sing-box to Xray use only local loopback. There is no telemetry or Rosetun account. The application update check only reports a new version; it does not download or install it. Logs stay on this machine; the service log is accessible only to administrators, and **Collect report** receives it only for the Windows account that started the session. When **Verbose log** is off, destination addresses in engine messages are replaced with `[hidden]`; the VPN server address and error cause remain. Site addresses are logged only while the temporary **Verbose log** setting is enabled. Automatic *subscription* updates are separate from application updates.

With **Lockdown** on and no connection, Rosetun itself (the app and the `rosetun` command) still reaches the internet directly: your subscription provider, list addresses, `cp.cloudflare.com` for **System check**, and the other requests above that go directly when disconnected (server checks, the public IP, the update check). Other programs do not. Your subscription provider then sees your real IP address, just as without Lockdown.

## Troubleshooting

- Run **System check** (Settings → Service and log) first: it finds other VPN clients, Zapret or WinDivert, a system proxy and a wrong clock. It also runs by itself after a failed connection and shows the first finding under the error.
- Another VPN client in TUN mode can prevent the tunnel from starting. Disconnect it and retry.
- Traffic-modifying programs such as zapret can disrupt the connection to the VPN server. Exclude the server addresses in that program's settings.
- If setup stops because standard users can change a folder under `C:\Program Files\Rosetun`, this usually follows **Continue** in File Explorer, which gives your account permanent access to a protected Rosetun folder such as `data`. Uninstall Rosetun and install it again. To read the service log, use **Collect report** or an editor run as administrator instead.
- **No network connection** means Windows has no working network, so the server is not to blame. Connecting fails at once. While connected, a short network change does not break the session; with **Reconnect automatically** on, Rosetun waits for the network and reconnects when it returns, and the kill switch keeps the internet closed meanwhile.
- **Wi-Fi with a sign-in page** (a hotel or a café) or **a wrong clock** with **Lockdown** on: the sign-in page cannot open and Windows cannot set the time without the tunnel, and the tunnel cannot start without them. Turn Lockdown off for a moment, sign in or correct the clock, connect, and turn Lockdown on again.
- **No network at all and Rosetun does not open**, with Lockdown on: run `rosetun reset-firewall` in a terminal as administrator. It removes Lockdown without the service. Uninstalling Rosetun removes it too.
- **Lockdown on this computer leaves Hyper-V virtual machines without network**, and most likely WSL2, Docker Desktop, Windows Sandbox and Mobile hotspot as well. Turn Lockdown off while you need them.

## How it works

```text
GUI (user) ──named pipe──► Rosetun service (SYSTEM) ──► sing-box.exe ──► TUN
                                    │                        │
                                    │                        └──loopback──► xray.exe (some servers)
                                    └── WFP: kill switch / DNS lock
```

The service (`rosetun-helper-privileged`) starts sing-box, which runs the tunnel, rules and DNS. For servers that go through Xray, sing-box hands the connection over loopback to `xray.exe`, which the service also starts and which connects to the server. The service owns protection, so closing the GUI does not remove it, and the kill switch holds while the service is running. Without Lockdown, if the service itself crashes, Windows removes its firewall filters (fail-open). This avoids leaving the computer permanently offline.

With **Lockdown** on, Rosetun also keeps persistent WFP filters in its own sublayer that block everything outside the tunnel. Windows keeps them across a service crash and a restart, and the Base Filtering Engine (BFE) restores them at boot, with boot-time filters covering the time before it starts (fail-closed). They are removed only by turning Lockdown off, by `rosetun reset-firewall` (as administrator) or by uninstalling Rosetun.

## Build from source

Use Rust 1.96 or newer with the MSVC toolchain on Windows. Run `cargo build --release` to build the binaries and `cargo test --workspace` to run tests. See [installer instructions](installer/README.md) for packaging and the [VM test rig](tools/README.md) for elevated failure testing.

Before committing, run `git config core.hooksPath tools/hooks` once. The hooks reject AI attribution and non-Conventional commit messages, patch files, real proxy hosts and your Windows account name in added lines, and unformatted code on push. CI runs the same message and added-line checks.

## Security

See [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## Licenses

Rosetun is licensed under **GPL-3.0-or-later**, © 2026 Sandaar. See [LICENSE](LICENSE). The bundled sing-box executable is the unmodified official build and is licensed under GPL-3.0-or-later. The bundled Xray-core executable is the unmodified official build and is licensed under MPL-2.0; its source is attached to each release, and its license is installed in `licenses/`. Xray's `geoip.dat` and `geosite.dat` are not installed. The executable embeds Wintun 0.14.1, copyrighted by WireGuard LLC and distributed under the [Wintun Prebuilt Binaries License](installer/third-party/wintun-prebuilt-binaries-license.txt); its license and notice are installed as `licenses/wintun-prebuilt-binaries-license.txt` and `licenses/wintun.txt`. The Manrope and Cormorant Garamond fonts use OFL-1.1. Notices for Rust crates are installed as `licenses/third-party.html`.

Rosetun is not affiliated with sing-box, SagerNet or Project X.
