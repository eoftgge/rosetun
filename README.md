English | [Русский](README.ru.md)

# Rosetun

Rosetun is a Windows VPN client powered by sing-box. A Windows service maintains the kill switch and DNS lock; routing rules split traffic by app and website, and provider subscriptions supply servers.

<a href="https://github.com/eoftgge/rosetun/releases"><img src=".github/assets/download.svg" alt="Download Rosetun for Windows" height="56"></a>

**Alpha software:** expect bugs. Settings may be reset between alpha releases.

## Features

- A **Kill switch** blocks traffic when the tunnel drops. Without it, a DNS lock keeps system DNS from leaking outside the tunnel throughout the session, including while the engine restarts.
- **Routing rules** for apps and websites, with **Quick templates** and actions **Through VPN**, **Direct** and **Block**.
- Provider subscriptions in plain or base64-encoded link lists, Xray JSON and sing-box JSON. **Send device ID** (HWID) is optional for providers that require it.
- VLESS, VMess, Trojan, Shadowsocks and Hysteria2 nodes (Salamander obfuscation and port hopping); TCP, WebSocket, gRPC and HTTPUpgrade transports for TCP-based nodes; plain, TLS and Reality security modes. Hysteria2 uses QUIC over UDP.
- **DNS through the tunnel** via a configurable DNS-over-HTTPS resolver.
- Change the server, rules or DNS while connected: Rosetun restarts the tunnel in a second or two without disconnecting, and the kill switch keeps traffic blocked meanwhile.
- **Temporary rules:** add a rule only until disconnect; it applies at once and is never saved.
- **Reconnect automatically** after sleep or an engine failure, with a DNS watchdog while connected.
- **Server checks:** a TCP ping and a URL test that sends a request through each server, even while connected.
- System tray, **Start with Windows**, and English and Russian interfaces.

## Install

Download the installer from [Releases](https://github.com/eoftgge/rosetun/releases). Windows 10 or 11, x64, is required. The installer is not code-signed yet; if SmartScreen says "Windows protected your PC", select **More info** and then **Run anyway**.

Uninstalling leaves your configuration in `%APPDATA%\Rosetun`.

### Verify the download

Compare `Get-FileHash .\rosetun-<version>-setup.exe -Algorithm SHA256` with the entry in the release's `SHA256SUMS.txt`. For a public tagged release, verify provenance with `gh attestation verify .\rosetun-<version>-setup.exe --repo eoftgge/rosetun`.

## Privacy and network access

Rosetun makes these network requests:

- To the VPN server for the tunnel; **TCP ping** also makes a TCP connection attempt to each server being checked while the tunnel is down.
- **URL test** and the current server's delay on the connection screen each send one HTTPS request to `https://cp.cloudflare.com/generate_204` through the server being checked or the current server. URL test connects directly to each server, outside the tunnel.
- To your subscription provider to fetch or update subscriptions, using `User-Agent: Rosetun/<version>` by default. When **Send device ID** is on, the request also includes `x-hwid`, `x-device-os`, `x-ver-os` and `x-device-model`. Subscription URLs may contain credentials; an HTTP subscription sends its token without encryption.
- To the configured DNS-over-HTTPS resolver through the tunnel. The service also checks DNS by querying `example.com` during connection and random names beneath `example.com` while the tunnel is up.
- To `https://1.1.1.1/cdn-cgi/trace` through the tunnel for the exit country and public IP shown on the connection screen. The exit IP is hidden by default and is not written to the log.
- If DNS stalls, the watchdog also sends an HTTP `HEAD` request to `1.1.1.1:80` through the tunnel to distinguish a DNS failure from a lost path.
- Before connecting, system DNS resolves the VPN server name; provider and ping hostnames may also be resolved by the operating system.
- When changing servers while connected, the new server's name is resolved through the current tunnel.

The engine's control API is contacted only over local loopback. There is no telemetry, application update checker or Rosetun account. Logs stay on this machine; the service log is accessible only to administrators. Site addresses are logged only while the temporary **Verbose log** setting is enabled. Automatic *subscription* updates are separate from application updates.

## How it works

```text
GUI (user) ──named pipe──► Rosetun service (SYSTEM) ──► sing-box.exe ──► TUN
                                    └── WFP: kill switch / DNS lock
```

The service owns protection, so closing the GUI does not remove it. If the service itself crashes, Windows removes its firewall filters (fail-open). This avoids leaving the computer permanently offline.

## Build from source

Use Rust 1.96 or newer with the MSVC toolchain on Windows. Run `cargo build --release` to build the binaries and `cargo test --workspace` to run tests. See [installer instructions](installer/README.md) for packaging and the [VM test rig](tools/README.md) for elevated failure testing.

## Security

See [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## Licenses

Rosetun is licensed under **GPL-3.0-or-later**, © 2026 Sandaar. See [LICENSE](LICENSE). The bundled sing-box executable is the unmodified official build and is licensed under GPL-3.0-or-later. The Manrope and Cormorant Garamond fonts use OFL-1.1. Notices for Rust crates are installed as `licenses/third-party.html`.

Rosetun is not affiliated with sing-box or SagerNet.

![CI](https://github.com/eoftgge/rosetun/actions/workflows/ci.yml/badge.svg)
