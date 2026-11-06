English | [Русский](README.ru.md)

<p align="center"><img src=".github/assets/banner.svg" alt="Rosetun: VPN client for Windows and Linux" width="100%"></p>

<p align="center">
  <a href="https://eoftgge.github.io/rosetun/en/"><img src="https://img.shields.io/badge/Website-8C2338?style=for-the-badge" alt="Website"></a>
  <a href="https://eoftgge.github.io/rosetun/en/help/"><img src="https://img.shields.io/badge/Help-432D36?style=for-the-badge" alt="Help"></a>
  <a href="https://eoftgge.github.io/rosetun/en/providers/"><img src="https://img.shields.io/badge/For%20providers-432D36?style=for-the-badge" alt="For providers"></a>
</p>

<p align="center">
<img alt="CI" src="https://img.shields.io/github/actions/workflow/status/eoftgge/rosetun/ci.yml?style=for-the-badge&logo=rust">
<img alt="GitHub issues by-label" src="https://img.shields.io/github/issues/eoftgge/rosetun/bug?style=for-the-badge&logo=github">
</p>

<p align="center">
  <a href="https://github.com/eoftgge/rosetun/releases/tag/v0.5.0-beta.1"><img src=".github/assets/download.svg" alt="Download Rosetun for Windows" height="56"></a>
  <a href="https://github.com/eoftgge/rosetun/releases/tag/v0.5.0-beta.1"><img src=".github/assets/download-linux.svg" alt="Download Rosetun for Debian 13" height="56"></a>
</p>

Rosetun is a VPN client for Windows and Linux. sing-box runs the tunnel, rules and DNS; for VLESS + REALITY servers, Xray behind sing-box carries the connection to the server. A system service keeps the kill switch and the DNS lock in the firewall. Rules split traffic by program, website and IP address, and provider subscriptions supply the servers.

**Young project:** one developer maintains it with AI coding agents, and it has few users yet. Please report what breaks in [Issues](https://github.com/eoftgge/rosetun/issues).

## Requirements

**Windows:** Windows 11, x64. Windows 10 runs on one tester's computer; the failure tests have not run on it.

**Linux:** Debian 13, amd64, with systemd and nftables (the package depends on them) and cgroup v2. polkit (`pkexec`, `polkitd`) is recommended: without it, the window cannot change Lockdown, and you run `sudo rosetun lockdown on` or `off` in a terminal. Linux is new in this beta.

| Desktop | Tray | System proxy settings |
| --- | --- | --- |
| KDE Plasma, Wayland and X11 | Yes | Changed by Rosetun (`kioslaverc`) |
| GNOME | Only with an extension that provides a tray; not tested. Without a tray, closing the window closes the program | Changed by Rosetun (`gsettings`); not tested on a real desktop |
| Others | Where a tray host answers; not tested | Rosetun shows the address to enter yourself |

Linux does not have these yet:

- rules by program: the engines run without root and cannot read other programs, so a connection with such a rule is refused;
- file dialogs: a QR code is read from the clipboard only, and there is no screen capture;
- **Collect report** and the buttons that open a folder (see [Troubleshooting](#troubleshooting));
- the system proxy and packet interception checks in **System check**;
- a remembered window position.

## Features

### Connection and protection

- A **Kill switch** blocks traffic when the tunnel drops. A **DNS lock** keeps system DNS from leaving outside the tunnel when the kill switch is off. It depends on the firewall: if it cannot be set, Rosetun still connects and says so.
- *Experimental:* **Lockdown** (Settings → Connection) closes the internet to everything outside the tunnel, also while disconnected, after a restart (from boot, before you sign in) and if the service stops or crashes. While it is on, the kill switch is always on. Incoming connections are blocked too, except from your network when **Local network** is on. Turning it on and off asks for confirmation and an administrator's rights: UAC on Windows, polkit on Linux. `rosetun lockdown` needs a terminal opened as administrator, or `sudo`. The way out is under [Troubleshooting](#troubleshooting).
- **The protection in place** shows on the connection screen, in the tray tooltip and in `rosetun status`, which also says what is missing and whether it stays if the service crashes:

  ```text
  protection: kill switch
  if the service crashes: this stays in place
  ```

- **The network stays closed through an update**, with the kill switch on, on both systems, and **after a service crash** on Linux only. See [Protection guarantees](#protection-guarantees).
- On Linux the service checks its firewall table every two seconds and puts it back if another program removed or changed it. `rosetun status` says when it did, or that it cannot.
- **Reconnect** in the tray menu or `rosetun reconnect` restarts the tunnel to the same server under the same protection.
- Change the server, rules or DNS while connected: Rosetun restarts the tunnel in a second or two without disconnecting, and the kill switch keeps traffic blocked meanwhile.
- **Reconnect automatically** after sleep, a network outage or an engine failure, with a DNS watchdog while connected.

### TUN and System proxy

**Connection mode** (Settings → Connection) chooses how traffic reaches the VPN. **TUN**, the default, takes all of this computer's traffic. **System proxy** starts a local proxy (HTTP and SOCKS5 on one port, 10808 unless you change it) and points your desktop's proxy settings at it, for when TUN gets in the way of another VPN, an anti-cheat or an antivirus, or when you only need the browser.

- **What goes through the VPN:** only programs that use the system proxy, which means browsers and most applications. Rules by site, address and list work as in TUN, and rules by program too on Windows.
- **What does not:** programs that ignore the system proxy, such as games, many console programs and Windows services (WinHTTP is left as it is). Without the kill switch they go direct, and so does their DNS: this mode has no DNS lock, since it has no adapter. Point console programs at the proxy yourself (`curl -x http://127.0.0.1:10808 ...`); Rosetun does not set `http_proxy` and other variables, which running programs would not read anyway.
- **Kill switch** here is strict: only Rosetun's engine and this computer's loopback reach the network, while you are connected too, so everything that does not use the proxy stays without network. Off by default, and it asks before it goes on.
- **Access from the local network** (off by default) lets a phone or a TV on your network use the proxy: Settings shows the address to enter. On Windows only the networks this computer's adapters are connected to get in, without the VPN servers' own addresses, for as long as the session lasts. On Linux the proxy listens only on the private addresses of physical interfaces. Under **Lockdown** it needs **Local network** too, and otherwise stays closed to other devices.
- **Your own settings come back:** what you had before, an automatic configuration script or a proxy of your own included, is saved next to the configuration and restored when you disconnect, quit or change the mode, and at the next start after a crash or a power cut. If you changed the proxy yourself meanwhile, Rosetun leaves your change alone.
- The `rosetun` command starts the proxy but does not change the desktop's settings: only the app does that.

### Rules

- **Routing rules** for programs (Windows), websites, IP addresses and subnets, and lists, with **Quick templates** and actions **Through VPN**, **Direct** and **Block**.
- **Exits:** a rule can send its traffic through another country or a specific server while the rest goes through the server on the main screen. Picking a country or a server in the rule creates an exit on the **Exits** tab, where you can change its server and turn on a fallback to any server of the same country. If an exit's server disappears, its rules block traffic; they never go direct.
- **Lists:** GeoIP and GeoSite (Xray `.dat` files, sing-box rule sets) and your own text lists, from a file or a link. A list from a link is downloaded again only when it has changed (`ETag` / `Last-Modified`).
- **Undo:** Ctrl+Z steps back through your changes on the Rules tab, **Revert** returns to the rules applied to the connection, and Del removes the selected rule without asking.
- **Temporary rules:** add a rule only until disconnect; it applies at once and is never saved.
- **Connections** on the Traffic tab: while connected, what your programs connect to right now, grouped by program, with the route each connection took and why (which rule, list or the default). Create a rule or close a connection from there. The list is kept only in memory for the account that connected and is cleared on disconnect; it is never written to disk or to the log.

### Local network

**Local network** (Settings → Connection) lets programs reach devices on your network past the tunnel, also with the kill switch on: a printer, a NAS, a game console, USB over IP (such as VirtualHere) and game streaming (such as Sunshine and Moonlight). Off by default; turn it off on public networks. Your router's DNS is not used: names are looked up through the VPN.

**On Windows** it opens only the networks the computer's own adapters are connected to, each on its own adapter, plus link-local addresses (169.254.x.x). **Private networks behind the router**, off by default, also opens every private range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 and IPv6 fc00::/7) on any adapter.

**On Linux** the firewall opens every private range and link-local addresses on any interface, which is wider than on Windows: it has no segment of its own, and VPN servers' addresses are not left out. **Private networks behind the router** also sends private addresses past the tunnel in the engine's rules.

On Windows:

- Finding devices (mDNS, LLMNR, SSDP, broadcasts) works for programs that send their search on each adapter, as Windows itself and most discovery libraries do, and for broadcasts to 255.255.255.255 from any program. Such a broadcast from a program that leaves the choice of adapter to Windows uses Windows' preferred adapter. If a virtual adapter (such as VirtualBox's) has the same or a better metric than the real one, Windows can pick it; give the virtual adapter a higher metric. With Local network off, such a broadcast goes into the tunnel.
- Multicast (mDNS, SSDP) from a program that leaves the choice of adapter to Windows goes into the tunnel and does not reach the local network. Rosetun cannot change that with routes.
- A connected network wider than /16 is not opened. When the computer moves to another network, Rosetun follows it within a few seconds with a short reconnect; the kill switch stays on meanwhile.
- Local IPv6 addresses stay closed while the tunnel carries IPv4 only. Reach local devices by their IPv4 addresses.
- A VPN server's own addresses stay out of what is opened, also for private networks behind the router, and a rule that sends such an address through the VPN still wins.
- A device in another subnet than this computer is not on your network: put both in one subnet or turn on Private networks behind the router. To see which way Windows sends traffic to a device, run in PowerShell (with the device's address):

  ```powershell
  Find-NetRoute -RemoteIPAddress 192.0.2.10
  ```

  `InterfaceAlias` must be your Ethernet or Wi-Fi adapter, not `rosetun0`, and `IPAddress` this computer's address on that network.

With **Lockdown** on, the same networks are open while disconnected too, and devices on them can connect to this computer. `rosetun lockdown on --lan private` turns Lockdown on with private networks behind the router.

### Subscriptions and servers

- Provider subscriptions in plain or base64-encoded link lists, Xray JSON and sing-box JSON. Add one from its link, from a QR code (an image file, the clipboard or a part of the screen on Windows, the clipboard on Linux) or from a provider's `rosetun://` link.
- HTTP, HTTPS and SOCKS5 proxies of your own, on the **Proxy** tab of the add dialog.
- **Send device ID** (HWID) is on by default: panels that limit devices answer "subscription not found" without it. Turn it off for a subscription in the add dialog (`--no-hwid` in the CLI). See [Privacy and network access](#privacy-and-network-access).
- VLESS, VMess, Trojan, Shadowsocks and Hysteria2 nodes (Salamander obfuscation and port hopping); TCP, WebSocket, gRPC and HTTPUpgrade transports for TCP-based nodes, and XHTTP (SplitHTTP) through Xray; plain, TLS and Reality security modes. Hysteria2 uses QUIC over UDP. Not supported yet, so such servers are skipped: XHTTP with a separate download server, mKCP, QUIC and HTTP/2 transports, VLESS encryption, Shadowsocks plugins and other protocols.
- **Connection through Xray** (Settings → Advanced): **Automatically** (default) uses Xray for VLESS servers with REALITY and for XHTTP, and sing-box for the rest; **Without Xray** connects to every server with sing-box alone; **Xray for all servers** sends every supported server except Hysteria2 through Xray. The server list marks servers that go through Xray.
- **TLS fragmentation** (Settings → Advanced): splits the first packets to the server, which helps when a provider cuts the connection by its first packet. Servers that Xray carries go through Xray while it is on; the connection screen says whether it applies to the current server.
- **DNS through the tunnel** via a configurable DNS-over-HTTPS resolver.
- **Server checks:** a TCP ping and a URL test that sends a request through each server, even while connected, through the same chain as the connection.

### Everyday use

- **Start at sign-in:** on Windows a scheduled task, on Linux an autostart entry in your home folder. The option is in Settings.
- The **tray icon** shows the state by shape: the rose is in colour only while connected; otherwise it is grey with a badge for connecting, traffic blocked, a failed connection and the service not running. Its menu shows the state, connects or disconnects, reconnects, switches between your five most recent servers and opens the window.
- **Notifications** say when the VPN drops, comes back or cannot connect; they name no server, since they can show on the lock screen. Turn them off in Settings › General.
- **Quitting** Rosetun while connected asks whether to disconnect or keep the VPN, which the service holds without the window; the answer can be remembered (Settings › General › **When quitting Rosetun**).
- **New versions** are offered on the connection screen, in the tray menu and by one notification per version, until you update or skip that version. Nothing is downloaded or installed by itself.
- English and Russian interfaces, six colour themes and **Reduce motion**. Server names and your own input can be in other scripts, drawn with system fonts: the Windows fonts folder, or fontconfig on Linux. Right-to-left text shows without shaping.
- **System check** (Settings → Service and log) looks for a wrong clock, other VPN clients or their adapters and a network that replaces DNS answers, and on Windows for a system proxy and for Zapret or WinDivert intercepting packets. It runs by itself after a failed connection and changes nothing.
- **Collect report** (Settings → Service and log, Windows) saves one text file for a bug report: versions, settings without secrets, the connection state, the system check and the logs. IP addresses, links, domains, email addresses, keys and passwords, server, subscription, list and rule set names, and your account name are removed.
- Command line: `rosetun status`, `temporary`, `connect`, `apply`, `probe`, `delay`, `exits`, `select`, `sub add|update|list|remove`, `nodes`, `config`, `connections`, `connections close`, `xray auto|off|always`, `lan on|off`, `lockdown on|off`, `reconnect`, `open-network`, `reset-firewall`, `disconnect`, `shutdown`.

## Protection guarantees

What stays closed outside the tunnel at each moment:

- **open:** Rosetun closes nothing. While connected in TUN, programs' traffic still goes into the tunnel; nothing stops it from going around if the tunnel fails.
- **DNS closed:** system DNS cannot leave outside the tunnel; everything else is open.
- **closed:** nothing leaves outside the tunnel. In the proxy mode, nothing but the engine and loopback.
- **held:** closed, and it stays closed until you connect or run `rosetun open-network`.
- **\*** read from the code: no matrix scenario covers this cell. Every other cell has a scenario in [`tools/vm`](tools/README.md); a release's notes say which matrices were run for it.

"No protection" means the kill switch is off and the DNS lock is not in place: the firewall refused it, or the tunnel has no DNS of its own.

**Windows**

| Event | No protection | DNS lock | Kill switch | Lockdown | Proxy | Proxy, kill switch |
| --- | --- | --- | --- | --- | --- | --- |
| Disconnected | open | open | open | closed | open | open\* |
| Connected | open | DNS closed | closed | closed | open | closed |
| Engine restart | open | DNS closed | closed | closed\* | open\* | closed |
| Service crash | open\* | open | open | closed | open\* | open\* |
| Service stopped | open\* | open\* | open | closed | open\* | open\* |
| Update | open\* | open | held | closed | open\* | held\* |
| Restart of the computer | open\* | open\* | open\* | closed | open\* | open\* |

**Linux**

| Event | No protection | DNS lock | Kill switch | Lockdown | Proxy | Proxy, kill switch |
| --- | --- | --- | --- | --- | --- | --- |
| Disconnected | open | open | open | closed | open | open |
| Connected | open | DNS closed | closed | closed | open | closed |
| Engine restart | open | DNS closed\* | closed | closed\* | open\* | closed |
| Service crash | open\* | DNS closed until the service restarts, then open | held | closed | open\* | held\* |
| Service stopped | open\* | open\* | open | closed | open\* | open |
| Update | open\* | DNS closed until the new service starts, then open\* | held | closed | open\* | held\* |
| Restart of the computer | open\* | open\* | open\* | closed | open\* | open\* |

The difference to remember: **on Windows a crash of the service opens the network**, because the firewall removes a session's filters with its process, and only Lockdown stays. On Linux the firewall table outlives the service, so a kill switch holds the network closed after a crash. A restart of the computer opens both, except under Lockdown. On Windows a hold from an update is Lockdown's persistent set, so by the code it also lasts through a restart (no scenario covers it); on Linux it does not.

**Not tested:**

- Windows 10 in the failure tests: it is only known to run on one tester's computer;
- other firewalls and antivirus programs with their own network filters, and firewalld on Linux (Rosetun's units start after it; `nftables.service` is covered);
- sleep and hibernation with Lockdown on real hardware (Windows: only a virtual machine's sleep; Linux: not at all);
- a power cut on Linux;
- going back to 0.4;
- on Linux, **Local network** from a program that does not pick the interface itself;
- on Linux, the window, the tray and the polkit prompt in an automated run: no matrix drives a desktop. KDE Plasma was checked by hand, on Wayland and X11.

Lockdown protects against accidental leaks: the VPN drops, the service stops, the computer boots. It does not protect against malware you run yourself. The kill switch stays the main protection.

## Install

### Windows

Download `rosetun-<version>-setup.exe` from [Releases](https://github.com/eoftgge/rosetun/releases). The installer is not code-signed yet; if SmartScreen says "Windows protected your PC", select **More info** and then **Run anyway**. See the [code signing policy](CODE_SIGNING_POLICY.md).

You can choose an installation folder, but not inside a user profile or where standard users can change it; the SYSTEM service requires a protected folder. Uninstalling keeps your configuration in `%APPDATA%\Rosetun` by default, or you can choose to delete your settings, subscriptions and rules.

**Update:** run the new installer over the old version. With the kill switch on, the network stays closed through the update, and the app starts and connects again. If it cannot connect, the connection screen offers **Connect** and **Open network**; `rosetun open-network` does the same. Lockdown stays on.

**Settings:** when the configuration format changes, Rosetun keeps a copy of the previous file beside it at the first save (such as `config.v7.json`); the copy contains the same subscription URLs. An older version refuses a newer file and does not overwrite it.

**Going back to 0.4** (not tested):

1. In 0.5, disconnect, so your own proxy settings come back. 0.4 knows nothing of them.
2. Uninstall 0.5 and keep your settings. This removes Lockdown, an update's hold and the sign-in task, which 0.4 does not know how to remove.
3. Install 0.4.
4. Close Rosetun and restore the settings in PowerShell. Without `config.v7.json`, the file is still format 7, so skip this step. Changes made in 0.5 are lost.

   ```powershell
   Move-Item -Force "$env:APPDATA\Rosetun\config.v7.json" "$env:APPDATA\Rosetun\config.json"
   ```

5. Turn on **Start with Windows** and Lockdown again if you use them.

### Debian 13

Download `rosetun_<version>_amd64.deb` from [Releases](https://github.com/eoftgge/rosetun/releases), [verify it](#verify-the-download), install it and add yourself to the group that may reach the service:

```sh
sudo apt install ./rosetun_<version>_amd64.deb
sudo usermod -aG rosetun "$USER"
```

Then **restart the computer**. Logging out is not enough: your systemd user manager can outlive the logout and pass its old groups on to the programs it starts. If you skip the last command, the window offers the same with **Add me**.

**Update:** install the new package the same way. With the kill switch on, the network stays closed through the update: a running window restarts itself and connects again. Without a window, `rosetun status` says `network: held closed`, `rosetun connect` connects and `rosetun open-network` opens it. Lockdown stays on.

**Remove:** `sudo apt remove rosetun` takes Lockdown off first. If it cannot, the removal stops and Rosetun stays, so the network can still be opened.

**Purge:** `sudo apt purge rosetun` also removes the lists and state in `/var/lib/rosetun`. Your settings and autostart entry in your home folder (`~/.config/rosetun`) and the `rosetun` group stay.

### Verify the download

`SHA256SUMS.txt` in each release lists the installer and the package. For a release built from a tag, GitHub also holds a build provenance attestation for both. An attestation says which workflow built the file; it is not a code signature.

Windows:

```powershell
Get-FileHash .\rosetun-<version>-setup.exe -Algorithm SHA256
gh attestation verify .\rosetun-<version>-setup.exe --repo eoftgge/rosetun
```

Debian:

```sh
sha256sum --check --ignore-missing SHA256SUMS.txt
gh attestation verify rosetun_<version>_amd64.deb --repo eoftgge/rosetun
```

The file of a beta is named `rosetun_0.5.0-beta.1_amd64.deb`; `dpkg` shows its version as `0.5.0~beta.1`.

## Privacy and network access

Rosetun makes these network requests:

- To the VPN server for the tunnel; **TCP ping** also makes a TCP connection attempt to each server being checked while the tunnel is down.
- **URL test** and the delay on the connection screen send two HTTPS requests at once, to `https://cp.cloudflare.com/generate_204` and `https://www.gstatic.com/generate_204`, through the server being checked, the current server or each exit's server. URL test connects directly to each server, outside the tunnel. While connecting and while connected, the service sends the same requests through the current server to check that it works; this cannot be turned off.
- To your subscription provider to fetch or update subscriptions, using `User-Agent: Rosetun/<version>` by default. Subscription URLs may contain credentials; an HTTP subscription sends its token without encryption. With **Send device ID** on, the default, the request also carries:

  | Header | Windows | Linux |
  | --- | --- | --- |
  | `x-hwid` | A SHA-256 hash, cut to 16 bytes, of `MachineGuid` and the subscription server's host | The same, of `/etc/machine-id` and the host |
  | `x-device-os` | `Windows` | `Linux` |
  | `x-ver-os` | The version and build from the registry | `PRETTY_NAME` from `os-release` |
  | `x-device-model` | The computer's model from the BIOS, or `PC` | The model from `/sys/class/dmi/id/product_name`, or `PC` |

  `MachineGuid` and `machine-id` themselves are not sent, and neither are your account name or your network adapters' addresses. Different subscription servers get different IDs, so they cannot match your device; subscriptions added before 0.4 keep their earlier ID, which is the same for all of them.
- To the addresses of lists, given by you or by a subscription, when a list is added or updated and with subscription updates (turn them off under **Update subscriptions automatically**). Rosetun sends `ETag` / `Last-Modified` from the previous download, so an unchanged list is not downloaded again. The request goes through the tunnel when connected.
- To the configured DNS-over-HTTPS resolver through the tunnel. The service also checks DNS by querying `example.com` during connection and random names beneath `example.com` while the tunnel is up.
- To `https://1.1.1.1/cdn-cgi/trace` for the public IP and country shown on the connection screen: through the current server when connected, and directly when disconnected, after a failed connection or when the service is unavailable. The IP is hidden by default and is not written to the log. Exits make no requests of their own: their country comes from the server name.
- To `https://api.github.com/repos/eoftgge/rosetun/releases` for the release list at launch if it has never been checked or the last successful check was over a day ago, then once a day, and when you click **Check now**. When GitHub refuses it for its hourly limit (403 or 429), which happens behind a shared VPN address, Rosetun reads `https://github.com/eoftgge/rosetun/releases.atom` instead. The request goes through the tunnel when connected. Automatic checks are on by default; turn them off under **Settings → About → Check for updates**. The last successful check time, the version it found, any skipped version and the version the tray has announced are saved in the settings file. Nothing is downloaded or installed automatically.
- **System check** sends an HTTP `HEAD` request to `http://cp.cloudflare.com/`, unencrypted, to compare your clock with its `Date` header. It runs when you click **Check**, by itself after a failed connection and in **Collect report**; it goes directly without a tunnel and through the tunnel when connected. Without a connection it also sends two DNS queries to `1.1.1.1`, one over UDP and one over TCP, for the service name `whoami.cloudflare`, and compares the answers to see whether the network replaces DNS; Cloudflare sees your IP address, as with any DNS query to it. While connected or while the kill switch holds after a failure it sends no DNS queries, and **Collect report** shows the last result without asking again.
- If DNS stalls, the watchdog sends HTTP `HEAD` requests to `1.1.1.1:80` and to `connectivitycheck.gstatic.com/generate_204` through the tunnel to distinguish a DNS failure from a lost path. The second name is resolved through the tunnel's DNS when the connection starts.
- Before connecting, system DNS resolves the VPN server name; provider and ping hostnames may also be resolved by the operating system.
- When changing servers while connected, the new server's name is resolved through the current tunnel.

**Not sent:** there is no telemetry and no Rosetun account. The application update check only reports a new version. Program icons come from this computer; on Windows a program on a network drive or path gets no icon, so showing one never connects to another computer. The engine's control API and the link from sing-box to Xray use only local loopback.

**In the proxy mode** Rosetun's own requests, such as subscription updates, go through the local proxy, so your provider sees the VPN's address, as in TUN.

**With Lockdown on and no connection**, Rosetun itself (the app and the `rosetun` command) still reaches the internet directly: your subscription provider, list addresses, `cp.cloudflare.com` for **System check**, and the other requests above that go directly when disconnected (server checks, the public IP, the update check). Other programs do not. Your subscription provider then sees your real IP address, just as without Lockdown.

**Logs** stay on this computer.

- The service log is in `data\logs` under the installation folder on Windows, for administrators only, and in the system journal on Linux, for root and the journal's readers (the groups `adm` and `systemd-journal` on Debian). **Collect report** receives it only for the Windows account that started the session.
- When **Verbose log** is off, destination addresses in engine messages are replaced with `[hidden]`. The VPN server's name or address and the error's cause can remain. Site addresses are logged only while the temporary **Verbose log** setting is on.
- **Local network** writes the networks it opens to the service log, and a public network only as `public`.

## Troubleshooting

- Run **System check** (Settings → Service and log) first. It also runs by itself after a failed connection and shows the first finding under the error.
- **No network at all with Lockdown on, and Rosetun does not open.** This removes Lockdown without the service. In a terminal opened as administrator on Windows:

  ```powershell
  & 'C:\Program Files\Rosetun\rosetun.exe' reset-firewall
  ```

  Use your own folder if you chose another. On Linux:

  ```sh
  sudo rosetun reset-firewall
  ```

  Uninstalling Rosetun removes Lockdown too.
- **The network is closed after an update or a crash**, and `rosetun status` says `network: held closed`. Connect, or open it: **Open network** on the connection screen, or `rosetun open-network`. Without a working service, use `reset-firewall` as above.
- **A site does not open right after connecting:** browsers keep their own DNS cache. Rosetun clears the Windows DNS cache when it connects and disconnects, but not theirs. Restart the browser.
- **Another VPN client** in TUN mode can prevent the tunnel from starting. Disconnect it and retry. A program that changes traffic, such as zapret, can disrupt the connection to the server: exclude the server addresses in its settings.
- **Linux: No access to the Rosetun service.** Your account is not in the `rosetun` group yet, or your session started before it joined. Press **Add me**, or run `sudo usermod -aG rosetun "$USER"`, and restart the computer.
- **Linux: Rosetun says another program changed the firewall rules.** `nftables.service` and firewalld can start with `flush ruleset`, which removes Rosetun's table. The service puts it back within seconds and `rosetun status` says when. If it says `firewall rules: cannot be checked or put back`, treat the network as unprotected and reconnect.
- **Linux: KDE programs do not use the proxy.** Check that `~/.config/kioslaverc` has `ProxyType=1` under `[Proxy Settings]` and that `XDG_CURRENT_DESKTOP` contains `KDE`; otherwise Rosetun shows the address to enter yourself. KDE programs read the settings again by a signal and Chromium watches the file; restart other programs. The `rosetun` command never changes these settings.
- **Linux: Without a connection subscriptions do not update under Lockdown.** Rosetun started outside your desktop session, as the window says. Restart it from the desktop.
- **TLS fragmentation** works only for servers that Xray carries (VLESS, VMess, Trojan, Shadowsocks) and helps with some providers only. Hysteria2 and HTTP or SOCKS5 servers connect without it, and it is unavailable while **Without Xray** is selected.
- **No network connection** means the system has no working network, so the server is not to blame. Connecting fails at once. While connected, a short network change does not break the session; with **Reconnect automatically** on, Rosetun waits for the network and reconnects when it returns, and the kill switch keeps the internet closed meanwhile.
- **Wi-Fi with a sign-in page** (a hotel or a café) or **a wrong clock** with **Lockdown** on: the sign-in page cannot open and the system cannot set the time without the tunnel, and the tunnel cannot start without them. Turn Lockdown off for a moment, sign in or correct the clock, connect, and turn Lockdown on again.
- **Lockdown leaves virtual machines without network.** Confirmed for Hyper-V on Windows, and most likely WSL2, Docker Desktop, Windows Sandbox and Mobile hotspot as well; on Linux, virtual machines and containers on this computer without a Rosetun connection. Turn Lockdown off while you need them.
- **Windows: the window fails to open or draws incorrectly after an update:** quit Rosetun from the tray, then run `$env:ROSETUN_RENDERER='glow'; & 'C:\Program Files\Rosetun\rosetun-gui.exe'` in PowerShell (adjust the path if needed). Use **Collect report** and send the report with a description of the problem.
- **Windows: setup stops because standard users can change a folder under `C:\Program Files\Rosetun`.** This usually follows **Continue** in File Explorer, which gives your account permanent access to a protected Rosetun folder such as `data`. Uninstall Rosetun and install it again. To read the service log, use **Collect report** or an editor run as administrator instead.

**Report a problem** in [Issues](https://github.com/eoftgge/rosetun/issues), with the steps and the error text. On Windows attach **Collect report**. On Linux attach the output below and remove addresses, links and names first: unlike the report, these logs are not cleaned.

```sh
rosetun status
sudo journalctl -u rosetun-helper -b --no-pager
cat ~/.config/rosetun/rosetun-gui.log
```

Report a vulnerability privately: see [SECURITY.md](SECURITY.md).

## How it works

```text
Windows
GUI, CLI (user) ──named pipe──► Rosetun service (SYSTEM) ──► sing-box.exe ──► TUN
                                     │                            │
                                     │                            └──loopback──► xray.exe (some servers)
                                     └── WFP: kill switch, DNS lock, Lockdown

Linux
GUI, CLI (group rosetun) ──socket──► rosetun-helper (root) ──► sing-box (rosetun-engine) ──► TUN
                                     │                            │
                                     │                            └──loopback──► xray (rosetun-engine)
                                     └── nftables + cgroup: kill switch, DNS lock, Lockdown
```

The service (`rosetun-helper-privileged`) starts sing-box, which runs the tunnel, rules and DNS. For servers that go through Xray, sing-box hands the connection over loopback to Xray, which the service also starts and which connects to the server. The service owns protection, so closing the window does not remove it. In the proxy mode there is no TUN: the engine listens as a local proxy.

**Windows.** The kill switch and DNS lock are WFP filters in the service's dynamic session, so Windows removes them if the service stops or crashes (fail-open). This avoids leaving the computer permanently offline. The service runs sing-box from its own copy, `data\engines\sing-box.exe`, which only SYSTEM and Administrators can open. While connected, sing-box adds a firewall permit for its own executable that Rosetun's blocks cannot override, so no other account may start that executable. The copy is refreshed and checked by SHA-256 when the service starts; if it cannot be made, connecting fails rather than running the installed `sing-box.exe`.

With **Lockdown** on, Rosetun also keeps persistent WFP filters in its own sublayer that block everything outside the tunnel. Windows keeps them across a service crash and a restart, and the Base Filtering Engine (BFE) restores them at boot, with boot-time filters covering the time before it starts (fail-closed). They are removed only by turning Lockdown off, by `rosetun reset-firewall` or by uninstalling Rosetun. An update's hold is the same set with a marker.

**Linux.** The firewall is one nftables table, `inet rosetun`, written in one transaction. The service runs in a cgroup with two leaves, `helper` and `engines`, and the table permits by cgroup, not by program path or account. Engines run as `rosetun-engine`, which has no login, no home and no other group, with only `CAP_NET_ADMIN`, `CAP_NET_RAW` and `CAP_NET_BIND_SERVICE`. The service runs them only from root-owned files. A polkit rule lets that account set a link's DNS in systemd-resolved, so system DNS follows the tunnel.

The table outlives the service, so a crash leaves it in place, and the restarted service keeps the network closed. It does not outlive a restart of the computer: Lockdown's record in `/var/lib/rosetun/lockdown` does, and `rosetun-lockdown.service` writes the table again before any network comes up. The app and the `rosetun` command get out under Lockdown only from their own systemd scopes.

**What Lockdown leaves open.** The engines get through only when the service starts them, and the Rosetun app and the `rosetun` command only over TCP and DNS and only while not connected, but a program running under your account can still go out through the `rosetun` command, among many other ways.

## Build from source

Use Rust 1.96 or newer, with the MSVC toolchain on Windows. Run `cargo build --release` to build the binaries and `cargo test --workspace` to run tests.

- **Windows installer:** `./installer/build.ps1` builds `target/installer/rosetun-<version>-setup.exe`. See the [installer instructions](installer/README.md).
- **Debian package:** `installer/linux/build-deb.sh --release` builds `rosetun_<version>_amd64.deb`, on Debian 13 or in Debian under WSL, as an ordinary user. See the [same instructions](installer/README.md#debian-package).
- **Failure testing** on virtual machines: the [VM test rig](tools/README.md).

Before committing, run `git config core.hooksPath tools/hooks` once. The hooks reject AI attribution and non-Conventional commit messages, patch files, real proxy hosts and your Windows account name in added lines, and unformatted code on push. CI runs the same message and added-line checks.

## Links for providers

A button on a provider's page can open Rosetun with a subscription filled in: `rosetun://add/<subscription link>`, with the link raw (`rosetun://add/https://example.com/sub`) or percent-encoded (`rosetun://add/https%3A%2F%2Fexample.com%2Fsub`). An optional `#name` at the end suggests the subscription's name (`rosetun://add/https://example.com/sub#Example`). Rosetun only shows the **Add subscription** dialog with the link, its name and the provider's host; nothing is downloaded or added until you click **Add**. A link to a subscription you already have only brings it into view.

The Windows installer registers the scheme for all users. The Debian package registers it through its `.desktop` file (`x-scheme-handler/rosetun`). A running Rosetun takes the link from a later start through a channel only your account can open: a named pipe on Windows, a socket in `$XDG_RUNTIME_DIR` on Linux.

More for providers, with response headers: [the site's page](https://eoftgge.github.io/rosetun/en/providers/).

## Security

See [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## Licenses

Rosetun is licensed under **GPL-3.0-or-later**, © 2026 Sandaar. See [LICENSE](LICENSE). The bundled sing-box executable is the unmodified official build and is licensed under GPL-3.0-or-later. The bundled Xray-core executable is the unmodified official build and is licensed under MPL-2.0; its source is attached to each release. Xray's `geoip.dat` and `geosite.dat` are not installed. On Windows, the sing-box executable embeds Wintun 0.14.1, copyrighted by WireGuard LLC and distributed under the [Wintun Prebuilt Binaries License](installer/third-party/wintun-prebuilt-binaries-license.txt). The Manrope and Cormorant Garamond fonts use OFL-1.1.

Licenses and notices, for Rust crates too, are installed in `licenses/` on Windows and in `/usr/share/doc/rosetun/licenses` on Linux.

Rosetun is not affiliated with sing-box, SagerNet or Project X.
