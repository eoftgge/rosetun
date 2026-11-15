+++
title = "Privacy and network access"
weight = 9

[extra]
group = "Protection and privacy"
overview = "Privacy and network access"
+++

Rosetun makes these network requests:

- To the VPN server for the tunnel; **TCP ping** also makes a TCP connection attempt to each server being checked while the tunnel is down.
- **URL test** and a full delay on the connection screen send two HTTPS requests at once, to `https://cp.cloudflare.com/generate_204` and `https://www.gstatic.com/generate_204`, through the server being checked, the current server or each exit's server. URL test connects directly to each server, outside the tunnel. While connecting and while connected, the service sends the same requests through the current server to check that it works; this cannot be turned off. A repeated delay, the default, sends two requests in a row over one connection to `https://cp.cloudflare.com/generate_204` only, through the same servers.
- To your subscription provider to fetch or update subscriptions, using `User-Agent: Rosetun/<version>` by default. Subscription URLs may contain credentials; an HTTP subscription sends its token without encryption. With **Send device ID** on, the default, the request also carries:
  | Header | Windows | Linux |
  |---|---|---|
  | `x-hwid` | A SHA-256 hash, cut to 16 bytes, of `MachineGuid` and the subscription server's host | The same, of `/etc/machine-id` and the host |
  | `x-device-os` | `Windows` | `Linux` |
  | `x-ver-os` | The version and build from the registry | `PRETTY_NAME` from `os-release` |
  | `x-device-model` | The computer's model from the BIOS, or `PC` | The model from `/sys/class/dmi/id/product_name`, or `PC` |
  `MachineGuid` and `machine-id` themselves are not sent, and neither are your account name or your network adapters' addresses. Different subscription servers get different IDs, so they cannot match your device; subscriptions added before 0.4 keep their earlier ID, which is the same for all of them.
- To the addresses of lists, given by you or by a subscription, when a list is added or updated and with subscription updates (turn them off under **Update subscriptions automatically**). Rosetun sends `ETag` / `Last-Modified` from the previous download, so an unchanged list is not downloaded again. The request goes through the tunnel when connected.
- To the configured DNS-over-HTTPS resolver through the tunnel. The service also checks DNS by querying `example.com` during connection and random names beneath `example.com` while the tunnel is up.
- To `https://1.1.1.1/cdn-cgi/trace` for the public IP and country shown on the connection screen: through the current server when connected, and directly when disconnected, after a failed connection or when the service is unavailable. On Linux without rules by program it follows your rules, so a Direct rule for that address or a Direct default sends it directly and shows your own IP. The IP is hidden by default and is not written to the log. Exits make no requests of their own: their country comes from the server name.
- To `https://api.github.com/repos/eoftgge/rosetun/releases` for the release list at launch if it has never been checked or the last successful check was over a day ago, then once a day, and when you click **Check now**. When GitHub refuses it for its hourly limit (403 or 429), which happens behind a shared VPN address, Rosetun reads `https://github.com/eoftgge/rosetun/releases.atom` instead. The request goes through the tunnel when connected. Automatic checks are on by default; turn them off under **Settings → About → Check for updates**. The last successful check time, the version it found, any skipped version and the version the tray has announced are saved in the settings file. Nothing is downloaded or installed automatically.
- **System check** sends an HTTP `HEAD` request to `http://cp.cloudflare.com/`, unencrypted, to compare your clock with its `Date` header. It runs when you click **Check**, by itself after a failed connection and in **Collect report**; it goes directly without a tunnel and through the tunnel when connected. Without a connection it also sends two DNS queries to `1.1.1.1`, one over UDP and one over TCP, for the service name `whoami.cloudflare`, and compares the answers to see whether the network replaces DNS; Cloudflare sees your IP address, as with any DNS query to it. While connected or while the kill switch holds after a failure it sends no DNS queries, and **Collect report** shows the last result without asking again.
- If DNS stalls, the watchdog sends HTTP `HEAD` requests to `1.1.1.1:80` and to `connectivitycheck.gstatic.com/generate_204` through the tunnel to distinguish a DNS failure from a lost path. The second name is resolved through the tunnel's DNS when the connection starts.
- Before connecting, system DNS resolves the VPN server name; provider and ping hostnames may also be resolved by the operating system.
- When changing servers while connected, the new server's name is resolved through the current tunnel.

**Not sent:** there is no telemetry and no Rosetun account. The application update check only reports a new version. Program icons come from this computer; on Windows a program on a network drive or path gets no icon, so showing one never connects to another computer. The engine's control API and the link from sing-box to Xray use only local loopback.

**In the proxy mode** Rosetun's own requests, such as subscription updates, go through the local proxy, so your provider sees the VPN's address, as in TUN.

**With Lockdown on and no connection**, Rosetun itself (the app and the `rosetun` command) still reaches the internet directly: your subscription provider, list addresses, `cp.cloudflare.com` for **System check**, and the other requests above that go directly when disconnected (server checks, the public IP, the update check). Other programs do not. Your subscription provider then sees your real IP address, just as without Lockdown.

**Logs** stay on this computer.

- The service log is in `data\logs` under the installation folder on Windows, for administrators only, and in the system journal on Linux, for root and the journal's readers (the groups `adm` and `systemd-journal` on Debian). **Collect report** receives it only for the Windows account that started the session. On Linux it reads the journal as your own account, with the machine name removed; an account that may not read it gets a note in the report instead.
- When **Verbose log** is off, destination addresses in engine messages are replaced with `[hidden]`. The VPN server's name or address and the error's cause can remain. Site addresses are logged only while the temporary **Verbose log** setting is on.
- **Local network** writes the networks it opens to the service log, and a public network only as `public`.
