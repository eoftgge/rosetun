+++
title = "How it works"
weight = 11

[extra]
group = "Protection and privacy"
+++

<pre class="diagram"><code>Windows
GUI / CLI
    │ named pipe
    ▼
Rosetun (SYSTEM) ── WFP protection
    │
    ├── sing-box ── TUN
    └── Xray (loopback from sing-box)

Linux
GUI / CLI (rosetun group)
    │ socket
    ▼
Rosetun (root) ── nftables + cgroup
    │
    ├── sing-box ── TUN
    └── Xray (loopback from sing-box)
        rosetun-engine account</code></pre>

The service (`rosetun-helper-privileged`) starts sing-box, which runs the tunnel, rules and DNS. For servers that go through Xray, sing-box hands the connection over loopback to Xray, which the service also starts and which connects to the server. The service owns protection, so closing the window does not remove it. In the proxy mode there is no TUN: the engine listens as a local proxy.

**Windows.** The kill switch and DNS lock are WFP filters in the service's dynamic session, so Windows removes them if the service stops or crashes (fail-open). This avoids leaving the computer permanently offline. The service runs sing-box from its own copy, `data\engines\sing-box.exe`, which only SYSTEM and Administrators can open. While connected, sing-box adds a firewall permit for its own executable that Rosetun's blocks cannot override, so no other account may start that executable. The copy is refreshed and checked by SHA-256 when the service starts; if it cannot be made, connecting fails rather than running the installed `sing-box.exe`.

With **Lockdown** on, Rosetun also keeps persistent WFP filters in its own sublayer that block everything outside the tunnel. Windows keeps them across a service crash and a restart, and the Base Filtering Engine (BFE) restores them at boot, with boot-time filters covering the time before it starts (fail-closed). They are removed only by turning Lockdown off, by `rosetun reset-firewall` or by uninstalling Rosetun. An update's hold is the same set with a marker.

**Linux.** The firewall is one nftables table, `inet rosetun`, written in one transaction. The service runs in a cgroup with two leaves, `helper` and `engines`, and the table permits by cgroup, not by program path or account. Engines run as `rosetun-engine`, which has no login, no home and no other group, with only `CAP_NET_ADMIN`, `CAP_NET_RAW` and `CAP_NET_BIND_SERVICE`. The service runs them only from root-owned files. A polkit rule lets that account set a link's DNS in systemd-resolved, so system DNS follows the tunnel.

The table outlives the service, so a crash leaves it in place, and the restarted service keeps the network closed. It does not outlive a restart of the computer: Lockdown's record in `/var/lib/rosetun/lockdown` does, and `rosetun-lockdown.service` writes the table again before any network comes up. The app and the `rosetun` command get out under Lockdown only from their own systemd scopes.

**What Lockdown leaves open.** The engines get through only when the service starts them, and the Rosetun app and the `rosetun` command only over TCP and DNS and only while not connected, but a program running under your account can still go out through the `rosetun` command, among many other ways.

Enabled rules by program additionally require `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`; see the [Linux program rule limitations](../rules/). systemd restarts the service after a crash without a start rate limit. Package upgrades mark the stop as an upgrade before stopping the service, so the protection table stays in place for the new service.

## About Rosetun {#about-rosetun}

Rosetun is a VPN client for Windows and Linux. sing-box runs the tunnel, rules and DNS; for VLESS + REALITY servers, Xray behind sing-box carries the connection to the server. A system service keeps the kill switch and the DNS lock in the firewall. Rules split traffic by program, website and IP address, and provider subscriptions supply the servers.

**Young project:** one developer maintains it with AI coding agents, and it has few users yet. Please report what breaks in [Issues](https://github.com/eoftgge/rosetun/issues).

## Security {#security}

What counts as a vulnerability is on the [Security model](../security/) page; [SECURITY.md](https://github.com/eoftgge/rosetun/blob/master/SECURITY.md) explains private vulnerability reporting.
