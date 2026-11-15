+++
title = "Connection and protection"
weight = 2

[extra]
group = "Getting started"
overview = "Connection and protection"
+++

In Settings → Connection, Lockdown is nested under Kill switch. While Lockdown is on, the parent stays on and cannot be turned off: **On together with Lockdown**. The **Settings** link in the Protection card opens this section.

- A **Kill switch** blocks traffic when the tunnel drops. A **DNS lock** keeps system DNS from leaving outside the tunnel when the kill switch is off. It depends on the firewall: if it cannot be set, Rosetun still connects and says so.
- *Experimental:* **Lockdown** (Settings → Connection) closes the internet to everything outside the tunnel, also while disconnected, after a restart (from boot, before you sign in) and if the service stops or crashes. While it is on, the kill switch is always on. Incoming connections are blocked too, except from your network when **Local network** is on. Turning it on and off asks for confirmation and an administrator's rights: UAC on Windows, polkit on Linux. `rosetun lockdown` needs a terminal opened as administrator, or `sudo`. The way out is under [Troubleshooting](../troubleshooting/).
- **The protection in place** shows on the connection screen, in the tray tooltip and in `rosetun status`, which also says what is missing and whether it stays if the service crashes:
  ```
  protection: kill switch
  if the service crashes: this stays in place
  ```
- **The network stays closed through an update**, with the kill switch on, on both systems, and **after a service crash** on Linux only. See [Protection guarantees](../guarantees/).
- On Linux the service checks its firewall table every two seconds and puts it back if another program removed or changed it. `rosetun status` says when it did, or that it cannot.
- **Reconnect** in the tray menu or `rosetun reconnect` restarts the tunnel to the same server under the same protection.
- Change the server, rules or DNS while connected: Rosetun restarts the tunnel in a second or two without disconnecting, and the kill switch keeps traffic blocked meanwhile.
- **Reconnect automatically** after sleep, a network outage or an engine failure, with a DNS watchdog while connected.
