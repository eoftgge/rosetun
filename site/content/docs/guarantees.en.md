+++
title = "Protection guarantees"
weight = 7

[extra]
overview = "Overview"
+++

What stays closed outside the tunnel at each moment:

- **open:** Rosetun closes nothing. While connected in TUN, programs' traffic still goes into the tunnel; nothing stops it from going around if the tunnel fails.
- **DNS closed:** system DNS cannot leave outside the tunnel; everything else is open.
- **closed:** nothing leaves outside the tunnel. In the proxy mode, nothing but the engine and loopback.
- **held:** closed, and it stays closed until you connect or run `rosetun open-network`.
- **\*** read from the code: no matrix scenario covers this cell. Every other cell has a scenario in [`tools/vm`](https://github.com/eoftgge/rosetun/blob/master/tools/README.md); a release's notes say which matrices were run for it.

"No protection" means the kill switch is off and the DNS lock is not in place: the firewall refused it, or the tunnel has no DNS of its own. On Windows sing-box closes port 53 outside the tunnel by itself while it runs, so system DNS can leave only while it restarts, or after the service stops. On Linux a program that picks the physical interface itself can also send DNS past the tunnel while connected.

## Windows {#windows}

| Event | No protection | DNS lock | Kill switch | Lockdown | Proxy | Proxy, kill switch |
|---|---|---|---|---|---|---|
| Disconnected | open | open | open | closed | open | open\* |
| Connected | open | DNS closed | closed | closed | open | closed |
| Engine restart | open | DNS closed | closed | closed\* | open\* | closed |
| Service crash | open\* | open | open | closed | open\* | open\* |
| Service stopped | open\* | open\* | open | closed | open\* | open\* |
| Update | open\* | open | held | closed | open\* | held\* |
| Restart of the computer | open\* | open\* | open\* | closed | open\* | open\* |

## Linux {#linux}

| Event | No protection | DNS lock | Kill switch | Lockdown | Proxy | Proxy, kill switch |
|---|---|---|---|---|---|---|
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
- on Linux, the window, the tray and the polkit prompt in an automated run: no matrix drives a desktop. GNOME was checked by hand; KDE Plasma was not, on Wayland or X11.

Lockdown protects against accidental leaks: the VPN drops, the service stops, the computer boots. It does not protect against malware you run yourself. The kill switch stays the main protection.
