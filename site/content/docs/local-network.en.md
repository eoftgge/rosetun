+++
title = "Local network"
weight = 5

[extra]
overview = "Local network"
+++

**Local network** (Settings → Connection) lets programs reach devices on your network past the tunnel, also with the kill switch on: a printer, a NAS, a game console, USB over IP (such as VirtualHere) and game streaming (such as Sunshine and Moonlight). Off by default; turn it off on public networks. Your router's DNS is not used: names are looked up through the VPN.

**On Windows** it opens only the networks the computer's own adapters are connected to, each on its own adapter, plus link-local addresses (169.254.x.x). **Private networks behind the router**, off by default, also opens every private range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 and IPv6 fc00::/7) on any adapter.

**On Linux** it does the same, with the interfaces the system calls physical: a network card, or a bridge that carries the default route. The firewall (nftables) opens each connected network only on its own interface and link-local addresses on the physical ones; docker0, virbr0, tunnels and other software interfaces are not part of it. **Private networks behind the router** opens the private ranges on any interface, as on Windows. After a restart with Lockdown on, the computer's own network opens a few seconds after the service starts, when it has read it; private networks behind the router are open from the start.

On both systems a connected network wider than /16 is not opened, and the addresses of your VPN servers stay out of what is opened: a server in your own network is reached through the tunnel only. On Linux nothing has measured yet where a multicast datagram from a program that picks no interface goes; programs that send on each interface (mDNS, SSDP, most discovery libraries) are expected to work, as on Windows.

Notes:

- On Windows, finding devices (mDNS, LLMNR, SSDP, broadcasts) works for programs that send their search on each adapter, as Windows itself and most discovery libraries do, and for broadcasts to 255.255.255.255 from any program. Such a broadcast from a program that leaves the choice of adapter to Windows uses Windows' preferred adapter. If a virtual adapter (such as VirtualBox's) has the same or a better metric than the real one, Windows can pick it; give the virtual adapter a higher metric. With Local network off, such a broadcast goes into the tunnel.
- On Windows, multicast (mDNS, SSDP) from a program that leaves the choice of adapter to Windows goes into the tunnel and does not reach the local network. Rosetun cannot change that with routes.
- A connected network wider than /16 is not opened. When the computer moves to another network, Rosetun follows it within a few seconds with a short reconnect; the kill switch stays on meanwhile.
- Local IPv6 addresses stay closed while the tunnel carries IPv4 only. Reach local devices by their IPv4 addresses.
- A VPN server's own addresses stay out of what is opened, also for private networks behind the router, and a rule that sends such an address through the VPN still wins.
- A device in another subnet than this computer is not on your network: put both in one subnet or turn on Private networks behind the router. To see which way a Linux system sends traffic to a device, run `ip route get 192.0.2.10` with the device's address; the line must name your Ethernet or Wi-Fi interface, not `rosetun0`. On Windows, run in PowerShell (with the device's address):
  ```
  Find-NetRoute -RemoteIPAddress 192.0.2.10
  ```
  `InterfaceAlias` must be your Ethernet or Wi-Fi adapter, not `rosetun0`, and `IPAddress` this computer's address on that network.

With **Lockdown** on, the same networks are open while disconnected too, and devices on them can connect to this computer. `rosetun lockdown on --lan private` turns Lockdown on with private networks behind the router. `--lan` also saves the choice in the settings of whoever runs the command, so that account's next connect keeps it.
