+++
title = "Security model"
weight = 10

[extra]
group = "Protection and privacy"
+++

What Rosetun protects, what counts as a vulnerability and what does not. To report one privately, use [Security → Report a vulnerability](https://github.com/eoftgge/rosetun/security/advisories/new); [SECURITY.md](https://github.com/eoftgge/rosetun/blob/master/SECURITY.md) says which versions get fixes and how reports are handled. For how the protection works, see [How it works](../how-it-works/); for what stays closed at each moment, [Protection guarantees](../guarantees/).

## What to report {#what-to-report}

**On both systems:**

- **Traffic outside the tunnel:** a way around the kill switch, the DNS lock or Lockdown, including from another account on the same computer while connected. Name the moment and the mode, as in the table of [Protection guarantees](../guarantees/), where that cell says the network is closed.
- **Leaks:** subscription links, credentials, server addresses or visited sites in logs, in **Collect report**, in notifications or in the interface where they should be hidden.
- **Input from outside:** a `rosetun://` link that adds or downloads anything before you confirm it; a subscription or list that makes Rosetun write outside its folders or run anything; an update offer that points anywhere but this repository's releases; a program icon read from a network path.

**On Windows:**

- **The SYSTEM service and its named pipe:** a standard account controlling another account's tunnel, changing Lockdown without administrator rights, or a program posing as the service to the app or the `rosetun` command.
- **The installation:** ways for a standard account to change the installation folder or its ancestors, `data` or `data\engines`, and so replace or start a program the service runs.
- **The proxy mode's filters:** with **Access from the local network** on, a device outside this computer's own networks reaching the proxy, or the proxy reachable after the session ended.
- **The update's hold:** traffic leaving while the installer holds the network closed.

**On Linux:**

- **The service's socket and the group `rosetun`** (`/run/rosetun/helper.sock`, mode 0660): an account outside the group reaching the service, a member controlling another account's tunnel or changing Lockdown without root, or a program posing as the service, which the client checks runs as root.
- **polkit:** the action `io.github.eoftgge.rosetun.lockdown` running anything but `/usr/lib/rosetun/rosetun`, or running without an administrator's password; the rule for `rosetun-engine` giving more than the DNS settings of a link in systemd-resolved.
- **The account `rosetun-engine`:** an engine getting more than `CAP_NET_ADMIN`, `CAP_NET_RAW` and `CAP_NET_BIND_SERVICE`, another group, or a way into the service; the service running an engine from a file that is not root's. The exception is a session with an enabled rule by program: its sing-box also holds `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`, which is nearly root, so taking over that sing-box is taking over the computer (see [Programs on Linux](../rules/#programs-on-linux)). Those two reaching any other engine or session is a vulnerability.
- **The nftables table `inet rosetun`:** an account without root changing it, or a change the service does not notice or put back; a program outside the engines' cgroup getting the engines' permit, or outside the app's and the command's scopes getting theirs under Lockdown.
- **`/var/lib/rosetun`:** the folder, Lockdown's record or the lists readable or writable without root; a damaged record that leaves the network open.
- **The `.deb` package:** a maintainer script that opens the network during an upgrade, removes the way out before Lockdown is gone, or leaves a file others can write; an upgrade marker in `/run/rosetun` that an ordinary account can set.
- **`rosetun://` links through the socket** in `$XDG_RUNTIME_DIR`: another account delivering a link to your Rosetun, or the `.desktop` handler running anything but `rosetun-gui --open-url`.

A report should not contain subscription links, server links, credentials or unredacted logs: such links can contain passwords. **Collect report** (Settings → Service and log) removes them and is safe to attach.

## Out of scope {#out-of-scope}

- Malware already running under your account or as administrator. Lockdown stops accidental leaks, not a program you run yourself (see [How it works](../how-it-works/)).
- An administrator or root changing Rosetun, its service or its firewall rules.
- What your VPN server or subscription provider can see by design: the traffic the server carries, and your real IP address when Rosetun updates a subscription without a connection or uses an ordinary direct path with VPN updates switched off. See [Updates through VPN](../subscriptions/#updates).
- Bugs in sing-box, Xray or Wintun themselves: please report them to those projects. Do report to us when the way Rosetun runs them opens a hole. In 0.4 one such case was fixed: while connected, sing-box's own firewall permit let any account on the computer start Rosetun's `sing-box.exe` and get around the tunnel.

## A folder that was ever writable {#writable-folder}

Install-folder checks inspect current ownership and ACLs. They cannot detect access handles opened while a folder or file was writable in the past: changing its ACL does not revoke those handles. If an installation was ever writable by an untrusted account, do not execute its binaries or treat an in-place upgrade as a repair. Disable the affected service using trusted administrative tools before rebooting to clear old handles, then reinstall into a fresh protected folder.

To check that a download is the file Rosetun published, see [Verify the download](../install/#verify-the-download).
