+++
title = "Rules"
weight = 5

[extra]
group = "Setup"
+++

- **Routing rules** for programs, websites, IP addresses and subnets, and lists, with **Quick templates** and actions **Through VPN**, **Direct** and **Block**.
- **Exits:** a rule can send its traffic through another country or a specific server while the rest goes through the server on the main screen. Picking a country or a server in the rule creates an exit on the **Exits** tab, where you can change its server and turn on a fallback to any server of the same country. If an exit's server disappears, its rules block traffic; they never go direct.
- **Lists:** GeoIP and GeoSite (Xray `.dat` files) and sing-box rule sets (`.srs`) and your own text lists, from a file or a link. A list from a link is downloaded again only when it has changed (`ETag` / `Last-Modified`).
- **Undo:** Ctrl+Z steps back through your changes on the Rules tab, **Revert** returns to the rules applied to the connection, and Del removes the selected rule without asking.
- **Temporary rules:** add a rule only until disconnect; it applies at once and is never saved.
- **Connections** on the Traffic tab: while connected, what your programs connect to right now, grouped by program, with the route each connection took and why (which rule, list or the default). Create a rule or close a connection from there. The list is kept only in memory for the account that connected and is cleared on disconnect; it is never written to disk or to the log.

## Check an address {#test}

On the Rules tab, type a site, an IP address or a program into **Check an address or program**. One line says where the set in use sends it: the route, and the rule, list or default behind it. Nothing connects and nothing goes over the network. Click the rule's number to find it in the table. The temporary rules of the running connection count.

Some answers are left open, and the line says so and shows what the rules say otherwise. A private address with **Local network** on depends on your network, which only the service knows. A program's name alone cannot meet a rule on a full path, and a site's name cannot meet a rule on an IP address. A list that cannot be read here, such as an uploaded `.srs`, leaves the answer open too.

CLI: `rosetun rules test <address|program>` prints the same line and exits with 0, also for an open answer. Input that is no site, IP address or program exits with 2.

## Programs on Linux {#programs-on-linux}

**Rules by program on Linux** have a price. To find a connection's program, sing-box reads the processes of every account, so a session with an enabled rule by program gives its engine `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`: nearly root for anything that takes the engine over. Without such a rule the engine has neither. Where the service cannot give them (outside its systemd unit, say), a connection with such a rule is refused with the reason.

A known sing-box error on Linux sometimes attributes a connection to the wrong program ([SagerNet/sing-box#4501](https://github.com/SagerNet/sing-box/issues/4501), open; Windows is not affected). So a **Direct** rule for a program can now and then let another program's connection past the tunnel, also with the kill switch on, because the kill switch lets the engine out. A connection whose program is not found matches no rule by program and goes by the rules after them. If this matters, use rules by site and IP instead, and keep **Through VPN** as the default with no **Direct** rule by program.

## Two-hop exits {#two-hop}

Experimental.

An exit can reach its server through another exit, so the traffic goes A → B. Both are proxy exits of the same connection.

1. Add servers A and B, then create their exits on the **Exits** tab.
2. Edit exit B. Set **Connect through** to exit A and save. The path reads **A → B**.
3. Point the rule you want at **B**. Use **Apply** for a running connection.

This changes only the traffic that the rule selects. It does not send all of the computer's traffic through B. In System proxy mode an application must use the local proxy; traffic that does not keeps its existing rules and protection settings.

**Directly** in B's editor restores the ordinary connection to B's server. It is not the rule destination **Direct**. **Cancel** discards the changes in the editor. A failed **Apply** restores the saved rules, DNS and exit paths; temporary rules stay. An exit that another exit connects through cannot be deleted: change the path of the dependent exit first.

Limits:

- Exactly two exits. An exit cannot connect through itself, and there are no cycles or third hops.
- B is an HTTP, HTTPS or SOCKS5 proxy, and its server is an IPv4 or IPv6 address, not a name. HTTPS still verifies the certificate; set the expected TLS server name where it is needed.
- A can be any server that sing-box can reach, including one that runs through Xray, such as VLESS with REALITY when Xray is set to **Automatically**. B through Xray and TLS fragmentation do not work for this path.
- Rosetun does not look up B's name itself, so B's address must be given as a number. The name of A is resolved by the usual rules. DNS for the sites you open follows your DNS settings, so this feature does not promise that all DNS goes through B.
- UDP, including QUIC, that a rule sends through B is blocked. It does not fall back to A or to a direct connection. Other rules keep their behaviour.
- A missing exit, an unreachable proxy, wrong credentials or a failed HTTPS handshake never switches to a shorter path. After a changed subscription, a country fallback or a different mode, the service checks the path again.
- B's delay measures the whole path A → B. The exit IP on the connection screen describes the main route, not B's public address.

**Connect through** appears when at least one other exit can be used. If TLS fragmentation is the only obstacle, the editor prompts you to turn it off. If an existing path becomes unavailable, you can choose **Directly**.

## Export and import {#exchange}

In Rules, select the desired set in the picker (Main), then open the three-dot menu beside it. Export all or selected rules of that set, or import rules. The selected set does not need to be active. Export the document to the clipboard or save it as a JSON file. Use the same menu to import from a file or the clipboard. On Linux, file dialogs use XDG Desktop Portal. If the dialog is unavailable, use the clipboard. In the preview, choose an existing destination set and Add or Replace, or choose New set, enter its name and click Import. The new set is created only on confirmation and is not activated automatically. Duplicates are skipped. The whole import, including the default rule and list references, can be undone with Ctrl+Z.

Import always shows a preview: destinations, duplicates, invalid rules, disabled rules and unavailable servers. The default rule stays unchanged unless you select its separate checkbox. Broad Direct rules carry a warning. A rules document cannot be imported through a `rosetun://` link.

List contents are never included. URL sources are included only after you confirm the displayed hosts; links can contain access keys. Without consent, list rules arrive disabled and require a list. File lists arrive disabled and require the named file. Import does not download a list.

Program names are translated between Windows and Linux: `firefox.exe` becomes `firefox`, with Linux case preserved. Paths from another system remain disabled. A server is matched by its exact name, subscription name and country. An absent or ambiguous match falls back to Through VPN with a warning.

The exchange format is independent of settings: `format: "rosetun-rules"`, `version: 1`, application version, source system, optional default target, rules and referenced lists. Internal rule/list/server IDs, server addresses, ports, keys, passwords, list contents, hashes and update times are omitted. List references use zero-based document indexes. Unknown document fields and unsupported versions are rejected; invalid individual rules are reported and skipped. Limits: 4 MiB and 10,000 rules or lists.

```
{
  "format": "rosetun-rules",
  "version": 1,
  "exported_by": "0.6.0",
  "system": "windows",
  "default_target": "proxy",
  "rules": [
    {"enabled": true, "matcher": {"domain": {"suffix": "example.com"}}, "target": "proxy"},
    {"enabled": true, "matcher": {"ip_cidr": "192.0.2.0/24"}, "target": "block"}
  ],
  "lists": []
}
```

CLI: `rosetun rules export [--selected-ids 1,2] [--with-list-urls] [FILE|-]`; `rosetun rules import [--replace] [--yes] FILE|-`. Export defaults to standard output. Import prints a preview and asks before saving; `--yes` approves the rules and keeps the existing default. A separate interactive question approves a default change. When reading a document from standard input, confirmation uses the terminal. Treat a document containing list links as a secret and review Direct rules before importing.
