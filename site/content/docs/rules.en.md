+++
title = "Rules"
weight = 4
+++

- **Routing rules** for programs, websites, IP addresses and subnets, and lists, with **Quick templates** and actions **Through VPN**, **Direct** and **Block**.
- **Exits:** a rule can send its traffic through another country or a specific server while the rest goes through the server on the main screen. Picking a country or a server in the rule creates an exit on the **Exits** tab, where you can change its server and turn on a fallback to any server of the same country. If an exit's server disappears, its rules block traffic; they never go direct.
- **Lists:** GeoIP and GeoSite (Xray `.dat` files, sing-box rule sets) and your own text lists, from a file or a link. A list from a link is downloaded again only when it has changed (`ETag` / `Last-Modified`).
- **Undo:** Ctrl+Z steps back through your changes on the Rules tab, **Revert** returns to the rules applied to the connection, and Del removes the selected rule without asking.
- **Temporary rules:** add a rule only until disconnect; it applies at once and is never saved.
- **Connections** on the Traffic tab: while connected, what your programs connect to right now, grouped by program, with the route each connection took and why (which rule, list or the default). Create a rule or close a connection from there. The list is kept only in memory for the account that connected and is cleared on disconnect; it is never written to disk or to the log.

## Programs on Linux {#programs-on-linux}

**Rules by program on Linux** have a price. To find a connection's program, sing-box reads the processes of every account, so a session with an enabled rule by program gives its engine `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`: nearly root for anything that takes the engine over. Without such a rule the engine has neither. Where the service cannot give them (outside its systemd unit, say), a connection with such a rule is refused with the reason.

A known sing-box error on Linux sometimes attributes a connection to the wrong program ([SagerNet/sing-box#4501](https://github.com/SagerNet/sing-box/issues/4501), open; Windows is not affected). So a **Direct** rule for a program can now and then let another program's connection past the tunnel, also with the kill switch on, because the kill switch lets the engine out. A connection whose program is not found matches no rule by program and goes by the rules after them. If this matters, use rules by site and IP instead, and keep **Through VPN** as the default with no **Direct** rule by program.

## Export and import {#exchange}

In Rules, select the desired set in the picker (Main), then open the three-dot menu beside it. Export all or selected rules of that set, or import rules. The selected set does not need to be active. Copy the document to the clipboard or save a JSON file on Windows. Linux currently supports the clipboard only. Import from the same menu. In the preview, choose an existing destination set and Add or Replace, or choose New set, enter its name and click Import. The new set is created only on confirmation and is not activated automatically. Duplicates are skipped. The whole import, including the default rule and list references, can be undone with Ctrl+Z.

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
