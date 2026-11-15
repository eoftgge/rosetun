+++
title = "Rosetun"
description = 'Rosetun. VPN client. Subscriptions, rules and connection protection.'
template = "index.html"

[extra]
headline = 'Your traffic. Your rules.'
lead = 'VPN client for Windows and Linux: subscriptions, rules, kill switch and Lockdown.'
download_windows = 'Download for Windows'
download_linux = 'Download for Linux'
all_releases = 'All releases'
verify_download = 'Verify download'
features_eyebrow = 'MADE FOR YOUR ROUTINE'
features_title = 'One connection. More choice.'
note = 'Rosetun protects against accidental leaks, not malware running under your account. Without Lockdown, a service crash removes the block on Windows; on Linux the kill switch stays. Lockdown is experimental: third-party firewalls, antivirus software, hibernation and sleep on real hardware are untested. <a href="docs/privacy/">Network requests and protection model</a>'
screens_title = 'A look at the interface'
screens_lead = 'Explore the key features of Rosetun in one interface.'
lightbox_label = 'Screenshot preview'
lightbox_close = 'Close preview'

[[extra.features]]
title = 'Connection protection'
text = 'The kill switch blocks traffic when the tunnel drops and keeps the network closed through an update. Without it, a DNS lock keeps system DNS inside the tunnel. The window and rosetun status show what is in place and what is missing. Experimental Lockdown keeps traffic blocked without a connection and after a restart.'

[[extra.features]]
title = 'Your rules'
text = 'Send apps, websites and IP addresses through the VPN, connect directly or block them. Use GeoIP, GeoSite and your own lists. Undo a change with Ctrl+Z. Temporary rules last until you disconnect. Rules by app work on Windows and Linux. See the <a href="docs/rules/">Linux limitations</a>.'

[[extra.features]]
title = 'More than one exit'
text = 'Choose another country or server for an individual rule. If its exit server disappears, that traffic is blocked and never falls back to a direct connection.'

[[extra.features]]
title = 'Subscriptions at hand'
text = 'Add a subscription with a link, a QR code or a rosetun:// button on your provider’s site, or your own HTTP, HTTPS or SOCKS5 proxy. You can turn off device ID sharing for each subscription.'

[[extra.features]]
title = 'Connection choices'
text = 'VLESS, VMess, Trojan, Shadowsocks and Hysteria2. sing-box and Xray engines, REALITY and XHTTP, TLS fragmentation. See the provider page for transports and limitations.'

[[extra.features]]
title = 'Privacy without promises'
text = 'No telemetry. The app contacts your provider, servers, DNS, lists, GitHub and network check services. Connections stay in memory until you disconnect and are not written to disk.'

[[extra.features]]
title = 'TUN or system proxy'
text = '''TUN takes all of this computer's traffic. System proxy covers the programs that use it, for when TUN gets in the way, with a strict kill switch and access from your network if you want them.'''

[[extra.features]]
title = 'Your local network'
text = 'Reach a printer, a NAS or game streaming past the tunnel. On Windows only your own network opens, unless you also open private networks behind the router. On Linux every private range opens.'

[[extra.screens]]
image = 'main'
alt = 'Rosetun: Connection and protection'
caption = 'Connection and Protection'

[[extra.screens]]
image = 'traffic'
alt = 'Rosetun: Traffic and connections'
caption = 'Traffic and Connections'

[[extra.screens]]
image = 'rules'
alt = 'Rosetun: Routing rules'
caption = 'Routing Rules'

[[extra.screens]]
image = 'lists'
alt = 'Rosetun: Lists'
caption = 'Lists: SRS, Xray geosite and geoip'

[[extra.screens]]
image = 'exits'
alt = 'Rosetun: Exit nodes'
caption = 'Exit Nodes'

[[extra.screens]]
image = 'settings'
alt = 'Rosetun: Protection settings'
caption = 'Protection Settings'
+++

{%- set r = load_data(path="data/release.json", required=false) -%}
<p class="release-detail"><span>{% if r %}Version {{ r.version }}{% else %}Stable release. Files and checksums are on GitHub Releases.{% endif %}</span></p>
<p class="eyebrow">DOWNLOAD</p>

<h2>Verify the installer</h2>

The installer has no Windows code-signing certificate yet. Compare its SHA-256 with the line below and SHA256SUMS.txt from the release.

```
Get-FileHash .\{{ r?.installer or "rosetun-VERSION-setup.exe" }} -Algorithm SHA256
```

[SHA256SUMS.txt]({{ r?.checksum_url or "https://github.com/eoftgge/rosetun/releases/latest" }})

```
{{ r?.sha256_line or "SHA256SUMS.txt: checksum is listed in the release file" }}
```

For public tagged releases, the workflow creates an installer provenance attestation. Verify it with GitHub CLI. This verifies build provenance; it is not a Windows code signature.

```
gh attestation verify .\{{ r?.installer or "rosetun-VERSION-setup.exe" }} --repo eoftgge/rosetun
```

<p>The Debian package is in SHA256SUMS.txt and has an attestation too: <a href="docs/install/#debian-13">Debian 13</a>.</p>

<p><a href="help/">Installation and first launch</a></p>
