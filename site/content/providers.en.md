+++
title = "For providers"
description = "For providers. VPN client. Subscriptions, rules and connection protection."
template = "providers.html"

[extra]
eyebrow = "ROSETUN FOR YOUR USERS"
lead = "A regular subscription. One button to add it."
+++
{% <prose_section> %}
<h2>A button on your website</h2>

Format: `rosetun://add/<subscription URL>#name`. The HTTP(S) URL can be raw or percent-encoded as a whole. The optional name is percent-decoded and limited to 64 characters. The full link is limited to 8192 bytes.

```
<a href="rosetun://add/https%3A%2F%2Fprovider.example%2Fsubscription%2Fdemo#Example">Add to Rosetun</a>
```

Once Rosetun is installed, the system opens the link in the app: on Windows through the scheme the installer registers, on Linux through the package's `.desktop` handler (`x-scheme-handler/rosetun`). The experimental macOS build does not implement the `rosetun://` URL handler yet. A later start hands the link to a running Rosetun through a channel only the user's account can open, a named pipe on Windows and a socket in `$XDG_RUNTIME_DIR` on Linux. Users see an add dialog with the provider host. Fetching and adding start only after confirmation. An existing subscription opens its card; a link does not replace an open dialog.

Use HTTPS. An HTTP subscription sends its token without encryption. Escape ampersands as `&amp;` in raw HTML.
{% </prose_section> %}


{% <prose_section> %}
<h2>Formats and servers</h2>

One URI per line, plain or base64. Xray JSON: a configuration object or an array of configurations; each supplies the supported outbound tagged proxy, or the first supported outbound. sing-box JSON: an object with outbounds; service entries selector, urltest, direct, block and dns are skipped. WireGuard `.conf` files. This imports servers, not the entire routing configuration.

VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC v5, AnyTLS and WireGuard. TCP, WebSocket, gRPC, HTTPUpgrade; XHTTP (SplitHTTP) through Xray. Unencrypted transport, TLS and REALITY. Hysteria2 uses QUIC over UDP, with Salamander and port hopping. TUIC v5 uses QUIC over UDP (`tuic://`, sing-box JSON). AnyTLS uses TCP over TLS or REALITY (`anytls://`, sing-box JSON). WireGuard uses UDP (`wireguard://`, `wg://`, sing-box JSON, Xray JSON and `.conf` files, including Cloudflare WARP `reserved` bytes).

Unsupported: Clash YAML, encrypted Happ links, XHTTP with a separate download server, mKCP, QUIC transport for TCP protocols, HTTP/2, VLESS encryption, Shadowsocks plugins and other protocols (such as AmneziaWG). Unsupported nodes are skipped and named by protocol in the card’s import report. Import fails if no usable nodes remain. The subscription response is limited to 5 MiB after decompression.
{% </prose_section> %}


{% <prose_section> %}
<h2>Response headers</h2>

<table><thead><tr><th>Header</th><th>Handling</th></tr></thead><tbody><tr><th scope="row"><code>subscription-userinfo</code></th><td> upload and download: bytes; total: byte limit; expire: Unix time in seconds. Zero total and expire mean no limit or expiry. Usage and expiry appear on the subscription card. </td></tr><tr><th scope="row"><code>profile-title</code></th><td> Subscription title, up to 128 characters. Plain text or base64:…; used on import when the user has not supplied a name. </td></tr><tr><th scope="row"><code>content-disposition</code></th><td> Fallback title from filename or UTF-8 filename*. Up to 128 characters; profile-title takes precedence. </td></tr><tr><th scope="row"><code>profile-update-interval</code></th><td> Integer hours. Automatic updates clamp the interval to 1–168 hours; the default is 12 hours. Users can disable automatic updates. </td></tr><tr><th scope="row"><code>support-url / profile-web-page-url</code></th><td> Support and account links on the card. HTTP(S) only; text is limited to 2048 characters before URL validation. </td></tr><tr><th scope="row"><code>announce</code></th><td> Announcement on the subscription card: plain text or base64:…, up to 1000 characters. </td></tr><tr><th scope="row"><code>x-hwid-max-devices-reached / x-hwid-not-supported / x-hwid-limit</code></th><td> A case-insensitive true stops parsing with a device-limit error; announce accompanies the error. </td></tr></tbody></table>

Control and bidirectional formatting characters are removed from display text. Invalid metadata values are ignored. The same metadata is read from `# key: value` comments in URI lists. The `routing` header is not processed and does not install rules.
{% </prose_section> %}


{% <prose_section> %}
<h2>What your server receives</h2>

The default is `User-Agent: Rosetun/<version>`; users can override it. With “Send device ID” enabled, requests include `x-hwid`, `x-device-os`, `x-ver-os` and `x-device-model`. If device information cannot be obtained, the request proceeds without it.

Sharing is on by default and can be disabled per subscription, or with `--no-hwid` in the CLI. New subscriptions use an ID specific to the subscription server host: paths, tokens and ports do not change it. Different hosts receive different IDs. Subscriptions added before 0.4 retain their previous shared ID. OS version and model are limited to 64 printable ASCII characters; other characters become ?.

On Windows `x-device-os` is `Windows`, the ID comes from `MachineGuid`, the version from the registry and the model from the BIOS. On Linux `x-device-os` is `Linux`, the ID comes from `/etc/machine-id`, the version from `PRETTY_NAME` in `os-release` and the model from `/sys/class/dmi/id/product_name`. The model is `PC` when the system gives none. The system's identifier itself is never sent, only a hash of it. On macOS, device ID headers are not sent yet.
{% </prose_section> %}


{% <prose_section> %}
<h2>Test your subscription</h2>

1. Install the current release and open the add button.
2. Check the host, confirm the import and check servers, title, usage, expiry and card links.
3. Refresh the subscription. For errors, open the card and import report details.
4. Prepare a sanitized response and headers to reproduce the problem. Include the Rosetun version, expected behavior and error text. Do not send tokens, HWIDs, real addresses or keys.

[Report a problem](https://github.com/eoftgge/rosetun/issues) · [Collect a report](../help/)
{% </prose_section> %}

