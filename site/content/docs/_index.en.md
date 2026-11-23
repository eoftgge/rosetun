+++
title = "Documentation"
sort_by = "weight"
template = "docs.html"
page_template = "doc.html"

[extra]
toc_labels = { "history" = "History" }
+++

## New in 0.7 {#new-in-07}

- Back up settings before updating from 0.6. Rosetun 0.7 saves settings in format 13 and keeps `config.v9.json` (or `config.v12.json` from 0.7.0-beta.1) beside it. [Update and rollback](../docs/install/#update)
- Editable [rule groups and the Templates catalog](../docs/rules/#groups), plus search and [address check](../docs/rules/#test) combined in one field.
- Added TUIC v5, AnyTLS and WireGuard support (including `.conf` files and Cloudflare WARP `reserved` bytes), Xray balancers (`routing.balancers`, `observatory` / `burstObservatory`), TCP `finalmask` (`header-custom`), a subscription User-Agent selector and automatic Xray routing for all VLESS nodes, with skipped unsupported protocols named in subscription import reports. [Subscriptions and servers](../docs/subscriptions/)
- `SHA256SUMS.txt` is signed with the release key, and Windows builds can [download and verify updates](../docs/install/#windows) in the app. Added Black and White themes, country flags or two-letter codes and bundled Noto Color Emoji. [Everyday use](../docs/everyday/)
- Experimental [macOS (Apple Silicon)](../docs/macos/) `.pkg` build for macOS 14+ (without kill switch or Lockdown).

## Documentation history {#history}

- [0.6.0 release notes](https://github.com/eoftgge/rosetun/releases/tag/v0.6.0)
- [0.5.1 release notes](https://github.com/eoftgge/rosetun/releases/tag/v0.5.1)
- [0.4 reference (Windows)](https://github.com/eoftgge/rosetun/blob/v0.4.0/README.md)
