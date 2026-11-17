+++
title = "Documentation"
sort_by = "weight"
template = "docs.html"
page_template = "doc.html"

[extra]
toc_labels = { "history" = "History" }
+++

## New in 0.6 {#new-in-06}

- Back up settings before updating from 0.5. Rosetun 0.6 saves settings in format 9. [Update and rollback](../docs/install/#update)
- Share rules as a JSON file or through the clipboard, preview imports and check where an address or program goes. [Rules](../docs/rules/)
- Use a [two-hop exit](../docs/rules/#two-hop) for selected TCP traffic, send [subscription updates through VPN](../docs/subscriptions/#updates) and see a [warning about persistent routes around TUN](../docs/protection/#bypass-warning).
- Choose between a full request and a repeated request for delay measurements. [Everyday use](../docs/everyday/)
- On Linux, Local network covers the networks directly attached to your computer. File dialogs, reports, system checks and window restore are available. [Linux support](../docs/linux/)

## Documentation history {#history}

- [0.5.1 release notes](https://github.com/eoftgge/rosetun/releases/tag/v0.5.1)
- [0.4 reference (Windows)](https://github.com/eoftgge/rosetun/blob/v0.4.0/README.md)
