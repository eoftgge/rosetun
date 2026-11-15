+++
title = "Links for providers"
weight = 14

[extra]
overview = "Links for providers"
+++

A button on a provider's page can open Rosetun with a subscription filled in: `rosetun://add/<subscription link>`, with the link raw (`rosetun://add/https://example.com/sub`) or percent-encoded (`rosetun://add/https%3A%2F%2Fexample.com%2Fsub`). An optional `#name` at the end suggests the subscription's name (`rosetun://add/https://example.com/sub#Example`). Rosetun only shows the **Add subscription** dialog with the link, its name and the provider's host; nothing is downloaded or added until you click **Add**. A link to a subscription you already have only brings it into view.

The Windows installer registers the scheme for all users. The Debian package registers it through its `.desktop` file (`x-scheme-handler/rosetun`). A running Rosetun takes the link from a later start through a channel only your account can open: a named pipe on Windows, a socket in `$XDG_RUNTIME_DIR` on Linux.

More for providers, with response headers: [the site's page](https://eoftgge.github.io/rosetun/en/providers/).
