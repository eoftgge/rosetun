# Rosetun — open problems

*Rule mode: Manually. This is a snapshot, not a standing truth — verified
against `origin/master` at `5db85e1` and the Hyper-V failure matrix (38/38).
Re-check anything here against the code before acting on it, and delete entries
as they are fixed.*

## Product

**First connect on a slow machine can still be slow.** On a laptop that never
had Rosetun it took about 3 s. In the test VM the Defender scan of a new
`sing-box.exe` took 6 to over 30 s; it now happens at install time (the
installer launches sing-box once) and at helper start, on a thread. The first
TUN creation still installs the Wintun driver inside the first connect, against
a 15 s readiness deadline. If a slow machine still fails, cache the version
check by path, size and mtime and measure the driver install.

**Without the kill switch, a stalled engine leaks silently.** sing-tun routes
the default route through a gateway, and Windows dead-gateway detection moves
traffic to the physical adapter when TCP through the TUN stops being answered.
With the kill switch this is blocked; without it, nothing reports it. Worth a
health signal in the client.

**DNS stops if the DoH connection dies silently.** sing-box 1.14.1 sends every
query over one HTTP/2 connection with no `ReadIdleTimeout` or `PingTimeout`
(`dns/transport/https_transport.go`). A connection that stops answering without
being closed — a NAT entry dropped during sleep, a network change that leaves
the old socket open — blocks all name resolution until the OS gives up on it.
The helper checks DNS only before `Connected`. Options: look for a fix in later
sing-box releases; a periodic DNS probe from the helper that reports a degraded
state; restarting the engine as a last resort. Seen once on a laptop after sleep: web pages stopped loading while Telegram,
which connects by IP, kept working. A second, short sleep did not reproduce
it; a long sleep with `Resolve-DnsName` against a request by IP is the next
check. A Wi-Fi switch recovered at once, as expected: the old sockets are
closed rather than left hanging. Likely fix once confirmed: the service
accepts power events and restarts the engine under protection on resume.

**Names resolved before connect stay in application caches.** Browsers and
other apps keep their own DNS caches, so answers obtained before connect — from
the ISP, or fake-ip addresses (198.18.0.0/15) from another VPN client — are
still used afterwards. The traffic still goes through the TUN, but to the wrong
address, and a site can fail until the app's cache expires. Options: flush the
system resolver cache on connect, and a hint in the client to restart the
browser.

## Correctness

- In console mode (the VM rig, development) the `shutdown` request is still
  honoured for any local account that can write to the pipe. The service
  refuses it.
- The engine is stopped by a kill only (`engine-singbox/src/lib.rs`, `stop`).
  In the matrix sing-box removed its adapter anyway, but that is sing-box
  behaviour, not a guarantee.

## To determine

- `DeviceDesc == "sing-tun Tunnel"` is not enforced in adapter validation.
  Confirm its stability for the pinned sing-box version before using it as an
  extra stale-adapter discriminator.
- Whether the `\\?\` binary path is why sing-box failed to create its own
  firewall rule. Irrelevant while the TUN stack is gVisor, but the same path is
  `argv[0]` for anything else that derives identity from it.
- Throughput and CPU cost of the gVisor stack against `system` on a real link.
- The default resolver. `8.8.8.8` / `dns.google` was intermittently dropped by
  DPI at the rig's exit, and the rig now uses Yandex. Whether the default should
  change, or the client should try a fallback list when the DNS check fails,
  depends on where users' nodes exit.
