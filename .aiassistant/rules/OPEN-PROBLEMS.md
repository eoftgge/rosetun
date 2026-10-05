---
apply: manually
---

# Rosetun — open problems

*Rule mode: Manually. This is a snapshot, not a standing truth — verified
against `origin/master` at `be13454` and the Hyper-V failure matrix (38/38).
Re-check anything here against the code before acting on it, and delete entries
as they are fixed.*

## Product

**First connect on a fresh system can time out.** The version check and the
first engine start wait for the Defender scan of a new `sing-box.exe` (6 to over
30 s in the test VM), and the first TUN creation installs the Wintun driver.
Against a 30 s version-check timeout and a 15 s readiness deadline the first
connect can fail while the retry succeeds. Options: run the version check once
at helper start or install time and cache the result by path, size and mtime;
let the installer launch sing-box once.

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
state; restarting the engine as a last resort. Not reproduced yet: the matrix's
adapter toggle gets the same address back within a second.

**Names resolved before connect stay in application caches.** Browsers and
other apps keep their own DNS caches, so answers obtained before connect — from
the ISP, or fake-ip addresses (198.18.0.0/15) from another VPN client — are
still used afterwards. The traffic still goes through the TUN, but to the wrong
address, and a site can fail until the app's cache expires. Options: flush the
system resolver cache on connect, and a hint in the client to restart the
browser.

## Correctness

- The `shutdown` request is honoured for any local account that can write to
  the pipe. Teardown is graceful, but anyone can stop the helper and with it
  the protection.
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
