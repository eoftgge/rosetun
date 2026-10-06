---
apply: by file patterns
patterns: crates/rosetun-engine*/**
---

# Rosetun — engine backends

*Rule mode: By file patterns — `crates/rosetun-engine*/**`.*

An engine backend renders a configuration, locates a binary and spawns a
process. It does not touch routing, firewalls or any privileged API: the helper
owns all of that.

## Invariants

**The engine owns the TUN and all ordinary routes.** sing-box runs with
`auto_route`; Rosetun never installs the same routes, and the routing plan
deliberately carries no TUN or default-route fields. Two owners of the routing
table fight.

**Capabilities must not lie.** `EngineCapabilities` declares what the engine can
express, `render()` returns the enabled rules it cannot represent, and the
helper rejects the connect before spawn. A backend claiming a capability it does
not implement turns the guarantee into a trap — worse than having no check at
all. A stub backend claims nothing.

**`EngineBackend: Send + Sync`.** Its methods take `&self` and the registry
hands out `&dyn`, so Sync is needed on the merits. This is the opposite of the
routing backend, which is `Send` only.

**Nothing platform-specific crosses this boundary.** No LUIDs, no WFP types, no
Windows handles in engine-facing traits. Interface identity is discovered by the
platform routing layer from the name the engine was configured with.

**Unsupported rules are reported by identity, not by count.** The caller has to
be able to name the rules it is refusing.

## sing-box configuration contract

The supported version is pinned (`SUPPORTED_SING_BOX_VERSION`, currently
1.14.1) and checked with `sing-box version` before every spawn.

**Verify every configuration field against the documentation of the pinned tag,
not against memory or a newer version.** sing-box rejects unknown fields with a
FATAL at startup, and fields move between releases: the legacy DNS server format
was removed in 1.14.0, and `log.disable_color` is not a configuration field at
all. Colours are turned off with the `--disable-color` command-line flag.

**The TUN inbound uses `"stack": "gvisor"`.** The `system` stack (and `mixed`,
which uses `system` for TCP) hands every TUN connection back through the Windows
network stack to a listening socket inside sing-box. That is an inbound
connection to `sing-box.exe`, so it depends on Windows Firewall allowing it.
sing-box tries to add that rule itself and ignores failure; in a clean Windows
the rule was never created, all TCP through the tunnel was silently dropped
while DNS (UDP, already in gVisor) kept working. gVisor keeps TCP inside the
process and does not depend on firewall state or group policy.

**`strict_route` stays on together with `auto_route`.** In sing-tun 0.9.3
(`tun_windows.go`, used by sing-box 1.14.1) strict route opens its own dynamic
WFP session: a hard permit for sing-box, a permit for the TUN, a block of port 53
on every other interface and, when the TUN has no IPv6 address, a block of all
IPv6 connects. That last filter keeps IPv6 from bypassing an IPv4-only TUN when
the kill switch is off. Giving the TUN an IPv6 address removes it and sends IPv6
into the tunnel instead, which only helps when nodes have IPv6 at their exit.
These filters die with the sing-box process; after an engine crash only the
Rosetun kill switch holds.

**DNS goes through the proxy as DoH (`"type": "https"`), not DoT.** In 1.14.1
the DoT transport opens a separate TLS connection per query until it has probed
that the server allows reuse (`dns/transport/multiplexer.go`, `dispatch` →
`exchangeSingle`). Windows fires a burst of queries the moment the tunnel comes
up, and those parallel handshakes through the node stalled name resolution for
10–20 s after Connected. DoH runs on HTTP/2 and multiplexes every query over one
connection from the first request. Port 443 is also harder to block than 853.
Do not switch to plain UDP DNS through the proxy: many Shadowsocks nodes do not
relay UDP.

**The resolver must be reachable from the node's exit, not from the client.**
It comes from `Settings.dns` (IP literal, server name, optional port and path;
default `8.8.8.8` / `dns.google`) and is rendered with `tls.server_name`, so
resolving the resolver needs no DNS. A resolver blocked at the exit gives a
tunnel that connects but resolves nothing, with no error in the log: Shadowsocks
does not propagate upstream connection failures, it just leaves the connection
silent. The helper's DNS check before `Connected` turns that into a failed
connect with a reason.

**The node address is an IP literal by the time it reaches the config.** The
helper resolves the server before the kill switch goes up and substitutes the
address, keeping the original name as SNI or Host where the transport needs
one. A domain server address would need `domain_resolver`, which would need DNS
that only works through the tunnel being built.

**Route rules start with `sniff`, then `hijack-dns`.** Domain rules cannot match
without sniffing, and DNS packets must be hijacked before user rules can send
them anywhere. `route.auto_detect_interface` stays on, or the engine's own
outbound connections loop into its TUN.

**`process_name` ignores letter case on Windows.** Checked by hand with 1.14.1:
a `CURL.EXE → direct` rule matched `curl.exe` exactly as `curl.exe → direct`
did. So on Windows two process-name rules that differ only in case are the same
rule. `process_path` was not checked; until it is, treat it as case-sensitive.
Domain rules are stored in lower case by the core, because domains are
case-insensitive and sing-box domain matching has not been checked either.

## Process lifecycle

Readiness is the INFO line `sing-box started (<seconds>s)` on stderr, followed
by the helper's phase-2 validation of the adapter. That makes two things
load-bearing: the log level must never be set above `info`, and logs must not be
redirected to a file with `log.output`, because readiness reads stderr.

The version check and the first spawn of a newly installed binary wait for the
Defender scan of that file. In the test VM that took 6–15 s when the guest was
idle and over 30 s when it was busy right after a checkpoint restore. That is
why the version check timeout is 30 s. The helper therefore runs the check
once on a thread at start, and the installer launches sing-box once, so the
scan does not land on the user's first connect.

Piped stdout and stderr must be drained. An undrained pipe fills, and the engine
then blocks on its next log write — the tunnel freezes with no error anywhere.
Anything that runs on the drain thread must therefore never panic.

The helper logs each engine line at the level the engine gave it, under the
`engine_output` target (`rosetun_engine::ENGINE_OUTPUT_TARGET`). The helper's
default filter passes that target at every level, because `Settings::log_level`
already limits what the engine writes. A custom `ROSETUN_LOG` replaces the whole
filter, so add `engine_output=trace` to it to keep TRACE lines.

The helper's process-lifetime job kills the engine with the helper. In the VM
failure matrix sing-box 1.14.1 removed its Wintun adapter in every tested exit
path, including a forced kill of the helper.

## Traffic statistics

**The Clash API serves statistics only, on loopback, with a fresh secret per
engine start.** `ControlEndpoint::local()` picks a free port on `127.0.0.1` and a
256-bit secret; `render` adds `experimental.clash_api` only when the helper
passes one. The secret lives in the helper's memory and in the run-directory
config (SYSTEM and Administrators only). `ControlEndpoint` and the probe redact
it in `Debug`, and it never reaches a log. Picking the port and binding it are
not atomic: if another process takes the port first, sing-box fails to start
and the connect fails as an ordinary engine error.

**Traffic comes from the totals in `GET /connections`.** The helper polls once
a second and derives rates from two samples; a smaller total reads as zero. The
probe's `ureq` agent has `proxy(None)`, so proxy settings from the environment
never redirect the local request. Only `uploadTotal` and `downloadTotal` are
parsed. The connection list carries the user's destinations, so neither it nor
a `serde_json` message about it is ever logged. The totals count every
connection the engine routes, direct rules included, not only proxied traffic.

**Statistics never affect the tunnel.** Failures zero the rates, keep the
totals and never change the connection state. A monitor that cannot start is
logged and skipped; the connect still succeeds. The monitor thread takes only
the status mutex, never the session mutex. `stop_engine` stops it, waiting at
most the 1 s request timeout plus 100 ms, and zeroes the traffic. An engine that
exits on its own leaves the monitor polling errors until the next connect or
disconnect.

## Rejected approaches

**The `system` and `mixed` TUN stacks** — see the configuration contract above.

**DoT and UDP DNS through the proxy** — see the configuration contract above.

**Xray is not in the near-term engine set.** Its TUN integration is weaker, it
has no equivalent native process-aware rules and no equivalent auto-route or DNS
hijack model. Supporting it would require a separate pipeline — own routing plus
tun2socks, or reduced capabilities, or dropping process rules. mihomo is the
second engine because it fits the existing backend trait unchanged.
The Xray crate may stay in the workspace as a stub, but must not be registered
in the helper, offered as an available engine, extended, or given dependencies.

**Own TUN, `tun-rs`, tun2socks and an own data plane are deferred.** The
engine-owned architecture keeps native process rules and a mature networking
implementation. Revisit only against a concrete requirement that native engine
TUN cannot meet. No own process classifier while this holds — process rules stay
inside backend capabilities.

**A sing-box Clash API endpoint is not a shutdown or discovery authority.** It
has no quit endpoint, and it is not engine-neutral.

**No raw configuration escape hatch.** The neutral rule model plus the
unsupported list covers the current problem more safely. Add one only against a
real need.

## External constraints

On Windows a child process is not killed when its parent exits, and a GUI-less
child has no console signal to receive. Without a working graceful stop the only
option is a forced kill.

## When adding the mihomo backend

Write it against the stabilised contract — ownership mode, lifecycle, readiness,
capabilities, error mapping — not alongside changes to it. Pin a minimum version
and confirm native TUN, auto-route, the strict-route equivalent, process rules,
DNS behaviour, protocol mappings, Reality/uTLS, traffic API and graceful
shutdown or reload before relying on any of them. Check its TUN stack and DNS
transport against the same two failure modes described above.

Choose the YAML serializer against the dependency checklist rather than reaching
for `serde_yaml` by reflex. A hand-written emitter is acceptable only for a
strictly bounded configuration and only if no maintained serializer qualifies.

Test both backends from one neutral fixture covering every matcher, all three
targets, a disabled rule and the default target; compare the rendered output,
the unsupported list, rule order and semantics.
