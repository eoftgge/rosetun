# Isolated Two-VM Lab and Wire Observer

This document describes the isolated two-VM QEMU network topology, the `lab-smoke` qualification
command, the wire-level leak observer, and the lab VM image fixtures (`lab-v5` through `lab-v5o`).

For the suite catalog and CLI overview, see [../README.md](../README.md).

## Isolated two-VM wire topology

The controller connects a disposable `test` VM and a disposable `lab` VM (router + fixtures +
observer) over a single private `AF_UNIX/SOCK_STREAM` socketpair passed to QEMU via
`-netdev stream,id=labwire,addr.type=fd,addr.str=<fd>,server=off` (`virtio-net-pci`). No TAP,
bridge, user NAT, hostfwd, host route, or host network namespace is created; `-nodefaults -nic none`
blocks implicit NICs. Both VMs share one stand lease via `lab.LabPair`, each with its own run
directory, overlay, manifest, UUID, and completion proof.

```text
test VM (MAC 00:00:5e:00:53:61)             lab VM (MAC 00:00:5e:00:53:62, router + observer)
192.0.2.2/24           Ethernet             192.0.2.1/24  (+ 192.0.2.20 LAN_PEER in lab-v5n+)
2001:db8:6a:1::2/64  <------------->        2001:db8:6a:1::1/64
  (test-wire)          socketpair /           (lab-wire, AF_PACKET capture)
                       _WireRelay                      |
                                            rt-route: 203.0.113.1/24, 2001:db8:6a:2::1/64
                                                       | veth (inside disposable lab VM)
                                            rtlab namespace / rt-target:
                                              203.0.113.2/24, 2001:db8:6a:2::2/64
                                              HTTP :8080, HTTPS :443, UDP echo :9000,
                                              Authoritative DNS :53, Markers UDP :9100
                                              Resolver/DoH: 203.0.113.53 (:53 / :443)
                                              Routed/2nd node & B-hop (lab-v5n / lab-v5o)
```

- **Addressing:** strictly RFC 5737 (`192.0.2.0/24`, `203.0.113.0/24`, `198.51.100.0/24`) and
  RFC 3849 (`2001:db8:6a::/48`), plus narrow owner-approved private exceptions for LAN/Proxy tests
  (`10.254.254.1` in Linux L3, `192.168.77.2/24` in Linux Proxy, `10.255.255.1` in Windows LAN).
- **Reconnectable relay (`_WireRelay`):** framing-aware (`uint32` big-endian Ethernet frame length
  prefix) relay used when the `test` VM performs hard `power_cycle` restarts (Windows Lockdown),
  keeping the `lab` socket and `capture.pcap` continuously open without corrupting frames.
- **Nested virtualization note:** on KVM-in-Hyper-V (WSL2), set `vcpus = 2` under `[qemu]` in local
  lab configs (example files default to `1`) to prevent single-vCPU scheduling stalls during
  lock-step probe exchanges.

## `lab-smoke` and observer controls

`lab-smoke` qualifies the two-VM wire and observer without running Rosetun. It uses its own config
schema (`lab.v1` in [../lab.example.toml](../lab.example.toml) or `lab.v2` in
[../lab-tunnel.example.toml](../lab-tunnel.example.toml)).

```sh
python3 -B -m tools.vm.matrix lab-smoke --config /srv/lab.toml --dry-run
python3 -B -m tools.vm.matrix lab-smoke --config /srv/lab.toml
python3 -B -m tools.vm.matrix lab-smoke --config /srv/lab.toml --canary
python3 -B -m tools.vm.matrix lab-smoke --config /srv/lab.toml --tunnel --dns --evidence-disk
python3 -B -m tools.vm.matrix lab-smoke --config /srv/lab.toml --control extra-packet
```

- **Base probes (8 exchanges):** HTTP (`:8080`), UDP nonce echo (`:9000`), and authoritative DNS
  over UDP and TCP (`:53`, answering `<run>.<nonce>.lab.test`), each over IPv4 and routed IPv6,
  using fresh 96-bit nonces and 128-bit run IDs verified across client answer, target log, and pcap.
- **Flags:**
  - `--canary`: injects one unexpected UDP datagram (`:9999`) and one unexpected TCP SYN
    (`203.0.113.9`); exits 0 only when `leak == DETECTED`, `canary_flows == ["tcp", "udp"]`,
    `canary_other == 0`, and observer health is clean.
  - `--tunnel`: adds the lab VPN node (`sing-box`) and lab HTTPS target (`203.0.113.2:443`).
  - `--dns`: adds lab recursive/stub resolver and DoH target (`203.0.113.53`, requires `--tunnel`).
  - `--evidence-disk`: writes `capture.pcap` to a separate raw evidence disk attached to the lab VM
    (read back by the host after lab VM shutdown, removing the 128 KiB QGA file-read ceiling).
  - `--control {extra-packet,observer-stopped,observer-killed,link-down}`: headless observer
    controls that exit 0 only when the observer reports the exact expected `DETECTED` or
    `UNVERIFIED` refusal.
- **Base `lab-smoke` limits:** 60 s capture (up to 2700 s / 60 MiB on evidence disk for matrix
  suites), 2048-byte full frames (no silent truncation), 5 s socket timeouts (`REQUEST_TIMEOUT`,
  `RESPONSE_TIMEOUT`, `MARKER_TIMEOUT`), zero kernel `PACKET_STATISTICS` drops tolerated.

## Wire leak observer and classification

Capture runs via `AF_PACKET` on `lab-wire` inside the lab VM (outside the `test` VM; the lab VM
itself remains trusted). After the lab VM closes, the controller hashes and parses `capture.pcap`,
`targets.json`, and `health.json`.

### Phase windows and markers

Guest suites bracket protected phases with UDP datagrams to `203.0.113.2:9100` (`open` / `close`,
carrying run ID, fresh nonce, and window label), acknowledged by the lab observer. Closing markers
are sent only after firewall/protection teardown (`! table_present` on Linux, `protection: none` on
Windows), so a stuck firewall leaves the window unclosed (`UNVERIFIED`). The lab VM records its own
monotonic timestamps for capture start/end and marker handling; guest and lab clocks are never
compared.

### Frame categories and verdicts

Every parsed Ethernet frame gets exactly one category:

| Category | Meaning |
| --- | --- |
| `probe` | Expected `lab-smoke` probe exchange matching family, addresses, MACs, port, and nonce/answer payload. |
| `marker` | Run's opening or closing UDP `:9100` window marker (request or reply). |
| `tunnel` | Authorized traffic between the `test` VM and configured lab VPN node endpoints (including lab-to-test ICMPv4 Port Unreachable referencing an authorized UDP tunnel endpoint during outage tests). |
| `infrastructure` | Fixed allowlist (`INFRASTRUCTURE` in `lab_protocol.py`): ARP between `192.0.2.2` and `192.0.2.1` (broadcast/unicast zero-THA requests, replies, and RFC 1122 2.3.2.1 unicast neighbor polls from test to lab), ICMPv6 NS/NA between lab/link-local addresses, RS/RA, and MLD. |
| `allowed` | Frames matching narrow per-window `ALLOWANCES` declared by specific suites (e.g., `arp-announcement`, `arp-probe`, `ipv6-dad`, `ipv6-unspecified-rs`, `lan-peer-arp`, `lan-mdns`, `lan-ssdp`, `lan-broadcast`, `extra-address-arp`, `shared-proxy-peer`, `shared-proxy-server`, DHCPv4). Unknown allowance names raise `ValueError`. |
| `unexpected` | Any other frame to/from the `test` VM's MAC or IP (including any IPv4/IPv6 fragment involving the test VM). |
| `foreign` | Frame unrelated to the `test` VM's MAC/IPs; counted, never affects verdicts. |
| `unparsed` | Truncated or unreadable frame; forces `UNVERIFIED`. |

Window verdicts:

- `NONE`: zero `unexpected` frames, valid ordered open/close markers, clean observer health
  (`error: false`, `dropped: 0`, `finished: true`), complete parse.
- `EXPECTED`: observed direct flows match the suite's exact declared expectation for that window
  (e.g., a Direct rule or intentional no-kill-switch probe) and zero extra unexpected frames.
- `MISMATCH`: fewer direct flows than expected (contradicts a guest `PASS` claim).
- `DETECTED`: at least one unexpected frame (preserved regardless of observer health — a seen leak
  stays a leak).
- `UNVERIFIED`: missing/unclosed/out-of-order markers, observer error/drops, unparsed frames, or
  capture cutoff. Never promoted to `NONE`.
- `LISTED`: calibration/baseline windows recorded for inspection without judging background OS noise
  (used on Windows `baseline` / `recovery` / `rest`).

## Lab image progression and fixtures

The lab helper consists of `tools/vm/linux/guest/lab-entry.py` installed at
`/usr/local/libexec/rosetun-lab/entry` and `tools/vm/matrix/lab_protocol.py` beside it (root-owned,
non-writable by ordinary users; `/etc/rosetun-lab-role` set to `lab`, `systemd-networkd` and SSH
masked).

| Image | Key capabilities & fixtures | Used by |
| --- | --- | --- |
| `lab-v5` / `lab-v5m` | Base router + `rtlab` targets (HTTP `:8080`, HTTPS `:443`, UDP `:9000`, DNS `:53`, markers `:9100`), `sing-box` Shadowsocks node (`192.0.2.1:8388`), lab resolver + DoH (`203.0.113.53`), evidence disk capture, Linux L4 SSH poller (`192.0.2.1` -> `192.0.2.2:22`). | `lab-smoke`, `linux-l3`/`proxy`/`l5`/`l4`, `windows-lab-smoke`, `windows-list`, `windows-failure`, `windows-lockdown` |
| `lab-v5n` | Built on `lab-v5m` + lab CA cert (`rosetun-lab-ca.crt`). Adds opt-in `lan_fixtures`: peer IP `192.0.2.20` (`LAN_PEER`) with TCP listener (`:19080`), echo (`:19081`, 600 s long session), hold-open (`:19082`), and UDP mDNS/SSDP/broadcast listeners (`5353`/`1900`/`19083`); routed node `203.0.113.10`; `PRIVATE_BEHIND_ROUTER` (`10.255.255.1:80`); `sing-box` `lab-dns` (`203.0.113.53`). Adds controller-mediated `lab-action-requested` actions `probe_proxy` and `lan_state`. | `windows-proxy`, `windows-lan`, `windows-upgrade`, `windows-failure` |
| `lab-v5o` | Built on `lab-v5n`. Adds opt-in `extended_fixtures`: multi-protocol primary node on `192.0.2.1` (SS `8388`, Hysteria2 `8389/udp`, TUIC `8392/udp`, AnyTLS `8393/tcp` with pinned `proto-cert.pem`); second SS node (`192.0.2.1:8391` -> `203.0.113.10`); pinned Xray-core (`8390` VLESS+REALITY, `8394` VLESS+REALITY+XHTTP, local TLS 1.3 cover `127.0.0.1:8443`); `TwoHopProxy` B-hop on `203.0.113.20` / `2001:db8:6a:2::20` (`proxy-b.lab.test`: HTTP `3128`/`3129`, HTTPS `3130`/`3131`, SOCKS5 `1080`/`1081`) + LAN B-hop `192.0.2.10`; RFC 2131 `DhcpServer` on `lab-wire`; actions `fixture_state` and `fixture_control`; deduplicating `DnsLog(aggregate=True)`. | `windows-protocols`, `windows-twohop` |

### Controller-mediated lab actions (`lab-action-requested`)

Windows runners that need out-of-band lab probes or mid-run fixture toggles (Stages 10d and 10f)
write `state: "lab-action-requested"` with `action: {id, kind, ...}` into `status.json`. The host
controller dispatches the request to `lab-entry.py` over the lab VM's QGA channel and writes the
response back into `<ROOT>\lab-action-result.json` atomically (chunked via `write_reply_scripts`
when needed to stay below the 64 KiB QGA script ceiling). Long runs reserve explicit
`planned_session_rotations` QGA headroom so frequent action polling does not exhaust session
recovery budgets.
