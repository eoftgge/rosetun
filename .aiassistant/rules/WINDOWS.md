---
apply: by file patterns
patterns: crates/rosetun-routing/**
---

# Rosetun — Windows routing and WFP

*Rule mode: By file patterns — `crates/rosetun-routing/**`.*

The routing layer does leak protection only. It never installs ordinary routes:
the engine owns the TUN and its routes.

## Invariants

**The kill switch is two phases inside one long-lived dynamic WFP session.**
Outbound protection must exist before the engine spawns, but the TUN LUID only
exists after the adapter is created. Never collapse this into one atomic
install, and never close the session between phases.

**Phase 1 blocks all outbound IPv4 and IPv6 before the engine spawns.** It
closes the leak window between spawn and tunnel readiness. All filters live at
`ALE_AUTH_CONNECT_V4/V6` in the Rosetun sublayer.

**Phase 1 permits the engine executable by application ID, to any
destination.** The engine enforces routing policy itself: besides the node
endpoint it makes direct connections for direct rules and LAN access. The app
ID comes from `FwpmGetAppIdFromFileName0` on the canonical binary path; the
`\\?\` form that `std::fs::canonicalize` returns is accepted.

**Phase 1 also permits loopback and DHCPv4, and nothing else unless the user
opts into LAN access.** With `allow_lan`, the private ranges (10/8, 172.16/12,
192.168/16, 169.254/16, fe80::/10, fc00::/7) are permitted, but DNS (TCP and
UDP 53) to those ranges is blocked at a higher weight, so a LAN resolver cannot
become a DNS leak.

**Phase 2 permits traffic on the validated TUN local-interface LUID.** It stops
a same-name stale or unrelated adapter from becoming a bypass.

**Weights, highest first: TUN permit 4, private DNS block 3, bootstrap permits
2, block-all 1.** The TUN permit must outrank the private DNS block: the TUN's
own DNS address (172.19.0.2) sits inside 172.16/12. Within one sublayer only the
highest-weight matching filter decides.

**Phase-2 authorization is idempotent and retried only on `TunnelNotReady`.**
Any other error is real and must fail the connect immediately.

**TUN discovery belongs to this layer, not to the engine abstraction.**
Keeps engine backends platform-neutral and makes the contract work for any
engine that creates a named TUN adapter. The LUID must not cross the crate's
public boundary.

**A discovered adapter must match alias, expected configured IPv4 and
operational `Up` state.** An alias alone can resolve to a stale adapter left by
a previous forced termination.

**The dynamic session stays owned by the routing guard until explicit
teardown.** Windows then removes the dynamic objects if the helper exits or
crashes, and dropping the session *is* the rollback.

## Rejected approaches

**Do not pin the endpoint address in the engine permit.** It was the first
design and was removed: an address-plus-app-ID permit blocks every connection
the engine legitimately makes elsewhere, such as direct rules and LAN, and ties
the engine to one resolved address. The engine is the policy enforcer.

**Do not install all filters atomically before engine spawn.**
The TUN LUID does not exist until the engine creates the adapter.

**Do not close the WFP session after phase 1.**
Dynamic WFP objects are deleted when their owning engine handle closes.

**Do not authorize a TUN by alias, interface index or an engine-reported
identifier alone; do not match an adapter by alias only.**
WFP local-interface filtering requires a LUID, and an alias can resolve to a
stale adapter.

**Do not open overlapping WFP sessions to stage a change.** The provider and
sublayer keys are fixed GUIDs and global in BFE, so a second session adding them
fails with `FWP_E_ALREADY_EXISTS`.

**Do not use a sing-box Clash API endpoint as discovery authority.**
It is not a reliable engine-neutral source of adapter lifecycle state.

**Do not use `RPC_C_AUTHN_NONE` when opening the WFP engine.**
On the tested system it fails with `ERROR_NOT_SUPPORTED` (50).

**Do not add Neighbor Solicitation or Advertisement conditions at
`ALE_AUTH_CONNECT_V6`, and do not allow all ICMPv6 to compensate.**
The ALE connect layer cannot match ICMP type under the attempted condition
model, and allow-all-ICMPv6 would open a direct IPv6 bypass. IPv6 ND is blocked
while protection is up. Narrowly scoped ND filters are only possible at a packet
layer, and must never be bought by widening ALE connect policy.

**Do not return references into a temporary `GetAdaptersAddresses` buffer.**
The buffer dies at function return.

**Do not make `RoutingBackend: Sync`.** It is always used through `&mut` behind
a mutex, and real backends hold OS handles that are Send but often not Sync.

## External constraints

Verified behaviour of things outside this codebase.

- `FWPM_CONDITION_IP_LOCAL_INTERFACE` consumes a LUID, not an adapter name or
  interface index. The alias is only an OS lookup key, usable once the adapter
  exists.
- WFP takes an IPv4 address in `FWP_UINT32` in **host order**
  (`u32::from_be_bytes(octets)` / `u32::from(addr)`); `FWP_BYTE_ARRAY16` holds
  IPv6 in network order; `SOCKADDR_IN.sin_addr.S_addr` is network order again.
  Check which API you are on before converting.
- A dynamic WFP session deletes its providers, sublayers and filters when its
  engine handle closes. This is deliberate fail-open recovery for a helper crash.
- `FwpmEngineOpen0` requires `RPC_C_AUTHN_WINNT` on the tested system.
- The Base Filtering Engine service must be running and the helper must be
  elevated for this backend to work at all.
- `GetAdaptersAddresses` can return `ERROR_BUFFER_OVERFLOW` again after the size
  query, because adapter creation and removal race enumeration. Keep it a
  retryable readiness condition, not a hard failure.
- `windows-sys 0.61.2` does not export `ConvertInterfaceAliasToLuidW`. Use
  `ConvertInterfaceAliasToLuid` with `NET_LUID_LH` and NDIS support.
- `NET_LUID_LH` in the generated bindings has no `Debug`, `PartialEq` or `Eq`.
  Treat `Value` as opaque except for comparison, diagnostics and passing to WFP.
- A connect blocked at `ALE_AUTH_CONNECT` fails immediately with `WSAEACCES`,
  which curl prints as "Bad access". An application seeing it under the kill
  switch is being protected, not broken; look for why its traffic did not take
  the TUN.
- sing-tun installs the TUN default route through a gateway (`172.19.0.2`, route
  metric 0, interface metric 0). If TCP through the TUN stops being answered,
  Windows dead-gateway detection moves default traffic to the physical adapter.
  Under the kill switch that surfaces as `WSAEACCES`; without it, traffic
  silently bypasses the tunnel. `Find-NetRoute` and the source address in curl's
  verbose output show which adapter was really used.
- With `strict_route`, sing-tun opens its own dynamic WFP session in a sublayer
  of weight 0xFFFF: a hard permit (`FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`) for
  sing-box's app ID, a TUN permit, a block of port 53 on other interfaces and,
  with an IPv4-only TUN, a block of all IPv6. A hard permit in a higher sublayer
  cannot be overridden from the Rosetun sublayer, so Rosetun cannot restrict the
  engine while it runs — it does not try to. These filters close with sing-box,
  which is why the matrix checks IPv6 in `FailedProtected`: only there are
  Rosetun's filters tested alone. WFP audit events show filters of both.

## Diagnosing a block

WFP audit tells which filter dropped a connection and from which local address.
Enable it by GUID, because subcategory names are localized:

```powershell
auditpol.exe /set /subcategory:'{0CCE9226-69AE-11D9-BED3-505054503030}' /failure:enable
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5157 } -MaxEvents 20
```

Read the event message rather than `Properties[n]`: newer Windows builds added
fields to event 5157, so positional indexes shift between versions.

## Deliberate oddities — do not "fix" these

`preflight()` opens its own throwaway dynamic session, adds the provider and
sublayer and drops it, which deletes them again. That is intentional: it is a
privilege and capability probe, and `begin_protection` re-creates both in its
own session.

No crash recovery journal. RAII plus the dynamic WFP lifetime is the whole
recovery story for now. A persistent journal would need separate decisions about
safe reconciliation, user network changes between crash and restart, storing
identifiers, and protecting machine-wide state.
