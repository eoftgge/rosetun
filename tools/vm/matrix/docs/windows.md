# Windows Suites, Launch Profile, and Artifact Contracts

This document covers the Windows QEMU launch profile, Windows infrastructure smokes (Stages 9b–9d),
the eight autonomous Windows lab matrices (Stages 10a–10f), and the structured Hyper-V artifact
contracts for List and Proxy.

For the suite catalog and CLI overview, see [../README.md](../README.md). For Hyper-V host runners,
see [../../windows/README.md](../../windows/README.md). For building the base Windows image, see
[../../windows-image/README.md](../../windows-image/README.md).

> **Diagnostic status:** Windows base images carry `qualified: false` and `activated: false`. Every
> Windows run records `release_gate: false` and `security_invariants: "UNVERIFIED"`. Release
> acceptance and Hyper-V parity decisions belong strictly to the owner (see
> [evidence.md](evidence.md)).

## Windows launch profile and smokes

### Launch profile (`windows-uefi-q35-v1`, Stage 9b)

Windows runs use `WindowsQemuConfig` and `images.WindowsImageDescriptor` (schema
`rosetun.matrix.image.v1`, `guest_os: "windows"`, profile `windows-uefi-q35-v1`):

- **Machine and devices:** `-machine q35,smm=off` (or `smm=on` per descriptor),
  `-global ICH9-LPC.disable_s3=1`, `-rtc base=utc`, descriptor CPU string with Hyper-V
  enlightenments (`hv-vpindex`, `hv-synic`, `hv-stimer`), virtio-blk disk overlay, virtio-net at
  the fixed PCI slot with MAC `00:00:5e:00:53:61` (`test-wire`), `tpm-crb`, VGA (`-display none`,
  used for `screendump`), and virtio-serial `org.qemu.guest_agent.0`.
- **Per-run state copies:** `prepare` copies `OVMF_VARS.fd` and every TPM state file into the run
  directory, verifying SHA-256 against the descriptor before and after copy. Base image files are
  never mutated and are re-verified after shutdown (`image-unchanged`) using the cross-process
  digest cache ([controller.md](controller.md#image-descriptors-and-disk-digest-cache)).
- **`swtpm` lifecycle:** `swtpm socket --tpm2 --terminate` starts before QEMU with `mode=0600` on
  `swtpm.sock`, is registered in `manifest.json` (`id: "swtpm"`), and is reaped after QEMU exits.
  `completion_verified` requires confirmed exit of both `swtpm` and `qemu`.

### Windows QGA conventions (Stage 9c)

`qga.Qga(guest_os='windows')` differs from Linux QGA in four ways:

- **Boot identity:** read immediately via `reg.exe query ...\PrefetchParameters /v BootId` as
  `win-<N>` (avoids cold PowerShell timeouts on fresh boots) and cross-checked with
  `Win32_OperatingSystem.LastBootUpTime`.
- **No shell:** `guest-exec` uses full Windows paths (`C:\Windows\System32\...`) with
  `capture-output: separated` (64 KiB cap per stream).
- **PowerShell 5.1 + UTF-8:** commands run via `powershell.exe -NoProfile -NonInteractive
  -ExecutionPolicy Bypass -EncodedCommand` writing raw UTF-8 stdout/stderr (independent of console
  code page or locale).
- **Post-wait liveness (`Vm.ready_guest`):** after long idle waits (`settle_seconds`,
  `rest_seconds`), the controller sends `guest-ping` and transparently opens a fresh QGA session
  (`recover_guest`) if the idle session died before sending any one-shot window marker.

### Infrastructure smokes (`9b`–`9d`)

| Suite | Schema / Example | What it verifies |
| --- | --- | --- |
| `windows-boot-smoke` | `execution.windows.v1` / [execution-windows-boot-smoke.example.toml](../execution-windows-boot-smoke.example.toml) | Single-VM boot (`-nic none`), `swtpm` + UEFI + QMP watch, `screendump.png`, ACPI power-button shutdown, `image-unchanged`. |
| `windows-reboot-smoke` | `execution.windows.v1` / [execution-windows-reboot-smoke.example.toml](../execution-windows-reboot-smoke.example.toml) | Single-VM Windows QGA (`reg.exe` `BootId`, UTF-8 round-trip), 1 planned restart, `boot_chain` verification (`win-N` -> `win-(N+1)`). |
| `windows-lab-smoke` | `execution.windows.v2` / [execution-windows-lab-smoke.example.toml](../execution-windows-lab-smoke.example.toml) | Two-VM lab wire (requires 4096 + 2048 + 768 MiB free RAM), static network (`192.0.2.2/24`, `2001:db8:6a:1::2/64`, DNS `203.0.113.53`), lab CA install, `settle_seconds` (60 s), 10 exchanges in judged window `probes` (`NONE`), plus 600 s informational `rest` window (`windows-noise-report`). |

## Shared autonomous Windows lab runner contract

All eight Windows lab matrices (Stages 10a–10f) share one controller and guest architecture:

- **Read-only ISO delivery (`windows_media`):** builds an ISO 9660 level-3/Joliet disc via
  `xorriso` carrying pinned `rosetun.exe`, `rosetun-helper-privileged.exe`, pinned `sing-box.exe`
  (1.14.3, SHA-256 verified), optional `desktop_proxy.exe` / `xray.exe` / Inno Setup installers,
  guest runner scripts, and the plan JSON. Attached read-only as `ide-cd` (`bus=ide.2`); hashes are
  checked on the controller before launch and re-checked by the guest starter after copy.
- **Autonomous scheduled-task runner:** the controller boots the lab + test VMs, configures static
  lab networking and the lab CA, waits `settle_seconds` (default 60 s), starts the guest runner as a
  SYSTEM scheduled task, and polls only `<ROOT>\status.json` (plus `lab-action-requested` dispatches
  when used). Guest runner scripts stay under the 65,536-byte QGA ceiling and are verified by
  `tools/vm/windows/tests/Test-RosetunScriptArguments.ps1`.
- **Wire bracketing and calibration:** every matrix brackets `baseline` and `recovery` calibration
  windows (proving direct IPv4 HTTPS `203.0.113.2:443`, IPv6 HTTP `[2001:db8:6a:2::2]:8080`, and
  UDP/TCP DNS `203.0.113.53:53` work outside protection; missing calibration marks the run
  `unverified`, exit 2) and strictly judges protected session windows with zero name-based noise
  tolerance.
- **Post-cleanup `_AFTER` audit:** after guest cleanup, the controller independently inspects the
  guest for lingering services, tasks, processes (`sing-box.exe`, `xray.exe`, `desktop_proxy.exe`,
  helper), TUN adapter, binaries, temp users, extra IP addresses, and active WFP state (`netsh wfp
  show state`, checking Rosetun session provider `51a47ec7-6459-4b84-8854-075e1576e7f9`, sublayer
  `0c035ef5-4c5c-4583-ad9c-179791360f5e`, and Lockdown provider/sublayer where applicable). Any
  leftover raises `cleanup-left:...` (exit 1).
- **Exit codes:** `0` all checks `PASS`, judged windows `EXPECTED`/`NONE`, wire cross-checks agree,
  fixtures answered, cleanup `PASS` with `left: []`, both VMs `completion_verified`; `1` behavioral
  finding (`findings`); `2` unverified/infrastructure error (`unverified`); `130` interrupted.
  Windows lab suites are not attachable (`recover --close` if interrupted) and `report` refuses them
  without independent wire evidence.

## Windows lab matrices (Stages 10a–10f)

### Stage 10a: Windows List (`windows-list`)

- **Command / config:** `run windows-list`, `execution.windows.v3`,
  [execution-windows-list.example.toml](../execution-windows-list.example.toml), summary
  `rosetun.matrix.windows-list-summary.v1`.
- **Catalog / runner:** `tools/vm/windows/list-checks.json` (11 checks, same IDs as Hyper-V
  `Invoke-ListMatrix.ps1`), `guest/run-windows-list.ps1`, lab image `lab-v5m`.
- **Windows:** `baseline` (listed + confirms direct HTTPS/DNS) and `session` (judged `EXPECTED`:
  tunnel frames + exactly 1 direct TCP flow for `binary.direct`, zero extra unexpected frames).
  Artifacts are also assessed through the `windows_list` adapter.

### Stage 10b: Windows Failure Core (`windows-failure`)

- **Command / config:** `run windows-failure`, `execution.windows.v4`,
  [execution-windows-failure.example.toml](../execution-windows-failure.example.toml), summary
  `rosetun.matrix.windows-failure-summary.v1`.
- **Catalog / runner:** slices of `tools/vm/windows/failure-core.tsv`, `guest/run-windows-failure.ps1`
  + `failure-probes.ps1`, lab image `lab-v5m` / `lab-v5n`.
- **Cases (7, one per run via `[failure].case`):**
  - `engine-killed` (17 checks), `helper-killed` (12), `no-network` (15), `apply-rules` (14),
    `reconnect` (16), `temporary` (18), `dns-lock` (12).
- **Windows:** `baseline`, `session`, `recovery`. All cases except `temporary` expect zero direct
  flows (`NONE`) in `session`; `temporary` expects exactly 1 direct TCP flow (`203.0.113.2:443`).
- **Scope note:** `rosetun probe` checks (`*.server-check-*`) are omitted in the offline lab and
  recorded explicitly in plan `limitations`.

### Stage 10c: Windows Lockdown (`windows-lockdown`)

- **Command / config:** `run windows-lockdown`, `execution.windows.v5`,
  [execution-windows-lockdown.example.toml](../execution-windows-lockdown.example.toml).
- **Catalog / runner:** `tools/vm/windows/lockdown-core.tsv` (72 checks, Scenarios 1–2 and 4–10),
  `guest/run-windows-lockdown.ps1`, lab image `lab-v5m`.
- **Cases (`[lockdown].case`):**
  - `core` (57 checks, 1 boot, `power_cut_repeats = 0`, 3 windows: `baseline`, `lockdown-core`, `recovery`)
  - `reboot` (18–24 checks, `2 + 2 * repeats` boots, 3 windows: `baseline`, `reboot-lockdown`, `recovery`)
  - `full` (72 checks, canonical `power_cut_repeats = 3`, `power_cut_delay_seconds = 2` -> **8
    distinct boots**: 1 initial + 1 clean reboot + 6 hard `power_cycle` cuts; 4 windows)
- **Windows & invariants:** `lockdown-core` expects 1 direct TCP flow (`on.cli-path-egress-open`) +
  tunnel traffic; `reboot-lockdown` expects zero direct flows (`NONE`) with narrow RFC 4862/5227
  `REBOOT_ALLOWANCES` (`ipv6-dad`, `arp-probe`, `arp-announcement`). `boot_chain` must hold all
  expected `win-*` IDs. `_AFTER` verifies absence of Lockdown WFP provider/sublayer, `Rosetun`
  service, resume/boot tasks, and `RosetunMatrixUser`.

### Stage 10d: Windows Proxy (`windows-proxy`) and Local Network (`windows-lan`)

Both suites require lab image `lab-v5n` (`lan_fixtures = true` + `lab-action-requested` protocol).

- **`windows-proxy`:**
  - Config: `execution.windows.v6`,
    [execution-windows-proxy.example.toml](../execution-windows-proxy.example.toml) (adds pinned
    `desktop_proxy.exe`).
  - Catalog / runner: `tools/vm/windows/proxy-checks.json` (46 checks: strict proxy, auth, rules,
    WinINet apply/restore/crash-restore under `RosetunProxyUser`, LAN sharing, Lockdown + sharing),
    `guest/run-windows-proxy.ps1`.
  - Windows (5): `baseline`, `recovery`, plus judged `strict` (`NONE`), `sharing-strict` (`NONE` +
    allowances `lan-peer-arp`, `shared-proxy-peer`, `shared-proxy-server`), and `lockdown` (`NONE` +
    `lan-peer-arp`, `shared-proxy-peer`). `_AFTER` checks Lockdown WFP, `RosetunProxyUser`, and
    `desktop_proxy.exe`.
- **`windows-lan`:**
  - Config: `execution.windows.v7`,
    [execution-windows-lan.example.toml](../execution-windows-lan.example.toml) (`long_session_seconds`
    in `10..900`, canonical `600`).
  - Catalog / runner: `tools/vm/windows/lan-core.tsv` (72 checks: `allow_lan` on/off, peer TCP,
    mDNS/SSDP/limited broadcast, 600 s peer echo session, live IPv4 add/remove `198.51.100.10/26`,
    explicit LAN rules, `allow_private_behind_router` to `10.255.255.1:80`, refused live `apply`,
    in-network VPN server exclusion on `192.0.2.1`, `lan-reopen`), `guest/run-windows-lan.ps1`.
  - Windows (11): `baseline`, `recovery`, plus 9 judged windows (`lan-on`, `address-change`,
    `lan-rule`, `lan-private`, `lan-off`, `switch`, `lan-server`, `lan-server-private`,
    `lan-reopen`) with exact flow expectations and narrow LAN allowances. `_AFTER` verifies
    `198.51.100.10` removal and clean WFP state.

### Stage 10e: Windows Upgrade (`windows-upgrade`)

- **Command / config:** `run windows-upgrade`, `execution.windows.v8`,
  [execution-windows-upgrade.example.toml](../execution-windows-upgrade.example.toml) (pins two
  distinct Inno Setup installers for the same AppId + checkout recovery CLI/helper).
- **Catalog / runner:** `tools/vm/windows/upgrade-checks.json` (45 checks ported from
  `Invoke-UpgradeMatrix.ps1`), `guest/run-windows-upgrade.ps1`, lab image `lab-v5n`.
- **Windows (6):** `baseline`, `recovery`, plus 4 judged scenario windows: `lockdown` (`NONE`),
  `kill-switch` (`NONE`, verifies upgrade-hold provider `496d09fa-1d9a-451b-871f-35ba72197795`
  placed and removed on reconnect), `no-kill-switch` (`EXPECTED`: 1 direct HTTPS flow), and `broken`
  (`NONE` after interrupted setup until recovery `reset-firewall`). Interactive GUI checks stay on
  Hyper-V/manual testing.

### Stage 10f: Windows Protocols (`windows-protocols`) and Two-Hop (`windows-twohop`)

Both suites require lab image `lab-v5o` (`extended_fixtures`, multi-protocol node, Xray-core,
`TwoHopProxy`, `DhcpServer`, `fixture_state`/`fixture_control`, `DnsLog(aggregate=True)`).

- **`windows-protocols`:**
  - Config: `execution.windows.v9`,
    [execution-windows-protocols.example.toml](../execution-windows-protocols.example.toml) (adds
    pinned `xray.exe` and `proto_cert_sha256`).
  - Catalog / runner: `tools/vm/windows/protocols-checks.tsv` (17 checks: Hysteria2, TUIC + node
    outage, AnyTLS, Xray VLESS+REALITY + helper kill, Xray VLESS+REALITY+XHTTP + `xray=off` refusal
    under Lockdown, second-node switch to `203.0.113.10`, DHCPv4 lease renewal while connected),
    `guest/run-windows-protocols.ps1`.
  - Windows (9): `baseline`, `recovery`, plus 7 judged windows (`hysteria2`, `tuic`, `anytls`,
    `xray-reality`, `xray-xhttp`, `second-node`, `dhcp`), all expecting `NONE` with protocol-scoped
    tunnel endpoints and narrow DHCP/ARP allowances in `dhcp` only.
- **`windows-twohop`:**
  - Config: `execution.windows.v10`,
    [execution-windows-twohop.example.toml](../execution-windows-twohop.example.toml) (adds
    `proxy_port`, `xray`, `twohop_cert_sha256`, `twohop_untrusted_cert_sha256`).
  - Catalog / runner: `tools/vm/windows/two-hop-scenarios.tsv` (20 scenarios x 2 modes = 40 checks
    across `tun` and `system-proxy`: HTTP/HTTPS/SOCKS5 IPv4/IPv6/auth/domain-B, LAN B-hop, untrusted
    cert refusal, UDP/QUIC block, B-hop outage/timeout/auth-error, live apply/switch, Lockdown +
    B-hop outage, mixed-engine and Xray-first-hop chains), `guest/run-windows-twohop.ps1`, 137 lab
    actions (`planned_session_rotations = 20`).
  - Windows (4): `baseline`, `recovery`, plus 2 judged windows (`twohop-tun`, `twohop-proxy`), both
    expecting `NONE` (`unexpected: 0`), hop-A tunnel traffic only, zero direct B-hop traffic, zero
    guest DNS queries for `proxy-b.lab.test`, and lab HTTPS evidence from `203.0.113.20`.

### Developer stand verification summary (not owner qualification)

All eight Windows lab suites passed consecutive clean developer runs on Debian 13/WSL2 + QEMU
10.0.13 + untouched `windows-11-26h2-pro-v1` (2026-11-20 through 2026-11-24; `exit 0`, `findings: []`,
`unverified: []`, `image_unchanged: true`, `left: []`, both VMs `completion_verified: true`):

| Suite | Lab image | Checks | Judged windows | Typical duration |
| --- | --- | --- | --- | --- |
| `windows-list` | `lab-v5m` | 11 PASS | 1 (`session`) | ~189 s |
| `windows-failure` (all 7 cases) | `lab-v5m` / `v5n` | 12–18 PASS | 1 (`session`) | ~205–214 s / case |
| `windows-lockdown` (`core` / `full`) | `lab-v5m` | 57 / 72 PASS (8 boots) | 1 / 2 | ~312 s / ~623 s |
| `windows-proxy` | `lab-v5n` | 46 PASS (9 lab actions) | 3 | ~290–301 s |
| `windows-lan` (canonical 600 s) | `lab-v5n` | 72 PASS (120 echoes) | 9 | ~920–926 s |
| `windows-upgrade` | `lab-v5n` | 45 PASS | 4 | ~340–357 s |
| `windows-protocols` | `lab-v5o` | 17 PASS (17 lab actions) | 7 | ~177 s |
| `windows-twohop` | `lab-v5o` | 40 PASS (137 lab actions) | 2 | ~752 s |

## Windows List artifacts

Opt-in structured artifact recording is supported by
[../../windows/Invoke-ListMatrix.ps1](../../windows/Invoke-ListMatrix.ps1) via
`-ResultDirectory <new-directory>` (without it, legacy table/exit behavior is unchanged). It also
supplies the assessment format shared with `windows-list`.

```powershell
.\tools\vm\windows\Invoke-ListMatrix.ps1 -SingBoxPath .\tools\sing-box.exe -RequestPath .\tools\vm\windows\request-local.json -ResultDirectory .\target\list-run-001
python -B -m tools.vm.matrix report target/list-run-001/report.json --plan target/list-run-001/plan.json
```

The target directory must not exist; relative paths resolve against the current PowerShell location.
The recorder generates a GUID `run_id`, captures the Hyper-V VM GUID and initial UTC boot time, and
writes `plan.json` before modifying the guest. Credentials, request bodies, node configs, and raw
exception text are never written.

| File | Contract |
| --- | --- |
| `plan.json` | `rosetun.windows-list.plan.v2`: `catalog_digest`, suite, profile, mode policy, identity (`run_id`, `vm_id`, `boot_id`), ordered 11-check catalog snapshot. Old Windows `plan.v1` is rejected; Linux `plan.v1` remains supported. |
| `events.jsonl` | Append-only `rosetun.windows-list.event.v1` lines: `run_id`, 1-based sequence, check ID, result, safe reason code (`checked`, `condition-false`, `condition-exception`, `srs-compile-failed`, `interrupted`). |
| `report.json` | `rosetun.windows-list.report.v1`: initial identity, final boot, exact journal checks, counts, cleanup status, and safe `{reason: "infrastructure-error", place}` entries. |
| `status.json` | `rosetun.windows-list.status.v1`: same identity, `state: "finished"`, final event count; written atomically after `report.json` and cleanup. |

- **Canonical `catalog_digest` (SHA-256):** compact UTF-8 JSON (no BOM, no whitespace/trailing
  newline) of the ordered 6-field catalog array with fixed ordinal key order
  `detail,evidence,group,id,required,title`, lowercase booleans, and Python `ensure_ascii=True`
  escaping (slash unescaped, non-BMP as UTF-16 surrogate pairs). Detects accidental edits only; not
  a cryptographic signature.
- **Cleanup contract:** `PASS` requires read-back confirmation that the guest list directory is
  absent, tunnel state is `Disconnected`, and any host node owned by this run (matched by PID +
  UTC creation ticks, never listener absence alone) has exited. Reused nodes and `-KeepNode` nodes
  stay outside cleanup scope; unknown state stays `UNVERIFIED`; a surviving owned process is
  `ERROR`.
- **Offline planning & tests:**
  ```powershell
  python -B -m tools.vm.matrix plan windows-list --config tools/vm/matrix/example.toml --profile exploratory
  pwsh -NoProfile -File tools/vm/windows/tests/Test-RosetunListResults.ps1 -Directory target/synthetic-list-001
  pwsh -NoProfile -File tools/vm/windows/tests/Test-RosetunListCleanup.ps1
  ```

### Structured Windows Proxy contract

`Invoke-ProxyMatrix.ps1 -ResultDirectory <new-directory>` records structured results under schemas
`rosetun.windows-proxy.plan.v1`, `event.v1`, `report.v1`, and `status.v1` (46 assertions in
execution order, parameters `use_host_node`, `keep_node`, `proxy_port`).

```powershell
python -B -m tools.vm.matrix plan windows-proxy --config tools/vm/matrix/example.toml --profile exploratory
python -B -m tools.vm.matrix plan windows-proxy --without-host-node --config tools/vm/matrix/example.toml --profile exploratory
python -B -m tools.vm.matrix report target/proxy-with-node/report.json --plan target/proxy-with-node/plan.json
pwsh -NoProfile -File tools/vm/windows/tests/Test-RosetunProxyFinalization.ps1 -Directory target/synthetic-proxy-finalize-001
```

- **Coverage:** with `-UseHostNode`, both `sharing.*.server` assertions are required; without it
  they record `SKIP` (`host-node-disabled`) and exploratory acceptance reports `selected-variant`
  coverage. Observed `FAIL` in either `report.json` or `events.jsonl` survives corruption or missing
  completion.
- **Cleanup components:** reports `node`, `lan`, `watch`, `listener`, `connection`, `lockdown`,
  `desktop`, and `files` separately (`ERROR` > `UNVERIFIED` > `PASS`; `NOT_CREATED` when unacquired;
  `RETAINED` allowed only for owned `node` with `-KeepNode`). See
  [../../windows/README.md#structured-windows-proxy-results](../../windows/README.md#structured-windows-proxy-results).
- **WFP XML reader:** Lockdown cleanup verifies CLI off-status and absence of Lockdown objects in
  parsed `netsh wfp show state` XML (`<wfpstate>`, optionally followed by an empty
  `<firewallState><dynamicKeywordAddresses/></firewallState>` trailer, DTDs disabled). Any unknown
  or populated trailer, duplicate root, or malformed XML remains `UNVERIFIED`.
