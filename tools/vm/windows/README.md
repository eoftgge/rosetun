# Windows VM Runners, Catalogs, and Legacy Hyper-V Harnesses

> **Primary VM test path:** Autonomous Windows matrices with independent wire-level leak observation
> run in the isolated QEMU/KVM lab — see
> [../matrix/docs/WINDOWS.md](../matrix/docs/WINDOWS.md) (`windows-list`, `windows-failure`,
> `windows-lockdown`, `windows-proxy`, `windows-lan`, `windows-upgrade`, `windows-protocols`,
> `windows-twohop`).
>
> The Hyper-V PowerShell Direct scripts below are **legacy harnesses** retained for manual checks,
> GUI-interactive upgrade inspection, and owner parity comparison.

## Directory contents

- **`guest/`** — autonomous PowerShell 5.1 runners (`run-windows-*.ps1`, `lib.ps1`,
  `failure-probes.ps1`) executed inside the QEMU lab VM via read-only ISO delivery.
- **Check catalogs** — `list-checks.json` (11), `failure-core.tsv` (132), `lockdown-core.tsv` (72),
  `proxy-checks.json` (46), `lan-core.tsv` (72), `upgrade-checks.json` (45),
  `protocols-checks.tsv` (17), `two-hop-scenarios.tsv` (40).
- **`tests/`** — offline PowerShell unit, AST, finalization, and cleanup tests (no VM required).
- **`Invoke-*Matrix.ps1`, `RosetunVm.psm1`, `Rosetun{List,Proxy}Results.psm1`** — legacy Hyper-V
  PowerShell Direct harnesses, host test-node helpers, and diagnostic probes.

## Offline PowerShell tests (no VM required)

```powershell
pwsh -NoProfile -File tools/vm/windows/tests/Test-RosetunScriptArguments.ps1
pwsh -NoProfile -File tools/vm/windows/tests/Test-RosetunListResults.ps1 -Directory target/synthetic-list-001
pwsh -NoProfile -File tools/vm/windows/tests/Test-RosetunListCleanup.ps1
pwsh -NoProfile -File tools/vm/windows/tests/Test-RosetunProxyFinalization.ps1 -Directory target/synthetic-proxy-finalize-001
pwsh -NoProfile -File tools/vm/windows/tests/Test-RosetunFailureChecks.ps1
pwsh -NoProfile -File tools/vm/windows/tests/Test-RosetunUpgradeRequests.ps1
pwsh -NoProfile -File tools/vm/windows/tests/Test-RosetunWfpSublayer.ps1
```

## Legacy Hyper-V harnesses

Run from an elevated PowerShell 7 on the Windows host with host Lockdown **off** and a prepared
Windows 11 Gen 2 Hyper-V VM (`rosetun-test`, 4 vCPU, 4 GB RAM, `Default Switch`, `clean` checkpoint,
credential stored via `Get-Credential | Export-Clixml "$env:USERPROFILE\.rosetun-vm-credential.xml"`).

One-time host firewall rules on `vEthernet (Default Switch)` for `-UseHostNode`:

```powershell
New-NetFirewallRule -DisplayName 'Rosetun VM test node TCP' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8388,8389,8390,8391,8392,8445 -InterfaceAlias 'vEthernet (Default Switch)'
New-NetFirewallRule -DisplayName 'Rosetun VM test node UDP' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 8443,8444 -InterfaceAlias 'vEthernet (Default Switch)'
```

| Script | Purpose |
| --- | --- |
| `Invoke-FailureMatrix.ps1` | Core failure, kill switch, DNS lock, REALITY/XHTTP, connections list, delay, exit rule |
| `Invoke-ListMatrix.ps1` | Text & compiled SRS rule-set list checks (supports `-ResultDirectory`; see [Stage 10a](../matrix/docs/WINDOWS.md#stage-10a-windows-list-windows-list)) |
| `Invoke-LanMatrix.ps1` | Local network, mDNS/SSDP/broadcast, 10 min long session, live IP change (`-MulticastTraceOnly` invokes `Trace-RosetunGuestMulticast.ps1`) |
| `Invoke-ProxyMatrix.ps1` | System proxy, WinINet `desktop_proxy.exe`, LAN sharing, Lockdown (supports `-ResultDirectory`) |
| `Invoke-LockdownMatrix.ps1` | Lockdown across helper kill, sleep/resume, reboot, and power cuts |
| `Invoke-UpgradeMatrix.ps1` | Silent Inno Setup upgrade (`-PreviousSetup`, `-CurrentSetup`, `-RestoreCheckpoint`) |
| `Invoke-LockdownProbe.ps1`, `Invoke-PowerCutConnectProbe.ps1` | Standalone WFP/Lockdown and post-power-cut readiness probes |

Common invocation pattern:

```powershell
.\tools\vm\windows\Invoke-FailureMatrix.ps1 -SingBoxPath .\tools\sing-box.exe -RequestPath .\tools\vm\windows\request-local.json -UseHostNode -RealityCoverSite 'example.com' -Build
```

Pinned `sing-box.exe` is fetched and SHA-256 verified by `Install-RosetunSingBox` (from
`RosetunVm.psm1`). Pass `-NodeBindInterface '<Adapter>'` if a host TUN VPN interferes with host
node egress. Logs from failed runs are collected under `tools/vm/logs/` (git-ignored).

### Structured Windows List and Proxy results

`Invoke-ListMatrix.ps1` and `Invoke-ProxyMatrix.ps1` accept opt-in `-ResultDirectory <new-directory>`
to emit deterministic `plan.json`, `events.jsonl`, `report.json`, and `status.json` artifacts
assessable with `python -B -m tools.vm.matrix report <report.json> --plan <plan.json>`:

- **List (`rosetun.windows-list.plan.v2`):** 11 required checks, canonical SHA-256 `catalog_digest`,
  PID + creation-time node cleanup verification. Full contract in
  [../matrix/docs/WINDOWS.md#windows-list-artifacts](../matrix/docs/WINDOWS.md#windows-list-artifacts).
- **Proxy (`rosetun.windows-proxy.plan.v1`):** see the section below and
  [../matrix/docs/WINDOWS.md#structured-windows-proxy-contract](../matrix/docs/WINDOWS.md#structured-windows-proxy-contract).

### Structured Windows Proxy results

```powershell
.\tools\vm\windows\Invoke-ProxyMatrix.ps1 -SingBoxPath .\tools\sing-box.exe -RequestPath .\tools\vm\windows\request-local.json -UseHostNode -ResultDirectory .\target\proxy-with-node
.\tools\vm\windows\Invoke-ProxyMatrix.ps1 -SingBoxPath .\tools\sing-box.exe -RequestPath .\tools\vm\windows\request-local.json -ResultDirectory .\target\proxy-without-node
python -B -m tools.vm.matrix report target/proxy-with-node/report.json --plan target/proxy-with-node/plan.json
```

- **Catalog & coverage:** 46 assertions (`proxy-checks.json`). `-UseHostNode` requires both
  `sharing.*.server` checks; without it they record `SKIP` (`host-node-disabled`) and acceptance
  reports `selected-variant`. An interruption records `interrupted`.
- **Cleanup components:** `node`, `lan`, `watch`, `listener`, `connection`, `lockdown`, `desktop`,
  and `files` are reported independently (`ERROR` > `UNVERIFIED` > `PASS`; `NOT_CREATED` when
  unacquired; `RETAINED` allowed only for owned `node` with `-KeepNode`). Owned node stop checks
  PID + UTC creation ticks; desktop WinINet settings are compared in memory and never overwrite
  foreign user edits.
- **Lockdown WFP read-back & evidence boundary:** requires CLI `lockdown: off` and parsed
  `netsh wfp show state` XML (`<wfpstate>` plus optional empty `<firewallState>` trailer, DTDs
  disabled) with zero Lockdown objects. Active WFP dumps do not expose inactive boot-time filters
  after BFE startup; invariants remain `UNVERIFIED` and `release_gate` stays `false`.

## Recovery after an interrupted Hyper-V run

If a Lockdown, Upgrade, or Lockdown Probe run is killed mid-flight and leaves the guest without
network:

1. **Reset Rosetun Lockdown / upgrade hold** (in the guest, elevated):
   ```powershell
   Stop-Process -Name rosetun-helper-privileged -ErrorAction SilentlyContinue
   C:\rosetun\rosetun-helper-privileged.exe --reset-firewall
   Unregister-ScheduledTask RosetunLockdownMatrixBootCheck -Confirm:$false -ErrorAction SilentlyContinue
   ```
2. **Reset standalone Lockdown probe** (if `Invoke-LockdownProbe.ps1` was interrupted):
   ```powershell
   C:\rosetun\lockdown-probe\lockdown_probe.exe persistent remove
   Unregister-ScheduledTask RosetunLockdownBootCheck -Confirm:$false -ErrorAction SilentlyContinue
   ```
3. **Reset guest DNS / static IP** (if interrupted during LAN or Lockdown name-zone checks):
   ```powershell
   Set-DnsClientServerAddress -InterfaceIndex <idx> -ResetServerAddresses
   ```
4. **Full clean reset:** restore the Hyper-V `clean` checkpoint (`Restore-VMSnapshot -VMName rosetun-test -Name clean`).

Relevant WFP provider GUIDs for manual inspection (`netsh wfp show filters` / `show state`):
- Rosetun Lockdown: `f12dbedd-f3c7-4a72-b0f8-20559c88b112`
- Rosetun Upgrade Hold: `496d09fa-1d9a-451b-871f-35ba72197795`
- Standalone Lockdown Probe: `681cc7b8-4f59-4eac-8c10-06bf2aa25d17`
