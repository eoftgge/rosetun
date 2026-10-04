# Rosetun VM test rig

Runs the privileged helper, the CLI and sing-box inside a Hyper-V virtual machine
and drives them from the host over PowerShell Direct. The kill switch can block
all networking in the guest without touching the host, and PowerShell Direct
talks over VMBus, so it keeps working while the guest is locked down.

`Invoke-FailureMatrix.ps1` restores a clean checkpoint, deploys a fresh build and
walks through the kill-switch failure scenarios, printing a PASS/FAIL table.

## Files

| File | Purpose |
|---|---|
| `vm/RosetunVm.psm1` | Module with every building block: VM session, deploy, helper task, CLI, probes |
| `vm/Invoke-FailureMatrix.ps1` | The failure matrix |
| `vm/test-node.json` | sing-box config for a Shadowsocks test node running on the host |
| `vm/request-local.json` | `ConnectRequest` pointing at the test node, with the test password |
| `sing-box.exe` | The pinned sing-box build (currently 1.14.1). Not committed: `Install-RosetunSingBox` downloads it from the sing-box GitHub releases and checks its SHA-256 |

## Topology

```
guest apps ─► rosetun0 (TUN) ─► sing-box (guest) ─► Shadowsocks ─► test node (host) ─► host network ─► internet
                                     │
                                     └── kill switch: everything else in the guest is blocked by WFP
```

The guest reaches the host through the Hyper-V Default Switch (NAT). The test
node on the host gives the rig a proxy that is always reachable, independent of
real nodes and of censorship on the way to them.

## One-time setup

All host commands run in an elevated PowerShell from the repository root.

### 1. Create the VM

Windows 11 Pro, Generation 2, Default Switch, 4 vCPU, 4 GB of static memory.
One vCPU is not enough: right after a checkpoint restore Defender and Windows
Update compete with every scenario and timeouts start firing.

```powershell
New-VM -Name rosetun-test -Generation 2 -MemoryStartupBytes 4GB `
    -NewVHDPath 'D:\Hyper-V\rosetun-test.vhdx' -NewVHDSizeBytes 64GB -SwitchName 'Default Switch'
Set-VMProcessor -VMName rosetun-test -Count 4
Set-VMMemory -VMName rosetun-test -DynamicMemoryEnabled $false
Set-VMKeyProtector -VMName rosetun-test -NewLocalKeyProtector
Enable-VMTPM -VMName rosetun-test
Add-VMDvdDrive -VMName rosetun-test -Path 'C:\path\to\Win11.iso'
Set-VMFirmware -VMName rosetun-test -FirstBootDevice (Get-VMDvdDrive -VMName rosetun-test)
Start-VM -Name rosetun-test
```

Open the VM window and press a key at "Press any key to boot from CD or DVD",
or the firmware falls through to "boot loader failed". During setup choose a
local account: on Pro, "Sign-in options → Domain join instead" skips the
Microsoft account.

### 2. Store the guest credential

```powershell
Get-Credential | Export-Clixml "$env:USERPROFILE\.rosetun-vm-credential.xml"
```

The file is encrypted with DPAPI and only readable by your user on this
machine.

If `Connect-RosetunVm` later reports that the guest session is not elevated,
run this once inside the guest, elevated, so a local administrator gets a full
token over PowerShell Direct:

```powershell
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System `
    -Name LocalAccountTokenFilterPolicy -Value 1 -Type DWord
```

### 3. Host test node

Allow the node's port on the Default Switch interface only, so the LAN does not
see it:

```powershell
New-NetFirewallRule -DisplayName 'rosetun test node' -Direction Inbound -Protocol TCP -LocalPort 8388 `
    -InterfaceAlias 'vEthernet (Default Switch)' -Action Allow
```

### 4. Connect request

`vm/request-local.json` is committed and points at the test node. Its minimal
shape, if you need another one:

```json
{
  "selection": { "subscription": "local", "node": "test-node" },
  "node": {
    "id": "test-node",
    "name": "Host test node",
    "server": "replaced-by-UseHostNode",
    "port": 8388,
    "outbound": { "shadowsocks": { "method": "aes-128-gcm", "password": "rosetun-test" } }
  },
  "rule_set": { "id": "base", "name": "Base", "default_target": "proxy" },
  "settings": {
    "kill_switch": true,
    "log_level": "debug",
    "dns": { "server": "77.88.8.8", "server_name": "common.dot.dns.yandex.net" }
  }
}
```

`-UseHostNode` replaces `server` with the host's current Default Switch address
in the copy sent to the guest. The address changes with every host reboot.
Keep `default_target` at `proxy`: with `block`, sing-box rejects everything but
DNS and the tunnel looks broken.

The resolver is set to Yandex DoH because the test node exits through the
developer's own network, where DPI drops TLS connections to `dns.google` now
and then. Without `dns`, the default is Google (`8.8.8.8`, `dns.google`). The
resolver is contacted from the node's exit, so it has to be reachable from
there, not from the guest.

### 5. Prepare the clean checkpoint

The checkpoint is restored before every matrix run, so whatever the guest does
right after a restore happens in every run. Prepare it so the guest is quiet:

1. Install all pending Windows updates in the VM, rebooting until none remain.
2. Turn off automatic updates and refresh Defender signatures:

   ```powershell
   Import-Module .\tools\vm\RosetunVm.psm1 -Force
   Invoke-RosetunGuest {
       $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
       New-Item -Path $key -Force | Out-Null
       Set-ItemProperty -Path $key -Name NoAutoUpdate -Value 1 -Type DWord
       Update-MpSignature
   }
   ```

3. Bring the tunnel up once, so the Wintun driver is already installed (start
   the test node first, see "Every session"):

   ```powershell
   Publish-Rosetun -BuildDir .\target\release -SingBoxPath 'tools\sing-box.exe' `
       -RequestPath .\tools\vm\request-local.json -UseHostNode
   Register-RosetunHelper
   Start-RosetunHelper
   Connect-RosetunTunnel
   Wait-RosetunState Connected -TimeoutSeconds 120
   Disconnect-RosetunTunnel
   Stop-RosetunHelper
   ```

4. Wait until the guest is idle. This prints guest CPU load five times; go on
   once it stays under 10:

   ```powershell
   Invoke-RosetunGuest {
       1..5 | ForEach-Object {
           (Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'").PercentProcessorTime
           Start-Sleep -Seconds 2
       }
   }
   ```

5. Take the checkpoint, replacing any older one with the same name:

   ```powershell
   Get-VMCheckpoint -VMName rosetun-test -Name clean -ErrorAction SilentlyContinue | Remove-VMCheckpoint
   Checkpoint-VM -Name rosetun-test -SnapshotName clean
   ```

## Every session

1. Elevated PowerShell in the repository root:

   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   Import-Module .\tools\vm\RosetunVm.psm1 -Force
   ```

   The scripts are unsigned and files downloaded from the web carry the Mark of
   the Web; `Get-ChildItem .\tools\vm | Unblock-File` is the permanent fix.

2. Make sure the pinned sing-box is in place. This downloads it once and does
   nothing when the checksum already matches:

   ```powershell
   Install-RosetunSingBox
   ```

   When the pinned version changes, update the version and SHA-256 in
   `Install-RosetunSingBox` together with `SUPPORTED_SING_BOX_VERSION`.

3. Start the test node. It runs hidden in the background and logs at debug
   level to `vm\logs\test-node.log`, which a failed matrix run collects
   together with the helper logs:

   ```powershell
   Start-RosetunTestNode -BindInterface 'Ethernet 2'
   ```

   `-BindInterface` sends the node's own traffic out of the named physical
   adapter. Use it when a VPN client runs in TUN mode on the host: such a client
   accepts the node's TCP connections itself and now and then leaves them open
   without data, which shows up as DNS through the tunnel never answering.
   `Get-NetAdapter` lists the adapter names. `Stop-RosetunTestNode` stops the
   node. Running it by hand in a window still works
   (`& .\tools\sing-box.exe run --disable-color -c .\tools\vm\test-node.json`),
   but then its log stays in that window.

4. Build and run the matrix:

   ```powershell
   .\tools\vm\Invoke-FailureMatrix.ps1 -SingBoxPath 'tools\sing-box.exe' `
       -RequestPath .\tools\vm\request-local.json -RestoreCheckpoint -UseHostNode -Build
   ```

   Every run copies the helper and the CLI from `target\release` into the
   guest. `-Build` runs `cargo build --release` first; without it, whatever is
   in `target\release` is deployed, stale or not.

Without `-RestoreCheckpoint` the matrix runs against the current guest state,
which is faster when iterating but not reproducible.

### Iterating on one scenario

To try a change by hand without the whole matrix, redeploy into the running
guest and drive it with the module functions:

```powershell
Update-Rosetun -SingBoxPath 'tools\sing-box.exe' -RequestPath .\tools\vm\request-local.json -UseHostNode -Build
Connect-RosetunTunnel
Wait-RosetunState Connected
Test-RosetunTunnelEgress
Get-RosetunHelperLog -Tail 50
```

`Update-Rosetun` stops the helper, copies the new binaries and the request,
re-registers the task and starts the helper again.

## The matrix

| Scenario | What must hold |
|---|---|
| baseline | Direct egress from the guest works before connecting, so the probes themselves work |
| connect | State is `Connected`; traffic, DNS included, goes through the TUN within 5 s; direct egress is blocked |
| engine killed | State becomes `FailedProtected`; direct egress stays blocked |
| reconnect | Connecting from `FailedProtected` reaches `Connected` with no leak while it happens |
| failed reconnect | With the engine binary hidden, the state stays `FailedProtected` and direct egress stays blocked |
| disconnect | State is `Disconnected`, direct egress works again, the adapter is gone |
| shutdown | With the tunnel up, a shutdown request stops the engine, removes the adapter and restores egress |
| helper killed | Known fail-open: the engine dies with the helper and the adapter disappears |
| restart | A new helper connects cleanly after a killed one |
| unreachable reconnect | From `FailedProtected`, a node that never answers fails the helper's DNS check; the state stays `FailedProtected` and egress stays blocked |
| unreachable connect | From `Disconnected`, the same node fails the DNS check; the state is `Failed`, protection is released and the adapter is gone |

"Direct egress" is a curl bound to the guest's physical adapter address. "Through
the TUN" is checked by curl's local address, not just by success, so a request
that bypasses the tunnel does not count.

The unreachable node is the same request with the server replaced by
`192.0.2.1` (TEST-NET-1, reserved and unroutable). `Publish-Rosetun` writes it to
the guest as `request-unreachable.json`. In the script, "unreachable reconnect"
runs right after "failed reconnect", and "unreachable connect" right after
"disconnect".

## Guest layout

| Path | Content |
|---|---|
| `C:\rosetun\` | Helper, CLI, `sing-box.exe`, `request.json` |
| `C:\rosetun\helper.log` | Log of the current helper run (`ROSETUN_LOG=debug`), sing-box output included |
| `C:\rosetun\helper-<time>.log` | Logs of earlier helper runs, kept on every restart; after a killed helper or a failed scenario they are the evidence |
| `C:\ProgramData\Rosetun\run\sing-box\config.json` | The config sing-box actually received |

The helper runs as SYSTEM from the scheduled task `RosetunHelper`.

## Diagnostics

When the matrix fails it copies every helper log of the run, and the test
node log, to `vm\logs\<time>\` on the host; `Save-RosetunLogs` does the same
by hand. Add `/tools/vm/logs/` to `.gitignore`.

```powershell
Get-RosetunState
Get-RosetunHelperLog -Tail 100
Get-RosetunHelperLog -Tail 400 | Select-String 'inbound connection|dns|ERROR|WARN'

# What sing-box was given
Invoke-RosetunGuest { Get-Content C:\ProgramData\Rosetun\run\sing-box\config.json }

# Does the proxy path work at all, with no TUN, WFP or DNS hijack? Run disconnected.
Test-RosetunProxyPath | Format-List

# Which part of the tunnel comes up late after Connected
Measure-RosetunTunnelWarmup

# Where a request really goes
Invoke-RosetunGuest { curl.exe -v --max-time 10 -o NUL https://www.example.com 2>&1 | ForEach-Object { "$_" } }
Invoke-RosetunGuest { Find-NetRoute -RemoteIPAddress 1.1.1.1 | Format-List InterfaceAlias, IPAddress, NextHop }
```

How to read the common symptoms:

| Symptom | Meaning |
|---|---|
| curl: `Bad access` | WFP blocked the connect (`WSAEACCES`). The kill switch is working; the traffic did not take the TUN |
| `inbound DNS packet` in the log, but no `inbound connection` lines | TCP never reaches sing-box: check the TUN stack and the route that Windows really picked |
| DNS connections to the resolver open, but no `dns: exchanged` lines | The resolver is unreachable from the node's exit. Shadowsocks reports no error for this |
| `Test-RosetunProxyPath` fails | The problem is between the guest and the node, or at the node's exit, not in Rosetun |

To see which WFP filter blocked a connection, see "Diagnosing a block" in the
Windows rules.

## Pitfalls already paid for

- **The test node must be running.** Without it the tunnel still comes up and
  only the traffic check fails. `-UseHostNode` refuses to deploy if nothing
  listens on the node port.
- **Defender scans every new executable on first launch.** `Publish-Rosetun`
  launches sing-box once untimed so the scan does not hit the helper's 30 s
  version-check timeout; `Start-RosetunHelper` waits up to 60 s for the pipe.
- **Task Scheduler ignores a start while an instance is still running.**
  `Start-RosetunHelper` and `Stop-RosetunHelper` wait for the previous instance.
- **Localized Windows.** Use SIDs, GUIDs and CIM classes, never display names
  of groups, audit subcategories or performance counters.
- **Windows PowerShell writes a UTF-8 BOM with `-Encoding utf8`**, which both
  sing-box and serde_json reject. The module writes JSON with
  `[IO.File]::WriteAllText`.
- **A VPN client running in TUN mode on the host also captures the guest's NAT
  traffic** and the test node's own traffic. That is why the rig uses a node on
  the host instead of a real one, and why the node is bound to the physical
  adapter: through FlClashX, the node's DoH connections to 8.8.8.8 now and then
  stayed open without data and failed the helper's DNS check.
- **Host-side reachability checks test the host VPN, not the network.** With a
  VPN client in TUN mode on the host, a plain `curl.exe` from the host goes
  through that client; an "Empty reply from server" then says nothing about the
  target. Bind curl to the physical adapter instead:
  `curl.exe --interface (Get-NetIPAddress -InterfaceAlias 'Ethernet 2' -AddressFamily IPv4).IPAddress ...`
- **Release builds link the CRT statically** (`.cargo/config.toml`). A clean
  Windows has no `vcruntime140.dll`, and a dynamically linked helper dies
  before writing a single log line.
