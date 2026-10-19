# Hyper-V test nodes

Run PowerShell as Administrator on the host with the host VPN off. Once, allow the test nodes only on the Hyper-V Default Switch; the main node serves Shadowsocks on TCP 8388 and Hysteria2 on UDP 8443. The second Shadowsocks node on TCP 8389 blocks Cloudflare at its exit; Xray serves VLESS + REALITY + Vision on TCP 8390:

```powershell
New-NetFirewallRule -DisplayName 'Rosetun VM test node TCP' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8388 -InterfaceAlias 'vEthernet (Default Switch)'
New-NetFirewallRule -DisplayName 'Rosetun VM test node UDP' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 8443 -InterfaceAlias 'vEthernet (Default Switch)'
New-NetFirewallRule -DisplayName 'Rosetun VM Cloudflare-blocked node TCP' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8389 -InterfaceAlias 'vEthernet (Default Switch)'
New-NetFirewallRule -DisplayName 'Rosetun VM REALITY node TCP' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8390 -InterfaceAlias 'vEthernet (Default Switch)'
New-NetFirewallRule -DisplayName 'Rosetun VM exit node TCP' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8391 -InterfaceAlias 'vEthernet (Default Switch)'
```

Run the failure matrix directly; `-UseHostNode` starts the host test nodes. Pass a reachable REALITY cover site's DNS name (no scheme or port) as `-RealityCoverSite`; do not use a personal domain in files committed to git:

```powershell
.\tools\vm\Invoke-FailureMatrix.ps1 -SingBoxPath .\tools\sing-box.exe -RequestPath .\tools\vm\request-local.json -UseHostNode -RealityCoverSite 'example.com' -Build *>&1 | Tee-Object -FilePath .\target\matrix.txt
```

Replace `example.com` with a suitable real cover site before running. The matrix imports `RosetunVm.psm1` itself. With `-UseHostNode`, it starts both sing-box host nodes and a fresh Xray v26.10.10 node. It downloads the **same `Xray-windows-64.zip`** pinned in `installer/build.ps1`, checks the archive SHA-256 before extracting `xray.exe`, and copies the binary into the guest. The verified archive is cached under the git-ignored `tools/vm/logs/` directory. Xray generates fresh X25519 keys and a short ID at startup; the server config containing the private key is deleted after startup, and the server and extracted binary are removed in `finally` even with `-KeepNode`. Do not commit or paste any generated keys or logs. On first start, `Start-RosetunTestNode` generates a self-signed certificate for `rosetun-test.invalid`; its key, certificate and separate node logs also stay under `tools/vm/logs/`. The matrix derives its Hysteria2 and REALITY requests using the host's current Default Switch address. Check the matrix exit status and every PASS/FAIL result in `target/matrix.txt`. It tests the new REALITY connection, tunneled UDP datagrams to a temporary host listener, rejection without Xray, child/helper death and protected node switching alongside all previous scenarios. The UDP listener's Default Switch firewall rule is created only for the check and removed afterwards. The "no network" scenario disables the guest's physical adapter before connect (checking fast failure without WFP filters or TUN), then verifies protected network loss, continuous leak prevention and automatic recovery after the adapter returns; adapter restoration runs in `finally`.

`no network session` uses the derived `request-auto-reconnect.json`; `network change` uses the base `request.json` with auto-reconnect off.

`apply series` connects with an isolated config built from `request.json` (`apply-series\config.json`) and runs 20 CLI applies in a row, each with a changed rule: every apply must succeed and stay Connected, direct egress must stay blocked when the kill switch is on, and the note counts engine start retries and `already exists` lines in `helper.log`.

`Rule through another server` (with `-UseHostNode`) starts a second plain node on TCP 8391 (`Start-RosetunTestNode -ExitNode`, stopped in `finally`), connects with `request-rule-exit.json` whose Exit rule sends `yandex.ru` (`ExitRuleUrl`) through it, counts each node's logged connections to check which node carried the rule and the rest, checks that `rosetun delay` reports the second node, applies an isolated config (`exit-matrix\config.json`) whose country exit lists an unreachable decoy first and checks that the exit stays on the session's node (`rosetun exits` names it, the rule still reaches the second node), then stops the second node and checks that `rosetun delay` reports it not answering, only the rule fails, the session stays Connected and direct egress stays blocked.

Run the separate list rule-set scenario after the same guest/network prerequisites are satisfied (the owner runs this, not the agent):

```powershell
.\tools\vm\Invoke-ListMatrix.ps1 -SingBoxPath .\tools\sing-box.exe -RequestPath .\tools\vm\request-local.json -UseHostNode -Build *>&1 | Tee-Object -FilePath .\target\list-matrix.txt
```

It uses an isolated guest configuration, uploads a text list with `example.com` through CLI `connect`, checks Block against reachable `example.org`, compiles the same rule to SRS with `sing-box rule-set compile`, and uploads it with CLI `apply` before checking Direct with a blocked default. It disconnects and removes its guest-side list fixture afterwards. Check every PASS/FAIL result and the command exit status; do not commit the generated guest configuration or helper logs.

Both matrices stop sing-box host nodes on completion or error only if that invocation started them; the failure matrix also cleans up the Cloudflare-blocked node. An already-running sing-box node is reused and left alone. Add `-KeepNode` to keep newly started sing-box nodes for consecutive runs; it **never** keeps the REALITY server or its ephemeral keys. The REALITY port must be free at matrix startup. Add `-NodeBindInterface 'Ethernet'` to bind node outbounds to a physical adapter when a host TUN VPN would otherwise capture their traffic; this takes effect only when the matrix starts a node. To start or stop a sing-box node manually for debugging, import `./tools/vm/RosetunVm.psm1` and call `Start-RosetunTestNode -SingBoxPath ./tools/sing-box.exe` or `Stop-RosetunTestNode`; add `-CloudflareBlocked` for the second node. The stop command warns rather than terminating a foreign or partial listener.

Before running, the guest must have a DHCP-assigned IPv4 address with a default route and be able to connect to the host's link-local IPv6 address on TCP 8388. The failure matrix verifies both baselines; the list scenario checks direct egress and DNS before connecting. A temporary static IPv4 address can restore connectivity for diagnosis, but it cannot pass the DHCP recovery check after the guest adapter restarts. The Default Switch does not pass IPv6 neighbor discovery, so the matrix pins each side's link-local neighbor on the other (the host in the guest, the guest's current MAC on the host) in ActiveStore only, and removes the entries it created in `finally`, also after an interrupted run. A failed IPv6 baseline would make every "IPv6 blocked" result meaningless, so the matrix stops there and prints both neighbor entries; fix guest-to-host IPv6 reachability before running it again.

`Invoke-LockdownProbe.ps1` is a study for the 0.3 Lockdown, not a matrix: it checks which WFP permits from a dynamic session beat a persistent block in another sublayer, and whether the block holds across reboots. Run it with Rosetun disconnected in the guest (the owner runs it); it reboots the guest unless `-SkipReboot` is given:

```powershell
.\tools\vm\Invoke-LockdownProbe.ps1 -Build *>&1 | Tee-Object -FilePath .\target\lockdown-probe.txt
```

It copies `lockdown_probe.exe` and a renamed curl into `C:\rosetun\lockdown-probe` and registers the startup task `RosetunLockdownBootCheck`; `finally` removes the persistent objects, the task and the folder, so nothing is left after cleanup. If the run was interrupted and the guest has no network, run in the guest as administrator `C:\rosetun\lockdown-probe\lockdown_probe.exe persistent remove` (safe to repeat; `persistent status` shows what is left), then `Unregister-ScheduledTask RosetunLockdownBootCheck -Confirm:$false`. Without the binary, `netsh wfp show filters` lists the filters of provider `681cc7b8-4f59-4eac-8c10-06bf2aa25d17`, and restoring the `clean` checkpoint removes everything.
