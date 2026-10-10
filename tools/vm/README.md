# Hyper-V test nodes

Run PowerShell as Administrator on the host. Allow the test nodes only on the Hyper-V Default Switch; the TCP node serves Shadowsocks on 8388 and the UDP node serves Hysteria2 on 8443:

```powershell
New-NetFirewallRule -DisplayName 'Rosetun VM test node TCP' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8388 -InterfaceAlias 'vEthernet (Default Switch)'
New-NetFirewallRule -DisplayName 'Rosetun VM test node UDP' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 8443 -InterfaceAlias 'vEthernet (Default Switch)'
```

Start the host node before running the matrix:

```powershell
Import-Module .\tools\vm\RosetunVm.psm1 -Force
Start-RosetunTestNode
.\tools\vm\Invoke-FailureMatrix.ps1 -SingBoxPath .\tools\sing-box.exe -RequestPath .\tools\vm\request-local.json -UseHostNode -Build *>&1 | Tee-Object -FilePath .\target\matrix.txt
```

`Start-RosetunTestNode` generates a self-signed certificate for `rosetun-test.invalid` on first run. The key, certificate and node log stay under the git-ignored `tools/vm/logs/` directory; do not commit or paste them. The matrix derives its Hysteria2 request using the host's current Default Switch address. Check the matrix exit status and every PASS/FAIL result in `target/matrix.txt`. The matrix also repeats five immediate connects, cancels a dead-node connect after three seconds and checks that a dead server is reported as unreachable within 20 seconds.

Run the separate list rule-set scenario after the same guest/network prerequisites are satisfied (the owner runs this, not the agent):

```powershell
.\tools\vm\Invoke-ListMatrix.ps1 -SingBoxPath .\tools\sing-box.exe -RequestPath .\tools\vm\request-local.json -UseHostNode -Build *>&1 | Tee-Object -FilePath .\target\list-matrix.txt
```

It uses an isolated guest configuration, uploads a text list with `example.com` through CLI `connect`, checks Block against reachable `example.org`, compiles the same rule to SRS with `sing-box rule-set compile`, and uploads it with CLI `apply` before checking Direct with a blocked default. It disconnects and removes its guest-side list fixture afterwards. Check every PASS/FAIL result and the command exit status; do not commit the generated guest configuration or helper logs.

Before running, the guest must have a DHCP-assigned IPv4 address with a default route and be able to connect to the host's link-local IPv6 address on TCP 8388. The failure matrix verifies both baselines; the list scenario checks direct egress and DNS before connecting. A temporary static IPv4 address can restore connectivity for diagnosis, but it cannot pass the DHCP recovery check after the guest adapter restarts. A failed IPv6 baseline makes subsequent "IPv6 blocked" results inconclusive; fix guest-to-host IPv6 reachability before treating those checks as evidence of protection.
