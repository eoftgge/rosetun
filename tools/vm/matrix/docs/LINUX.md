# Linux Suites (QEMU / QGA and Lab)

This document covers the QEMU/QGA execution path for Linux suites (`linux-l2`, `linux-l3`,
`linux-proxy`, `linux-l5`, `linux-l4`, and `linux-reboot-smoke`), read-only media delivery, and
Linux lab wire windows. Existing Hyper-V/SSH workflows remain in
[../../linux/README.md](../../linux/README.md).

For the suite catalog and CLI overview, see [../README.md](../README.md). For controller leases
and lifecycle, see [CONTROLLER.md](CONTROLLER.md); for the two-VM wire observer, see
[LAB.md](LAB.md).

## Read-only media delivery (`l2_media`)

All Linux execution suites deliver owner-built artifacts to a guest without a network using a
read-only ISO (`l2_media.py`, built with `xorriso`) attached as an optical drive and imported once
inside the guest by `/usr/local/libexec/rosetun-matrix/stage-l2.py`:

- **Provenance and byte pinning:** `content_directory` must hold owner-built binaries and
  `provenance.json` matching the suite's stage (`l2`, `l3`, `proxy`, `l5`, `l4`). Checkout scripts,
  TSV catalogs, and `packaging/linux/` unit files are compared byte-for-byte against
  `source_checkout`. Generated request files are rendered deterministically by `l3_requests.py`
  and never placed manually in `content_directory`.
- **Size and magic limits:** text files <= 256 KiB, ELF binaries <= 512 MiB, Debian `.deb`
  packages (`Profile.packages`, L5 only) <= 128 MiB with `!<arch>\n` magic, verified on both the
  controller and the guest importer (`stage-l2.py`).
- **One-shot import:** `stage-l2.py` checks VM UUID, observed boot ID, and media digests before
  copying into the guest staging directory, then `guest/start.sh` dispatches the autonomous job via
  `systemd-run` / `launch.sh` under strict `job.env` validation.

## Owner-prepared Linux L2 execution (stage 5a)

`linux_l2.LinuxL2Job` and `python3 -B -m tools.vm.matrix run linux-l2 --config CONFIG` execute the
existing 34-row `run-l2.sh` IPC transport suite (`tools/vm/linux/scenarios.tsv`) inside a single
isolated VM (`-nic none`, no lab VM, no SSH/Hyper-V/WSL):

```sh
python3 -B -m tools.vm.matrix run linux-l2 --config /srv/execution-l2.toml --dry-run
python3 -B -m tools.vm.matrix run linux-l2 --config /srv/execution-l2.toml
```

- **Configuration:** [../execution.example.toml](../execution.example.toml), schema
  `rosetun.matrix.execution.v1`.
- **Execution flow:** takes a stand lease, builds and verifies the read-only ISO, boots the pinned
  Linux image, imports the package via QGA (`stage-l2.py`), starts the autonomous guest unit,
  waits by polling job status (Stage 8c), collects `report.json` + `status.json`, runs the offline
  assessor (`rosetun.matrix.assessment.v1`), and closes the VM cleanly.
- **Reattach:** non-lab `linux-l2` (and non-lab `linux-l3`) runs can be resumed after step `submit`
  with `attach` (see [CONTROLLER.md](CONTROLLER.md#run-state-on-disk-and-reattach-stage-w)).
  Qualifying runs require `attached: false`.
- **Scope:** validates the IPC transport (`SO_PEERCRED`), helper policy/server unit tests, and
  stand preflight/cleanup. Makes no claim about network protection, kill switch, or Lockdown.

## Bounded smoke delivery over QGA (stage 4b.3)

The opt-in infrastructure smoke delivery API (`rosetun.smoke-stage.v1`, `jobs.py` / `staging.py`)
verifies the guest launcher and start dispatcher independently of Rosetun scenarios:

- Delivers a tiny, schema-pinned smoke package over bounded QGA calls, executes it via the same
  installed launcher, and reads back a strict JSON result.
- Bound to stand ID, VM UUID, and observed boot ID; enforces QGA call and relay byte ceilings.
- Does not invoke SSH harnesses or qualify VPN protection.

## Linux suites in the two-VM lab

Adding `--lab` with a `rosetun.matrix.execution.v3` configuration attaches the `test` VM to the
isolated `lab` VM wire ([LAB.md](LAB.md)), enables UDP `:9100` window markers (`LAB_MARKER_ADDRESS`),
collects `capture.pcap` on the lab evidence disk, and cross-checks guest verdicts against observed
wire frames. Without `--lab` (`execution.v2`, `-nic none`), delivery and guest failure reporting are
tested without a network.

### Summary of Linux suites

| Suite | Catalog rows (active / `not-run`) | Config schema / example | Summary schema | Reboots | Wire windows (`--lab`) |
| --- | --- | --- | --- | --- | --- |
| `linux-l2` | 34 (34 / 0) | `execution.v1` / [execution.example.toml](../execution.example.toml) | `execution-summary.v1` | 0 | Single VM (no lab) |
| `linux-l3` | 63 (43 / 20) | `execution.v2` / `v3` / [execution-l3-lab.example.toml](../execution-l3-lab.example.toml) | `l3-summary.v1` | 0 | All kill-switch, DNS, route, LAN, IPv6, and stop windows judged |
| `linux-proxy` | 47 (27 / 20) | `execution.v2` / `v3` (`suite = "linux-proxy"`) | `proxy-summary.v1` | 0 | 7 windows (`proxy_open`, `strict`, `mode_change`, `share`, `share_off`, `lockdown_share`, `stopped`) |
| `linux-l5` | 17 (17 / 0) | `execution.v2` / `v3` (`suite = "linux-l5"`) | `l5-summary.v1` | 0 | 2 windows (`upgrade_ks`, `upgrade_lockdown`) |
| `linux-l4` | 27 (27 / 0) | `execution.v2` / `v3` / [execution-l4-lab.example.toml](../execution-l4-lab.example.toml) | `l4-summary.v1` | 2 (3 boots) | 1 coarse window (`lockdown`) |
| `linux-reboot-smoke` | 3 (3 / 0) | `execution.v2` / [execution-reboot-smoke.example.toml](../execution-reboot-smoke.example.toml) | `execution-summary.v1` | 1 (2 boots) | Single VM (reboot controller smoke) |

### Suite-specific contracts

- **`linux-l3` (Kill switch, DNS, routing, LAN, IPv6):**
  - Runs `run-l3.sh` with 6 generated requests (`l3_requests.py`) and pinned `sing-box`
    (`sing_box_sha256`). Twenty `two-hop.*` rows are marked `not-run` (`SKIP`) and excluded from
    the active group.
  - Every session window is judged against explicit flow expectations (`l3_tables.py`); narrow
    allowances cover LAN and IPv6 DAD where required.
  - Supports `--control stop-helper` (stops the helper inside a protected window, injects a direct
    HTTPS request, and exits 0 only when the observer flags `DETECTED` and `DISAGREE`) and
    `--diagnostic` (enables engine destination naming for debugging; never qualifies, exits >= 2).
- **`linux-proxy` (System proxy, sharing, Lockdown):**
  - Requires `rosetun-helper-privileged`, `rosetun`, `desktop_proxy`, and `sing-box` plus the
    three `packaging/linux/` unit files.
  - Because proxy LAN sharing requires a private IPv4 address, `run-proxy.sh` temporarily adds the
    owner-approved lab exception **`192.168.77.2/24`** when `LAB_MARKER_ADDRESS` is set and removes
    it in cleanup.
  - Seven windows (`proxy_tables.py`): `proxy_open` expects 1 direct HTTPS flow (`proxy.around-open`);
    the other six (`strict`, `mode_change`, `share`, `share_off`, `lockdown_share`, `stopped`)
    expect `NONE`. Supports `--control stop-helper`.
- **`linux-l5` (Debian `.deb` install, upgrade, remove, purge):**
  - Delivers `rosetun-old.deb` and `rosetun-new.deb` built by `build-artifacts.sh --deb` (no
    standalone `sing-box` or ELF binaries; `sing_box_sha256` is omitted from `[l3]`).
  - Two windows (`l5_tables.py`): `upgrade_ks` and `upgrade_lockdown`, both expecting `NONE`.
  - Cross-checks the guest nftables leak counter (`inet rosetun-l5-watch`) against the wire
    observer (`group.counter.agreement`; any mismatch raises `counter-contradicted-by-window`,
    exit 1). Supports `--control stop-helper`.
- **`linux-l4` (Lockdown across planned reboots):**
  - Requires `build-artifacts.sh --l4` (`"stage": "l4"`), `sing-box`, and a test image with SSHD
    enabled for `inbound.lan-open`.
  - Uses `planned_reboots = 2` (3 distinct boots in `boot_chain`; mismatch exits 2).
  - Single coarse window `lockdown` (`l4_tables.py`) spanning 19 scenarios across the first reboot:
    expects exactly 4 TCP flows to `203.0.113.2:443` and 4 UDP flows to `203.0.113.53:53` (the
    permitted `rosetun-gui`/`rosetun-cli` scope probes), `tunnel` traffic, `inbound-poll` SSH
    traffic from the lab poller (`LAB_POLLER_KEY`, `ssh-ed25519`), and `ipv6-dad` allowance during
    reboot. Supports `--control stop-helper`.
- **`linux-reboot-smoke`:**
  - Single-VM controller check for Stage 8c planned reboot handling (`planned_reboots = 1`, 2 boots,
    RESET coalescing, QGA recovery, and `boot_chain` validation).

### Exit codes for `--lab` suites

- `0`: all active checks `PASS`, all expected windows matched (`NONE` / `EXPECTED`), cross-checks
  `AGREE`, required fixtures answered, cleanup `PASS`, both VMs `completion_verified`.
- `1`: behavioral finding (failed scenario, wire `DETECTED` or `MISMATCH`, cross-check `DISAGREE`,
  or cleanup failure).
- `2`: infrastructure or unverified condition (error, missing/unclosed window, missing fixture,
  boot-chain mismatch, unverified completion, or `--diagnostic`).
- `130`: interrupted.
