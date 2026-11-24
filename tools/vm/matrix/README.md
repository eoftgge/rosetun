# VM Matrix Controller and Assessment Foundation

Python 3.11+ and the standard library are sufficient for offline planning, assessment, evidence
packing, and unit tests. Run commands from the repository root (`python3 -B -m tools.vm.matrix ...`).
Live QEMU/KVM execution requires Linux x86_64 with KVM, QEMU 10.0.13, `qemu.qmp==0.0.6`, `xorriso`,
and (for Windows guests) `swtpm`. Legacy Hyper-V matrices in [../linux/README.md](../linux/README.md)
and [../windows/README.md](../windows/README.md) remain supported.

> **Important:** Internal QEMU qualification, offline tests, and evidence packs **never grant
> release acceptance**. Every assessment and evidence manifest keeps `release_gate: false` and
> `security_invariants: "UNVERIFIED"`. Parity judgment and release sign-off remain exclusively with
> the owner.

## Documentation index

| Document | Contents |
| --- | --- |
| [docs/controller.md](docs/controller.md) | Stand leases, resource ledgers, blocked-stand recovery, Stage W run-state & `attach`, QEMU/QGA lifecycle, planned reboots & `power_cycle`, image digest cache, offline `plan`/`report` schemas & limits |
| [docs/lab.md](docs/lab.md) | Isolated two-VM wire topology, `lab-smoke` & observer controls, frame classification & window verdicts, lab images (`lab-v5m`, `lab-v5n`, `lab-v5o`) & `lab-action-requested` protocol |
| [docs/linux.md](docs/linux.md) | Read-only ISO media delivery (`l2_media`), owner-prepared L2 execution, QGA smoke delivery, and Linux lab suites (`linux-l2`, `linux-l3`, `linux-proxy`, `linux-l5`, `linux-l4`, `linux-reboot-smoke`) |
| [docs/windows.md](docs/windows.md) | Windows launch profile (`windows-uefi-q35-v1`) & smokes (`9b`–`9d`), autonomous Windows lab matrices (`10a`–`10f`), and structured Hyper-V List & Proxy artifact contracts |
| [docs/evidence.md](docs/evidence.md) | Release evidence packs (`evidence` command, `--include-archive`, Linux + all 8 Windows suites, `manifest.json` counters, refusal codes, owner parity/signing workflow) |

## Suite catalog

### Linux suites

| Suite | Checks (active / `not-run`) | Config schema / example | Scope |
| --- | --- | --- | --- |
| `linux-l2` | 34 / 0 | `execution.v1` / [execution.example.toml](execution.example.toml) | Single-VM IPC transport & helper unit tests |
| `linux-l3` | 43 / 20 | `execution.v2`–`v3` / [execution-l3-lab.example.toml](execution-l3-lab.example.toml) | Kill switch, DNS lock, routing, LAN, IPv6 (`--lab`) |
| `linux-proxy` | 27 / 20 | `execution.v2`–`v3` (`suite = "linux-proxy"`) | System proxy, strict KS, LAN sharing, Lockdown (`--lab`) |
| `linux-l5` | 17 / 0 | `execution.v2`–`v3` (`suite = "linux-l5"`) | `.deb` install, upgrade under KS/Lockdown, remove, purge (`--lab`) |
| `linux-l4` | 27 / 0 | `execution.v2`–`v3` / [execution-l4-lab.example.toml](execution-l4-lab.example.toml) | Lockdown persistence across 2 planned reboots / 3 boots (`--lab`) |
| `linux-reboot-smoke` | 3 / 0 | `execution.v2` / [execution-reboot-smoke.example.toml](execution-reboot-smoke.example.toml) | Single-VM planned reboot controller smoke (1 reboot) |

### Windows smokes and lab matrices

| Suite | Checks | Config schema / example | Lab image | Scope |
| --- | --- | --- | --- | --- |
| `windows-boot-smoke` | — | `execution.windows.v1` / [execution-windows-boot-smoke.example.toml](execution-windows-boot-smoke.example.toml) | — | Single-VM UEFI + `swtpm` boot, screendump, ACPI shutdown |
| `windows-reboot-smoke` | — | `execution.windows.v1` / [execution-windows-reboot-smoke.example.toml](execution-windows-reboot-smoke.example.toml) | — | Single-VM Windows QGA (`BootId`, UTF-8) + 1 planned restart |
| `windows-lab-smoke` | 10 probes | `execution.windows.v2` / [execution-windows-lab-smoke.example.toml](execution-windows-lab-smoke.example.toml) | `lab-v5m` | Two-VM wire probes (`probes`) + 600 s noise report (`rest`) |
| `windows-list` | 11 | `execution.windows.v3` / [execution-windows-list.example.toml](execution-windows-list.example.toml) | `lab-v5m` | Text & compiled SRS rule-set list routing (Stage 10a) |
| `windows-failure` | 12–18 / case | `execution.windows.v4` / [execution-windows-failure.example.toml](execution-windows-failure.example.toml) | `lab-v5m`/`v5n` | 7 failure core cases: crash, no-network, apply, reconnect, temp, DNS lock (Stage 10b) |
| `windows-lockdown` | 57 / 18–24 / 72 | `execution.windows.v5` / [execution-windows-lockdown.example.toml](execution-windows-lockdown.example.toml) | `lab-v5m` | Lockdown `core`, `reboot`, `full` (8 boots: 1 reboot + 6 `power_cycle` cuts, Stage 10c) |
| `windows-proxy` | 46 | `execution.windows.v6` / [execution-windows-proxy.example.toml](execution-windows-proxy.example.toml) | `lab-v5n` | System proxy, WinINet desktop settings, LAN sharing, Lockdown (Stage 10d) |
| `windows-lan` | 72 | `execution.windows.v7` / [execution-windows-lan.example.toml](execution-windows-lan.example.toml) | `lab-v5n` | Local network, mDNS/SSDP/broadcast, 600 s session, live IP change (Stage 10d) |
| `windows-upgrade` | 45 | `execution.windows.v8` / [execution-windows-upgrade.example.toml](execution-windows-upgrade.example.toml) | `lab-v5n` | Inno Setup silent upgrade under Lockdown, KS hold, no-KS, interrupted setup (Stage 10e) |
| `windows-protocols` | 17 | `execution.windows.v9` / [execution-windows-protocols.example.toml](execution-windows-protocols.example.toml) | `lab-v5o` | Hysteria2, TUIC outage, AnyTLS, Xray REALITY/XHTTP, 2nd node, DHCP renew (Stage 10f) |
| `windows-twohop` | 40 | `execution.windows.v10` / [execution-windows-twohop.example.toml](execution-windows-twohop.example.toml) | `lab-v5o` | 20 two-hop proxy chain scenarios x 2 modes (`tun` + `system-proxy`, Stage 10f) |

## CLI quick reference

```sh
# Offline diagnostics, planning, and assessment
python3 -B -m tools.vm.matrix doctor
python3 -B -m tools.vm.matrix plan <suite> --config tools/vm/matrix/example.toml --profile exploratory
python3 -B -m tools.vm.matrix report <report.json> --plan <plan.json>

# Stand inspection, recovery, and reattach
python3 -B -m tools.vm.matrix runs --state-directory STATE
python3 -B -m tools.vm.matrix recover --state-directory STATE
python3 -B -m tools.vm.matrix recover --state-directory STATE --run-id RUN_ID --close
python3 -B -m tools.vm.matrix recover --state-directory STATE --run-id RUN_ID --archive
python3 -B -m tools.vm.matrix attach  --state-directory STATE --run-id RUN_ID

# Isolated two-VM lab smoke and matrix execution (Linux KVM stand)
python3 -B -m tools.vm.matrix lab-smoke --config /srv/lab.toml [--dry-run] [--canary] [--tunnel --dns --evidence-disk]
python3 -B -m tools.vm.matrix run <suite> --config CONFIG [--dry-run] [--lab] [--control stop-helper] [--diagnostic]

# Deterministic release evidence packs (read-only against state)
python3 -B -m tools.vm.matrix evidence --state-directory STATE [--include-archive] --run RUN1 --run RUN2 --out DIR
```

**Exit codes (general convention):**
- `0`: command succeeded (for `run`, all checks and judged windows passed with verified completion;
  for `evidence`, pack built; never means release approval).
- `1`: behavioral finding or unaccepted valid assessment (`findings`, failed check, wire leak or
  mismatch, cleanup failure, or `evidence` refusal).
- `2`: input/CLI error, infrastructure failure, or `unverified` run (missing window/marker/fixture,
  boot-chain mismatch, unverified completion, or `--diagnostic`).
- `130`: interrupted.

## Stand recovery quick reference

An unfinished run keeps its stand locked (`stand has unresolved runs`). Inspect first with `recover`
(read-only):

1. `process_status: alive` -> close gracefully via QMP with `recover --run-id R --close` (or
   `attach --run-id R` for non-lab `linux-l2`/`linux-l3` runs past `submit`), then archive.
2. `process_status: absent` (or finished with verified completion) -> move out of `runs/` with
   `recover --run-id R --archive`.
3. `process_status: unknown` -> check live QEMU processes with `pgrep -af qemu-system` for the run's
   `root.qcow2` path, stop only a verified match, and move manually. Never delete lock files under
   `locks/`.

See [docs/controller.md#blocked-stands-and-recovery](docs/controller.md#blocked-stands-and-recovery)
for full details.

## Offline tests in CI

`.github/workflows/vm-matrix.yml` runs the offline test suite without KVM on two runners:

```sh
python -m unittest discover -s tools/vm/matrix/tests -t .
```

- **Ubuntu 24.04 (Python 3.13, stand version):** runs the full controller, lab, Linux, Windows
  controller, and evidence tests (skips only the ~18 PowerShell-only tests when `pwsh` is absent),
  plus a validation pass over every `execution*.example.toml` configuration.
- **Windows 2025 (Python 3.11):** runs all schema, assessment, Windows PowerShell producer/AST
  tests, and cross-platform evidence tests; Linux-only QEMU controller tests (`lifecycle.start`,
  `/proc`, pidfd, 107-byte `AF_UNIX` control sockets, `st_ctime` identity checks) are explicitly
  skipped via `tests/posix_only.py`. Windows stays on Python 3.11 because Python 3.13 on Windows
  reports `st_ctime` differently for open file descriptors versus paths.
- **PowerShell syntax/AST checks:** `pwsh -NoProfile -File tools/vm/windows/tests/Test-RosetunScriptArguments.ps1`
  verifies all PowerShell scripts under `tools/vm/`.
