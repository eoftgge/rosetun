# Rosetun Developer & Test Tools

This directory contains the VM test infrastructure, image builders, release tooling, site scripts,
performance utilities, and git hooks for Rosetun.

## Directory overview

| Directory | Purpose | Documentation |
| --- | --- | --- |
| `vm/matrix/` | **Primary VM test controller:** isolated two-VM QEMU/KVM lab, wire-level leak observer, Linux & Windows autonomous matrices, offline plan/report assessor, and deterministic release evidence packs | [vm/matrix/README.md](vm/matrix/README.md) |
| `vm/windows-image/` | Reproducible offline Windows 11 QEMU image & OVMF firmware builder (UEFI, Secure Boot, TPM 2.0, noise reduction) | [vm/windows-image/README.md](vm/windows-image/README.md) |
| `vm/windows/` | Windows guest runners & check catalogs used by `vm/matrix/`, plus legacy Hyper-V PowerShell Direct harnesses and offline PowerShell tests | [vm/windows/README.md](vm/windows/README.md) |
| `vm/linux/` | Linux guest runners (`run-l2..l5.sh`, `run-proxy.sh`, `lab-entry.py`), scenario TSV catalogs, Debian 13 artifact builders, and legacy Hyper-V/SSH harness | [vm/linux/README.md](vm/linux/README.md) |
| `release/` | Release bundle assembly and minisign signing scripts | [release/README.md](release/README.md) |
| `site/` | Static website build, link/content verification, and Zola installer | [site/README.md](site/README.md) |
| `perf/` | PresentMon GUI frame-presentation benchmark (`Measure-RosetunPresents.ps1`) | [perf/README.md](perf/README.md) |
| `arch/` | Arch Linux `PKGBUILD` update and validation helpers (`update-pkgbuild.sh`, `check-package.sh`) | — |
| `hooks/` | Local git hooks (`pre-commit`, `commit-msg`, `pre-push`, `check-range.sh`) | — |

## VM test infrastructure

Rosetun's kill switch, Lockdown, DNS lock, system proxy, LAN, upgrade, multi-protocol, and two-hop
proxy chain guarantees are exercised in isolated virtual machines:

- **QEMU/KVM isolated two-VM lab ([vm/matrix/README.md](vm/matrix/README.md)):** connects a
  disposable `test` VM (Linux or Windows) to a disposable `lab` VM (router, VPN nodes, DNS/DoH,
  HTTPS target, two-hop B-hop proxy, DHCP server, and `AF_PACKET` wire observer) over a private
  `AF_UNIX` socketpair with no host network exposure. Supports offline CI tests
  (`.github/workflows/vm-matrix.yml`) and deterministic release evidence packs
  ([vm/matrix/docs/EVIDENCE.md](vm/matrix/docs/EVIDENCE.md)).
  - Controller, leases, recovery, and schemas: [vm/matrix/docs/CONTROLLER.md](vm/matrix/docs/CONTROLLER.md)
  - Two-VM lab topology, observer, and fixtures: [vm/matrix/docs/LAB.md](vm/matrix/docs/LAB.md)
  - Linux suites (`linux-l2`, `linux-l3`, `linux-proxy`, `linux-l5`, `linux-l4`, `linux-reboot-smoke`): [vm/matrix/docs/LINUX.md](vm/matrix/docs/LINUX.md)
  - Windows smokes & matrices (`windows-list`, `windows-failure`, `windows-lockdown`, `windows-proxy`, `windows-lan`, `windows-upgrade`, `windows-protocols`, `windows-twohop`): [vm/matrix/docs/WINDOWS.md](vm/matrix/docs/WINDOWS.md)
- **Legacy Hyper-V harnesses ([vm/windows/README.md](vm/windows/README.md), [vm/linux/README.md](vm/linux/README.md)):**
  PowerShell Direct (Windows) and SSH (Linux) scripts retained for manual checks and owner parity
  comparison against the QEMU lab.

## Quick offline verification

```sh
# Cross-platform VM matrix unit tests (Linux & Windows)
python3 -B -m unittest discover -s tools/vm/matrix/tests -t .

# PowerShell argument-mode lint across all scripts in tools/vm/
pwsh -NoProfile -File tools/vm/windows/tests/Test-RosetunScriptArguments.ps1
```
