# Linux VM Runners, Catalogs, and Legacy Hyper-V/SSH Stand

> **Primary VM test path:** Autonomous Linux matrices with independent wire-level leak observation
> run in the isolated QEMU/KVM lab — see [../matrix/docs/LINUX.md](../matrix/docs/LINUX.md)
> (`linux-l2`, `linux-l3`, `linux-proxy`, `linux-l5`, `linux-l4`, `linux-reboot-smoke`).
>
> - Opt-in [owner-prepared Python/QGA L2 path](../matrix/docs/LINUX.md#owner-prepared-linux-l2-execution-stage-5a)
> - Opt-in [QGA infrastructure smoke delivery](../matrix/docs/LINUX.md#bounded-smoke-delivery-over-qga-stage-4b3)
>
> The Hyper-V/SSH harness below (`Invoke-LinuxL2Matrix.ps1`, `RosetunLinuxVm.psm1`) is a **legacy
> stand** retained for manual checks and owner parity comparison.

## Build target note

Builds here intentionally target **Debian 13**, including WSL clones and L5 `.deb` packages
(`--stand-debian13`). They validate Debian 13 only. Portable Linux releases are compiled and
packaged on **Debian 12 (glibc 2.36)** in the pinned container defined in
`.github/workflows/release.yml` (see `installer/README.md` for local Docker/Podman reproduction).

## Directory contents

| Path | Purpose |
| --- | --- |
| `guest/lab-entry.py` | Isolated QEMU lab VM router, fixtures, and `AF_PACKET` observer entry point |
| `guest/run-{l2,l3,l4,l5,proxy,reboot-smoke,smoke}.sh` | Autonomous guest matrix runners (shared by QEMU lab and Hyper-V) |
| `guest/{start.sh,launch.sh,lib.sh,install-launcher.sh,stage-l2.py,stage-smoke.py}` | Guest staging, media import, `systemd-run` dispatcher, and lab marker helpers |
| `scenarios*.tsv` | Authoritative scenario catalogs: L2 (34), L3 (63), Proxy (47), L4 (27), L5 (17), reboot-smoke (3) |
| `build-artifacts.sh`, `build-in-wsl.sh`, `l2_test_artifacts.py` | Stage artifact builders (`--l2`, `--l3`, `--proxy`, `--l4`, `--deb`) and `provenance.json` generator |
| `prepare-l3-image.py` | Helper for preparing Linux QEMU lab/test images |
| `Invoke-LinuxL2Matrix.ps1`, `RosetunLinuxVm.psm1`, `stand.example.psd1` | Legacy Hyper-V/SSH orchestration harness |
| `tests/` | Offline unit and harness tests (no VM required) |

## Evidence categories (L2)

| Evidence | Scenarios | Meaning |
| --- | --- | --- |
| `transport-fixture` | `credentials.*`, `untrusted-server.*`, `exclusivity.*`, `stale.*`, `occupied.*` | Real Unix-socket transport and `SO_PEERCRED` via `l2_transport_fixture` |
| `helper-unit-stub-backends` | `unit.server-*`, `unit.helper-*` | Helper policies and `Server` lifecycle with stub backends |
| `ipc-unit-tests` | `unit.ipc-*` | IPC unit tests in unprivileged temporary directories |
| `infrastructure` | `preflight.*`, `stale.verified-removal` | Stand preflight and cleanup checks |
| `not-run` | `missing-group.refusal` (L2), `two-hop.*` (L3/Proxy) | Optional/unimplemented on this stand; always reported `SKIP` |

## Offline tests (no VM, no privileges)

```sh
python3 -m unittest discover -s tools/vm/linux/tests -p 'test_l2_test_artifacts.py'
bash tools/vm/linux/tests/selftest-lib.sh
bash tools/vm/linux/tests/selftest-smoke.sh
```

```powershell
pwsh -NoProfile -File tools/vm/linux/tests/Test-LinuxHarness.ps1
```

## Legacy Hyper-V/SSH quick start

The legacy harness drives a separate Debian 13 Hyper-V VM over SSH using a local git-ignored
`tools/vm/linux/stand.local.psd1` copied from `stand.example.psd1` (pinned VM name, `l2-clean`
checkpoint, guest SSH host key, `l2admin` key, and launcher installed via
`guest/install-launcher.sh`):

```powershell
.\tools\vm\linux\Invoke-LinuxL2Matrix.ps1 -Run
```

Add `-Stage L3`, `-Stage Proxy`, `-Stage L4`, or `-Stage L5` for the higher stages. Every `-Run`
restores the clean checkpoint, builds or verifies owner-staged artifacts against `provenance.json`,
uploads them over SSH, dispatches the detached `systemd` unit, collects `report.json` +
`status.json`, and validates the report.

## Recovery from an interrupted Hyper-V run

If SSH is unavailable after an interrupted run, use the Hyper-V VM console:

1. Log in as `l2admin` and inspect the unit: `systemctl status rosetun-l2-<run-id>.service`.
2. Stop it if still active (`sudo systemctl stop rosetun-l2-<run-id>.service`); `ExecStopPost`
   writes the final report and runs cleanup.
3. Check `/var/lib/rosetun-l2/<run-id>/report/report.json` (`cleanup` section) and inspect
   `/run/rosetun` or `pgrep -a l2_transport_fixture` if cleanup reported an error.
4. For a full clean reset, run the next `-Run` (which restores `l2-clean` first).
