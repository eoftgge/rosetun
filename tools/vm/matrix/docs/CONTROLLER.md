# Controller, Leases, Lifecycle, and Schemas

This document covers the host-side controller architecture in `tools/vm/matrix/`: stand leases,
resource ledgers, crash recovery, run-state persistence, QEMU/QGA lifecycle, planned reboots and
power cuts, image verification, and offline plan/assessment schemas.

For the suite catalog and CLI overview, see [../README.md](../README.md).

## Local stand leases and resource ledgers

`resources.py` manages stand exclusivity, run manifests, and completion checks without executing a
matrix. Every worker sharing a stand must pass the same **absolute local state directory** and
case-sensitive `stand_id`. Network filesystems, UNC paths, mapped drives, and symlink/reparse
ancestors are rejected.

```text
<state-directory>/
  locks/<sha256-of-stand-id>.lock   # permanent lock file; never delete or rotate
  image-digests/                    # cross-process Windows disk digest cache (0700/0600)
  runs/<run-id>/
    manifest.json                   # rosetun.matrix.resources.v1
    run-state.json                  # rosetun.matrix.run-state.v1
    lifecycle.jsonl                 # append-only bounded lifecycle journal
    completion.json                 # rosetun.matrix.completion.v1
    execution-summary.json          # suite summary
    qmp.sock, qga.sock, control.lock
    <registered run-local files>
  archive/<run-id>/                 # reconciled runs moved by `recover --archive`
  archive/<run-id>.archive.json
```

- **Leasing (`StandLease`):** holds a nonblocking OS lock (`fcntl.flock` on POSIX, `msvcrt.locking`
  on Windows). Another contender fails with `stand is already leased`. Lock files are permanent;
  process exit releases the OS lock but never marks resources cleaned.
- **Unresolved runs block reuse:** after acquiring the stand lock, any prior run in `runs/` without
  a verified `completion.json` blocks new runs (`stand has unresolved runs`). An unreadable or
  corrupted manifest blocks every stand because ownership cannot be established.
- **Manifest (`rosetun.matrix.resources.v1`):** exact fields `schema`, `run_id`, `stand_id`,
  `owner_token`, `state`, `resources`, `reasons`. States: `preparing`, `prepared`, `starting`,
  `running`, `stopping`, `exited`, `error`, `quarantined`. Updates use an exclusive temporary file,
  `fsync`, and atomic rename. Unknown fields, duplicate JSON keys, and malformed JSON fail closed.
- **Owner tokens:** random 256-bit local ownership markers (not cryptographic isolation against
  same-user processes). Never copy `owner_token` into logs, reports, or evidence packs.
- **Resource entries:**
  - `file` (`id`, `kind`, `path`): relative slash-separated paths inside the run directory; rejects
    `..`, backslashes, drive/UNC prefixes, symlinks, alternate data streams, tildes, DOS device
    names, and case-only duplicates. Register before creating the file.
  - `socket` (`id`, `kind`, `path`): UNIX control sockets (`qmp.sock`, `qga.sock`, `swtpm.sock`),
    registered before spawn.
  - `process` (`id`, `kind`, `pid`, `platform`, `boot_id`, `start_id`, `executable`): captures host
    boot ID and OS creation identity (`/proc/<pid>/stat` start ticks on Linux, creation FILETIME on
    Windows) directly from the created process. PID alone is never sufficient.

## Blocked stands and recovery

`runs` and `recover` inspect `<state-directory>` read-only (never creating directories or printing
owner tokens). For each run, `recover` reports its state, reasons, and `process_status` (Linux
`/proc/sys/kernel/random/boot_id` and `/proc/<pid>/stat`):

- `absent`: host rebooted, PID does not exist, or start time differs (reused PID). A run with no
  process record is `absent` only if it could not have spawned one (`prepared`, `error`, or
  `quarantined` without a `start intent` row in `lifecycle.jsonl`).
- `alive`: the exact recorded process is still running.
- `unknown`: check could not be made (non-Linux, unreadable `/proc`, or a run with no process
  record in `starting`/`running`/`stopping`/`exited` or `quarantined` after `start intent`).

Recovery actions:

- **Archive a finished or `absent` run:**
  ```sh
  python3 -B -m tools.vm.matrix recover --state-directory STATE --run-id RUN_ID --archive
  ```
  Acquires the stand lock, moves `runs/<RUN_ID>` to `archive/<RUN_ID>`, and writes
  `archive/<RUN_ID>.archive.json`. Never deletes files, never signals processes, and refuses
  `alive`, `unknown`, `run-manifest-invalid`, or existing archive targets.
- **Close a live run with named sockets (Stage W+):**
  ```sh
  python3 -B -m tools.vm.matrix recover --state-directory STATE --run-id RUN_ID --close
  ```
  Verifies host boot, PID/start time via pidfd, and QMP `query-uuid`, sends QMP `quit`, reaps or
  observes exit of QEMU (and `swtpm` for Windows runs), marks `run-state.json` `quarantined`
  (`closed-by-recover`), and writes verified `completion.json` (`returncode: null` paired with
  `exit exit-observed`). Exit 0 on verified close, 1 on refusal, 2 on unverified close.
- **Manual fallback for `unknown` or pre-Stage-W runs:** inspect with `pgrep -af qemu-system` for
  the run's `root.qcow2` path, stop the verified process manually, confirm `absent`, then archive
  (or move manually if `unknown`).

## Run state on disk and reattach (Stage W)

A dying controller (SSH drop or kill) leaves QEMU running on named sockets so a new process can
close or finish it:

- **Control channels:** QEMU listens (`server=on,wait=off`) on `runs/<id>/qmp.sock` and `qga.sock`
  inside a `0700` run directory with umask `0177` (`0600` sockets). Socket paths exceeding 107 bytes
  or containing commas are refused before launch — keep `state_directory` short.
- **Single controller:** an OS lock on `runs/<id>/control.lock` prevents concurrent controllers
  (`run-control-locked`). Process death releases it automatically.
- **`run-state.json` (`rosetun.matrix.run-state.v1`):** written atomically by `evidence.py` with
  `phase` (`preparing`, `running`, `collecting`, `closing`, `completed`, `quarantined`), `step`
  (`intent`/`done`/`error`), up to 256 `transitions`, `identities` (including `boot_chain`),
  `host.boot_id`, absolute `deadlines`, `budgets`, `job`, `owner_digest`, `configuration_sha256`,
  `controller.commit`, and `attachments`.
- **Reattach (`attach`):**
  ```sh
  python3 -B -m tools.vm.matrix attach --state-directory STATE --run-id RUN_ID
  ```
  Supported for non-lab `run linux-l2` and `run linux-l3` runs after step `submit`. Lab runs and
  Windows suites are not attachable (`attach-lab-run-not-resumable` / `run-not-attachable`); use
  `recover --close`. Attached summaries set `attached: true`; qualification and release evidence
  packs require `attached: false`.
  Refusal reasons (exit 2, no changes): `stand-locked`, `run-control-locked`,
  `vm-process-not-alive`, `vm-process-identity-mismatch`, `host-boot-changed`, `qmp-uuid-mismatch`,
  `controller-version-mismatch`, `attach-phase-not-resumable`, `attach-lab-run-not-resumable`,
  `run-already-finished`, `run-not-attachable`.

## Bounded QEMU lifecycle, QGA, reboots, and `power_cycle`

### Base lifecycle and budgets

The controller launches QEMU paused (`-S`), verifies `query-uuid` over QMP, enforces strict
resource/RPC budgets recorded before spending, and closes with bounded escalation (ACPI power-down,
QMP `quit`, signals).

| Resource / counter | Base limit | With `planned_reboots = n` |
| --- | --- | --- |
| `qmp_calls` | 128 (last reserved for `quit`) | 128 |
| `qmp_events` | 128 | 128 |
| `qmp_bytes_o` / `qmp_bytes_i` | 1 MiB each (64 KiB steps) | 1 MiB each |
| `qga_calls` (per session) | 128 | 128 |
| `qga_recoveries` | 4 (+ `planned_session_rotations` where configured) | `4 + n` |
| `qga_observations` | 32 | `32 + 12 * n` |
| `job_calls` | 112 | 112 |
| `job_polls` | 4 | 4 |

### Planned guest reboots (Stage 8c)

Suites with `planned_reboots > 0` (`linux-reboot-smoke`: 1, `linux-l4`: 2; Windows Lockdown also
uses planned reboots alongside power cuts) track resets via QMP `RESET` (`guest: true`):

- `Vm.watch_resets()` polls events every 2 s (`WATCH_SECONDS`) without spending QMP calls.
- Multiple QEMU `RESET` events emitted within `RESET_MERGE_US` (1 s from the first reset, up to
  `RESET_MERGE_LIMIT = 4` merged events) while the new boot is unconfirmed coalesce into one reboot
  (`guest-reset-coalesced`).
- Any unexpected reset terminates the run (`LifecycleError`, exit 2): `unplanned-guest-reset`,
  `host-reset-outside-reset`, `guest-reset-before-first-boot`, `guest-reset-merge-limit`,
  `guest-reboot-unobserved`.
- `await_rebooted_guest` acquires a fresh QGA session (up to 12 attempts, 5 s apart, 180 s ceiling)
  and appends the new boot ID to `Vm.boot_chain`. Unchanged (`guest-reset-boot-id-unchanged`),
  repeated (`boot-id-repeated`), or reset-free (`boot-id-changed-without-reset`) changes fail closed.

### Hard power cuts (`power_cycle`, Stage 10c)

`lifecycle.Vm.power_cycle()` simulates abrupt power loss inside a single run (used by
`windows-lockdown`) within a strict `planned_power_cuts` budget:

- Sends `SIGKILL` to the `test` QEMU process and terminates its paired `swtpm`, records
  `power-cycle-N` in `run-state.json`, closes old QMP/QGA handles, and restarts `swtpm` + QEMU on
  the same `root.qcow2` overlay, `OVMF_VARS.fd`, `tpm/` state, `vm_uuid`, and `windows-media.iso`.
- Registers each new generation in `manifest.json` as `qemu-N` / `swtpm-N` (appending stderr to
  `qemu-stderr.log`); `lifecycle.attach()` selects the highest generation so `recover --close`
  works after power cycles.
- The lab wire relay (`_WireRelay`) is length-prefixed and reconnectable on the `test` side while
  keeping the `lab` capture continuously open.

## Image descriptors and disk digest cache

- **Image descriptors (`rosetun.matrix.image.v1`):** pin disk size, SHA-256, and platform fields.
  Linux runs use `guest_os: "linux"` (`pc-i440fx-10.0`, SeaBIOS). Windows runs use
  `images.WindowsImageDescriptor` (`guest_os: "windows"`, profile `windows-uefi-q35-v1`) which
  strictly validates UEFI firmware code/vars, TPM files, CPU enlightenments, PCI slots, and fixed
  MAC `00:00:5e:00:53:61`. `activated` and `qualified` must both be `false` (diagnostic only).
- **Cross-process disk digest cache (`STATE/image-digests/`):** avoids re-hashing ~12+ GB Windows
  base images on every run. Entries (`0600` in `0700` dir, no symlinks, <= 4 KiB) key on all five
  stat attributes: `(device, inode, size, mtime_ns, ctime_ns)` plus exact path and descriptor
  SHA-256. Any mismatch triggers a full streaming SHA-256 pass and atomic cache rewrite. Both pre-run
  and post-run `image-unchanged` checks enforce this rule. Small Linux images are hashed every time.

## Offline configuration, plans, and assessment schemas

Offline `plan` and `report` commands operate on local files without a VM:

```sh
python3 -B -m tools.vm.matrix plan linux-l4 --config matrix.local.toml --profile exploratory > plan.json
python3 -B -m tools.vm.matrix report saved/report.json --plan plan.json
```

- **Planning config (`example.toml`):** integer `schema = 1`, `profiles.<name>.mode` in
  `{"exploratory", "release"}`, optional paired `run_id` and `boot_id` copied from an independent
  staging record. Unbound plans (`run_id`/`boot_id` absent) are inspection-only and cannot accept a
  report.
- **Plan (`rosetun.matrix.plan.v1`):** `suite`, `profile`, `policy`, `planned_reboots` (2 for L4, 0
  for other assessed suites), ordered 6-field `catalog` (`id`, `required`, `evidence`, `group`,
  `detail`, `title`), and `catalog_digest` (SHA-256 of compact sorted-key ASCII JSON, order
  significant). Assessment never reloads the current TSV in place of the saved plan.
- **Linux input (`schema: 1`):** requires `report.json` (`run_id`, `guest.boot_id`,
  `guest.boot_id_at_end`, `scenarios`, `summary`, `cleanup.status`; plus `guest.boot_ids` for L4)
  and adjacent `status.json` (`run_id`, `state: "finished"`). Execution statuses are strictly
  `PASS`, `FAIL`, `SKIP`, `ERROR` (`UNVERIFIED` is rejected in legacy inputs).
- **Assessment (`rosetun.matrix.assessment.v1`):** contains `execution`, `validation`, `rows`,
  `legacy_verdict`, `invariant` (always `UNVERIFIED`), `cleanup`, `coverage` (`none`/`partial`/
  `complete`), `acceptance` (`release` always `false`), and `sources` (SHA-256 of raw files). Raw
  files are never modified and free-form raw reasons are omitted.

### Aggregation rules and regression correspondence

- Rejects unknown schemas/statuses, duplicate JSON keys, non-finite numbers, missing/duplicate/
  unknown scenario IDs, required `SKIP`, relabelled evidence, or `not-run` with `PASS`.
- Recomputes summary counts from raw rows; any `FAIL` is preserved ahead of `ERROR`, then missing
  execution (`UNVERIFIED`), then required `SKIP` (`legacy_verdict` keeps `ERROR` before `FAIL` for
  compatibility).
- Cleanup must be `PASS`; a successful execution never overrides failed or missing cleanup.
- **Release acceptance is never granted:** security-invariant verification stays `UNVERIFIED` and
  `acceptance.release` is always `false`.
- `tests/test_matrix.py` maintains full regression correspondence with `Test-LinuxHarness.ps1`
  (complete/partial reports, missing/unfinished status, foreign run/boot IDs, L4 boot-chain cases,
  dropped/duplicate/unknown/relabelled rows, lying summaries, cleanup/schema errors, strict JSON,
  and CLI exit codes).
