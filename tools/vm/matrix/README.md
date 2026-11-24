# VM matrix foundation

Python 3.11+ and the standard library are sufficient for offline work. Run
commands from the repository root. The CLI reads local files and writes JSON
to stdout. Explicit lifecycle/QGA Python APIs also support owner-controlled VM
operations; the limited L2 execution path is described below. Existing legacy
matrices remain supported. Internal QEMU qualification does not establish
network protection or scenario/release acceptance.

## Offline tests in CI

`vm-matrix.yml` runs `python -m unittest discover -s tools/vm/matrix/tests -t .`
on ubuntu-24.04 (Python 3.13, the stand's version) and on windows-2025
(Python 3.11). Windows stays on the floor of the tools because 3.13 there reports
`st_ctime` differently for an open file and for a path, and the Linux-only file
identity checks (`linux_l2._hash`, `images.verify_bytes`) compare both.

The QEMU controller runs on Linux alone (KVM, AF_UNIX control sockets under a
path of at most 107 bytes, pidfd), and the temporary directory of a Windows
runner is already longer than that. A test that goes through the real
`lifecycle.start` or opens such a socket is skipped there, with
`tests/posix_only.py` giving the reason, instead of weakening the path check.
The Windows helpers (`windows_*`, the PowerShell producers) are not skipped.

Windows skips 339 of 1784 tests, a Linux host with `qemu.qmp` 18 (the Windows
pieces it cannot run without PowerShell). On Windows, besides those that need
Linux `/proc`, bash, POSIX-only fixtures or `qemu.qmp`, the skipped ones are the
controller groups:

- `lifecycle.start` and what is built on it: `test_lifecycle`, `test_jobs`,
  `test_staging`, `test_qga_recovery`, `test_reboots` (chains, budgets, waits),
  `test_linux_l2`, `test_l2_media` (import), `test_lab_controls`, the joint
  start of two machines in `test_l3_lab`, `test_lab` and `test_lab_evidence`
  (disk pairs), the delivery groups of `test_stage_profiles`, the start, attach and
  smoke groups of `test_windows_run`, `test_windows_reboot` and `test_image_digest_cache` (stand-in QEMU and swtpm
  processes, `st_ctime`), and the start of the Windows guest on the lab's wire in `test_windows_lab`;
- tests that take those fixtures to look at evidence bytes: `test_evidence`
  (journals, owner token), `test_orchestrator` (reservation);
- the relay budget over an AF_UNIX socket pair in `test_run_state`;
- one test that reads the Linux stand's example paths in `test_reboots`.

## When a stand is blocked

A run that did not reach a verified completion keeps its stand locked:
`run` and the lease refuse with "stand has unresolved runs". One run whose
manifest cannot be read blocks every stand.

`python -m tools.vm.matrix recover --state-directory D` only reads. For each run
it prints the state, the reasons and `process_status`, the result of comparing
the recorded VM process with the host (`/proc/sys/kernel/random/boot_id` and
the start time in `/proc/<pid>/stat`; Linux only):

- `absent`: another boot, no such PID, or a different start time (a reused
  PID). A run that recorded no process is `absent` only if it could not have
  started one: state `prepared` or `error`, or `quarantined` with no
  `start intent` row in `lifecycle.jsonl` (no journal at all counts).
- `alive`: the same process is still running.
- `unknown`: the check could not be made (unreadable `/proc`, not Linux, a
  Windows process record). A run with no process record is `unknown` in every
  other case (`starting`, `running`, `stopping`, `exited`, `quarantined` with
  a `start intent` row, an unreadable or oversized journal): QEMU is recorded
  only after it is spawned, so a controller that died in between leaves a
  live QEMU and no record of it.

`recover --state-directory D --run-id R --archive` moves one run with
`absent` to `archive/R` in the same state directory and writes
`archive/R.archive.json` (previous state and reasons, the status of each
process, UTC time, no owner token). It first takes the stand's OS lock, so it
refuses while a controller is alive, and it refuses if `archive/R` exists.
Afterwards the stand can be leased again. A run that completed with verified
evidence is archived the same way.

`--archive` does not delete anything, does not stop or signal any process and
does not touch a run whose manifest is unreadable or belongs to another run
(the refusal is `run-manifest-invalid`); those stay a manual case. Refusals
print `archived: false` and a `reason`, and change nothing.

On `alive` the VM is still running and holds the overlay. For a run started
with named control sockets (stage W and later), `recover --state-directory D
--run-id R --close` quits it and records completion, or `attach` carries the
run on (see "Stage W: run state on disk and reattach"). For an older run, stop
that QEMU yourself (the controller is gone, so nothing else will), check that
`recover` now shows `absent`, then archive. On `unknown` establish the
process state by hand first. For a run with no process record, run
`pgrep -af qemu-system` and look for the run's `root.qcow2` path in a command
line. If one matches, it is that run's VM: stop it, then archive by hand
once no such process is left. If none matches, the run has no VM; move it out
of `runs/` yourself, since `--archive` refuses `unknown`.

## Stage W: run state on disk and reattach

A run no longer lives only in its controller's memory. A controller that dies
(an SSH drop to the stand, a kill) leaves QEMU running; a new process can find
the run, connect to it and finish it.

### Channels

- QMP and QGA are UNIX sockets that QEMU listens on (`server=on,wait=off`):
  `runs/R/qmp.sock` and `runs/R/qga.sock`. The run directory is created 0700,
  QEMU runs with umask 0177 so the sockets are 0600, and both are checked
  (owner, mode, socket type, no symbolic link) before every connection. Both
  paths are registered in `manifest.json` as resources of kind `socket` before
  QEMU starts. A path longer than 107 bytes or with a comma is refused before
  launch: keep the state directory short.
- One controller at a time: it holds an OS lock on `runs/R/control.lock` from
  before the spawn until completion. A second controller is refused
  (`run-control-locked`); the stand lock refuses it earlier (`stand-locked`).
  The lock goes with the process, so a dead controller never blocks.
- A new agent session is a new connection to `qga.sock`; QEMU serves one client
  per socket, so the old session is closed first. The lab wire between two
  machines is unchanged: it is a data link, not a control channel.
- QEMU's stderr goes to the controller that started it. After that controller
  dies, `qemu-stderr.log` ends there; QEMU ignores the broken pipe.

### `run-state.json`

Schema `rosetun.matrix.run-state.v1`, written only by `evidence.py`, replaced
atomically on every change (a scratch file `run-state.<random>.tmp` that a dead
controller leaves behind is kept and never blocks the next write). Fields:

- `phase`: `preparing`, `running`, `collecting`, `closing`, then `completed`
  (verified completion) or `quarantined` with `reason`; `step` is the last
  step with `status` `intent`, `done` or `error`; `transitions` keeps every one
  (at most 256). Each controller step is written as an intent before it runs
  and as done or error after it. A step left at intent is unknown.
- `identities`: host run, guest run, import, lab, VM UUID, guest boot ID (the last of `boot_chain`).
- `boot_chain`: the boot IDs the controller confirmed, in order (stage 8c); a file without it is read with its one boot.
- `host.boot_id` and `deadlines` (`job_deadline`, `wait_until`) as absolute
  times on the host's real-time clock.
- `budgets`: what the run has spent, recorded before it is spent:
  `qmp_calls` (128, the last one reserved for `quit`), `qmp_events` (128),
  `qmp_bytes_o`/`qmp_bytes_i` (1 MiB each way, recorded in 64 KiB steps),
  `qga_recoveries` (4, and one more for each planned guest reboot), `qga_observations` (32), `job_calls` (112), `job_polls`
  (4). QGA calls (128) and QGA relay bytes stay per session, as before; every
  new session is a counted recovery. The lifecycle journal counts its own rows.
- `job`: submission, launcher and job state, guest PID, session.
- `owner_digest` (SHA-256 of the owner token, as in `completion.json`),
  `configuration_sha256`, `controller.commit` (the checkout's commit, or null),
  `attachments`.

No passwords, keys or node addresses; the owner token never appears.

### Commands and exit codes

`python -m tools.vm.matrix attach --state-directory S --run-id R` carries on a
`run linux-l2` or `run linux-l3` (not `--lab`) whose controller died after the
job was submitted (step `submit` or later). It takes the stand under a recovery
lease (which never creates a run), checks the recorded QEMU (pid, host boot and
start time, again through a pidfd), takes the run lock, connects to `qmp.sock`
and compares `query-uuid`; then opens one agent session (a recovery), rebuilds
the job from `linux-<stage>/plan.json`, `package.json` and the run state, waits
(by reading the job's status, stage 8c) until `wait_until`, collects (at most the polls left) and closes. A run killed
while closing is only closed; an assessment already saved is read back, never
collected again. The summary carries `attached: true` and `attachments`; the
exit code is the one the original command would have given (0 accepted, 1 not
accepted, 2 error or unverified completion, 130 interrupted). An ordinary run's
summary carries `attached: false`, `attachments: 0`. **A qualification step
of this README requires `attached: false`** until the owner decides otherwise.

Refusals print `attached: false`, `refused: <reason>` and exit 2, and change
nothing: `stand-locked`, `run-control-locked`, `vm-process-not-alive` (the
recorded process is gone or its pid now belongs to another process),
`vm-process-identity-mismatch`, `host-boot-changed`, `qmp-uuid-mismatch`,
`controller-version-mismatch` (attach with the commit that started the run),
`attach-phase-not-resumable` (died before submission: use `recover --close`),
`attach-lab-run-not-resumable`, `run-already-finished`, `run-not-attachable`.

`recover --state-directory S --run-id R --close` connects the same way, sends
`quit`, waits for the exit through the pidfd and records completion. The run
state ends `quarantined` with `closed-by-recover`, the summary gains that error
and `attached: true`, and the ledger ends verified, so the stand is free:
exit 0. A refusal prints `refused` and exits 1; a close that did not verify
exits 2. An attached controller is not QEMU's parent: the exit status is not
observable, so `completion.json` records `returncode: null` after an `exit
exit-observed` journal row (accepted only together).

### For the owner

No new descriptors and no image changes: nothing to reinstall. Runs started
before this stage have no sockets: `--close` refuses them (`run-not-attachable`)
and the old manual way applies.

## Owner-prepared Linux L2 execution (stage 5a)

`linux_l2.LinuxL2Job` runs the existing L2 Bash checks through the installed
launcher and QGA. It requires an original live `Vm` with QGA enabled, its live
lease and an independently observed Linux boot. It does not build or deliver
artifacts. This pre-staged Python API remains available alongside the stage 5c
execution CLI described at the end of this document.

The owner prepares a disposable Linux x86-64/systemd image with qemu-guest-agent,
the installed `/usr/local/libexec/rosetun-l2/launch` matching the selected checkout,
the stand marker `/etc/rosetun-l2-stand-id`, group `rosetun` and two distinct
ordinary non-admin accounts in that group. QGA runs as root and permits
`guest-sync-delimited`, `guest-info`, `guest-ping`, `guest-file-open`,
`guest-file-read`, `guest-file-close`, `guest-exec`, `guest-exec-status`.
No SSH, WSL, Windows or Hyper-V is required for this orchestration. No network
device, firewall exception, dependency installation or image modification is
performed by this API. Image, agent, installed launcher and controller remain
trusted; boot observation is not attestation.

Before creating the job, the owner supplies already built Linux artifacts and
places the verified complete package at
`/root/rosetun-l2-stage/<guest-run-id>` in that VM, after observing its current
boot. Choose a new legacy-format guest run ID for every job. Retain the same
package on the controller at an explicit absolute local path. Its exact files are:

```text
guest/launch.sh
guest/start.sh
guest/lib.sh
guest/run-l2.sh
scenarios.tsv
job.env
artifacts/l2_transport_fixture
artifacts/rosetun_helper_privileged_tests
artifacts/rosetun_ipc_tests
artifacts/provenance.json
manifest.sha256
```

Only `guest` and `artifacts` directories are allowed. Files must be regular,
without symlinks/reparse points, including ancestors. The manifest lists each
payload file once with lowercase SHA-256 and two spaces; it excludes itself.
Each binary is limited to 512 MiB and stream-hashed in 1 MiB blocks. Other files
are limited to 256 KiB. Scripts and TSV must match the selected checkout's
LF-normalized legacy staging bytes. ELF checks require little-endian x86-64
executables/PIE. Provenance schema/target, artifact hashes, source SHA, boolean
dirty state and legacy status/diff digest must match the selected checkout.
This confirms agreement with recorded metadata, not cryptographic proof that
those sources produced the binaries. The legacy dirty digest does not hash
untracked file contents. The owner must independently trust artifact origin.

`job.env` has exactly the nine legacy L2 fields: `RUN_ID`, `STAND_ID`,
`EXPECTED_BOOT_ID`, `USER_A`, `USER_B`, `BIOS_GUID`,
`SCENARIO_TIMEOUT_SECONDS`, `UNIT_TIMEOUT_SECONDS`, `JOB_TIMEOUT_SECONDS`.
Use plain unquoted safe values, distinct account names and canonical nonzero
UUIDs. `STAND_ID` must match the live stand lease. `BIOS_GUID` is the configured QEMU VM UUID; the guest retains the exact
legacy DMI comparison (including its existing SMBIOS byte-order handling).
The guest still checks the stand marker, actual DMI, boot, systemd, accounts,
group, absence of foreign service/process and free endpoint. Host validation
does not replace these checks. Scenario/unit timeouts are 10..86400 seconds;
this API limits job timeout to the legacy CLI's 60..7200 seconds (default 900).

With `vm` already started and observed by the owner:

```python
from tools.vm.matrix.linux_l2 import LinuxL2Job

job = LinuxL2Job(vm, enabled=True,
                 package_directory='/absolute/owner-package',
                 checkout='/absolute/selected-checkout')
job.submit()
# After allowing the autonomous job to finish, explicitly collect:
outcome = job.collect()
# After a lost channel, on the same live controller only:
# vm.recover_guest()
# outcome = job.collect()  # Never submit again.
```

The constructor saves `linux-l2/plan.json` before submission: guest run ID as
assessment `policy.run_id`, independent QGA boot ID as `policy.boot_id`, full
catalog snapshot and digest. `package.json` and the shared `job-evidence.jsonl`
retain the mapping **host run ID / guest run ID / stand ID / VM UUID / boot ID**,
package hashes/sizes and provenance. `lifecycle.start` registers all fixed L2
evidence files before entering running state. No running ledger registration is
opened. A VM can own either a smoke job/package or one L2 job.

Submission freshly probes QGA and reads boot ID, persists intent, then issues
one `guest-exec` with the fixed launcher path and three validated arguments:
guest ID, fixed stage directory and manifest digest. No shell command string
is sent. An uncertain exec response leaves submission unknown; there is no
automatic resubmit. The existing `start.sh` uses autonomous `systemd-run` with
`ExecStopPost` cleanup/finalization. Controller crash recovery is not provided.

Collection exposes only this run's `report/status.json` and `report/report.json`;
there are no arbitrary paths or extra diagnostics. The one exception is the L3
profile: it also reads the service journal `run-l3.sh` saves as
`report/helper-journal.txt` (its last 400 lines, written before the report), as a third,
optional file of at most 256 KiB, read the same way and saved as
`linux-l3/<n>/helper-journal.txt` (a place for each of the four attempts is reserved
before the VM runs). It is read after the status and the report agree and before the
last boot check, and it is evidence only: a guest that has no such file, or one over the
limit (the first 256 KiB and one byte are kept, and the journal says so), changes neither the
assessment nor the verification. A transport failure while reading it fails the attempt like
any other. The L2 collection does not read it. Collection first requires a finished
status with matching guest run/boot, reads the report, then requires identical
finished status bytes and another fresh QGA boot check. The legacy producer
publishes report once under a finalization lock, then publishes finished status;
a report appearing before finished is insufficient. A changed boot fails closed.
Launcher status is polled only in its original QGA session; after recovery it
remains unknown if its exit was not observed; a known exit result is preserved.
Recovery does not reset job deadline or counters and never
implicitly repeats an uncertain exec/open.

Limits are separate from smoke: 32 KiB reads, 8 KiB per status, 256 KiB per report,
at most ten report reads, four explicit collection attempts and 112 job RPCs
(the last reserved for known-handle closure). The existing 128-RPC session and
1 MiB relay limits remain unchanged and may stop collection earlier. Boot/probe
RPCs count toward the job budget. The deadline is creation time plus configured
job timeout plus 180 seconds for the existing 120-second systemd stop/cleanup
and collection. Every RPC is at most five seconds and honors that absolute
deadline. No waiting loop or automatic channel recovery is introduced; the
owner chooses when to spend each of the four collection attempts. A known
handle is closed in finally while the channel/deadline/budget permit; otherwise
closure stays unconfirmed. No unknown open is retried within an attempt.

Strict base64/count/EOF checks reject malformed reads, empty non-EOF progress,
oversize and excessive block counts. Per-attempt `linux-l2/<n>/{status,report,
status-after}.json` retain received raw bytes (including a single overflow
detection byte), with SHA-256, size and complete/partial markers in the journal,
before JSON parsing or assessment. Files from earlier attempts remain retained.
The final `assessment.json` comes from the unchanged `report.assess()`;
`report.assess_files()` can also read each saved report with the saved plan.
Only complete, consistent pairs are assessed. Parsing, transport and boot errors
leave assessment absent and verification UNVERIFIED.

`snapshot()` separates submission, launcher, L2 terminal state, report validation,
scenario assessment and overall `accepted`. A known launcher failure prevents
overall acceptance even if assessment alone accepts its supplied report.
Assessment retains guest cleanup, scenario execution and exploratory acceptance;
FAIL, ERROR, mandatory SKIP, missing/duplicate scenarios, foreign run/boot,
summary disagreement and unsuccessful cleanup cannot be accepted. VM completion
is a separate lifecycle contract and cannot make a failed L2 successful.
Security invariants stay UNVERIFIED and release gate stays false. L2 covers IPC,
credentials, endpoint behavior and related unit tests; it proves no network leak
absence, TUN, nftables or Lockdown behavior. L3/L4/L5/Proxy are not migrated.

Offline tests use inert ELF headers, synthetic legacy reports and fake QGA.
Run `python -B -m unittest tools.vm.matrix.tests.test_linux_l2 -q` and the existing
matrix tests/legacy self-tests. Separate real L2 qualification passed on
2026-11-11 on the existing Debian 13/WSL2 KVM stand, using source/artifacts from
`88d05d55f05c72cbc2a6a9ab0826486f8b3efa8a` (recorded clean build checkout),
Rust 1.96.0, QEMU/qemu-ga 10.0.13, pc-i440fx-10.0, qemu.qmp 0.0.6,
host Python 3.13.5, guest kernel 6.12.115+deb13.1-amd64 and systemd 257.13.
The owner separately authorized the build, package preparation and real VM runs.
No images or dependencies were downloaded or installed. Seven already cached
Cargo archives were reused locally after Cargo.lock checksum verification;
the build ran with `CARGO_NET_OFFLINE=true`.

Five fresh overlays covered normal Python/QGA execution, a dropped real exec PID
reply before the relay forwarded it, a stopped agent after the first report
block, changed boot rejection, and direct legacy launcher execution through an
independent serial console. The four completed L2 runs each produced 33 PASS,
one optional `missing-group.refusal` SKIP and cleanup PASS. Every retained report
was 9,500 bytes. A qualification-only RPC wrapper requested 4 KiB blocks from
the real agent to exercise multi-block collection (three blocks per report);
production's 32 KiB request size and limits were unchanged. The read-loss case
retained its first 4,096 bytes and unconfirmed handle evidence, then recovered
the same boot and collected without resubmission. The lost exec reply left
submission unknown and recovered only through saved results. Deadlines were
unchanged. Each completed unit had one journal start and independent console
checks confirmed the endpoint and fixture absent. A new QGA-observed boot
rejected collection even though VM completion subsequently succeeded.

All five final VMs and one earlier diagnostic VM had verified completion, child
reap and closed local sessions/endpoints; the stand was reused. The original
base remained 476,774,400 bytes with SHA-256
`f4a05e7aba2c889437f6bce798926a381b7ebf257178e75d140493f817b74de8`.
Packages were manually copied through the independent console from a temporary
read-only 9p share into each overlay. This is qualification setup, not an L2
delivery API. The earlier diagnostic attempt retained a DrvFS UID through
`cp -a`; explicit root ownership in the guest fixed placement without changing
launcher checks. Its overlay, interrupted-run evidence and completion remain
retained separately.

The direct legacy and Python/QGA runs used the same catalog, scripts and
binaries on equivalent fresh stands. Per-ID comparison matched required flags,
evidence, groups, expectations, actual results and successful cleanup; raw
reasons are retained separately. Original PowerShell and Python assessment
also agreed on all 34 rows in all four complete real reports. This qualifies
that limited launcher/Bash/result comparison. Full legacy Hyper-V/SSH host
orchestration parity remains UNRUN. Unknown guest-handle closure, controller
restart, power-loss durability and other images/builds remain unqualified;
release gate stays false and security invariants UNVERIFIED.

Evidence is retained under git-ignored
`tools/vm/logs/qga-5a-qualification-20261111/`: build provenance and local-cache
reuse record, qualification harness, `real-2/qualification-results.json`,
`real-2/scenario-comparison.json`, `real-2/legacy-assessment-comparison.json`,
serial logs and per-run ledger/QGA/job/raw-result/completion evidence. Production
source hashes were checked against the qualified commit. Linux offline checks:
245 Python tests (18 platform skips), 35 targeted tests without skips,
legacy shell self-test 122/122 and smoke shell self-test PASS. The earlier smoke
qualification remains separate from these actual L2 results.

Manual qualification by the owner:

1. Independently verify artifact provenance and prepare the image/accounts/stand
   marker/launcher above. Observe `vm.observe_guest()`, then manually place a
   fresh package bound to its VM UUID and boot; retain the matching host package.
2. Use the API above once; let the configured job finish and collect. Retain plan,
   package, raw report/status, job/QGA journals and separate VM completion evidence.
   Acceptance requires all 33 mandatory IDs with matching evidence and cleanup.
3. On a separate fresh job, interrupt the agent channel, then explicitly call
   `vm.recover_guest()` and `job.collect()`. Confirm same boot, one launcher
   invocation, retained partial evidence and unchanged deadline. A changed boot
   or unknown exec must never trigger resubmission.
4. Compare saved legacy and Python-path runs by each ID below, required flag,
   evidence, actual result/reason and cleanup, with matched checkout/artifacts and
   equivalent clean stands. Send back all saved evidence and version/image data
   for discrepancies. Equal PASS counts do not establish parity. The limited
   real comparison above does not establish full Hyper-V/SSH orchestration parity.

Large artifact delivery remains manual and is the next stage; smoke delivery is
unchanged. The scenario mapping below refers to the same unchanged `run-l2.sh`
producer and TSV in both paths, not a second implementation of the checks.

| Scenario ID (legacy = Python) | Required in both | Evidence in both | Producer in both |
|---|---|---|---|
| `preflight.identity` | yes | `infrastructure` | `run-l2.sh` |
| `preflight.accounts` | yes | `infrastructure` | `run-l2.sh` |
| `preflight.no-foreign-service` | yes | `infrastructure` | `run-l2.sh` |
| `preflight.endpoint-free` | yes | `infrastructure` | `run-l2.sh` |
| `credentials.endpoint-directory` | yes | `transport-fixture` | `run-l2.sh` |
| `credentials.socket-mode` | yes | `transport-fixture` | `run-l2.sh` |
| `credentials.owner-uid` | yes | `transport-fixture` | `run-l2.sh` |
| `credentials.spoofed-hello` | yes | `transport-fixture` | `run-l2.sh` |
| `credentials.endpoint-env-ignored` | yes | `transport-fixture` | `run-l2.sh` |
| `credentials.other-uid` | yes | `transport-fixture` | `run-l2.sh` |
| `credentials.root-uid` | yes | `transport-fixture` | `run-l2.sh` |
| `credentials.clean-exit` | yes | `transport-fixture` | `run-l2.sh` |
| `untrusted-server.client-refused` | yes | `transport-fixture` | `run-l2.sh` |
| `untrusted-server.no-bytes-sent` | yes | `transport-fixture` | `run-l2.sh` |
| `exclusivity.second-bind-refused` | yes | `transport-fixture` | `run-l2.sh` |
| `exclusivity.inode-unchanged` | yes | `transport-fixture` | `run-l2.sh` |
| `exclusivity.original-still-serves` | yes | `transport-fixture` | `run-l2.sh` |
| `exclusivity.original-clean-exit` | yes | `transport-fixture` | `run-l2.sh` |
| `stale.restart-refused` | yes | `transport-fixture` | `run-l2.sh` |
| `stale.socket-preserved` | yes | `transport-fixture` | `run-l2.sh` |
| `stale.verified-removal` | yes | `infrastructure` | `run-l2.sh` |
| `occupied.regular-file-preserved` | yes | `transport-fixture` | `run-l2.sh` |
| `occupied.symlink-preserved` | yes | `transport-fixture` | `run-l2.sh` |
| `unit.server-shutdown-without-clients` | yes | `helper-unit-stub-backends` | `run-l2.sh` |
| `unit.server-shutdown-full-client-limit` | yes | `helper-unit-stub-backends` | `run-l2.sh` |
| `unit.server-shutdown-preserves-replacement` | yes | `helper-unit-stub-backends` | `run-l2.sh` |
| `unit.helper-uid-policies` | yes | `helper-unit-stub-backends` | `run-l2.sh` |
| `unit.helper-shutdown-non-admin` | yes | `helper-unit-stub-backends` | `run-l2.sh` |
| `unit.ipc-untrusted-server-before-write` | yes | `ipc-unit-tests` | `run-l2.sh` |
| `unit.ipc-drop-preserves-replacement` | yes | `ipc-unit-tests` | `run-l2.sh` |
| `unit.ipc-drop-preserves-foreign-objects` | yes | `ipc-unit-tests` | `run-l2.sh` |
| `unit.ipc-symlink-directories` | yes | `ipc-unit-tests` | `run-l2.sh` |
| `unit.ipc-unsafe-directories` | yes | `ipc-unit-tests` | `run-l2.sh` |
| `missing-group.refusal` | no | `not-run` | `run-l2.sh` |

`missing-group.refusal` is optional because it requires a separate clean VM without group `rosetun`; the stand never removes or renames that group.


## Optional Linux QGA observation (stages 4a and 4b.1)

Set `QemuConfig(..., qga=True)` explicitly before `prepare`. Omitted/false keeps
legacy launch plans unchanged. `start` adds a second listening socket in the
run directory, `-chardev socket,id=guestagent,path=<run>/qga.sock,server=on,wait=off`,
`-device virtio-serial-pci,id=guestserial` and
`-device virtserialport,bus=guestserial.0,chardev=guestagent,name=org.qemu.guest_agent.0`.
Only the two child descriptors are inherited; parent copies of child ends close
immediately after spawn. QMP and QGA own separate streams and states. No TCP
listener or guest network is added (`-nic none` remains). `start` confirms QMP
only and does not wait for the agent in the initially paused VM.

Source compatibility review used released QEMU 9.2.0/10.0.0 protocol schemas,
with the 10.0.0 [socket backend](https://github.com/qemu/qemu/blob/v10.0.0/chardev/char-socket.c),
[serial bus](https://github.com/qemu/qemu/blob/v10.0.0/hw/char/virtio-serial-bus.c),
[PCI device](https://github.com/qemu/qemu/blob/v10.0.0/hw/virtio/virtio-serial-pci.c)
and [port device](https://github.com/qemu/qemu/blob/v10.0.0/hw/char/virtio-console.c).
These define fd-backed connected sockets, the controller/bus and named chardev
port. This is source review, not runtime qualification of an installed build.
The owner must pin and qualify the exact QEMU/qemu-img, versioned machine, BIOS,
kernel and agent package; the earlier synthetic QMP qualification of 10.0.13
is not QGA qualification. Other releases need another compatibility review.

`qga.Qga` exposes `connect(timeout)`, `probe(timeout)`, `read_boot_id(timeout)`
and `close()`. Only the fixed boot ID path is exposed. The released
[qemu.qmp 0.0.6 public API](https://gitlab.com/qemu-project/python-qemu-qmp/-/blob/v0.0.6/qemu/qmp/qmp_client.py)
provides `await_greeting=False` and `negotiate=False` specifically for QGA.
The adapter never sends a monitor greeting or qmp_capabilities. The library does
not implement the QGA sentinel synchronization. A narrow preflight sends 0xFF
and guest-sync-delimited with a random 63-bit ID, discards stale bytes, resets its
partial parser on each sentinel, and accepts only the matching integer response.
It reads one byte at a time to avoid consuming the following library data;
this phase has one deadline and a 64 KiB total budget. Regular JSON framing,
request IDs and RPC errors then belong to the library, over the existing bounded
byte relay (64 KiB buffers, 1 MiB per direction). No library internals are used.

All calls are serialized outside an existing asyncio loop. Each RPC timeout is
finite and at most 60 seconds; a session permits at most 128 RPCs. Probe validates
`guest-info` types and all required commands, including enabled and
success-response flags, before ping or file access. Read uses mode `r`, validates
an integer handle, strict base64, byte count, boolean EOF, a 64-byte total bound
and canonical nonzero Linux UUID. It closes a known handle in finally when the
stream remains usable. After any uncertain exchange (including timeout) the
session is poisoned: no late reply is consumed by another operation and no
operation is automatically retried. Confirmed RPC rejections remain distinct from uncertain exchanges, so a rejected
read still attempts file-close. The 128th RPC is reserved for a known handle
close; local budget exhaustion cannot consume that slot. A timed-out open/read/close can leave an
unconfirmed guest handle until the agent/guest is restarted. Completion confirms
host controls closed and child reaped; it does not prove guest handle closure.

`Vm.observe_guest()` connects once, probes and reads boot_id. It records run ID,
VM UUID, QGA session ID, UTC, result, agent version/required capabilities and boot
ID in bounded `qga-observations.jsonl` (at most 32 observations). Owner tokens
are neither sent to the guest nor written to this journal. `guest_observation`
is the latest successful observation, cleared before a failed attempt or reset.
Ping establishes agent availability only, never Rosetun or whole-OS readiness.
Boot ID is an in-guest observation, not cryptographic attestation.

Reset invalidates QGA even when RESET confirmation fails. Subsequent
`observe_guest()` calls explicitly fail until `recover_guest()` creates a new
session. RESET, sync and ping cannot confirm a new boot. See stage 4b.1 below.
QGA loss cannot block QMP control or killing/reaping the owned child.
QGA close failure blocks completion and stand reuse; completion verification
requires the last QGA closure entry after the final child reap and before
completion for opt-in plans. Pending launch socket ends remain owned by the VM
until their closure is confirmed, including startup error paths. The shared byte
relay checks every owned endpoint after its worker stops; a stopped thread alone
is insufficient closure evidence. Thread-start failure closes the newly created
relay socket pair.

The owner supplies a minimal prepared Linux x86-64 BIOS image with kernel
`CONFIG_VIRTIO_CONSOLE`/virtio-console support, installed qemu-guest-agent and an
enabled service using virtio-serial at
`/dev/virtio-ports/org.qemu.guest_agent.0`. Its RPC allowlist must include exactly
the operations required here: `guest-sync-delimited`, `guest-ping`, `guest-info`,
`guest-file-open`, `guest-file-read`, `guest-file-close`. File-open permission in
the agent is generally broader than the fixed path this controller exposes.
QGA usually runs privileged inside the guest: trust the image, agent and local
controller. Record image origin, distro/kernel/agent versions, preparation steps,
size and SHA-256 in owner evidence and retain the matching image descriptor.
The stage 4a API does not provision, download or modify a base image. The manual
qualification fixture below was prepared separately with owner authorization.
The released [agent configuration](https://github.com/qemu/qemu/blob/v10.0.0/docs/interop/qemu-ga.rst)
and [RPC schema](https://github.com/qemu/qemu/blob/v10.0.0/qga/qapi-schema.json)
define the port, allowlist and synchronization requirements.

Partial owner-authorized qualification on 2026-11-11: Debian 13/WSL2,
qemu.qmp 0.0.6 from an existing environment, QEMU 10.0.13 and
`pc-i440fx-10.0`, with KVM accessible as root. A diskless VM accepted the exact
two fd-backed channels and virtio devices above. With no guest OS/agent, QGA
synchronization failed as expected while QMP still reported running; forced
kill/reap and closure of both child endpoints, both parent streams and adapters
were confirmed. No image, disk or guest network was used. This checks device
parameters and channel independence only. Real qemu-ga, Linux guest boot_id,
reset/reobservation, guest-service stop and firewall/Lockdown were UNRUN at that
point; the subsequent real-guest results follow below.
Completion is covered by offline lifecycle tests, not this diskless experiment.
Installed-library synthetic peers also exercise successful QGA RPCs and a
confirmed read rejection followed by file-close; they do not run qemu-ga.

Real Linux guest qualification on 2026-11-11 used the same QEMU/qemu.qmp/KVM
versions, Debian 13 nocloud build `20261103-2651`, kernel
`6.12.115+deb13.1-amd64`, systemd `257.13-1~deb13u1` and guest-agent package
`1:10.0.13+ds-0+deb13u1`. The official
[Debian Cloud image](https://cloud.debian.org/images/cloud/trixie/latest/debian-13-nocloud-amd64.qcow2)
was downloaded and checked against its published HTTPS SHA512SUMS. Its copy was
prepared offline using chroot apt with service starts suppressed, the six-RPC
allowlist above, fixed locale/timezone/hostname and a disabled interactive
first-boot wizard. No host packages were installed; downloads, guest packages,
images, caches and evidence were stored on D:.

The prepared compressed qcow2 is 476774400 bytes, SHA-256
`f4a05e7aba2c889437f6bce798926a381b7ebf257178e75d140493f817b74de8`.
This is an isolated qualification image with root serial autologin, not a
production guest image. Only the qualification launcher adds an independent
fd-backed ISA serial console to the production launch arguments; it adds no
NIC, SSH transport, QGA guest-exec or custom guest agent. The existing
`prepare/start/observe_guest/reset/hard_off` APIs and completion validator run
against real children and real qemu-ga, without fake RPC responses.

Two final scenarios passed:

- Boot, probe and repeated boot_id observation: agent version/capabilities were
  accepted, and the QGA UUID matched `/proc/sys/kernel/random/boot_id` read via
  the independent serial console. Only loopback appeared in the guest.
- Agent stop via the serial console: systemd confirmed inactive; subsequent
  QGA observation failed, QMP still confirmed running, and hard_off reaped the
  owned child. Both scenarios confirmed controls closed, valid completion,
  stand lease reuse and unchanged base-image bytes. Owner tokens were absent
  from launch arguments, observations and completion reports.

The boot scenario also confirmed RESET and invalidation: the API returned
`qga-unavailable-recovery-unsupported`, and the prior observation remained
cleared. The serial console independently observed a different boot_id after
reset. **QGA did not observe or confirm that new boot**; same-VM QGA recovery
was unsupported in stage 4a. Initial provisioning and serial-harness failures are
retained with the local evidence; the final rerun passed after correcting the
interactive first-boot setup and console buffering/CR-LF handling.

Local evidence and the prepared image are retained under the git-ignored
`tools/vm/logs/qga-4a-qualification-20261111/`: `provenance.json`,
`image-descriptor.json`, `qualification-results.json`, preparation/qualification
scripts, serial logs and per-run lifecycle/completion files. Private resource
manifests contain owner tokens and must not be published. No Rosetun scenario,
controller-loss durability or firewall/Lockdown qualification was performed.
Firewall and Lockdown settings were not changed.

Stage 4a results above are historical; they do not qualify the stage 4b.1
implementation below. The separate stage 4b.1 qualification is recorded below.

### Explicit recovery with the original live controller (stage 4b.1)

`vm.recover_guest()` closes the old client, creates a fresh session, performs
`guest-sync-delimited`, validates capabilities and reads boot_id again. It is
allowed only for the active owned VM under its original live StandLease and
process. `observe_guest()` never recovers implicitly. Controller crash recovery,
attachment to another process and autonomous guest jobs are unsupported.

VM retains the original connected QGA endpoint without reading it. Every Qga
owns a separate `dup()`; ByteRelay owns that duplicate and an internal socketpair.
QMPClient receives only the relay's client socket through its public API.
Disconnect closes the library stream; relay close stops and joins its worker
and closes every endpoint. Pending asyncio tasks must stop before the loop can
close. An uncertain disconnect or relay closure blocks replacement. VM final
close closes the session and retained endpoint before recording aggregate QGA
closure for completion; any endpoint error blocks completion and stand reuse.
QMP ownership and configurations without QGA retain their existing behavior.

Duplicates share input/output queues and OS blocking flags: they are not separate
channels. There is at most one reader, guarded against overlapping observe,
recover, reset and close calls. Each sync explicitly restores timeout mode after
the prior relay's nonblocking mode. No shutdown is used on the VM endpoint;
library disconnect operates only on its isolated relay socketpair. See the
[pinned protocol source](https://gitlab.com/qemu-project/python-qemu-qmp/-/blob/v0.0.6/qemu/qmp/protocol.py).
All lifecycle calls still require serialization by the caller.

There are at most four recovery attempts, including failed replacements, and
32 observation/replacement records total per VM. At most five sessions each
allow 128 RPCs, 64 KiB sync input and 1 MiB per relay direction; recovery never
resets the VM counters. Each observation/recovery has one deadline for sync,
probe and file operations (at most 60 seconds); old-session teardown additionally
has bounded disconnect, worker-join and task-cancellation waits of one second
each. Time spent closing the old session consumes the recovery deadline.
Every replacement uses a fresh session UUID and distinct 63-bit sync ID within
the VM. Stale replies, partial JSON and old sync IDs are discarded before the
new library reader starts. The protocol relies on the agent processing its
ordered stream; it does not authenticate a malicious guest.

After timeout the old operation remains uncertain and is never replayed.
Recovery makes a new observation, which may open a new boot_id handle; it does
not prove that a previously lost guest handle was closed. Agent restart may
retain the same boot_id. `previous_boot_id` preserves the last successful
observation; `reset_boot_id` preserves the baseline at reset. Current
`guest_observation` is cleared on reset or failure. `boot_comparison` is same,
changed, or unknown if no baseline existed. Only changed relative to an observed
pre-reset ID sets `new_boot_confirmed`; a same ID keeps reset confirmation
pending. Availability and boot identity do not establish application readiness
or scenario PASS. Journals record operation, attempt, reason, old/new session,
boot IDs and comparison, excluding the owner token. Failed recovery leaves QGA
unavailable while QMP and owned-child hard_off remain available.

Real Linux recovery qualification on 2026-11-11 (local time) passed on the
same prepared Debian 13 base and QEMU 10.0.13 / pc-i440fx-10.0 / KVM stand as
stage 4a, using qemu.qmp 0.0.6 and Python 3.13.5 in Debian WSL2. No packages
were installed. The qualification launcher adds only the independent fd-backed
ISA serial console used in stage 4a; QGA clients, duplicates, relay, library,
VM process and completion checks are real.

Confirmed in one original live controller and lease:

- Initial QGA boot_id matched the independent serial console. The guest had
  loopback only, with `-nic none` and no added network or firewall exception.
- RESET invalidated observation; explicit recovery returned a new session and
  a different QGA boot_id matching the console, with `new_boot_confirmed=True`.
- Agent stop through the console caused QGA timeout with live QMP. Agent restart
  followed by explicit recovery returned a new session and the same boot_id,
  without rebooting Linux.
- A further recovery with the agent stopped failed explicitly; QMP still
  reported running and hard_off reaped the child. All four session duplicates,
  reader loops/relay workers and the retained VM endpoint were confirmed closed.
- Completion validated; another lease/run started and completed on the same
  stand. Both runs have verified completion. The base remained 476774400 bytes,
  SHA-256 `f4a05e7aba2c889437f6bce798926a381b7ebf257178e75d140493f817b74de8`.
  Owner tokens were absent from argv, public journals and completion reports.

Linux offline checks passed: all 69 targeted QGA/QMP/lifecycle/recovery tests
ran without skips, including the installed-library sequential-session peer;
all 181 foundation tests passed with 18 platform-specific skips. Local evidence
is retained in git-ignored `tools/vm/logs/qga-4b1-qualification-20261111/`:
`qualify.py`, `qualification-results.json`, serial log and per-run state.
The results record the initial HEAD and SHA-256 of each production control
module under test. Manifests remain private because they contain owner tokens.
This qualification proves neither closure of an unknown guest handle nor
controller-crash recovery, autonomous jobs, Rosetun scenario acceptance or
firewall/Lockdown protection. Those capabilities remain unqualified.

Owner repeat qualification on another prepared Linux image/build:

1. Record exact QEMU, qemu.qmp, kernel and agent versions, image descriptor and
   base SHA-256. Prepare with `QemuConfig(..., qga=True)`, then `vm = start(run)`,
   `vm.resume()`, `first = vm.observe_guest()`. Compare boot_id with an independent
   serial console and retain the observation journal.
2. Run `vm.reset()`, then explicitly `row = vm.recover_guest()` once the agent
   is available (each failure consumes one of four attempts). Require a different
   QGA boot_id and `row['new_boot_confirmed'] is True`; confirm it via console.
   A same ID or unknown comparison does not qualify a new boot.
3. Via the independent console run `systemctl stop qemu-guest-agent`; require
   `vm.observe_guest()` to fail and `vm.status()` to remain available. Start the
   service with `systemctl start qemu-guest-agent`. Add no management network.
4. Run `row = vm.recover_guest()` without rebooting the OS. Require a new session
   ID, successful capabilities/boot observation and the same boot_id as step 2.
5. Stop the agent again, require `vm.recover_guest()` to fail explicitly, then
   check `vm.status()` and run `vm.hard_off()`. Require child reap and all host
   controls closed. Unknown guest handles must remain reported as uncertain.
6. Validate `completion_verified(run.directory, run._read())`, release the lease,
   acquire a new StandLease and create another run. Recheck base size/SHA-256.
   Retain sanitized journals, completion and provenance; report exact failing
   operation and observed IDs on mismatch. Firewall/Lockdown and Rosetun scenario
   acceptance require separate qualification and receive no PASS here.

Before designing the next stage (autonomous guest job and retained results),
read `tools/vm/linux/guest/launch.sh` and `tools/vm/linux/guest/start.sh`: staged
file validation and systemd launch already exist. Do not duplicate them without
an explicit justification.

Offline fake adapter tests and the optional installed-library synthetic peer test
are not tests of real qemu-ga. No security scenario gets PASS from agent
availability. Stage 4b (autonomous guest jobs and retained results after controller
loss) is not implemented; this stage makes no controller-loss durability claim.

## Bounded QEMU lifecycle (stage 3c.1)

Execution is an internal Python API on Linux x86-64/KVM only, BIOS/i440fx,
network disabled. The CLI remains read-only and requires only Python 3.11+.
Execution optionally requires **qemu.qmp==0.0.6**, pinned in
`requirements-qmp.txt`. Nothing installs it automatically. Fake adapter tests
and CLI imports work without it. The upstream library requires Python >=3.8,
has no mandatory runtime dependencies, uses asyncio internally and marks its
0.0.x API alpha: upgrades require a new API review and integration qualification.
Its [public library code](https://gitlab.com/qemu-project/python-qemu-qmp/-/blob/v0.0.6/qemu/qmp/__init__.py)
is LGPL-2.0-or-later; distribution metadata also lists GPLv2 for bundled tools.
This adapter does not import legacy/deprecated interfaces or copy upstream code.

`qmp_adapter.Qmp` uses public `QMPClient.connect(connected_socket)`, `execute`,
`listener`, the extensible `EventListener.accept` hook and `disconnect`. JSON framing, request IDs and
protocol negotiation belong to the library. Since stage W, QEMU listens on
`qmp.sock` and `qga.sock` in the private run directory and the controller
connects (it no longer inherits one end of a socket pair); a bounded byte-only
relay adds no listener. The relay caps each buffer at 64 KiB and each direction
at 1 MiB per run; exceeding the budget closes the channel. QMP has a 64 KiB read
limit, at most 128 commands and 128 observed events per run, whichever
controller spends them (recorded in `run-state.json`). The library forbids removing its default listener;
its public accept hook counts all events and declines default retention, keeping
that history empty. Operation listeners are temporary. Buffered replies are
forwarded before a peer's EOF is propagated.
The synchronous facade owns one event loop: call it serially outside another
running event loop. Timeout arguments are finite, positive and <=60 seconds.
Cancellation/disconnect and relay shutdown are bounded; failure to confirm control
closure blocks completion. Package exceptions become safe reason codes.

`start(run, timeout=5)` revalidates the saved plan, base and image chain, starts
an owned child with `-S`, records Linux process identity and checks UUID, KVM and
prelaunch status. This is monitor readiness, never guest readiness. There is no
TCG, WHPX or HVF fallback. `status`, `pause` and `resume` retain their API;
pause/resume confirm query-status. Operation semantics:

- `reset()` subscribes before sending system_reset and requires RESET as well as
  the command response. It does not establish guest boot or a new guest boot ID.
- `request_shutdown(timeout=...)` sends ACPI and waits a bounded time for the own
  child to exit and be reaped, then closes controls and saves completion. A timeout
  raises and remains an operation error even if later `close()` succeeds.
- `powerdown()` preserves its old request-only meaning. Migrate callers requiring
  exit confirmation to `request_shutdown`; a reply is not guest shutdown.
- `hard_off()` sends no ACPI or quit; it kills/reaps only the original Popen child.
  This is not physical power removal from the host disk subsystem.
- `close()` attempts QMP quit, bounded wait, terminate/wait and kill/wait. QMP EOF,
  a reply and a SHUTDOWN event cannot substitute for child wait/reap. Completed
  close is idempotent. Interruptions propagate after bounded teardown attempts.

Before spawn the ledger registers `qemu-stderr.log`, `lifecycle.jsonl` and
`completion.json`. stderr uses an unbuffered pipe and bounded reader: 256 KiB of
input is retained, further data is drained/discarded with an overflow flag. Its
working memory is one 4096-byte read plus a token-sized redaction tail. Owner tokens
are redacted across chunk boundaries. Overflow/read errors fail observed operations;
reader close/join cannot wait indefinitely. Raw stderr is local evidence and is
never automatically included in public reports. Other secrets may still occur
in external output: sanitize it independently before sharing.

The versioned lifecycle JSONL records UTC, run/stand/VM identity, sequence,
intents, command acceptance, event/process observations and operation outcomes.
Operation errors survive teardown; evidence-write failures independently quarantine
resources. Exit confirmation is separate from successful evidence persistence.

A new StandLease can reuse a stand only when every prior run on it has a valid
`rosetun.matrix.completion.v1` contract written by the original owner under its
live lease. Validation requires exited state, full resource/identity agreement,
return codes for every registered process, closed controls, retained regular files,
and a digest of a complete identity-matched v2 lifecycle journal ending in
completion. The saved plan UUID must agree. A bare exited state, old ledger,
missing/partial/unknown completion, starting/running/stopping, quarantine or invalid
manifest blocks reuse. Invalid manifests with no established owner block all stands.
These local consistency checks cannot defeat malicious edits by the file owner.
No PID from a manifest is signalled, no age-based release or automatic recovery
is implemented, and no files are deleted. Failed/unconfirmed exits retain the
in-memory lease guard; reaped children with failed evidence leave blocking ledger.

Offline validation uses fake public adapters and fake children. When the pinned
package and Unix sockets are available, an additional test exercises the actual
library against a synthetic peer, including RESET before the command reply and
absence of default event retention; otherwise that test is explicitly skipped.

Stage 3c.1 was manually checked on Debian 13/WSL2, Python 3.13.5,
qemu.qmp 0.0.6, QEMU/qemu-img 10.0.13, SeaBIOS 1.16.3 and `pc-i440fx-10.0` on
KVM. Seven scenarios passed: RESET confirmation, shutdown timeout followed by
close, ACPI shutdown using a synthetic real-mode boot sector, hard-off without
ACPI, QMP disconnect, stderr overflow/token redaction, and completion/reuse.
The boot sector only enables/polls the PM1 power-button bit and requests S5;
it is not a Linux guest, guest runner or transport. The stderr overflow case
injects bytes into the owned stderr pipe from the host; it does not claim that
QEMU generated those bytes. All seven children were reaped, controls/reader
threads closed, bases unchanged, overlays retained and no owned listeners seen.
New leases/runs succeeded after verified completion; deliberately incomplete
new runs and corrupted proof remained blocking. The expected shutdown timeout
remained an operation error. TCG was not used. These are local integration
results for the pinned synthetic fixtures, not real-image or security evidence.

Remaining owner qualification includes real guest ACPI behavior, Rosetun
readiness, controller crash, hardware/storage failures and a wider
QEMU/kernel/platform combination. None is inferred from the synthetic results.
Owner qualification on an isolated Linux/KVM host:

1. Independently provision the pinned library, trusted QEMU/BIOS and image; keep
   state private. Prepare a new run and start under the same original lease.
2. Confirm prelaunch, resume/pause, RESET before/after command reply, normal ACPI
   shutdown, shutdown timeout followed by close, hard-off and QMP disconnect.
   Verify command/event/child-exit observations separately, including stderr limits.
3. Confirm child reap, closed controls and complete evidence; acquire a fresh lease
   and create a new run while old disks/logs remain. Missing/corrupt completion,
   evidence-write failures and an unconfirmed child must block reuse. Keep private
   manifests; share only sanitized journals, diagnostics and observed discrepancies.

The following result is **historical, before stage 3c.1** and does not qualify
this new adapter, shutdown/reset semantics or completion/reuse contract:

A local owner-authorized check on Debian 13 under WSL2, QEMU/qemu-img 10.0.13,
SeaBIOS 1.16.3 and `pc-i440fx-10.0` passed on an empty synthetic qcow2 disk:
prelaunch, resume/pause, reset/powerdown requests, QMP disconnect, early child
exit, and bounded forced kill. All four owned children were reaped; base bytes
were unchanged, overlays retained, live lease release refused and no owned TCP
or listening Unix socket observed. KVM was confirmed enabled through QMP; TCG
was not used. This checks process/monitor lifecycle only. No guest OS was booted,
and no real image, security behavior or production stand is qualified by it.

## QEMU disk and launch preparation (stage 3b)

`images.py` and `qemu.py` provide an internal preparation API, separate from the
reporting TOML profiles. There is no VM run command. `prepare(run, image, config)`
requires an empty `PreparedRun` created under its original live `StandLease`.
It can execute **qemu-img only**, using explicit argv without a shell. Supplying
`executor=` replaces external commands for offline tests. The preparation API never invokes QEMU; lifecycle execution is separate.

`ImageDescriptor` has exactly the constructor fields `schema`
(`rosetun.matrix.image.v1`), `identifier`, `guest_os` (`linux`), `architecture`
(`x86_64`), absolute local `path`, physical `size_bytes`, lowercase `sha256`,
`format` (`qcow2`) and `profile` (`bios-i440fx-v1`). Obtain the expected size and
digest independently from the trusted image provenance. No image is downloaded.
The base must be a regular file outside the run directory, without symlink or
reparse ancestors. Keep it offline and immutable throughout preparation and any
future lifecycle. The API checks bytes before and after image operations; it does
not protect against a malicious concurrent writer or establish image provenance.

`QemuConfig` fields are `schema` (`rosetun.matrix.qemu.v1`), absolute local
`executable`, `image_executable`, `bios`, a versioned `machine` matching
`pc-i440fx-N.N`, `accelerator` (`kvm`), `cpu` (`host`), `memory_mib` (256..65536,
default 1024), and `vcpus` (1..64, default 1). The three paths must name regular
files. The owner supplies a SeaBIOS binary and an available machine type from the
chosen installation; this profile does not qualify UEFI or Secure Boot. There
are no writable firmware variables. Other architectures, firmware profiles and
accelerators, including TCG fallback, are rejected. Preparing fixtures on Windows
does not imply that KVM can run there. No host-capability probe is implemented.
Spaces and Unicode paths are supported. Commas and control characters are
rejected before external commands, including in the state directory. Traversal,
UNC/network paths on Windows, and symlink/reparse ancestors are rejected using
the ledger's local-path rules. POSIX filesystem locality remains the caller's duty.
Windows alternate data streams, reserved device names and trailing dot/space
aliases are also rejected. Size mismatches are rejected before hashing; the
hash read is capped at the declared size plus one byte and checks file identity
and timestamps for changes during the read.

Preparation proceeds serially:

1. Register `preparation.jsonl` and `launch-plan.json` before dangerous operations.
   Validate contracts, paths, base size and SHA-256.
2. Run structured `qemu-img info --output=json --backing-chain -f qcow2`.
   Require one qcow2 base, complete format-specific data, no backing image,
   external data file, encryption, dirty/corrupt flag or internal snapshots.
3. Register `root.qcow2` before `qemu-img create -f qcow2 -F qcow2 -b BASE OVERLAY`.
   Refuse any existing destination. Run directories and UUIDs are unique.
4. Inspect the overlay chain with the same info command. Require exactly the
   overlay and verified base, explicit qcow2 backing format, exact absolute
   backing filenames, matching virtual sizes and no auxiliary storage.
   Recheck base bytes before saving the plan.
5. Save the plan with exclusive creation and fsync. It records the validated
   inputs, UUID and deterministic argv for those inputs. Disk attachment uses
   JSON `-blockdev`, an explicitly read-only base with null backing, and only
   the run overlay as the writable guest disk. Networking is `-nic none` with
   `-nodefaults`; display, monitor, serial and parallel are disabled. No directory
   sharing, physical disk, passthrough device or public listener is configured.

The executor caps each output pipe at 256 KiB and uses a 30-second command timeout,
with bounded kill/reap and pipe-reader joins during teardown. Pipe read errors
also block success. The builder is private to the verified preparation path;
there is no independent public API that treats an arbitrary disk path as verified.
Nonzero exit codes, missing executables, invalid/empty/duplicate-key JSON,
non-UTF-8 JSON, NaN/Infinity, incomplete metadata and unexpected chains block preparation.
QEMU's optional `children` field is accepted only for exactly one `file` child
whose filename is the same container, whose size matches that file rounded to
512 bytes, and whose own children are empty. Its format-specific data must be
an empty `file` record with a clean flag; unknown fields, auxiliary files,
backing children and deeper graphs remain rejected. Diagnostics retain
stage, exact command argv and limits, verified image summaries, return code,
byte counts and safe failure codes, never raw command output, exception strings
or owner tokens. A failure records `error`, or
`quarantined` when an overlay/partial file exists. Files are retained in place;
quarantine does not move or delete them. Diagnostics and plan paths are already
registered, because failed runs cannot register new resources. If ownership or
the lease is lost, further writes stop; the last durable intent remains for
independent recovery. An interrupted plan write may leave partial evidence.
Failure-state updates and failure diagnostics are attempted independently, so
one unavailable evidence file does not prevent retaining the other. Interrupts
retain partial files and propagate after recording the failure when possible.

Never retry in the same run or automatically archive unresolved runs. The stand
remains blocked by the existing ledger recovery policy. This stage adds no
`released` state or cleanup. A saved plan has `executed: false` and
`kvm_qualified: false`; it is neither scenario PASS nor proof of a real qcow2,
successful boot or security-matrix coverage. The separate lifecycle API above
adds execution without automatic resource cleanup; stage 4a above adds optional
QGA observation and stage 4b.1 adds explicit live-controller session recovery.
Guest runners and network laboratories remain outside scope.

Options were checked against the official [qemu-img reference](https://www.qemu.org/docs/master/tools/qemu-img.html),
[invocation reference](https://www.qemu.org/docs/master/system/invocation.html), and
[ImageInfo/QCOW2 QAPI reference](https://www.qemu.org/docs/master/interop/qemu-storage-daemon-qmp-ref.html).
These are moving **master** documents, not a compatibility promise for an
installed release. No QEMU version has been qualified here. Before real use, the
owner must pin the QEMU/qemu-img build, BIOS artifact and machine type, compare
the matching release documentation, and verify its actual JSON fields, JSON
blockdev syntax, options and KVM availability. The strict metadata reader can
reject releases with different or incomplete observations; do not bypass it.

Offline verification (temporary text fixtures and fake command executor):

```powershell
python -B -m unittest tools.vm.matrix.tests.test_qemu tools.vm.matrix.tests.test_qemu_executor tools.vm.matrix.tests.test_resources tools.vm.matrix.tests.test_matrix -q
```

Owner qualification, on a disposable Linux x86-64/KVM host only:

1. Record `/absolute/path/qemu-system-x86_64 --version`,
   `/absolute/path/qemu-img --version`,
   `/absolute/path/qemu-system-x86_64 -machine help` and
   `/absolute/path/qemu-system-x86_64 -accel help`. Pin the artifacts and select
   an explicitly supported versioned i440fx machine. These probes do not prove
   successful KVM execution.
2. Independently verify the trusted base size/digest and the selected SeaBIOS
   artifact. In a private fresh state directory, construct `ImageDescriptor`
   and `QemuConfig` with those exact paths, then call `prepare(create_run(lease),
   image, config)` inside `with StandLease(state_directory, "local-qemu-a") as lease:`.
   Expect three qemu-img calls, preserved base bytes, a two-image chain and a
   preparation-only launch plan. Inspect `manifest.json` privately; never share
   its token. Keep `preparation.jsonl` and `launch-plan.json` for discrepancies.
3. Qualify a failed create on disposable fixtures and verify evidence retention
   and blocked reuse. Use only the lifecycle API above for execution under the
   original lease, never the saved preparation argv directly.

## Local stand leases and resource records

`resources.py` supplies ownership, manifests and completion validation; it never executes a matrix.
Choose an **absolute local state directory** explicitly. All workers that can
touch the same stand must use the same directory and the same case-sensitive
stand ID. Different state directories do not coordinate. Network filesystems
are unsupported; POSIX callers must ensure the selected filesystem is local.
Windows requires a fixed local drive and rejects UNC paths and mapped network
drives. Symlink/reparse ancestors are rejected.

```text
<state-directory>/
  locks/<sha256-of-stand-id>.lock
  runs/<run-id>/
    manifest.json
    <registered run-local files>
    .manifest-<random>   # possible evidence of an interrupted write
```

`StandLease(state_directory, stand_id)` is a context manager. It holds a
nonblocking OS lock on an open handle (`msvcrt.locking` on Windows,
`fcntl.flock` on POSIX). Another contender receives `stand is already leased`.
Lock files are permanent: never unlink, replace, rotate or truncate them outside
the held lease. PID metadata is diagnostic only; no age or PID test releases a
lease. Ordinary exit and process death release the OS lock, but do not establish
resource cleanup. Instances are single-use: re-entry raises, repeated release is
harmless. Mutations require the original live lease. Use this API serially from
one controlling thread; concurrent writers within a lease are unsupported.
A fork child cannot mutate records through an inherited lease. Releasing its
inherited handle does not unlock the parent's lease. Mutations also check that
the lock path still refers to the held file; replacement fails closed. This does
not authorize lock rotation or defend against malicious concurrent replacement.

After locking, every prior run without a validated completion contract blocks new preparation. Invalid
manifests block all stands because their ownership cannot be established. Even
an empty prepared run remains unresolved. Retained files are not deleted by completion. It is intentionally conservative. Keep records until independent manual
verification permits archiving them outside `runs/`; never delete a lock file.

Example of preparation through the internal API (not a VM invocation):

```python
from tools.vm.matrix.resources import StandLease, create_run

with StandLease(state_directory, "local-qemu-a") as lease:
    run = create_run(lease)  # random run ID; exclusive directory creation
    run.register({"id": "overlay", "kind": "file", "path": "disks/root.qcow2"})
    # A future provider creates the file only after durable registration.
```

The manifest schema is `rosetun.matrix.resources.v1`, with exactly `schema`,
`run_id`, `stand_id`, `owner_token`, `state`, `resources`, `reasons`. Identity
fields stay fixed across updates; the in-memory run identity is frozen and its
representation omits the token. Owner tokens are random 256-bit ownership
identifiers, **not cryptographic protection against another process of the same
user**. The environment, state directory and cooperating worker are trusted;
this is not a defense against concurrent malicious filesystem replacement or
hard-link attacks. Keep the state directory private to the worker. Never copy
tokens to logs or reports.

States are `preparing`, `prepared`, `starting`, `running`, `stopping`, `exited`,
`error`, `quarantined`; `create_run` writes
`prepared`, meaning only that the ledger exists. `register` durably adds an
entry. `mark("error"|"quarantined", reason_code)` records identifier-only
reasons and preserves files. Failed runs cannot return to `prepared`.
`read_manifest` validates identity against optional independently held expected
IDs/token. Manifests and lock files must be regular files. Unknown fields,
duplicate JSON keys, schemas, invalid types and
malformed/partial JSON fail closed. Updates use a same-directory exclusive
temporary file, flush/fsync and atomic replace (plus directory fsync on POSIX).
An interrupted write may leave the previous manifest and temporary evidence;
an interruption before the first manifest leaves an invalid directory. Power
loss durability still depends on the OS/filesystem. No manifest is a scenario
PASS, report or completion marker; existing Linux/List/Proxy schemas are unchanged.

File entries contain exactly `id`, `kind: "file"`, `path`. Paths use portable
relative slash-separated components inside the run directory. Absolute,
drive-relative, UNC, `..`, backslash, alternate streams, Windows device names
and symlink/reparse traversal are rejected, including existing final targets.
The manifest and temporary-manifest namespace are reserved case-insensitively.
Tildes are rejected to exclude Windows 8.3 aliases; DOS device variants are
rejected on every OS. Case-only file aliases cannot be separate ledger entries.
Register intent
before creation; a registered file may be absent and is never presumed cleaned.

Process entries contain exactly `id`, `kind: "process"`, positive integer `pid`,
`platform` (`windows` or `posix`), `boot_id`, `start_id`, `executable`.
The next provider must capture these directly from the created process:
host boot identity, OS creation identity (Windows creation FILETIME or Linux
`/proc/<pid>/stat` start ticks), and executable identity/path. PID alone is never
sufficient. This stage stores and validates fields only; it does not discover,
verify, adopt or terminate any process.

Read-only inspection requires an explicit directory and creates nothing when
it is absent:

```powershell
python -B -m tools.vm.matrix runs --state-directory D:\local-matrix-state
python -B -m tools.vm.matrix recover --state-directory D:\local-matrix-state
```

`recover` is always a dry-run plan. Both commands omit owner tokens. Invalid
entries are reported as quarantined with unknown identity, without guessing
ownership from directory names or exposing raw parser errors. Exit 0 means
inspection completed, never successful execution or cleanup; inspect problems
and reasons. Input/path errors return 2. Quarantine retains evidence; it neither
stops processes nor removes files, directories or network objects.

Before any future deletion, QEMU Provider must independently confirm the held
stand lease, original run identity/token, manifest validity, file containment
with current symlink/reparse checks, and exact resource ownership. Before any
PID action it must compare boot and creation identity against the live process,
handle PID reuse and unavailable observations conservatively, and confirm the
original process has exited before removing dependent files/control endpoints.
Unknown state must remain quarantined. Disk preparation and bounded QMP lifecycle
are implemented above. Guest transport, network objects and deletion/automatic
recovery remain outside scope.

Autonomous resource tests use temporary directories and bounded harmless child
processes. The platform-specific test for another OS is explicitly skipped;
passing these tests does not qualify that OS or QEMU.

```powershell
python -B -m tools.vm.matrix doctor
python -B -m tools.vm.matrix plan linux-l2 --config tools/vm/matrix/example.toml --profile exploratory
python -B -m unittest discover -s tools/vm/matrix/tests -q
```

`-B` avoids Python bytecode cache writes. `doctor` reports the OS, architecture,
Python version and required local source files. Optional QEMU discovery uses
PATH lookup only; it does not execute the binary. `qualified: false` means that
neither binary presence nor these diagnostics prove backend capability.

Supported suites: `linux-l2`, `linux-l3`, `linux-l4`, `linux-l5`, `linux-proxy`,
and `windows-list`.
Their catalogs remain in [../linux](../linux/README.md).

## Configuration and plans

[example.toml](example.toml) contains unbound planning profiles. Config schema is
integer `1`; the only top-level fields are `schema` and `profiles`. Each named
profile requires `mode = "exploratory"` or `mode = "release"`. Optional `run_id`
and `boot_id` must be supplied together as nonempty strings. Unknown fields,
versions and modes are errors.

For assessment of an already saved run, create a local configuration with those
two IDs copied from its independently saved host staging record. Do not derive
the expected identity from the report being checked. The package never invents
a run ID, stamps a run as executed or obtains identity from a guest. An unbound
plan is useful for inspection but cannot accept a report.

Save stdout as UTF-8 JSON, for example in PowerShell 7:

```powershell
python -B -m tools.vm.matrix plan linux-l4 --config matrix.local.toml --profile exploratory | Set-Content -Encoding utf8 plan.json
python -B -m tools.vm.matrix report saved/report.json --plan plan.json
```

The second command reads `saved/status.json` alongside the report. Keep both
original files and the saved plan. Redirect the assessment into a different file
if needed; never overwrite a raw input with the assessment.

Plan schema is `rosetun.matrix.plan.v1`:

| Field | Meaning |
| --- | --- |
| `suite`, `profile` | Selected suite and profile name |
| `policy` | Exact selected profile, including optional expected identity |
| `planned_reboots` | Two for L4, zero for every other supported suite |
| `catalog` | Ordered array of `id`, boolean `required`, `evidence`, `group`, `detail`, `title` |
| `catalog_digest` | SHA-256 of the canonical catalog array |

Canonical encoding is Python JSON with sorted object keys, ASCII escapes,
separators `,` and `:`, UTF-8 bytes, no final newline. Array order is significant.
The digest covers all six fields and is independent of TSV line endings. Plans
contain no timestamps or machine paths and are deterministic for the same input.
The reader validates catalog structure, duplicate IDs, digest and reboot policy.
It never reads the current TSV in place of the saved catalog. The digest detects
accidental snapshot changes; it is not a signature or proof of provenance.
Keep the plan and staging record under the owner's control.

## Input and assessment schemas

The Linux adapter reads existing Linux JSON with integer
`schema: 1`. Windows List uses the separate format below. Existing
execution statuses are exactly `PASS`, `FAIL`, `SKIP`, `ERROR`; adding
`UNVERIFIED` to that old input schema would silently change its contract and is
therefore rejected. The new assessment vocabulary includes all five statuses.

Required input fields are `run_id`, `guest.boot_id`, `guest.boot_id_at_end`,
`scenarios`, `summary`, `cleanup.status`; L4 also requires `guest.boot_ids`.
Each scenario supplies `id`, `result`, and the unchanged `evidence` category.
The companion status must have the expected `run_id` and `state: "finished"`.
If status has a `boot_id`, it must match the report's final boot. Display metadata
such as timestamps, reasons and duration remains in the original files and is
not treated as evidence. The separate status is the completion marker, as in
the PowerShell validator; a report file alone is insufficient.

Assessment schema is `rosetun.matrix.assessment.v1`:

| Field | Meaning |
| --- | --- |
| `execution` | Observed status, raw row counts, and every FAIL's row index and ID |
| `validation` | `PASS` or `ERROR`, with structural, identity and consistency problems |
| `rows` | Expected scenarios, execution status, invariant status and row problems |
| `legacy_verdict` | Conservative compatibility verdict for the existing Linux checks |
| `invariant` | `UNVERIFIED` with the unsupported verification reason |
| `cleanup` | Independently reported cleanup status; missing/invalid becomes `ERROR` |
| `coverage` | `none`, `partial`, or `complete` for legacy scenario coverage only |
| `acceptance` | Selected mode, exploratory eligibility, release eligibility, selected-mode acceptance |
| `sources` | SHA-256 of original report, status and plan bytes; unreadable status hash is null |

Raw reports remain separate and unchanged; the assessment does not rename old
evidence or rewrite failures. It omits free-form raw reasons, which may contain
sensitive diagnostic data. CLI input errors produce a smaller assessment with
`validation.status: "ERROR"` and false acceptance, without echoing raw input.

## Aggregation and limits

- Unknown schemas/statuses, duplicate JSON keys, non-finite JSON constants,
  malformed/truncated JSON and invalid field types are rejected.
- All catalog scenarios must have exactly one row, including optional ones.
  Missing, duplicate or unknown IDs are errors in both modes. A required SKIP
  is an error. Missing/relabelled evidence and `not-run` with PASS are errors.
- Run IDs must match the saved plan in both report and status. The initial boot
  must match the plan. L4's nonempty boot chain starts there, contains distinct
  nonempty IDs, ends at the reported final boot, and permits at most two reboots.
  Fewer planned reboots are judged by the scenario results, like the old harness.
  Other suites must not reboot; a supplied boot chain is checked there too.
- Summary counts and total are recomputed from raw rows, including duplicates
  and unknown rows, which remain validation errors. Counts must be integers,
  not booleans or strings. Overall must agree with raw failures/errors and
  cleanup. A guest ERROR is always blocking (finalization can record an abort
  without a separate ERROR row). Optional summary coverage must agree too.
- Execution aggregation preserves any FAIL before considering ERROR, then
  missing execution (`UNVERIFIED`), then required SKIP. Optional SKIP permits an
  execution PASS with partial coverage. Validation errors still block acceptance;
  `legacy_verdict` uses ERROR before FAIL, matching the old validator's priority.
  A later infrastructure error cannot remove FAIL counts or failure rows.
- Cleanup must be PASS. A successful execution never overrides failed or
  missing cleanup. The adapter only checks the recorded cleanup claim; it cannot
  inspect the current guest or prove host checkpoint restoration.
- Exploratory accepts valid existing checks with optional SKIP and labels their
  coverage partial. It does not excuse absent rows, required SKIP, FAIL or ERROR.
  Coverage is none when the legacy verdict is not PASS.
- Release requires successful required execution, verified required invariants,
  valid input and successful cleanup. Required FAIL, ERROR, SKIP or UNVERIFIED
  blocks it. **This foundation never grants release acceptance:** independent
  security-invariant verification is unsupported and always UNVERIFIED. Even
  complete legacy execution PASS is not full release verification.

`transport-fixture`, `real-service`, `real-package` and other existing categories
remain exactly what the TSV declares. The class `not-run` marks a scenario that has no
check yet (the `two-hop.*` rows of the L3 and Proxy catalogs): it is never required, the
script records it SKIP before any session opens, the assessor takes that SKIP as no
problem (and a PASS of such a scenario as one), and the L3 summary lists it outside the group. They are not external packet capture.
No evidence is not evidence of no leak. PCAP analysis, cryptographic attestation,
an authenticated evidence store, autonomous guest jobs, network labs and scenario
migration are not implemented. QEMU preparation, bounded QMP lifecycle and minimal
QGA observation have a separate internal API described above. Unit tests do not qualify any OS/backend or prove
network protection.

Exit codes: `0` for successful doctor/plan or accepted exploratory assessment;
`1` for missing doctor prerequisites or a valid but unaccepted assessment
(including release UNVERIFIED or execution FAIL); `2` for input, validation or
CLI usage errors. Argument parsing errors go to stderr; assessment and input
validation results are JSON on stdout. A zero exploratory code is never a release
approval; inspect `acceptance.release` explicitly.

## Regression correspondence

[tests/test_matrix.py](tests/test_matrix.py) builds explicitly synthetic reports
in temporary directories. No synthetic report is shipped as a real run.

| Existing `Test-LinuxHarness.ps1` report checks | Python coverage |
| --- | --- |
| Complete report, optional SKIP | Every catalog; partial exploratory acceptance |
| Missing report/status, unfinished job | File/JSON failures and completion checks |
| Foreign run/status, initial/final boot | Identity and boot-chain tests |
| L4 ordered, shorter, excessive, repeated or unlisted boots | Boot-chain subcases |
| Dropped/required SKIP/invented scenario | Missing required/optional, SKIP, unknown and duplicate IDs |
| No-check PASS, relabelled evidence | `not-run`, missing and changed category |
| FAIL, lying summary | Execution failure, counts/total/overall/coverage consistency |
| Cleanup error/missing, unknown schema | Cleanup, schema and unknown-status cases |

Additional tests cover deterministic snapshots, invalid TOML/plan contracts,
strict JSON, separate invariant UNVERIFIED, FAIL preservation after errors,
snapshot-only assessment, unchanged raw files, and CLI exit codes from the
repository root. Process timeouts, artifact validation and other execution-side
harness tests are outside this package and are not reimplemented here.


## Windows List artifacts

Only [Invoke-ListMatrix.ps1](../windows/Invoke-ListMatrix.ps1) supports opt-in
`-ResultDirectory <new-directory>`. Without it the existing invocation, checks,
output and exit behavior remain. It never runs through Python. Example for the
owner on the configured Hyper-V host, using already built artifacts:

```powershell
.\tools\vm\windows\Invoke-ListMatrix.ps1 -SingBoxPath .\tools\sing-box.exe -RequestPath .\tools\vm\windows\request-local.json -ResultDirectory .\target\list-run-001
python -B -m tools.vm.matrix report target/list-run-001/report.json --plan target/list-run-001/plan.json
```

The directory must not exist. Relative result paths resolve against the current
PowerShell location. The recorder retains the absolute directory for all artifacts,
independently of the process working directory or later location changes.
The recorder generates a GUID run ID, captures the
Hyper-V VM GUID and guest initial UTC boot time independently, and saves the plan
before building, starting a host node or modifying the guest. Identity reads may
open the existing PowerShell Direct session. It does not record credentials,
request contents, node configuration, exception text or legacy free-form notes.

| File | Contract |
| --- | --- |
| `plan.json` | `rosetun.windows-list.plan.v2`: `catalog_digest`, suite, profile, mode policy, identity (`run_id`, `vm_id`, `boot_id`), ordered catalog snapshot |
| `events.jsonl` | Each newline-terminated `rosetun.windows-list.event.v1` contains run ID, sequence starting at 1, stable check ID, result and safe reason code; appended immediately |
| `report.json` | `rosetun.windows-list.report.v1`: initial identity, final boot, exact journal checks, counts (`total`, `pass`, `fail`, `skip`), cleanup status and safe infrastructure errors |
| `status.json` | `rosetun.windows-list.status.v1`: same identity, `state: finished`, final event count; written after cleanup handling and report finalization |

Final report and status use temporary files and same-directory rename. A failed
write aborts with a nonzero exit; no completion is inferred from report presence.
An abrupt interruption may leave only the plan and a journal prefix. Keep those
files: observed FAIL remains in assessment even with missing/corrupt report,
status or subsequent journal records. These files are local evidence, not signed
attestation; retain the original plan independently under owner control.

[list-checks.json](../windows/list-checks.json) declares all 11 existing checks;
ID literals also occur at each Test-Step call. All checks are required. After SRS
compilation FAIL, its four dependent checks get SKIP / `srs-compile-failed`.
After an infrastructure exception, remaining checks get SKIP / `interrupted`.
An exception inside Test-Step still means legacy FAIL / `condition-exception`.
Infrastructure failures are separate `{reason: infrastructure-error, place:
execution|cleanup|export}` entries. Mandatory skips block exploratory acceptance.

Cleanup is PASS only with read-back confirmation that the guest list directory is
absent and the tunnel state is Disconnected, plus confirmed termination of any
host node owned by this run and included in cleanup. The start helper captures
PID and UTC creation ticks directly from the created process; its existing boolean
return contract is unchanged. The stop helper retains its listener checks and
also checks this identity before stopping. After the stop attempt, a separate
process check confirms exit (including PID reuse), reports a still-live original
process as ERROR, and leaves unavailable identity/state UNVERIFIED. A missing
listener or successful stop return alone proves nothing. Guest cleanup ERROR is
never promoted to PASS. Reused foreign nodes are left alone. `-KeepNode` explicitly
retains a newly started node outside the cleanup scope; it is not needed to work
around unverified stopping. No checkpoint restoration is claimed.

Windows plan.v2 stores SHA-256 of the saved ordered catalog array, covering all
six fields (`id`, `required`, `evidence`, `group`, `detail`, `title`). The canonical
representation is compact JSON: fixed ordinal key order `detail,evidence,group,id,
required,title`, lowercase booleans, no whitespace or final newline, UTF-8 without
BOM. Strings use Python `ensure_ascii=True` escaping: quote and backslash escaped,
short escapes for backspace/tab/LF/form feed/CR, other controls and all code units
above ASCII 126 as lowercase `\uXXXX` (non-BMP characters as UTF-16 surrogate
pairs). Slash is unescaped; Unicode is not normalized. Scenario order is significant.
PowerShell implements this encoding explicitly without Python at runtime; ordinary
`ConvertTo-Json` is used only for artifact serialization, not canonical hashing.
The reader requires the stored digest and verifies it against the saved snapshot;
it never substitutes the current `list-checks.json`. Missing, malformed or changed
digests are rejected. Windows plan.v1 is explicitly rejected with an instruction to
record a new run; it cannot be upgraded into verified evidence by filling in a hash.
Linux plan.v1 and Linux reports keep their existing contract. The digest detects
accidental changes; anyone who edits the snapshot can recompute it. It does not
establish trusted provenance or authenticate any test result.

The adapter validates schemas/types, saved identities, final boot, catalog order,
unique IDs, contiguous sequences, full coverage, reason codes, journal/report
agreement, counts, cleanup and completion. It uses only the saved plan, never the
current catalog. Execution FAIL is retained separately from validation ERROR.
Invariants stay UNVERIFIED and release acceptance always stays false. Exploratory
can accept only a complete, valid run with every required check PASS and confirmed
cleanup. Existing checks and their network results are not independent security
evidence.

An inspection-only plan can be generated with:

```powershell
python -B -m tools.vm.matrix plan windows-list --config tools/vm/matrix/example.toml --profile exploratory
```

This has null identity and cannot accept a run; use the recorder's saved plan for
assessment. Windows profiles contain only `mode`; Linux identity profiles and
saved v1 plans retain their existing contract.

Autonomous checks, without Hyper-V, services, network tests or admin rights:

```powershell
python -B -m unittest discover -s tools/vm/matrix/tests -q
pwsh -NoProfile -File tools/vm/windows/tests/Test-RosetunListResults.ps1 -Directory target/synthetic-list-001
pwsh -NoProfile -File tools/vm/windows/tests/Test-RosetunScriptArguments.ps1
pwsh -NoProfile -File tools/vm/windows/tests/Test-RosetunListCleanup.ps1
```

Python integration tests execute the real PowerShell recorder in temporary
folders, extract only Test-Step from the matrix AST, and assess its serialized
files. PowerShell 7 must be available for these tests; otherwise integration is
explicitly skipped. Synthetic reports never qualify Hyper-V behavior.

Manual checks for the owner:

1. With host Lockdown off and the configured VM available, run the invocation
   above in a new directory. Confirm the familiar table still lists the same
   checks in the same order; retain the host transcript and all four artifacts.
2. Run the Python report command. Expect complete exploratory acceptance when
   all 11 checks pass and cleanup is confirmed, with release false and invariant
   UNVERIFIED. With `-UseHostNode` and without `-KeepNode`, also confirm that
   the created process has ended and cleanup is PASS. An unavailable process
   check must block acceptance with UNVERIFIED; a live original process means ERROR.
3. In a disposable run, interrupt between checks. The absence of completion must
   block acceptance; already appended failures must remain visible. Compare a
   separate invocation without `-ResultDirectory` with the previous table and
   normal exit behavior. Send back the transcript, exit codes and artifact folder
   if behavior differs; do not include credential or request files.

### Structured Windows Proxy contract

`windows-proxy` is a distinct suite. It uses `rosetun.windows-proxy.plan.v1`,
`event.v1`, `report.v1`, and `status.v1`. List plan.v2 and Linux plan.v1 retain
their existing contracts. The Windows assessment journal/identity machinery is
shared; coverage and cleanup policy are suite specific.

```powershell
python -B -m tools.vm.matrix plan windows-proxy --config tools/vm/matrix/example.toml --profile exploratory
python -B -m tools.vm.matrix plan windows-proxy --without-host-node --config tools/vm/matrix/example.toml --profile exploratory
python -B -m tools.vm.matrix report target/proxy-with-node/report.json --plan target/proxy-with-node/plan.json
python -B -m unittest discover -s tools/vm/matrix/tests -q
```

The plan holds ordered six-field catalog rows, their canonical SHA-256 digest,
run/VM/initial boot identity, profile/mode, and parameters `use_host_node`,
`keep_node`, `proxy_port`. Offline plans have null identity and cannot accept a
run. Use the producer's saved plan for assessment. Assessment never reloads the
current catalog. Events contain only schema, run ID, sequence, stable ID,
result and safe reason code. PASS uses `checked`; FAIL uses `condition-false` or
`condition-exception`; SKIP uses `host-node-disabled` or `interrupted`.

Reports contain initial identity, final boot identity, exact journal events,
summary counts, safe infrastructure errors, and cleanup `{status, components}`.
The eight component keys and limitations are described in
[the runner guide](../windows/README.md#structured-windows-proxy-results).
`status.json` is the completion marker written atomically after `report.json`;
each contains its suite schema and original identity. Writes refuse overwrite;
write errors block success. A FAIL in either report or journal survives other
artifact corruption, invalid saved plans, cleanup errors and missing completion.
No credentials, request contents, node addresses, desktop settings or arbitrary
exceptions belong in these artifacts.

Exploratory acceptance requires all required checks for the saved variant,
valid conditional SKIPs, artifact agreement, unchanged guest boot, no
infrastructure errors and confirmed component cleanup. Limited coverage is
reported separately as `selected-variant`; full execution FAIL remains FAIL.
Independent security evidence is not implemented: invariants are UNVERIFIED
and release acceptance is false.

Autonomous tests extract actual PowerShell AST functions and call sites, inspect
the sharing loop variants and exercise the real recorder under PowerShell 7 and
Windows PowerShell where available. Guest/host operations are replaced for
cleanup tests. No VM module is imported and no matrix body is executed.

Proxy cleanup Lockdown now verifies a successful CLI off-status observation and
absence of Lockdown objects/references in a successfully parsed active WFP dump.
The dump must contain providers, sublayers, layers and per-layer filter collections;
missing or malformed observations remain UNVERIFIED. Existing ERROR and
NOT_CREATED are preserved. Active-dump cleanup PASS cannot prove absence of
boot-time filters hidden after BFE startup, and does not change the invariant or
release policy. See the runner guide for this evidence boundary.

The real finalization integration test is also run by the foundation suite:

```powershell
pwsh -NoProfile -File tools/vm/windows/tests/Test-RosetunProxyFinalization.ps1 -Directory target/synthetic-proxy-finalize-001
```

It executes the actual nested/outer finally AST with external operations replaced,
checks both coverage variants, remaining Lockdown, failed off commands, malformed
or unavailable observations, prior errors, a phase not started, failures inside
the nested phase and export errors. Its positive case obtains component PASS
through the cleanup path instead of assigning PASS in the serialization fixture.
Python assesses the resulting saved artifacts. This is infrastructure validation;
the owner must still run both Proxy variants on Hyper-V using new result directories
and check cleanup.components.lockdown, desktop restoration and resource ownership. Send back
plan.json, events.jsonl, report.json and status.json with sanitized discrepancies.

The Windows Proxy WFP reader accepts a complete `wfpstate` fragment optionally
followed by the observed `firewallState` fragment containing one empty
`dynamicKeywordAddresses` element. It parses every fragment, including the
trailer, with DTDs disabled. It never strips arbitrary text after `</wfpstate>`.
Unknown/populated trailers, duplicate WFP roots, malformed XML and extra content
remain UNVERIFIED. Regression cases exercise the real reader and finally path,
including the two-fragment format under Windows PowerShell 5.1. This changes only
read-back format handling; all CLI-status, active-object and acceptance checks
remain in force.
# Bounded smoke delivery over QGA (stage 4b.3)

Delivery qualification **passed on 2026-11-11** on the Debian 13/WSL2 KVM stand
described below. Historical 4b.2 qualification remains separate and covers only
the manual pre-staged path.
No Linux L2 payload or Rust binary delivery is implemented here.

The original live controller can build, stage, then use the existing job API:

```python
from pathlib import Path
from tools.vm.matrix.staging import SmokePackage

vm.observe_guest()
package = SmokePackage.build(
    vm, enabled=True, checkout=Path('/absolute/reviewed/rosetun'),
    guest_run_id='20261111T010203Z-0123abcd',
    attempt_id='0123456789abcdef0123456789abcdef', delay_seconds=20)
package.stage()                 # create, bounded writes, finalize, verify receipt
job = package.smoke_job(enabled=True)
job.submit()
# Wait externally for the autonomous job, retaining these objects and the lease.
result = job.collect()
```

Use fresh guest and attempt IDs, not the example values. Only `infra-smoke-v1`
is supported. The fixed manifest order is `guest/launch.sh`, `guest/start.sh`,
`guest/lib.sh`, `guest/run-smoke.sh`, `job.env`; every line is lowercase SHA-256,
two ASCII spaces, path, LF. The manifest does not hash itself. Source scripts
must be regular UTF-8 files with LF and a final LF; CRLF is rejected rather than
silently converted. Source metadata and open-file identity are checked around
bounded reads, with symlink/reparse checks on all parents. `job.env` uses ASCII
and LF, generated in the key order documented below from the live observation;
delay is integer 0..30. There is no arbitrary input-path list.

The immutable in-memory snapshot supplies all writes. The exact six package
files and `digest.sha256` are retained under the run's `smoke-package/`, alongside
bounded `staging.jsonl` with identities, counters, handle uncertainty and the raw
verified receipt. These eight fixed files are reserved before VM startup for a
QGA-enabled run, initially empty. Registration during `running` remains forbidden.
One build/delivery attempt is allowed per live Vm; a failed attempt requires a
new run and fresh IDs, preserving the old evidence. No cleanup is performed.

Before preparing the trusted base image, the owner must separately review and
install `../linux/guest/stage-smoke.py` as the executable root-owned regular file
`/usr/local/libexec/rosetun-l2/stage-smoke` (mode 0755), alongside the existing
reviewed `launch`. Compare SHA-256 of installed bytes with reviewed source and
record both hashes with image identity. All parents must be root-owned without
group/other write or symlinks. Create `/root/rosetun-l2-stage` as a root-owned
mode-0700 directory out of band. The image must already provide `/usr/bin/python3`
with its standard library and Linux libc `renameat2`; no dependency is installed
by the controller. The separate helper keeps the old three-argument launcher and
legacy profile dispatch unchanged, and never executes or imports delivered code.
It receives only `create|finalize HOST GUEST VM_UUID BOOT_ID ATTEMPT DIGEST`.
Neither helper nor launcher is established through QGA delivery. Do not add a
sudoers or SSH rule for the helper.

Staging explicitly probes `guest-file-write`, `guest-exec`, `guest-exec-status`
in addition to the observation RPCs. QGA runs as root. Its write and execution
allowlist privileges are general at the agent boundary; this controller limits
them to the fixed helper, the six snapshot paths and the existing launcher.
Observation and direct manual `SmokeJob` do not require write RPC capability.
No shell strings, archives, network, daemon or shared directory are used.

The helper exclusively creates `.attempt-ATTEMPT/package/guest` under the fixed
root, reserves the six empty payload files as mode 0600, and records immutable
attempt identity. QGA write opens retain these private modes; qemu-ga's default
creation mode may otherwise be 0666. All guest directories/files must
be root-owned, without symlinks or group/other write; directories are private,
and files must have one link. Finalization checks the exact tree, byte sizes,
canonical manifest, every hash and exact smoke environment against the supplied
identity and current DMI UUID/boot ID. It fsyncs payload files and directories,
then uses `renameat2(RENAME_NOREPLACE)` to atomically publish
`/root/rosetun-l2-stage/GUEST`. Even an empty existing destination is refused.
It syncs both rename parents, writes `ready.json` exclusively in the attempt
directory, fsyncs that receipt and directories. Receipt schema
`rosetun.smoke-stage.v1` binds host/guest run IDs, VM UUID, boot ID, attempt ID,
manifest SHA-256 and state `ready`. A helper exit code alone does not authorize
launch. Only a matching receipt does; the VM identity/observation is checked
again when constructing and submitting the job, using exactly its guest ID/digest.
Staged submit also reads the live boot ID again before invoking the launcher.

Limits are 24 KiB per script/file, 1 KiB for the guest environment, 64 KiB for
the entire six-file package, 8192 raw bytes per write, 4096 bytes per receipt,
96 KiB base64 payload sent, 48 staging RPCs across all sessions, a 180-second
deadline from build, 5 seconds per RPC and four status polls per helper call,
with up to one second between status polls.
For the maximum package, six files require at most 13 blocks (sum of rounded
sizes), fewer than 87,424 base64 bytes, 12 open/close RPCs, 10 helper exec/status
RPCs, two probe RPCs and three receipt RPCs: at most 40 staging RPCs. Remaining
eight slots permit bounded inspection after uncertainty (each explicit recovery
is charged six slots: sync, probe and boot read). Existing session limit
128 and job limit 64 are unchanged; delivery starts only with at most 16 session
RPCs already used, leaving the full delivery and job budgets. Repeated job polls
or other observation operations can still exhaust a session and require explicit
recovery. Recovery never resets attempt counters or its deadline. Local evidence
is capped at 64 KiB. No `guest-file-flush` is used as a durability claim.

Confirmed short writes are rejected, as are zero progress, invalid counts and
EOF. Known handles are closed in `finally` when the channel and close reservation
permit. Lost open/write/close/finalize replies retain `unknown` and handle status;
there is no automatic retry, resume, overwrite, deletion or launcher call.
After explicit `vm.recover_guest()`, `package.check_receipt()` may inspect only
the saved receipt. It cannot repeat create, write or finalize. Unknown/foreign
receipts, a changed boot or expired budget block launch. A crash between publish
and receipt creation leaves an unusable retained package. Controller crash
recovery remains outside scope. For all outcomes, security invariants remain
UNVERIFIED and release gate false.

Offline checks: `python -m unittest discover -s tools/vm/matrix/tests` includes
fake QGA delivery/recovery tests and guest helper tests using temporary trees
and substituted privileged operations. Existing Linux shell self-tests remain
separate: `bash tools/vm/linux/tests/selftest-lib.sh` and `selftest-smoke.sh`.
Native Windows tests do not establish Linux publication/sync or guest behavior.

Real stage 4b.3 qualification used QEMU/qemu-ga 10.0.13, pc-i440fx-10.0,
qemu.qmp 0.0.6 and host Python 3.13.5. The guest was Debian 13, kernel
6.12.115+deb13.1-amd64 and systemd 257.13-1~deb13u1. The owner authorized real
qualification separately from implementation. Five fresh writable overlays
covered the following cases, with the original live controller and lease:

- The independent console installed only the reviewed trust anchors and enabled
  the write/exec RPCs. The controller delivered all 34,185 package bytes via QGA,
  checked the ready receipt, and used existing submit/collect successfully. Every
  published file's SHA-256 matched an independent console observation. Delivery
  used 31 slots and the job used 13 RPCs. Duplicate stage, submit and launcher
  invocations were refused; the unit journal showed exactly one start.
- Corrupting a delivered script before finalization caused rejection with no
  receipt or launcher execution. Partial files remained. Creating a destination
  with a foreign sentinel likewise caused rejection without replacement or
  deletion of that sentinel.
- Stopping qemu-ga after the first confirmed file write and before the next
  write caused a real exchange timeout with live QMP. No write retry or job
  launch occurred. Explicit agent restart/recovery preserved the same boot ID;
  receipt inspection alone was permitted and rejected the missing receipt.
  Partial data and unconfirmed handle evidence remained.
- Stopping qemu-ga after guest finalization but before its status reply was
  received left delivery unknown. Explicit recovery checked only the saved
  receipt, then permitted one successful smoke job. The attempt used 36 slots
  including recovery and receipt inspection; no create/write/finalize was
  repeated. This tests loss of finalization status, not a lost initial exec PID.
- All five VM children were reaped, local sessions/endpoints/relay workers
  closed, completion verified and the stand reused. Three earlier diagnostic
  overlays were also retained with verified completion. Base size/SHA-256 stayed
  476,774,400 bytes and
  `f4a05e7aba2c889437f6bce798926a381b7ebf257178e75d140493f817b74de8`.

Qualification exposed qemu-ga's 0666 creation mode and overly short helper poll
intervals; private file reservation and one-second poll spacing fixed these
without changing trust checks or RPC limits. Regression tests cover both.
Linux offline checks passed, including the full Python suite and both shell
self-tests (legacy 122/122). Evidence is retained under git-ignored
`tools/vm/logs/qga-4b3-qualification-20261111/`: qualification harness/results,
source and installed-anchor hashes, console logs, offline logs and per-run
staging/job/completion evidence. Owner tokens were checked absent from public
journals, argv and results. No dependencies, guest network, SSH rule, builds or
base-image changes were used. Unknown guest-handle closure, power-loss durability,
controller crash recovery, Linux L2 and VPN security remain unqualified. Security
invariants stay UNVERIFIED and release gate false.

Owner repeat qualification on another prepared stand:

1. Record base identity and reviewed installed launcher/helper hashes via the
   independent console. Start a disposable prepared overlay with QGA, enable
   the additional RPCs, observe boot and execute the API above. Do not copy a
   package manually for each run. Require a verified receipt, successful saved
   smoke result, closed handles and verified VM completion, with release false.
2. On a new run/IDs, stop before finalization using an independently reviewed
   qualification harness and corrupt a delivered file through the console.
   Finalization must refuse it without a receipt or launcher execution; preserve
   all guest partial files and host staging evidence.
3. On another new run/IDs, interrupt the agent channel during a write. Require
   unknown delivery, no second write attempt and no job start. Restart the agent,
   call explicit recovery and inspect only the receipt. Missing receipt must
   block launch; retain all partial evidence and finish the owned VM normally.
4. Interrupt the response to finalization after guest publication. After recovery,
   require exact receipt agreement before constructing the job; confirm one job
   start and refusal of duplicate stage/submit. Existing targets, foreign files
   and partial attempts must remain intact. Verify child reap, descriptor closure,
   completion evidence, lease reuse and unchanged base hash. Save commands,
   versions, host/guest evidence and console observations; report discrepancies
   with staging/job journals and completion, keeping owner tokens private.

# Autonomous infrastructure smoke over QGA (stage 4b.2, manual pre-staged path)

This opt-in path is an infrastructure diagnostic, not a Rosetun scenario or VPN
protection evidence. It uses the original live Python controller and its lease.
It does not implement package delivery or controller crash recovery. Existing
matrix profiles and result assessment remain separate.

The owner must install the reviewed `../linux/guest/launch.sh` at exactly
`/usr/local/libexec/rosetun-l2/launch`, executable and root-owned, with root-owned
parents without group/other write or symlinks. Compare its SHA-256 with the
reviewed source before qualification. The launcher checks its installed file and
directory; this API assumes the owner has established that trust anchor and the
guest image is trusted. QGA runs as root, without sudo or `SUDO_UID`. Only root's
home `/root` is supported by this API. Do not add an SSH/sudo rule for this smoke.

In addition to observation's existing RPCs, explicitly enable `guest-exec` and
`guest-exec-status` in the guest agent's allowlist. These are privileged general
execution capabilities at the agent boundary; the Python facade restricts them
to the installed launcher, validated arguments and the returned PID. The agent
allowlist itself does not restrict executable paths. No write-file RPC is used.
Observation alone still requires only its original RPC set. The supported real
guest baseline is qemu-ga 10.0.13 with host qemu.qmp 0.0.6; check agent capabilities
at runtime. See the [QGA reference](https://www.qemu.org/docs/master/interop/qemu-ga-ref.html#command-guest-exec):
`guest-exec` returns a launcher PID; `guest-exec-status` reaps its metadata on exit.
Neither indicates the outcome of the independent systemd job. Output capture is
disabled, and no shell command string, stdin payload, environment injection or
arbitrary executable is accepted.

Owner preparation (inside the guest, out of band): create a new mode-0700
`/root/rosetun-l2-stage/GUEST_RUN_ID`, under a root-owned parent without group/other
write. Copy the reviewed scripts as regular files with LF endings. The exact
package is:

```text
guest/launch.sh
guest/start.sh
guest/lib.sh
guest/run-smoke.sh
job.env
manifest.sha256
```

No artifacts directory, binaries, scenarios or other files belong in this
package. `run-smoke.sh` in the manifest explicitly selects smoke; `PROFILE` must
also be `infra-smoke-v1`. Unknown profiles are rejected. Do not use the legacy
PowerShell `New-RosetunLinuxJobEnv`, `New-RosetunLinuxStage` or
`Start-RosetunLinuxJob` for this package: those remain the legacy matrix/SSH path.
Reuse is confined to the verified guest launcher, start dispatcher and strict
environment reader. Smoke has its own strict durable writer and result contract.

`job.env` has exactly one occurrence of each of these keys (no quoting):

```text
PROFILE=infra-smoke-v1
HOST_RUN_ID=the_exact_python_prepared_run_id
RUN_ID=20261111T010203Z-0123abcd
VM_UUID=12345678-1234-4234-8234-123456789abd
EXPECTED_BOOT_ID=12345678-1234-4234-8234-123456789abc
JOB_ID=smoke
DELAY_SECONDS=20
```

Replace example identities with the exact live VM UUID, observed Linux boot ID,
Python run ID and a fresh legacy guest run ID. The host ID uses the existing
Python identifier grammar (up to 96 characters); the separate guest ID retains
`YYYYMMDDTHHMMSSZ-xxxxxxxx`. No truncation or implicit conversion occurs: the
facade records this explicit mapping and verifies both identities on collection.
VM UUID is compared to Linux DMI product_uuid, boot ID to `/proc`.
Delay is an integer 0..30 seconds; job runtime is capped at 45 seconds, followed
by a 5-second control-group stop limit and ExecStopPost finalization.

From the staged directory, the owner generates the manifest over exactly the
five payload files, then obtains the digest of the manifest itself:

```sh
sha256sum guest/launch.sh guest/start.sh guest/lib.sh guest/run-smoke.sh job.env >manifest.sha256
sha256sum manifest.sha256
```

Supply that digest and the exact guest run ID to the host. No code here copies
the package into the guest. The launcher verifies the manifest, copies into
`/var/lib/rosetun-l2/GUEST_RUN_ID`, verifies the protected copies and starts the
verified `start.sh`. Exclusive run-directory creation rejects repeated launcher
invocations, including concurrent ones; a second atomic job claim also remains
after execution. Failed/partial run directories are retained and never restarted
under the same identity. This is not an exactly-once guarantee across crashes.

API in the original live process, after `vm.observe_guest()`:

```python
from tools.vm.matrix.jobs import SmokeJob

job = SmokeJob(vm, enabled=True, guest_run_id=guest_run_id,
               manifest_sha256=owner_verified_manifest_digest)
job.submit()       # exactly one attempt for this live Vm
job.inspect()      # saved started marker; may raise JobError(UNVERIFIED)
# After channel loss, retain vm, job and the lease:
vm.recover_guest() # explicit; never hidden inside submit/collect
result = job.collect()
```

`submit()` records intent before execution. An exchange timeout leaves submission
`unknown` and poisons the QGA session; it never retries. Keep the same `job`
object and recover explicitly before inspecting saved state. A new facade for
that Vm is rejected. Absence/open errors, lost replies, missing terminal data,
identity/digest mismatch, malformed JSON/base64/count/EOF, oversized content and
artifact hash mismatch raise an error with verification `UNVERIFIED`. Unknown
does not mean absent and never permits resubmission. A known handle is closed
when the channel permits; unconfirmed open/close states remain in host evidence.
There is no reconnect-to-job API after controller loss.

The contract separates `submission`, `launcher`, `job` and `verification`.
`VERIFIED` means the saved terminal record and required artifact agree with this
attempt's identities; check `job == 'succeeded'` separately. `error` and `timeout`
are valid terminal failures. The security invariants stay `UNVERIFIED` and release
gate stays false even for a successful diagnostic or successful VM completion.

Reads are restricted to `report/smoke-started.json`, `smoke-terminal.json` and
`smoke-artifact.txt` under this fixed guest run directory. Each file is capped at
4096 bytes; strict JSON schemas and artifact SHA-256 are checked. Guest writes
use a same-directory temporary file, file sync, rename and directory sync;
terminal failures are finalized by ExecStopPost if the main process cannot write.
Unit stdout/stderr are discarded, files have an 8192-byte systemd limit, and the
actual diagnostic artifact is one fixed short line. Results are never removed
on collection. Host evidence (including bounded raw collected bytes) is retained
in pre-registered `job-evidence.jsonl`, capped at 256 KiB, separately from
lifecycle, completion and legacy reports. Evidence failure blocks trustworthy
completion. Limits per job: 180-second total deadline from facade creation,
10 seconds per API operation, 5 seconds per RPC, 64 RPCs and 12 explicit polls.
Existing QGA session limits (128 RPCs) and recovery limits are unchanged. These
budgets include known-handle close reservations; exhaustion cannot imply success.

Offline checks: `python -m unittest discover -s tools/vm/matrix/tests`, plus
`bash tools/vm/linux/tests/selftest-lib.sh` and
`bash tools/vm/linux/tests/selftest-smoke.sh` on Linux. The latter uses private
temporary copies and substituted system commands, never real systemd services.
Linux shell checks on other hosts are UNRUN, not qualification evidence.

Real-guest qualification on 2026-11-11 (local time) passed on the existing
Debian 13/WSL2 KVM stand: QEMU 10.0.13, pc-i440fx-10.0, qemu.qmp 0.0.6,
Python 3.13.5, guest kernel 6.12.115+deb13.1-amd64, systemd 257.13-1~deb13u1
and qemu-ga 1:10.0.13+ds-0+deb13u1. Two independent writable overlays reused the
prepared base above. Only the qualification harness added the independent serial
console and prepared the reviewed package/installed launcher out of band before
submit; production code performed no guest writes through QGA. Only the two job
RPCs were added to the guest allowlist. No NIC, SSH, firewall exception, dependency
installation or base-image modification was used.

Confirmed with real QGA, systemd, original live controller and lease:

- Saved started marker, followed by agent stop and a QGA observation timeout
  while QMP remained running. The autonomous job completed during channel loss.
  Agent restart and explicit `recover_guest()` returned a new session with the
  same boot ID; `collect()` verified the saved successful terminal and artifact.
- Both facade duplicate submit and a second installed-launcher invocation were
  rejected. Each unit journal recorded one start, with `NRestarts=0` observed
  while active. No second autonomous job was started.
- Deliberately absent and truncated terminal files were rejected as UNVERIFIED;
  restoring the original terminal allowed verified collection without resubmit.
- A separately reviewed qualification variant changed only the diagnostic sleep
  to a bounded 60 seconds, exceeding the unchanged 45-second unit runtime limit.
  systemd stopped it and ExecStopPost saved a verified `timeout` terminal.
  Successful VM completion retained that failed job outcome.
- Both children were reaped, all sessions/relay workers and retained endpoints
  closed, and completion verified. A third run acquired the same stand and
  started/completed successfully. Base size and SHA-256 remained 476774400 bytes,
  `f4a05e7aba2c889437f6bce798926a381b7ebf257178e75d140493f817b74de8`.

Linux offline checks passed: 194 foundation tests with 18 platform skips,
31 targeted tests without skips, legacy shell self-test 122 checks and the new
smoke shell self-test. Qualification initially exposed a test-only dynamic shell
variable collision in the fake `mktemp`; its fixture scope was corrected before
the real runs. Local evidence is retained in git-ignored
`tools/vm/logs/qga-4b2-qualification-20261111/`: `qualify.py`,
`qualification-results.json`, source/package hashes, serial logs, offline test
log and per-run state/evidence/completion files. Owner tokens remain private and
were checked absent from public journals, argv and qualification results.
Lost `guest-exec` response behavior remains covered by offline tests; this real
qualification does not establish closure of unknown guest handles, reboot or
controller-crash durability, Rosetun scenarios or VPN protection.

Owner repeat qualification plan:

1. Prepare and review the package, submit, confirm the saved started marker.
2. Lose the QGA session while keeping the VM, controller and lease alive.
3. Explicitly recover QGA, collect and validate the saved terminal/artifact.
4. Confirm one unit invocation/claim and that duplicate submit cannot run again.
5. Qualify a timeout (a reviewed test package with bounded work exceeding 45s)
   and incomplete terminal data; confirm timeout/error versus UNVERIFIED.
6. Close the VM, verify completion and lease reuse, and inspect retained job
   evidence separately from completion.

Transient units and the current transport do not establish persistence across
reboot, hard-off or controller crash. Package delivery is the next stage; Linux
L2 migration follows it. Neither is implemented here.

## Read-only L2 media delivery (stage 5b)

This optional Python API delivers the existing L2 package without a network or
manual guest copy. The stage 5a pre-staged API remains available. Historical 5a
results do not qualify media delivery. Release gate stays closed; network
security invariants remain **UNVERIFIED**.

The owner supplies a trusted installed **xorriso 1.5.6** executable by absolute
path. Absence or a different reported version fails preflight; nothing is
installed automatically. Its `-no_rc -as mkisofs -iso-level 3 -R -V ... -o ...`
interface writes ISO9660 with Rock Ridge names and ordinary files only. See the
[upstream xorrisofs manual](https://www.gnu.org/software/xorriso/man_1_xorrisofs.html)
and [xorriso manual](https://www.gnu.org/software/xorriso/man_1_xorriso.html).
`-no_rc` disables startup files. Metadata is not normalized: **no byte reproducibility
claim** is made. Tool diagnostics/version, exact input hashes/sizes, source status,
provenance, retained snapshot, content manifest and ISO digest/size are recorded.

Only Linux/KVM, `pc-i440fx-10.0`, the owner-pinned QEMU 10.0.13 / SeaBIOS stand
is supported for this path. Review uses the released 10.0 device interface:
[virtio block serial/read-only support](https://github.com/qemu/qemu/blob/v10.0.0/hw/block/virtio-blk.c),
[raw/read-only block options](https://github.com/qemu/qemu/blob/v10.0.0/qapi/block-core.json),
and [bootindex semantics](https://github.com/qemu/qemu/blob/v10.0.0/docs/system/bootindex.rst).
An explicit raw read-only block graph is attached to a separate virtio-blk-pci
with serial `rosetun-l2-media`. Root alone gets bootindex=1; no hotplug is used.
Old plans without the option keep their previous argv. The ISO's size/hash is
checked again immediately before spawn. Firmware and exact patched QEMU build
need separate owner qualification outside the recorded configuration below.

The prepared image must already contain the matching trusted launcher, stand
marker, group, ordinary test accounts and root QGA described in stage 5a. The
owner installs `tools/vm/linux/guest/stage-l2.py` as root:root mode 0755 at
`/usr/local/libexec/rosetun-l2/stage-l2`, with trusted root-owned parent directories,
and creates `/root/rosetun-l2-stage` root:root mode 0700. Python 3, Linux
`renameat2(RENAME_NOREPLACE)`, virtio_blk/sysfs, ISO9660 support, and trusted
`/usr/bin/mount` and `/usr/bin/umount` are required. Import never creates accounts,
a stand marker or system configuration. No code is executed from the ISO.

Prepare an **exact local immutable input tree**, using already built artifacts:
`guest/{launch,start,lib,run-l2}.sh`, `scenarios.tsv`, and
`artifacts/{l2_transport_fixture,rosetun_helper_privileged_tests,rosetun_ipc_tests,provenance.json}`.
Scripts/catalog must match the chosen checkout with LF normalization; no extra
files/directories, links, `job.env`, or run manifest are accepted. Binary ELF,
provenance, source status/diff and catalog checks reuse `validate_package`.
No Cargo or WSL is invoked. `content.sha256` is generated in the owned snapshot.

```python
from tools.vm.matrix.qemu import prepare
from tools.vm.matrix.lifecycle import start
from tools.vm.matrix.l2_media import attach_media
from tools.vm.matrix.l2_import import L2Import

# run is an empty owned PreparedRun under the held StandLease;
# config has qga=True and the pinned machine; image is independently pinned.
prepare(run, image, config)
attach_media(run, directory='/srv/l2-input', checkout='/srv/rosetun',
             xorriso='/usr/bin/xorriso')
vm = start(run)                 # initially paused
vm.resume()
vm.observe_guest()             # boot ID is first learned here
attempt = L2Import(vm, enabled=True, guest_run_id='20261111T010203Z-0123abcd',
                   import_id='0123456789abcdef0123456789abcdef',
                   user_a='l2a', user_b='l2b')
attempt.stage()                 # one guest-exec, bounded status polling
# Explicitly refresh the finite QGA session budget before the existing L2 job.
vm.recover_guest()
attempt.check_receipt()         # reads saved evidence, does not repeat import
job = attempt.linux_l2_job(checkout='/srv/rosetun', enabled=True)
job.submit()
# After the existing autonomous L2 unit finishes:
result = job.collect()          # unchanged L2 assessment
vm.hard_off()                  # retain all files; completion is not delivery proof
```

Trust boundary: the host controller, checkout/provenance matching, installed
packager/QEMU, guest OS/QGA and installed helper are trusted, not attested.
The helper enumerates sysfs by the fixed serial, requires exactly one whole
virtio block device, read-only state and matching device numbers, then hashes
the full expected ISO bytes. Neither serial nor volume label proves identity.
It mounts only that device in a new attempt-owned directory with
`ro,nodev,nosuid,noexec`, verifies the exact file tree/content manifest, streams
copies, sets root ownership and explicit 0755/0644 modes in a private 0700 tree,
generates only validated job.env values, rehashes the final package, fsyncs files
and directories, and publishes without replacing even an empty destination.
Only confirmed unmount allows the durable ready receipt. A mount timeout or
unknown unmount retains the attempt and fails explicitly, without general cleanup.

The receipt binds host/guest run, stand, VM UUID, boot, import ID, ISO digest/size,
content manifest digest and final package manifest digest. The host independently
computes the exact job.env and final manifest after observing boot and retains
them locally. A receipt cannot introduce a new trusted manifest digest. Submit
requires the matching receipt and another fresh QGA boot check.

Limits: 512 MiB per ELF, 256 KiB per other input, 1600 MiB input aggregate,
1700 MiB ISO. Inputs are hashed and copied with change detection; the external
checkout is never the packager's source. Version preflight is 10 seconds; packaging
300 seconds; each output pipe is capped at 64 KiB. Import has a separate
900-second deadline, at most 24 status polls spaced 30 seconds apart, and 48
import RPCs including receipt inspection. General QGA and smoke limits are
unchanged. Slow imports may exhaust a QGA session; explicit `recover_guest()`
starts a fresh channel, not a fresh import. All partial local/guest data is retained.

After lost exec/status/receipt, keep the original `attempt` and `vm`. Never call
`stage()` again and never construct another facade. Explicit `vm.recover_guest()`
and `attempt.check_receipt()` may establish readiness from its saved receipt.
Missing/foreign receipt, changed boot or unknown cleanup blocks L2. Controller
crash recovery is out of scope. VM completion proves process/control closure,
not delivery or a successful L2 result.

Owner repeat qualification plan:

1. Record prepared image/BIOS/QEMU/qemu-ga/kernel/xorriso versions, source identity,
   base hash and the hashes of the three **real already built L2 binaries**.
   Create the exact local input tree and execute the API above under a fresh
   stand lease. Save ledger, preparation/import evidence, receipt and assessment.
   No console package copy, shared folders, SSH or network delivery in this path.
2. Confirm only the separate serial device is read-only, the root disk boots,
   and guest receipt hashes equal host expectations. Run/collect all 34 existing
   scenarios, preserving the existing optional SKIP behavior and cleanup checks.
   On mismatch return status/report/assessment and retained import evidence.
3. In a separate run, lose QGA during import. Verify submit stays blocked, no
   repeated helper exec occurs, and explicit recovery inspects only the saved
   receipt. Missing receipt or unknown unmount remains an explicit failure.
4. In a separate run pre-create the guest destination, including an empty
   directory. Verify it is never replaced and no ready receipt permits submit.
5. Confirm base and ISO hashes are unchanged, all controls/children close, and
   the stand can be leased again after verified lifecycle completion. Inspect
   retained attempts/mounts as owner; completion alone is not delivery success.

Real stage 5b qualification on 2026-11-11 passed separately from stage 5a.
The owner authorized real VM/media qualification and installation of the missing
host xorriso package and dependencies. No binaries were rebuilt. Controller and
installed importer bytes match signed commit `14a3c17`; the three existing ELF
artifacts and their unchanged provenance match the clean selected source
`88d05d55f05c72cbc2a6a9ab0826486f8b3efa8a`. Source/provenance agreement remains
recorded consistency evidence, not build-origin attestation.

Environment: Debian 13/WSL2 KVM, Python 3.13.5, qemu.qmp 0.0.6,
QEMU/qemu-img 10.0.13, xorriso 1.5.6, SeaBIOS and `pc-i440fx-10.0`.
Guest: kernel 6.12.115+deb13.1-amd64, systemd 257.13-1~deb13u1,
qemu-ga 1:10.0.13+ds-0+deb13u1. A separately prepared standalone image contains
only the trusted installed helpers and image prerequisites. Serial provisioning
installed those trust anchors before the delivery cases; it never supplied an
L2 package. The production main path used only the ISO device for package bytes,
with no NIC, SSH, 9p, virtiofs or shared folder.

Four final cases passed on independent overlays under sequential leases of the
same stand:

- Normal ISO import, verified receipt, explicit QGA session recovery and receipt
  inspection, followed by the existing LinuxL2Job submit/collect and assessment.
- A qualification wrapper discarded the real import PID response and closed the
  QGA session while import continued. Job creation and repeated stage were
  refused. Explicit recovery read the saved receipt, then the existing L2 job
  completed. Exactly one importer exec occurred, without retransferring files.
- A pre-existing empty guest destination was retained; no receipt or job allowed.
- A pre-existing nonempty destination retained its sentinel; no receipt or job
  allowed. Failed imports did not become successful delivery on VM completion.

Both complete L2 reports contain all 34 scenarios: 33 PASS, the unchanged
`missing-group.refusal` SKIP requiring a separate groupless VM, zero FAIL/ERROR,
and cleanup PASS. Successful import left no attempt mount. Duplicate submit
was refused. Repeated leases, child/control completion and retained artifacts
were checked. Diagnostic provisioning/console attempts are retained separately;
no production checks were bypassed to turn them into successful cases.

The original base remains 476774400 bytes with SHA-256
`f4a05e7aba2c889437f6bce798926a381b7ebf257178e75d140493f817b74de8`.
The separately prepared base is 1259470848 bytes with SHA-256
`f971ba9e6810bafd452d4969c5611b23f670d5df2cdc4af3e9479a84135ebcfe`.
Per-run ISO hashes and final receipts are retained for independent comparison.
Linux offline checks passed: 265 tests, 18 platform skips; targeted L2/media/
executor checks passed 41 tests without skips. Local evidence is retained in
`tools/vm/logs/qga-5b-qualification-20261111/`, including the qualification harness,
preflight/source hashes, both image descriptors, raw reports, receipts,
per-run ledgers/completion and serial logs.

This qualifies only the recorded delivery configuration and cases. Mount/unmount
failure injection, malformed media and device ambiguity remain offline tests;
real forced-unmount failure and arbitrary transport fault timing are UNRUN.
Provisioning used sync and confirmed hard-off after guest shutdown did not
confirm; no power-loss durability is claimed. Controller restart, other images
or tool builds, full legacy host-orchestration parity and network protection
remain unqualified. Security invariants stay **UNVERIFIED**; release gate stays
closed.

## Stage 5c: one-command exploratory Linux L2

The sequential controller reuses disk preparation, immutable ISO delivery,
receipt gating, LinuxL2Job and its existing assessment. Stage 5a/5b qualification
above remains evidence for those recorded APIs/configurations. **Real one-command
qualification passed on 2026-11-11 for the configuration and cases below.** No L3 or
network lab is included. Security invariants remain UNVERIFIED; release gate false.

Copy [execution.example.toml](execution.example.toml) to an owner configuration.
Replace the image size/hash placeholders with the independently verified trusted
prepared image descriptor. Supply absolute installed QEMU/qemu-img/BIOS/xorriso
paths, a state directory and stand ID, the exact immutable L2 content directory,
and the source checkout matching its existing artifacts/provenance. The image
must already contain the trusted launcher/import helper, stand marker, group,
two ordinary test accounts, Python, QGA and the stage 5b prerequisites above.
Nothing builds, installs, downloads, provisions accounts or deletes evidence.

`rosetun.matrix.execution.v1` is separate from assessment profile schema 1.
Every table rejects unknown/missing fields. Only exploratory, Linux x86_64/KVM,
BIOS i440fx `pc-i440fx-10.0`, host CPU and QGA are supported. The descriptor
and QEMU fields retain their existing contracts. There is no configurable argv,
shell command, Python adapter or expected boot ID. Scenario/unit timeouts accept
10..86400 seconds, job 60..7200; defaults in the example are 30/180/900.
Stage deadlines are elapsed seconds: preparation 600 by default (each external
command also retains its existing lower limit), boot at most 300, import at most
900; execution must equal job + 180. The controller checkout is recorded separately
from `source_checkout`. A newer controller with the older verified artifact
checkout, as in stage 5b, is supported; those two revisions need not match.

```sh
python -m tools.vm.matrix run linux-l2 --config /srv/linux-l2.toml --dry-run
python -m tools.vm.matrix run linux-l2 --config /srv/linux-l2.toml
```

Dry-run hashes the base and immutable input, compares checkout scripts/catalog,
checks paths/configuration and reads existing ledgers. It creates no directory,
lease, run or file, invokes no external executable and needs no qemu.qmp package.
It explicitly defers Git HEAD/status/diff provenance matching, executable version,
qemu.qmp and KVM availability checks to execution. It does not qualify the backend.
Read-only doctor/plan/report/runs/recover remain available without qemu.qmp.
An explicit execution command selects the stand without interactive confirmation.

stdout is one versioned `rosetun.matrix.execution-summary.v1` JSON object; stderr
contains short stage progress, run ID and artifact directory. Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Accepted exploratory L2 assessment, confirmed VM completion, no unresolved infrastructure error |
| 1 | Collected L2 assessment rejected (including required FAIL/ERROR/SKIP or failed guest cleanup) with confirmed VM completion |
| 2 | Configuration, delivery, infrastructure, telemetry, evidence or teardown failure |
| 130 | KeyboardInterrupt, even if subsequent teardown succeeds |

Code 0 never means release acceptance. Delivery and execution are distinct from
VM completion. An uncertain exec is never repeated: only the original object
may inspect its receipt/results after bounded channel recovery. Missing or foreign
evidence cannot pass. Original and close failures are kept together by stage,
exception kind and safe reason code; arbitrary exception text/stderr is omitted.

Waiting deliberately favors a small auditable budget over low latency. Initial
QGA startup has at most 20 observations, each capped at 10 seconds, spaced by up
to 15 seconds, inside the boot deadline. Before any guest operation, failed initial
channels may be closed/replaced; this does not consume post-operation recoveries.
Import retains its 48-RPC, 24-status-poll, 900-second limits. A lost import response
waits until at most 60 seconds before that deadline, then reads the receipt after
one recovery. A missing receipt fails. The ordinary import path also refreshes
the QGA session before receipt/job work. At most one additional recovery for
unknown submit and one for failed collection are allowed: at most three of the
existing four recovery slots, never another helper/launcher exec.

After submit the controller waits **at most job timeout + 125 seconds**, including the existing 120-second systemd
stop/cleanup allowance and five seconds for final publication. Since stage 8c it reads the job's status file on the way
(see "Waiting by reading the status") and collects as soon as it says `finished`; a job that does not say so is
collected after the whole wait, 1025 seconds for the default 900-second job, or 7325 for the maximum 7200-second job.
One final collection may follow 15 seconds later. No increased collect limit is needed. All reads remain under the
job + 180 second deadline. A normal boot check costs five RPCs (info/ping/open/read/close), submit
six, and collection with the maximum 256 KiB report costs at most 28: two boot
checks (10), launcher status (1), two <=8 KiB status reads (6), report open + nine
reads including the overflow/EOF probe + close (11). Thus submit plus two maximum
collections needs at most **62 of 112 job RPCs**, independent of job duration; the at most 16 looks of the wait
(3 RPCs each) take 48 more, 110 in all, and stop at 52 spent.
The refreshed QGA session uses five recovery-observation RPCs, eight receipt RPCs,
then at most 62 job RPCs, totaling 75 of 128. Unusual short reads may exhaust the
unchanged limits and fail explicitly. Recovery opens a new bounded session;
it never resets the job/import counters or deadlines. Loss of telemetry cannot
be converted to acceptance by teardown.

RPC and elapsed-time budgets are simultaneous ceilings, not reserved successful
latency. Each RPC is capped at five seconds and the absolute job deadline. The
nominal 55-second collection window after job + 125 shrinks by submit/recovery
time; a maximum report whose every RPC takes five seconds cannot fit and must
fail within the unchanged deadline. No timeout or RPC allowance is silently raised.

Artifacts remain under `<state_directory>/runs/<host_run_id>/`. Identity linkage
is registered and fsynced before disk/media preparation. The summary is also
registered and initially written before launch; completion requires its existence,
not its final bytes. After close, the final summary replaces that placeholder
atomically and records hashes/paths of available evidence, original assessment,
delivery/execution states, completion and manual-recovery flag. It does not hash
itself, publish the private owner token or embed raw stderr. Lifecycle journal
bytes remain frozen after completion. A final summary write error yields code 2;
the retained placeholder is not a successful result. No run directory is retried.

```sh
python -m tools.vm.matrix runs --state-directory /srv/rosetun-state
python -m tools.vm.matrix recover --state-directory /srv/rosetun-state
```

Both commands only inspect records. A preparation failure before any VM has no
fabricated completion; its unresolved ledger blocks reuse. An unconfirmed child
exit/control closure retains the original lease while the controller lives,
and the ledger blocks reuse after exit. Controller restart recovery, attaching
to a process from its PID, cleaning old runs and repairing completion are not
implemented. The owner must diagnose retained evidence/resources independently.
Never delete a blocking record merely to obtain another lease.

Owner repeat qualification plan:

1. Record prepared image/helper/tool hashes and source identities, run the dry-run
   command above, then the ordinary command directly, without a qualification
   harness. Expect all existing L2 rows, the documented optional SKIP, cleanup PASS,
   code 0, matching receipt hashes and verified completion. Save stdout/stderr.
2. On a separate overlay, pre-create the guest import destination using the
   owner's provisioning procedure. Run the same command. Expect import refusal,
   code 2, retained destination/evidence and no launcher submission.
3. On a separate run, stop/restart the guest agent during import or execution
   through the owner's console. Confirm exactly one importer/launcher intent;
   recovery reads saved evidence only. Absent/foreign evidence must give code 2.
4. Interrupt a run with Ctrl-C. Expect code 130 and either confirmed completion
   or an explicit manual-recovery requirement, with all overlay/ISO/logs retained.
5. Use runs/recover to verify completion, compare base/ISO hashes and run another
   ordinary command on the same stand. Only verified lifecycle completion permits
   lease reuse; unresolved cases require owner diagnosis. Return the versioned
   summary, assessments, receipt and completion if any expectation differs.

Real stage 5c qualification passed on 2026-11-11 using the existing Debian 13/WSL2
KVM stand, QEMU/qemu-img 10.0.13, SeaBIOS, `pc-i440fx-10.0`, xorriso 1.5.6,
Python 3.13.5 and the existing qemu.qmp 0.0.6 environment. No artifacts were built,
dependencies installed or images downloaded. The unchanged prepared stage 5b
image and immutable L2 input were reused. Artifact provenance matches clean source
`88d05d55f05c72cbc2a6a9ab0826486f8b3efa8a`; all controller Python bytes match
signed implementation commit `3343866`. Initial HEAD was `4decec1`.

All five cases used sequential leases of the same stand ID and existing ledger,
with scenario/unit/job timeouts 30/180/180 and execution deadline 360 seconds:

| Case | Observed result |
| --- | --- |
| Ordinary direct CLI, without a qualification harness | Exit 0, accepted L2 and verified completion |
| Existing empty guest import destination | Exit 2, no verified receipt, no L2 submission, verified VM completion |
| Lost real QGA report response and closed client | Retained 4096-byte prefix, channel recovery, second collection, exit 0 |
| POSIX SIGINT during wait after real submit | Exit 130, original KeyboardInterrupt retained, verified VM completion |
| Another ordinary CLI after the preceding cases | Exit 0 on the same stand, accepted L2 and verified completion |

The three complete L2 reports each contain 33 PASS, the unchanged optional
`missing-group.refusal` SKIP, zero FAIL/ERROR and cleanup PASS. Each case recorded
exactly one importer intent; each eligible case recorded exactly one launcher
intent. Ordinary runs used 26 job RPCs, recovered collection 37 of the existing
112. No production adapters, clock, assessment or orchestrator were replaced.
Separate diagnostic wrappers created the refusal condition, discarded a real
report response after an initial short read, or sent SIGINT; ordinary cases
invoked the CLI directly. This tests that specific channel loss, not all agent
daemon failures or transport timings.

All five new completion proofs, final summary readback, frozen lifecycle journals,
base/ISO hashes, owner-token absence in public evidence and correspondence to the
signed controller bytes were independently checked. All disks, media and evidence
remain retained. Read-only runs/recover were also executed. Evidence and diagnostic
scripts are under `tools/vm/logs/qga-5c-qualification-20261111/`; resource ledgers
remain in the reused stage 5b state directory referenced by each summary.
Full Linux offline tests passed: 288 tests, 18 platform skips with qemu.qmp;
without that optional package, 288 tests passed with 22 skips.

Real runs with the default 900-second or maximum 7200-second job timeout, maximum
report size, new CLI lost-import/lost-submit timing, arbitrary daemon faults,
unconfirmed teardown, controller restart and other images/tool builds remain
UNRUN here. Existing API qualifications and offline rejection/budget tests remain
separate evidence. This qualifies the recorded exploratory L2 cases only;
network security invariants remain UNVERIFIED and release gate remains false.

## Isolated two-VM lab smoke (stage 6a)

This separate infrastructure path does not run Rosetun, sing-box, Kill Switch
scenarios or `run-l3.sh`. Linux L3 has **not** been migrated. All security
invariants remain **UNVERIFIED**, release gate **false**, even with smoke exit 0.

```text
test VM                     lab VM (router + observer)
192.0.2.2/24     Ethernet    192.0.2.1/24
2001:db8:6a:1::2/64 <------> 2001:db8:6a:1::1/64
                            |
                  rt-route 203.0.113.1/24, 2001:db8:6a:2::1/64
                            | veth (inside disposable lab VM only)
                  rtlab namespace / rt-target
                            203.0.113.2/24, 2001:db8:6a:2::2/64
                            HTTP :8080, UDP echo :9000, DNS UDP/TCP :53
```

One profile, eight probes: HTTP, UDP nonce echo, authoritative DNS over UDP and
TCP, each over IPv4 and routed IPv6. DNS answers only the current run's exact
`<run>.<nonce>.lab.test` A questions, with the fixed documentation A answer;
RD/RA are clear and no resolver or recursion is used. Each probe has a fresh
96-bit nonce and 128-bit run ID, also present in HTTP/UDP payloads. Neither an
old packet nor an empty capture qualifies anything. The controller checks the
actual answer, target log, and pcap request/response addresses, family, transport,
service port and matching client port. IPv6 neighbor pings cannot substitute.
Unsupported fragmentation/segmentation or missing payload evidence fails closed
as infrastructure UNVERIFIED; this is not a general TCP reassembly tool.

`lab.py::lab_smoke` and CLI `lab-smoke` use a separate `lab.v1` configuration,
never an assessment profile. Copy `lab.example.toml` and replace paths, image
sizes and SHA256 placeholders with owner-verified values. Python 3.11+, Linux
x86_64 KVM, QEMU/qemu-img **10.0.13**, SeaBIOS, `pc-i440fx-10.0` and the existing
`qemu.qmp==0.0.6` are required. No build/install/download is performed.

```sh
python -m tools.vm.matrix lab-smoke --config /srv/lab.toml --dry-run
# Owner only, after preparing the images and checking isolation:
python -m tools.vm.matrix lab-smoke --config /srv/lab.toml
```

Dry-run reads configuration and local prerequisites only, without creating a
lease, files, subprocesses or sockets. It does not qualify the binaries or images.
Execution verifies binary versions and base-image integrity, takes one lab lease,
creates two separate run/manifest/writable overlays and fresh UUIDs, then starts
both VM processes through the existing lifecycle. The identity ledger explicitly
links both members, role and endpoint before endpoint creation. MACs are
`00:00:5e:00:53:61` (test) and `00:00:5e:00:53:62` (lab); devices are `test-wire`
and `lab-wire`. Guests select by unique MAC and role, never an eth0 assumption.

The sole data channel is a connected `AF_UNIX/SOCK_STREAM` socketpair passed to
QEMU as `-netdev stream,id=labwire,addr.type=fd,addr.str=<fd>,server=off` and
`virtio-net-pci`. There is no listener, reconnect, user NAT, hostfwd, TAP, bridge,
host route or host namespace. `-nodefaults -nic none` remains, preventing an
implicit second NIC. QMP and QGA use separate inherited control socketpairs.
Controller copies of the network descriptors close before guest probes.
No Ethernet forwarding is implemented in Python.

Exact upstream support was checked against QEMU **v10.0.13**:
[NetdevStreamOptions](https://github.com/qemu/qemu/blob/v10.0.13/qapi/net.json),
[stream client](https://github.com/qemu/qemu/blob/v10.0.13/net/stream.c), and
[socket_connect FD branch](https://github.com/qemu/qemu/blob/v10.0.13/util/qemu-sockets.c).
These netdev fields use SocketAddress, independently of chardev syntax.
The recorded descriptor/channel qualification is described below.

The second VM is authorized only by a LabPair bound to the two original runs
and their original live lease; arbitrary second starts remain forbidden. Existing
single-VM L2 plans and networking behavior are unchanged. Each VM has its own
completion proof. The lab summary is successful only after both verified VM
completions and channel close, without errors and with qualified evidence.
Failure starting the second VM closes the owned first VM with bounded hard-off;
failed child/control/channel closure cannot produce lab success. Unresolved
ledgers block reuse even after the controller exits. Artifacts are retained;
there is no controller-crash recovery, automatic cleanup or PID attachment.

Prepared image contract (provisioned separately from `lab-smoke`):

- Both images are disposable, trusted, BIOS Linux x86_64 with root qemu-ga over
  virtio-serial, Python 3, iproute2 at `/usr/sbin/ip`, procfs/sysfs and permission
  for guest-exec/status and bounded guest-file reads. Install
  `linux/guest/lab-entry.py` as `/usr/local/libexec/rosetun-lab/entry`, executable,
  and `matrix/lab_protocol.py` beside it as `lab_protocol.py`. Files and their
  parent directories must be root owned and not writable by ordinary users.
  Use the exact reviewed controller/helper bytes. No SSH or firewall management
  exceptions are needed. Guest root/QGA are trusted management surfaces.
- `/etc/rosetun-lab-role` contains exactly `test` or `lab`. No network manager,
  DHCP, SLAAC, external DNS, VPN, Rosetun, extra NICs or default external routes.
  Disable cloud-init networking and socket activation of unwanted network
  services; disabling only a service's enablement does not prevent reactivation.
  On lab, mask networkd and its socket so they cannot remove helper-owned static
  addresses. On test, use one MAC-matched static network profile with priority
  over distribution defaults. Disable SSH services/sockets in both images.
  Both images have IPv6 enabled. Firewall policy must permit the fixture paths;
  the helper does not flush existing firewall policy to hide a provisioning error.
- Test image: preconfigure addresses shown above, link up, and **only** static
  routes `203.0.113.0/24 via 192.0.2.1` and
  `2001:db8:6a:2::/64 via 2001:db8:6a:1::1`. Disable DAD for deterministic static
  provisioning, or let it finish before image readiness. Test helper only probes;
  it does not mutate routes or services.
- Lab image: initially unaddressed data NIC; no `rtlab`, `rt-route`, `rt-target`
  or `/run/rosetun-lab` claim. Root needs CAP_NET_ADMIN, CAP_SYS_ADMIN (setns),
  CAP_NET_RAW, namespace/veth support and writable forwarding sysctls. The helper
  checks DMI UUID, observed boot ID, fixed role, unique MAC and one-shot run claim
  before changing addresses, forwarding, routes or services **inside lab only**.
  Services are Python stdlib, with no package downloads. No host mutations.

Capture uses AF_PACKET on the lab ingress interface, outside test VM, recording
Ethernet pcap plus controlled target logs. The observer is independent of test VM;
**the lab VM itself remains trusted**, so this is not independence from lab root.
The controller saves/reads back `capture.pcap`, `targets.json`, `health.json` under
the lab run and records SHA256. Summary separately records VM/QGA readiness,
IPv4/IPv6/services, observer, evidence completeness and both completions. Exit 2
is infrastructure failure/UNVERIFIED, never 'no leaks'; interrupted runs use 130.

Fixed limits: capture 60 seconds, 128 KiB total pcap, 2048-byte full frames
(no silent truncation), kernel receive buffer requested 256 KiB; logs/health and
helper JSON each 32 KiB, eight accepted target requests, socket waits 5 seconds
(a server for a request, a client for an answer, the test machine for the echo of a
marker; `REQUEST_TIMEOUT`, `RESPONSE_TIMEOUT` and `MARKER_TIMEOUT` in
`lab_protocol.py`, once 1 and 2 seconds), guest command timeout 5 seconds, boot wait 120
seconds per VM, guest facade 90 seconds, 40 status polls at 0.5 seconds per call,
file reads 16 KiB and the unchanged QGA 128-RPC ceiling. Normal VM close retains
the existing bounded lifecycle behavior. Kernel PACKET_STATISTICS drops, write
errors, overflow, capture deadline, incomplete files, missing required traffic and
nonzero helper status all prevent qualification. TCP handling is deliberately
small and can reject short/split requests as infrastructure failure.

**Nested virtualization.** On a stand that runs KVM inside another hypervisor (WSL2
on Hyper-V), give each machine two vCPUs: set `vcpus = 2` in the `[qemu]` table of
the lab configuration (`qemu.vcpus`). With one vCPU per machine a guest can stop for a
second or more while the other one answers, which is the suspected cause of lab
smokes that passed in one run and failed in the next with a connection that never
closed. This is a recommendation for the stand: the default of `vcpus` and the
lab example files stay at 1. A server that waits for a request holds the whole observer
loop for up to the wait above, so a stalled client costs a few seconds, not the run.

Owner repeat qualification:

1. Review image/helper hashes, role markers, static routes, disabled managers,
   no external interfaces/routes and no installed VPN software. Run the dry-run
   command above, then the ordinary smoke command on the isolated prepared stand.
   Expect eight exact answers, bidirectional evidence for each, all infrastructure
   dimensions PASS, two verified completions, closed channel, exit 0, release false.
2. Independently read the saved pcap (e.g. owner's installed Wireshark), JSON logs,
   SHA256 and both completion proofs. Confirm routed IPv6 target rather than
   link-local traffic; compare read-only base hashes before/after.
3. On fresh overlays, use the owner's guest console to remove a target address
   while capture is active (target unavailable), terminate the observer process,
   and separately disconnect `test-wire` with QMP `set_link` during readiness.
   Every case must yield exit 2, qualified false and UNVERIFIED, with teardown
   evidence retained. An answering target without matching capture cannot qualify.
   No missing-packet case is a protection/blocking PASS.
4. Interrupt, inspect retained ledgers with `runs`/`recover`, and verify both VM
   exits before reusing the stand. Diagnose blocked reuse; never delete a ledger
   merely to bypass uncertain completion. Return both run directories, stdout,
   stderr and summary if any expected result differs.

Future legacy mapping (not applied to `run-l3.sh` or PowerShell): HOST_ADDRESS
will mean the lab VM's internal `192.0.2.1`, NODE_PORT a future VPN fixture port
(**not** HTTP :8080), PROBE_ADDRESS routed `203.0.113.2` (IPv6 counterpart above),
DNS_PROBE_ADDRESS routed `203.0.113.2:53`. Existing peer `198.51.100.1/.2` stays
reserved, with no overlap. HTTPS with validated certificate trust, VPN endpoints,
DHCP/SLAAC, interface changes and transfer of every old L3 check with distinct new
evidence are next-stage work. HTTP smoke cannot satisfy legacy HTTPS/VPN checks.

### Recorded real infrastructure qualification

Real stage 6a qualification passed on 2026-11-11 on the existing Debian 13/WSL2
KVM stand: QEMU/qemu-img 10.0.13, SeaBIOS, `pc-i440fx-10.0`, Python 3.13.5 and
qemu.qmp 0.0.6. Controller and installed production helper bytes correspond to
signed implementation `2b7cbb3`. No builds, package installation, image downloads,
host network interfaces/routes/namespaces or external network connections were
used. Two new, separate flattened images were provisioned from the existing
verified L2 base using serial in disposable VMs without a NIC. The source base
remained unchanged. Provisioning completion and helper SHA256 were checked.

| Case | Observed result | Completion |
| --- | --- | --- |
| Ordinary direct `lab-smoke` CLI | Exit 0, eight exact answers, both families/services/observer/evidence PASS | Both verified |
| Target addresses removed inside lab namespace after capture readiness | Exit 2, qualification false, no protection PASS | Both verified |
| Observer process stopped after capture readiness | Exit 2, qualification false | Both verified |
| Lab data interface down after capture readiness | Exit 2, qualification false; QGA management remains available | Both verified |
| Another ordinary direct CLI on the same stand/ledger | Exit 0, eight answers and all infrastructure dimensions PASS | Both verified |
| Second QEMU child spawn refused with a real first VM running | Exit 2, first child boundedly stopped; no fabricated second completion | First verified; second run quarantined |

The three network faults used an additional preinstalled fixed qualification
entry `/usr/local/libexec/rosetun-lab/qualify-fault`, with three allowlisted
actions and VM/boot/run/role checks. Diagnostic QGA calls never execute a shell.
The controller's production probes, replies, qualification and close operations
were retained. The spawn-refusal harness raises an OS error at the second Popen;
the first process and its teardown are real. That case uses its own stand/ledger:
its unresolved member blocks reuse, while the ordinary stand remains reusable.

Both positive captures were read back, parsed and matched to the saved nonces,
responses and target logs; record lengths, complete frames, SHA256, routed IPv6,
zero drops, absent DHCP and both VM completion proofs were checked. All eleven
VM processes actually started in these six cases were reaped with verified
completion; no QEMU remained. Ten completions belong to the ordinary stand,
one to the dedicated spawn-refusal stand. Image/source integrity and ordinary
lease reuse were checked independently. Linux offline regression: **307 tests,
18 skips, OK**. Artifacts, prepared image descriptors/configuration and diagnostic
fixtures remain in `tools/vm/logs/lab-6a-qualification-20261111/` locally.

Earlier provisioning/diagnostic attempts remain separate, unqualified evidence:
inherited network activation produced DHCP, and extra serial fault instrumentation
failed QGA readiness before injection. Corrected prepared images disable that
activation; fixed-entry injection avoids the extra console. Unresolved experimental
ledgers were retained, without invented completion or automatic recovery.

UNRUN: real capture overflow/write failures or kernel drops, arbitrary transport
faults and unconfirmed termination, controller restart, other images/tool builds,
VPN and HTTPS fixtures, and all existing L3 protection scenarios. Offline rejection
tests cover the documented limits; they do not make these real cases qualified.
This record qualifies infrastructure only. Linux L3 remains unmigrated, security
invariants remain **UNVERIFIED**, release gate remains **false**.

## Lab leak observer (stage 6b)

Stage 6a shows that the expected exchanges happened. Stage 6b adds the opposite
claim, "nothing else was sent", for the two-VM lab only. Rosetun, sing-box and
`run-l3.sh` are untouched and L3 is still not migrated.

The summary keeps the 6a `qualification` and adds `leak` beside it, with
`leak_reason`, `observer_reasons` (every reason that would stop `NONE`, not only the
first), `categories`, `unexpected`, `canary`, `canary_flows`, `canary_other` and
`window`:

- `DETECTED`: at least one captured frame is `unexpected`. This holds whatever
  the observer's health: a leak that was seen stays a leak.
- `NONE`: no `unexpected` frame; the opening and closing markers each appear once
  in both directions, the opening one before every exchange frame and the closing
  one after; the whole capture parsed and stayed under its size limit; the
  observer was ready and its health is clean (`error` false, `dropped` 0,
  `finished` true); both markers were answered to the test machine; and the lab
  machine's own clock puts the capture start before both markers and the capture
  end after the closing one.
- `UNVERIFIED`: everything else, with the first reason in `leak_reason`. It never
  turns into `NONE`. An empty or header-only capture, a stopped observer, a downed
  link before the closing marker, a truncated record, a fragment between other
  machines or any frame the parser cannot read all land here, as does a capture that ends before the
  closing marker.

Every parsed frame has exactly one category, counted in `categories`:

| Category | Meaning |
| --- | --- |
| `probe` | A frame of one of the eight expected exchanges: same family, protocol, addresses, hardware addresses, service port, and the run's marker or answer in the payload. A TCP segment without data counts only on a connection that carried a matching request or answer, so SYN, ACK, FIN, RST and repeats of that connection are probe frames and a bare connection to a service port is not. All probe frames with data and every SYN must lie between the opening answer and the closing request; the data-free, SYN-free segments of a connection that carried data (the final ACK or FIN of the close) may also come after the closing request, wherever in the capture, and do not affect the order. |
| `marker` | The run's opening or closing marker, request or answer. |
| `infrastructure` | Only the listed service traffic between the two machines, kept in one table (`INFRASTRUCTURE`) next to the addresses in `lab_protocol.py`: ARP requests and replies between `192.0.2.2` and `192.0.2.1` (a request is the broadcast or unicast one with a zero target hardware address, or the unicast neighbor poll the test machine sends the lab, whose destination and target hardware address are the lab's: how a stack checks that a neighbor it knows still answers, RFC 1122 2.3.2.1; the same frame from the lab to the test machine, or with any other address, stays `unexpected`), and ICMPv6 neighbor solicitation and advertisement between the two lab addresses and their link-local addresses, router solicitation and advertisement, and multicast listener messages. |
| `unexpected` | Any other frame whose sender or receiver hardware address is the test machine's, or whose sender or receiver address is the test machine's: ICMP, another port or target, another prefix, another EtherType, broadcast or multicast outside the table, and any IPv4 or IPv6 fragment sent by or addressed to the test machine (the lab exchanges are never fragmented; the description is `fragment`, judged from the Ethernet and IP headers only). A fragment whose IP header cannot be read, or one between other machines, stays `unparsed`. |
| `foreign` | A frame with neither the test machine's hardware address nor its addresses, such as the lab machine's own traffic. Counted; it never changes the verdict. |

`unparsed` counts frames that could not be read. `unexpected` lists at most the
first 16 as tuples of EtherType, family, protocol, addresses, ports and size, never
payload; the addresses are documentation values. Frames before the opening marker
and after the closing one are judged like any other, but without both markers in
order the verdict cannot be `NONE`.

The markers are two UDP datagrams to port 9100 of the IPv4 target, sent by the test
machine before the first exchange and after the last, each carrying the run ID, a
fresh nonce and `open` or `close`. The target answers and the test machine checks
the answer. The lab observer records its own monotonic capture start, capture end
and the times it served each marker in `health.json`. Times from the two machines
are never compared: the test machine's send times appear in `window` for the
journal only.

Positive control:

```sh
python -m tools.vm.matrix lab-smoke --config /srv/lab.toml --canary
```

After the ordinary exchanges and before the closing marker the test machine sends
one UDP datagram to port 9999 of the target, which nothing serves, and one TCP SYN
to `203.0.113.9`, which nothing holds. It waits for no answer. Frames the lab's
router returns for these two packets (ICMP errors that quote them) belong to the
same flows. An ordinary run exits 0 only when `qualified` is true and `leak` is
`NONE`. A `--canary` run exits 0 only when `qualified` is true, `leak` is
`DETECTED`, `canary_flows` is exactly `tcp` and `udp`, `canary_other` is 0, and the
window is proven as for `NONE`: both markers found and ordered and
`observer_reasons` empty. A seen canary in a capture that could not have said `NONE`
proves nothing about the observer. Any other combination exits 2.

Allowances are for the L3 scenarios that switch the network, not for `lab-smoke`,
which declares none and whose command line has no option for them. Such a scenario
passes a set of names to `classify` or `leak_verdict`; a frame matching a declared
name is counted under `categories.allowed[name]` instead of `unexpected`, and the
key `allowed` exists only when names were declared. The fixed table `ALLOWANCES`
next to `INFRASTRUCTURE` holds `arp-announcement` (broadcast naming the sender's own
address as sender and target), `arp-probe` (broadcast from `0.0.0.0` for the
sender's own address), `ipv6-dad` (neighbor solicitation from `::` to the
solicited-node group of the sender's own or a link-local address) and
`ipv6-unspecified-rs` (router solicitation from `::` to `ff02::2`). The sender is
the test or the lab machine. An unknown name is a `ValueError` before parsing.
Temporary and other IPv6 addresses are not covered: that traffic stays `unexpected`.

This changes the helper bytes. The owner must reinstall
`linux/guest/lab-entry.py` and `matrix/lab_protocol.py` in both images and update
the image descriptors before any real qualification; the 6a record above was made
with the earlier bytes and does not cover this stage.

Owner qualification on the prepared stand, after reinstalling the helper:

1. Ordinary `lab-smoke`: exit 0, `leak` `NONE`, both markers found and ordered.
   If an unlisted frame shows up (for example IPv6 router solicitation or
   multicast listener traffic outside the table), the run is `DETECTED`; send the
   summary instead of widening the table.
2. `lab-smoke --canary`: exit 0, `leak` `DETECTED`, `canary_flows` `["tcp", "udp"]`.
3. `lab-smoke --control extra-packet`: exit 0, the leak `DETECTED` (stage 7c1).
4. `lab-smoke --control observer-stopped`: exit 0, `leak` `UNVERIFIED`, never `NONE`
   (stage 7c1).
5. `lab-smoke --control link-down`: exit 0, `leak` `UNVERIFIED` (stage 7c1).
   Fallback without the commands: send one extra packet by hand from the test machine's console
   during capture (exit 2, `DETECTED`), stop the observer in the middle of the window, or run
   `set_link test-wire off` through QMP before the closing marker: `UNVERIFIED`.
6. Read the saved pcap in Wireshark: the frame counts per category match
   `categories` in the summary.

### Why a lab helper failed

A run that ends `UNVERIFIED` or with `operation-failed` has to say where. Two
records do.

- **Observer.** When `serve` stops on an error, `health.json` carries three fields
  next to `error: true`. `error_reason` is the exception class and a short code
  (`ValueError:capture-limit`, `OSError:eio`), at most 96 characters and with no
  address outside the documentation ranges. `error_at` is the lab machine's own
  monotonic clock: compare it with `capture_started` and the marker times, never
  with the test machine's. `error_in` is where the observer was: `capture`,
  `marker`, `http`, `udp` (also for `dns-udp`), `dns-tcp`, `https`, `dns`, `doh`,
  `node`, `setup` or `finish`. Only the first failure is kept. `finish` covers the
  deadline and the closing steps (the pcap header, `dns.json`, `https.json`,
  `node.log`, `targets.json`, which no longer hide the health record when they
  fail); a server thread of DNS or DoH that dies, and an overflow of `dns.json`,
  are `dns` or `doh`. A clean run has none of the three fields.
- **Test machine.** An exchange that fails makes the helper print
  `lab-helper-failed:<name>:<family>:<reason>:<elapsed>ms`, for example
  `lab-helper-failed:http:6:timeout:5003ms`. The name is the service (`http`,
  `udp`, `dns-udp`, `dns-tcp`), `https-direct`, `https-tunnel`, `dns-plain`,
  `dns-doh-singbox`, `marker-open`, `marker-close`, `canary`, or `client` and
  `dns-client` for starting the throwaway sing-box. The reason is the helper's own
  fixed word, an errno name (`econnrefused`) or `timeout`. Refusals before the first
  marker keep their plain reason (`missing-sing-box`). Any other exception, one the
  helper did not expect (a failure while printing its own answer, a bug), prints
  `lab-helper-failed:<class>:<message>` in lowercase, cleaned as `error_reason` is: at
  most 96 characters and no address outside the documentation ranges, for example
  `lab-helper-failed:typeerror:object-of-type-bytes-is-not-json-serializable`. The
  bare `lab-helper-failed` is never printed.

The controller copies a code that fits `[a-z0-9:._-]{1,96}` into the error row of
the summary as `helper_reason`. `reason` stays what it was (`lab-helper-failed`, or
`lab-helper-failed-<word>` for a plain refusal). A failed helper always has a
`helper_reason`: when its stderr held no code that fits, was cut by the output limit
or came from a helper that still printed the bare word, it is `reason-not-reported`,
which names the controller's own gap and never something the guest said.

#### One exchange does not stop the observer

An error in one connection or datagram of a target service (`http`, `udp`,
`dns-udp`, `dns-tcp`), of the HTTPS target, or a marker with the wrong content or in
the wrong order, is that exchange's failure. The connection is closed, the target's
log gets a refusal row `{"service", "family", "reason"}` (`targets.json`;
`https.json` for the HTTPS target; at most eight rows per log, so a stream of bad
clients stays bounded), and the capture goes on. The exchange does not qualify:
the log has no answered row for it, or has a refusal row, so `qualified` is false.
`leak` is judged from the capture as always, and the markers the observer did serve
stay in `health.json`. A refusal row has no `response` and is never counted as an
answered exchange: not in the limit of eight answered rows of `targets.json`, not in
the sixteen of `https.json`, not in the `https` block of an L3 summary.

What still stops the observer, with `error: true` and `UNVERIFIED`, is its own
work: the capture socket, writing the pcap, the evidence disk, the size limits
(the capture, more than eight answered rows, sixteen in `https.json`, `dns.json`)
and the deadline. A failed exchange is a failed exchange; a failed observation is
unknown. The servers of DNS and DoH already answered a bad client on their own
threads and are unchanged.

This changes the helper bytes: the owner installs `linux/guest/lab-entry.py` and
`matrix/lab_protocol.py` in both images again and updates the descriptors.

## Stage 7b1: lab VPN node and HTTPS target

Stage 7b1 gives the lab two more fixtures and a way to qualify them: a VPN node
and an HTTPS target. Rosetun is **not** started, `run-l3.sh` is untouched and L3
does not run through the lab yet. The only Shadowsocks client is a throwaway
sing-box on the test machine whose job is to prove the node works. Security
invariants stay **UNVERIFIED** and the release gate stays false.

```text
test VM 192.0.2.2 --- lab VM 192.0.2.1:8388   VPN node: sing-box, Shadowsocks aes-128-gcm
                           |  direct out via rt-route 203.0.113.1
                      rtlab 203.0.113.2:443    HTTPS target: Python ssl, IP SAN, lab CA
```

**What it checks.** That the node accepts a Shadowsocks connection from the
test machine and relays it, that the HTTPS target answers with a certificate
the system store of the test image trusts (no `-k`, no `--cacert`), and that the
observer tells the two paths apart on the wire:

- `https-direct`: the test machine connects straight to `203.0.113.2:443`. The
  target's log shows source `192.0.2.2`.
- `https-tunnel`: a throwaway sing-box client on the test machine (SOCKS on
  `127.0.0.1` only, Shadowsocks out, no DNS) reaches the same target through the
  node. The target's log shows source `203.0.113.1`, the router side of the lab.
  On the wire it is only TCP to `192.0.2.1:8388`.

**What it does not check.** Rosetun, its kill switch, its DNS lock, any L3
scenario, DNS, IPv6 through the node, UDP through the node, or anything about the
real engine beyond the pinned version starting and relaying one connection.
`aes-128-gcm` and the lab-only password come from `l3-request-template.json`, the
one place both the L3 requests and the node read them from.

### Observer: category `tunnel`

`classify` and `leak_verdict` take two optional arguments, both off by default so
stage 6b is unchanged. `tunnel_port` adds the category `tunnel`: TCP between the
test machine and `192.0.2.1` on that port, either way, with the payload never
read. Without it those frames stay `unexpected`. `https` (the `https-direct`
exchange, the client port its helper reported and the target's own log) makes the
one `https-direct` connection a `probe` by its four-tuple, because TLS hides the
payload. If the helper's port and the log's single row for that path (source
`192.0.2.2`) disagree, those frames stay `unexpected`. Any other frame of the test
machine to `203.0.113.2:443`, including a second direct connection, is
`unexpected`. The port may not be `443`, `9999`, a port of `PORTS` or the
client's SOCKS port `10808`.

### Helper fixtures

All paths are fixed in `lab-entry.py`. A missing, foreign-owned or
group-writable file is a refusal with a fixed reason (`lab-helper-failed-<reason>`
in the controller's error), never a skip, and nothing in the guest changes first.

| Role | What the helper does when the request has a `tunnel` block |
| --- | --- |
| Lab, `setup` | Checks the engine (hash), the certificate and the key. In the observer, before `capture_ready`: serves HTTPS on `203.0.113.2:443` in `rtlab`, writes the node's configuration itself (one Shadowsocks inbound on `192.0.2.1:<port>`, `direct` outbound, no DNS, no other inbound), starts sing-box and waits until it is alive and listening. |
| Lab, `finish` | Records whether the node was still alive, stops it and records its exit code in `health.json` (`node`). Saves `https.json` (source, client port, path, lab monotonic time; at most 16 rows) and `node.log` (sing-box's own log at level `info`, so that it names every connection the node takes and the destination it opens; every address outside the documentation ranges blanked; repeated lines folded as described under "The node log" below; at most `LOG_LIMIT`; the marks in it are part of the text and never a reason of the observer). |
| Test, `probe` | Checks the engine and the CA file (hash) before the opening marker. After the eight exchanges and before the closing marker: `https-direct` (stdlib `ssl`, system store, `server_hostname` the IP), then a throwaway sing-box client, `https-tunnel` through a hand-written SOCKS5 handshake, and the client is stopped. Returns the client port of `https-direct`, both answers and the client's exit code. |

Without a `tunnel` block the requests and the answers of stages 6a and 6b are
byte for byte what they were.

### Prepared image contract v5

This is added next to the 6a contract, which stays as written above for history.
It applies to both images unless it says otherwise. The 6a record is not valid for
v5: the owner qualifies 6a and 6b again on v5 (see below).

- **Test.** Everything in the 6a contract except the route restriction: the
  default IPv4 route goes through `192.0.2.1` (no IPv6 default yet). The lab CA
  certificate is in the system store (`update-ca-certificates` or the
  distribution's equivalent), its PEM file at
  `/usr/local/share/ca-certificates/rosetun-lab-ca.crt`. sing-box of the pinned
  version (1.14.3) at `/usr/local/libexec/rosetun-lab/sing-box`: not a service and
  not on `PATH`; only the helper starts it. The packages 7a needs are here too:
  `nft`, `curl` with TFTP, `dig`.
- **Lab.** Everything in the 6a contract plus the same sing-box binary at the same
  path, the HTTPS target's certificate at
  `/usr/local/libexec/rosetun-lab/https-cert.pem` and its key at
  `/usr/local/libexec/rosetun-lab/https-key.pem` (root, mode `0600` for the key),
  and **no** service that starts the node at boot. The lab still gets no route to
  the outside: the stand has no external network.
- **Keys.** The CA key is in no image. The owner makes the CA and the target
  certificate on the stand while preparing the images and keeps the CA key off
  them. Directories and files above are root-owned and not writable by others.
- **Hashes.** `sing_box_sha256` is the SHA-256 of the one binary used in both
  images; `ca_sha256` is the SHA-256 of the CA PEM file on the test image. Both go
  in the `[tunnel]` table of the configuration.
- **A quiet test image.** With a default route the test machine can reach the
  lab's router, so anything that calls out on its own is extra traffic in the
  capture, and the observer reports it as `unexpected`. The test image has no
  service or timer that goes onto the network by itself: `systemd-timesyncd` (its
  NTP queries were the first one found on the stand), `apt-daily.timer`,
  `apt-daily-upgrade.timer`, `fwupd-refresh.timer` and anything like them
  (`motd-news.timer`, package-metadata refreshers, telemetry). Mask them, do not
  only disable them: a masked unit cannot be started by a socket, a timer or a
  dependency. Check after a boot, before the image is sealed:
  `systemctl list-timers --all` shows none of them, and `ss -tunap` lists no
  connection and no UDP socket of a process that is not one of the image's own
  services (no port 123, no established TCP). A unit that shows up in either list
  and is not named here is judged by the same question: does it open a connection
  without being asked? If it does, mask it.
- **What the stand showed.** `apt-listchanges.timer` and `apt-listchanges.service` are masked
  too: they made background DNS queries, which are extra traffic in the capture like the units
  above. And the default IPv4 route through `192.0.2.1` is required, not a convenience: without
  it Rosetun finds no physical interface (`physical_default_interface` in
  `crates/rosetun-routing/src/platform/linux/physical.rs` reads the default route of the main
  table) and the group of stage 7b2b stopped at seven passes.

Check the test image on the stand before a qualification, after a boot:

```sh
ip route                      # a default route via 192.0.2.1; no 203.0.113.0/24 route
systemctl list-timers --all   # none of the masked timers, nothing that calls out
cat /etc/resolv.conf          # exactly: nameserver 203.0.113.53
```

For L3, remove the legacy test image's `203.0.113.0/24 via 192.0.2.1`
route. sing-tun preserves specific routes in the main table for non-DNS
traffic, so that route sends the HTTPS probe onto the physical interface,
where the kill switch drops it before it reaches the engine. Keep the IPv4
default route through the lab. Do not change the restricted 6a images in place.
To prepare a new copy of an already provisioned L3 test image, offline:

```sh
python tools/vm/linux/prepare-l3-image.py /srv/test-old.qcow2 /srv/test-new.qcow2 \
  --source-sha256 OLD_SHA256 --descriptor /srv/test-new.image.json
```

This requires `qemu-img` and `guestfish`. The source must be a stopped,
standalone qcow2 image. The tool preserves the source, verifies the network
file after writing the copy, and creates a new image descriptor. Copy its
fields into `[image]` in a new execution configuration before the dry-run
(all but `sshd`, which only a v6 descriptor has; see stage 7c2).

Certificates, with a term and the IP SAN (the guest clocks must be inside the
validity period: check `date` in both images after preparing them):

```sh
openssl ecparam -name prime256v1 -genkey -noout -out lab-ca.key
openssl req -x509 -new -key lab-ca.key -sha256 -days 825 -subj '/CN=Rosetun lab CA' \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -out rosetun-lab-ca.crt
openssl ecparam -name prime256v1 -genkey -noout -out https-key.pem
openssl req -new -key https-key.pem -subj '/CN=203.0.113.2' -out target.csr
printf 'subjectAltName=IP:203.0.113.2\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n' > target.ext
openssl x509 -req -in target.csr -CA rosetun-lab-ca.crt -CAkey lab-ca.key -CAcreateserial \
  -sha256 -days 825 -extfile target.ext -out https-cert.pem
sha256sum rosetun-lab-ca.crt /path/to/sing-box
```

Install `rosetun-lab-ca.crt` on the test image only, `https-cert.pem` and
`https-key.pem` on the lab image only, and keep `lab-ca.key` out of both.

### Reinstall the helper

This stage changes `linux/guest/lab-entry.py` and `matrix/lab_protocol.py`, so
their hashes change. The owner installs the new bytes in **both** v5 images
(`/usr/local/libexec/rosetun-lab/entry` and `lab_protocol.py` beside it) and
updates the image descriptors before any qualification. The 6a and 6b records
were made with earlier bytes and do not cover this stage.

### Configuration and command

`rosetun.matrix.lab.v2` is `lab.v1` plus a `[tunnel]` table (`sing_box_sha256`,
`ca_sha256`, `node_port`, normally `8388`). Version 1 files read as before and do
not accept `--tunnel`. Start from [lab-tunnel.example.toml](lab-tunnel.example.toml).

```sh
python -m tools.vm.matrix lab-smoke --config /srv/lab-v2.toml --dry-run --tunnel
python -m tools.vm.matrix lab-smoke --config /srv/lab-v2.toml --tunnel
python -m tools.vm.matrix lab-smoke --config /srv/lab-v2.toml --tunnel --canary
```

`--tunnel` exits 0 only when everything stage 6b needs holds (qualified, `leak`
`NONE`, window proven) and also: `https-direct` was answered and `https.json`
has exactly one row for it, from `192.0.2.2`, from the client port the helper
reported; `https-tunnel` was answered and `https.json` has exactly one row for it,
from `203.0.113.1`; the `tunnel` category is above zero; the node was alive at
`finish`. With `--canary` the canary conditions of 6b replace `leak` `NONE`.
The summary gains `https` (the two exchanges) and a `tunnel` block next to the old
fields:

| Field | Meaning |
| --- | --- |
| `direct` | `https-direct` answered, exactly one row from `192.0.2.2`, matching port |
| `via_node` | `https-tunnel` answered, exactly one row from `203.0.113.1` |
| `tunnel_frames` | frames in the category `tunnel` |
| `node` | `alive_at_finish` and the node's `exit_code` |
| `client_exit` | exit code of the throwaway client (informational) |

Summaries without `--tunnel` are unchanged. `https.json` and `node.log` are saved
beside `capture.pcap` in the lab run. The sing-box configuration format of the
pinned version is exercised only by this qualification; no offline test starts it.

### Owner qualification

1. Prepare the v5 images by the contract, make the CA and the target certificate,
   install the helper and `lab_protocol.py` in both images and update the
   descriptors and the `[tunnel]` hashes.
2. Repeat 6a and 6b on v5: ordinary `lab-smoke`, `--canary`, one extra packet by
   hand, the observer stopped, the channel cut (the lists above).
3. `lab-smoke --tunnel`: exit 0, source `192.0.2.2` for the direct exchange,
   `203.0.113.1` for the one through the node, `leak` `NONE`.
4. `lab-smoke --tunnel --canary`: exit 0, exactly the canary's two flows.
5. Stop the node from the lab console before `https-tunnel`: exit 2.
6. Read the pcap in Wireshark: frames to port 8388 and exactly one direct
   connection to `203.0.113.2:443`.
7. Repeat `run linux-l2` and the 7a run on v5: results as before.

## Stage 7b2a: lab DNS, evidence disk and phase windows

Stage 7b2a prepares the lab for a full Linux L3 run without running it: a
resolver and a DoH target, a separate disk for the capture, and observation
windows per phase. Rosetun and `run-l3.sh` are untouched and L3 does not run
through the lab yet. Security invariants stay **UNVERIFIED**, the release gate
stays false. The helper changes: the owner installs `linux/guest/lab-entry.py`
and `matrix/lab_protocol.py` in **both** images and updates the descriptors.

### Lab resolver and DoH target

Only when the helper request carries `dns: true`. Both live in the `rtlab`
namespace, on addresses added to `rt-target` by `setup`:

| Service | Address | What it does |
| --- | --- | --- |
| Resolver | `203.0.113.53` UDP and TCP 53 | Every `A` question of class `IN` gets one answer, `203.0.113.2`; `AAAA` and every other type or class get an empty `NOERROR`. No recursion (RA clear). A message that cannot be read gets `FORMERR`, another opcode `NOTIMP`; a response or less than a header gets no answer. |
| DoH | `203.0.113.3:443`, path `/dns-query` | RFC 8484 `POST` (`application/dns-message`) and `GET` (`?dns=` base64url), the same responder. Wrong path 404, other method 405, other content type 415, body or `dns` value over 512 bytes 413, unreadable message 400. HTTP/1.1 only, ALPN `http/1.1`, at most 16 requests per connection. |

Both write `dns.json` beside the other lab artifacts: one row per question with
`source`, `transport` (`udp`, `tcp`, `doh`), `name` (cut at 96 characters) and
`type`. At most 256 rows and `LOG_LIMIT`; an overflow makes the observer
unclean. The servers run on threads of their own, so a slow client never delays
the capture.

Whether the DoH client of sing-box 1.14.3 accepts an HTTP/1.1 server is checked
only on the stand. If it does not, that blocks the stage; HTTP/2 is not
implemented without a separate decision.

The DoH certificate is signed by the same lab CA as the HTTPS target and has
both names. Install `doh-cert.pem` and `doh-key.pem` (root, mode `0600` for the
key) beside the other fixtures on the lab image only:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out doh-key.pem
openssl req -new -key doh-key.pem -subj '/CN=doh.lab.test' -out doh.csr
printf 'subjectAltName=DNS:doh.lab.test,IP:203.0.113.3\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n' > doh.ext
openssl x509 -req -in doh.csr -CA rosetun-lab-ca.crt -CAkey lab-ca.key -CAcreateserial \
  -sha256 -days 825 -extfile doh.ext -out doh-cert.pem
```

A missing or unsafe file is a refusal (`missing-doh-certificate`,
`missing-doh-key`) before anything in the guest changes.

### Addition to the prepared image contract v5

The **test** image resolves through the lab: `/etc/resolv.conf` holds exactly
`nameserver 203.0.113.53`, no other server and no local caching resolver
(`systemd-resolved`, `dnsmasq` and the like are absent or masked). Without it
`dig example.com A` of the baseline check has nothing to ask.

### Evidence disk

`lab-smoke --evidence-disk` (also with `--tunnel`, `--canary` and `--dry-run`)
gives the lab machine a second disk and keeps the capture there instead of
behind QGA, whose reads stop near 2 MiB per session.

- The controller creates `evidence.img` in the lab run directory as a registered
  resource: raw, writable, exactly 64 MiB, zeroed. QEMU gets it as a second
  `virtio-blk` device with `serial=rosetun-lab-evidence`, added to the lab
  machine's arguments only. The test machine does not see it, and the launch
  plan stored at preparation is unchanged; without the flag every launch
  argument is what it was before.
- The helper finds the disk only at
  `/dev/disk/by-id/virtio-rosetun-lab-evidence` and refuses without it
  (`missing-evidence-disk`, `evidence-disk-not-a-block-device`) before it
  changes anything.
- Format: a 4096-byte header, then the pcap. Header (little endian): magic
  `RTLABEV1`, version `1`, completion flag, the 32-character lab run ID, pcap
  length (8 bytes), SHA-256 of the pcap, zeros. The helper writes the pcap as a
  stream, syncs it, writes the header last and syncs the device. A run that
  failed leaves the flag clear. The pcap limit is 60 MiB; the 128 KiB limit of
  stage 6a stays for runs without the disk.
- The controller reads the image only after it stopped the lab machine and its
  completion is verified. It checks magic, version, run ID, flag, header
  padding, the image size, the length, the SHA-256 and that only zeros follow the
  pcap, then writes `capture.pcap` of the run with `evidence.write_file`. Any
  difference gives `leak` `UNVERIFIED` with the reason (`evidence-truncated`,
  `evidence-size`, `evidence-sha256`, `evidence-incomplete`, `evidence-run-id`,
  `evidence-trailing-bytes`, `evidence-magic`, `evidence-version`,
  `evidence-length`, `evidence-header-padding`), exit 2 and no partial analysis.
  The summary gains `evidence_disk` (`verified`, `reason`, `pcap_bytes`,
  `pcap_sha256`) only with the flag.
- The capture duration is a request field, `duration_seconds`, from 60 (the
  default) to 2100 (the job limit of `run-l3.sh` plus 300). The facade of the
  guest (`Guest.deadline`, 90 seconds from its creation) no longer bounds the
  capture: `setup` starts `serve` and checks it with a short call, and `serve`
  ends with `finish` or at its own deadline. A caller that waits longer passes
  `lifetime` to `Guest`.

### Phase windows

For a run that needs many observation windows (L3 has about twenty: one per
protected session) the request carries `windows: true` and no markers of its
own. The test machine's script sends one UDP datagram per boundary to
`203.0.113.2:9100`:

```text
rosetun-lab-marker:<run>.<index>.<word>.<label>
```

`index` counts windows from zero, `word` is `open` or `close`, `label` is
`[a-z0-9_.-]{1,48}` (in L3 the scenario function's name). The nonce of stage 6b
is gone: the run ID makes it fresh and the index orders it. The helper answers
`rosetun-lab-ack:` plus the datagram and logs `word`, `index`, `label` and its
own time in `health.json`; it accepts any index, in the order they come, up to
100 windows. The two-marker mode with nonces of 6a and 6b is unchanged.

`lab_protocol.classify_windows(raw, run, windows_expected, health=..., ready=...)`
splits the capture. `windows_expected` lists the expected windows as
`{label, expected}`; `expected` may only be `NONE` for now. `tunnel_port`,
`allowances`, `https` and `probes` are per run.

- A window runs from its opening to its closing marker. Inside it the rules of
  6b apply: any `unexpected` frame is `DETECTED`.
- `NONE` needs both markers asked and answered once each, in order; indexes in
  sequence from zero without a gap; the expected label; a whole capture; a clean
  observer; and a `health.json` marker log equal to the markers seen on the wire.
- A frame outside every window is counted in `outside_window` (category
  `outside-window`, with the first 16 described) and changes no verdict. This is
  where baseline traffic before the first window goes.
- A window without its closing marker is `UNVERIFIED`. A repeated, skipped or
  reversed index, an `open` inside an open window and a `close` without its
  `open` make every window from that place on `UNVERIFIED`; a leak already seen
  stays `DETECTED`. A marker of another run is an `unexpected` frame.

### Owner qualification

1. Make the DoH certificate, install it and the helper in both images, put the
   resolver into the test image, update the descriptors.
2. `lab-smoke`, `--canary`, `--tunnel` as before: the same results.
3. `lab-smoke --tunnel --evidence-disk`: the capture comes from the disk, its
   SHA-256 in `evidence_disk` equals that of `capture.pcap`, `leak` `NONE`.
4. From the test console while a lab run with `dns: true` is up:
   `dig example.com A` answers `203.0.113.2`, and
   `curl --doh-url https://203.0.113.3/dns-query https://example.com/` or
   similar answers (this proves the DoH certificate chain and name). The
   controller has no command that holds such a run open yet.

### `lab-smoke --dns`: the resolver and DoH with sing-box

Stage 7b2a switched the resolver and the DoH target on only for a request with `dns: true`, which no
command sent. `lab-smoke --tunnel --dns` (also with `--evidence-disk` and `--dry-run`; without
`--tunnel` it is refused before anything starts) sends that request to both helpers and adds two
exchanges to the test, after `https-tunnel` and before the closing marker. The question this
answers on the stand: does the DoH client of sing-box 1.14.3 accept a server that speaks only
HTTP/1.1? Every connection of stage 7b2b depends on it.

- `dns-plain`: a stdlib `A` question over UDP from `192.0.2.2` to `203.0.113.53:53` for
  `<run>.<nonce>.lab.test`. The answer must be the one fixed address `203.0.113.2`. In the
  observer these frames are a `probe` by their tuple and the question they carry (as the exchanges
  of 6a); any other frame to the resolver or to `203.0.113.3`, and any other UDP 53, is `unexpected`.
- `dns-doh-singbox`: a second throwaway sing-box client of the test machine, with the DNS server of
  Rosetun (`render.rs::dns_section`: `type` `https`, `server` `203.0.113.3`, `tls.server_name`
  `doh.lab.test`, `detour` to the node), Shadowsocks out to the node, and one rule
  `{"action": "resolve", "server": "dns-proxy"}`. The helper asks its SOCKS inbound for
  `<run>.<nonce>.lab.test:443` as a domain and then speaks TLS with `server_hostname`
  `203.0.113.2` (the certificate of the target is for the IP). The target answers with the nonce.

The whole client configuration:

```json
{"log": {"level": "warn", "timestamp": false},
 "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 10808}],
 "outbounds": [{"type": "shadowsocks", "tag": "node", "server": "192.0.2.1", "server_port": 8388,
                "method": "aes-128-gcm", "password": "<lab-only password of the template>"}],
 "dns": {"servers": [{"type": "https", "tag": "dns-proxy", "server": "203.0.113.3",
                      "tls": {"server_name": "doh.lab.test"}, "detour": "node"}]},
 "route": {"rules": [{"action": "resolve", "server": "dns-proxy"}], "final": "node"}}
```

It differs from what Rosetun renders in three places: the outbound is tagged `node`, not `proxy`;
the inbound is SOCKS, not TUN; and the `resolve` rule names the server, where Rosetun's bare
`resolve` only prepares address rules. The DNS server entry is the same, with the default port 443
and path `/dns-query`. One open point: whether sing-box sends the resolved address or still the
domain to the Shadowsocks server after `resolve` was not checked offline. If it sends the domain, the
node would have to resolve it itself and fail, and `dns.json` would show no DoH question: the check
then fails, which is the answer.

`--dns` exits 0 only when everything `--tunnel` needs holds and also: `dns.json` has exactly one
`udp` question for the `dns-plain` name from `192.0.2.2`; every question for the `dns-doh-singbox`
name came by `doh` from `203.0.113.1` (through the node) and there is at least one; the target logged
exactly one request for the `dns-doh-singbox` path, from `203.0.113.1`; the helper saw both answers;
`leak` is `NONE`. The summary gains `dns` (`plain`, `doh_via_node`, `doh_requests`, `client_exit`,
the first 4 KiB of the client's log with addresses outside the documentation ranges blanked, `client_log_path`
and `failed`). Summaries without `--dns` are unchanged, as are the requests of every other run.

**When an exchange fails.** The check does not end the run with a bare error. The helper returns the failed
exchange as `failed`: `{"exchange", "reason", "elapsed_ms"}`, where `exchange` is `dns-plain`, `dns-client`
(starting the throwaway client) or `dns-doh-singbox`, `reason` the helper's own word, an errno name or
`timeout`, and `elapsed_ms` how long that exchange took. The answers before it are kept, the client is stopped
and its exit code (`client_exit`, `null` when it never started) and log (`client_log`, `""` when there is
none) come back with it, so the run goes on to its closing marker and the capture is judged as usual; the
exit is 2, as for any DNS check that is not proven. A `failed` that does not have this shape is not believed
(`null`) and the lookups it would have answered are false all the same. The controller saves the client's log
as `client.log` in the **test** run's directory (registered with the run only in a `--dns` run, written whole,
never when it holds the run's owner token) and the block names the file in `client_log_path`; `null` when
there was no helper answer. The log is cut at 4 KiB, not at `LOG_LIMIT`, because the whole answer of the
helper may not pass `LOG_LIMIT`.

The reason a `--dns` run failed used to be lost when the helper could not print its own answer: the client's
log was bytes, `json.dumps` raised a `TypeError` and the helper printed the bare `lab-helper-failed`, with
`dns.plain` and `doh_via_node` false and no reason. The log is text now, and any such failure prints its code
(see "Why a lab helper failed").

**Reinstall.** `linux/guest/lab-entry.py` and `matrix/lab_protocol.py` changed: the owner installs
them in **both** images again and updates the descriptors.

Manual check: `lab-smoke --tunnel --dns --evidence-disk`, exit 0. If `dns-doh-singbox` fails, keep
`node.log`, the `dns` block (`failed`, `client_exit`) with `client.log` of the test run, and `dns.json`
of the lab run.

## Stage 7b2b: the L3 kill switch group in the lab

Stage 7b2b runs the real Linux L3 stage through the lab: `run linux-l3 --lab` starts the lab
machine and the test machine of stages 7b1 and 7b2a together and runs **all 60 scenarios** of the catalog
(the 20 `two-hop.*` among them have no check and are recorded SKIP "UNRUN"), exactly
as `run-l3.sh` runs them, on the test machine. The lab machine is the VPN node (`192.0.2.1:8388`),
the HTTPS target (`203.0.113.2:443`), the resolver and the DoH target, and it records the wire to its
evidence disk. Only the **kill switch group** is judged; the other scenarios run and appear in the
summary as the script reported them. Nothing is accepted: the release gate stays false and the
security invariants stay **UNVERIFIED**.

```text
test VM 192.0.2.2  --- lab VM 192.0.2.1:8388  VPN node (sing-box, Shadowsocks)
 run-l3.sh, ISO         rtlab 203.0.113.2:443  HTTPS target     203.0.113.53 resolver
 window markers  --->   rtlab 203.0.113.2:9100 marker service  203.0.113.3:443 DoH
                        evidence disk: the capture, one pcap for the whole run
```

### The group and its windows

Judged are the 16 scenarios below. A *window* is one protected session, from just before
`rosetun connect` to just after the protection is gone; the observer judges only the frames of the
test machine inside a window. The label of a window is the function of `run-l3.sh` that opened the
session, so scenarios that run in one session share its window:

| Window label | Scenarios that ran in it |
| --- | --- |
| none (no protected session) | `preflight.identity`, `preflight.accounts`, `preflight.no-foreign-service`, `preflight.tools`, `preflight.baseline`, `install.service` |
| `reported` | `protection.reported` |
| `identity` | `engine.identity`, `engine.files` (the second ends the session the first opened) |
| `connect_ks` | `killswitch.direct-blocked`, `killswitch.tunnel-passes`, `lan.off`, `killswitch.foreign-table`, `killswitch.engine-killed`, `killswitch.flush-restored`, `killswitch.disconnect` |

So there is no window of its own for `killswitch.engine-killed`: a leak while the engine is killed is
a leak in the window `connect_ks`, and every pass in that window is contradicted by it.

### Markers in `run-l3.sh`

`job.env` gains one optional key, `LAB_MARKER_ADDRESS` (`203.0.113.2:9100`), only in a run inside
the lab. Without it `run-l3.sh` does what it did and the Hyper-V path is unchanged: no datagram, no
file, no new line in a result or a note. With it, `lab_mark open` runs before `rosetun connect` in
`connect_with`, and `lab_mark close` runs after the protection is confirmed gone: in `disconnect`
(after `Disconnected`), after `rosetun open-network`, after `systemctl stop`, after the restarted
helper removed a DNS lock, and at the end of the peer scenarios. The marker is one UDP datagram
(bash `/dev/udp`) `rosetun-lab-marker:<run>.<index>.<word>.<label>`; the lab echoes it and the
script waits at most two seconds for the echo. It is sent only while there is no table
`inet rosetun` and the state is `Disconnected`, except that a closing marker also goes while the
service is not active (a stopped service answers no status; stage 7c1). Otherwise nothing is sent,
nothing else changes, and the window stays open, which the observer calls unverified. Index and label of the open window live
in the run's state directory, so `finalize` and a restarted function still know them.

`<run>` is 32 hexadecimal digits, the first 32 of `sha256("rosetun-lab-run:" + RUN_ID)` where
`RUN_ID` is the guest's run ID; the controller derives the same digits (`marker_run_id`) and uses
them as the lab ID of the run.

### How the windows are found

`classify_windows(..., windows_expected=None, required_labels=...)` takes the windows from the
capture: index `n` is window `n`, its label is the one its markers carry, and a label may repeat. The
count is not known beforehand (an implicit `disconnect`, two connects in `rules.capabilities`,
scenarios skipped after a FAIL), so an extra session spoils nothing. The rules of 6b apply to each
window by itself; an index out of sequence still spoils every window from that place on. The three
labels of the group each need at least one window; one without any is listed in `missing_labels` and
only its scenarios are unobserved. The exact list of stage 7b2a stays for `lab-smoke`.

### Cross-check and exit code

The summary (`rosetun.matrix.l3-summary.v1`) has three parts next to the usual stage fields:

- `legacy`: the report of `run-l3.sh` as it is, its SHA-256, its summary and every row.
- `lab`: what the fixtures did (`node` alive at finish, `https`, `dns`, `doh` answered; all four are
  required, see "The HTTPS target in an L3 run"), the evidence disk, and every window with its
  label, index, verdict, reasons and categories.
- `crosscheck`: one row per scenario of the group, `AGREE`, `DISAGREE`, `UNOBSERVED` or
  `NOT_APPLICABLE`. A pass in a clean window is `AGREE`; a pass in a window with a leak is
  `DISAGREE`; a pass whose window is unverified or missing is `UNOBSERVED`; anything the script did
  not pass, and the scenarios without a session, are `NOT_APPLICABLE` (a failure stays a failure).
  The scenarios outside the group are listed in `out_of_scope` without a verdict. `group` says what
  decided the code.

| Exit | Meaning |
| --- | --- |
| 0 | The whole group passed, every row `AGREE` or `NOT_APPLICABLE`, the observer clean, the fixtures answered, the evidence disk verified, both machines completed. |
| 1 | A finding: a scenario of the group failed, a pass is `DISAGREE`, or a window of the group saw a leak. A finding stands whatever else went wrong. |
| 2 | Nothing found, but the run cannot vouch for itself: a controller error, a machine that did not stop, no report, an unverified evidence disk, a fixture that did not answer, an unclean observer, a pass nobody observed (`UNOBSERVED`, which includes a window that never closed), a scenario of the group that did not run. |
| 130 | Interrupted. |

Scenarios outside the group, and windows outside it that cannot be verified, change no code. A leak
in a window outside the group is shown (`lab.windows`, `group.outside_leaks`) but does not change the
code either, because several scenarios outside the group leave the protection off on purpose and
nothing declares those expectations yet (`LEAK_OUTSIDE_THE_GROUP_FAILS` in `l3_summary.py` turns
that on).

### Flows of each window

Each row of `lab.windows` has `flows`, read from the capture that was already taken (headers only, no
payload is parsed) and judged by nothing: they change no verdict and no code. They say what the
connections of the test machine did inside the window, from its opening marker to its closing one:

```json
{"connections": [{"kind": "node", "client": "192.0.2.2:43000", "server": "192.0.2.1:8388",
                  "frames_out": 4, "frames_back": 3, "bytes_out": 120, "bytes_back": 400,
                  "first_ms": 500, "last_ms": 1750, "syn": true, "syn_ack": true,
                  "fin": ["out", "back"], "rst": []}],
 "omitted": 0}
```

- `kind` is `node` (the node's own port on `192.0.2.1`), `target` (the HTTPS target, `203.0.113.2:443`,
  reached directly) or `other`. A connection of the engine to the node is a `node` flow; a `curl` that
  the tunnel carries has no flow of its own on the wire, only bytes in the one to the node.
- `frames_*` and `bytes_*` count the frames and the TCP payload bytes the test machine sent (`out`) and
  received (`back`). `first_ms` and `last_ms` are the capture times of the first and the last frame,
  in milliseconds after the opening marker (null when the capture has no time for it). A connection that
  began before the window shows no `syn`.
- `syn` is a SYN without ACK, `syn_ack` a SYN with ACK; `fin` and `rst` list the sides that sent one.
  So a connection that only ever got a `syn` has `frames_back` 0 and no `syn_ack`, and a refused one
  has `rst: ["back"]`.
- At most 64 connections are kept per window, in the order of their first frame; `omitted` counts the
  others.
- Each row of `lab.windows` also has `clock`: `open_at` and `close_at`, the time by the clock of the lab
  machine (seconds since the epoch) at which the capture saw the request that opened the window and the
  one that closed it, or null for one that is missing. They are what the scenarios are lined up with
  (see below).

`lab.https_refusals` lists the connections the HTTPS target turned away (`service`, `family` and the
`reason` of the rows of `https.json` that have one, at most eight; any other field is dropped). The
rows do not name the client, so they say what failed (`ssl-...`, `timeout`) and not who.

### Scenarios outside the group

They run and are reported. Stage 7c2 moved every session under the kill switch where no direct traffic
is expected into the group (see "Stage 7c2" below); what stays outside needs either a declared expectation
of direct traffic, which stage 7c3 adds, or a fixture the lab does not have yet:

- `rules.direct-other-account` (the second window `capabilities`) and `rules.proxy-default-direct`
  (`through_vpn_by_program`) send a program direct by design, so their windows are `DETECTED`.
- `dnslock.*` and `crash.dns-lock-killed` leave the network open on purpose (a DNS lock without a kill
  switch, UDP 53 that is meant to leave): their windows are `DETECTED` too.
- `lan.on`, `lan.private-closed`, `lan.private-open`, `lan.follows-change`: Local network sessions let the
  own network through by design, and no host in a private range exists in the lab. `lan.off` stays in the
  group: it runs in `connect_ks`.
- `ipv6.neighbor` is skipped: the test machine has no IPv6 default router.
- The 20 `two-hop.*` have no check yet.

Until stage 7c2, `inbound.reply` failed here because the test image had no `sshd`; image contract v6 adds one.

### Configuration and commands

`rosetun.matrix.execution.v3` is version 2 for the L3 suite plus a `[lab]` block: `[lab.image]` (the
descriptor of the lab image), `[lab.tunnel]` (as in `lab.v2`), and `https_cert_sha256` and
`doh_cert_sha256`, the hashes of the two certificates on the lab image. `[l3]` must name the lab's
own addresses (`host_address` `192.0.2.1`, `probe_address` `203.0.113.2`, `node_port` equal to the
tunnel's). `timeouts.job` is at most 1800, default in the example 900; the capture lasts
`job + 300` seconds and also covers the boot and the import of the test machine. Versions 1 and 2
never carry `[lab]` and refuse `--lab`; a version 3 file needs `--lab`. Start from
[execution-l3-lab.example.toml](execution-l3-lab.example.toml).

```sh
python -m tools.vm.matrix run linux-l3 --lab --config /srv/linux-l3-lab.toml --dry-run
python -m tools.vm.matrix run linux-l3 --lab --config /srv/linux-l3-lab.toml
```

Order: lease; the two runs; both overlays; the evidence disk; the L3 requests and the ISO of the test
run; the lab machine starts and is set up (node, HTTPS target, resolver, DoH, capture to the
disk, `capture_ready`); the test machine starts; import; `job.env` with `LAB_MARKER_ADDRESS`; the
job; collection; `finish` on the lab; both machines stop; the evidence disk is read and checked; the
windows are found; the summary. A failure after the first machine started closes both. A job
that fails (`submit`, `wait` or the collections) does not stop there: the lab machine is still capturing, so the run
goes on to `finish`, the lab's files, the stop of both machines (the test machine hard, the lab machine as ever), the
disk and the windows, and the error of the job stays first in `errors` and decides the exit code. Before, such a failure
left the disk unread (`evidence.reason` `not-read`, no windows, fixtures not seen) and said nothing of what the lab had
seen. A guest that gave no report has no note of when its network went on, and the poller's answers are then not called
leaks (the run is unproven by its error either way). A failure of the lab itself, or before the job exists, still leaves
the disk unread. The lab machine pins the certificates: the helper refuses a certificate whose hash is not in the
request.

### Reinstall

This stage changes `linux/guest/lab-entry.py` (the pinned certificates), `linux/guest/stage-l2.py`
(the optional `LAB_MARKER_ADDRESS` of the L3 profile), `linux/guest/start.sh` and
`linux/guest/run-l3.sh` (reached through the package) and `matrix/lab_protocol.py`. Install the new
`lab-entry.py` and `lab_protocol.py` in both images and `stage-l2.py` in the test image, and update
the descriptors, before any qualification.

### The HTTPS target in an L3 run

A request with `windows: true` (the one `run linux-l3 --lab` sends and `lab-smoke` never does) puts the
HTTPS target of `203.0.113.2:443` in L3 mode. `lab-smoke` keeps what stage 7b1 made it: two exact
requests, any other one refused, and the log of up to 16 rows.

- **What it answers.** Any `GET` and `HEAD` of HTTP/1.0 or 1.1 with any path, from `192.0.2.2` (direct)
  or `203.0.113.1` (through the node): `200`, a short fixed body without a nonce (none for `HEAD`) and
  `Connection: close`; the connection is then closed. The `curl https://203.0.113.2/` of `run-l3.sh`
  is one of these. The two exchanges of 7b1 are still known by their exact request and answered with
  their nonce, and are logged as rows as before. Another method or version, a request cut short or
  larger than 4 KiB, a client that sends it too slowly, a TLS handshake that fails or a source that is
  neither of the two is refused: the connection is closed, the log gets a refusal row with the reason
  (`unsupported-method`, `unsupported-version`, `bad-http-request`, `short-request`, `request-limit`,
  `timeout`, `unexpected-request`, `ssl-<openssl reason>`) and the observer goes on.
- **One thread per connection**, as the DoH target has, so a slow client never delays the capture; at
  most 32 at a time, and a 33rd connection is closed with the reason `connection-limit`.
- **The log is not a line per request.** `https.json` is still a JSON list: the first 16 requests whole
  (`source`, `port`, `at`, and `method` and `path_class` or, for a 7b1 exchange, `path`), the refusal
  rows (at most eight), and one last element `{"kind": "counts", "counts": [...], "rows_dropped",
  "counts_dropped"}` with a counter per (`source`, `method`, `path_class` `root` or `other`; `root` is `/`
  with or without a query). Requests beyond the 16th are only counted (`rows_dropped`), and more than 64
  distinct counters are dropped (`counts_dropped`). Neither makes the observer unclean, and neither
  counts as an error of the run.
- **When the `https` fixture works.** The counters hold an answer to `192.0.2.2` and an answer to
  `203.0.113.1`: the test machine reached the target directly (outside the protected windows, where the
  script does it) and through the node. The summary's `https` block says which of the two it was
  (`direct`, `via_node`, `requests`). One path alone is not a working target and the run ends with 2
  (`fixtures-not-seen:https`). The same goes for `doh`: the DNS check of Rosetun's connect goes
  through the DoH target, so it is a required fixture with `node`, `https` and `dns`.

Reinstall the helper (`linux/guest/lab-entry.py`) in both images before qualification.

### A diagnostic run

```sh
python -m tools.vm.matrix run linux-l3 --lab --diagnostic --config /srv/linux-l3-lab.toml
```

`--diagnostic` (only with `--lab`; it is refused otherwise) is for finding out why a scenario failed,
not for qualifying anything. The generator of the L3 requests sets `settings.verbose_log_until` (the
year 2100, as the two program requests always do) in all six requests, so that the log of the engine in
the service journal names the destinations of the connections; in the lab those are documentation
addresses only. Without the flag the six files are byte for byte what they were (a test pins their
digests). The package check accepts the diagnostic kind as a whole, never a mixture.

The summary says `"diagnostic": true`, `group.unproven` has `diagnostic-run`, and the exit code is never
below 2: a finding is still shown in `outcome` and `group.findings`, but the run counts toward no
qualification (130 stays 130). Nothing else is judged differently.

#### The node log

`node.log` is the log of the lab node at level `info`, which has a line for every connection and most
of them say the same. The helper folds it: once every address outside the documentation ranges is
blanked and the numbers that identify a connection are removed (`[3365492301 2ms]` becomes `[#]`), lines
that are equal become one, in the place of the first, followed by `[xN, lines A-B]`: how many there were
and the numbers of the first and the last of them in the log. Ports stay, so two connections from
different client ports are two lines. A line longer than 512 characters is cut.

If what is left still does not fit `LOG_LIMIT` (32 KiB), the beginning and the end are kept (a quarter
of the room for the beginning) around one line, `[N lines dropped here]`, where `N` is how many lines of
the log were left out of the middle. If the helper itself could read only the last MiB of the file,
`[earlier lines dropped]` stands first. These lines are part of the text and never a reason of the
observer.

#### The flows behind the node

A diagnostic run also asks the lab helper to count, on `rt-route` (the link between the node and the
routed namespace of the targets), the TCP and UDP flows that cross it: what the node itself sends on
to the HTTPS target and what comes back. The capture on the wire between the two machines shows a
`curl` of the test machine only as bytes inside the connection to the node, so this is the one place
that says whether the node opened its own connection to `203.0.113.2:443`. The count has a socket and a
thread of its own and no part in the observer: if it cannot start or fails on the way, the file says so
(`error`) and the capture, the verdicts and the exit code are as they would have been.

The lab machine writes `route-flows.json` (at most 256 KiB, every address outside the documentation
ranges blanked) and the controller keeps it beside `https.json` and passes it on as `lab.route_flows`,
field by field and only in the shape the helper writes it (a row of another shape is counted in
`rejected_rows`). If the file cannot be read, `lab.route_flows` is null and `route_flows_error` says at
which step; nothing else of the run changes.

```json
{"flows": [{"proto": "tcp", "client": "203.0.113.1:51000", "server": "203.0.113.2:443",
            "frames_out": 4, "frames_back": 3, "bytes_out": 120, "bytes_back": 400,
            "first_at": 1760000000.5, "last_at": 1760000015.5,
            "syn": true, "syn_ack": true, "fin": [], "rst": ["back"]}],
 "omitted_frames": 0, "other_frames": 2, "unparsed_frames": 0, "error": null, "dropped": 0}
```

- The client is the side that sent the first packet (a SYN-ACK seen first names the other side). `out`
  is toward the server, `back` from it; `bytes_*` are the payload sizes the IP headers declare.
- `first_at` and `last_at` are seconds since the epoch by the clock of the lab machine, not of the test
  machine and not of the capture on the wire.
- At most 512 flows are kept, in the order of their first packet; the packets of any further one are
  counted in `omitted_frames`. `other_frames` are packets that are not TCP or UDP (ARP, ICMP, fragments).
  `dropped` is what the kernel dropped on the socket of the count.

Reinstall the helper (`linux/guest/lab-entry.py` and `matrix/lab_protocol.py`) in both images.

#### The whole service journal

`run-l3.sh` saves the last 400 lines of the journal of `rosetun-helper.service` beside its report, and
a window of the run may be older than that. A diagnostic run therefore asks the test machine for the
whole journal of the boot, once, right after the report has been collected and before the lab machine
finishes: one fixed command through the guest agent, no argument from anywhere else,

```text
/usr/bin/journalctl -b -u rosetun-helper.service -o short-monotonic --no-pager
```

The output is cleaned the way the short journal is (every byte but a newline and printable ASCII becomes
`?`) and kept as `linux-l3/helper-journal-full.txt` in the run of the test machine, with its SHA-256 in
the summary's `evidence`. At most 1 MiB is kept: a longer journal keeps its first and its last whole
lines around one line, `[N bytes left out]`. The time is `short-monotonic`, seconds since the boot of
the test machine, so it is not the wall clock of anything else.

The place of the file is registered only for a diagnostic run, and the call may start after the deadline
of the job (by up to 300 seconds), which no other call of the job may. If the guest cannot give the
journal (the command fails or does not end, or the agent refuses), `journal_full_error` of the summary
says at which step and nothing else of the run changes: the results already collected, the assessment
and the exit code stay as they were.

#### The scenarios against the flows

A diagnostic run adds `alignment` to the summary: for each of the sixteen scenarios of the group, when it ran
and which flows were open then, from the capture on `lab-wire` (the `flows` of its window) and from
`route-flows.json`. It exists to tell, for one scenario, whether its connection reached the node, whether the
node reached the target and whether the target answered. It judges nothing, and if it cannot be made
(`alignment` is null) `alignment_error` says why and the rest of the summary is as it would have been.

Everything in it is approximate, and each entry says `approximate: true`, because the report of the script
has no start time for a scenario. It has its duration, and one time, when the script finished, by the clock of
the test machine, to the second. So:

- `report_begin` and `report_end` are the scenario's place by the test machine's clock, counted back from the
  end of the report as if the scenarios had followed one another with no pause. They did not (a connect or a
  restart is in no duration), so an earlier scenario is shown later than it ran by every pause after it.
- `interval_ms` is where the scenario ran, by the clock of the lab machine, in milliseconds after the request
  that opened its window: `begin` is the time of the scenarios of the window that ran before it, `end` is the
  length of the window less the time of those after it, so it ran somewhere inside, and `slack` is what the
  window had besides the durations of its scenarios (negative if the durations do not fit in it, a sign that
  the window is not what the report ran in). A scenario that belongs to no window (`preflight.*`, `install.service`),
  or whose window lacks a marker, has no interval and no flows. If several windows carry its label (the
  script was run again), the first that has both markers, from the window's number on (stage 7c2), is used and
  `windows_with_label` says how many there are.
- `wire_flows` are the connections of the test machine in the window (the rows of `lab.windows[].flows`) and
  `route_flows` those of `lab.route_flows`, whose `first_ms` and `last_ms` here are the times of the first and the
  last packet in the same milliseconds, so the two lists can be read side by side. A flow is listed when its first
  and last packet bracket any of the interval; one with no time is listed with `time_unknown`. At most 24 of each
  kind are listed for a scenario and `wire_omitted` and `route_omitted` count the others. A route flow may have
  begun before the window (a negative `first_ms`).
- `clock` estimates how far the two machines' clocks are apart: `by_window` has, for each window of the group,
  the time of its opening marker by the lab machine's clock less the time at which the test machine's clock puts
  the window's first scenario, `offset_s` is the median of those and `spread_s` the difference of the largest
  and the smallest. The pauses make an earlier window look later, so the later windows are the ones to trust and
  a large spread means that the offset is not known better than that. The report counts to the second.

Read it for `killswitch.tunnel-passes` like this: a flow to the node (`kind: node`) that lasts as long as the
`curl` (about 15 s) with bytes both ways says the stream left the test machine; a flow of `route_flows` from
`203.0.113.1` to `203.0.113.2:443` says the node opened its own connection, and its bytes and `rst` say how far
that got; no such flow while the node's side of the wire shows bytes toward it means the node did not pass it
on.

### Owner qualification

1. `run linux-l3 --lab --dry-run`, then the ordinary command. Expect the group `PASS`, the
   cross-check `AGREE`, exit 0, and keep the summary.
2. Legacy L3 on Hyper-V with the new `run-l3.sh`: all `PASS`, as before.
3. Positive control: `run linux-l3 --lab --control stop-helper` (stage 7c1): exit 0.
   Fallback by hand: during the window `connect_ks`, `systemctl stop rosetun-helper` from the console
   of the test machine; the table goes, the probes of the script leave directly, that window is
   `DETECTED`, exit 1.
4. Stop the observer on the lab machine in the middle of the run: exit 2. (`lab-smoke --control
   observer-stopped` shows the same for the observer itself.)
5. Compare the rows of the group with a run on Hyper-V.

## Stage 7c1: controls of the observer without a console, and the window after a stop

Nothing here widens what the lab accepts. Stage 7b2b qualified on the stand (16 of 16, the cross-check
`AGREE`, two runs alike), but that the observer *catches* a leak and does *not* say `NONE` without proof
was shown only by the canary of 6b; the other controls needed the guest console or a hand-made QMP
command, so a qualifying agent could not run them. This stage makes them commands. Every new window
of stage 7c2 that says `NONE` leans on them.

### The window after a stop

Found by the first two runs of 7b2b: the window `stopped` was `DETECTED`. After `systemctl stop
rosetun-helper.service` nothing answers `rosetun status`, so `lab_mark close` (which needed the state
`Disconnected`) never went out, and the direct request that followed landed in the open window.
`lab_mark close` now also goes when there is no table `inet rosetun` and either the state is
`Disconnected` or the service is not active; `lab_mark open` is as before. Every other call
(`disconnect`, `connect_with`, the end of the peer scenarios, `crash.open-network`,
`crash.dns-lock-killed`) runs with the service active, so its condition is the old one. Without
`LAB_MARKER_ADDRESS` nothing changes, on Hyper-V too.

### `lab-smoke --control NAME`

One key, not together with `--canary` or `--tunnel` (exit 2 from the parser). Each control exits 0 only
when exactly its refusal was obtained and 2 otherwise; the summary has a block `control` with `name`,
`expected` (in words), `intervened`, `link_restored` and `met`. Ordinary and `--canary` summaries have no
such block and send the same requests to the guests as before.

| `NAME` | What it does | Exit 0 only if |
| --- | --- | --- |
| `extra-packet` | sends the canary's packets, but the run is judged as an ordinary one | `leak` `DETECTED`, `canary_flows` `["tcp", "udp"]`, `canary_other` 0, both markers found and ordered, `observer_reasons` empty, no error, `qualified` |
| `observer-stopped` | the controller has the lab stop its observer the ordinary way (`halt`) between the markers | `leak` `UNVERIFIED` (never `NONE`), `window-markers-missing-or-repeated` **and `capture-halted-in-window`** in `observer_reasons`, the markers not found, and exactly one error: the closing exchange of the test machine (`marker-close`) |
| `observer-killed` | the lab sends `SIGKILL` to its own observer between the markers (`halt`; no pid comes from the controller) | `leak` `UNVERIFIED` (never `NONE`), `observer_reasons` exactly `observer-gone`, the markers not found, and exactly two errors: the closing exchange of the test machine (`marker-close`) and the refusal `observer-gone` of the controller (stage `lab-smoke`) |
| `link-down` | the controller runs `set_link test-wire off` through QMP between the markers and `on` again before the machines close | the same as `observer-stopped`, except that `capture-halted-in-window` must **not** be in `observer_reasons`, and `link_restored` true |

The three differ in what the observer could still say. A stopped observer ends its capture on request and
its `health.json` carries `halted` (only `halt` leaves it), which the verdict turns into
`capture-halted-in-window`: the one reason a cut link cannot give, because there the observer runs on,
healthy, to the `finish`. A killed observer gets no chance to write: no `health.json`, no target log, and a
pcap that may be cut off. `finish` does not wait for it: the lab sees that the process of its observer
(recorded by the lab at the setup, checked in `/proc` to be the observer of this run before it is signalled
or trusted) is gone and answers `observer_gone`, so the controller reads nothing, judges nothing and ends
the run as refused, with `observer-gone` as the reason. The kill needs no new right: the helper runs as
root, as it does for everything else. A run whose `finish` did not find the observer gone is read as an
ordinary run and the control fails.

For the three that stop something the test machine waits `CONTROL_HOLD_SECONDS` (20) after its exchanges and before the
closing marker, only when the request names the control (`control` in the request options, accepted
only with these three names and no canary). The controller acts on the *event*: while the test machine's
helper runs it polls the lab with the new read-only operation `window`, which says whether the lab
served the opening marker and has answered every exchange the request expects (the observer touches
`exchanges-done` only for a request with a control, and only when the last of them is answered), and
acts once, on the first yes. The marker alone is not enough: the test machine still has exchanges to
make after it, and a cut in the middle of them would add errors of its own. If the helper ends before
the lab says yes, nothing is stopped: `control.intervened` stays false, the errors name
`exchanges-not-completed` and the exit is 2. `observer-stopped` calls the new lab operation `halt`, which
stops the observer the way `finish` does, after marking the stop as asked for (`finish` then finds it
stopped, but only for that control); `observer-killed` calls `halt` too, which signals the observer and
touches neither the stop file nor the mark; `link-down` calls `Vm.set_link(False)` of the test machine. The link is brought back after `finish`
(so that what the test machine sends once it is back is not judged), and in any case before the
machines close, also when the run failed; a link that cannot be brought back is an error.

`set_link` goes through the same QMP facade and lifecycle journal as `stop` and `cont`: the rows
`link-down` and `link-up` (`intent`, `command-accepted`, `error`) stand in `lifecycle.jsonl` of the
test run, and the facade takes `set_link` only with exactly `name` (`test-wire` or `lab-wire`) and
`up` (a boolean). Both machines still end with `completion_verified`; if not, the exit is 2.

### `run linux-l3 --lab --control stop-helper`

The positive control of the L3 observer, one key, only with `--lab` and not with `--diagnostic` (both
refused before anything starts). `job.env` gains an optional last key `LAB_CONTROL=stop-helper`, only
together with `LAB_MARKER_ADDRESS` (the importer, the helper in the image and `run-l3.sh` all refuse
anything else). In `scenario_kill_switch`, right after `killswitch.direct-blocked` is recorded PASS and
in the same window `connect_ks`, `run-l3.sh` stops `rosetun-helper.service` and makes one `direct_https`.
The scenarios after it run as usual and may fail: this is a control run, and the summary says so
(`control: "stop-helper"`, `control_result`). Without `LAB_CONTROL` `run-l3.sh` does exactly what it did.

Exit code of the run, in place of the ordinary one: 0 only when the window `connect_ks` is `DETECTED`,
it holds a TCP flow from the test machine to `203.0.113.2:443` that the target answered (SYN and
SYN-ACK), `killswitch.direct-blocked` is `DISAGREE` in the cross-check, an ordinary run would have exited
1 and both machines are completed (`control_result.ordinary_exit_code` keeps that ordinary code). Anything
else is 2, an interruption 130. A run with a control is never a qualification of the group.

### Reinstall

Changed in the images: `linux/guest/lab-entry.py` and `matrix/lab_protocol.py` in **both** images (the
control request, the operations `window` and `halt`, the hold, the moment of the intervention, the mark of a
stopped observer, the kill), and `linux/guest/stage-l2.py` in the **test** image (the optional
`LAB_CONTROL`). `linux/guest/run-l3.sh` and `linux/guest/start.sh` reach the
test machine through the package and need no reinstall. Update the image descriptors of both images
(the new SHA-256 and size of each) before any qualification; the tunnel descriptors (`sing_box_sha256`,
`ca_sha256`) do not change. The Hyper-V path needs the new `run-l3.sh` only when its owner takes it.

### Owner qualification

Build both images again with the new `lab-entry.py` and `lab_protocol.py` and the test image with the new
`stage-l2.py`, and update the image descriptors of both (see "Reinstall"). Each command in its own run on
the clean checkpoint. Stop at the first unexpected result and send back the summaries and the retained
artifacts.

1. `lab-smoke --config <lab.toml>`, then `lab-smoke --config <lab.toml> --canary`: as in 6b.
2. `lab-smoke --config <lab.toml> --control extra-packet`, then `--control observer-stopped`, then
   `--control observer-killed`, then `--control link-down`: exit 0 each; `control.met` true; `leak`
   `DETECTED`, `UNVERIFIED`, `UNVERIFIED`, `UNVERIFIED`. The `observer_reasons` of the second hold
   `capture-halted-in-window`, those of the third are exactly `observer-gone`, those of the fourth do not
   hold `capture-halted-in-window`. If a run exits 2 with `control.intervened` false and the error
   `exchanges-not-completed`, the exchanges of the test machine did not finish in time: send the summary.
3. `run linux-l3 --config <l3.toml>` without the laboratory: 4 PASS, 1 FAIL (`preflight.baseline`), 20 SKIP,
   35 ERROR, exit 1, as in 7a.
4. `run linux-l3 --lab --config <l3.toml>`, twice in a row (each on the clean checkpoint): 16 of 16, exit 0
   both times, and the window `stopped` `NONE` (it is outside the group, so it is read in `lab.windows`).
5. `run linux-l3 --lab --control stop-helper --config <l3.toml>`: exit 0, `control_result.met` true.
6. `run linux-l2 --config <l2.toml>`: as in the stage 5c qualification (`stage-l2.py` changed).
7. `runs --state-directory <state>`: every run `completion_verified`, and the stand not locked.

## Stage 7c2: the L3 group with every other kill switch session, and sshd for `inbound.reply`

Until now the group was 16 scenarios: the preflight, the installation and three windows (`reported`,
`identity`, `connect_ks`). The other sessions under the kill switch already ran in the lab, and in the two
qualification runs of 7b2b their windows were `NONE`, but the exit code did not depend on them. This stage
makes them part of the group: **27 scenarios**. Windows where direct traffic is expected (rules that send a
program direct, a DNS lock, Local network, `lan.on`) stay outside: they need declared expectations (stage
7c3). Nothing is accepted: the release gate stays false and the security invariants stay **UNVERIFIED**.

### A window is a label and a number

`WINDOW_OF` in `l3_summary.py` names, for each scenario, a pair (label, number) or `None`. The number counts
the windows with that label from zero, in the order of the capture, and only that one window is judged for the
scenario. `rules.capabilities` needs this: its function opens two sessions, the first under the kill switch
alone and the second with a rule that sends a program direct, in which `rules.direct-other-account` (outside
the group) then runs and which is `DETECTED` by design. The scenario is judged in `capabilities` 0 only.

- Each label of the group has an expected count of windows (`WINDOWS_PER_LABEL`: 2 for `capabilities`, 1 for
  the others); `forwarded`, which opens only now and then, may have at most one (`WINDOWS_AT_MOST`).
- A window beyond the count (a session opened again after a reconnect or a FAIL) is a session under the kill
  switch that nobody expected: it is judged by no scenario, but a leak in it is a finding (exit 1,
  `leak-in-group-window`), as in a judged window. A session the script opens again comes after the ones it
  expects, so their numbers stay right.
- A window within the count that no scenario of the group judges (today only `capabilities` 1, where
  `rules.direct-other-account` runs, until stage 7c3) stays outside: a leak in it is listed in
  `group.outside_leaks` and changes no code.
- Any other count than expected, more or fewer, means the run is not numbered as the script numbers it, so it
  cannot vouch for itself: without a finding the code is 2, with `window-count:<label>:expected=<n>,seen=<m>`
  (`expected=at-most-1` for `forwarded`) in `group.unproven`. With fewer windows nothing tells which session is
  missing, so no window of that label is judged and its scenarios are `UNOBSERVED`. A window is never judged
  for a scenario that belongs to another session.
- `lab.window_counts` lists each of these labels with `expected` (or `at_most`), `seen` and `as_expected`. Each
  row of `lab.windows` also has `number`, `judged` and `beyond`; `in_group` keeps saying only whether the label
  is one of the group's.
- The control `stop-helper` of stage 7c1 reads the same judged window, `connect_ks` 0.

### The group and its windows

| Label | Number | Scenarios judged in it |
| --- | --- | --- |
| none | | `preflight.identity`, `preflight.accounts`, `preflight.no-foreign-service`, `preflight.tools`, `preflight.baseline`, `install.service`, `upgrade.unprotected` |
| `reported` | 0 | `protection.reported` |
| `identity` | 0 | `engine.identity`, `engine.files` |
| `connect_ks` | 0 | `killswitch.direct-blocked`, `killswitch.tunnel-passes`, `lan.off`, `killswitch.foreign-table`, `killswitch.engine-killed`, `killswitch.flush-restored`, `killswitch.disconnect` |
| `capabilities` | 0 (of 2) | `rules.capabilities` |
| `restart_guarded` | 0 | `rules.restart-guarded`, `rules.search-misses` |
| `inbound` (or `forwarded`, see below) | 0 | `inbound.reply`, `forward.blocked` |
| `killed` | 0 | `crash.helper-killed`, `crash.open-network` |
| `five_kills` | 0 | `crash.five-kills` |
| `upgraded` | 0 | `upgrade.restart` |
| `stopped` | 0 | `stop.removes-table` |

`upgrade.unprotected` restarts the service with no session at all: it has no window, as the preflight.

**The peer scenarios.** `inbound` sets up the peer namespace, reads the banner of sshd from the peer without
Rosetun, and only then connects; `forwarded` connects only if no session is open. So:

- With sshd (image contract v6), `inbound` opens the window `inbound` and `forwarded` runs in it; the window
  closes in the `disconnect` of `forwarded`, before the peer's request that must answer again. Both scenarios
  are judged in `inbound` 0.
- If `inbound` stopped before its connect (no banner, as in every 7b2b run, or no peer namespace), it failed
  and its row is `NOT_APPLICABLE`; `forwarded` opens a window of its own, `forwarded`, and `forward.blocked` is
  judged in that one (`OWN_WINDOW_WHEN_OPENED`). The same holds if `inbound` connected but its session was gone
  when `forwarded` ran. `lab.window_counts` then shows `inbound` 0 of 1.
- A pass of `inbound.reply` without a window `inbound` is `UNOBSERVED`.

### Where each window opens and closes

Checked in `run-l3.sh`; it is not changed by this stage. Every closing marker waits for the table
`inet rosetun` to be gone (`lab_mark`), so no window closes before the protection is removed, and in every case
below the closing marker goes before the direct request that follows the session.

| Scenario | Function | Sessions | Where the window closes |
| --- | --- | --- | --- |
| `rules.capabilities` | `capabilities` | 2 (two windows) | window 0 in the second `connect_with` (its `disconnect`, then `lab_mark close`); window 1 in the `connect_with` of `through_vpn_by_program` |
| `rules.restart-guarded` | `restart_guarded` | 1 | the `disconnect` at the end of `scenario_program_rules`, after `rules.search-misses` |
| `rules.search-misses` | `scenario_program_rules` (recorded inline, no `check`) | 0 | the same; it reads the journal inside the window |
| `inbound.reply` | `inbound` | 1 | the `disconnect` of `forwarded`; if that fails, the `lab_mark close` after `forward.blocked` |
| `forward.blocked` | `forwarded` | 0, or 1 when no session is open | as above, in the window `inbound` or its own |
| `crash.helper-killed` | `killed` | 1 | `opened`, after `rosetun open-network` and `! table_present`, before `direct_https` |
| `crash.open-network` | `opened` | 0 | the same |
| `crash.five-kills` | `five_kills` | 2 `connect_with`, one window | the `disconnect` before the final `direct_https` |
| `upgrade.restart` | `upgraded` | 2 `connect_with`, one window | the final `disconnect` |
| `stop.removes-table` | `stopped` | 1 | after `systemctl stop` and `! table_present`, before `direct_https` (stage 7c1) |

**Why `five_kills` and `upgraded` have one window each.** `lab_mark` sends nothing while the table
`inet rosetun` exists. Between the two connects of each function the network is held closed: after the
service is killed (`five_kills`) or restarted for an upgrade (`upgraded`), the restarted service keeps the
table as a hold, and its state reads `Disconnected`. The second `connect_with` therefore runs no `disconnect`
(the state is already `Disconnected`, and a `disconnect` would lift the hold), and both its `lab_mark close`
and its `lab_mark open` find the table and do nothing. The connect brings the tunnel up under the hold and
lifts the hold only once it is connected, so the protection never lapses, and the one window runs from the
first connect to the `disconnect` at the end. A second window with either label means the hold was gone at
the second connect: the run cannot vouch for itself (exit 2), a leak in the extra window is a finding, and a
leak while the hold was gone falls in the first window, whose verdict stands.

If `crash.helper-killed` fails, `scenario_crash` returns with the window `killed` open; the first
`disconnect` of `upgraded` lifts the hold and closes it before any direct request.

### Image contract v6 (test image)

v5 plus sshd for `inbound.reply`, which reads the banner `SSH-` on `198.51.100.1:22` (`PEER_HOST_ADDRESS`, the
guest's end of the veth to the peer namespace; the address exists only between `peer_up` and `peer_down`). The
lab image does not change. Hyper-V is not affected: its guest has its own sshd.

- **Packages.** `openssh-server` and its Debian 13 dependencies, installed offline from a directory the owner
  supplies (`--sshd-debs DIR`). The directory holds only `.deb` files (no links, no other entry) and must
  include `openssh-server`. The tool never downloads and never reaches a network: it runs `dpkg -i` inside the
  image through guestfish, with a `policy-rc.d` that forbids starting anything while the maintainer scripts run.
  The name, SHA-256 and size of every package go into the descriptor (`sshd.debs`).
- **Units of its own.** The packaged `ssh.socket` of Debian 13 (openssh-server 1:10.0p1-7) listens on port 22
  of every address with `Accept=no`, handing its socket to the daemon of `ssh.service`, so it is not used. The
  tool writes two units to `/etc/systemd/system` and enables the socket:
  - `l3-lab-sshd.socket`: `ListenStream=198.51.100.1:22`, `FreeBind=yes` (the address does not exist at boot),
    `Accept=yes`, `WantedBy=sockets.target`;
  - `l3-lab-sshd@.service`: the `[Service]` lines of the packaged `sshd@.service` (`sshd -i` with
    `StandardInput=socket`, the `RuntimeDirectory` of sshd), so systemd hands each connection to `sshd -i` and
    sshd binds nothing itself.

  The names do not start with `rosetun`: `preflight.no-foreign-service` refuses any unit that does.
  Never the address on the lab wire (`192.0.2.2`), never `0.0.0.0`.
- **Packaged units masked.** `ssh.socket` and `ssh.service` are disabled and masked, and so is the alias
  `sshd.service`: no dependency (`rescue-ssh.target` among them), socket or hand can start the daemon.
  `/etc/ssh/sshd_config.d/rosetun-lab.conf` sets `ListenAddress 198.51.100.1:22`: `sshd -i` ignores it, it is a
  second bound should the daemon ever be started.
- **Keys.** The host keys are created in the image at installation (`ssh-keygen -A`), so every overlay of the
  image has the same ones. That is acceptable here: sshd is reachable only from the peer namespace inside the
  test machine, no client trusts or pins these keys, the scenario reads only the banner and the start of the key
  exchange, and the image never leaves the stand. The private keys are not secrets of anything else; do not
  reuse the image outside the lab.
- **Check after writing.** The tool reads the copy back with `guestfish --ro` and refuses it unless
  `ssh.socket`, `ssh.service` and `sshd.service` are links to `/dev/null` and linked from no `.wants` or
  `.requires`; `l3-lab-sshd.socket` is enabled and its effective settings (the unit and every drop-in in
  `socket.d` and `l3-lab-sshd.socket.d`, in order, an empty `ListenStream=` resetting the list) are exactly one
  `ListenStream=198.51.100.1:22` with no other `Listen*`, `FreeBind=yes` and `Accept=yes`;
  `l3-lab-sshd@.service` is exactly the text the tool writes, without a drop-in; a host key exists; and
  neither the `policy-rc.d` nor the package directory is left. A refused copy is deleted.
- **Preflight.** No preflight looks at sshd: `preflight.no-foreign-service` checks units named `rosetun*` (hence
  the names above), the helper's files, the table and the peer namespace. A listening socket opens no connection, so the quiet image
  of v5 stays quiet.

```sh
python tools/vm/linux/prepare-l3-image.py /srv/test-v5.qcow2 /srv/test-v6.qcow2 \
  --source-sha256 V5_SHA256 --descriptor /srv/test-v6.image.json \
  --sshd --sshd-debs /srv/sshd-debs
```

`--sshd` without `--sshd-debs`, or the other way round, is refused by the parser (exit 2). Without both the tool
prepares a v5 image as before. Copy the fields of the descriptor into `[image]` except `sshd`, which stays in the
descriptor as the record of the packages.

Check the new image after a boot, before sealing it:

```sh
systemctl is-enabled l3-lab-sshd.socket ssh.socket ssh.service   # enabled, masked, masked
systemctl show -p Listen -p Accept l3-lab-sshd.socket            # Listen=198.51.100.1:22 (Stream), Accept=yes
ss -tlnp                                  # 198.51.100.1:22 held by systemd, nothing on 0.0.0.0:22 or 192.0.2.2:22
```

If the boot shows another address or an sshd daemon, stop and send the output.

### What to reinstall

Only the test image: build v6 from the v5 image with `prepare-l3-image.py --sshd` and update the descriptor in
the execution configuration. `l3_summary.py` and `l3_align.py` run on the controller; nothing in either image
changes, so the lab image, its descriptor and the helpers stay as in stage 7c1.

### Exit codes

The meanings of 0, 1, 2 and 130 are those of stage 7b2b. The group is larger, so a failure or a leak in any of
the new scenarios or windows is now a finding (1), a leak in a window of a label of the group beyond its count
is a finding too, and a pass in a window that is unverified or missing is `UNOBSERVED` (2). A new reason for 2:
a label of the group with another count of windows than expected (`window-count:...`).
`LEAK_OUTSIDE_THE_GROUP_FAILS` stays false.

### Qualification

Each command in its own run on the clean checkpoint. Stop at the first unexpected result and send back the
summaries and the retained artifacts.

1. Build the v6 test image with `prepare-l3-image.py --sshd --sshd-debs DIR`; write the new descriptor into the
   configurations (`[image]` of L2 and L3, `[test_image]` of the lab configuration).
2. `lab-smoke --config <lab.toml>`, `lab-smoke --config <lab.toml> --canary`, then the controls of 7c1
   (`--control extra-packet`, `--control observer-stopped`, `--control observer-killed`, `--control link-down`)
   on the new images: exit 0 each, as in 7c1.
3. `run linux-l3 --config <l3.toml>` without the lab: 4 PASS, 1 FAIL (`preflight.baseline`), 20 SKIP,
   35 ERROR, exit 1, as in 7a.
4. `run linux-l3 --lab --config <l3-lab.toml>`, twice in a row: the group 27 PASS (`inbound.reply` among them),
   the cross-check without `DISAGREE` and without `UNOBSERVED`, `lab.window_counts` all `as_expected`, exit 0
   both times.
5. `run linux-l3 --lab --control stop-helper --config <l3-lab.toml>`: exit 0, `control_result.met` true.
6. `run linux-l2 --config <l2.toml>`, then `runs --state-directory <state>`: every run `completion_verified`.

## Stage 7c3: expectations of the windows with direct traffic, and a specific route

After stage 7c2 the windows where direct traffic is expected by design (rules that send a program direct, a DNS lock
without the kill switch) stayed outside the group: `DETECTED`, judged by nothing, so a leak beyond what they are meant
to send was invisible. This stage fixes, in the controller, exactly what each of them may show, adds their scenarios to
the group (**35 scenarios**), and adds the scenario `route.specific-bypass`. Nothing is accepted: the release gate stays
false and the security invariants stay **UNVERIFIED**.

### The flows of the unexpected frames

Each row of `lab.windows` gains `direct`: the frames of the test machine in the window that are `unexpected` (not the
tunnel, not the infrastructure), grouped by flow. A flow is a TCP connection or a UDP exchange by protocol and
four-tuple, so a SYN or a datagram sent again stays one flow.

```json
{"flows": [{"protocol": "udp", "kind": "resolver", "client": "192.0.2.2:42724", "server": "203.0.113.53:53",
            "frames_out": 2, "frames_back": 2, "opened": true}],
 "other_frames": 0, "omitted_frames": 0}
```

- `kind` is `target` (TCP to the HTTPS target `203.0.113.2:443`), `resolver` (UDP to the lab resolver
  `203.0.113.53:53`) or `other`.
- `opened` says the test machine started the flow inside the window: a SYN without ACK it sent, or for UDP an
  outbound first frame.
- `other_frames` counts the unexpected frames of no flow (ARP, ICMP, a fragment), `omitted_frames` those beyond 64
  flows. With the frames of the flows they account for every unexpected frame of the window.

`flows`, the TCP connections of every category, stays as it was. `direct` is read from the same capture and changes no
verdict by itself.

### Expectations and verdicts

`EXPECTED_FLOWS` in `l3_summary.py` names, by window (label, number), the flows the test machine opens past the tunnel
by design, each with its exact count. The controller fixes them from what the functions of `run-l3.sh` send; the guest
declares nothing and cannot change them. Every row of `lab.windows` gains `expected_flows` (empty without an
expectation) and `verdict`; `leak` stays what the observer saw.

| `verdict` | When |
| --- | --- |
| `EXPECTED` | every unexpected frame belongs to a flow the test machine opened that the expectation names, in exactly the expected number, and the window is clean otherwise |
| `MISMATCH` | nothing beyond the expectation, but fewer flows: the script says traffic went out and the observer did not see it |
| `DETECTED` | more of an expected flow, a flow of another kind or not opened by the test machine, or any frame of no flow, whatever else went wrong |
| `UNVERIFIED` | nothing beyond the expectation, but the window cannot vouch for itself (the observer's reasons of stage 7b2b) |
| `NONE` | a window without an expectation and without a leak, as before |

A window without an expectation keeps the observer's verdict. In the cross-check a pass in an `EXPECTED` window is
`AGREE`, a pass in a `MISMATCH` or `DETECTED` window is `DISAGREE`; a failure stays a failure. The exit codes keep
their meaning: a `DISAGREE` is 1, a `DETECTED` window that is judged or beyond its count is 1
(`leak-in-group-window`), a `MISMATCH` is 1 through the `DISAGREE` of its scenarios. A window of a label beyond its
count has no expectation, so anything in it is a leak.

| Window | Flows expected | Count | Where the count comes from |
| --- | --- | --- | --- |
| `capabilities` 1 (or `direct_for_other_account` 0) | TCP to `203.0.113.2:443`, opened by the test machine | 1 | `direct_for_other_account`: two `expect_route`, the curl of the other account `direct`, the other program `tunnel`; one `route_of` is one curl, one connection |
| `through_vpn_by_program` 0 | the same | 1 | the same, the other way round: the other program `direct` |
| `dns_lock` 0 | the same | 1 | `dns_lock`: `expect_udp_dns_refused` is refused in the guest and sends nothing, one `direct_https`; `dig` in `dns_tunnel` goes through the tunnel |
| `dns_lock_unavailable` 0 | UDP to `203.0.113.53:53`, opened by the test machine | 1 | one `expect_udp_dns_sent` (curl's TFTP request, sent twice when the reply is no TFTP, one source port) |
| `missing_through_restart` 0 | the same | 1 | one `expect_udp_dns_sent` while sing-box restarts |
| `dns_lock_killed` 0 | TCP to `203.0.113.2:443` | 1 | the one `direct_https` of `kill_helper` while the lock still stands; the window closes once the restarted helper removed the table, before `expect_udp_dns_sent` and the last `direct_https` |
| `specific_bypass_dns_lock` 0 | the same | 1 | the one `route_of` of the scenario below; outside the group |
| `specific_bypass` 0 | none | 0 | `tunnel_https` and `direct_https` are both dropped in the guest |

The qualification runs of stages 7b2b and 7c1 showed exactly these on the wire: in each of the target windows one
connection (9 to 11 frames out, 7 or 8 back, SYN, SYN-ACK and FIN both ways), in each of the two resolver windows one
exchange of two datagrams each way from one source port. Nothing else was unexpected in them. The windows of the new
scenario have not run yet; their counts come from the script alone. The lab configuration
must name the lab resolver as `dns_probe_address` (`203.0.113.53`), or it is refused: the expected UDP is an exchange
with it.

### The group

| Label | Number | Scenarios judged in it |
| --- | --- | --- |
| (those of stage 7c2) | | the 27 of stage 7c2 |
| `capabilities` (or `direct_for_other_account`, see below) | 1 | `rules.direct-other-account` |
| `through_vpn_by_program` | 0 | `rules.proxy-default-direct` |
| `dns_lock` | 0 | `dnslock.direct-blocked`, `dnslock.tunnel-passes` |
| `dns_lock_unavailable` | 0 | `dnslock.unavailable` |
| `missing_through_restart` | 0 | `dnslock.unavailable-restart` |
| `dns_lock_killed` | 0 | `crash.dns-lock-killed` |
| `specific_bypass` | 0 | `route.specific-bypass` |

- `direct_for_other_account` connects only if the second session of `capabilities` is gone (after a failure there); it
  then opens a window of its own and `rules.direct-other-account` is judged there (`OWN_WINDOW_WHEN_OPENED`, at most
  one, as `forwarded`).
- Where the windows close was checked in `run-l3.sh`, which this part does not change: every closing marker waits for
  the table `inet rosetun` to be gone and the state `Disconnected`, and in none of these windows does a direct probe
  meant for after the session come before the closing marker. `dns_lock_killed` closes after `! table_present` and
  before its last probes (unlike `stopped` before stage 7c1).
- `specific_bypass_dns_lock` (at most one) is outside the group: it only adds to the note of `route.specific-bypass`. A
  `DETECTED` there is listed in `group.outside_leaks` and a `MISMATCH` changes nothing.
- Outside the group stay only the Local network windows (`lan_on`, `lan_private_closed`, `lan_private_open`,
  `lan_follows_change`, stage 7e), the window of `ipv6.neighbor` when it runs, and `specific_bypass_dns_lock`. So
  `LEAK_OUTSIDE_THE_GROUP_FAILS` stays false.

### The scenario `route.specific-bypass`

Sing-box with `auto_route` leaves a route of the main table that is more specific than its own in force, so traffic to
that address goes past the tunnel (the class of attack that uses a DHCP server's classless static routes, option 121).
The scenario characterises this known weakness; the product is not changed.

- It runs after the kill switch scenarios, not required (`required=no`), on the Hyper-V path too (the gateway is then
  the Default Switch's).
- Kill-switch session (`specific_bypass`): connect, then `<probe address>/32 via <default gateway> dev <physical>` into
  the main table, `tunnel_https`, `direct_https`. PASS if the direct path is refused. The note says whether HTTPS
  through the tunnel still answered (expected: no, the kill switch drops what the route sends past the tunnel). The
  route is removed before the `disconnect`.
- Only after that part passed, a session with the DNS lock alone (`specific_bypass_dns_lock`): connect, the same route,
  one `route_of` as the first account, whose answer (`direct`, `tunnel`, `no answer ...`) goes into the note; the route
  is removed, then `disconnect`. This part never changes the result.
- The route is written to the state directory before it goes in; the scenario removes it at its end whatever the
  outcome, and the cleanup (also in `finalize`) removes one that is left and names it in `cleanup.actions`.

The catalog has 60 rows. A run without the lab records 35 ERROR "not run" (stage 7a), and the PowerShell harness test
lists `route.specific-bypass` and `ipv6.neighbor` as the runnable scenarios that are not required.

### What to reinstall

No image changes. The content directory takes the new `guest/run-l3.sh` and `scenarios-l3.tsv` from the checkout (they
are compared byte for byte). `lab_protocol.py` changed only in `classify_windows`, which the controller runs on the
capture it read; `lab-entry.py` in the images never calls it, so the copies of `lab_protocol.py` in the images need not
be reinstalled (doing so changes nothing). `l3_summary.py` and `execution.py` run on the controller.

### Qualification

Each command in its own run on the clean checkpoint. Stop at the first unexpected result and send back the summaries
and the retained artifacts.

1. Copy `guest/run-l3.sh` and `scenarios-l3.tsv` of the checkout into the content directory; images and their
   descriptors as in stage 7c2.
2. `run linux-l3 --config <l3.toml>` without the lab: 4 PASS, 1 FAIL (`preflight.baseline`), 20 SKIP, 35 ERROR,
   exit 1.
3. `run linux-l3 --lab --config <l3-lab.toml>`, twice in a row: the group 35 of 35 PASS, the cross-check `AGREE` or
   `NOT_APPLICABLE` only, every window of the group `NONE` or `EXPECTED` (seven `EXPECTED`, counting
   `specific_bypass_dns_lock`), `lab.window_counts` all `as_expected`, 22 windows, exit 0 both times. The note of
   `route.specific-bypass` is expected to say that HTTPS through the tunnel did not answer and that with the DNS lock
   alone it went `direct`; send it back whatever it says.
4. `run linux-l3 --lab --control stop-helper --config <l3-lab.toml>`: exit 0, `control_result.met` true.
5. `run linux-l2 --config <l2.toml>`, then `runs --state-directory <state>`: every run `completion_verified`.

The owner alone runs the legacy L3 on Hyper-V (`Invoke-LinuxL2Matrix.ps1 -Run -Stage L3`): the new scenario runs there
too, and its note shows the same two answers for the Default Switch.

## Stage 7e: Local network and IPv6 in the group, and every window judged

After stage 7c3 the Local network windows, the window of `ipv6.neighbor` (SKIP in the lab: no IPv6 router) and the
DNS-lock session of `route.specific-bypass` were outside the group, so a leak in them decided nothing. This stage
fixes what the Local network windows may show, gives the lab an IPv6 router, adds those five scenarios to the group
(**40 scenarios**) and makes a leak in any window a finding. Nothing is accepted: the release gate stays false and the
security invariants stay **UNVERIFIED**. `run-l3.sh` and `scenarios-l3.tsv` do not change (60 rows), so neither does
the Hyper-V path.

### Local network: the flows and their expectations

The functions of `scenario_lan_on` use two addresses that `run-l3.sh` picks from the test machine's own address and
the host node's (`192.0.2.2`, `192.0.2.1` in the lab):

- `neighbor_address`: the first of `.250`, `.251`, `.252` of the own /24 that is neither, so `192.0.2.250`. Nobody holds
  it, on purpose: the TFTP datagram of `expect_udp_sent_to` leaves nftables and waits for ARP, which nobody answers, so
  the datagram itself never reaches the wire. The ARP requests are the proof that it got past the kill switch (a
  datagram dropped in the output hook never asks for its neighbor). A lab host on that address would add frames and a
  second address to the infrastructure table for no stronger proof, so the lab has none.
- `behind_router_address`: the first private address outside the own first two octets, so `10.254.254.1`, the
  owner-approved private address of the lab (an exception to the documentation addresses). The datagram goes to the
  lab's router, which has no route there and answers each one with a destination unreachable (type 3) from
  `192.0.2.1`.

Two new members of the flows of a window (`direct`), both read from the headers:

- `protocol` `arp`, `kind` `neighbor`: the broadcast ARP requests of the test machine (sender `192.0.2.2` with its
  own MAC, target MAC zero) for one address other than the lab's. All requests for that address are one flow, opened by
  the test machine, `frames_out` counting them. An answer, an announcement, a request from another address or to one
  machine is no part of it and stays `other_frames`.
- A destination unreachable from the lab's router (`192.0.2.1`, the lab's MAC, to the test machine) that quotes a
  datagram of a UDP flow already seen in the window is a frame back of that flow. Any other ICMP error stays
  `other_frames`. This applies to every window, the ones of stage 7c3 included.

| Window | Flows expected | Count | Where the count comes from |
| --- | --- | --- | --- |
| `lan_on` 0 | ARP for `192.0.2.250` | 1 | one `expect_udp_sent_to` the neighbor; `direct_node` and `direct_https` are dropped in the guest |
| `lan_private_closed` 0 | none | 0 | `expect_udp_refused_to` is refused in the guest |
| `lan_private_open` 0 | UDP to `10.254.254.1:69`, opened by the test machine; ARP for `192.0.2.250` | 1 each | one `expect_udp_sent_to` each address; `udp_dns_to`, `direct_node` and `direct_https` are dropped in the guest |
| `lan_follows_change` 0 | none | 0 | only `direct_https`, dropped; nothing in the script sends to `203.0.113.5/24` while it is on the interface, and no run showed a frame for it |

Why one ARP flow and not an exact number of requests: the kernel sends `mcast_solicit` requests (3 by default) for each
resolution, and whether curl's retry starts a second resolution depends on its timers against the kernel's. Every lab
run so far showed three requests in `lan_on` and in `lan_private_open` and two datagrams with two errors back to
`10.254.254.1` (twelve runs of stages 7b2b and 7c1, read again with this stage's code: both windows `EXPECTED`,
`lan_private_closed` and `lan_follows_change` `NONE`, no ARP for `203.0.113.0/24`). The category cannot cover anything
else: one sender, one target per flow, broadcast requests only, and any flow beyond the expected ones is a leak.

| Label | Number | Scenario judged in it |
| --- | --- | --- |
| `lan_on` | 0 | `lan.on` |
| `lan_private_closed` | 0 | `lan.private-closed` |
| `lan_private_open` | 0 | `lan.private-open` |
| `lan_follows_change` | 0 | `lan.follows-change` |
| `neighbor` | 0 | `ipv6.neighbor` |

Each function opens its own session and ends it with `disconnect`, whose closing marker waits for the table to be gone.

### IPv6 in the lab and the allowance

The lab's link-local address `fe80::200:5eff:fe00:5362` (the modified EUI-64 of its MAC) is the test machine's IPv6
default router. The lab's kernel makes that address itself when the link comes up (the captures of earlier L3 runs show
multicast listener reports from it). In an L3 run only (`windows: true`), `setup` also runs
`ip -6 addr replace fe80::200:5eff:fe00:5362/64 dev <link> nodad` after the link is up and writes `0` to
`/proc/sys/net/ipv6/icmp/echo_ignore_all`, so the address is there and answers echo whatever the image set. The kernel
answers neighbor solicitation and echo; nothing else is served. `lab-smoke` and the requests of 6a and 6b change
nothing.

`ipv6.neighbor` then runs instead of SKIP: without Rosetun it reads the router from `ip -6 route show default` and
pings it; its session `neighbor` (Local network) flushes the neighbor cache, pings the router twice and sends one
datagram to `2001:db8::1`, which the kill switch refuses in the guest. The window has no expectation (`NONE`).

- Neighbor solicitation and advertisement between the two link-local addresses are infrastructure already (any
  link-local address of either machine, to the solicited-node group or the other machine).
- The echo is the allowance `ipv6-link-local-echo`: an echo request (type 128, code 0) from `fe80::200:5eff:fe00:5361`
  (the test machine's EUI-64 address) to `fe80::200:5eff:fe00:5362` with the lab's MAC as destination, or the echo
  reply (129, code 0) the other way. Not from or to a global address, not another link-local address, not a request of
  the lab, not to a group, not over IPv4.
- The allowance holds in the windows labelled `neighbor` only (`WINDOW_ALLOWANCES` in `l3_summary.py`, the new
  `window_allowances` of `classify_windows`). The same echo in any other window is `unexpected`, and the ping without
  Rosetun, before the session, falls outside every window, where it is only counted.

On Hyper-V the scenario reads whatever router the guest has, as before, or is SKIP.

### Image contract v6b (test image)

v6 plus the IPv6 router. `prepare-l3-image.py --ipv6-router` changes only the network file the tool already edits
(`/etc/systemd/network/00-rosetun-lab.network`):

- in its one `[Network]` section `LinkLocalAddressing=ipv6`, `IPv6LinkLocalAddressGenerationMode=eui64` and
  `IPv6AcceptRA=no`, each added when missing and kept when it already has that value. The one value replaced is the
  `LinkLocalAddressing=no` of the quiet v6a image (the contract of v6 turns the test machine's link-local address off
  on purpose, and v6b cannot work without it: the route goes through the lab's `fe80::` address and the echo
  allowance names the test machine's EUI-64 one). That single line becomes `LinkLocalAddressing=ipv6` in place; any
  value other than `no` and `ipv6`, a second `LinkLocalAddressing` line, any other conflicting setting or a second
  `[Network]` section is refused;
- one route `[Route] Destination=::/0 Gateway=fe80::200:5eff:fe00:5362`; a file that already has an IPv6 default
  route, a link-local or `_ipv6ra` gateway or an IPv6 `Gateway=` in `[Network]` is refused, so the output of v6b is
  not prepared again. The route `2001:db8:6a:2::/64 via 2001:db8:6a:1::1` of the 6a contract stays;
- no address is added. The file read back from the copy must be the source with that one replacement plus what v6b
  adds, each setting once with its value, the same `Address=` lines as before, exactly that one IPv6 default route
  and every other section and setting unchanged, or the copy is deleted. The descriptor gains `ipv6_router` (the
  gateway, the settings and `replaced`: for each replaced setting its value `before` and `after`, `{}` when none).

```sh
python tools/vm/linux/prepare-l3-image.py /srv/test-v6.qcow2 /srv/test-v6b.qcow2 \
  --source-sha256 V6_SHA256 --descriptor /srv/test-v6b.image.json --ipv6-router
```

`--ipv6-router` goes alone or with `--sshd`. Copy the fields of the descriptor into `[image]` except `sshd` and
`ipv6_router`. Check the new image after a boot, before sealing it:

```sh
ip -6 route show default          # default via fe80::200:5eff:fe00:5362 dev <if> proto static ...
ip -6 addr show dev <if>          # fe80::200:5eff:fe00:5361/64 and 2001:db8:6a:1::2/64 only, no temporary address
sysctl net.ipv6.conf.<if>.accept_ra   # 0
networkctl status <if>
```

If another address, another IPv6 route or a router advertisement shows up, stop and send the output.

Frames the link-local address adds to the wire (judged by `classify` in `lab_protocol.py`; none of the tables is
widened for them):

| Frame of the test machine | Category |
| --- | --- |
| Neighbor solicitation and advertisement with the lab, from or to `fe80::200:5eff:fe00:5361` (to the solicited-node group or the peer; the target is a link-local address or one of the two lab addresses) | `infrastructure` |
| Multicast listener report (version 2, to `ff02::16`) from the link-local address, for its solicited-node group | `infrastructure` |
| Duplicate address detection of the link-local address: neighbor solicitation from `::` to `ff02::1:ff00:5361`, sent once when the link comes up (boot, or a link that goes down and up) | `unexpected` where nothing declares `ipv6-dad`, which is `lab-smoke` and every window of the L3 group (only `neighbor` declares an allowance, the echo); outside a window of an L3 run it is counted in `outside_window` only |
| Router solicitation | none: `IPv6AcceptRA=no` makes the kernel send none. From the link-local address to `ff02::2` it would be `infrastructure`, from `::` it would need `ipv6-unspecified-rs` and be `unexpected` |
| Echo to the lab's link-local address (`ipv6.neighbor`) | the allowance `ipv6-link-local-echo` in a window labelled `neighbor`, `unexpected` anywhere else |
| Anything else from the link-local address, such as a multicast name query (LLMNR, mDNS) | `unexpected` |

The duplicate address detection of the test machine's global address `2001:db8:6a:1::2` is the same frame with
another target and is judged the same way already in v6a. The link-local one is sent when the link comes up, which
in an ordinary run is before the capture starts, but a link that goes down and up inside a capture sends it again,
and then it is `DETECTED`: nothing declares `ipv6-dad` now. If it shows up in a real run, send the summary instead
of widening the tables; the decision is the owner's.

### Every window is judged

`LEAK_OUTSIDE_THE_GROUP_FAILS` is now true. A window is outside when no scenario of the group is judged in it and it is
not beyond the count of a label of the group. Its verdict after the expectation decides:

| Verdict of a window outside | Effect |
| --- | --- |
| `NONE`, `EXPECTED` | nothing |
| `MISMATCH` | characterises rather than protects: no code of its own, listed in `group.outside_mismatches` |
| `DETECTED` | a finding, `leak-outside-group`, exit 1 |
| any other (`UNVERIFIED`) | the run cannot vouch for itself: `outside-window-not-verified:<label>:<number>:<verdict>` in `group.unproven`, exit 2 unless something else is a finding (1 comes before 2) |

`group.outside_windows` lists every window outside with its verdict. The exit codes keep the meanings of stage 7b2b;
the new reasons are `leak-outside-group` for 1 and `outside-window-not-verified:...` for 2.

What stays outside, and why it is judged all the same:

- `specific_bypass_dns_lock` 0: its result is not the scenario's (the part under the kill switch decides
  `route.specific-bypass`), but it is held against its one direct request, so anything more is a leak.
- A window of a label no table names: no ordinary run has one (every function of `run-l3.sh` that opens a session has a
  label in `WINDOWS_PER_LABEL` or `WINDOWS_AT_MOST`, which a test checks), so anything in it is a leak.

A window of a label of the group with fewer windows than expected is not judged and is no finding of its own: which
session is missing is unknown, so is what the window should show (`capabilities` 0 shows nothing, 1 a direct request).
It is listed in `group.outside_leaks` if `DETECTED`, and the run cannot vouch for itself (`window-count`, exit 2), as
in stage 7c2.

The owner accepted these choices of the stage: the ARP requests for a neighbor are one flow per target address with
any number of requests (the kernel's timers decide the number); a destination unreachable about a UDP flow is a
frame back of that flow in every window; a window of a label short of its count is exit 2 and no finding; and the IPv6
default route is there in every session, since the observer sees any IPv6 frame the engine sends past the tunnel.

### What to reinstall

- `linux/guest/lab-entry.py` and `matrix/lab_protocol.py` in **both** images (`lab-entry.py` imports `LINK_LOCALS`
  from `lab_protocol.py`, so the two go together), then update both image descriptors.
- The test image: build v6b from that v6 copy with `--ipv6-router` and write its descriptor into the configurations
  (`[image]` of L2 and L3, `[test_image]` of the lab configuration).
- `l3_summary.py` and `l3_lab.py` run on the controller. The content directory is the one of stage 7c3: `run-l3.sh`
  and `scenarios-l3.tsv` did not change.

### Qualification

Each command in its own run on the clean checkpoint. Stop at the first unexpected result and send back the summaries
and the retained artifacts.

1. Install the helper in both images and build v6b as above; update the descriptors in the configurations.
2. `lab-smoke --config <lab.toml>`, `lab-smoke --config <lab.toml> --canary`, then `--control extra-packet`,
   `--control observer-stopped`, `--control observer-killed` and `--control link-down`: exit 0 each, as in 7c1. The
   test machine now has an IPv6 default route; an unexpected frame from it in `lab-smoke` is a result to send back.
3. `run linux-l3 --config <l3.toml>` without the lab: 4 PASS, 1 FAIL (`preflight.baseline`), 20 SKIP, 35 ERROR, exit 1.
4. `run linux-l3 --lab --config <l3-lab.toml>`, twice in a row: the group 40 of 40 PASS (`ipv6.neighbor` PASS among
   them), the cross-check `AGREE` or `NOT_APPLICABLE` only, 23 windows, each `NONE` or `EXPECTED` (nine `EXPECTED`:
   the seven of stage 7c3, `lan_on` and `lan_private_open`), `lab.window_counts` all `as_expected`,
   `group.outside_windows` only `specific_bypass_dns_lock` (`EXPECTED`), no `findings`, exit 0 both times. In the
   window `neighbor` `categories.allowed` is expected to show `ipv6-link-local-echo` 4 (two pings) and
   `infrastructure` the neighbor discovery; send the counts back whatever they are.
5. `run linux-l3 --lab --control stop-helper --config <l3-lab.toml>`: exit 0, `control_result.met` true.
6. `run linux-l2 --config <l2.toml>`, then `runs --state-directory <state>`: every run `completion_verified`.

The checks of stage W are not repeated.

### The scenario `route.bypass-warning` (61 rows, group of 41)

`dev` added `route.bypass-warning` (required) as the first row of `scenarios-l3.tsv`; `run-l3.sh` runs it after
`scenario_lan_on` and before `scenario_dns_lock`. The catalog now has 61 rows (39 required) and the group 41
scenarios; the product, the script and the order of the catalog are the owner's and did not change.

- Window `bypass_warning` 0 (`WINDOW_OF`, one window per run in `WINDOWS_PER_LABEL`), after `lan_follows_change` and
  before `neighbor` in the group. The session is `connect_with` a DNS lock; the scenario adds `1.1.1.1/32 dev <physical>
  proto 186` only for the helper to look it up, sends no packet to it, reads `cli status` and removes the route. It
  does not call `disconnect`: the `connect_with` of `dns_lock` ends the session (its `disconnect` and closing marker
  come before any probe), so nothing of `dns_lock` falls into this window.
- No entry in `EXPECTED_FLOWS`: the window is expected to show no frame to the target or the resolver (`NONE`), and
  anything else there is a leak.
- The summary and the cross-check read windows by label and number, not by the order of the catalog, so the first
  row of the TSV and its execution after `lan` need no change.

## Stage 8a: Linux Proxy in the lab

`run linux-proxy` delivers the Proxy package (system proxy without TUN, the strict kill switch of the first phase,
sharing, Lockdown, the GUI's module for the desktop's proxy settings, the stop of the service) as `run linux-l3`
delivers L3, and `run linux-proxy --lab` runs `run-proxy.sh` inside the lab of stage 7b2b, with windows and
expectations as for L3. Nothing is accepted: the release gate stays false and the security invariants stay
**UNVERIFIED**. No Proxy run has been through the lab yet: every count below comes from `run-proxy.sh` alone and
has not been compared with the wire.

### Profile and requests

- The stage profile `proxy` (`PROFILES` in `linux_l2.py`, the importer `guest/stage-l2.py`) is exactly
  `PROXY_START_REQUIRED` of `guest/start.sh`: the L3 sources with `guest/run-proxy.sh` and `scenarios-proxy.tsv`,
  the binaries `rosetun-helper-privileged`, `rosetun`, `desktop_proxy` (the three that
  `build-artifacts.sh --proxy` records in `provenance.json`, `"stage": "proxy"`) and `sing-box` (hashed against
  `[l3].sing_box_sha256`), the units `rosetun-helper.service`, `rosetun-engine.rules` and `rosetun-lockdown.service`
  of `packaging/linux/` (compared byte for byte), and four generated requests. Its evidence goes to `linux-proxy/`,
  the service's journal included.
- The requests are made by `l3_requests.render_proxy` from the L3 template, as `New-RosetunLinuxProxyRequests`
  makes them from the kill-switch request: `request-kill-switch.json` is the L3 file byte for byte (`mode.change`
  starts from it), and `request-proxy.json`, `request-proxy-strict.json` and `request-proxy-share.json` add
  `connection_mode` `system_proxy` and `local_proxy` (`port` 10808, `share_on_lan`) with the kill switch off, on and
  off. Documentation addresses only; a test pins their digests.
- `job.env` takes `LAB_MARKER_ADDRESS` and `LAB_CONTROL` for `proxy` as for `l3` (the importer in the image,
  `start.sh`, `validate_env` and `run-proxy.sh` all accept them, last and only together in that order). The Hyper-V
  path writes neither.
- The configuration is `rosetun.matrix.execution.v2` (without the lab) or `v3` (with it) with `suite = "linux-proxy"`
  and the same `[l3]` table as L3 (the node, the probes, the engine's hash): start from the L3 examples and change
  the suite. The content directory holds the files above (the requests are never in it).

### The lab's private address

The service shares its proxy only on a private address of a physical interface (`private_addresses` of the routing
crate), and the test machine's address on the lab wire is `192.0.2.2`. The owner approved one private address for
the lab, **`192.168.77.2/24`**, as an exception to the documentation addresses (as `10.254.254.1` of stage 7e). It is
not in the image: only with `LAB_MARKER_ADDRESS`, `run-proxy.sh` adds it to the physical interface once
`install.service` passed and before the first session, removes it after `stop.removes-table`, and the cleanup
removes one that is left; both removals are cleanup actions of the report. The service reads the private addresses
at every connect (and watches them during a shared session), so the address does not have to exist when the service
starts. The share scenarios then look for the proxy on that address; without the lab they look, as before, on the
interface's first address. It does not collide with the private addresses `run-l3.sh` derives for Local network,
and L3 never adds it.

### Windows

The markers (`lab_mark`, `lab_label`, `lab_send`, `lab_run_id`) moved from `run-l3.sh` to `guest/lib.sh` unchanged;
`run-l3.sh` and `run-proxy.sh` use them from there. `connect_with` and `disconnect` of `run-proxy.sh` are those of
`run-l3.sh`. A window is labelled by the function that opened its session, so the functions that open one are named
after their windows.

| Label | Scenarios | Opens | Closes | Expectation | From |
| --- | --- | --- | --- | --- | --- |
| `proxy_open` | `proxy.through`, `proxy.around-open`, `proxy.loopback-only` | `connect_with request-proxy.json` | the `disconnect` at the start of `busy` | **EXPECTED**: one TCP to `203.0.113.2:443` | the one `direct_https` of `proxy.around-open`; the curl through the proxy is the engine's connection to the node (`tunnel`) |
| none | `proxy.port-busy` | (no session: `cli connect` must fail with the port taken) | | | |
| `strict` | `strict.through`, `strict.around-blocked`, `strict.first-phase`, `strict.engine-killed`, `strict.disconnect` | `connect_with request-proxy-strict.json` | the `disconnect` of `gone`, before its `direct_https` | `NONE` | three `direct_https` dropped in the guest |
| `mode_change` | `mode.change` | `connect_with request-kill-switch.json` | the `disconnect` inside the `connect_with` of `share` | `NONE` | two `direct_https` dropped in the guest |
| `share` | `share.listens`, `share.peer-refused` | `connect_with request-proxy-share.json` | the `connect_with` of `share_off` | `NONE` | the request to the proxy on `192.168.77.2` stays in the machine; the peer is behind a veth |
| `share_off` | `share.off` | `connect_with request-proxy.json` | the `disconnect` at the end of `scenario_share` | `NONE` | nothing is sent |
| `lockdown_share` | `lockdown.share-closed`, `lockdown.share-open`, `lockdown.off` | `lab_mark open` at the start of the function, before the Lockdown unit and `lockdown on --lan off` | `lab_mark close` after `lockdown off` and `! table_present` | `NONE` | one `direct_https`, dropped by Lockdown |
| `stopped` | `stop.removes-table` | `connect_with request-proxy-strict.json` | `lab_mark close` after `systemctl stop` and `! table_present`, before `direct_https` (rule of 7c1) | `NONE` | nothing is sent inside |
| none | `preflight.*`, `install.service`, `desktop.*` | | | | `desktop.*` only write files (as on Hyper-V, there is no KDE session) |

Every closing marker waits for the table `inet rosetun` to be gone (`lab_mark`), so no window closes before the
protection is removed, and no direct request meant for after a session comes before its close. A run where every
scenario passed has these seven windows, one of each label (`WINDOWS_PER_LABEL`).

**Under Lockdown no marker goes out** (the table is there all the time). So `lockdown_share` is one coarse window:
the restart of the service with the Lockdown unit, Lockdown without Local network and its session, the `disconnect`,
Lockdown with Local network and its session, the `disconnect` and `lockdown off`. A leak anywhere in it contradicts all
three scenarios, and which one leaked is not told. Likewise `opened` connects inside that window (its markers find the
table and do nothing). If Lockdown did not go on, `opened` would open a window of its own, of a label no table names,
where anything is a leak.

### The group

All 27 scenarios but the 20 `two-hop.*` (SKIP "UNRUN", as in L3): the five `preflight.*`, `install.service`, the
`proxy.*`, `strict.*`, `mode.change`, the three `share.*`, the three `lockdown.*`, the four `desktop.*` and
`stop.removes-table`. `share.listens` and `lockdown.share-open` are in it thanks to the private address. The tables
are in `proxy_tables.py`; `l3_summary.py` judges either suite with the same code (`tables_for`), and the L3 tables
and their results did not change. The exit codes are those of stage 7b2b and 7e; the summary schema is
`rosetun.matrix.proxy-summary.v1` with the same fields. `LEAK_OUTSIDE_THE_GROUP_FAILS` is true, and the fixtures
required are those of L3 (`node`, `https` direct and through the node, `dns`, `doh`: the helper's DNS check at
connect goes through the engine's DNS, whose server is the DoH target, in the proxy mode too). `--diagnostic` is
for L3 only.

What is derived, not seen: that the engine in the proxy mode without the kill switch (`proxy_open`, `share`,
`share_off`) sends nothing past the node but what the script asks for. If the first runs show more (a DNS query of
the engine, say), the windows say `DETECTED` and the expectation is to be discussed, not widened by guess.

### Control

`run linux-proxy --lab --control stop-helper`: right after `strict.through` passed, in the window `strict`,
`run-proxy.sh` stops the service and makes one `direct_https` (`control_stop_helper`, the same as in L3). The
scenarios after it may fail. Exit 0 only when the window `strict` is `DETECTED` with a TCP flow from the test
machine to `203.0.113.2:443` that the target answered, `strict.through` is `DISAGREE`, an ordinary run would have
exited 1 and both machines completed. Without `LAB_CONTROL` the script does what it did.

### What to reinstall

- The test image: `guest/stage-l2.py` (the profile `proxy`), then its descriptor in the configurations. The lab image
  does not change: `lab-entry.py` and `lab_protocol.py` are as in stage 7e.
- The content directories: `guest/lib.sh` and `guest/start.sh` changed, and every package compares them byte for byte
  with the checkout, so the L2, L3 and Proxy content directories all take the new copies (L3 also the new
  `guest/run-l3.sh`). The Proxy content directory is new: `build-artifacts.sh --proxy`, the Linux `sing-box`, the
  three units of `packaging/linux/`, `guest/run-proxy.sh` and `scenarios-proxy.tsv`.
- The Hyper-V path takes the new `run-proxy.sh`, `run-l3.sh`, `lib.sh` and `start.sh` only when its owner does; without
  `LAB_MARKER_ADDRESS` none of them sends a marker or adds an address.

### Qualification

Each command in its own run on the clean checkpoint. Stop at the first unexpected result and send back the summaries
and the retained artifacts.

1. Install `stage-l2.py` in the test image and update its descriptor; prepare the Proxy content directory; copy the new
   `lib.sh`, `start.sh` and `run-l3.sh` into the L2 and L3 content directories.
2. `run linux-proxy --config <proxy.toml>` without the lab (`--dry-run` first): 4 PASS, `preflight.baseline` FAIL (no
   route to `203.0.113.2`), 20 SKIP, 22 ERROR "not run", `completion` true, exit 1.
3. `run linux-proxy --lab --config <proxy-lab.toml>`, twice in a row: the group 27 of 27 PASS, the cross-check `AGREE`
   or `NOT_APPLICABLE` only, seven windows, `proxy_open` `EXPECTED` and the other six `NONE`, `lab.window_counts` all
   `as_expected`, `group.outside_windows` empty, no `findings`, exit 0 both times. The cleanup actions name the
   removal of `192.168.77.2`. Send back the `direct` flows of `proxy_open`, `share` and `share_off` whatever they are.
4. `run linux-proxy --lab --control stop-helper --config <proxy-lab.toml>`: exit 0, `control_result.met` true.
5. `run linux-l3 --lab --config <l3-lab.toml>` once: as in stage 7e (40 of 40, exit 0); L3 is not broken.
6. `run linux-l2 --config <l2.toml>`, then `runs --state-directory <state>`: every run `completion_verified`.

## Stage 8b: Linux L5 in the lab

`run linux-l5` delivers the L5 package (the real `.deb` installed, upgraded under the kill switch and under Lockdown,
removed and purged) as `run linux-l3` delivers L3, and `run linux-l5 --lab` runs `run-l5.sh` inside the lab of stage
7b2b on a test image of its own. Nothing is accepted: the release gate stays false and the security invariants stay
**UNVERIFIED**. No L5 run has been through the lab yet: every count below comes from `run-l5.sh` alone.

### Profile and the package class

- The stage profile `l5` (`PROFILES` in `linux_l2.py`, the importer `guest/stage-l2.py`) is exactly
  `L5_START_REQUIRED` of `guest/start.sh`: the sources with `guest/run-l5.sh` and `scenarios-l5.tsv`, the two packages
  `rosetun-old.deb` and `rosetun-new.deb` that `build-artifacts.sh --deb` makes of one commit (both recorded in
  `provenance.json`, `"stage": "l5"`, and checked against it), and three generated requests. No ELF binary and no
  `sing-box`: the packages bring the programs, the units and the engines. Its evidence goes to `linux-l5/`, the
  service's journal included.
- A new file class, **package**: a file of `Profile.packages` must start with the magic of an ar archive
  (`!<arch>\n`), is at most 128 MiB (`PACKAGE_LIMIT`; ELF stays at 512 MiB, text at 256 KiB), is hashed in the media
  manifest like every other file and is never opened beyond its first bytes on the controller. The importer in the
  image checks the same bound and, after the copy, the magic again; packages are installed with mode `0644`.
- The requests are `request-kill-switch.json`, `request-lan.json` and `request-dns-lock.json` of the L3 generator,
  byte for byte (`l3_requests.render_l5`; a test pins their digests). `run-l5.sh` itself only uses the first.
- `job.env` takes `LAB_MARKER_ADDRESS` and `LAB_CONTROL` for `l5` as for `l3` and `proxy` (the importer, `start.sh`,
  `validate_env` and `run-l5.sh`). The Hyper-V path writes neither, and `start.sh` reads them only as optional keys.
- The configuration is `rosetun.matrix.execution.v2` (without the lab) or `v3` (with it) with `suite = "linux-l5"`
  and the `[l3]` table **without** `sing_box_sha256`: the engines come inside the packages, which `provenance.json`
  vouches for. A `sing_box_sha256` there is refused, as a package with an engine hash is. Start from the L3 examples,
  change the suite and delete that line. `timeouts.job = 900` is enough (the estimate is 4 to 6 minutes).

### The L5 test image

A separate image (owner, 2026-11-16), made from the test image **v5k** (no sshd, no IPv6 router: L5 uses neither):

```sh
python tools/vm/linux/prepare-l3-image.py /srv/test-v5k.qcow2 /srv/test-l5.qcow2 \
  --source-sha256 V5K_SHA256 --descriptor /srv/test-l5.image.json \
  --deps-debs /srv/l5-debs --check-package /srv/content-l5/artifacts/rosetun-new.deb \
  --check-package /srv/content-l5/artifacts/rosetun-old.deb
```

- `--deps-debs DIR` holds only `.deb` files (no link, no other entry, no `rosetun_*` package). They are installed
  offline with `dpkg -i` under a `policy-rc.d` that starts nothing, and `dpkg --audit` must print nothing; the
  descriptor gets `l5_dependencies` with every file's hash. It goes neither with `--sshd` nor with `--ipv6-router`.
  The network file gets the same change as for L3 (the legacy probe route goes).
- **What the package needs.** `Depends:` of the package is written by `installer/linux/build-deb.sh`:
  `nftables, systemd, init-system-helpers (>= 1.65.2)`, the shared libraries `dpkg-shlibdeps` finds in
  `rosetun-helper-privileged`, `rosetun-gui` and `rosetun` at build time, and `GUI_LIBRARIES`: `libegl1`, `libgl1`,
  `libwayland-client0`, `libwayland-egl1`, `libx11-6`, `libx11-xcb1`, `libxcb1`, `libxcursor1`, `libxi6`,
  `libxkbcommon-x11-0`, `libxkbcommon0`, `libxrender1` (each with the floor in the script). `install.desktop` needs
  `desktop-file-utils` too, which the package only recommends. These sixteen names (`L5_DEPENDS`, compared with the
  build script by a test) must be installed in the image, or it is refused. The shared libraries are known only from
  a built package: with `--check-package` the tool reads the control file of each package (with the standard library,
  nothing is unpacked or installed) and refuses an image where any group of its `Pre-Depends` and `Depends` is not met
  at its version (dpkg's version order, `Provides` counted). The directory must hold the transitive closure of what
  v5k lacks; nothing is downloaded.
- **Quiet.** The unit directories are read before and after the installation. Any unit a dependency enables (a link
  in a `.wants`, `.requires` or `.upholds` folder of `/etc/systemd/system` or `/usr/lib/systemd/system`) is refused
  unless `L5_ALLOWED_UNITS` names it; it names none. A mask of v5k that is gone is refused too. New masks and aliases
  are listed in the output.
- **No rosetun.** The tool refuses a `rosetun` package among the files and in the package database of the image, and
  `preflight.no-foreign-service` of `run-l5.sh` refuses any rosetun unit, file or package on the machine.
- After the image is built, install the importer `stage-l2.py` of this commit in it (as for the other test images)
  and copy the fields of the descriptor into `[image]` except `l5_dependencies`.
- v5k carries the lab helper of its time. A run inside the lab needs the helper of this commit in the test image too:
  install `linux/guest/lab-entry.py` and `matrix/lab_protocol.py` together (as in stage 7e) along with `stage-l2.py`.
  The qualification did that before `--deps-debs`, on a copy of v5k; either order gives the same files.

### Windows

`connect_with` and `disconnect` of `run-l5.sh` are those of `run-l3.sh` (markers from `lib.sh`); the functions that
open a window are named after it.

| Label | Scenarios | Opens | Closes | Expectation |
| --- | --- | --- | --- | --- |
| none | `preflight.*`, `install.*`, `upgrade.watch` | | | the direct request of `upgrade.watch` comes before any window |
| `upgrade_ks` | `upgrade.kill-switch-no-leak`, `upgrade.kill-switch-hold`, `upgrade.reconnect` | `connect_with request-kill-switch.json` | the `disconnect` of `do_reconnect`, once the table is gone, before its `direct_https` | `NONE`; the engine's connections to the node are `tunnel`, many of them while the prober runs, their number not fixed |
| `upgrade_lockdown` | `upgrade.lockdown`, `remove.refused`, `remove.lockdown` | `lab_mark open` after the downgrade, right before `lockdown on --lan on` | `lab_mark close` in `do_remove` after `dpkg -r` and `table_present` false, before `direct_https` | `NONE` |
| none | `purge.state` | | | |

Between the two connects of `upgrade_ks` the hold keeps the table, so no marker goes and the window is one, as
`upgraded` in L3. Under Lockdown no marker goes either, so `upgrade_lockdown` is one coarse window. `upgrade_lockdown`
begins with `lab_mark close`, which closes a window `upgrade_ks` left open when one of its scenarios failed before the
disconnect (nothing is sent otherwise). Every close waits for the table to be gone. A clean run has these two
windows, one of each label. The group is all 17 scenarios; the summary schema is `rosetun.matrix.l5-summary.v1`
(tables in `l5_tables.py`, judged by `l3_summary.py` as L3 and Proxy are, whose tables did not change).

### The counter and its twin

`upgrade.kill-switch-no-leak` counts, in the table `inet rosetun-l5-watch` (postrouting, priority 300), every packet
that leaves the physical interface for the probe address while dpkg upgrades the package; it passes only with none.
The observer of `upgrade_ks` is its twin, and `group.counter` of the summary sets them side by side: `script_count`
(0 for a pass, the number at the head of the reason for a failure, else unknown), `observer_direct_frames` (the
unexpected frames of the window) and `observer_frames_to_address` (those sent to `203.0.113.2`). `agreement` is
`AGREE` when both saw some or both none, `DISAGREE` when one did and the other did not (a finding,
`counter-contradicted-by-window`, exit 1), `UNKNOWN` when a number is missing. The observer's window is wider than
the counter's span (it also holds the hold and the reconnect), so a direct frame there that the counter could not
see is a disagreement too.

### Control

`run linux-l5 --lab --control stop-helper`: right after `upgrade.kill-switch-no-leak` passed, inside `upgrade_ks`,
`run-l5.sh` stops the service and makes one `direct_https` (`control_stop_helper`, as in L3). Without Lockdown the
hold an upgrade leaves ends with an ordinary stop (the routing crate's Linux backend), so the request leaves. The
scenarios after it may fail. Exit 0 only when `upgrade_ks` is `DETECTED` with a TCP flow to `203.0.113.2:443` that
the target answered, `upgrade.kill-switch-no-leak` is `DISAGREE` (and so is the counter), an ordinary run would have
exited 1 and both machines completed.

### Limits

The lab's limits are enough for L5 and did not change: a job of at most 1800 s in the lab (`timeouts.job = 900`
suggested), the capture of 60 MiB on the evidence disk (1 to 3 MB expected, to be measured), up to 100 windows (two).
The media holds the two packages (about 41 MB each) within `TOTAL_LIMIT`.

### What to reinstall or build

- The L5 test image (above), with the new `stage-l2.py`; the L3 and Proxy test image takes the new `stage-l2.py` too.
  The lab image does not change.
- The content directories: `guest/start.sh` changed, so the L2, L3 and Proxy content directories take the new copy.
  The L5 content directory is new: `build-artifacts.sh --deb` (both packages and `provenance.json`), `guest/launch.sh`,
  `start.sh`, `lib.sh`, `run-l5.sh` and `scenarios-l5.tsv`; never a request or `sing-box`.
- The Hyper-V path takes the new `run-l5.sh` and `start.sh` only when its owner does; without `LAB_MARKER_ADDRESS`
  and `LAB_CONTROL` neither sends a marker nor stops anything.

### Qualification

Each command in its own run. Stop at the first unexpected result and send back the summaries and the retained
artifacts.

1. Build the L5 image as above (with `--check-package` for both packages) and install `stage-l2.py` in it and in the
   L3 test image; update the descriptors; prepare the L5 content directory; copy the new `start.sh` into the L2, L3
   and Proxy content directories.
2. `run linux-l5 --config <l5.toml>` without the lab (`--dry-run` first): 4 PASS, `preflight.baseline` FAIL (no route
   to `203.0.113.2`), 12 ERROR "not run", `completion` true, exit 1.
3. `run linux-l5 --lab --config <l5-lab.toml>`, twice in a row: the group 17 of 17 PASS, the cross-check `AGREE` or
   `NOT_APPLICABLE` only, two windows, both `NONE`, `group.counter.agreement` `AGREE` with `script_count` 0 and
   `observer_direct_frames` 0, `lab.window_counts` all `as_expected`, no `findings`, exit 0. Write down the size of
   `capture.pcap` (`evidence.disk.pcap_bytes`) and the number of `tunnel` frames of `upgrade_ks`.
4. `run linux-l5 --lab --control stop-helper --config <l5-lab.toml>`: exit 0, `control_result.met` true.
5. `run linux-l3 --lab --config <l3-lab.toml>` and `run linux-proxy --lab --config <proxy-lab.toml>` once each: as in
   stages 7e and 8a; neither is broken.
6. `run linux-l2 --config <l2.toml>`, then `runs --state-directory <state>`: every run `completion_verified`.

## Stage 8c: planned guest reboots in the controller

The controller can now carry a job through a reboot of the guest that the job asks for, and it waits for a job by reading
its status instead of sleeping. Nothing here runs Linux L4: that is stage 8d. Nothing is accepted: the release gate stays
false and the security invariants stay **UNVERIFIED**. No run has been through a real reboot yet; the offline tests use a
fake QEMU on named sockets and scripted agents.

### Events and the chain of boots

- QEMU says a guest reset as a QMP `RESET` event with `guest: true`. Events are read only while the controller looks, so
  `Vm.watch_resets()` (the wait calls it every `WATCH_SECONDS` = 2 seconds, whatever the interval of its looks at the
  status file, and every guest observation calls it first) lets the loop run for a quarter of a second. It sends no
  command and spends no QMP call; each event costs one of the 128 `qmp_events`. The step is short because of what a late
  read costs: Linux L4 reboots its guest again 27 seconds after the first reset, and a controller that read the queue
  only every 151 seconds found both RESETs at once and could take one boot of two (the qualification of 8d). A reset is
  read within two seconds and the new session is taken at once, in the same step.
- A guest reset within the plan is **registered**: the journal row `guest-reset-observed` (result `1-of-2`, `2-of-2`),
  the run-state step `guest-reset-N` at intent (before anything else), the current agent session invalidated, and the
  VM `reset_pending` with `reset_kind = guest`. The plan is `planned_reboots` of the suite (`config.PLANNED_REBOOTS`:
  `linux-reboot-smoke` 1, `linux-l4` 2, every other suite 0; at most 2, `run_state.MAX_PLANNED_REBOOTS`).
- **One reboot is often several RESETs.** Linux tries more than one way to reset a machine in a row (the ACPI reset
  register, port 0xCF9, the keyboard controller), and QEMU reports each with `guest: true`; on QEMU 10.0 one
  `systemctl reboot` gave two, 67 ms apart. `Qmp.take_resets()` hands every RESET over as a `ResetEvent` (`guest`, QEMU's
  `reason` field when it has one, and QEMU's own timestamp in microseconds, each `None` when absent or malformed), and the
  rows say what was seen. A guest RESET that comes **while the reboot is unconfirmed** (registered, new boot ID not yet
  taken) and is stamped within `RESET_MERGE_US` = **1 second** after the *first* RESET of that reboot is part of it: the
  row `guest-reset-coalesced` (`1-of-1 merged=1 +67ms reason=... qemu=SECONDS.MICROSECONDS`), no step, nothing spent of the
  plan. The window is by QEMU's time, so a late look does not change it, and it is counted from the first RESET, not from
  the last. Why one second: the attempts of a reboot are tens of milliseconds apart, while no guest gets through firmware,
  bootloader and kernel to a userspace that answers the agent in that time. At most `RESET_MERGE_LIMIT` = **4** RESETs
  are merged into one reboot (five in all, about the number of ways Linux has); a fifth merge is `guest-reset-merge-limit`.
  A RESET after the new boot ID was taken is a reboot of its own and counts against the plan as below. A RESET with no
  time, or one after the window, **while the boot of the reboot pending is not yet taken**, is a reboot whose boot nobody
  observed: `guest-reboot-unobserved`, below.
- Every other reset is an **error that ends the run** (`LifecycleError`, exit 2, the VM closed hard), and no later boot ID
  is taken: `unplanned-guest-reset` (more guest resets than planned, or any when none is), `host-reset-outside-reset`
  (a `RESET` without `guest: true` that `Vm.reset()` did not cause), `guest-reset-before-first-boot`,
  `guest-reset-merge-limit` (see above), and `guest-reboot-unobserved` (a guest RESET outside the merge window while the
  boot of the earlier reboot is unconfirmed: the chain would lack a boot ID, whatever the plan still allows; before, such
  a RESET was registered as the next reboot and the earlier boot was lost). The row `guest-reset-observed` says which,
  with the event's reason and time, and the refusal is sticky. It takes one journal row, as the others do.
- After a registered reset `await_rebooted_guest` gives the new session: the first try is `recover_guest` (the one
  recovery the reset earns), then up to eleven more tries, 5 seconds apart (`RESET_RETRY_SECONDS`; 10 seconds at most for a
  try, 180 seconds in all, as the eight tries 15 seconds apart covered 200), each a new session that spends an
  observation and no recovery. A boot ID is taken only when it **differs** from the last of the chain: the same one is
  `guest-reset-boot-id-unchanged` (no reset happened), one already in the chain is `boot-id-repeated`, and a changed one
  with no RESET behind it is `boot-id-changed-without-reset`. Each refusal is the result of the observation row.
- The chain is `Vm.boot_chain`, kept in `run-state.json` as `boot_chain` (the first element is the boot the job was
  submitted on; `identities.boot_id` is always its last element, so summaries read as before). `RunState.update` of
  `identities.boot_id` starts it; later boots join only through `extend_boot_chain`, never twice. A file written before
  the chain existed is read with its one boot.
- The job takes the chain from the controller, never from the guest: `submit` needs the chain to be exactly the first
  boot, `_begin` and `_fresh_boot` check `vm.last_boot_id` and the guest's reading against its last element, and the
  collection needs `status.boot_id` to be that element and the report's `boot_ids` to equal the chain element by
  element, or the job is refused (`l2-result-UNVERIFIED`, with the row `l2-boot-chain-mismatch` in `job-evidence.jsonl`
  naming both lists). `report.assess` still judges the guest's list against the plan.
- `attach` takes the chain from the run state and the last boot ID from its end. A controller that died after it saw a
  reset and before it confirmed the boot left `guest-reset-N` at intent: the attached controller starts with the reset
  pending and waits for the boot as the first one would (`attach-guest` then uses `await_rebooted_guest`); the count of
  registered resets is the number of those intents. The merge window goes on from the first RESET's time, which the
  controller keeps in the run state's `collected` section (`guest_reset_N_us`, QEMU's microseconds, and
  `guest_reset_N_merged`, the count so far; no new schema version) before it writes the intent of `guest-reset-N`. A run
  state without them (a reset that carried no time) merges nothing. The budgets continue from the file, so the recoveries of the reboot
  stay spent. A lab run is never attached, as before: after the death of its controller, `recover --close`.

### Budgets (the numbers)

| | before | with `planned_reboots` = n |
|---|---|---|
| `qga_recoveries` | 4 | 4 + n (one per reboot; the file allows 6 at most) |
| journal rows of the lifecycle | 110 ordinary + 18 reserve | the same; 2 per reboot, 6 at most (up to 4 merged RESETs) |
| `qmp_calls` | 128 | the same; a reboot sends none |
| `qmp_events` | 128 | the same; one per RESET, so 5 per reboot at most |
| `qga_observations` | 32 | the same (kept; see below); 1 per reboot when its first try succeeds, 12 at most |
| `job_calls` | 112 | the same; 3 per look of the wait |

- **Journal rows.** One reboot takes two rows of the ordinary journal: `guest-reset-observed` and
  `boot-chain-extended` (a refused reset takes one), and each RESET merged into it one more, `guest-reset-coalesced`: 6
  rows for a reboot at most. An ordinary run is 10 rows (start 2, resume 3, close 5); with two planned reboots it is 14,
  and with two reboots of four merged RESETs each 22, of the 110 ordinary rows, and the teardown reserve of 18 is
  untouched (`test_two_planned_resets_fit_in_the_ordinary_rows...`, `CoalescedBudgetTests`). A merge reserves the row of
  the merge and the one that will confirm the boot. A reset that would take the ordinary rows over their limit is
  refused with `lifecycle-journal-limit` and leaves no trace.
- **Run-state steps.** A reboot writes `guest-reset-N` twice (intent, done) into the 256 transitions, merged RESETs
  none (each writes the run state's `collected` section once: at most 4 + 1 writes a reboot).
- **QGA.** The rule is 4 + planned: `import-refresh` takes one, an uncertain submit or collection at most two more, each
  reboot one; the retries of a slow boot cost observations only.
- **Linux L4 (two reboots), recounted for the prompt wait.** Recoveries: 4 + 2 = 6, as before (the wait reads the reset at
  once but still takes one recovery per reboot). Observations, 32 as before: the first boot 1, each recovery 1 (6 in all,
  two of them the reboots' first tries), and the retries of a boot that is not up yet, at most 11 for each reboot, so
  1 + 6 + 2 x 11 = 29 at the very worst; a guest that answers within 15 seconds costs 1 or 2 for a reboot. A prompt first
  try finds the guest still booting more often than the late one did, which is why the retries are closer together and
  the cap of tries was raised from 8 to 12; the number of the budget is not changed because the worst case still fits
  (the retries of the first boot, up to 20, are not counted: that boot comes before everything above). Journal rows: two
  reboots are 14 of the 110 ordinary rows, 22 at most with merged RESETs, and `guest-reboot-unobserved` is one row more
  (the refused reset takes one); reading QMP every two seconds writes nothing unless it finds a RESET, so a run with no
  reboot has the journal it had.

### Waiting by reading the status

- `LinuxL2Job.wait(seconds, sleep, clock)` replaces the fixed `job + 125` of `run`, of `attach` and of the lab run
  (`l3_lab.py`); the bound is the same, so a run with no reboots waits no longer than before. The wait looks at
  `status.json` (open, read, close: 3 job calls) every `max(30, seconds / 16)` seconds: 46 seconds for the usual 725,
  never more than 16 looks. The calls are the reason: of the 112 of a job, the submission takes 6 and each of the two
  collections at most 28, so 16 looks (48) fit and the looking stops at 52 spent, the rest being waited out as a
  fixed wait always was. Nothing a look reads is saved except a row `l2-poll` when the state or the boot changes.
- A look that finds `state: finished` for this run on the boot the controller confirmed last ends the wait at once;
  `collect` follows and does what it always did (`job_polls` is spent by collections only, never by looks).
- QMP is read **every 2 seconds** (`WATCH_SECONDS`), and the looks at the status file keep their interval and their
  calls (3 each, 16 at most, stopping at 52 spent). A planned reset is recovered in the step that read it: the session is
  new and the boot ID is taken before the next look, which no longer has to wait for the interval. The look that failed
  because the agent stopped before the machine reset is explained by that: the reset is read at the next step, and the
  old extra 30 seconds of grace are gone with the reason for them. The job's two reboots 27 seconds apart are both taken.
- A look that fails (a lost session, an invalid reply) ends the looking, not the wait: the reset that explains it is
  recovered inside the wait when a planned one turns up, and the looking starts again. Any other failure leaves the old
  branch: the wait runs out, `collect`, `collect-recovery`, `collect-final`. An unplanned reset, and a second one before
  the boot of the first is taken (`guest-reboot-unobserved`), end the wait with an error and no collection.
- The job's own deadline, the `wait_until` of the run state and the lab capture (`DURATION_MAX`) are as they were.

### The smoke job

`run linux-reboot-smoke --config <reboot-smoke.toml>` (`--dry-run` first; `execution-reboot-smoke.example.toml`, schema
`execution.v2` with `suite = "linux-reboot-smoke"`, no `[l3]` table, no lab, `timeouts.job = 300`) delivers the profile
`reboot-smoke` and runs `guest/run-reboot-smoke.sh`: it records the first boot, checks the identity, installs and enables
its own unit `rosetun-l2-resume.service` (the pattern of `run-l4.sh`), writes `rebooting` and runs `systemctl reboot`.
After the boot the unit appends the second boot ID, checks that it differs and that the unit is what runs, removes
itself and closes the report with `boot_ids` of two. Its three scenarios (`scenarios-reboot-smoke.tsv`) are
`preflight.identity`, `reboot.planned` and `reboot.continued`, all required. There is no Rosetun service, program or
network change; the package is the guest scripts, the catalog and `provenance.json` (`"stage": "reboot-smoke"`, no
artifacts), which `build-artifacts.sh --reboot-smoke OUTPUT_DIR` makes (it still needs the pinned toolchain for the
record of the build).

- `start.sh` knows the stage (`reboot_smoke_start_path_allowed`, `REBOOT_SMOKE_START_REQUIRED`: 7 files) and reads the
  keys of an L2 `job.env`. `stage-l2.py` has the profile, so the importer takes it.
- The content directory is `guest/launch.sh`, `start.sh`, `lib.sh`, `run-reboot-smoke.sh`, `scenarios-reboot-smoke.tsv`
  and `artifacts/provenance.json`, byte for byte of the checkout.
- Expected result: 3 PASS, `boot_chain` of two in the summary's `execution`, `qga_recoveries` 2 in `run-state.json`
  (one for the import, one for the reboot), `identities.boot_id` the second boot, `completion` true, exit 0. Killed after
  the reboot, `attach` finishes it.

### What to reinstall or build

- The test image takes the new `stage-l2.py` (the importer knows the profile); the image itself does not change. The
  smoke needs nothing beyond systemd and the agent.
- The content directories of L2, L3, Proxy and L5 take the new `guest/start.sh` (the stage test and the key list changed).
  The smoke content directory is new, as above.
- Nothing on the Hyper-V path changes.

### Qualification

Each command in its own run. Stop at the first unexpected result and send back the summaries, `run-state.json`,
`lifecycle.jsonl` and `qga-observations.jsonl` of the retained runs.

1. Install `stage-l2.py` in the test image, prepare the smoke content directory, copy the new `start.sh` into the other
   content directories.
2. `run linux-l2 --config <l2.toml>` (the wait by reading must give the same 34 results; note when it ended against the
   old 1025 seconds): exit 0, `completion_verified`.
3. `run linux-reboot-smoke --config <reboot-smoke.toml> --dry-run`, then the run: 3 PASS, exit 0. In `lifecycle.jsonl`
   the rows `guest-reset-observed` (`1-of-1`) and `boot-chain-extended` (`2`); in `run-state.json` `boot_chain` of two,
   the steps `guest-reset-1` intent and done; in `qga-observations.jsonl` the recovery with `reason: guest-reset` and
   `new_boot_confirmed: true`. Write down how many tries the new boot took and how long the reboot lasted.
4. The same run killed (`kill -9` of the controller) after the reboot and again before it: `attach --state-directory ...
   --run-id ...`; the run ends `completed`, `attached: true`, and `qga_recoveries` was not set back to 0.
5. `runs --state-directory <state>`: every run `completion_verified`.
6. The lab L3 once (`run linux-l3 --lab --config <l3-lab.toml>`): the same results and windows as in stage 7e; the wait
   by reading must not change the capture or its windows.

## Stage 8d: Linux L4 in the lab

`run linux-l4` delivers the L4 job (the real service under Lockdown, ending in two reboots of the guest) as a stage
profile, and `run linux-l4 --lab` runs `run-l4.sh` inside the lab of stage 7b2b on a test image of its own, with the
lab machine polling the guest over SSH and the controller carrying the job through its reboots (stage 8c). Nothing is
accepted: the release gate stays false and the security invariants stay **UNVERIFIED**. No L4 run has been through the
lab yet: every count below comes from `run-l4.sh` alone, and the runs of the qualification below are what confirms it.
The Hyper-V L4 stays the owner's: without `LAB_MARKER_ADDRESS`, `LAB_CONTROL` and `LAB_POLLER_KEY` in `job.env`
`run-l4.sh` sends nothing, notes nothing and installs no key (`Test-LinuxHarness.ps1` and `selftest-lib.sh` pin that).

### Profile and delivery

- The stage profile `l4` (`PROFILES` in `linux_l2.py`, the importer `guest/stage-l2.py`) is exactly `L4_START_REQUIRED`
  of `guest/start.sh`: the sources with `guest/run-l4.sh` and `scenarios-l4.tsv`, the three programs of the L3 job
  (`rosetun-helper-privileged`, `rosetun`, `sing-box`), `rosetun-helper.service`, `rosetun-engine.rules`,
  `rosetun-lockdown.service` (all three from the checkout, compared byte for byte) and three requests, which are
  `request-kill-switch.json`, `request-lan.json` and `request-dns-lock.json` of the L3 generator byte for byte
  (`l3_requests.render_l4`). Its evidence goes to `linux-l4/`, the service's journal included.
- `build-artifacts.sh --l4 OUTPUT_DIR` builds the same two programs as `--l3` and records them as `"stage": "l4"` in
  `provenance.json`, which the profile requires. The Hyper-V path keeps `--l3`.
- `job.env` takes the lab keys last, in this order: `LAB_MARKER_ADDRESS`, `LAB_CONTROL`, `LAB_POLLER_KEY` (the last for
  L4 alone, and only with the marker address). `start.sh`, `validate_env`, `stage-l2.py` and `run-l4.sh` agree on the
  shape of the key: the base64 blob of an `ssh-ed25519` public key (68 characters, 51 bytes, checked in all four).
  The Hyper-V path writes none of them.
- The configuration is `rosetun.matrix.execution.v2` (without the lab) or `v3` (with it) with `suite = "linux-l4"` and
  the `[l3]` table **with** `sing_box_sha256` (the engine is delivered by the owner, as for L3). The examples are
  `execution-l4.example.toml` and `execution-l4-lab.example.toml`.

### The window and the expectations

One window, `lockdown` (the variant of the single coarse window): `run-l4.sh` opens it right before Lockdown goes on the
first time (`lockdown --lan off` of `turned_on`; the label is the name of that function) and closes it in `reset` of
`exit.reset-firewall`, once the table is gone and before its direct request. Under Lockdown no marker can leave the test
machine, so nothing divides the window: it holds `lockdown.direct-blocked` to `exit.reset-firewall` (19 scenarios), the
first reboot among them. The index and the label live in the guest's state directory, which survives the reboot, so the
close comes from the resume phase. `lockdown.denied`, the preflight, `install.service` and `reboot.without-record`
(after the second reboot, with no record the network is open and the direct request leaves) are outside any window. The
group is all 27 scenarios; the summary schema is `rosetun.matrix.l4-summary.v1` (tables in `l4_tables.py`, judged by
`l3_summary.py` as the other suites are).

What the window shows, counted from the code of the script (the numbers a test reads out of it):

| Flow of the test machine | Count | Where it comes from |
| --- | --- | --- |
| TCP to `203.0.113.2:443` | 4 | `scope_probe` of the scopes Lockdown permits: `gui_scope` (`rosetun-gui`), `cli_scope` (`rosetun-cli`), `after` (`rosetun-gui`, after the session), `killed` (`rosetun-cli`, after the restart): one HTTPS connection each |
| UDP to `203.0.113.53:53` | 4 | the same four probes: one TFTP datagram each (curl sends it twice from one socket when the answer is no TFTP: one flow by four-tuple) |
| none | 0 | `others` (`rosetun-other`) and `scope_closed` (`rosetun-gui` during a session) are refused in the guest, and so is every `direct_https`, `routed_https` and `user_direct_https` under Lockdown |
| `tunnel` | not counted | the connects of `lockdown.session`, `after`'s and `reboot.service-completes`: the engine's connections to the node |
| `inbound-poll` | any number | the poller's frames, below |
| `ipv6-dad` allowance | any number | the guest's kernel checking its own IPv6 addresses (neighbor solicitation from `::`) while the first reboot brings the interface up |

Neighbor discovery and MLD are infrastructure already. The allowance is the one the boot needs and nothing wider: an ARP
probe or announcement, should the network manager send one, would be a finding to look at, not to admit. The second boot
comes after the window closed, so its frames are only counted (`outside_window`). A flow beyond these counts is
`DETECTED` (exit 1), one fewer is `MISMATCH`, which contradicts the passes of the window. `REQUIRED_FIXTURES` are the
node, the HTTPS target and DoH: no scenario of L4 asks the plain resolver a question (its datagrams are TFTP), so it is not
required. Without a `lockdown` window or with a second one the run exits 2 (`window-count`).

### Reboots

`planned_reboots = 2` (`config.PLANNED_REBOOTS`), taken by the mechanism of stage 8c: the controller takes each guest
`RESET` from QMP, recovers the agent's session and takes a new boot ID, three boots in all. `group.boot_chain` of the
summary says `expected` 3 and `seen`; fewer or more than three cannot vouch for the run (`boot-chain:expected=3,seen=N`,
exit 2). Any other guest reset is an error that ends the run (`unplanned-guest-reset`, exit 2, no collection). The test
machine's `vm.planned_reboots` is set before it starts, as `run linux-l4` sets it. A lab run is never attached: after the
death of its controller, `recover --close`.

### The SSH poller

`inbound.lan-open` waits for a new SSH connection from the host node after the local network went on. In the lab the
host node is the lab machine (`192.0.2.1`), so the lab helper now has a poller: the `ssh` client logs in as `root` to
`192.0.2.2:22` every 10 seconds (`-b 192.0.2.1`, `ConnectTimeout=5`, killed after 15), from the moment the capture is ready
to the end of the run, and runs `true`. sshd's journal then holds the `Accepted publickey ... from 192.0.2.1` that the
script reads. Each attempt is a row of `poller.json` (time, result `accepted`, `failed`, `timeout` or `error`, exit code,
elapsed milliseconds; at most 256 rows, about 23 KB of the 32 KiB bound; an attempt past the 256th is `poller-log-limit`),
a file of the lab run, counted in the summary as `lab.poller`.

- **The key is one-time.** The controller makes a new Ed25519 pair for each run (`poller_key.py`: the public key by the
  reference construction of RFC 8032, which needs no `ssh-keygen` on the controller, and the private key in the OpenSSH
  format `ssh -i` reads; a test has `ssh-keygen -y` read it where one exists). The private key goes to the lab machine
  alone, in the `poller` block of the request that sets it up and of the one that finishes it, and is never written to the
  controller. On the lab machine the helper keeps only its hash in `claim.json` and `identity.json`, writes the key to
  `poller.key` (mode 0600, on the tmpfs) for the length of the capture and removes it. It is in no image, no summary and no
  report: the controller checks every summary for it and, if it ever finds it, replaces it and exits 2
  (`poller-key-redacted`). The command line of the lab helper holds it while the capture runs, as it holds the node's
  password. A fingerprint of the public key may be quoted; the key itself never.
- **Where the public half is installed** (decided here): `run-l4.sh` appends one line to `/root/.ssh/authorized_keys` before
  the install phase and removes exactly that line, and what it created, in its cleanup. The line is
  `restrict,command="/bin/true" ssh-ed25519 BLOB rosetun-lab-poller`: the key can run nothing but `true`, forward nothing and
  allocate no terminal. The alternative, a file of the package that the image copies, would add a file to `L4_START_REQUIRED`,
  which the Hyper-V path does not send; the value rides in `job.env`, the one file the controller already writes for the run,
  and the image holds no key at all. The cost is that `run-l4.sh` touches `/root/.ssh` on a lab run, which its cleanup
  undoes and its report says (`removed the poller's key`).
- **The observer.** The category `inbound-poll` (`lab_protocol.classify_windows(..., inbound_poll=...)`) is exactly: TCP
  from `192.0.2.1` to port 22 of `192.0.2.2`, between the two machines' MACs, whenever it is sent (a SYN nobody answers is
  the poller's own business), and the test machine's segments from port 22 back to a port the poller used, **from the moment
  its local network went on**. Any other frame of that pair, a reply before that moment or to another port, is an unexpected
  frame and a leak. The moment is the guest's note: `lockdown_lan_on` writes the epoch milliseconds to the state directory
  before it runs `lockdown on --lan on`, and cleanup says `lan-on-ms=N` in `cleanup.actions`. The two machines' clocks are
  the host's at boot and drift by a fraction of a second, so answers count from that moment less 2 seconds
  (`LAN_ON_SLACK_SECONDS`); a run that never says it admits no answer. The poller's frames are never part of a window's
  `flows`.
- **The test image** has sshd on `192.0.2.2:22` and `169.254.77.1:22` (below). The first is where the poller connects, the
  second the guest's end of the veth to the peer namespace (`inbound.closed`, `inbound.lan-link-local-closed`). That is a
  change of the contract of image v6, which never let sshd listen on the guest's own address, and it holds for the L4
  image only.
- **The lab image** needs `/usr/bin/ssh` (openssh-client, installed offline by its owner). The helper checks it as a
  root-owned regular file in `setup`, before it changes anything, and refuses with `poller-ssh-missing`.
- What the run cannot know is whether Lockdown's local network lets the own segment `192.0.2.0/24` in (it is no private
  range): the script looks for `iifname PHYS ip saddr ... accept` for its own segment, and if only private ranges get one,
  `inbound.lan-open` fails in the lab for that reason. The qualification shows it.

### The L4 test image (v7)

Made from the L3 test image with sshd and the IPv6 router (v6b, with the lab helper installed), by the same tool:

```sh
python tools/vm/linux/prepare-l3-image.py /srv/test-v6c.qcow2 /srv/test-l4.qcow2 \
  --source-sha256 V6C_SHA256 --descriptor /srv/test-l4.image.json --l4 --deps-debs /srv/l4-debs
```

- `--l4` needs `--deps-debs DIR` (only `.deb` files, no `rosetun_*`, installed offline with `dpkg -i` under a `policy-rc.d`
  that starts nothing, `dpkg --audit` silent) and goes with none of `--sshd`, `--sshd-debs`, `--ipv6-router`,
  `--check-package`. The directory holds the closure of `dbus-user-session`, `nftables` and `openssh-server` that v6c lacks.
- It adds `l4-lab-sshd.socket` (`ListenStream=192.0.2.2:22` and `169.254.77.1:22`, `FreeBind=yes`, `Accept=yes`) and
  `l4-lab-sshd@.service` (the lines of the packaged per-connection template), enabled in `sockets.target`, beside the v6
  socket, which stays. Neither name starts with `rosetun`, which `preflight.no-foreign-service` refuses.
- **Checked by reading** (a copy of the unit directories, `/var/lib/dpkg/status`, `/etc/ssh`, `/etc/nftables.conf`): the
  three packages installed and no `rosetun`; `/usr/lib/systemd/user/dbus.socket` there; `nftables.service` there and **not
  enabled** (the job enables it itself, after it looked at a boot without it); `/etc/nftables.conf` there with a line
  `flush ruleset` (it is never written: a package without it is refused); the v6 sshd check as it was; the L4 socket
  listening exactly on the two addresses, with `FreeBind` and `Accept=yes`, the template exactly the one this tool writes
  and without a drop-in; the installation adding that one link (`sockets.target.wants/l4-lab-sshd.socket`) and taking none
  away; no `policy-rc.d`, package directory or script left.
- **Quiet.** The unit links are read before and after the dependencies: any unit they enable is refused (`L4_ALLOWED_UNITS`
  names none), a lost mask is refused, new masks and aliases are listed.
- The descriptor gets `l4` with the packages' hashes, the installed versions, the sockets and the hash of
  `/etc/nftables.conf`; the output of v6c's other fields stays as it was. After the image is built, install the importer
  `stage-l2.py` of this commit in it and copy the fields of the descriptor into `[image]` except `l4`.

### Limits

`timeouts.job` is the time limit of **each** of the three phases (the guest's systemd limits each by it), so the budgets
come from `config.job_span` (a suite with `PHASES`; every other suite and the reboot smoke job keep their one phase):

| | One phase of 600 s | Where |
| --- | --- | --- |
| span of the job | 3 * 600 + 2 * 240 (`REBOOT_SECONDS`) = **2280 s** | `config.job_span` |
| the controller's wait | 2280 + 125 = **2405 s**, a look every 151 s, 16 looks at most | `config.wait_seconds`, `LinuxL2Job.wait` |
| job deadline, `deadlines.execution` | 2280 + 180 = **2460 s** (`execution` must equal it) | `linux_l2`, `execution.validate` |
| the lab's capture | 2280 + 300 = **2580 s** | `l3_lab.capture_seconds`, `CAPTURE_SLACK` |
| longest capture, `DURATION_MAX` | **2700 s** (was 2100) | `lab_protocol` |
| longest phase that fits | (2700 - 300 - 480) / 3 = **640 s** | `execution.validate_lab` |

A one-phase job keeps its limit, 1800 s, so that 1800 + 300 fits in 2700 with room. The estimate of a run is 10 to 15
minutes with three boots, far under the span. The other numbers:

- **Calls of the job:** 112, of which the submission takes 6, each of the two collections at most 28 and the wait's 16 looks
  3 each (48): 110.
- **Lifecycle journal:** 14 rows of the 110 ordinary ones with two reboots (22 with four merged RESETs each), the reserve of 18
  untouched; 2 rows per reboot.
- **QGA recoveries:** 6 (4 + 2): the import's, an uncertain submit's or collection's, and one per reboot. A boot that takes
  the retries costs observations only (8 per reboot at most of 32).
- **QMP events:** 5 per reboot at most, 10 of 128.
- **Capture:** under 1 MB expected (the poller's logins are 5 to 10 KB each, 60 to 100 of them in a run), 64 MiB on the
  evidence disk (60 MiB of capture). To be measured in the first run: write down `evidence.disk.pcap_bytes`.
- **Lab files:** six of at most 32 KiB each (`poller.json` the sixth); one window of at most 100.

### Control

`run linux-l4 --lab --control stop-helper`: with the service stopped for the first reboot, `run-l4.sh` turns the boot
unit of Lockdown off (`control_stop_helper`), so nothing closes the network early in the next boot, and right after that
boot, before any scenario runs, makes one direct request (`control_direct_request`). The network is open then and the
request reaches the target, so the window shows a **fifth** connection to the target where the script asks for four:
`DETECTED`. The point is chosen because the request is guaranteed to leave (no table before the helper starts, the resume
unit waits for `network-online.target`, and the request is the script's own `direct_https`) and the window cannot miss it
(it spans the first reboot). The scenario the control contradicts is `exit.denied-without-root`, the last one that passed
before the reboot (the scenarios after it, `reboot.*`, fail without the boot unit). Exit 0 only when `lockdown` is
`DETECTED` with a TCP flow to `203.0.113.2:443` that the target answered, that scenario is `DISAGREE`, an ordinary run
would have exited 1, and both machines completed.

### What to reinstall or build

- **The L4 test image** (above), from the L3 test image with sshd and the IPv6 router, with `stage-l2.py` of this
  commit (it knows the profile and the poller's key) and the lab helper of this commit; it needs the `.deb` closure
  directory for `--deps-debs`. The other test images need nothing: their importers do not change in what they accept.
- **The lab image, a new letter** (the owner names it): install `linux/guest/lab-entry.py` and `matrix/lab_protocol.py`
  together (the poller, the category and the longer capture are in both) and `openssh-client`. The lab image of L3, Proxy and
  L5 runs with the new helper as before: a run without a `poller` block starts no poller.
- **The L4 content directory** (new): `build-artifacts.sh --l4` (both programs and `provenance.json`), the owner's
  `sing-box`, `guest/launch.sh`, `start.sh`, `lib.sh`, `run-l4.sh`, `scenarios-l4.tsv` and the three units and the rules of
  `packaging/linux` as artifacts; never a request. The L2, L3, Proxy and L5 content directories take the new `start.sh`.
- The Hyper-V path takes the new `run-l4.sh` and `start.sh` only when its owner does.

### Qualification

Each command in its own run. Stop at the first unexpected result and send back the summaries and the retained
artifacts (`poller.json`, `run-state.json`, `lifecycle.jsonl` and the capture of each lab run).

1. Build the L4 image as above and install `stage-l2.py` and the lab helper in it; build the new lab image letter; prepare
   the L4 content directory; copy the new `start.sh` into the other content directories; update the descriptors.
2. `run linux-l4 --config <l4.toml>` without the lab (`--dry-run` first): the four first preflight checks PASS,
   `preflight.baseline` FAIL (no route to `203.0.113.2`), 22 ERROR "not run", no reboot (one boot in the chain),
   `completion` true, exit 1. The job needs `timeouts.job = 600` and `deadlines.execution = 2460`.
3. `run linux-l4 --lab --config <l4-lab.toml>`, twice in a row: the group 27 of 27 PASS, the cross-check `AGREE` or
   `NOT_APPLICABLE` only, one window `lockdown` with the verdict `EXPECTED` (4 TCP, 4 UDP), `lab.window_counts` as
   expected, `group.boot_chain` of three, `lab.poller` with an `accepted` attempt after the local network went on, no
   `findings`, no `unproven`, exit 0. Write down `evidence.disk.pcap_bytes`, the number of poll attempts and when the
   first one was accepted, how long each reboot took and the tries of its new boot. In the capture, any answer of the test
   machine to the poller before `lan-on-ms` less 2 s would show as an unexpected frame.
4. `run linux-l4 --lab --control stop-helper --config <l4-lab.toml>`: exit 0, `control_result.met` true.
5. `run linux-l3 --lab`, `run linux-proxy --lab` and `run linux-l5 --lab` once each, as in stages 7e, 8a and 8b: none is
   broken (the longer `DURATION_MAX` and the new helper are the changes they share).
6. `run linux-l2 --config <l2.toml>`, then `runs --state-directory <state>`: every run `completion_verified`.

Hyper-V L4 stays with the owner: the guest scripts are the ones of that matrix, with the wrappers above.

## Stage 7a: Linux L3 delivery without network

`run linux-l3` delivers the L3 package to one VM and runs the existing
`run-l3.sh` through the same launcher and QGA as `run linux-l2`. The VM keeps
`-nic none`; no lab VM is started and no network appears. The scripts, the
scenario catalog and the guest-side checks are the ones the Hyper-V matrix uses.
Nothing in them is changed.

**What it checks.** That the controller can prepare the six L3 requests, build
and verify the L3 package and ISO, import it once, start the job, collect the
report and assess it with the unchanged assessor, and that the VM completes
cleanly. This qualifies delivery, not scenarios.

**What it does not check.** Without a route to the probe address the baseline
cannot pass. `run-l3.sh` then marks every later scenario ERROR ("a preflight
check failed, nothing was installed"), so `install.service`, the kill switch, DNS
lock, crashes and every other protection scenario do not run. Nothing here says
anything about Linux firewall behavior. Security invariants stay `UNVERIFIED`
and the release gate stays false.

**Expected result on the stand:**

| Scenario | Result |
| --- | --- |
| `preflight.identity`, `preflight.accounts`, `preflight.no-foreign-service`, `preflight.tools` | PASS |
| `preflight.baseline` | FAIL, the reason names the missing route to `203.0.113.2` |
| the 20 `two-hop.*` (evidence class `not-run`, not required) | SKIP, "UNRUN: ..." |
| the other 35 (34 before stage 7c3 added `route.specific-bypass`) | ERROR, "not run" |

The report is complete (60 rows), the cleanup is PASS, the assessment is not
accepted, and the summary has `completion` true and `delivery.state` `ready`.
The assessor's `validation` shows `ERROR` with the single problem "guest reports
an infrastructure error or aborted run", because the guest's own summary says
ERROR; any other problem (a missing row, a foreign run or boot) is a defect.
Exit code 1. Code 2 means a delivery, telemetry or teardown failure and says
nothing about the scenarios.

### Content directory

The owner prepares it like the L2 one (an immutable tree, LF text, no links):

| Path | Source |
| --- | --- |
| `guest/launch.sh`, `guest/start.sh`, `guest/lib.sh`, `guest/run-l3.sh`, `scenarios-l3.tsv` | the same files of `source_checkout` (`tools/vm/linux/`), compared byte for byte |
| `artifacts/rosetun-helper-privileged`, `artifacts/rosetun`, `artifacts/provenance.json` | `tools/vm/linux/build-artifacts.sh --l3 OUTPUT_DIR`; `provenance.json` has `"stage": "l3"` and the SHA-256 of both binaries |
| `artifacts/sing-box` | the Linux sing-box of the supported version, delivered by the owner; ELF x86-64 |
| `artifacts/rosetun-helper.service`, `artifacts/rosetun-engine.rules` | copies of `packaging/linux/` in `source_checkout`, compared byte for byte |
| `artifacts/request-*.json` | none: the controller generates them in the run directory, and the content directory must not contain them |

The sing-box binary is hashed, never executed, on the controller. Its SHA-256 is
required in the `[l3]` table of the configuration and must equal the file's: the
build step records no engine, so the configuration is the only voucher for it.
Size limits are the L2 ones: 512 MiB for each ELF file, 256 KiB for every text
file, 1600 MiB in total.

**The six requests** (`request-kill-switch.json`, `request-lan.json`,
`request-lan-private.json`, `request-dns-lock.json`, `request-program-direct.json`,
`request-program-proxy.json`) are generated by `l3_requests.py` from the public
template `l3-request-template.json`: documentation addresses only (node
`192.0.2.1:8388`, DNS `203.0.113.3`, TUN `198.51.100.65/30`), reserved names
(`lab-node.test`, `doh.lab.test`, rules for `*.lab.test`) and a fixed laboratory
Shadowsocks password. The generator reads no owner request. The controller
creates the files as registered resources of the run, in `l3-requests/` of the
run directory, after it prepares the disk and before it builds the media (exclusive
create). The content directory is never written: it stays the exact input tree,
and a request file in it stops the run (`l3-requests-in-content`). The media step
takes these six files from the run and everything else from the content
directory, checks both with the same hashes and size limits, and snapshots them
together, so the snapshot and the ISO carry the requests. `--dry-run` writes
nothing: it checks the content directory without requests and renders them in
memory with the same generator. Package validation also requires every request
to name the same node as `HOST_ADDRESS` and `NODE_PORT` of `job.env`.

In `run linux-l3 --lab` the lab pair (the evidence disk, the lab's files and the test machine's `client.log`)
registers its files after the media, because the requests and the media accept only the resources of a freshly
prepared run. A stage that fails with an error of this package shows its code in the summary, a builtin
`ValueError` or `OSError` included; any other failure stays `operation-failed`.

### Configuration

`rosetun.matrix.execution.v2` adds `suite` (`linux-l2` or `linux-l3`) and, for
`linux-l3`, an `[l3]` table. Version 1 files still read as `linux-l2`, unchanged.
Copy [execution-l3.example.toml](execution-l3.example.toml); everything else is as
in stage 5c.

| `[l3]` key | Meaning | Default |
| --- | --- | --- |
| `sing_box_sha256` | SHA-256 of `artifacts/sing-box` | none, required |
| `host_address` | `HOST_ADDRESS` and `node.server` of the requests | `192.0.2.1` |
| `node_port` | `NODE_PORT` and `node.port` of the requests | `8388` |
| `probe_address` | `PROBE_ADDRESS` | `203.0.113.2` |
| `dns_probe_address` | `DNS_PROBE_ADDRESS` | `203.0.113.53` |

The addresses must be IPv4 documentation addresses (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`); the VM has no network, so none of them
answers. The example sets `job` to 300 seconds: stage 7a ends after the preflight
checks, but the controller still waits for the job, at most `job + 125` seconds, before it collects.
Raise `job` (and `deadlines.execution` to `job + 180`) for a run of every scenario.

```sh
python -m tools.vm.matrix run linux-l3 --config /srv/linux-l3.toml --dry-run
python -m tools.vm.matrix run linux-l3 --config /srv/linux-l3.toml
```

The suite on the command line must match the configuration. The summary schema is
the stage 5c one plus `suite`; the `run-l3.sh` results are in `assessment` as the
assessor returns them. There is no `lab` or `crosscheck` block yet. Waiting, the
number of collections, read limits and RPC budgets are the L2 ones and were not
raised. The size of a real L3 report against them was not measured here: if one
exceeds a limit, the run fails explicitly and the limit is to be discussed, not
changed.

### Stage profiles

One table (`PROFILES` in `linux_l2.py`) names, per stage, the scripts, artifacts,
`job.env` fields and the expected `provenance.stage`. `l2` is the old set; `l3` is
exactly `L3_START_REQUIRED` of `guest/start.sh`. The media record, the import
request and the receipt name the profile only for `l3`, so the bytes of an L2
package, ISO, `job.env` and receipt are unchanged. Job evidence of an L3 run goes
to `linux-l3/` instead of `linux-l2/`.

### Image of the test VM

For stage 7a the owner prepares the image as for L2 (the stage 5b prerequisites:
launcher, importer, stand marker, `rosetun` group, two ordinary accounts, Python,
QGA) and adds what the L3 preflight looks for: `nft` in `/usr/sbin`, `curl` with
the tftp protocol, `dig`, cgroup v2, `setpriv` and `ip netns`. No network and no
routes are needed.

**Reinstall the importer.** `tools/vm/linux/guest/stage-l2.py` changed: it takes
the stage profile from the verified import request, and its L3 content list now
includes `request-lan-private.json` (the sixth request, for the four Local
network scenarios). The owner installs the importer in the test image again. Its hash differs from the one
in the image, so the owner installs the new bytes at
`/usr/local/libexec/rosetun-l2/stage-l2` (root-owned, as before) and updates the
image descriptor. The new importer handles `l2` requests exactly as before, so the
L2 run uses it too.

### Owner qualification

1. Build `build-artifacts.sh --l3`, add the Linux `sing-box` of the supported
   version, copy the unit and rules, update the test image and the importer.
2. `run linux-l3 --dry-run`, then the ordinary command.
3. Expect 4 PASS, `preflight.baseline` FAIL (route to `203.0.113.2`), 20 SKIP
   (`two-hop.*`, "UNRUN"), 35 ERROR "not run", `completion` true, exit 1.
4. Run the ordinary `run linux-l2` again on the same stand and image: the result
   must be as in the stage 5c qualification.

Send back the summary, the saved `linux-l3/` evidence and the receipt if any
expectation differs.

## Stage 9b: the Windows launch profile and `windows-boot-smoke`

Status: **offline tests only, the stand result below is of one developer run and qualifies nothing.** The
controller starts and closes one Windows guest of the image of stage 9a (`../windows-image/`): no guest agent
job (stage 9c) and no lab (9d). Linux profiles, their configuration files and their plans are unchanged (the
Linux execution files keep their exact field lists). The release gate is false and the security invariants
are UNVERIFIED.

### The image and what `qualified: false` means

`images.WindowsImageDescriptor` is the descriptor `image.json` of stage 9a: the Linux contract
(`rosetun.matrix.image.v1`) with `guest_os: windows`, profile `windows-uefi-q35-v1` and a `windows` block. The
block is read strictly (unknown or missing fields, a PCI slot twice, a CPU string that is not `host` and
switches, a TPM file name with a path, are refused). The controller hashes what it will use: the disk like a
Linux disk, the firmware code, the variable store and every TPM state file the descriptor lists. The disk is
tens of gigabytes and the stand needs minutes for a pass, so a pass counts for the later checks of the same
controller process as long as the file's identity (device, inode, size, change times) is the one it saw; since
stage 9c the memory of a pass also outlives the process, and the check after the run follows the same rule (see
"The digest of the disk between processes" in Stage 9c).

`activated` must be false and `qualified` must be false, and no other value is accepted: the controller has no
qualification of a Windows image, so it never reads `qualified` as a permission. A run of such an image is
**diagnostic**: its summary says `qualified: false` and `diagnostic: true`, it counts for no parity table and
the release gate stays false. The image becomes qualified by the owner's decision after stage 9d, with a
controller that has a rule for it; until then `true` is refused, not trusted. Only the suite
`windows-boot-smoke` and, since stage 9c, `windows-reboot-smoke` take a Windows image; the Linux suites refuse it
(`guest_os` is not `linux`).

### The command line

`QemuConfig` stays the Linux configuration (machine `pc-i440fx-N.N`). A Windows run uses
`WindowsQemuConfig`: the same fields plus `swtpm`, with machine `q35` and `qga = true`. Its values must be the
image's: `bios` is the firmware code the descriptor names, `memory_mib` and `vcpus` are the descriptor's,
`machine` is `q35`; anything else is refused before a run is created. `_launch_plan` then gives, as the plan
(`launch-plan.json`) and `windows_run.launch` build it:

- `-machine q35,smm=off` (or `smm=on` with the secure flash property, as the descriptor's `uefi.smm` says),
  `-global ICH9-LPC.disable_s3=1`: the machine of the build.
- `-cpu` is the string of the descriptor (`devices.cpu`: the hidden virtualization flags and the Hyper-V
  enlightenments the idle measurement needed).
- `-rtc base=utc`: the guest keeps UTC (the answer file sets the zone and the time service is off), so its
  clock is the host's RTC read as UTC. That is QEMU's default and the build used it; it is given so that
  nothing depends on a default.
- Firmware: the code as a read-only pflash and **the run's own copy** of the variable store as the second.
- The disk is an overlay of the run over the verified, read-only image, as for Linux.
- Devices, slots and the MAC are those of the descriptor, because Windows binds its network settings to the
  adapter: virtio-blk at the disk slot, virtio-net (the test MAC, id `test-wire`) at the net slot,
  `tpm-crb` on the swtpm socket, VGA at its slot, and, added by `lifecycle.start` as for Linux, the
  virtio-serial adapter at its slot with the `org.qemu.guest_agent.0` port. The NIC has no network backend:
  the adapter exists and is connected to nothing (`-nic none`).
- `-display none`, no VNC, no listener. The VGA adapter is there for `screendump`, which reads it.
- QMP is the Linux one: QEMU listens on `qmp.sock` in the private run directory, started with `-S`.

### State of the run: the copies

`prepare` copies the image's variable store (`OVMF_VARS.fd`) and every TPM state file (`tpm/NAME`) into the
run directory, registers each one before it is written, and checks the bytes against the descriptor's digest
while they move and again once written. The image's own files are only read. `start` checks the copies again
before it spawns anything, so a copy that is not the image's file stops the run with no process. After the run
the copies differ from the image's files (the guest wrote its firmware store and the TPM its state); the
image's files do not, and the smoke checks it.

### swtpm as a resource of the run

`swtpm socket --tpm2 --terminate` is started by `lifecycle.start` before QEMU, with the state in the run's
`tpm/`, its control socket `swtpm.sock` (mode 0600: swtpm gives a control socket mode 0660 whatever its umask says, and the controller refuses a socket that others can reach) and its log `swtpm.log` (level 1) in the run directory. The
controller never connects to the socket: swtpm ends when the first connection closes, and that connection is
QEMU's. The process is recorded in the ledger as a `process` resource with the id `swtpm` (pid, host boot,
start time, executable, like `qemu`), registered before QEMU is spawned.

- Journal (`lifecycle.jsonl`): `swtpm started` after its identity is recorded, `swtpm child-reaped` (or
  `exit-observed` for an attached controller) after it ended, which is after QEMU's own exit was confirmed
  and before the row `exit`. A Windows run keeps four rows of the ordinary journal in reserve for these.
- Closing: QEMU first (ACPI power-down, `quit`, signals, as for Linux), then the TPM ends by itself; if it does
  not within the timeout it is terminated, then killed. A TPM that survives is `vm-exit-unconfirmed` like a
  QEMU that does. A QEMU that cannot be spawned takes the already started TPM down with it, and the run is
  quarantined as before.
- `completion.json` lists both processes, in the ledger's order (`swtpm`, then `qemu`), each with its return
  code; `completion_verified` needs both.
- A controller that dies leaves both processes: `runs` shows them (`process_status: alive`), `recover --archive`
  refuses while either lives, and `recover --run-id R --close` (the attach of `lifecycle.attach`) takes a pidfd of
  each, ends QEMU through QMP and the TPM with it, and records the completion. A TPM that is already gone when
  the controller attaches is recorded as gone, not as an error. A controller that dies between the spawn of
  swtpm and the spawn of QEMU leaves only the TPM: the run is not attachable (`run-not-attachable`), and the
  TPM is visible in `runs` as alive; it is stopped by hand after checking its recorded identity.

### `run windows-boot-smoke`

    python3 -B -m tools.vm.matrix run windows-boot-smoke --config CONFIG [--dry-run]

The configuration is its own (`execution-windows-boot-smoke.example.toml`, schema
`rosetun.matrix.execution.windows.v1`): the state directory, the stand id, the path of the descriptor
(`image_descriptor`), the `[qemu]` block of `WindowsQemuConfig`, `[smoke]` with `boot_wait_seconds` and
`shutdown_wait_seconds`, and the preparation deadline. It has no L2 content, accounts or lab; `--lab`,
`--control` and `--diagnostic` are refused. Use a state directory of its own: a diagnostic run is not a
qualification and shares no stand with one.

The steps are `preflight`, `lease`, `create-run`, `save-identities`, `prepare`, `start`, `resume`, `watch`,
`screendump`, `shutdown`, `close` and `image-unchanged`. The machine is resumed and watched for
`boot_wait_seconds`: every ten seconds `query-status` must say `running` and no RESET may have been
reported (a guest reset is `unplanned-guest-reset` or `guest-reset-before-first-boot`, an error). Then
`screendump` writes `screendump.png` into the run, `request_shutdown(wait=shutdown_wait_seconds)` sends the
ACPI power-down (the image's power button is set to shut down) and waits for QEMU to exit, and the run closes.
A guest that does not shut down in time is `shutdown-unconfirmed`: the run closes hard, as a Linux run does
after an error, and exits with 2. There is no `guest-shutdown`: the guest agent is stage 9c. After the close,
the disk, the firmware and the TPM files of the image are hashed again (`image-unchanged`).

Exit code: 0 when nothing failed, the completion is verified, the shutdown was the ACPI one, a screenshot was
taken and the image is unchanged; 1 never; 2 for any error or an unverified completion; 130 interrupted. The
summary (`execution-summary.json`, `rosetun.matrix.execution-summary.v1`) carries `execution` with the VM UUID,
`kvm_qualified` (the plan's, false), `boot_wait_seconds`, the number of samples, `guest_status`, the
screenshot's size and SHA-256, `shutdown` (`acpi` or `forced`), `image_unchanged`, the image's identifier and
digest with `qualified: false`, and the duration; the run's `completion` (`completion_verified`) and the
digests of every retained file are in the summary as for Linux.

### Checked on the stand (2026-11-19, a developer's run, not a qualification)

Debian 13 on WSL2, QEMU 10.0.13, swtpm from the distribution, the image of 9a
(`windows-11-26h2-pro-v1`, disk SHA-256 `1c9c5a60...32ea`), `boot_wait_seconds = 90`, one guest at a time,
a state directory of its own. Two runs, nothing else:

- The first one stopped in `start`: swtpm gives its control socket mode 0660 whatever the umask says, and the
  controller refuses a control socket others can reach (`vm-start-failed`). swtpm was started, recorded and
  reaped; QEMU was never spawned; the run is quarantined, as for any failed start. The command line now says
  `mode=0600`. The stand-in swtpm of the offline tests now sets its socket's mode the same way.
- The second one: exit 0, `completion_verified` true, `shutdown: acpi`, `image_unchanged: true`, 426 s in all
  (the two passes over the 12.4 GB disk take most of it). QEMU started paused 3 s after swtpm, ran 91 s
  (10 samples, `running`), the screenshot (`screendump.png`, PNG, 1280x800, 490042 bytes) shows the Windows 11
  lock screen with the time of the host in UTC, and the ACPI power-down made the guest shut down by itself in
  26 s (`shutdown child-exit-observed`). Both processes were reaped (return codes 0 and 0, swtpm first in the
  ledger). The run's `OVMF_VARS.fd` differs from the image's after the run and the image's does not. QEMU printed
  one line on stderr, `warning: nic test-wire has no peer`: the adapter has no backend, as intended.

What this does not show: that the guest has Secure Boot or the TPM (the agent asks that, stage 9c), that it is
at rest, that a controller killed while the guest runs is recovered on the real stand (the offline tests do it
on stand-in processes), or anything about the observer.

### Not done here, UNRUN

- No guest agent job, no boot ID, no reboot (9c) and no lab (9d): a Windows reboot during the watch is an
  error, not a planned one.
- Whether the guest answers the power button at the logon screen is what the smoke shows; the guest never logs
  on by itself in this image.
- The variable store of the guest is writable by it (the firmware has no SMM), as the descriptor says.
- A run needs the whole disk hashed twice (about two and a half minutes a pass on the stand). Stage 9c remembers a
  pass between runs: the first run of an image on a stand hashes it once, the later ones none.

## Stage 9c: the guest agent of a Windows guest and one planned restart

Status: **offline tests, and the developer's runs on the stand written below, which qualify nothing.** The controller
works with a Windows guest of the 9a image through the guest agent as it does with a Linux guest since stage 8c, and
carries it through one restart that it asks for. No lab (9d), no Rosetun in the guest and no script of the controller in
it: the image is only read. The release gate is false and the security invariants are UNVERIFIED. Linux suites, their
configurations and their budgets are unchanged.

### The digest of the disk between processes

A run of 9b hashed the 12.4 GB disk twice (about two and a half minutes a pass on the stand). The controller now keeps
the memory of a pass in the state directory of the stand, `image-digests/`, one small file for each disk: its path, the
digest the pass found (and that the descriptor says), and the file's identity as the pass read it, which is the key:

| `device` | `inode` | `size` | `mtime_ns` | `ctime_ns` |
|---|---|---|---|---|

- The record is used only when **every part** of the key is the one it names, and the digest it names is the
  descriptor's. Anything else is a full pass: a changed size, inode or device, a changed modification time, **a changed
  change time**. The change time is the part that matters: a file's owner can set its modification time back after
  changing it, but not its change time, so a disk replaced by another of the same size and given the old
  modification time still has a new key. A change of the change time with no change of the bytes (a `chmod`, a copy
  over the same path) costs one pass and no more.
- A record that is not there, cannot be read, is a link, is larger than 4 KiB, is not JSON, has other fields than
  these eight, has a number that is not an integer, or names another path, digest or schema, is no record: the disk is
  hashed in full and a good record is written over it. The directory of the records is created `0700`, the records
  `0600`, and neither the directory nor a record is followed when it is a link. A record that another user owns or
  that others can read or write (a mode wider than `0600`), or one in a directory like that (wider than `0700`, or
  another user's), is no record either: the disk is hashed in full and the record is written again with the right mode;
  a directory that is ours and too wide is made `0700` first, and one that is not ours is left alone and written to
  not at all.
- A record is written only after a full pass that **matched** the descriptor, atomically (a temporary file in the same
  directory, `fsync`, `rename`, `fsync` of the directory), and a pass that fails writes nothing. A cache that cannot be
  written is no error: the next process hashes again.
- The check after a run, `image-unchanged`, follows the same rule as the one before it: a full pass if the key
  changed, none if it did not. The disk is the read-only backing file of the run's overlay, so a guest cannot change it,
  and a controller that did would have changed its change time. A forced pass is still there (`fresh`), and the
  process's own memory of passes stays in front of the file.
- The run directory tells where the records are (`STATE/runs/ID`, its grandparent is the state directory); a run
  directory anywhere else keeps only the memory of the process. The records belong to the state directory and are trusted
  as much as its run manifests are: whoever can write them can write those. The Linux disks (small) are hashed every time,
  as before.

On the stand the first run of the image in a state directory hashed the disk once (about 150 seconds) and the later runs
none: preparation took seconds.

### The guest agent of a Windows guest

`qga.Qga(guest_os='windows')` (the Vm passes it for a Windows run) changes four things and nothing else:

- **The boot identity.** Linux reads `boot_id` from procfs. A Windows guest has no such file, and the image may not be
  changed to write one at start (a task `ONSTART` would be that). Two readings were tried on the stand. The time of the last
  boot (`Win32_OperatingSystem.LastBootUpTime`) and the count of boots that the system keeps in
  `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters`, value `BootId`, raised by one at every
  start of the kernel. Both need a PowerShell, and the first PowerShell of a fresh boot of the image took more than a
  minute on the stand (two tries of 30 seconds timed out, the third answered), so reading the identity by it made an
  observation fail with the guest well. The count is therefore read by `reg.exe query ... /v BootId`, which answers at
  once and prints ASCII whatever the guest's language (`REG_DWORD` is not translated), and the boot identity is
  `win-COUNT`, a name the run state takes (the first boot of a copy of the image was `win-4`, the next `win-5`). The
  count of the guest and the time of its last boot are read again by the evidence's PowerShell, and the run is
  accepted only if they agree with the chain: the name must be `win-` and the count PowerShell reads, and after the
  restart both the count and the kernel's start time must be new. A guest whose count did not change would end the
  run as `guest-reset-boot-id-unchanged`, loudly, and not as a boot nobody noticed.
- **Programs.** `guest-exec` is CreateProcess with no shell, so a program is a full path and its words
  (`Qga.run_program`, `Qga.start_program`). The two streams come apart (`capture-output: separated`; `merged` does not
  exist on Windows); each is cut off at 64 KiB and a truncated or not base64 stream, a missing exit code, a `signal` (an
  unhandled exception is told that way) and a pid that is not a plain integer are refusals that end the session. The
  status is asked for 0.25, 0.5, 1, 2 and then every 5 seconds (300 seconds of waiting take about 60 calls), each ask one of the session's 128 calls, and a program that
  outlives its time ends the session (it may still run: nothing here kills it). A program that takes the guest down is
  started and not waited for.
- **PowerShell 5.1 and UTF-8.** A command runs as `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass
  -EncodedCommand` (a UTF-16LE script in base64, so there is nothing to quote) and writes its answer to the **raw**
  standard output stream as UTF-8 bytes without a byte order mark, and an error (type and message) to the raw standard
  error stream with exit code 1. The console's code page, the profile and the culture are never consulted, so the same
  answer arrives on an English and on a Russian guest. The evidence carries a text that only UTF-8 crosses (e acute and an
  ideograph, written as character codes): the run is not accepted if it does not come back unchanged. The guest's error
  text is kept in the evidence rows and never becomes the name of an error.
- **Paths** are Windows paths with a drive: `C:\Windows\System32\...` for `powershell.exe`, `reg.exe` and
  `shutdown.exe`.

`Qga.probe` of a Windows session also requires `guest-exec` and `guest-exec-status` in the agent's list, like a Linux job.

### `run windows-reboot-smoke`

    python3 -B -m tools.vm.matrix run windows-reboot-smoke --config CONFIG [--dry-run]

The configuration is that of `windows-boot-smoke` (`execution-windows-reboot-smoke.example.toml`, the same schema and
the same `[qemu]`) with `suite = "windows-reboot-smoke"` and a `[smoke]` of four times: `agent_wait_seconds` (1 to 300,
the longest the first boot may take to answer), `reset_wait_seconds` (1 to 600, from the request to the RESET),
`reboot_wait_seconds` (1 to 900, from the RESET to the agent of the new boot) and `shutdown_wait_seconds`. `--lab`,
`--control` and `--diagnostic` are refused.

The steps are those of the boot smoke up to `resume`, then `boot`, `evidence`, `reboot`, `reset`, `new-boot`,
`evidence-after`, `shutdown`, `close` and `image-unchanged`:

1. `boot`: new agent sessions until one answers, with `win-COUNT` taken as the first boot of the chain (a try is 30
   seconds, 15 seconds apart; no recovery is spent).
2. `evidence`: one PowerShell says what the guest is (caption, version, build, architecture, culture), whether Secure
   Boot is on (`Confirm-SecureBootUEFI`), whether the TPM is there and ready (`Get-Tpm`), the count of boots, the time of
   the last boot, the uptime and the UTF-8 text. It is written as a row of `job-evidence.jsonl`
   (`rosetun.windows-evidence.v1`, `when: before`). A reading that failed is `null` and does not stop the run, but the run
   is accepted only with Secure Boot true, a TPM present and ready, and the text intact.
3. `reboot`: `shutdown.exe /r /t 0` through the agent (`Vm.request_guest_reboot`), started and not waited for: the agent
   goes down with the guest. It is the way the guest's own scripts would restart it, needs no task in the image and is not
   `guest-shutdown`, which this guest does not answer. The journal gets `guest-reboot intent` and `requested`
   (or `error`), and the session is closed to use.
4. `reset`: QMP is read every two seconds (`Vm.wait_guest_reset`, the loop of stage 8c) until the guest's RESET is
   registered: the journal row `guest-reset-observed` (`1-of-1`), the step `guest-reset-1` at intent, the session
   invalidated, the chain waiting for its boot. A RESET of the host, a second RESET after the merge window and any other
   case of stage 8c end the run as there (`unplanned-guest-reset`, `guest-reboot-unobserved`, ...). The merge of RESETs
   within one second of the first, up to four more, is the Linux mechanism and is unchanged; Windows gave one RESET on
   the stand.
5. `new-boot`: `await_rebooted_guest` with the limits of a Windows guest: the first try is the recovery the reset earns,
   then new sessions with no recovery, each 30 seconds at the most and 5 seconds apart, for 300 seconds at the most (12 tries
   at the most). The new identity is taken only if it differs from the chain's last (the Linux refusals stay:
   `guest-reset-boot-id-unchanged`, `boot-id-repeated`, `boot-id-changed-without-reset`).
6. `evidence-after`: the same reading on the new boot (`when: after`).
7. `shutdown`: the ACPI power button as in 9b.

**Limits.** In stages 9a and 9b the agent answered 28 to 78 seconds after QEMU started; on the first run of this stage
about 50 seconds after the resume and about 40 seconds after the RESET of the restart, which came 24 seconds after the
request. So: 300 seconds for the first boot (four times the slowest start seen; the first `wait_initial_guest` allows
no more than 300), 180 seconds for the RESET (Windows stops its services first), 300 for the new boot, and **300 for one
try of the evidence's PowerShell**, which is slow on a fresh boot of the image: the qualifier saw the first one take 10, 82,
108 and more than 180 seconds on a cold disk, and the first version's limit of 180 ended a run as `qga-exec-timeout`. A
try that times out is made **once more** on a new session (the journal of the evidence says so: the row
`guest-evidence-timeout` with the attempt, the seconds and the reason, and the repeat is one recovery, taken with
`recover_guest`); two tries in a row that time out are an honest refusal (`qga-exec-timeout` at the step `evidence`, exit
2), and a PowerShell that fails is not asked again. The run has no total time of its own, only those of its steps, so the
longest it can spend on the evidence is two readings of two tries of 300 seconds each, 20 minutes, and with the other
limits (300 + 180 + 300 + 240 seconds, and the preparation's) well under any limit of the controller; the 128 calls of a
session hold a try of 300 seconds. The Linux limits (10 seconds a try and 180 in all) would have ended a Windows reboot
as `rebooted-guest-deadline`.

**Budgets.** `planned_reboots` is 1 (`config.PLANNED_REBOOTS`), so `qga_recoveries` may be 4 + 1: a run takes exactly one
(the recovery of the reset), and a repeat of the evidence takes one more each, three at the most with the two readings,
still within the limit; `qga_observations` (32): about 7 at the most for the first boot and 12 for the new one,
the stand used 6; the journal of the lifecycle has 106 ordinary rows and a reboot takes 4 (2 for the request, 2 for the
reset and the chain) and 1 more for each merged RESET. Reading QMP every two seconds writes nothing unless it finds a RESET.

**Where the guest scripts are.** There are none. The run needs no program in the guest that survives the restart, and
a status file, a task `ONSTART` and the atomic write that Linux has for them would change the image or reach into it
for nothing; the programs are the system's own (`reg.exe`, PowerShell, `shutdown.exe`). `tools/vm/windows/`, the
owner's Hyper-V tools, is untouched, and no `guest/windows` directory exists; a later suite that needs a runner in the
guest (10a) will bring it with the status file it needs.

**The summary** (`execution`): `accepted`, `boot_chain` (two `win-COUNT`), `guest_resets` (1), `resets_merged`,
`planned_reboots`, `qga_recoveries`, `qga_observations`, `agent_ready_seconds`, `reset_seconds` (from the request to the
RESET), `reboot_seconds` (from the request to the new boot), `guest` and `guest_after` (what the guest said before and
after: system, Secure Boot, TPM, UTF-8, the count and the time of the boot), `shutdown`, `image_unchanged`, the image's
identifier and digest with `qualified: false`. Exit 0 only with no error, a verified completion, an ACPI shutdown, the
image unchanged, a chain of two different boots after one restart, and both readings standing; 1 for a run that
finished with a reading that does not (Secure Boot off, no TPM, text mangled); 2 for any error; 130 interrupted.

### A controller killed while it waits for the restart

`attach --state-directory S --run-id R` takes a `windows-reboot-smoke` over from the step `reboot` on (`reboot`, `reset`,
`new-boot`, `evidence-after`; before it nothing in the guest can be carried on and the answer is
`attach-phase-not-resumable`: `recover --run-id R --close`). It sets the plan's one reset, takes the evidence the dead
controller wrote for the first boot from `job-evidence.jsonl`, and then, by what the run state says:

- **The RESET was read and the new boot is not taken** (`guest-reset-1` at intent): it waits for the boot as the first
  controller would (the first try opens the session and is the recovery the reset earns).
- **The new boot is taken**: it opens a session on it, records the evidence once more and shuts down.
- **The RESET was not read.** QMP events that nobody read are gone. A guest that answers with a boot identity other than
  the chain's last is **`boot-id-changed-without-reset`**, the honest end of the run (as for Linux: no hole is put
  into the chain and no boot is invented). A guest that is still on the old boot, or whose agent says nothing yet, is
  waited for until its RESET (`reset_wait_seconds`, counted from the attach), and the run goes on.

The budgets continue from the run state (`qga_recoveries` is not set back to 0), the summary says `attached: true`, and
`recover --close` closes any such run, the TPM with it, as in 9b.

### Checked on the stand (2026-11-19, a developer's runs, not a qualification)

Debian 13 on WSL2, QEMU 10.0.13, swtpm 0.7.1, the image of 9a (`windows-11-26h2-pro-v1`, Windows 11 Pro 10.0.26300),
a state directory of its own, one guest at a time, the checkout of this stage (not clean). Three runs of
`windows-reboot-smoke` and nothing else that counts:

- **The first one** (the first run of the image in the state directory) hashed the disk once, 150 seconds, and wrote the
  record. It read the boot identity by PowerShell, the first version of this stage: the first try found no agent, the
  next two timed out at 30 seconds with the agent up (it answered `guest-info` and `guest-ping`), and the fourth got the
  answer 140 seconds after the resume. That is why the identity is read by `reg.exe` now. The run ended well all the same:
  exit 0, 405 s, one RESET 23.6 s after the request, the new boot taken 64 s after it.
- **The second one** (`2e463076f8c5...`, the code of this stage): exit 0, `completion_verified` true, **170.5 s** in
  all, preparation without a pass over the disk (the record was found) and the check after the run without one.
  `boot_chain` `["win-4", "win-5"]`; the agent answered 48.9 s after the resume; the evidence took 9 s; **one RESET**,
  `guest-reset-observed 1-of-1 reason=guest-reset`, 21.4 s after the request (no merged RESET); the agent of the new boot
  answered, and `boot-chain-extended 2` was written, 58.5 s after the request (the first try, the recovery, found the agent
  not yet up after 30 seconds; the second took the boot at once); `qga_recoveries` **1** (the limit is 4 + 1),
  `qga_observations` 4; the ACPI power button shut the guest down in 14 s. Evidence before and after: Windows 11 Pro
  10.0.26300 64-bit, Secure Boot `true`, TPM present and ready, the UTF-8 text intact, count of boots 4 then 5, time of the
  last boot 08:42:01.5 then 08:43:14.5 (UTC); `guest-info` of the agent says 110.2.3 with `guest-exec`, `guest-exec-status` and
  the file commands enabled. The image's disk, firmware variables and TPM files are unchanged (`image-unchanged`).
- **The third one** (`87125d9dcf39...`): the controller was killed with `SIGKILL` at the step `reset` (the request had
  been made, the RESET not yet read) and `attach` took the run over: exit 0, `attached: true`, `attachments` 1, `boot_chain`
  `["win-4", "win-5"]`, **`qga_recoveries` 2** (the attach and the reset's own: not set back to 0, within 4 + 1),
  `qga_observations` 4. The attach found no answering agent (the guest was going down) and went on to read QMP,
  registered the RESET 33 s after the attach began, and took the new boot 10 s later; the evidence of the first boot was
  taken from the dead controller's row, and the evidence of the new boot with the shutdown that followed ended the run.
  The image check after it was done without a pass.

What this does not show: a restart of a guest with more than one RESET, a RESET that came while nobody was connected (that
is the offline test of the stand-in guest), the limits under a slower host, and the first PowerShell of a fresh boot being
quick (it was not on the first run).


### Not done here, UNRUN

- No lab (9d) and no sleep, power cut or fast startup; the restart is the guest's own, not a power cut.
- The first PowerShell of a boot can take more than a minute (10 to more than 180 seconds were seen): the evidence has
  300 seconds a try and a repeat. The repeat was run on the stand-in guest only. Whether the slowness is the image (its
  first boot after a build) or any fresh boot of a cold disk is not known.
- A restart that gives more than one RESET on Windows was not seen; the merge is the Linux mechanism and is covered by the
  stand-in guest only.
- An `attach` whose RESET came while nobody was connected was run offline only.
- Windows restarts by Windows Update, a crash with automatic restart or `Disable-RosetunBootRecovery` are an
  `unplanned-guest-reset`, as intended; the image has no Update.
- No qualification: the image is `qualified: false`, the run is diagnostic.

### What to reinstall

Nothing in the image. The controller needs only the files of the checkout and the stand's state directory, which fills
its `image-digests/` itself.

## Stage 9d: a Windows guest on the lab's wire, `windows-lab-smoke`

Status: **offline tests, and the developer's run on the stand written below, which qualifies nothing.** The Windows guest
of the 9a image is connected to the wire of the lab like the Linux test machine of stages 7 and 8, without Rosetun in it,
and the observer says what it sends: the eight probes of the lab contract and, after them, ten minutes of nothing, which
are listed and not judged (see "Decisions of 2026-11-20"). The release gate is false and the security invariants are UNVERIFIED. The image stays `qualified: false` and the run is
diagnostic whatever it reports. Linux suites, their configurations and budgets are unchanged.

### Why this is a stopping point

The classifier of the lab knows ARP, neighbor discovery and multicast listener messages between the two machines as
`infrastructure`, and every other frame of the test machine is `unexpected` (stage 6b). A Windows guest says more than
that by itself. This stage does not decide what may be allowed: **no tolerance is added to `lab_protocol` and the observer
is not weakened.** What the resting guest sends is written down, group by group, as `windows-noise-report`, and each group
outside `infrastructure` is a finding for the owner, who decides whether the image is made quieter (a standard setting
of the operating system, a change of `first-logon.ps1` and a new build by the qualifier) or whether the observer learns
to allow it (and with it the rule that a window is judged whole). The Windows Firewall of the guest is not touched: it is
a filtering layer of its own and would distort what is judged.

### Decisions of 2026-11-20

The first run on the stand (below) showed what a resting Windows says, and the owner decided what follows from it:

- **The poll of the gateway is infrastructure.** A unicast ARP request from the test machine to the lab's hardware address,
  naming the lab's address as target and the lab's hardware address as target hardware address, is `infrastructure` for
  every suite (a stack sends it to check a neighbor it knows, RFC 1122 2.3.2.1; Linux does the same). Only this frame:
  another target hardware address or destination, another target or sender address, the broadcast with a lab target
  hardware address, and the same request from the lab to the test machine keep the category they had.
- **The guest settles before the probes** (`settle_seconds`, below), so that what the download of updates and the set-up
  leave behind does not fall in the one-second window of the probes. The window of the probes is judged as before: a
  foreign frame in it is `DETECTED`.
- **The rest only lists.** The window `rest` and the `windows-noise-report` stay as they were (every group, `unexpected`,
  the names of the DNS questions and TLS hellos), but the report is information: `noise: FOUND` or `NONE` changes neither
  the exit code nor the verdict of the run. The run is decided by the network, the CA, the probes, the window of the
  probes, the `qualify` of the lab and the observer (a rest that was not observed, `UNVERIFIED`, cannot be vouched for: exit 2). The
  classifier and the observer are not weakened, no tolerance by name is added and the lab's resolver is unchanged. The
  telemetry of Windows stays as natural traffic on purpose: the stages with a tunnel (10) are where it has to go into the
  tunnel, or not leave at all while the tunnel is blocked.
- **Operating system settings against the noise are not applied.** `DisableRootAutoUpdate`, `EnableFontProviders` = 0 and
  the policies of Edge for updates and experiments (the table below) are planned for the next rebuild of the image,
  together with the work of stage 10c, not for this one.
- The report also accounts for the frames outside the window: `outside` (before the first marker), `between` (in no
  window, from the first marker to the end of the rest) and `after`, and `accounting` counts every frame of the capture
  once (markers, those three, the frames of the window of rest and those of the other windows; `complete` says the sum is
  the number of frames read).

### The machines

Two machines run under one lease, as for the Linux suites of the lab: the lab machine (the image of the lab, 2048 MiB: the
routing, the targets, the lab resolver, the HTTPS target and the capture to its evidence disk) and the Windows guest
(4096 MiB, the image's own devices). Both are needed at once, so the preflight refuses a host whose available memory is
less than both and 768 MiB for QEMU, swtpm and the controller (`host-memory-too-small`); the guest's memory is never
reduced to make it fit.

The guest's network adapter is the one of the image (the same device, slot and MAC, `00:00:5e:00:53:61`, which is the
lab's test machine): `lifecycle.start` gives it the lab's wire backend (`netdev=labwire`) instead of adding a second
adapter, which would leave the settings of the first one behind. An image whose MAC is not the lab's test MAC is refused.
The lab machine is started first and sets up its capture; the guest starts after it, so the capture holds the boot too.

### The network of the guest

The image is qualified and frozen, so the addresses are **not** in it: the controller sets them through the guest agent
once the guest answers, in the guest's own PowerShell 5.1 (the mechanism of 9c: encoded command, UTF-8 on the raw
streams, exit code). The first script is `network`: on the adapter that has the MAC it turns DHCP off, removes what DHCP
and the link-local fallback made, sets `192.0.2.2/24` with the gateway `192.0.2.1`, `2001:db8:6a:1::2/64` with the
default route through `2001:db8:6a:1::1`, and the DNS server `203.0.113.53` (the lab resolver); then it waits until both
addresses are `Preferred` and reads back the addresses, the default routes and the DNS servers. The controller compares
that with the contract (`address-v4-missing`, `address-v6-not-preferred`, `route-v4-missing`, `dns-servers`, `adapter-mac`
...): **any difference stops the run** (`windows-network-not-as-the-lab-says`, exit 2) before anything else is sent, and
the readings are in the summary and in the job evidence. The lab sends no router advertisement, so the IPv6 address and
route are static.

The second is `certificate`: the lab's CA (a PEM file on the controller whose SHA-256 must be the `ca_sha256` the lab
machine pins; the file is decoded on the controller and its DER goes to the guest) is added to `Cert:\LocalMachine\Root`,
and the answer must carry the thumbprint of those bytes. The HTTPS probe then goes through the system's own validation.

The frames the set-up itself makes (the guest's DHCP attempts before the address is set, the ARP probe and announcement of
the new address, DAD, neighbor solicitations and advertisements, router solicitations, multicast listener reports) happen
before the first window opens, so the observer counts them in `outside_window` and in the `outside` part of the noise
report, and they judge nothing. Those of them that fall in a window are judged by the same rules as everything else.

### The probes (window `probes`)

One PowerShell, between an opening and a closing marker (the marker is a UDP datagram to the lab's marker service, which
the guest sends and the lab acknowledges, as the Linux script's functions do), runs:

- the **eight probes of the lab contract**, IPv4 and IPv6: `http` (TCP 8080), `udp` (9000), `dns-udp` and `dns-tcp` (53) to
  the lab's targets. The bytes are exactly the ones the Linux helper sends (the request is built in the guest from the
  run's name and the probe's nonce, which is all the guest is told), on `System.Net.Sockets.TcpClient` and `UdpClient`
  bound to the guest's own address; the controller compares what came back with what the lab answers
  (`lab_protocol.answer`), and the lab machine's own log of the same exchanges and the capture decide again
  (`lab_protocol.qualify`);
- one **HTTPS** request to the target (`203.0.113.2:443`, IPv4: the target has no IPv6 listener) with `SslStream`, which
  checks the certificate against the machine's root store, the lab's CA among them, and its IP address; the guest reports the
  port it used, and the target's log must hold the one request from that port, which is what lets the observer tell the
  connection from a leak (as for `https-direct` of stage 7b1);
- one **lookup** of a name of the run at the lab resolver, `Resolve-DnsName -Server 203.0.113.53 -DnsOnly`, which the
  resolver's log must hold once, from the guest's address.

The ten exchanges are judged by the window: a frame in it outside the probes, the markers and `infrastructure` is
`unexpected`, and the window is `DETECTED`.

### The first exchange after a long wait

A session of the agent that has sat idle for minutes may be dead without anyone having said so, and the first real
exchange on it (a window marker, which is never repeated blind: a second UDP marker is `window-markers-missing-or-repeated`)
would be the one to find out. In the run that happened once: after the ten minutes of rest the closing marker found the
session gone (`qga-exchange-failed` at `guest-rest-close`). So the first exchange after every wait of the controller (the
settling, the rest, and the pauses of later stages) is preceded by `Vm.ready_guest`: a `guest-ping`, asked again once on
the same session when no reply comes (the library matches replies by their id, so a late one is dropped), and when that
does not answer either, `recover_guest()`: a new session, one of the run's QGA recoveries, before anything is sent. Each
check is a row of the job evidence (`guest-settle-session`, `guest-rest-session`: `pings`, `recovered`, `ended`). The error
of a failed exchange keeps what ended it: `cause` (in the error of the summary, in the observation row and in `LifecycleError`)
is the class of the exception and, for the system's own (`OSError`: the number and `strerror`, `EOFError`, a timeout), its
words, in the alphabet `[a-z0-9:._-]`; the text of any other class (the agent library quotes what the guest sent) is
left out, and a file name never is in it.

### Settling (before the window `probes`)

After the network and the CA, and before the opening marker of the probes, the controller sends nothing to the guest for
`settle_seconds` (0 to 300; 60 when the field is left out, 60 in the example), as in the rest: it only looks at the two
machines. The step is `settle`; the seconds waited are `settle` in the summary, and the lab's capture is as much longer.

### Rest (window `rest`)

A second pair of markers brackets `rest_seconds` (600 in the example) in which the controller sends **nothing** to the guest:
it only reads QMP events and the state of the two processes (no command, so no budget is spent). The report is made from
that window. `windows_noise.report` takes the capture the lab machine kept and gives, for each sender, protocol,
destination, port and category of the frames of the window: the number of frames and bytes, the number of source ports (the
flows of a TCP or UDP group), and the first and last time (seconds after the opening marker and UTC). It lists the
`unexpected` groups apart, and the frames before the first window as context (`outside`, seconds from the start of the
capture). **`noise` is `NONE` only when every frame of the window is `infrastructure`; otherwise it is `FOUND`, and each
group outside `infrastructure` is in `unexpected` or `other`;** a missing or untimed window is `UNVERIFIED`. The groups are
also in the summary as `noise_table` (one line each). **The report informs and decides nothing**: the `leak` of the window
`rest` may be `DETECTED` and the run still ends with 0; only a window that was not observed (`UNVERIFIED`, or reasons of the
observer) fails the run. The frames outside the window are in `outside`, `between` and `after`, and `accounting` adds
them to those of the window and the markers.

### `run windows-lab-smoke`

    python3 -B -m tools.vm.matrix run windows-lab-smoke --config CONFIG [--dry-run]

The configuration is `execution-windows-lab-smoke.example.toml`, schema `rosetun.matrix.execution.windows.v2`: the
fields of the other Windows suites, a `[smoke]` of `agent_wait_seconds`, `script_seconds` (one PowerShell of the guest, up to
300: the first of a boot took more than 180 on the stand), `settle_seconds` (0 to 300, optional, 60 when left out), `rest_seconds` (60 to 900) and `shutdown_wait_seconds`, and a
`[lab]` block with the lab's image, its QEMU (the pinned i440fx machine), the pins of stage 7 (`sing_box_sha256`,
`ca_sha256`, the two certificate hashes) and the path of the CA's PEM. The lab capture lasts
`agent_wait + 4 * script + settle + rest + 300` seconds and may not pass the observer's 2700. `--lab`, `--control` and
`--diagnostic` are refused; `attach` does not take this suite (a run killed in the middle is closed with
`recover --run-id R --close`, then examined).

The steps are `preflight`, `lease`, `create-run-lab`, `create-run-test`, `prepare-lab`, `prepare-test`, `evidence-disk`,
`start-lab`, `resume-lab`, `boot-lab`, `lab-setup`, `start-test`, `resume-test`, `boot-test`, `wire-close`, `network`,
`certificate`, `settle`, `probes`, `rest`, `lab-finish`, `lab-read-*`, `shutdown-test` (the ACPI power button), `close-test`,
`close-lab`, `evidence-read`, `windows`, `image-unchanged`.

Exit code, by the convention of the matrix (see "Exit codes" of stage 7c2): **0** when nothing failed, both machines
completed, the guest shut down by its own power button, the image is unchanged, the network stood, every probe passed (and
was seen by the lab machine and the capture), the window `probes` is `NONE` and the window `rest` was observed (whatever
it holds: `noise` is information); **1** for a finding: a probe that did not get the lab's answer, a window `probes` that is
`DETECTED` (`execution.findings`); a finding stands whatever else went wrong; **2** when the run cannot vouch for itself and
found nothing: any error (a network that is not the lab's, a guest that cannot run its script, a machine that left, an
unverified completion), a window that is `UNVERIFIED` or has reasons of the observer, the lab's own `qualify` that failed, a
probe the lab did not log, markers that were not acknowledged, a rest that was not observed (`execution.unverified` names
each); **130** for an interruption. A failed probe script does not end the run (the capture still holds what the guest did,
and the rest is the point), but it is an error, and a window `probes` that is `DETECTED` beside it is not attributed to the
guest (the script that would name its own exchanges did not answer): 2. The summary
(`rosetun.matrix.windows-lab-summary.v1`, in both runs) has `execution` with the network, the certificate, `probes`,
`windows` (leak, reason and counts of each), `noise`, `noise_report` and `noise_table`, and `lab` with the observer's
windows and the digests of what the lab machine kept.

### Checked on the stand (2026-11-19, a developer's run, not a qualification)

Debian 13 on WSL2 (7.9 GB), QEMU 10.0.13, the image of 9a (`windows-11-26h2-pro-v1`), the lab image of stage 7 (2048 MiB,
2 vCPUs) and the guest (4096 MiB, 4 vCPUs) together, `rest_seconds = 600`, a state directory of its own, one run and
nothing else that counts. The checkout was not clean (this stage's files).

- **The run:** exit 1, 738 s in all, both machines `completion_verified`, the guest shut down by its power button, the image
  unchanged, no error, no QGA recovery (2 observations), the capture 81501 bytes and its evidence disk read back whole. The
  network stood at the first try (`Ethernet`, both addresses `Preferred`, both default routes, the lab resolver as the only DNS
  server), the CA was added to the machine store (`CN=Rosetun lab CA`, thumbprint as the controller computed it), and **all
  ten exchanges passed**: the eight probes, the HTTPS request (validated by the system against the lab CA and the IP address
  of the target) and the lookup at the lab resolver. The lab machine's own `qualify` said `qualified: true`.
- **Window `probes`: `NONE`** (64 frames of probes, 4 of markers, nothing else).
- **Window `rest` (601 s): `DETECTED`, `noise: FOUND`**, 462 frames, 19 `infrastructure` and 443 `unexpected`. What the
  guest did, with the names read from its own frames:
  - **DNS** to the lab resolver, 30 questions over 575 s: `ctldl.windowsupdate.com` (A and AAAA, 17), `settings-win.data.microsoft.com`,
    `fs.microsoft.com`, `msedge.api.cdp.microsoft.com`, `config.edge.skype.com`, `ecs.office.com`, `go.microsoft.com`,
    `mobile.events.data.microsoft.com` (one A or AAAA or both each). The lab resolver answers every A question with the
    target's address, so each name was followed by a connection.
  - **TCP to the target, port 443**: 19 connections (107 frames), each a TLS ClientHello whose server name is one of
    `config.edge.skype.com` (4), `msedge.api.cdp.microsoft.com` (4), `mobile.events.data.microsoft.com` (4), `ecs.office.com` (3),
    `go.microsoft.com` (2), `fs.microsoft.com`, `settings-win.data.microsoft.com`; the target's certificate does not
    fit those names and the guest ended each one (the target logged 8 `ssl-unexpected_eof_while_reading`, the most it keeps).
  - **TCP to the target, port 80**: 18 connections (90 frames), a SYN each, refused by the lab (nothing listens there);
    the names are those of the DNS questions, `ctldl.windowsupdate.com` for most.
  - **ARP**: 9 unicast ARP requests of the guest for the gateway (neighbor reachability, `tha` is the gateway's MAC, not
    zero), classified `unexpected` because the classifier takes only a request whose target hardware address is zero; the lab's
    replies and the lab's own requests with the guest's replies are `infrastructure` (9 + 4 + 4 frames), as are one
    neighbor solicitation and its advertisement at the start.
  - The bursts come all through the window (first at 4 s, the last at 579 s), densest between 449 s and 471 s; no group stops.
- Before the first window (boot and the set-up of the guest, 64 frames, in `outside`): the guest's ARP probes for
  an address of `169.254.0.0/16` and `192.0.2.2`, four DHCP discovers, router solicitations, neighbor discovery and multicast listener
  reports, all of it before the first window opened.

What this says: the image is quiet on its own at the link level and **not quiet once its DNS works**. The traffic is that of
Windows components that look for their servers by name, not of the lab's set-up. The report is in the summary and was also
made again from the retained capture (`windows_noise.report`), which is how the names above reached it.

### Checked on the stand again (2026-11-20, after the decisions above, not a qualification)

The same image, the lab image and the machines as above, `settle_seconds = 60`, `rest_seconds = 600`, a state directory of its
own, one run that counts. (Two attempts before it did not: the first ended with `qga-exchange-failed` when the closing
marker of the rest was sent, the guest's agent not answering after the ten minutes, with no further evidence of the cause;
the next two were stopped when the WSL virtual machine itself was restarted while the guest booted, at a time the host's
commit memory was almost used up by other programs. Nothing of them is counted.)

- **The run:** exit **0**, 759 s, no error, both machines `completion_verified`, the guest shut down by its power button,
  the image unchanged, `accepted`. The network stood, the CA was imported, **all ten exchanges passed** and the lab's `qualify`
  said `qualified: true`. The guest was left alone for 60.0 s before the probes and for 600.0 s in the rest.
- **Window `probes`: `NONE`** (64 frames of probes, 4 of markers, nothing else). What the guest was still saying after its
  set-up (DNS questions to the lab resolver, the first connections to the target) came before the opening marker, in the
  frames the report counts as `outside`.
- **Window `rest` (601 s):** `noise: FOUND`, shown and not judged: 470 frames, 24 `infrastructure` and 446 `unexpected`. The
  unicast ARP requests of the guest for the gateway (7) and the lab's answers are `infrastructure`.

| from | protocol | peer | port | frames | class | first (s) | last (s) |
|---|---|---|---|---|---|---|---|
| test | udp | 203.0.113.53 | 53 | 32 | unexpected | 3.357 | 517.991 |
| lab | udp | 203.0.113.53 | 53 | 32 | unexpected | 3.357 | 517.992 |
| test | tcp | 203.0.113.2 | 443 | 118 | unexpected | 3.358 | 528.554 |
| lab | tcp | 203.0.113.2 | 443 | 94 | unexpected | 3.358 | 528.553 |
| test | tcp | 203.0.113.2 | 80 | 85 | unexpected | 3.652 | 518.557 |
| lab | tcp | 203.0.113.2 | 80 | 85 | unexpected | 3.652 | 518.557 |
| test | arp | 192.0.2.1 | request | 7 | infrastructure | 9.412 | 456.413 |
| lab | arp | 192.0.2.2 | reply | 7 | infrastructure | 9.412 | 456.413 |
| lab | arp | 192.0.2.2 | request | 2 | infrastructure | 70.855 | 447.176 |
| test | arp | 192.0.2.1 | reply | 2 | infrastructure | 70.856 | 447.178 |
| lab / test | icmpv6 | link-local addresses | 135, 136 | 6 | infrastructure | 3.527 | 13.514 |

  The names asked for: DNS `ctldl.windowsupdate.com` (A 7, AAAA 11), `config.edge.skype.com`, `msedge.api.cdp.microsoft.com`
  (2 A and 2 AAAA each), `fs.microsoft.com`, `go.microsoft.com`, `settings-win.data.microsoft.com` (one each); TLS server
  names `config.edge.skype.com` (8), `msedge.api.cdp.microsoft.com` (8), `ecs.office.com` (2), `go.microsoft.com` (2),
  `fs.microsoft.com` and `settings-win.data.microsoft.com` (1).
- **Accounting:** the capture has 699 frames, all read: 8 markers, 157 before the first marker, 64 in the window of the probes,
  470 in the rest, none between the windows and none after, and the sum is 699 (`accounting.complete`).

### What can be done about it (proposals, none applied, all UNRUN)

The owner's decision of 2026-11-20 is that these settings are **planned for the next rebuild of the image** (with stage
10c) and not made now; the rest is listed meanwhile.

Each is a standard setting of the operating system, so a step of `first-logon.ps1` and a new build of the image by the
qualifier, not an exception in the observer; the sources are the pages of Microsoft Learn on connection endpoints
and on managing connections from Windows components. Whether a setting does what the page says on this build is what a
new resting capture decides.

| Seen at rest | Setting the documentation names | Remark |
|---|---|---|
| `ctldl.windowsupdate.com` (A, AAAA, TCP 80), the most frequent | `HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot\DisableRootAutoUpdate` = 1 (policy "Turn off Automatic Root Certificates Update") | the page warns that sites may stop working; it is the component that checks the trust list when a chain is built, as the HTTPS probe does with the lab CA |
| `fs.microsoft.com` (font streaming) | `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableFontProviders` = 0 (policy "Enable Font Providers" disabled), restart | |
| `msedge.api.cdp.microsoft.com` (Edge update), `config.edge.skype.com` (Edge configuration) | Edge policies `EdgeUpdate\UpdateDefault` = 0, `AutoUpdateCheckPeriodMinutes` = 0 and `ExperimentationAndConfigurationServiceControl` = 0 | the image already disables the updater's services and policy, so another component may be the one that asks: which is not known |
| `settings-win.data.microsoft.com` | listed under "Settings" (apps update their configuration); the page names no switch of its own | `AllowTelemetry` = 0 and the services are already off |
| `mobile.events.data.microsoft.com`, `ecs.office.com`, `go.microsoft.com` | not on those pages | |
| unicast ARP requests for the gateway | none: it is the stack's neighbor reachability check | done: the classifier takes this one frame as `infrastructure` (see "Decisions of 2026-11-20") |

The other way is to make the lab not answer these names (the resolver would refuse them, so nothing follows the question).
That changes the lab, not the image, and with it what "rest" means; it is not done here either.

### Not done here, UNRUN

- Nothing qualifies: the image is `qualified: false`, the run is diagnostic, and no parity table or gate is touched.
- Only a run of ten minutes of rest has been seen (see below). Whether the guest's noise changes after longer rest, after a
  reboot or with the real Internet is not known; stage 10 scenarios (WFP) are not started.
- IPv6 has the lab's static address and default route; no router advertisement, DHCPv4 or DHCPv6 server exists in the lab, so
  nothing says what the guest does when it is offered them.
- The probes go from the guest's own PowerShell; the HTTPS probe uses `SslStream`, not `curl.exe` or `Invoke-WebRequest`, so that the
  request has the exact bytes the target accepts for its exchange.
- A controller killed in the middle of the run is not attached (`recover --close` and a new run).

### What to reinstall

Nothing in the images: the lab machine's `lab-entry.py` and its pinned fixtures are those of stage 8, and `lab_protocol.py`
gains only `classified_frames`, which runs on the controller.

## Stage 10a: the List matrix of a Windows guest in the lab, `windows-list`

Status: **offline tests, and the developer's runs on the stand written below, which qualify nothing.** The Windows guest of
the 9a image is on the wire of the lab, as in stage 9d, but now with Rosetun in it: the eleven checks of the Hyper-V List
matrix (`tools/vm/windows/Invoke-ListMatrix.ps1`, `list-checks.json`, the same ids) run in the guest against the lab's
targets, Rosetun connects to the lab's VPN node, and the observer judges the wire. The release gate is false, the security
invariants are UNVERIFIED, the image stays `qualified: false` and the run is diagnostic whatever it reports. The image is
not changed (the network and the CA still come through the agent, as in 9d); Linux suites, configurations and budgets are
unchanged.

### Decisions

- **Delivery without a network: a read-only disc.** The guest has the lab's wire and nothing else, and what crosses that wire
  is the observer's. The agent's file calls are no way for 80 MB (a session has 128 calls and a megabyte of room in each
  direction). So the run makes an ISO (`windows_media`, `xorriso`, label `ROSETUNLIST`, ISO 9660 level 3 with long Joliet
  names) of the three binaries, the runner and its plan, and QEMU gives it to the guest as a DVD drive on the machine's own
  SATA controller (`-device ide-cd,drive=winmedia,bus=ide.2`, `lab.LabPair(media=True)`, a read-only raw block device). The
  drive is a launch option, not a change of the image: the image file is byte for byte what it was, and the run still checks
  that (`image-unchanged`). The controller hashes each file against a pin (the build of the checkout by the configuration,
  sing-box by the matrix), writes the record `windows-media.json`, and hashes the disc again right before the guest starts;
  the starter script carries the hash of each runner file and the plan names the hash and size of each binary, which the
  runner checks after it copied them (a mismatch ends the run). Not chosen: the agent's file calls (too small), a file server
  on the lab machine (the lab image is frozen, and the transfer would be frames of the observer's capture).
- **The build.** The Windows binaries are those of the checkout, built on the Windows host with a target directory off the
  system drive: `cargo build --release -p rosetun -p rosetun-helper-privileged --target-dir E:\rosetun-target-win` (the GUI is
  not needed). `sing-box.exe` is the pinned 1.14.3 of `Install-RosetunSingBox` (`5c19bb3f...faf`); the validator refuses any
  other hash, so the Windows and Hyper-V matrices run the same engine.
- **How Rosetun runs in the guest.** As in the Hyper-V List: the console helper `rosetun-helper-privileged.exe` as a
  scheduled task `RosetunHelper` (SYSTEM, log to a file), the CLI `rosetun.exe connect` and `apply` with `ROSETUN_CONFIG` on
  an isolated configuration (version 3 of the format, as the Hyper-V script writes it, so the same migration reads it). No
  installer and no service: the stage is the List, not the installation. **The runner is autonomous**: the controller
  starts it once (a PowerShell that finds the disc, copies and hashes five small files, makes the task `RosetunListRunner`
  and starts it), and from then on only reads `C:\rosetun-list\status.json` with `cmd /c type` (two calls) every
  `poll_seconds`; the runner rewrites that file whole after every step (a temporary file and a replace), so a lost agent
  session costs a new session (counted in `qga_recoveries`) and not the run. The controller sends nothing else meanwhile.
  The runner keeps the artifacts of the Hyper-V matrix as well (`RosetunListResults.psm1`: `plan.json`, `events.jsonl`,
  `report.json`, `status.json`), which the controller copies out and assesses with the existing `windows_list` adapter, the
  identity being the VM's UUID and the guest's own count of boots.
- **Cleanup**, as in the Hyper-V matrix and more: `rosetun disconnect`, the closing marker only when `rosetun status` says
  `Disconnected` and `protection: none`, the list directory removed, the helper stopped hard, `rosetun-helper-privileged
  --reset-firewall` (exit 0), the task unregistered, the tunnel adapter gone, the binaries removed. The runner says PASS,
  ERROR or UNVERIFIED for it, and then the controller reads the guest again with a script of its own (the helper task and
  process, the engine process, the adapter, the binaries, the list directory, and the runner's own task and directory,
  which it removes): a leftover is a finding. The guest is shut down by its power button and the overlay is thrown away, but
  the cleanup is done and read all the same.

### The checks and the lab

| id | Hyper-V | lab |
| --- | --- | --- |
| `baseline.egress` | `curl --interface <physical>` to `https://1.1.1.1` | the same curl to `https://203.0.113.2/` (the lab's HTTPS target, certificate checked against the lab CA) |
| `baseline.dns` | a UDP question for `example.com` to `1.1.1.1:53` from the physical address | a UDP question for a name of the run to the lab's resolver `203.0.113.53:53`, from `192.0.2.2` |
| `text.connect` | `connect` with a text list holding `example.com` | the same, the list holds `listed.lab.test`, the node is the lab's `192.0.2.1:8388` |
| `text.tunnel` | `https://example.org` through the tunnel (curl's local address is the tunnel's) | `https://unlisted.lab.test/` (DNS through the tunnel to the lab's DoH, local address the tunnel's, remote address the target's, HTTP 200) |
| `text.block` | `https://example.com` is blocked | `https://listed.lab.test/` is blocked |
| `text.physical` | direct curl to `1.1.1.1` fails | direct curl to the target from the physical address fails |
| `binary.compile` | `sing-box rule-set compile` of `domain_suffix example.com` | the same for `listed.lab.test` |
| `binary.apply` | `apply` of the compiled list, state `Connected` | the same |
| `binary.direct` | `example.com` opens with the Direct rule | `listed.lab.test` opens with the Direct rule: the engine connects to the target itself |
| `binary.default` | `example.org` follows the Block default | `unlisted.lab.test` follows the Block default |
| `binary.physical` | direct curl fails | the same as `text.physical` |

The lab's resolver and its DoH target answer any name of the lab with the target's address, so a name stands for a domain with
the same meaning: listed, or not, and then the rule decides. What is not the same: the target's certificate has an IP address
and no name, so the requests by name use `--insecure` (the routing is what is checked, not the certificate; the answer must
still come from the target's address with HTTP 200); and the lab has no real Internet, so the Hyper-V matrix's "reachable from
the node's exit" is "reachable from the lab's router".

### The windows and what they are judged by

The runner marks two windows with the markers of the lab (UDP to the marker service, sent by the guest, acknowledged by the
lab, never sent twice):

| Label | From | To | What is judged |
| --- | --- | --- | --- |
| `baseline` | the marker, before the connect | the marker, after `baseline.dns` | **listed, not judged** (`baseline_noise`, `baseline_table`): what a Windows guest says before a tunnel stands is its own, as in the rest of 9d. That the direct probes work is what the guest's checks say and the lab confirms: the window must show the connection to the target (`disagree:baseline.egress` otherwise) and the lab's resolver must have logged the name (`disagree:baseline.dns`). |
| `session` | just before `rosetun connect` | `protection: none` after `disconnect` (a closing marker that cannot go out because the protection is still there is an unclosed window: unverified) | **judged, with no tolerance by name.** Expected flows (`SESSION_EXPECTED`): the node's connections (category `tunnel`) and exactly one direct TCP connection to the target (`binary.direct`, the Direct rule: the engine's own connection past the tunnel, by design). Anything else outside `infrastructure` is `DETECTED`: Windows' own names (Microsoft endpoints) have to go into the tunnel, or not leave at all while the kill switch is up, and a direct frame under the kill switch is a leak. Fewer flows than expected is `MISMATCH`, which contradicts `binary.direct`. |

### Command, configuration, summary

    python3 -B -m tools.vm.matrix run windows-list --config CONFIG [--dry-run]

The configuration is `execution-windows-list.example.toml`, schema `rosetun.matrix.execution.windows.v3`: the fields of the
other Windows suites with a `[list]` of the times (`agent_wait_seconds`, `script_seconds`, `settle_seconds`, `runner_seconds`,
`poll_seconds`, `shutdown_wait_seconds`), the `xorriso` of the host, the paths and SHA-256 of `rosetun.exe` and
`rosetun-helper-privileged.exe`, and the sing-box with the pinned hash, and the `[lab]` block of 9d. The lab capture lasts
`agent_wait + 3 * script + 120 + settle + runner + 300` seconds and may not pass the observer's 2700. `--lab`, `--control` and
`--diagnostic` are refused; `attach` does not take this suite. The host must have 4 GiB, the lab's 2 GiB and 768 MiB free
(`host-memory-too-small`), as in 9d.

The steps are those of 9d up to `evidence-disk`, then `media`, the lab's start, `media-unchanged`, `start-test`, `boot-test`,
`wire-close`, `network`, `certificate`, `settle`, `start-runner`, `runner` (the polls), `collect`, `assess`, `after`,
`lab-finish`, `lab-read-*`, `shutdown-test`, `close-*`, `evidence-read`, `windows`, `image-unchanged`. The first exchange after
each wait (the settling) is guarded by the ping of 9d, and a poll that fails is tried again on a new session up to three
times; a session close to its 128 calls is replaced before the poll that would pass them.

The summary (`rosetun.matrix.windows-list-summary.v1`, in both runs) has `execution` with the network, the certificate, the
disc (`media`: the hash of every file and of the ISO), the runner (state, step, notes, the seconds, the polls), `checks` (the
eleven), `assessment` (the Hyper-V adapter's verdict on the artifacts), `markers`, `cleanup` (the runner's and what the
controller found left), `identity`, `windows` (leak, verdict, flows and expectation of each), `fixtures`, `baseline_*`,
`findings` and `unverified`. The artifacts of the Hyper-V matrix are in the test run's `windows-list/`.

Exit code, by the convention of the matrix: **0** when all eleven checks pass, the window `session` is `EXPECTED`, the wire
agrees with the guest, the four fixtures of the lab answered, the artifacts are assessed accepted and the cleanup is `PASS` and
nothing is left; **1** for a finding (`findings`): a check that failed, a window `session` that is `DETECTED` or `MISMATCH`, a
pass the wire contradicts, a cleanup that failed or left something (a finding stands whatever else went wrong); **2** when
the run cannot vouch for itself (`unverified`): an error, a runner that did not end in `runner_seconds`, a check that did not
run, artifacts the assessment refuses, a window or a marker that was not observed whole, a fixture that did not answer, a
cleanup nobody could read, a guest that is not the machine the controller started; **130** for an interruption.

### Offline tests

`tests/test_windows_list_lab.py`: the disc (names, pins, a file that changes while it is copied, the size limit, a tool that
fails, the disc changed before the start), the plan and the start script, the status file (shape, every refusal, the markers),
the drive and the resources, the configuration (every field strict, the example), and the whole run on fakes: the order, what
is sent to the guest between the start and the end of the runner (only reads of the status), every verdict and exit code above,
a poll that fails, a session near its calls, a runner that never ends. The runner itself is a PowerShell script checked on the
stand; `tools/vm/windows/tests/Test-RosetunScriptArguments.ps1` parses it.

### Checked on the stand (2026-11-20, a developer's runs, not a qualification)

Debian 13 on WSL2 (7.9 GB), QEMU 10.0.13, the image of 9a (`windows-11-26h2-pro-v1`), the lab image `lab-v5m`, a state
directory of its own (`state-10a-dev`), the Windows build of the checkout (`rosetun.exe`, `rosetun-helper-privileged.exe`) and
the pinned sing-box 1.14.3. The checkout was not clean (this stage's files). Five runs; the first three are told as they were:

1. **Exit 1.** The runner failed before its first check: its task passed the drive of the disc as `F:\` inside quotes, and a
   trailing backslash ends the quote on a command line. Its cleanup then failed on a task that was already gone (`.State` of
   nothing under strict mode) and overwrote the first error in the status. Fixed: the runner takes the drive letter, treats an
   absent task as absent, and keeps the first error (a later one is appended to its text). The controller read all of it
   honestly: `cleanup-error`, `cleanup-left:binaries`, unverified windows.
2. **Exit 0** (all eleven PASS, window `session` `EXPECTED`).
3. **Exit 1, `window-detected:session`.** The window `session` held two frames of the probe's connection of the window
   `baseline` (the lab's FIN and the guest's ACK, 0.09 s after the closing marker of the baseline and 0.06 s after the opening
   marker of the session): the target closes a connection a moment after the guest, and the runner opened the next window 26 ms
   after it closed the previous one. This is not noise to allow but an edge of the runner's own: it now waits three seconds
   before the closing marker of the baseline, so that the close lands in its own window. No tolerance was added, nor any
   exception in the observer.
4. and 5. **Exit 0 twice in a row**, the runs below, with the code that is committed.

| run | exit | duration | checks | `baseline` (listed) | `session` | cleanup |
| --- | --- | --- | --- | --- | --- | --- |
| `780f7cd0...` | 0 | 189.2 s | 11 PASS | probe 2, unexpected 15 (one HTTPS connection to the target: 9 frames out, 6 back) | `EXPECTED`: tunnel 168, infrastructure 2, unexpected 17 (the one direct connection to the target) | runner `PASS`, nothing left, assessment `PASS` |
| `c3f109a5...` | 0 | 189.1 s | 11 PASS | probe 2, unexpected 15 (the same) | `EXPECTED`: tunnel 169, unexpected 18 (the same one connection) | runner `PASS`, nothing left, assessment `PASS` |

Both: `completed`, both machines `completion_verified`, the guest shut down by its power button, the image unchanged, the four
fixtures of the lab answered (the node alive, the target answering the guest directly and the node's exit, the resolver and
the DoH target), the four markers sent once and acknowledged, no QGA recovery. The runner took 20 s of the 189 (the first launch
of sing-box took 1 to 2 s, Defender did not delay it; the ping before the runner was answered at the first try), and one read of its status found it finished.

What the wire said of Windows: before the session the guest said nothing of its own in the window `baseline` of these two runs
(after the 60 s of settling). In the failed third run it had made two connections to the target's port 80 (a name of its own
that the lab's resolver answers with the target: the chain check of the certificate, as `ctldl.windowsupdate.com` in 9d), which
the runner's windows listed and did not judge. Inside the session no frame of Windows' own went outside the tunnel in any run;
a longer observation (the 600 s of the rest of 9d with a tunnel up) is not part of this stage, so what Windows says over a
longer session is not known.



### Not done here, UNRUN

- Nothing qualifies: the image is `qualified: false`, the run is diagnostic, and no parity table or gate is touched.
- The Hyper-V List and this run were not compared on the same day or the same build; the table above is a correspondence of
  meaning, not a result.
- IPv6 is the lab's static address; the checks use IPv4 only, as the Hyper-V ones.
- No run with the kill switch of other suites (Failure, Lockdown, Proxy, LAN, Upgrade): stages 10b to 10e.
- A controller killed in the middle of the run is not attached (`recover --close` and a new run).

### What to reinstall or build

Nothing in the images. The Windows binaries (build above), the configuration with their hashes, and `xorriso` on the host.

## Stage 10b: the Failure core of a Windows guest in the lab, `windows-failure`

Status: **offline tests, and the developer's runs on the stand written below, which qualify nothing.** Each run executes one
selected case of the Failure core (`engine-killed`, `helper-killed`, `no-network`, `apply-rules`, `reconnect`, `temporary`
or `dns-lock`) on a fresh disposable Windows guest against the isolated lab wire, reusing the stage 10a read-only ISO
delivery (`rosetun.exe`, `rosetun-helper-privileged.exe`, pinned `sing-box.exe` 1.14.3, `lib.ps1`, `run-windows-failure.ps1`,
`failure-probes.ps1`, `RosetunListResults.psm1`) and autonomous runner loop. The release gate stays false, the security
invariants stay UNVERIFIED, the image stays `qualified: false`, and `full_matrix` is recorded as `UNVERIFIED`.

### Cases, windows and calibration

Each case selects its slice of `tools/vm/windows/failure-core.tsv`: the four physical baseline checks, the four connect
checks (`connect.state-is-connected`, `connect.tunnel-carries-traffic-within-5-s-dns-included`,
`connect.direct-egress-is-blocked`, `connect.ipv6-outside-the-tunnel-is-blocked`), and the case's own scenario group(s):

- `engine-killed` (17 checks): kills `sing-box` under the kill switch, checks `FailedProtected` and blocks across IPv4,
  IPv6 and DNS, then disconnects and checks recovery.
- `helper-killed` (12 checks): kills `rosetun-helper-privileged` and its task hard, checks that `sing-box` and the TUN
  adapter disappear, the kernel closes the dynamic WFP session, and direct IPv4/IPv6/DNS return.
- `no-network` (15 checks): disables the physical adapter before `connect`, verifies `Failed` / `NoNetwork` within 10 s
  with no WFP filters, TUN adapter or engine, re-enables the adapter and verifies connect and block.
- `apply-rules` (14 checks): applies a rule set over a connected session without changing the node and checks tunnel
  traffic and direct IPv4/IPv6 blocks.
- `reconnect` (16 checks): reconnects with a background direct-egress probe running and verifies zero leaks across the
  restart, unchanged node, WFP persistence and tunnel traffic.
- `temporary` (18 checks): applies a temporary direct rule for `listed.lab.test` with a `block` default, verifies the
  listed domain goes direct while `unlisted.lab.test` and direct IP egress stay blocked, then disconnects and reconnects
  with the base request to confirm zero temporary rules remain.
- `dns-lock` (12 checks): connects with `kill_switch = false` (DNS lock only) and verifies tunnel traffic, direct DNS
  block and IPv6 block outside the tunnel.

The runner marks **three** windows on the wire (`baseline`, `session`, `recovery`):

- `baseline` (listed, not judged for background noise) and `recovery`: both ends of the run calibrate all four physical
  paths on the wire (IPv4 HTTPS to `203.0.113.2:443`, IPv6 HTTP to `[2001:db8:6a:2::2]:8080`, UDP DNS and TCP DNS for the
  run's control name). If any of the four is missing from the wire or resolver log, the run is marked `unverified`
  (`control-flow-missing:<phase>` or `control-dns-missing:<phase>:<transport>`): a refused probe in `session` is not
  accepted unless both ends prove the physical path works.
- `session`: strictly judged with no tolerance by name. Every case except `temporary` expects **zero** direct flows
  (`verdict: EXPECTED` with `leak: NONE`); `temporary` expects **one** direct TCP flow to `203.0.113.2:443` (the temporary
  direct rule). If `connect.tunnel-carries-traffic-within-5-s-dns-included` passes without tunnel frames on the wire,
  cross-checking raises `disagree:connect.tunnel-carries-traffic-within-5-s-dns-included`.

### Post-cleanup WFP verification

After the runner finishes and reports its own cleanup, the controller runs `_AFTER` in the guest. In addition to checking
tasks, processes, tunnel adapter, binaries and directories, `_AFTER` captures `netsh.exe wfp show state` into temporary
files under `$env:TEMP` (redirecting stdout/stderr and removing the temporary files in `finally`), fails closed if the
snapshot is unavailable or incomplete (`<wfpstate>`, `</wfpstate>`, `<providerKey>`, `<subLayerKey>`), and checks that
neither the Rosetun WFP provider (`51a47ec7-6459-4b84-8854-075e1576e7f9`) nor sublayer
(`0c035ef5-4c5c-4583-ad9c-179791360f5e`) remains. Any leftover (`wfp_provider`, `wfp_sublayer`, or other resource) is a
finding (`cleanup-left:...`).

### Command, configuration, summary and omissions

    python3 -B -m tools.vm.matrix run windows-failure --config CONFIG [--dry-run]

The configuration is `execution-windows-failure.example.toml`, schema `rosetun.matrix.execution.windows.v4`, with
`[failure]` (`case` plus the timing, `xorriso` and binary hash fields of `[list]`). `report` refuses `windows-failure`
without wire evidence. Summary schema: `rosetun.matrix.windows-failure-summary.v1`.

Omitted from `windows_failure.selected()` (catalog `failure-core.tsv` stays intact, and the plan's `limitations` state
this explicitly):
- `engine-killed.server-check-works-under-protection` and `dns-lock.server-check-works-with-the-dns-lock` (alongside
  `connect.server-check-works-while-connected`): `rosetun probe` tests hardcoded public HTTPS endpoints unreachable on the
  isolated lab wire.
- `reconnect.state-is-connected-after-engine-kill` and `reconnect.no-leak-while-reconnecting`: post-crash reconnect phase
  kept separate from the in-session `reconnect` group.

### Offline tests

`tests/test_windows_failure.py`: catalog slices and check IDs for all 7 cases against `run-windows-failure.ps1`, job plan
and IPv6/request fields, start script and `SCRIPT_LIMIT_MAX`, schema `windows.v4` validation and `execution-windows-failure.example.toml`,
CLI `plan` and `report` refusal without wire evidence, full synthetic runs across `engine-killed`, `temporary` and
`dns-lock`, missing calibration flow/DNS (`exit_code == 2`), unexpected/missing direct flows in `session` (`exit_code == 1`),
and leftover `wfp_provider` / `wfp_sublayer` findings (`exit_code == 1`). `tools/vm/windows/tests/Test-RosetunScriptArguments.ps1`
parses `run-windows-failure.ps1` and `failure-probes.ps1`.

### Checked on the stand (2026-11-23, developer runs, not a qualification)

Debian 13 on WSL2 (7.9 GB), QEMU 10.0.13, `windows-11-26h2-pro-v1`, `lab-v5m`, dedicated state directory `state-10b-dev`,
Windows release build of the checkout and pinned `sing-box` 1.14.3 (working tree dirty with this stage's changes). Three
cases run back-to-back with the final code:

| case | run | exit | duration | checks | `session` window | cleanup |
| --- | --- | --- | --- | --- | --- | --- |
| `engine-killed` | `197b6966...` | 0 | 213.6 s | 17 PASS | `EXPECTED` (`leak: NONE`, tunnel 80, unexpected 0) | runner `PASS`, `left: []` (WFP clean) |
| `temporary` | `f0616df2...` | 0 | 213.7 s | 18 PASS | `EXPECTED` (tunnel 209, 1 expected direct flow, unexpected 17) | runner `PASS`, `left: []` (WFP clean) |
| `helper-killed` | `caf0e8cd...` | 0 | 213.2 s | 12 PASS | `EXPECTED` (`leak: NONE`, tunnel 78, unexpected 0) | runner `PASS`, `left: []` (WFP clean) |
| `no-network` (2026-11-24, `lab-v5n`) | `48956fb2...` | 0 | 205.3 s | 15 PASS | `EXPECTED` (`leak: NONE`, tunnel 89, unexpected 0) | runner `PASS`, `left: []` (WFP clean) |
| `apply-rules` (2026-11-24, `lab-v5n`) | `c461dd9b...` | 0 | 206.5 s | 14 PASS | `EXPECTED` (`leak: NONE`, tunnel 174, unexpected 0) | runner `PASS`, `left: []` (WFP clean) |
| `reconnect` (2026-11-24, `lab-v5n`) | `3e84af9d...` | 0 | 210.3 s | 16 PASS | `EXPECTED` (`leak: NONE`, tunnel 183, unexpected 0) | runner `PASS`, `left: []` (WFP clean) |
| `dns-lock` (2026-11-24, `lab-v5n`) | `84a36adc...` | 0 | 204.8 s | 12 PASS | `EXPECTED` (`leak: NONE`, tunnel 177, unexpected 0) | runner `PASS`, `left: []` (WFP clean) |

All seven runs: `accepted: true`, `findings: []`, `unverified: []`, `image_unchanged: true`, all four lab fixtures
answered (`dns`, `doh`, `https` direct and `via_node`, `node`), all six markers sent once and acknowledged, guest shut
down via ACPI. Live verification of the four remaining cases caught and fixed two guest-script bugs: resolving the
physical adapter `-Name` for `Disable-NetAdapter`/`Enable-NetAdapter` in `no-network`, and outer-quoting the
`cmd.exe /d /c` command line in `Start-FailureEgressWatch` for `reconnect`.

### Not done here, UNRUN

- Nothing qualifies: `qualified: false`, diagnostic runs only, no release gate or Hyper-V parity table is touched.
- Extended protocols, second-node, two-hop, and DHCP fixtures: stage 10f.

## Stage 10c: Windows Lockdown (`windows-lockdown`) and controller `power_cycle`

`run windows-lockdown` exercises Rosetun Lockdown on the isolated two-machine wire (`lab-v5m` + `windows-11-26h2-pro-v1`),
covering Scenarios 1–2 and 4–10 (Lockdown on while disconnected, Lockdown with an active tunnel, helper crash/restart
under Lockdown, clean reboot with boot-time Lockdown persistence, abrupt power cuts while Lockdown is active/connected,
`lockdown off`, `reset-firewall`, and `uninstall`). Every run stays `qualified: false` and diagnostic only.

### Controller `power_cycle` capability

To simulate hard power loss without leaving the run or discarding the guest's disk/UEFI/TPM state:

- `lifecycle.Vm.power_cycle()` kills the running `test` QEMU process (`SIGKILL`) and terminates its paired `swtpm`,
  records `power-cycle-N` in `run-state.json` (with a strict per-run `planned_power_cuts` budget), closes the old QMP/QGA
  handles, and restarts `swtpm` + QEMU inside the **same run** on the same `root.qcow2` overlay, `OVMF_VARS.fd`, `tpm/`
  directory, `vm_uuid`, and `windows-media.iso`.
- Each restarted generation is registered in `manifest.json` as `qemu-N` / `swtpm-N` (starting at `1`), stderr continues
  into `qemu-stderr.log` in append mode, and `lifecycle.attach()` selects the highest `qemu`/`qemu-N` and
  `swtpm`/`swtpm-N` generation so `recover --close` works on post-`power_cycle` runs.
- `lab._WireRelay` is framing-aware (`uint32` big-endian Ethernet frame length prefix) and reconnectable on the `test`
  socket while keeping the `lab` socket and `capture.pcap` stream continuously open: an abrupt disconnect mid-frame on
  the `test` side discards the partial frame without corrupting the `lab` stream, and `prepare_test_reconnect()` accepts
  the restarted `test` VM seamlessly.

### Guest suite, cases and wire windows

Catalog: `tools/vm/windows/lockdown-core.tsv` (72 checks in total across Scenarios 1–2 and 4–10). Guest runner:
`tools/vm/windows/guest/run-windows-lockdown.ps1` (64,461 bytes, below the 65,536-byte QGA script limit). Three cases
are supported under `[lockdown]`:

- `core` (`power_cut_repeats = 0`, single boot): 57 checks, 3 wire windows (`baseline`, `lockdown-core`, `recovery`).
- `reboot` (`power_cut_repeats = 1..3`, multi-boot): 18–24 checks (`1 + 1 + 2 * repeats` boots), 3 wire windows
  (`baseline`, `reboot-lockdown`, `recovery`).
- `full` (`power_cut_repeats = 1..3`, multi-boot; canonical `power_cut_repeats = 3`, `power_cut_delay_seconds = 2`):
  72 checks across 8 distinct boots (`1` initial boot + `1` clean guest reboot + `6` abrupt power cuts), 4 wire windows
  (`baseline`, `lockdown-core`, `reboot-lockdown`, `recovery`).

How the four wire windows are judged:

- `baseline` and `recovery` (calibration only, `verdict: null`): verify direct IPv4 HTTPS (`203.0.113.2:443`), direct
  IPv6 HTTP (`[2001:db8:6a:2::2]:8080`), and plain UDP + TCP DNS (`203.0.113.53:53`) work before Lockdown and after
  Lockdown teardown/uninstall. Missing calibration flows or DNS are recorded as `unverified` (`exit_code == 2`).
- `lockdown-core` (judged): expects **one** direct TCP flow (`203.0.113.2:443`, corresponding to
  `on.cli-path-egress-open` while Lockdown permits only the configured Rosetun CLI/helper egress path) plus tunnel frames
  for `connected.tunnel-carries-traffic`, and zero other unexpected traffic.
- `reboot-lockdown` (judged): opens immediately before enabling Lockdown prior to the clean Windows reboot and closes
  immediately after `rosetun lockdown off` on the post-reboot desktop (with a 2 s settle delay before `lockdown off` so
  OS background probes cannot wake before the UDP close marker is sent). Expects **zero** direct flows (`leak: NONE`),
  tunnel frames for `reboot.connect-opens-tunnel`, and grants `REBOOT_ALLOWANCES = ('ipv6-dad', 'arp-probe', 'arp-announcement')`
  only for genuine RFC 4862 / RFC 5227 address-duplication frames emitted by Windows during reboot.
- Multi-boot invariants: `boot_chain` must contain `1 + planned_reboots + planned_power_cuts` distinct `win-*` boot IDs,
  and `guest_resets` / `power_cycles` must match the planned counts; any mismatch marks the run `unverified` (`exit_code == 2`).

### Post-cleanup Lockdown verification

After the runner finishes and reports its own cleanup, the controller runs `_AFTER` in the guest. Beyond the standard
task/process/adapter/binary/directory and session WFP checks, `_AFTER` inspects `netsh.exe wfp show state` for the
Lockdown WFP provider (`f12dbedd-f3c7-4a72-b0f8-20559c88b112`) and sublayer (`f829a64d-c373-4d92-9d66-e1c680f3794f`),
verifies the `Rosetun` service, `RosetunLockdownResume` / `RosetunLockdownBootCheck` tasks, and the temporary
`RosetunMatrixUser` standard user are absent. Any leftover raises `cleanup-left:...` (`exit_code == 1`).

### Command and configuration

    python3 -B -m tools.vm.matrix run windows-lockdown --config CONFIG [--dry-run]

The configuration is `execution-windows-lockdown.example.toml`, schema `rosetun.matrix.execution.windows.v5`, with
`[lockdown]` (`case`, `power_cut_repeats`, `power_cut_delay_seconds`, plus the timing, `xorriso`, and pinned binary hash
fields). `report` refuses `windows-lockdown` without wire evidence.

### Offline tests

`tests/test_windows_lockdown.py`: catalog slices and check-ID parity against `run-windows-lockdown.ps1`, QGA payload and
`status.json` size ceilings for 72 checks, schema `windows.v5` validation and `execution-windows-lockdown.example.toml`,
CLI `plan` and `report` refusal, `run_state` / `resources` / `diagnostics` power-cut extensions, framing-aware
`_WireRelay` survival across abrupt `test` disconnect, `lifecycle.Vm.power_cycle()` budget enforcement,
`lifecycle.attach()` latest `qemu-N`/`swtpm-N` generation selection, and full synthetic multi-boot runs (8 boots,
`core`, `reboot` leak detection, leftover Lockdown WFP/task/user findings, and truncated `boot_chain` `unverified`).
`tools/vm/windows/tests/Test-RosetunScriptArguments.ps1` parses `run-windows-lockdown.ps1`.

### Checked on the stand (2026-11-23 / 2026-11-24, developer runs, not a qualification)

Debian 13 on WSL2, QEMU 10.0.13, `windows-11-26h2-pro-v1`, `lab-v5m`, dedicated state directory `state-10c-dev`,
Windows release build of the checkout and pinned `sing-box` 1.14.3, canonical `settle_seconds = 60`,
`power_cut_repeats = 3`, `power_cut_delay_seconds = 2` (working tree dirty with this stage's changes):

| case | run | exit | duration | checks | boots (`boot_chain`) | judged windows | cleanup |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `core` | `b0961bce...` | 0 | 311.6 s | 57 PASS | 1 (`win-4`) | `lockdown-core: EXPECTED` (tunnel 199, 1 expected direct flow, unexpected 15) | runner `PASS`, `left: []` |
| `full` (run 1) | `7d11bd8f...` | 0 | 623.8 s | 72 PASS | 8 (`win-4`..`win-11`, 1 reboot + 6 cuts) | `lockdown-core: EXPECTED` (tunnel 197, 1 expected direct flow, unexpected 17); `reboot-lockdown: EXPECTED` (`leak: NONE`, tunnel 86, unexpected 0, allowed `arp-probe: 3, arp-announcement: 2`) | runner `PASS`, `left: []` |
| `full` (run 2) | `620e1b8f...` | 0 | 622.7 s | 72 PASS | 8 (`win-4`..`win-11`, 1 reboot + 6 cuts) | `lockdown-core: EXPECTED` (tunnel 211, 1 expected direct flow, unexpected 15); `reboot-lockdown: EXPECTED` (`leak: NONE`, tunnel 84, unexpected 0, allowed `arp-probe: 3, arp-announcement: 2`) | runner `PASS`, `left: []` |

All three runs: `accepted: true`, `findings: []`, `unverified: []`, `image_unchanged: true`, both `-lab` and `-test`
`completion_verified: true`, zero leftover Lockdown/session WFP providers/sublayers, tasks, services, or users. Live
bring-up also caught and fixed: `attach()` generation lookup for post-`power_cycle` `qemu-N`/`swtpm-N` processes;
Windows RFC 5227 IPv4 DAD frames (`arp-probe` + `arp-announcement`) during clean reboot; moving the 2 s settle sleep
before `rosetun lockdown off` so post-reboot OS probes cannot fire before the UDP close marker; and adding a 5 s pause
after restoring the helper at the end of Scenario 5 so OS background retries woken by TUN teardown settle before
`reboot-lockdown` opens.

### Not done here, UNRUN

- Nothing qualifies: `qualified: false`, diagnostic runs only, no release gate or Hyper-V parity table is touched.
- Scenario 3 (LAN / inbound listener), DHCP renewal, sleep/resume, and real hardware power loss are out of scope here.
- Remaining Windows suite (Upgrade): stage 10e.

## Stage 10d: Windows Proxy (`windows-proxy`) and Local Network (`windows-lan`)

`run windows-proxy` and `run windows-lan` run the Windows Proxy and Windows Local Network (LAN) suites on the isolated
two-machine wire (`lab-v5n` + `windows-11-26h2-pro-v1`), keeping `qualified: false` and diagnostic-only status.

### Lab image `lab-v5n` and controller `lab-action-requested` protocol

Built from untouched `lab-v5m` with updated `lab-entry.py`, `lab_protocol.py`, and the lab CA certificate at
`/usr/local/share/ca-certificates/rosetun-lab-ca.crt`:

- **LAN & Proxy fixtures (`lan_fixtures = true`):**
  - Second peer address `192.0.2.20` (`LAN_PEER`) on the lab wire interface, plus a routed VPN node `203.0.113.10`
    (`ROUTED_NODE`) and a blackholed private-behind-router IP `10.255.255.1` (`PRIVATE_BEHIND_ROUTER`) with a TCP
    listener on `:80` inside the lab router.
  - Peer TCP fixtures on `192.0.2.20` and `192.0.2.1`: listener (`:19080`), echo (`:19081`, used for the 600 s long
    session), hold-open (`:19082`), and UDP/multicast capture for mDNS (`224.0.0.251:5353`), SSDP
    (`239.255.255.250:1900`), and limited broadcast (`255.255.255.255:19083`).
  - Lab `sing-box` node configuration adds UDP DNS server `lab-dns` (`203.0.113.53`, replying `203.0.113.2` for
    `listed.lab.test`) with `route.default_domain_resolver = "lab-dns"` so domain-targeted proxy probes resolve inside
    the isolated lab.
- **Controller-mediated lab actions (`lab-action-requested`):**
  - Both runners stay on the guest side of the wire and request out-of-band lab probes through `status.json`
    (`state: "lab-action-requested"`, `action: {id, kind, ...}`), which the host controller dispatches to `lab-entry.py`
    via QGA and writes back to `<ROOT>\lab-action-result.json`.
  - Supported actions: `probe_proxy` (from `192.0.2.20` or `192.0.2.1` to the guest's shared HTTP/SOCKS5 proxy port,
    verifying direct, tunneled, auth, and blocked behavior) and `lan_state` (reading observed peer tokens/connections
    and starting/stopping the hold-open listener).

### Windows Proxy (`windows-proxy`)

- Catalog: `tools/vm/windows/proxy-checks.json` (46 checks covering strict proxy, auth, rules, desktop WinINet
  apply/restore/crash-restore under a temporary `RosetunProxyUser` profile, LAN sharing, and Lockdown + shared proxy).
- Guest runner: `tools/vm/windows/guest/run-windows-proxy.ps1` (46,083 bytes, below the 65,536-byte QGA limit);
  uses a pinned `desktop_proxy.exe` binary alongside `rosetun.exe`, `rosetun-helper-privileged.exe`, and `sing-box.exe`.
- Five wire windows: `baseline` and `recovery` (calibration only, `verdict: null`), plus three judged windows:
  - `strict`: expects zero direct flows (`leak: NONE`), tunnel traffic present.
  - `sharing-strict`: expects zero unexpected flows (`leak: NONE`), tunnel traffic present, allowances
    `('lan-peer-arp', 'shared-proxy-peer', 'shared-proxy-server')`.
  - `lockdown`: expects zero unexpected flows (`leak: NONE`), tunnel traffic present, allowances
    `('lan-peer-arp', 'shared-proxy-peer')`.
- Post-cleanup `_AFTER` (`proxy=True`) additionally verifies Lockdown WFP provider/sublayer absence, no leftover
  `RosetunProxyUser` account/profile, and no lingering `desktop_proxy.exe` processes.

### Windows Local Network (`windows-lan`)

- Catalog: `tools/vm/windows/lan-core.tsv` (72 checks covering `allow_lan` on/off, peer TCP, mDNS/SSDP/limited
  broadcast, 600 s long-lived peer echo session, live IPv4 address add/remove with disjoint `/26` `198.51.100.10/26`,
  explicit LAN rules, `allow_private_behind_router` against `10.255.255.1:80`, refused live `apply` and disconnect/switch,
  in-network VPN server exclusion on `192.0.2.1`, and `lan-reopen`).
- Guest runner: `tools/vm/windows/guest/run-windows-lan.ps1` (46,416 bytes, below the 65,536-byte QGA limit).
- Eleven wire windows: `baseline` and `recovery` (calibration only), plus nine judged windows: `lan-on`,
  `address-change`, `lan-rule`, `lan-private`, `lan-off`, `switch`, `lan-server`, `lan-server-private`, and
  `lan-reopen`. Each judged window is checked against exact expected direct flows and narrow per-window allowances
  (`lan-peer-arp`, `lan-mdns`, `lan-ssdp`, `lan-broadcast`, `extra-address-arp`), plus cross-checks between guest
  check verdicts and pcap-observed flows/allowances.
- Post-cleanup `_AFTER` (`lan=True`) additionally verifies the temporary `198.51.100.10` address is removed from the
  physical adapter and session WFP state is clean.

### Commands and configurations

    python3 -B -m tools.vm.matrix run windows-proxy --config CONFIG [--dry-run]
    python3 -B -m tools.vm.matrix run windows-lan   --config CONFIG [--dry-run]

Configurations:
- `execution-windows-proxy.example.toml`, schema `rosetun.matrix.execution.windows.v6`, with `[proxy]` (`proxy_port`,
  `desktop_proxy`, `desktop_proxy_sha256`, plus timing, `xorriso`, and pinned binary hashes).
- `execution-windows-lan.example.toml`, schema `rosetun.matrix.execution.windows.v7`, with `[lan]`
  (`long_session_seconds` in `10..900`, canonical `600`, plus timing, `xorriso`, and pinned binary hashes).
`report` refuses both `windows-proxy` and `windows-lan` without wire evidence.

### Offline tests

- `tests/test_windows_proxy_lab.py`: 46-check catalog and `run-windows-proxy.ps1` parity, QGA payload ceiling,
  `windows.v6` validation and `execution-windows-proxy.example.toml`, CLI `plan`/`report` refusal, `probe_proxy` lab
  action dispatch, `sharing-strict`/`lockdown` window allowances, and synthetic full/leak/cleanup runs.
- `tests/test_windows_lan.py`: 72-check `lan-core.tsv` and `run-windows-lan.ps1` parity, QGA payload ceiling,
  `windows.v7` validation and `execution-windows-lan.example.toml`, `lab-entry.py` DNS resolver & LAN fixtures config,
  `lan_state` action dispatch, all 9 judged windows and cross-checks, and synthetic full/leak/cleanup runs.
- `tests/test_lab.py` and `tools/vm/windows/tests/Test-RosetunScriptArguments.ps1` cover the new packet allowances and
  PowerShell syntax/argument rules across `run-windows-proxy.ps1` and `run-windows-lan.ps1`.

### Checked on the stand (2026-11-24, developer runs, not a qualification)

Debian 13 on WSL2, QEMU 10.0.13, `windows-11-26h2-pro-v1`, `lab-v5n` (`sha256=7422229d...`, built from untouched
`lab-v5m` `sha256=5139fb9a...`), dedicated state directory `state-10d-dev`, Windows release build of the checkout
(`rosetun.exe`, `rosetun-helper-privileged.exe`, `desktop_proxy.exe`) and pinned `sing-box` 1.14.3, `settle_seconds = 60`
(working tree dirty with this stage's changes):

| suite | run | exit | duration | checks | lab actions | judged windows | cleanup |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `windows-proxy` (run 1) | `1eb8a01f...` | 0 | 289.5 s | 46 PASS | 9 | `strict: EXPECTED` (tunnel 389); `sharing-strict: EXPECTED` (tunnel 97, allowed `peer: 22, server: 5`); `lockdown: EXPECTED` (tunnel 157, allowed `peer: 27`) | runner `PASS`, `left: []` |
| `windows-proxy` (run 2) | `df62b71c...` | 0 | 300.8 s | 46 PASS | 9 | `strict: EXPECTED` (tunnel 392); `sharing-strict: EXPECTED` (tunnel 98, allowed `peer: 22, server: 5`); `lockdown: EXPECTED` (tunnel 156, allowed `peer: 27`) | runner `PASS`, `left: []` |
| `windows-lan` (smoke, `30 s`) | `6d2c9733...` | 0 | 356.1 s | 72 PASS | 9 | all 9 judged windows `EXPECTED` | runner `PASS`, `left: []` |
| `windows-lan` (canonical `600 s`, run 1) | `bd26a257...` | 0 | 925.9 s | 72 PASS (`120` echoes) | 9 | all 9 judged windows `EXPECTED` (`lan-on` tunnel 1382, `address-change` 205, `lan-rule` 62, `lan-private` 81, `lan-off` 237, `switch` 82, `lan-server` 109, `lan-server-private` 138, `lan-reopen` 60) | runner `PASS`, `left: []` |
| `windows-lan` (canonical `600 s`, run 2) | `044b4d31...` | 0 | 920.3 s | 72 PASS (`120` echoes) | 9 | all 9 judged windows `EXPECTED` (`lan-on` tunnel 1418, `address-change` 257, `lan-rule` 61, `lan-private` 63, `lan-off` 123, `switch` 63, `lan-server` 111, `lan-server-private` 216, `lan-reopen` 62) | runner `PASS`, `left: []` |

All five runs: `accepted: true`, `findings: []`, `unverified: []`, `image_unchanged: true`, both `-lab` and `-test`
`completion_verified: true`, zero leftover WFP/user/task/address state. Live bring-up caught and fixed:
- Lab `sing-box` DNS resolver (`lab-dns` -> `203.0.113.53` + `route.default_domain_resolver`) for `listed.lab.test` proxy checks.
- Setting WinINet `AutoConfigURL` via `wininet.dll` `InternetSetOptionW` instead of raw registry writes under fresh `RosetunProxyUser` profiles, plus `@(...)` array wrapping in `strict.restart` under PowerShell 5.1 StrictMode.
- Deriving `$tunAddress` from `plan.request.settings.tun.ipv4` (`198.51.100.65`) and using disjoint `/26` (`198.51.100.10/26`) so the added address does not overlap TUN `198.51.100.65/30`.
- Eliminating unprotected OS background-probe gaps inside judged LAN windows (`Clear-PeerNeighbor` sleep, redundant disconnects in `Connect-LanVariant`, and opening the `switch` judged window right before the reconnected `lan-on` session).

### Not done here, UNRUN

- Nothing qualifies: `qualified: false`, diagnostic runs only, no release gate or Hyper-V parity table is touched.
- Remaining Windows suite (Upgrade): stage 10e.

## Stage 10e: Windows Upgrade (`windows-upgrade`)

Run with the [Windows Upgrade execution example](execution-windows-upgrade.example.toml)
as a template. Use a dedicated state directory and pin two distinct Inno Setup
installers for the same application ID. The read-only ISO carries both installers,
the recovery binaries, and the runner. The controller verifies the media and the
runner checks the installer hashes before execution.

```
python3 -B -m tools.vm.matrix run windows-upgrade --config CONFIG [--dry-run]
```

The guest runs quiet setup and uninstall under SYSTEM. The
[check catalog](../windows/upgrade-checks.json) describes the four scenarios
ported from [the Hyper-V matrix](../windows/Invoke-UpgradeMatrix.ps1).

| Scenario | Guest and wire evidence |
| --- | --- |
| Disconnected with Lockdown | Lockdown remains active across the upgrade, direct egress is blocked, and the upgrade hold provider is absent. |
| Connected with the kill switch | The upgrade hold stays in force across service replacement, reconnect restores tunneled egress, and the hold provider is removed. |
| Connected with the kill switch disabled | Setup places no hold, and the observer expects one direct HTTPS flow to the lab target. |
| Interrupted setup | The runner interrupts setup after the hold appears and the old service stops. Direct egress remains blocked until the recovery CLI resets the firewall. |

The observer judges the four scenario windows against explicit direct-flow
expectations. Baseline and recovery calibrate HTTPS and DNS visibility.
The controller checks for leftover services, installers, GUI and engine
processes, registrations, scheduled tasks, and WFP objects after guest cleanup.
Saved guest reports require the journal and independent wire evidence.
The run is exploratory with `qualified: false` and `release_gate: false`.
Interactive GUI behavior stays with the Hyper-V and manual checks.

The [offline tests](tests/test_windows_upgrade.py) cover schema v8, both ISO
pins, the 45-check catalog and runner order, the QGA limits, and synthetic
acceptance, leak, calibration and cleanup outcomes. The guest script is
about 36 KiB and passes the Windows PowerShell 5.1 argument scan.

### Developer runs on the stand (2026-11-24)

Debian 13 on WSL2, QEMU 10.0.13, `windows-11-26h2-pro-v1`, `lab-v5n`
and a dedicated `state-10e-dev` directory. The old and new installers were
`0.7.0-beta.1` and `0.7.0-beta.2` from their published releases. Their
SHA-256 digests matched the signed release manifests. The checkout binaries
provided the recovery CLI and helper, and the guest settled for 60 seconds
before the runner started.

| Run | Exit | Duration | Checks | Judged windows | Cleanup |
| --- | --- | --- | --- | --- | --- |
| `49a8d3ae8a034000b844d74577c7e864` | 0 | 356.5 s | 45 PASS | all four `EXPECTED` | `PASS`, `left: []` |
| `6d411dc8e17b4562a4e36ba2dfc73026` | 0 | 339.6 s | 45 PASS | all four `EXPECTED` | `PASS`, `left: []` |

Both runs recorded `accepted: true`, `findings: []`, `unverified: []`,
`image_unchanged: true`, and verified completion for both VMs. The
`lockdown`, `kill-switch` and `broken` windows recorded zero unexpected
frames. The `no-kill-switch` window contained one answered direct HTTPS
flow to the lab target, as expected.

Bring-up required trimming Inno's padded product version, stopping the
service before the uninstaller resets the firewall, and removing the empty
directory the install helper had created. A five-second pause after each
old installation gives its background traffic time to settle before the
next window opens.

## Stage 12: release evidence pack

`evidence` copies the records of chosen finished runs into one new directory and
builds the parity tables from them. It reads the stand's state and writes nothing
there. It accepts nothing: **a pack is not an acceptance**. The release gate stays
false, the security invariants stay UNVERIFIED, and judging the pack and signing it
are the owner's, outside this tool.

```
python -m tools.vm.matrix evidence --state-directory STATE --run RUN [--run RUN ...] --out DIR
```

- `--run` is a run as `runs` lists it (`<id>-test`, `<id>-lab`), or the base
  identifier of a lab run, which stands for its `-lab` and `-test` directories
  together. Name each run once; the order of the arguments does not matter.
- `--out` must not exist and must lie outside the state. The pack is written to
  `DIR.partial` and renamed on success, so a refusal or a failure leaves nothing.
- Exit 0: built. Exit 1: refused (`built: false`, `reason`, and `run` when one run
  caused it). Exit 2: the state is unreadable or invalid.

### What the pack holds

- `runs/<directory>/`: `execution-summary.json`, `completion.json`,
  `run-state.json`, `lifecycle.jsonl` and every `report.json` under a
  `linux-*` or `windows-*` suite directory, byte for byte. The image descriptors
  are in the summary and in the manifest. Nothing else is copied: no `manifest.json`
  of the run (it carries the owner token), no execution identity, no disks, no
  media, and **no capture**. Only the capture's size and SHA-256 are recorded; when
  `capture.pcap` is in the lab's directory it is hashed and must match the summary.
  The owner token of a run and a private key are never evidence: a copied file that
  contains either stops the pack.
- `parity-<set>.tsv` for each suite (`l3`, `proxy`, `l4`, `l5`): the columns of the
  stage 8g tables (`id`, `required`, `result1..N`, `crosscheck1..N`, `window`,
  `window_verdict1..N`, `note`) and an empty `hyperv` column last, for the owner.
  The runs of a suite are the columns, in the order of their start. The `note` says
  only where the runs differ or a scenario is not among the assessment rows.
- `parity-summary.json`: per suite, per run: commit, `source_dirty`, images, run
  directories, exit code, summary hash, capture size and hash, start and end from the
  lifecycle journal, windows, scenario counts. It interprets nothing.
- `manifest.json`, schema `rosetun.matrix.release-evidence.v1`:
  `release_gate: false`, `security_invariants: "UNVERIFIED"`,
  `owner_signature: null`; `sets` (commit, run list and table per suite); `runs`
  (`run`, `suite`, `commit`, `source_dirty`, `source_dirty_digest`, `images`,
  `directories`, `exit_code`, `outcome`, `summary_schema`, `summary_sha256`,
  `completion_verified`, `attached`, `findings`, `unproven`, `pcap`, `started_utc`,
  `finished_utc`, `windows`, `window_counts_all_as_expected`, `scenario_counts`);
  `files` (bytes and SHA-256 of every file of the pack but the manifest).

The same runs give the same bytes: keys and files are sorted, and the content holds
no time of the build.

### Refusals

`run-not-found`, `duplicate-run`, `completion-not-verified` (the run's own
completion check fails), `summaries-differ` (the `-lab` and `-test` summaries are
not the same bytes), `summary-invalid`, `source-unknown`, `source-dirty`,
`commits-differ-in-a-set` (runs of one suite from different commits; suites may
differ), `diagnostic-run`, `attached-run` (`attached: true`, or no
`attached: false` in a summary that is not a lab's: a qualifying step needs
`attached: false`), `pcap-does-not-match-its-record`, `secret-in-evidence`,
`set-names-collide`, `out-exists`, `out-parent-missing`, `out-inside-state`.

### The owner's part

The owner fills `hyperv` for each scenario (the last legacy Hyper-V run: its number
and commit), notes the scenarios the lab sees differently, decides on the findings
and on `unproven`, and signs the pack or its manifest hash by a means of the owner's
own. The tool writes no signature and checks none; `owner_signature` stays `null` in
the pack. A table with an empty `hyperv` column is a draft.

### CI

`vm-matrix.yml` runs the tests of the pack (`test_release_evidence`) on both
runners with the rest of the offline tests; the one test that closes a run through
the real controller is `controller_only`. A Linux-only step validates every
`execution*.example.toml` with `execution.validate`: it needs no stand, but the
examples name Linux paths that are not absolute on Windows. CI has no release gate
and needs no KVM.
