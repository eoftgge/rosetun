# VM matrix foundation

Python 3.11+ and the standard library are sufficient for offline work. Run
commands from the repository root. The CLI reads local files and writes JSON
to stdout. Explicit lifecycle/QGA Python APIs also support owner-controlled VM
operations; the limited L2 execution path is described below. Existing legacy
matrices remain supported. Internal QEMU qualification does not establish
network protection or scenario/release acceptance.

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

On `alive` the VM is still running and holds the overlay. Stop that QEMU
yourself (the controller is gone, so nothing else will), check that
`recover` now shows `absent`, then archive. On `unknown` establish the
process state by hand first. For a run with no process record, run
`pgrep -af qemu-system` and look for the run's `root.qcow2` path in a command
line. If one matches, it is that run's VM: stop it, then archive by hand
once no such process is left. If none matches, the run has no VM; move it out
of `runs/` yourself, since `--archive` refuses `unknown`.

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
there are no arbitrary paths or extra diagnostics. It first requires a finished
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
legacy launch plans unchanged. `start` creates a second private connected Unix
socket pair and adds `-chardev socket,id=guestagent,fd=<child-fd>`,
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
protocol negotiation belong to the library. A private connected Unix socket pair
is retained; a bounded byte-only relay adds no listener. The relay caps each
buffer at 64 KiB and each direction at 1 MiB per session; exceeding the budget
closes the channel. QMP has a 64 KiB read limit, at most 128 commands and 128
observed events per session. The library forbids removing its default listener;
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
remain exactly what the TSV declares. They are not external packet capture.
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

After submit the controller waits the full **job timeout + 125 seconds without
RPCs**, including the existing 120-second systemd stop/cleanup allowance and
five seconds for final publication. First collection therefore occurs after
1025 seconds for the default 900-second job, or 7325 for the maximum 7200-second
job, even when L2 finishes early. One final collection may follow 15 seconds later. No status-only protocol
or increased collect limit is needed. All reads remain under the job + 180 second
deadline. A normal boot check costs five RPCs (info/ping/open/read/close), submit
six, and collection with the maximum 256 KiB report costs at most 28: two boot
checks (10), launcher status (1), two <=8 KiB status reads (6), report open + nine
reads including the overflow/EOF probe + close (11). Thus submit plus two maximum
collections needs at most **62 of 112 job RPCs**, independent of job duration.
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
helper JSON each 32 KiB, eight accepted target requests, socket I/O 1 second
(server) / 2 seconds (client), guest command timeout 5 seconds, boot wait 120
seconds per VM, guest facade 90 seconds, 40 status polls at 0.5 seconds per call,
file reads 16 KiB and the unchanged QGA 128-RPC ceiling. Normal VM close retains
the existing bounded lifecycle behavior. Kernel PACKET_STATISTICS drops, write
errors, overflow, capture deadline, incomplete files, missing required traffic and
nonzero helper status all prevent qualification. TCP handling is deliberately
small and can reject short/split requests as infrastructure failure.

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
`leak_reason`, `categories`, `unexpected`, `canary`, `canary_flows`,
`canary_other` and `window`:

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
  link before the closing marker, a truncated record, a fragment or any frame the
  parser cannot read all land here, as does a capture that ends before the
  closing marker.

Every parsed frame has exactly one category, counted in `categories`:

| Category | Meaning |
| --- | --- |
| `probe` | A frame of one of the eight expected exchanges: same family, protocol, addresses, hardware addresses, service port, and the run's marker or answer in the payload. A TCP segment without data counts only on a connection that carried a matching request or answer, so SYN, ACK, FIN, RST and repeats of that connection are probe frames and a bare connection to a service port is not. |
| `marker` | The run's opening or closing marker, request or answer. |
| `infrastructure` | Only the listed service traffic between the two machines, kept in one table (`INFRASTRUCTURE`) next to the addresses in `lab_protocol.py`: ARP requests and replies between `192.0.2.2` and `192.0.2.1`, and ICMPv6 neighbor solicitation and advertisement between the two lab addresses and their link-local addresses, router solicitation and advertisement, and multicast listener messages. |
| `unexpected` | Any other frame whose sender or receiver hardware address is the test machine's, or whose sender or receiver address is the test machine's: ICMP, another port or target, another prefix, another EtherType, broadcast or multicast outside the table. |
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
`DETECTED`, `canary_flows` is exactly `tcp` and `udp`, and `canary_other` is 0.
Any other combination exits 2.

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
3. From the test machine's console during capture, send one extra packet by hand
   (for example `ping -c1 203.0.113.2`): exit 2, `leak` `DETECTED`.
4. Stop the observer process on the lab machine in the middle of the window: `leak`
   `UNVERIFIED`, never `NONE`.
5. `set_link test-wire off` through QMP before the closing marker: `UNVERIFIED`.
6. Read the saved pcap in Wireshark: the frame counts per category match
   `categories` in the summary.
