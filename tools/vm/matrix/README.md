# VM matrix foundation

Python 3.11+ and the standard library are sufficient. Run commands from the
repository root. The CLI only reads local files and writes JSON to stdout.
It does not run scenarios, install dependencies, start services or create VMs.
The existing Bash/PowerShell matrices remain the execution tools, Hyper-V remains
the control stand. Internal QEMU qualification coverage is recorded below; it
does not establish network protection or scenario/release acceptance.

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
# Autonomous infrastructure smoke over QGA (stage 4b.2)

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
