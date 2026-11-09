# VM matrix foundation

Python 3.11+ and the standard library are sufficient. Run commands from the
repository root. The CLI only reads local files and writes JSON to stdout.
It does not run scenarios, install dependencies, start services or create VMs.
The existing Bash/PowerShell matrices remain the execution tools, Hyper-V remains
the control stand, and QEMU is the intended future backend.

## QEMU disk and launch preparation (stage 3b)

`images.py` and `qemu.py` provide an internal preparation API, separate from the
reporting TOML profiles. There is no VM run command. `prepare(run, image, config)`
requires an empty `PreparedRun` created under its original live `StandLease`.
It can execute **qemu-img only**, using explicit argv without a shell. Supplying
`executor=` replaces external commands for offline tests. Nothing invokes QEMU.

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
non-UTF-8 JSON, NaN/Infinity, incomplete metadata and unexpected chains block preparation. Diagnostics retain
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
successful boot or security-matrix coverage. Next: QEMU process lifecycle and
QMP, designed together with resource completion and recovery. QGA, guest runners
and network laboratories are outside this stage.

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
   and blocked reuse. Do not execute the saved QEMU argv in this stage. Boot,
   process stop/crash handling and QMP acceptance belong to the next stage.

## Local stand leases and resource records

`resources.py` adds a preparation-only internal API; it never executes a matrix.
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

After locking, every previous run of that stand blocks new preparation. Invalid
manifests block all stands because their ownership cannot be established. Even
an empty prepared run remains unresolved: this stage has no verified cleanup
state. It is intentionally conservative. Keep records until independent manual
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

States are `preparing`, `prepared`, `error`, `quarantined`; `create_run` writes
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
Unknown state must remain quarantined. QMP/QGA, overlays, endpoints, network
objects and cleanup implementation belong to later stages.

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
an evidence store, QEMU execution, QMP/QGA, guest agents, network labs and scenario
migration are not implemented. Unit tests do not qualify any OS/backend or prove
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
