# VM matrix foundation

Python 3.11+ and the standard library are sufficient. Run commands from the
repository root. This package only reads local files and writes JSON to stdout.
It does not run scenarios, install dependencies, start services or create VMs.
The existing Bash/PowerShell matrices remain the execution tools, Hyper-V remains
the control stand, and QEMU is the intended future backend.

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

The directory must not exist. The recorder generates a GUID run ID, captures the
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
