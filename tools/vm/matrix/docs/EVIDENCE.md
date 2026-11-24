# Release Evidence Packs (Stages 10g and 12)

`python3 -B -m tools.vm.matrix evidence` copies selected finished run records from a stand state
directory into a new, deterministic evidence directory and builds parity tables. It is strictly
read-only against the state directory and **never grants release acceptance**: `release_gate`
remains `false`, `security_invariants` remains `"UNVERIFIED"`, and `owner_signature` remains
`null`. Judging parity against legacy Hyper-V runs and signing the pack belong exclusively to the
owner.

For the suite catalog and CLI overview, see [../README.md](../README.md).

## Command and options

```sh
python3 -B -m tools.vm.matrix evidence \
  --state-directory STATE \
  [--include-archive] \
  --run RUN [--run RUN ...] \
  --out DIR
```

- `--run`: a run directory as listed by `runs` (`<id>-test`, `<id>-lab`), or the base identifier of
  a lab run (representing both `<id>-lab` and `<id>-test`). Each run must be named once; argument
  order does not affect output bytes.
- `--include-archive`: also searches reconciled runs previously moved into `STATE/archive/` by
  `recover --archive`. Without this flag, only `STATE/runs/` is searched. Packing from `archive/`
  produces byte-identical `runs/<directory>/` output to packing from `runs/`.
- `--out`: must not already exist and must lie outside `STATE`. The pack is staged in `DIR.partial`
  and atomically renamed on success, leaving nothing on refusal or error.
- **Exit codes:** `0` pack built; `1` refused (`built: false`, `reason`, and `run` when attributable
  to one run); `2` unreadable or invalid state directory.

## Supported suites and set grouping

| Platform | Suites | Parity table filename |
| --- | --- | --- |
| Linux lab | `linux-l3`, `linux-proxy`, `linux-l4`, `linux-l5` | `parity-l3.tsv`, `parity-proxy.tsv`, `parity-l4.tsv`, `parity-l5.tsv` |
| Windows lab (single-case) | `windows-list`, `windows-proxy`, `windows-lan`, `windows-upgrade`, `windows-protocols`, `windows-twohop` | `parity-<suite>.tsv` |
| Windows lab (per-case) | `windows-failure` (`engine-killed`, `helper-killed`, `no-network`, `apply-rules`, `reconnect`, `temporary`, `dns-lock`), `windows-lockdown` (`core`, `reboot`, `full`) | `parity-windows-failure-<case>.tsv`, `parity-windows-lockdown-<case>.tsv` |

Diagnostic infrastructure smokes (`windows-boot-smoke`, `windows-reboot-smoke`,
`windows-lab-smoke`, `linux-reboot-smoke`) are refused with `diagnostic-run`.

## Collecting three consecutive clean Windows runs

Because each run holds the stand until archived (`recover --run-id <id> --archive`), consecutive
runs are archived into `STATE/archive/` between executions and packed together with
`--include-archive`:

```sh
python3 -B -m tools.vm.matrix evidence \
  --state-directory STATE \
  --include-archive \
  --run RUN1 --run RUN2 --run RUN3 \
  --out ./evidence-windows-list
```

All runs in a set must come from the same clean commit (`source_dirty: false`, identical
`source_sha`). Different suites in the same pack may come from different commits if needed.

## Pack layout

```text
<DIR>/
  manifest.json             # rosetun.matrix.release-evidence.v1
  parity-summary.json       # per-suite, per-run factual records
  parity-<set>.tsv          # one TSV table per suite/case set
  runs/<directory>/         # byte-for-byte copied evidence files
```

- **`runs/<directory>/`:** copies only `execution-summary.json`, `completion.json`,
  `run-state.json`, `lifecycle.jsonl`, and any `report.json` under `linux-*` or `windows-*`. Never
  copies `manifest.json` (contains `owner_token`), execution identities, disks, media ISOs, or
  `capture.pcap`. When `capture.pcap` is present in the lab directory, it is hashed and verified
  against the summary (`pcap-does-not-match-its-record` on mismatch). Any copied file containing a
  run's owner token or a private key aborts the pack (`secret-in-evidence`).
- **`parity-<set>.tsv`:** columns `id`, `required`, `result1..N`, `crosscheck1..N`, `window`,
  `window_verdict1..N`, `note`, and an empty trailing `hyperv` column for the owner. Runs are
  ordered by start time. For Windows suites, `preflight.checks` establishes row order and any
  `disagree:<id>` finding marks `DISAGREE` in `crosscheck1..N`.
- **`parity-summary.json`:** factual per-suite/per-run data (commit, `source_dirty`, images,
  directories, exit code, summary SHA-256, capture size/SHA-256, lifecycle start/end timestamps,
  windows, scenario counts, and optional `case` / `window_verdicts`).
- **`manifest.json` (`rosetun.matrix.release-evidence.v1`):**
  - Top-level invariants: `release_gate: false`, `security_invariants: "UNVERIFIED"`,
    `owner_signature: null`.
  - `sets`: per-set `commit`, run list, table path, and factual counters (`run_count`,
    `all_exit_zero`, `all_windows_as_expected`, `all_findings_empty`, `all_unproven_empty`).
  - `runs`: per-run metadata (`run`, `suite`, `commit`, `source_dirty`, `source_dirty_digest`,
    `images`, `directories`, `exit_code`, `outcome`, `summary_schema`, `summary_sha256`,
    `completion_verified`, `attached`, `findings`, `unproven`, `pcap`, `started_utc`,
    `finished_utc`, `windows`, `window_counts_all_as_expected`, `scenario_counts`, plus optional
    `case` and `window_verdicts`).
  - `files`: byte size and SHA-256 of every file in the pack except `manifest.json`.
- **Determinism:** sorted keys and file lists, no pack build timestamp; the same runs yield
  identical bytes.

## Refusal codes

`run-not-found`, `duplicate-run`, `run-in-runs-and-archive`, `completion-not-verified`,
`summaries-differ` (`-lab` and `-test` summaries differ), `summary-invalid`, `source-unknown`,
`source-dirty`, `commits-differ-in-a-set`, `diagnostic-run`, `attached-run` (`attached: true` or
missing `attached: false` on non-lab runs), `pcap-does-not-match-its-record`, `secret-in-evidence`,
`set-names-collide`, `out-exists`, `out-parent-missing`, `out-inside-state`.

## Owner workflow and CI

- **Owner's responsibility:** populate the `hyperv` column (legacy Hyper-V run ID and commit),
  annotate scenarios observed differently by the lab, adjudicate any `findings` or `unproven` entries,
  and sign the pack or `manifest.json` hash externally. A table with an empty `hyperv` column is a
  draft.
- **CI:** `vm-matrix.yml` runs `tests/test_release_evidence.py` on both Ubuntu 24.04 and Windows
  2025 (with the single real-controller test guarded by `controller_only`). CI has no release gate
  and requires no KVM.
