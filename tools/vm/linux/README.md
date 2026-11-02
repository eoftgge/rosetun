# Linux L2 stand

A Hyper-V test bench for the Linux IPC transport (the L2 stage). The owner runs
it; nothing in it starts implicitly. It drives a **separate Debian 13 VM** over
SSH. The Windows matrices (`../windows/Invoke-*Matrix.ps1`, PowerShell Direct) and the
Windows VM `rosetun-test` are not involved and keep their behaviour.

What it proves and what it does not:

| Evidence | Scenarios | Meaning |
|---|---|---|
| `transport-fixture` | `credentials.*`, `untrusted-server.*`, `exclusivity.*`, `stale.*`, `occupied.*` | the real transport and `SO_PEERCRED` credentials, through `l2_transport_fixture` |
| `helper-unit-stub-backends` | `unit.server-*`, `unit.helper-*` | helper policies and `Server` lifecycle with stub backends and fake callers |
| `ipc-unit-tests` | `unit.ipc-*` | IPC unit tests in unprivileged temporary directories |
| `infrastructure` | `preflight.*`, `stale.verified-removal` | the stand's own checks |
| `not-run` | `missing-group.refusal` | needs a second VM without group `rosetun`; always reported SKIP |

The unit tests run as an ordinary account against the build you staged. They
are not a substitute for the fixture, and the fixture is not a substitute for
them. The stand makes **no claim** about the network, a kill switch, systemd
integration of Rosetun, engines or Lockdown. Those are later stages (below).

## Layout

| File | Purpose |
|---|---|
| `Invoke-LinuxL2Matrix.ps1` | Host entry point: stage a run, later collect and judge it |
| `RosetunLinuxVm.psm1` | Host module: SSH/SCP with a pinned host key, VM identity, artifact checks, report verdict |
| `build-artifacts.sh` | Builds the three Linux binaries inside Debian and records their provenance |
| `guest/start.sh` | The one command the owner runs in the guest with `sudo`; starts the autonomous job |
| `guest/run-l2.sh`, `guest/lib.sh` | The job itself: scenarios, cleanup, report |
| `scenarios.tsv` | The scenario list, shared by the guest and the host |
| `tests/` | Unprivileged self-tests of the stand (not a VM run) |

Reports go to `tools/vm/linux/logs/<run id>/` (git-ignored): `stage.json`,
`report.json`, `report.txt`. The guest keeps its own copy in
`/var/lib/rosetun-l2/<run id>/report/`.

## Trust model

- The host talks to the guest over SSH with a key, `StrictHostKeyChecking=yes`
  and a `known_hosts` file you create from a fingerprint you read on the VM
  console. There is no option to switch verification off, and no password,
  private key or credential is written to the repository, the stage or a report.
- The SSH account is an **ordinary** account. Only the privileged job needs root,
  and you start it yourself with `sudo` and your password. No `NOPASSWD` is needed.
- `start.sh` copies the staged files into `/var/lib/rosetun-l2/<run id>/`
  (root-owned, no group/other write), checks them against a manifest whose SHA-256
  you copy from the host's printout, and only runs the root-owned copies. The
  staging folder is 0700 and must belong to the account that ran `sudo`.
- The job is a transient systemd unit (`rosetun-l2-<run id>.service`), independent
  of your SSH session. It has a time limit; when the unit stops for any reason an
  `ExecStopPost` closes the report and cleans up, so a killed job still yields a
  report that cannot pass.
- No firewall rule is added or changed. The stand never stops, edits or removes a
  foreign service, user, group or directory.

## One-time preparation

### 1. The VM and the clean checkpoint

On the host, in an elevated PowerShell (Hyper-V cmdlets need it):

```powershell
New-VM -Name rosetun-linux-l2 -Generation 2 -MemoryStartupBytes 4GB `
    -NewVHDPath 'D:\Hyper-V\rosetun-linux-l2.vhdx' -NewVHDSizeBytes 40GB -SwitchName 'Default Switch'
Set-VMProcessor -VMName rosetun-linux-l2 -Count 4
Set-VMMemory -VMName rosetun-linux-l2 -DynamicMemoryEnabled $false
Set-VMFirmware -VMName rosetun-linux-l2 -SecureBootTemplate MicrosoftUEFICertificateAuthority
Add-VMDvdDrive -VMName rosetun-linux-l2 -Path 'C:\path\to\debian-13-amd64-netinst.iso'
Set-VMFirmware -VMName rosetun-linux-l2 -FirstBootDevice (Get-VMDvdDrive -VMName rosetun-linux-l2)
```

Install Debian 13 (x86-64) with the KDE desktop and the "SSH server" and "standard
system utilities" tasks. Use a name other than `rosetun-test`; the module refuses
that one. Use a VM that holds no data you care about.

### 2. Accounts, group and packages (in the guest, as an administrator)

The stand creates none of these. Do it once, before the checkpoint:

```sh
sudo apt-get install --no-install-recommends util-linux procps coreutils openssh-server
sudo groupadd rosetun
sudo useradd --create-home --shell /bin/bash --groups rosetun ipc_owner
sudo useradd --create-home --shell /bin/bash --groups rosetun ipc_other
sudo passwd -l ipc_owner && sudo passwd -l ipc_other   # nobody logs in as them
sudo useradd --create-home --shell /bin/bash --groups sudo l2admin
sudo passwd l2admin
echo 'rosetun-l2-stand-1' | sudo tee /etc/rosetun-l2-stand-id
```

- `ipc_owner` and `ipc_other` are the two ordinary test accounts. They must be
  in group `rosetun` and in no administrator group (`sudo`, `wheel`, `admin`).
- `l2admin` is the account SSH logs into and that runs `sudo`. It is **not** one of
  the test accounts. It needs a password-protected `sudo`; no `NOPASSWD`.
- `/etc/rosetun-l2-stand-id` is the identifier the host checks, so a second Linux
  VM can never be mistaken for the stand. Use your own value for `-StandId`.
- The group is `rosetun` exactly. Do not rename or remove it for any test.

### 3. SSH key and the pinned host key

On the host, generate a key that is used only for this stand and install its public
half:

```powershell
ssh-keygen -t ed25519 -f "$env:USERPROFILE\.ssh\rosetun-l2" -C rosetun-l2-stand
Get-Content "$env:USERPROFILE\.ssh\rosetun-l2.pub"    # paste into the guest's ~l2admin/.ssh/authorized_keys
```

In the guest (console or any trusted channel), read the host key's fingerprint:

```sh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
ip -4 -o addr show scope global
```

On the host, take the key from the network and **compare its fingerprint with the
one on the console** before you accept it:

```powershell
ssh-keyscan -t ed25519 <guest-address> > "$env:USERPROFILE\.ssh\rosetun-l2.known_hosts"
ssh-keygen -lf "$env:USERPROFILE\.ssh\rosetun-l2.known_hosts"     # must equal the console's value
```

If the two differ, delete the file and stop. The stand reads only this file; it
does not touch your normal `known_hosts`.

### 4. The clean checkpoint

Check that `/run/rosetun` does not exist, no Rosetun service or helper process is
installed or running, and the guest is idle. Then:

```powershell
Checkpoint-VM -Name rosetun-linux-l2 -SnapshotName l2-clean
(Get-VM -Name rosetun-linux-l2).VMId       # the value for -VmId
```

## Building the artifacts (WSL, not Windows)

The stand accepts only an x86-64 **Linux ELF** built in Debian. A Windows
`cargo build` copied to the guest is refused (a PE file, or the wrong hashes).

Commit what you want tested first. Build from a clean clone in Debian so the
recorded SHA and clean status are checkable. Debian needs `git`, a C linker and
Rust 1.96.0 (`sudo apt-get install git build-essential`; `rustup toolchain install 1.96.0`):

```sh
git clone --no-hardlinks /mnt/d/Repositories/rosetun ~/rosetun-l2-src
cd ~/rosetun-l2-src && git checkout <the commit SHA under test>
bash tools/vm/linux/build-artifacts.sh /mnt/d/Repositories/rosetun/target/l2-artifacts-1
```

The output directory must not exist. It holds the three binaries and
`provenance.json` (commit, dirty status, tool versions, hashes). The host compares
it with the checkout you stage from. If they differ, or git was missing at build
time, the report says **origin unconfirmed** and never presents the binary as a
verified build of the SHA.

## Running

Order matters; each step needs the previous one's output.

1. **Stage** (host, elevated PowerShell, repository root). Nothing is restored unless
   you pass `-RestoreCheckpoint l2-clean`, which you should for a reproducible run:

   ```powershell
   $vm = 'rosetun-linux-l2'
   $common = @{
       VmName = $vm; VmId = (Get-VM -Name $vm).VMId
       SshHost = '<guest-address>'; SshUser = 'l2admin'
       KnownHostsPath = "$env:USERPROFILE\.ssh\rosetun-l2.known_hosts"
       IdentityFile = "$env:USERPROFILE\.ssh\rosetun-l2"
       StandId = 'rosetun-l2-stand-1'
   }
   .\tools\vm\linux\Invoke-LinuxL2Matrix.ps1 @common -ArtifactDir .\target\l2-artifacts-1 `
       -UserA ipc_owner -UserB ipc_other -RestoreCheckpoint l2-clean
   ```

   It checks the VM id, the stand id file, the BIOS GUID and the boot id, copies the
   run into `~/rosetun-l2-stage/<run id>/`, and prints the exact `sudo` command.

2. **Start the job** (guest, logged in as `l2admin`, over SSH or the console). Paste
   the line the host printed; it has this shape:

   ```sh
   sudo bash ~/rosetun-l2-stage/<run id>/guest/start.sh <run id> ~/rosetun-l2-stage/<run id> <manifest sha256>
   ```

   `sudo` asks for your password. The job now runs by itself; you may close SSH.

3. **Collect** (host). It waits for the job, reads the status and report back
   over SSH, recomputes the verdict itself and exits 0 only on PASS:

   ```powershell
   .\tools\vm\linux\Invoke-LinuxL2Matrix.ps1 @common -Collect -RunId <run id> -WaitSeconds 1200
   ```

   `-Collect` works any time after a reconnect or a break in SSH.

## The report

`report.txt` (table) and `report.json` list the run id, source SHA and dirty status,
the hash of every artifact and whether their origin is confirmed, OS, kernel,
architecture, systemd and boot id, then per scenario: expectation, evidence kind,
PASS / FAIL / SKIP / ERROR, the reason and the duration, then the cleanup result
and the overall verdict.

The host recomputes the verdict; it does not trust the guest's summary. Anything
below is **ERROR**, never PASS: a missing, truncated, unfinished or foreign report;
a different run id or boot id (including a reboot during the run); a timeout; an
infrastructure error; a skipped or missing required scenario; a failed cleanup.
`missing-group.refusal` is always SKIP, so a fully green run reports coverage
`partial`.

## Recovery from an interrupted run

Use the Hyper-V console (the VM's window) when SSH is gone.

1. Log in as `l2admin`. Look at the job: `systemctl status rosetun-l2-<run id>.service`.
2. Stop it if it still runs: `sudo systemctl stop rosetun-l2-<run id>.service`. Its
   `ExecStopPost` finishes the report and runs the cleanup.
3. Read `/var/lib/rosetun-l2/<run id>/report/report.json` for the `cleanup` section.
4. If cleanup reported a problem, nothing was deleted on a guess. Inspect
   `stat /run/rosetun /run/rosetun/helper.sock` and `pgrep -a l2_transport_fixture`;
   remove only what the report names and you recognise as the stand's own.
5. The simplest full reset is `Restore-VMCheckpoint` of `l2-clean` from the host.
   `Get-VMCheckpoint -VMName rosetun-linux-l2 | Restore-VMCheckpoint` or the Hyper-V
   Manager does the same.

A run id is used once; start a new run instead of repeating an old one.

## Tests of the stand (no VM, no privileges)

```powershell
pwsh -NoProfile -File tools/vm/linux/tests/Test-LinuxHarness.ps1
```

```sh
bash tools/vm/linux/tests/selftest-lib.sh
```

They check report judgement, timeouts, foreign and incomplete reports, ELF and
provenance checks, and the guest cleanup that refuses foreign objects. They do not
replace a Hyper-V run.

## Next stages (not implemented here)

Each needs its own stand extension and a decision by the owner first:

- L3: a systemd unit for Rosetun and real helper lifecycle, engine identification.
- Kill switch and DNS lock on nftables, and the Linux contract for protection after
  a helper crash (the Windows fail-open expectation is **not** carried over).
- Lockdown, reboot and power-cut scenarios; the missing-group case on a clean VM.
- The `.deb` installer and desktop integration.
