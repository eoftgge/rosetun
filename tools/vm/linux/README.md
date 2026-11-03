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

## Quick start

After the one-time preparation below, commit what you want tested and run, from
the repository root in an elevated PowerShell 7:

```powershell
.\tools\vm\linux\Invoke-LinuxL2Matrix.ps1 -Run
```

It prints one line per stage and does, in order:

1. checks the host: administrator rights, the settings file, the pinned host key,
   WSL, the VM and its checkpoint;
2. builds exactly the committed `HEAD` in WSL into a new folder
   `target/l2-artifacts/<short sha>-<run id>` (it refuses a working tree with
   changes and lists them);
3. restores the checkpoint `l2-clean` and waits until the guest answers over SSH,
   at whatever address Hyper-V reports now;
4. checks that the guest is the stand (stand id, BIOS GUID, boot id) and copies
   the run to it;
5. starts the job through the installed launcher with `sudo -n` (no password);
6. waits for the job, reads the report back, prints the table and the path to
   `report.txt`.

It exits 0 only when the verdict is PASS. If the connection breaks while the job
runs, the job goes on in the guest; reconnect with
`.\tools\vm\linux\Invoke-LinuxL2Matrix.ps1 -Collect -RunId <run id> -WaitSeconds 1200`.

## Requirements on the host

- **Windows with Hyper-V** and the Hyper-V PowerShell module.
- **PowerShell 7.** The scripts start with `#Requires -Version 7.0`; Windows
  PowerShell 5.1 refuses them with a `#requires` error. Install it with
  `winget install Microsoft.PowerShell`.
- **Administrator rights**, because the Hyper-V cmdlets need them. Open Windows
  PowerShell as administrator (Start, right-click, "Run as administrator"), type
  `pwsh` in that window and `cd` to the repository. An elevated 5.1 window passes
  its rights to the `pwsh` started in it.
- The **Windows OpenSSH client** (`ssh`, `scp`, `ssh-keygen`), part of Windows.
- **WSL with Debian** as an ordinary default user, with git, a C linker and
  Rust 1.96.0 (the project MSRV):

  ```powershell
  wsl --install -d Debian
  ```

  ```sh
  sudo apt-get install git build-essential curl
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
  ~/.cargo/bin/rustup toolchain install 1.96.0
  ```

  You never work in WSL by hand: the host calls it. The build keeps a clone and
  the cargo cache in `~/.cache/rosetun-l2`, so a second build is quick.

## Layout

| File | Purpose |
|---|---|
| `Invoke-LinuxL2Matrix.ps1` | Host entry point: `-Run`, and the single steps `-InitKnownHosts`, `-PrepareLauncher`, stage (default), `-Collect` |
| `RosetunLinuxVm.psm1` | Host module: settings, SSH/SCP with a pinned host key, VM identity, the WSL build, artifact checks, report verdict |
| `stand.example.psd1` | The settings with documentation values; copy it to `stand.local.psd1` (git-ignored) |
| `build-in-wsl.sh` | Runs in WSL for the host: updates the stand's clone to `HEAD` and calls `build-artifacts.sh` |
| `build-artifacts.sh` | Builds the three Linux binaries inside Debian and records their provenance |
| `guest/install-launcher.sh` | One-time installation of the launcher and its sudoers rule in the guest |
| `guest/launch.sh` | The launcher: proves the staged files and hands over to the verified `start.sh` |
| `guest/start.sh` | Checks the run directory and starts the autonomous job |
| `guest/run-l2.sh`, `guest/lib.sh` | The job itself: scenarios, cleanup, report |
| `scenarios.tsv` | The scenario list, shared by the guest and the host |
| `tests/` | Unprivileged self-tests of the stand (not a VM run) |

Reports go to `tools/vm/linux/logs/<run id>/` (git-ignored): `stage.json`,
`report.json`, `report.txt`. The guest keeps its own copy in
`/var/lib/rosetun-l2/<run id>/report/`.

## Trust model

- The host talks to the guest over SSH with a key, `StrictHostKeyChecking=yes`
  and a `known_hosts` file of the stand only. The key is pinned under the stand id
  (`HostKeyAlias`), not under an address, so a new address keeps the check. There
  is no option to switch verification off, and no password, private key or
  credential is written to the repository, the stage or a report.
- The SSH account (`l2admin`) is an ordinary account. One sudoers rule,
  `/etc/sudoers.d/rosetun-l2`, lets it run **one path** as root without a
  password: the launcher `/usr/local/libexec/rosetun-l2/launch`. It is not
  `NOPASSWD: ALL`.
- **Plainly:** whoever holds the stand's SSH key gets root in this guest. The
  rule allows one path, but that path runs the stage the caller provides, so any
  code can run as root through it. What the single path does give: no general
  passwordless sudo, and every root run goes through the same checks. This is
  accepted because the key exists only for this stand and the VM is disposable
  and holds no data. Never install the launcher on a machine you care about.
- The launcher (root-owned, 0755, in a root-owned folder) checks the stage
  folder (`~l2admin/rosetun-l2-stage/<run id>`, 0700, owned by the account that ran
  `sudo`), proves the manifest against the hash the host computed, copies every
  listed file into `/var/lib/rosetun-l2/<run id>/` (root-owned, no group or other
  write) and verifies the copies. It then runs the **verified copy** of
  `guest/start.sh`. It never reads the job description and never starts the job
  itself.
- `start.sh` checks that the run directory holds exactly the files of this
  version, reads `job.env` through a strict reader and starts the job.
  Because the job's logic lives in the staged, verified `start.sh` and
  `run-l2.sh`, changing them needs no new launcher and no new checkpoint. Only a
  change of `guest/launch.sh` does; the host compares the installed launcher with
  the one in `HEAD` before every run and tells you.
- The job is a transient systemd unit (`rosetun-l2-<run id>.service`), independent
  of the SSH session. It has a time limit; when the unit stops for any reason an
  `ExecStopPost` closes the report and cleans up, so a killed job still yields a
  report that cannot pass.
- No firewall rule is added or changed. The stand never stops, edits or removes a
  foreign service, user, group or directory.

**Manual start with a password** stays as a fallback: when the launcher is not
installed, is an older version or `sudo -n` refuses, the host prints the exact
command, `sudo bash ~/rosetun-l2-stage/<run id>/guest/launch.sh <run id> <stage>
<manifest sha256>`, and waits. Paste it in the guest and enter the password; the
staged launcher checks itself against the manifest before anything runs.

## One-time preparation

Do the steps in this order. The checkpoint comes last.

### 1. The VM and Debian

On the host, in an elevated PowerShell:

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

### 2. Accounts, group and packages (in the guest)

The stand creates none of these:

```sh
sudo apt-get install --no-install-recommends util-linux procps coreutils openssh-server sudo hyperv-daemons
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
- `l2admin` is the account SSH logs into. It is **not** one of the test accounts.
  Its password is needed once for the launcher installation and for the manual
  fallback.
- `hyperv-daemons` reports the guest's address to Hyper-V, which is how the host
  finds the guest after every restore. Check on the host:
  `(Get-VMNetworkAdapter -VMName rosetun-linux-l2).IPAddresses` lists an IPv4 address.
- `/etc/rosetun-l2-stand-id` is the identifier the host checks, so a second Linux
  VM can never be mistaken for the stand. Use your own value as `StandId`.
- The group is `rosetun` exactly. Do not rename or remove it for any test.

### 3. SSH key and the settings file

On the host, make a key that is used only for this stand and install its public
half in the guest:

```powershell
ssh-keygen -t ed25519 -f "$env:USERPROFILE\.ssh\rosetun-l2" -C rosetun-l2-stand
Get-Content "$env:USERPROFILE\.ssh\rosetun-l2.pub"    # paste into ~l2admin/.ssh/authorized_keys in the guest
```

In the guest, as `l2admin`: `mkdir -p -m 700 ~/.ssh`, put the line into
`~/.ssh/authorized_keys` and `chmod 600 ~/.ssh/authorized_keys`.

Then copy the settings and change the values to yours:

```powershell
Copy-Item tools\vm\linux\stand.example.psd1 tools\vm\linux\stand.local.psd1
notepad tools\vm\linux\stand.local.psd1
```

`stand.local.psd1` is git-ignored. Leave `SshHost` empty to take the address from
Hyper-V. A parameter on the command line (`-VmName`, `-SshHost`, ...) wins over
the file.

### 4. Pin the guest's host key

```powershell
.\tools\vm\linux\Invoke-LinuxL2Matrix.ps1 -InitKnownHosts
```

It works only while `KnownHostsPath` is missing or empty. It connects once,
receives the ed25519 host key into a pending file and prints its fingerprint. On
the **VM console** (the Hyper-V window, not SSH) run:

```sh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Type `yes` only if both SHA256 values are equal. Anything else deletes the
pending key and nothing is kept. `ssh-keyscan` is not used: the Windows build
cannot agree on a key exchange with OpenSSH 10 in Debian 13 and writes an empty
file. The stand reads only its own file; your normal `known_hosts` is untouched.

### 5. The launcher

```powershell
.\tools\vm\linux\Invoke-LinuxL2Matrix.ps1 -PrepareLauncher
```

It copies `launch.sh` and `install-launcher.sh` to `~/rosetun-l2-launcher/` in the
guest and prints the command to run there as `l2admin`:

```sh
sudo bash ~/rosetun-l2-launcher/install-launcher.sh ipc_owner ipc_other
```

It installs `/usr/local/libexec/rosetun-l2/launch` and `/etc/sudoers.d/rosetun-l2`
(checked with `visudo` first) and prints the rule, which reads
`l2admin ALL=(root) NOPASSWD: /usr/local/libexec/rosetun-l2/launch`. It refuses
when `sudo` was run by root or by one of the two test accounts. Running it again
is harmless; `sudo bash ~/rosetun-l2-launcher/install-launcher.sh --remove`
removes both files.

### 6. The clean checkpoint

Check in the guest that `/run/rosetun` does not exist, no Rosetun service or
helper process is installed or running, and the guest is idle. Then, on the host:

```powershell
Checkpoint-VM -Name rosetun-linux-l2 -SnapshotName l2-clean
```

Every run starts by restoring this checkpoint, so it must already hold the
account, the key in `authorized_keys`, `hyperv-daemons` and the launcher. A
checkpoint taken before any of them brings the guest back without it: without the
key the host cannot log in, without the launcher every run falls back to the
password. After you change any of it, make the checkpoint again:

```powershell
Remove-VMCheckpoint -VMName rosetun-linux-l2 -Name l2-clean
Checkpoint-VM -Name rosetun-linux-l2 -SnapshotName l2-clean
```

## The single steps

`-Run` chains these; each also works alone.

- **Stage** (no mode switch): builds `HEAD`, checks the guest, copies the run and
  starts it through the launcher, or prints the manual command. It restores a
  checkpoint only with `-RestoreCheckpoint l2-clean`.
- **A given build:** `-ArtifactDir <folder>` (with Stage or `-Run`) skips the WSL
  build and takes a folder made by `build-artifacts.sh`. Its origin is
  confirmed only when its `provenance.json` records the same commit and working
  tree as the checkout; otherwise the report says `UNCONFIRMED`.
- **Collect:** `-Collect -RunId <run id> [-WaitSeconds 1200]` reads a run back
  and judges it, any time after a break in SSH.

Old artifact folders under `target/l2-artifacts/` are kept; delete them yourself
when you no longer need them.

## The report

`report.txt` (table) and `report.json` list the run id, source SHA and dirty status
(with the names of the changed paths, never their content), the hash of every
artifact and whether their origin is confirmed, OS, kernel, architecture, systemd
and boot id, then per scenario: expectation, evidence kind, PASS / FAIL / SKIP /
ERROR, the reason and the duration, then the cleanup result and the overall
verdict.

The host recomputes the verdict; it does not trust the guest's summary. Anything
below is **ERROR**, never PASS: a missing, truncated, unfinished or foreign report;
a different run id or boot id (including a reboot during the run); a timeout; an
infrastructure error; a skipped or missing required scenario; a failed cleanup.
`missing-group.refusal` is always SKIP, so a fully green run reports coverage
`partial`.

## When something goes wrong

- **The address changed** (after a reboot or a restore): nothing to do. The host
  reads the address from Hyper-V on every try and the key is pinned by stand id.
  If Hyper-V reports no IPv4 address, check `hyperv-daemons` in the guest, or put
  the address into `SshHost` for the moment.
- **The host key did not match** (`REMOTE HOST IDENTIFICATION HAS CHANGED` or
  `Host key verification failed`): stop. Compare
  `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the console with the
  pinned file (`ssh-keygen -lf <KnownHostsPath>`). Only if the guest was really
  reinstalled, delete the file, run `-InitKnownHosts` again and make the
  checkpoint again. A file made before keys were pinned by stand id holds an
  address and fails the same way: delete it and run `-InitKnownHosts`.
- **`sudo -n` refused** or the launcher is missing or old: the host prints the
  reason, the manual command for this run, and when the launcher is old, the steps
  to reinstall it (restore `l2-clean`, `-PrepareLauncher`, `install-launcher.sh`,
  make the checkpoint again). Check the rule with `sudo -l` as `l2admin`.
- **The build refused dirty paths:** the host builds only the committed `HEAD`.
  Commit, stash or delete the listed paths; git-ignored paths do not count.
- **`Build origin: UNCONFIRMED`:** only with `-ArtifactDir`. The folder was built
  from another commit or working tree than the checkout. Run without
  `-ArtifactDir`, or build that folder from the commit you have checked out.
- **The build in WSL failed** with "missing in WSL": install what it names (see
  the requirements above). A "moved to" message means `HEAD` changed during the
  run; start again.

## Recovery from an interrupted run

Use the Hyper-V console (the VM's window) when SSH is gone.

1. Log in as `l2admin`. Look at the job: `systemctl status rosetun-l2-<run id>.service`.
2. Stop it if it still runs: `sudo systemctl stop rosetun-l2-<run id>.service`. Its
   `ExecStopPost` finishes the report and runs the cleanup.
3. Read `/var/lib/rosetun-l2/<run id>/report/report.json` for the `cleanup` section.
4. If cleanup reported a problem, nothing was deleted on a guess. Inspect
   `stat /run/rosetun /run/rosetun/helper.sock` and `pgrep -a l2_transport_fixture`;
   remove only what the report names and you recognise as the stand's own.
5. The simplest full reset is the next `-Run`, which restores `l2-clean` first.

A run id is used once; start a new run instead of repeating an old one.

## Tests of the stand (no VM, no privileges)

```powershell
pwsh -NoProfile -File tools/vm/linux/tests/Test-LinuxHarness.ps1
```

```sh
bash tools/vm/linux/tests/selftest-lib.sh
```

They check report judgement, timeouts, foreign and incomplete reports, ELF and
provenance checks, settings and their precedence, address selection, host key
pinning, the start mode, the launcher's and `start.sh`'s path lists, the sudoers
rule and the installer's refusals, and the guest cleanup that refuses foreign
objects. They do not replace a Hyper-V run.

## Next stages (not implemented here)

Each needs its own stand extension and a decision by the owner first:

- L3: a systemd unit for Rosetun and real helper lifecycle, engine identification.
- Kill switch and DNS lock on nftables, and the Linux contract for protection after
  a helper crash (the Windows fail-open expectation is **not** carried over).
- Lockdown, reboot and power-cut scenarios; the missing-group case on a clean VM.
- The `.deb` installer and desktop integration.
