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
them. L2 makes **no claim** about the network, a kill switch, systemd
integration of Rosetun, engines or Lockdown. The kill switch on the real
service is the separate L3 run ("L3" below); Lockdown is a later stage.

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
3. restores the checkpoint `l2-clean` (taken from the powered-off VM), boots the
   guest and waits until it answers over SSH, at whatever address Hyper-V
   reports now;
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
| `Invoke-LinuxL2Matrix.ps1` | Host entry point: `-Run` (L2), `-Run -Stage L3`, and the single steps `-InitKnownHosts`, `-PrepareLauncher`, stage (default), `-Collect` |
| `RosetunLinuxVm.psm1` | Host module: settings, SSH/SCP with a pinned host key, VM identity, the WSL build, artifact checks, report verdict |
| `stand.example.psd1` | The settings with documentation values; copy it to `stand.local.psd1` (git-ignored) |
| `build-in-wsl.sh` | Runs in WSL for the host: updates the stand's clone to `HEAD` and calls `build-artifacts.sh` |
| `build-artifacts.sh` | Builds the three L2 binaries (or, with `--l3`, the release helper and CLI) inside Debian and records their provenance |
| `guest/install-launcher.sh` | One-time installation of the launcher and its sudoers rule in the guest |
| `guest/launch.sh` | The launcher: proves the staged files and hands over to the verified `start.sh` |
| `guest/start.sh` | Checks the run directory and starts the autonomous job of its stage |
| `guest/run-l2.sh`, `guest/lib.sh` | The L2 job itself: scenarios, cleanup, report |
| `guest/run-l3.sh` | The L3 job: installs the service, kill switch, DNS lock, IPv6, inbound and forwarding scenarios (a peer network namespace), crashes, cleanup, report |
| `scenarios.tsv`, `scenarios-l3.tsv` | The scenario lists, shared by the guest and the host |
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
helper process is installed or running, and the guest is idle. Then **shut the
VM down** and take the checkpoint of the powered-off VM, on the host:

```powershell
Stop-VM -Name rosetun-linux-l2
Checkpoint-VM -Name rosetun-linux-l2 -SnapshotName l2-clean
```

Why powered off: the Default Switch gets a new subnet at every Windows boot. A
checkpoint of a running guest holds its memory, so a restore resumes the guest
with the address of the old subnet, and after a host reboot the host cannot
reach it (SSH stays silent). A powered-off checkpoint makes every run a fresh
boot that takes an address of the current subnet; the stand checks the boot id
after that boot anyway. `-Run` refuses a checkpoint with memory (the VM comes
back `Saved` after the restore) and prints the commands below.

Every run starts by restoring this checkpoint, so it must already hold the
account, the key in `authorized_keys`, `hyperv-daemons` and the launcher. A
checkpoint taken before any of them brings the guest back without it: without the
key the host cannot log in, without the launcher every run falls back to the
password. After you change any of it, make the checkpoint again:

```powershell
Stop-VM -Name rosetun-linux-l2
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
  the address into `SshHost` for the moment (and empty it again afterwards).
- **The guest does not answer over SSH after a host reboot.** The error names
  the address Hyper-V reported, the host's `vEthernet (Default Switch)` subnet
  and whether they match. "Same subnet: no" means the guest resumed with an old
  address: `l2-clean` was taken from a running VM (`-Run` refuses that now) or
  `SshHost` holds an old address. Make the checkpoint from the powered-off VM
  (see "The clean checkpoint") and empty `SshHost`. "Same subnet: yes" points at
  the guest itself: look at the VM console (`systemctl status ssh`, `ip addr`).
- **`-Run` refused the checkpoint** ("holds the memory of a running guest"):
  run the four commands it printed: restore and start, check the guest is
  clean, `Stop-VM`, remove and take the checkpoint again.
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

## Manual service installation for checking

Not part of `-Run` and not judged by the stand: these steps put the real helper
under systemd in the stand VM by hand, from `packaging/linux/`. Restore
`l2-clean` first, and never take a checkpoint afterwards: the clean checkpoint
must not hold a Rosetun service (see "The clean checkpoint"). When you are done
checking, restore `l2-clean` again.

1. **Build** the helper and the CLI of the commit you check, in WSL, on the host
   (`D:\path\to\rosetun` is your checkout; the Linux build gets its own target
   folder so it never mixes with the Windows one):

   ```powershell
   wsl -d Debian --exec bash -lc 'cd /mnt/d/path/to/rosetun && export CARGO_TARGET_DIR=$HOME/.cache/rosetun-manual && cargo +1.96.0 build --release --locked -p rosetun-helper-privileged -p rosetun && mkdir -p target/linux-manual && cp $CARGO_TARGET_DIR/release/rosetun-helper-privileged $CARGO_TARGET_DIR/release/rosetun packaging/linux/rosetun-helper.service packaging/linux/rosetun-lockdown.service packaging/linux/io.github.eoftgge.rosetun.policy packaging/linux/rosetun.sysusers target/linux-manual/'
   ```

2. **Copy** them to the guest with the stand's key and pinned host key
   (`<address>` from `(Get-VMNetworkAdapter -VMName rosetun-linux-l2).IPAddresses`,
   the alias is your `StandId`):

   ```powershell
   ssh -i "$env:USERPROFILE\.ssh\rosetun-l2" -o UserKnownHostsFile="$env:USERPROFILE\.ssh\rosetun-l2.known_hosts" -o HostKeyAlias=rosetun-l2-stand-1 -o StrictHostKeyChecking=yes l2admin@<address> 'mkdir -p -m 700 rosetun-manual'
   scp -i "$env:USERPROFILE\.ssh\rosetun-l2" -o UserKnownHostsFile="$env:USERPROFILE\.ssh\rosetun-l2.known_hosts" -o HostKeyAlias=rosetun-l2-stand-1 -o StrictHostKeyChecking=yes target\linux-manual\* l2admin@<address>:rosetun-manual/
   ```

3. **Engines**, in the guest as `l2admin`. The versions must be the pinned
   ones (`SUPPORTED_SING_BOX_VERSION` and `SUPPORTED_XRAY_VERSION` in the engine
   crates; 1.14.3 and 26.10.21 at the time of writing). Compare each archive with
   the checksum its release page publishes before you install it:

   ```sh
   cd ~/rosetun-manual
   sudo apt-get install --no-install-recommends curl unzip nftables
   curl -fLO https://github.com/SagerNet/sing-box/releases/download/v1.14.3/sing-box-1.14.3-linux-amd64.tar.gz
   curl -fLO https://github.com/XTLS/Xray-core/releases/download/v26.10.21/Xray-linux-64.zip
   sha256sum sing-box-1.14.3-linux-amd64.tar.gz Xray-linux-64.zip
   tar -xzf sing-box-1.14.3-linux-amd64.tar.gz --strip-components=1 sing-box-1.14.3-linux-amd64/sing-box
   unzip -o Xray-linux-64.zip xray
   ```

4. **Install** (root, 0755 binaries in a root-owned folder: the helper refuses
   engines that anyone but root can change, and every folder above them must be
   root's too):

   ```sh
   cd ~/rosetun-manual
   sudo install -d -m 0755 -o root -g root /usr/lib/rosetun
   sudo install -m 0755 -o root -g root rosetun-helper-privileged rosetun sing-box xray /usr/lib/rosetun/
   sudo ln -sfn /usr/lib/rosetun/rosetun /usr/local/bin/rosetun
   sudo install -m 0644 -o root -g root rosetun-helper.service /usr/lib/systemd/system/rosetun-helper.service
   sudo install -m 0644 -o root -g root rosetun-lockdown.service /usr/lib/systemd/system/rosetun-lockdown.service
   sudo install -m 0644 -o root -g root io.github.eoftgge.rosetun.policy /usr/share/polkit-1/actions/io.github.eoftgge.rosetun.policy
   sudo install -m 0644 -o root -g root rosetun.sysusers /usr/lib/sysusers.d/rosetun.conf
   sudo systemd-sysusers
   sudo systemctl daemon-reload
   sudo systemctl enable rosetun-lockdown
   sudo systemctl enable --now rosetun-helper
   systemctl status rosetun-helper
   ```

   The kill switch needs `/usr/sbin/nft` (package `nftables`, installed above),
   cgroup v2 and the unit's delegated cgroup. Check that the helper moved into
   its leaf and that engines have theirs:

   ```sh
   systemctl show -p Delegate rosetun-helper
   cat /proc/$(systemctl show -p MainPID --value rosetun-helper)/cgroup
   ls -d /sys/fs/cgroup/system.slice/rosetun-helper.service/engines
   journalctl -u rosetun-helper -b | grep -E 'cgroup|kill switch'
   ```

   Expected: `Delegate=yes`, `0::/system.slice/rosetun-helper.service/helper`,
   the `engines` folder, and "engines start in their own cgroup" with no
   "the kill switch is not available" line.

   `systemd-sysusers` creates group `rosetun` only where it is missing; in the
   stand it already exists (step 2 of the preparation).

5. **Group membership.** Only members of `rosetun` may connect. Add the account
   that runs the CLI or the GUI, then log out and in again: a session keeps the
   groups it started with (`id` shows `rosetun` once it took effect):

   ```sh
   sudo usermod -aG rosetun <account>
   ```

6. **The table.** While a session with the kill switch or the DNS lock runs, and
   after a crash of the helper, the rules are in one table:

   ```sh
   sudo nft list table inet rosetun
   ```

   A normal stop (`systemctl stop`, a disconnect) removes it; "Error: No such
   file or directory" then means no table. After a crash of a kill-switch
   session the restarted helper keeps it (`rosetun status` says `network: held
   closed`) until a connect or `rosetun open-network`; a DNS lock alone it
   removes at once, and says so in the journal.

   The kill switch also closes what the machine forwards (chain `forward`):
   containers, virtual machines and a shared connection get only the tunnel,
   the local network with "Local network", and answers to connections opened
   towards them. Those whose traffic does not take the tunnel lose the
   network while the kill switch is on. The DNS lock drops only their DNS
   beside the tunnel.

7. **Lockdown.** The helper offers it only while `rosetun-lockdown.service` is
   enabled (a link in `sysinit.target.wants`, made by `systemctl enable` in
   step 4; enable it before the helper starts, which reads it at start).
   Turn it on as root, or from the GUI, which asks for an administrator's
   password through polkit (`pkexec`):

   ```sh
   sudo rosetun lockdown on            # or: sudo rosetun lockdown on --lan on
   rosetun status                      # lockdown: on
   sudo cat /var/lib/rosetun/lockdown  # the record the boot unit reads
   sudo nft list table inet rosetun    # chains input, output, forward, policy drop
   ```

   Without a connection only the GUI and the CLI get out (TCP and DNS), and
   only from their own user scopes (`app.slice/rosetun-gui.scope`,
   `rosetun-cli.scope`), which they make themselves with
   `systemd-run --user --scope`; the account must be in group `rosetun` and
   have a running user manager (`systemctl --user` works). Install the GUI as
   `/usr/lib/rosetun/rosetun-gui` for its permit; without that file only the
   CLI has one. The table survives `systemctl stop rosetun-helper` and a
   crash. After a reboot `rosetun-lockdown.service` writes it again before
   the network comes up:

   ```sh
   systemctl status rosetun-lockdown
   journalctl -b -o short-monotonic -u rosetun-lockdown -u NetworkManager -u systemd-networkd -u networking | head
   ```

   The way out without the service: `sudo rosetun reset-firewall` stops the
   helper, removes the table and the record, and starts the helper again.
   `sudo rosetun lockdown off` does the same through the running service.

8. **Removal**, if you do not simply restore `l2-clean`:

   ```sh
   sudo rosetun reset-firewall
   sudo systemctl disable --now rosetun-helper
   sudo systemctl disable rosetun-lockdown
   sudo rm -f /usr/lib/systemd/system/rosetun-helper.service /usr/lib/systemd/system/rosetun-lockdown.service /usr/share/polkit-1/actions/io.github.eoftgge.rosetun.policy /usr/lib/sysusers.d/rosetun.conf /usr/local/bin/rosetun
   sudo rm -rf /usr/lib/rosetun /var/lib/rosetun
   sudo systemctl daemon-reload
   ```

What the unit does: `Type=notify` (the helper reports ready once its socket is
published), `/run/rosetun` and `/var/lib/rosetun` created by systemd
(`RuntimeDirectory`, `StateDirectory`) and the runtime one removed on every stop
or crash, so a killed helper's socket never blocks the restart, `KillMode=mixed`
(the helper stops its engines itself), `Restart=on-failure` and `Delegate=yes`
(the helper's own cgroup leaves, for the kill switch). The comments in the unit
file explain each line.

## L3: the kill switch on the real service

A separate command on the same VM. It installs the real helper as the systemd
unit from the build of `HEAD`, connects through the host's test node and
checks the nftables kill switch and DNS lock from inside the guest:

```powershell
.\tools\vm\linux\Invoke-LinuxL2Matrix.ps1 -Run -Stage L3 -SingBoxPath .\tools\sing-box.exe -SingBoxLinuxPath .\target\sing-box-linux\sing-box
```

`-SingBoxPath` is the Windows `sing-box.exe` of the Windows matrices: the host
runs the same test node (`../windows/RosetunVm.psm1`, `Start-RosetunTestNode`,
Shadowsocks on TCP 8388 at the host's Default Switch address; the one-time
firewall rule of the Windows guide must exist). A node already listening is
reused and left running; one the run started is stopped at the end.
`-NodeBindInterface` is passed on to it. `-RequestPath` (default
`../windows/request-local.json`) gives the node's credentials and settings;
the run makes three requests from it with the node pointed at the host:
kill switch without and with "Local network", and without the kill switch
(the DNS lock). `-ProbeAddress` (default `1.1.1.1`) must answer HTTPS from the
guest without a tunnel and through the node. The DNS lock is checked with one
UDP datagram to port 53 of `-DnsProbeAddress` (by default the request's DNS
server when that is an IPv4 address, else `-ProbeAddress`), sent by curl as a
TFTP request bound to the physical interface. Nobody has to answer it: a drop
in the output hook fails `sendto()` in the guest at once ("Operation not
permitted"), while a datagram that left is just unanswered. So the check does
not depend on whether the network lets DNS to that resolver through (the
first runs showed TCP 53 to `1.1.1.1` and `77.88.8.8` dropped outside the
guest, which a TCP check cannot tell from the lock).

`-SingBoxLinuxPath` is the Linux engine the helper runs, the version in
`SUPPORTED_SING_BOX_VERSION` (1.14.3 at the time of writing). Download it on
the host and compare the archive's SHA-256 with the release page before you
use it:

```powershell
New-Item -ItemType Directory -Force target\sing-box-linux | Out-Null
Invoke-WebRequest https://github.com/SagerNet/sing-box/releases/download/v1.14.3/sing-box-1.14.3-linux-amd64.tar.gz -OutFile target\sing-box-linux\sing-box.tar.gz
Get-FileHash target\sing-box-linux\sing-box.tar.gz
tar -xzf target\sing-box-linux\sing-box.tar.gz -C target\sing-box-linux --strip-components=1 sing-box-1.14.3-linux-amd64/sing-box
```

**Before the first L3 run** the clean checkpoint needs `nftables`, `curl` and
`dig`: restore `l2-clean`, start the VM, run
`sudo apt-get install --no-install-recommends nftables curl bind9-dnsutils` in
the guest, then make the checkpoint again from the powered-off VM ("The clean
checkpoint" above). Nothing else changes: the launcher is the same.

The run restores `l2-clean` before it starts and again after it has read the
report (the VM is left off), so the service never stays in a checkpoint or a
running guest. The report cannot be collected later with `-Collect`: the
restore after the run removes the guest's copy, and the host keeps
`report.txt` and `report.json` under `tools/vm/linux/logs/<run id>`. The job's
own limit is 30 minutes (`-JobTimeoutSeconds`).

In the guest, as root, from a transient unit like L2 (the kill switch may cut
SSH off; the host reads the report afterwards):

| Scenario | Proof |
|---|---|
| `preflight.*` | stand id, boot id, BIOS GUID; nothing of Rosetun installed and no table `inet rosetun`; `nft`, `curl` with tftp, `dig`, cgroup v2; on the physical interface HTTPS to the probe address and TCP to the host node answer and UDP 53 leaves; `dig` with the guest's resolver answers |
| `install.service` | the unit starts, `/proc/<MainPID>/cgroup` is `…/rosetun-helper.service/helper`, the `engines` leaf exists, the journal has no "kill switch is not available" |
| `killswitch.direct-blocked` | with the kill switch, `curl --interface <physical>` to the probe address is refused (curl exit 7 or 28) and the table exists |
| `killswitch.tunnel-passes` | the same HTTPS request without `--interface` (through the tunnel) answers |
| `lan.off` | TCP to the host node on the physical interface is refused |
| `killswitch.foreign-table` | a table `inet rosetun-l3-foreign` with an accept-all output chain at priority -200 does not open the direct path; the stand deletes only that table |
| `killswitch.engine-killed` | `pkill -KILL sing-box`, then a direct probe every 0.3 s until `Connected` again: every probe refused, the table always there |
| `killswitch.disconnect` | a disconnect removes the table, the direct path answers |
| `lan.on` | with "Local network" the host node connects on the physical interface, the probe address does not |
| `dnslock.*` | without the kill switch: UDP 53 on the physical interface is refused in the guest ("Operation not permitted"), HTTPS to the probe address there answers; `dig` with the guest's resolver is answered through the tunnel |
| `ipv6.neighbor` | only with an IPv6 default router on the physical interface that answers a ping without Rosetun, else SKIP (not required): with the kill switch and "Local network", `ip -6 neigh flush`, then the router answers a ping on its link-local address (neighbor discovery passed), and a UDP datagram to `2001:db8::1` on the physical interface is refused in the guest |
| `inbound.reply` | a peer namespace `rosetun-l3-peer` on a veth pair (`198.51.100.1` guest, `198.51.100.2` peer) opens TCP to the guest's sshd and reads its banner; then the kill switch without "Local network" goes up and the peer still gets sshd's key exchange after sending its own banner; a UDP datagram from the guest to the peer is refused in the guest |
| `forward.blocked` | the guest forwards the peer's traffic (`ip_forward`, a NAT table `ip rosetun-l3-nat`, a routing rule that sends it out of the physical interface past the tunnel): HTTPS from the peer to the probe address answers before the connect, is dropped under the kill switch and answers after the disconnect; the stand then removes the namespace, the table and the rule and restores `ip_forward` |
| `crash.helper-killed` | `kill -KILL` of the helper: the table stays, the direct path stays refused, systemd restarts the helper (`NRestarts`), `rosetun status` says `network: held closed` |
| `crash.open-network` | `rosetun open-network` as the first account removes the table, the direct path answers |
| `crash.dns-lock-killed` | `kill -KILL` of the helper during a DNS-lock session: the table is there right after, the restarted helper removes it and its journal says "removed the DNS lock a crashed helper left", the status is not `held closed`, UDP 53 and HTTPS leave the physical interface |
| `stop.removes-table` | `systemctl stop` during a kill-switch session removes the table, the direct path answers |

What it does not prove: TCP 53 under the DNS lock (a dropped SYN looks like a
lost one; the rule matches both by `meta l4proto { tcp, udp }`); IPv6 where the
Default Switch gives the guest no IPv6 router (`ipv6.neighbor` is then
skipped); a session from the host itself (the peer namespace stands in for it,
because the host opens a new SSH connection for each step); an outgoing
connection opened before the kill switch while conntrack did not yet track it;
Lockdown (not offered on Linux); a
reboot or a power cut with the table in place; the GUI. The cleanup stops the
service, which removes its table; a table still there after the stop is a
cleanup ERROR and is left for the checkpoint restore, never deleted by the
stand.

## Next stages (not implemented here)

Each needs its own stand extension and a decision by the owner first:

- Lockdown on Linux; reboot and power-cut scenarios with the table in place.
- The missing-group case on a clean VM.
- The `.deb` installer and desktop integration.
