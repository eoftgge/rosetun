# Windows 11 guest image for the QEMU matrix

Status: **UNRUN.** Everything here was written and checked offline (unit tests on the generators and
on the command lines). No image has been built and no Windows guest has been started with these
files. The QEMU matrix stays exploratory: release gate false, security invariants UNVERIFIED.

This directory prepares the guest image that the Windows matrices on QEMU will boot. It is not part
of the controller in `../matrix/` and it does not run in a matrix run. It is the offline half of the
image stage: the answer media, the first-logon script, the build command and the measurement
command. Building and measuring happen later, on the stand, by someone who has installed the
packages listed below.

## Decisions

- Windows 11 25H2 Pro from the ordinary installation disc, **no product key, no activation**. The
  image is not activated and says so in its descriptor.
- Guest firmware: UEFI (OVMF, the Secure Boot build) with a software TPM 2.0 (swtpm), Secure Boot
  on. **No setup check is lowered**: no `LabConfig`, no `BypassNRO`, no registry trick. The local
  account comes from the documented `UserAccounts` and `OOBE` settings of the answer file.
- The guest is quiet because the operating system is configured to be quiet. Windows Firewall and
  the filtering platform are not touched, and the observer is not made more tolerant.
- Machine `q35`, `-cpu host,-vmx`. VMX is hidden from the guest so Windows cannot start Hyper-V or
  virtualization-based security: that would stack a second hypervisor on WSL2's nested KVM, which
  is slow and changes timing, and the matrix gains nothing from it.
- Devices are the ones the Linux guests already use: virtio-blk (disk), virtio-net (test MAC
  `00:00:5e:00:53:61`), virtio-serial with the `org.qemu.guest_agent.0` port, plus the chipset's
  AHCI controller for the three discs of the build. The same devices, at the same PCI slots, are
  used by the measurement boot, and are meant for the runs: Windows ties its network settings to
  the adapter, so another device list or MAC would create a second adapter and drop the first
  one's settings. The profile name for the descriptor is `windows-uefi-q35-v1`; the controller does
  not know it yet.
- The build network is QEMU's user-mode stack with `restrict=on`: the guest gets an address and has
  no way out, neither to the lab nor to the Internet. The image is built from the disc alone, so
  nothing is downloaded and no update can land in it. If Setup insists on a network during OOBE,
  `network = "nat"` in the configuration lets the guest out during the build only; the first-logon
  script then switches updates off at the end, so use it only as a measured fallback.
- Power: shutdown is ACPI (the power button is set to shut down). Power cuts and sleep are other
  stages. S3 is off in the firmware because the Secure Boot build of OVMF cannot do it.
- The password of the local account is generated for each build, written once to
  `account-password.txt` in the build directory (mode 0600), and passed to Setup in the obfuscated
  form of the answer file. It is not in the repository, in any log or in the descriptor. The answer
  media, which carries it, is deleted at the end of a successful build.

## Sources

| Input | Where it comes from | Pinned by |
|---|---|---|
| Windows 11 25H2 disc | the owner's file, for example `/mnt/d/Iso/win11_25h2.iso` in `example.toml`; used as it is | SHA-256 recorded in the descriptor (optionally pinned in the configuration) |
| virtio-win disc | downloaded by whoever builds the image | release and SHA-256 in the configuration; the build refuses a different file |
| OVMF code and variables | Debian package `ovmf` (`OVMF_CODE_4M.secboot.fd`, `OVMF_VARS_4M.ms.fd`) | the variables file is copied per image; its SHA-256 is in the descriptor |
| TPM emulator | Debian packages `swtpm`, `swtpm-tools` | the state directory is part of the image; its file hashes are in the descriptor |
| `qemu-ga` | the MSI on the virtio-win disc, `guest-agent\qemu-ga-x86_64.msi` | with the disc |

On the stand the packages are installed by the owner, once:

    sudo apt-get install ovmf swtpm swtpm-tools

## Files

- `example.toml`: the configuration, every key explained.
- `image_config.py`: strict loading of the configuration.
- `image_answers.py`: `Autounattend.xml` and the answer media command (`xorriso`, label `ROSETUN_ANSWERS`).
- `first-logon.ps1`: the first-logon script, one logged step per measure.
- `image_plan.py`: the `swtpm`, `qemu-img` and QEMU command lines, and the image descriptor.
- `image_guest.py`: small QMP and guest-agent clients (a key press, a ping, one program, one file).
- `build_image.py`: the command: `plan`, `build`, `measure`.

The tests are `../matrix/tests/test_windows_image.py`.

## Steps

1. Copy `example.toml` outside the repository and fill it in: the discs, the digest of the virtio-win
   disc, the tools, the firmware, the output directory (it must not exist).
2. `python3 build_image.py plan CONFIG` prints every command and runs nothing. Read it.
3. `python3 build_image.py build CONFIG`. It verifies the discs, generates the password and the
   answer media, creates the qcow2 disk, copies the firmware variables, starts `swtpm` and QEMU,
   presses a key through QMP while the Windows disc asks for one (the answer file cannot answer
   that), and then waits for the guest to shut itself down at the end of the first-logon script.
   It then hashes the results and writes `image.json`. VNC is on `127.0.0.1:5900` plus
   `vnc_display`, for diagnostics only. The build is an unattended install of about 30 to 90
   minutes; the first sign of trouble is a screen that does not change for ten minutes.
4. `python3 build_image.py measure CONFIG` boots a copy of the image (an overlay, a copy of the
   firmware variables, a copy of the TPM state) and prints and stores `measure.json`.

## What is measured

- Boot to the guest agent: the seconds from QEMU start until the agent answers `guest-ping`. The
  agent is a service, so this is reached before anyone logs on; the image does not log on by itself
  after the build.
- CPU load at rest: the mean of `\Processor(_Total)\% Processor Time` over 60 one-second samples,
  starting 300 seconds after the agent became ready, taken with `typeperf` through `guest-exec`.
- Size of the image file and its SHA-256.
- The first-logon log (`C:\ProgramData\rosetun-image\first-logon.log`) read back through the agent:
  every step is `OK` or `FAIL`, and the log ends with a `done` line. A missing `done` line or any
  `FAIL` stops the stage.
- Not measured by this tool: the traffic of a resting guest on the lab wire. It needs the lab
  machine on the same wire as the test machine and a capture on the lab side for ten minutes of
  rest; the list of frames is the result. Nothing in this directory attaches a guest to the lab.

## Stop point

Do not go on to the next stage if any of these holds:

- boot to the agent takes more than 5 minutes;
- CPU load at rest is 10 % or more, 5 minutes after the agent became ready;
- the traffic of the resting guest is not understood, that is, a frame that cannot be named and
  explained;
- a step of the first-logon log failed.

The answer to a stop is a finding to bring to the owner, not an exception to add to the observer.

## Measures against background traffic

Each one is a step of `first-logon.ps1` with its reason in the same line. The source column names
the documentation each setting comes from. All of them are UNRUN: whether a setting does what it
says on this build of Windows is what the resting capture decides.

| Step | What it does | Documentation area (only the ones named above were read) |
|---|---|---|
| `hibernation-off`, `fast-startup-off` | `powercfg /h off`, `HiberbootEnabled=0`: shutdown is a full shutdown and a restart a new kernel boot | Microsoft Learn, Hibernate and fast startup settings (powercfg options) |
| `power-button-shutdown`, `no-idle-sleep` | power button action 3 (shut down); no idle standby, display or disk timeout | Microsoft Learn, powercfg command-line options |
| `boot-recovery-off` | `bcdedit`: `recoveryenabled No`, `bootstatuspolicy ignoreallfailures` | Microsoft Learn, BCDEdit command-line options |
| `automatic-maintenance-off` | `MaintenanceDisabled=1` | Microsoft Learn, Automatic Maintenance |
| `device-encryption-off` | `PreventDeviceEncryption`; the setting is also in the answer file. A volume sealed to the TPM could not start from a copy of the image | Microsoft Learn, SecureStartup-FilterDriver `PreventDeviceEncryption` |
| `windows-update-policy`, `-services`, `-medic`, `update-tasks-off` | `NoAutoUpdate=1`, `SetDisableUXWUAccess=1`, services `wuauserv` and `UsoSvc` disabled, `WaaSMedicSvc` disabled by a one-shot SYSTEM task, update scheduled tasks disabled | Microsoft Learn, Manage additional Windows Update settings |
| `delivery-optimization-off` | `DODownloadMode=0`, `DoSvc` disabled | Microsoft Learn, Delivery Optimization reference |
| `store-auto-update-off`, `edge-update-off` | Store `AutoDownload=2`; Edge updater services and policy, Edge background mode off | Microsoft Learn, Windows Store policies; Microsoft Edge update policies |
| `telemetry-policy`, `-services`, `-tasks`, `error-reporting-off` | `AllowTelemetry=0`; `DiagTrack` and `dmwappushservice` disabled; appraiser and CEIP tasks off; error reporting off. On Pro, the value 0 is documented only for Enterprise, Education and Server, so the services are what actually stops the upload | Microsoft Learn, Configure Windows diagnostic data in your organization |
| `defender-cloud-off` | Defender stays on; cloud protection and sample submission off by policy | Microsoft Learn, Microsoft Defender Antivirus cloud protection policies |
| `consumer-features-off`, `connected-devices-off` | consumer content, OneDrive file sync, search suggestions, news and widgets off; `CDPSvc` disabled | Microsoft Learn, Manage connections from Windows components to Microsoft services |
| `time-service-off` | `W32Time` disabled: no NTP; the clock is the host's RTC and the zone is UTC, so the two agree | Microsoft Learn, Windows Time service |
| `ncsi-active-probe-off` | `EnableActiveProbing=0` and `NoActiveProbe=1`: no query and no request for the connectivity test host | Microsoft Learn, Network Connectivity Status Indicator FAQ (the probe host is `www.msftconnecttest.com`) |
| `llmnr-off` | `EnableMulticast=0`, the policy "Turn off multicast name resolution" | Microsoft Learn, ADMX_DnsClient policy CSP |
| `mdns-off` | `Dnscache\Parameters\EnableMDNS=0` | Microsoft Learn, mDNS in Windows (DNS client) |
| `netbios-off` | `NetbiosOptions=2` on every interface | Microsoft Learn, NetBT parameters |
| `ssdp-upnp-off`, `ws-discovery-off`, `lltd-off` | services `SSDPSRV`, `upnphost`, `FDResPub`, `fdPHost` disabled; the LLTD driver bindings removed from the adapters | Microsoft Learn, Windows service reference |
| `dhcpv6-off` | `netsh interface ipv6 set interface managedaddress=disabled otherstateful=disabled` on every interface | Microsoft Learn, netsh interface ipv6 |
| `ipv6-transition-off` | Teredo, ISATAP and 6to4 off | Microsoft Learn, netsh interface teredo, isatap, 6to4 |

IGMP and MLD reports of the IP stack cannot be switched off and are not tried. The observer's
classifier already names the neighbour and multicast-listener ones; any other multicast group the
resting guest joins is a finding.

The Microsoft pages were read for the settings of the answer file (image selection, driver paths,
product key behaviour, `AutoLogon`, `HideOnlineAccountScreens`, `PreventDeviceEncryption`) and for
the connectivity indicator and diagnostic data behaviour. The rest of the table is from knowledge
of Windows and has not been checked line by line against the documentation of this release.

## Known risks, all UNRUN

- Setup with no product key and no key element may stop on the product key page. The fallback is
  `empty_product_key_element = true` (an empty element, never a key); the documentation says the
  element must not be empty, so this is a measured fallback, not a recommendation.
- The out-of-box experience of Windows 11 may still ask for a network or an account in spite of
  `HideOnlineAccountScreens`; the answer is `network = "nat"` for the build, not `BypassNRO`.
- The disc language must match `language` (English by default): the guest agent output and the
  controller's parsing of it are written for English.
- Drivers are listed for the drive letters D to G, because the setup environment names the discs
  by arrival order. A missing path is skipped; the first-logon script installs the same drivers again
  with `pnputil`.
- The virtio-win drivers are signed by Microsoft but not WHQL-certified. If Secure Boot refuses one,
  the finding is reported; the answer is not to turn Secure Boot off.
- `-device ...,bus=pcie.0,addr=...` places the devices at fixed slots. QEMU may refuse a slot; a
  refusal changes this table in `image_plan.py` and the run profile together.
- The TPM state and the firmware variables are part of the image: they hold the boot entry Setup
  wrote and the TPM's persistent state. A run must start from a copy of both, taken with the disk.
- Discard is on for the disk and the script retrims the volume; whether the driver passes it
  through decides how small the file is.
- Whether `-cpu host,-vmx` alone is fast enough, or the Hyper-V enlightenments of the run profile are
  needed, is a measurement for the next stage, not decided here.

## Not done here

- No activation, no key, no evaluation image.
- No bypass of any installer check, and no Windows Firewall rule, filter or policy.
- No Internet access from the laboratory; the build network is the user-mode one.
- No attachment of the guest to the lab, and no change to the controller, `images.py` or the
  observer: the controller does not accept this descriptor yet.
