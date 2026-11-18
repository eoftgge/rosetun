# Windows 11 guest image for the QEMU matrix

Status: **UNRUN.** The generators, the command lines and the failure handling were written and
checked offline (unit tests). The firmware (see "Firmware: Secure Boot without SMM") was built on the
stand and started once to the Windows Setup screen, which is all that has been run. No image has
been built and no Windows guest has been installed or measured with these files. The QEMU matrix
stays exploratory: release gate false, security invariants UNVERIFIED.

This directory prepares the guest image that the Windows matrices on QEMU will boot. It is not part
of the controller in `../matrix/` and it does not run in a matrix run. It is the offline half of the
image stage: the firmware build, the answer media, the first-logon script, the build command and
the measurement command. Building and measuring happen later, on the stand, by someone who has
installed the packages listed below.

## Decisions

- Windows 11 26H2 Pro, English, from the ordinary installation disc, **no product key, no
  activation**. The image is not activated and says so in its descriptor. The build refuses a disc
  whose volume label does not carry the configured language, before it creates anything.
- Guest firmware: UEFI (OVMF built by `build-ovmf.sh`: Secure Boot, TPM 2.0 support, no SMM) with a
  software TPM 2.0 (swtpm), Secure Boot on. **No setup check is lowered**: no `LabConfig`, no
  `BypassNRO`, no registry trick; Secure Boot is not turned off and no firmware without it is used.
  The local account comes from the documented `UserAccounts` and `OOBE` settings of the answer file.
- The guest is quiet because the operating system is configured to be quiet. Windows Firewall and
  the filtering platform are not touched, and the observer is not made more tolerant.
- Machine `q35`, `-cpu host,-vmx,-svm`. Hardware virtualization is hidden from the guest so Windows
  cannot start Hyper-V or virtualization-based security: that would stack a second hypervisor on
  WSL2's nested KVM, which is slow and changes timing, and the matrix gains nothing from it. Both
  flags are given because the one that matters depends on the host CPU (Intel VMX, AMD SVM); QEMU
  accepts a minus on a flag the host lacks and it does nothing.
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
| Windows 11 26H2 disc | the owner's file, for example `/mnt/d/Iso/win11_26h2.iso` in `example.toml`; used as it is | SHA-256 recorded in the descriptor (optionally pinned in the configuration) |
| virtio-win disc | downloaded by whoever builds the image | release and SHA-256 in the configuration; the build refuses a different file |
| OVMF code and variables | built by `build-ovmf.sh` from edk2 at a pinned tag | `firmware.json` records the tag, the commit, the flags, the tools and the SHA-256 of the three files; the descriptor records the hashes of the code, the template and the image's own copy of the variables |
| TPM emulator | Debian packages `swtpm`, `swtpm-tools` | the state directory is part of the image; its file hashes are in the descriptor |
| `qemu-ga` | the MSI on the virtio-win disc, `guest-agent\qemu-ga-x86_64.msi` | with the disc |

On the stand the packages are installed by the owner, once:

    sudo apt-get install swtpm swtpm-tools

The Debian `ovmf` package is not needed by the image; it is what the finding below was compared with.

## Firmware: Secure Boot without SMM

**Finding.** On the stand (an AMD host, WSL2 under Hyper-V, so KVM is nested, QEMU 10.0.13) the
Secure Boot firmware of Debian (`OVMF_CODE_4M.secboot.fd`, which needs `-machine q35,smm=on`) starts
and shows the boot menu. When the Windows 11 boot loader starts, its first system management
interrupt (a write to port `0xb2`) makes KVM fail the vCPU (`KVM: entry failed, hardware error
0xffffffff`, `SMM=1`, `EIP=00008000`) and QEMU stops in `internal-error` about 18 seconds in. Hiding
VMX or SVM does not change it. The same disc with the same machine but the firmware without Secure
Boot and without SMM (`OVMF_CODE_4M.fd`, `smm=off`) reaches the Setup screen. This is a limit of
system management mode under nested KVM on this stand, not of Windows or of the disc.

**The firmware used.** `build-ovmf.sh WORK_DIRECTORY` builds `OvmfPkg/OvmfPkgX64.dsc` of edk2 at a
pinned tag, `RELEASE`, with `-D SECURE_BOOT_ENABLE=TRUE -D SMM_REQUIRE=FALSE -D TPM2_ENABLE=TRUE
-D FD_SIZE_4MB`: the Debian flags, minus the network stack (`-D NETWORK_ENABLE=FALSE`), because
the guest boots from a disk and a disc and the build network has no PXE or HTTP boot server. It
needs `nasm`, `iasl` (`acpica-tools`) and the headers of `uuid-dev`, which the stand lacks and the
script does not install: it downloads the pinned Debian trixie packages, checks their SHA-256,
unpacks them with `dpkg -x` into the work directory and points `PATH`, `C_INCLUDE_PATH` and
`LIBRARY_PATH` at that prefix. The work directory must be outside the repository. The result is
`OVMF_CODE.fd`, `OVMF_VARS.fd` (the empty store), `OVMF_VARS.ms.fd` (the variable template with the
Microsoft keys enrolled) and `firmware.json` in `WORK_DIRECTORY/out`. The build is a few minutes
after the sources are cloned (they are large, with all submodules); start it in the background.

**The variable template.** Debian's `OVMF_VARS_4M.ms.fd` was checked first. It has the layout of
this build (same size, same firmware volume and variable store headers), and with it the Windows
disc reached Setup. It was not taken, for three reasons: its `db` and `KEK` hold only the 2011
Microsoft certificates, while the 2011 certificates expire in 2026 and newer media and updates are
signed with the 2023 ones; it carries boot entries left by the machine that made it (`UiApp` and a
hard disk entry); and it ties the image to a Debian package version. The template is therefore made
from the empty store of this build with virt-firmware (a pinned release, in a venv of the work
directory): a platform key generated for the lab whose private key is discarded, the Microsoft
2011 and 2023 certificates in `db` and `KEK` (`--microsoft-db all --microsoft-kek all`) and Secure
Boot on. The platform key is new in every build, so the hash of the template differs between builds;
`firmware.json` lists the certificates and the pip versions. `VARS_TEMPLATE=debian` selects the
Debian file, after the header comparison.

**What "Secure Boot without SMM" means.** Secure Boot is on and enforced: the platform key and the
Microsoft keys are enrolled, the firmware verifies what it loads, and Windows is expected to report it as enabled (`measure` asks it).
What is missing is the protection of the variable store. With SMM the store can be written only
from system management mode; without it, it is an ordinary flash device that the operating system
of the guest can write, so code running in the guest with enough privilege could change the keys
(`SecureBootEnable`, `db`) or the boot variables. It does not mean that Secure Boot is off, that
the checks of the installer are lowered, or that the firmware is the one of a product. It is
acceptable for a laboratory whose guest is not an adversary of its own firmware; the descriptor
says `varstore not SMM-protected` and `flavour secboot-nosmm`, and `smm = false` in the
configuration selects `-machine q35,smm=off` without the `secure=on` flash property. With
`smm = true` the command line is the one of the distribution firmware, as before.

**Checked on the stand (2026-11-19), and nothing more.** edk2 `edk2-stable202502`, commit
`fbe0805b2091393406952e84724188f8c1941837`, GCC 14.2, `nasm` 2.16.03, `iasl` 20250404, virt-firmware
25.12:

| File | SHA-256 |
|---|---|
| `OVMF_CODE.fd` (3 653 632 bytes) | `7284e023857eb36380043446f70865a549e9f7895dc0fe902958a423380c0cf1` |
| `OVMF_VARS.fd` (the empty store) | `5d2ac383371b408398accee7ec27c8c09ea5b74a0de0ceea6513388b15be5d1e` |
| `OVMF_VARS.ms.fd` (this build's platform key) | `809ab88766c2daa054db599a5f6553b5139dcf56a4cfb5c7071c6b417217283d` |

With this code, `smm=off`, the template, swtpm and `-cpu host,-vmx,-svm`, the Windows 11 26H2 disc
was booted with the space bar pressed for the first 30 seconds and left for 90: the machine stayed
`running` the whole time, QEMU printed nothing, and the screen was the Windows Setup language page.
The Debian template gave the same result. After that boot the variable store still held the
platform key, `KEK`, `db` and `SecureBootEnable` on. The firmware refuses what it should: an
unsigned UEFI application (the shell built from the same tree) on a disk is `Access Denied` with this
firmware, and starts with Debian's firmware without Secure Boot. What has not been run: an
installation, `Confirm-SecureBootUEFI` or `Get-Tpm` in a guest, anything with `smm = true` on this
code.

The wait for a failed machine was also tried on the real crash of the finding (Debian's firmware,
`smm=on`, the same disc): the watch saw `internal-error` after 17 seconds, took the screenshot,
printed the end of the QEMU log with the `entry failed` register dump, and QEMU and `swtpm` exited
with code 0 after the QMP `quit`. The label check read `CCCOMA_X64FRE_EN-US_DV9` from the disc.
The screenshot watch was tried on a real QEMU with shortened times (every 4 seconds, a stall after
20) on the static text screen of a firmware that has nothing to boot: it stopped the machine as
`screen-stalled`, kept only the last three frames, and QEMU and `swtpm` exited with code 0.

## Files

- `example.toml`: the configuration, every key explained.
- `image_config.py`: strict loading of the configuration.
- `image_answers.py`: `Autounattend.xml` and the answer media command (`xorriso`, label `ROSETUN_ANSWERS`).
- `first-logon.ps1`: the first-logon script, one logged step per measure.
- `build-ovmf.sh`: the firmware build (outside the controller, on the stand).
- `image_plan.py`: the `swtpm`, `qemu-img` and QEMU command lines, and the image descriptor.
- `image_guest.py`: small QMP and guest-agent clients (a key press, the run state, a screenshot, a ping,
  one program, one file) and the Secure Boot and TPM questions.
- `build_image.py`: the command: `plan`, `build`, `measure`.

The tests are `../matrix/tests/test_windows_image.py`.

## Steps

0. `bash build-ovmf.sh WORK_DIRECTORY` once, in the background, and copy `OVMF_CODE.fd` and
   `OVMF_VARS.ms.fd` from its `out` directory to where the configuration points.
1. Copy `example.toml` outside the repository and fill it in: the discs, the digest of the virtio-win
   disc, the tools, the firmware and `smm`, the output directory (it must not exist).
2. `python3 build_image.py plan CONFIG` prints every command and runs nothing. Read it.
3. `python3 build_image.py build CONFIG`. It verifies the discs (the virtio-win digest, then the
   language of the Windows disc from the volume label in its ISO 9660 header, such as
   `CCCOMA_X64FRE_EN-US_DV9`; another language is refused before the output directory is
   created), generates the password and the
   answer media, creates the qcow2 disk, copies the firmware variables, starts `swtpm` and QEMU,
   presses a key through QMP while the Windows disc asks for one (the answer file cannot answer
   that), and then waits for the guest to shut itself down at the end of the first-logon script.
   It then hashes the results and writes `image.json`. VNC is on `127.0.0.1:5900` plus
   `vnc_display`, for diagnostics only. The build is an unattended install of about 30 to 90
   minutes; the first sign of trouble is a screen that does not change for ten minutes.
   The command takes a screenshot every two minutes into `screens/` of the build directory (the last
   thirty stay as `screen-NNNN.ppm`) and writes the SHA-256 of each to `build.jsonl`, because QMP serves
   one client and nobody else can take one while the build waits. A frame that has not changed for
   twenty minutes ends the build as `screen-stalled`, the same way as a failed machine below: an
   out-of-box page that waits for an answer looks exactly like that, while copying files and restarts
   change the frame all the time.
   While it waits, the command asks QEMU for its run state every few seconds over QMP. A machine in
   `internal-error`, `guest-panicked`, `io-error` or `paused` ends the build at once with the
   reason, a screenshot (`failure-screen.ppm` in the build directory) and the end of `qemu.log`;
   QEMU is then told to quit over QMP and `swtpm` is stopped. The same happens when the time runs out.
4. `python3 build_image.py measure CONFIG` boots a copy of the image (an overlay, a copy of the
   firmware variables, a copy of the TPM state) and prints and stores `measure.json`.

## What is measured

- Boot to the guest agent: the seconds from QEMU start until the agent answers `guest-ping`. The
  agent is a service, so this is reached before anyone logs on; the image does not log on by itself
  after the build.
- CPU load at rest: the mean of `\Processor(_Total)\% Processor Time` over 60 one-second samples,
  starting 300 seconds after the agent became ready, taken with `typeperf` through `guest-exec`.
- Secure Boot and the TPM as the guest reports them, through the agent: `Confirm-SecureBootUEFI`
  must say `True`, and `Get-Tpm` must show `TpmPresent` and `TpmReady` true. Both go to
  `measure.json`. The boot of the measurement is watched in the same way as the build.
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
- a step of the first-logon log failed;
- Secure Boot is not confirmed enabled, or the TPM is not present and ready (`False` or an error is
  a stop, not a value to explain away).

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

## Measured on the stand

- Without a key element Setup of the 26H2 disc stops on the product key page. With
  `empty_product_key_element = true` (an empty element, never a key) it goes on, copies the files and
  restarts. The documentation says the element must not be empty, so this is a measured behaviour of
  this disc, not a recommendation; `example.toml` sets it.
- The out-of-box experience stopped on "Is this the right country or region?" because the answer file
  gave the language and the keyboard only in the windowsPE pass, whose component does not reach the
  installed system. The file now has `Microsoft-Windows-International-Core` with `InputLocale`,
  `SystemLocale`, `UILanguage` and `UserLocale`, from `language`, in `specialize` and in `oobeSystem`
  (the documentation lists exactly these two passes for each of the four settings). Whether it clears
  the page is the next run's result.

## Known risks, all UNRUN

- Of the `OOBE` settings the documentation lists, the file already has `HideEULAPage`,
  `HideOEMRegistrationScreen`, `HideOnlineAccountScreens`, `HideWirelessSetupInOOBE`,
  `NetworkLocation` and `ProtectYourPC` (3); `HideLocalAccountScreen` is there too although the
  documentation says it applies to Windows Server editions only, so it does nothing on Pro and the
  local account comes from `LocalAccounts`. `VMModeOptimizations` needs `sysprep /mode:vm` and is not
  used. The documentation says the sign-in page appears only when there is an Internet connection, and
  names no setting that removes the network page itself: with `network = "restricted"` the out-of-box
  experience may still ask for a network, and the answer is `network = "nat"` for the build, not
  `BypassNRO`.
- The disc language must match `language` (English by default): the guest agent output and the
  controller's parsing of it are written for English. The build checks the label of the disc, which
  names the language on Microsoft discs; a disc relabelled by someone else could pass it.
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
- Whether `-cpu host,-vmx,-svm` alone is fast enough, or the Hyper-V enlightenments of the run profile are
  needed, is a measurement for the next stage, not decided here.

## Not done here

- No activation, no key, no evaluation image.
- No bypass of any installer check, and no Windows Firewall rule, filter or policy.
- No Internet access from the laboratory; the build network is the user-mode one.
- No attachment of the guest to the lab, and no change to the controller, `images.py` or the
  observer: the controller does not accept this descriptor yet.
