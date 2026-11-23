+++
title = "Install"
weight = 1

[extra]
group = "Getting started"
toc_labels = { "debian-13" = "Debian 13", "macos" = "macOS (Apple Silicon)" }
+++

{%- set r = load_data(path="data/release.json", required=false) -%}
## Requirements {#requirements}

**Windows:** Windows 11, x64. Windows 10 runs on one tester's computer; the failure tests have not run on it.

**Linux:** amd64 with systemd, nftables and cgroup v2. Debian 13 is the reference distribution. With polkit (`pkexec`, `polkitd`) you can change Lockdown in the app. You can also run `sudo rosetun lockdown on` or `sudo rosetun lockdown off` in a terminal.

**macOS (Apple Silicon) · experimental build:** macOS 14 Sonoma or later on Apple Silicon (`arm64`). Intel Macs are not supported. Kill switch and Lockdown are unavailable on macOS.

## Windows {#windows}

Download `{{ r?.installer or "rosetun-<version>-setup.exe" }}` from [Releases]({{ r?.download_url or "https://github.com/eoftgge/rosetun/releases" }}). The installer is not code-signed yet; if SmartScreen says "Windows protected your PC", select **More info** and then **Run anyway**. See the [code signing policy](https://github.com/eoftgge/rosetun/blob/master/CODE_SIGNING_POLICY.md).

You can choose an installation folder, but not inside a user profile or where standard users can change it; the SYSTEM service requires a protected folder. Uninstalling keeps your configuration in `%APPDATA%\Rosetun` by default, or you can choose to delete your settings, subscriptions and rules.

**Update:** run the new installer over the old version. With the kill switch on, the network stays closed through the update, and the app starts and connects again. If it cannot connect, the connection screen offers **Connect** and **Open network**; `rosetun open-network` does the same. Lockdown stays on.

From 0.7 on Windows, the new-version notice offers **Download**: the app downloads the installer and checks it, then the button becomes **Install and restart**. The install asks for administrator rights. **Open on GitHub** and **Skip this version** are there too. On Linux and macOS, updating stays manual.

{% if not r?.deb_url %}

No Debian package is available in this release. See GitHub Releases.

{% endif %}

## Debian / Ubuntu / Linux Mint {#debian-13}

**Distributions (amd64, glibc 2.36 or newer):** Debian 13 is verified by the system test matrices. Ubuntu 24.04+, Linux Mint 22+ and other Debian/Ubuntu derivatives with this glibc or newer, systemd, nftables and polkit are expected to work with the same `.deb`; manual Ubuntu verification is pending.

Systems without systemd and Flatpak, Snap and AppImage packages are unsupported: Rosetun needs a privileged system service and access to the host firewall and TUN device.

{% if r?.deb_url %}

Download `{{ r?.deb or "rosetun_<version>_amd64.deb" }}` from [Releases]({{ r?.deb_url or "https://github.com/eoftgge/rosetun/releases" }}), [verify it](../install/#verify-the-download), install it and add yourself to the group that may reach the service:

```
sudo apt install ./{{ r?.deb or "rosetun_<version>_amd64.deb" }}
sudo usermod -aG rosetun "$USER"
```

{% endif %}

Then **restart the computer**. Logging out is not enough: your systemd user manager can outlive the logout and pass its old groups on to the programs it starts. If you skip the last command, the window offers the same with **Add me**.

**Update:** install the new package the same way. With the kill switch on, the network stays closed through the update: a running window restarts itself and connects again. Without a window, `rosetun status` says `network: held closed`, `rosetun connect` connects and `rosetun open-network` opens it. Lockdown stays on.

**Remove:** `sudo apt remove rosetun` takes Lockdown off first. If it cannot, the removal stops and Rosetun stays, so the network can still be opened.

**Purge:** `sudo apt purge rosetun` also removes the lists and state in `/var/lib/rosetun`. Your settings and autostart entry in your home folder (`~/.config/rosetun`) and the `rosetun` group stay.

## Arch Linux {#arch-linux}

The Rosetun repository carries the `rosetun-bin` recipe. Review the recipe for the release before building on Arch.

```
git clone --branch v{{ r?.version or "VERSION" }} https://github.com/eoftgge/rosetun.git
cd rosetun
bash tools/arch/update-pkgbuild.sh v{{ r?.version or "VERSION" }}
cd packaging/arch
makepkg -si
sudo systemctl enable --now rosetun-helper rosetun-lockdown
sudo usermod -aG rosetun "$USER"
sudo reboot
```

The package installs the release binaries with their matching sing-box and Xray builds.

### System DNS in TUN mode {#arch-dns}

Enable `systemd-resolved` so sing-box can register the tunnel's DNS server with the system.

```sh
sudo systemctl enable --now systemd-resolved.service
```

If Rosetun is already connected, disconnect and connect again. Then check the DNS servers on the tunnel interface and try a system lookup.

```sh
resolvectl status rosetun0
timeout 5s getent ahosts example.org
```

The tunnel's DNS should appear under **DNS Servers**. If it appears but the lookup still fails, check that the system resolver uses `systemd-resolved`. The recommended `/etc/resolv.conf` setup for its local DNS stub is a symlink to `/run/systemd/resolve/stub-resolv.conf`. [systemd-resolved manual](https://man.archlinux.org/man/systemd-resolved.service.8.en)

**Update:** update the package, then run `sudo rosetun-helper-privileged --restart-for-upgrade`. A normal `systemctl restart` opens the network with the kill switch on. The upgrade command preserves the hold until you reconnect or run `rosetun open-network`. Services are enabled by you, never by the package.

**Remove:** `sudo pacman -R rosetun-bin`. A transaction hook resets Lockdown before deleting files and refuses removal if that fails. To recover first: `sudo rosetun reset-firewall`. User settings and the group stay.

**Validation status.** The GUI has had a manual check on Arch. The automated Linux system matrices cover Debian 13.

## macOS (Apple Silicon) · experimental build {#macos}

This experimental build is for Apple Silicon (`arm64`) Macs running macOS 14 or later. **Kill switch and Lockdown are unavailable on macOS:** if the tunnel drops, traffic may go direct. See [macOS support](../macos/) for details and limits.

{% if r?.macos_url %}

Download `{{ r.macos }}` from [Releases]({{ r.macos_url }}), [verify it](../install/#verify-the-download) and open the `.pkg` installer (or install from Terminal):

```
sudo installer -pkg ./{{ r.macos }} -target /
```

{% else %}

No experimental macOS package is available in this stable release. See [GitHub Releases](https://github.com/eoftgge/rosetun/releases).

{% endif %}

The installer places `/Applications/Rosetun.app`, `/usr/local/bin/rosetun`, the helper and bundled engines in `/usr/local/libexec/rosetun` (owned by `root:wheel`), and starts the `launchd` service (`/Library/LaunchDaemons/io.github.eoftgge.rosetun.helper.plist`). User settings live in `~/.config/rosetun`.

If the `.pkg` in a release is not signed with Apple Developer ID, Gatekeeper may block opening it with a double-click: verify the checksum and attestation below, then open it from the context menu (**Open**) or install it with `sudo installer`.

**Update:** run the new `.pkg` over the existing installation. The installer stops the `launchd` service cleanly, replaces the files and starts it again. User settings in `~/.config/rosetun` are kept.

**Remove:** run in Terminal:

```
sudo /usr/local/libexec/rosetun/uninstall.sh
```

The script stops the `launchd` service, removes `Rosetun.app`, the CLI, helper, engines, runtime socket, `/private/var/log/rosetun-helper.log` and the `pkgutil` receipt. User settings in `~/.config/rosetun` stay. Pass `--purge` to also remove helper state and lists in `/Library/Application Support/Rosetun`.

## Updating from 0.6 {#update}

Before updating, copy your settings folder. The default path is `%APPDATA%\Rosetun` on Windows and `~/.config/rosetun` on Linux. The backup contains your subscription URLs. Keep it private.

Use the update procedure for your platform above to carry over settings and Lockdown. The first settings save in 0.7 converts format 9 to **format 13** and leaves the previous file beside it (`config.v9.json` from 0.6, or `config.v12.json` from 0.7.0-beta.1). Rosetun 0.6 and 0.7.0-beta.1 refuse to open a format 13 file and leave it intact.

## Going back to 0.6 {#rollback}

1. Disconnect in 0.7 so your own proxy settings come back.
2. Uninstall 0.7 and keep your settings. On Debian, use `apt remove` to retain data that `apt purge` would remove.
3. Install 0.6 and close Rosetun.
4. If your configuration was saved in format 13, restore a copy of your pre-update `config.json`. You can also copy `config.v9.json` to `config.json` in the settings folder if that backup exists. Keep a separate copy of the format 13 file if you want to retain your 0.7 changes.
5. Re-enable autostart and Lockdown if you used them.

## Verify the download {#verify-the-download}

`SHA256SUMS.txt` in each release lists the installers and packages. For a release built from a tag, GitHub also holds a build provenance attestation for them. An attestation says which workflow built the file; it is not a code signature.

From 0.7, `SHA256SUMS.txt` is signed with the release key. Download `SHA256SUMS.txt` and `SHA256SUMS.txt.minisig` from the release page and check the signature with [minisign](https://jedisct1.github.io/minisign/):

```
minisign -Vm SHA256SUMS.txt -P RWSDO2nJ1GqGnPiNy6v88Pz2L8A8Ru/1XSux4rHWdO9FIcLudiCYltbQ
```

The same public key is in the repository: [`minisign.pub`](https://github.com/eoftgge/rosetun/blob/master/crates/rosetun-core/keys/minisign.pub). Releases before 0.7 are not signed.

Windows:

```
Get-FileHash .\{{ r?.installer or "rosetun-<version>-setup.exe" }} -Algorithm SHA256
gh attestation verify .\{{ r?.installer or "rosetun-<version>-setup.exe" }} --repo eoftgge/rosetun
```

{% if r?.deb_url %}

Debian:

```
sha256sum --check --ignore-missing SHA256SUMS.txt
gh attestation verify {{ r?.deb or "rosetun_<version>_amd64.deb" }} --repo eoftgge/rosetun
```

{% endif %}

{% if r?.macos_url %}

macOS (Apple Silicon):

```
shasum -a 256 {{ r.macos }}
gh attestation verify {{ r.macos }} --repo eoftgge/rosetun
```

{% endif %}
