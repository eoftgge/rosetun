+++
title = "Install"
weight = 1

[extra]
group = "Getting started"
toc_labels = { "debian-13" = "Debian 13" }
+++

{%- set r = load_data(path="data/release.json", required=false) -%}
## Requirements {#requirements}

**Windows:** Windows 11, x64. Windows 10 runs on one tester's computer; the failure tests have not run on it.

**Linux:** Debian 13, amd64, with systemd and nftables (the package depends on them) and cgroup v2. polkit (`pkexec`, `polkitd`) is recommended: without it, the window cannot change Lockdown, and you run `sudo rosetun lockdown on` or `off` in a terminal. Linux is supported since 0.5.

## Windows {#windows}

Download `{{ r?.installer or "rosetun-<version>-setup.exe" }}` from [Releases]({{ r?.download_url or "https://github.com/eoftgge/rosetun/releases" }}). The installer is not code-signed yet; if SmartScreen says "Windows protected your PC", select **More info** and then **Run anyway**. See the [code signing policy](https://github.com/eoftgge/rosetun/blob/master/CODE_SIGNING_POLICY.md).

You can choose an installation folder, but not inside a user profile or where standard users can change it; the SYSTEM service requires a protected folder. Uninstalling keeps your configuration in `%APPDATA%\Rosetun` by default, or you can choose to delete your settings, subscriptions and rules.

**Update:** run the new installer over the old version. With the kill switch on, the network stays closed through the update, and the app starts and connects again. If it cannot connect, the connection screen offers **Connect** and **Open network**; `rosetun open-network` does the same. Lockdown stays on.

**Settings:** when the configuration format changes, Rosetun keeps a copy of the previous file beside it at the first save (such as `config.v7.json`); the copy contains the same subscription URLs. An older version refuses a newer file and does not overwrite it.

**Going back to 0.4** (not tested):

1. In 0.5, disconnect, so your own proxy settings come back. 0.4 knows nothing of them.
2. Uninstall 0.5 and keep your settings. This removes Lockdown, an update's hold and the sign-in task, which 0.4 does not know how to remove.
3. Install 0.4.
4. Close Rosetun and restore the settings in PowerShell. Without `config.v7.json`, the file is still format 7, so skip this step. Changes made in 0.5 are lost.
   ```
   Move-Item -Force "$env:APPDATA\Rosetun\config.v7.json" "$env:APPDATA\Rosetun\config.json"
   ```
5. Turn on **Start with Windows** and Lockdown again if you use them.

{% if not r?.deb_url %}

No Debian package is available in this release. See GitHub Releases.

{% endif %}

## Debian / Ubuntu / Linux Mint {#debian-13}

**Distributions (amd64, glibc 2.36 or newer):** Debian 13 is verified by the system test matrices. Ubuntu 24.04+, Linux Mint 22+ and other Debian/Ubuntu derivatives with this glibc or newer, systemd, nftables and polkit are expected to work with the same `.deb`; manual Ubuntu verification is pending.

The Arch Linux binary recipe `rosetun-bin` is available in the repository; AUR publication and runtime verification are pending. See [installation and updates](../install/#arch-linux).

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

The `rosetun-bin` recipe is in the Rosetun repository. AUR publication is pending. Review the recipe for the release and build the package on Arch:

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

The package installs the release binaries with their pinned sing-box and Xray. The Arch engine packages are not required. Once the recipe is published in AUR, `yay -S rosetun-bin` or `git clone https://aur.archlinux.org/rosetun-bin.git` followed by `makepkg -si` will provide the same package.

**Update:** update the package, then run `sudo rosetun-helper-privileged --restart-for-upgrade`. A normal `systemctl restart` opens the network with the kill switch on. The upgrade command preserves the hold until you reconnect or run `rosetun open-network`. Services are enabled by you, never by the package.

**Remove:** `sudo pacman -R rosetun-bin`. A transaction hook resets Lockdown before deleting files and refuses removal if that fails. To recover first: `sudo rosetun reset-firewall`. User settings and the group stay.

**Validation status:** Arch requires manual verification without a VM matrix; automated system checks run only on Debian 13. Arch runtime verification is pending.

## Verify the download {#verify-the-download}

`SHA256SUMS.txt` in each release lists the installer and the package. For a release built from a tag, GitHub also holds a build provenance attestation for both. An attestation says which workflow built the file; it is not a code signature.

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
