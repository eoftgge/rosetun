English | [Русский](README.ru.md)


Arch Linux: the `rosetun-bin` AUR recipe is prepared for 0.5.0; see [installation and safe updates](https://eoftgge.github.io/rosetun/en/docs/install/#arch-linux).
<p align="center"><img src=".github/assets/banner.svg" alt="Rosetun: VPN client for Windows and Linux" width="100%"></p>

<p align="center">
  <a href="https://eoftgge.github.io/rosetun/en/"><img src="https://img.shields.io/badge/Website-8C2338?style=for-the-badge" alt="Website"></a>
  <a href="https://eoftgge.github.io/rosetun/en/docs/"><img src="https://img.shields.io/badge/Documentation-432D36?style=for-the-badge" alt="Documentation"></a>
  <a href="https://eoftgge.github.io/rosetun/en/help/"><img src="https://img.shields.io/badge/Help-432D36?style=for-the-badge" alt="Help"></a>
  <a href="https://eoftgge.github.io/rosetun/en/providers/"><img src="https://img.shields.io/badge/For%20providers-432D36?style=for-the-badge" alt="For providers"></a>
</p>

<p align="center">
<img alt="CI" src="https://img.shields.io/github/actions/workflow/status/eoftgge/rosetun/ci.yml?style=for-the-badge&logo=rust">
<img alt="GitHub issues by-label" src="https://img.shields.io/github/issues/eoftgge/rosetun/bug?style=for-the-badge&logo=github">
</p>

<p align="center">
  <a href="https://github.com/eoftgge/rosetun/releases"><img src=".github/assets/download.svg" alt="Download Rosetun for Windows" height="56"></a>
  <a href="https://github.com/eoftgge/rosetun/releases"><img src=".github/assets/download-linux.svg" alt="Download Rosetun for Debian 13" height="56"></a>
</p>

Rosetun is a VPN client for Windows and Linux, built on sing-box and Xray.
A system service protects against leaks independently of the engine.

**Young project:** one developer with AI coding agents, and few users yet. Report problems in [Issues](https://github.com/eoftgge/rosetun/issues).

## Highlights

- Kill switch and system DNS protection.
- Experimental Lockdown: protection while disconnected too.
- TUN and System proxy (since 0.5).
- Rules by program, website, IP and list, with separate exits.
- Provider subscriptions, QR codes and `rosetun://` links.
- Local network access and automatic reconnect.
- Tray, notifications and CLI; English and Russian interfaces.

## Install

Windows 11 x64: download the installer above and run it. [Verify and install](https://eoftgge.github.io/rosetun/en/docs/install/).

Linux amd64 (since the 0.5 preview): verified on Debian 13; expected on Ubuntu 24.04+, Linux Mint 22+ and Debian/Ubuntu derivatives with glibc >= 2.36, systemd, nftables and polkit. Arch: AUR recipe prepared, runtime check pending. Systems without systemd and Flatpak/Snap/AppImage are unsupported because a privileged host service is required. [Linux support](https://eoftgge.github.io/rosetun/en/docs/linux/). Download the `.deb` and run:

```sh
sudo apt install ./rosetun_<version>_amd64.deb
```

[Join the `rosetun` group and restart the computer](https://eoftgge.github.io/rosetun/en/docs/install/#debian-13).

## Documentation

[Guide](https://eoftgge.github.io/rosetun/en/docs/) · [Help](https://eoftgge.github.io/rosetun/en/help/) · [For providers](https://eoftgge.github.io/rosetun/en/providers/).

[Build from source](https://eoftgge.github.io/rosetun/en/docs/build/) · [Security](SECURITY.md).

Stable release: 0.4 for Windows. The documentation labels 0.5 additions separately.

## Troubleshooting

[Windows and Linux instructions, Lockdown recovery and logs](https://eoftgge.github.io/rosetun/en/docs/troubleshooting/).

### Debian 13

[Install, update and remove](https://eoftgge.github.io/rosetun/en/docs/install/#debian-13).

## Licenses

Rosetun: **GPL-3.0-or-later**, © 2026 Sandaar. [LICENSE](LICENSE).
sing-box: GPL-3.0-or-later; Xray-core: MPL-2.0; Wintun: [Prebuilt Binaries License](installer/third-party/wintun-prebuilt-binaries-license.txt); fonts: OFL-1.1.
[Full notices, component sources and installed licenses](https://eoftgge.github.io/rosetun/en/docs/licenses/).
Rosetun is not affiliated with sing-box, SagerNet or Project X.
