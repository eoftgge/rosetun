English | [Русский](README.ru.md)

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
  <a href="https://github.com/eoftgge/rosetun/releases/latest"><img src=".github/assets/download.svg" alt="Download" height="56"></a>
</p>

Rosetun is a VPN client for Windows and Linux, built on sing-box and Xray.
A system service protects against leaks independently of the engine.

**Stable release: 0.5.1 · Windows and Linux.**

**Young project:** one developer with AI coding agents, and few users yet. Report problems in [Issues](https://github.com/eoftgge/rosetun/issues).

## Highlights

- Kill switch and system DNS protection.
- Experimental Lockdown: protection while disconnected too.
- TUN and System proxy.
- Rules by program, website, IP and list, with separate exits.
- Provider subscriptions, QR codes and `rosetun://` links.
- Local network access and automatic reconnect.
- Tray, notifications and CLI; English and Russian interfaces.

## Install

Choose a file from the release linked above:

- **Windows 11 x64:** run `rosetun-0.5.1-setup.exe`.
- **Debian / Ubuntu / Linux Mint, amd64:** install `rosetun_0.5.1_amd64.deb`, join the service group and restart the computer:

```sh
sudo apt install ./rosetun_0.5.1_amd64.deb
sudo usermod -aG rosetun "$USER"
sudo reboot
```

Debian 13 is verified. Ubuntu 24.04+, Linux Mint 22+ and compatible derivatives are expected to work; see [Linux support and requirements](https://eoftgge.github.io/rosetun/en/docs/linux/).

**Arch Linux:** build the binary package from the recipe in this repository; AUR publication and runtime verification are pending. [Install and update safely](https://eoftgge.github.io/rosetun/en/docs/install/#arch-linux).

[Verify downloads, update, remove and recover from Lockdown](https://eoftgge.github.io/rosetun/en/docs/install/).

## Documentation

[Guide](https://eoftgge.github.io/rosetun/en/docs/) · [Help](https://eoftgge.github.io/rosetun/en/help/) · [For providers](https://eoftgge.github.io/rosetun/en/providers/).

[Build from source](https://eoftgge.github.io/rosetun/en/docs/build/) · [Security](SECURITY.md).

## Troubleshooting

[Windows and Linux instructions, Lockdown recovery and logs](https://eoftgge.github.io/rosetun/en/docs/troubleshooting/).

## Licenses

Rosetun: **GPL-3.0-or-later**, © 2026 Sandaar. [LICENSE](LICENSE).
sing-box: GPL-3.0-or-later; Xray-core: MPL-2.0; Wintun: [Prebuilt Binaries License](installer/third-party/wintun-prebuilt-binaries-license.txt); fonts: OFL-1.1.
[Full notices, component sources and installed licenses](https://eoftgge.github.io/rosetun/en/docs/licenses/).
Rosetun is not affiliated with sing-box, SagerNet or Project X.
