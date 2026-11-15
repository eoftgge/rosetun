+++
title = "Build from source"
weight = 14

[extra]
group = "Reference"
overview = "Build from source"
+++

Use Rust 1.99 or newer, with the MSVC toolchain on Windows. Run `cargo build --release` to build the binaries and `cargo test --workspace` to run tests.

- **Windows installer:** `./installer/build.ps1` builds `target/installer/rosetun-<version>-setup.exe`. See the [installer instructions](https://github.com/eoftgge/rosetun/blob/master/installer/README.md).
- **Debian package:** `installer/linux/build-deb.sh --release` builds `rosetun_<version>_amd64.deb`, on Debian 13 or in Debian under WSL, as an ordinary user. See the [same instructions](https://github.com/eoftgge/rosetun/blob/master/installer/README.md#debian-package).
- **Failure testing** on virtual machines: the [VM test rig](https://github.com/eoftgge/rosetun/blob/master/tools/README.md).

Before committing, run `git config core.hooksPath tools/hooks` once. The hooks reject AI attribution and non-Conventional commit messages, patch files, real proxy hosts and your Windows account name in added lines, and unformatted code on push. CI runs the same message and added-line checks.
