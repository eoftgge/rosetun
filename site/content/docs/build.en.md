+++
title = "Build from source"
weight = 14

[extra]
group = "Reference"
overview = "Build from source"
+++

Use Rust 1.99 or newer, with the MSVC toolchain on Windows. Run `cargo build --release` to build the binaries and `cargo test --workspace` to run tests.

- **Windows installer:** `./installer/build.ps1` builds `target/installer/rosetun-<version>-setup.exe`. See the [installer instructions](https://github.com/eoftgge/rosetun/blob/master/installer/README.md).
- **Linux release assets:** `installer/linux/build-deb.sh --release` builds the Debian package and Linux archive from the same binaries. The release build runs as a regular user in the pinned Debian 12 container. Tests on the local Debian 13 stand use a separate build. [Packaging instructions](https://github.com/eoftgge/rosetun/blob/master/installer/README.md#debian-package)
- **Failure testing** on virtual machines: the [VM test rig](https://github.com/eoftgge/rosetun/blob/master/tools/README.md).

Before committing, run `git config core.hooksPath tools/hooks` once. The hooks reject AI attribution and non-Conventional commit messages, patch files, real proxy hosts and your Windows account name in added lines, and unformatted code on push. CI runs the same message and added-line checks.
