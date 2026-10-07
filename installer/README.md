# Windows installer

Requires Rust 1.96 or newer, Inno Setup 6.3 or newer, `cargo-about` 0.9.2 (`cargo install cargo-about --locked --version 0.9.2 --features cli`), and `curl.exe` (included with Windows 10 and newer).

From the repository root, run `./installer/build.ps1` in PowerShell. The result is `target/installer/rosetun-<version>-setup.exe`; the build prints its path and SHA-256. The script checks the pinned sing-box version against the Rust engine and verifies the downloaded executable's SHA-256 before packaging it. A verified copy and its `LICENSE` are reused on subsequent builds. The version comes from `Cargo.toml`; a `-alpha.N` suffix appears only in textual version fields, not the numeric file version.

The installer places these files under `C:\Program Files\Rosetun`:

| Path | Purpose |
| --- | --- |
| `rosetun-gui.exe` | Desktop GUI and tray application |
| `rosetun-helper-privileged.exe` | Windows service and manual service management |
| `rosetun.exe` | Command-line client |
| `sing-box.exe` | Tunnel engine |
| `licenses/` | Rosetun and sing-box licenses, sing-box source information, bundled font licenses, and Rust crate license notices |
| `data/` | Service data, created by the service and accessible only to administrators; its log is `data/logs/helper.log` |

The `Rosetun` service starts automatically and restarts after a failure. From an elevated PowerShell session, `& 'C:\Program Files\Rosetun\rosetun-helper-privileged.exe' --install-service` installs or updates it, and the same executable with `--uninstall-service` removes it. Upgrades stop the GUI and service before replacing files; uninstall removes the service and installation directory but preserves `%APPDATA%\Rosetun`.

The installer is not signed yet, so SmartScreen may warn when it starts: choose **More info** → **Run anyway**. Test installation, upgrades, connectivity and removal on a clean VM snapshot, without the matrix test rig.

## Releases

A signed `v<version>` tag matching the version in `Cargo.toml` builds and publishes a GitHub Release. Versions with `-alpha.N` or another prerelease suffix are marked as prereleases. Existing releases are never overwritten.

Use **Run workflow** on the Release workflow for a test build: it uploads the installer, checksums and release notes as an artifact without publishing a release. Run `./installer/build.ps1 -Release` to build the same assets locally, including the sing-box source archive, `SHA256SUMS.txt` and bilingual release notes.
