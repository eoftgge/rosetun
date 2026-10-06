# Windows installer

Requires Rust 1.96 or newer, Inno Setup 6.3 or newer, and `curl.exe` (included with Windows 10 and newer).

From the repository root, run `./installer/build.ps1` in PowerShell. The result is `target/installer/rosetun-<version>-setup.exe`; the build prints its path and SHA-256. The script checks the pinned sing-box version against the Rust engine and verifies the downloaded executable's SHA-256 before packaging it. A verified copy and its `LICENSE` are reused on subsequent builds.

The installer places these files under `C:\Program Files\Rosetun`:

| Path | Purpose |
| --- | --- |
| `rosetun-gui.exe` | Desktop GUI and tray application |
| `rosetun-helper-privileged.exe` | Windows service and manual service management |
| `rosetun.exe` | Command-line client |
| `sing-box.exe` | Tunnel engine |
| `licenses/sing-box.txt` | sing-box license |
| `licenses/OFL-*.txt` | Bundled font licenses |
| `data/` | Service data, created by the service and accessible only to administrators; its log is `data/logs/helper.log` |

The `Rosetun` service starts automatically and restarts after a failure. From an elevated PowerShell session, `& 'C:\Program Files\Rosetun\rosetun-helper-privileged.exe' --install-service` installs or updates it, and the same executable with `--uninstall-service` removes it. Upgrades stop the GUI and service before replacing files; uninstall removes the service and installation directory but preserves `%APPDATA%\Rosetun`.

The installer is not signed yet, so SmartScreen may warn when it starts: choose **More info** → **Run anyway**. Test installation, upgrades, connectivity and removal on a clean VM snapshot, without the matrix test rig.
