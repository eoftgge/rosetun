# Windows installer

Requires Rust 1.96 or newer, Inno Setup 6.3 or newer, `cargo-about` 0.9.2 (`cargo install cargo-about --locked --version 0.9.2 --features cli`), and `curl.exe` (included with Windows 10 and newer).

From the repository root, run `./installer/build.ps1` in PowerShell. The result is `target/installer/rosetun-<version>-setup.exe`; the build prints its path and SHA-256. The script checks the pinned sing-box version against the Rust engine and verifies the downloaded executable's SHA-256 before packaging it. A verified copy and its `LICENSE` are reused on subsequent builds. The version comes from `Cargo.toml`; a `-alpha.N` suffix appears only in textual version fields, not the numeric file version.

The default install folder is `C:\Program Files\Rosetun`. On a first install, you may select another safe folder on a local drive; upgrades reuse the previous folder without showing the folder page. The SYSTEM service runs both its helper and `sing-box.exe` from this folder, so a standard user must not be able to modify it or its parents. The installer checks the folder before copying anything, assigns Administrators ownership, and applies a non-inheriting DACL: SYSTEM and Administrators have full access, while Users can read and run the installed files. Service data remains readable only by SYSTEM and Administrators. An unsafe existing installation cannot be upgraded: uninstall it and reinstall in a safe folder.

The installer places these files in the chosen folder:

| Path | Purpose |
| --- | --- |
| `rosetun-gui.exe` | Desktop GUI and tray application |
| `rosetun-helper-privileged.exe` | Windows service and manual service management |
| `rosetun.exe` | Command-line client |
| `sing-box.exe` | Tunnel engine |
| `licenses/` | Rosetun and sing-box licenses, sing-box source information, bundled font licenses, and Rust crate license notices |
| `data/` | Service data, created by the service and accessible only to administrators; its log is `data/logs/helper.log` |

The `Rosetun` service starts automatically and restarts after a failure. From an elevated PowerShell session, `& 'C:\Program Files\Rosetun\rosetun-helper-privileged.exe' --install-service` installs or updates it, and the same executable with `--uninstall-service` removes it. Use the chosen folder instead of `C:\Program Files\Rosetun` if necessary. Upgrades stop the GUI and service before replacing files. At service startup, an unsafe folder is logged as a warning, but the service continues.

The installer runs a temporary copy of the helper with `--verify-install-dir <path>` and `--secure-install-dir <path>` before installing files, then `--finalize-install-dir <path>` after copying and before starting the service. Finalization assigns safe ownership and permissions to newly copied files and rechecks the tree. Verification is read-only. It requires an absolute drive path below the volume root, a fixed local drive with persistent ACLs, and a location outside user profiles and the Windows directory. No existing path component may be a junction or symlink; existing parents must be owned by SYSTEM, Administrators or TrustedInstaller and must not grant standard users the right to modify, delete or rename them. A root ACL that merely permits creating folders is acceptable. The target must be empty or contain an earlier Rosetun helper. An earlier installation's folder and its contents must have trusted owners and no standard-user write rights. A past writable ACL can leave usable handles even after it is repaired; if a previous installation was ever writable by another account, avoid its binaries and an in-place upgrade. Disable the affected service with trusted administrative tools before rebooting, then reinstall into a new protected folder. The secure command atomically creates missing folders with protected ACLs, replaces an existing empty target with a freshly protected directory so old writable handles cannot survive at the installation path, and resets safe old contents to inherited permissions. A post-copy finalization error prevents service startup and returns a nonzero setup exit code, but files already copied are not rolled back; uninstall and reinstall in that case.

Only `DELETE` on the volume root is ignored: the root itself cannot be renamed or deleted. `FILE_DELETE_CHILD`, `WRITE_DAC` and all other dangerous rights on the root still cause a rejection; for example, a root granting `Everyone:(OI)(CI)(F)` (`Все:(OI)(CI)(F)` on Russian Windows) is unsafe.

On failure, install-directory helper commands print `path=<offending folder>` followed by a one-line reason to stdout. The verifier returns:

| Exit code | Meaning |
| --- | --- |
| `0` | Safe to install |
| `2` | Invalid, relative, UNC, or volume-root path |
| `3` | Not a local fixed drive |
| `4` | No persistent filesystem ACLs |
| `5` | Inside the profiles or Windows directory |
| `6` | Reparse point in the path or previous installation contents |
| `7` | Untrusted owner of a parent, installation, or existing content |
| `8` | A parent, installation, or existing content is writable by standard users |
| `9` | Occupied folder without an earlier Rosetun installation |
| `10` | Inspection or security operation failed |

`--secure-install-dir` and `--finalize-install-dir` return `0` on success or a nonzero verification/operation code. A silent install, including `/VERYSILENT /DIR=C:\Example\Rosetun`, runs the same checks and fails with a nonzero setup exit code on an unsafe directory. Uninstall removes the service and installation tree, including `{app}\data`. In interactive removal an unchecked-by-default option can additionally delete settings, subscriptions and rules in the displayed `{userappdata}\Rosetun` folder of the account running the elevated uninstaller. Other accounts' data stays; `/SILENT` and `/VERYSILENT` never delete user data.

The installer is not signed yet, so SmartScreen may warn when it starts: choose **More info** → **Run anyway**. Test installation, upgrades, connectivity and removal on a clean VM snapshot, without the matrix test rig.

## Releases

A signed `v<version>` tag matching the version in `Cargo.toml` builds and publishes a GitHub Release. Versions with `-alpha.N` or another prerelease suffix are marked as prereleases. Existing releases are never overwritten.

Use **Run workflow** on the Release workflow for a test build: it uploads the installer, checksums and release notes as an artifact without publishing a release. Run `./installer/build.ps1 -Release` to build the same assets locally, including the sing-box source archive, `SHA256SUMS.txt` and bilingual release notes.
