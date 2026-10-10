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
| `licenses/` | Rosetun, sing-box and prebuilt Wintun licenses, Wintun notices, sing-box source information, bundled font licenses, and Rust crate license notices |
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

## Bundled Wintun license and version updates

The official sing-box 1.14.1 executable embeds the prebuilt Wintun 0.14.1 amd64 DLL. After verifying either the cached or downloaded sing-box executable, the build scans its bytes for `MZ` and hashes exactly 427552 bytes at each eligible offset. Packaging stops unless a candidate matches SHA-256 `E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE`. The executable remains unchanged; no DLL is extracted.

The installer includes `licenses/wintun.txt` and the unchanged `licenses/wintun-prebuilt-binaries-license.txt`. The latter comes from [the upstream 0.14.1 tag](https://git.zx2c4.com/wintun/plain/prebuilt-binaries-license.txt?h=0.14.1), with SHA-256 `9aaf948856ce8845a762121306039ef09d0eeb4d9e4f4c355647d4081e818087`.

When updating sing-box, also review its embedded Wintun version. Download the matching official `wintun-<version>.zip` from `https://www.wintun.net/builds/`, verify the byte length and SHA-256 of `bin/amd64/wintun.dll`, and compare the archive's license with the unchanged license from that upstream tag. Stop on any mismatch; do not bypass the guard. Update `$wintunVersion`, `$wintunDllLength` and `$wintunDllHash` beside the sing-box pin in `build.ps1`, the vendored license if it changed, and the version/hash documentation here. Review the public license notices and release-note template as well. Verify that the official sing-box executable passes the embedded-DLL guard before releasing.

## Releases

All development takes place on `dev`; `master` contains only released commits and remains the default branch. There are no pull requests between these branches. CI runs on pushes to both branches. A signed `v<version>` tag on `master` matching the version in `Cargo.toml` builds and publishes a GitHub Release. Versions with `-alpha.N` or another prerelease suffix are marked as prereleases. Existing releases are never overwritten.

First use **Actions → Release → Run workflow** on `dev` for a test build: it uploads the installer, checksums and release notes as an artifact without publishing a release. Then fast-forward `master` and tag the released commit:

```sh
# Trial: Actions → Release → Run workflow on dev
git switch master
git merge --ff-only dev
git tag -s vX.Y.Z -m "Rosetun X.Y.Z"
git push origin master vX.Y.Z
```

Run `./installer/build.ps1 -Release` to build the same assets locally, including the sing-box source archive, `SHA256SUMS.txt` and bilingual release notes. To fix an already released version, commit the fix on `master`, tag and push the corrected release, then bring that commit back to `dev` with `git switch dev && git merge -S master` and push `dev`.
