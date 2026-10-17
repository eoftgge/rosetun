# Code signing policy

**Rosetun releases are not code-signed yet.** Rosetun is preparing an application to SignPath Foundation. The signing arrangement and controls below are planned; they do not imply acceptance by the Foundation or that any current release is signed.

Planned attribution:

Free code signing provided by [SignPath.io](https://signpath.io), certificate by [SignPath Foundation](https://signpath.org).

## Scope and provenance

The planned signed artifacts are `rosetun-gui.exe`, `rosetun-helper-privileged.exe`, `rosetun.exe`, and `rosetun-<version>-setup.exe`. Rosetun binaries and the installer are built by [GitHub Actions](.github/workflows/release.yml) from a version tag: on `master` for a release and its betas, or on `dev` for a beta of the next minor version; the workflow refuses any other tag. The owner signs every commit with GPG, and `master` and the version tags are protected by repository rulesets. Public tagged releases include a GitHub build provenance attestation for the installer, verifiable with `gh attestation verify .\rosetun-<version>-setup.exe --repo eoftgge/rosetun`. An attestation is not a code signature.

The installer separately verifies the pinned SHA-256 of the official sing-box executable and the byte length and SHA-256 of its embedded Wintun DLL, and from 0.2 the pinned SHA-256 of the official Xray-core archive. These third-party executables are bundled untouched, with their licenses and notices; they are not among the Rosetun artifacts planned for signing. The Wintun DLL is the prebuilt, WireGuard-signed binary distributed under the Wintun Prebuilt Binaries License; its source is available under GPL-2.0.

## Roles and approval

Project owner [@eoftgge](https://github.com/eoftgge) is the sole committer, reviewer, and signing approver. Every signing request will require their manual approval. Two-factor authentication is required for accounts with access to the repository or signing system. These roles do not provide independent review; signing is not a guarantee that the software is free of defects.

## Privacy

Rosetun is a VPN client and necessarily contacts the servers and services described in [Privacy and network access](README.md#privacy-and-network-access). This includes subscription providers, configured DNS resolvers, connectivity and public-IP endpoints, and GitHub for update checks. There is no telemetry or Rosetun account; logs stay on the local machine. Some requests may include subscription credentials or optional device information. See the linked section for the full list of requests, defaults, and controls; this policy does not claim that Rosetun makes no network requests.
