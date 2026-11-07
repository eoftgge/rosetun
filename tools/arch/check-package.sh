#!/bin/bash
# Container-only packaging smoke check, without installing Rosetun or services.
set -euo pipefail
archive=$(realpath -- "${1:?usage: check-package.sh LINUX_ARCHIVE}")
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
[ "$(id -u)" -ne 0 ]
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
cp "$repo"/packaging/arch/{PKGBUILD,rosetun-bin.install,rosetun-remove.hook,pre-remove.sh} "$work/"
cp "$archive" "$work/"
cd "$work"
asset=${archive##*/}
hash=$(sha256sum "$asset" | cut -d' ' -f1)
# Only the source location changes for an unpublished CI artifact; package()
# and all installation/removal files remain exactly the owner recipe.
sed -i -e "s|^source=.*|source=('$asset')|" \
    -e "s/^sha256sums=.*/sha256sums=('$hash')/" PKGBUILD
makepkg --printsrcinfo >.SRCINFO
makepkg --nodeps --noconfirm
namcap PKGBUILD ./*.pkg.tar.zst
[ "$(vercmp 0.6.0beta1 0.6.0)" -lt 0 ]
[ "$(vercmp 0.6.0beta2 0.6.0beta10)" -lt 0 ]
tar -tf ./*.pkg.tar.zst | grep -q '^usr/share/libalpm/hooks/10-rosetun-remove.hook$'
