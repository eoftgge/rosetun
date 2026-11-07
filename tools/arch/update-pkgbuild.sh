#!/bin/bash
# Run on Arch, as an ordinary user. Downloads metadata but never publishes.
set -euo pipefail
export LC_ALL=C
tag=${1:?usage: update-pkgbuild.sh vVERSION}
[[ $tag =~ ^v([0-9]+\.[0-9]+\.[0-9]+)(-(beta|alpha)\.([0-9]+))?$ ]] || exit 64
version=${tag#v}
pkgver=${version/-/}
if [[ $version == *-* ]]; then
    base=${BASH_REMATCH[1]}
    kind=${BASH_REMATCH[3]}
    number=${BASH_REMATCH[4]}
    pkgver=$base$kind$number
    [ "$(vercmp "$pkgver" "$base")" -lt 0 ]
fi
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd "$repo/packaging/arch"
command -v makepkg >/dev/null
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
curl --fail --silent --show-error --location --proto '=https' \
    "https://github.com/eoftgge/rosetun/releases/download/$tag/SHA256SUMS.txt" >"$work/sums"
asset=rosetun-$version-linux-amd64.tar.gz
hash=$(awk -v name="$asset" '$2 == name { print $1 }' "$work/sums")
[[ $hash =~ ^[0-9a-f]{64}$ ]] || { echo "missing or ambiguous checksum for $asset" >&2; exit 1; }
sed -e "s/^pkgver=.*/pkgver=$pkgver/" -e 's/^pkgrel=.*/pkgrel=1/' \
    -e "s/^_release=.*/_release=$version/" -e "s/^sha256sums=.*/sha256sums=('$hash')/" PKGBUILD >"$work/PKGBUILD"
cp rosetun-bin.install rosetun-remove.hook pre-remove.sh "$work/"
# Generate before modifying the recipe so a makepkg error leaves it intact.
(cd "$work" && makepkg --printsrcinfo) >"$work/.SRCINFO"
cp "$work/PKGBUILD" PKGBUILD
cp "$work/.SRCINFO" .SRCINFO
cat <<'COMMANDS'
Review PKGBUILD and .SRCINFO, then run makepkg and namcap (see README.md).
Owner publication commands, from the repository root:
git clone ssh://aur@aur.archlinux.org/rosetun-bin.git ../rosetun-bin-aur
cp packaging/arch/{PKGBUILD,.SRCINFO,rosetun-bin.install,rosetun-remove.hook,pre-remove.sh} ../rosetun-bin-aur/
cd ../rosetun-bin-aur
git add PKGBUILD .SRCINFO rosetun-bin.install rosetun-remove.hook pre-remove.sh
git commit -S -m 'packaging: Update rosetun-bin' -m 'Import the published Linux archive and its release checksum.'
git push
COMMANDS
