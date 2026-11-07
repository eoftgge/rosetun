#!/bin/bash
# Repackage the Debian payload; never rebuild binaries or duplicate its layout.
set -euo pipefail
export LC_ALL=C TZ=UTC
umask 022
package=$(realpath -- "${1:?usage: build-archive.sh PACKAGE VERSION}")
version=${2:?missing release version}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta)\.[0-9]+)?$ ]] || exit 64
: "${SOURCE_DATE_EPOCH:?set SOURCE_DATE_EPOCH to the source commit timestamp}"
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]+$ ]] || exit 64
out=$(dirname -- "$package")/rosetun-$version-linux-amd64.tar.gz
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
dpkg-deb --extract "$package" "$stage"
mkdir -p "$stage/usr/share/licenses"
mv "$stage/usr/share/doc/rosetun/licenses" "$stage/usr/share/licenses/rosetun"
rm "$stage/usr/lib/rosetun/licenses"
ln -s ../../share/licenses/rosetun "$stage/usr/lib/rosetun/licenses"
tar --sort=name --format=gnu --owner=0 --group=0 --numeric-owner \
    --mtime="@$SOURCE_DATE_EPOCH" -C "$stage" -cf - usr | gzip -9n >"$out"
printf 'Archive: %s\n' "$out"
sha256sum -- "$out"
