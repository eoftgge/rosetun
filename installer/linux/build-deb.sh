#!/bin/bash
# Builds rosetun_<version>_amd64.deb for Debian 13. Run it as an ordinary user
# on Debian (or in Debian under WSL). dpkg-deb --root-owner-group gives root's
# ownership without root or fakeroot, and the package has no build step that
# would need debhelper or cargo-deb.
#
#   installer/linux/build-deb.sh [--release] [--package-version VERSION]
#
# --release            installs the pinned cargo-about when it is missing
# --package-version    a Debian version instead of the one from Cargo.toml, for
#                      the test stand's "previous" package
#
# The result is <target>/deb/rosetun_<version>_amd64.deb. The same commit, built
# in the same folder, gives the same bytes: SOURCE_DATE_EPOCH is the commit's
# time unless it is set, and paths, order, times and modes are fixed below.

set -euo pipefail
export LC_ALL=C TZ=UTC
umask 022

# Update these together with installer/build.ps1, SUPPORTED_SING_BOX_VERSION
# and SUPPORTED_XRAY_VERSION.
SING_BOX_VERSION=1.14.3
SING_BOX_ARCHIVE_SHA256=e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee
XRAY_VERSION=26.10.21
XRAY_ARCHIVE_SHA256=0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978
CARGO_ABOUT_VERSION=0.9.2
ICON_SIZES=(16 22 24 32 48 64 96 128 256 512)
MAINTAINER='eoftgge <eoftgge@users.noreply.github.com>'
# Loaded with dlopen, so dpkg-shlibdeps cannot see them: the window on Wayland
# and on X11, and OpenGL through EGL or GLX.
GUI_LIBRARIES='libegl1, libgl1, libwayland-client0, libwayland-egl1, libx11-6, libx11-xcb1, libxcb1, libxcursor1, libxi6, libxkbcommon-x11-0, libxkbcommon0, libxrender1'

die() {
    printf 'build-deb.sh: %s\n' "$1" >&2
    exit 1
}

release=false
package_version=
while [ $# -gt 0 ]; do
    case $1 in
    --release) release=true ;;
    --package-version)
        [ $# -ge 2 ] || die '--package-version needs a value'
        package_version=$2
        shift
        ;;
    *) die "unknown argument $1" ;;
    esac
    shift
done

[ "$(id -u)" -ne 0 ] || die 'do not build as root'
[ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || die 'needs x86_64 Linux'
if [ -d "$HOME/.cargo/bin" ]; then PATH=$HOME/.cargo/bin:$PATH; fi
for tool in cargo curl dpkg-deb dpkg-shlibdeps git gzip sha256sum tar unzip; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is missing"
done
export RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-1.96.0}

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd -- "$repo"

supported_version() {
    sed -n "s/^pub const $1: &str = \"\([^\"]*\)\";.*/\1/p" "$2"
}
[ "$SING_BOX_VERSION" = "$(supported_version SUPPORTED_SING_BOX_VERSION crates/rosetun-engine-singbox/src/version.rs)" ] ||
    die "sing-box $SING_BOX_VERSION differs from SUPPORTED_SING_BOX_VERSION"
[ "$XRAY_VERSION" = "$(supported_version SUPPORTED_XRAY_VERSION crates/rosetun-engine-xray/src/version.rs)" ] ||
    die "Xray $XRAY_VERSION differs from SUPPORTED_XRAY_VERSION"

version=$(awk '
    /^\[/ { section = $0 }
    section == "[workspace.package]" && $1 == "version" { gsub(/"/, "", $3); print $3; exit }
' Cargo.toml)
[ -n "$version" ] || die 'cannot read the version from Cargo.toml'
# 0.5.0-alpha.1 must sort before 0.5.0, which is what "~" means to dpkg.
deb_version=${package_version:-${version/-/\~}}
[[ $deb_version =~ ^[0-9][0-9A-Za-z.+~]*$ ]] || die "invalid Debian version $deb_version"

: "${SOURCE_DATE_EPOCH:=$(git log -1 --format=%ct)}"
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]+$ ]] || die 'invalid SOURCE_DATE_EPOCH'
export SOURCE_DATE_EPOCH

installed_cargo_about() {
    [ "$(cargo about --version 2>/dev/null)" = "cargo-about $CARGO_ABOUT_VERSION" ]
}
if ! installed_cargo_about; then
    install_hint="cargo install cargo-about --locked --version $CARGO_ABOUT_VERSION --features cli --force"
    $release || die "cargo-about $CARGO_ABOUT_VERSION is required: $install_hint"
    $install_hint
    installed_cargo_about || die "cargo-about $CARGO_ABOUT_VERSION is unavailable after installation"
fi

target=${CARGO_TARGET_DIR:-$repo/target}
mkdir -p -- "$target"
target=$(cd -- "$target" && pwd -P)
export CARGO_TARGET_DIR=$target
out=$target/deb
cache=$out/cache
mkdir -p -- "$cache"

sha256_of() {
    sha256sum -- "$1" | cut -d' ' -f1
}

# fetch URL FILE SHA256: the cached file when its hash is right.
fetch() {
    local url=$1 file=$cache/$2 expected=$3 actual
    if [ -f "$file" ] && [ "$(sha256_of "$file")" = "$expected" ]; then
        return
    fi
    rm -f -- "$file" "$file.download"
    curl --fail --silent --show-error --location --proto '=https' --output "$file.download" "$url"
    actual=$(sha256_of "$file.download")
    if [ "$actual" != "$expected" ]; then
        rm -f -- "$file.download"
        die "$url has SHA-256 $actual, expected $expected"
    fi
    mv -- "$file.download" "$file"
}

sing_box_name=sing-box-$SING_BOX_VERSION-linux-amd64
sing_box_archive=$sing_box_name.tar.gz
xray_archive=Xray-$XRAY_VERSION-linux-64.zip
fetch "https://github.com/SagerNet/sing-box/releases/download/v$SING_BOX_VERSION/$sing_box_archive" \
    "$sing_box_archive" "$SING_BOX_ARCHIVE_SHA256"
fetch "https://github.com/XTLS/Xray-core/releases/download/v$XRAY_VERSION/Xray-linux-64.zip" \
    "$xray_archive" "$XRAY_ARCHIVE_SHA256"

# Build paths stay out of the binaries, so where the checkout is does not matter
# to anyone who reads a panic message.
export CARGO_PROFILE_RELEASE_STRIP=symbols
export RUSTFLAGS="--remap-path-prefix=$repo=/rosetun --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$target=/target"
cargo build -q --release --locked -p rosetun-gui -p rosetun-helper-privileged -p rosetun

work=$(mktemp -d "$out/stage.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
root=$work/root
chmod 0700 "$work"
mkdir -p "$root/DEBIAN"
chmod 0640 "$root/DEBIAN"
[ "$(stat -c %a "$root/DEBIAN")" = 640 ] || die "$out keeps no file modes; set CARGO_TARGET_DIR to a Linux filesystem"
chmod 0755 "$root/DEBIAN"

# place MODE SOURCE DESTINATION
place() {
    install -D -m "$1" -- "$2" "$root/$3"
}

lib=usr/lib/rosetun
doc=usr/share/doc/rosetun
licenses=$doc/licenses

for program in rosetun-helper-privileged rosetun-gui rosetun; do
    place 0755 "$target/release/$program" "$lib/$program"
done
tar -xzf "$cache/$sing_box_archive" -C "$work" "$sing_box_name/sing-box" "$sing_box_name/LICENSE"
place 0755 "$work/$sing_box_name/sing-box" "$lib/sing-box"
unzip -q -o "$cache/$xray_archive" xray -d "$work"
place 0755 "$work/xray" "$lib/xray"
mkdir -p "$root/usr/bin"
ln -s ../lib/rosetun/rosetun "$root/usr/bin/rosetun"
ln -s ../lib/rosetun/rosetun-gui "$root/usr/bin/rosetun-gui"
# The GUI's "Licenses" button opens the folder beside its program.
ln -s ../../share/doc/rosetun/licenses "$root/$lib/licenses"

place 0644 packaging/linux/rosetun-helper.service usr/lib/systemd/system/rosetun-helper.service
place 0644 packaging/linux/rosetun-lockdown.service usr/lib/systemd/system/rosetun-lockdown.service
place 0644 packaging/linux/rosetun.sysusers usr/lib/sysusers.d/rosetun.conf
place 0644 packaging/linux/io.github.eoftgge.rosetun.policy usr/share/polkit-1/actions/io.github.eoftgge.rosetun.policy
place 0644 packaging/linux/rosetun.desktop usr/share/applications/rosetun.desktop
place 0644 crates/rosetun-gui/assets/icon/rosetun.svg usr/share/icons/hicolor/scalable/apps/rosetun.svg
for size in "${ICON_SIZES[@]}"; do
    place 0644 "packaging/linux/icons/$size.png" "usr/share/icons/hicolor/${size}x$size/apps/rosetun.png"
done

mkdir -p "$root/$licenses"
place 0644 LICENSE "$licenses/rosetun.txt"
place 0644 "$work/$sing_box_name/LICENSE" "$licenses/sing-box.txt"
place 0644 installer/third-party/xray-mpl-2.0.txt "$licenses/xray-mpl-2.0.txt"
for font_license in crates/rosetun-gui/assets/fonts/OFL-*.txt; do
    place 0644 "$font_license" "$licenses/${font_license##*/}"
done
cargo -q about generate --fail --locked installer/third-party.hbs -o "$root/$licenses/third-party.html"
chmod 0644 "$root/$licenses/third-party.html"
cat >"$root/$licenses/sing-box-source.txt" <<NOTICE
sing-box $SING_BOX_VERSION is licensed under the GNU General Public License,
version 3 or later (see sing-box.txt). Rosetun ships the unmodified official
build $sing_box_archive, SHA-256 $SING_BOX_ARCHIVE_SHA256.

Corresponding source:
https://github.com/SagerNet/sing-box/tree/v$SING_BOX_VERSION
https://github.com/SagerNet/sing-box/archive/refs/tags/v$SING_BOX_VERSION.tar.gz

Every Rosetun release on GitHub also carries a copy of that source archive.
NOTICE
cat >"$root/$licenses/xray-source.txt" <<NOTICE
Rosetun ships the unmodified official Xray-core $XRAY_VERSION executable,
Xray-linux-64.zip SHA-256 $XRAY_ARCHIVE_SHA256, under the Mozilla Public License 2.0
(see xray-mpl-2.0.txt). No Xray geoip.dat or geosite.dat files are installed.

Corresponding source:
https://github.com/XTLS/Xray-core/tree/v$XRAY_VERSION
https://github.com/XTLS/Xray-core/archive/refs/tags/v$XRAY_VERSION.tar.gz

Every Rosetun release on GitHub also carries a copy of that source archive.
NOTICE
sed -e "s/@SING_BOX_VERSION@/$SING_BOX_VERSION/" -e "s/@XRAY_VERSION@/$XRAY_VERSION/" \
    packaging/linux/copyright.in >"$root/$doc/copyright"
{
    printf 'rosetun (%s) unstable; urgency=medium\n\n' "$deb_version"
    printf '  * Rosetun %s: https://github.com/eoftgge/rosetun/releases\n\n' "$version"
    printf ' -- %s  %s\n' "$MAINTAINER" "$(date -u -R -d "@$SOURCE_DATE_EPOCH")"
} | gzip -9n >"$root/$doc/changelog.Debian.gz"

# dpkg-shlibdeps wants a source package's control file in the working folder.
mkdir -p "$work/shlibs/debian"
: >"$work/shlibs/debian/control"
libraries=$(cd "$work/shlibs" && dpkg-shlibdeps -O \
    -e"$root/$lib/rosetun-helper-privileged" -e"$root/$lib/rosetun-gui" -e"$root/$lib/rosetun" 2>/dev/null |
    sed -n 's/^shlibs:Depends=//p')
[ -n "$libraries" ] || die 'dpkg-shlibdeps found no libraries'

for script in prerm postinst postrm; do
    place 0755 "packaging/linux/debian/$script" "DEBIAN/$script"
done
find "$root" -type d -exec chmod 0755 {} +
installed_kib=$(find "$root" -path "$root/DEBIAN" -prune -o -type f -printf '%s\n' |
    awk '{ total += $1 } END { printf "%d", (total + 1023) / 1024 }')

# nftables, systemd and the helpers run the service. pkexec only asks for the
# password of the GUI's Lockdown switch and its "add me to the group" button;
# the kill switch and `sudo rosetun` work without it, so it is not required.
cat >"$root/DEBIAN/control" <<CONTROL
Package: rosetun
Version: $deb_version
Architecture: amd64
Maintainer: $MAINTAINER
Installed-Size: $installed_kib
Depends: nftables, systemd, init-system-helpers (>= 1.66), $libraries, $GUI_LIBRARIES
Recommends: desktop-file-utils, hicolor-icon-theme, pkexec
Section: net
Priority: optional
Homepage: https://github.com/eoftgge/rosetun
Description: VPN client with a kill switch and Lockdown
 Rosetun connects through VLESS, VMess, Trojan, Shadowsocks and other
 protocols. sing-box and Xray are included.
 .
 The kill switch keeps the network closed while the tunnel is down. Lockdown
 keeps it closed from the moment the computer starts, until you connect.
CONTROL

(cd "$root" && find usr -type f -print0 | sort -z | xargs -0 md5sum) >"$root/DEBIAN/md5sums"
chmod 0644 "$root/DEBIAN/control" "$root/DEBIAN/md5sums" "$root/$doc/copyright" \
    "$root/$doc/changelog.Debian.gz" "$root/$licenses/sing-box-source.txt" "$root/$licenses/xray-source.txt"
find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

package=$out/rosetun_${deb_version}_amd64.deb
rm -f -- "$package"
dpkg-deb --root-owner-group --threads-max=1 -Zxz --build "$root" "$package" >/dev/null
printf 'Package: %s\nSHA-256: %s\n' "$package" "$(sha256_of "$package")"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf 'deb=%s\n' "$package" >>"$GITHUB_OUTPUT"
fi
