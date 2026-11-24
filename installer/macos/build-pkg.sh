#!/bin/bash
# Builds rosetun-<version>-macos-arm64-experimental.pkg on Apple Silicon macOS.
# Run as an ordinary user.
#
#   installer/macos/build-pkg.sh [--release] [--allow-unsigned] [--skip-notarize]
#
# --release          installs the pinned cargo-about when it is missing
# --allow-unsigned   builds an unsigned .pkg when Developer ID identities are unset
# --skip-notarize    skips notarization even when Developer ID identities are set
#
# Optional signing and notarization environment variables:
#   APPLE_DEVELOPER_ID_APP        "Developer ID Application: ... (TEAMID)"
#   APPLE_DEVELOPER_ID_INSTALLER  "Developer ID Installer: ... (TEAMID)"
#   APPLE_NOTARY_KEYCHAIN_PROFILE keychain profile stored with notarytool
#     or
#   APPLE_API_KEY_PATH, APPLE_API_KEY_ID, APPLE_API_ISSUER_ID
#     or
#   APPLE_ID, APPLE_APP_PASSWORD, APPLE_TEAM_ID
#
# The result is <target>/macos/rosetun-<version>-macos-arm64-experimental.pkg.

set -euo pipefail
export LC_ALL=C TZ=UTC
umask 022

# Update these together with installer/build.ps1, installer/linux/build-deb.sh,
# SUPPORTED_SING_BOX_VERSION and SUPPORTED_XRAY_VERSION.
SING_BOX_VERSION=1.14.3
SING_BOX_ARCHIVE_SHA256=0360ce634a04c26a6b4fd957517987bb4f6c8950f63435ce3c5af2fcae5860c5
XRAY_VERSION=26.11.9
XRAY_ARCHIVE_SHA256=233f0c66681cd0726f81a6b2b6ed6a5710869e312047b522e46ed53035bebd26
CARGO_ABOUT_VERSION=0.9.2
PKG_IDENTIFIER=io.github.eoftgge.rosetun

die() {
    printf 'build-pkg.sh: %s\n' "$1" >&2
    exit 1
}

release=false
allow_unsigned=false
skip_notarize=false
while [ $# -gt 0 ]; do
    case $1 in
    --release) release=true ;;
    --allow-unsigned) allow_unsigned=true ;;
    --skip-notarize) skip_notarize=true ;;
    *) die "unknown argument $1" ;;
    esac
    shift
done

[ "$(id -u)" -ne 0 ] || die 'do not build as root'
[ "$(uname -s)-$(uname -m)" = Darwin-arm64 ] || die 'needs Apple Silicon macOS (Darwin arm64)'
if [ -d "$HOME/.cargo/bin" ]; then PATH=$HOME/.cargo/bin:$PATH; fi
for tool in cargo codesign curl git iconutil pkgbuild pkgutil plutil productbuild shasum sips tar unzip; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is missing"
done
[ -x /usr/libexec/PlistBuddy ] || die '/usr/libexec/PlistBuddy is missing'
export RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-1.99.1}

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
short_version=${version%%-*}
[[ $short_version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid workspace version $version"

signing_enabled=false
if [ -n "${APPLE_DEVELOPER_ID_APP:-}" ] || [ -n "${APPLE_DEVELOPER_ID_INSTALLER:-}" ]; then
    [ -n "${APPLE_DEVELOPER_ID_APP:-}" ] || die 'APPLE_DEVELOPER_ID_APP must be set alongside APPLE_DEVELOPER_ID_INSTALLER'
    [ -n "${APPLE_DEVELOPER_ID_INSTALLER:-}" ] || die 'APPLE_DEVELOPER_ID_INSTALLER must be set alongside APPLE_DEVELOPER_ID_APP'
    signing_enabled=true
elif ! $allow_unsigned; then
    die 'APPLE_DEVELOPER_ID_APP and APPLE_DEVELOPER_ID_INSTALLER are unset; pass --allow-unsigned for an unsigned build'
fi

notary_mode=none
if $signing_enabled && ! $skip_notarize; then
    if [ -n "${APPLE_NOTARY_KEYCHAIN_PROFILE:-}" ]; then
        notary_mode=profile
    elif [ -n "${APPLE_API_KEY_PATH:-}" ] && [ -n "${APPLE_API_KEY_ID:-}" ] && [ -n "${APPLE_API_ISSUER_ID:-}" ]; then
        [ -f "$APPLE_API_KEY_PATH" ] || die "APPLE_API_KEY_PATH does not exist: $APPLE_API_KEY_PATH"
        notary_mode=api_key
    elif [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_APP_PASSWORD:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ]; then
        notary_mode=apple_id
    else
        die 'notarization credentials are required for signed builds (or pass --skip-notarize)'
    fi
fi

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
out=$target/macos
cache=$out/cache
mkdir -p -- "$cache"

sha256_of() {
    shasum -a 256 -- "$1" | awk '{ print $1 }'
}

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

sing_box_name=sing-box-$SING_BOX_VERSION-darwin-arm64
sing_box_archive=$sing_box_name.tar.gz
xray_archive=Xray-$XRAY_VERSION-macos-arm64-v8a.zip
fetch "https://github.com/SagerNet/sing-box/releases/download/v$SING_BOX_VERSION/$sing_box_archive" \
    "$sing_box_archive" "$SING_BOX_ARCHIVE_SHA256"
fetch "https://github.com/XTLS/Xray-core/releases/download/v$XRAY_VERSION/Xray-macos-arm64-v8a.zip" \
    "$xray_archive" "$XRAY_ARCHIVE_SHA256"

# Keep build paths out of panic messages and strip debug symbols.
export CARGO_PROFILE_RELEASE_STRIP=symbols
export RUSTFLAGS="--remap-path-prefix=$repo=/rosetun --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$target=/target"
# Build the CLI separately so it does not inherit GUI crate features.
cargo build -q --release --locked --target aarch64-apple-darwin -p rosetun-gui -p rosetun-helper-privileged
cargo build -q --release --locked --target aarch64-apple-darwin -p rosetun
release_dir=$target/aarch64-apple-darwin/release

work=$(mktemp -d "$out/stage.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
chmod 0700 "$work"
root=$work/root
scripts=$work/scripts
mkdir -p "$root" "$scripts"

place() {
    local mode=$1 src=$2 dst=$root/$3
    mkdir -p -- "$(dirname -- "$dst")"
    install -m "$mode" -- "$src" "$dst"
}

app=Applications/Rosetun.app
app_contents=$app/Contents
app_licenses=$app_contents/Resources/licenses
libexec=usr/local/libexec/rosetun

# Build Rosetun.icns from the repository's rendered PNG icons.
iconset=$work/Rosetun.iconset
mkdir -p "$iconset"
cp packaging/linux/icons/16.png "$iconset/icon_16x16.png"
cp packaging/linux/icons/32.png "$iconset/icon_16x16@2x.png"
cp packaging/linux/icons/32.png "$iconset/icon_32x32.png"
cp packaging/linux/icons/64.png "$iconset/icon_32x32@2x.png"
cp packaging/linux/icons/128.png "$iconset/icon_128x128.png"
cp packaging/linux/icons/256.png "$iconset/icon_128x128@2x.png"
cp packaging/linux/icons/256.png "$iconset/icon_256x256.png"
cp packaging/linux/icons/512.png "$iconset/icon_256x256@2x.png"
cp packaging/linux/icons/512.png "$iconset/icon_512x512.png"
sips -z 1024 1024 packaging/linux/icons/512.png --out "$iconset/icon_512x512@2x.png" >/dev/null
iconutil -c icns "$iconset" -o "$work/Rosetun.icns"

# Populate Rosetun.app.
place 0755 "$release_dir/rosetun-gui" "$app_contents/MacOS/rosetun-gui"
place 0644 "$work/Rosetun.icns" "$app_contents/Resources/Rosetun.icns"
sed -e "s/@SHORT_VERSION@/$short_version/g" -e "s/@BUNDLE_VERSION@/$version/g" \
    packaging/macos/Info.plist.in >"$work/Info.plist"
plutil -lint "$work/Info.plist" >/dev/null
place 0644 "$work/Info.plist" "$app_contents/Info.plist"

# Populate helper, bundled engines, CLI, LaunchDaemon plist and uninstall script.
place 0755 "$release_dir/rosetun-helper-privileged" "$libexec/rosetun-helper-privileged"
place 0755 "$release_dir/rosetun" usr/local/bin/rosetun
place 0755 packaging/macos/uninstall.sh "$libexec/uninstall.sh"
plutil -lint packaging/macos/io.github.eoftgge.rosetun.helper.plist >/dev/null
place 0644 packaging/macos/io.github.eoftgge.rosetun.helper.plist \
    Library/LaunchDaemons/io.github.eoftgge.rosetun.helper.plist

tar -xzf "$cache/$sing_box_archive" -C "$work" "$sing_box_name/sing-box" "$sing_box_name/LICENSE"
place 0755 "$work/$sing_box_name/sing-box" "$libexec/sing-box"
unzip -q -o "$cache/$xray_archive" xray -d "$work"
place 0755 "$work/xray" "$libexec/xray"

# Populate licenses inside Rosetun.app/Contents/Resources/licenses.
place 0644 LICENSE "$app_licenses/rosetun.txt"
place 0644 "$work/$sing_box_name/LICENSE" "$app_licenses/sing-box.txt"
place 0644 installer/third-party/xray-mpl-2.0.txt "$app_licenses/xray-mpl-2.0.txt"
for font_license in crates/rosetun-gui/assets/fonts/OFL-*.txt; do
    place 0644 "$font_license" "$app_licenses/${font_license##*/}"
done
place 0644 crates/rosetun-gui/assets/flags/MIT-flag-icons.txt "$app_licenses/MIT-flag-icons.txt"
cargo -q about generate --fail --locked installer/third-party.hbs -o "$root/$app_licenses/third-party.html"
chmod 0644 "$root/$app_licenses/third-party.html"

cat >"$root/$app_licenses/sing-box-source.txt" <<NOTICE
sing-box $SING_BOX_VERSION is licensed under the GNU General Public License,
version 3 or later (see sing-box.txt). Rosetun ships the unmodified official
build $sing_box_archive, SHA-256 $SING_BOX_ARCHIVE_SHA256.

Corresponding source:
https://github.com/SagerNet/sing-box/tree/v$SING_BOX_VERSION
https://github.com/SagerNet/sing-box/archive/refs/tags/v$SING_BOX_VERSION.tar.gz

Every Rosetun release on GitHub also carries a copy of that source archive.
NOTICE
chmod 0644 "$root/$app_licenses/sing-box-source.txt"

cat >"$root/$app_licenses/xray-source.txt" <<NOTICE
Rosetun ships the unmodified official Xray-core $XRAY_VERSION executable,
Xray-macos-arm64-v8a.zip SHA-256 $XRAY_ARCHIVE_SHA256, under the Mozilla Public License 2.0
(see xray-mpl-2.0.txt). No Xray geoip.dat or geosite.dat files are installed.

Corresponding source:
https://github.com/XTLS/Xray-core/tree/v$XRAY_VERSION
https://github.com/XTLS/Xray-core/archive/refs/tags/v$XRAY_VERSION.tar.gz

Every Rosetun release on GitHub also carries a copy of that source archive.
NOTICE
chmod 0644 "$root/$app_licenses/xray-source.txt"

# Stage installer scripts.
install -m 0755 packaging/macos/scripts/preinstall "$scripts/preinstall"
install -m 0755 packaging/macos/scripts/postinstall "$scripts/postinstall"

# Developer ID signing of Mach-O executables and the .app bundle (inside-out).
if $signing_enabled; then
    sign_binary() {
        codesign --force --options runtime --timestamp --sign "$APPLE_DEVELOPER_ID_APP" "$1"
    }
    sign_binary "$root/$libexec/sing-box"
    sign_binary "$root/$libexec/xray"
    sign_binary "$root/$libexec/rosetun-helper-privileged"
    sign_binary "$root/usr/local/bin/rosetun"
    sign_binary "$root/$app_contents/MacOS/rosetun-gui"
    codesign --force --options runtime --timestamp --sign "$APPLE_DEVELOPER_ID_APP" "$root/$app"

    codesign --verify --deep --strict --verbose=2 "$root/$app"
    for bin in "$root/$libexec/rosetun-helper-privileged" "$root/$libexec/sing-box" \
        "$root/$libexec/xray" "$root/usr/local/bin/rosetun"; do
        codesign --verify --strict --verbose=2 "$bin"
    done
fi

# Build non-relocatable component package and product archive.
component_plist=$work/component.plist
pkgbuild --analyze --root "$root" "$component_plist" >/dev/null
/usr/libexec/PlistBuddy -c 'Set :0:BundleIsRelocatable false' "$component_plist"

component_pkg=$work/rosetun-component.pkg
pkgbuild \
    --root "$root" \
    --component-plist "$component_plist" \
    --scripts "$scripts" \
    --identifier "$PKG_IDENTIFIER" \
    --version "$version" \
    --install-location / \
    --ownership recommended \
    "$component_pkg" >/dev/null

distribution_xml=$work/distribution.xml
sed -e "s/@VERSION@/$version/g" packaging/macos/distribution.xml.in >"$distribution_xml"

package=$out/rosetun-$version-macos-arm64-experimental.pkg
rm -f -- "$package"

product_args=(
    --distribution "$distribution_xml"
    --package-path "$work"
)
if $signing_enabled; then
    product_args+=(--sign "$APPLE_DEVELOPER_ID_INSTALLER" --timestamp)
fi
productbuild "${product_args[@]}" "$package" >/dev/null

notarized=false
if $signing_enabled; then
    pkgutil --check-signature "$package"
    if [ "$notary_mode" != none ]; then
        notary_args=(submit "$package" --wait)
        case $notary_mode in
        profile)
            notary_args+=(--keychain-profile "$APPLE_NOTARY_KEYCHAIN_PROFILE")
            ;;
        api_key)
            notary_args+=(--key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER_ID")
            ;;
        apple_id)
            notary_args+=(--apple-id "$APPLE_ID" --password "$APPLE_APP_PASSWORD" --team-id "$APPLE_TEAM_ID")
            ;;
        esac
        xcrun notarytool "${notary_args[@]}"
        xcrun stapler staple "$package"
        xcrun stapler validate "$package"
        spctl --assess --type install -vv "$package"
        notarized=true
    fi
else
    printf 'build-pkg.sh: built unsigned macOS package (Developer ID signing was not configured).\n' >&2
fi

printf 'Package: %s\nSHA-256: %s\nSigned: %s\nNotarized: %s\n' \
    "$package" "$(sha256_of "$package")" "$signing_enabled" "$notarized"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
    {
        printf 'pkg=%s\n' "$package"
        printf 'signed=%s\n' "$signing_enabled"
        printf 'notarized=%s\n' "$notarized"
    } >>"$GITHUB_OUTPUT"
fi
