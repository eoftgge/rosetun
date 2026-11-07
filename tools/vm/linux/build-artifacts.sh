#!/bin/bash
# Builds the Linux artifacts of the L2 stand inside Debian (WSL or the build VM).
# Never run it as root and never cross-build from Windows: the stand accepts only
# an x86-64 ELF made here, together with provenance.json describing the build.
#
#   tools/vm/linux/build-artifacts.sh [--l3 | --proxy | --deb] OUTPUT_DIR
#
# Without an option: the L2 artifacts (transport fixture and unit test binaries). With
# --l3: the release helper and CLI that the L3 matrix installs as the real service.
# --proxy: the same, and the tool that changes the desktop's proxy as the GUI does.
# With --deb: the package twice, as the new version and as an older one to upgrade
# from; it needs what installer/linux/build-deb.sh needs.
# OUTPUT_DIR must not exist yet. Needs Rust 1.96.0 (the project MSRV) and a C linker.
# CARGO_TARGET_DIR may point at a Linux filesystem directory to keep the build fast.

set -eu
export LC_ALL=C

stage=l2
if [ "${1-}" = --l3 ]; then
    stage=l3
    shift
elif [ "${1-}" = --proxy ]; then
    stage=proxy
    shift
elif [ "${1-}" = --deb ]; then
    stage=l5
    shift
fi
out=${1-}
[ -n "$out" ] || { echo "usage: build-artifacts.sh [--l3 | --proxy | --deb] OUTPUT_DIR" >&2; exit 64; }
[ "$(id -u)" -ne 0 ] || { echo "build-artifacts.sh: do not build as root" >&2; exit 1; }
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || { echo "build-artifacts.sh: needs an x86_64 Linux host" >&2; exit 1; }
[ ! -e "$out" ] || { echo "build-artifacts.sh: $out already exists" >&2; exit 1; }

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)
cd -- "$repo"

if sha=$(git rev-parse HEAD 2>/dev/null) && [[ $sha =~ ^[0-9a-f]{40}$ ]]; then
    if [ -n "$(git status --porcelain=v1 -uall --no-renames)" ]; then dirty=true; else dirty=false; fi
    # Same bytes the host hashes: raw status, a separator line, then the binary diff.
    # Untracked files count by name only; their content is not part of the digest.
    digest=$( { git status --porcelain=v1 -uall --no-renames; printf '\n--\n'; git diff HEAD --binary --no-ext-diff; } | sha256sum | cut -d' ' -f1)
else
    sha=unknown dirty=unknown digest=unknown
fi

hash_of() { sha256sum -- "$1" | cut -d' ' -f1; }

# provenance NAME...: provenance.json for these files of OUTPUT_DIR.
provenance() {
    local name last=${!#}
    printf '{\n  "schema": 1,\n  "stage": "%s",\n  "target": "x86_64-unknown-linux-gnu",\n' "$stage"
    printf '  "source_sha": "%s",\n  "source_dirty": %s,\n  "source_dirty_digest": "%s",\n' "$sha" "$dirty" "$digest"
    printf '  "toolchain": {"rustc": "%s", "cargo": "%s"},\n' \
        "$(rustc +1.96.0 --version | tr -d '"')" "$(cargo +1.96.0 --version | tr -d '"')"
    printf '  "built_on": {"os": "%s", "kernel": "%s", "arch": "%s"},\n' \
        "$(. /etc/os-release && printf '%s' "${PRETTY_NAME-unknown}" | tr -d '"')" "$(uname -r | tr -d '"')" "$(uname -m)"
    printf '  "artifacts": {\n'
    for name in "$@"; do
        printf '    "%s": {"sha256": "%s"}' "$name" "$(hash_of "$out/$name")"
        if [ "$name" = "$last" ]; then printf '\n'; else printf ',\n'; fi
    done
    printf '  }\n}\n'
}

target_dir=$(cargo +1.96.0 metadata --locked --format-version 1 --no-deps | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')

if [ "$stage" = l5 ]; then
    # build_deb DESTINATION ARGS...: one package, under the name the stand expects.
    build_deb() {
        local destination=$1 built
        shift
        built=$(bash installer/linux/build-deb.sh "$@" | sed -n 's/^Package: //p')
        [ -n "$built" ] && [ -f "$built" ] || { echo "build-artifacts.sh: the package was not built" >&2; exit 1; }
        install -m 0644 -- "$built" "$out/$destination"
    }
    mkdir -p -- "$out"
    build_deb rosetun-old.deb --package-version 0.0.1~stand
    build_deb rosetun-new.deb
    provenance rosetun-old.deb rosetun-new.deb >"$out/provenance.json"
elif [ "$stage" = proxy ]; then
    cargo +1.96.0 build -q --locked --release -p rosetun-helper-privileged -p rosetun
    cargo +1.96.0 build -q --locked --release -p rosetun-shell --example desktop_proxy
    for name in rosetun-helper-privileged rosetun examples/desktop_proxy; do
        [ -f "$target_dir/release/$name" ] || { echo "build-artifacts.sh: a build product was not found" >&2; exit 1; }
    done
    mkdir -p -- "$out"
    install -m 0755 -- "$target_dir/release/rosetun-helper-privileged" "$out/rosetun-helper-privileged"
    install -m 0755 -- "$target_dir/release/rosetun" "$out/rosetun"
    install -m 0755 -- "$target_dir/release/examples/desktop_proxy" "$out/desktop_proxy"
    provenance rosetun-helper-privileged rosetun desktop_proxy >"$out/provenance.json"
elif [ "$stage" = l3 ]; then
    cargo +1.96.0 build -q --locked --release -p rosetun-helper-privileged -p rosetun
    for name in rosetun-helper-privileged rosetun; do
        [ -f "$target_dir/release/$name" ] || { echo "build-artifacts.sh: a build product was not found" >&2; exit 1; }
    done
    mkdir -p -- "$out"
    install -m 0755 -- "$target_dir/release/rosetun-helper-privileged" "$out/rosetun-helper-privileged"
    install -m 0755 -- "$target_dir/release/rosetun" "$out/rosetun"
    provenance rosetun-helper-privileged rosetun >"$out/provenance.json"
else
    json=$(mktemp)
    trap 'rm -f -- "$json"' EXIT
    cargo +1.96.0 build -q --locked -p rosetun-ipc --example l2_transport_fixture
    cargo +1.96.0 test -q --locked --no-run --message-format=json -p rosetun-ipc -p rosetun-helper-privileged >"$json"

    # Executables of the three targets, taken from cargo's own report.
    find_exe() {
        # find_exe KIND NAME
        grep '"reason":"compiler-artifact"' "$json" | grep -F "\"kind\":[\"$1\"]" | grep -F "\"name\":\"$2\"" |
            grep '"executable":"' | grep -F '"test":'"${3-false}" |
            sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | tail -n 1
    }
    fixture=$target_dir/debug/examples/l2_transport_fixture
    ipc_tests=$(find_exe lib rosetun_ipc true)
    helper_tests=$(find_exe bin rosetun-helper-privileged true)
    for file in "$fixture" "$ipc_tests" "$helper_tests"; do
        [ -n "$file" ] && [ -f "$file" ] || { echo "build-artifacts.sh: a build product was not found" >&2; exit 1; }
    done

    mkdir -p -- "$out"
    install -m 0755 -- "$fixture" "$out/l2_transport_fixture"
    install -m 0755 -- "$helper_tests" "$out/rosetun_helper_privileged_tests"
    install -m 0755 -- "$ipc_tests" "$out/rosetun_ipc_tests"
    provenance l2_transport_fixture rosetun_helper_privileged_tests rosetun_ipc_tests >"$out/provenance.json"
fi
chmod 0644 "$out/provenance.json"

echo "artifacts written to $out"
echo "source: $sha dirty=$dirty"
