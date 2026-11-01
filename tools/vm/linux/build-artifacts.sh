#!/bin/bash
# Builds the Linux artifacts of the L2 stand inside Debian (WSL or the build VM).
# Never run it as root and never cross-build from Windows: the stand accepts only
# an x86-64 ELF made here, together with provenance.json describing the build.
#
#   tools/vm/linux/build-artifacts.sh OUTPUT_DIR
#
# OUTPUT_DIR must not exist yet. Needs Rust 1.96.0 (the project MSRV) and a C linker.
# CARGO_TARGET_DIR may point at a Linux filesystem directory to keep the build fast.

set -eu
export LC_ALL=C

out=${1-}
[ -n "$out" ] || { echo "usage: build-artifacts.sh OUTPUT_DIR" >&2; exit 64; }
[ "$(id -u)" -ne 0 ] || { echo "build-artifacts.sh: do not build as root" >&2; exit 1; }
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || { echo "build-artifacts.sh: needs an x86_64 Linux host" >&2; exit 1; }
[ ! -e "$out" ] || { echo "build-artifacts.sh: $out already exists" >&2; exit 1; }

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)
cd -- "$repo"

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
target_dir=$(cargo +1.96.0 metadata --locked --format-version 1 --no-deps | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
fixture=$target_dir/debug/examples/l2_transport_fixture
ipc_tests=$(find_exe lib rosetun_ipc true)
helper_tests=$(find_exe bin rosetun-helper-privileged true)
for file in "$fixture" "$ipc_tests" "$helper_tests"; do
    [ -n "$file" ] && [ -f "$file" ] || { echo "build-artifacts.sh: a build product was not found" >&2; exit 1; }
done

if sha=$(git rev-parse HEAD 2>/dev/null) && [[ $sha =~ ^[0-9a-f]{40}$ ]]; then
    if [ -n "$(git status --porcelain=v1 -uall --no-renames)" ]; then dirty=true; else dirty=false; fi
    # Same bytes the host hashes: raw status, a separator line, then the binary diff.
    # Untracked files count by name only; their content is not part of the digest.
    digest=$( { git status --porcelain=v1 -uall --no-renames; printf '\n--\n'; git diff HEAD --binary --no-ext-diff; } | sha256sum | cut -d' ' -f1)
else
    sha=unknown dirty=unknown digest=unknown
fi

mkdir -p -- "$out"
install -m 0755 -- "$fixture" "$out/l2_transport_fixture"
install -m 0755 -- "$helper_tests" "$out/rosetun_helper_privileged_tests"
install -m 0755 -- "$ipc_tests" "$out/rosetun_ipc_tests"

hash_of() { sha256sum -- "$1" | cut -d' ' -f1; }
{
    printf '{\n  "schema": 1,\n  "target": "x86_64-unknown-linux-gnu",\n'
    printf '  "source_sha": "%s",\n  "source_dirty": %s,\n  "source_dirty_digest": "%s",\n' "$sha" "$dirty" "$digest"
    printf '  "toolchain": {"rustc": "%s", "cargo": "%s"},\n' \
        "$(rustc +1.96.0 --version | tr -d '"')" "$(cargo +1.96.0 --version | tr -d '"')"
    printf '  "built_on": {"os": "%s", "kernel": "%s", "arch": "%s"},\n' \
        "$(. /etc/os-release && printf '%s' "${PRETTY_NAME-unknown}" | tr -d '"')" "$(uname -r | tr -d '"')" "$(uname -m)"
    printf '  "artifacts": {\n'
    printf '    "l2_transport_fixture": {"sha256": "%s"},\n' "$(hash_of "$out/l2_transport_fixture")"
    printf '    "rosetun_helper_privileged_tests": {"sha256": "%s"},\n' "$(hash_of "$out/rosetun_helper_privileged_tests")"
    printf '    "rosetun_ipc_tests": {"sha256": "%s"}\n' "$(hash_of "$out/rosetun_ipc_tests")"
    printf '  }\n}\n'
} >"$out/provenance.json"
chmod 0644 "$out/provenance.json"

echo "artifacts written to $out"
echo "source: $sha dirty=$dirty"
