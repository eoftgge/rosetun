#!/bin/bash
# Builds the L2 stand artifacts of one exact commit inside WSL. The host
# (Invoke-LinuxL2Matrix.ps1) calls it through `wsl -d <distro> --exec`; nobody needs to
# open WSL by hand. It keeps its own clone and cargo cache under ~/.cache/rosetun-l2
# and writes nothing else except OUTPUT_DIR.
#
#   build-in-wsl.sh SOURCE_REPO COMMIT_SHA OUTPUT_DIR [--l3]
#
# SOURCE_REPO is the Windows checkout as WSL sees it (/mnt/<drive>/...). COMMIT_SHA
# must be its HEAD. The build itself is build-artifacts.sh of that very commit.

set -eu
export LC_ALL=C

die() {
    printf 'build-in-wsl.sh: %s\n' "$1" >&2
    exit "${2-1}"
}

[ $# -eq 3 ] || { [ $# -eq 4 ] && [ "$4" = --l3 ]; } || die "usage: build-in-wsl.sh SOURCE_REPO COMMIT_SHA OUTPUT_DIR [--l3]" 64
src=$1 sha=$2 out=$3 stage=()
[ $# -eq 3 ] || stage=(--l3)
[[ $sha =~ ^[0-9a-f]{40}$ ]] || die "invalid commit id '$sha'" 64
[[ $out == /* ]] || die "OUTPUT_DIR must be an absolute path" 64
[ "$(id -u)" -ne 0 ] || die "do not build as root; make an ordinary account the WSL default user"
[ -e "$src/.git" ] || die "$src is not a git checkout"

# rustup installs into ~/.cargo/bin, which a non-login WSL shell may not have on PATH.
if [ -d "$HOME/.cargo/bin" ]; then PATH=$HOME/.cargo/bin:$PATH; fi

missing=()
command -v git >/dev/null 2>&1 || missing+=("git (sudo apt-get install git)")
command -v cc >/dev/null 2>&1 || missing+=("a C linker (sudo apt-get install build-essential)")
if ! command -v rustup >/dev/null 2>&1; then
    missing+=("rustup (curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh, then rustup toolchain install 1.96.0)")
elif ! rustup run 1.96.0 rustc --version >/dev/null 2>&1; then
    missing+=("Rust 1.96.0 (rustup toolchain install 1.96.0)")
fi
if [ "${#missing[@]}" -gt 0 ]; then
    printf 'build-in-wsl.sh: missing in WSL: %s\n' "${missing[@]}" >&2
    exit 3
fi

cache=$HOME/.cache/rosetun-l2
clone=$cache/src
export CARGO_TARGET_DIR=$cache/target
mkdir -p -- "$cache"
[ -e "$clone" ] || git init -q -- "$clone"
[ -d "$clone/.git" ] && [ ! -L "$clone" ] || die "$clone exists but is not the stand's clone; move it away"
cd -- "$clone"

# The Windows checkout may look foreign-owned to WSL's git; trust only it, only here.
git -c safe.directory="$src" -c safe.directory="$src/.git" \
    fetch -q --no-tags -- "$src" "+HEAD:refs/rosetun-l2/host-head" || die "git fetch from $src failed"
fetched=$(git rev-parse --verify -q 'refs/rosetun-l2/host-head^{commit}') || die "the fetched HEAD is not a commit"
[ "$fetched" = "$sha" ] || die "the host checkout moved to $fetched; start the run again"

# Destructive steps run only inside the stand's own clone.
git checkout -q --force --detach "$sha"
git clean -q -ffd
[ "$(git rev-parse HEAD)" = "$sha" ] || die "checkout of $sha failed"
[ -z "$(git status --porcelain=v1 -uall)" ] || die "the clone in $clone is not clean after checkout"

[ ! -e "$out" ] || die "$out already exists"
mkdir -p -- "$(dirname -- "$out")"
exec bash "$clone/tools/vm/linux/build-artifacts.sh" "${stage[@]}" "$out"
