#!/bin/bash
# Root entry of the Linux L2 stand. install-launcher.sh installs this file once as
# /usr/local/libexec/rosetun-l2/launch, and the only sudoers rule of the stand lets
# the SSH account run that path without a password. The owner may also run the
# staged copy by hand: sudo bash <stage>/guest/launch.sh ...
#
#   launch RUN_ID STAGE_DIR MANIFEST_SHA256
#
# The launcher establishes which bytes run: it checks the stage and its owner,
# proves the manifest against the hash the host computed, copies every listed file
# into a root-owned run directory and verifies the copies. Then it runs the
# verified copy of guest/start.sh, which decides what the job is and starts it. The
# launcher never reads job.env and never starts the job itself, so a change of the
# job needs no reinstallation of this file.

set -u
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
umask 022

L2_LAUNCH_INSTALLED=/usr/local/libexec/rosetun-l2/launch
L2_LAUNCH_BASE=/var/lib/rosetun-l2

l2_launch_die() {
    printf 'launch: %s\n' "$1" >&2
    exit 1
}

# Every name a stage may carry, and nothing that can leave the run directory:
# one level, no leading dot, no "..". start.sh narrows this to its exact list.
l2_launch_path_allowed() {
    [[ $1 =~ ^(guest/[a-z0-9][a-z0-9-]*\.sh|[a-z0-9][a-z0-9-]*\.(tsv|env)|artifacts/[A-Za-z0-9_][A-Za-z0-9_.-]*)$ ]] &&
        [[ $1 != *..* ]]
}

l2_launch_mode() {
    case $1 in
        *.json | *.tsv | *.env) printf '0644' ;;
        *) printf '0755' ;;
    esac
}

# Reads a manifest into L2_LAUNCH_PATHS. Fails on a malformed or foreign line, a
# duplicate, an empty manifest or one without guest/start.sh.
l2_launch_read_manifest() {
    local line path seen=' '
    L2_LAUNCH_PATHS=()
    while IFS= read -r line || [ -n "$line" ]; do
        [ -n "$line" ] || continue
        [[ $line =~ ^[0-9a-f]{64}\ \ (.+)$ ]] || { L2_LAUNCH_ERROR="malformed manifest line"; return 1; }
        path=${BASH_REMATCH[1]}
        l2_launch_path_allowed "$path" || { L2_LAUNCH_ERROR="manifest names a path the stand does not use: $path"; return 1; }
        [[ $seen != *" $path "* ]] || { L2_LAUNCH_ERROR="manifest names $path twice"; return 1; }
        seen="$seen$path "
        L2_LAUNCH_PATHS+=("$path")
    done <"$1"
    [ "${#L2_LAUNCH_PATHS[@]}" -gt 0 ] || { L2_LAUNCH_ERROR="the manifest is empty"; return 1; }
    [[ $seen == *" guest/start.sh "* ]] || { L2_LAUNCH_ERROR="the manifest lacks guest/start.sh"; return 1; }
}

# A root-owned directory or file that neither group nor others can write.
l2_launch_root_only() {
    [ ! -L "$1" ] && [ "$(stat -c %u -- "$1")" -eq 0 ] && [ $((0$(stat -c %a -- "$1") & 022)) -eq 0 ]
}

l2_launch_main() {
    [ "$(id -u)" -eq 0 ] || l2_launch_die "run it with sudo"
    [ $# -eq 3 ] || l2_launch_die "usage: launch RUN_ID STAGE_DIR MANIFEST_SHA256"
    local run_id=$1 stage=$2 manifest_hash=$3
    [[ $run_id =~ ^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$ ]] || l2_launch_die "invalid run id"
    [[ $manifest_hash =~ ^[0-9a-f]{64}$ ]] || l2_launch_die "invalid manifest hash"

    local self
    self=$(readlink -f -- "${BASH_SOURCE[0]}") || l2_launch_die "cannot resolve the launcher path"
    if [ "$self" = "$L2_LAUNCH_INSTALLED" ]; then
        l2_launch_root_only "$self" && l2_launch_root_only "${self%/*}" ||
            l2_launch_die "the installed launcher or its directory is not root-owned without group or other write"
    fi

    # The stage is the private folder the host created for this run, in the home
    # of the account that ran sudo.
    local uid=${SUDO_UID-0} home
    [[ $uid =~ ^[0-9]+$ ]] || l2_launch_die "invalid SUDO_UID"
    home=$(getent passwd "$uid" | cut -d: -f6)
    [[ $home == /* ]] || l2_launch_die "cannot find the home directory of uid $uid"
    [ "$stage" = "$home/rosetun-l2-stage/$run_id" ] || l2_launch_die "the stage must be $home/rosetun-l2-stage/$run_id"
    local parent=${stage%/*}
    [ -d "$parent" ] && [ ! -L "$parent" ] && [ "$(stat -c %u -- "$parent")" = "$uid" ] &&
        [ $((0$(stat -c %a -- "$parent") & 022)) -eq 0 ] || l2_launch_die "$parent is not a private folder of uid $uid"
    [ -d "$stage" ] && [ ! -L "$stage" ] || l2_launch_die "stage directory is missing or a symlink"
    local stage_owner stage_mode
    stage_owner=$(stat -c %u -- "$stage")
    stage_mode=$(stat -c %a -- "$stage")
    if [ "$stage_owner" != "$uid" ] && [ "$stage_owner" != 0 ]; then
        l2_launch_die "stage directory is owned by uid $stage_owner, not by the account that ran sudo"
    fi
    [ $((0$stage_mode & 077)) -eq 0 ] || l2_launch_die "stage directory mode $stage_mode lets other accounts in; use 0700"
    [ -f "$stage/manifest.sha256" ] && [ ! -L "$stage/manifest.sha256" ] || l2_launch_die "manifest.sha256 is missing"

    # Everything below works on a private copy, so the staged files cannot change under it.
    local work
    work=$(mktemp -d /run/rosetun-l2-launch.XXXXXX) || l2_launch_die "cannot create a private work directory"
    trap 'rm -rf -- "$work"' EXIT
    cp -- "$stage/manifest.sha256" "$work/manifest.sha256" || l2_launch_die "cannot read the manifest"
    local actual
    actual=$(sha256sum -- "$work/manifest.sha256" | cut -d' ' -f1)
    [ "$actual" = "$manifest_hash" ] || l2_launch_die "manifest hash $actual is not the one the host computed"
    l2_launch_read_manifest "$work/manifest.sha256" || l2_launch_die "$L2_LAUNCH_ERROR"

    # A launcher run from the stage must itself be the one the manifest describes.
    if [ "$self" != "$L2_LAUNCH_INSTALLED" ]; then
        local self_hash listed
        self_hash=$(sha256sum -- "$self" | cut -d' ' -f1)
        listed=$(awk '$2 == "guest/launch.sh" { print $1 }' "$work/manifest.sha256")
        [ -n "$listed" ] && [ "$self_hash" = "$listed" ] ||
            l2_launch_die "this launcher is not the guest/launch.sh of the staged run; use the one from the stage"
    fi

    local base=$L2_LAUNCH_BASE
    if [ -e "$base" ] || [ -L "$base" ]; then
        [ -d "$base" ] && l2_launch_root_only "$base" || l2_launch_die "$base is not a root-owned directory without group or other write"
    else
        install -d -m 0755 -o root -g root -- "$base" || l2_launch_die "cannot create $base"
    fi
    local run="$base/$run_id"
    [ ! -e "$run" ] && [ ! -L "$run" ] || l2_launch_die "$run already exists; a run id is used once"
    install -d -m 0755 -o root -g root -- "$run" || l2_launch_die "cannot create $run"

    local path source_file
    for path in "${L2_LAUNCH_PATHS[@]}"; do
        source_file="$stage/$path"
        [ -f "$source_file" ] && [ ! -L "$source_file" ] || l2_launch_die "staged file $path is missing or a symlink"
        if [[ $path == */* ]]; then
            install -d -m 0755 -o root -g root -- "$run/${path%/*}" || l2_launch_die "cannot create a folder for $path"
        fi
        install -m "$(l2_launch_mode "$path")" -o root -g root -- "$source_file" "$run/$path" || l2_launch_die "cannot copy $path"
    done
    install -m 0644 -o root -g root -- "$work/manifest.sha256" "$run/manifest.sha256" || l2_launch_die "cannot copy the manifest"

    # Verify the root-owned copies, not the staged files the user could still touch.
    (cd -- "$run" && sha256sum --check --strict --quiet manifest.sha256) || l2_launch_die "a copied file does not match the manifest"
    local found expected
    found=$(cd -- "$run" && find . -mindepth 1 -type f ! -name manifest.sha256 -printf '%P\n' | LC_ALL=C sort)
    expected=$(printf '%s\n' "${L2_LAUNCH_PATHS[@]}" | LC_ALL=C sort)
    [ "$found" = "$expected" ] || l2_launch_die "the run directory holds files the manifest does not list"

    rm -rf -- "$work"
    trap - EXIT
    exec /usr/bin/env -i PATH="$PATH" LC_ALL=C SUDO_UID="$uid" \
        /bin/bash "$run/guest/start.sh" "$run_id" "$run" "$manifest_hash"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    l2_launch_main "$@"
fi
