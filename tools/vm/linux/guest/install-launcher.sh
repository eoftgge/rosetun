#!/bin/bash
# One-time setup of the Linux L2 stand's launcher in the guest, before the clean
# checkpoint. The owner runs it by hand, as the SSH account, with sudo:
#
#   sudo bash install-launcher.sh USER_A USER_B     install or refresh
#   sudo bash install-launcher.sh --remove          remove both files
#
# It installs launch.sh from the same folder as a root-owned
# /usr/local/libexec/rosetun-l2/launch and adds /etc/sudoers.d/rosetun-l2 with one
# rule: the account that ran sudo may run that one path as root without a password.
# USER_A and USER_B are the stand's test accounts; they never get the rule.
#
# Whoever holds that account's SSH key gets root in this guest through the rule.
# That is accepted for a disposable stand VM only.

set -u
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
umask 022

L2_LAUNCHER_DIR=/usr/local/libexec/rosetun-l2
L2_LAUNCHER=$L2_LAUNCHER_DIR/launch
L2_SUDOERS=/etc/sudoers.d/rosetun-l2

l2_install_die() {
    printf 'install-launcher.sh: %s\n' "$1" >&2
    exit 1
}

# The single sudoers line: one account, root only, one absolute path, no arguments
# pattern and never ALL.
l2_sudoers_line() {
    printf '%s ALL=(root) NOPASSWD: %s\n' "$1" "$2"
}

# l2_check_sudo_user NAME UID USER_A USER_B: the account that may get the rule.
l2_check_sudo_user() {
    local name=$1 uid=$2 user_a=$3 user_b=$4
    [ -n "$name" ] || { L2_INSTALL_ERROR="SUDO_USER is empty; run it with sudo from the SSH account"; return 1; }
    [[ $name =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || { L2_INSTALL_ERROR="SUDO_USER '$name' is not an ordinary account name"; return 1; }
    [ "$name" != root ] && [ "$uid" != 0 ] || { L2_INSTALL_ERROR="the rule is never given to root; run it with sudo from the SSH account"; return 1; }
    [ "$name" != "$user_a" ] && [ "$name" != "$user_b" ] ||
        { L2_INSTALL_ERROR="$name is a test account of the stand; the rule belongs to the SSH account"; return 1; }
    return 0
}

l2_install_remove() {
    rm -f -- "$L2_SUDOERS" || l2_install_die "cannot remove $L2_SUDOERS"
    rm -f -- "$L2_LAUNCHER" || l2_install_die "cannot remove $L2_LAUNCHER"
    if [ -d "$L2_LAUNCHER_DIR" ] && [ -z "$(ls -A -- "$L2_LAUNCHER_DIR")" ]; then rmdir -- "$L2_LAUNCHER_DIR"; fi
    printf 'removed %s and %s\n' "$L2_SUDOERS" "$L2_LAUNCHER"
}

l2_install_main() {
    [ "$(id -u)" -eq 0 ] || l2_install_die "run it with sudo"
    if [ $# -eq 1 ] && [ "$1" = --remove ]; then
        l2_install_remove
        return
    fi
    [ $# -eq 2 ] || l2_install_die "usage: install-launcher.sh USER_A USER_B | --remove"
    local user_a=$1 user_b=$2
    [[ $user_a =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] && [[ $user_b =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || l2_install_die "invalid test account names"
    l2_check_sudo_user "${SUDO_USER-}" "${SUDO_UID-}" "$user_a" "$user_b" || l2_install_die "$L2_INSTALL_ERROR"
    local user=$SUDO_USER
    [ "$(id -u -- "$user" 2>/dev/null)" = "$SUDO_UID" ] || l2_install_die "SUDO_USER and SUDO_UID do not name the same account"
    command -v visudo >/dev/null || l2_install_die "visudo is missing (sudo package)"

    local here source_file
    here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) || l2_install_die "cannot find my folder"
    source_file=$here/launch.sh
    [ -f "$source_file" ] && [ ! -L "$source_file" ] || l2_install_die "launch.sh is missing next to install-launcher.sh"

    local parent=${L2_LAUNCHER_DIR%/*}
    # Debian does not ship /usr/local/libexec.
    [ -e "$parent" ] || [ -L "$parent" ] || install -d -m 0755 -o root -g root -- "$parent" || l2_install_die "cannot create $parent"
    [ -d "$parent" ] && [ ! -L "$parent" ] && [ "$(stat -c %u -- "$parent")" -eq 0 ] &&
        [ $((0$(stat -c %a -- "$parent") & 022)) -eq 0 ] || l2_install_die "$parent is not a root-owned directory without group or other write"
    if [ -e "$L2_LAUNCHER_DIR" ] || [ -L "$L2_LAUNCHER_DIR" ]; then
        [ -d "$L2_LAUNCHER_DIR" ] && [ ! -L "$L2_LAUNCHER_DIR" ] || l2_install_die "$L2_LAUNCHER_DIR is not a plain directory"
    fi
    install -d -m 0755 -o root -g root -- "$L2_LAUNCHER_DIR" || l2_install_die "cannot create $L2_LAUNCHER_DIR"
    chown root:root -- "$L2_LAUNCHER_DIR" && chmod 0755 -- "$L2_LAUNCHER_DIR" || l2_install_die "cannot set the mode of $L2_LAUNCHER_DIR"

    # Both files are written beside their target and renamed into place, so sudo
    # never reads a half-written rule (it skips names with a dot).
    local tmp
    tmp=$(mktemp "$L2_LAUNCHER_DIR/.launch.XXXXXX") || l2_install_die "cannot create a temporary file"
    install -m 0755 -o root -g root -- "$source_file" "$tmp" && mv -f -- "$tmp" "$L2_LAUNCHER" ||
        { rm -f -- "$tmp"; l2_install_die "cannot install $L2_LAUNCHER"; }

    tmp=$(mktemp /etc/sudoers.d/.rosetun-l2.XXXXXX) || l2_install_die "cannot create a temporary sudoers file"
    l2_sudoers_line "$user" "$L2_LAUNCHER" >"$tmp" && chown root:root -- "$tmp" && chmod 0440 -- "$tmp" ||
        { rm -f -- "$tmp"; l2_install_die "cannot write the sudoers rule"; }
    visudo -cqf "$tmp" >/dev/null || { rm -f -- "$tmp"; l2_install_die "visudo rejected the rule; nothing was changed"; }
    mv -f -- "$tmp" "$L2_SUDOERS" || { rm -f -- "$tmp"; l2_install_die "cannot install $L2_SUDOERS"; }

    printf 'installed %s\n  sha256 %s\n' "$L2_LAUNCHER" "$(sha256sum -- "$L2_LAUNCHER" | cut -d' ' -f1)"
    printf 'installed %s:\n  %s' "$L2_SUDOERS" "$(cat -- "$L2_SUDOERS")"
    printf 'Make the clean checkpoint again after this step.\n'
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    l2_install_main "$@"
fi
