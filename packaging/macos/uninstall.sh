#!/bin/bash
# Removes the Rosetun macOS app, CLI, LaunchDaemon, bundled engines and runtime files.
# User settings in ~/.config/rosetun are never deleted.
#
# Usage:
#   sudo /usr/local/libexec/rosetun/uninstall.sh [--purge]
set -euo pipefail

LABEL='io.github.eoftgge.rosetun.helper'
PLIST="/Library/LaunchDaemons/$LABEL.plist"
PKG_ID='io.github.eoftgge.rosetun'

purge=false
while [ $# -gt 0 ]; do
    case $1 in
    --purge) purge=true ;;
    -h|--help)
        cat <<'USAGE'
Usage: sudo /usr/local/libexec/rosetun/uninstall.sh [--purge]

Stops the Rosetun LaunchDaemon and removes Rosetun.app, the CLI, bundled
engines, runtime socket and helper log. User settings in ~/.config/rosetun
are preserved.

  --purge   also remove helper state and downloaded lists in
            /Library/Application Support/Rosetun
USAGE
        exit 0
        ;;
    *)
        printf 'uninstall.sh: unknown argument %s\n' "$1" >&2
        exit 1
        ;;
    esac
    shift
done

if [ "$(id -u)" -ne 0 ]; then
    printf 'uninstall.sh: run with sudo: sudo %s\n' "$0" >&2
    exit 1
fi

if /bin/launchctl print "system/$LABEL" >/dev/null 2>&1; then
    /bin/launchctl bootout "system/$LABEL" >/dev/null 2>&1 ||
        /bin/launchctl bootout system "$PLIST" >/dev/null 2>&1 || true

    for _ in $(seq 1 20); do
        if ! /usr/bin/pgrep -x rosetun-helper-privileged >/dev/null 2>&1; then
            break
        fi
        /bin/sleep 0.5
    done
fi

/bin/rm -f -- "$PLIST"
/bin/rm -rf -- /Applications/Rosetun.app
/bin/rm -f -- /usr/local/bin/rosetun
/bin/rm -rf -- /usr/local/libexec/rosetun
/bin/rm -rf -- /private/var/run/rosetun
/bin/rm -f -- /private/var/log/rosetun-helper.log

if $purge; then
    /bin/rm -rf -- '/Library/Application Support/Rosetun'
fi

/usr/sbin/pkgutil --forget "$PKG_ID" >/dev/null 2>&1 || true

printf 'Rosetun has been removed.\n'
if ! $purge; then
    printf 'Helper state in /Library/Application Support/Rosetun was kept (use --purge to remove it).\n'
fi
printf 'User settings in ~/.config/rosetun were preserved.\n'
