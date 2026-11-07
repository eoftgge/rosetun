#!/bin/sh
set -eu
if ! /usr/lib/rosetun/rosetun-helper-privileged --reset-firewall; then
    echo 'rosetun: removal refused; cannot reset Lockdown. Run sudo rosetun reset-firewall and retry.' >&2
    exit 1
fi
