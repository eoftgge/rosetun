#!/bin/sh
# What CI checks on every push: the messages of the commits in FROM..TO and the
# lines they add (no long dashes in Fluent files, no real proxy hosts).
#   sh tools/hooks/check-range.sh origin/dev HEAD
. "$(dirname "$0")/lib.sh"

from=$1
to=$2
status=0
rosetun_check_commits "$from..$to" || status=1
problems=$(git diff -U0 --no-color --no-ext-diff --diff-filter=ACMR "$from" "$to" |
    rosetun_added_line_problems)
if [ -n "$problems" ]; then
    printf '%s\n' "$problems" >&2
    status=1
fi
exit "$status"
