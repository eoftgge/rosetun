#!/bin/bash
# Privileged launcher of the Linux L2 stand. The owner runs it by hand with sudo
# after the host staged a run; nothing starts it implicitly.
#
#   start.sh RUN_ID STAGE_DIR MANIFEST_SHA256
#
# It copies the staged files into a root-owned run directory, proves the copies
# against the manifest whose hash the owner typed from the host's printout, and
# starts the autonomous test job as a transient systemd unit. The unit does not
# depend on the SSH session. This is stand infrastructure, not a Rosetun service.

set -u
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
umask 022

BASE=/var/lib/rosetun-l2

die() { printf 'start.sh: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run it with sudo"
[ $# -eq 3 ] || die "usage: start.sh RUN_ID STAGE_DIR MANIFEST_SHA256"
run_id=$1 stage=$2 manifest_hash=$3

[[ $run_id =~ ^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$ ]] || die "invalid run id"
[[ $manifest_hash =~ ^[0-9a-f]{64}$ ]] || die "invalid manifest hash"
[[ $stage == /* ]] && [[ $stage != *..* ]] || die "stage directory must be an absolute path without .."
[ -d "$stage" ] && [ ! -L "$stage" ] || die "stage directory is missing or a symlink"

# The staging directory is the login account's private folder. A directory that
# any other account can modify could swap files between the checks and the copy.
stage_owner=$(stat -c %u -- "$stage")
stage_mode=$(stat -c %a -- "$stage")
if [ "$stage_owner" != "${SUDO_UID-0}" ] && [ "$stage_owner" != 0 ]; then
    die "stage directory is owned by uid $stage_owner, not by the account that ran sudo"
fi
[ $((0$stage_mode & 077)) -eq 0 ] || die "stage directory mode $stage_mode lets other accounts in; use 0700"
[ -f "$stage/manifest.sha256" ] && [ ! -L "$stage/manifest.sha256" ] || die "manifest.sha256 is missing"

# Everything below works on a private copy, so the staged files cannot change under it.
work=$(mktemp -d /run/rosetun-l2-start.XXXXXX) || die "cannot create a private work directory"
trap 'rm -rf -- "$work"' EXIT
cp -- "$stage/manifest.sha256" "$work/manifest.sha256" || die "cannot read the manifest"
actual=$(sha256sum -- "$work/manifest.sha256" | cut -d' ' -f1)
[ "$actual" = "$manifest_hash" ] || die "manifest hash $actual is not the one the host printed"

allowed='^(guest/(lib|run-l2|start)\.sh|scenarios\.tsv|job\.env|artifacts/[A-Za-z0-9_.-]+)$'
paths=()
while IFS= read -r line; do
    [ -n "$line" ] || continue
    [[ $line =~ ^[0-9a-f]{64}\ \ (.+)$ ]] || die "malformed manifest line"
    path=${BASH_REMATCH[1]}
    [[ $path =~ $allowed ]] || die "manifest names a path the stand does not use: $path"
    paths+=("$path")
done <"$work/manifest.sha256"
[ "${#paths[@]}" -gt 0 ] || die "the manifest is empty"
for need in guest/lib.sh guest/run-l2.sh guest/start.sh scenarios.tsv job.env artifacts/l2_transport_fixture \
    artifacts/rosetun_helper_privileged_tests artifacts/rosetun_ipc_tests artifacts/provenance.json; do
    printf '%s\n' "${paths[@]}" | grep -qxF -- "$need" || die "the manifest lacks $need"
done

# This script must be the one the manifest describes.
self_hash=$(sha256sum -- "${BASH_SOURCE[0]}" | cut -d' ' -f1)
listed=$(grep -F "  guest/start.sh" "$work/manifest.sha256" | cut -d' ' -f1)
[ "$self_hash" = "$listed" ] || die "this launcher is not the guest/start.sh of the staged run; install it from the stage again"

# One stand run at a time, and only on a machine that has no Rosetun service.
if systemctl list-units --all --no-legend 'rosetun-l2-*' 2>/dev/null | grep -q 'running\|activating'; then
    die "another stand run is still active; wait for it or stop it from the Hyper-V console"
fi

if [ -e "$BASE" ] || [ -L "$BASE" ]; then
    [ -d "$BASE" ] && [ ! -L "$BASE" ] || die "$BASE is not a plain directory"
    [ "$(stat -c %u -- "$BASE")" -eq 0 ] && [ $((0$(stat -c %a -- "$BASE") & 022)) -eq 0 ] ||
        die "$BASE is not a root-owned directory without group or other write"
else
    install -d -m 0755 -o root -g root -- "$BASE" || die "cannot create $BASE"
fi

run="$BASE/$run_id"
[ ! -e "$run" ] && [ ! -L "$run" ] || die "$run already exists; a run id is used once"
install -d -m 0755 -o root -g root -- "$run" "$run/guest" "$run/artifacts" || die "cannot create $run"
install -d -m 0755 -o root -g root -- "$run/report" || die "cannot create the report directory"
install -d -m 0700 -o root -g root -- "$run/state" || die "cannot create the state directory"

for path in "${paths[@]}"; do
    source_file="$stage/$path"
    [ -f "$source_file" ] && [ ! -L "$source_file" ] || die "staged file $path is missing or a symlink"
    case $path in
        *.json | *.tsv | *.env) mode=0644 ;;
        *) mode=0755 ;;
    esac
    install -m "$mode" -o root -g root -- "$source_file" "$run/$path" || die "cannot copy $path"
done
install -m 0644 -o root -g root -- "$work/manifest.sha256" "$run/manifest.sha256" || die "cannot copy the manifest"

# Verify the root-owned copies, not the staged files the user could still touch.
(cd -- "$run" && sha256sum --check --strict --quiet manifest.sha256) || die "a copied file does not match the manifest"
found=$(cd -- "$run" && find guest artifacts scenarios.tsv job.env -type f | LC_ALL=C sort)
expected=$(printf '%s\n' "${paths[@]}" | LC_ALL=C sort)
[ "$found" = "$expected" ] || die "the run directory holds files the manifest does not list"

# The job description is only read through the strict reader in lib.sh.
. "$run/guest/lib.sh"
RUN_ID='' JOB_TIMEOUT_SECONDS=900
l2_read_env_file "$run/job.env" RUN_ID STAND_ID EXPECTED_BOOT_ID USER_A USER_B BIOS_GUID \
    SCENARIO_TIMEOUT_SECONDS UNIT_TIMEOUT_SECONDS JOB_TIMEOUT_SECONDS || die "job.env is not valid"
[ "$RUN_ID" = "$run_id" ] || die "job.env belongs to another run"
[[ $JOB_TIMEOUT_SECONDS =~ ^[0-9]{2,5}$ ]] || die "invalid job time limit"

unit="rosetun-l2-$run_id"
systemd-run --quiet --collect --unit="$unit" \
    --description="Rosetun Linux L2 stand run $run_id (test infrastructure)" \
    --property=KillMode=control-group \
    --property=TimeoutStopSec=30 \
    --property=RuntimeMaxSec="$JOB_TIMEOUT_SECONDS" \
    --property=ExecStopPost="/bin/bash $run/guest/run-l2.sh finalize $run" \
    /bin/bash "$run/guest/run-l2.sh" run "$run" || die "systemd-run failed"

printf 'started %s.service\nrun directory: %s\nreport:        %s/report/report.json\n' "$unit" "$run" "$run"
printf 'The job runs without this session. Check it from the host with -Collect.\n'
