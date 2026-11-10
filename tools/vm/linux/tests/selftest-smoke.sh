#!/bin/bash
# Private temporary files and shell replacements only; never calls systemd.
set -eu
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
run_id=20261111T010203Z-0123abcd
run=$work/$run_id
mkdir -p "$run/guest"
cp "$here/../guest/"{launch,lib,start,run-smoke}.sh "$run/guest/"
boot=12345678-1234-4234-8234-123456789abc
vm=12345678-1234-4234-8234-123456789abd
# Identity probes are replaced only in this temporary package.
printf '\nsmoke_boot_id() { echo %s; }\nsmoke_vm_uuid() { echo %s; }\n' "$boot" "$vm" >>"$run/guest/run-smoke.sh"
cat >"$run/job.env" <<EOF
PROFILE=infra-smoke-v1
HOST_RUN_ID=python_run_1
RUN_ID=$run_id
VM_UUID=$vm
EXPECTED_BOOT_ID=$boot
JOB_ID=smoke
DELAY_SECONDS=1
EOF
(cd "$run"; sha256sum guest/*.sh job.env >manifest.sha256)
digest=$(sha256sum "$run/manifest.sha256" | cut -d' ' -f1)
. "$run/guest/start.sh"
BASE=$work
id() { [ "$1" = -u ] && echo 0; }
stat() { if [ "$2" = %u ]; then echo 0; else command stat "$@"; fi; }
systemd-run() { printf '%s\n' "$@" >"$work/unit-args"; }
l2_start_main "$run_id" "$run" "$digest"
grep -qx -- '--property=RuntimeMaxSec=45' "$work/unit-args"
grep -qx -- '--property=KillMode=control-group' "$work/unit-args"
# start refuses a second invocation even when no transient unit is running.
if (l2_start_main "$run_id" "$run" "$digest") 2>/dev/null; then exit 1; fi
rm -rf "$run/report"
if (l2_start_main "$run_id" "$run" "$(printf '%064d' 0)") 2>/dev/null; then exit 1; fi
. "$run/guest/lib.sh"
. "$run/guest/run-smoke.sh"
smoke_validate "$run" "$digest"
EXPECTED_BOOT_ID=foreign
smoke_boot_id() { echo foreign; }
if smoke_validate "$run" "$digest"; then exit 1; fi
. "$run/guest/launch.sh"
for bad in ../job.env guest/../start.sh guest/a/b.sh /etc/passwd; do
    if l2_launch_path_allowed "$bad"; then exit 1; fi
done
for path in "${SMOKE_START_REQUIRED[@]}"; do smoke_start_path_allowed "$path"; done
if smoke_start_path_allowed guest/run-l2.sh; then exit 1; fi
if l2_start_path_allowed guest/run-smoke.sh; then exit 1; fi

. "$run/guest/run-smoke.sh"
smoke_validate "$run" "$digest"
RUN=$run DIGEST=$digest
mkdir "$run/report"
sleep() { :; }
smoke_execute run
grep -q '"state":"succeeded"' "$run/report/smoke-terminal.json"
if (smoke_execute run) 2>/dev/null; then exit 1; fi
rm "$run/report/smoke-terminal.json"
SERVICE_RESULT=timeout smoke_execute finalize
grep -q '"state":"timeout"' "$run/report/smoke-terminal.json"
rm "$run/report/smoke-terminal.json"
SERVICE_RESULT=signal smoke_execute finalize
grep -q '"state":"error"' "$run/report/smoke-terminal.json"
rm -rf "$run/report"
mkdir "$run/report"
set +e
(set -e; sleep() { return 1; }; smoke_execute run)
failed_rc=$?
set -e
[ "$failed_rc" -ne 0 ]
grep -q '"state":"error"' "$run/report/smoke-terminal.json"
rm -rf "$run/report"

# Exercise the original launch entry in a subshell, redirecting all privileged
# operations into the temporary tree. exec is intercepted before start.sh.
stage=$work/home/rosetun-l2-stage/$run_id
mkdir -p "$stage"
chmod 700 "$stage"
cp -r "$run/guest" "$run/job.env" "$run/manifest.sha256" "$stage/"
fake_launch() (
    local fixture_root=$work
    SUDO_UID=0
    L2_LAUNCH_BASE=$work/base-$1
    L2_LAUNCH_INSTALLED=$(readlink -f "$here/../guest/launch.sh")
    getent() { printf 'root:x:0:0::%s:/bin/bash\n' "$fixture_root/home"; }
    install() {
        local args=()
        while [ $# -gt 0 ]; do
            case $1 in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac
        done
        command install "${args[@]}"
    }
    mktemp() { command mktemp -d "$fixture_root/launch.XXXXXX"; }
    exec() { printf 'intercepted\n' >"$fixture_root/exec"; }
    l2_launch_main "$run_id" "$stage" "$2"
)
fake_launch good "$digest"
[ -f "$work/exec" ]
if fake_launch good "$digest" 2>/dev/null; then exit 1; fi
if fake_launch bad "$(printf '%064d' 0)" 2>/dev/null; then exit 1; fi
mv "$stage/guest" "$stage/real-guest"
ln -s real-guest "$stage/guest"
if fake_launch symlink "$digest" 2>/dev/null; then exit 1; fi
printf 'selftest-smoke: PASS (offline only)\n'
