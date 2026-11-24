#!/bin/bash
# The smoke job of the controller's planned guest reboot, as root: no Rosetun service, no network
# change. Phase one runs from the transient unit start.sh made. It records the boot, enables a unit
# of its own that continues the job (rosetun-l2-resume.service, the pattern of run-l4.sh), and
# reboots the guest once. After the boot that unit finishes the job and closes the report, which
# lists both boot IDs.
#
#   run-reboot-smoke.sh run RUN_DIR        phase one: preflight, resume unit, reboot
#   run-reboot-smoke.sh resume RUN_DIR     after the reboot (rosetun-l2-resume.service)
#   run-reboot-smoke.sh finalize RUN_DIR   clean up and close the report if a phase never got to
#                                          (ExecStopPost, or the end of the last phase)

set -u
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
umask 022

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=lib.sh
. "$here/lib.sh"

mode=${1-}
RUN=${2-}
case $mode in run | resume | finalize) ;; *) echo "usage: run-reboot-smoke.sh run|resume|finalize RUN_DIR" >&2; exit 64 ;; esac
[ -d "$RUN" ] || { echo "run directory $RUN is missing" >&2; exit 64; }
RUN=$(cd -- "$RUN" && pwd -P)

STATE=$RUN/state
REPORT=$RUN/report
SCENARIOS=$RUN/scenarios-reboot-smoke.tsv
RESULTS=$STATE/results.jsonl
RESUME_UNIT=rosetun-l2-resume.service
STAND_UNIT_DIR=/etc/systemd/system

RUN_ID='' STAND_ID='' EXPECTED_BOOT_ID='' USER_A='' USER_B='' BIOS_GUID=''
SCENARIO_TIMEOUT_SECONDS=30 UNIT_TIMEOUT_SECONDS=180 JOB_TIMEOUT_SECONDS=900
EXPECTED_ARCH=x86_64

boot_id() { cat /proc/sys/kernel/random/boot_id; }

write_status() {
    printf '{"run_id":%s,"state":%s,"current":%s,"updated":%s,"boot_id":%s}\n' \
        "$(l2_json_string "$RUN_ID")" "$(l2_json_string "$1")" "$(l2_json_string "${2-}")" \
        "$(l2_json_string "$(l2_now_utc)")" "$(l2_json_string "$(boot_id)")" |
        l2_atomic_write "$REPORT/status.json" 0644
}

# record ID RESULT REASON START_MS
record() {
    local id=$1 result=$2 reason=$3 started=$4 evidence group title
    evidence=$(awk -F'\t' -v id="$id" '$1 == id { print $3 }' "$SCENARIOS")
    group=$(awk -F'\t' -v id="$id" '$1 == id { print $4 }' "$SCENARIOS")
    title=$(awk -F'\t' -v id="$id" '$1 == id { print $6 }' "$SCENARIOS")
    l2_append_line "$RESULTS" "$(printf '{"id":%s,"group":%s,"evidence":%s,"expectation":%s,"result":%s,"reason":%s,"duration_ms":%s}' \
        "$(l2_json_string "$id")" "$(l2_json_string "$group")" "$(l2_json_string "$evidence")" \
        "$(l2_json_string "$title")" "$(l2_json_string "$result")" \
        "$(l2_json_string "$reason")" "$(($(l2_now_ms) - started))")"
    write_status running "$id"
}

fail_reason=''
# check ID NOTE CONDITION...: PASS when the condition holds.
check() {
    local id=$1 note=$2 started
    shift 2
    started=$(l2_now_ms)
    write_status running "$id"
    if "$@"; then
        record "$id" PASS "$note" "$started"
    else
        record "$id" FAIL "${fail_reason:-the condition did not hold}" "$started"
    fi
    fail_reason=''
}

# ---------------------------------------------------------------- phases

identity_holds() {
    local bios
    [ "$(boot_id)" = "$EXPECTED_BOOT_ID" ] || { fail_reason="boot id changed since the host connected"; return 1; }
    [ "$(uname -m)" = "$EXPECTED_ARCH" ] || { fail_reason="architecture is not $EXPECTED_ARCH"; return 1; }
    [ -d /run/systemd/system ] || { fail_reason="systemd is not the running init"; return 1; }
    [ "$(cat "$L2_STAND_ID_FILE" 2>/dev/null)" = "$STAND_ID" ] || { fail_reason="the stand id file does not match"; return 1; }
    bios=$(tr 'A-F' 'a-f' </sys/class/dmi/id/product_uuid 2>/dev/null)
    if [ "$bios" != "${BIOS_GUID,,}" ] && [ "$bios" != "$(l2_guid_swap "$BIOS_GUID")" ]; then
        fail_reason="the guest BIOS GUID does not belong to the selected VM"
        return 1
    fi
}

stand_unit() {
    cat >"$STAND_UNIT_DIR/$RESUME_UNIT" <<EOF
# Rosetun Linux reboot smoke (test infrastructure): the job after its one reboot.
[Unit]
Description=Rosetun Linux reboot smoke: after a reboot (test infrastructure)

[Service]
Type=exec
KillMode=control-group
TimeoutStopSec=120
RuntimeMaxSec=$JOB_TIMEOUT_SECONDS
ExecStart=/bin/bash $RUN/guest/run-reboot-smoke.sh resume $RUN
ExecStopPost=/bin/bash $RUN/guest/run-reboot-smoke.sh finalize $RUN

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$STAND_UNIT_DIR/$RESUME_UNIT"
}

reboot_now() {
    local phase=$1
    printf '%s\n' "$phase" >"$STATE/phase"
    : >"$STATE/rebooting"
    stand_unit && : >"$STATE/stand-units" && systemctl daemon-reload && systemctl enable --quiet "$RESUME_UNIT" || return 1
    write_status rebooting "$phase"
    sync
    systemctl --no-block reboot
}

phase_one() {
    check preflight.identity "stand id, boot id, $EXPECTED_ARCH, systemd and BIOS GUID agree" identity_holds
    if grep -q '"id":"preflight.identity".*"result":"PASS"' "$RESULTS"; then
        reboot_now reboot-1 || {
            rm -f -- "$STATE/rebooting"
            record reboot.planned ERROR "the resume unit could not be installed or the reboot not requested" "$(l2_now_ms)"
        }
    fi
}

second_boot() {
    local first second
    first=$(sed -n 1p "$STATE/boot-ids")
    second=$(sed -n 2p "$STATE/boot-ids")
    [ "$(wc -l <"$STATE/boot-ids" | tr -d '[:space:]')" = 2 ] || { fail_reason="the job saw other than two boots"; return 1; }
    [ "$first" = "$EXPECTED_BOOT_ID" ] || { fail_reason="the first boot is not the one the host connected to"; return 1; }
    [ "$second" = "$(boot_id)" ] && [ "$second" != "$first" ] || { fail_reason="the boot ID did not change"; return 1; }
}

carried_on() {
    [ "$(cat "$STATE/phase" 2>/dev/null)" = reboot-1 ] || { fail_reason="no phase was saved before the reboot"; return 1; }
    systemctl is-active --quiet "$RESUME_UNIT" || { fail_reason="$RESUME_UNIT is not what runs this phase"; return 1; }
}

phase_resume() {
    rm -f -- "$STATE/rebooting"
    l2_append_line "$STATE/boot-ids" "$(boot_id)"
    write_status running reboot-1
    check reboot.planned "the second boot has another boot ID than the first" second_boot
    check reboot.continued "the stand's own unit ran the job after the reboot" carried_on
}

# ---------------------------------------------------------------- cleanup and report

cleanup() {
    L2_CLEANUP_STATUS=PASS L2_CLEANUP_ACTIONS='' L2_CLEANUP_PROBLEMS=''
    if [ -f "$STATE/stand-units" ]; then
        systemctl disable --quiet "$RESUME_UNIT" 2>/dev/null
        if rm -f -- "$STAND_UNIT_DIR/$RESUME_UNIT" && rm -f -- "$STATE/stand-units"; then
            L2_CLEANUP_ACTIONS="removed the stand's boot unit"
        else
            L2_CLEANUP_PROBLEMS="could not remove $RESUME_UNIT"
            L2_CLEANUP_STATUS=ERROR
        fi
        systemctl daemon-reload
    fi
}

boot_ids_json() {
    local ids='' id
    while IFS= read -r id; do
        [[ $id =~ ^[0-9a-f-]{36}$ ]] || continue
        ids="$ids${ids:+,}$(l2_json_string "$id")"
    done <"$STATE/boot-ids"
    printf '[%s]' "$ids"
}

finalize() {
    exec 8>"$STATE/finalize.lock"
    flock 8
    [ -f "$REPORT/report.json" ] && return 0
    # The planned reboot: the next phase goes on after it.
    [ -f "$STATE/rebooting" ] && return 0
    local started_cleanup
    started_cleanup=$(l2_now_ms)
    cleanup
    local cleanup_ms=$(($(l2_now_ms) - started_cleanup))

    local id required
    while IFS=$'\t' read -r id required _; do
        [ "$id" = id ] && continue
        [ "$required" = yes ] || continue
        grep -q "\"id\":\"$id\"" "$RESULTS" 2>/dev/null ||
            record "$id" ERROR "no result was recorded; the job ended early" "$(l2_now_ms)"
    done <"$SCENARIOS"

    local pass fail err skip total overall coverage lines='' line
    pass=$(grep -c '"result":"PASS"' "$RESULTS" 2>/dev/null)
    fail=$(grep -c '"result":"FAIL"' "$RESULTS" 2>/dev/null)
    err=$(grep -c '"result":"ERROR"' "$RESULTS" 2>/dev/null)
    skip=$(grep -c '"result":"SKIP"' "$RESULTS" 2>/dev/null)
    total=$((pass + fail + err + skip))
    if [ "$err" -gt 0 ] || [ "$L2_CLEANUP_STATUS" != PASS ] || [ -f "$STATE/aborted" ]; then
        overall=ERROR
    elif [ "$fail" -gt 0 ]; then
        overall=FAIL
    else
        overall=PASS
    fi
    if [ "$overall" != PASS ]; then coverage=none
    elif [ "$skip" -gt 0 ]; then coverage=partial
    else coverage=complete; fi
    while IFS= read -r line; do
        lines="$lines${lines:+,}$line"
    done <"$RESULTS"
    {
        printf '{"schema":1,"run_id":%s,"finished":%s,' "$(l2_json_string "$RUN_ID")" "$(l2_json_string "$(l2_now_utc)")"
        printf '"guest":{"os":%s,"kernel":%s,"arch":%s,"systemd":%s,"boot_id":%s,"boot_id_at_end":%s,"boot_ids":%s},' \
            "$(l2_json_string "$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME-unknown}")")" \
            "$(l2_json_string "$(uname -r)")" "$(l2_json_string "$(uname -m)")" \
            "$(l2_json_string "$(systemctl --version 2>/dev/null | head -n 1)")" \
            "$(l2_json_string "$EXPECTED_BOOT_ID")" "$(l2_json_string "$(boot_id)")" "$(boot_ids_json)"
        printf '"summary":{"overall":%s,"coverage":%s,"pass":%s,"fail":%s,"error":%s,"skip":%s,"total":%s},' \
            "$(l2_json_string "$overall")" "$(l2_json_string "$coverage")" "$pass" "$fail" "$err" "$skip" "$total"
        printf '"cleanup":{"status":%s,"actions":%s,"problems":%s,"duration_ms":%s},' \
            "$(l2_json_string "$L2_CLEANUP_STATUS")" "$(l2_json_string "$L2_CLEANUP_ACTIONS")" \
            "$(l2_json_string "$L2_CLEANUP_PROBLEMS")" "$cleanup_ms"
        printf '"scenarios":[%s]}\n' "$lines"
    } | l2_atomic_write "$REPORT/report.json" 0644
    write_status finished
}

# ---------------------------------------------------------------- main

load_job() {
    l2_read_env_file "$RUN/job.env" RUN_ID STAND_ID EXPECTED_BOOT_ID USER_A USER_B BIOS_GUID \
        SCENARIO_TIMEOUT_SECONDS UNIT_TIMEOUT_SECONDS JOB_TIMEOUT_SECONDS || return 1
    l2_valid_run_id "$RUN_ID" || { echo "invalid run id" >&2; return 1; }
    [ "$(basename -- "$RUN")" = "$RUN_ID" ] || { echo "run directory does not match the run id" >&2; return 1; }
    [[ $JOB_TIMEOUT_SECONDS =~ ^[0-9]{2,5}$ ]] || { echo "invalid job time limit" >&2; return 1; }
}

load_job || exit 65
mkdir -p "$STATE" "$REPORT"
: >>"$RESULTS"

if [ "$mode" = finalize ]; then
    [ -f "$REPORT/report.json" ] || [ -f "$STATE/rebooting" ] || : >"$STATE/aborted"
    finalize
    exit 0
fi

trap 'finalize' EXIT
# A planned reboot stops this unit too: that is no abort.
trap '[ -f "$STATE/rebooting" ] || : >"$STATE/aborted"; exit 143' TERM INT
if [ "$mode" = run ]; then
    write_status running preflight
    l2_append_line "$STATE/boot-ids" "$(boot_id)"
    phase_one
else
    phase_resume
fi
exit 0
