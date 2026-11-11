#!/bin/bash
# Runs the Linux L2 scenarios inside the guest, as root, from a systemd transient
# unit started by start.sh. It never depends on the SSH session that started it.
#
#   run-l2.sh run RUN_DIR        run every scenario, then clean up and write the report
#   run-l2.sh finalize RUN_DIR   clean up and close the report if `run` never got to
#                                (ExecStopPost of the unit: the job was killed or timed out)
#
# Only the transport fixture and the unprivileged unit test binaries of the run
# directory are executed. No service, engine, firewall or network change is made.

set -u
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
umask 022

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=lib.sh
. "$here/lib.sh"

mode=${1-}
RUN=${2-}
case $mode in run | finalize) ;; *) echo "usage: run-l2.sh run|finalize RUN_DIR" >&2; exit 64 ;; esac
[ -d "$RUN" ] || { echo "run directory $RUN is missing" >&2; exit 64; }
RUN=$(cd -- "$RUN" && pwd -P)

STATE=$RUN/state
REPORT=$RUN/report
ART=$RUN/artifacts
SCENARIOS=$RUN/scenarios.tsv
FIX=$ART/l2_transport_fixture
EP_DIR=$L2_ENDPOINT_DIR
EP=$EP_DIR/helper.sock
RESULTS=$STATE/results.jsonl

RUN_ID='' STAND_ID='' EXPECTED_BOOT_ID='' USER_A='' USER_B='' BIOS_GUID=''
SCENARIO_TIMEOUT_SECONDS=30 UNIT_TIMEOUT_SECONDS=180 JOB_TIMEOUT_SECONDS=900
EXPECTED_ARCH=x86_64

write_status() {
    # write_status STATE [CURRENT]: state is running | finished; never says passed.
    printf '{"run_id":%s,"state":%s,"current":%s,"updated":%s,"boot_id":%s}\n' \
        "$(l2_json_string "$RUN_ID")" "$(l2_json_string "$1")" "$(l2_json_string "${2-}")" \
        "$(l2_json_string "$(l2_now_utc)")" "$(l2_json_string "$(cat /proc/sys/kernel/random/boot_id)")" |
        l2_atomic_write "$REPORT/status.json" 0644
}

# record ID RESULT EXPECTATION REASON START_MS
record() {
    local id=$1 result=$2 expectation=$3 reason=$4 started=$5 evidence group
    evidence=$(awk -F'\t' -v id="$id" '$1 == id { print $3 }' "$SCENARIOS")
    group=$(awk -F'\t' -v id="$id" '$1 == id { print $4 }' "$SCENARIOS")
    l2_append_line "$RESULTS" "$(printf '{"id":%s,"group":%s,"evidence":%s,"expectation":%s,"result":%s,"reason":%s,"duration_ms":%s}' \
        "$(l2_json_string "$id")" "$(l2_json_string "$group")" "$(l2_json_string "$evidence")" \
        "$(l2_json_string "$expectation")" "$(l2_json_string "$result")" \
        "$(l2_json_string "$reason")" "$(($(l2_now_ms) - started))")"
    write_status running "$id"
}

# Each check is `check ID ... -- CONDITION`: PASS when the condition holds.
# `fail_reason` is filled by the condition when it can say why it failed.
fail_reason=''
check() {
    local id=$1 started=$2 expectation=$3 pass_note=$4
    shift 4
    # fail_reason may be preset by the caller; the condition may refine it.
    if "$@"; then
        record "$id" PASS "$expectation" "$pass_note" "$started"
    else
        record "$id" FAIL "$expectation" "${fail_reason:-the condition did not hold}" "$started"
    fi
    fail_reason=''
}

title_of() { awk -F'\t' -v id="$1" '$1 == id { print $6 }' "$SCENARIOS"; }

uid_of() { id -u -- "$1"; }
gid_of() { id -g -- "$1"; }

# as_user USER COMMAND...: the command as that account, with its own groups and a
# clean environment, from a directory it can use. Never grants anything extra.
as_user() {
    local user=$1
    shift
    setpriv --reuid="$(uid_of "$user")" --regid="$(gid_of "$user")" --init-groups --reset-env -- "$@"
}

user_run() {
    local seconds=$1 user=$2
    shift 2
    L2_OUT=$(cd "$RUN/work-$user" && timeout --kill-after=3 "$seconds" setpriv --reuid="$(uid_of "$user")" \
        --regid="$(gid_of "$user")" --init-groups --reset-env -- "$@" 2>&1 </dev/null)
    L2_RC=$?
}

# start_bg LABEL OUTFILE EXPECTED_EXE COMMAND...: starts a background process and
# sets BG_PID. The process is recorded only after it has exec'd EXPECTED_EXE: until
# then /proc shows the forked shell, and a record made at that moment would never
# match the real process again. A crashed run can then clean exactly this process.
start_bg() {
    local label=$1 out=$2 expected=$3 deadline=$((SECONDS + 5))
    shift 3
    "$@" >"$out" 2>&1 </dev/null &
    BG_PID=$!
    while [ "$(readlink "/proc/$BG_PID/exe" 2>/dev/null)" != "$expected" ]; do
        if [ "$SECONDS" -ge "$deadline" ] || ! kill -0 "$BG_PID" 2>/dev/null; then
            return 1
        fi
        sleep 0.05
    done
    l2_record_process "$STATE" "$label" "$BG_PID"
}

wait_for_text() {
    local file=$1 text=$2 pid=$3 seconds=$4 deadline=$((SECONDS + $4))
    while [ "$SECONDS" -lt "$deadline" ]; do
        grep -q -F -- "$text" "$file" 2>/dev/null && return 0
        kill -0 "$pid" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}

# wait_exit PID SECONDS: sets WAIT_RC to the exit code, or fails on timeout.
wait_exit() {
    local pid=$1 deadline=$((SECONDS + $2))
    while kill -0 "$pid" 2>/dev/null; do
        [ "$SECONDS" -lt "$deadline" ] || return 1
        sleep 0.1
    done
    wait "$pid"
    WAIT_RC=$?
}

socket_stat() { stat -c '%U:%G %a %F' -- "$1" 2>/dev/null; }
inode_of() { stat -c '%d:%i' -- "$1" 2>/dev/null; }

# ---------------------------------------------------------------- preflight

scenario_preflight() {
    local started
    started=$(l2_now_ms)

    local boot_now arch os kernel
    boot_now=$(cat /proc/sys/kernel/random/boot_id)
    arch=$(uname -m)
    os=$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME-unknown}")
    kernel=$(uname -r)
    pre_identity() {
        local stand bios=''
        stand=$(cat "$L2_STAND_ID_FILE" 2>/dev/null)
        [ -n "$stand" ] && [ "$stand" = "$STAND_ID" ] || { fail_reason="stand id file $L2_STAND_ID_FILE does not match the requested stand"; return 1; }
        [ "$boot_now" = "$EXPECTED_BOOT_ID" ] || { fail_reason="boot id changed since the host connected; the guest restarted"; return 1; }
        [ "$arch" = "$EXPECTED_ARCH" ] || { fail_reason="architecture is $arch, not $EXPECTED_ARCH"; return 1; }
        [ -d /run/systemd/system ] || { fail_reason="systemd is not the running init"; return 1; }
        [ -n "$BIOS_GUID" ] || { fail_reason="the job carries no BIOS GUID of the selected VM"; return 1; }
        bios=$(tr 'A-F' 'a-f' </sys/class/dmi/id/product_uuid 2>/dev/null)
        [ -n "$bios" ] || { fail_reason="product_uuid is unreadable"; return 1; }
        if [ "$bios" != "${BIOS_GUID,,}" ] && [ "$bios" != "$(l2_guid_swap "$BIOS_GUID")" ]; then
            fail_reason="the guest BIOS GUID does not belong to the selected VM"
            return 1
        fi
    }
    check preflight.identity "$started" "$(title_of preflight.identity)" "stand id, boot id, $arch, systemd and BIOS GUID agree" pre_identity

    started=$(l2_now_ms)
    pre_accounts() {
        local gid ua ub group
        getent group rosetun >/dev/null || { fail_reason="group rosetun does not exist"; return 1; }
        [ -n "$USER_A" ] && [ -n "$USER_B" ] && [ "$USER_A" != "$USER_B" ] || { fail_reason="two different test accounts are required"; return 1; }
        ua=$(uid_of "$USER_A") && ub=$(uid_of "$USER_B") || { fail_reason="a test account does not exist"; return 1; }
        [ "$ua" != "$ub" ] && [ "$ua" -ne 0 ] && [ "$ub" -ne 0 ] || { fail_reason="test accounts need distinct non-zero UIDs"; return 1; }
        for group in "$USER_A" "$USER_B"; do
            id -nG -- "$group" | tr ' ' '\n' | grep -qx rosetun || { fail_reason="$group is not in group rosetun"; return 1; }
            if id -nG -- "$group" | tr ' ' '\n' | grep -qxE 'sudo|wheel|admin|root'; then
                fail_reason="$group belongs to an administrator group"
                return 1
            fi
        done
        gid=$(getent group rosetun | cut -d: -f3)
        [ "$gid" -ne 0 ] || { fail_reason="group rosetun has GID 0"; return 1; }
    }
    check preflight.accounts "$started" "$(title_of preflight.accounts)" "uids $(uid_of "$USER_A" 2>/dev/null) and $(uid_of "$USER_B" 2>/dev/null) are ordinary members of rosetun" pre_accounts

    started=$(l2_now_ms)
    pre_service() {
        local found=''
        if systemctl list-units --all --no-legend 'rosetun*' 2>/dev/null | grep -v "rosetun-l2-" | grep -q .; then
            found="a rosetun systemd unit is present"
        fi
        if pgrep -x rosetun-helper-privileged >/dev/null 2>&1; then
            found="a rosetun-helper-privileged process is running"
        fi
        if pgrep -f l2_transport_fixture >/dev/null 2>&1; then
            found="an l2_transport_fixture process already runs"
        fi
        [ -z "$found" ] || { fail_reason="$found; the stand does not stop foreign services, stop it yourself"; return 1; }
    }
    check preflight.no-foreign-service "$started" "$(title_of preflight.no-foreign-service)" "no Rosetun unit or helper process" pre_service

    started=$(l2_now_ms)
    pre_endpoint() {
        if [ -e "$EP_DIR" ] || [ -L "$EP_DIR" ]; then
            fail_reason="$EP_DIR already exists; inspect it, the stand will not touch it"
            return 1
        fi
        printf 'ENDPOINT_PREEXISTING=no\n' >"$STATE/endpoint.env"
    }
    check preflight.endpoint-free "$started" "$(title_of preflight.endpoint-free)" "$EP_DIR is absent" pre_endpoint

    GUEST_OS=$os GUEST_KERNEL=$kernel GUEST_ARCH=$arch
    # shellcheck disable=SC2034
    GUEST_BOOT_ID=$boot_now
    local acct work
    for acct in "$USER_A" "$USER_B"; do
        work=$RUN/work-$acct
        [ -d "$work" ] || install -d -m 0700 -o "$(uid_of "$acct" 2>/dev/null)" -g "$(gid_of "$acct" 2>/dev/null)" "$work" 2>/dev/null
    done
}

preflight_ok() {
    for id in preflight.identity preflight.accounts preflight.no-foreign-service preflight.endpoint-free; do
        grep -q "\"id\":\"$id\".*\"result\":\"PASS\"" "$RESULTS" || return 1
    done
}

skip_rest() {
    # skip_rest REASON: required scenarios that could not run get an ERROR, never a PASS.
    local reason=$1 id required
    while IFS=$'\t' read -r id required _; do
        [ "$id" = id ] && continue
        grep -q "\"id\":\"$id\"" "$RESULTS" 2>/dev/null && continue
        [ "$id" = missing-group.refusal ] && continue
        record "$id" ERROR "$(title_of "$id")" "not run: $reason" "$(l2_now_ms)"
    done <"$SCENARIOS"
}

# ---------------------------------------------------------------- credentials

parse_auth() {
    # parse_auth TEXT: prints "uid admin" from the fixture's Hello answer.
    local text=$1
    [[ $text =~ authenticated\ uid=([0-9]+)\ admin=(true|false) ]] || return 1
    printf '%s %s' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
}

scenario_credentials() {
    local started out=$STATE/serve-credentials.out ua ub
    ua=$(uid_of "$USER_A")
    ub=$(uid_of "$USER_B")
    started=$(l2_now_ms)
    start_bg fixture-credentials "$out" "$FIX" "$FIX" serve 5 || {
        for id in credentials.endpoint-directory credentials.socket-mode credentials.owner-uid credentials.spoofed-hello \
            credentials.endpoint-env-ignored credentials.other-uid credentials.root-uid credentials.clean-exit; do
            record "$id" ERROR "$(title_of "$id")" "could not start or record the fixture server" "$started"
        done
        return
    }
    local pid=$BG_PID
    if ! wait_for_text "$out" "fixture listening" "$pid" 15 || [ ! -S "$EP" ]; then
        for id in credentials.endpoint-directory credentials.socket-mode credentials.owner-uid credentials.spoofed-hello \
            credentials.endpoint-env-ignored credentials.other-uid credentials.root-uid credentials.clean-exit; do
            record "$id" ERROR "$(title_of "$id")" "the fixture server did not start: $(l2_sanitize "$(head -c 300 "$out")")" "$started"
        done
        return
    fi
    l2_record_object "$STATE" endpoint-dir "$EP_DIR"
    l2_record_object "$STATE" endpoint-socket "$EP"

    started=$(l2_now_ms)
    dir_ok() {
        local line
        line=$(socket_stat "$EP_DIR")
        [[ $line == root:* ]] || { fail_reason="directory is $line"; return 1; }
        [ $(( 0$(stat -c %a -- "$EP_DIR") & 022 )) -eq 0 ] || { fail_reason="directory mode allows group or other write: $line"; return 1; }
    }
    check credentials.endpoint-directory "$started" "$(title_of credentials.endpoint-directory)" "$(socket_stat "$EP_DIR")" dir_ok

    started=$(l2_now_ms)
    mode_ok() {
        local line
        line=$(socket_stat "$EP")
        [ "$line" = "root:rosetun 660 socket" ] || { fail_reason="socket is $line"; return 1; }
    }
    check credentials.socket-mode "$started" "$(title_of credentials.socket-mode)" "root:rosetun 660 socket" mode_ok

    local auth
    started=$(l2_now_ms)
    user_run "$SCENARIO_TIMEOUT_SECONDS" "$USER_A" "$FIX" client "$EP"
    l2_timed_out && fail_reason="timed out" || fail_reason="uid/admin not as required: $(l2_sanitize "$L2_OUT")"
    owner_ok() { auth=$(parse_auth "$L2_OUT") && [ "$L2_RC" -eq 0 ] && [ "$auth" = "$ua false" ]; }
    check credentials.owner-uid "$started" "$(title_of credentials.owner-uid)" "uid=$ua admin=false" owner_ok

    started=$(l2_now_ms)
    user_run "$SCENARIO_TIMEOUT_SECONDS" "$USER_A" "$FIX" spoof-hello
    l2_timed_out && fail_reason="timed out" || fail_reason="spoofed Hello changed the identity: $(l2_sanitize "$L2_OUT")"
    spoof_ok() { auth=$(parse_auth "$L2_OUT") && [ "$L2_RC" -eq 0 ] && [ "$auth" = "$ua false" ]; }
    check credentials.spoofed-hello "$started" "$(title_of credentials.spoofed-hello)" "uid=$ua admin=false despite claiming UID 0" spoof_ok

    started=$(l2_now_ms)
    user_run "$SCENARIO_TIMEOUT_SECONDS" "$USER_A" env ROSETUN_HELPER_ENDPOINT=/nonexistent-rosetun-l2/helper.sock "$FIX" spoof-hello
    l2_timed_out && fail_reason="timed out" || fail_reason="the variable changed the endpoint: $(l2_sanitize "$L2_OUT")"
    env_ok() { auth=$(parse_auth "$L2_OUT") && [ "$L2_RC" -eq 0 ] && [ "$auth" = "$ua false" ]; }
    check credentials.endpoint-env-ignored "$started" "$(title_of credentials.endpoint-env-ignored)" "default endpoint still used with the variable set" env_ok

    started=$(l2_now_ms)
    user_run "$SCENARIO_TIMEOUT_SECONDS" "$USER_B" "$FIX" client "$EP"
    l2_timed_out && fail_reason="timed out" || fail_reason="uid/admin not as required: $(l2_sanitize "$L2_OUT")"
    other_ok() { auth=$(parse_auth "$L2_OUT") && [ "$L2_RC" -eq 0 ] && [ "$auth" = "$ub false" ] && [ "$ub" != "$ua" ]; }
    check credentials.other-uid "$started" "$(title_of credentials.other-uid)" "uid=$ub admin=false" other_ok

    started=$(l2_now_ms)
    l2_run_bounded "$SCENARIO_TIMEOUT_SECONDS" "$FIX" client "$EP"
    l2_timed_out && fail_reason="timed out" || fail_reason="root did not authenticate as UID 0 admin: $(l2_sanitize "$L2_OUT")"
    root_ok() { auth=$(parse_auth "$L2_OUT") && [ "$L2_RC" -eq 0 ] && [ "$auth" = "0 true" ]; }
    check credentials.root-uid "$started" "$(title_of credentials.root-uid)" "uid=0 admin=true" root_ok

    started=$(l2_now_ms)
    clean_exit_ok() {
        wait_exit "$pid" 15 || { fail_reason="the fixture did not exit after its last connection"; return 1; }
        [ "$WAIT_RC" -eq 0 ] || { fail_reason="the fixture exited with $WAIT_RC: $(l2_sanitize "$(cat "$out")")"; return 1; }
        [ ! -e "$EP" ] && [ ! -L "$EP" ] || { fail_reason="the socket is still there"; return 1; }
    }
    check credentials.clean-exit "$started" "$(title_of credentials.clean-exit)" "exit 0 and the socket is gone" clean_exit_ok
}

# ---------------------------------------------------------------- untrusted user server

scenario_untrusted() {
    local started probe server_out=$STATE/user-server.out
    started=$(l2_now_ms)
    probe=$(cd "$RUN/work-$USER_A" && timeout 10 setpriv --reuid="$(uid_of "$USER_A")" --regid="$(gid_of "$USER_A")" --init-groups --reset-env -- mktemp -d /tmp/rosetun-l2.XXXXXXXX 2>/dev/null)
    if [ -z "$probe" ] || [ ! -d "$probe" ]; then
        record untrusted-server.client-refused ERROR "$(title_of untrusted-server.client-refused)" "could not create a probe directory as $USER_A" "$started"
        record untrusted-server.no-bytes-sent ERROR "$(title_of untrusted-server.no-bytes-sent)" "no probe directory" "$started"
        return
    fi
    l2_record_object "$STATE" tmp-dir "$probe"
    start_bg user-server "$server_out" "$FIX" setpriv --reuid="$(uid_of "$USER_A")" --regid="$(gid_of "$USER_A")" \
        --init-groups --reset-env -- "$FIX" user-server "$probe/helper.sock"
    local pid=$BG_PID
    if ! wait_for_text "$server_out" "fixture waiting" "$pid" 15; then
        record untrusted-server.client-refused ERROR "$(title_of untrusted-server.client-refused)" "the user server did not start: $(l2_sanitize "$(cat "$server_out")")" "$started"
        record untrusted-server.no-bytes-sent ERROR "$(title_of untrusted-server.no-bytes-sent)" "the user server did not start" "$started"
        return
    fi
    l2_record_object "$STATE" tmp-socket "$probe/helper.sock"

    user_run "$SCENARIO_TIMEOUT_SECONDS" "$USER_A" "$FIX" client "$probe/helper.sock"
    refused_ok() {
        [ "$L2_RC" -ne 0 ] && ! l2_timed_out || { fail_reason="the client was not refused (exit $L2_RC): $(l2_sanitize "$L2_OUT")"; return 1; }
        [[ $L2_OUT == *"unsafe type, owner or mode"* || $L2_OUT == *"must run as root"* || $L2_OUT == *"trusted owner, group and mode"* ]] ||
            { fail_reason="refused for an unexpected reason: $(l2_sanitize "$L2_OUT")"; return 1; }
    }
    check untrusted-server.client-refused "$started" "$(title_of untrusted-server.client-refused)" "refused before Hello with a policy error" refused_ok

    started=$(l2_now_ms)
    no_bytes_ok() {
        wait_exit "$pid" 30 || { fail_reason="the user server did not finish"; return 1; }
        [ "$WAIT_RC" -eq 0 ] || { fail_reason="the user server reported a problem: $(l2_sanitize "$(cat "$server_out")")"; return 1; }
        grep -q -F "no request bytes received" "$server_out" || { fail_reason="the server did not confirm an empty request"; return 1; }
    }
    check untrusted-server.no-bytes-sent "$started" "$(title_of untrusted-server.no-bytes-sent)" "the server reported no request bytes" no_bytes_ok

    # Exactly the recorded objects, as the account that made them; nothing recursive.
    local sock_rec dir_rec
    sock_rec=$(l2_last_record "$STATE/objects.tsv" "$probe/helper.sock")
    if [ -S "$probe/helper.sock" ] && [ "$sock_rec" = "$(l2_object_fingerprint "$probe/helper.sock")" ]; then
        as_user "$USER_A" rm -- "$probe/helper.sock"
    fi
    dir_rec=$(l2_last_record "$STATE/objects.tsv" "$probe")
    if [ -d "$probe" ] && [ "$dir_rec" = "$(l2_object_fingerprint "$probe")" ]; then
        as_user "$USER_A" rmdir -- "$probe" 2>/dev/null
    fi
}

# ---------------------------------------------------------------- exclusivity

scenario_exclusivity() {
    local started out=$STATE/serve-exclusive.out pid before
    started=$(l2_now_ms)
    start_bg fixture-exclusive "$out" "$FIX" "$FIX" serve 1 || {
        for id in exclusivity.second-bind-refused exclusivity.inode-unchanged exclusivity.original-still-serves exclusivity.original-clean-exit; do
            record "$id" ERROR "$(title_of "$id")" "could not start or record the fixture server" "$started"
        done
        return
    }
    pid=$BG_PID
    if ! wait_for_text "$out" "fixture listening" "$pid" 15 || [ ! -S "$EP" ]; then
        for id in exclusivity.second-bind-refused exclusivity.inode-unchanged exclusivity.original-still-serves exclusivity.original-clean-exit; do
            record "$id" ERROR "$(title_of "$id")" "the first server did not start: $(l2_sanitize "$(cat "$out")")" "$started"
        done
        return
    fi
    l2_record_object "$STATE" endpoint-socket "$EP"
    before=$(inode_of "$EP")

    started=$(l2_now_ms)
    l2_run_bounded "$SCENARIO_TIMEOUT_SECONDS" "$FIX" serve 1
    second_ok() {
        [ "$L2_RC" -ne 0 ] && ! l2_timed_out || { fail_reason="the second bind was not refused (exit $L2_RC): $(l2_sanitize "$L2_OUT")"; return 1; }
        [[ $L2_OUT == *"helper endpoint exists"* || $L2_OUT == *AddrInUse* ]] || { fail_reason="refused for an unexpected reason: $(l2_sanitize "$L2_OUT")"; return 1; }
    }
    check exclusivity.second-bind-refused "$started" "$(title_of exclusivity.second-bind-refused)" "refused as an occupied endpoint" second_ok

    started=$(l2_now_ms)
    inode_ok() { [ "$(inode_of "$EP")" = "$before" ] || { fail_reason="inode changed from $before to $(inode_of "$EP")"; return 1; }; }
    check exclusivity.inode-unchanged "$started" "$(title_of exclusivity.inode-unchanged)" "device:inode stayed $before" inode_ok

    started=$(l2_now_ms)
    user_run "$SCENARIO_TIMEOUT_SECONDS" "$USER_A" "$FIX" client "$EP"
    serves_ok() {
        local auth
        auth=$(parse_auth "$L2_OUT") && [ "$L2_RC" -eq 0 ] || { fail_reason="the original listener no longer serves: $(l2_sanitize "$L2_OUT")"; return 1; }
    }
    check exclusivity.original-still-serves "$started" "$(title_of exclusivity.original-still-serves)" "the original listener answered" serves_ok

    started=$(l2_now_ms)
    orig_exit_ok() {
        wait_exit "$pid" 15 || { fail_reason="the original listener did not exit"; return 1; }
        [ "$WAIT_RC" -eq 0 ] || { fail_reason="the original listener exited with $WAIT_RC"; return 1; }
        [ ! -e "$EP" ] && [ ! -L "$EP" ] || { fail_reason="the socket is still there"; return 1; }
    }
    check exclusivity.original-clean-exit "$started" "$(title_of exclusivity.original-clean-exit)" "exit 0 and the socket is gone" orig_exit_ok
}

# ---------------------------------------------------------------- stale socket

scenario_stale() {
    local started out=$STATE/serve-stale.out pid fingerprint identity start exe
    started=$(l2_now_ms)
    start_bg fixture-stale "$out" "$FIX" "$FIX" serve 1 || {
        for id in stale.restart-refused stale.socket-preserved stale.verified-removal; do
            record "$id" ERROR "$(title_of "$id")" "could not start or record the fixture server" "$started"
        done
        return
    }
    pid=$BG_PID
    if ! wait_for_text "$out" "fixture listening" "$pid" 15 || [ ! -S "$EP" ]; then
        for id in stale.restart-refused stale.socket-preserved stale.verified-removal; do
            record "$id" ERROR "$(title_of "$id")" "the fixture server did not start: $(l2_sanitize "$(cat "$out")")" "$started"
        done
        return
    fi
    l2_record_object "$STATE" endpoint-socket "$EP"
    fingerprint=$(l2_object_fingerprint "$EP")
    identity=$(l2_process_identity "$pid")
    start=${identity%% *}
    exe=${identity#* }
    # Only the process this run started, identified by PID, start time and exe.
    if [ "$exe" != "$FIX" ] || ! l2_process_alive_as "$pid" "$start" "$exe"; then
        for id in stale.restart-refused stale.socket-preserved stale.verified-removal; do
            record "$id" ERROR "$(title_of "$id")" "refusing to kill pid $pid: it is not this run's fixture ($exe)" "$started"
        done
        return
    fi
    kill -KILL "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    if ! l2_wait_process_gone "$pid" "$start" "$exe" 10; then
        for id in stale.restart-refused stale.socket-preserved stale.verified-removal; do
            record "$id" ERROR "$(title_of "$id")" "the killed fixture is still running; leaving the socket" "$started"
        done
        return
    fi

    started=$(l2_now_ms)
    l2_run_bounded "$SCENARIO_TIMEOUT_SECONDS" "$FIX" serve 1
    restart_ok() {
        [ "$L2_RC" -ne 0 ] && ! l2_timed_out || { fail_reason="the restart was not refused (exit $L2_RC): $(l2_sanitize "$L2_OUT")"; return 1; }
        [[ $L2_OUT == *"helper endpoint exists"* || $L2_OUT == *AddrInUse* ]] || { fail_reason="refused for an unexpected reason: $(l2_sanitize "$L2_OUT")"; return 1; }
    }
    check stale.restart-refused "$started" "$(title_of stale.restart-refused)" "refused the stale socket" restart_ok

    started=$(l2_now_ms)
    preserved_ok() {
        [ "$(l2_object_fingerprint "$EP")" = "$fingerprint" ] || { fail_reason="the stale socket changed or vanished: $(l2_object_fingerprint "$EP")"; return 1; }
    }
    check stale.socket-preserved "$started" "$(title_of stale.socket-preserved)" "the same socket object remains" preserved_ok

    started=$(l2_now_ms)
    removal_ok() {
        local reason
        l2_process_alive_as "$pid" "$start" "$exe" && { fail_reason="the fixture process still exists"; return 1; }
        reason=$(l2_remove_recorded "$STATE/objects.tsv" "$EP") || { fail_reason="left in place: $reason. Inspect it with stat and remove it yourself"; return 1; }
        [ ! -e "$EP" ] && [ ! -L "$EP" ]
    }
    check stale.verified-removal "$started" "$(title_of stale.verified-removal)" "removed only after the identity checks passed" removal_ok
}

# ---------------------------------------------------------------- occupied path

scenario_occupied() {
    local started
    started=$(l2_now_ms)
    if [ -e "$EP" ] || [ -L "$EP" ] || [ ! -d "$EP_DIR" ]; then
        record occupied.regular-file-preserved ERROR "$(title_of occupied.regular-file-preserved)" "the endpoint path is not free for this scenario" "$started"
        record occupied.symlink-preserved ERROR "$(title_of occupied.symlink-preserved)" "the endpoint path is not free for this scenario" "$started"
        return
    fi

    printf 'rosetun l2 regular file\n' >"$EP" && chmod 0600 "$EP"
    l2_record_object "$STATE" endpoint-file "$EP"
    local file_fp
    file_fp=$(l2_object_fingerprint "$EP")
    l2_run_bounded "$SCENARIO_TIMEOUT_SECONDS" "$FIX" serve 1
    file_ok() {
        [ "$L2_RC" -ne 0 ] && ! l2_timed_out || { fail_reason="serve was not refused (exit $L2_RC)"; return 1; }
        [ "$(l2_object_fingerprint "$EP")" = "$file_fp" ] || { fail_reason="the regular file changed: $(l2_object_fingerprint "$EP")"; return 1; }
    }
    check occupied.regular-file-preserved "$started" "$(title_of occupied.regular-file-preserved)" "refused; inode and content unchanged" file_ok
    l2_remove_recorded "$STATE/objects.tsv" "$EP" >/dev/null

    started=$(l2_now_ms)
    ln -s rosetun-l2-no-such-target "$EP"
    l2_record_object "$STATE" endpoint-symlink "$EP"
    local link_fp
    link_fp=$(l2_object_fingerprint "$EP")
    l2_run_bounded "$SCENARIO_TIMEOUT_SECONDS" "$FIX" serve 1
    link_ok() {
        [ "$L2_RC" -ne 0 ] && ! l2_timed_out || { fail_reason="serve was not refused (exit $L2_RC)"; return 1; }
        [ "$(l2_object_fingerprint "$EP")" = "$link_fp" ] || { fail_reason="the symlink changed: $(l2_object_fingerprint "$EP")"; return 1; }
    }
    check occupied.symlink-preserved "$started" "$(title_of occupied.symlink-preserved)" "refused; symlink untouched" link_ok
    l2_remove_recorded "$STATE/objects.tsv" "$EP" >/dev/null
}

# ---------------------------------------------------------------- unit tests

scenario_units() {
    local id required evidence group detail title bin name binary
    while IFS=$'\t' read -r id required evidence group detail title; do
        [ "$group" = unit_helper ] || [ "$group" = unit_ipc ] || continue
        local started
        started=$(l2_now_ms)
        bin=${detail%%:*}
        name=${detail#*:}
        case $bin in
            helper) binary=$ART/rosetun_helper_privileged_tests ;;
            ipc) binary=$ART/rosetun_ipc_tests ;;
            *) record "$id" ERROR "$title" "unknown test binary $bin" "$started"; continue ;;
        esac
        user_run "$UNIT_TIMEOUT_SECONDS" "$USER_A" env "TMPDIR=$RUN/work-$USER_A" "$binary" --exact "$name" --test-threads=1
        if l2_timed_out; then
            record "$id" ERROR "$title" "timed out after ${UNIT_TIMEOUT_SECONDS}s" "$started"
        elif [ "$L2_RC" -eq 0 ] && [[ $L2_OUT == *"test result: ok. 1 passed; 0 failed"* ]]; then
            record "$id" PASS "$title" "$name passed as $USER_A" "$started"
        elif [[ $L2_OUT == *"running 0 tests"* ]]; then
            record "$id" ERROR "$title" "the test name matched nothing; the binary and the list are out of step" "$started"
        else
            record "$id" FAIL "$title" "exit $L2_RC: $(l2_sanitize "$(printf '%s' "$L2_OUT" | tail -n 6)")" "$started"
        fi
    done <"$SCENARIOS"
}

scenario_missing_group() {
    record missing-group.refusal SKIP "$(title_of missing-group.refusal)" \
        "needs a separate clean VM without group rosetun; the stand never removes or renames the group" "$(l2_now_ms)"
}

# ---------------------------------------------------------------- report

# Closes the report: cleanup first, then the verdict. Safe to call twice.
finalize() {
    exec 8>"$STATE/finalize.lock"
    flock 8
    if [ -f "$REPORT/report.json" ]; then
        return 0
    fi
    local started_cleanup
    started_cleanup=$(l2_now_ms)
    l2_cleanup_run "$STATE" "$EP_DIR"
    local cleanup_ms=$(($(l2_now_ms) - started_cleanup))

    # A required scenario that left no line cannot count as passed.
    local id required missing=''
    while IFS=$'\t' read -r id required _; do
        [ "$id" = id ] && continue
        [ "$required" = yes ] || continue
        grep -q "\"id\":\"$id\"" "$RESULTS" 2>/dev/null || {
            record "$id" ERROR "$(title_of "$id")" "no result was recorded; the job ended early" "$(l2_now_ms)"
            missing="$missing $id"
        }
    done <"$SCENARIOS"

    local pass fail err skip total overall coverage lines=''
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
        printf '"guest":{"os":%s,"kernel":%s,"arch":%s,"systemd":%s,"boot_id":%s,"boot_id_at_end":%s},' \
            "$(l2_json_string "${GUEST_OS-unknown}")" "$(l2_json_string "${GUEST_KERNEL-unknown}")" \
            "$(l2_json_string "${GUEST_ARCH-unknown}")" "$(l2_json_string "$(systemctl --version 2>/dev/null | head -n 1)")" \
            "$(l2_json_string "${GUEST_BOOT_ID-unknown}")" "$(l2_json_string "$(cat /proc/sys/kernel/random/boot_id)")"
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
}

load_job || exit 65
mkdir -p "$STATE" "$REPORT"
: >>"$RESULTS"

if [ "$mode" = finalize ]; then
    # The unit ended. If `run` already wrote the report this does nothing; otherwise
    # the job was killed, so the verdict is built from what exists and cannot pass.
    [ -f "$REPORT/report.json" ] || : >"$STATE/aborted"
    finalize
    exit 0
fi

trap 'finalize' EXIT
trap ': >"$STATE/aborted"; exit 143' TERM INT
write_status running preflight

scenario_preflight
if preflight_ok; then
    scenario_credentials
    scenario_untrusted
    scenario_exclusivity
    scenario_stale
    scenario_occupied
    scenario_units
else
    skip_rest "a preflight check failed, nothing else was started"
fi
scenario_missing_group
exit 0
