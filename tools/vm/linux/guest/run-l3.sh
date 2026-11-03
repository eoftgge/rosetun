#!/bin/bash
# Runs the Linux L3 scenarios inside the guest, as root, from a systemd transient
# unit started by start.sh: the real helper as the systemd service, its nftables
# kill switch and DNS lock, a crash and a stop. It never depends on the SSH session
# that started it; the kill switch may cut that session off.
#
#   run-l3.sh run RUN_DIR        install the service, run every scenario, clean up,
#                                write the report
#   run-l3.sh finalize RUN_DIR   clean up and close the report if `run` never got to
#                                (ExecStopPost of the unit: the job was killed or timed out)
#
# The host restores the clean checkpoint before and after the run; the cleanup
# here still removes what this run installed, and only that.

set -u
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
umask 022

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=lib.sh
. "$here/lib.sh"

mode=${1-}
RUN=${2-}
case $mode in run | finalize) ;; *) echo "usage: run-l3.sh run|finalize RUN_DIR" >&2; exit 64 ;; esac
[ -d "$RUN" ] || { echo "run directory $RUN is missing" >&2; exit 64; }
RUN=$(cd -- "$RUN" && pwd -P)

STATE=$RUN/state
REPORT=$RUN/report
ART=$RUN/artifacts
SCENARIOS=$RUN/scenarios-l3.tsv
RESULTS=$STATE/results.jsonl

PREFIX=/usr/lib/rosetun
UNIT_FILE=/usr/lib/systemd/system/rosetun-helper.service
CLI=$PREFIX/rosetun
NFT=/usr/sbin/nft
FOREIGN_TABLE=rosetun-l3-foreign
SERVICE_LEAF=/sys/fs/cgroup/system.slice/rosetun-helper.service

RUN_ID='' STAND_ID='' EXPECTED_BOOT_ID='' USER_A='' USER_B='' BIOS_GUID=''
HOST_ADDRESS='' NODE_PORT='' PROBE_ADDRESS=''
SCENARIO_TIMEOUT_SECONDS=30 UNIT_TIMEOUT_SECONDS=180 JOB_TIMEOUT_SECONDS=1800
EXPECTED_ARCH=x86_64
PHYS=''

write_status() {
    printf '{"run_id":%s,"state":%s,"current":%s,"updated":%s,"boot_id":%s}\n' \
        "$(l2_json_string "$RUN_ID")" "$(l2_json_string "$1")" "$(l2_json_string "${2-}")" \
        "$(l2_json_string "$(l2_now_utc)")" "$(l2_json_string "$(cat /proc/sys/kernel/random/boot_id)")" |
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

# check ID PASS_NOTE CONDITION...: PASS when the condition holds; the condition
# sets fail_reason to say why it did not.
fail_reason=''
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

passed() { grep -q "\"id\":\"$1\".*\"result\":\"PASS\"" "$RESULTS"; }

uid_of() { id -u -- "$1"; }
gid_of() { id -g -- "$1"; }

# cli SECONDS COMMAND...: the CLI as the first account; output in CLI_OUT.
cli() {
    local seconds=$1
    shift
    CLI_OUT=$(cd "$RUN/work-$USER_A" && timeout --kill-after=3 "$seconds" setpriv --reuid="$(uid_of "$USER_A")" \
        --regid="$(gid_of "$USER_A")" --init-groups --reset-env -- "$CLI" "$@" 2>&1 </dev/null)
    CLI_RC=$?
}

state_line() {
    cli 15 status
    printf '%s\n' "$CLI_OUT" | sed -n 's/^state: //p' | head -n 1
}

# wait_state PATTERN SECONDS: until `rosetun status` shows a matching state.
wait_state() {
    local pattern=$1 deadline=$((SECONDS + $2)) state=''
    while [ "$SECONDS" -lt "$deadline" ]; do
        state=$(state_line)
        [[ $state =~ $pattern ]] && return 0
        sleep 1
    done
    fail_reason="the state stayed '${state:-unknown}' instead of $pattern"
    return 1
}

connect_with() {
    local request=$1
    # A scenario that failed half-way may have left a session.
    [[ $(state_line) =~ ^Disconnected ]] || cli 60 disconnect
    install -m 0600 -o "$(uid_of "$USER_A")" -g "$(gid_of "$USER_A")" -- "$ART/$request" "$RUN/work-$USER_A/$request"
    cli 120 connect "$request"
    [ "$CLI_RC" -eq 0 ] || { fail_reason="connect with $request failed: $CLI_OUT"; return 1; }
    wait_state '^Connected' 30
}

disconnect() {
    cli 60 disconnect
    wait_state '^Disconnected' 30
}

table_present() { "$NFT" list table inet rosetun >/dev/null 2>&1; }

# curl_rc ARGS...: curl's exit code, 0 when it reached the other end.
curl_rc() {
    curl -s -o /dev/null --connect-timeout 3 --max-time 8 "$@" </dev/null
    printf '%s' "$?"
}

# Refused locally (7) or timed out (28) counts as blocked. 45 means curl could not
# bind the interface, which proves nothing either way.
blocked_rc() { [ "$1" = 7 ] || [ "$1" = 28 ]; }
reached_rc() { ! blocked_rc "$1" && [ "$1" != 45 ] && [ "$1" != 2 ]; }

direct_https() { curl_rc --interface "$PHYS" "https://$PROBE_ADDRESS/"; }
direct_dns_tcp() { curl_rc --interface "$PHYS" "http://$PROBE_ADDRESS:53/"; }
direct_node() { curl_rc --interface "$PHYS" "http://$HOST_ADDRESS:$NODE_PORT/"; }
tunnel_https() { curl_rc --max-time 15 "https://$PROBE_ADDRESS/"; }

expect_blocked() {
    local what=$1 rc
    rc=$("$2")
    blocked_rc "$rc" || { fail_reason="$what was not refused (curl exit $rc)"; return 1; }
}

expect_reached() {
    local what=$1 rc
    rc=$("$2")
    reached_rc "$rc" || { fail_reason="$what did not answer (curl exit $rc)"; return 1; }
}

main_pid() { systemctl show -p MainPID --value rosetun-helper.service 2>/dev/null; }

# ---------------------------------------------------------------- preflight

scenario_preflight() {
    pre_identity() {
        local stand bios
        stand=$(cat "$L2_STAND_ID_FILE" 2>/dev/null)
        [ -n "$stand" ] && [ "$stand" = "$STAND_ID" ] || { fail_reason="stand id file $L2_STAND_ID_FILE does not match the requested stand"; return 1; }
        [ "$(cat /proc/sys/kernel/random/boot_id)" = "$EXPECTED_BOOT_ID" ] || { fail_reason="boot id changed since the host connected"; return 1; }
        [ "$(uname -m)" = "$EXPECTED_ARCH" ] || { fail_reason="architecture is not $EXPECTED_ARCH"; return 1; }
        [ -d /run/systemd/system ] || { fail_reason="systemd is not the running init"; return 1; }
        bios=$(tr 'A-F' 'a-f' </sys/class/dmi/id/product_uuid 2>/dev/null)
        if [ -z "$BIOS_GUID" ] || { [ "$bios" != "${BIOS_GUID,,}" ] && [ "$bios" != "$(l2_guid_swap "$BIOS_GUID")" ]; }; then
            fail_reason="the guest BIOS GUID does not belong to the selected Hyper-V VM"
            return 1
        fi
    }
    check preflight.identity "stand id, boot id, architecture, systemd and BIOS GUID agree" pre_identity

    pre_accounts() {
        local account
        getent group rosetun >/dev/null || { fail_reason="group rosetun does not exist"; return 1; }
        [ -n "$USER_A" ] && [ -n "$USER_B" ] && [ "$USER_A" != "$USER_B" ] || { fail_reason="two different test accounts are required"; return 1; }
        for account in "$USER_A" "$USER_B"; do
            [ "$(uid_of "$account" 2>/dev/null || echo 0)" -ne 0 ] || { fail_reason="$account is missing or root"; return 1; }
            id -nG -- "$account" | tr ' ' '\n' | grep -qx rosetun || { fail_reason="$account is not in group rosetun"; return 1; }
            if id -nG -- "$account" | tr ' ' '\n' | grep -qxE 'sudo|wheel|admin|root'; then
                fail_reason="$account belongs to an administrator group"
                return 1
            fi
        done
    }
    check preflight.accounts "two ordinary members of rosetun" pre_accounts

    pre_service() {
        if systemctl list-units --all --no-legend 'rosetun*' 2>/dev/null | grep -v 'rosetun-l2-' | grep -q .; then
            fail_reason="a rosetun systemd unit is present; restore the clean checkpoint"
            return 1
        fi
        pgrep -x rosetun-helper-privileged >/dev/null 2>&1 && { fail_reason="a helper process runs"; return 1; }
        for path in "$PREFIX" "$UNIT_FILE" /run/rosetun /var/lib/rosetun; do
            [ ! -e "$path" ] || { fail_reason="$path exists; the stand installs only on a clean guest"; return 1; }
        done
        if [ -x "$NFT" ] && table_present; then
            fail_reason="the table inet rosetun exists already"
            return 1
        fi
        : >"$STATE/clean-before-install"
    }
    check preflight.no-foreign-service "nothing of Rosetun is installed or running" pre_service

    pre_tools() {
        [ -x "$NFT" ] || { fail_reason="$NFT is missing (apt-get install nftables)"; return 1; }
        command -v curl >/dev/null || { fail_reason="curl is missing"; return 1; }
        command -v dig >/dev/null || { fail_reason="dig is missing (apt-get install bind9-dnsutils)"; return 1; }
        [ -f /sys/fs/cgroup/cgroup.controllers ] || { fail_reason="cgroup v2 is not mounted"; return 1; }
    }
    check preflight.tools "nft, curl, dig and cgroup v2 present" pre_tools

    pre_baseline() {
        PHYS=$(ip -o route get "$PROBE_ADDRESS" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p')
        [[ $PHYS =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || { fail_reason="no route to $PROBE_ADDRESS"; return 1; }
        printf 'PHYS=%s\n' "$PHYS" >"$STATE/phys.env"
        expect_reached "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https || return 1
        expect_reached "TCP 53 to $PROBE_ADDRESS on $PHYS" direct_dns_tcp || return 1
        expect_reached "the host node $HOST_ADDRESS:$NODE_PORT on $PHYS" direct_node || return 1
    }
    check preflight.baseline "the probe and the host node answer on the physical interface" pre_baseline
}

preflight_ok() {
    local id
    for id in preflight.identity preflight.accounts preflight.no-foreign-service preflight.tools preflight.baseline; do
        passed "$id" || return 1
    done
}

skip_rest() {
    local reason=$1 id
    while IFS=$'\t' read -r id _; do
        [ "$id" = id ] && continue
        grep -q "\"id\":\"$id\"" "$RESULTS" 2>/dev/null && continue
        record "$id" ERROR "not run: $reason" "$(l2_now_ms)"
    done <"$SCENARIOS"
}

# ---------------------------------------------------------------- scenarios

scenario_install() {
    do_install() {
        : >"$STATE/installed"
        install -d -m 0755 -o root -g root "$PREFIX" &&
            install -m 0755 -o root -g root "$ART/rosetun-helper-privileged" "$ART/rosetun" "$ART/sing-box" "$PREFIX/" &&
            install -m 0644 -o root -g root "$ART/rosetun-helper.service" "$UNIT_FILE" ||
            { fail_reason="installing the files failed"; return 1; }
        systemctl daemon-reload && timeout "$UNIT_TIMEOUT_SECONDS" systemctl start rosetun-helper.service ||
            { fail_reason="the service did not start: $(systemctl status --no-pager rosetun-helper.service 2>&1 | tail -n 3)"; return 1; }
        local pid own
        pid=$(main_pid)
        own=$(cat "/proc/$pid/cgroup" 2>/dev/null)
        [ "$own" = "0::/system.slice/rosetun-helper.service/helper" ] || { fail_reason="the helper is in '$own', not in its leaf"; return 1; }
        [ -d "$SERVICE_LEAF/engines" ] || { fail_reason="the engines' leaf does not exist"; return 1; }
        if journalctl -b -u rosetun-helper.service --no-pager 2>/dev/null | grep -q 'kill switch is not available'; then
            fail_reason="the helper reports the kill switch unavailable: $(journalctl -b -u rosetun-helper.service --no-pager | grep 'kill switch is not available' | tail -n 1)"
            return 1
        fi
        install -d -m 0700 -o "$(uid_of "$USER_A")" -g "$(gid_of "$USER_A")" "$RUN/work-$USER_A"
        cli 15 status
        [ "$CLI_RC" -eq 0 ] || { fail_reason="rosetun status failed: $CLI_OUT"; return 1; }
    }
    check install.service "the unit runs, the helper is in its leaf, the kill switch is offered" do_install
}

scenario_kill_switch() {
    connect_ks() {
        connect_with request-kill-switch.json || return 1
        table_present || { fail_reason="connected but the table is missing"; return 1; }
        expect_blocked "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https
    }
    check killswitch.direct-blocked "the direct path was refused while connected" connect_ks
    if ! passed killswitch.direct-blocked; then
        return
    fi
    check killswitch.tunnel-passes "HTTPS through the tunnel answered" expect_reached "HTTPS through the tunnel" tunnel_https
    check lan.off "the host node was refused on the physical interface" expect_blocked "the host node" direct_node

    foreign() {
        "$NFT" -f - <<EOF || { fail_reason="could not add the foreign table"; return 1; }
table inet $FOREIGN_TABLE {
	chain output {
		type filter hook output priority -200; policy accept;
		meta l4proto { tcp, udp, icmp } accept
	}
}
EOF
        : >"$STATE/foreign-table"
        local result=0
        expect_blocked "HTTPS to $PROBE_ADDRESS on $PHYS with the foreign table" direct_https || result=1
        "$NFT" delete table inet "$FOREIGN_TABLE" && rm -f -- "$STATE/foreign-table"
        if [ "$result" -eq 0 ] && ! table_present; then
            fail_reason="the table inet rosetun went away with the foreign one"
            result=1
        fi
        return "$result"
    }
    check killswitch.foreign-table "the foreign accept did not open the direct path" foreign

    engine_killed() {
        pkill -KILL -x sing-box || { fail_reason="no sing-box process to kill"; return 1; }
        local probes=0 rc deadline=$((SECONDS + 60)) state=''
        while [ "$SECONDS" -lt "$deadline" ]; do
            rc=$(curl_rc --connect-timeout 1 --max-time 2 --interface "$PHYS" "https://$PROBE_ADDRESS/")
            probes=$((probes + 1))
            blocked_rc "$rc" || { fail_reason="probe $probes reached the direct path (curl exit $rc) during the restart"; return 1; }
            table_present || { fail_reason="the table disappeared during the restart"; return 1; }
            if [ "$probes" -ge 5 ]; then
                state=$(state_line)
                [[ $state =~ ^Connected ]] && break
            fi
            sleep 0.3
        done
        [[ $state =~ ^Connected ]] || { fail_reason="no Connected within 60 s after the engine was killed (state '$state')"; return 1; }
        expect_blocked "HTTPS to $PROBE_ADDRESS on $PHYS after the restart" direct_https
    }
    check killswitch.engine-killed "every probe was refused until Connected again" engine_killed

    disconnect_removes() {
        disconnect || return 1
        ! table_present || { fail_reason="the table stays after a disconnect"; return 1; }
        expect_reached "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https
    }
    check killswitch.disconnect "the table went away and the direct path answered" disconnect_removes
}

scenario_lan_on() {
    lan_on() {
        connect_with request-lan.json || return 1
        expect_reached "the host node" direct_node || return 1
        expect_blocked "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https || return 1
        disconnect
    }
    check lan.on "the host node connected, the probe address did not" lan_on
}

scenario_dns_lock() {
    dns_lock() {
        connect_with request-dns-lock.json || return 1
        table_present || { fail_reason="no table: the DNS lock is not installed"; return 1; }
        expect_blocked "TCP 53 to $PROBE_ADDRESS on $PHYS" direct_dns_tcp || return 1
        expect_reached "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https
    }
    check dnslock.direct-blocked "TCP 53 was refused, HTTPS answered" dns_lock
    dns_tunnel() {
        local answer
        answer=$(dig +time=3 +tries=2 "@$PROBE_ADDRESS" example.com A 2>&1)
        printf '%s' "$answer" | grep -q 'status: NOERROR' || { fail_reason="dig through the tunnel got no answer"; return 1; }
        disconnect
    }
    check dnslock.tunnel-passes "dig through the tunnel was answered" dns_tunnel
}

scenario_crash() {
    killed() {
        connect_with request-kill-switch.json || return 1
        local old restarts_before restarts deadline
        old=$(main_pid)
        restarts_before=$(systemctl show -p NRestarts --value rosetun-helper.service)
        kill -KILL "$old" || { fail_reason="could not kill the helper"; return 1; }
        sleep 0.5
        table_present || { fail_reason="the table went away with the helper"; return 1; }
        expect_blocked "HTTPS to $PROBE_ADDRESS on $PHYS after the crash" direct_https || return 1
        deadline=$((SECONDS + 60))
        while [ "$SECONDS" -lt "$deadline" ]; do
            restarts=$(systemctl show -p NRestarts --value rosetun-helper.service)
            if [ "$restarts" -gt "$restarts_before" ] && systemctl is-active --quiet rosetun-helper.service; then
                break
            fi
            sleep 1
        done
        [ "${restarts:-0}" -gt "$restarts_before" ] || { fail_reason="systemd did not restart the helper"; return 1; }
        deadline=$((SECONDS + 30))
        while [ "$SECONDS" -lt "$deadline" ]; do
            cli 15 status
            [ "$CLI_RC" -eq 0 ] && break
            sleep 1
        done
        printf '%s\n' "$CLI_OUT" | grep -q '^network: held closed' || { fail_reason="status does not report the network held closed: $CLI_OUT"; return 1; }
        table_present || { fail_reason="the restarted helper removed the table"; return 1; }
        expect_blocked "HTTPS to $PROBE_ADDRESS on $PHYS during the hold" direct_https
    }
    check crash.helper-killed "the table stayed, the helper restarted and reports the hold" killed
    passed crash.helper-killed || return

    opened() {
        cli 30 open-network
        [ "$CLI_RC" -eq 0 ] || { fail_reason="open-network failed: $CLI_OUT"; return 1; }
        ! table_present || { fail_reason="the table stays after open-network"; return 1; }
        expect_reached "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https
    }
    check crash.open-network "the table went away and the direct path answered" opened
}

scenario_stop() {
    stopped() {
        connect_with request-kill-switch.json || return 1
        timeout "$UNIT_TIMEOUT_SECONDS" systemctl stop rosetun-helper.service || { fail_reason="systemctl stop failed"; return 1; }
        ! table_present || { fail_reason="the table stays after a normal stop"; return 1; }
        expect_reached "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https
    }
    check stop.removes-table "the table went away with the stop and the direct path answered" stopped
}

# ---------------------------------------------------------------- cleanup and report

# Removes what this run installed, and only that. A table the service left after
# its stop stays: the stand never deletes the service's table; the checkpoint
# restore after the run does.
cleanup() {
    L2_CLEANUP_STATUS=PASS L2_CLEANUP_ACTIONS='' L2_CLEANUP_PROBLEMS=''
    note() { L2_CLEANUP_ACTIONS="$L2_CLEANUP_ACTIONS${L2_CLEANUP_ACTIONS:+; }$1"; }
    problem() { L2_CLEANUP_PROBLEMS="$L2_CLEANUP_PROBLEMS${L2_CLEANUP_PROBLEMS:+; }$1"; L2_CLEANUP_STATUS=ERROR; }
    if [ -f "$STATE/foreign-table" ]; then
        if "$NFT" delete table inet "$FOREIGN_TABLE" 2>/dev/null || ! "$NFT" list table inet "$FOREIGN_TABLE" >/dev/null 2>&1; then
            rm -f -- "$STATE/foreign-table"
            note "removed the foreign test table"
        else
            problem "could not remove the foreign test table inet $FOREIGN_TABLE"
        fi
    fi
    [ -f "$STATE/installed" ] || return 0
    if systemctl is-active --quiet rosetun-helper.service; then
        timeout 60 systemctl stop rosetun-helper.service && note "stopped the service" || problem "could not stop the service"
    fi
    if [ -x "$NFT" ] && table_present; then
        problem "the table inet rosetun is still there after the service stopped; restore the checkpoint"
    fi
    rm -f -- "$UNIT_FILE" && systemctl daemon-reload && note "removed the unit"
    systemctl reset-failed rosetun-helper.service 2>/dev/null
    rm -rf -- "$PREFIX" /var/lib/rosetun && note "removed the installed files"
    rm -f -- "$STATE/installed"
}

finalize() {
    exec 8>"$STATE/finalize.lock"
    flock 8
    [ -f "$REPORT/report.json" ] && return 0
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
        printf '"guest":{"os":%s,"kernel":%s,"arch":%s,"systemd":%s,"boot_id":%s,"boot_id_at_end":%s},' \
            "$(l2_json_string "$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME-unknown}")")" \
            "$(l2_json_string "$(uname -r)")" "$(l2_json_string "$(uname -m)")" \
            "$(l2_json_string "$(systemctl --version 2>/dev/null | head -n 1)")" \
            "$(l2_json_string "$EXPECTED_BOOT_ID")" "$(l2_json_string "$(cat /proc/sys/kernel/random/boot_id)")"
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
        SCENARIO_TIMEOUT_SECONDS UNIT_TIMEOUT_SECONDS JOB_TIMEOUT_SECONDS HOST_ADDRESS NODE_PORT PROBE_ADDRESS || return 1
    l2_valid_run_id "$RUN_ID" || { echo "invalid run id" >&2; return 1; }
    [ "$(basename -- "$RUN")" = "$RUN_ID" ] || { echo "run directory does not match the run id" >&2; return 1; }
    [[ $HOST_ADDRESS =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "invalid host address" >&2; return 1; }
    [[ $PROBE_ADDRESS =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "invalid probe address" >&2; return 1; }
    [[ $NODE_PORT =~ ^[0-9]{1,5}$ ]] || { echo "invalid node port" >&2; return 1; }
}

load_job || exit 65
mkdir -p "$STATE" "$REPORT"
: >>"$RESULTS"

if [ "$mode" = finalize ]; then
    [ -f "$REPORT/report.json" ] || : >"$STATE/aborted"
    finalize
    exit 0
fi

trap 'finalize' EXIT
trap ': >"$STATE/aborted"; exit 143' TERM INT
write_status running preflight

scenario_preflight
if preflight_ok; then
    scenario_install
    if passed install.service; then
        scenario_kill_switch
        scenario_lan_on
        scenario_dns_lock
        scenario_crash
        scenario_stop
    fi
    skip_rest "an earlier step failed; see the first FAIL"
else
    skip_rest "a preflight check failed, nothing was installed"
fi
exit 0
