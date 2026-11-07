#!/bin/bash
# Runs the Linux L3 scenarios inside the guest, as root, from a systemd transient
# unit started by start.sh: the real helper as the systemd service, its nftables
# kill switch and DNS lock, a crash and a stop. It never depends on the SSH session
# that started it. A peer network namespace on a veth pair stands in for another
# machine: it opens a connection to the guest and has its traffic forwarded.
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
COUNT_TABLE=rosetun-l3-count
SERVICE_LEAF=/sys/fs/cgroup/system.slice/rosetun-helper.service
# The peer: documentation addresses on a link of their own, a NAT table of the
# stand's own and a routing rule that sends the peer's traffic out of the
# physical interface, past the tunnel's routes.
PEER_NS=rosetun-l3-peer
PEER_HOST_IF=rl3-host
PEER_IF=rl3-peer
PEER_HOST_ADDRESS=198.51.100.1
PEER_ADDRESS=198.51.100.2
PEER_TABLE=7731
PEER_RULE_PRIORITY=50
NAT_TABLE=rosetun-l3-nat

RUN_ID='' STAND_ID='' EXPECTED_BOOT_ID='' USER_A='' USER_B='' BIOS_GUID=''
HOST_ADDRESS='' NODE_PORT='' PROBE_ADDRESS='' DNS_PROBE_ADDRESS=''
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
        --regid="$(gid_of "$USER_A")" --init-groups --reset-env -- /usr/bin/env NO_COLOR=1 "$CLI" "$@" 2>&1 </dev/null)
    CLI_RC=$?
    # The report keeps 300 characters: no colour codes, and the error first.
    CLI_OUT=$(printf '%s' "$CLI_OUT" | sed 's/\x1b\[[0-9;]*m//g')
}

# The CLI's own error line without its time stamp, or the whole output.
cli_error() {
    local line
    line=$(printf '%s\n' "$CLI_OUT" | grep -E ' ERROR ' | tail -n 1 | sed 's/^[0-9T:.Z-]* *//')
    printf '%s' "${line:-$CLI_OUT}"
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
    [ "$CLI_RC" -eq 0 ] || { fail_reason="connect with $request failed: $(cli_error)"; return 1; }
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

# DNS straight out of the physical interface, without needing anyone to answer:
# curl sends one UDP datagram to port 53 (a TFTP request) bound to the
# interface. A drop in the output hook fails sendto() at once with EPERM, which
# curl's trace prints as "Operation not permitted"; a datagram that left the
# guest just goes unanswered. TCP cannot tell the two apart: a dropped SYN is
# retried until the same timeout as a SYN lost in the network.
udp_dns_out() {
    UDP_OUT=$(curl -v -s -o /dev/null --connect-timeout 3 --max-time 4 --interface "$PHYS"         "tftp://$DNS_PROBE_ADDRESS:53/rosetun-l3" 2>&1 </dev/null)
    UDP_RC=$?
}

expect_udp_dns_refused() {
    udp_dns_out
    printf '%s' "$UDP_OUT" | grep -q 'Operation not permitted' ||
        { fail_reason="UDP 53 to $DNS_PROBE_ADDRESS on $PHYS was sent, not refused (curl exit $UDP_RC)"; return 1; }
}

expect_udp_dns_sent() {
    udp_dns_out
    if printf '%s' "$UDP_OUT" | grep -q 'Operation not permitted'; then
        fail_reason="UDP 53 to $DNS_PROBE_ADDRESS on $PHYS was refused locally without Rosetun; another firewall drops it"
        return 1
    fi
    case $UDP_RC in
        1 | 2 | 45) fail_reason="curl could not send UDP 53 on $PHYS (curl exit $UDP_RC)"; return 1 ;;
    esac
}

# The resolver the guest is configured with, as a user's program asks it.
system_dns_answers() {
    dig +time=3 +tries=2 example.com A 2>&1 | grep -q 'status: NOERROR'
}

main_pid() { systemctl show -p MainPID --value rosetun-helper.service 2>/dev/null; }

# flush_and_wait_restored: what `flush ruleset` in a firewall's configuration does,
# then until the helper's next check put the table back.
flush_and_wait_restored() {
    local deadline
    "$NFT" flush ruleset || { fail_reason="nft flush ruleset failed"; return 1; }
    deadline=$((SECONDS + 10))
    until table_present; do
        [ "$SECONDS" -lt "$deadline" ] || { fail_reason="the table did not come back within ten seconds"; return 1; }
        sleep 0.2
    done
}

# kill_helper: SIGKILL to the helper, then until systemd restarted it and its
# socket answers `rosetun status` (in CLI_OUT).
kill_helper() {
    local old restarts_before restarts='' deadline
    old=$(main_pid)
    restarts_before=$(systemctl show -p NRestarts --value rosetun-helper.service)
    kill -KILL "$old" || { fail_reason="could not kill the helper"; return 1; }
    sleep 0.5
    KILLED_TABLE_PRESENT=0
    table_present && KILLED_TABLE_PRESENT=1
    KILLED_DIRECT_RC=$(direct_https)
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
        [ "$CLI_RC" -eq 0 ] && return 0
        sleep 1
    done
    fail_reason="the restarted helper does not answer: $CLI_OUT"
    return 1
}

# The peer side: a curl or a shell in the peer namespace.
in_peer() { ip netns exec "$PEER_NS" "$@"; }
peer_https() { in_peer curl -s -o /dev/null --connect-timeout 3 --max-time 8 "https://$PROBE_ADDRESS/" </dev/null; printf '%s' "$?"; }

# A UDP datagram from the guest to the peer, as udp_dns_out sends one: refused
# in the guest ("Operation not permitted") when the output hook drops it.
guest_to_peer_refused() {
    local out
    out=$(curl -v -s -o /dev/null --connect-timeout 3 --max-time 4 "tftp://$PEER_ADDRESS:69/rosetun-l3" 2>&1 </dev/null)
    printf '%s' "$out" | grep -q 'Operation not permitted'
}

peer_up() {
    : >"$STATE/peer"
    ip netns add "$PEER_NS" &&
        ip link add "$PEER_HOST_IF" type veth peer name "$PEER_IF" netns "$PEER_NS" &&
        ip addr add "$PEER_HOST_ADDRESS/30" dev "$PEER_HOST_IF" &&
        ip link set "$PEER_HOST_IF" up &&
        in_peer ip link set lo up &&
        in_peer ip addr add "$PEER_ADDRESS/30" dev "$PEER_IF" &&
        in_peer ip link set "$PEER_IF" up &&
        in_peer ip route add default via "$PEER_HOST_ADDRESS" ||
        { fail_reason="could not set up the peer namespace"; return 1; }
    local gateway
    gateway=$(ip -o route get "$PROBE_ADDRESS" 2>/dev/null | sed -n 's/.* via \([0-9.]*\) .*/\1/p')
    cat /proc/sys/net/ipv4/ip_forward >"$STATE/ip-forward-before"
    ip route add "$PROBE_ADDRESS/32" ${gateway:+via "$gateway"} dev "$PHYS" table "$PEER_TABLE" &&
        ip rule add iif "$PEER_HOST_IF" lookup "$PEER_TABLE" priority "$PEER_RULE_PRIORITY" &&
        "$NFT" -f - <<EOF &&
table ip $NAT_TABLE {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr $PEER_ADDRESS oif "$PHYS" masquerade
	}
}
EOF
        sysctl -qw net.ipv4.ip_forward=1 ||
        { fail_reason="could not set up forwarding for the peer"; return 1; }
}

peer_down() {
    [ -f "$STATE/peer" ] || return 0
    local result=0
    if [ -f "$STATE/peer-session.pid" ]; then
        kill "$(cat "$STATE/peer-session.pid")" 2>/dev/null
        rm -f -- "$STATE/peer-session.pid"
    fi
    ip rule del iif "$PEER_HOST_IF" lookup "$PEER_TABLE" priority "$PEER_RULE_PRIORITY" 2>/dev/null
    ip route flush table "$PEER_TABLE" 2>/dev/null
    "$NFT" delete table ip "$NAT_TABLE" 2>/dev/null
    ip link del "$PEER_HOST_IF" 2>/dev/null
    ip netns del "$PEER_NS" 2>/dev/null
    if [ -f "$STATE/ip-forward-before" ]; then
        sysctl -qw "net.ipv4.ip_forward=$(cat "$STATE/ip-forward-before")" || result=1
        rm -f -- "$STATE/ip-forward-before"
    fi
    if ip netns list 2>/dev/null | grep -qw -- "$PEER_NS" || ip link show "$PEER_HOST_IF" >/dev/null 2>&1 ||
        "$NFT" list table ip "$NAT_TABLE" >/dev/null 2>&1 || ip rule show | grep -q "lookup $PEER_TABLE"; then
        result=1
    fi
    [ "$result" -eq 0 ] && rm -f -- "$STATE/peer"
    return "$result"
}

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
        if ip netns list 2>/dev/null | grep -qw -- "$PEER_NS" || ip link show "$PEER_HOST_IF" >/dev/null 2>&1; then
            fail_reason="the peer namespace $PEER_NS or its link $PEER_HOST_IF exists already"
            return 1
        fi
        : >"$STATE/clean-before-install"
    }
    check preflight.no-foreign-service "nothing of Rosetun is installed or running" pre_service

    pre_tools() {
        [ -x "$NFT" ] || { fail_reason="$NFT is missing (apt-get install nftables)"; return 1; }
        command -v curl >/dev/null || { fail_reason="curl is missing"; return 1; }
        curl -V 2>/dev/null | grep -qw tftp || { fail_reason="curl was built without tftp, which the UDP 53 check uses"; return 1; }
        command -v dig >/dev/null || { fail_reason="dig is missing (apt-get install bind9-dnsutils)"; return 1; }
        [ -f /sys/fs/cgroup/cgroup.controllers ] || { fail_reason="cgroup v2 is not mounted"; return 1; }
    }
    check preflight.tools "nft, curl, dig and cgroup v2 present" pre_tools

    pre_baseline() {
        PHYS=$(ip -o route get "$PROBE_ADDRESS" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p')
        [[ $PHYS =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || { fail_reason="no route to $PROBE_ADDRESS"; return 1; }
        printf 'PHYS=%s\n' "$PHYS" >"$STATE/phys.env"
        expect_reached "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https || return 1
        expect_udp_dns_sent || return 1
        system_dns_answers || { fail_reason="the guest's own resolver does not answer dig"; return 1; }
        expect_reached "the host node $HOST_ADDRESS:$NODE_PORT on $PHYS" direct_node || return 1
    }
    check preflight.baseline "the probe and the host node answer, UDP 53 leaves, the resolver answers" pre_baseline
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
        l2_install_engine_account "$STATE" "$ART" || { fail_reason="could not make the engines' account"; return 1; }
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

scenario_protection_reported() {
    reported() {
        connect_with request-kill-switch.json || return 1
        cli 15 status
        printf '%s\n' "$CLI_OUT" | grep -q '^protection: kill switch' ||
            { fail_reason="status does not say the kill switch is in place: $CLI_OUT"; return 1; }
        printf '%s\n' "$CLI_OUT" | grep -q '^if the service crashes: this stays in place' ||
            { fail_reason="status does not say the kill switch stays after a crash: $CLI_OUT"; return 1; }
        ! printf '%s\n' "$CLI_OUT" | grep -q '^protection missing' ||
            { fail_reason="status names something as missing: $CLI_OUT"; return 1; }
        disconnect
    }
    check protection.reported "status names the kill switch and that it stays after a crash" reported
}

scenario_engine() {
    identity() {
        local pid engine_uid engine_gid status
        connect_with request-kill-switch.json || return 1
        pid=$(pgrep -x sing-box | head -n 1)
        [ -n "$pid" ] || { fail_reason="no sing-box process"; return 1; }
        status=$(cat "/proc/$pid/status")
        engine_uid=$(id -u rosetun-engine) engine_gid=$(id -g rosetun-engine)
        printf '%s\n' "$status" | grep -qP "^Uid:\t$engine_uid\t$engine_uid\t$engine_uid\t$engine_uid$" ||
            { fail_reason="sing-box runs as: $(printf '%s\n' "$status" | grep '^Uid:')"; return 1; }
        printf '%s\n' "$status" | grep -qP "^Gid:\t$engine_gid\t$engine_gid\t$engine_gid\t$engine_gid$" ||
            { fail_reason="sing-box has the group: $(printf '%s\n' "$status" | grep '^Gid:')"; return 1; }
        printf '%s\n' "$status" | grep -qP "^Groups:\t$engine_gid ?$" ||
            { fail_reason="sing-box has the groups: $(printf '%s\n' "$status" | grep '^Groups:')"; return 1; }
        local set
        for set in CapPrm CapEff CapAmb; do
            printf '%s\n' "$status" | grep -qP "^$set:\t0000000000003400$" ||
                { fail_reason="sing-box has $(printf '%s\n' "$status" | grep "^$set:")"; return 1; }
        done
        printf '%s\n' "$status" | grep -qP '^NoNewPrivs:\t1$' || { fail_reason="sing-box may gain privileges"; return 1; }
        [ "$(cat "/proc/$pid/cgroup")" = "0::/system.slice/rosetun-helper.service/engines" ] ||
            { fail_reason="sing-box is in $(cat "/proc/$pid/cgroup")"; return 1; }
        grep -qP '^CapBnd:\t00000000000834e5$' "/proc/$(main_pid)/status" ||
            { fail_reason="the helper has $(grep '^CapBnd:' "/proc/$(main_pid)/status")"; return 1; }
    }
    check engine.identity "sing-box runs as rosetun-engine with exactly its three capabilities" identity

    files() {
        passed engine.identity || { fail_reason="no session under the engines' account to test with"; return 1; }
        local folder expected config as_engine
        for folder in "/run/rosetun/private 710" "/run/rosetun/private/sing-box 750" "/run/rosetun/private/xray 750"; do
            expected="${folder##* } root rosetun-engine"
            [ "$(stat -c '%a %U %G' -- "${folder% *}")" = "$expected" ] ||
                { fail_reason="${folder% *} is $(stat -c '%a %U %G' -- "${folder% *}"), not $expected"; return 1; }
        done
        config=$(find /run/rosetun/private/sing-box -maxdepth 1 -type f -name '*.json' | head -n 1)
        [ -n "$config" ] || { fail_reason="no configuration in the engines' folder"; return 1; }
        as_engine=(setpriv --reuid=rosetun-engine --regid=rosetun-engine --clear-groups --)
        "${as_engine[@]}" test -r "$config" || { fail_reason="the engines' account cannot read $config"; return 1; }
        ! "${as_engine[@]}" test -w "$config" || { fail_reason="the engines' account can change $config"; return 1; }
        ! "${as_engine[@]}" test -w /run/rosetun/private/sing-box || { fail_reason="the engines' account can write its folder"; return 1; }
        ! setpriv --reuid="$(uid_of "$USER_A")" --regid="$(gid_of "$USER_A")" --init-groups -- test -r "$config" ||
            { fail_reason="$USER_A can read the engine's configuration"; return 1; }
        disconnect
    }
    check engine.files "the engine reads its configuration and writes nothing, an ordinary account does not get in" files
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
    flush_restored() {
        passed killswitch.tunnel-passes || { fail_reason="no kill-switch session to test through"; return 1; }
        flush_and_wait_restored || return 1
        expect_blocked "HTTPS to $PROBE_ADDRESS on $PHYS after the flush" direct_https || return 1
        cli 15 status
        printf '%s\n' "$CLI_OUT" | grep -q '^firewall rules: another program changed them; put back' ||
            { fail_reason="status does not say the rules were put back: $CLI_OUT"; return 1; }
        journalctl -b -u rosetun-helper.service --no-pager 2>/dev/null | grep -q 'another program changed the table' ||
            { fail_reason="the journal does not say the table was put back"; return 1; }
        [[ $(state_line) =~ ^Connected ]] || { fail_reason="the session did not stay Connected"; return 1; }
    }
    check killswitch.flush-restored "the table came back, the direct path was refused, the journal and status said so" flush_restored
    check killswitch.disconnect "the table went away and the direct path answered" disconnect_removes
}

# engine_capabilities MASK: sing-box holds exactly these, in the three sets.
engine_capabilities() {
    local mask=$1 pid status set
    pid=$(pgrep -x sing-box | head -n 1)
    [ -n "$pid" ] || { fail_reason="no sing-box process"; return 1; }
    status=$(cat "/proc/$pid/status")
    for set in CapPrm CapEff CapAmb; do
        printf '%s\n' "$status" | grep -qP "^$set:\t0*$mask$" ||
            { fail_reason="sing-box has $(printf '%s\n' "$status" | grep "^$set:"), not $mask"; return 1; }
    done
}

# route_of ACCOUNT PROGRAM: how PROGRAM's HTTPS request to the probe address left,
# run as ACCOUNT: "direct" when a connection to it was opened out of the physical
# interface, "tunnel" when it answered and none was. A tunnelled request reaches that
# interface addressed to the node, and its own packets go out of the tunnel's, so
# neither counts. Only the opening packet counts: sing-box closes an earlier request's
# direct connection after that curl has exited, into this one's count.
route_of() {
    local account=$1 program=$2 family=ip rc packets
    [[ $PROBE_ADDRESS == *:* ]] && family=ip6
    "$NFT" -f - <<EOF || { printf 'no counter table'; return 0; }
table inet $COUNT_TABLE {
	chain output {
		type filter hook output priority -300; policy accept;
		oifname "$PHYS" $family daddr $PROBE_ADDRESS tcp flags & (syn | ack) == syn counter
	}
}
EOF
    timeout --kill-after=3 25 setpriv --reuid="$(uid_of "$account")" --regid="$(gid_of "$account")" --init-groups \
        --reset-env -- "$program" -s -o /dev/null --connect-timeout 5 --max-time 15 "https://$PROBE_ADDRESS/" </dev/null
    rc=$?
    packets=$("$NFT" list table inet "$COUNT_TABLE" | grep -oP 'counter packets \K[0-9]+')
    "$NFT" delete table inet "$COUNT_TABLE"
    if ! reached_rc "$rc" || [ "$rc" -ge 124 ]; then
        printf 'no answer (exit %s)' "$rc"
    elif [ "${packets:-0}" -gt 0 ]; then
        printf 'direct'
    else
        printf 'tunnel'
    fi
}

expect_route() {
    local what=$1 account=$2 program=$3 wanted=$4 route
    route=$(route_of "$account" "$program")
    [ "$route" = "$wanted" ] || { fail_reason="$what: $route, not $wanted"; return 1; }
}

# apply_guarded REQUEST MASK: applies REQUEST and probes the direct path until it
# returns. The engine has to be a new process holding MASK, and no probe may get out.
apply_guarded() {
    local request=$1 mask=$2 before after apply_pid probes=0 rc
    before=$(pgrep -x sing-box | head -n 1)
    install -m 0600 -o "$(uid_of "$USER_A")" -g "$(gid_of "$USER_A")" -- "$ART/$request" "$RUN/work-$USER_A/$request"
    (cd "$RUN/work-$USER_A" && timeout --kill-after=3 120 setpriv --reuid="$(uid_of "$USER_A")" \
        --regid="$(gid_of "$USER_A")" --init-groups --reset-env -- /usr/bin/env NO_COLOR=1 "$CLI" apply "$request") \
        >/dev/null 2>&1 </dev/null &
    apply_pid=$!
    while kill -0 "$apply_pid" 2>/dev/null; do
        rc=$(curl_rc --connect-timeout 1 --max-time 2 --interface "$PHYS" "https://$PROBE_ADDRESS/")
        probes=$((probes + 1))
        if ! blocked_rc "$rc" || ! table_present; then
            wait "$apply_pid"
            fail_reason="applying $request: probe $probes got out (curl exit $rc) or the table went away"
            return 1
        fi
        sleep 0.2
    done
    wait "$apply_pid" || { fail_reason="applying $request failed"; return 1; }
    [ "$probes" -gt 0 ] || { fail_reason="applying $request ended before the first probe"; return 1; }
    wait_state '^Connected' 30 || return 1
    after=$(pgrep -x sing-box | head -n 1)
    [ -n "$after" ] && [ "$after" != "$before" ] || { fail_reason="applying $request did not restart sing-box"; return 1; }
    engine_capabilities "$mask" || return 1
    expect_blocked "HTTPS to $PROBE_ADDRESS on $PHYS after applying $request" direct_https
}

scenario_program_rules() {
    local other_dir curl_path other
    curl_path=$(command -v curl)
    other_dir=$(mktemp -d /var/tmp/rosetun-l3-program.XXXXXX)
    chmod 0755 "$other_dir"
    # The same binary, so only the program's path tells the two requests apart.
    other="$other_dir/l3-other-program"
    install -m 0755 -- "$curl_path" "$other"

    capabilities() {
        connect_with request-kill-switch.json || return 1
        engine_capabilities 3400 || return 1
        connect_with request-program-direct.json || return 1
        engine_capabilities 83404
    }
    check rules.capabilities "sing-box held 0x3400 without a rule by program and 0x83404 with one" capabilities

    direct_for_other_account() {
        [[ $(state_line) =~ ^Connected ]] || connect_with request-program-direct.json || return 1
        expect_route "curl of $USER_B" "$USER_B" "$curl_path" direct &&
            expect_route "another program of $USER_B" "$USER_B" "$other" tunnel
    }
    check rules.direct-other-account "another account's curl went direct and another program of that account through the tunnel" direct_for_other_account

    through_vpn_by_program() {
        connect_with request-program-proxy.json || return 1
        expect_route "curl of $USER_B" "$USER_B" "$curl_path" tunnel &&
            expect_route "another program of $USER_B" "$USER_B" "$other" direct
    }
    check rules.proxy-default-direct "with Direct by default another account's curl went through the tunnel and another program direct" through_vpn_by_program

    restart_guarded() {
        connect_with request-kill-switch.json || return 1
        apply_guarded request-program-direct.json 83404 &&
            apply_guarded request-kill-switch.json 3400
    }
    check rules.restart-guarded "adding and removing the rule restarted sing-box with its capabilities, every probe refused" restart_guarded

    # For the report: how often the search found nothing. It fails only when nothing was
    # found at all. The engine's INFO and DEBUG lines reach the journal because the
    # requests turn on the verbose log.
    local started found misses
    started=$(l2_now_ms)
    write_status running rules.search-misses
    found=$(journalctl -b -u rosetun-helper.service --no-pager 2>/dev/null | grep -c 'found process path')
    misses=$(journalctl -b -u rosetun-helper.service --no-pager 2>/dev/null | grep -cE 'process not found|find process path')
    if [ "$found" -gt 0 ]; then
        record rules.search-misses PASS "$found lookups found the program, $misses did not" "$started"
    else
        record rules.search-misses FAIL "the journal has no lookup that found a program ($misses did not)" "$started"
    fi

    disconnect
    rm -rf -- "$other_dir"
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
        expect_udp_dns_refused || return 1
        expect_reached "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https
    }
    check dnslock.direct-blocked "UDP 53 was refused locally, HTTPS answered" dns_lock
    dns_tunnel() {
        passed dnslock.direct-blocked || { fail_reason="no DNS-lock session to test through"; return 1; }
        [[ $(state_line) =~ ^Connected ]] || { fail_reason="the DNS-lock session is not Connected"; return 1; }
        system_dns_answers || { fail_reason="dig with the guest's resolver got no answer through the tunnel"; return 1; }
        disconnect
    }
    check dnslock.tunnel-passes "dig with the guest's resolver was answered through the tunnel" dns_tunnel
    dns_lock_unavailable() {
        # The helper trusts an nft binary only root can change, so this fails its
        # check and nothing else: sing-box does not run that binary.
        : >"$STATE/nft-untrusted"
        chmod o+w "$NFT" || { fail_reason="could not change the mode of $NFT"; return 1; }
        local rc=0
        connect_with request-dns-lock.json || rc=1
        chmod o-w "$NFT"
        rm -f -- "$STATE/nft-untrusted"
        [ "$rc" -eq 0 ] || return 1
        ! table_present || { fail_reason="the table is there though the lock could not go in"; return 1; }
        cli 15 status
        printf '%s\n' "$CLI_OUT" | grep -q '^protection: none' ||
            { fail_reason="status does not say nothing is in place: $CLI_OUT"; return 1; }
        printf '%s\n' "$CLI_OUT" | grep -q '^protection missing: DNS lock: the firewall is unavailable' ||
            { fail_reason="status does not name the missing lock and its reason: $CLI_OUT"; return 1; }
        expect_udp_dns_sent || return 1
        disconnect || return 1
        cli 15 status
        ! printf '%s\n' "$CLI_OUT" | grep -q '^protection missing' ||
            { fail_reason="status still names a missing lock after the disconnect: $CLI_OUT"; return 1; }
    }
    check dnslock.unavailable "the session connected without the lock, status named it and its reason, UDP 53 left" dns_lock_unavailable
    # The leak this records is the expected one, and what is checked is that the
    # status says so. The binary stays untrusted, or the restart would put the lock in.
    dns_lock_unavailable_restart() {
        local rc=0
        : >"$STATE/nft-untrusted"
        chmod o+w "$NFT" || { fail_reason="could not change the mode of $NFT"; return 1; }
        missing_through_restart || rc=1
        chmod o-w "$NFT"
        rm -f -- "$STATE/nft-untrusted"
        [ "$rc" -eq 0 ] || return 1
        disconnect
    }
    missing_through_restart() {
        says_lock_missing() {
            cli 15 status
            printf '%s\n' "$CLI_OUT" | grep -q '^protection missing: DNS lock: ' ||
                { fail_reason="status does not name the missing lock $1: $CLI_OUT"; return 1; }
        }
        connect_with request-dns-lock.json || return 1
        says_lock_missing "before the restart" || return 1
        pkill -KILL -x sing-box || { fail_reason="no sing-box process to kill"; return 1; }
        expect_udp_dns_sent || return 1
        says_lock_missing "during the restart" || return 1
        wait_state '^Connected' 60 || return 1
        says_lock_missing "after the restart"
    }
    check dnslock.unavailable-restart "UDP 53 left during the restart, as status said before, during and after" dns_lock_unavailable_restart
}

# ---------------------------------------------------------------- IPv6, inbound, forwarding

scenario_ipv6() {
    local id=ipv6.neighbor started router
    started=$(l2_now_ms)
    write_status running "$id"
    router=$(ip -6 route show default dev "$PHYS" 2>/dev/null | sed -n 's/.* via \(fe80:[0-9a-f:]*\) .*/\1/p' | head -n 1)
    if [ -z "$router" ]; then
        record "$id" SKIP "no IPv6 default router on $PHYS, so there is no neighbor to resolve" "$started"
        return
    fi
    if ! ping -6 -c 2 -W 2 "$router%$PHYS" >/dev/null 2>&1; then
        record "$id" SKIP "the IPv6 router $router does not answer a ping without Rosetun" "$started"
        return
    fi
    neighbor() {
        connect_with request-lan.json || return 1
        # Without a cache entry the ping needs neighbor discovery first.
        ip -6 neigh flush dev "$PHYS"
        ping -6 -c 2 -W 3 "$router%$PHYS" >/dev/null 2>&1 ||
            { fail_reason="the IPv6 router $router did not answer under the kill switch: $(ip -6 neigh show "$router" dev "$PHYS")"; return 1; }
        local out
        out=$(curl -v -s -o /dev/null --connect-timeout 3 --max-time 4 --interface "$PHYS" "tftp://[2001:db8::1]:69/rosetun-l3" 2>&1 </dev/null)
        printf '%s' "$out" | grep -q 'Operation not permitted' ||
            { fail_reason="a UDP datagram to 2001:db8::1 on $PHYS was not refused locally"; return 1; }
        disconnect
    }
    if neighbor; then
        record "$id" PASS "the router answered after the flush, 2001:db8::1 was refused" "$started"
    else
        record "$id" FAIL "${fail_reason:-the condition did not hold}" "$started"
    fi
    fail_reason=''
}

scenario_peer() {
    FORWARD_BEFORE=''
    inbound() {
        peer_up || return 1
        FORWARD_BEFORE=$(peer_https)
        # The peer opens a TCP session to sshd and reads its banner; once the
        # kill switch is up it sends its own and must get sshd's key exchange.
        rm -f -- "$STATE/peer-go" "$STATE/peer-banner" "$STATE/peer-answer"
        in_peer bash -c '
            exec 3<>"/dev/tcp/$1/22" || exit 1
            IFS= read -r -t 5 banner <&3 || exit 1
            printf "%s\n" "$banner" >"$2/peer-banner"
            for _ in $(seq 1 600); do [ -f "$2/peer-go" ] && break; sleep 0.2; done
            printf "SSH-2.0-rosetun-l3\r\n" >&3
            timeout 10 head -c 64 <&3 >"$2/peer-answer"
        ' peer-session "$PEER_HOST_ADDRESS" "$STATE" </dev/null >/dev/null 2>&1 &
        printf '%s\n' "$!" >"$STATE/peer-session.pid"
        local deadline=$((SECONDS + 10))
        while [ ! -s "$STATE/peer-banner" ] && [ "$SECONDS" -lt "$deadline" ]; do sleep 0.2; done
        grep -q '^SSH-' "$STATE/peer-banner" 2>/dev/null ||
            { fail_reason="the peer got no sshd banner from $PEER_HOST_ADDRESS without Rosetun"; return 1; }
        connect_with request-kill-switch.json || return 1
        : >"$STATE/peer-go"
        deadline=$((SECONDS + 15))
        while [ ! -s "$STATE/peer-answer" ] && [ "$SECONDS" -lt "$deadline" ]; do sleep 0.2; done
        [ -s "$STATE/peer-answer" ] ||
            { fail_reason="sshd's answer did not reach the peer under the kill switch"; return 1; }
        guest_to_peer_refused ||
            { fail_reason="the guest could send a new datagram to the peer under the kill switch"; return 1; }
    }
    check inbound.reply "the peer's session got sshd's answer, a datagram to the peer was refused" inbound

    forwarded() {
        [ -f "$STATE/peer" ] || { fail_reason="the peer namespace was not set up"; return 1; }
        reached_rc "$FORWARD_BEFORE" ||
            { fail_reason="the peer did not reach $PROBE_ADDRESS through the guest without Rosetun (curl exit $FORWARD_BEFORE); forwarding does not work here"; return 1; }
        [[ $(state_line) =~ ^Connected ]] || connect_with request-kill-switch.json || return 1
        local rc
        rc=$(peer_https)
        blocked_rc "$rc" || { fail_reason="forwarded HTTPS from the peer was not dropped (curl exit $rc)"; return 1; }
        disconnect || return 1
        rc=$(peer_https)
        reached_rc "$rc" || { fail_reason="forwarded HTTPS from the peer did not answer after the disconnect (curl exit $rc)"; return 1; }
    }
    check forward.blocked "forwarded HTTPS answered, was dropped under the kill switch, answered again" forwarded
    [[ $(state_line) =~ ^Disconnected ]] || cli 60 disconnect
    # What stays is the cleanup's to remove and report.
    peer_down
}

scenario_crash() {
    killed() {
        connect_with request-kill-switch.json || return 1
        kill_helper || return 1
        [ "$KILLED_TABLE_PRESENT" = 1 ] || { fail_reason="the table went away with the helper"; return 1; }
        blocked_rc "$KILLED_DIRECT_RC" || { fail_reason="HTTPS to $PROBE_ADDRESS on $PHYS was not refused after the crash (curl exit $KILLED_DIRECT_RC)"; return 1; }
        printf '%s\n' "$CLI_OUT" | grep -q '^network: held closed' || { fail_reason="status does not report the network held closed: $CLI_OUT"; return 1; }
        printf '%s\n' "$CLI_OUT" | grep -q '^protection: network held closed after a service crash' || { fail_reason="status does not call it the hold after a crash: $CLI_OUT"; return 1; }
        table_present || { fail_reason="the restarted helper removed the table"; return 1; }
        expect_blocked "HTTPS to $PROBE_ADDRESS on $PHYS during the hold" direct_https || return 1
        # Past the service's first checks: nobody but the service touched the table.
        sleep 5
        cli 15 status
        ! printf '%s\n' "$CLI_OUT" | grep -q '^firewall rules: another program' ||
            { fail_reason="status blames another program for the service's own rules: $CLI_OUT"; return 1; }
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

    dns_lock_killed() {
        connect_with request-dns-lock.json || return 1
        table_present || { fail_reason="no table: the DNS lock is not installed"; return 1; }
        kill_helper || return 1
        [ "$KILLED_TABLE_PRESENT" = 1 ] || { fail_reason="the table went away with the helper, before the restart"; return 1; }
        ! printf '%s\n' "$CLI_OUT" | grep -q '^network: held closed' || { fail_reason="status reports the network held closed after a DNS-lock crash"; return 1; }
        ! table_present || { fail_reason="the restarted helper kept the DNS lock's table"; return 1; }
        journalctl -b -u rosetun-helper.service --no-pager 2>/dev/null | grep -q 'removed the DNS lock a crashed helper left' ||
            { fail_reason="the journal does not say that the DNS lock was removed"; return 1; }
        expect_udp_dns_sent || return 1
        expect_reached "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https
    }
    check crash.dns-lock-killed "the restarted helper removed the DNS lock and said so, UDP 53 left" dns_lock_killed

    five_kills() {
        local round leaf=/system.slice/rosetun-helper.service
        connect_with request-kill-switch.json || return 1
        for round in 1 2 3 4 5; do
            kill_helper || { fail_reason="round $round: $fail_reason"; return 1; }
            [ "$KILLED_TABLE_PRESENT" = 1 ] || { fail_reason="round $round: the table went away with the helper"; return 1; }
            blocked_rc "$KILLED_DIRECT_RC" ||
                { fail_reason="round $round: HTTPS on $PHYS was not refused right after the kill (curl exit $KILLED_DIRECT_RC)"; return 1; }
            expect_blocked "HTTPS to $PROBE_ADDRESS on $PHYS in round $round" direct_https ||
                { fail_reason="round $round: $fail_reason"; return 1; }
        done
        # The service has settled: the same connect as ever, with this start's cgroups.
        sleep 15
        connect_with request-kill-switch.json || return 1
        expect_reached "HTTPS through the tunnel" tunnel_https || return 1
        expect_blocked "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https || return 1
        "$NFT" list table inet rosetun | grep -q "${leaf#/}/engines" ||
            { fail_reason="the rules do not name the engines' cgroup"; return 1; }
        [ "$(cat "/proc/$(pgrep -x sing-box | head -n 1)/cgroup")" = "0::$leaf/engines" ] ||
            { fail_reason="sing-box is not in the cgroup the rules name"; return 1; }
        disconnect || return 1
        expect_reached "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https
    }
    check crash.five-kills "closed through five kills; then a connect works under rules with the current cgroups" five_kills
}

scenario_upgrade_restart() {
    upgraded() {
        disconnect || return 1
        local watch=rosetun-l3-upgrade pid packets rc=0
        if ! "$NFT" -f - <<EOF
 table inet $watch {
     chain postrouting {
         type filter hook postrouting priority 300; policy accept;
         oifname "$PHYS" ip daddr $PROBE_ADDRESS counter
     }
 }
EOF
        then fail_reason="cannot install upgrade counter"; return 1; fi
        # Prove the counter sees real direct traffic before relying on zero.
        direct_https
        packets=$("$NFT" list table inet "$watch" | sed -n 's/.*counter packets \([0-9]*\).*/\1/p')
        "$NFT" delete table inet "$watch"
        [ "${packets:-0}" -gt 0 ] || { fail_reason="upgrade counter saw no baseline traffic"; return 1; }
        connect_with request-kill-switch.json || return 1
        if ! "$NFT" -f - <<EOF
 table inet $watch {
     chain postrouting {
         type filter hook postrouting priority 300; policy accept;
         oifname "$PHYS" ip daddr $PROBE_ADDRESS counter
     }
 }
EOF
        then fail_reason="cannot install upgrade counter"; return 1; fi
        : >"$STATE/upgrade-watch"
        (
            while [ -e "$STATE/upgrade-watch" ]; do
                direct_https
                curl -s -o /dev/null --connect-timeout 1 --max-time 1 "https://$PROBE_ADDRESS/" </dev/null
            done
        ) &
        pid=$!
        # Atomic replacement matches pacman's unlink/extract behavior, avoiding
        # ETXTBSY while the old helper and engine still have their inodes open.
        for program in rosetun-helper-privileged rosetun sing-box; do
            install -m 0755 -o root -g root "$ART/$program" "$PREFIX/$program.new" &&
                mv -f "$PREFIX/$program.new" "$PREFIX/$program" || rc=1
        done
        if [ "$rc" -eq 0 ]; then
            timeout "$UNIT_TIMEOUT_SECONDS" "$PREFIX/rosetun-helper-privileged" --restart-for-upgrade >"$REPORT/upgrade-restart.txt" 2>&1 || rc=1
            # A repeated request must retain the hold as well.
            timeout "$UNIT_TIMEOUT_SECONDS" "$PREFIX/rosetun-helper-privileged" --restart-for-upgrade >>"$REPORT/upgrade-restart.txt" 2>&1 || rc=1
        fi
        rm -f "$STATE/upgrade-watch"
        wait "$pid" || true
        packets=$("$NFT" list table inet "$watch" | sed -n 's/.*counter packets \([0-9]*\).*/\1/p')
        "$NFT" delete table inet "$watch"
        [ "$rc" -eq 0 ] || { fail_reason="file replacement or upgrade restart failed"; return 1; }
        [ "${packets:-missing}" = 0 ] || { fail_reason="upgrade leaked $packets packets"; return 1; }
        cli 15 status
        printf '%s\n' "$CLI_OUT" | grep -q '^network: held closed' || { fail_reason="upgrade hold not reported"; return 1; }
        connect_with request-kill-switch.json || return 1
        expect_reached "HTTPS through the tunnel after upgrade" tunnel_https || return 1
        disconnect
    }
    check upgrade.restart "no direct packets during file replacement and two upgrade restarts; reconnect works" upgraded
    idle_restart() {
        disconnect || return 1
        timeout "$UNIT_TIMEOUT_SECONDS" "$PREFIX/rosetun-helper-privileged" --restart-for-upgrade >"$REPORT/upgrade-idle.txt" 2>&1 || return 1
        grep -q 'network was not held closed' "$REPORT/upgrade-idle.txt" || return 1
        expect_reached "direct HTTPS after an idle upgrade restart" direct_https
    }
    check upgrade.unprotected "an unprotected restart keeps direct egress available" idle_restart
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
    if [ -f "$STATE/nft-untrusted" ]; then
        chmod o-w "$NFT" && rm -f -- "$STATE/nft-untrusted" && note "gave $NFT its mode back" || problem "could not give $NFT its mode back"
    fi
    if [ -f "$STATE/peer" ]; then
        peer_down && note "removed the peer namespace" || problem "could not remove the peer namespace $PEER_NS, its NAT table or routing rule"
    fi
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
    l2_remove_engine_account "$STATE" && note "removed the engines' account" || problem "could not remove the engines' account"
    rm -f -- "$STATE/installed"
}

finalize() {
    exec 8>"$STATE/finalize.lock"
    flock 8
    [ -f "$REPORT/report.json" ] && return 0
    local started_cleanup
    started_cleanup=$(l2_now_ms)
    # The host restores the checkpoint after the run, so it fetches this copy.
    if [ -f "$STATE/installed" ]; then
        journalctl -b -u rosetun-helper.service --no-pager -o short-monotonic 2>/dev/null | tail -n 400 |
            LC_ALL=C tr -c '\n -~' '?' | l2_atomic_write "$REPORT/helper-journal.txt" 0644
    fi
    rm -f "$STATE/upgrade-watch"
    "$NFT" delete table inet rosetun-l3-upgrade 2>/dev/null || true
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
        SCENARIO_TIMEOUT_SECONDS UNIT_TIMEOUT_SECONDS JOB_TIMEOUT_SECONDS HOST_ADDRESS NODE_PORT PROBE_ADDRESS DNS_PROBE_ADDRESS || return 1
    l2_valid_run_id "$RUN_ID" || { echo "invalid run id" >&2; return 1; }
    [ "$(basename -- "$RUN")" = "$RUN_ID" ] || { echo "run directory does not match the run id" >&2; return 1; }
    [[ $HOST_ADDRESS =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "invalid host address" >&2; return 1; }
    [[ $PROBE_ADDRESS =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "invalid probe address" >&2; return 1; }
    [[ $DNS_PROBE_ADDRESS =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "invalid DNS probe address" >&2; return 1; }
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
        scenario_protection_reported
        scenario_engine
        scenario_kill_switch
        scenario_program_rules
        scenario_lan_on
        scenario_dns_lock
        scenario_ipv6
        scenario_peer
        scenario_crash
        scenario_upgrade_restart
        scenario_stop
    fi
    skip_rest "an earlier step failed; see the first FAIL"
else
    skip_rest "a preflight check failed, nothing was installed"
fi
exit 0
