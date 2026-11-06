#!/bin/bash
# Runs the system proxy scenarios inside the guest, as root, from a systemd transient
# unit started by start.sh: the real helper as the systemd service in the proxy mode,
# with and without its strict kill switch, sharing, Lockdown, and the GUI's module for
# the desktop's settings. The stand has no KDE session to run the GUI in. It never
# depends on the SSH session that started it.
#
#   run-proxy.sh run RUN_DIR        install the service, run every scenario, clean up,
#                                   write the report
#   run-proxy.sh finalize RUN_DIR   clean up and close the report if `run` never got to
#                                   (ExecStopPost of the unit: the job was killed or timed out)
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
case $mode in run | finalize) ;; *) echo "usage: run-proxy.sh run|finalize RUN_DIR" >&2; exit 64 ;; esac
[ -d "$RUN" ] || { echo "run directory $RUN is missing" >&2; exit 64; }
RUN=$(cd -- "$RUN" && pwd -P)

STATE=$RUN/state
REPORT=$RUN/report
ART=$RUN/artifacts
SCENARIOS=$RUN/scenarios-proxy.tsv
RESULTS=$STATE/results.jsonl

PREFIX=/usr/lib/rosetun
LOCKDOWN_UNIT_FILE=/usr/lib/systemd/system/rosetun-lockdown.service
# What the requests of this stage say.
PROXY_PORT=10808
TUN_NAME=rosetun0
UNIT_FILE=/usr/lib/systemd/system/rosetun-helper.service
CLI=$PREFIX/rosetun
NFT=/usr/sbin/nft
FOREIGN_TABLE=rosetun-l3-foreign
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
        command -v python3 >/dev/null && command -v ss >/dev/null || { fail_reason="python3 or ss is missing"; return 1; }
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

# ---------------------------------------------------------------- the proxy mode

proxy_rc() { curl_rc --max-time 15 --proxy "http://$1:$PROXY_PORT" "https://$PROBE_ADDRESS/"; }
through_proxy() { proxy_rc 127.0.0.1; }

# The addresses something listens on at the proxy's port, one a line.
listening_on() {
    ss -Hltn "sport = :$PROXY_PORT" 2>/dev/null | awk '{ print $4 }' | sed 's/:[0-9]*$//; s/^\[//; s/\]$//; s/%.*$//' | LC_ALL=C sort -u
}

phys_address() {
    ip -4 -o addr show dev "$PHYS" scope global 2>/dev/null | awk '{ print $4 }' | cut -d/ -f1 | head -n 1
}

no_adapter() {
    [ ! -e "/sys/class/net/$TUN_NAME" ] || { fail_reason="the adapter $TUN_NAME exists in the proxy mode"; return 1; }
}

scenario_plain() {
    plain() {
        connect_with request-proxy.json || return 1
        no_adapter || return 1
        ! table_present || { fail_reason="the table is there without the kill switch"; return 1; }
        expect_reached "HTTPS through the proxy" through_proxy
    }
    check proxy.through "connected without an adapter or a table, and the proxy answered" plain
    around() { expect_reached "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https; }
    check proxy.around-open "a request around the proxy went out by itself" around
    loopback_only() {
        local where
        where=$(listening_on)
        [ "$where" = 127.0.0.1 ] || { fail_reason="the proxy listens on: $(printf '%s' "$where" | tr '\n' ' ')"; return 1; }
    }
    check proxy.loopback-only "only 127.0.0.1 listens" loopback_only
}

scenario_busy() {
    busy() {
        disconnect || return 1
        python3 -c "import socket,time;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',$PROXY_PORT));s.listen();time.sleep(60)" &
        local holder=$! rc=0 deadline=$((SECONDS + 15))
        # A fixed wait lost to a slow first start of Python: the connect then found the
        # port free, and that looked like the service ignoring a taken port.
        until listening_on | grep -qxF 127.0.0.1; do
            if [ "$SECONDS" -ge "$deadline" ] || ! kill -0 "$holder" 2>/dev/null; then
                kill "$holder" 2>/dev/null
                wait "$holder" 2>/dev/null
                fail_reason="the stand's program did not take port $PROXY_PORT"
                return 1
            fi
            sleep 0.2
        done
        install -m 0600 -o "$(uid_of "$USER_A")" -g "$(gid_of "$USER_A")" -- "$ART/request-proxy-strict.json" "$RUN/work-$USER_A/request-proxy-strict.json"
        cli 120 connect request-proxy-strict.json
        if [ "$CLI_RC" -eq 0 ]; then
            fail_reason="the connect succeeded with the port taken"; rc=1
        elif ! printf '%s' "$CLI_OUT" | grep -q "$PROXY_PORT"; then
            fail_reason="the error does not name the port: $(cli_error)"; rc=1
        elif table_present; then
            fail_reason="the table went up for a connect that could not start"; rc=1
        fi
        kill "$holder" 2>/dev/null
        wait "$holder" 2>/dev/null
        cli 60 disconnect
        return "$rc"
    }
    check proxy.port-busy "the connect failed naming the port, with no table" busy
}

scenario_strict() {
    connected() {
        connect_with request-proxy-strict.json || return 1
        no_adapter || return 1
        table_present || { fail_reason="no table with the kill switch"; return 1; }
        expect_reached "HTTPS through the proxy" through_proxy
    }
    check strict.through "the kill switch stood, without an adapter, and the proxy answered" connected
    around() { expect_blocked "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https; }
    check strict.around-blocked "a request around the proxy was refused" around
    no_lock() {
        "$NFT" list table inet rosetun | grep -q 'oif "'"$TUN_NAME"'"' && { fail_reason="the table permits a tunnel"; return 1; }
        return 0
    }
    check strict.first-phase "the table has no second phase" no_lock
    engine_killed() {
        local pid rc
        pid=$(pgrep -f "$PREFIX/sing-box" | head -n 1)
        [ -n "$pid" ] || { fail_reason="no engine to kill"; return 1; }
        kill -9 "$pid"
        rc=$(direct_https)
        blocked_rc "$rc" || { fail_reason="the direct path answered while the engine was down (curl $rc)"; return 1; }
        wait_state '^Connected' 60 || return 1
        sleep 2
        expect_reached "HTTPS through the proxy" through_proxy &&
            expect_blocked "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https
    }
    check strict.engine-killed "the path stayed refused through an engine restart" engine_killed
    gone() {
        disconnect || return 1
        ! table_present || { fail_reason="the table stayed after a disconnect"; return 1; }
        expect_reached "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https
    }
    check strict.disconnect "a disconnect removed the table and the direct path answered" gone
}

scenario_mode_change() {
    change() {
        connect_with request-kill-switch.json || return 1
        install -m 0600 -o "$(uid_of "$USER_A")" -g "$(gid_of "$USER_A")" -- "$ART/request-proxy-strict.json" "$RUN/work-$USER_A/request-proxy-strict.json"
        cli 120 apply request-proxy-strict.json
        [ "$CLI_RC" -eq 0 ] || { fail_reason="apply failed: $(cli_error)"; return 1; }
        wait_state '^Connected' 30 || return 1
        table_present || { fail_reason="the table was gone after the change"; return 1; }
        no_adapter || return 1
        expect_blocked "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https || return 1
        expect_reached "HTTPS through the proxy" through_proxy || return 1
        cli 120 apply request-kill-switch.json
        [ "$CLI_RC" -eq 0 ] || { fail_reason="apply back failed: $(cli_error)"; return 1; }
        wait_state '^Connected' 30 || return 1
        [ -e "/sys/class/net/$TUN_NAME" ] || { fail_reason="the adapter did not come back"; return 1; }
        expect_blocked "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https
    }
    check mode.change "TUN to the proxy and back through apply, the table up throughout" change
}

scenario_share() {
    local own
    own=$(phys_address)
    shared() {
        connect_with request-proxy-share.json || return 1
        listening_on | grep -qxF "$own" || { fail_reason="nothing listens on $own: $(listening_on | tr '\n' ' ')"; return 1; }
        rosetun_private "$own" || { fail_reason="$own is not a private address, so the check says nothing"; return 1; }
        local rc
        rc=$(proxy_rc "$own")
        reached_rc "$rc" || { fail_reason="the proxy on $own did not answer (curl $rc)"; return 1; }
    }
    check share.listens "the shared proxy listens on the physical interface's address and answers there" shared
    not_on_software() {
        listening_on | grep -qxF "$PEER_HOST_ADDRESS" && { fail_reason="the proxy listens on the peer's link"; return 1; }
        listening_on | grep -qE '^(0\.0\.0\.0|::|\*)$' && { fail_reason="the proxy listens on a wildcard"; return 1; }
        peer_up || return 1
        local rc
        rc=$(in_peer curl -s -o /dev/null --connect-timeout 3 --max-time 8 --proxy "http://$PEER_HOST_ADDRESS:$PROXY_PORT" "https://$PROBE_ADDRESS/" </dev/null; printf '%s' "$?")
        blocked_rc "$rc" || { fail_reason="the peer got through (curl $rc)"; return 1; }
    }
    check share.peer-refused "a peer behind a software link does not reach the proxy" not_on_software
    unshared() {
        connect_with request-proxy.json || return 1
        listening_on | grep -qxF "$own" && { fail_reason="the proxy still listens on $own"; return 1; }
        return 0
    }
    check share.off "with the switch off nothing listens on the physical interface's address" unshared
    disconnect
}

# Only for a check above: 10/8, 172.16/12, 192.168/16.
rosetun_private() {
    [[ $1 =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.) ]]
}

scenario_lockdown() {
    lockdown_cli() {
        CLI_OUT=$("$CLI" lockdown "$@" </dev/null 2>&1) && return 0
        fail_reason="rosetun lockdown $*: $(printf '%s' "$CLI_OUT" | sed 's/\x1b\[[0-9;]*m//g' | tail -n 1)"
        return 1
    }
    closed() {
        install -m 0644 -o root -g root "$ART/rosetun-lockdown.service" "$LOCKDOWN_UNIT_FILE" &&
            systemctl daemon-reload && systemctl enable --quiet rosetun-lockdown.service ||
            { fail_reason="installing the Lockdown unit failed"; return 1; }
        : >"$STATE/lockdown-unit"
        # The service reads what it can offer once, when it starts, and it started
        # before this stage enabled the unit.
        timeout "$UNIT_TIMEOUT_SECONDS" systemctl restart rosetun-helper.service ||
            { fail_reason="the service did not start again with the Lockdown unit enabled"; return 1; }
        lockdown_cli on --lan off || return 1
        connect_with request-proxy-share.json || return 1
        expect_reached "HTTPS through the proxy" through_proxy || return 1
        expect_blocked "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https || return 1
        listening_on | grep -qxF "$(phys_address)" && { fail_reason="sharing is on without Lockdown's local network"; return 1; }
        return 0
    }
    check lockdown.share-closed "without its local network Lockdown keeps the proxy on loopback" closed
    opened() {
        disconnect || return 1
        lockdown_cli on --lan on || return 1
        connect_with request-proxy-share.json || return 1
        listening_on | grep -qxF "$(phys_address)" || { fail_reason="sharing stayed off with Lockdown's local network"; return 1; }
        "$NFT" list table inet rosetun | grep -q 'ip saddr {' || { fail_reason="the input chain takes no private range"; return 1; }
    }
    check lockdown.share-open "with its local network the proxy is shared and the input chain takes the private ranges" opened
    off() {
        disconnect || return 1
        lockdown_cli off || return 1
        ! table_present || { fail_reason="the table stayed after Lockdown went off"; return 1; }
    }
    check lockdown.off "Lockdown went off with the session" off
}

# The module the GUI uses, as the first account with a KDE desktop of its own:
# the stand has no KDE session to run the GUI in.
desktop_tool() {
    local home=$RUN/work-$USER_A/home
    (cd "$RUN/work-$USER_A" && timeout --kill-after=3 30 setpriv --reuid="$(uid_of "$USER_A")" \
        --regid="$(gid_of "$USER_A")" --init-groups --reset-env -- /usr/bin/env \
        HOME="$home" XDG_CONFIG_HOME="$home/.config" XDG_CURRENT_DESKTOP=KDE \
        "$ART/desktop_proxy" "$@" </dev/null 2>/dev/null)
}

scenario_desktop() {
    local home=$RUN/work-$USER_A/home record=$RUN/work-$USER_A/home/desktop-proxy.json
    local file=$home/.config/kioslaverc
    install -d -m 0700 -o "$(uid_of "$USER_A")" -g "$(gid_of "$USER_A")" "$home" "$home/.config"
    printf '[Proxy Settings]\nProxyType=2\nProxy Config Script=http://proxy.example.com/wpad.dat\n\n[Other]\nKept=yes\n' >"$file"
    chown "$(uid_of "$USER_A"):$(gid_of "$USER_A")" "$file"
    set_ours() {
        [ "$(desktop_tool set "$record" "$PROXY_PORT")" = Applied ] || { fail_reason="the tool did not apply"; return 1; }
        grep -qx 'ProxyType=1' "$file" && grep -qxF "httpProxy=http://127.0.0.1 $PROXY_PORT" "$file" &&
            grep -qxF "socksProxy=socks://127.0.0.1 $PROXY_PORT" "$file" && grep -qx 'Kept=yes' "$file" ||
            { fail_reason="kioslaverc does not hold the proxy and the other keys"; return 1; }
    }
    check desktop.set "kioslaverc holds the local proxy, and other keys stayed" set_ours
    back() {
        [ "$(desktop_tool restore "$record")" = Restored ] || { fail_reason="the tool did not restore"; return 1; }
        grep -qx 'ProxyType=2' "$file" && ! grep -q '^httpProxy=' "$file" && grep -q '^Proxy Config Script=' "$file" ||
            { fail_reason="kioslaverc did not come back"; return 1; }
    }
    check desktop.restore "kioslaverc came back after a disconnect" back
    crashed() {
        # The tool exits without restoring, which is what kill -9 leaves behind.
        [ "$(desktop_tool set "$record" "$PROXY_PORT")" = Applied ] || { fail_reason="the tool did not apply"; return 1; }
        [ -f "$record" ] || { fail_reason="no record outlived the process"; return 1; }
        back
    }
    check desktop.crash "the next start restored what a killed process left" crashed
    foreign() {
        desktop_tool set "$record" "$PROXY_PORT" >/dev/null
        sed -i 's|^httpProxy=.*|httpProxy=http://proxy.example.com 3128|' "$file"
        [ "$(desktop_tool restore "$record")" = LeftAsTheyAre ] || { fail_reason="the tool touched settings not its own"; return 1; }
        grep -qxF 'httpProxy=http://proxy.example.com 3128' "$file" || { fail_reason="the setting changed by hand is gone"; return 1; }
    }
    check desktop.foreign "settings changed by hand stayed" foreign
}

scenario_stop() {
    stopped() {
        connect_with request-proxy-strict.json || return 1
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
    if [ -f "$STATE/lockdown-unit" ]; then
        "$CLI" lockdown off </dev/null >/dev/null 2>&1
        systemctl disable --quiet rosetun-lockdown.service 2>/dev/null
        rm -f -- "$LOCKDOWN_UNIT_FILE" "$STATE/lockdown-unit" && note "removed the Lockdown unit"
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
        scenario_plain
        scenario_busy
        scenario_strict
        scenario_mode_change
        scenario_share
        scenario_lockdown
        scenario_desktop
        scenario_stop
    fi
    skip_rest "an earlier step failed; see the first FAIL"
else
    skip_rest "a preflight check failed, nothing was installed"
fi
exit 0
