#!/bin/bash
# Runs the Linux L5 scenarios inside the guest, as root: the real package. It
# installs the previous .deb, upgrades it to the new one during a kill-switch
# session and under Lockdown, and removes and purges it, with a removal that
# cannot take Lockdown off.
#
#   run-l5.sh run RUN_DIR        the scenarios, then finalize
#   run-l5.sh finalize RUN_DIR   clean up and close the report if `run` never got to
#                                (ExecStopPost)
#
# Both packages come from one commit and differ in version: the first package
# ever published has no predecessor to take the upgrade from, and dpkg runs the
# outgoing package's prerm, which is the code under test. Lockdown stays on with
# the local network, so the host's SSH keeps working on the Default Switch.

set -u
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C DEBIAN_FRONTEND=noninteractive
umask 022

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=lib.sh
. "$here/lib.sh"

mode=${1-}
RUN=${2-}
case $mode in run | finalize) ;; *) echo "usage: run-l5.sh run|finalize RUN_DIR" >&2; exit 64 ;; esac
[ -d "$RUN" ] || { echo "run directory $RUN is missing" >&2; exit 64; }
RUN=$(cd -- "$RUN" && pwd -P)

STATE=$RUN/state
REPORT=$RUN/report
ART=$RUN/artifacts
SCENARIOS=$RUN/scenarios-l5.tsv
RESULTS=$STATE/results.jsonl

PREFIX=/usr/lib/rosetun
UNIT_FILE=/usr/lib/systemd/system/rosetun-helper.service
CLI=$PREFIX/rosetun
HELPER=$PREFIX/rosetun-helper-privileged
NFT=/usr/sbin/nft
RECORD=/var/lib/rosetun/lockdown
SERVICE_LEAF=/sys/fs/cgroup/system.slice/rosetun-helper.service
OLD_DEB=$ART/rosetun-old.deb
NEW_DEB=$ART/rosetun-new.deb
# A counter after every filter of the output path, never a verdict: what a
# firewall dropped does not get here, so one packet counted is one packet out.
WATCH_TABLE=rosetun-l5-watch

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
# The resolver the guest is configured with, as a user's program asks it.
system_dns_answers() {
    dig +time=3 +tries=2 example.com A 2>&1 | grep -q 'status: NOERROR'
}

main_pid() { systemctl show -p MainPID --value rosetun-helper.service 2>/dev/null; }

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
        if dpkg-query -W -f='${Status}' rosetun 2>/dev/null | grep -q 'install\|config-files'; then
            fail_reason="the package rosetun is known to dpkg already"
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
        command -v dpkg >/dev/null || { fail_reason="dpkg is missing"; return 1; }
        [ -f /sys/fs/cgroup/cgroup.controllers ] || { fail_reason="cgroup v2 is not mounted"; return 1; }
    }
    check preflight.tools "nft, curl, dig, dpkg and cgroup v2 present" pre_tools

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

# ---------------------------------------------------------------- package

package_version() { dpkg-deb -f "$1" Version; }
installed_version() { dpkg-query -W -f='${Version}' rosetun 2>/dev/null; }
installed_cleanly() { [ "$(dpkg-query -W -f='${db:Status-Abbrev}' rosetun 2>/dev/null)" = 'ii ' ]; }

# dpkg_run ARGS...: dpkg's output in DPKG_OUT, its exit code in DPKG_RC.
dpkg_run() {
    DPKG_OUT=$(timeout --kill-after=10 "$UNIT_TIMEOUT_SECONDS" dpkg "$@" 2>&1 </dev/null)
    DPKG_RC=$?
}

install_package() {
    local package=$1 wanted
    wanted=$(package_version "$package")
    dpkg_run -i "$package"
    if [ "$DPKG_RC" -ne 0 ]; then
        fail_reason="dpkg -i failed ($DPKG_RC): $(printf '%s' "$DPKG_OUT" | tail -n 4 | tr '\n' ' ')"
        return 1
    fi
    [ "$(installed_version)" = "$wanted" ] && installed_cleanly ||
        { fail_reason="dpkg reports $(installed_version), wanted $wanted, installed cleanly"; return 1; }
}

wait_service_answers() {
    local deadline=$((SECONDS + 30))
    while [ "$SECONDS" -lt "$deadline" ]; do
        cli 15 status
        [ "$CLI_RC" -eq 0 ] && return 0
        sleep 1
    done
    fail_reason="the service does not answer: $CLI_OUT"
    return 1
}

status_says() { cli 15 status; printf '%s\n' "$CLI_OUT" | grep -qF -- "$1"; }

lockdown_on() {
    local out
    if ! out=$("$CLI" lockdown on --lan on 2>&1 </dev/null); then
        fail_reason="rosetun lockdown on failed: $out"
        return 1
    fi
    status_says 'lockdown: on' || { fail_reason="status does not say Lockdown is on: $CLI_OUT"; return 1; }
    [ -f "$RECORD" ] || { fail_reason="Lockdown's record is missing"; return 1; }
}

watch_up() {
    : >"$STATE/watch"
    "$NFT" -f - <<EOF
table inet $WATCH_TABLE {
	chain postrouting {
		type filter hook postrouting priority 300; policy accept;
		oifname "$PHYS" ip daddr $PROBE_ADDRESS log prefix "rosetun-l5-watch: " flags skuid counter
	}
}
EOF
}

watch_down() {
    "$NFT" delete table inet "$WATCH_TABLE" 2>/dev/null
    ! "$NFT" list table inet "$WATCH_TABLE" >/dev/null 2>&1
}

# Back to zero. `nft reset counters` is for named counters and leaves a rule's alone;
# `reset rules` needs a newer nft than a stand may have. A new table works on all.
watch_zero() {
    watch_down && watch_up && [ "$(watch_packets)" = 0 ]
}

# Who sent what the counter saw since the kernel log's time $1, for the report:
# account, protocol and port with a count, and when the first and the last left. Short,
# as a reason keeps 300 characters; the lines go to the report's folder as well.
watch_senders() {
    local lines="$REPORT/watch-packets.txt"
    journalctl -k -b --no-pager -o short-monotonic --since "@$1" 2>/dev/null | grep 'rosetun-l5-watch: ' >"$lines"
    [ -s "$lines" ] || { printf 'the kernel log has none of them'; return 0; }
    printf '%s; first %s, last %s, started %s' \
        "$(grep -oE 'PROTO=[A-Z0-9]+( |.* )DPT=[0-9]+|UID=[0-9]+' "$lines" | sed 's/ .* / /' | paste -d' ' - - |
            sort | uniq -c | sort -rn | head -n 3 | sed 's/^ *//' | paste -sd, -)" \
        "$(sed -n '1s/^\[ *\([0-9.]*\)\].*/\1/p' "$lines")" "$(sed -n '$s/^\[ *\([0-9.]*\)\].*/\1/p' "$lines")" \
        "$(cut -d' ' -f1 /proc/uptime)"
}

watch_packets() {
    "$NFT" list table inet "$WATCH_TABLE" 2>/dev/null | sed -n 's/.*counter packets \([0-9]*\).*/\1/p' | head -n 1
}

# Keeps asking for the probe both ways while dpkg works, and notes each moment
# the table is gone. The attempts themselves are what the counter would see.
# With the tunnel gone the route leads out of the physical interface again.
tunnel_blocked_https() { curl_rc "https://$PROBE_ADDRESS/"; }

prober() {
    while [ ! -e "$STATE/prober-stop" ]; do
        curl -s -o /dev/null --connect-timeout 1 --max-time 1 --interface "$PHYS" "https://$PROBE_ADDRESS/" </dev/null
        curl -s -o /dev/null --connect-timeout 1 --max-time 1 "https://$PROBE_ADDRESS/" </dev/null
        printf '.' >>"$STATE/prober-attempts"
        table_present || printf '.' >>"$STATE/prober-no-table"
    done
}

# ---------------------------------------------------------------- scenarios

scenario_install() {
    do_package() {
        : >"$STATE/installed"
        install_package "$OLD_DEB"
    }
    check install.package "the previous package is installed" do_package
    passed install.package || return 0

    do_service() {
        systemctl --quiet is-active rosetun-helper.service || { fail_reason="the service is not running"; return 1; }
        systemctl --quiet is-enabled rosetun-helper.service || { fail_reason="the service is not enabled"; return 1; }
        systemctl --quiet is-enabled rosetun-lockdown.service || { fail_reason="the boot unit is not enabled"; return 1; }
        getent group rosetun >/dev/null || { fail_reason="group rosetun does not exist"; return 1; }
        local own program
        own=$(cat "/proc/$(main_pid)/cgroup" 2>/dev/null)
        [ "$own" = "0::/system.slice/rosetun-helper.service/helper" ] || { fail_reason="the helper is in '$own', not in its leaf"; return 1; }
        [ -d "$SERVICE_LEAF/engines" ] || { fail_reason="the engines' leaf does not exist"; return 1; }
        for program in rosetun rosetun-gui rosetun-helper-privileged sing-box xray; do
            [ "$(stat -c '%U %a' -- "$PREFIX/$program")" = 'root 755' ] || { fail_reason="$program is not root's with mode 0755"; return 1; }
        done
        [ "$(readlink -f /usr/bin/rosetun)" = "$CLI" ] || { fail_reason="/usr/bin/rosetun does not lead to the CLI"; return 1; }
        [ ! -e "$RECORD" ] || { fail_reason="Lockdown's record exists on a new installation"; return 1; }
        table_present && { fail_reason="the table exists on a new installation"; return 1; }
        install -d -m 0700 -o "$(uid_of "$USER_A")" -g "$(gid_of "$USER_A")" "$RUN/work-$USER_A"
        wait_service_answers
    }
    check install.service "the service, the boot unit and the group" do_service

    do_desktop() {
        local size
        desktop-file-validate /usr/share/applications/rosetun.desktop 2>/dev/null
        [ "$?" -ne 1 ] || { fail_reason="the menu entry does not validate"; return 1; }
        grep -q '^x-scheme-handler/rosetun=.*rosetun\.desktop' /usr/share/applications/mimeinfo.cache 2>/dev/null ||
            { fail_reason="the desktop database has no rosetun:// handler (is desktop-file-utils installed?)"; return 1; }
        for size in 16 22 24 32 48 64 96 128 256 512; do
            [ -f "/usr/share/icons/hicolor/${size}x$size/apps/rosetun.png" ] || { fail_reason="no $size px icon"; return 1; }
        done
        [ -f /usr/share/icons/hicolor/scalable/apps/rosetun.svg ] || { fail_reason="no scalable icon"; return 1; }
        [ -f /usr/share/polkit-1/actions/io.github.eoftgge.rosetun.policy ] || { fail_reason="no polkit policy"; return 1; }
        [ -f /usr/share/polkit-1/rules.d/50-rosetun-engine.rules ] || { fail_reason="no polkit rule for the engines' account"; return 1; }
        getent passwd rosetun-engine >/dev/null || { fail_reason="the package did not make the engines' account"; return 1; }
        [ -s /usr/share/doc/rosetun/copyright ] || { fail_reason="no copyright file"; return 1; }
    }
    check install.desktop "the menu entry, the handler, the icons and the policy" do_desktop

    do_repeat() {
        local before version
        before=$(main_pid)
        version=$(installed_version)
        /var/lib/dpkg/info/rosetun.postinst configure "" >/dev/null 2>&1 || { fail_reason="postinst configure failed"; return 1; }
        /var/lib/dpkg/info/rosetun.postinst configure "$version" >/dev/null 2>&1 || { fail_reason="postinst configure failed the second time"; return 1; }
        [ "$(main_pid)" = "$before" ] || { fail_reason="the helper was restarted: an ordinary stop would open the network"; return 1; }
    }
    check install.repeat "the helper keeps its process" do_repeat
}

scenario_upgrade() {
    do_watch() {
        local packets
        watch_up || { fail_reason="could not load the counter"; return 1; }
        direct_https >/dev/null
        packets=$(watch_packets)
        [ "${packets:-0}" -gt 0 ] || { fail_reason="HTTPS to the probe was not counted"; return 1; }
        watch_zero || { fail_reason="could not bring the counter back to zero"; return 1; }
    }
    check upgrade.watch "the counter works" do_watch
    passed upgrade.watch || return 0

    do_no_leak() {
        local prober_pid packets attempts missing since
        connect_with request-kill-switch.json || return 1
        table_present || { fail_reason="a kill-switch session has no table"; return 1; }
        watch_zero || { fail_reason="could not bring the counter back to zero"; return 1; }
        since=$(date +%s)
        rm -f -- "$STATE/prober-stop" "$STATE/prober-attempts" "$STATE/prober-no-table"
        prober &
        prober_pid=$!
        install_package "$NEW_DEB"
        local installed=$?
        : >"$STATE/prober-stop"
        wait "$prober_pid"
        [ "$installed" -eq 0 ] || return 1
        packets=$(watch_packets)
        attempts=$(stat -c %s -- "$STATE/prober-attempts" 2>/dev/null || echo 0)
        missing=$(stat -c %s -- "$STATE/prober-no-table" 2>/dev/null || echo 0)
        [ "$attempts" -gt 0 ] || { fail_reason="the prober made no attempt during the upgrade"; return 1; }
        [ "$missing" -eq 0 ] || { fail_reason="the table was gone at $missing of $attempts looks"; return 1; }
        [ "${packets:-1}" -eq 0 ] || { fail_reason="$packets packets past the tunnel: $(watch_senders "$since")"; return 1; }
    }
    check upgrade.kill-switch-no-leak "the table stayed and nothing left past the tunnel" do_no_leak
    passed upgrade.kill-switch-no-leak || return 0

    do_hold() {
        wait_service_answers || return 1
        status_says 'network: held closed' || { fail_reason="the new service reports no hold: $CLI_OUT"; return 1; }
        [ ! -e /run/rosetun/upgrading ] || { fail_reason="the upgrade's marker is still there"; return 1; }
        expect_blocked "HTTPS on $PHYS" direct_https || return 1
        expect_blocked "HTTPS by the route" tunnel_blocked_https || return 1
    }
    check upgrade.kill-switch-hold "the hold, closed both ways" do_hold

    do_reconnect() {
        install -m 0600 -o "$(uid_of "$USER_A")" -g "$(gid_of "$USER_A")" -- "$ART/request-kill-switch.json" "$RUN/work-$USER_A/request-kill-switch.json"
        cli 120 connect request-kill-switch.json
        [ "$CLI_RC" -eq 0 ] || { fail_reason="connect failed: $(cli_error)"; return 1; }
        wait_state '^Connected' 30 || return 1
        status_says 'network: held closed' && { fail_reason="the hold outlived the connect"; return 1; }
        expect_reached "HTTPS through the tunnel" tunnel_https || return 1
        disconnect || return 1
        table_present && { fail_reason="the table outlived the disconnect"; return 1; }
        expect_reached "HTTPS on $PHYS after the disconnect" direct_https
    }
    check upgrade.reconnect "connect lifts the hold, disconnect opens the network" do_reconnect

    do_lockdown() {
        install_package "$OLD_DEB" || return 1
        wait_service_answers || return 1
        lockdown_on || return 1
        install_package "$NEW_DEB" || return 1
        wait_service_answers || return 1
        status_says 'lockdown: on' || { fail_reason="Lockdown is off after the upgrade: $CLI_OUT"; return 1; }
        status_says 'network: held closed' && { fail_reason="Lockdown is reported as the hold"; return 1; }
        [ -f "$RECORD" ] || { fail_reason="the record is gone"; return 1; }
        table_present || { fail_reason="the table is gone"; return 1; }
        expect_blocked "HTTPS on $PHYS" direct_https
    }
    check upgrade.lockdown "Lockdown survives the upgrade" do_lockdown
}

scenario_remove() {
    do_refused() {
        mount --bind /usr/bin/false "$NFT" || { fail_reason="could not put the failing nft in place"; return 1; }
        : >"$STATE/nft-mounted"
        dpkg_run -r rosetun
        umount "$NFT" && rm -f -- "$STATE/nft-mounted"
        [ "$DPKG_RC" -ne 0 ] || { fail_reason="dpkg --remove succeeded although Lockdown could not be removed"; return 1; }
        printf '%s' "$DPKG_OUT" | grep -q 'rosetun reset-firewall' || { fail_reason="the way out was not printed: $DPKG_OUT"; return 1; }
        [ -x "$HELPER" ] && [ -x "$CLI" ] || { fail_reason="the programs were removed"; return 1; }
        installed_cleanly || { fail_reason="dpkg reports the state '$(dpkg-query -W -f='${db:Status-Abbrev}' rosetun)'"; return 1; }
        [ -f "$RECORD" ] || { fail_reason="the record is gone"; return 1; }
        table_present || { fail_reason="the table is gone"; return 1; }
        expect_blocked "HTTPS on $PHYS" direct_https
    }
    check remove.refused "the removal stopped and the network stayed closed" do_refused

    do_remove() {
        dpkg_run -r rosetun
        [ "$DPKG_RC" -eq 0 ] || { fail_reason="dpkg --remove failed ($DPKG_RC): $(printf '%s' "$DPKG_OUT" | tail -n 4 | tr '\n' ' ')"; return 1; }
        [ ! -e "$PREFIX" ] || { fail_reason="$PREFIX is still there"; return 1; }
        [ ! -e "$UNIT_FILE" ] || { fail_reason="the unit file is still there"; return 1; }
        systemctl --quiet is-active rosetun-helper.service && { fail_reason="the service still runs"; return 1; }
        table_present && { fail_reason="the table is still there"; return 1; }
        [ ! -e "$RECORD" ] || { fail_reason="the record is still there"; return 1; }
        expect_reached "HTTPS on $PHYS" direct_https
    }
    check remove.lockdown "the network is open, the programs are gone" do_remove

    do_purge() {
        dpkg_run -P rosetun
        [ "$DPKG_RC" -eq 0 ] || { fail_reason="dpkg --purge failed ($DPKG_RC): $(printf '%s' "$DPKG_OUT" | tail -n 4 | tr '\n' ' ')"; return 1; }
        [ ! -e /var/lib/rosetun ] || { fail_reason="/var/lib/rosetun is still there"; return 1; }
        getent group rosetun >/dev/null || { fail_reason="the group was removed"; return 1; }
        dpkg-query -W rosetun >/dev/null 2>&1 && { fail_reason="dpkg still knows the package"; return 1; }
        if find /etc/systemd/system -name 'rosetun-*' ! -name 'rosetun-l2-*' 2>/dev/null | grep -q .; then
            fail_reason="a unit link or mask is left in /etc/systemd/system"
            return 1
        fi
    }
    check purge.state "/var/lib/rosetun is gone, the group stays" do_purge
}

cleanup() {
    L2_CLEANUP_STATUS=PASS L2_CLEANUP_ACTIONS='' L2_CLEANUP_PROBLEMS=''
    note() { L2_CLEANUP_ACTIONS="$L2_CLEANUP_ACTIONS${L2_CLEANUP_ACTIONS:+; }$1"; }
    problem() { L2_CLEANUP_PROBLEMS="$L2_CLEANUP_PROBLEMS${L2_CLEANUP_PROBLEMS:+; }$1"; L2_CLEANUP_STATUS=ERROR; }
    : >"$STATE/prober-stop"
    if [ -f "$STATE/nft-mounted" ]; then
        umount "$NFT" && rm -f -- "$STATE/nft-mounted" && note "restored nft" || problem "could not restore $NFT"
    fi
    if [ -f "$STATE/watch" ]; then
        watch_down && rm -f -- "$STATE/watch" && note "removed the counter" || problem "could not remove the table inet $WATCH_TABLE"
    fi
    [ -f "$STATE/installed" ] || return 0
    # Lockdown or a hold may be on: the package's own way out, then its removal.
    if [ -x "$HELPER" ]; then
        timeout 90 "$HELPER" --reset-firewall >/dev/null 2>&1 && note "reset the firewall" || problem "reset-firewall failed"
    fi
    if timeout 120 dpkg -P rosetun >/dev/null 2>&1; then
        note "purged the package"
    else
        problem "could not purge the package; restore the checkpoint"
    fi
    if [ -x "$NFT" ] && table_present; then
        problem "the table inet rosetun is still there; restore the checkpoint"
    fi
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
    if [ -f "$STATE/phys.env" ]; then PHYS=$(sed -n 's/^PHYS=//p' "$STATE/phys.env"); fi
    scenario_install
    if passed install.service; then
        scenario_upgrade
        if installed_cleanly && passed upgrade.lockdown; then
            scenario_remove
        fi
    fi
    skip_rest "an earlier step failed; see the first FAIL"
else
    skip_rest "a preflight check failed, nothing was installed"
fi
exit 0
