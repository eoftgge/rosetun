#!/bin/bash
# Runs the Linux L4 scenarios inside the guest, as root: Lockdown on the real
# service. Phase one runs from the transient unit start.sh made, like L3; it ends
# with a reboot. A stand unit (rosetun-l2-resume.service) runs the phases after
# each reboot, and another (rosetun-l2-early.service) looks at the table early in
# boot, after rosetun-lockdown.service and before any network manager. Two
# reboots: with Lockdown's record, then without it.
#
#   run-l4.sh run RUN_DIR        phase one: install, Lockdown without a reboot, reboot
#   run-l4.sh resume RUN_DIR     after a reboot (rosetun-l2-resume.service)
#   run-l4.sh early RUN_DIR      early in boot (rosetun-l2-early.service): notes the table
#   run-l4.sh finalize RUN_DIR   clean up and close the report if a phase never got to
#                                (ExecStopPost, or the end of the last phase)
#
# Lockdown without "Local network" cuts the host's SSH (the Default Switch is a
# private network): the job never needs SSH, the host only polls and keeps polling
# while it cannot connect. Every phase that turns Lockdown on without the local
# network turns the local network back on before its next step, and the cleanup
# removes Lockdown (`rosetun-helper-privileged --reset-firewall`) before the report
# is closed, so the host can always read it in the end. If the guest stays out of
# reach, the host's wait runs out and its checkpoint restore removes everything.

set -u
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
umask 022

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=lib.sh
. "$here/lib.sh"

mode=${1-}
RUN=${2-}
case $mode in run | resume | early | finalize) ;; *) echo "usage: run-l4.sh run|resume|early|finalize RUN_DIR" >&2; exit 64 ;; esac
[ -d "$RUN" ] || { echo "run directory $RUN is missing" >&2; exit 64; }
RUN=$(cd -- "$RUN" && pwd -P)

STATE=$RUN/state
REPORT=$RUN/report
ART=$RUN/artifacts
SCENARIOS=$RUN/scenarios-l4.tsv
RESULTS=$STATE/results.jsonl

PREFIX=/usr/lib/rosetun
UNIT_DIR=/usr/lib/systemd/system
UNIT_FILE=$UNIT_DIR/rosetun-helper.service
LOCKDOWN_UNIT_FILE=$UNIT_DIR/rosetun-lockdown.service
POLICY_FILE=/usr/share/polkit-1/actions/io.github.eoftgge.rosetun.policy
EARLY_UNIT=rosetun-l2-early.service
RESUME_UNIT=rosetun-l2-resume.service
STAND_UNIT_DIR=/etc/systemd/system
CLI=$PREFIX/rosetun
HELPER=$PREFIX/rosetun-helper-privileged
NFT=/usr/sbin/nft
RECORD=/var/lib/rosetun/lockdown
# The peer: a namespace on a veth pair with link-local addresses, which are part
# of "Local network" (and of no real network), so the local network decides
# whether it may reach the guest.
PEER_NS=rosetun-l4-peer
PEER_HOST_IF=rl4-host
PEER_IF=rl4-peer
PEER_HOST_ADDRESS=169.254.77.1
PEER_ADDRESS=169.254.77.2
NETWORK_MANAGERS=(NetworkManager.service systemd-networkd.service networking.service)

RUN_ID='' STAND_ID='' EXPECTED_BOOT_ID='' USER_A='' USER_B='' BIOS_GUID=''
HOST_ADDRESS='' NODE_PORT='' PROBE_ADDRESS='' DNS_PROBE_ADDRESS=''
SCENARIO_TIMEOUT_SECONDS=30 UNIT_TIMEOUT_SECONDS=180 JOB_TIMEOUT_SECONDS=3000
EXPECTED_ARCH=x86_64
PHYS=''

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

# as_user SECONDS COMMAND...: the first account, with its user manager's runtime
# folder, as a program of its desktop session would run. The limit is in here
# because timeout runs programs and cannot run this function.
as_user() {
    local seconds=$1 uid
    shift
    uid=$(uid_of "$USER_A")
    timeout --kill-after=3 "$seconds" setpriv --reuid="$uid" --regid="$(gid_of "$USER_A")" --init-groups --reset-env -- \
        /usr/bin/env XDG_RUNTIME_DIR="/run/user/$uid" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
        NO_COLOR=1 "$@"
}

# cli SECONDS COMMAND...: the CLI as the first account; output in CLI_OUT.
cli() {
    local seconds=$1
    shift
    CLI_OUT=$(cd "$RUN/work-$USER_A" && as_user "$seconds" "$CLI" "$@" 2>&1 </dev/null)
    CLI_RC=$?
    CLI_OUT=$(printf '%s' "$CLI_OUT" | sed 's/\x1b\[[0-9;]*m//g')
}

# cli_root SECONDS COMMAND...: the CLI as root, as `sudo rosetun ...`.
cli_root() {
    local seconds=$1
    shift
    CLI_OUT=$(timeout --kill-after=3 "$seconds" /usr/bin/env -i PATH="$PATH" NO_COLOR=1 "$CLI" "$@" 2>&1 </dev/null)
    CLI_RC=$?
    CLI_OUT=$(printf '%s' "$CLI_OUT" | sed 's/\x1b\[[0-9;]*m//g')
}

cli_error() {
    local line
    line=$(printf '%s\n' "$CLI_OUT" | grep -E ' ERROR ' | tail -n 1 | sed 's/^[0-9T:.Z-]* *//')
    printf '%s' "${line:-$CLI_OUT}"
}

state_line() {
    cli 15 status
    printf '%s\n' "$CLI_OUT" | sed -n 's/^state: //p' | head -n 1
}

lockdown_line() {
    cli 15 status
    printf '%s\n' "$CLI_OUT" | sed -n 's/^lockdown: //p' | head -n 1
}

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

curl_rc() {
    curl -s -o /dev/null --connect-timeout 3 --max-time 8 "$@" </dev/null
    printf '%s' "$?"
}

blocked_rc() { [ "$1" = 7 ] || [ "$1" = 28 ]; }
reached_rc() { ! blocked_rc "$1" && [ "$1" != 45 ] && [ "$1" != 2 ]; }

direct_https() { curl_rc --interface "$PHYS" "https://$PROBE_ADDRESS/"; }
# Without --interface: the route the system picks (the tunnel during a session).
routed_https() { curl_rc --max-time 15 "https://$PROBE_ADDRESS/"; }

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

# in_scope UNIT SHELL_COMMAND: the first account runs a shell command in a user
# scope of that name, as the GUI and the CLI put themselves in theirs. The
# command's last output line is its result.
in_scope() {
    as_user 60 /usr/bin/systemd-run --user --scope --quiet --collect \
        --slice=app.slice --unit="$1" -- /bin/sh -c "$2" 2>&1 </dev/null | tail -n 1
}

# scope_line "RC COUNT": whether a probe's last line holds its two numbers. Any
# other text is systemd-run's error, which must not pass for a curl result.
scope_line() { [[ $1 =~ ^[0-9]+\ [0-9]+$ ]]; }

# What a program in the scope gets, all in one run of the scope: a scope made
# again is a new cgroup, with a new ID the table does not name until the next
# hello. So `rosetun status` first (its hello makes the service look for the
# scope), then HTTPS on the physical interface, and one UDP datagram to port 53
# there, with the lines of curl's trace that say the output hook refused it: curl
# retries, so a refusal prints more than once. Fails when the scope did
# not run; a scope of the same name must be gone before the next can be made.
scope_probe() {
    local unit=$1 uid line deadline=$((SECONDS + 15))
    uid=$(uid_of "$USER_A")
    while [ -e "/sys/fs/cgroup/user.slice/user-$uid.slice/user@$uid.service/app.slice/$unit.scope" ]; do
        [ "$SECONDS" -lt "$deadline" ] || { fail_reason="$unit.scope of the last probe is still there"; return 1; }
        sleep 1
    done
    line=$(in_scope "$unit" "$CLI status >/dev/null 2>&1; curl -s -o /dev/null --connect-timeout 3 --max-time 8 --interface $PHYS https://$PROBE_ADDRESS/ </dev/null; https=\$?; dns=\$(curl -v -s -o /dev/null --connect-timeout 3 --max-time 4 --interface $PHYS tftp://$DNS_PROBE_ADDRESS:53/rosetun-l4 2>&1 </dev/null | grep -c 'Operation not permitted'); echo \"\$https \$dns\"")
    scope_line "$line" || { fail_reason="$unit.scope did not run: $line"; return 1; }
    SCOPE_HTTPS=${line%% *}
    SCOPE_DNS=${line##* }
}

# A process of the same account outside any permitted scope.
user_direct_https() {
    as_user 20 /usr/bin/curl -s -o /dev/null --connect-timeout 3 --max-time 8 --interface "$PHYS" "https://$PROBE_ADDRESS/" </dev/null
    printf '%s' "$?"
}

main_pid() { systemctl show -p MainPID --value rosetun-helper.service 2>/dev/null; }

# Waits until the helper answers `rosetun status`.
helper_answers() {
    local deadline=$((SECONDS + 30))
    while [ "$SECONDS" -lt "$deadline" ]; do
        cli 15 status
        [ "$CLI_RC" -eq 0 ] && return 0
        sleep 1
    done
    fail_reason="the helper does not answer: $CLI_OUT"
    return 1
}

lockdown_as_root() {
    cli_root 60 lockdown "$@"
    [ "$CLI_RC" -eq 0 ] || { fail_reason="sudo rosetun lockdown $* failed: $CLI_OUT"; return 1; }
}

in_peer() { ip netns exec "$PEER_NS" "$@"; }

# The peer opens TCP to the guest's sshd and reads its banner.
peer_reaches_ssh() {
    in_peer timeout 8 bash -c "exec 3<>/dev/tcp/$PEER_HOST_ADDRESS/22 && head -c 4 <&3" 2>/dev/null | grep -q '^SSH-'
}

peer_up() {
    : >"$STATE/peer"
    ip netns add "$PEER_NS" &&
        ip link add "$PEER_HOST_IF" type veth peer name "$PEER_IF" netns "$PEER_NS" &&
        ip addr add "$PEER_HOST_ADDRESS/30" dev "$PEER_HOST_IF" &&
        ip link set "$PEER_HOST_IF" up &&
        in_peer ip link set lo up &&
        in_peer ip addr add "$PEER_ADDRESS/30" dev "$PEER_IF" &&
        in_peer ip link set "$PEER_IF" up ||
        { fail_reason="could not set up the peer namespace"; return 1; }
}

peer_down() {
    [ -f "$STATE/peer" ] || return 0
    ip link del "$PEER_HOST_IF" 2>/dev/null
    ip netns del "$PEER_NS" 2>/dev/null
    if ip netns list 2>/dev/null | grep -qw -- "$PEER_NS" || ip link show "$PEER_HOST_IF" >/dev/null 2>&1; then
        return 1
    fi
    rm -f -- "$STATE/peer"
}

# ---------------------------------------------------------------- phase one

scenario_preflight() {
    pre_identity() {
        local stand bios
        stand=$(cat "$L2_STAND_ID_FILE" 2>/dev/null)
        [ -n "$stand" ] && [ "$stand" = "$STAND_ID" ] || { fail_reason="stand id file $L2_STAND_ID_FILE does not match the requested stand"; return 1; }
        [ "$(boot_id)" = "$EXPECTED_BOOT_ID" ] || { fail_reason="boot id changed since the host connected"; return 1; }
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
        local path
        if systemctl list-units --all --no-legend 'rosetun*' 2>/dev/null | grep -v 'rosetun-l2-' | grep -q .; then
            fail_reason="a rosetun systemd unit is present; restore the clean checkpoint"
            return 1
        fi
        pgrep -x rosetun-helper-privileged >/dev/null 2>&1 && { fail_reason="a helper process runs"; return 1; }
        for path in "$PREFIX" "$UNIT_FILE" "$LOCKDOWN_UNIT_FILE" "$POLICY_FILE" "$STAND_UNIT_DIR/$EARLY_UNIT" \
            "$STAND_UNIT_DIR/$RESUME_UNIT" /run/rosetun /var/lib/rosetun; do
            [ ! -e "$path" ] || { fail_reason="$path exists; the stand installs only on a clean guest"; return 1; }
        done
        if [ -x "$NFT" ] && table_present; then
            fail_reason="the table inet rosetun exists already"
            return 1
        fi
        if [ "$(loginctl show-user "$USER_A" -p Linger --value 2>/dev/null)" = yes ]; then
            fail_reason="$USER_A already lingers; the stand turns it on and off itself"
            return 1
        fi
        if ip netns list 2>/dev/null | grep -qw -- "$PEER_NS" || ip link show "$PEER_HOST_IF" >/dev/null 2>&1; then
            fail_reason="the peer namespace $PEER_NS or its link $PEER_HOST_IF exists already"
            return 1
        fi
    }
    check preflight.no-foreign-service "nothing of Rosetun is installed or running" pre_service

    pre_tools() {
        [ -x "$NFT" ] || { fail_reason="$NFT is missing (apt-get install nftables)"; return 1; }
        command -v curl >/dev/null || { fail_reason="curl is missing"; return 1; }
        curl -V 2>/dev/null | grep -qw tftp || { fail_reason="curl was built without tftp, which the UDP 53 checks use"; return 1; }
        [ -x /usr/bin/systemd-run ] || { fail_reason="/usr/bin/systemd-run is missing"; return 1; }
        [ -f /usr/lib/systemd/user/dbus.socket ] || { fail_reason="the user bus is missing (apt-get install dbus-user-session)"; return 1; }
        command -v sshd >/dev/null || [ -x /usr/sbin/sshd ] || { fail_reason="sshd is missing"; return 1; }
        [ -f /sys/fs/cgroup/cgroup.controllers ] || { fail_reason="cgroup v2 is not mounted"; return 1; }
    }
    check preflight.tools "nft, curl with tftp, systemd-run, the user bus, sshd and cgroup v2 present" pre_tools

    pre_baseline() {
        PHYS=$(ip -o route get "$PROBE_ADDRESS" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p')
        [[ $PHYS =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || { fail_reason="no route to $PROBE_ADDRESS"; return 1; }
        printf 'PHYS=%s\n' "$PHYS" >"$STATE/phys.env"
        expect_reached "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https
    }
    check preflight.baseline "the probe answers HTTPS on the physical interface" pre_baseline
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

stand_units() {
    cat >"$STAND_UNIT_DIR/$EARLY_UNIT" <<EOF
# Rosetun Linux L4 stand (test infrastructure): looks at the table early in boot.
[Unit]
Description=Rosetun Linux L4 stand: the table at boot (test infrastructure)
DefaultDependencies=no
RequiresMountsFor=$RUN
After=rosetun-lockdown.service
Wants=network-pre.target
Before=network-pre.target

[Service]
Type=oneshot
ExecStart=/bin/bash $RUN/guest/run-l4.sh early $RUN

[Install]
WantedBy=sysinit.target
EOF
    cat >"$STAND_UNIT_DIR/$RESUME_UNIT" <<EOF
# Rosetun Linux L4 stand (test infrastructure): the scenarios after a reboot.
[Unit]
Description=Rosetun Linux L4 stand: after a reboot (test infrastructure)
Wants=network-online.target
After=network-online.target

[Service]
Type=exec
KillMode=control-group
TimeoutStopSec=120
RuntimeMaxSec=$JOB_TIMEOUT_SECONDS
ExecStart=/bin/bash $RUN/guest/run-l4.sh resume $RUN
ExecStopPost=/bin/bash $RUN/guest/run-l4.sh finalize $RUN

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$STAND_UNIT_DIR/$EARLY_UNIT" "$STAND_UNIT_DIR/$RESUME_UNIT"
}

scenario_install() {
    do_install() {
        : >"$STATE/installed"
        install -d -m 0755 -o root -g root "$PREFIX" &&
            install -m 0755 -o root -g root "$ART/rosetun-helper-privileged" "$ART/rosetun" "$ART/sing-box" "$PREFIX/" &&
            install -m 0755 -o root -g root "$ART/rosetun" "$PREFIX/rosetun-gui" &&
            install -m 0644 -o root -g root "$ART/rosetun-helper.service" "$UNIT_FILE" &&
            install -m 0644 -o root -g root "$ART/rosetun-lockdown.service" "$LOCKDOWN_UNIT_FILE" ||
            { fail_reason="installing the files failed"; return 1; }
        stand_units
        : >"$STATE/stand-units"
        systemctl daemon-reload &&
            systemctl enable --quiet rosetun-lockdown.service "$EARLY_UNIT" &&
            timeout "$UNIT_TIMEOUT_SECONDS" systemctl start rosetun-helper.service ||
            { fail_reason="the units did not start: $(systemctl status --no-pager rosetun-helper.service 2>&1 | tail -n 3)"; return 1; }
        loginctl enable-linger "$USER_A" && : >"$STATE/linger" || { fail_reason="could not start $USER_A's user manager"; return 1; }
        local uid deadline
        uid=$(uid_of "$USER_A")
        deadline=$((SECONDS + 30))
        until [ -S "/run/user/$uid/bus" ] || [ "$SECONDS" -ge "$deadline" ]; do sleep 1; done
        [ -S "/run/user/$uid/bus" ] || { fail_reason="$USER_A's user bus did not appear"; return 1; }
        install -d -m 0700 -o "$uid" -g "$(gid_of "$USER_A")" "$RUN/work-$USER_A"
        helper_answers || return 1
        cli 15 lockdown off
        printf '%s\n' "$CLI_OUT" | grep -q 'not available' && { fail_reason="the helper does not offer Lockdown: $CLI_OUT"; return 1; }
        [[ $(lockdown_line) == off ]] || { fail_reason="Lockdown is on before anyone turned it on: $CLI_OUT"; return 1; }
    }
    check install.service "the units run, the boot unit is enabled, the helper offers Lockdown" do_install
}

scenario_enable() {
    denied() {
        cli 30 lockdown on
        [ "$CLI_RC" -ne 0 ] || { fail_reason="an ordinary account turned Lockdown on"; return 1; }
        printf '%s\n' "$CLI_OUT" | grep -q 'only root' || { fail_reason="the refusal does not say who may: $CLI_OUT"; return 1; }
        [[ $(lockdown_line) == off ]] && ! table_present && [ ! -e "$RECORD" ] || { fail_reason="something changed anyway"; return 1; }
    }
    check lockdown.denied "an ordinary account is refused and nothing changes" denied

    turned_on() {
        lockdown_as_root on --lan off || return 1
        [[ $(lockdown_line) == on ]] || { fail_reason="status does not say Lockdown is on: $CLI_OUT"; return 1; }
        [ "$(stat -c '%u %a' -- "$RECORD" 2>/dev/null)" = "0 600" ] || { fail_reason="the record is missing or not root's alone"; return 1; }
        "$NFT" list table inet rosetun 2>/dev/null | grep -q 'hook input' || { fail_reason="the table has no input chain"; return 1; }
        expect_blocked "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https || return 1
        expect_blocked "HTTPS to $PROBE_ADDRESS by the route" routed_https
    }
    check lockdown.direct-blocked "Lockdown is on, recorded root-only, and the direct path is refused" turned_on
    passed lockdown.direct-blocked || return

    gui_scope() {
        scope_probe rosetun-gui || return 1
        reached_rc "$SCOPE_HTTPS" || { fail_reason="HTTPS from rosetun-gui.scope did not answer (curl exit '$SCOPE_HTTPS')"; return 1; }
        [ "$SCOPE_DNS" = 0 ] || { fail_reason="UDP 53 from rosetun-gui.scope was refused ($SCOPE_DNS refusals in curl's trace)"; return 1; }
    }
    check lockdown.gui-scope "the GUI's scope gets HTTPS and DNS out of the physical interface" gui_scope

    cli_scope() {
        scope_probe rosetun-cli || return 1
        reached_rc "$SCOPE_HTTPS" || { fail_reason="HTTPS from rosetun-cli.scope did not answer (curl exit '$SCOPE_HTTPS')"; return 1; }
        [ "$SCOPE_DNS" = 0 ] || { fail_reason="UDP 53 from rosetun-cli.scope was refused ($SCOPE_DNS refusals in curl's trace)"; return 1; }
    }
    check lockdown.cli-scope "the CLI's scope gets HTTPS and DNS out of the physical interface" cli_scope

    others() {
        expect_blocked "HTTPS from $USER_A outside a scope" user_direct_https || return 1
        scope_probe rosetun-other || return 1
        blocked_rc "$SCOPE_HTTPS" || { fail_reason="HTTPS from rosetun-other.scope was not refused (curl exit '$SCOPE_HTTPS')"; return 1; }
        [ "$SCOPE_DNS" -ge 1 ] || { fail_reason="UDP 53 from rosetun-other.scope was not refused ($SCOPE_DNS refusals in curl's trace)"; return 1; }
    }
    check lockdown.other-process "the same account outside the two scopes is refused" others

    inbound_closed() {
        peer_up || return 1
        ! peer_reaches_ssh || { fail_reason="the peer reached sshd under Lockdown without the local network"; return 1; }
    }
    check inbound.closed "without the local network the peer does not reach sshd" inbound_closed

    # From here on the local network stays on: the host's SSH comes back.
    inbound_lan() {
        lockdown_as_root on --lan on || return 1
        peer_reaches_ssh || { fail_reason="the peer did not reach sshd with the local network"; return 1; }
        expect_blocked "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https
    }
    check inbound.lan-open "with the local network the peer reaches sshd, the internet stays closed" inbound_lan
    peer_down
}

scenario_session() {
    session() {
        connect_with request-dns-lock.json || return 1
        expect_reached "HTTPS through the tunnel" routed_https || return 1
        expect_blocked "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https || return 1
        "$NFT" list table inet rosetun 2>/dev/null | grep -q 'policy drop' || { fail_reason="the session under Lockdown is not all-traffic"; return 1; }
    }
    check lockdown.session "a session without the kill switch connects, gets the kill switch and the tunnel answers" session

    scope_closed() {
        scope_probe rosetun-gui || return 1
        blocked_rc "$SCOPE_HTTPS" || { fail_reason="HTTPS from rosetun-gui.scope on $PHYS was not refused during the session (curl exit '$SCOPE_HTTPS')"; return 1; }
    }
    check lockdown.session-scope-closed "during the session the GUI's scope does not get past the tunnel" scope_closed

    after() {
        disconnect || return 1
        expect_blocked "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https || return 1
        scope_probe rosetun-gui || return 1
        reached_rc "$SCOPE_HTTPS" || { fail_reason="the GUI's scope did not get its permit back (curl exit '$SCOPE_HTTPS')"; return 1; }
    }
    check lockdown.after-session "after the disconnect the network stays closed and the GUI's scope gets out again" after
}

scenario_crash() {
    stopped() {
        timeout "$UNIT_TIMEOUT_SECONDS" systemctl stop rosetun-helper.service || { fail_reason="systemctl stop failed"; return 1; }
        table_present || { fail_reason="the table went away with the stop"; return 1; }
        expect_blocked "HTTPS to $PROBE_ADDRESS on $PHYS with the service stopped" direct_https || return 1
        timeout "$UNIT_TIMEOUT_SECONDS" systemctl start rosetun-helper.service || { fail_reason="the service did not start again"; return 1; }
        helper_answers
    }
    check crash.stopped "a stopped service leaves the network closed" stopped

    killed() {
        local old restarts_before restarts='' deadline
        old=$(main_pid)
        restarts_before=$(systemctl show -p NRestarts --value rosetun-helper.service)
        kill -KILL "$old" || { fail_reason="could not kill the helper"; return 1; }
        sleep 0.5
        table_present || { fail_reason="the table went away with the helper"; return 1; }
        expect_blocked "HTTPS to $PROBE_ADDRESS on $PHYS right after the kill" direct_https || return 1
        deadline=$((SECONDS + 60))
        while [ "$SECONDS" -lt "$deadline" ]; do
            restarts=$(systemctl show -p NRestarts --value rosetun-helper.service)
            [ "$restarts" -gt "$restarts_before" ] && systemctl is-active --quiet rosetun-helper.service && break
            sleep 1
        done
        [ "${restarts:-0}" -gt "$restarts_before" ] || { fail_reason="systemd did not restart the helper"; return 1; }
        helper_answers || return 1
        [[ $(lockdown_line) == on ]] || { fail_reason="the restarted helper does not report Lockdown: $CLI_OUT"; return 1; }
        ! printf '%s\n' "$CLI_OUT" | grep -q '^network: held closed' || { fail_reason="Lockdown is reported as the crash hold"; return 1; }
        expect_blocked "HTTPS to $PROBE_ADDRESS on $PHYS after the restart" direct_https || return 1
        scope_probe rosetun-cli || return 1
        reached_rc "$SCOPE_HTTPS" || { fail_reason="the CLI's scope has no permit from the restarted helper (curl exit '$SCOPE_HTTPS')"; return 1; }
    }
    check crash.killed "a killed helper leaves the network closed; the restarted one writes its permits again" killed
}

scenario_exit_denied() {
    off_denied() {
        cli 30 lockdown off
        [ "$CLI_RC" -ne 0 ] || { fail_reason="an ordinary account turned Lockdown off"; return 1; }
        [[ $(lockdown_line) == on ]] && table_present && [ -e "$RECORD" ] || { fail_reason="Lockdown changed anyway"; return 1; }
    }
    check exit.denied-without-root "an ordinary account cannot turn Lockdown off" off_denied
}

# The first reboot: the helper does not start by itself, so after the boot only
# the boot unit's set is in place until the resume phase starts the helper.
reboot_now() {
    local phase=$1
    printf '%s\n' "$phase" >"$STATE/phase"
    : >"$STATE/rebooting"
    systemctl enable --quiet "$RESUME_UNIT" || return 1
    write_status rebooting "$phase"
    sync
    systemctl --no-block reboot
}

phase_one() {
    write_status running preflight
    scenario_preflight
    if ! preflight_ok; then
        skip_rest "a preflight check failed, nothing was installed"
        return
    fi
    scenario_install
    if passed install.service; then
        scenario_enable
        if passed lockdown.direct-blocked; then
            scenario_session
            scenario_crash
            scenario_exit_denied
            if passed inbound.lan-open; then
                systemctl disable --quiet rosetun-helper.service 2>/dev/null
                timeout "$UNIT_TIMEOUT_SECONDS" systemctl stop rosetun-helper.service
                reboot_now reboot-1 && return
                record reboot.table-before-network ERROR "could not reboot" "$(l2_now_ms)"
            fi
        fi
    fi
    skip_rest "an earlier step failed; see the first FAIL"
}

# ---------------------------------------------------------------- after a reboot

# The table and the time, as rosetun-l2-early.service saw them.
early() {
    local listing=no
    table_present && listing=yes
    printf 'table=%s\nuptime=%s\n' "$listing" "$(cut -d' ' -f1 /proc/uptime)" >"$STATE/early-$(boot_id)"
}

# When a unit's main process started or ended, in microseconds since boot; 0
# when it did not run in this boot.
started_us() { systemctl show -p ExecMainStartTimestampMonotonic --value "$1" 2>/dev/null || echo 0; }
ended_us() { systemctl show -p ExecMainExitTimestampMonotonic --value "$1" 2>/dev/null || echo 0; }

phase_after_first_reboot() {
    before_network() {
        local early="$STATE/early-$(boot_id)" lockdown_end manager start ran=0
        [ -f "$early" ] || { fail_reason="rosetun-l2-early.service did not run in this boot"; return 1; }
        grep -qx 'table=yes' "$early" || { fail_reason="no table before network-pre.target"; return 1; }
        systemctl is-active --quiet rosetun-lockdown.service || { fail_reason="rosetun-lockdown.service is not active"; return 1; }
        lockdown_end=$(ended_us rosetun-lockdown.service)
        [ "${lockdown_end:-0}" -gt 0 ] || { fail_reason="rosetun-lockdown.service has no exit time"; return 1; }
        for manager in "${NETWORK_MANAGERS[@]}"; do
            start=$(started_us "$manager")
            [ "${start:-0}" -gt 0 ] || continue
            ran=1
            [ "$start" -gt "$lockdown_end" ] || { fail_reason="$manager started at ${start} us, before Lockdown's set (${lockdown_end} us)"; return 1; }
        done
        [ "$ran" = 1 ] || { fail_reason="no known network manager ran in this boot"; return 1; }
    }
    check reboot.table-before-network "the table was in place before network-pre.target and before every network manager" before_network

    closed() {
        ! systemctl is-active --quiet rosetun-helper.service || { fail_reason="the helper runs; it was left disabled"; return 1; }
        expect_blocked "HTTPS to $PROBE_ADDRESS on $PHYS with the boot set alone" direct_https || return 1
        expect_blocked "HTTPS to $PROBE_ADDRESS by the route with the boot set alone" routed_https || return 1
        ! "$NFT" list table inet rosetun 2>/dev/null | grep -q cgroupv2 || { fail_reason="the boot set names a cgroup"; return 1; }
    }
    check reboot.closed-before-service "before the service starts only the boot set is there, and it closes the network" closed

    completed() {
        timeout "$UNIT_TIMEOUT_SECONDS" systemctl start rosetun-helper.service || { fail_reason="the service did not start"; return 1; }
        helper_answers || return 1
        [[ $(lockdown_line) == on ]] || { fail_reason="the helper does not report Lockdown after the reboot: $CLI_OUT"; return 1; }
        "$NFT" list table inet rosetun 2>/dev/null | grep -q 'rosetun-helper.service/engines' || { fail_reason="the helper did not add the engines' permit"; return 1; }
        connect_with request-kill-switch.json || return 1
        expect_reached "HTTPS through the tunnel" routed_https || return 1
        disconnect
    }
    check reboot.service-completes "the started service adds its permits and a connect works" completed

    reset() {
        cli_root 120 reset-firewall
        [ "$CLI_RC" -eq 0 ] || { fail_reason="sudo rosetun reset-firewall failed: $CLI_OUT"; return 1; }
        ! table_present || { fail_reason="the table stays after reset-firewall"; return 1; }
        [ ! -e "$RECORD" ] || { fail_reason="the record stays after reset-firewall"; return 1; }
        helper_answers || return 1
        [[ $(lockdown_line) == off ]] || { fail_reason="the helper still reports Lockdown: $CLI_OUT"; return 1; }
        expect_reached "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https
    }
    check exit.reset-firewall "reset-firewall as root opens the network and removes the record" reset
    if passed exit.reset-firewall; then
        reboot_now reboot-2 && return
    fi
    skip_rest "an earlier step failed; see the first FAIL"
}

phase_after_second_reboot() {
    opened() {
        local early="$STATE/early-$(boot_id)"
        systemctl is-active --quiet rosetun-lockdown.service || { fail_reason="rosetun-lockdown.service did not run"; return 1; }
        journalctl -b -u rosetun-lockdown.service --no-pager 2>/dev/null | grep -q 'Lockdown is off' ||
            { fail_reason="the boot unit did not say Lockdown is off"; return 1; }
        [ -f "$early" ] && grep -qx 'table=no' "$early" || { fail_reason="a table was there early in boot"; return 1; }
        ! table_present || { fail_reason="a table is there without the record"; return 1; }
        expect_reached "HTTPS to $PROBE_ADDRESS on $PHYS" direct_https
    }
    check reboot.without-record "without the record the boot leaves the network open" opened
}

phase_resume() {
    local phase
    phase=$(cat "$STATE/phase" 2>/dev/null)
    rm -f -- "$STATE/rebooting"
    l2_append_line "$STATE/boot-ids" "$(boot_id)"
    [ -f "$STATE/phys.env" ] && l2_read_env_file "$STATE/phys.env" PHYS
    write_status running "$phase"
    case $phase in
        reboot-1) phase_after_first_reboot ;;
        reboot-2) phase_after_second_reboot ;;
        *) skip_rest "the resume phase found no phase to run" ;;
    esac
}

# ---------------------------------------------------------------- cleanup and report

cleanup() {
    L2_CLEANUP_STATUS=PASS L2_CLEANUP_ACTIONS='' L2_CLEANUP_PROBLEMS=''
    note() { L2_CLEANUP_ACTIONS="$L2_CLEANUP_ACTIONS${L2_CLEANUP_ACTIONS:+; }$1"; }
    problem() { L2_CLEANUP_PROBLEMS="$L2_CLEANUP_PROBLEMS${L2_CLEANUP_PROBLEMS:+; }$1"; L2_CLEANUP_STATUS=ERROR; }
    if [ -f "$STATE/peer" ]; then
        peer_down && note "removed the peer namespace" || problem "could not remove the peer namespace $PEER_NS"
    fi
    if [ -f "$STATE/linger" ]; then
        loginctl disable-linger "$USER_A" && rm -f -- "$STATE/linger" && note "stopped lingering for $USER_A" ||
            problem "could not turn lingering off for $USER_A"
    fi
    if [ -f "$STATE/stand-units" ]; then
        systemctl disable --quiet "$EARLY_UNIT" "$RESUME_UNIT" 2>/dev/null
        rm -f -- "$STAND_UNIT_DIR/$EARLY_UNIT" "$STAND_UNIT_DIR/$RESUME_UNIT" && rm -f -- "$STATE/stand-units" &&
            note "removed the stand's boot units"
    fi
    [ -f "$STATE/installed" ] || { systemctl daemon-reload; return 0; }
    # The way out the product gives: it stops the service, removes the table and
    # the record, and opens the network for the host before the report closes.
    if [ -e "$RECORD" ] || { [ -x "$NFT" ] && table_present; }; then
        if [ -x "$HELPER" ] && timeout 120 "$HELPER" --reset-firewall >/dev/null 2>&1; then
            note "removed Lockdown with reset-firewall"
        else
            problem "reset-firewall failed; Lockdown may still be on"
        fi
    fi
    if systemctl is-active --quiet rosetun-helper.service; then
        timeout 60 systemctl stop rosetun-helper.service && note "stopped the service" || problem "could not stop the service"
    fi
    if [ -x "$NFT" ] && table_present; then
        problem "the table inet rosetun is still there; restore the checkpoint"
    fi
    systemctl disable --quiet rosetun-helper.service rosetun-lockdown.service 2>/dev/null
    rm -f -- "$UNIT_FILE" "$LOCKDOWN_UNIT_FILE" "$POLICY_FILE" && systemctl daemon-reload && note "removed the units"
    systemctl reset-failed rosetun-helper.service rosetun-lockdown.service 2>/dev/null
    rm -rf -- "$PREFIX" /var/lib/rosetun && note "removed the installed files"
    rm -f -- "$STATE/installed"
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
    # A planned reboot: the next phase goes on after it.
    [ -f "$STATE/rebooting" ] && return 0
    local started_cleanup
    started_cleanup=$(l2_now_ms)
    if [ -f "$STATE/installed" ]; then
        {
            journalctl -b -u rosetun-lockdown.service --no-pager -o short-monotonic 2>/dev/null | tail -n 50
            journalctl -b -u rosetun-helper.service --no-pager -o short-monotonic 2>/dev/null | tail -n 400
        } | LC_ALL=C tr -c '\n -~' '?' | l2_atomic_write "$REPORT/helper-journal.txt" 0644
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
        SCENARIO_TIMEOUT_SECONDS UNIT_TIMEOUT_SECONDS JOB_TIMEOUT_SECONDS HOST_ADDRESS NODE_PORT PROBE_ADDRESS DNS_PROBE_ADDRESS || return 1
    l2_valid_run_id "$RUN_ID" || { echo "invalid run id" >&2; return 1; }
    [ "$(basename -- "$RUN")" = "$RUN_ID" ] || { echo "run directory does not match the run id" >&2; return 1; }
    [[ $PROBE_ADDRESS =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "invalid probe address" >&2; return 1; }
    [[ $DNS_PROBE_ADDRESS =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "invalid DNS probe address" >&2; return 1; }
    [[ $JOB_TIMEOUT_SECONDS =~ ^[0-9]{2,5}$ ]] || { echo "invalid job time limit" >&2; return 1; }
}

load_job || exit 65
mkdir -p "$STATE" "$REPORT"

if [ "$mode" = early ]; then
    early
    exit 0
fi

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
    l2_append_line "$STATE/boot-ids" "$(boot_id)"
    phase_one
else
    phase_resume
fi
exit 0
