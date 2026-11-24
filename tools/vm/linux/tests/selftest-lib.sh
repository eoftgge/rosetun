#!/bin/bash
# Unprivileged self-test of the guest helpers (lib.sh). It touches only a private
# temporary directory: no root, no /run/rosetun, no services, no network.
#
#   bash tools/vm/linux/tests/selftest-lib.sh
#
# This proves the stand's own bookkeeping (timeouts, identity checks, cleanup that
# refuses foreign objects, atomic writes). It is not a Hyper-V run.

set -u
export LC_ALL=C
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

export L2_SELFTEST=1
export L2_SELFTEST_ENDPOINT_DIR=$work/run-rosetun
# shellcheck source=../guest/lib.sh
. "$here/../guest/lib.sh"

failures=0
passes=0
expect() {
    local name=$1
    shift
    if "$@"; then
        passes=$((passes + 1))
    else
        failures=$((failures + 1))
        printf 'FAIL  %s\n' "$name"
    fi
}
expect_not() {
    local name=$1
    shift
    if "$@"; then
        failures=$((failures + 1))
        printf 'FAIL  %s\n' "$name"
    else
        passes=$((passes + 1))
    fi
}

new_state() {
    state=$(mktemp -d "$work/state.XXXXXX")
    : >"$state/objects.tsv"
    : >"$state/processes.tsv"
}

# A fake endpoint directory with a socket, recorded as a run would record it.
make_endpoint() {
    mkdir "$L2_ENDPOINT_DIR"
    printf 'ENDPOINT_PREEXISTING=no\n' >"$state/endpoint.env"
    l2_record_object "$state" endpoint-dir "$L2_ENDPOINT_DIR"
    python3 - "$L2_ENDPOINT_DIR/helper.sock" <<'PY' 2>/dev/null || mkfifo "$L2_ENDPOINT_DIR/helper.sock"
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.bind(sys.argv[1])
PY
    l2_record_object "$state" endpoint-socket "$L2_ENDPOINT_DIR/helper.sock"
}

# --- bounded commands: a hanging command is killed and reported as timed out
l2_run_bounded 1 sleep 30
expect "a hanging command is reported as a timeout" l2_timed_out
l2_run_bounded 5 sh -c 'echo ok'
expect_not "a quick command is not a timeout" l2_timed_out
expect "a quick command keeps its output" test "$L2_OUT" = ok

# --- sanitizing keeps reports valid JSON
expect "control characters and quotes are neutralized" \
    test "$(l2_json_string $'a"b\\c\nd')" = '"a\"b\\c d"'
long=$(printf 'x%.0s' $(seq 1 400))
expect "long text is cut to 300 characters" test "$(l2_sanitize "$long" | wc -c)" -eq 300

# --- run ids
expect "a valid run id is accepted" l2_valid_run_id 20261101T220100Z-0123abcd
expect_not "a run id with a path is refused" l2_valid_run_id '../20261101T220100Z-0123abcd'
expect_not "a run id with uppercase hex is refused" l2_valid_run_id 20261101T220100Z-0123ABCD

# --- strict job file reader
printf 'RUN_ID=x1\nUSER_A=alice\n' >"$work/ok.env"
expect "a conservative job file is read" bash -c ". '$here/../guest/lib.sh'; l2_read_env_file '$work/ok.env' RUN_ID USER_A"
printf 'RUN_ID=$(id)\n' >"$work/evil.env"
expect_not "a job value with shell syntax is refused" bash -c ". '$here/../guest/lib.sh'; l2_read_env_file '$work/evil.env' RUN_ID" 2>/dev/null
printf 'OTHER=1\n' >"$work/key.env"
expect_not "an unlisted job key is refused" bash -c ". '$here/../guest/lib.sh'; l2_read_env_file '$work/key.env' RUN_ID" 2>/dev/null

# --- GUID spelling
expect "a BIOS GUID matches its byte-swapped spelling" \
    test "$(l2_guid_swap 00112233-4455-6677-8899-aabbccddeeff)" = 33221100-5544-7766-8899-aabbccddeeff

# --- atomic write
new_state
printf 'one\n' | l2_atomic_write "$state/file" 0644
expect "an atomic write lands the content" test "$(cat "$state/file")" = one
expect "an atomic write leaves no temporary files" test "$(ls -A "$state" | grep -c '^\.tmp\.')" -eq 0
expect_not "an atomic write into a missing directory fails" bash -c ". '$here/../guest/lib.sh'; echo x | l2_atomic_write '$work/missing/f' 0644" 2>/dev/null

# --- process identity: a recorded process is recognized only while it is itself
sleep 60 &
pid=$!
identity=$(l2_process_identity "$pid")
start=${identity%% *}
exe=${identity#* }
expect "a live process matches its identity" l2_process_alive_as "$pid" "$start" "$exe"
expect_not "a different start time does not match" l2_process_alive_as "$pid" 1 "$exe"
expect_not "a different executable does not match" l2_process_alive_as "$pid" "$start" /bin/false
kill -KILL "$pid"
wait "$pid" 2>/dev/null
expect_not "a dead process no longer matches" l2_process_alive_as "$pid" "$start" "$exe"
expect "waiting for a dead process returns at once" l2_wait_process_gone "$pid" "$start" "$exe" 1

# --- cleanup of a normal run
new_state
make_endpoint
l2_cleanup_run "$state" "$L2_ENDPOINT_DIR"
expect "cleanup removes the recorded socket and directory" test "$L2_CLEANUP_STATUS" = PASS
expect "the recorded directory is gone" test ! -e "$L2_ENDPOINT_DIR"

# --- cleanup kills only a process the run recorded, and reports a stubborn one
new_state
make_endpoint
sleep 60 &
pid=$!
l2_record_process "$state" fixture "$pid"
l2_cleanup_run "$state" "$L2_ENDPOINT_DIR"
expect "cleanup stops the recorded process" test "$L2_CLEANUP_STATUS" = PASS
sleep 0.2
expect_not "the recorded process is gone" kill -0 "$pid" 2>/dev/null
wait "$pid" 2>/dev/null

new_state
sleep 60 &
pid=$!
printf 'fixture|%s|1|/bin/sleep\n' "$pid" >"$state/processes.tsv"
l2_cleanup_run "$state" "$L2_ENDPOINT_DIR"
expect "a process with a different identity is left alone" kill -0 "$pid"
kill -KILL "$pid"
wait "$pid" 2>/dev/null

# --- cleanup must not touch a replaced or foreign endpoint
new_state
make_endpoint
rm -- "$L2_ENDPOINT_DIR/helper.sock"
printf 'foreign\n' >"$L2_ENDPOINT_DIR/helper.sock"
l2_cleanup_run "$state" "$L2_ENDPOINT_DIR"
expect "a replaced socket is reported as an error" test "$L2_CLEANUP_STATUS" = ERROR
expect "a replaced socket is preserved" test "$(cat "$L2_ENDPOINT_DIR/helper.sock")" = foreign
expect "the directory is kept while a foreign object is in it" test -d "$L2_ENDPOINT_DIR"
rm -- "$L2_ENDPOINT_DIR/helper.sock"
rmdir -- "$L2_ENDPOINT_DIR"

new_state
make_endpoint
printf 'x\n' >"$L2_ENDPOINT_DIR/other"
l2_cleanup_run "$state" "$L2_ENDPOINT_DIR"
expect "an unexpected entry is reported as an error" test "$L2_CLEANUP_STATUS" = ERROR
expect "an unexpected entry is preserved" test -f "$L2_ENDPOINT_DIR/other"
rm -rf -- "$L2_ENDPOINT_DIR"

new_state
printf 'ENDPOINT_PREEXISTING=no\n' >"$state/endpoint.env"
mkdir "$L2_ENDPOINT_DIR"
l2_cleanup_run "$state" "$L2_ENDPOINT_DIR"
expect "a directory the run never recorded is an error" test "$L2_CLEANUP_STATUS" = ERROR
expect "a directory the run never recorded is preserved" test -d "$L2_ENDPOINT_DIR"
rmdir -- "$L2_ENDPOINT_DIR"

new_state
printf 'ENDPOINT_PREEXISTING=yes\n' >"$state/endpoint.env"
mkdir "$L2_ENDPOINT_DIR"
l2_cleanup_run "$state" "$L2_ENDPOINT_DIR"
expect "a directory that existed before the run is left without error" test "$L2_CLEANUP_STATUS" = PASS
expect "a directory that existed before the run is preserved" test -d "$L2_ENDPOINT_DIR"
rmdir -- "$L2_ENDPOINT_DIR"

# --- verified removal of a stale object
new_state
mkdir "$work/stale-dir"
printf 'a\n' >"$work/stale-dir/s"
l2_record_object "$state" stale "$work/stale-dir/s"
expect "an unchanged recorded object is removed" l2_remove_recorded "$state/objects.tsv" "$work/stale-dir/s"
printf 'a\n' >"$work/stale-dir/s"
l2_record_object "$state" stale "$work/stale-dir/s"
rm -- "$work/stale-dir/s"
printf 'b\n' >"$work/stale-dir/s"
expect_not "a substituted object is refused" l2_remove_recorded "$state/objects.tsv" "$work/stale-dir/s"
expect "a refused object stays" test -f "$work/stale-dir/s"
expect_not "an object nobody recorded is refused" l2_remove_recorded "$state/objects.tsv" "$work/never-recorded"

# --- symlinks are fingerprinted as links, never followed
ln -s nowhere "$work/link"
expect "a dangling symlink has a fingerprint" l2_object_fingerprint "$work/link"
l2_record_object "$state" link "$work/link"
rm -- "$work/link"
ln -s elsewhere "$work/link"
expect_not "a changed symlink target is a different object" l2_remove_recorded "$state/objects.tsv" "$work/link"

# --- launcher and start.sh: who checks what
launch=$here/../guest/launch.sh
start=$here/../guest/start.sh
installer=$here/../guest/install-launcher.sh
launcher_allows() { bash -c '. "$1" && l2_launch_path_allowed "$2"' _ "$launch" "$1"; }
start_allows() { bash -c '. "$1" && l2_start_path_allowed "$2"' _ "$start" "$1"; }
for path in guest/start.sh guest/launch.sh guest/run-l2.sh scenarios.tsv job.env artifacts/provenance.json artifacts/rosetun_ipc_tests; do
    expect "the launcher accepts $path" launcher_allows "$path"
done
expect "the launcher accepts a guest script a later stand may add" launcher_allows guest/new-step.sh
for path in ../etc/passwd /etc/passwd guest/../x.sh artifacts/.. artifacts/.hidden artifacts/a..b guest/sub/x.sh \
    manifest.sha256 artifacts/a/b guest/Start.sh 'job.env x'; do
    expect_not "the launcher refuses $path" launcher_allows "$path"
done
expect_not "start.sh refuses a name only the launcher's wider list accepts" start_allows guest/new-step.sh
expect_not "start.sh refuses an artifact it does not use" start_allows artifacts/extra
required=$(bash -c '. "$1" && printf "%s\n" "${L2_START_REQUIRED[@]}"' _ "$start")
expect "start.sh requires the launcher, the job scripts and the artifacts" test "$(printf '%s\n' "$required" | wc -l)" -eq 10
while IFS= read -r path; do
    expect "every required path passes both lists: $path" bash -c '. "$1" && l2_launch_path_allowed "$3" && . "$2" && l2_start_path_allowed "$3"' _ "$launch" "$start" "$path"
done <<<"$required"
l3_allows() { bash -c '. "$1" && l3_start_path_allowed "$2"' _ "$start" "$1"; }
required_l3=$(bash -c '. "$1" && printf "%s\n" "${L3_START_REQUIRED[@]}"' _ "$start")
expect "start.sh requires the L3 job, the service, the engine and the requests" test "$(printf '%s\n' "$required_l3" | wc -l)" -eq 18
expect "L3 requires the request for private networks behind the router" grep -qxF artifacts/request-lan-private.json <<<"$required_l3"
while IFS= read -r path; do
    expect "every required L3 path passes both lists: $path" bash -c '. "$1" && l2_launch_path_allowed "$3" && . "$2" && l3_start_path_allowed "$3"' _ "$launch" "$start" "$path"
done <<<"$required_l3"
expect_not "an L3 stage refuses the L2 fixture" l3_allows artifacts/l2_transport_fixture
expect_not "an L3 stage refuses the L2 job" l3_allows guest/run-l2.sh
expect_not "an L2 stage refuses the L3 job" start_allows guest/run-l3.sh
expect_not "an L3 stage refuses another request" l3_allows artifacts/request-other.json
expect "start.sh picks the job by the stage" grep -q 'job="$run/guest/run-$stage.sh"' "$start"

# --- the reboot smoke stage: the guest scripts and the record of the build, nothing of Rosetun
smoke_allows() { bash -c '. "$1" && reboot_smoke_start_path_allowed "$2"' _ "$start" "$1"; }
required_smoke=$(bash -c '. "$1" && printf "%s\n" "${REBOOT_SMOKE_START_REQUIRED[@]}"' _ "$start")
expect "start.sh requires the smoke job, its catalog and the record of the build" \
    test "$(printf '%s\n' "$required_smoke" | wc -l)" -eq 7
while IFS= read -r path; do
    expect "every required smoke path passes both lists: $path" \
        bash -c '. "$1" && l2_launch_path_allowed "$3" && . "$2" && reboot_smoke_start_path_allowed "$3"' _ "$launch" "$start" "$path"
done <<<"$required_smoke"
expect_not "the smoke stage refuses a program" smoke_allows artifacts/rosetun
expect_not "the smoke stage refuses the L2 fixture" smoke_allows artifacts/l2_transport_fixture
expect_not "the smoke stage refuses another job" smoke_allows guest/run-l4.sh
expect_not "an L2 stage refuses the smoke job" start_allows guest/run-reboot-smoke.sh
expect "start.sh tells the smoke stage by its job" \
    grep -q "grep -q '  guest/run-reboot-smoke\\\\.sh\$' \"\$run/manifest.sha256\"" "$start"
expect "the smoke stage reads the keys of an L2 job.env only" \
    grep -q '^    case \$stage in l2 | reboot-smoke) ;; \*) keys+=(HOST_ADDRESS NODE_PORT PROBE_ADDRESS DNS_PROBE_ADDRESS) ;; esac$' "$start"
smoke=$here/../guest/run-reboot-smoke.sh
expect "run-reboot-smoke.sh is valid shell" bash -n "$smoke"
expect "run-reboot-smoke.sh reads exactly the keys of an L2 job.env" \
    grep -q 'USER_B BIOS_GUID \\$' "$smoke"
expect "run-reboot-smoke.sh does not finish a report before its reboot is over" \
    grep -q '^    \[ -f "\$STATE/rebooting" \] && return 0$' "$smoke"
expect_not "run-reboot-smoke.sh touches no Rosetun file or unit" grep -Eq 'rosetun-(helper|lockdown|engine)|/usr/lib/rosetun' "$smoke"
expect "run-l3.sh reads the host node values through the strict reader" \
    grep -q 'JOB_TIMEOUT_SECONDS HOST_ADDRESS NODE_PORT PROBE_ADDRESS DNS_PROBE_ADDRESS' "$here/../guest/run-l3.sh"
expect_not "run-l3.sh never deletes the service's own table" \
    grep -Eq 'delete table inet rosetun([^-]|$)' "$here/../guest/run-l3.sh"

# --- run-l3.sh: the lab window markers (only with LAB_MARKER_ADDRESS)
l3=$here/../guest/run-l3.sh
expect "run-l3.sh takes LAB_MARKER_ADDRESS as an optional key of job.env" \
    grep -q 'DNS_PROBE_ADDRESS LAB_MARKER_ADDRESS LAB_CONTROL || return 1' "$l3"
lib=$here/../guest/lib.sh
expect "lib.sh sends no marker unless the address is set" grep -q '^    \[ -n "\$LAB_MARKER_ADDRESS" \] || return 0$' "$lib"
expect_not "run-l3.sh keeps no marker function of its own" grep -Eq '^lab_(mark|label|send|run_id)\(\)' "$l3"
expect "start.sh lets only an L3, Proxy, L5 or L4 stage read LAB_MARKER_ADDRESS" \
    grep -q '^    case \$stage in l3 | proxy | l5 | l4) keys+=(LAB_MARKER_ADDRESS LAB_CONTROL) ;; esac$' "$start"
expect "start.sh lets the L4 stage alone read LAB_POLLER_KEY" \
    grep -q '^    \[ "\$stage" != l4 \] || keys+=(LAB_POLLER_KEY)$' "$start"
expect "run-l4.sh takes the lab keys of job.env, the poller's key among them, as optional keys" \
    grep -q 'DNS_PROBE_ADDRESS LAB_MARKER_ADDRESS LAB_CONTROL LAB_POLLER_KEY || return 1' "$here/../guest/run-l4.sh"
expect "run-l4.sh refuses a control without a marker address" \
    grep -q '^    \[ -z "\$LAB_CONTROL" \] || { \[ "\$LAB_CONTROL" = stop-helper \] && \[ -n "\$LAB_MARKER_ADDRESS" \]; } ||$' "$here/../guest/run-l4.sh"
expect "run-l4.sh refuses a poller key that is not an ed25519 blob or has no marker address" \
    grep -q 'AAAAC3NzaC1lZDI1NTE5AAAAI\[A-Za-z0-9+/\]{43}\$ \]\] && \[ -n "\$LAB_MARKER_ADDRESS" \]' "$here/../guest/run-l4.sh"
expect "run-l5.sh takes LAB_MARKER_ADDRESS and LAB_CONTROL as optional keys of job.env" \
    grep -q 'DNS_PROBE_ADDRESS LAB_MARKER_ADDRESS LAB_CONTROL || return 1' "$here/../guest/run-l5.sh"
expect "run-l5.sh refuses a control without a marker address" \
    grep -q '^    \[ -z "\$LAB_CONTROL" \] || { \[ "\$LAB_CONTROL" = stop-helper \] && \[ -n "\$LAB_MARKER_ADDRESS" \]; } ||$' "$here/../guest/run-l5.sh"
l5_start=$work/l5-start.sh
expect "start.sh reads the lab keys of a Hyper-V L5 job.env as before: they are absent" \
    bash -c '. "$1" && RUN_ID= LAB_MARKER_ADDRESS= && printf "RUN_ID=x\n" >"$2" && l2_read_env_file "$2" RUN_ID LAB_MARKER_ADDRESS LAB_CONTROL && [ -z "$LAB_MARKER_ADDRESS" ]' _ "$lib" "$l5_start"
expect "run-proxy.sh takes LAB_MARKER_ADDRESS and LAB_CONTROL as optional keys of job.env" \
    grep -q 'DNS_PROBE_ADDRESS LAB_MARKER_ADDRESS LAB_CONTROL || return 1' "$here/../guest/run-proxy.sh"
expect "run-proxy.sh refuses a control without a marker address" \
    grep -q '^    \[ -z "\$LAB_CONTROL" \] || { \[ "\$LAB_CONTROL" = stop-helper \] && \[ -n "\$LAB_MARKER_ADDRESS" \]; } ||$' "$here/../guest/run-proxy.sh"
# --- run-l4.sh: what its lab wrappers do without a lab and with one (the functions only, lib.sh's own lab_mark)
l4_functions=$work/l4-functions.sh
awk '/^(lockdown|lockdown_lan_on|poller_authorize)\(\) \{/ { on = 1 } on { print } /^}/ { on = 0 }' \
    "$here/../guest/run-l4.sh" >"$l4_functions"
expect "the L4 lab wrappers were found in run-l4.sh" test -s "$l4_functions"
l4_state=$work/l4-state
mkdir -p "$l4_state"
expect "without a lab the L4 wrappers send nothing, note nothing and install no key" \
    bash -c '. "$1"; . "$2"; d=$3; lockdown_as_root() { echo "on $*" >>"$d/calls"; }; STATE=$d
        LAB_MARKER_ADDRESS= LAB_POLLER_KEY= POLLER_DIR=$d/ssh POLLER_AUTHORIZED=$d/ssh/authorized_keys
        lockdown --lan off && lockdown_lan_on && poller_authorize &&
        [ "$(cat "$d/calls")" = "$(printf "on on --lan off\non on --lan on")" ] && [ ! -e "$d/lan-on-ms" ] &&
        [ ! -e "$d/ssh" ] && [ ! -e "$d/poller-key" ]' _ "$lib" "$l4_functions" "$l4_state"
rm -rf "$l4_state"
mkdir -p "$l4_state"
expect "with a lab the local network is noted before it goes on, in milliseconds, and the key is made restricted" \
    bash -c '. "$1"; . "$2"; d=$3; lockdown_as_root() { [ -s "$d/lan-on-ms" ] && echo noted-before >"$d/order"; }; STATE=$d
        # The stand installs as root for root; here only the mode counts.
        install() { local keep=(); while [ $# -gt 0 ]; do case $1 in -o | -g) shift 2 ;; *) keep+=("$1"); shift ;; esac; done
            command install "${keep[@]}"; }
        LAB_POLLER_KEY=AAAAC3NzaC1lZDI1NTE5AAAAIDdaiAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea
        POLLER_DIR=$d/ssh POLLER_AUTHORIZED=$d/ssh/authorized_keys LAB_MARKER_ADDRESS=203.0.113.2:9100
        lockdown_lan_on && grep -qx noted-before "$d/order" && grep -Eq "^[0-9]{13}$" "$d/lan-on-ms" &&
        poller_authorize && [ "$(stat -c %a "$d/ssh")" = 700 ] && [ "$(stat -c %a "$d/ssh/authorized_keys")" = 600 ] &&
        grep -qx "restrict,command=\"/bin/true\" ssh-ed25519 $LAB_POLLER_KEY rosetun-lab-poller" "$d/ssh/authorized_keys" &&
        [ -e "$d/poller-dir" ] && [ -e "$d/poller-file" ] && [ -e "$d/poller-key" ]' _ "$lib" "$l4_functions" "$l4_state"
lab_functions=$work/lab-functions.sh
awk '/^# -+ lab windows/ { on = 1 } on' "$lib" >"$lab_functions"
expect "the lab window functions were found in lib.sh" test -s "$lab_functions"
py=$(command -v python3 || command -v python || true)
if [ -n "$py" ]; then
    cat >"$work/echo-server.py" <<'PY'
import socket, sys
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(('127.0.0.1', 0))
open(sys.argv[1], 'w').write(str(server.getsockname()[1]))
with open(sys.argv[2], 'ab', buffering=0) as log:
    while True:
        data, peer = server.recvfrom(512)
        log.write(data + b'\n')
        server.sendto(b'rosetun-lab-ack:' + data, peer)
PY
    "$py" "$work/echo-server.py" "$work/echo-port" "$work/echo-log" &
    echo_pid=$!
    for _ in $(seq 1 50); do [ -s "$work/echo-port" ] && break; sleep 0.1; done
    mark_state=$work/mark-state
    mkdir -p "$mark_state"
    # A stand-in for the guest: the table, the state and the two helpers lab_mark calls.
    cat >"$work/mark-harness.sh" <<'SH'
. "$LAB_FUNCTIONS"
STATE=$MARK_STATE RUN_ID=20261113T101010Z-0a1b2c3d
table_present() { [ -f "$MARK_STATE/table" ]; }
state_line() { if [ -e "$MARK_STATE/service-stopped" ]; then :; else cat "$MARK_STATE/state"; fi; }
systemctl() { [ ! -e "$MARK_STATE/service-stopped" ]; }
connect_with() { lab_mark "$1"; }
connect_ks() { connect_with open; }
disconnect() { lab_mark close; }
Odd_Name.1() { connect_with open; }
"$@"
SH
    mark() { LAB_FUNCTIONS=$lab_functions MARK_STATE=$mark_state LAB_MARKER_ADDRESS=${MARK_ADDRESS-127.0.0.1:$(cat "$work/echo-port")} bash "$work/mark-harness.sh" "$@"; }
    export -f mark
    export work lab_functions mark_state
    run_id_hash=$(printf '%s' 'rosetun-lab-run:20261113T101010Z-0a1b2c3d' | sha256sum | cut -c1-32)
    printf 'Disconnected\n' >"$mark_state/state"
    expect "without an address nothing is sent or written" bash -c 'MARK_ADDRESS= ; export MARK_ADDRESS; LAB_FUNCTIONS=$1 MARK_STATE=$2 LAB_MARKER_ADDRESS= bash "$3" connect_ks; [ ! -e "$2/lab-window" ] && [ ! -e "$2/lab-index" ]' _ "$lab_functions" "$mark_state" "$work/mark-harness.sh"
    expect "a closing marker without an open window sends nothing" mark disconnect
    expect "an open window is sent by the function that asked for it" mark connect_ks
    expect "the first window has index 0 and the function's name" grep -qx "rosetun-lab-marker:$run_id_hash.0.open.connect_ks" "$work/echo-log"
    expect "the open window is kept in STATE" grep -qx '0 connect_ks' "$mark_state/lab-window"
    expect "the closing marker keeps the index and the label of the opening one" mark disconnect
    expect "the closing marker is on the wire" grep -qx "rosetun-lab-marker:$run_id_hash.0.close.connect_ks" "$work/echo-log"
    expect_not "a closed window leaves nothing open" test -e "$mark_state/lab-window"
    expect "the next window has the next index, a lower-case label" mark 'Odd_Name.1'
    expect "an odd function name becomes a valid label" grep -qx "rosetun-lab-marker:$run_id_hash.1.open.odd_name.1" "$work/echo-log"
    expect "a second closing marker without a window is not sent" bash -c 'before=$(wc -l <"$1"); mark disconnect; mark disconnect; [ "$(wc -l <"$1")" -eq $((before + 1)) ]' _ "$work/echo-log"
    : >"$work/echo-log"
    : >"$mark_state/table"
    expect "no marker is sent while the table is there" bash -c 'mark connect_ks; [ ! -s "$1" ]' _ "$work/echo-log"
    rm -f -- "$mark_state/table"
    printf 'Connected\n' >"$mark_state/state"
    expect "no marker is sent unless the state is Disconnected" bash -c 'mark connect_ks; [ ! -s "$1" ]' _ "$work/echo-log"
    expect "a refused marker leaves no window and uses no index" bash -c '[ ! -e "$1/lab-window" ] && [ "$(cat "$1/lab-index")" = 2 ]' _ "$mark_state"
    printf 'Disconnected\n' >"$mark_state/state"
    expect "an echo that never comes does not fail the caller" bash -c 'MARK_ADDRESS=127.0.0.1:9; export MARK_ADDRESS; mark connect_ks'
    mark connect_ks
    : >"$work/echo-log"
    printf 'Connected\n' >"$mark_state/state"
    expect "a closing marker waits while a service that answers is not Disconnected" bash -c 'mark disconnect; [ ! -s "$1" ]' _ "$work/echo-log"
    : >"$mark_state/service-stopped"
    : >"$mark_state/table"
    expect "no closing marker is sent while the table is there, a stopped service or not" bash -c 'mark disconnect; [ ! -s "$1" ]' _ "$work/echo-log"
    rm -f -- "$mark_state/table"
    expect "an opening marker is not sent while the service is stopped" bash -c 'mark connect_ks; [ ! -s "$1" ]' _ "$work/echo-log"
    expect "the window is still open after the refused markers" test -f "$mark_state/lab-window"
    expect "a closing marker is sent once the service is stopped and the table is gone" bash -c 'mark disconnect; grep -q "\.close\.connect_ks$" "$1"' _ "$work/echo-log"
    expect_not "the window is closed after that marker" test -e "$mark_state/lab-window"
    rm -f -- "$mark_state/service-stopped"
    kill "$echo_pid" 2>/dev/null
    wait "$echo_pid" 2>/dev/null
else
    printf 'note  no python; the lab marker functions were not run
'
fi

# --- run-proxy.sh: the lab's private address for sharing (only with LAB_MARKER_ADDRESS)
proxy=$here/../guest/run-proxy.sh
share_functions=$work/share-functions.sh
awk '/^lab_share_up\(\) \{/ { on = 1 } on { print } on && /^share_address\(\) \{/ { last = 1 } last && /^\}/ { exit }' \
    "$proxy" >"$share_functions"
expect "the lab share functions were found in run-proxy.sh" grep -q '^share_address() {' "$share_functions"
expect "run-proxy.sh adds only the owner-approved private address" grep -qx 'LAB_SHARE_ADDRESS=192.168.77.2/24' "$proxy"
cat >"$work/share-harness.sh" <<'SH'
. "$SHARE_FUNCTIONS"
STATE=$SHARE_STATE PHYS=eth9 LAB_SHARE_ADDRESS=192.168.77.2/24
# A stand-in for ip(8): every call is logged, the address list is a file.
ip() {
    printf '%s\n' "$*" >>"$SHARE_STATE/ip-calls"
    case "$1 $2" in
        "addr add") printf '    inet %s scope global %s\n' "$3" "$5" >>"$SHARE_STATE/addresses" ;;
        "addr del") grep -vF " $3 " "$SHARE_STATE/addresses" >"$SHARE_STATE/a.tmp"; mv "$SHARE_STATE/a.tmp" "$SHARE_STATE/addresses" ;;
        "-4 -o") printf '2: eth9    inet 192.0.2.2/24 brd 192.0.2.255 scope global eth9\n'; sed 's/^/2: eth9/' "$SHARE_STATE/addresses" ;;
    esac
}
phys_address() { printf '192.0.2.2'; }
"$@"
SH
share() { SHARE_FUNCTIONS=$share_functions SHARE_STATE=$share_state LAB_MARKER_ADDRESS=$SHARE_MARKER bash "$work/share-harness.sh" "$@"; }
share_state=$work/share-state
mkdir -p "$share_state"
: >"$share_state/addresses"
SHARE_MARKER=''
share lab_share_up
expect "without a lab the private address is never added" test ! -e "$share_state/ip-calls"
expect "without a lab nothing is kept in STATE for it" test ! -e "$share_state/lab-share-address"
expect "without a lab sharing is looked for on the physical interface's own address" test "$(share share_address)" = 192.0.2.2
expect "without a lab there is nothing to remove" share lab_share_down
expect "without a lab no ip command runs at all" test ! -e "$share_state/ip-calls"
SHARE_MARKER=203.0.113.2:9100
share lab_share_up
expect "with a lab the private address goes on the physical interface" grep -qx 'addr add 192.168.77.2/24 dev eth9' "$share_state/ip-calls"
expect "with a lab the interface is kept in STATE for a later finalize" grep -qx eth9 "$share_state/lab-share-address"
expect "with a lab sharing is looked for on the private address" test "$(share share_address)" = 192.168.77.2
expect "the private address is removed again" share lab_share_down
expect "the removal names the same address and interface" grep -qx 'addr del 192.168.77.2/24 dev eth9' "$share_state/ip-calls"
expect_not "nothing of it is left in STATE" test -e "$share_state/lab-share-address"
expect "after the removal sharing is looked for on the physical interface's own address" test "$(share share_address)" = 192.0.2.2
expect "a removal after the last scenario is a cleanup action" grep -q 'private address ${LAB_SHARE_ADDRESS%/\*} after the last scenario"$' "$proxy"
expect "a removal by the cleanup is a cleanup action" grep -q '^        lab_share_down && note ' "$proxy"
expect "the address goes on only after the service is installed, before the first session" \
    bash -c 'grep -A1 "^    if passed install.service; then$" "$1" | grep -qx "        lab_share_up"' _ "$proxy"

read_manifest() { bash -c '. "$1" && l2_launch_read_manifest "$2"' _ "$launch" "$1"; }
h=$(printf '0%.0s' $(seq 1 64))
printf '%s  guest/start.sh\n%s  job.env\n' "$h" "$h" >"$work/m-ok"
expect "a manifest with guest/start.sh is read" read_manifest "$work/m-ok"
printf '%s  guest/start.sh\n%s  guest/start.sh\n' "$h" "$h" >"$work/m-dup"
expect_not "a manifest naming a file twice is refused" read_manifest "$work/m-dup"
printf '%s  job.env\n' "$h" >"$work/m-nostart"
expect_not "a manifest without guest/start.sh is refused" read_manifest "$work/m-nostart"
printf '%s guest/start.sh\n' "$h" >"$work/m-bad"
expect_not "a malformed manifest line is refused" read_manifest "$work/m-bad"
printf '%s  ../start.sh\n%s  guest/start.sh\n' "$h" "$h" >"$work/m-escape"
expect_not "a manifest path that leaves the run directory is refused" read_manifest "$work/m-escape"
: >"$work/m-empty"
expect_not "an empty manifest is refused" read_manifest "$work/m-empty"

expect "the launcher refuses to run without root" bash -c 'bash "$1" x y z 2>&1 | grep -q "with sudo"' _ "$launch"
expect "start.sh refuses to run without root" bash -c 'bash "$1" x y z 2>&1 | grep -q "with sudo"' _ "$start"
expect_not "the launcher never starts the job itself" grep -q 'systemd-run' "$launch"
expect_not "the launcher sources no other file" grep -Eq '^[[:space:]]*(\.|source)[[:space:]]' "$launch"
expect "the launcher hands over only to the verified copy of start.sh" grep -q '/bin/bash "$run/guest/start.sh"' "$launch"
expect "start.sh starts the job and reads job.env through the strict reader" \
    bash -c 'grep -q "^    systemd-run " "$1" && grep -q "l2_read_env_file \"\$run/job.env\"" "$1"' _ "$start"

# --- one-time launcher installation
sudoers_line() { bash -c '. "$1" && l2_sudoers_line "$2" "$3"' _ "$installer" "$1" "$2"; }
installed=$(bash -c '. "$1" && printf %s "$L2_LAUNCHER"' _ "$installer")
expect "the installer and the launcher agree on the path" \
    test "$installed" = "$(bash -c '. "$1" && printf %s "$L2_LAUNCH_INSTALLED"' _ "$launch")"
line=$(sudoers_line l2admin "$installed")
expect "the sudoers rule is the one expected line" \
    test "$line" = 'l2admin ALL=(root) NOPASSWD: /usr/local/libexec/rosetun-l2/launch'
expect "the sudoers rule is a single line" test "$(sudoers_line l2admin "$installed" | wc -l)" -eq 1
expect "the sudoers rule names exactly one absolute command, not ALL" \
    bash -c 'cmd=${1#*NOPASSWD: }; [ "$cmd" = "$2" ] && [[ $cmd == /* ]] && [[ $cmd != *" "* ]] && [[ $cmd != *ALL* ]]' _ "$line" "$installed"
visudo=$(PATH=$PATH:/usr/sbin:/sbin command -v visudo || true)
if [ -n "$visudo" ]; then
    printf '%s\n' "$line" >"$work/sudoers"
    expect "visudo accepts the sudoers rule" "$visudo" -cqf "$work/sudoers"
else
    printf 'note  visudo is not installed; the sudoers syntax was not checked\n'
fi
check_user() { bash -c '. "$1" && l2_check_sudo_user "$2" "$3" "$4" "$5"' _ "$installer" "$@"; }
expect "an ordinary SSH account may get the rule" check_user l2admin 1000 ipc_owner ipc_other
expect_not "an empty SUDO_USER is refused" check_user '' 1000 ipc_owner ipc_other
expect_not "root is refused" check_user root 0 ipc_owner ipc_other
expect_not "an account with uid 0 is refused" check_user toor 0 ipc_owner ipc_other
expect_not "the first test account is refused" check_user ipc_owner 1001 ipc_owner ipc_other
expect_not "the second test account is refused" check_user ipc_other 1002 ipc_owner ipc_other
expect_not "an odd account name is refused" check_user 'l2 admin' 1000 ipc_owner ipc_other
expect "the installer refuses to run without root" bash -c 'bash "$1" ipc_owner ipc_other 2>&1 | grep -q "with sudo"' _ "$installer"

printf 'selftest-lib: %s passed, %s failed\n' "$passes" "$failures"
[ "$failures" -eq 0 ]
