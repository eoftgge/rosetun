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
expect "start.sh requires the L3 job, the service, the engine and the requests" test "$(printf '%s\n' "$required_l3" | wc -l)" -eq 15
while IFS= read -r path; do
    expect "every required L3 path passes both lists: $path" bash -c '. "$1" && l2_launch_path_allowed "$3" && . "$2" && l3_start_path_allowed "$3"' _ "$launch" "$start" "$path"
done <<<"$required_l3"
expect_not "an L3 stage refuses the L2 fixture" l3_allows artifacts/l2_transport_fixture
expect_not "an L3 stage refuses the L2 job" l3_allows guest/run-l2.sh
expect_not "an L2 stage refuses the L3 job" start_allows guest/run-l3.sh
expect_not "an L3 stage refuses another request" l3_allows artifacts/request-other.json
expect "start.sh picks the job by the stage" grep -q 'job="$run/guest/run-$stage.sh"' "$start"
expect "run-l3.sh reads the host node values through the strict reader" \
    grep -q 'JOB_TIMEOUT_SECONDS HOST_ADDRESS NODE_PORT PROBE_ADDRESS DNS_PROBE_ADDRESS' "$here/../guest/run-l3.sh"
expect_not "run-l3.sh never deletes the service's own table" \
    grep -Eq 'delete table inet rosetun([^-]|$)' "$here/../guest/run-l3.sh"

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
