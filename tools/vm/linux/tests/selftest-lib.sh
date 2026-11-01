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

printf 'selftest-lib: %s passed, %s failed\n' "$passes" "$failures"
[ "$failures" -eq 0 ]
