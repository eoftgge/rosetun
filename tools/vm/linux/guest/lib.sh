#!/bin/bash
# Shared helpers of the Linux L2 stand. Sourced by the stand scripts, never run.
# Plain bash and coreutils only, so a minimal Debian guest is enough.

L2_PATH=/usr/sbin:/usr/bin:/sbin:/bin
L2_BASE=/var/lib/rosetun-l2
L2_ENDPOINT_DIR=/run/rosetun
L2_STAND_ID_FILE=/etc/rosetun-l2-stand-id
# Only the offline self-test may point the endpoint elsewhere; the systemd job
# starts with a clean environment, so the variable cannot redirect a real run.
if [ "${L2_SELFTEST-}" = 1 ] && [ -n "${L2_SELFTEST_ENDPOINT_DIR-}" ]; then
    L2_ENDPOINT_DIR=$L2_SELFTEST_ENDPOINT_DIR
fi

l2_now_utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }
l2_now_ms() { date +%s%3N; }

l2_valid_run_id() {
    [[ ${1-} =~ ^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$ ]]
}

# One line of printable ASCII, at most 300 characters. Command output can carry
# anything; the report must stay valid JSON and free of control characters.
l2_sanitize() {
    local text=${1-}
    text=$(printf '%s' "$text" | LC_ALL=C tr '\n\r\t' '   ' | LC_ALL=C tr -c ' -~' '?')
    printf '%s' "${text:0:300}"
}

l2_json_string() {
    local text
    text=$(l2_sanitize "${1-}")
    text=${text//\\/\\\\}
    text=${text//\"/\\\"}
    printf '"%s"' "$text"
}

# l2_atomic_write FILE MODE < content: temp file in the same directory, fsync,
# rename, then a best-effort fsync of the directory. Readers never see a partial file.
l2_atomic_write() {
    local file=$1 mode=$2 dir tmp
    dir=$(dirname -- "$file")
    tmp=$(mktemp "$dir/.tmp.XXXXXX") || return 1
    if cat >"$tmp" && chmod "$mode" "$tmp" && sync -- "$tmp" && mv -f -- "$tmp" "$file"; then
        sync -- "$dir" 2>/dev/null
        return 0
    fi
    rm -f -- "$tmp"
    return 1
}

# l2_append_line FILE LINE: one write per record, flushed to disk before returning.
l2_append_line() {
    printf '%s\n' "$2" >>"$1" && sync -- "$1"
}

# type|device:inode|uid:gid|mode[|sha256 of a regular file or target of a symlink].
# The object itself is described, never what a symlink points to.
l2_object_fingerprint() {
    local path=$1 base extra=''
    base=$(stat -c '%F|%d:%i|%u:%g|%a' -- "$path" 2>/dev/null) || return 1
    if [ -L "$path" ]; then
        extra=$(readlink -- "$path")
    elif [ -f "$path" ]; then
        extra=$(sha256sum -- "$path" | cut -d' ' -f1)
    fi
    printf '%s|%s' "$base" "$extra"
}

# l2_process_identity PID: "starttime exe" while the process exists and is not a
# zombie. Start time plus executable survives PID reuse.
l2_process_identity() {
    local pid=$1 line rest exe
    local -a fields
    [[ $pid =~ ^[0-9]+$ ]] || return 1
    line=$(cat "/proc/$pid/stat" 2>/dev/null) || return 1
    rest=${line##*) }
    read -r -a fields <<<"$rest"
    [ "${fields[0]-}" != Z ] && [ "${fields[0]-}" != X ] || return 1
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || return 1
    printf '%s %s' "${fields[19]-}" "$exe"
}

l2_process_alive_as() {
    local pid=$1 start=$2 exe=$3 identity
    identity=$(l2_process_identity "$pid") || return 1
    [ "$identity" = "$start $exe" ]
}

# l2_wait_process_gone PID START EXE SECONDS
l2_wait_process_gone() {
    local pid=$1 start=$2 exe=$3 deadline=$((SECONDS + $4))
    while l2_process_alive_as "$pid" "$start" "$exe"; do
        [ "$SECONDS" -lt "$deadline" ] || return 1
        sleep 0.1
    done
    return 0
}

# l2_run_bounded SECONDS COMMAND...: sets L2_RC and L2_OUT (stdout and stderr).
# A command that outlives the limit is killed; L2_RC is then 124 or 137.
l2_run_bounded() {
    local seconds=$1
    shift
    L2_OUT=$(timeout --kill-after=3 "$seconds" "$@" 2>&1 </dev/null)
    L2_RC=$?
}

l2_timed_out() { [ "${L2_RC-0}" -eq 124 ] || [ "${L2_RC-0}" -eq 137 ]; }

# Objects and processes the run created, so cleanup removes nothing else.
# objects.tsv: label|path|fingerprint   processes.tsv: label|pid|starttime|exe
l2_record_object() {
    local state=$1 label=$2 path=$3 fingerprint
    fingerprint=$(l2_object_fingerprint "$path") || return 1
    l2_append_line "$state/objects.tsv" "$label|$path|$fingerprint"
}

l2_record_process() {
    local state=$1 label=$2 pid=$3 identity start exe
    identity=$(l2_process_identity "$pid") || return 1
    start=${identity%% *}
    exe=${identity#* }
    l2_append_line "$state/processes.tsv" "$label|$pid|$start|$exe"
}

# l2_last_record FILE PATH: the newest recorded fingerprint of PATH, or nothing.
l2_last_record() {
    local file=$1 target=$2 label path fingerprint last=''
    [ -f "$file" ] || return 0
    while IFS='|' read -r label path fingerprint; do
        [ "$path" = "$target" ] && last=$fingerprint
    done <"$file"
    printf '%s' "$last"
}

# l2_remove_recorded OBJECTS_FILE PATH: unlink PATH only if it is still exactly the
# object recorded for it. Prints the reason on refusal.
l2_remove_recorded() {
    local recorded live
    recorded=$(l2_last_record "$1" "$2")
    [ -n "$recorded" ] || { echo "no record of $2 in this run"; return 1; }
    live=$(l2_object_fingerprint "$2") || { echo "$2 is already absent"; return 2; }
    [ "$recorded" = "$live" ] || { echo "$2 is not the recorded object"; return 1; }
    rm -- "$2"
}

# l2_cleanup_run STATE_DIR ENDPOINT_DIR
# Stops the processes this run started (matched by PID, start time and executable),
# then removes the recorded socket and the endpoint directory only if each is
# still the exact recorded object and the directory was absent before the run.
# Anything else is left in place. Sets L2_CLEANUP_STATUS (PASS|ERROR),
# L2_CLEANUP_ACTIONS and L2_CLEANUP_PROBLEMS.
l2_cleanup_run() {
    local state=$1 dir=$2 label pid start exe entry recorded live preexisting=yes
    local -a actions=() problems=() entries=()
    local objects=$state/objects.tsv

    if [ -f "$state/processes.tsv" ]; then
        while IFS='|' read -r label pid start exe; do
            [ -n "$pid" ] || continue
            l2_process_alive_as "$pid" "$start" "$exe" || continue
            kill -TERM "$pid" 2>/dev/null
            if ! l2_wait_process_gone "$pid" "$start" "$exe" 5; then
                kill -KILL "$pid" 2>/dev/null
                l2_wait_process_gone "$pid" "$start" "$exe" 5
            fi
            if l2_process_alive_as "$pid" "$start" "$exe"; then
                problems+=("process $label (pid $pid) did not stop")
            else
                actions+=("stopped $label (pid $pid)")
            fi
        done <"$state/processes.tsv"
    fi

    if [ -f "$state/endpoint.env" ]; then
        preexisting=$(sed -n 's/^ENDPOINT_PREEXISTING=\(yes\|no\)$/\1/p' "$state/endpoint.env" | tail -n 1)
        [ -n "$preexisting" ] || preexisting=yes
    fi

    if [ -e "$dir" ] || [ -L "$dir" ]; then
        recorded=$(l2_last_record "$objects" "$dir")
        live=$(l2_object_fingerprint "$dir")
        if [ -z "$recorded" ] && [ "$preexisting" = yes ]; then
            actions+=("$dir existed before this run and was not touched")
        elif [ -z "$recorded" ]; then
            problems+=("$dir appeared during this run but was never recorded; left untouched, inspect it with stat and ls -la")
        elif [ "$recorded" != "$live" ]; then
            problems+=("$dir is not the directory this run recorded; left untouched")
        else
            local clean=1
            shopt -s nullglob dotglob
            entries=("$dir"/*)
            shopt -u nullglob dotglob
            for entry in "${entries[@]}"; do
                if [ "$(basename -- "$entry")" != helper.sock ]; then
                    problems+=("unexpected entry $entry; left untouched")
                    clean=0
                    continue
                fi
                recorded=$(l2_last_record "$objects" "$entry")
                live=$(l2_object_fingerprint "$entry")
                if [ -n "$recorded" ] && [ "$recorded" = "$live" ]; then
                    if rm -- "$entry"; then
                        actions+=("removed $entry")
                    else
                        problems+=("could not remove $entry")
                        clean=0
                    fi
                else
                    problems+=("$entry is not the object this run recorded; left untouched")
                    clean=0
                fi
            done
            if [ "$clean" -eq 1 ] && [ "$preexisting" = no ]; then
                if rmdir -- "$dir"; then
                    actions+=("removed $dir")
                else
                    problems+=("could not remove $dir")
                fi
            elif [ "$clean" -eq 1 ]; then
                actions+=("left $dir: it existed before this run")
            fi
        fi
    else
        actions+=("no endpoint directory left")
    fi

    L2_CLEANUP_ACTIONS=$(IFS=';'; printf '%s' "${actions[*]-}")
    L2_CLEANUP_PROBLEMS=$(IFS=';'; printf '%s' "${problems[*]-}")
    if [ "${#problems[@]}" -eq 0 ]; then
        L2_CLEANUP_STATUS=PASS
    else
        L2_CLEANUP_STATUS=ERROR
    fi
}

# l2_read_env_file FILE KEY...: strict KEY=VALUE reader for the job description.
# Only listed keys, only conservative values; never evaluated by the shell.
# l2_install_engine_account STATE ART: what the package brings for the engines:
# their account, and the polkit rule that lets it set the tunnel's DNS. Each is
# noted in STATE when this run made it, for l2_remove_engine_account.
l2_install_engine_account() {
    local state=$1 art=$2
    if ! getent passwd rosetun-engine >/dev/null; then
        useradd --system --no-create-home --shell /usr/sbin/nologin rosetun-engine || return 1
        : >"$state/engine-account"
    fi
    if [ -d /usr/share/polkit-1 ]; then
        install -d -m 0755 /usr/share/polkit-1/rules.d &&
            install -m 0644 -o root -g root "$art/rosetun-engine.rules" /usr/share/polkit-1/rules.d/50-rosetun-engine.rules ||
            return 1
        : >"$state/engine-rule"
    fi
}

l2_remove_engine_account() {
    local state=$1
    if [ -f "$state/engine-rule" ]; then
        rm -f -- /usr/share/polkit-1/rules.d/50-rosetun-engine.rules "$state/engine-rule" || return 1
    fi
    if [ -f "$state/engine-account" ]; then
        userdel rosetun-engine && rm -f -- "$state/engine-account" || return 1
    fi
}

l2_read_env_file() {
    local file=$1 key value allowed line
    shift
    while IFS= read -r line || [ -n "$line" ]; do
        [ -n "$line" ] || continue
        key=${line%%=*}
        value=${line#*=}
        [ "$key" != "$line" ] || { echo "malformed line in $file" >&2; return 1; }
        allowed=0
        for entry in "$@"; do
            [ "$entry" = "$key" ] && allowed=1
        done
        [ "$allowed" -eq 1 ] || { echo "unexpected key $key in $file" >&2; return 1; }
        [[ $value =~ ^[A-Za-z0-9._:@/+=-]*$ ]] || { echo "unsafe value for $key in $file" >&2; return 1; }
        printf -v "$key" '%s' "$value"
    done <"$file"
}

# l2_guid_swap GUID: the first three fields byte-swapped. SMBIOS and Hyper-V show
# the same machine GUID in either order, so both spellings are accepted.
l2_guid_swap() {
    local g=${1,,}
    [[ $g =~ ^([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})-([0-9a-f]{2})([0-9a-f]{2})-([0-9a-f]{2})([0-9a-f]{2})-(.*)$ ]] || return 1
    printf '%s%s%s%s-%s%s-%s%s-%s' \
        "${BASH_REMATCH[4]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[1]}" \
        "${BASH_REMATCH[6]}" "${BASH_REMATCH[5]}" "${BASH_REMATCH[8]}" "${BASH_REMATCH[7]}" \
        "${BASH_REMATCH[9]}"
}
