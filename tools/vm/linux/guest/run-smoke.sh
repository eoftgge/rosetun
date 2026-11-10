#!/bin/bash
# Infrastructure only. No network, Rosetun or machine configuration operations.
smoke_boot_id() { cat /proc/sys/kernel/random/boot_id; }
smoke_vm_uuid() { tr 'A-F' 'a-f' </sys/class/dmi/id/product_uuid; }
smoke_validate() {
    local run=$1 digest=$2 key
    PROFILE='' HOST_RUN_ID='' RUN_ID='' VM_UUID='' EXPECTED_BOOT_ID='' JOB_ID='' DELAY_SECONDS=''
    local keys=(PROFILE HOST_RUN_ID RUN_ID VM_UUID EXPECTED_BOOT_ID JOB_ID DELAY_SECONDS)
    [ "$(wc -c <"$run/job.env")" -le 1024 ] || return 1
    for key in "${keys[@]}"; do
        [ "$(grep -c "^$key=" "$run/job.env")" -eq 1 ] || return 1
    done
    l2_read_env_file "$run/job.env" "${keys[@]}" || return 1
    [ "$PROFILE" = infra-smoke-v1 ] && [ "$JOB_ID" = smoke ] || return 1
    [[ $HOST_RUN_ID =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,95}$ ]] || return 1
    l2_valid_run_id "$RUN_ID" && [ "${run##*/}" = "$RUN_ID" ] || return 1
    [[ $digest =~ ^[0-9a-f]{64}$ ]] || return 1
    [ "$(sha256sum "$run/manifest.sha256" | cut -d' ' -f1)" = "$digest" ] || return 1
    [[ $VM_UUID =~ ^[0-9a-f-]{36}$ ]] && [[ $EXPECTED_BOOT_ID =~ ^[0-9a-f-]{36}$ ]] || return 1
    [ "$(smoke_boot_id)" = "$EXPECTED_BOOT_ID" ] || return 1
    [ "$(smoke_vm_uuid)" = "$VM_UUID" ] || return 1
    [[ $DELAY_SECONDS =~ ^([0-9]|[12][0-9]|30)$ ]] || return 1
}

smoke_atomic() {
    local file=$1 tmp
    tmp=$(mktemp "${file%/*}/.smoke.XXXXXX") || return 1
    cat >"$tmp" && chmod 0600 "$tmp" && sync -- "$tmp" &&
        mv -f -- "$tmp" "$file" && sync -- "${file%/*}"
}

smoke_record() {
    printf '{"schema":"rosetun.infra-smoke.v1","host_run_id":"%s","guest_run_id":"%s","vm_uuid":"%s","boot_id":"%s","job_id":"smoke","manifest_sha256":"%s","state":"%s","artifact_sha256":"%s"}\n' \
        "$HOST_RUN_ID" "$RUN_ID" "$VM_UUID" "$EXPECTED_BOOT_ID" "$DIGEST" "$1" "${2-}" |
        smoke_atomic "$RUN/report/smoke-$3.json"
}

smoke_main() {
    set -eu
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
    umask 077
    [ $# -eq 3 ] || exit 64
    local mode=$1
    RUN=$2 DIGEST=$3
    [ "$RUN" = "/var/lib/rosetun-l2/${RUN##*/}" ] && [ ! -L "$RUN" ] || exit 64
    . "$RUN/guest/lib.sh"
    [ "$(readlink -f -- "${BASH_SOURCE[0]}")" = "$RUN/guest/run-smoke.sh" ] || exit 65
    smoke_validate "$RUN" "$DIGEST" || exit 65
    smoke_execute "$mode"
}

smoke_execute() {
    local mode=$1
    case $mode in
        run)
            # Atomic claim remains after every outcome; never restart this identity.
            mkdir "$RUN/report/smoke-claim" || exit 66
            sync -- "$RUN/report" || exit 67
            trap 'smoke_record error "" terminal' ERR
            smoke_record started '' started
            sleep "$DELAY_SECONDS"
            printf 'infra-smoke-v1: bounded local diagnostic completed\n' | smoke_atomic "$RUN/report/smoke-artifact.txt"
            local hash
            hash=$(sha256sum "$RUN/report/smoke-artifact.txt" | cut -d' ' -f1)
            smoke_record succeeded "$hash" terminal
            ;;
        finalize)
            [ -f "$RUN/report/smoke-terminal.json" ] && return 0
            case ${SERVICE_RESULT-unknown} in timeout) smoke_record timeout '' terminal ;;
                *) smoke_record error '' terminal ;; esac
            ;;
        *) exit 64 ;;
    esac
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    smoke_main "$@"
fi
