#!/bin/bash
# Starts the autonomous job of one Linux L2 stand run. Only the launcher
# (guest/launch.sh) runs it, from the root-owned run directory it has just filled
# and verified; it is never run from the stage.
#
#   start.sh RUN_ID RUN_DIR MANIFEST_SHA256
#
# It checks that the run directory holds exactly the files this version of the
# stand uses, reads the job description and starts the job as a transient systemd
# unit that does not depend on the SSH session. This is stand infrastructure, not a
# Rosetun service. Changing it needs no reinstallation of the launcher.

set -u
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
umask 022

BASE=/var/lib/rosetun-l2

die() { printf 'start.sh: %s\n' "$*" >&2; exit 1; }

# The exact composition of a stage of this version, for each stage; the launcher
# accepts a wider set of names so that a new file here needs no new launcher.
l2_start_path_allowed() {
    [[ $1 =~ ^(guest/(launch|lib|run-l2|start)\.sh|scenarios\.tsv|job\.env|artifacts/(l2_transport_fixture|rosetun_helper_privileged_tests|rosetun_ipc_tests|provenance\.json))$ ]]
}
L2_START_REQUIRED=(guest/launch.sh guest/lib.sh guest/run-l2.sh guest/start.sh scenarios.tsv job.env
    artifacts/l2_transport_fixture artifacts/rosetun_helper_privileged_tests artifacts/rosetun_ipc_tests
    artifacts/provenance.json)
l3_start_path_allowed() {
    [[ $1 =~ ^(guest/(launch|lib|run-l3|start)\.sh|scenarios-l3\.tsv|job\.env|artifacts/(rosetun-helper-privileged|rosetun|sing-box|rosetun-helper\.service|rosetun-engine\.rules|request-(kill-switch|lan|lan-private|dns-lock|program-direct|program-proxy)\.json|provenance\.json))$ ]]
}
L3_START_REQUIRED=(guest/launch.sh guest/lib.sh guest/run-l3.sh guest/start.sh scenarios-l3.tsv job.env
    artifacts/rosetun-helper-privileged artifacts/rosetun artifacts/sing-box artifacts/rosetun-helper.service artifacts/rosetun-engine.rules
    artifacts/request-kill-switch.json artifacts/request-lan.json artifacts/request-lan-private.json artifacts/request-dns-lock.json
    artifacts/request-program-direct.json artifacts/request-program-proxy.json
    artifacts/provenance.json)
l4_start_path_allowed() {
    [[ $1 =~ ^(guest/(launch|lib|run-l4|start)\.sh|scenarios-l4\.tsv|job\.env|artifacts/(rosetun-helper-privileged|rosetun|sing-box|rosetun-(helper|lockdown)\.service|rosetun-engine\.rules|request-(kill-switch|lan|dns-lock)\.json|provenance\.json))$ ]]
}
proxy_start_path_allowed() {
    [[ $1 =~ ^(guest/(launch|lib|run-proxy|start)\.sh|scenarios-proxy\.tsv|job\.env|artifacts/(rosetun-helper-privileged|rosetun|desktop_proxy|sing-box|rosetun-(helper|lockdown)\.service|rosetun-engine\.rules|request-(kill-switch|lan|dns-lock|proxy|proxy-strict|proxy-share)\.json|provenance\.json))$ ]]
}
PROXY_START_REQUIRED=(guest/launch.sh guest/lib.sh guest/run-proxy.sh guest/start.sh scenarios-proxy.tsv job.env
    artifacts/rosetun-helper-privileged artifacts/rosetun artifacts/desktop_proxy artifacts/sing-box
    artifacts/rosetun-helper.service artifacts/rosetun-engine.rules artifacts/rosetun-lockdown.service artifacts/request-kill-switch.json
    artifacts/request-proxy.json artifacts/request-proxy-strict.json artifacts/request-proxy-share.json
    artifacts/provenance.json)
L4_START_REQUIRED=(guest/launch.sh guest/lib.sh guest/run-l4.sh guest/start.sh scenarios-l4.tsv job.env
    artifacts/rosetun-helper-privileged artifacts/rosetun artifacts/sing-box artifacts/rosetun-helper.service artifacts/rosetun-engine.rules
    artifacts/rosetun-lockdown.service artifacts/request-kill-switch.json artifacts/request-lan.json
    artifacts/request-dns-lock.json artifacts/provenance.json)
l5_start_path_allowed() {
    [[ $1 =~ ^(guest/(launch|lib|run-l5|start)\.sh|scenarios-l5\.tsv|job\.env|artifacts/(rosetun-old\.deb|rosetun-new\.deb|request-kill-switch\.json|request-lan\.json|request-dns-lock\.json|provenance\.json))$ ]]
}
L5_START_REQUIRED=(guest/launch.sh guest/lib.sh guest/run-l5.sh guest/start.sh scenarios-l5.tsv job.env
    artifacts/rosetun-old.deb artifacts/rosetun-new.deb artifacts/request-kill-switch.json
    artifacts/request-lan.json artifacts/request-dns-lock.json artifacts/provenance.json)

l2_start_root_only() {
    [ ! -L "$1" ] && [ "$(stat -c %u -- "$1")" -eq 0 ] && [ $((0$(stat -c %a -- "$1") & 022)) -eq 0 ]
}

smoke_start_path_allowed() {
    [[ $1 =~ ^(guest/(launch|lib|run-smoke|start)\.sh|job\.env)$ ]]
}
SMOKE_START_REQUIRED=(guest/launch.sh guest/lib.sh guest/run-smoke.sh guest/start.sh job.env)

l2_start_main() {
    [ "$(id -u)" -eq 0 ] || die "run it through the launcher with sudo"
    [ $# -eq 3 ] || die "usage: start.sh RUN_ID RUN_DIR MANIFEST_SHA256"
    local run_id=$1 run=$2 manifest_hash=$3
    [[ $run_id =~ ^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$ ]] || die "invalid run id"
    [[ $manifest_hash =~ ^[0-9a-f]{64}$ ]] || die "invalid manifest hash"
    [ "$run" = "$BASE/$run_id" ] || die "the run directory must be $BASE/$run_id"
    [ "$(readlink -f -- "${BASH_SOURCE[0]}")" = "$run/guest/start.sh" ] ||
        die "start.sh runs only from the run directory the launcher filled"
    [ -d "$BASE" ] && l2_start_root_only "$BASE" || die "$BASE is not a root-owned directory without group or other write"
    local dir
    for dir in "$run" "$run/guest"; do
        [ -d "$dir" ] && l2_start_root_only "$dir" || die "$dir is not a root-owned directory without group or other write"
    done
    [ -f "$run/manifest.sha256" ] && l2_start_root_only "$run/manifest.sha256" || die "the run's manifest is missing or not root-owned"
    [ "$(sha256sum -- "$run/manifest.sha256" | cut -d' ' -f1)" = "$manifest_hash" ] || die "the run's manifest is not the one the host computed"

    # A stage that carries the L3, L4 or L5 job is that stage and must hold only its files.
    local stage=l2 allowed=l2_start_path_allowed required=("${L2_START_REQUIRED[@]}")
    if grep -q '  guest/run-smoke\.sh$' "$run/manifest.sha256"; then
        stage=smoke allowed=smoke_start_path_allowed required=("${SMOKE_START_REQUIRED[@]}")
    elif grep -q '  guest/run-l3\.sh$' "$run/manifest.sha256"; then
        stage=l3 allowed=l3_start_path_allowed required=("${L3_START_REQUIRED[@]}")
    elif grep -q '  guest/run-l4\.sh$' "$run/manifest.sha256"; then
        stage=l4 allowed=l4_start_path_allowed required=("${L4_START_REQUIRED[@]}")
    elif grep -q '  guest/run-l5\.sh$' "$run/manifest.sha256"; then
        stage=l5 allowed=l5_start_path_allowed required=("${L5_START_REQUIRED[@]}")
    elif grep -q '  guest/run-proxy\.sh$' "$run/manifest.sha256"; then
        stage=proxy allowed=proxy_start_path_allowed required=("${PROXY_START_REQUIRED[@]}")
    fi
    if [ "$stage" != smoke ]; then
        [ -d "$run/artifacts" ] && l2_start_root_only "$run/artifacts" || die "unsafe artifacts directory"
    fi
    local line path paths=()
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        [[ $line =~ ^[0-9a-f]{64}\ \ (.+)$ ]] || die "malformed manifest line"
        path=${BASH_REMATCH[1]}
        "$allowed" "$path" || die "manifest names a path the $stage stand does not use: $path"
        paths+=("$path")
    done <"$run/manifest.sha256"
    local need
    for need in "${required[@]}"; do
        printf '%s\n' "${paths[@]}" | grep -qxF -- "$need" || die "the manifest lacks $need"
    done
    (cd -- "$run" && sha256sum --check --strict --quiet manifest.sha256) || die "a file of the run does not match the manifest"
    local found expected
    found=$(cd -- "$run" && find . -mindepth 1 ! -name manifest.sha256 ! -type d -printf '%P\n' | LC_ALL=C sort)
    expected=$(printf '%s\n' "${paths[@]}" | LC_ALL=C sort)
    [ "$found" = "$expected" ] || die "the run directory holds files the manifest does not list"
    found=$(cd -- "$run" && find . -mindepth 1 -type d -printf '%P\n' | LC_ALL=C sort | tr '\n' ' ')
    if [ "$stage" = smoke ]; then
        [ "$found" = "guest " ] || die "unexpected smoke folders"
    else
        [ "$found" = "artifacts guest " ] || die "the run directory holds unexpected folders: $found"
    fi

    if [ "$stage" = smoke ]; then
        . "$run/guest/lib.sh"
        . "$run/guest/run-smoke.sh"
        smoke_validate "$run" "$manifest_hash" || die "invalid smoke identity or inputs"
        install -d -m 0700 -- "$run/report" || die "cannot create smoke report"
        sync -- "$run" || die "cannot sync smoke run"
        local smoke_job="$run/guest/run-smoke.sh"
        systemd-run --quiet --collect --unit="rosetun-l2-$run_id" \
            --property=KillMode=control-group --property=TimeoutStopSec=5 \
            --property=RuntimeMaxSec=45 --property=LimitFSIZE=8192 \
            --property=StandardOutput=null --property=StandardError=null \
            --property="ExecStopPost=/bin/bash $smoke_job finalize $run $manifest_hash" \
            /bin/bash "$smoke_job" run "$run" "$manifest_hash" || die "systemd-run failed"
        return
    fi

    # One stand run at a time, and only on a machine that has no Rosetun service.
    if systemctl list-units --all --no-legend 'rosetun-l2-*' 2>/dev/null | grep -q 'running\|activating'; then
        die "another stand run is still active; wait for it or stop it from the Hyper-V console"
    fi

    install -d -m 0755 -o root -g root -- "$run/report" || die "cannot create the report directory"
    install -d -m 0700 -o root -g root -- "$run/state" || die "cannot create the state directory"

    # The job description is only read through the strict reader in lib.sh.
    . "$run/guest/lib.sh"
    RUN_ID='' JOB_TIMEOUT_SECONDS=900
    local keys=(RUN_ID STAND_ID EXPECTED_BOOT_ID USER_A USER_B BIOS_GUID
        SCENARIO_TIMEOUT_SECONDS UNIT_TIMEOUT_SECONDS JOB_TIMEOUT_SECONDS)
    [ "$stage" = l2 ] || keys+=(HOST_ADDRESS NODE_PORT PROBE_ADDRESS DNS_PROBE_ADDRESS)
    # The lab observer's marker service; absent from every job.env of the Hyper-V matrix.
    [ "$stage" != l3 ] || keys+=(LAB_MARKER_ADDRESS)
    l2_read_env_file "$run/job.env" "${keys[@]}" || die "job.env is not valid"
    [ "$RUN_ID" = "$run_id" ] || die "job.env belongs to another run"
    [[ $JOB_TIMEOUT_SECONDS =~ ^[0-9]{2,5}$ ]] || die "invalid job time limit"

    # The L3 and L4 cleanups stop the real service, which may take its own 45 s.
    local unit="rosetun-l2-$run_id" job="$run/guest/run-$stage.sh"
    systemd-run --quiet --collect --unit="$unit" \
        --description="Rosetun Linux ${stage^^} stand run $run_id (test infrastructure)" \
        --property=KillMode=control-group \
        --property=TimeoutStopSec=120 \
        --property=RuntimeMaxSec="$JOB_TIMEOUT_SECONDS" \
        --property=ExecStopPost="/bin/bash $job finalize $run" \
        /bin/bash "$job" run "$run" || die "systemd-run failed"

    printf 'started %s.service\nrun directory: %s\nreport:        %s/report/report.json\n' "$unit" "$run" "$run"
    printf 'The job runs without this session. Check it from the host with -Collect.\n'
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    l2_start_main "$@"
fi
