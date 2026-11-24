#!/usr/bin/env bash
# Build OVMF with Secure Boot and without SMM (SMM_REQUIRE=FALSE) from edk2 at a pinned tag.
#
#     build-ovmf.sh WORK_DIRECTORY
#
# Nothing is installed into the system. The three build tools the stand lacks (nasm, iasl, the uuid
# headers) come from pinned Debian packages unpacked with `dpkg -x` into WORK_DIRECTORY/tools. The
# work directory must be outside the repository. The result is WORK_DIRECTORY/out:
#
#     OVMF_CODE.fd, OVMF_VARS.fd, OVMF_VARS.ms.fd, firmware.json
#
# OVMF_VARS.ms.fd is the variable template with the platform key of the lab and the Microsoft keys
# of 2011 and 2023 (db and KEK) enrolled and Secure Boot switched on. It is made from the empty
# store of this very build with virt-firmware, a pinned pip release in a venv of the work directory.
# VARS_TEMPLATE=debian copies the template of the Debian `ovmf` package instead (2011 keys only)
# after checking that its store has the layout of this build.
set -euo pipefail

EDK2_TAG=edk2-stable202502
EDK2_URL=https://github.com/tianocore/edk2.git
DEBIAN_POOL=https://deb.debian.org/debian/pool/main
# 26.x needs a module that Python 3.13 no longer has.
VIRT_FIRMWARE_VERSION=25.12
PLATFORM_KEY_NAME='Rosetun lab Secure Boot'
# name|pool path|SHA-256 of the .deb (Debian trixie, as of 2026-11-19)
DEBS=(
    'nasm_2.16.03-1_amd64.deb|n/nasm|e5096e91356d643f54d46f3ede1d8d44e45c81a3995fb057c28ec51e3791818f'
    'acpica-tools_20250404-1_amd64.deb|a/acpica-unix|eea598bdb5d10ae51801f7c586a51f33335c60d964f5f18203cdda47fd5ab069'
    'uuid-dev_2.41.5-0+deb13u1_amd64.deb|u/util-linux|cb7d7db20e5d91193c2c6629a3f4aa917e3bc558c72b7f2db7203bcfa9a3ba1b'
)
# The flags are the ones of the Debian build, minus network boot: the guest boots from a disk and a
# disc, and the build network has no PXE or iSCSI server to offer. HTTP boot, TLS and IPv6 are off
# in this tag by default (Debian turns them on). The network driver stack itself stays: the
# firmware description of this tag names the virtio network driver unconditionally.
BUILD_FLAGS=(-D SECURE_BOOT_ENABLE=TRUE -D SMM_REQUIRE=FALSE -D TPM2_ENABLE=TRUE -D FD_SIZE_4MB
             -D NETWORK_PXE_BOOT_ENABLE=FALSE -D NETWORK_ISCSI_ENABLE=FALSE)
DEBIAN_VARS=/usr/share/OVMF/OVMF_VARS_4M.ms.fd

work=${1:?usage: build-ovmf.sh WORK_DIRECTORY}
mkdir -p "$work"
work=$(cd "$work" && pwd)
case "$work" in
    */rosetun|*/rosetun/*) echo 'the work directory must be outside the repository' >&2; exit 2 ;;
esac
prefix=$work/tools
out=$work/out
mkdir -p "$work/debs" "$prefix" "$out"

for entry in "${DEBS[@]}"; do
    IFS='|' read -r name path sha <<<"$entry"
    if [ ! -f "$work/debs/$name" ]; then
        curl -fsSL -o "$work/debs/$name" "$DEBIAN_POOL/$path/$name"
    fi
    echo "$sha  $work/debs/$name" | sha256sum -c --quiet
    dpkg -x "$work/debs/$name" "$prefix"
done

export PATH="$prefix/usr/bin:$PATH"
export C_INCLUDE_PATH="$prefix/usr/include${C_INCLUDE_PATH:+:$C_INCLUDE_PATH}"
export LIBRARY_PATH="$prefix/usr/lib/x86_64-linux-gnu${LIBRARY_PATH:+:$LIBRARY_PATH}"
export NASM_PREFIX="$prefix/usr/bin/"
export IASL_PREFIX="$prefix/usr/bin/"
export PYTHON_COMMAND=python3
# The `libuuid.so` link of uuid-dev points at a library of the same package family that was not
# unpacked; the runtime library the stand already has is the one to link against.
system_uuid=/usr/lib/x86_64-linux-gnu/libuuid.so.1
test -e "$system_uuid" || { echo 'the stand has no libuuid.so.1' >&2; exit 1; }
ln -sf "$system_uuid" "$prefix/usr/lib/x86_64-linux-gnu/libuuid.so"
nasm -v >/dev/null
iasl -v >/dev/null

if [ ! -d "$work/edk2/.git" ]; then
    git clone --branch "$EDK2_TAG" --depth 1 --recurse-submodules --shallow-submodules --jobs 4 \
        "$EDK2_URL" "$work/edk2"
fi
cd "$work/edk2"
commit=$(git rev-parse "$EDK2_TAG^{commit}")
test "$(git rev-parse HEAD)" = "$commit"
if git submodule status --recursive | grep -q '^[-+U]'; then
    echo 'a submodule is not at the commit the tag pins' >&2
    exit 1
fi

if grep -q '_GCC5_' BaseTools/Conf/tools_def.template; then
    toolchain=GCC5
else
    toolchain=GCC
fi

# edksetup.sh reads the arguments of whoever sources it as its own options.
set --
set +u
# shellcheck disable=SC1091
. ./edksetup.sh
set -u
make -C BaseTools -j"$(nproc)" >"$work/basetools.log" 2>&1
# A build directory of earlier flags would be reused by the incremental build.
rm -rf "Build/OvmfX64/RELEASE_$toolchain"
build -a X64 -p OvmfPkg/OvmfPkgX64.dsc -t "$toolchain" -b RELEASE -n "$(nproc)" "${BUILD_FLAGS[@]}" \
    >"$work/build.log" 2>&1 || { tail -40 "$work/build.log" >&2; exit 1; }

fv=$work/edk2/Build/OvmfX64/RELEASE_$toolchain/FV
cp "$fv/OVMF_CODE.fd" "$out/OVMF_CODE.fd"
cp "$fv/OVMF_VARS.fd" "$out/OVMF_VARS.fd"

template_source=${VARS_TEMPLATE:-virt-firmware}
case "$template_source" in
    virt-firmware)
        python3 -m venv "$work/virt-firmware-venv"
        "$work/virt-firmware-venv/bin/pip" install --quiet "virt-firmware==$VIRT_FIRMWARE_VERSION"
        # The generated platform key is not kept: nobody can enroll another key afterwards, which is
        # what a lab image wants. The variable store keeps its layout; only variables are added.
        "$work/virt-firmware-venv/bin/virt-fw-vars" --input "$out/OVMF_VARS.fd" \
            --output "$out/OVMF_VARS.ms.fd" --enroll-generate "$PLATFORM_KEY_NAME" \
            --microsoft-db all --microsoft-kek all --secure-boot >"$work/virt-fw-vars.log" 2>&1
        ;;
    debian)
        # The firmware reinitializes a store whose firmware volume or variable store header differs
        # from its own, and the keys are lost; so compare the sizes and the headers.
        python3 - "$out/OVMF_VARS.fd" "$DEBIAN_VARS" <<'PY'
import sys
built, debian = (open(path, 'rb').read() for path in sys.argv[1:3])
if len(built) != len(debian):
    sys.exit(f'store sizes differ: {len(built)} and {len(debian)}')
# 0x38 bytes of firmware volume header, then the variable store header (GUID, size, format, state).
if built[:0x48] != debian[:0x48]:
    sys.exit('store headers differ')
PY
        cp "$DEBIAN_VARS" "$out/OVMF_VARS.ms.fd"
        ;;
    *)
        echo 'VARS_TEMPLATE is virt-firmware or debian' >&2
        exit 2
        ;;
esac

python3 - "$work" "$out" "$commit" "$toolchain" "$template_source" "$EDK2_TAG" "$EDK2_URL" \
    "${BUILD_FLAGS[*]}" "$VIRT_FIRMWARE_VERSION" "$PLATFORM_KEY_NAME" "${DEBS[@]}" <<'PY'
import hashlib, json, re, subprocess, sys
work, out, commit, toolchain, source, tag, url, flags, virt_version, key_name, *debs = sys.argv[1:]


def sha(path):
    with open(path, 'rb') as stream:
        return hashlib.sha256(stream.read()).hexdigest()


def run(*argv):
    return subprocess.run(argv, capture_output=True, text=True, check=True)


def first_line(*argv):
    result = run(*argv)
    return (result.stdout or result.stderr).strip().splitlines()[0]


submodules = [' '.join(line.split()[:2]) for line in
              run('git', '-C', f'{work}/edk2', 'submodule', 'status', '--recursive').stdout.splitlines()]
iasl = next(line.strip() for line in run(f'{work}/tools/usr/bin/iasl', '-v').stdout.splitlines()
            if 'version' in line)
template = {'file': 'OVMF_VARS.ms.fd', 'source': source}
if source == 'virt-firmware':
    vfw = f'{work}/virt-firmware-venv/bin'
    frozen = run(f'{vfw}/pip', 'freeze').stdout.split()
    listing = run(f'{vfw}/virt-fw-vars', '--input', f'{out}/OVMF_VARS.ms.fd', '--print', '--verbose').stdout
    template.update({
        'virt_firmware': virt_version, 'pip_freeze': frozen,
        'command': f'virt-fw-vars --input OVMF_VARS.fd --output OVMF_VARS.ms.fd --enroll-generate '
                   f'"{key_name}" --microsoft-db all --microsoft-kek all --secure-boot',
        'certificates': sorted(set(re.findall(r'subject (CN=.*)', listing)))})
else:
    template['note'] = 'Debian package ovmf; Microsoft 2011 keys only'

record = {
    'schema': 'rosetun.matrix.firmware.v1', 'flavour': 'secboot-nosmm', 'smm': False,
    'varstore_smm_protected': False,
    'edk2': {'url': url, 'tag': tag, 'commit': commit, 'submodules': submodules},
    'build': {'dsc': 'OvmfPkg/OvmfPkgX64.dsc', 'target': 'RELEASE', 'toolchain': toolchain,
              'architecture': 'X64', 'flags': flags},
    'tools': {'gcc': first_line('gcc', '--version'), 'python3': first_line('python3', '--version'),
              'git': first_line('git', '--version'), 'make': first_line('make', '--version'),
              'nasm': first_line(f'{work}/tools/usr/bin/nasm', '-v'), 'iasl': iasl,
              'debian_packages': [{'file': entry.split('|')[0], 'sha256': entry.split('|')[2]}
                                  for entry in debs]},
    'files': {name: sha(f'{out}/{name}') for name in ('OVMF_CODE.fd', 'OVMF_VARS.fd', 'OVMF_VARS.ms.fd')},
    'variable_template': template,
}
with open(f'{out}/firmware.json', 'w', encoding='utf-8', newline='\n') as stream:
    json.dump(record, stream, indent=2, sort_keys=True)
    stream.write('\n')
PY
echo "done: $out"
