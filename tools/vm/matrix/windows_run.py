"""The launch profile of a Windows guest (stage 9b): command lines, per-run state files and their checks.

Nothing here starts a process. The device list, the PCI slots, the MAC and the CPU string are the ones the
descriptor of the image names, because Windows binds its network settings to the adapter: another list or
another MAC at run time would create a second adapter and drop the first one's configuration. The run
starts from copies of the firmware variables and of the TPM state of the image, made into the run
directory, so that the image is never written and every run begins from the same state.
"""

import hashlib
import json
import os
from pathlib import Path
import stat

from .images import FIRMWARE_LIMIT, sha256_of
from .resources import resource_path

RUN_VARS = 'OVMF_VARS.fd'
TPM_DIRECTORY = 'tpm'
SWTPM_SOCKET = 'swtpm.sock'
SWTPM_LOG = 'swtpm.log'
SCREENSHOT = 'screendump.png'
# The id of the firmware-variables copy; the TPM files follow as windows-tpm-0, windows-tpm-1, ...
VARS_ID = 'windows-vars'
TPM_ID = 'windows-tpm-'
# What a Windows start adds to the lifecycle journal on top of the ordinary rows: the swtpm start row and one
# swtpm exit row for each of the two closes that a failed teardown may need.
JOURNAL_MARGIN = 4


def run_files(facts):
    """The files a run holds copies of: (resource id, path relative to the run directory), in a fixed order."""
    files = [(VARS_ID, RUN_VARS)]
    files += [(TPM_ID + str(index), TPM_DIRECTORY + '/' + name)
              for index, name in enumerate(facts['tpm_files'])]
    return files


def expected_digests(facts):
    """The SHA-256 each copy must have until the guest has run: that of the image's own file."""
    digests = {RUN_VARS: facts['vars'][1]}
    digests.update({TPM_DIRECTORY + '/' + name: digest for name, digest in facts['tpm_files'].items()})
    return digests


def swtpm_argv(config, run_directory):
    """`--terminate` makes swtpm end when QEMU closes its control connection, so no TPM outlives a run.

    The socket is the owner's alone: swtpm gives its control socket mode 0660 whatever the umask says, and the
    controller refuses a control socket that others can reach.
    """
    directory = str(run_directory)
    return [config.swtpm, 'socket', '--tpm2', '--tpmstate', f'dir={directory}/{TPM_DIRECTORY}',
            '--ctrl', f'type=unixio,path={directory}/{SWTPM_SOCKET},mode=0600', '--terminate',
            '--log', f'file={directory}/{SWTPM_LOG},level=1']


def check(config, image):
    """The configuration must name what the image was built with: any other firmware or machine is refused."""
    facts = image.facts()
    if (config.machine != facts['machine'] or config.bios != facts['code'][0]
            or config.memory_mib != facts['memory_mib'] or config.vcpus != facts['vcpus']
            or config.qga is not True or config.cpu != 'host'):
        raise ValueError('windows-configuration-image-mismatch')


def launch(config, image, overlay, vm_uuid):
    """The QEMU argv (without the monitor, the agent channel and `-S`, which `lifecycle.start` adds) and the
    record of the run's own files and of the swtpm command; the run directory is the overlay's."""
    facts = image.facts()
    check(config, image)
    if overlay.name != 'root.qcow2':
        raise ValueError('unexpected-overlay-name')
    directory = str(overlay.parent)
    slots = facts['slots']
    argv = [config.executable, '-no-user-config', '-nodefaults',
            '-machine', 'q35,smm=on' if facts['smm'] else 'q35,smm=off', '-accel', 'kvm',
            # S3 is off in the firmware: the Secure Boot build of OVMF cannot do it.
            '-global', 'ICH9-LPC.disable_s3=1']
    if facts['smm']:
        argv += ['-global', 'driver=cfi.pflash01,property=secure,value=on']
    # The disk is an overlay over the verified, read-only image; the firmware code is read-only and the
    # variables are this run's own copy.
    base = {'driver': 'qcow2', 'read-only': True, 'backing': None,
            'file': {'driver': 'file', 'filename': image.path}}
    disk = {'driver': 'qcow2', 'node-name': 'root', 'backing': base,
            'file': {'driver': 'file', 'filename': directory + '/root.qcow2'}}
    argv += ['-cpu', facts['cpu'], '-m', str(config.memory_mib), '-smp', str(config.vcpus),
             # The guest keeps UTC (the answer file sets the zone, the time service is off), so its clock is the
             # host's RTC read as UTC; QEMU's default says the same, and it is given so that nothing depends on it.
             '-uuid', vm_uuid, '-rtc', 'base=utc', '-nic', 'none',
             '-drive', f'if=pflash,format=raw,unit=0,readonly=on,file={facts["code"][0]}',
             '-drive', f'if=pflash,format=raw,unit=1,file={directory}/{RUN_VARS}',
             '-blockdev', json.dumps(disk, sort_keys=True),
             '-device', f'virtio-blk-pci,drive=root,bus=pcie.0,addr={slots["disk"]},bootindex=1',
             # No network backend: the adapter exists, as in the image, and is not connected to anything.
             '-device', f'virtio-net-pci,id=test-wire,mac={facts["mac"]},bus=pcie.0,addr={slots["net"]}',
             '-chardev', f'socket,id=chrtpm,path={directory}/{SWTPM_SOCKET}',
             '-tpmdev', 'emulator,id=tpm0,chardev=chrtpm', '-device', 'tpm-crb,tpmdev=tpm0',
             # The display is a VGA adapter nobody watches (`screendump` reads it): no VNC, no window.
             '-device', f'VGA,bus=pcie.0,addr={slots["vga"]}',
             '-display', 'none', '-monitor', 'none', '-serial', 'none', '-parallel', 'none']
    record = {'smm': facts['smm'], 'cpu': facts['cpu'], 'vars': directory + '/' + RUN_VARS,
              'tpm_directory': directory + '/' + TPM_DIRECTORY, 'tpm_files': list(facts['tpm_files']),
              'swtpm_argv': swtpm_argv(config, directory),
              'qga_device': f'virtio-serial-pci,id=guestserial,bus=pcie.0,addr={slots["serial"]}'}
    return argv, record


WIRE_BACKEND = 'labwire'


def join_wire(argv, mac, wire_id='test-wire'):
    """`argv` with the image's network adapter attached to the lab's wire backend.

    The adapter is the one the launch profile names, with the image's MAC; it is never added a second time, because
    a second adapter would leave the first one's network settings behind. The MAC must be the test machine's of the
    lab: an adapter with another address would not be the machine the lab's observer judges.
    """
    from .lab_protocol import MACS
    if mac != MACS['test']:
        raise ValueError('windows-mac-is-not-the-labs-test-machine')
    wanted = f'virtio-net-pci,id={wire_id},mac={mac},'
    found = [index for index, item in enumerate(argv) if item.startswith(wanted)]
    if len(found) != 1:
        raise ValueError('windows-network-adapter-not-found')
    return [item + ',netdev=' + WIRE_BACKEND if index == found[0] else item for index, item in enumerate(argv)]


def _copy(source, target, digest):
    """Copy one small file into the run, checking the bytes against the image's digest while they move."""
    hasher = hashlib.sha256()
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(descriptor, 'wb') as out, open(source, 'rb') as stream:
        remaining = FIRMWARE_LIMIT + 1
        while remaining:
            block = stream.read(min(1024 * 1024, remaining))
            if not block:
                break
            remaining -= len(block)
            hasher.update(block)
            out.write(block)
        out.flush()
        os.fsync(out.fileno())
    if remaining <= 0 or hasher.hexdigest() != digest or sha256_of(target, FIRMWARE_LIMIT) != digest:
        raise ValueError('windows-state-copy-mismatch')


def prepare_files(run, image, event):
    """Copy the firmware variables and the TPM state of the image into the run, registering each file first.

    The image's own files are only read. `event` receives one diagnostics row naming the copies and their digests.
    """
    facts = image.facts()
    directory = Path(run.directory)
    tpm = resource_path(directory, TPM_DIRECTORY)
    sources = {RUN_VARS: facts['vars'][0]}
    sources.update({TPM_DIRECTORY + '/' + name: os.path.join(facts['tpm_directory'], name)
                    for name in facts['tpm_files']})
    digests = expected_digests(facts)
    for identifier, relative in run_files(facts):
        run.register({'id': identifier, 'kind': 'file', 'path': relative})
    tpm.mkdir(mode=0o700)
    if os.name == 'posix':
        os.chmod(tpm, 0o700)
    for relative, source in sources.items():
        run._read()
        _copy(source, resource_path(directory, relative), digests[relative])
    event({'stage': 'windows-files', 'status': 'copied', 'digests': digests})


def verify_files(run_directory, image):
    """Before the launch the copies still are the image's files, byte for byte."""
    facts = image.facts()
    for relative, digest in expected_digests(facts).items():
        path = resource_path(run_directory, relative)
        if not stat.S_ISREG(path.lstat().st_mode) or sha256_of(path, FIRMWARE_LIMIT) != digest:
            raise ValueError('windows-state-copy-mismatch')


def check_resources(manifest, image):
    """The copies of the run are exactly the ones the image calls for, no more and no fewer."""
    wanted = dict(run_files(image.facts()))
    found = {r['id']: r['path'] for r in manifest['resources']
             if r['id'] == VARS_ID or r['id'].startswith(TPM_ID)}
    if found != wanted:
        raise ValueError('incomplete-windows-resources')
