"""Command lines of the image build and of the measurement boot, and the image descriptor.

Nothing here starts a process. The device set is one table used by both commands, and it is the set
the matrix runs will use: Windows binds the network settings to the adapter, so a different device
list or MAC at run time would create a second adapter and lose the first one's configuration.
"""

import hashlib
import json
import posixpath

SCHEMA = 'rosetun.matrix.image.v1'
PROFILE = 'windows-uefi-q35-v1'
QGA_NAME = 'org.qemu.guest_agent.0'
TPM_STATE_FILE = 'tpm2-00.permall'

# Slots on the q35 root complex are fixed so that the guest sees the same PCI addresses in every
# boot. Slot 0 is the host bridge and 0x1f the chipset; the VGA adapter takes 1.
PCI_SLOTS = {'vga': '0x1', 'disk': '0x3', 'net': '0x4', 'serial': '0x5'}
# Press-any-key of the Windows disc needs a keyboard event while it is on screen; Setup itself is
# unattended. These are the QMP key names sent for that.
PRESS_KEY = 'spc'


def _join(directory, name):
    return posixpath.join(str(directory).replace('\\', '/'), name)


class Layout:
    """File names inside one build or measurement directory."""

    def __init__(self, directory):
        self.directory = str(directory).replace('\\', '/')
        for attribute, name in (
                ('disk', 'windows.qcow2'), ('vars', 'OVMF_VARS.fd'), ('tpm_state', 'tpm'),
                ('tpm_socket', 'swtpm.sock'), ('tpm_log', 'swtpm.log'), ('qmp', 'qmp.sock'),
                ('qga', 'qga.sock'), ('answers_iso', 'answers.iso'), ('answers_tree', 'answers'),
                ('secret', 'account-password.txt'), ('descriptor', 'image.json'),
                ('events', 'build.jsonl')):
            setattr(self, attribute, _join(self.directory, name))


def swtpm_argv(config, layout):
    # --terminate: swtpm exits when QEMU closes the control connection, so no TPM outlives a run.
    return [config.swtpm, 'socket', '--tpm2', '--tpmstate', f'dir={layout.tpm_state}',
            '--ctrl', f'type=unixio,path={layout.tpm_socket}', '--terminate',
            '--log', f'file={layout.tpm_log},level=5']


def xorriso_argv(config, answers_arguments):
    return [config.xorriso, *answers_arguments]


def qemu_img_create_argv(config, layout):
    return [config.qemu_img, 'create', '-f', 'qcow2', layout.disk, f'{config.disk_gib}G']


def qemu_img_overlay_argv(config, base, overlay):
    return [config.qemu_img, 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', base, overlay]


def _blockdev(node, filename, *, read_only):
    return json.dumps({'driver': 'raw', 'node-name': node, 'read-only': read_only,
                       'file': {'driver': 'file', 'filename': filename, 'read-only': read_only}},
                      sort_keys=True)


def qemu_argv(config, layout, uuid, *, install, disk=None, vars_file=None, tpm_socket=None,
              qmp_socket=None, qga_socket=None, answers_iso=None):
    """The one QEMU command line. `install` adds the three optical drives and the boot order for Setup.

    - `-machine q35,smm=on` and the pflash pair: Secure Boot firmware keeps its variable store writable
      by system management mode only (`secure=on`) and cannot do S3 (`disable_s3=1`); both are the
      edk2 requirements of the secboot build.
    - `-cpu host,-vmx`: hides VMX from the guest, so Windows cannot start Hyper-V or virtualization-based
      security. They would put a second hypervisor under the first inside WSL2's nested KVM, which is
      slow and changes timing, and the matrix gains nothing from them.
    - virtio-blk, virtio-net and virtio-serial, the same as the Linux guests: the driver set to qualify
      is the one the matrix controller already knows. No USB, no sound, no balloon.
    - the network is a user-mode stack with `restrict=on`: the guest gets an address and nothing
      beyond it, so a build never reaches the lab or the Internet.
    """
    disk = disk or layout.disk
    vars_file = vars_file or layout.vars
    tpm_socket = tpm_socket or layout.tpm_socket
    netdev = 'user,id=buildnet,restrict=on' if config.network == 'restricted' else 'user,id=buildnet'
    argv = [config.qemu_system, '-no-user-config', '-nodefaults',
            '-machine', 'q35,smm=on', '-accel', 'kvm',
            '-global', 'ICH9-LPC.disable_s3=1',
            '-global', 'driver=cfi.pflash01,property=secure,value=on',
            '-cpu', 'host,-vmx', '-m', str(config.memory_mib), '-smp', str(config.vcpus),
            '-uuid', uuid,
            '-drive', f'if=pflash,format=raw,unit=0,readonly=on,file={config.ovmf_code}',
            '-drive', f'if=pflash,format=raw,unit=1,file={vars_file}',
            '-blockdev', json.dumps({'driver': 'qcow2', 'node-name': 'root', 'discard': 'unmap',
                                     'file': {'driver': 'file', 'filename': disk}}, sort_keys=True),
            '-device', f'virtio-blk-pci,drive=root,bus=pcie.0,addr={PCI_SLOTS["disk"]},bootindex=1',
            '-netdev', netdev,
            '-device', f'virtio-net-pci,netdev=buildnet,id=test-wire,mac={config.mac},'
                       f'bus=pcie.0,addr={PCI_SLOTS["net"]}',
            '-device', f'virtio-serial-pci,id=guestserial,bus=pcie.0,addr={PCI_SLOTS["serial"]}',
            '-chardev', f'socket,id=guestagent,path={qga_socket or layout.qga},server=on,wait=off',
            '-device', f'virtserialport,bus=guestserial.0,chardev=guestagent,name={QGA_NAME}',
            '-chardev', f'socket,id=chrtpm,path={tpm_socket}',
            '-tpmdev', 'emulator,id=tpm0,chardev=chrtpm',
            '-device', 'tpm-crb,tpmdev=tpm0',
            '-device', f'VGA,bus=pcie.0,addr={PCI_SLOTS["vga"]}',
            # Diagnostics for the owner only: loopback, no password, one display number.
            '-display', f'vnc=127.0.0.1:{config.vnc_display}',
            '-qmp', f'unix:{qmp_socket or layout.qmp},server=on,wait=off',
            '-monitor', 'none', '-serial', 'none', '-parallel', 'none']
    if install:
        for index, (node, path) in enumerate((('winiso', config.windows_iso),
                                              ('virtio', config.virtio_win_iso),
                                              ('answers', answers_iso or layout.answers_iso))):
            argv += ['-blockdev', _blockdev(node, path, read_only=True),
                     '-device', f'ide-cd,drive={node},bus=ide.{index},'
                                f'bootindex={2 if node == "winiso" else 3 + index}']
    return argv


def sha256_file(path, block=1024 * 1024):
    digest = hashlib.sha256()
    size = 0
    with open(path, 'rb') as stream:
        while chunk := stream.read(block):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def descriptor(config, layout, *, uuid, windows_iso_sha256, disk_sha256, disk_size, vars_sha256,
               tpm_files, built_at):
    """The image descriptor. The Windows fields are an extension of the Linux contract; the controller
    accepts none of it until the launch profile of stage 9b exists, so `qualified` stays false."""
    return {
        'schema': SCHEMA, 'identifier': config.identifier, 'guest_os': 'windows',
        'architecture': 'x86_64', 'path': layout.disk, 'size_bytes': disk_size,
        'sha256': disk_sha256, 'format': 'qcow2', 'profile': PROFILE,
        'windows': {
            'edition': config.edition_name or f'image index {config.image_index}',
            'language': config.language, 'hostname': config.hostname, 'account': config.username,
            'activated': False, 'qualified': False, 'built_at': built_at,
            'installation_media': {'sha256': windows_iso_sha256},
            'virtio_win': {'version': config.virtio_win_version, 'sha256': config.virtio_win_sha256},
            'uefi': {'secure_boot': True, 'code': config.ovmf_code,
                     'vars': {'path': layout.vars, 'sha256': vars_sha256}},
            'tpm': {'version': '2.0', 'device': 'tpm-crb', 'emulator': 'swtpm',
                    'state': {'directory': layout.tpm_state, 'files': tpm_files}},
            'devices': {'machine': 'q35', 'cpu': 'host,-vmx', 'memory_mib': config.memory_mib,
                        'vcpus': config.vcpus, 'disk': 'virtio-blk-pci', 'net': 'virtio-net-pci',
                        'mac': config.mac, 'serial': 'virtio-serial-pci', 'qga': QGA_NAME,
                        'pci_slots': dict(PCI_SLOTS), 'uuid_at_build': uuid},
        },
    }
