"""Disk preparation and launch plans; execution is isolated in lifecycle.py."""

from dataclasses import dataclass, asdict
import json
import math
import os
import re
import subprocess
import threading
import uuid

from .images import IMAGE_REFUSALS, WindowsImageDescriptor, image_chain, local_file
from . import windows_run
from .evidence import append_row
from .resources import resource_path, execution_resources

OUTPUT_LIMIT = 256 * 1024
TIMEOUT_SECONDS = 30


class CommandError(ValueError):
    pass


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes = b''


def execute(argv, *, timeout, output_limit):
    """Bound both pipes during collection; discard raw exceptions at the API boundary."""
    if (type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0
            or type(output_limit) is not int or output_limit <= 0):
        raise CommandError('invalid-command-limits')
    # Unbuffered pipes avoid a buffered-reader close waiting on its reader lock.
    # Do not use Popen's context manager: its __exit__ may wait without a timeout.
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, shell=False, bufsize=0)
    threads = []
    try:
        buffers = [bytearray(), bytearray()]
        overflow = threading.Event()
        read_error = threading.Event()

        def stop():
            try:
                process.kill()
            except OSError:
                pass

        def drain(pipe, buffer):
            try:
                while block := pipe.read(4096):
                    remaining = output_limit + 1 - len(buffer)
                    buffer.extend(block[:max(0, remaining)])
                    if len(buffer) > output_limit:
                        overflow.set()
                        stop()
                        break
            except (OSError, ValueError):
                read_error.set()
                stop()

        threads = [threading.Thread(target=drain, args=pair, daemon=True)
                   for pair in zip((process.stdout, process.stderr), buffers)]
        for thread in threads:
            thread.start()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            raise CommandError("command-timeout") from None
        for thread in threads:
            thread.join(timeout=1)
        if overflow.is_set() or any(thread.is_alive() for thread in threads):
            raise CommandError("command-output-limit")
        if read_error.is_set():
            raise CommandError("command-output-read-failed")
        return CommandResult(process.returncode, bytes(buffers[0]), bytes(buffers[1]))
    except CommandError as error:
        # Callers may retain bounded partial diagnostics for failed preparation.
        error.stdout, error.stderr = bytes(buffers[0][:output_limit]), bytes(buffers[1][:output_limit])
        raise
    finally:
        try:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)
        finally:
            process.stdout.close()
            process.stderr.close()
            for thread in threads:
                thread.join(timeout=1)


@dataclass(frozen=True)
class QemuConfig:
    schema: str
    executable: str
    image_executable: str
    bios: str
    machine: str
    accelerator: str = 'kvm'
    cpu: str = 'host'
    memory_mib: int = 1024
    vcpus: int = 1
    qga: bool = False

    def validate(self):
        if (self.schema != 'rosetun.matrix.qemu.v1' or self.accelerator != 'kvm'
                or self.cpu != 'host' or type(self.machine) is not str
                or not re.fullmatch(r'pc-i440fx-[0-9]+\.[0-9]+', self.machine)):
            raise ValueError("unsupported QEMU configuration")
        self._validate_common()

    def _validate_common(self):
        if type(self.memory_mib) is not int or not 256 <= self.memory_mib <= 65536:
            raise ValueError("memory out of range")
        if type(self.vcpus) is not int or not 1 <= self.vcpus <= 64:
            raise ValueError("vCPU count out of range")
        if type(self.qga) is not bool:
            raise ValueError('invalid QGA option')
        for path in (self.executable, self.image_executable, self.bios):
            local_file(path)


@dataclass(frozen=True)
class WindowsQemuConfig(QemuConfig):
    """The launch configuration of a Windows image: machine `q35`, the agent channel, and the TPM emulator.

    `bios` is the firmware code the image was built with. The configuration of a Linux guest has no such
    field, so the Linux execution files keep their exact field list.
    """

    swtpm: str = ''

    def validate(self):
        # The image's device list has the agent channel, so the profile always has it.
        if (self.schema != 'rosetun.matrix.qemu.v1' or self.accelerator != 'kvm' or self.cpu != 'host'
                or self.machine != 'q35' or self.qga is not True or type(self.swtpm) is not str):
            raise ValueError("unsupported QEMU configuration")
        local_file(self.swtpm)
        self._validate_common()


def qemu_config_of(record):
    """The configuration a launch plan carries: the Windows one when it names a TPM emulator."""
    return WindowsQemuConfig(**record) if type(record) is dict and 'swtpm' in record else QemuConfig(**record)


def _launch_plan(config, image, overlay, vm_uuid, *, media=None):
    """Build only after prepare has verified the owned overlay and image chain."""
    config.validate()
    uuid.UUID(vm_uuid)
    windows = isinstance(image, WindowsImageDescriptor)
    if windows != isinstance(config, WindowsQemuConfig):
        raise ValueError('image-profile-machine-mismatch')
    if windows:
        if media is not None:
            raise ValueError('unsupported-windows-media')
        argv, record = windows_run.launch(config, image, overlay, vm_uuid)
        configuration = asdict(config)
        return {'schema': 'rosetun.matrix.qemu-launch.v1', 'executed': False,
                'kvm_qualified': False, 'firmware_profile': image.profile,
                'uuid': vm_uuid, 'image': image.record(), 'config': configuration, 'argv': argv,
                'windows_run': record}
    # JSON avoids the -drive keyval grammar. The verified base is read-only and
    # its backing is explicitly null rather than discovered at VM startup.
    base = {'driver': 'qcow2', 'read-only': True, 'backing': None,
            'file': {'driver': 'file', 'filename': image.path}}
    disk = {'driver': 'qcow2', 'node-name': 'root', 'backing': base,
            'file': {'driver': 'file', 'filename': str(overlay)}}
    argv = [config.executable, '-no-user-config', '-nodefaults',
            '-machine', config.machine, '-accel', 'kvm', '-cpu', 'host',
            '-m', str(config.memory_mib), '-smp', str(config.vcpus),
            '-uuid', vm_uuid, '-bios', config.bios, '-nic', 'none',
            '-display', 'none', '-monitor', 'none', '-serial', 'none',
            '-parallel', 'none', '-blockdev', json.dumps(disk, sort_keys=True),
            '-device', 'virtio-blk-pci,drive=root']
    if media is not None:
        from .l2_media import SERIAL
        if not config.qga or config.machine != 'pc-i440fx-10.0':
            raise ValueError('unsupported-l2-media-configuration')
        argv[argv.index('virtio-blk-pci,drive=root')] = 'virtio-blk-pci,drive=root,bootindex=1'
        argv += ['-blockdev', json.dumps(dict(driver='raw', **{'node-name': 'l2media',
                 'read-only': True, 'file': dict(driver='file', filename=media['path'],
                                               **{'read-only': True})}), sort_keys=True),
                 '-device', 'virtio-blk-pci,drive=l2media,id=l2media,serial=' + SERIAL]
    configuration = asdict(config)
    if not config.qga:
        configuration.pop('qga')
    result = {'schema': 'rosetun.matrix.qemu-launch.v1', 'executed': False,
            'kvm_qualified': False, 'firmware_profile': image.profile,
            'uuid': vm_uuid, 'image': image.record(), 'config': configuration, 'argv': argv}
    if media is not None:
        result['l2_media'] = media
    return result


def prepare(run, image, config, *, executor=execute):
    """Prepare one disk in an owned, empty PreparedRun under its StandLease.

    Executor receives argv, timeout and output_limit, and returns CommandResult.
    Never retry in this directory; retain failed and partial resources.
    """
    manifest = run._read()
    if manifest['state'] != 'prepared' or manifest['resources'] != execution_resources(manifest):
        raise ValueError("preparation requires an empty owned run")
    diagnostics = 'preparation.jsonl'
    plan_path = 'launch-plan.json'
    overlay_path = 'root.qcow2'
    for name in (diagnostics, plan_path, overlay_path):
        path = resource_path(run.directory, name)
        if path.exists():
            raise ValueError("preparation destination already exists")
    for name in (diagnostics, plan_path):
        run.register({'id': name.split('.')[0], 'kind': 'file', 'path': name})

    def event(value, *, initial=False):
        # No external output, exception strings or ownership records are logged.
        append_row(run, diagnostics, value, create=initial, forbid=run._identity[2])

    stage = 'validate'
    overlay = resource_path(run.directory, overlay_path)
    try:
        event({'stage': stage, 'status': 'started'}, initial=True)
        config.validate()
        if isinstance(image, WindowsImageDescriptor) != isinstance(config, WindowsQemuConfig):
            raise ValueError("image profile and machine do not match")
        if isinstance(image, WindowsImageDescriptor):
            windows_run.check(config, image)
        if run._identity[2] in json.dumps({'image': image.record(), 'config': asdict(config),
                                          'directory': str(run.directory)}):
            raise ValueError("ownership identity cannot appear in preparation inputs")
        base = image.validate(run.directory)
        # Apply the same grammar restriction to the future overlay path.
        if ',' in str(overlay) or any(ord(c) < 32 for c in str(overlay)):
            raise ValueError("unsupported QEMU path characters")

        def command(operation, arguments):
            run._read()
            argv = [config.image_executable, *arguments]
            event({'stage': operation, 'status': 'command-intent', 'argv': argv,
                   'timeout_seconds': TIMEOUT_SECONDS, 'output_limit_bytes': OUTPUT_LIMIT})
            result = executor(argv,
                              timeout=TIMEOUT_SECONDS, output_limit=OUTPUT_LIMIT)
            if (not isinstance(result, CommandResult) or type(result.returncode) is not int
                    or type(result.stdout) is not bytes or type(result.stderr) is not bytes):
                raise CommandError('invalid-command-result')
            if max(len(result.stdout), len(result.stderr)) > OUTPUT_LIMIT:
                raise CommandError('command-output-limit')
            event({'stage': operation, 'status': 'command-returned',
                   'returncode': result.returncode, 'stdout_bytes': len(result.stdout),
                   'stderr_bytes': len(result.stderr)})
            if result.returncode != 0:
                raise CommandError('command-nonzero')
            return result.stdout

        def info(path):
            return command(stage, ['info', '--output=json', '--backing-chain', '-f', 'qcow2', str(path)])

        stage = 'base-info'
        size = image_chain(info(base), [base])
        image.verify_bytes(run.directory)
        event({'stage': stage, 'status': 'verified', 'path': str(base), 'format': 'qcow2',
               'virtual_size': size, 'size_bytes': image.size_bytes, 'sha256': image.sha256,
               'backing': None, 'external_data_file': False})
        run.register({'id': 'overlay', 'kind': 'file', 'path': overlay_path})
        stage = 'overlay-create'
        run._read()
        overlay = resource_path(run.directory, overlay_path)
        if overlay.exists():
            raise ValueError("overlay destination already exists")
        command(stage, ['create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(base), str(overlay)])
        local_file(overlay)
        stage = 'overlay-info'
        image_chain(info(overlay), [overlay, base], size)
        image.verify_bytes(run.directory)
        event({'stage': stage, 'status': 'verified', 'path': str(overlay), 'format': 'qcow2',
               'virtual_size': size, 'backing': str(base), 'external_data_file': False})
        if isinstance(image, WindowsImageDescriptor):
            # The run's own copies of the firmware variables and of the TPM state; the image is only read.
            stage = 'windows-files'
            windows_run.prepare_files(run, image, event)
        stage = 'save-plan'
        plan = _launch_plan(config, image, overlay, str(uuid.uuid4()))
        run._read()
        with resource_path(run.directory, plan_path).open('x', encoding='utf-8', newline='\n') as stream:
            json.dump(plan, stream, sort_keys=True, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        event({'stage': 'prepared', 'status': 'preparation-only', 'virtual_size': size})
        run.mark('prepared')
        return plan
    except BaseException as error:
        # Lost ownership prevents further writes, including diagnostics. The prior
        # command intent remains on disk for independent recovery inspection.
        reason = str(error) if isinstance(error, CommandError) else 'preparation-failed'
        if isinstance(error, (subprocess.TimeoutExpired, TimeoutError)):
            reason = 'command-timeout'
        if reason not in ('command-timeout', 'command-output-limit', 'command-nonzero',
                          'command-output-read-failed', 'invalid-command-result'):
            reason = 'preparation-failed'
        try:
            run.mark('quarantined' if overlay.exists() else 'error', reason)
        except (OSError, ValueError):
            pass
        try:
            event({'stage': stage, 'status': 'failed', 'reason': reason})
        except (OSError, ValueError):
            pass
        if isinstance(error, AssertionError) or not isinstance(error, Exception):
            raise
        failed = ValueError('QEMU preparation failed; retain run evidence')
        # Which of the image's files was refused is a fixed sentence of the controller's own: the summary may say it.
        if str(error) in IMAGE_REFUSALS:
            failed.image_refusal = str(error)
        raise failed from None
