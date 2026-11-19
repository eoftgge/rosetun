"""A prepared Windows image on disk, made with the real descriptor writer of stage 9a, for the offline tests of 9b.

The files are small and named as the build names them (`windows.qcow2`, `OVMF_VARS.fd`, `tpm/`), the firmware
code and the variable template are beside them, and the descriptor is the one `image_plan.descriptor` writes, so
what the controller accepts is what the image tool produces. Nothing here is a Windows installation.
"""

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys
import tomllib

from tools.vm.matrix.images import WindowsImageDescriptor
from tools.vm.matrix.qemu import WindowsQemuConfig
from tools.vm.matrix.resources import StandLease, create_run
from tools.vm.matrix.tests import test_qemu

TOOL = Path(__file__).resolve().parents[2] / 'windows-image'
sys.path.insert(0, str(TOOL))
import image_config  # noqa: E402
import image_plan  # noqa: E402

DISK = b'not a real Windows disk; executor must be fake'
VARS = b'the variable store of the image'
TPM = {'.lock': b'', 'tpm2-00.permall': b'the persistent TPM state of the image'}
CODE = b'the firmware code of the image'
TEMPLATE = b'the variable template'


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class WindowsFixture(test_qemu.PreparationTests):
    """The preparation fixture of the offline tests with a Windows image and its launch configuration."""

    def __init__(self, state=None):
        super().__init__()
        self.state_directory = state

    def build(self, root):
        self.root = Path(root)
        self.directory = self.root / 'win-image'
        self.firmware = self.root / 'firmware'
        for directory in (self.directory, self.firmware, self.directory / 'tpm'):
            directory.mkdir(parents=True, exist_ok=True)
        self.base = self.directory / 'windows.qcow2'
        self.original = DISK
        self.base.write_bytes(DISK)
        self.vars = self.directory / 'OVMF_VARS.fd'
        self.vars.write_bytes(VARS)
        self.code = self.firmware / 'OVMF_CODE.fd'
        self.code.write_bytes(CODE)
        template = self.firmware / 'OVMF_VARS.ms.fd'
        template.write_bytes(TEMPLATE)
        for name, data in TPM.items():
            (self.directory / 'tpm' / name).write_bytes(data)
        with (TOOL / 'example.toml').open('rb') as stream:
            data = tomllib.load(stream)
        data['firmware'].update(ovmf_code=str(self.code), ovmf_vars_template=str(template))
        data['build']['output_directory'] = str(self.directory)
        self.build_config = replace(image_config.parse(data), smm=False)
        layout = image_plan.Layout(self.directory)
        self.record = image_plan.descriptor(
            self.build_config, layout, uuid='36b93578-50fa-43a8-ad1f-8ba0dbd6fb42', windows_iso_sha256='0' * 64,
            disk_sha256=sha256(DISK), disk_size=len(DISK), vars_sha256=sha256(VARS), code_sha256=sha256(CODE),
            template_sha256=sha256(TEMPLATE), tpm_files={name: sha256(item) for name, item in TPM.items()},
            built_at='2026-11-19T06:16:21+00:00')
        self.image = WindowsImageDescriptor(**self.record)
        self.descriptor_file = self.directory / 'image.json'
        self.descriptor_file.write_text(json.dumps(self.record, sort_keys=True), encoding='utf-8')
        executable = os.path.realpath(sys.executable)
        # The tool that would run qemu-img is the base file itself, as in the Linux fixture: nothing is executed.
        self.config = WindowsQemuConfig('rosetun.matrix.qemu.v1', executable, str(self.base), str(self.code), 'q35',
                                        memory_mib=4096, vcpus=4, qga=True, swtpm=executable)
        self.calls = []
        self.hook = None

    def setUp(self):
        import tempfile
        temp = tempfile.TemporaryDirectory(prefix='windows 9b ')
        self.addCleanup(temp.cleanup)
        self.build(temp.name)
        self.lease = StandLease(self.root / 'state', 'stand').acquire()
        self.addCleanup(self.lease.release)
        self.run = create_run(self.lease)
