"""Stage 9b: the controller launches and closes a Windows guest of the 9a image, offline.

The descriptor is the one the image tool writes. QEMU and swtpm are stand-in processes (`fake_qemu`, `fake_swtpm`)
that listen on the sockets the controller names, so the process ownership, the run's own copies of the firmware
variables and of the TPM state, and the order in which the two processes start and stop are the real ones.
"""

import contextlib
from copy import deepcopy
from dataclasses import asdict, fields
import hashlib
import io
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import tomllib
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tools.vm.matrix import cli, images, lifecycle, orchestrator, qmp_adapter, windows_run, windows_smoke
from tools.vm.matrix.images import ImageDescriptor, WindowsImageDescriptor, load_windows_descriptor
from tools.vm.matrix.qemu import QemuConfig, WindowsQemuConfig, _launch_plan, prepare, qemu_config_of
from tools.vm.matrix.resources import ArchiveRefused, _process_status, archive_run, completion_verified
from tools.vm.matrix.resources import StandLease, inspect_runs, read_manifest
from tools.vm.matrix.tests import fake_controller, windows_fixture
from tools.vm.matrix.tests.posix_only import controller_only, linux_stand_paths

REPOSITORY = Path(__file__).resolve().parents[4]
EXAMPLE = Path(__file__).resolve().parents[1] / 'execution-windows-boot-smoke.example.toml'
image_plan = windows_fixture.image_plan
UUID = '12345678-1234-4234-8234-123456789abc'
LINUX_FIELDS = ['schema', 'executable', 'image_executable', 'bios', 'machine', 'accelerator', 'cpu', 'memory_mib',
                'vcpus', 'qga']
LINUX_IMAGE_FIELDS = ['schema', 'identifier', 'guest_os', 'architecture', 'path', 'size_bytes', 'sha256', 'format',
                      'profile']


def values(argv, option):
    return [argv[index + 1] for index, item in enumerate(argv) if item == option]


class Base(unittest.TestCase):
    def setUp(self):
        self.fixture = windows_fixture.WindowsFixture()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.run_directory = self.fixture.run.directory

    def plan(self, **changes):
        fixture = self.fixture
        return _launch_plan(changes.get('config', fixture.config), changes.get('image', fixture.image),
                            self.run_directory / 'root.qcow2', UUID)

    def with_record(self, *path, value):
        record = deepcopy(self.fixture.record)
        target = record['windows']
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        return windows_fixture.WindowsImageDescriptor(**record)


class DescriptorTests(Base):
    def test_the_descriptor_the_image_tool_writes_is_accepted(self):
        image = self.fixture.image
        self.assertEqual(self.fixture.base, image.validate(self.run_directory))
        facts = image.facts()
        self.assertEqual(image_plan.PCI_SLOTS, facts['slots'])
        self.assertEqual(image_plan.CPU, facts['cpu'])
        self.assertEqual('00:00:5e:00:53:61', facts['mac'])
        self.assertFalse(facts['smm'])
        self.assertEqual(['.lock', 'tpm2-00.permall'], list(facts['tpm_files']))

    def test_the_descriptor_file_is_read_strictly(self):
        path = self.fixture.descriptor_file
        self.assertEqual(self.fixture.image, load_windows_descriptor(path))
        text = path.read_text(encoding='utf-8')
        duplicate = path.with_name('duplicate.json')
        duplicate.write_text(text[:-1] + ', "format": "qcow2"}', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            load_windows_descriptor(duplicate)
        extra = path.with_name('extra.json')
        extra.write_text(text[:-1] + ', "extra": 1}', encoding='utf-8')
        with self.assertRaises(ValueError):
            load_windows_descriptor(extra)
        linux = path.with_name('linux.json')
        linux.write_text(json.dumps({k: v for k, v in self.fixture.record.items() if k != 'windows'}),
                         encoding='utf-8')
        with self.assertRaises(ValueError):
            load_windows_descriptor(linux)

    def test_what_the_image_does_not_claim_or_cannot_be_trusted_with_is_refused(self):
        slots = dict(image_plan.PCI_SLOTS, vga='0x3')
        cases = [(('activated',), True), (('qualified',), True), (('qualified',), 'false'),
                 (('uefi', 'secure_boot'), False), (('uefi', 'smm'), 'no'), (('uefi', 'code', 'sha256'), 'abc'),
                 (('tpm', 'version'), '1.2'), (('tpm', 'device'), 'tpm-tis'),
                 (('tpm', 'state', 'files'), {'../x': '0' * 64, 'tpm2-00.permall': '0' * 64}),
                 (('tpm', 'state', 'files'), {'.lock': '0' * 64}),
                 (('devices', 'machine'), 'pc-i440fx-10.0'), (('devices', 'cpu'), 'host,-vmx -drive x'),
                 (('devices', 'cpu'), 'kvm64'), (('devices', 'cpu'), 'host,x=1;y'),
                 (('devices', 'mac'), '00:00:5e:00:53'), (('devices', 'pci_slots'), slots),
                 (('devices', 'pci_slots'), dict(image_plan.PCI_SLOTS, vga='0x1f')),
                 (('devices', 'qga'), 'org.example.agent'), (('devices', 'memory_mib'), '4096')]
        for path, value in cases:
            with self.subTest(path=path, value=value), self.assertRaises(ValueError):
                self.with_record(*path, value=value).facts()
        record = deepcopy(self.fixture.record)
        record['windows']['surprise'] = 1
        with self.assertRaises(ValueError):
            WindowsImageDescriptor(**record).facts()

    def test_a_changed_file_of_the_image_is_refused_whichever_it_is(self):
        directory = self.fixture.directory
        for path in (self.fixture.base, self.fixture.vars, self.fixture.code, directory / 'tpm' / 'tpm2-00.permall',
                     directory / 'tpm' / '.lock'):
            original = path.read_bytes()
            path.write_bytes(original + b'x')
            try:
                with self.subTest(path=path.name), self.assertRaises(ValueError):
                    self.fixture.image.validate(self.run_directory)
            finally:
                path.write_bytes(original)
        self.fixture.image.validate(self.run_directory)

    def test_the_linux_contract_keeps_its_fields_and_refuses_a_windows_image(self):
        self.assertEqual(LINUX_IMAGE_FIELDS, [f.name for f in fields(ImageDescriptor)])
        self.assertEqual(LINUX_FIELDS, [f.name for f in fields(QemuConfig)])
        linux = {k: v for k, v in self.fixture.record.items() if k != 'windows'}
        with self.assertRaisesRegex(ValueError, 'unsupported image contract'):
            ImageDescriptor(**linux).validate(self.run_directory)
        self.assertNotIn('windows', ImageDescriptor(**dict(linux, guest_os='linux',
                                                           profile='bios-i440fx-v1')).record())
        self.assertIn('windows', self.fixture.image.record())

    def test_the_disk_is_hashed_in_full_once_and_again_when_asked_or_when_the_file_changed(self):
        image, directory = self.fixture.image, self.run_directory
        with patch.object(ImageDescriptor, 'verify_bytes', autospec=True,
                          side_effect=ImageDescriptor.verify_bytes) as hashed:
            image.validate(directory)
            image.verify_bytes()
            windows_fixture.WindowsImageDescriptor(**self.fixture.record).validate(directory)
            self.assertEqual(1, hashed.call_count)
            image.validate(directory, fresh=True)
            self.assertEqual(2, hashed.call_count)
            os.utime(self.fixture.base, ns=(1, 1))
            image.verify_bytes()
            self.assertEqual(3, hashed.call_count)
        self.fixture.base.write_bytes(windows_fixture.DISK[:-1] + b'!')
        with self.assertRaises(ValueError):
            image.verify_bytes()

    def test_a_descriptor_of_another_contract_is_refused(self):
        for name, value in (('profile', 'bios-i440fx-v1'), ('guest_os', 'linux'), ('format', 'raw'),
                            ('architecture', 'aarch64'), ('schema', 'rosetun.matrix.image.v2')):
            record = dict(self.fixture.record, **{name: value})
            with self.subTest(name=name), self.assertRaises(ValueError):
                WindowsImageDescriptor(**record).validate(self.run_directory)


class PlanTests(Base):
    def test_the_command_line_has_the_images_firmware_disk_and_tpm_and_no_network_or_display(self):
        fixture = self.fixture
        plan = self.plan()
        argv, directory = plan['argv'], str(self.run_directory)
        self.assertEqual(['q35,smm=off'], values(argv, '-machine'))
        self.assertEqual([image_plan.CPU], values(argv, '-cpu'))
        self.assertEqual(['base=utc'], values(argv, '-rtc'))
        self.assertEqual(['4096'], values(argv, '-m'))
        self.assertEqual(['4'], values(argv, '-smp'))
        self.assertEqual([UUID], values(argv, '-uuid'))
        self.assertEqual([f'if=pflash,format=raw,unit=0,readonly=on,file={fixture.code}',
                          f'if=pflash,format=raw,unit=1,file={directory}/OVMF_VARS.fd'], values(argv, '-drive'))
        disk = json.loads(values(argv, '-blockdev')[0])
        self.assertEqual(directory + '/root.qcow2', disk['file']['filename'])
        self.assertTrue(disk['backing']['read-only'])
        self.assertEqual(fixture.image.path, disk['backing']['file']['filename'])
        self.assertIsNone(disk['backing']['backing'])
        self.assertEqual(['none'], values(argv, '-display'))
        self.assertEqual(['none'], values(argv, '-nic'))
        for option in ('-vnc', '-netdev', '-net', '-qmp', '-bios', '-S', '-mon', '-snapshot'):
            self.assertNotIn(option, argv)
        self.assertIn(f'socket,id=chrtpm,path={directory}/swtpm.sock', values(argv, '-chardev'))
        self.assertEqual(['emulator,id=tpm0,chardev=chrtpm'], values(argv, '-tpmdev'))
        self.assertNotIn(fixture.vars.as_posix(), json.dumps(argv))
        self.assertFalse(plan['executed'])
        self.assertFalse(plan['kvm_qualified'])
        self.assertEqual('windows-uefi-q35-v1', plan['firmware_profile'])

    def test_the_devices_slots_mac_and_cpu_are_the_ones_the_build_used(self):
        fixture = self.fixture
        plan = self.plan()
        built = image_plan.qemu_argv(fixture.build_config, image_plan.Layout(fixture.directory), UUID, install=False)
        run_devices, built_devices = values(plan['argv'], '-device'), values(built, '-device')
        for fragment in ('virtio-blk-pci,drive=root,bus=pcie.0,addr=0x3,bootindex=1', 'tpm-crb,tpmdev=tpm0',
                         'VGA,bus=pcie.0,addr=0x1'):
            self.assertIn(fragment, run_devices)
            self.assertIn(fragment, built_devices)
        built_net = next(d for d in built_devices if d.startswith('virtio-net-pci'))
        run_net = next(d for d in run_devices if d.startswith('virtio-net-pci'))
        self.assertEqual(built_net.replace('netdev=buildnet,', ''), run_net)
        self.assertEqual('virtio-net-pci,id=test-wire,mac=00:00:5e:00:53:61,bus=pcie.0,addr=0x4', run_net)
        built_serial = next(d for d in built_devices if d.startswith('virtio-serial-pci'))
        self.assertEqual(built_serial, plan['windows_run']['qga_device'])
        self.assertEqual(image_plan.QGA_NAME, images.QGA_PORT)
        # The agent channel (the serial adapter and its port) is the two the controller adds when it starts QEMU.
        self.assertEqual(len(built_devices) - 2, len(run_devices))
        for option in ('-machine', '-cpu', '-global', '-m', '-smp'):
            self.assertEqual(values(built, option), values(plan['argv'], option))

    def test_the_machine_with_system_management_mode_has_the_secure_flash_property(self):
        image = self.with_record('uefi', 'smm', value=True)
        argv = self.plan(image=image)['argv']
        self.assertEqual(['q35,smm=on'], values(argv, '-machine'))
        self.assertIn('driver=cfi.pflash01,property=secure,value=on', values(argv, '-global'))
        self.assertEqual(['ICH9-LPC.disable_s3=1', 'driver=cfi.pflash01,property=secure,value=on'],
                         values(argv, '-global'))

    def test_the_tpm_command_ends_with_its_only_client_and_writes_into_the_run(self):
        directory = str(self.run_directory)
        argv = self.plan()['windows_run']['swtpm_argv']
        self.assertEqual([self.fixture.config.swtpm, 'socket', '--tpm2', '--tpmstate', f'dir={directory}/tpm',
                          '--ctrl', f'type=unixio,path={directory}/swtpm.sock,mode=0600', '--terminate',
                          '--log', f'file={directory}/swtpm.log,level=1'], argv)

    def test_the_configuration_must_name_what_the_image_was_built_with(self):
        from dataclasses import replace
        fixture = self.fixture
        for name, value in (('bios', str(fixture.vars)), ('memory_mib', 2048), ('vcpus', 2), ('qga', False),
                            ('cpu', 'host,hv-time'), ('swtpm', ''), ('machine', 'pc-i440fx-10.0'),
                            ('accelerator', 'tcg')):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.plan(config=replace(fixture.config, **{name: value}))

    def test_a_linux_image_and_a_windows_configuration_do_not_mix(self):
        fixture = self.fixture
        path = str(fixture.base)
        linux_image = ImageDescriptor('rosetun.matrix.image.v1', 'linux-test', 'linux', 'x86_64', path,
                                      len(fixture.original), hashlib.sha256(fixture.original).hexdigest(), 'qcow2',
                                      'bios-i440fx-v1')
        linux_config = QemuConfig('rosetun.matrix.qemu.v1', path, path, path, 'pc-i440fx-9.2', qga=True)
        with self.assertRaisesRegex(ValueError, 'image-profile-machine-mismatch'):
            self.plan(image=linux_image)
        with self.assertRaisesRegex(ValueError, 'image-profile-machine-mismatch'):
            self.plan(config=linux_config)
        self.assertNotIn('windows_run', _launch_plan(linux_config, linux_image, self.run_directory / 'root.qcow2',
                                                      UUID))

    def test_the_plan_is_deterministic_and_carries_no_secret(self):
        plan = self.plan()
        self.assertEqual(plan, self.plan())
        text = json.dumps(plan)
        self.assertNotIn(self.fixture.run._identity[2], text)
        self.assertEqual(plan['config'], asdict(self.fixture.config))
        self.assertEqual(self.fixture.config, qemu_config_of(plan['config']))
        self.assertEqual(self.fixture.image, images.image_of(plan['image']))
        linux = QemuConfig('rosetun.matrix.qemu.v1', 'a', 'b', 'c', 'pc-i440fx-9.2')
        self.assertEqual(linux, qemu_config_of(asdict(linux)))

    @linux_stand_paths
    def test_the_example_configuration_validates(self):
        with EXAMPLE.open('rb') as stream:
            config = windows_smoke.validate(tomllib.load(stream))
        self.assertEqual('windows-boot-smoke', config['suite'])
        self.assertEqual('q35', config['qemu']['machine'])


class PrepareTests(Base):
    def image_files(self):
        directory = self.fixture.directory
        return {path.name: path.read_bytes() for path in (self.fixture.base, self.fixture.vars, self.fixture.code,
                                                          directory / 'tpm' / '.lock',
                                                          directory / 'tpm' / 'tpm2-00.permall')}

    def test_the_run_gets_its_own_copies_and_the_image_is_not_touched(self):
        before = self.image_files()
        plan = self.fixture.prepare()
        self.assertEqual(before, self.image_files())
        self.assertEqual(windows_fixture.VARS, (self.run_directory / 'OVMF_VARS.fd').read_bytes())
        for name, data in windows_fixture.TPM.items():
            self.assertEqual(data, (self.run_directory / 'tpm' / name).read_bytes())
        resources = {r['id']: r['path'] for r in read_manifest(self.run_directory)['resources']}
        self.assertEqual({'windows-vars': 'OVMF_VARS.fd', 'windows-tpm-0': 'tpm/.lock',
                          'windows-tpm-1': 'tpm/tpm2-00.permall'},
                         {k: v for k, v in resources.items() if k.startswith('windows-')})
        if os.name == 'posix':
            self.assertEqual(0o600, (self.run_directory / 'OVMF_VARS.fd').stat().st_mode & 0o777)
            self.assertEqual(0o700, (self.run_directory / 'tpm').stat().st_mode & 0o777)
        rows = [json.loads(line) for line in (self.run_directory / 'preparation.jsonl').read_text().splitlines()]
        copied = [row for row in rows if row.get('stage') == 'windows-files']
        self.assertEqual(1, len(copied))
        self.assertEqual(windows_fixture.sha256(windows_fixture.VARS), copied[0]['digests']['OVMF_VARS.fd'])
        self.assertEqual(plan, json.loads((self.run_directory / 'launch-plan.json').read_text()))
        self.assertIn('windows_run', plan)

    def test_a_changed_image_file_stops_the_preparation_before_anything_is_created(self):
        self.fixture.vars.write_bytes(b'someone wrote the store of the image')
        self.fixture.failed()
        self.assertEqual([], self.fixture.calls)
        self.assertFalse((self.run_directory / 'OVMF_VARS.fd').exists())
        self.assertFalse((self.run_directory / 'tpm').exists())

    def test_a_source_that_changes_after_it_was_checked_is_not_taken_as_the_image(self):
        def tamper(argv):
            if argv[1] == 'create':
                self.fixture.vars.write_bytes(b'tampered between the check and the copy')
        self.fixture.hook = tamper
        self.fixture.failed(state='quarantined')

    def test_the_run_is_refused_when_the_configuration_names_other_firmware(self):
        from dataclasses import replace
        self.fixture.config = replace(self.fixture.config, bios=str(self.fixture.vars))
        self.fixture.failed()


@controller_only
class Running(Base):
    """A real `lifecycle.start` on the stand-in QEMU and swtpm."""

    def setUp(self):
        super().setUp()
        self.spawned = []
        for item in fake_controller.patches():
            item.start()
            self.addCleanup(item.stop)
        self.addCleanup(self.stop_leftovers)
        self.plan_record = self.fixture.prepare()
        # The prelaunch check repeats the overlay observation, the third call of the fake.
        self.fixture.calls = self.fixture.calls[:2]

    def stop_leftovers(self):
        try:
            resources = read_manifest(self.run_directory)['resources']
        except (OSError, ValueError):
            return
        for resource in resources:
            if resource['kind'] == 'process' and _process_status(resource) == 'alive':
                os.kill(resource['pid'], signal.SIGKILL)

    def start(self):
        def info(argv, *, timeout, output_limit):
            return self.fixture.fake(argv, timeout=30, output_limit=output_limit)
        return lifecycle.start(self.fixture.run, timeout=5, executor=info)

    def processes(self):
        return [r for r in read_manifest(self.run_directory)['resources'] if r['kind'] == 'process']

    def journal(self):
        return [json.loads(line) for line in (self.run_directory / 'lifecycle.jsonl').read_text().splitlines()]

    def actions(self):
        return [(row['action'], row['result']) for row in self.journal()]

    def test_the_tpm_starts_before_qemu_and_both_are_owned_processes(self):
        vm = self.start()
        processes = self.processes()
        self.assertEqual(['swtpm', 'qemu'], [r['id'] for r in processes])
        self.assertEqual(['alive', 'alive'], [_process_status(r) for r in processes])
        self.assertEqual([('start', 'intent'), ('swtpm', 'started'), ('start', 'qmp-ready-paused')], self.actions())
        self.assertEqual(lifecycle.ORDINARY_ROWS - windows_run.JOURNAL_MARGIN, vm.ordinary_rows)
        self.assertEqual('prelaunch', vm.status()['status'])
        cmdline = Path('/proc/%d/cmdline' % processes[1]['pid']).read_bytes().split(b'\0')
        for argument in (b'-S', b'virtio-serial-pci,id=guestserial,bus=pcie.0,addr=0x5',
                         b'virtserialport,bus=guestserial.0,chardev=guestagent,name=org.qemu.guest_agent.0'):
            self.assertIn(argument, cmdline)
        resources = {r['id']: r['path'] for r in read_manifest(self.run_directory)['resources']
                     if r['kind'] != 'process'}
        self.assertEqual({'swtpm-socket': 'swtpm.sock', 'swtpm-log': 'swtpm.log', 'screendump': 'screendump.png'},
                         {k: v for k, v in resources.items() if k in ('swtpm-socket', 'swtpm-log', 'screendump')})
        self.assertFalse([p for p in resources.values() if p.startswith(('linux-', 'smoke-package'))])
        vm.hard_off()

    def test_an_acpi_shutdown_ends_qemu_then_the_tpm_and_the_run_completes(self):
        vm = self.start()
        vm.resume()
        vm.screendump()
        self.assertTrue((self.run_directory / 'screendump.png').read_bytes().startswith(b'PNG fake png'))
        self.assertEqual(0, vm.request_shutdown(wait=30))
        self.assertTrue(vm.completed)
        manifest = read_manifest(self.run_directory)
        self.assertTrue(completion_verified(self.run_directory, manifest))
        proof = json.loads((self.run_directory / 'completion.json').read_text())
        self.assertEqual([('swtpm', 0), ('qemu', 0)], [(e['resource']['id'], e['returncode']) for e in proof['exits']])
        actions = self.actions()
        self.assertLess(actions.index(('swtpm', 'child-reaped')), actions.index(('exit', 'child-reaped')))
        self.assertEqual(('completion', 'controls-closed-child-reaped'), actions[-1])
        # The guest changed the run's copies; the image's own files are what they were.
        self.assertTrue((self.run_directory / 'OVMF_VARS.fd').read_bytes().endswith(b'written by the fake guest'))
        self.assertTrue((self.run_directory / 'tpm' / 'tpm2-00.permall').read_bytes().endswith(b'guest session'))
        self.fixture.image.validate(self.run_directory)
        self.assertEqual(windows_fixture.VARS, self.fixture.vars.read_bytes())

    def test_a_hard_off_leaves_neither_process(self):
        vm = self.start()
        vm.resume()
        vm.hard_off()
        proof = json.loads((self.run_directory / 'completion.json').read_text())
        self.assertEqual([('swtpm', 0), ('qemu', -signal.SIGKILL)],
                         [(e['resource']['id'], e['returncode']) for e in proof['exits']])
        self.assertTrue(completion_verified(self.run_directory, read_manifest(self.run_directory)))

    def test_a_guest_that_ignores_its_power_button_is_an_error_and_a_hard_close_still_completes(self):
        with patch.dict(os.environ, FAKE_QEMU_IGNORE_POWERDOWN='1'):
            vm = self.start()
        vm.resume()
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'shutdown-unconfirmed'):
            vm.request_shutdown(wait=1)
        vm.close(hard=True)
        self.assertTrue(completion_verified(self.run_directory, read_manifest(self.run_directory)))

    def test_the_wait_for_the_shutdown_is_bounded(self):
        vm = self.start()
        for wait in (0, -1, 601, float('inf'), 'long'):
            with self.subTest(wait=wait), self.assertRaisesRegex(lifecycle.LifecycleError, 'invalid-shutdown-wait'):
                vm.request_shutdown(wait=wait)
        vm.hard_off()

    def test_a_qemu_that_cannot_be_spawned_takes_the_tpm_with_it(self):
        def popen(argv, **kwargs):
            if argv[1:2] == ['socket']:
                return fake_controller.fake_popen(argv, **kwargs)
            raise OSError('spawn failed')
        with patch.object(lifecycle.subprocess, 'Popen', popen):
            with self.assertRaises(lifecycle.LifecycleError):
                self.start()
        processes = self.processes()
        self.assertEqual(['swtpm'], [r['id'] for r in processes])
        self.assertEqual('absent', _process_status(processes[0]))
        self.assertEqual('quarantined', read_manifest(self.run_directory)['state'])
        self.assertIn(('swtpm', 'child-reaped'), self.actions())

    def test_a_tpm_that_does_not_start_stops_the_start_before_qemu(self):
        with patch.dict(os.environ, FAKE_SWTPM_FAIL='1'):
            with self.assertRaises(lifecycle.LifecycleError):
                self.start()
        self.assertEqual(['swtpm'], [r['id'] for r in self.processes()])
        self.assertEqual('quarantined', read_manifest(self.run_directory)['state'])
        self.assertFalse((self.run_directory / 'qmp.sock').exists())

    def test_a_copy_that_is_not_the_images_file_is_refused_before_any_process(self):
        (self.run_directory / 'OVMF_VARS.fd').write_bytes(b'not what the image holds')
        with patch.object(lifecycle.subprocess, 'Popen', side_effect=AssertionError('no process')):
            with self.assertRaisesRegex(lifecycle.LifecycleError, 'prelaunch-validation-failed'):
                self.start()
        self.assertEqual('prepared', read_manifest(self.run_directory)['state'])
        self.assertEqual([], self.processes())

    def test_a_run_without_its_copies_is_refused(self):
        manifest_path = self.run_directory / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        manifest['resources'] = [r for r in manifest['resources'] if r['id'] != 'windows-tpm-1']
        manifest_path.write_text(json.dumps(manifest))
        with patch.object(lifecycle.subprocess, 'Popen', side_effect=AssertionError('no process')):
            with self.assertRaises(lifecycle.LifecycleError):
                self.start()


@unittest.skipUnless(sys.platform.startswith('linux') and hasattr(os, 'pidfd_open'), 'needs Linux /proc and pidfds')
class AttachTests(unittest.TestCase):
    """A controller killed with both processes running; a later one closes the run (`recover --close`)."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='windows 9b ')
        self.addCleanup(temp.cleanup)
        self.state = Path(temp.name) / 'state'
        for item in [*fake_controller.patches(), patch.object(orchestrator, '_current_commit', return_value=None)]:
            item.start()
            self.addCleanup(item.stop)
        self.addCleanup(self.stop_leftovers)

    def stop_leftovers(self):
        for directory in (self.state / 'runs').glob('*'):
            try:
                for resource in read_manifest(directory)['resources']:
                    if resource['kind'] == 'process' and _process_status(resource) == 'alive':
                        os.kill(resource['pid'], signal.SIGKILL)
            except (OSError, ValueError):
                pass

    def killed(self, phase):
        process = fake_controller.REAL_POPEN(
            [sys.executable, '-B', '-m', 'tools.vm.matrix.tests.fake_controller', str(self.state), phase, 'windows'],
            cwd=REPOSITORY, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        self.addCleanup(process.wait)
        self.addCleanup(process.stdout.close)
        if not select.select([process.stdout], [], [], 60)[0]:
            self.fail('the controller did not reach ' + phase)
        word, run_id = process.stdout.readline().decode().split()
        self.assertEqual('READY', word)
        os.kill(process.pid, signal.SIGKILL)
        process.wait()
        return run_id

    def directory(self, run_id):
        return self.state / 'runs' / run_id

    def processes(self, run_id):
        return [r for r in read_manifest(self.directory(run_id))['resources'] if r['kind'] == 'process']

    def journal(self, run_id):
        return [(row['action'], row['result']) for row in
                map(json.loads, (self.directory(run_id) / 'lifecycle.jsonl').read_text().splitlines())]

    def test_recover_close_sees_the_tpm_and_ends_both_processes(self):
        run_id = self.killed('watch')
        processes = self.processes(run_id)
        self.assertEqual(['swtpm', 'qemu'], [r['id'] for r in processes])
        self.assertEqual(['alive', 'alive'], [_process_status(r) for r in processes])
        entry = next(r for r in inspect_runs(self.state) if r['run_id'] == run_id)
        self.assertEqual('alive', entry['process_status'])
        self.assertEqual(['swtpm', 'qemu'], [p['id'] for p in entry['processes']])
        with self.assertRaisesRegex(ArchiveRefused, 'process-alive'):
            archive_run(self.state, run_id)
        answer, code = orchestrator.close_run(self.state, run_id)
        self.assertEqual((0, True, None), (code, answer['completion_verified'], answer['refused']))
        self.assertEqual(['absent', 'absent'], [_process_status(r) for r in self.processes(run_id)])
        rows = self.journal(run_id)
        self.assertIn(('swtpm', 'exit-observed'), rows)
        self.assertIn(('exit', 'exit-observed'), rows)
        self.assertTrue(all(run['completion_verified'] for run in inspect_runs(self.state)))
        StandLease(self.state, 'stand').acquire().release()

    def test_a_tpm_that_is_already_gone_does_not_stop_the_close(self):
        run_id = self.killed('watch')
        swtpm = self.processes(run_id)[0]
        os.kill(swtpm['pid'], signal.SIGKILL)
        for _ in range(100):
            if _process_status(swtpm) == 'absent':
                break
            select.select([], [], [], 0.05)
        self.assertEqual('absent', _process_status(swtpm))
        answer, code = orchestrator.close_run(self.state, run_id)
        self.assertEqual((0, True), (code, answer['completion_verified']))
        self.assertEqual(['absent', 'absent'], [_process_status(r) for r in self.processes(run_id)])

    def test_a_controller_killed_before_the_start_leaves_nothing_to_close(self):
        run_id = self.killed('start')
        self.assertEqual([], self.processes(run_id))
        answer, code = orchestrator.close_run(self.state, run_id)
        self.assertEqual(('run-not-attachable', 1), (answer['refused'], code))
        self.assertTrue(archive_run(self.state, run_id)['archived'])


@controller_only
class SmokeTests(Base):
    """`run windows-boot-smoke` end to end on the stand-in processes."""

    def setUp(self):
        super().setUp()
        fixture = self.fixture
        for item in [*fake_controller.patches(),
                     patch.object(windows_smoke.os, 'access', return_value=True),
                     patch('importlib.metadata.version', return_value='0.0.6'),
                     patch('tools.vm.matrix.linux_l2.source_identity',
                           return_value=dict(source_sha='0' * 40, source_dirty=False,
                                             source_dirty_digest='0' * 64))]:
            item.start()
            self.addCleanup(item.stop)
        self.addCleanup(self.stop_leftovers)
        self.state = fixture.root / 'smoke-state'
        self.config = dict(schema=windows_smoke.SCHEMA, suite='windows-boot-smoke', mode='exploratory',
                           platform='linux-x86_64-kvm', state_directory=str(self.state), stand_id='smoke',
                           image_descriptor=str(fixture.descriptor_file), qemu=asdict(fixture.config),
                           smoke=dict(boot_wait_seconds=1, shutdown_wait_seconds=20),
                           deadlines=dict(preparation=600))

        def prepare_run(run, image, config, *, executor):
            fixture.run = run
            return prepare(run, image, config, executor=fixture.fake)

        def start(run, *, timeout):
            fixture.calls = fixture.calls[:2]
            return lifecycle.start(run, timeout=timeout, executor=lambda argv, *, timeout, output_limit:
                                   fixture.fake(argv, timeout=30, output_limit=output_limit))
        self.adapters = SimpleNamespace(prepare=prepare_run, execute=fixture.fake, start=start)

    def stop_leftovers(self):
        for directory in (self.state / 'runs').glob('*'):
            try:
                for resource in read_manifest(directory)['resources']:
                    if resource['kind'] == 'process' and _process_status(resource) == 'alive':
                        os.kill(resource['pid'], signal.SIGKILL)
            except (OSError, ValueError):
                pass

    def smoke(self):
        return windows_smoke.run_windows_boot_smoke(self.config, adapters=self.adapters, progress=lambda stage: None)

    def test_a_clean_run_starts_watches_photographs_and_shuts_down_by_the_power_button(self):
        result = self.smoke()
        self.assertEqual([], result['errors'])
        self.assertEqual(0, result['exit_code'])
        self.assertTrue(result['completion'])
        execution = result['execution']
        self.assertTrue(execution['accepted'])
        self.assertEqual(('running', 'acpi', True), (execution['guest_status'], execution['shutdown'],
                                                       execution['image_unchanged']))
        self.assertFalse(execution['kvm_qualified'])
        self.assertFalse(execution['image']['qualified'])
        self.assertEqual(self.fixture.image.sha256, execution['image']['sha256'])
        self.assertEqual(1, execution['boot_wait_seconds'])
        self.assertGreaterEqual(execution['samples'], 1)
        self.assertGreater(execution['screenshot']['bytes'], 0)
        self.assertEqual((False, True, False), (result['qualified'], result['diagnostic'], result['release_gate']))
        self.assertEqual('UNVERIFIED', result['security_invariants'])
        run = self.state / 'runs' / result['identities']['host_run_id']
        plan = json.loads((run / 'launch-plan.json').read_text())
        self.assertEqual(plan['uuid'], execution['uuid'])
        evidence = {row['path'] for row in result['evidence']}
        self.assertTrue({'screendump.png', 'swtpm.log', 'OVMF_VARS.fd', 'tpm/tpm2-00.permall', 'lifecycle.jsonl',
                         'completion.json'} <= evidence)
        saved = json.loads((run / 'execution-summary.json').read_text())
        self.assertEqual(0, saved['exit_code'])
        self.assertEqual('completed', json.loads((run / 'run-state.json').read_text())['phase'])
        self.assertEqual(['absent', 'absent'], [_process_status(r) for r in read_manifest(run)['resources']
                                                if r['kind'] == 'process'])
        self.fixture.image.validate(run)

    def test_a_guest_that_does_not_shut_down_is_an_error_and_is_stopped_the_way_linux_is(self):
        self.config['smoke']['shutdown_wait_seconds'] = 1
        with patch.dict(os.environ, FAKE_QEMU_IGNORE_POWERDOWN='1'):
            result = self.smoke()
        self.assertEqual(2, result['exit_code'])
        self.assertEqual([('shutdown', 'shutdown-unconfirmed')], [(e['stage'], e['reason']) for e in result['errors']])
        self.assertTrue(result['completion'])
        self.assertFalse(result['execution']['accepted'])
        self.assertEqual('forced', result['execution']['shutdown'])
        # As for Linux: the run state is `completed` when the completion is verified, whatever the exit code says.
        run = self.state / 'runs' / result['identities']['host_run_id']
        self.assertEqual('completed', json.loads((run / 'run-state.json').read_text())['phase'])

    def test_an_image_that_changed_before_the_run_is_refused_before_any_process(self):
        self.fixture.vars.write_bytes(b'changed')
        with patch.object(lifecycle.subprocess, 'Popen', side_effect=AssertionError('no process')):
            result = self.smoke()
        self.assertEqual(2, result['exit_code'])
        self.assertEqual('prepare', result['errors'][0]['stage'])
        self.assertFalse(result['execution']['accepted'])
        self.assertIsNone(result['execution']['uuid'])


class CommandTests(Base):
    def toml(self, config):
        lines = []
        for key, value in config.items():
            if not isinstance(value, dict):
                lines.append('%s = %s' % (key, json.dumps(value)))
        for key, value in config.items():
            if isinstance(value, dict):
                lines.append('[%s]' % key)
                lines += ['%s = %s' % (name, json.dumps(item)) for name, item in value.items()]
        return '\n'.join(lines) + '\n'

    def config(self):
        fixture = self.fixture
        config = dict(schema=windows_smoke.SCHEMA, suite='windows-boot-smoke', mode='exploratory',
                      platform='linux-x86_64-kvm', state_directory=str(fixture.root / 'cli-state'),
                      stand_id='smoke', image_descriptor=str(fixture.descriptor_file), qemu=asdict(fixture.config),
                      smoke=dict(boot_wait_seconds=90, shutdown_wait_seconds=180), deadlines=dict(preparation=900))
        path = fixture.root / 'smoke.toml'
        path.write_text(self.toml(config), encoding='utf-8')
        return config, path

    def command(self, *arguments):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cli.main(list(arguments))
        return code, json.loads(output.getvalue())

    def test_the_dry_run_prints_the_plan_and_creates_nothing(self):
        config, path = self.config()
        code, plan = self.command('run', 'windows-boot-smoke', '--config', str(path), '--dry-run')
        self.assertEqual(0, code)
        self.assertTrue(plan['dry_run'])
        self.assertFalse(plan['image']['qualified'])
        self.assertFalse(plan['release_gate'])
        self.assertEqual('UNVERIFIED', plan['security_invariants'])
        self.assertFalse(Path(config['state_directory']).exists())

    def test_the_options_of_the_lab_and_the_linux_suites_are_refused(self):
        _, path = self.config()
        for option in (['--lab'], ['--diagnostic'], ['--control', 'stop-helper']):
            with self.subTest(option=option):
                code, answer = self.command('run', 'windows-boot-smoke', '--config', str(path), *option)
                self.assertEqual(2, code)
                self.assertIn('error', answer)
        code, answer = self.command('run', 'linux-l2', '--config', str(path), '--dry-run')
        self.assertEqual(2, code)

    def test_a_configuration_with_other_fields_or_times_is_refused(self):
        config, _ = self.config()
        for change in (lambda c: c.update(extra=1), lambda c: c['smoke'].update(boot_wait_seconds=0),
                       lambda c: c['smoke'].update(shutdown_wait_seconds=601), lambda c: c.update(mode='release'),
                       lambda c: c.update(suite='linux-l2'), lambda c: c['qemu'].pop('swtpm'),
                       lambda c: c['qemu'].update(machine='pc-i440fx-10.0'), lambda c: c.update(stand_id='a b')):
            changed = deepcopy(config)
            change(changed)
            with self.subTest(), self.assertRaises(ValueError):
                windows_smoke.preflight(changed, dry_run=True)


class ScreenshotCommandTests(unittest.TestCase):
    def qmp(self):
        executed = []

        class Client:
            events = SimpleNamespace(accept=None)

            def __init__(self, **kwargs):
                pass

            async def execute(self, name, arguments=None):
                executed.append((name, arguments))
                return {}
        relay = SimpleNamespace(client=None, close=lambda: None)
        return qmp_adapter.Qmp(None, client_factory=Client, relay_factory=lambda stream: relay), executed

    def test_a_screenshot_takes_one_absolute_file_and_a_known_format_and_nothing_else(self):
        qmp, executed = self.qmp()
        arguments = dict(filename='/run/directory/screendump.png', format='png')
        qmp.command('screendump', 5, arguments=arguments)
        self.assertEqual([('screendump', arguments)], executed)
        for name, bad in (('screendump', None), ('screendump', dict(filename='shot.png', format='png')),
                          ('screendump', dict(filename='/a,b.png', format='png')),
                          ('screendump', dict(filename='/a.png', format='jpeg')),
                          ('screendump', dict(filename='/a.png', format='png', device='x')),
                          ('screendump', dict(filename=5, format='png')),
                          ('screendump', dict(filename='/a\n.png', format='png')),
                          ('stop', dict(filename='/a.png', format='png')),
                          ('set_link', dict(filename='/a.png', format='png'))):
            with self.subTest(arguments=bad), self.assertRaisesRegex(ValueError, 'invalid-qmp-arguments'):
                qmp.command(name, 5, arguments=bad)
        self.assertEqual(1, len(executed))
