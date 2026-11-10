"""Offline preparation tests. No QEMU or qemu-img process is executed."""

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools.vm.matrix.images import ImageDescriptor
from tools.vm.matrix.qemu import CommandResult, QemuConfig, prepare, _launch_plan
from tools.vm.matrix.resources import PreparedRun, StandLease, create_run, read_manifest


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='qemu tests Юникод ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / 'base image.qcow2'
        self.original = b'not a real disk; executor must be fake'
        self.base.write_bytes(self.original)
        self.image = ImageDescriptor('rosetun.matrix.image.v1', 'linux-test', 'linux',
                                     'x86_64', str(self.base), len(self.original),
                                     hashlib.sha256(self.original).hexdigest(), 'qcow2', 'bios-i440fx-v1')
        self.config = QemuConfig('rosetun.matrix.qemu.v1', str(self.base), str(self.base),
                                 str(self.base), 'pc-i440fx-9.2')
        self.lease = StandLease(self.root / 'state', 'stand').acquire()
        self.addCleanup(self.lease.release)
        self.run = create_run(self.lease)
        self.calls = []
        self.hook = None

    def info(self, path):
        return {'filename': str(path), 'format': 'qcow2', 'virtual-size': 1048576,
                'format-specific': {'type': 'qcow2', 'data': {'compat': '1.1', 'refcount-bits': 16}}}

    def fake(self, argv, *, timeout, output_limit):
        self.assertEqual(self.config.image_executable, argv[0])
        self.assertEqual(30, timeout)
        self.assertEqual(256 * 1024, output_limit)
        self.calls.append(argv)
        manifest = self.run._read()
        registered = {r['path'] for r in manifest['resources']}
        self.assertTrue({'preparation.jsonl', 'launch-plan.json'} <= registered)
        if self.hook:
            response = self.hook(argv)
            if response is not None:
                return response
        overlay = self.run.directory / 'root.qcow2'
        if len(self.calls) == 1:
            self.assertEqual([argv[0], 'info', '--output=json', '--backing-chain', '-f', 'qcow2', str(self.base)], argv)
            self.assertNotIn('root.qcow2', registered)
            result = [self.info(self.base)]
        elif len(self.calls) == 2:
            self.assertIn('root.qcow2', registered)
            self.assertFalse(overlay.exists())
            self.assertEqual([argv[0], 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(self.base), str(overlay)], argv)
            overlay.write_bytes(b'fake overlay')
            return CommandResult(0, b'')
        else:
            self.assertEqual(3, len(self.calls))
            self.assertEqual([argv[0], 'info', '--output=json', '--backing-chain', '-f', 'qcow2', str(overlay)], argv)
            entry = self.info(overlay)
            entry.update({'backing-filename': str(self.base), 'full-backing-filename': str(self.base),
                          'backing-filename-format': 'qcow2'})
            result = [entry, self.info(self.base)]
        return CommandResult(0, json.dumps(result).encode())

    def prepare(self, **kwargs):
        # An accidental real subprocess is a test failure, even if installed.
        with patch('subprocess.Popen', side_effect=AssertionError('real process forbidden')):
            return prepare(self.run, kwargs.get('image', self.image),
                           kwargs.get('config', self.config), executor=self.fake)

    def failed(self, state='error', **kwargs):
        with self.assertRaises(ValueError):
            self.prepare(**kwargs)
        self.assertEqual(state, read_manifest(self.run.directory)['state'])
        self.assertEqual(self.original, self.base.read_bytes())
        self.assertFalse((self.run.directory / 'launch-plan.json').exists())
        token = self.run._identity[2]
        for path in self.run.directory.glob('*.jsonl'):
            self.assertNotIn(token, path.read_text())

    def test_success_sequence_plan_is_deterministic_and_preparation_only(self):
        plan = self.prepare()
        self.assertEqual(3, len(self.calls))
        self.assertFalse(plan['executed'])
        self.assertFalse(plan['kvm_qualified'])
        self.assertEqual('bios-i440fx-v1', plan['firmware_profile'])
        argv = plan['argv']
        self.assertEqual('kvm', argv[argv.index('-accel') + 1])
        self.assertEqual('none', argv[argv.index('-nic') + 1])
        self.assertEqual('none', argv[argv.index('-monitor') + 1])
        self.assertEqual('none', argv[argv.index('-display') + 1])
        self.assertIn('-nodefaults', argv)
        for option in ('-net', '-netdev', '-virtfs', '-fsdev', '-vnc', '-qmp', '-drive', '-hda'):
            self.assertNotIn(option, argv)
        self.assertEqual(['virtio-blk-pci,drive=root'],
                         [argv[i+1] for i, arg in enumerate(argv) if arg == '-device'])
        disk = json.loads(argv[argv.index('-blockdev') + 1])
        self.assertEqual(str(self.run.directory / 'root.qcow2'), disk['file']['filename'])
        self.assertTrue(disk['backing']['read-only'])
        self.assertIsNone(disk['backing']['backing'])
        self.assertEqual(plan, _launch_plan(self.config, self.image, self.run.directory / 'root.qcow2', plan['uuid']))
        self.assertEqual(plan, json.loads((self.run.directory / 'launch-plan.json').read_text()))
        self.assertEqual(self.original, self.base.read_bytes())
        for name in ('launch-plan.json', 'preparation.jsonl'):
            self.assertNotIn(self.run._identity[2], (self.run.directory / name).read_text())
        before = (self.run.directory / 'root.qcow2').read_bytes()
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual(before, (self.run.directory / 'root.qcow2').read_bytes())

    def test_size_mismatch(self):
        self.failed(image=replace(self.image, size_bytes=1))
        self.assertEqual([], self.calls)

    def test_digest_mismatch(self):
        self.failed(image=replace(self.image, sha256='0' * 64))
        self.assertEqual([], self.calls)

    def test_invalid_base_observations(self):
        mutations = [lambda x: x.update(format='raw'),
                     lambda x: x.update({'backing-filename': '/unexpected'}),
                     lambda x: x['format-specific']['data'].update({'data-file': '/external'}),
                     lambda x: x['format-specific']['data'].update({'data-file-raw': False}),
                     lambda x: x.pop('format-specific'), lambda x: x.pop('virtual-size'),
                     lambda x: x.update({'dirty-flag': True})]
        # Each case has its own run/stand; unresolved evidence is never released.
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self.run = create_run(self.lease)
                self.calls = []
                entry = self.info(self.base)
                mutate(entry)
                self.hook = lambda argv: CommandResult(0, json.dumps([entry]).encode())
                self.failed()
                self.assertEqual(1, len(self.calls))

    def test_missing_malformed_and_incomplete_json(self):
        for output in (b'', b'{', b'null', b'{}', b'[]', b'[{}]', b'[{"format":"raw","format":"qcow2"}]'):
            with self.subTest(output=output):
                self.run = create_run(self.lease)
                self.calls = []
                self.hook = lambda argv: CommandResult(0, output)
                self.failed()

    def test_nonfinite_numbers_and_non_utf8_json_are_rejected(self):
        for value in (float('nan'), float('inf'), -float('inf'), 'utf16'):
            with self.subTest(value=value):
                self.run = create_run(self.lease)
                self.calls = []
                entry = self.info(self.base)
                if value != 'utf16':
                    entry['actual-size'] = value
                output = json.dumps([entry]).encode('utf-16' if value == 'utf16' else 'utf-8')
                self.hook = lambda argv: CommandResult(0, output)
                self.failed()

    def test_wrong_size_is_rejected_without_hashing_the_file(self):
        original_open = Path.open
        def guarded_open(path, *args, **kwargs):
            if path == self.base and args and args[0] == 'rb':
                self.fail('a size mismatch must be rejected before reading base bytes')
            return original_open(path, *args, **kwargs)
        with patch.object(Path, 'open', guarded_open):
            with self.assertRaises(ValueError):
                self.prepare(image=replace(self.image, size_bytes=1))
        self.assertEqual('error', self.run._read()['state'])
        self.assertEqual(self.original, self.base.read_bytes())
        self.assertEqual([], self.calls)

    @unittest.skipUnless(os.name == 'nt', 'Windows alternate streams and aliases')
    def test_windows_stream_and_alias_paths_are_rejected(self):
        for path in (str(self.base) + ':hidden', str(self.base) + '.', str(self.base) + ' '):
            with self.subTest(path=path), self.assertRaises(ValueError):
                replace(self.image, path=path).validate(self.run.directory)

    def test_failed_diagnostic_write_does_not_prevent_quarantine(self):
        broken = False
        original_open = Path.open
        def hook(argv):
            nonlocal broken
            if argv[1] == 'create':
                (self.run.directory / 'root.qcow2').write_bytes(b'partial')
                broken = True
                return CommandResult(7, b'')
        def failing_open(path, *args, **kwargs):
            if broken and path.name == 'preparation.jsonl':
                raise OSError('diagnostic storage unavailable')
            return original_open(path, *args, **kwargs)
        self.hook = hook
        with patch.object(Path, 'open', failing_open), self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual('quarantined', self.run._read()['state'])
        self.assertEqual(b'partial', (self.run.directory / 'root.qcow2').read_bytes())

    def test_initial_diagnostic_failure_marks_error(self):
        original_open = Path.open
        def failing_open(path, *args, **kwargs):
            if path.name == 'preparation.jsonl':
                raise OSError('diagnostic storage unavailable')
            return original_open(path, *args, **kwargs)
        with patch.object(Path, 'open', failing_open), self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual('error', self.run._read()['state'])
        self.assertEqual([], self.calls)

    def test_manifest_failure_does_not_prevent_diagnostic_failure_record(self):
        self.hook = lambda argv: CommandResult(7, b'')
        with patch.object(PreparedRun, 'mark', side_effect=OSError('manifest unavailable')):
            with self.assertRaises(ValueError):
                self.prepare()
        records = [json.loads(line) for line in (self.run.directory / 'preparation.jsonl').read_text().splitlines()]
        self.assertEqual('failed', records[-1]['status'])

    def test_interrupt_is_preserved_and_partial_disk_is_quarantined(self):
        def hook(argv):
            if argv[1] == 'create':
                (self.run.directory / 'root.qcow2').write_bytes(b'partial')
                raise KeyboardInterrupt()
        self.hook = hook
        with self.assertRaises(KeyboardInterrupt):
            self.prepare()
        self.assertEqual('quarantined', self.run._read()['state'])
        self.assertEqual(b'partial', (self.run.directory / 'root.qcow2').read_bytes())

    def test_executor_assertions_are_not_hidden_as_expected_input_failures(self):
        def hook(argv):
            raise AssertionError('fake executor contract failed')
        self.hook = hook
        with self.assertRaisesRegex(AssertionError, 'fake executor contract failed'):
            self.prepare()
        self.assertEqual('error', self.run._read()['state'])

    def test_base_changed_during_info_blocks_overlay_creation(self):
        def hook(argv):
            self.base.write_bytes(b'X' * len(self.original))
        self.hook = hook
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual(1, len(self.calls))
        self.assertEqual('error', self.run._read()['state'])
        self.assertFalse((self.run.directory / 'root.qcow2').exists())

    def test_plan_write_failure_preserves_quarantined_disk(self):
        original_open = Path.open
        def failing_open(path, *args, **kwargs):
            if path.name == 'launch-plan.json':
                raise OSError('plan storage unavailable')
            return original_open(path, *args, **kwargs)
        with patch.object(Path, 'open', failing_open):
            self.failed('quarantined')
        self.assertEqual(3, len(self.calls))

    def test_nonzero_timeout_and_output_limit_preserve_partial_overlay(self):
        for failure in ('nonzero', 'timeout', 'limit', 'missing-executable'):
            with self.subTest(failure=failure):
                self.run = create_run(self.lease)
                self.calls = []
                def hook(argv):
                    if argv[1] == 'create':
                        self.assertIn('root.qcow2', {r['path'] for r in self.run._read()['resources']})
                        (self.run.directory / 'root.qcow2').write_bytes(b'partial')
                        if failure == 'timeout':
                            raise subprocess.TimeoutExpired(argv, 30)
                        if failure == 'missing-executable':
                            raise FileNotFoundError('untrusted ' + self.run._identity[2])
                        if failure == 'limit':
                            return CommandResult(0, b'x' * (256 * 1024 + 1))
                        return CommandResult(7, self.run._identity[2].encode())
                self.hook = hook
                self.failed('quarantined')
                self.assertEqual(b'partial', (self.run.directory / 'root.qcow2').read_bytes())
                self.assertEqual(2, len(self.calls))

    def test_backing_mismatch_and_overlay_format(self):
        for mode in ('backing', 'format', 'external', 'size', 'chain'):
            with self.subTest(mode=mode):
                self.run = create_run(self.lease)
                self.calls = []
                def hook(argv):
                    if len(self.calls) == 3:
                        entry = self.info(self.run.directory / 'root.qcow2')
                        entry.update({'backing-filename': str(self.base), 'full-backing-filename': str(self.base),
                                      'backing-filename-format': 'qcow2'})
                        if mode == 'backing':
                            entry['backing-filename'] = '/foreign'
                        if mode == 'format':
                            entry['format'] = 'raw'
                        if mode == 'external':
                            entry['format-specific']['data']['data-file'] = '/foreign'
                        if mode == 'size':
                            entry['virtual-size'] = 2
                        chain = [entry, self.info(self.base)]
                        if mode == 'chain':
                            chain.append(self.info(self.base))
                        return CommandResult(0, json.dumps(chain).encode())
                self.hook = hook
                self.failed('quarantined')

    def test_existing_destination_is_not_overwritten(self):
        overlay = self.run.directory / 'root.qcow2'
        overlay.write_bytes(b'foreign')
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual(b'foreign', overlay.read_bytes())
        self.assertEqual([], self.calls)

    def test_foreign_run_and_lost_lease(self):
        original_run = self.run
        self.run = PreparedRun(self.lease, (self.run._identity[0], 'foreign', self.run._identity[2]))
        with self.assertRaises(ValueError):
            self.prepare()
        self.run = original_run
        self.lease.release()
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual([], self.calls)

    def test_lease_lost_during_create_preserves_intent(self):
        def hook(argv):
            if argv[1] == 'create':
                (self.run.directory / 'root.qcow2').write_bytes(b'partial')
                self.lease.release()
                return CommandResult(0, b'')
        self.hook = hook
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual(2, len(self.calls))
        self.assertTrue((self.run.directory / 'root.qcow2').exists())
        self.assertFalse((self.run.directory / 'launch-plan.json').exists())
        self.assertIn('command-intent', (self.run.directory / 'preparation.jsonl').read_text())

    def test_unsupported_contracts_and_ranges(self):
        for field, values in {'accelerator': ['whpx', 'hvf', 'tcg', 'kvm:tcg'],
                              'memory_mib': [True, 0, 65537], 'vcpus': [False, 0, 65],
                              'cpu': ['host,+vmx'], 'machine': ['pc', 'q35', 'pc-i440fx-9.2,accel=tcg']}.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    replace(self.config, **{field: value}).validate()
        for field, value in [('architecture', 'aarch64'), ('guest_os', 'windows'),
                             ('profile', 'uefi'), ('format', 'raw'), ('schema', 'unknown')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                replace(self.image, **{field: value}).validate(self.run.directory)

    def test_traversal_comma_and_base_in_run_are_rejected(self):
        inside = self.run.directory / 'base.qcow2'
        inside.write_bytes(self.original)
        comma = self.root / 'base,unsafe.qcow2'
        comma.write_bytes(self.original)
        for path in (inside, comma, self.root / '..' / self.root.name / self.base.name):
            with self.subTest(path=path), self.assertRaises(ValueError):
                replace(self.image, path=str(path)).validate(self.run.directory)
        self.failed(image=replace(self.image, path=str(comma)))
        self.assertEqual([], self.calls)

    def test_missing_base_and_directory_are_rejected(self):
        for path in (self.root / 'missing', self.root):
            with self.subTest(path=path), self.assertRaises((ValueError, OSError)):
                replace(self.image, path=str(path)).validate(self.run.directory)

    def test_option_and_shell_characters_remain_filename_data(self):
        self.base = self.root / 'base=options;[test]# Юникод.qcow2'
        self.base.write_bytes(self.original)
        self.image = replace(self.image, path=str(self.base))
        plan = self.prepare()
        disk = json.loads(plan['argv'][plan['argv'].index('-blockdev') + 1])
        self.assertEqual(str(self.base), disk['backing']['file']['filename'])

    def test_symlink_overlay_destination_is_rejected(self):
        overlay = self.run.directory / 'root.qcow2'
        try:
            overlay.symlink_to(self.base)
        except OSError:
            self.skipTest('host does not permit file symlinks')
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual([], self.calls)
        self.assertEqual(self.original, self.base.read_bytes())

    def test_owner_token_in_input_is_never_persisted(self):
        self.failed(image=replace(self.image, identifier=self.run._identity[2]))
        self.assertEqual([], self.calls)

    def test_comma_in_run_directory_blocks_all_commands(self):
        with StandLease(self.root / 'state,unsafe', 'other') as lease:
            self.run = create_run(lease)
            self.failed()
            self.assertEqual([], self.calls)

    def test_successful_create_without_file_is_an_error(self):
        self.hook = lambda argv: CommandResult(0, b'') if argv[1] == 'create' else None
        self.failed()
        self.assertEqual(2, len(self.calls))

    def test_nonzero_base_info_is_not_success(self):
        self.hook = lambda argv: CommandResult(1, json.dumps([self.info(self.base)]).encode())
        self.failed()
        self.assertEqual(1, len(self.calls))

    def test_overlay_info_timeout_keeps_overlay(self):
        def hook(argv):
            if len(self.calls) == 3:
                raise TimeoutError('untrusted ' + self.run._identity[2])
        self.hook = hook
        self.failed('quarantined')
        self.assertTrue((self.run.directory / 'root.qcow2').exists())
        self.assertIn('command-timeout', (self.run.directory / 'preparation.jsonl').read_text())

    def test_uuids_are_unique_between_preparations(self):
        first = self.prepare()
        self.run = create_run(self.lease)
        self.calls = []
        second = self.prepare()
        self.assertNotEqual(first['uuid'], second['uuid'])

    def test_symlink_ancestor_is_rejected(self):
        link = self.root / 'linked'
        try:
            link.symlink_to(self.base.parent, target_is_directory=True)
        except OSError:
            self.skipTest('host does not permit directory symlinks')
        self.failed(image=replace(self.image, path=str(link / self.base.name)))
        self.assertEqual([], self.calls)

    @unittest.skipUnless(os.name == 'nt', 'Windows junction/reparse check')
    def test_reparse_attribute_is_rejected_without_external_commands(self):
        real_lstat = Path.lstat
        def lstat(path, *args, **kwargs):
            result = real_lstat(path, *args, **kwargs)
            if path == self.base:
                class Reparse:
                    st_mode = result.st_mode
                    st_file_attributes = 0x400
                return Reparse()
            return result
        with patch.object(Path, 'lstat', lstat):
            self.failed()
        self.assertEqual([], self.calls)


class ImageChildTests(unittest.TestCase):
    def test_only_the_same_container_file_leaf_is_accepted(self):
        import copy
        from tools.vm.matrix.images import image_chain
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'base.qcow2'
            path.write_bytes(b'synthetic')
            leaf = {'children': [], 'virtual-size': 512,
                    'filename': str(path), 'format': 'file', 'actual-size': 4096,
                    'format-specific': {'type': 'file', 'data': {}}, 'dirty-flag': False}
            info = {'format': 'qcow2', 'filename': str(path), 'virtual-size': 1048576,
                    'format-specific': {'type': 'qcow2', 'data': {'compat': '1.1', 'refcount-bits': 16}},
                    'children': [{'name': 'file', 'info': leaf}]}
            self.assertEqual(1048576, image_chain(json.dumps([info]).encode(), [path]))
            mutations = [lambda x: x.update(children=[]),
                         lambda x: x['children'].append(copy.deepcopy(x['children'][0])),
                         lambda x: x['children'][0].update(name='data-file'),
                         lambda x: x['children'][0]['info'].update(filename='/external'),
                         lambda x: x['children'][0]['info'].update(format='qcow2'),
                         lambda x: x['children'][0]['info'].update(children=[{}]),
                         lambda x: x['children'][0]['info'].update({'virtual-size': True}),
                         lambda x: x['children'][0]['info'].update({'virtual-size': 1}),
                         lambda x: x['children'][0]['info'].update({'actual-size': True}),
                         lambda x: x['children'][0]['info'].update({'dirty-flag': True}),
                         lambda x: x['children'][0]['info'].update({'data-file': '/external'}),
                         lambda x: x['children'][0]['info'].update({'backing-filename': '/external'}),
                         lambda x: x['format-specific']['data'].update(children=[])]
            for index, mutate in enumerate(mutations):
                value = copy.deepcopy(info)
                mutate(value)
                with self.subTest(index=index), self.assertRaises(ValueError):
                    image_chain(json.dumps([value]).encode(), [path])


if __name__ == '__main__':
    unittest.main()
