"""Offline media/import tests. No packager, mount, services or devices."""

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.vm.matrix import linux_l2 as l2, l2_media as media, l2_import as delivery
from tools.vm.matrix.qemu import CommandResult, CommandError
from tools.vm.matrix.tests import test_linux_l2, test_qemu, test_jobs
from tools.vm.matrix.tests.test_linux_l2 import CHECKOUT, SOURCE, package
from tools.vm.matrix.tests.test_qga import BOOT
from tools.vm.matrix.tests.test_jobs import GUEST

spec = importlib.util.spec_from_file_location('stage_l2', CHECKOUT / 'tools/vm/linux/guest/stage-l2.py')
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class MediaTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_qemu.PreparationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.prepare()
        self.run = self.fixture.run
        path = self.run.directory / 'launch-plan.json'
        self.plan = json.loads(path.read_bytes())
        self.plan['config']['qga'] = True
        self.plan['config']['machine'] = 'pc-i440fx-10.0'
        path.write_text(json.dumps(self.plan))
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        package(self.root, BOOT)
        (self.root / 'job.env').unlink()
        (self.root / 'manifest.sha256').unlink()
        self.patcher = patch.object(l2, 'source_identity', return_value=SOURCE)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.commands = []

    def executor(self, argv, **limits):
        self.commands.append((argv, limits))
        if argv[-1] == '-version':
            return CommandResult(0, b'xorriso 1.5.6\n')
        Path(argv[argv.index('-o') + 1]).write_bytes(b'inert ISO fixture')
        return CommandResult(0, b'')

    def build(self, executor=None):
        return media.attach_media(self.run, directory=self.root, checkout=CHECKOUT,
                                  xorriso=self.plan['config']['executable'], executor=executor or self.executor)

    def test_snapshot_composition_argv_and_read_only_plan(self):
        record = self.build()
        self.assertNotIn('job.env', {p.name for p in (self.run.directory / 'l2-snapshot').iterdir()})
        self.assertEqual(300, self.commands[1][1]['timeout'])
        argv = self.commands[1][0]
        self.assertEqual(['-as', 'mkisofs', '-iso-level', '3', '-R', '-V', 'ROSETUN_L2'], argv[2:9])
        self.assertEqual(str(self.run.directory / 'l2-snapshot'), argv[-1])
        plan = json.loads((self.run.directory / 'launch-plan.json').read_bytes())
        self.assertIn('virtio-blk-pci,drive=root,bootindex=1', plan['argv'])
        self.assertIn('virtio-blk-pci,drive=l2media,id=l2media,serial=rosetun-l2-media', plan['argv'])
        block = json.loads(plan['argv'][-3])
        self.assertTrue(block['read-only'])
        self.assertEqual('raw', block['driver'])
        media.verify_media(record)
        Path(record['path']).write_bytes(b'corrupt')
        with self.assertRaises(ValueError):
            media.verify_media(record)

    def test_start_rechecks_iso_before_any_external_operation(self):
        record = self.build()
        Path(record['path']).write_bytes(b'changed after preparation')
        from tools.vm.matrix import lifecycle
        with patch.object(lifecycle, '_host'), patch.object(lifecycle.subprocess, 'Popen') as spawn:
            with self.assertRaises(lifecycle.LifecycleError):
                lifecycle.start(self.run, executor=lambda *a, **k: self.fail('unexpected image tool'))
        spawn.assert_not_called()

    def test_timeout_retains_partial_and_intent(self):
        def fail(argv, **limits):
            if argv[-1] == '-version':
                return self.executor(argv, **limits)
            Path(argv[argv.index('-o') + 1]).write_bytes(b'partial')
            error = CommandError('command-timeout')
            error.stdout, error.stderr = b'partial diagnostic', b'bounded stderr'
            raise error
        with self.assertRaises(CommandError):
            self.build(fail)
        self.assertEqual(b'partial', (self.run.directory / 'l2-media.iso').read_bytes())
        self.assertTrue((self.run.directory / 'l2-snapshot/artifacts/provenance.json').exists())
        self.assertIn('failed-retain-partials', (self.run.directory / 'l2-media.jsonl').read_text())
        self.assertIn('partial diagnostic', (self.run.directory / 'l2-media.jsonl').read_text())

    def test_changed_source_during_copy_is_rejected(self):
        real = media.copy_verified
        def change(src, dst, sha, size):
            src.write_bytes(src.read_bytes() + b'changed')
            real(src, dst, sha, size)
        with patch.object(media, 'copy_verified', side_effect=change), self.assertRaises(ValueError):
            self.build()
        self.assertEqual(1, len(self.commands))

    def test_immutable_extra_file_and_bad_binary_are_rejected(self):
        (self.root / 'job.env').write_bytes(b'not on ISO')
        with self.assertRaises(ValueError):
            l2.validate_package(self.root, checkout=CHECKOUT, immutable=True)
        (self.root / 'job.env').unlink()
        (self.root / 'artifacts' / l2.BINARIES[0]).write_bytes(b'MZ')
        with self.assertRaises(ValueError):
            l2.validate_package(self.root, checkout=CHECKOUT, immutable=True)

    def test_missing_tool_and_wrong_version_are_preflight_errors(self):
        with patch.object(media, 'local_file', side_effect=ValueError('missing tool')):
            with self.assertRaises(ValueError):
                self.build()
        self.assertEqual([], self.commands)

    def test_wrong_version_fails_without_packing(self):
        with self.assertRaises(ValueError):
            self.build(lambda argv, **limits: CommandResult(0, b'xorriso 1.5.8'))
        self.assertFalse((self.run.directory / 'l2-media.iso').exists())

    def test_output_overflow_fails_without_packing(self):
        with self.assertRaises(ValueError):
            self.build(lambda argv, **limits: CommandResult(0, b'x' * 65537))
        self.assertFalse((self.run.directory / 'l2-media.iso').exists())

    def test_nonzero_preflight_fails_without_packing(self):
        with self.assertRaises(ValueError):
            self.build(lambda argv, **limits: CommandResult(1, b'xorriso 1.5.6'))
        self.assertFalse((self.run.directory / 'l2-media.iso').exists())


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_jobs.JobsTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.vm, self.agent = self.fixture.vm, self.fixture.agent
        del self.vm._smoke_job
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        package(self.root, self.vm.vm_uuid, self.vm.run._identity[1])
        (self.root / 'job.env').unlink()
        (self.root / 'manifest.sha256').unlink()
        with patch.object(l2, 'source_identity', return_value=SOURCE):
            p = l2.validate_package(self.root, checkout=CHECKOUT, immutable=True)
        content = media.manifest(p['hashes'], media.CONTENT)
        (self.root / 'content.sha256').write_bytes(content)
        self.vm._l2_media = dict(package=p, sha256='c' * 64, size=2048,
                                 content_sha256=hashlib.sha256(content).hexdigest())
        # Reserve as start() would, before a live controller is constructed.
        from tools.vm.matrix.resources import _atomic_manifest
        record = self.vm.run._read()
        for index, n in enumerate(media.RESOURCES):
            record['resources'].append(dict(id='import-test-' + str(index), kind='file', path=n))
            path = self.vm.run.directory / n
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        _atomic_manifest(self.vm.run.directory, record)
        for n in media.CONTENT:
            (self.vm.run.directory / 'l2-package' / n).write_bytes((self.root / n).read_bytes())
        self.obj = delivery.L2Import(self.vm, guest_run_id=GUEST, import_id='d' * 32,
                                    user_a='l2a', user_b='l2b', enabled=True)
        self.fixture.files['ready.json'] = json.dumps(dict(self.obj.identity,
            schema='rosetun.l2-import.v1', state='ready')).encode()

    def test_success_uses_existing_job_and_final_env_manifest(self):
        value = self.obj.stage()
        self.assertEqual('ready', value['state'])
        encoded = base64.b64encode(json.dumps(self.obj.request).encode()).decode()
        identity, hashes, sizes, env, final = helper.request(encoded)
        self.assertEqual(identity, self.obj.identity)
        self.assertIn(('EXPECTED_BOOT_ID=' + BOOT).encode(), env)
        self.assertEqual(final, (self.vm.run.directory / 'l2-package/manifest.sha256').read_bytes())
        with patch.object(l2, 'source_identity', return_value=SOURCE):
            job = self.obj.linux_l2_job(checkout=CHECKOUT, enabled=True)
        self.assertIsInstance(job, l2.LinuxL2Job)
        job.submit()
        from tools.vm.matrix.tests.test_matrix import synthetic_inputs
        _, report, status = synthetic_inputs()
        report['run_id'] = GUEST
        report['guest'] = dict(boot_id=BOOT, boot_id_at_end=BOOT)
        status.update(run_id=GUEST, boot_id=BOOT)
        self.fixture.files.update({'report.json': json.dumps(report).encode(), 'status.json': json.dumps(status).encode()})
        self.assertEqual('PASS', job.collect()['verification'])
        paths = [a['path'] for n, a in self.agent.client.commands if n == 'guest-exec']
        self.assertEqual([delivery.HELPER, l2.LAUNCHER], paths)

    def test_lost_exec_receipt_and_foreign_receipt_never_repeat_import(self):
        self.agent.client.responses['guest-exec'] = lambda: (_ for _ in ()).throw(ValueError('lost'))
        with self.assertRaises(ValueError):
            self.obj.stage()
        with self.assertRaises(ValueError):
            self.obj.stage()
        with self.assertRaises(ValueError):
            self.obj.require_ready()
        self.assertEqual(1, sum(n == 'guest-exec' for n, _ in self.agent.client.commands))
        with self.assertRaises(ValueError):
            delivery.L2Import(self.vm, guest_run_id=GUEST, import_id='e' * 32,
                              user_a='l2a', user_b='l2b', enabled=True)


    def test_lost_status_or_receipt_can_only_inspect_saved_receipt(self):
        self.agent.client.responses['guest-exec-status'] = lambda: (_ for _ in ()).throw(ValueError('lost status'))
        with self.assertRaises(ValueError):
            self.obj.stage()
        with self.assertRaises(ValueError):
            self.obj.stage()
        replacement = self.fixture.agent_new()
        self.fixture.install_files(replacement)
        with patch.object(delivery.l2, 'source_identity', return_value=SOURCE), \
                patch('tools.vm.matrix.lifecycle.Qga', return_value=replacement):
            from tools.vm.matrix.tests import test_lifecycle
            with patch('socket.socketpair', test_lifecycle.REAL_SOCKETPAIR):
                self.vm.recover_guest()
        self.obj.check_receipt()
        self.assertTrue(self.obj.receipt_verified)
        self.assertFalse(any(n == 'guest-exec' for n, _ in replacement.client.commands))
        self.assertEqual(1, sum(n == 'guest-exec' for n, _ in self.agent.client.commands))

    def test_boot_is_required_before_env_creation_and_bad_manifest_is_rejected(self):
        self.vm.guest_observation = None
        del self.vm._l2_import
        with self.assertRaises(ValueError):
            delivery.L2Import(self.vm, guest_run_id=GUEST, import_id='e' * 32,
                              user_a='l2a', user_b='l2b', enabled=True)
        request = json.loads(json.dumps(self.obj.request))
        request['identity']['manifest_sha256'] = 'f' * 64
        with self.assertRaises(ValueError):
            helper.request(base64.b64encode(json.dumps(request).encode()).decode())

    def test_foreign_receipt_and_boot_change_block_submit(self):
        self.fixture.files['ready.json'] = b'{}'
        with self.assertRaises(ValueError):
            self.obj.stage()
        with self.assertRaises(ValueError):
            self.obj.linux_l2_job(checkout=CHECKOUT, enabled=True)
        self.vm.last_boot_id = 'e' * 36
        with self.assertRaises(ValueError):
            self.obj.check_receipt()

    def test_lost_receipt_requires_explicit_recovery_without_new_exec(self):
        opened = self.agent.client.responses['guest-file-open']
        def lose_receipt():
            path = self.agent.client.commands[-1][1]['path']
            if path.endswith('/ready.json'):
                raise TimeoutError('lost receipt')
            return opened()
        self.agent.client.responses['guest-file-open'] = lose_receipt
        with self.assertRaises(ValueError):
            self.obj.stage()
        with self.assertRaises(ValueError):
            self.obj.stage()
        replacement = self.fixture.agent_new()
        self.fixture.install_files(replacement)
        with patch('tools.vm.matrix.lifecycle.Qga', return_value=replacement):
            from tools.vm.matrix.tests import test_lifecycle
            with patch('socket.socketpair', test_lifecycle.REAL_SOCKETPAIR):
                self.vm.recover_guest()
        self.obj.check_receipt()
        self.assertFalse(any(n == 'guest-exec' for n, _ in replacement.client.commands))

    def test_changed_boot_blocks_existing_job_submit(self):
        self.obj.stage()
        with patch.object(l2, 'source_identity', return_value=SOURCE):
            job = self.obj.linux_l2_job(checkout=CHECKOUT, enabled=True)
        self.vm.last_boot_id = 'foreign-boot'
        with self.assertRaises(ValueError): job.submit()
        self.assertEqual(1, sum(n == 'guest-exec' for n, _ in self.agent.client.commands))

    def test_import_poll_budget_does_not_repeat_exec(self):
        self.agent.client.responses['guest-exec-status'] = {'exited': False}
        with patch.object(delivery.time, 'sleep') as sleep, self.assertRaises(ValueError):
            self.obj.stage()
        self.assertEqual(23, sleep.call_count)
        self.assertFalse(self.obj.receipt_verified)
        self.assertEqual(24, sum(n == 'guest-exec-status' for n, _ in self.agent.client.commands))
        self.assertEqual(1, sum(n == 'guest-exec' for n, _ in self.agent.client.commands))

    def test_guest_copy_and_no_replace_unmount_failure(self):
        class Adapter:
            def find(inner): return Path('/unused'), 2048
            def verify(inner, *args): pass
            def mount(inner, device, target):
                import shutil
                shutil.copytree(self.root, target, dirs_exist_ok=True)
            def unmount(inner, target): pass
        def publish(source, target):
            if os.path.lexists(target):
                raise ValueError('destination exists')
            source.rename(target)
        with tempfile.TemporaryDirectory() as temp, patch.object(helper, 'ROOT', Path(temp)), \
                patch.object(helper, 'sync_dir'), patch.object(helper, 'trusted'), patch.object(os, 'fsync'), \
                patch.object(helper, 'publish', side_effect=publish), \
                patch.object(os, 'chown', create=True), patch.object(os, 'fchown', create=True), patch.object(os, 'fchmod', create=True), \
                patch.object(os, 'O_NOFOLLOW', getattr(os, 'O_NOFOLLOW', 0), create=True), \
                patch.object(os, 'O_NONBLOCK', getattr(os, 'O_NONBLOCK', 0), create=True):
            i, hashes, sizes, env, final = helper.request(base64.b64encode(json.dumps(self.obj.request).encode()).decode())
            helper.import_media(i, hashes, sizes, env, final, Adapter())
            self.assertEqual(env, (Path(temp) / GUEST / 'job.env').read_bytes())
            before = (Path(temp) / GUEST / 'job.env').read_bytes()
            with self.assertRaises(ValueError):
                helper.import_media(i, hashes, sizes, env, final, Adapter())
            self.assertEqual(before, (Path(temp) / GUEST / 'job.env').read_bytes())
            i = dict(i, guest_run_id='20261111T010203Z-ffffffff', import_id='f' * 32)
            class Broken(Adapter):
                def unmount(inner, target): raise ValueError('unmount unknown')
            with self.assertRaises(ValueError):
                helper.import_media(i, hashes, sizes, env, final, Broken())
            self.assertFalse((Path(temp) / ('.import-' + i['import_id']) / 'ready.json').exists())


class GuestValidationTests(unittest.TestCase):
    def test_device_missing_ambiguous_writable_and_partition_are_rejected(self):
        from types import SimpleNamespace
        import stat
        class Node:
            def __init__(self, path=''):
                self.path = path
                self.name = path.rsplit('/', 1)[-1]
            def __truediv__(self, n): return Node(self.path + '/' + n)
            def iterdir(self): return [Node('vda') for _ in range(count)]
            def exists(self): return partition if self.name == 'partition' else True
            def read_text(self):
                return {'serial': helper.SERIAL, 'ro': readonly, 'dev': '0:0', 'size': '4'}[self.name]
            def resolve(self): return SimpleNamespace(name='virtio_blk')
            def lstat(self): return SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=0)
        readonly, partition = '1', False
        with patch.object(helper, 'Path', side_effect=Node), \
                patch.object(os, 'major', return_value=0, create=True), \
                patch.object(os, 'minor', return_value=0, create=True):
            for count in (0, 2):
                with self.assertRaises(ValueError): helper.LinuxDevice().find()
            count = 1
            readonly = '0'
            with self.assertRaises(ValueError): helper.LinuxDevice().find()
            readonly, partition = '1', True
            with self.assertRaises(ValueError): helper.LinuxDevice().find()
            partition = False
            self.assertEqual(2048, helper.LinuxDevice().find()[1])

    def test_guest_tree_hashes_links_and_trusted_permissions(self):
        import stat
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for n in media.CONTENT:
                p = root / n
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b'inert')
            (root / 'content.sha256').write_bytes(b'inert')
            helper.composition(root)
            (root / 'unexpected').mkdir()
            with self.assertRaises(ValueError): helper.composition(root)
            (root / 'unexpected').rmdir()
            real = Path.lstat
            def link(p):
                return SimpleNamespace(st_mode=stat.S_IFLNK) if p.name == 'launch.sh' else real(p)
            with patch.object(Path, 'lstat', link), self.assertRaises(ValueError):
                helper.composition(root)
            with patch.object(os, 'O_NOFOLLOW', getattr(os, 'O_NOFOLLOW', 0), create=True), \
                    patch.object(os, 'O_NONBLOCK', getattr(os, 'O_NONBLOCK', 0), create=True), \
                    self.assertRaises(ValueError):
                helper.copy_file(root / 'content.sha256', root / 'target', 5, 'f' * 64)
            path = root / 'content.sha256'
            for uid, mode, links in ((1, 0o100644, 1), (0, 0o100666, 1), (0, 0o100644, 2)):
                with patch.object(Path, 'lstat', return_value=SimpleNamespace(
                        st_uid=uid, st_mode=mode, st_nlink=links)), self.assertRaises(ValueError):
                    helper.trusted(path)


if __name__ == '__main__':
    unittest.main()
