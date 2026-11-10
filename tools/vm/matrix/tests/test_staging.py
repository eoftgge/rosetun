"""Offline delivery tests: original Vm lifecycle with in-memory QGA peers."""

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tools.vm.matrix import staging
from tools.vm.matrix.jobs import JobError
from tools.vm.matrix.qga import QgaError
from tools.vm.matrix.tests.test_jobs import JobsTests, GUEST

CHECKOUT = Path(__file__).resolve().parents[4]
ATTEMPT = '0123456789abcdef' * 2


class StagingTests(JobsTests):
    # Inherited jobs tests also verify that the manual path remains available.
    def build(self, **kw):
        del self.vm._smoke_job
        return staging.SmokePackage.build(self.vm, checkout=CHECKOUT, enabled=True,
                                          guest_run_id=GUEST, attempt_id=ATTEMPT, **kw)

    def peer(self, package):
        commands = self.agent.client.responses['guest-info']['supported_commands']
        commands.append(dict(name='guest-file-write', enabled=True, **{'success-response': True}))
        self.sent = {}
        self.path = None
        def opened():
            self.path = self.agent.client.commands[-1][1]['path']
            return 8
        def written():
            args = self.agent.client.commands[-1][1]
            data = base64.b64decode(args['buf-b64'])
            self.sent[self.path] = self.sent.get(self.path, b'') + data
            return {'count': len(data), 'eof': False}
        self.agent.client.responses['guest-file-open'] = opened
        self.agent.client.responses['guest-file-write'] = written
        raw = (json.dumps(dict(package.identity, schema='rosetun.smoke-stage.v1', state='ready')) + '\n').encode()
        self.receipt = raw
        self.agent.client.responses['guest-file-read'] = lambda: {
            'count': len(self.receipt), 'eof': True, 'buf-b64': base64.b64encode(self.receipt).decode()}

    def test_exact_bytes_manifest_and_existing_job_path(self):
        package = self.build(delay_seconds=1)
        original = tuple(package._files)
        self.peer(package)
        with patch.object(staging, '_read_source', side_effect=AssertionError('must not reread')):
            package.stage()
        self.assertEqual('ready', package.state)
        prefix = staging.ROOT + '/.attempt-' + ATTEMPT + '/package/'
        self.assertEqual(dict(original), {p.removeprefix(prefix): data for p, data in self.sent.items()})
        expected = ''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n' for name, data in original[:-1]).encode()
        self.assertEqual(expected, original[-1][1])
        for name, data in original:
            self.assertEqual(data, (self.vm.run.directory / 'smoke-package' / name).read_bytes())
        self.job = package.smoke_job(enabled=True)
        self.install_files(self.agent)
        self.job.submit()
        self.terminal()
        self.assertEqual('VERIFIED', self.job.collect()['verification'])
        self.assertLessEqual(package.calls, 40)
        self.vm.hard_off()
        self.assertTrue(self.vm.completed)

    def test_write_counts_fail_closed_and_close_known_handle(self):
        for count in (0, 1, True, -1, staging.BLOCK + 1):
            with self.subTest(count=count):
                # Each subcase has a separate original live Vm.
                if hasattr(self.vm, '_smoke_package'):
                    self.close_vm()
                    self.doCleanups()
                    self.setUp()
                package = self.build()
                self.peer(package)
                self.agent.client.responses['guest-file-write'] = {'count': count, 'eof': False}
                with self.assertRaises(JobError):
                    package.stage()
                self.assertEqual('unknown', package.state)
                self.assertIn('closed', package.handles.values())
                self.assertEqual(1, sum(n == 'guest-exec' for n, _ in self.agent.client.commands))
                with self.assertRaises(JobError):
                    package.stage()
                with self.assertRaises(JobError):
                    package.smoke_job(enabled=True)

    def test_lost_open_write_close_and_finalize_never_repeat(self):
        for operation in ('guest-file-open', 'guest-file-write', 'guest-file-close', 'finalize'):
            with self.subTest(operation=operation):
                if hasattr(self.vm, '_smoke_package'):
                    self.close_vm()
                    self.doCleanups()
                    self.setUp()
                package = self.build()
                self.peer(package)
                if operation == 'finalize':
                    def execute():
                        args = self.agent.client.commands[-1][1]['arg']
                        if args[0] == 'finalize':
                            raise TimeoutError()
                        return {'pid': 42}
                    self.agent.client.responses['guest-exec'] = execute
                else:
                    self.agent.client.responses[operation] = TimeoutError()
                with self.assertRaises(QgaError):
                    package.stage()
                self.assertFalse(self.agent.valid)
                commands = len(self.agent.client.commands)
                with self.assertRaises(JobError):
                    package.stage()
                self.assertEqual(commands, len(self.agent.client.commands))
                with self.assertRaises(JobError):
                    package.smoke_job(enabled=True)
                if operation == 'finalize':
                    replacement = self.agent_new()
                    replacement.client.responses['guest-file-open'] = 9
                    from tools.vm.matrix import lifecycle
                    with patch.object(lifecycle, 'Qga', return_value=replacement):
                        self.vm.recover_guest()
                    replacement.client.responses['guest-file-read'] = self.agent.client.responses['guest-file-read']
                    package.check_receipt()
                    self.assertFalse(any(n in ('guest-exec', 'guest-file-write') for n, _ in replacement.client.commands))

    def test_foreign_receipt_and_boot_change_block_submit(self):
        package = self.build()
        self.peer(package)
        self.receipt = b'{}\n'
        with self.assertRaises(JobError):
            package.stage()
        for key in package.identity:
            value = dict(package.identity, schema='rosetun.smoke-stage.v1', state='ready')
            value[key] = 'foreign'
            self.receipt = json.dumps(value).encode()
            with patch.object(package, '_file', return_value=self.receipt):
                with self.assertRaises(JobError):
                    package.check_receipt()
        self.receipt = json.dumps(dict(package.identity, schema='rosetun.smoke-stage.v1', state='ready')).encode()
        package.check_receipt()
        job = package.smoke_job(enabled=True)
        self.vm.last_boot_id = '12345678-1234-4234-8234-123456789aaa'
        with self.assertRaises(JobError):
            job.submit()

    def test_registration_stays_closed_and_sources_are_strict(self):
        with self.assertRaises(ValueError):
            self.vm.run.register({'id': 'arbitrary', 'kind': 'file', 'path': 'foreign'})
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'source.sh'
            source.write_bytes(b'echo test\r\n')
            with self.assertRaises(JobError):
                staging._read_source(source)
            source.write_bytes(b'echo test\n')
            real_regular = staging._regular_file
            calls = [0]
            def changed(path):
                calls[0] += 1
                if calls[0] == 2:
                    source.write_bytes(b'echo changed\n')
                return real_regular(path)
            with patch.object(staging, '_regular_file', changed):
                with self.assertRaises(JobError):
                    staging._read_source(source)
            if os.name == 'posix':
                link = Path(folder) / 'link'
                link.symlink_to(source)
                with self.assertRaises(ValueError):
                    staging._read_source(link)

    def test_limits_reparse_opt_in_and_traversal(self):
        with self.assertRaises(JobError):
            staging.SmokePackage.build(self.vm, checkout=CHECKOUT, guest_run_id=GUEST, attempt_id=ATTEMPT)
        del self.vm._smoke_job
        for changes in ({'guest_run_id': '../escape'}, {'attempt_id': '../escape'},
                        {'checkout': CHECKOUT / '..'}, {'delay_seconds': 31}, {'delay_seconds': True}):
            args = dict(checkout=CHECKOUT, enabled=True, guest_run_id=GUEST, attempt_id=ATTEMPT)
            args.update(changes)
            with self.assertRaises(JobError):
                staging.SmokePackage.build(self.vm, **args)
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'large'
            source.write_bytes(b'x' * (staging.FILE_LIMIT + 1))
            with self.assertRaises(JobError):
                staging._read_source(source)
            with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=0o100600, st_file_attributes=0x400)):
                with self.assertRaises(ValueError):
                    staging._read_source(source)

    def test_live_boot_change_without_observation_blocks_launcher(self):
        package = self.build()
        self.peer(package)
        package.stage()
        job = package.smoke_job(enabled=True)
        with patch.object(self.agent, 'read_boot_id', return_value='12345678-1234-4234-8234-123456789aaa'):
            with self.assertRaises(JobError):
                job.submit()
        self.assertFalse(any(n == 'guest-exec' and a['path'].endswith('/launch')
                             for n, a in self.agent.client.commands))

    def test_attempt_budgets_survive_recovery_and_deadline(self):
        package = self.build()
        self.peer(package)
        package.stage()
        package.calls = staging.RPC_LIMIT - 5
        self.vm.qga_recoveries += 1
        with self.assertRaises(JobError):
            package.check_receipt()
        self.assertGreaterEqual(package.calls, staging.RPC_LIMIT)
        package.calls = 0
        package.deadline = 0
        with self.assertRaises(JobError):
            package.smoke_job(enabled=True)

    def test_failed_ready_evidence_never_authorizes_launch(self):
        package = self.build()
        self.peer(package)
        real_evidence = package._evidence
        def evidence(operation, **extra):
            if operation == 'ready':
                raise JobError('simulated-evidence-failure')
            return real_evidence(operation, **extra)
        with patch.object(package, '_evidence', side_effect=evidence):
            with self.assertRaises(JobError):
                package.stage()
        self.assertFalse(package.receipt_verified)
        self.assertEqual('unknown', package.state)
        with self.assertRaises(JobError):
            package.smoke_job(enabled=True)

    def test_helper_polling_keeps_four_polls_and_one_second_intervals(self):
        package = self.build()
        self.peer(package)
        polls = [0]
        def status():
            polls[0] += 1
            return {'exited': True, 'exitcode': 0} if polls[0] % 4 == 0 else {'exited': False}
        self.agent.client.responses['guest-exec-status'] = status
        with patch.object(staging.time, 'sleep') as sleep:
            package.stage()
        self.assertEqual(8, polls[0])
        self.assertEqual([((1,), {})] * 6, sleep.call_args_list)
        self.assertEqual(2, sum(n == 'guest-exec' for n, _ in self.agent.client.commands))
        self.assertLessEqual(package.calls, 40)


class GuestHelperTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('stage_smoke', CHECKOUT / 'tools/vm/linux/guest/stage-smoke.py')
        self.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.helper)

    def test_trust_rejects_foreign_owner_permissions_and_links(self):
        import stat
        for mode, uid, links in ((stat.S_IFREG | 0o600, 1, 1),
                                 (stat.S_IFREG | 0o666, 0, 1),
                                 (stat.S_IFLNK | 0o777, 0, 1),
                                 (stat.S_IFREG | 0o600, 0, 2)):
            with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=mode, st_uid=uid, st_nlink=links)):
                with self.assertRaises(ValueError):
                    self.helper.trusted(Path('foreign'))

    def test_guest_create_finalize_exact_package_and_retention(self):
        h = self.helper
        machine = '12345678-1234-4234-8234-123456789abd'
        boot = '12345678-1234-4234-8234-123456789abc'
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            payload = {name: b'#!/bin/bash\necho fixture\n' for name in h.PAYLOAD[:-1]}
            payload['job.env'] = (f'PROFILE=infra-smoke-v1\nHOST_RUN_ID=host\nRUN_ID={GUEST}\n'
                                  f'VM_UUID={machine}\nEXPECTED_BOOT_ID={boot}\nJOB_ID=smoke\nDELAY_SECONDS=0\n').encode()
            manifest = ''.join(hashlib.sha256(payload[name]).hexdigest() + '  ' + name + '\n'
                               for name in h.PAYLOAD).encode()
            payload['manifest.sha256'] = manifest
            args = ['create', 'host', GUEST, machine, boot, ATTEMPT, hashlib.sha256(manifest).hexdigest()]
            # Only temporary filesystem operations; all root/system probes are fakes.
            def trusted(path, *, directory=False, private=False):
                info = path.lstat()
                h.require(not path.is_symlink() and (path.is_dir() if directory else path.is_file()))
                return info
            def publish(source, target):
                if os.path.lexists(target):
                    raise FileExistsError()
                os.rename(source, target)
            with patch.object(h, 'ROOT', root), patch.object(h, 'parents'), \
                    patch.object(h, 'trusted', side_effect=trusted), \
                    patch.object(h, 'INSTALLED', root / 'installed'), \
                    patch.object(h.os, 'geteuid', return_value=0, create=True), \
                    patch.object(h, 'boot_id', return_value=boot), \
                    patch.object(h, 'vm_uuid', return_value=machine), \
                    patch.object(h, 'sync_dir'), patch.object(h.os, 'fsync'), \
                    patch.object(h.os, 'O_NOFOLLOW', 0, create=True), \
                    patch.object(h.os, 'O_NONBLOCK', 0, create=True), \
                    patch.object(h, 'publish', side_effect=publish):
                (root / 'installed').write_bytes(b'trust anchor')
                h.main(args)
                attempt = root / ('.attempt-' + ATTEMPT)
                package = attempt / 'package'
                for name in h.FILES:
                    self.assertEqual(b'', (package / name).read_bytes())
                    if os.name == 'posix':
                        self.assertEqual(0o600, (package / name).stat().st_mode & 0o777)
                for name, data in payload.items():
                    (package / name).write_bytes(data)
                final = ['finalize', *args[1:]]
                # Incomplete, unknown and corrupt inputs preserve partial evidence.
                (package / 'job.env').unlink()
                with self.assertRaises((FileNotFoundError, ValueError)):
                    h.main(final)
                (package / 'job.env').write_bytes(payload['job.env'])
                (package / 'foreign').write_bytes(b'retain')
                with self.assertRaises(ValueError):
                    h.main(final)
                self.assertEqual(b'retain', (package / 'foreign').read_bytes())
                (package / 'foreign').rename(root / 'saved-foreign')
                (package / 'guest/lib.sh').write_bytes(b'corrupt\n')
                with self.assertRaises(ValueError):
                    h.main(final)
                (package / 'guest/lib.sh').write_bytes(payload['guest/lib.sh'])
                (root / GUEST).mkdir()
                with self.assertRaises(ValueError):
                    h.main(final)
                self.assertTrue(package.exists())
                (root / GUEST).rmdir()
                h.main(final)
                receipt = json.loads((attempt / 'ready.json').read_bytes())
                self.assertEqual('ready', receipt['state'])
                self.assertFalse(package.exists())
                self.assertEqual(payload, {name: (root / GUEST / name).read_bytes() for name in h.FILES})
                with self.assertRaises(ValueError):
                    h.main(final)
                with self.assertRaises(ValueError):
                    h.main(args)
                self.assertTrue((attempt / 'ready.json').exists())

    def test_identifiers_are_checked_before_system_operations(self):
        args = ['create', 'host', GUEST, '12345678-1234-4234-8234-123456789abd',
                '12345678-1234-4234-8234-123456789abc', ATTEMPT, 'a' * 64]
        with patch.object(self.helper.os, 'geteuid', return_value=0, create=True):
            for index in range(7):
                bad = args.copy()
                bad[index] = '../escape'
                with self.assertRaises(ValueError):
                    self.helper.main(bad)


if __name__ == '__main__':
    unittest.main()
