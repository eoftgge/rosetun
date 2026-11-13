"""Synthetic legacy reports, inert ELF headers and fake QGA only."""

import base64
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.vm.matrix import lifecycle, linux_l2 as l2
from tools.vm.matrix.jobs import JobError, SmokeJob
from tools.vm.matrix.qga import QgaError
from tools.vm.matrix.report import assess, assess_files
from tools.vm.matrix.tests import test_jobs
from tools.vm.matrix.tests.test_jobs import GUEST
from tools.vm.matrix.tests.test_matrix import synthetic_inputs, summarize
from tools.vm.matrix.tests.test_qga import BOOT, read

CHECKOUT = Path(__file__).resolve().parents[4]
SOURCE = dict(source_sha='a' * 40, source_dirty=False, source_dirty_digest='b' * 64)


def package(root, vm_uuid, stand='synthetic-l2'):
    for name in l2.SOURCES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((CHECKOUT / 'tools/vm/linux' / name).read_bytes().replace(b'\r\n', b'\n').rstrip(b'\n') + b'\n')
    (root / 'artifacts').mkdir()
    elf = b'\x7fELF\x02\x01' + b'\0' * 10 + b'\x02\0\x3e\0' + b'inert fixture; never execute'
    for name in l2.BINARIES:
        (root / 'artifacts' / name).write_bytes(elf)
    provenance = dict(schema=1, stage='l2', target='x86_64-unknown-linux-gnu', **SOURCE,
                      artifacts={n: dict(sha256=hashlib.sha256(elf).hexdigest()) for n in l2.BINARIES})
    (root / 'artifacts/provenance.json').write_text(json.dumps(provenance), encoding='ascii')
    env = dict(RUN_ID=GUEST, STAND_ID=stand, EXPECTED_BOOT_ID=BOOT,
               BIOS_GUID=vm_uuid, USER_A='l2a', USER_B='l2b', SCENARIO_TIMEOUT_SECONDS='30',
               UNIT_TIMEOUT_SECONDS='180', JOB_TIMEOUT_SECONDS='900')
    (root / 'job.env').write_bytes(''.join(f'{k}={v}\n' for k, v in env.items()).encode())
    manifest(root)


def manifest(root):
    (root / 'manifest.sha256').write_bytes(''.join(
        hashlib.sha256((root / n).read_bytes()).hexdigest() + '  ' + n + '\n'
        for n in l2.PAYLOAD).encode())


class PackageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        package(self.root, BOOT)
        self.source = patch.object(l2, 'source_identity', return_value=SOURCE)
        self.source.start()
        self.addCleanup(self.source.stop)

    def validate(self):
        return l2.validate_package(self.root, checkout=CHECKOUT)

    def test_exact_package_catalog_and_streamed_hashing(self):
        with patch.object(Path, 'read_bytes', autospec=True, side_effect=Path.read_bytes) as reader:
            value = self.validate()
        self.assertEqual((34, 33), (len(value['catalog']), sum(r['required'] for r in value['catalog'])))
        self.assertIn('not cryptographic', value['origin'])
        self.assertFalse(any(call.args[0].name in l2.BINARIES for call in reader.call_args_list))

    def test_modified_binary_manifest_provenance_catalog_and_elf_rejected(self):
        path = self.root / 'artifacts' / l2.BINARIES[0]
        original = path.read_bytes()
        path.write_bytes(original + b'changed')
        with self.assertRaises(ValueError):
            self.validate()
        manifest(self.root)
        with self.assertRaises(ValueError):
            self.validate()
        path.write_bytes(original)
        for key, value in (('target', 'aarch64'), ('source_sha', 'c' * 40),
                           ('source_dirty', True), ('source_dirty_digest', 'd' * 64)):
            p = self.root / 'artifacts/provenance.json'
            saved = p.read_bytes()
            data = json.loads(saved)
            data[key] = value
            p.write_text(json.dumps(data), encoding='ascii')
            manifest(self.root)
            with self.assertRaises(ValueError):
                self.validate()
            p.write_bytes(saved)
        path.write_bytes(b'MZ' + original[2:])
        p = self.root / 'artifacts/provenance.json'
        data = json.loads(p.read_bytes())
        data['artifacts'][path.name]['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        p.write_text(json.dumps(data), encoding='ascii')
        manifest(self.root)
        with self.assertRaisesRegex(ValueError, 'elf'):
            self.validate()
        catalog = self.root / 'scenarios.tsv'
        catalog.write_bytes(catalog.read_bytes().replace(b'preflight.identity', b'changed.identity'))
        manifest(self.root)
        with self.assertRaisesRegex(ValueError, 'catalog'):
            self.validate()

    def test_extra_empty_directory_bad_paths_duplicate_manifest_and_limits(self):
        extra = self.root / 'extra'
        extra.mkdir()
        with self.assertRaises(ValueError):
            self.validate()
        extra.rmdir()
        p = self.root / 'manifest.sha256'
        saved = p.read_bytes()
        for raw in (saved + saved, saved.replace(b'guest/lib.sh', b'../lib.sh')):
            p.write_bytes(raw)
            with self.assertRaises(ValueError):
                self.validate()
        p.write_bytes(saved)
        with self.assertRaises(ValueError):
            l2._hash(self.root / 'artifacts' / l2.BINARIES[0], 1)

    def test_source_digest_uses_legacy_status_separator_and_diff(self):
        self.source.stop()
        status, diff = b' M file\n', b'diff --git a/file b/file\n'
        with patch.object(l2.subprocess, 'run', side_effect=[
                SimpleNamespace(stdout=b'a' * 40 + b'\n'), SimpleNamespace(stdout=status),
                SimpleNamespace(stdout=diff)]) as git:
            source = l2.source_identity(CHECKOUT)
        self.assertEqual('safe.directory=' + CHECKOUT.as_posix(), git.call_args_list[0].args[0][2])
        self.assertEqual(hashlib.sha256(status + b'\n--\n' + diff).hexdigest(), source['source_dirty_digest'])
        self.assertTrue(source['source_dirty'])


class ExecutionTests(unittest.TestCase):
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
        with patch.object(l2, 'source_identity', return_value=SOURCE):
            self.job = l2.LinuxL2Job(self.vm, enabled=True, package_directory=self.root, checkout=CHECKOUT)
        _, self.report, self.status = synthetic_inputs()
        self.report['run_id'] = GUEST
        self.report['guest'] = dict(boot_id=BOOT, boot_id_at_end=BOOT)
        self.status.update(run_id=GUEST, boot_id=BOOT)
        self.files = {}
        self.publish()
        self.peer(self.agent)

    def publish(self):
        self.files.update({'report.json': json.dumps(self.report).encode(),
                           'status.json': json.dumps(self.status).encode()})

    def peer(self, agent):
        self.offset, self.current = 0, b''
        self.block_size = l2.BLOCK
        def opened():
            path = agent.client.commands[-1][1]['path']
            self.current = ((BOOT + '\n').encode() if path == '/proc/sys/kernel/random/boot_id'
                            else self.files[path.rsplit('/', 1)[1]])
            self.offset = 0
            return 7
        def reading():
            count = min(agent.client.commands[-1][1]['count'], self.block_size)
            block = self.current[self.offset:self.offset + count]
            self.offset += len(block)
            return read(block, eof=self.offset == len(self.current))
        agent.client.responses.update({'guest-file-open': opened, 'guest-file-read': reading})

    def test_identity_plan_fixed_launcher_one_attempt_and_legacy_assessment(self):
        self.assertNotEqual(self.job.identity['host_run_id'], GUEST)
        self.assertEqual(self.job.plan['policy'], dict(mode='exploratory', run_id=GUEST, boot_id=BOOT))
        self.assertEqual(self.vm.run._identity[1], self.job.identity['stand_id'])
        self.job.plan['policy']['run_id'] = 'mutated-copy'
        self.job.submit()
        args = [a for n, a in self.agent.client.commands if n == 'guest-exec']
        self.assertEqual([dict(path=l2.LAUNCHER, arg=[GUEST, '/root/rosetun-l2-stage/' + GUEST,
            self.job.identity['manifest_sha256']], **{'capture-output': False})], args)
        self.block_size = 2048
        result = self.job.collect()
        self.assertEqual(assess(self.report, self.status, self.job.plan), result['assessment'])
        self.assertTrue(result['assessment']['acceptance']['accepted'])
        self.assertFalse(result['release_gate'])
        self.assertFalse(any(n == 'guest-file-open' and a['path'].endswith('/helper-journal.txt')
                             for n, a in self.agent.client.commands))
        self.assertEqual(self.files['report.json'], (self.vm.run.directory / 'linux-l2/1/report.json').read_bytes())
        saved = assess_files(self.vm.run.directory / 'linux-l2/1/report.json', self.vm.run.directory / 'linux-l2/plan.json')
        saved.pop('sources')
        self.assertEqual(result['assessment'], saved)
        for action in (self.job.submit, lambda: SmokeJob(self.vm, enabled=True, guest_run_id=GUEST, manifest_sha256='a' * 64)):
            with self.assertRaises(JobError):
                action()

    def test_unknown_exec_recovery_keeps_deadline_and_never_resubmits(self):
        self.agent.client.responses['guest-exec'] = TimeoutError()
        with self.assertRaises(QgaError):
            self.job.submit()
        self.assertEqual('unknown', self.job.submission)
        deadline = self.job.deadline
        agent = self.fixture.agent_new()
        self.peer(agent)
        with patch.object(lifecycle, 'Qga', return_value=agent):
            self.vm.recover_guest()
        self.assertEqual(deadline, self.job.deadline)
        self.assertTrue(self.job.collect()['assessment']['acceptance']['accepted'])
        self.assertFalse(any(n == 'guest-exec' for n, _ in agent.client.commands))
        with self.assertRaises(JobError):
            self.job.submit()

    def test_report_published_before_finished_and_changed_status_do_not_accept(self):
        self.job.submit()
        self.status['state'] = 'running'
        self.publish()
        with self.assertRaises(JobError):
            self.job.collect()
        self.assertIsNone(self.job.assessment)
        self.assertFalse(any(n == 'guest-file-open' and a['path'].endswith('/report.json')
                             for n, a in self.agent.client.commands))
        self.status['state'] = 'finished'
        self.publish()
        original = self.agent.client.responses['guest-file-open']
        def changing():
            result = original()
            if self.agent.client.commands[-1][1]['path'].endswith('/report.json'):
                self.files['status.json'] += b' '
            return result
        self.agent.client.responses['guest-file-open'] = changing
        with self.assertRaises(JobError):
            self.job.collect()

    def test_missing_duplicate_fail_error_required_skip_cleanup_and_summary(self):
        self.job.submit()
        original = copy.deepcopy(self.report)
        mutations = [lambda r: r['scenarios'].pop(0),
                     lambda r: r['scenarios'].append(copy.deepcopy(r['scenarios'][0])),
                     *[lambda r, s=s: r['scenarios'][0].update(result=s) for s in ('FAIL', 'ERROR', 'SKIP')],
                     lambda r: r['cleanup'].update(status='FAIL'),
                     lambda r: r.update(run_id='foreign'),
                     lambda r: r['guest'].update(boot_id_at_end='foreign')]
        for mutation in mutations:
            self.report = copy.deepcopy(original)
            mutation(self.report)
            summarize(self.report)
            self.publish()
            # Each result gets a fresh facade budget for this isolated validation test.
            self.job.polls = self.job.calls = self.agent.calls = 0
            result = self.job.collect()
            self.assertFalse(result['assessment']['acceptance']['accepted'])
            self.assertEqual(assess(self.report, self.status, self.job.plan), result['assessment'])
        self.report = original
        self.report['summary']['pass'] = 999
        self.publish()
        self.job.polls = self.job.calls = self.agent.calls = 0
        self.assertFalse(self.job.collect()['assessment']['acceptance']['accepted'])
        self.vm.hard_off()
        self.assertTrue(self.vm.completed)
        self.assertFalse(self.job.snapshot()['assessment']['acceptance']['accepted'])

    def test_corrupt_data_read_limit_and_partial_evidence(self):
        self.job.submit()
        for raw in (b'[]', b'{', b'{"schema":1,"schema":2}', b'x' * (l2.REPORT_LIMIT + 1)):
            self.files['report.json'] = raw
            self.job.calls = self.job.polls = self.agent.calls = 0
            with self.assertRaises(JobError):
                self.job.collect()
            retained = (self.vm.run.directory / 'linux-l2/1/report.json').read_bytes()
            self.assertEqual(raw[:l2.REPORT_LIMIT + 1], retained)
            self.assertIn('closed', self.job.handles.values())

    def test_bad_base64_counts_eof_lost_open_and_finite_budgets(self):
        self.job.submit()
        # Bypass only boot observation so malformed responses reach the L2 reader.
        with patch.object(self.job, '_fresh_boot'):
            for value in (read(b'x', count=True), read(b'x', eof=1), read(b'x', **{'buf-b64': '!'}),
                          read(b'x', count=0), read(b'', eof=False)):
                self.agent.client.responses['guest-file-read'] = value
                with self.assertRaises(JobError):
                    self.job.collect()
                self.job.polls = self.job.calls = self.agent.calls = 0
            self.agent.client.responses['guest-file-open'] = TimeoutError()
            before = len(self.agent.client.commands)
            with self.assertRaises(JobError):
                self.job.collect()
            self.assertEqual(1, sum(n == 'guest-file-open' for n, _ in self.agent.client.commands[before:]))
            self.assertIn('unconfirmed', self.job.handles.values())
        self.job.polls = l2.POLLS
        with self.assertRaises(JobError):
            self.job.collect()
        self.job.polls = 0
        self.job.deadline = 0
        with self.assertRaises(JobError):
            self.job.collect()

    def test_fresh_foreign_boot_prevents_submit_and_later_collection(self):
        with patch.object(self.agent, 'read_boot_id', return_value='22222222-2222-2222-2222-222222222222'):
            with self.assertRaises(JobError):
                self.job.submit()
        self.assertFalse(any(n == 'guest-exec' for n, _ in self.agent.client.commands))
        self.job.submit()
        self.vm.last_boot_id = 'foreign'
        with self.assertRaises(JobError):
            self.job.collect()

    def test_package_is_bound_to_vm_and_observed_boot_before_job_creation(self):
        del self.vm._linux_l2_job
        for key in ('BIOS_GUID', 'EXPECTED_BOOT_ID', 'STAND_ID'):
            path = self.root / 'job.env'
            saved = path.read_bytes()
            lines = saved.decode().splitlines()
            lines = [key + '=22222222-2222-2222-2222-222222222222'
                     if line.startswith(key + '=') else line for line in lines]
            path.write_bytes(('\n'.join(lines) + '\n').encode())
            manifest(self.root)
            with patch.object(l2, 'source_identity', return_value=SOURCE), self.assertRaisesRegex(JobError, 'mismatch'):
                l2.LinuxL2Job(self.vm, enabled=True, package_directory=self.root, checkout=CHECKOUT)
            path.write_bytes(saved)
        self.assertFalse(any(n == 'guest-exec' for n, _ in self.agent.client.commands))

    def test_lost_read_retains_prefix_and_handle_uncertainty_then_recovers(self):
        self.job.submit()
        self.report['padding'] = 'x' * 40000
        self.publish()
        original = self.agent.client.responses['guest-file-read']
        def lost():
            if self.current == self.files['report.json'] and self.offset:
                raise TimeoutError()
            return original()
        self.agent.client.responses['guest-file-read'] = lost
        with self.assertRaises(JobError):
            self.job.collect()
        self.assertEqual(self.files['report.json'][:l2.BLOCK],
                         (self.vm.run.directory / 'linux-l2/1/report.json').read_bytes())
        self.assertIn('close-unconfirmed', self.job.handles.values())
        replacement = self.fixture.agent_new()
        self.peer(replacement)
        with patch.object(lifecycle, 'Qga', return_value=replacement):
            self.vm.recover_guest()
        self.assertTrue(self.job.collect()['accepted'])
        self.assertFalse(any(n == 'guest-exec' for n, _ in replacement.client.commands))

    def test_known_launcher_failure_is_separate_from_report_acceptance(self):
        self.job.submit()
        self.agent.client.responses['guest-exec-status'] = dict(exited=True, exitcode=1)
        result = self.job.collect()
        self.assertTrue(result['assessment']['acceptance']['accepted'])
        self.assertFalse(result['accepted'])
        self.assertEqual('exited-error', result['launcher'])
        replacement = self.fixture.agent_new()
        self.peer(replacement)
        with patch.object(lifecycle, 'Qga', return_value=replacement):
            self.vm.recover_guest()
        result = self.job.collect()
        self.assertFalse(result['accepted'])
        self.assertEqual('exited-error', result['launcher'])


if __name__ == '__main__':
    unittest.main()
