"""The release evidence pack on synthetic runs: what it copies, what it refuses and that it builds the same bytes twice."""

import contextlib
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.vm.matrix import cli, orchestrator, release_evidence
from tools.vm.matrix.resources import SCHEMA as RESOURCES_SCHEMA, read_manifest
from tools.vm.matrix.tests import fake_controller
from tools.vm.matrix.tests.posix_only import controller_only

COMMIT = '15fa2ae1a66157206d16b098448e6574b4d8be4f'
OWNER = 'a1' * 32
PCAP = b'synthetic capture bytes'
IMAGE = {'architecture': 'x86_64', 'format': 'qcow2', 'guest_os': 'linux', 'identifier': 'test-image', 'path': '/img/t.qcow2',
         'profile': 'bios-i440fx-v1', 'schema': 'rosetun.matrix.image.v1', 'sha256': '1' * 64, 'size_bytes': 10}
LAB_IMAGE = dict(IMAGE, identifier='lab-image', sha256='2' * 64)
IDS = ('preflight.identity', 'alpha.one', 'alpha.two')
REPOSITORY = Path(__file__).resolve().parents[4]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def summary(*, suite='linux-l5', results=None, commit=COMMIT, dirty=False, exit_code=0, **changes):
    results = results or {name: 'PASS' for name in IDS}
    value = {
        'schema': 'rosetun.matrix.l5-summary.v1', 'suite': suite, 'mode': 'lab', 'exit_code': exit_code,
        'outcome': 'group-clean', 'release_gate': False, 'security_invariants': 'UNVERIFIED',
        'preflight': {'controller_source': {'source_sha': commit, 'source_dirty': dirty, 'source_dirty_digest': '3' * 64}},
        'configuration': {'image': IMAGE, 'lab': {'image': LAB_IMAGE}},
        'group': {'results': results, 'findings': [], 'unproven': [], 'passed': True},
        'legacy': {'scenarios': [{'id': name, 'result': result} for name, result in results.items()]},
        'crosscheck': [{'id': 'preflight.identity', 'agreement': 'NOT_APPLICABLE', 'window': None, 'window_verdict': None},
                       {'id': 'alpha.one', 'agreement': 'AGREE', 'window': 'w1', 'window_verdict': 'NONE'},
                       {'id': 'alpha.two', 'agreement': 'AGREE', 'window': 'w2', 'window_verdict': 'EXPECTED'}],
        'execution': {'assessment': {'rows': [{'id': name, 'required': True} for name in IDS]}},
        'lab': {'windows': [{}, {}], 'window_counts': [{'as_expected': True}, {'as_expected': True}],
                'qualification': {'evidence': {'pcap_bytes': len(PCAP), 'pcap_sha256': sha(PCAP)}}},
    }
    value.update(changes)
    return value


def journal(start):
    rows = [{'action': 'start', 'utc': '2026-11-18T12:%02d:00+00:00' % start},
            {'action': 'completion', 'utc': '2026-11-18T12:%02d:30+00:00' % start}]
    return ''.join(json.dumps(row) + '\n' for row in rows).encode()


class Stand(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.temp = Path(temp.name)
        self.state = self.temp / 'state'
        (self.state / 'runs').mkdir(parents=True)
        self.out = self.temp / 'pack'
        patcher = patch.object(release_evidence, 'completion_verified', return_value=True)
        self.verified = patcher.start()
        self.addCleanup(patcher.stop)
        self.counter = 0

    def run_directory(self, name, *, content=None, start=0, pcap=PCAP, extra=None):
        directory = self.state / 'runs' / name
        (directory / 'linux-l5' / '1').mkdir(parents=True)
        (directory / 'manifest.json').write_text(json.dumps({
            'schema': RESOURCES_SCHEMA, 'run_id': name, 'stand_id': 'stand', 'owner_token': OWNER, 'state': 'exited',
            'resources': [], 'reasons': []}))
        raw = json.dumps(content if content is not None else summary()).encode()
        files = {'execution-summary.json': raw, 'completion.json': b'{"schema": "completion"}',
                 'run-state.json': b'{"phase": "completed"}', 'lifecycle.jsonl': journal(start),
                 'linux-l5/1/report.json': b'{"report": 1}', 'linux-l5/1/helper-journal.txt': b'not evidence',
                 'execution-identity.json': b'{"claim": "kept out"}', 'l2-media.iso': b'not evidence', **(extra or {})}
        for relative, data in files.items():
            (directory / relative).write_bytes(data)
        if pcap is not None:
            (directory / 'capture.pcap').write_bytes(pcap)
        return directory

    def lab_run(self, base, *, content=None, start=0, **options):
        """A lab run as the stand has it: the same summary in the -lab and the -test directory."""
        content = content if content is not None else summary()
        self.run_directory(base + '-lab', content=content, start=start, **options)
        self.run_directory(base + '-test', content=content, start=start, pcap=None)
        return base

    def build(self, *tokens, out=None):
        return release_evidence.build_pack(self.state, list(tokens), out or self.out)

    def refused(self, *tokens, **options):
        with self.assertRaises(release_evidence.EvidenceRefused) as caught:
            self.build(*tokens, **options)
        self.assertFalse(os.path.lexists(self.out))
        self.assertFalse(os.path.lexists(str(self.out) + '.partial'))
        return caught.exception.reason

    def tree(self, root):
        return {path.relative_to(root).as_posix(): path.read_bytes() for path in sorted(Path(root).rglob('*'))
                if path.is_file()}

    def manifest(self):
        return json.loads((self.out / 'manifest.json').read_text())


class PackTests(Stand):
    def setUp(self):
        super().setUp()
        self.lab_run('aaa', start=1)
        self.lab_run('bbb', start=2, content=summary(results={'preflight.identity': 'PASS', 'alpha.one': 'PASS',
                                                                  'alpha.two': 'FAIL'}))

    def test_a_pack_holds_the_records_and_the_tables_and_no_capture(self):
        result = self.build('aaa', 'bbb')
        self.assertEqual((True, ['linux-l5']), (result['built'], result['sets']))
        names = set(self.tree(self.out))
        self.assertEqual({'manifest.json', 'parity-l5.tsv', 'parity-summary.json'}, {n for n in names if '/' not in n})
        for role in ('lab', 'test'):
            self.assertTrue({'completion.json', 'execution-summary.json', 'lifecycle.jsonl', 'run-state.json',
                             'linux-l5/1/report.json'} <= {n.split('/', 2)[2] for n in names if n.startswith('runs/aaa-%s/' % role)})
        self.assertFalse([n for n in names if n.endswith(('.pcap', '.iso'))])
        self.assertFalse([n for n in names if n.endswith('/manifest.json')])
        self.assertFalse([n for n in names if 'identity' in n or 'journal.txt' in n])
        self.assertFalse(os.path.lexists(str(self.out) + '.partial'))

    def test_the_manifest_states_what_the_pack_is_not_and_hashes_every_file(self):
        self.build('aaa', 'bbb')
        manifest = self.manifest()
        self.assertEqual(('rosetun.matrix.release-evidence.v1', False, 'UNVERIFIED', None),
                         (manifest['schema'], manifest['release_gate'], manifest['security_invariants'],
                          manifest['owner_signature']))
        tree = self.tree(self.out)
        listed = manifest['files']
        self.assertEqual(set(tree) - {'manifest.json'}, set(listed))
        for name, row in listed.items():
            self.assertEqual((len(tree[name]), sha(tree[name])), (row['bytes'], row['sha256']), name)
        first = manifest['runs'][0]
        self.assertEqual(('aaa', 'linux-l5', COMMIT, False, True, False, 0, 'group-clean', [], []),
                         (first['run'], first['suite'], first['commit'], first['source_dirty'], first['completion_verified'],
                          first['attached'], first['exit_code'], first['outcome'], first['findings'], first['unproven']))
        self.assertEqual({'lab': LAB_IMAGE['sha256'], 'test': IMAGE['sha256']},
                         {role: row['sha256'] for role, row in first['images'].items()})
        self.assertEqual({'bytes': len(PCAP), 'sha256': sha(PCAP), 'file_present': True, 'file_matches': True}, first['pcap'])
        self.assertEqual(['aaa-lab', 'aaa-test'], first['directories'])
        self.assertEqual(['aaa', 'bbb'], manifest['sets']['linux-l5']['runs'])

    def test_the_same_input_gives_the_same_bytes_in_any_order_and_at_any_time(self):
        self.build('aaa', 'bbb')
        second = self.temp / 'second'
        self.build('bbb', 'aaa', out=second)
        self.assertEqual(self.tree(self.out), self.tree(second))
        text = (self.out / 'manifest.json').read_text()
        self.assertNotIn('built', text)

    def test_a_run_may_be_named_by_its_directory_and_then_stands_alone(self):
        self.build('aaa-test')
        self.assertEqual(['aaa-test'], self.manifest()['runs'][0]['directories'])

    def test_the_table_is_the_8g_one_with_a_column_left_to_the_owner(self):
        self.build('aaa', 'bbb')
        raw = (self.out / 'parity-l5.tsv').read_text()
        self.assertNotIn('\r', raw)
        rows = list(csv.reader(raw.splitlines(), delimiter='\t'))
        self.assertEqual(['id', 'required', 'result1', 'result2', 'crosscheck1', 'crosscheck2', 'window', 'window_verdict1',
                          'window_verdict2', 'note', 'hyperv'], rows[0])
        self.assertEqual(['preflight.identity', 'yes', 'PASS', 'PASS', 'NOT_APPLICABLE', 'NOT_APPLICABLE', '-', '-', '-', '', ''],
                         rows[1])
        self.assertEqual(['alpha.two', 'yes', 'PASS', 'FAIL', 'AGREE', 'AGREE', 'w2', 'EXPECTED', 'EXPECTED',
                          'result differs between runs', ''], rows[3])
        self.assertEqual({''}, {row[-1] for row in rows[1:]})

    def test_the_summary_table_lists_the_runs_in_the_order_of_their_columns(self):
        self.build('bbb', 'aaa')
        runs = json.loads((self.out / 'parity-summary.json').read_text())['linux-l5']['runs']
        self.assertEqual([('aaa', 1), ('bbb', 2)], [(row['run_id'], row['run']) for row in runs])
        self.assertEqual(({'PASS': 3}, {'FAIL': 1, 'PASS': 2}), (runs[0]['group_counts'], runs[1]['group_counts']))
        self.assertEqual((2, True), (runs[0]['windows'], runs[0]['window_counts_all_as_expected']))
        self.assertEqual(['2026-11-18T12:01:00+00:00', '2026-11-18T12:01:30+00:00'],
                         [runs[0]['started_utc'], runs[0]['finished_utc']])

    def test_a_scenario_missing_from_a_run_stays_empty_and_is_noted_not_judged(self):
        self.lab_run('ccc', start=3, content=summary(results={'preflight.identity': 'PASS', 'alpha.one': 'PASS',
                                                                   'alpha.two': 'PASS', 'extra.id': 'SKIP'}))
        self.build('aaa', 'ccc')
        rows = {row[0]: row for row in csv.reader((self.out / 'parity-l5.tsv').read_text().splitlines(), delimiter='\t')}
        self.assertEqual(['extra.id', '-', '-', 'SKIP'], rows['extra.id'][:4])
        self.assertEqual('result differs between runs; not in the assessment rows', rows['extra.id'][-2])

    def test_each_suite_gets_its_own_table(self):
        self.lab_run('ddd', content=summary(suite='linux-l4'))
        self.build('aaa', 'ddd')
        self.assertEqual({'parity-l4.tsv', 'parity-l5.tsv'}, {n for n in self.tree(self.out) if n.startswith('parity-') and n.endswith('.tsv')})

    def test_the_state_is_left_as_it_was(self):
        before = self.tree(self.state)
        self.build('aaa', 'bbb')
        self.assertEqual(before, self.tree(self.state))


class RefusalTests(Stand):
    def test_a_dirty_source_is_refused(self):
        self.lab_run('aaa', content=summary(dirty=True))
        self.assertEqual('source-dirty', self.refused('aaa'))

    def test_a_source_without_its_record_is_refused(self):
        self.lab_run('aaa', content=summary(preflight={}))
        self.assertEqual('source-unknown', self.refused('aaa'))

    def test_a_diagnostic_run_is_refused(self):
        self.lab_run('aaa', content=summary(diagnostic=True))
        self.assertEqual('diagnostic-run', self.refused('aaa'))

    def test_an_attached_run_is_refused_and_so_is_a_run_that_does_not_say_it_was_not(self):
        self.lab_run('aaa', content=summary(attached=True, attachments=1))
        self.assertEqual('attached-run', self.refused('aaa'))
        self.run_directory('plain', content=summary(mode='exploratory'))
        self.assertEqual('attached-run', self.refused('plain'))
        self.run_directory('says', content=summary(mode='exploratory', attached=False, attachments=0))
        self.build('says')

    def test_a_run_whose_completion_is_not_verified_is_refused(self):
        self.lab_run('aaa')
        self.verified.return_value = False
        self.assertEqual('completion-not-verified', self.refused('aaa'))

    def test_runs_of_one_set_from_different_commits_are_refused(self):
        self.lab_run('aaa')
        self.lab_run('bbb', content=summary(commit='b' * 40))
        self.assertEqual('commits-differ-in-a-set', self.refused('aaa', 'bbb'))

    def test_different_commits_in_different_sets_are_not_a_conflict(self):
        self.lab_run('aaa')
        self.lab_run('bbb', content=summary(suite='linux-l4', commit='b' * 40))
        self.build('aaa', 'bbb')

    def test_a_missing_run_a_repeated_run_and_unreadable_names_are_refused(self):
        self.lab_run('aaa')
        self.assertEqual('run-not-found', self.refused('zzz'))
        self.assertEqual('duplicate-run', self.refused('aaa', 'aaa'))
        with self.assertRaises(ValueError):
            self.build('../aaa')

    def test_the_two_directories_of_a_lab_run_must_carry_the_same_summary(self):
        self.lab_run('aaa')
        (self.state / 'runs' / 'aaa-test' / 'execution-summary.json').write_text(json.dumps(summary(exit_code=1)))
        self.assertEqual('summaries-differ', self.refused('aaa'))

    def test_a_capture_that_is_not_the_one_the_summary_hashed_is_refused(self):
        self.lab_run('aaa')
        (self.state / 'runs' / 'aaa-lab' / 'capture.pcap').write_bytes(PCAP + b'x')
        self.assertEqual('pcap-does-not-match-its-record', self.refused('aaa'))

    def test_the_owner_token_or_a_private_key_in_a_file_stops_the_pack(self):
        self.lab_run('aaa', extra={'linux-l5/1/report.json': ('{"x": "%s"}' % OWNER).encode()})
        self.assertEqual('secret-in-evidence', self.refused('aaa'))
        self.lab_run('bbb', extra={'linux-l5/1/report.json': b'-----BEGIN OPENSSH PRIVATE KEY-----'})
        self.assertEqual('secret-in-evidence', self.refused('bbb'))

    def test_the_target_must_be_new_and_outside_the_state(self):
        self.lab_run('aaa')
        self.out.mkdir()
        with self.assertRaises(release_evidence.EvidenceRefused) as caught:
            self.build('aaa')
        self.assertEqual('out-exists', caught.exception.reason)
        self.assertEqual([], list(self.out.iterdir()))
        self.out.rmdir()
        self.assertEqual('out-parent-missing', self.refused('aaa', out=self.temp / 'no' / 'pack'))
        self.assertEqual('out-inside-state', self.refused('aaa', out=self.state / 'pack'))
        self.assertFalse((self.state / 'pack').exists())

    def test_no_run_is_an_error_of_use(self):
        with self.assertRaises(ValueError):
            self.build()


class CommandTests(Stand):
    def command(self, *arguments):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = cli.main(['evidence', '--state-directory', str(self.state), *arguments])
        return code, json.loads(stream.getvalue())

    def test_the_command_prints_the_result_and_exits_zero(self):
        self.lab_run('aaa')
        code, result = self.command('--run', 'aaa', '--out', str(self.out))
        self.assertEqual(0, code)
        self.assertEqual((True, False, 'UNVERIFIED', None), (result['built'], result['release_gate'],
                                                             result['security_invariants'], result['owner_signature']))
        self.assertEqual(sha((self.out / 'manifest.json').read_bytes()), result['manifest_sha256'])

    def test_a_refusal_exits_one_with_its_reason_and_builds_nothing(self):
        self.lab_run('aaa', content=summary(dirty=True))
        code, result = self.command('--run', 'aaa', '--out', str(self.out))
        self.assertEqual((1, False, 'source-dirty', 'aaa'), (code, result['built'], result['reason'], result['run']))
        self.assertFalse(self.out.exists())

    def test_unreadable_state_exits_two_without_details(self):
        (self.state / 'runs' / 'aaa').mkdir()
        code, result = self.command('--run', 'aaa', '--out', str(self.out))
        self.assertEqual((2, False), (code, result['built']))
        self.assertNotIn(str(self.state), json.dumps(result))


@unittest.skipUnless(sys.platform.startswith('linux') and hasattr(os, 'pidfd_open'), 'needs Linux /proc and pidfds')
@controller_only
class RealCompletionTests(unittest.TestCase):
    """A run closed by the real controller on the fake QEMU passes the real completion check."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.state = Path(temp.name) / 'state'
        self.out = Path(temp.name) / 'pack'
        for item in [*fake_controller.patches(), patch.object(orchestrator, '_current_commit', return_value=None),
                     patch.dict(os.environ, FAKE_QEMU_CONTROL=str(Path(temp.name) / 'fake.ctl'))]:
            item.start()
            self.addCleanup(item.stop)

    def closed_run(self):
        process = fake_controller.REAL_POPEN([sys.executable, '-B', '-m', 'tools.vm.matrix.tests.fake_controller',
                                              str(self.state), 'end'], cwd=REPOSITORY, stdout=subprocess.PIPE,
                                             stderr=subprocess.DEVNULL, start_new_session=True)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        self.addCleanup(process.wait)
        self.addCleanup(process.stdout.close)
        if not select.select([process.stdout], [], [], 60)[0]:
            self.fail('the controller did not close its run')
        word, run_id = process.stdout.readline().decode().split()
        self.assertEqual('CLOSED', word)
        return run_id

    def test_a_closed_run_gets_into_the_pack_and_an_open_one_does_not(self):
        run_id = self.closed_run()
        directory = self.state / 'runs' / run_id
        self.assertTrue((directory / 'run-state.json').is_file())
        (directory / 'execution-summary.json').write_text(json.dumps(summary(mode='exploratory', attached=False,
                                                                           attachments=0, lab=None)))
        result = release_evidence.build_pack(self.state, [run_id], self.out)
        self.assertTrue(result['built'])
        self.assertTrue(release_evidence.completion_verified(directory, read_manifest(directory)))
        journal_path = directory / 'lifecycle.jsonl'
        journal_path.write_bytes(journal_path.read_bytes() + b'{"tampered": true}\n')
        with self.assertRaises(release_evidence.EvidenceRefused) as caught:
            release_evidence.build_pack(self.state, [run_id], Path(self.out.parent) / 'second')
        self.assertEqual('completion-not-verified', caught.exception.reason)


if __name__ == '__main__':
    unittest.main()
