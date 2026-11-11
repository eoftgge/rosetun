"""The shared evidence writer: bytes, limits, registration and durability."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.vm.matrix import evidence
from tools.vm.matrix.resources import StandLease, create_run
from tools.vm.matrix import lifecycle, qemu
from tools.vm.matrix.jobs import JobError
from tools.vm.matrix.qemu import CommandResult
from tools.vm.matrix.tests import (test_jobs, test_l2_media, test_lifecycle, test_linux_l2,
                                   test_qemu, test_staging)


def old_row(value):
    """The formula every journal used before the shared writer existed."""
    return (json.dumps(value, sort_keys=True) + '\n').encode()


def fixture_of(case, fixture):
    fixture.setUp()
    case.addCleanup(fixture.doCleanups)
    return fixture


class JournalBytesTests(unittest.TestCase):
    """Each journal keeps the bytes its module wrote before the shared writer."""

    def assert_old_formula(self, path, *, last=()):
        raw = path.read_bytes()
        rows = [json.loads(line) for line in raw.splitlines()]
        self.assertGreaterEqual(len(rows), 2)
        self.assertEqual(b''.join(old_row(row) for row in rows), raw)
        if last:
            self.assertEqual(list(last), rows[-len(last):])
        return rows

    def test_lifecycle_and_job_journals(self):
        fixture = fixture_of(self, test_jobs.JobsTests())
        vm, directory = fixture.vm, fixture.vm.run.directory
        vm._event('probe', 'one')
        vm._event('probe', 'two')
        rows = self.assert_old_formula(directory / 'lifecycle.jsonl')
        self.assertEqual([('probe', 'one'), ('probe', 'two')],
                         [(r['action'], r['result']) for r in rows[-2:]])
        first, second = {'b': 1, 'a': 'é'}, {'z': [1, 2], 'a': None}
        vm._guest_row(first)
        vm._guest_row(second)
        self.assert_old_formula(directory / 'qga-observations.jsonl', last=(first, second))
        fixture.job._evidence('first', extra=1)
        fixture.job._evidence('second', extra=2)
        rows = self.assert_old_formula(directory / 'job-evidence.jsonl')
        self.assertEqual(['first', 'second'], [r['operation'] for r in rows[-2:]])

    def test_staging_journal(self):
        fixture = fixture_of(self, test_staging.StagingTests())
        package = fixture.build(delay_seconds=1)
        package._evidence('first')
        package._evidence('second')
        path = fixture.vm.run.directory / 'smoke-package' / 'staging.jsonl'
        self.assert_old_formula(path)
        self.assertTrue(path.read_bytes().isascii())

    def test_import_journal(self):
        fixture = fixture_of(self, test_l2_media.ImportTests())
        fixture.obj._evidence('first')
        fixture.obj._evidence('second')
        self.assert_old_formula(fixture.vm.run.directory / 'l2-import.jsonl')

    def test_preparation_journal(self):
        fixture = fixture_of(self, test_qemu.PreparationTests())
        fixture.prepare()
        self.assert_old_formula(fixture.run.directory / 'preparation.jsonl')

    def test_media_journal(self):
        fixture = fixture_of(self, test_l2_media.MediaTests())
        fixture.build()
        self.assert_old_formula(fixture.run.directory / 'l2-media.jsonl')


class OwnerTokenTests(unittest.TestCase):
    """No journal or evidence file takes a row that carries the run's owner token."""

    def assert_absent(self, directory, token):
        for path in directory.rglob('*'):
            if path.is_file() and path.name != 'manifest.json':
                self.assertNotIn(token.encode(), path.read_bytes(), path.name)

    def test_lifecycle_and_guest_observation_journals(self):
        fixture = fixture_of(self, test_jobs.JobsTests())
        vm = fixture.vm
        token = vm.run._identity[2]
        before = (vm.run.directory / 'lifecycle.jsonl').read_bytes()
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'lifecycle-evidence-write-failed'):
            vm._event('probe', token)
        self.assertTrue(vm.evidence_failed)
        self.assertEqual(before, (vm.run.directory / 'lifecycle.jsonl').read_bytes())
        vm.evidence_failed = False
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'qga-evidence-write-failed'):
            vm._guest_row({'leak': token})
        self.assertTrue(vm.evidence_failed)
        vm.evidence_failed = False
        with self.assertRaisesRegex(JobError, 'job-evidence-write-failed'):
            fixture.job._evidence('leak', leak=token)
        self.assertTrue(vm.evidence_failed)
        self.assert_absent(vm.run.directory, token)

    def test_staging_journal(self):
        fixture = fixture_of(self, test_staging.StagingTests())
        package = fixture.build(delay_seconds=1)
        token = fixture.vm.run._identity[2]
        with self.assertRaisesRegex(JobError, 'staging-evidence-failed'):
            package._evidence('leak', leak=token)
        self.assertTrue(fixture.vm.evidence_failed)
        self.assert_absent(fixture.vm.run.directory, token)

    def test_import_journal(self):
        fixture = fixture_of(self, test_l2_media.ImportTests())
        token = fixture.vm.run._identity[2]
        with self.assertRaisesRegex(ValueError, 'owner-token-in-evidence'):
            fixture.obj._evidence('leak', leak=token)
        self.assertEqual('unknown', fixture.obj.state)
        self.assertTrue(fixture.vm.evidence_failed)
        self.assert_absent(fixture.vm.run.directory, token)

    def test_linux_l2_evidence_files(self):
        fixture = fixture_of(self, test_linux_l2.ExecutionTests())
        token = fixture.vm.run._identity[2]
        with self.assertRaisesRegex(JobError, 'l2-evidence-write-failed'):
            fixture.job._save('plan.json', token.encode())
        self.assertTrue(fixture.vm.evidence_failed)
        self.assert_absent(fixture.vm.run.directory, token)

    def test_preparation_journal(self):
        fixture = fixture_of(self, test_qemu.PreparationTests())
        token = fixture.run._identity[2]
        leaking = fixture.root / (token + '.qcow2')
        leaking.write_bytes(fixture.original)
        image = fixture.image.__class__(**{**fixture.image.record(), 'path': str(leaking)})
        # The input check would stop this run first; bypass it to reach the journal.
        with patch.object(qemu, 'asdict', return_value={}), \
                patch.object(type(image), 'record', return_value={}), \
                self.assertRaises(ValueError):
            fixture.prepare(image=image)
        self.assert_absent(fixture.run.directory, token)
        self.assertEqual(['preparation-failed'], fixture.run._read()['reasons'])

    def test_media_journal(self):
        fixture = fixture_of(self, test_l2_media.MediaTests())
        token = fixture.run._identity[2]
        def leaking(argv, **limits):
            return CommandResult(0, b'xorriso 1.5.6\n' + token.encode())
        with self.assertRaises(ValueError):
            fixture.build(leaking)
        self.assertEqual('quarantined', fixture.run._read()['state'])
        self.assert_absent(fixture.run.directory, token)

    def test_completion_proof(self):
        fixture = fixture_of(self, test_lifecycle.LifecycleTests())
        vm = fixture.start()
        run = vm.run
        self.addCleanup(vm.stderr.file.close)
        self.addCleanup(run._lease._active.discard, vm)
        run.mark('exited')
        exits = [dict(resource=r, returncode=0) for r in run._read()['resources']
                 if r['kind'] == 'process']
        with self.assertRaisesRegex(ValueError, 'owner-token-in-evidence'):
            run._complete(exits, run._identity[2])
        self.assertFalse((run.directory / 'completion.json').exists())


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.lease = StandLease(Path(self.temp.name) / 'state', 'stand-a').acquire()
        self.addCleanup(self.lease.release)
        self.run = create_run(self.lease, 'run-a')
        self.token = self.run._identity[2]
        for name in ('journal.jsonl', 'nested/journal.jsonl', 'file.json'):
            self.run.register(dict(id=name.replace('/', '-').split('.')[0], kind='file', path=name))
        (self.run.directory / 'nested').mkdir()
        for name in ('journal.jsonl', 'nested/journal.jsonl', 'file.json'):
            (self.run.directory / name).touch()

    def read(self, name):
        return (self.run.directory / name).read_bytes()

    def test_rows_are_the_bytes_of_the_old_formula(self):
        rows = [{'b': 1, 'a': 'é'}, {'z': [1, 2], 'a': None}]
        for row in rows:
            evidence.append_row(self.run, 'journal.jsonl', row)
        self.assertEqual(b''.join(old_row(r) for r in rows), self.read('journal.jsonl'))
        self.assertEqual(old_row(rows[0]), evidence.encode_row(rows[0]))
        self.assertTrue(self.read('journal.jsonl').isascii())

    def test_the_owner_token_is_refused_before_anything_is_written(self):
        with self.assertRaisesRegex(ValueError, 'owner-token-in-evidence'):
            evidence.append_row(self.run, 'journal.jsonl', {'x': 'a' + self.token}, forbid=self.token)
        with self.assertRaisesRegex(ValueError, 'owner-token-in-evidence'):
            evidence.write_file(self.run, 'file.json', self.token.encode(), mode='overwrite',
                                forbid=self.token)
        self.assertEqual(b'', self.read('journal.jsonl'))
        self.assertEqual(b'', self.read('file.json'))
        evidence.append_row(self.run, 'journal.jsonl', {'x': self.token})
        self.assertIn(self.token.encode(), self.read('journal.jsonl'))

    def test_the_limit_after_the_write_counts_the_new_row(self):
        row = {'a': 1}
        size = len(old_row(row))
        evidence.append_row(self.run, 'journal.jsonl', row, max_bytes=2 * size)
        evidence.append_row(self.run, 'journal.jsonl', row, max_bytes=2 * size)
        with self.assertRaisesRegex(ValueError, 'evidence-size-limit'):
            evidence.append_row(self.run, 'journal.jsonl', row, max_bytes=2 * size)
        self.assertEqual(2 * size, len(self.read('journal.jsonl')))

    def test_the_limit_before_the_write_counts_only_the_current_size(self):
        row = {'a': 1}
        size = len(old_row(row))
        for _ in range(3):
            evidence.append_row(self.run, 'journal.jsonl', row, max_bytes=2 * size,
                                limit_check='before')
        with self.assertRaisesRegex(ValueError, 'evidence-size-limit'):
            evidence.append_row(self.run, 'journal.jsonl', row, max_bytes=2 * size,
                                limit_check='before')
        self.assertEqual(3 * size, len(self.read('journal.jsonl')))

    def test_a_missing_journal_is_created_when_the_limit_is_checked_before(self):
        evidence.append_row(self.run, 'fresh.jsonl', {'a': 1}, max_bytes=10, limit_check='before')
        self.assertEqual(old_row({'a': 1}), self.read('fresh.jsonl'))

    def test_an_unregistered_path_is_refused_when_registration_is_required(self):
        with self.assertRaisesRegex(ValueError, 'evidence-not-registered'):
            evidence.append_row(self.run, 'other.jsonl', {'a': 1}, require_registered=True)
        with self.assertRaisesRegex(ValueError, 'evidence-not-registered'):
            evidence.write_file(self.run, 'other.json', b'x', mode='create', require_registered=True)
        self.assertFalse((self.run.directory / 'other.jsonl').exists())
        self.assertFalse((self.run.directory / 'other.json').exists())

    def test_create_refuses_an_existing_file(self):
        evidence.append_row(self.run, 'first.jsonl', {'a': 1}, create=True)
        with self.assertRaises(FileExistsError):
            evidence.append_row(self.run, 'first.jsonl', {'a': 2}, create=True)
        self.assertEqual(old_row({'a': 1}), self.read('first.jsonl'))
        with self.assertRaises(FileExistsError):
            evidence.write_file(self.run, 'first.jsonl', b'x', mode='create')

    def test_a_regular_file_is_required_only_when_asked(self):
        with self.assertRaises(OSError):
            evidence.append_row(self.run, 'nope.jsonl', {'a': 1}, require_regular=True)
        self.assertFalse((self.run.directory / 'nope.jsonl').exists())

    def test_overwrite_replaces_and_readback_detects_a_changed_file(self):
        evidence.write_file(self.run, 'file.json', b'old content', mode='overwrite')
        evidence.write_file(self.run, 'file.json', b'new', mode='overwrite', readback=True)
        self.assertEqual(b'new', self.read('file.json'))
        real = Path.read_bytes
        with patch.object(Path, 'read_bytes', lambda path: real(path) + (b'!' if path.name == 'file.json' else b'')):
            with self.assertRaises(evidence.ReadbackError):
                evidence.write_file(self.run, 'file.json', b'x', mode='overwrite', readback=True)

    def test_replace_requires_a_temporary_name_and_only_then(self):
        with self.assertRaises(ValueError):
            evidence.write_file(self.run, 'file.json', b'x', mode='replace')
        with self.assertRaises(ValueError):
            evidence.write_file(self.run, 'file.json', b'x', mode='overwrite', temporary='t.tmp')

    def test_replace_swaps_the_content_through_the_named_temporary_file(self):
        evidence.write_file(self.run, 'file.json', b'old', mode='replace', temporary='file.tmp')
        self.assertEqual(b'old', self.read('file.json'))
        self.assertFalse((self.run.directory / 'file.tmp').exists())

    def test_a_failed_replace_keeps_the_old_content_whole(self):
        evidence.write_file(self.run, 'file.json', b'old content', mode='overwrite')
        with patch.object(evidence.os, 'replace', side_effect=OSError('interrupted')):
            with self.assertRaises(OSError):
                evidence.write_file(self.run, 'file.json', b'new content', mode='replace',
                                    temporary='file.tmp')
        self.assertEqual(b'old content', self.read('file.json'))
        self.assertEqual(b'new content', self.read('file.tmp'))

    def test_the_directory_is_synced_where_it_is_promised(self):
        synced = []
        with patch.object(evidence, 'fsync_directory', side_effect=synced.append):
            evidence.append_row(self.run, 'journal.jsonl', {'a': 1})
            self.assertEqual([], synced)
            evidence.append_row(self.run, 'nested/journal.jsonl', {'a': 1}, sync_parent=True)
            self.assertEqual([self.run.directory / 'nested'], synced)
            evidence.write_file(self.run, 'file.json', b'x', mode='overwrite')
            self.assertEqual(1, len(synced))
            evidence.write_file(self.run, 'file.json', b'x', mode='overwrite', sync_parent=True)
            self.assertEqual(2, len(synced))
            evidence.write_file(self.run, 'file.json', b'x', mode='replace', temporary='file.tmp')
            self.assertEqual([self.run.directory], synced[2:])

    def test_fsync_directory_opens_and_syncs_a_directory_on_posix_only(self):
        with patch.object(evidence.os, 'name', 'posix'), \
                patch.object(evidence.os, 'open', create=True, return_value=7) as opened, \
                patch.object(evidence.os, 'fsync') as fsync, \
                patch.object(evidence.os, 'close') as close:
            evidence.fsync_directory(self.run.directory)
        opened.assert_called_once()
        fsync.assert_called_once_with(7)
        close.assert_called_once_with(7)
        with patch.object(evidence.os, 'name', 'nt'), patch.object(evidence.os, 'fsync') as fsync:
            evidence.fsync_directory(self.run.directory)
        fsync.assert_not_called()

    def test_every_row_and_file_is_synced_to_disk(self):
        with patch.object(evidence.os, 'fsync') as fsync:
            evidence.append_row(self.run, 'journal.jsonl', {'a': 1})
            evidence.write_file(self.run, 'file.json', b'x', mode='overwrite')
        self.assertEqual(2, fsync.call_count)


if __name__ == '__main__':
    unittest.main()
