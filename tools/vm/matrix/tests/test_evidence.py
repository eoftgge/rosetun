"""The shared evidence writer: bytes, limits, registration and durability."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.vm.matrix import evidence
from tools.vm.matrix.resources import StandLease, create_run


def old_row(value):
    """The formula every journal used before the shared writer existed."""
    return (json.dumps(value, sort_keys=True) + '\n').encode()


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
