"""Stage 9c: the stand's record of a Windows disk's digest, kept between controller processes.

The disk is tens of gigabytes and a pass over it takes minutes, so a pass that matched the descriptor is recorded in
the state directory with the file's identity (device, inode, size, modification time and change time). The record is
trusted only while every part of the identity is the one it names; anything else is a full pass. The change time is
the part a file's owner cannot set, so a file replaced and given back its old modification time still differs.
"""

import json
import os
import unittest
from unittest.mock import patch

from tools.vm.matrix import images
from tools.vm.matrix.images import ImageDescriptor
from tools.vm.matrix.tests import test_windows_run as base
from tools.vm.matrix.tests import windows_fixture
from tools.vm.matrix.tests.posix_only import controller_only


class Cache(base.Base):
    def setUp(self):
        super().setUp()
        self.state = self.fixture.root / 'state'
        self.cache = self.state / images.DIGEST_CACHE
        self.disk = self.fixture.base

    def process(self):
        """What a new controller process has: the descriptor read afresh, and no memory of any pass."""
        patcher = patch.dict(images._HASHED, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        return windows_fixture.WindowsImageDescriptor(**self.fixture.record)

    def passes(self, image, operation=None):
        """How many full passes over the disk `operation` made."""
        with patch.object(ImageDescriptor, 'verify_bytes', autospec=True,
                          side_effect=ImageDescriptor.verify_bytes) as hashed:
            (operation or (lambda: image.validate(self.run_directory)))()
        return hashed.call_count

    def records(self):
        return sorted(self.cache.glob('*')) if self.cache.exists() else []

    def record(self):
        (path,) = self.records()
        return path, json.loads(path.read_text())


@controller_only
class RecordTests(Cache):
    def test_a_full_pass_leaves_one_record_in_the_state_directory_that_names_the_files_identity(self):
        self.assertEqual(1, self.passes(self.process()))
        path, record = self.record()
        info = self.disk.stat()
        self.assertEqual(dict(schema=images.DIGEST_CACHE_SCHEMA, path=str(self.disk), sha256=self.fixture.image.sha256,
                              device=info.st_dev, inode=info.st_ino, size=info.st_size, mtime_ns=info.st_mtime_ns,
                              ctime_ns=info.st_ctime_ns), record)
        self.assertEqual(0o700, self.cache.stat().st_mode & 0o777)
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
        # Nothing else is left beside it: no temporary file of the atomic write.
        self.assertEqual([path], self.records())

    def test_a_second_process_with_the_same_file_makes_no_pass(self):
        self.passes(self.process())
        image = self.process()
        self.assertEqual(0, self.passes(image))
        self.assertEqual(0, self.passes(image, lambda: image.verify_bytes(self.run_directory)))
        self.assertEqual(0, self.passes(self.process()))

    def test_the_check_after_a_run_follows_the_same_rule(self):
        image = self.process()
        self.passes(image)
        # The run read the disk and wrote nothing to it: its identity is the one the record names.
        self.assertEqual(0, self.passes(image, lambda: image.validate(self.run_directory)))

    def test_a_fresh_pass_is_made_when_asked_whatever_the_record_says(self):
        image = self.process()
        self.passes(image)
        self.assertEqual(1, self.passes(image, lambda: image.validate(self.run_directory, fresh=True)))

    def test_a_change_of_the_change_time_alone_makes_a_full_pass_that_a_restored_modification_time_does_not_hide(self):
        self.passes(self.process())
        info = self.disk.stat()
        changed = bytearray(self.disk.read_bytes())
        changed[0] ^= 1
        self.disk.write_bytes(bytes(changed))
        # The same size and the old modification time: only the change time tells.
        os.utime(self.disk, ns=(info.st_atime_ns, info.st_mtime_ns))
        after = self.disk.stat()
        self.assertEqual((info.st_size, info.st_mtime_ns), (after.st_size, after.st_mtime_ns))
        self.assertNotEqual(info.st_ctime_ns, after.st_ctime_ns)
        image = self.process()
        with self.assertRaisesRegex(ValueError, 'base image size or digest mismatch'):
            self.assertEqual(1, self.passes(image))
        # A pass that did not match the descriptor records nothing: the old record is not replaced by a bad one.
        self.assertEqual(info.st_ctime_ns, self.record()[1]['ctime_ns'])

    def test_a_file_with_the_same_bytes_and_another_identity_is_hashed_again_and_recorded_again(self):
        self.passes(self.process())
        original = self.disk.read_bytes()
        self.disk.write_bytes(original)
        image = self.process()
        self.assertEqual(1, self.passes(image))
        self.assertEqual(self.disk.stat().st_ctime_ns, self.record()[1]['ctime_ns'])
        self.assertEqual(0, self.passes(self.process()))

    def test_a_change_of_the_size_is_a_full_pass_and_a_refusal(self):
        self.passes(self.process())
        self.disk.write_bytes(self.disk.read_bytes() + b'x')
        with self.assertRaisesRegex(ValueError, 'size'):
            self.process().validate(self.run_directory)

    def test_a_replacement_of_the_file_by_another_inode_is_a_full_pass(self):
        self.passes(self.process())
        original = self.disk.read_bytes()
        replacement = self.disk.with_name('replacement')
        replacement.write_bytes(original)
        os.replace(replacement, self.disk)
        self.assertEqual(1, self.passes(self.process()))

    def test_a_descriptor_that_claims_another_digest_does_not_use_the_record_of_this_one(self):
        self.passes(self.process())
        record = dict(self.fixture.record, sha256='0' * 64)
        with self.assertRaises(ValueError):
            windows_fixture.WindowsImageDescriptor(**record).validate(self.run_directory)

    def test_two_files_have_two_records_and_a_copy_does_not_borrow_the_record_of_the_original(self):
        self.passes(self.process())
        copy = self.disk.with_name('copy.qcow2')
        copy.write_bytes(self.disk.read_bytes())
        record = dict(self.fixture.record, path=str(copy))
        image = windows_fixture.WindowsImageDescriptor(**record)
        self.assertEqual(1, self.passes(image))
        self.assertEqual(2, len(self.records()))

    def test_a_run_directory_outside_a_state_directory_keeps_the_memory_of_its_process_only(self):
        outside = self.fixture.root / 'elsewhere'
        outside.mkdir()
        image = self.process()
        self.assertEqual(1, self.passes(image, lambda: image.validate(outside)))
        self.assertEqual(0, self.passes(image, lambda: image.validate(outside)))
        self.assertEqual([], self.records())
        self.assertEqual(1, self.passes(self.process(), lambda: self.process().validate(outside)))


@controller_only
class BrokenRecordTests(Cache):
    def damage(self, change):
        self.passes(self.process())
        path, record = self.record()
        change(path, record)
        image = self.process()
        self.assertEqual(1, self.passes(image))
        # The pass wrote a good record over the bad one.
        self.assertEqual(0, self.passes(self.process()))

    def test_a_record_that_is_not_json_or_not_complete_or_not_ours_is_a_full_pass(self):
        def rewrite(value):
            return lambda path, record: path.write_text(value if isinstance(value, str) else json.dumps(value))
        for name, change in (('empty', rewrite('')), ('garbage', rewrite('}{ not json')),
                             ('array', rewrite([1, 2])), ('truncated', rewrite('{"schema": "rosetun')),
                             ('binary', lambda path, record: path.write_bytes(b'\xff\xfe\x00')),
                             ('schema', lambda path, record: rewrite(dict(record, schema='other'))(path, record)),
                             ('field missing', lambda path, record: rewrite({k: v for k, v in record.items()
                                                                           if k != 'inode'})(path, record)),
                             ('field added', lambda path, record: rewrite(dict(record, extra=1))(path, record)),
                             ('digest', lambda path, record: rewrite(dict(record, sha256='0' * 64))(path, record)),
                             ('path', lambda path, record: rewrite(dict(record, path='/other'))(path, record)),
                             ('size', lambda path, record: rewrite(dict(record, size=record['size'] + 1))(path, record)),
                             ('ctime', lambda path, record: rewrite(dict(record, ctime_ns=record['ctime_ns'] + 1))(
                                 path, record)),
                             ('mtime', lambda path, record: rewrite(dict(record, mtime_ns=record['mtime_ns'] + 1))(
                                 path, record)),
                             ('inode', lambda path, record: rewrite(dict(record, inode=record['inode'] + 1))(
                                 path, record)),
                             ('device', lambda path, record: rewrite(dict(record, device=record['device'] + 1))(
                                 path, record)),
                             ('string number', lambda path, record: rewrite(dict(record, size=str(record['size'])))(
                                 path, record)),
                             ('boolean number', lambda path, record: rewrite(dict(record, device=True))(path, record))):
            with self.subTest(name):
                self.damage(change)

    def test_a_record_that_is_larger_than_a_record_can_be_is_a_full_pass(self):
        self.damage(lambda path, record: path.write_text(json.dumps(record) + ' ' * images.DIGEST_CACHE_LIMIT))

    def test_a_record_that_is_a_link_or_a_directory_is_never_followed(self):
        self.passes(self.process())
        path, record = self.record()
        elsewhere = self.fixture.root / 'elsewhere.json'
        elsewhere.write_text(json.dumps(record))
        path.unlink()
        os.symlink(elsewhere, path)
        elsewhere.write_text('{}')
        self.assertEqual(1, self.passes(self.process()))
        # The new record replaces the link itself: what the link named is not written through.
        self.assertFalse(path.is_symlink())
        self.assertEqual('{}', elsewhere.read_text())
        self.assertEqual(0, self.passes(self.process()))

    def test_a_cache_directory_that_is_a_link_is_not_used_or_written(self):
        elsewhere = self.fixture.root / 'elsewhere'
        elsewhere.mkdir()
        self.state.mkdir(exist_ok=True)
        os.symlink(elsewhere, self.cache)
        self.assertEqual(1, self.passes(self.process()))
        self.assertEqual([], list(elsewhere.iterdir()))
        self.assertEqual(1, self.passes(self.process()))


@controller_only
class OwnershipTests(Cache):
    def test_a_record_that_others_can_read_or_write_is_no_record_and_is_replaced_with_the_right_mode(self):
        for mode in (0o644, 0o660, 0o604, 0o666):
            with self.subTest(mode=oct(mode)):
                self.passes(self.process())
                path, _ = self.record()
                path.chmod(mode)
                self.assertEqual(1, self.passes(self.process()))
                self.assertEqual(0o600, path.stat().st_mode & 0o777)
                self.assertEqual(0, self.passes(self.process()))

    def test_a_directory_wider_than_0700_is_no_cache_and_is_made_right_when_it_is_ours(self):
        self.passes(self.process())
        self.cache.chmod(0o755)
        self.assertEqual(1, self.passes(self.process()))
        self.assertEqual(0o700, self.cache.stat().st_mode & 0o777)
        self.assertEqual(0o600, self.record()[0].stat().st_mode & 0o777)
        self.assertEqual(0, self.passes(self.process()))
        self.cache.chmod(0o770)
        self.assertEqual(1, self.passes(self.process()))
        self.assertEqual(0o700, self.cache.stat().st_mode & 0o777)

    def test_a_record_or_a_directory_of_another_user_is_no_record_and_nothing_is_written_there(self):
        self.passes(self.process())
        before = self.record()
        other = os.geteuid() + 1
        with patch.object(images.os, 'geteuid', return_value=other):
            self.assertEqual(1, self.passes(self.process()))
        # The directory is not ours then, so the record is left as it was, and the pass is made every time.
        self.assertEqual(before, self.record())
        self.assertEqual(0o700, self.cache.stat().st_mode & 0o777)
        with patch.object(images.os, 'geteuid', return_value=other):
            self.assertEqual(1, self.passes(self.process()))
        self.assertEqual(0, self.passes(self.process()))


@controller_only
class WriteTests(Cache):
    def test_a_record_is_written_whole_or_not_at_all(self):
        self.passes(self.process())
        before = self.record()
        os.utime(self.disk, ns=(1, 1))
        with patch.object(images.os, 'replace', side_effect=OSError('replace failed')):
            # The pass itself succeeds (the bytes are the descriptor's); only the memory of it is lost.
            self.assertEqual(1, self.passes(self.process()))
        self.assertEqual(before, self.record())
        self.assertEqual([before[0]], self.records())
        self.assertEqual(1, self.passes(self.process()))

    def test_a_cache_that_cannot_be_written_never_fails_the_run(self):
        with patch.object(images.Path, 'mkdir', side_effect=OSError('read-only')):
            self.assertEqual(1, self.passes(self.process()))
        self.assertEqual([], self.records())

    def test_a_pass_that_does_not_match_the_descriptor_records_nothing(self):
        self.disk.write_bytes(windows_fixture.DISK[:-1] + b'!')
        with self.assertRaises(ValueError):
            self.process().validate(self.run_directory)
        self.assertEqual([], self.records())


if __name__ == '__main__':
    unittest.main()
