"""Exercise the real pipe collector with a fake Popen, never a real process."""

import io
import subprocess
import unittest
from unittest.mock import patch

from tools.vm.matrix.qemu import CommandError, execute


class FakeProcess:
    def __init__(self, stdout=b'{}', stderr=b'', failure=None):
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.failure = failure
        self.returncode = None
        self.waits = []
        self.kills = 0

    def wait(self, *, timeout):
        self.waits.append(timeout)
        if self.failure:
            failure, self.failure = self.failure, None
            raise failure
        if self.returncode is None:
            self.returncode = 0
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        self.kills += 1
        self.returncode = -9


class ExecutorTests(unittest.TestCase):
    def invoke(self, process, **kwargs):
        argv = ['/explicit path/qemu-img', 'info', '/image Юникод']
        with patch('tools.vm.matrix.qemu.subprocess.Popen', return_value=process) as popen:
            try:
                return execute(argv, timeout=30, output_limit=16, **kwargs)
            finally:
                popen.assert_called_once_with(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE, shell=False, bufsize=0)
                self.assertTrue(process.stdout.closed)
                self.assertTrue(process.stderr.closed)
                self.assertTrue(all(0 < duration <= 30 for duration in process.waits))

    def test_collects_both_pipes_and_preserves_nonzero_exit(self):
        process = FakeProcess(b'json', b'diagnostic')
        process.returncode = 7
        result = self.invoke(process)
        self.assertEqual((7, b'json', b'diagnostic'),
                         (result.returncode, result.stdout, result.stderr))

    def test_each_pipe_has_a_hard_output_limit(self):
        for stdout, stderr in ((b'x' * 100000, b''), (b'', b'x' * 100000)):
            with self.subTest(stderr=bool(stderr)):
                process = FakeProcess(stdout, stderr)
                with self.assertRaisesRegex(CommandError, 'command-output-limit'):
                    self.invoke(process)
                self.assertGreaterEqual(process.kills, 1)

    def test_output_at_limit_is_accepted(self):
        self.assertEqual(b'x' * 16, self.invoke(FakeProcess(b'x' * 16)).stdout)

    def test_timeout_kills_and_reaps_with_a_bounded_wait(self):
        process = FakeProcess(failure=subprocess.TimeoutExpired('private argv', 30))
        with self.assertRaisesRegex(CommandError, 'command-timeout'):
            self.invoke(process)
        self.assertEqual(1, process.kills)
        self.assertEqual([30, 2], process.waits)

    def test_cancellation_also_kills_and_reaps(self):
        process = FakeProcess(failure=KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            self.invoke(process)
        self.assertEqual(1, process.kills)
        self.assertEqual([30, 2], process.waits)

    def test_pipe_read_failure_cannot_be_silently_accepted(self):
        class BrokenReader(io.BytesIO):
            def read(self, size):
                raise OSError('private error text')
        process = FakeProcess()
        process.stdout = BrokenReader()
        with self.assertRaisesRegex(CommandError, 'command-output-read-failed'):
            self.invoke(process)

    def test_invalid_limits_are_rejected_before_popen(self):
        for timeout, limit in ((0, 16), (float('nan'), 16), (float('inf'), 16),
                               (True, 16), (30, 0), (30, True)):
            with self.subTest(timeout=timeout, limit=limit), patch('subprocess.Popen') as popen:
                with self.assertRaises(CommandError):
                    execute(['/absolute/qemu-img'], timeout=timeout, output_limit=limit)
                popen.assert_not_called()


if __name__ == '__main__':
    unittest.main()
