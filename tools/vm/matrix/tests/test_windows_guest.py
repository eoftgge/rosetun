"""Stage 9c: the agent's programs, the boot identity and the evidence of a Windows guest, offline.

The agent is a scripted client (`test_qga.Client`) that answers `guest-exec` and `guest-exec-status` as the Windows agent
does; nothing here runs PowerShell. The real command line, the UTF-8 channel and the guest's readings are checked on the
stand, and by the named-socket cases of `test_windows_reboot`.
"""

import base64
import json
import time
import unittest
from unittest.mock import patch

from tools.vm.matrix import windows_guest
from tools.vm.matrix.qga import EXEC_OUTPUT_LIMIT, Qga, QgaError, REQUIRED
from tools.vm.matrix.tests.test_qga import Client, Relay, Stream

EXEC = ('guest-exec', 'guest-exec-status')
LAST_BOOT = '2026-11-19T07:08:50.1234567Z'
EVIDENCE = dict(caption='Microsoft Windows 11 Pro', version='10.0.26200', build='26200', architecture='64-bit',
                culture='en-US', secure_boot=True, secure_boot_error=None, tpm=dict(present=True, ready=True),
                last_boot=LAST_BOOT, boot_counter=41, uptime_ms=61000, utf8_probe=windows_guest.UTF8_PROBE)
REG_OUTPUT = ('\r\nHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\'
              'PrefetchParameters\r\n    BootId    REG_DWORD    0x29\r\n\r\n').encode('ascii')


def b64(data):
    return base64.b64encode(data).decode()


def info(*extra):
    return {'version': '109.0.0', 'supported_commands': [
        {'name': name, 'enabled': True, 'success-response': True} for name in (*REQUIRED, *extra)]}


def done(out=b'', err=b'', code=0, **more):
    return dict({'exited': True, 'exitcode': code, 'out-data': b64(out), 'err-data': b64(err)}, **more)


class Base(unittest.TestCase):
    def adapter(self, *, guest_os='windows', commands=EXEC, statuses=None):
        stream = Stream(b'\xff{"return":123}\n')
        adapter = Qga(stream, client_factory=Client, relay_factory=Relay, guest_os=guest_os)
        adapter.sleep = lambda seconds: None
        self.addCleanup(adapter.close)
        with patch('secrets.randbits', return_value=123):
            adapter.connect(1)
        adapter.client.responses['guest-info'] = info(*commands)
        adapter.client.responses['guest-exec'] = {'pid': 4242}
        queue = list(statuses if statuses is not None else [done(b'{}')])
        adapter.client.responses['guest-exec-status'] = lambda: queue.pop(0)
        adapter.probe(1)
        return adapter

    def answer(self, adapter, text, *, err=b'', code=0):
        queue = [done(text.encode('utf-8'), err, code)]
        adapter.client.responses['guest-exec-status'] = lambda: queue.pop(0)


class CommandLineTests(unittest.TestCase):
    def test_a_script_runs_as_one_encoded_command_that_answers_in_utf8_bytes_on_the_raw_streams(self):
        words = windows_guest.arguments('Get-Date')
        self.assertEqual(['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand'], words[:-1])
        self.assertTrue(words[-1].isascii())
        script = base64.b64decode(words[-1]).decode('utf-16-le')
        self.assertIn('Get-Date', script)
        for needle in ('UTF8Encoding $false', '[Console]::OpenStandardOutput()', '[Console]::OpenStandardError()',
                       "$ErrorActionPreference = 'Stop'", 'exit 1'):
            self.assertIn(needle, script)
        # The console's encoding is never consulted, and no file is written.
        self.assertNotIn('OutputEncoding', script)
        self.assertNotIn('Out-File', script)

    def test_a_script_that_is_not_text_or_is_too_long_is_refused(self):
        for script in ('', None, b'Get-Date', 'x' * (windows_guest.SCRIPT_LIMIT + 1)):
            with self.subTest(), self.assertRaises(windows_guest.GuestAnswerError):
                windows_guest.arguments(script)

    def test_the_programs_are_full_paths_and_the_restart_is_now_with_no_countdown(self):
        self.assertTrue(windows_guest.POWERSHELL.endswith('\\WindowsPowerShell\\v1.0\\powershell.exe'))
        self.assertEqual('C:\\Windows\\System32\\shutdown.exe', windows_guest.SHUTDOWN)
        self.assertEqual(['/r', '/t', '0'], windows_guest.REBOOT_ARGUMENTS)

    def test_the_scripts_change_nothing_in_the_guest(self):
        for script in (windows_guest.EVIDENCE_SCRIPT,):
            for verb in ('Set-', 'New-', 'Remove-', 'Restart-', 'Stop-', 'Out-File', 'Add-Content', 'schtasks'):
                self.assertNotIn(verb, script)
        self.assertEqual(['query', windows_guest.BOOT_KEY, '/v', 'BootId'], windows_guest.BOOT_ARGUMENTS)
        self.assertTrue(windows_guest.REG.endswith('\\System32\\reg.exe'))


class BootIdTests(unittest.TestCase):
    def test_the_boot_id_is_the_guests_count_of_boots_as_reg_exe_prints_it(self):
        self.assertEqual(41, windows_guest.boot_count(REG_OUTPUT))
        self.assertEqual('win-41', windows_guest.boot_id(REG_OUTPUT))
        self.assertEqual('win-0', windows_guest.boot_id(REG_OUTPUT.replace(b'0x29', b'0x0')))
        self.assertEqual('win-4294967295', windows_guest.boot_id(REG_OUTPUT.replace(b'0x29', b'0xFFFFFFFF')))
        # Unix line ends and a value in capitals or in small letters read the same.
        self.assertEqual('win-171', windows_guest.boot_id(REG_OUTPUT.replace(b'\r\n', b'\n').replace(b'0x29', b'0xAb')))

    def test_what_is_not_one_line_of_the_count_is_refused(self):
        key = REG_OUTPUT.split(b'\r\n')[1]
        for output in (b'', b'x', b'\r\n' + key + b'\r\n', REG_OUTPUT + REG_OUTPUT.split(b'\r\n', 2)[2],
                       REG_OUTPUT.replace(b'REG_DWORD', b'REG_SZ'), REG_OUTPUT.replace(b'BootId', b'Other'),
                       REG_OUTPUT.replace(b'0x29', b'41'), REG_OUTPUT.replace(b'0x29', b'0x123456789'),
                       REG_OUTPUT.replace(b'0x29', b'0x'), REG_OUTPUT.replace(b'0x29', b'0x-1'),
                       REG_OUTPUT.replace(b'REG_DWORD', 'REG_DWÖRD'.encode('utf-8')),
                       b'x' * (windows_guest.OUTPUT_LIMIT + 1), 'text', None):
            with self.subTest(output=str(output)[:40]), self.assertRaises(windows_guest.GuestAnswerError):
                windows_guest.boot_id(output)

    def test_the_boot_id_is_a_name_the_run_state_takes_and_the_counts_of_two_boots_differ(self):
        from tools.vm.matrix import run_state
        self.assertEqual('win-41', run_state._name(windows_guest.boot_id(REG_OUTPUT)))
        self.assertNotEqual(windows_guest.boot_id(REG_OUTPUT), windows_guest.boot_id(REG_OUTPUT.replace(b'0x29', b'0x2a')))


class EvidenceTests(unittest.TestCase):
    def test_the_evidence_keeps_its_readings_and_says_whether_the_text_crossed_as_utf8(self):
        value = windows_guest.evidence(json.dumps(EVIDENCE))
        self.assertTrue(value['utf8_ok'])
        self.assertIs(True, value['secure_boot'])
        mangled = windows_guest.evidence(json.dumps(dict(EVIDENCE, utf8_probe='\u00c3\u00a9?')))
        self.assertFalse(mangled['utf8_ok'])

    def test_a_reading_that_failed_is_null_and_not_a_refusal_of_the_answer(self):
        value = windows_guest.evidence(json.dumps(dict(EVIDENCE, secure_boot=None, tpm=None,
                                                       secure_boot_error='not supported')))
        self.assertEqual((None, None), (value['secure_boot'], value['tpm']))

    def test_an_answer_of_the_wrong_shape_is_refused(self):
        for change in ({'secure_boot': 'True'}, {'tpm': {'present': True}}, {'tpm': {'present': 1, 'ready': 1}},
                       {'build': 26200}, {'caption': None}, {'secure_boot_error': 4}, {'secure_boot': 0},
                       {'boot_counter': -1}, {'boot_counter': True}, {'uptime_ms': '1'}):
            with self.subTest(change=change), self.assertRaises(windows_guest.GuestAnswerError):
                windows_guest.evidence(json.dumps(dict(EVIDENCE, **change)))
        with self.assertRaises(windows_guest.GuestAnswerError):
            windows_guest.evidence(json.dumps({k: v for k, v in EVIDENCE.items() if k != 'tpm'}))


class ProgramTests(Base):
    def test_a_windows_session_needs_the_exec_commands_and_a_linux_one_does_not(self):
        with self.assertRaisesRegex(QgaError, 'required-rpc-unsupported'):
            self.adapter(commands=())
        linux = self.adapter(guest_os='linux', commands=())
        self.assertEqual(list(REQUIRED), linux.info['required_commands'])
        self.assertEqual([*REQUIRED, *EXEC], self.adapter().info['required_commands'])

    def test_the_boot_id_is_the_count_of_boots_that_reg_exe_prints_and_no_powershell_is_started(self):
        adapter = self.adapter(statuses=[done(REG_OUTPUT)])
        self.assertEqual('win-41', adapter.read_boot_id(1))
        executed = [arguments for name, arguments in adapter.client.commands if name == 'guest-exec']
        self.assertEqual([{'path': windows_guest.REG, 'arg': ['query', windows_guest.BOOT_KEY, '/v', 'BootId'],
                           'capture-output': 'separated'}], executed)
        # No file of the guest is opened for the identity of a Windows boot.
        self.assertNotIn('guest-file-open', [c[0] for c in adapter.client.commands])

    def test_a_boot_id_that_reg_exe_could_not_give_is_an_error_of_the_observation(self):
        for status, reason in ((done(b'', b'ERROR: not found', 1), 'qga-boot-id-failed'),
                               (done(b'nothing here'), 'invalid-windows-boot-id'),
                               (done('0x29'.encode('utf-16-le')), 'invalid-windows-boot-id')):
            with self.subTest(reason=reason):
                adapter = self.adapter(statuses=[status])
                with self.assertRaisesRegex(QgaError, reason):
                    adapter.read_boot_id(1)

    def test_the_answer_is_read_as_utf8_and_the_two_streams_stay_apart(self):
        adapter = self.adapter()
        self.answer(adapter, windows_guest.UTF8_PROBE, err='avert\u00e9'.encode('utf-8'))
        self.assertEqual(windows_guest.UTF8_PROBE, adapter.powershell('x', 1))
        self.assertEqual('avert\u00e9', adapter.stderr_text)

    def test_a_program_still_running_is_polled_until_it_exits(self):
        waits = []
        adapter = self.adapter(statuses=[{'exited': False}, {'exited': False}, done(b'ok')])
        adapter.sleep = waits.append
        self.assertEqual('ok', adapter.powershell('x', 1))
        self.assertEqual(3, len([c for c in adapter.client.commands if c[0] == 'guest-exec-status']))
        # The first look comes soon and the later ones are spaced out.
        self.assertEqual([0.25, 0.5, 1.0], waits)

    def test_a_failed_script_is_an_error_that_keeps_the_guests_message_off_the_error(self):
        adapter = self.adapter()
        self.answer(adapter, '', err=b'System.Exception: secret detail', code=1)
        with self.assertRaisesRegex(QgaError, '^qga-powershell-failed$'):
            adapter.powershell('x', 1)
        self.assertEqual('System.Exception: secret detail', adapter.stderr_text)
        self.assertTrue(adapter.valid)

    def test_what_the_agent_says_wrongly_ends_the_session(self):
        cases = {
            'invalid-qga-exec-pid': ('guest-exec', {'pid': True}),
            'invalid-qga-exec-pid ': ('guest-exec', {'pid': 1, 'x': 2}),
            'invalid-qga-exec-status': ('guest-exec-status', {'exited': 'yes'}),
        }
        for reason, (command, value) in cases.items():
            with self.subTest(reason=reason):
                adapter = self.adapter()
                adapter.client.responses[command] = value
                with self.assertRaisesRegex(QgaError, reason.strip()):
                    adapter.powershell('x', 1)
                self.assertFalse(adapter.valid)

    def test_an_exit_with_no_code_or_a_signal_and_bad_or_cut_output_are_refused(self):
        bad = [dict(exited=True), dict(done(), signal=3), dict(done(), **{'out-truncated': True}),
               dict(done(), **{'err-truncated': True}), dict(done(), **{'out-data': 'not base64!'}),
               dict(done(), **{'out-data': b64(b'x' * (EXEC_OUTPUT_LIMIT + 1))}),
               dict(done(), **{'err-data': b64(b'x' * (EXEC_OUTPUT_LIMIT + 1))}),
               dict(done(), **{'out-data': 1}), dict(done(), exitcode='0')]
        for status in bad:
            with self.subTest(status=str(status)[:60]):
                adapter = self.adapter(statuses=[status])
                with self.assertRaises(QgaError):
                    adapter.powershell('x', 1)

    def test_output_that_is_not_utf8_is_refused(self):
        adapter = self.adapter(statuses=[done(b'\xff\xfe')])
        with self.assertRaisesRegex(QgaError, 'invalid-qga-powershell-output'):
            adapter.powershell('x', 1)

    def test_a_program_that_does_not_exit_in_time_ends_the_session_and_is_not_killed(self):
        adapter = self.adapter(statuses=[{'exited': False}] * 1000)
        adapter.sleep = lambda seconds: time.sleep(0.01)
        with self.assertRaisesRegex(QgaError, 'qga-exec-timeout'):
            adapter.powershell('x', 1, seconds=0.05)
        self.assertFalse(adapter.valid)

    def test_the_calls_of_a_session_stay_within_its_limit(self):
        adapter = self.adapter(statuses=[{'exited': False}] * 200)
        adapter.deadline = None
        with self.assertRaisesRegex(QgaError, 'qga-command-limit'):
            adapter.powershell('x', 1, seconds=3600)
        self.assertLessEqual(adapter.calls, 128)

    def test_a_restart_is_started_and_not_waited_for(self):
        adapter = self.adapter()
        pid = adapter.start_program(windows_guest.SHUTDOWN, list(windows_guest.REBOOT_ARGUMENTS), 1)
        self.assertEqual(4242, pid)
        name, arguments = adapter.client.commands[-1]
        self.assertEqual(('guest-exec', {'path': windows_guest.SHUTDOWN, 'arg': ['/r', '/t', '0'],
                                         'capture-output': False}), (name, arguments))
        self.assertNotIn('guest-exec-status', [c[0] for c in adapter.client.commands])

    def test_a_request_that_is_not_a_path_and_words_is_refused_before_it_is_sent(self):
        adapter = self.adapter()
        before = len(adapter.client.commands)
        for path, arguments in (('', []), (None, []), ('C:\\x.exe', 'a'), ('C:\\x.exe', [1])):
            with self.subTest(), self.assertRaisesRegex(QgaError, 'invalid-qga-exec-request'):
                adapter.start_program(path, arguments, 1)
        self.assertEqual(before, len(adapter.client.commands))

    def test_only_a_windows_session_runs_powershell_and_the_guest_system_is_one_of_two(self):
        with self.assertRaisesRegex(QgaError, 'qga-powershell-needs-windows'):
            self.adapter(guest_os='linux').powershell('x', 1)
        with self.assertRaisesRegex(QgaError, 'invalid-qga-guest-os'):
            Qga(Stream(b''), guest_os='macos')

    def test_a_program_cannot_be_run_before_the_agent_was_probed(self):
        adapter = Qga(Stream(b''), guest_os='windows')
        with self.assertRaisesRegex(QgaError, 'qga-probe-required'):
            adapter.start_program('C:\\x.exe', [], 1)
        with self.assertRaisesRegex(QgaError, 'qga-probe-required'):
            adapter.read_boot_id(1)


if __name__ == '__main__':
    unittest.main()
