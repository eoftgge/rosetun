"""Why a lab exchange failed: the DNS check of the test machine, and the one line the helper prints for anything else."""
import base64
import json
from pathlib import Path
import re
import socket
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.vm.matrix import lab, orchestrator, lab_protocol as wire
from tools.vm.matrix.tests.test_lab_fixtures import Base, runpy_main

CHECK = ('dns-plain', 'dns-client', wire.DNS_CHECK_DOH)


class DnsProbeBase(Base):
    """`probe_dns` with the sockets, the sing-box client and the TLS exchange replaced."""

    def setUp(self):
        super().setUp()
        nonces = iter(f'{i:024x}' for i in range(20, 30))
        self.request.update(role='test', operation='probe', dns=True,
                            dns_check=wire.dns_checks(self.request['lab_id'], nonces.__next__))
        self.root = Path(tempfile.mkdtemp())
        self.directory = self.root / self.request['lab_id']
        self.events, self.client_log, self.faults = [], b'', {}
        events = self.events
        owner = self

        class Sock:
            def __init__(self, *args):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def settimeout(self, value):
                pass

            def bind(self, address):
                pass

            def connect(self, address):
                pass

            def send(self, data):
                pass

            def recv(self, size):
                events.append('plain-asked')
                if 'dns-plain' in owner.faults:
                    raise owner.faults['dns-plain']
                return b'resolver-answer'

        def start(config, directory, name, address, port):
            events.append('start')
            directory.mkdir(parents=True, exist_ok=True)
            (directory / (name + '.stderr')).write_bytes(owner.client_log)
            if 'dns-client' in owner.faults:
                raise owner.faults['dns-client']
            return SimpleNamespace(name=name)

        def stop(process):
            events.append('stop')
            return True, -15

        def get(sock, exchange, context):
            events.append('doh-asked')
            if wire.DNS_CHECK_DOH in owner.faults:
                raise owner.faults[wire.DNS_CHECK_DOH]
            return wire.https_answer(exchange)

        for item in (patch.object(self.entry.socket, 'socket', Sock),
                     patch.object(self.entry.ssl, 'create_default_context', lambda: 'context'),
                     patch.object(self.entry, 'plain_reply_ok', lambda check, reply: True),
                     patch.object(self.entry, 'https_get', get),
                     patch.object(self.entry, 'start_process', start),
                     patch.object(self.entry, 'stop_process', stop),
                     patch.object(self.entry, 'socks_connect_domain', lambda sock, name, port: None),
                     patch.object(self.entry, 'ROOT', self.root)):
            item.start()
            self.addCleanup(item.stop)

    def probe(self, **fail):
        self.faults.update(fail)
        result = self.entry.probe_dns(self.request)
        # The helper's answer is JSON: whatever it holds must survive that.
        return json.loads(json.dumps(result))


class ProbeTests(DnsProbeBase):
    def test_a_complete_check_answers_both_exchanges_with_the_exit_and_the_log_of_the_client_as_text(self):
        self.client_log = b'WARN dns: nothing to say\n'
        result = self.probe()
        checks = self.request['dns_check']
        self.assertEqual({'plain', 'doh', 'client_exit', 'client_log'}, set(result))
        self.assertEqual(wire.https_answer(checks['doh']).hex(), result['doh']['response'])
        self.assertEqual(b'resolver-answer'.hex(), result['plain']['response'])
        self.assertEqual((-15, 'WARN dns: nothing to say\n'), (result['client_exit'], result['client_log']))
        self.assertEqual(['plain-asked', 'start', 'doh-asked', 'stop'], self.events)

    def test_every_exchange_that_fails_is_named_with_its_reason_and_its_time_and_the_run_goes_on(self):
        for name, error, reason in (('dns-plain', socket.timeout(), 'timeout'),
                                    ('dns-client', self.entry.Refused('dns-client-exited'), 'dns-client-exited'),
                                    (wire.DNS_CHECK_DOH, ValueError('unexpected-https-answer'),
                                     'unexpected-https-answer')):
            with self.subTest(exchange=name):
                self.events.clear()
                self.faults.clear()
                self.client_log = b'ERROR client: ' + name.encode() + b'\n'
                result = self.probe(**{name: error})
                self.assertEqual({'exchange', 'reason', 'elapsed_ms'}, set(result['failed']))
                self.assertEqual((name, reason), (result['failed']['exchange'], result['failed']['reason']))
                self.assertIsInstance(result['failed']['elapsed_ms'], int)
                self.assertGreaterEqual(result['failed']['elapsed_ms'], 0)
                # The client only exists once the plain question has been answered.
                self.assertEqual('' if name == 'dns-plain' else 'ERROR client: ' + name + '\n', result['client_log'])

    def test_what_was_answered_before_the_failure_is_kept_and_what_came_after_is_never_asked(self):
        result = self.probe(**{wire.DNS_CHECK_DOH: ValueError('unexpected-https-answer')})
        self.assertEqual({'plain', 'client_exit', 'client_log', 'failed'}, set(result))
        self.assertEqual(['plain-asked', 'start', 'doh-asked', 'stop'], self.events)
        self.events.clear()
        result = self.probe(**{'dns-plain': socket.timeout()})
        self.assertEqual({'client_exit', 'client_log', 'failed'}, set(result))
        self.assertEqual(['plain-asked'], self.events)
        self.assertIsNone(result['client_exit'])
        self.assertEqual('', result['client_log'])

    def test_a_client_that_started_is_stopped_and_its_exit_reported_when_the_lookup_fails(self):
        result = self.probe(**{wire.DNS_CHECK_DOH: socket.timeout()})
        self.assertEqual((-15, 'timeout'), (result['client_exit'], result['failed']['reason']))
        self.assertEqual('stop', self.events[-1])

    def test_a_client_that_never_started_has_no_exit_to_report(self):
        result = self.probe(**{'dns-client': self.entry.Refused('dns-client-not-listening')})
        self.assertIsNone(result['client_exit'])
        self.assertNotIn('stop', self.events)

    def test_the_failure_texts_are_the_ones_of_the_helper_line(self):
        with self.assertRaisesRegex(self.entry.ExchangeFailed, r'^dns-plain:4:timeout:\d+ms$') as raised:
            self.entry.exchange('dns-plain', 4, lambda: (_ for _ in ()).throw(socket.timeout()))
        error = raised.exception
        self.assertEqual(('dns-plain', 'timeout'), (error.name, error.reason))
        self.assertEqual('dns-plain:4:timeout:%dms' % error.elapsed_ms, str(error))
        self.assertEqual('http:6:timeout:5003ms', str(self.entry.ExchangeFailed('http:6:timeout:5003ms')))


class ClientLogTests(DnsProbeBase):
    def log(self, raw):
        self.directory.mkdir(parents=True, exist_ok=True)
        (self.directory / 'dns-client.stderr').write_bytes(raw)
        return self.entry.client_log_of(self.directory, 'dns-client')

    def test_addresses_outside_the_documentation_ranges_are_blanked_and_the_others_stay(self):
        text = self.log(b'dial 8.8.8.8:853 failed; node 192.0.2.1:8388 ok; 203.0.113.3 fine; '
                        b'peer 2001:db8::7 and fe80::1 and 2606:4700::1111\n')
        self.assertNotRegex(text, r'8\.8\.8\.8|fe80|2606')
        for kept in ('192.0.2.1', '203.0.113.3', '2001:db8::7'):
            self.assertIn(kept, text)
        self.assertEqual(3, text.count('[address]'))

    def test_the_log_is_cut_at_its_limit_and_never_longer_than_the_log_limit(self):
        text = self.log(b'x' * (wire.LOG_LIMIT * 2))
        self.assertEqual((self.entry.CLIENT_LOG_LIMIT, True), (len(text), len(text) <= wire.LOG_LIMIT))

    def test_bytes_that_are_not_text_become_replacement_characters_and_not_an_error(self):
        text = self.log(b'bad \xff\xfe bytes \xe2\x82')
        self.assertEqual('bad �� bytes �', text)
        self.assertIsInstance(text, str)

    def test_no_log_is_an_empty_one(self):
        self.assertEqual('', self.entry.client_log_of(self.directory, 'dns-client'))

    def test_the_answer_carries_a_log_the_helper_can_print(self):
        self.client_log = b'\xff' * 100 + b' 8.8.4.4 '
        result = self.probe()
        self.assertIsInstance(result['client_log'], str)
        self.assertNotIn('8.8.4.4', json.dumps(result))


class MainTests(Base):
    """The one line of stderr the controller reads after `lab-helper-failed:`."""

    def run_main(self, error=None, output=None):
        with patch.object(self.entry, 'main', side_effect=error, return_value=output), \
                patch.object(self.entry.sys, 'argv', ['entry', json.dumps(self.request)]), \
                patch('sys.stderr') as stderr, patch('sys.stdout') as stdout, \
                self.assertRaises(SystemExit) as raised:
            runpy_main(self.entry)
        self.assertEqual(2, raised.exception.code)
        self.assertEqual('', ''.join(c.args[0] for c in stdout.write.call_args_list))
        return ''.join(c.args[0] for c in stderr.write.call_args_list).strip()

    def code(self, line):
        self.assertTrue(line.startswith('lab-helper-failed:'), line)
        code = line[len('lab-helper-failed:'):]
        self.assertRegex(code, wire.HELPER_REASON.pattern)
        self.assertTrue(wire.HELPER_REASON.fullmatch(code), code)
        return code

    def test_an_exception_nobody_expected_is_printed_as_its_class_and_a_short_message(self):
        line = self.run_main(error=KeyError('no-such-key'))
        self.assertEqual('lab-helper-failed:keyerror:no-such-key', line)

    def test_an_answer_that_cannot_be_printed_is_the_failure_that_the_old_helper_hid(self):
        line = self.run_main(output=dict(client_log=b'bytes are not json'))
        self.assertEqual('typeerror:object-of-type-bytes-is-not-json-serializable', self.code(line))

    def test_the_code_is_lowercase_bounded_and_free_of_foreign_addresses(self):
        for name, error in (('address', OSError('connect to 8.8.8.8:853 and 2606:4700::1111 refused')),
                            ('documentation', RuntimeError('node 192.0.2.1 and 2001:db8::1')),
                            ('long', ValueError('x' * 500)),
                            ('long-class', type('A' * 200, (Exception,), {})('message')),
                            ('odd', ValueError('Ünï Cödé / Pâth \n\t "quoted"')),
                            ('empty', ValueError(''))):
            with self.subTest(name=name):
                code = self.code(self.run_main(error=error))
                self.assertLessEqual(len(code), 96)
                self.assertEqual(code.lower(), code)
                self.assertNotRegex(code, r'8\.8\.8\.8|2606')
        self.assertIn('192.0.2.1', self.run_main(error=RuntimeError('node 192.0.2.1')))

    def test_an_exception_that_cannot_describe_itself_still_gives_a_code(self):
        class Silent(Exception):
            def __str__(self):
                raise RuntimeError('no text')
        self.assertEqual('lab-helper-failed:unprintable-error', self.run_main(error=Silent()))

    def test_a_refusal_keeps_its_fixed_words_and_an_exchange_its_four_parts(self):
        self.assertEqual('lab-helper-failed:missing-sing-box', self.run_main(error=self.entry.Refused('missing-sing-box')))
        failure = self.entry.ExchangeFailed('dns-plain:4:timeout:5003ms')
        self.assertEqual('lab-helper-failed:dns-plain:4:timeout:5003ms', self.run_main(error=failure))

    def test_no_failure_is_the_bare_word_any_more(self):
        for error in (ValueError(), KeyError(), OSError(), Exception(), AssertionError()):
            with self.subTest(error=type(error).__name__):
                self.assertNotEqual('lab-helper-failed', self.run_main(error=error))
                self.assertRegex(self.run_main(error=error), r'^lab-helper-failed:[a-z0-9:._-]+$')


class ControllerTests(unittest.TestCase):
    """What the controller does with that line, however the guest said it."""

    def setUp(self):
        self.boot = '12345678-1234-4234-8234-123456789abc'
        self.status = dict(exited=True, exitcode=2)
        vm = SimpleNamespace(_check=lambda: None, _guest_lock=threading.Lock(), reset_pending=False,
                             vm_uuid=self.boot, last_boot_id=self.boot, qga=SimpleNamespace(
                                 _rpc=lambda name, timeout, args: dict(pid=1) if name == 'guest-exec' else self.status,
                                 read_boot_id=lambda _: self.boot, probe=lambda _: None, valid=True))
        self.guest = lab.Guest(vm, 'test', 'a' * 32, clock=lambda: 0, sleep=lambda _: None)

    def error_row(self, text=None, **status):
        self.status = dict(self.status, **status)
        if text is not None:
            self.status['err-data'] = base64.b64encode(text.encode()).decode()
        with self.assertRaises(lab.HelperFailed) as raised:
            self.guest.call('probe', [])
        return orchestrator.failure('probe', raised.exception)

    def test_a_code_the_helper_printed_reaches_the_row_as_it_is(self):
        row = self.error_row('lab-helper-failed:typeerror:object-of-type-bytes-is-not-json-serializable\n')
        self.assertEqual('typeerror:object-of-type-bytes-is-not-json-serializable', row['helper_reason'])

    def test_a_failed_helper_always_has_a_helper_reason(self):
        for name, text, status in (('bare-word', 'lab-helper-failed\n', {}), ('nothing-printed', None, {}),
                                   ('garbage', 'Traceback (most recent call last):', {}),
                                   ('foreign-code', 'lab-helper-failed:/etc/passwd', {}),
                                   ('cut', 'lab-helper-failed:abc', {'err-truncated': True})):
            with self.subTest(name=name):
                row = self.error_row(text, **status)
                self.assertEqual('reason-not-reported', row['helper_reason'])
                self.assertEqual('HelperFailed', row['kind'])


if __name__ == '__main__':
    unittest.main()
