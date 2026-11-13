"""The lab observer's own loop on loopback: a fake capture, fake services and the real `serve`."""
import base64
import errno
import json
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.vm.matrix import lab, orchestrator, lab_protocol as wire
from tools.vm.matrix.tests.test_lab_fixtures import load_entry, runpy_main, tunnel_block

LOOPBACK = '127.0.0.1'


class Boom(BaseException):
    """Not an `Exception`, so nothing in the loop may count it as one exchange's failure."""


class FakeCapture:
    """The router's capture socket: frames fed from the far end come out of `recv` like AF_PACKET ones."""

    def __init__(self, drops=0, explode=None):
        self.near = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.near.bind((LOOPBACK, 0))
        self.near.setblocking(False)
        self.far = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.drops, self.explode = drops, explode

    def fileno(self):
        return self.near.fileno()

    def recv(self, size):
        if self.explode is not None:
            raise self.explode
        return self.near.recv(size)

    def getsockopt(self, level, name, size):
        return struct.pack('II', 0, self.drops)

    def feed(self, frame):
        self.far.sendto(frame, self.near.getsockname())

    def close(self):
        self.near.close()
        self.far.close()


class Observer:
    """One `serve` run in a thread, with loopback sockets standing in for the target namespace."""

    def __init__(self, case, *, tunnel=False, dns=False, duration=30, capture=None, **request):
        self.case, self.entry = case, case.entry
        self.directory = Path(tempfile.mkdtemp())
        case.addCleanup(self.cleanup)
        nonces = iter(f'{i:024x}' for i in range(20))
        lab_id = 'a' * 32
        self.probes, self.window = wire.probes(lab_id, nonces.__next__), wire.markers(lab_id, nonces.__next__)
        local = lambda row: dict(row, source=LOOPBACK)
        self.request = dict(role='lab', lab_id=lab_id, interface='lab0', operation='serve', canary=False,
                            probes=[local(p) for p in self.probes], markers=[local(m) for m in self.window],
                            duration_seconds=duration, **request)
        if tunnel:
            self.request['tunnel'] = tunnel_block(lab_id, nonces)
        if dns:
            self.request['dns'] = True
        self.capture = capture or FakeCapture()
        self.addresses, self.error, self.thread = {}, None, None
        self.node = SimpleNamespace(name='node')
        for target in (patch.object(self.entry, 'open_capture', lambda interface: self.capture),
                       patch.object(self.entry, 'bind_targets', self.bind),
                       patch.object(self.entry, 'check_lab_fixtures'),
                       patch.object(self.entry, 'start_process', lambda *args: self.node),
                       patch.object(self.entry, 'stop_process', lambda process: (True, -15)),
                       patch.object(self.entry, 'dns_loop', lambda udp, tcp, log, stop: stop.wait()),
                       patch.object(self.entry, 'doh_loop', lambda doh, tls, log, stop: stop.wait())):
            target.start()
            case.addCleanup(target.stop)

    def bind(self, request, tunnel, selector, sockets, dns_sockets):
        def listener(key, kind):
            stream = socket.socket(socket.AF_INET, kind)
            stream.bind((LOOPBACK, 0))
            if kind == socket.SOCK_STREAM:
                stream.listen(4)
            sockets.append(stream)
            selector.register(stream, self.entry.selectors.EVENT_READ, key)
            self.addresses[key] = stream.getsockname()
        for family in (4, 6):
            for service in wire.SERVICES:
                listener((family, service), socket.SOCK_STREAM if service in ('http', 'dns-tcp') else socket.SOCK_DGRAM)
        listener((4, 'marker'), socket.SOCK_DGRAM)
        if tunnel is not None:
            listener((4, 'https'), socket.SOCK_STREAM)
        return (object() if tunnel is not None else None), ((None,) * 4 if request.get('dns') is True else None)

    def cleanup(self):
        (self.directory / 'stop').touch()
        if self.thread is not None:
            self.thread.join(10)
        self.capture.close()
        for path in self.directory.iterdir():
            path.unlink()
        self.directory.rmdir()

    def start(self):
        def run():
            try:
                self.entry.serve(self.request, self.directory)
            except BaseException as error:
                self.error = error
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        return self

    def wait_ready(self):
        for _ in range(100):
            if (self.directory / 'ready.json').exists() or not self.thread.is_alive():
                return self
            time.sleep(.05)
        raise AssertionError('observer never said ready')

    def finish(self):
        (self.directory / 'stop').touch()
        self.thread.join(10)
        self.case.assertFalse(self.thread.is_alive())
        return json.loads((self.directory / 'health.json').read_text())

    def run(self):
        """Start, let it settle for a moment, stop it and return its health record."""
        self.start().wait_ready()
        return self.finish()

    def send_datagram(self, key, data):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
            stream.settimeout(3)
            stream.sendto(data, self.addresses[key])
            return stream.recv(2048)

    def sendto(self, key, data):
        """One datagram, and no wait for an answer."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
            stream.sendto(data, self.addresses[key])

    def poke(self, service, family=4):
        """The one valid request of a probe, sent without waiting for the answer."""
        probe = next(p for p in self.request['probes'] if p['service'] == service and p['family'] == family)
        data = wire.query(probe)
        if service == 'http':
            data = b'GET /' + wire.token(probe) + b' HTTP/1.0\r\n\r\n'
        elif service == 'dns-tcp':
            data = struct.pack('!H', len(data)) + data
        if probe['protocol'] == 'tcp':
            with socket.create_connection(self.addresses[(family, service)], 3) as stream:
                stream.sendall(data)
        else:
            self.sendto((family, service), data)

    def marker(self, word):
        marker = next(m for m in self.window if m['word'] == word)
        return self.send_datagram((4, 'marker'), wire.marker_query(marker)), marker


class ObserverCase(unittest.TestCase):
    def setUp(self):
        self.entry = load_entry()


class ReasonTests(ObserverCase):
    def test_the_reason_is_the_class_and_a_short_lowercase_code(self):
        for error, expected in ((ValueError('capture-limit'), 'ValueError:capture-limit'),
                                (OSError(errno.EIO, 'Input/output error'), 'OSError:eio'),
                                (ConnectionResetError(errno.ECONNRESET, 'reset'),
                                 'ConnectionResetError:' + errno.errorcode[errno.ECONNRESET].lower()),
                                (socket.timeout('timed out'), 'TimeoutError:timeout'),
                                (subprocess.CalledProcessError(2, ['ip']), 'CalledProcessError:exit-2'),
                                (subprocess.TimeoutExpired(['ip'], 5), 'TimeoutExpired:timeout'),
                                (Boom(), 'Boom:boom'), (KeyboardInterrupt(), 'KeyboardInterrupt:keyboardinterrupt')):
            with self.subTest(error=expected):
                self.assertEqual(expected, self.entry.reason_of(error))

    def test_a_tls_failure_is_named_by_its_openssl_reason(self):
        failure = ssl.SSLError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed')
        failure.reason = 'CERTIFICATE_VERIFY_FAILED'
        self.assertEqual('SSLError:ssl-certificate_verify_failed', self.entry.reason_of(failure))

    def test_only_documentation_addresses_survive_in_a_reason(self):
        kept = self.entry.reason_of(RuntimeError('bad 2001:db8::5 and 198.51.100.7'))
        self.assertEqual('RuntimeError:bad-2001:db8::5-and-198.51.100.7', kept)
        gone = self.entry.reason_of(RuntimeError('x 8.8.8.8 2606:4700::1111 192.168.1.20 fe80::1'))
        for text in ('8.8.8.8', '2606', '4700', '1111', '192.168', 'fe80'):
            self.assertNotIn(text, gone)
        self.assertRegex(gone, r'^RuntimeError:x-address-address-address-address$')

    def test_a_long_message_is_cut_and_a_long_class_name_cannot_push_the_reason_past_ninety_six(self):
        self.assertEqual('ValueError:' + 'x' * 48, self.entry.reason_of(ValueError('x' * 500)))
        huge = type('E' * 200, (Exception,), {})
        self.assertEqual(96, len(self.entry.reason_of(huge('y' * 500))))
        self.assertLessEqual(len(self.entry.short_code(ValueError('z' * 500))), 48)

    def test_a_message_of_odd_characters_still_gives_a_code_of_the_fixed_alphabet(self):
        for message in ('/etc/shadow: no such file', 'Ünïcode \x00 and spaces', '', '!!!'):
            with self.subTest(message=message):
                self.assertRegex(self.entry.short_code(ValueError(message)), r'^[a-z0-9:._-]{1,48}$')


class ExchangeNameTests(ObserverCase):
    def test_a_failed_exchange_names_itself_its_family_why_and_how_long(self):
        def failing():
            time.sleep(.02)
            raise socket.timeout('timed out')
        with self.assertRaises(self.entry.Refused) as raised:
            self.entry.exchange('dns-tcp', 6, failing)
        self.assertRegex(str(raised.exception), r'^dns-tcp:6:timeout:[0-9]+ms$')
        self.assertGreaterEqual(int(str(raised.exception).rsplit(':', 1)[1][:-2]), 15)
        self.assertTrue(wire.HELPER_REASON.fullmatch(str(raised.exception)))

    def test_a_successful_exchange_returns_its_value(self):
        self.assertEqual(7, self.entry.exchange('http', 4, lambda: 7))

    def test_every_exchange_of_the_test_machine_is_named_by_its_own_service(self):
        request = dict(probes=wire.probes('a' * 32, iter(f'{i:024x}' for i in range(8)).__next__))
        for probe in request['probes']:
            def one(p, bad=probe):
                if p is bad:
                    raise ConnectionRefusedError(errno.ECONNREFUSED, 'refused')
                return dict(p, response='')
            with self.subTest(service=probe['service'], family=probe['family']), \
                    patch.object(self.entry, 'probe_one', one), self.assertRaises(self.entry.Refused) as raised:
                self.entry.probe_exchanges(request)
            # Windows names the same error WSAECONNREFUSED; the guest is Linux.
            self.assertRegex(str(raised.exception), '^%s:%d:%s:[0-9]+ms$' % (
                probe['service'], probe['family'], errno.errorcode[errno.ECONNREFUSED].lower()))

    def test_the_markers_and_the_canary_are_named_too(self):
        window = wire.markers('a' * 32, iter(f'{i:024x}' for i in range(2)).__next__)
        request = dict(probes=[], markers=window, canary=True)

        def marker_fails(word):
            def marker(m):
                if m['word'] == word:
                    raise ValueError('unexpected-marker-answer')
                return dict(m, response='')
            return marker
        for word in ('open', 'close'):
            with self.subTest(word=word), patch.object(self.entry, 'exchange_marker', marker_fails(word)), \
                    patch.object(self.entry, 'probe_exchanges', lambda request: []), \
                    patch.object(self.entry, 'send_canary'), patch.object(self.entry.time, 'sleep'), \
                    self.assertRaisesRegex(self.entry.Refused, '^marker-%s:4:unexpected-marker-answer:' % word):
                self.entry.probe_all(request)
        with patch.object(self.entry, 'exchange_marker', lambda m: dict(m, response='')), \
                patch.object(self.entry, 'probe_exchanges', lambda request: []), \
                patch.object(self.entry, 'send_canary', side_effect=ValueError('canary-not-sent')), \
                self.assertRaisesRegex(self.entry.Refused, '^canary:4:canary-not-sent:'):
            self.entry.probe_all(request)

    def test_the_helper_prints_the_exchange_after_the_failure_prefix(self):
        failure = self.entry.ExchangeFailed('http:6:timeout:5003ms')
        with patch.object(self.entry, 'main', side_effect=failure), \
                patch.object(self.entry.sys, 'argv', ['entry', '{}']), \
                patch('sys.stderr') as stderr, self.assertRaises(SystemExit) as raised:
            runpy_main(self.entry)
        self.assertEqual(2, raised.exception.code)
        self.assertEqual('lab-helper-failed:http:6:timeout:5003ms',
                         ''.join(c.args[0] for c in stderr.write.call_args_list).strip())


class HelperReasonTests(unittest.TestCase):
    def status(self, text):
        return {'err-data': base64.b64encode(text.encode()).decode()}

    def test_a_code_of_the_fixed_alphabet_reaches_the_summary_as_it_is(self):
        status = self.status('lab-helper-failed:http:6:timeout:5003ms\n')
        error = lab.HelperFailed(lab.refusal(status), lab.helper_code(status))
        self.assertEqual('http:6:timeout:5003ms', lab.helper_code(status))
        self.assertEqual('lab-helper-failed', lab.refusal(status))
        row = orchestrator.failure('probe', error)
        self.assertEqual(dict(stage='probe', kind='HelperFailed', reason='lab-helper-failed',
                              helper_reason='http:6:timeout:5003ms'), row)

    def test_a_plain_refusal_keeps_its_reason_and_gains_the_helper_reason(self):
        status = self.status('lab-helper-failed:missing-sing-box')
        row = orchestrator.failure('probe', lab.HelperFailed(lab.refusal(status), lab.helper_code(status)))
        self.assertEqual(('lab-helper-failed-missing-sing-box', 'missing-sing-box'),
                         (row['reason'], row['helper_reason']))

    def test_anything_else_stays_operation_failed_and_adds_nothing(self):
        for text in ('lab-helper-failed:/etc/passwd', 'lab-helper-failed:Upper', 'lab-helper-failed:a b',
                     'lab-helper-failed:' + 'a' * 97, 'lab-helper-failed:', 'lab-helper-failed', 'garbage'):
            with self.subTest(text=text):
                status = self.status(text)
                self.assertIsNone(lab.helper_code(status))
                row = orchestrator.failure('probe', lab.HelperFailed(lab.refusal(status), lab.helper_code(status)))
                self.assertNotIn('helper_reason', row)
        self.assertEqual(dict(stage='x', kind='ValueError', reason='operation-failed'),
                         orchestrator.failure('x', ValueError('a b')))

    def test_the_longest_code_fits_and_one_more_character_does_not(self):
        self.assertEqual('a' * 96, lab.helper_code(self.status('lab-helper-failed:' + 'a' * 96)))
        self.assertIsNone(lab.helper_code({'err-data': '!not-base64'}))
        self.assertIsNone(lab.helper_code({}))

    def test_a_reason_attached_to_a_foreign_exception_is_not_trusted(self):
        class Foreign(Exception):
            helper_reason = 'looks-fine'
        Foreign.__module__ = 'somewhere.else'
        self.assertNotIn('helper_reason', orchestrator.failure('x', Foreign('looks-fine')))
        error = lab.HelperFailed('lab-helper-failed', 'Not Valid')
        self.assertNotIn('helper_reason', orchestrator.failure('x', error))


class PlacesTests(ObserverCase):
    """Every place `error_in` can name, each reached by an exception no handler may swallow."""

    def stopped_by(self, place):
        """(Observer, health) of a run that Boom stops in `place`."""
        entry = self.entry
        tunnel = place in ('https', 'node')
        observer = Observer(self, tunnel=tunnel, dns=place in ('dns', 'doh'),
                            duration=0.4 if place == 'finish' else 30)

        def boom(*args, **kwargs):
            raise Boom('injected')
        if place == 'capture':
            observer.capture.explode = Boom('injected')
        elif place == 'marker':
            self.enterContext(patch.object(entry, 'accept_marker', boom))
        elif place in ('http', 'udp', 'dns-tcp'):
            self.enterContext(patch.object(entry, 'answer', boom))
        elif place == 'https':
            self.enterContext(patch.object(entry, 'https_exchange', boom))
        elif place == 'dns':
            self.enterContext(patch.object(entry, 'dns_loop', boom))
        elif place == 'doh':
            self.enterContext(patch.object(entry, 'doh_loop', boom))
        elif place == 'node':
            self.enterContext(patch.object(entry, 'start_process', boom))
        elif place == 'setup':
            self.enterContext(patch.object(entry, 'bind_targets', boom))
        observer.start()
        if place in ('node', 'setup', 'finish'):
            observer.thread.join(10)
        else:
            observer.wait_ready()
            if place == 'capture':
                observer.capture.feed(b'\x00' * 20)
            elif place == 'marker':
                observer.sendto((4, 'marker'), b'any')
            elif place in ('http', 'udp', 'dns-tcp'):
                observer.poke(place)
            elif place == 'https':
                socket.create_connection(observer.addresses[(4, 'https')], 3).close()
            # The server threads of DNS fail on their own while the loop goes on until it is stopped.
            if place not in ('dns', 'doh'):
                observer.thread.join(10)
        return observer, observer.finish()

    def test_each_place_is_named_where_the_observer_stopped(self):
        for place in wire.OBSERVER_PLACES:
            with self.subTest(place=place):
                observer, health = self.stopped_by(place)
                self.assertEqual((True, place), (health['error'], health['error_in']))
                self.assertRegex(health['error_reason'], '^(Boom:injected|ValueError:capture-deadline)$')
                self.assertIsInstance(health['error_at'], float)
                self.assertTrue(health['finished'])
                self.assertIsInstance(observer.error, ValueError)
                self.assertEqual('observer-unverified', str(observer.error))

    def test_the_two_datagram_services_name_themselves_by_the_place_they_share(self):
        for service in ('udp', 'dns-udp'):
            with self.subTest(service=service):
                observer = Observer(self)
                observer.start().wait_ready()
                probe = next(p for p in observer.request['probes'] if p['service'] == service and p['family'] == 4)
                self.enterContext(patch.object(self.entry, 'answer', side_effect=Boom('injected')))
                observer.poke(probe['service'])
                observer.thread.join(10)
                self.assertEqual('udp', observer.finish()['error_in'])

    def test_the_deadline_is_a_failure_to_finish_and_the_reason_says_so(self):
        _, health = self.stopped_by('finish')
        self.assertEqual(('finish', 'ValueError:capture-deadline'), (health['error_in'], health['error_reason']))

    def test_a_clean_run_records_no_reason_and_keeps_its_old_shape(self):
        health = Observer(self).run()
        self.assertEqual({'error', 'dropped', 'finished', 'capture_started', 'capture_ended', 'markers'}, set(health))
        self.assertEqual((False, 0, True), (health['error'], health['dropped'], health['finished']))

    def test_only_the_first_failure_is_kept(self):
        observer = Observer(self, dns=True)

        def late(*args):
            time.sleep(.3)
            raise ValueError('second')
        self.enterContext(patch.object(self.entry, 'dns_loop', side_effect=Boom('first')))
        self.enterContext(patch.object(self.entry, 'doh_loop', late))
        health = observer.run()
        self.assertEqual('dns', health['error_in'])
        self.assertEqual('Boom:first', health['error_reason'])

    def test_a_dns_log_overflow_names_the_server_that_overflowed(self):
        for transport, place in (('udp', 'dns'), ('tcp', 'dns'), ('doh', 'doh')):
            with self.subTest(transport=transport):
                log = self.entry.DnsLog()
                with patch.object(self.entry, 'DNS_LOG_ENTRIES', 1):
                    for _ in range(3):
                        log.record('192.0.2.2', transport, ('x.lab.test', 'A'))
                self.assertEqual((True, place), (log.overflow, log.overflow_in))

    def test_a_failure_while_closing_still_leaves_a_health_record_with_the_reason(self):
        with tempfile.TemporaryDirectory() as temp:
            device = Path(temp) / 'evidence'
            device.write_bytes(bytes(wire.EVIDENCE_HEADER_SIZE + 4096))
            observer = Observer(self, evidence_disk=True)

            def finish(writer, *, complete):
                writer.stream.close()
                raise OSError(errno.EIO, 'Input/output error')
            self.enterContext(patch.object(self.entry, 'evidence_device', lambda: device))
            self.enterContext(patch.object(self.entry.EvidenceWriter, 'finish', finish))
            health = observer.run()
        self.assertEqual((True, 'finish', 'OSError:eio'), (health['error'], health['error_in'], health['error_reason']))

    def test_a_failure_before_the_capture_exists_is_recorded_too(self):
        observer = Observer(self)
        self.enterContext(patch.object(self.entry, 'open_capture', side_effect=PermissionError(errno.EPERM, 'no')))
        observer.start().thread.join(10)
        health = observer.finish()
        self.assertEqual(('capture', 'PermissionError:eperm', None), (
            health['error_in'], health['error_reason'], health['capture_started']))


if __name__ == '__main__':
    unittest.main()
