"""The HTTPS target of an L3 run: any GET and HEAD is answered and counted, nothing a client does stops the observer."""
import socket
import ssl
import struct
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.vm.matrix import l3_lab, lab_protocol as wire
from tools.vm.matrix.tests.test_lab_fixtures import Base, Connection
from tools.vm.matrix.tests.test_lab_observer import LOOPBACK, Observer, ObserverCase

# The second address of the loopback net stands for the node's exit, the first for the test machine.
EXIT = '127.0.0.2'


class Plain:
    """A TLS connection whose handshake the test does not run: the bytes of a plain loopback socket."""

    def __init__(self, sock):
        self.sock = sock

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.sock.close()
        return False

    def __getattr__(self, name):
        return getattr(self.sock, name)

    def unwrap(self):
        pass


PLAIN = SimpleNamespace(wrap_socket=lambda sock, server_side: Plain(sock))


class HalfOpened:
    """A context whose handshake reads the start of a hello and then finds the client gone."""

    def wrap_socket(self, sock, server_side):
        # Peeking leaves the bytes of a client that does go on for the exchange to read.
        if len(sock.recv(5, socket.MSG_PEEK)) < 5:
            raise ssl.SSLEOFError(8, 'EOF occurred in violation of protocol')
        return Plain(sock)


def get(path='/', version='1.1', method='GET'):
    return ('%s %s HTTP/%s\r\nHost: 203.0.113.2\r\nUser-Agent: curl\r\n\r\n' % (method, path, version)).encode()


class ExchangeTests(Base):
    """`l3_exchange` on a connection that is not TLS: what is answered, what is written and what is refused."""

    def exchange(self, request, source=wire.CLIENTS[4]):
        connection = Connection(request)
        context = SimpleNamespace(wrap_socket=lambda sock, server_side: sock)
        with patch.object(self.entry.time, 'monotonic', return_value=7.5):
            result = self.entry.l3_exchange(connection, (source, 40000), context, self.request)
        return result, connection

    def test_get_and_head_of_both_versions_get_a_short_body_without_a_nonce_and_a_closed_connection(self):
        for version in ('1.0', '1.1'):
            for method in ('GET', 'HEAD'):
                for path in ('/', '/any/path?x=1'):
                    with self.subTest(version=version, method=method, path=path):
                        (row, counted, path_class), connection = self.exchange(get(path, version, method))
                        head, _, body = connection.sent.partition(b'\r\n\r\n')
                        self.assertTrue(head.startswith(('HTTP/%s 200 OK\r\n' % version).encode()))
                        self.assertIn(b'Content-Length: %d' % len(self.entry.L3_BODY), head)
                        self.assertIn(b'Connection: close', head)
                        self.assertEqual(b'' if method == 'HEAD' else self.entry.L3_BODY, body)
                        self.assertNotIn(b'rosetun-lab-https', connection.sent)
                        self.assertEqual((method, 'root' if path == '/' else 'other'), (counted, path_class))
                        self.assertEqual(dict(source=wire.CLIENTS[4], port=40000, method=method,
                                              path_class=path_class, at=7.5), row)
                        self.assertTrue(connection.unwrapped)

    def test_an_exchange_of_stage_7b1_is_still_known_by_its_exact_request(self):
        direct, via_node = self.tunnel['https']
        exact = b'GET ' + direct['path'].encode() + b' HTTP/1.0\r\n\r\n'
        (row, method, path_class), connection = self.exchange(exact)
        self.assertEqual(dict(source=wire.CLIENTS[4], port=40000, path=direct['path'], at=7.5), row)
        self.assertEqual(('GET', 'other'), (method, path_class))
        self.assertTrue(connection.sent.endswith(b'\r\n\r\n' + wire.https_answer(direct)))
        # The same path asked in another shape is an ordinary request and gets no nonce.
        (row, _, _), connection = self.exchange(get(via_node['path'], '1.1'))
        self.assertNotIn('path', row)
        self.assertNotIn(wire.https_answer(via_node), connection.sent)

    def test_what_is_not_a_get_or_a_head_of_http_1_is_refused_with_its_reason(self):
        for name, request, reason in (('post', get(method='POST'), 'unsupported-method'),
                                      ('options', get(method='OPTIONS'), 'unsupported-method'),
                                      ('http-2', get(version='2.0'), 'unsupported-version'),
                                      ('no-version', b'GET /\r\n\r\n', 'bad-http-request'),
                                      ('no-slash', b'GET x HTTP/1.1\r\n\r\n', 'bad-http-request'),
                                      ('not-ascii', b'GET /\xff HTTP/1.1\r\n\r\n', 'bad-http-request'),
                                      ('cut-short', b'GET / HTTP/1.1\r\nHost: x\r\n', 'short-request'),
                                      ('empty', b'', 'short-request'),
                                      ('too-long', b'GET /' + b'a' * 5000, 'request-limit')):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, '^' + reason + '$'):
                self.exchange(request)

    def test_a_source_that_is_neither_the_test_machine_nor_the_exit_of_the_node_is_refused_unread(self):
        connection = Connection(get())
        with self.assertRaisesRegex(ValueError, '^unexpected-request$'):
            self.entry.l3_exchange(connection, ('198.51.100.9', 40000), SimpleNamespace(
                wrap_socket=lambda sock, server_side: self.fail('a handshake was started')), self.request)
        (row, _, _), _ = self.exchange(get(), source=wire.EGRESS)
        self.assertEqual(wire.EGRESS, row['source'])

    def test_a_client_that_sends_a_byte_at_a_time_runs_out_of_time(self):
        class Slow(Connection):
            def recv(self, size):
                clock[0] += 3
                return b'x'
        clock = [100.0]
        with patch.object(self.entry.time, 'monotonic', side_effect=lambda: clock[0]), \
                self.assertRaisesRegex(TimeoutError, 'request-timeout'):
            self.entry.l3_exchange(Slow(b''), (wire.CLIENTS[4], 40000),
                                   SimpleNamespace(wrap_socket=lambda sock, server_side: sock), self.request)


class LogTests(Base):
    def row(self, source=wire.CLIENTS[4], port=40000):
        return dict(source=source, port=port, method='GET', path_class='root', at=1.0)

    def test_the_document_is_the_first_rows_then_one_element_of_counters(self):
        log = self.entry.HttpsLog()
        log.served(self.row(), 'GET', 'root')
        log.served(self.row(wire.EGRESS, 51000), 'HEAD', 'other')
        log.served(self.row(port=40001), 'GET', 'root')
        log.refused(ValueError('short-request'))
        document = log.document()
        self.assertEqual([self.row(), self.row(wire.EGRESS, 51000), self.row(port=40001),
                          dict(service='https', family=4, reason='short-request')], document[:4])
        self.assertEqual(dict(kind='counts', rows_dropped=0, counts_dropped=0, counts=[
            dict(source=wire.CLIENTS[4], method='GET', path_class='root', count=2),
            dict(source=wire.EGRESS, method='HEAD', path_class='other', count=1)]), document[4])
        self.assertEqual(5, len(document))

    def test_more_rows_than_sixteen_are_counted_and_dropped_not_an_error(self):
        log = self.entry.HttpsLog()
        for number in range(100):
            log.served(self.row(port=40000 + number), 'GET', 'root')
        document = log.document()
        self.assertEqual(16, len(document) - 1)
        self.assertEqual((84, 0, 100), (document[-1]['rows_dropped'], document[-1]['counts_dropped'],
                                        document[-1]['counts'][0]['count']))

    def test_refusals_do_not_use_the_places_of_the_rows(self):
        log = self.entry.HttpsLog()
        for _ in range(20):
            log.refused(ValueError('timeout'))
        for number in range(16):
            log.served(self.row(port=number), 'GET', 'root')
        document = log.document()
        self.assertEqual((8, 16, 0), (sum('reason' in row for row in document), sum('method' in row for row in document),
                                      document[-1]['rows_dropped']))

    def test_more_counters_than_the_limit_are_dropped_and_the_known_ones_keep_counting(self):
        log = self.entry.HttpsLog()
        with patch.object(self.entry, 'HTTPS_COUNT_KEYS', 2):
            for method, path_class in (('GET', 'root'), ('GET', 'other'), ('HEAD', 'root'), ('HEAD', 'other'),
                                       ('GET', 'root')):
                log.served(self.row(), method, path_class)
        counts = log.document()[-1]
        self.assertEqual((2, 2), (len(counts['counts']), counts['counts_dropped']))
        self.assertEqual(2, next(c['count'] for c in counts['counts'] if (c['method'], c['path_class']) == ('GET', 'root')))


class WorkerTests(Base):
    def test_a_failure_of_a_connection_is_a_refusal_row_and_never_an_exception(self):
        closed = []
        connection = SimpleNamespace(close=lambda: closed.append(True), settimeout=lambda value: None)
        log = self.entry.HttpsLog()
        context = SimpleNamespace(wrap_socket=lambda sock, server_side: (_ for _ in ()).throw(
            ssl.SSLEOFError(8, 'EOF occurred in violation of protocol')))
        self.entry.l3_worker(connection, (wire.CLIENTS[4], 40000), context, self.request, log)
        self.assertEqual([dict(service='https', family=4, reason='ssl-error')], log.document()[:-1])
        self.assertEqual([True], closed)


class ObserverTests(ObserverCase):
    """The real `serve` loop with a plain loopback stand-in for TLS and the loopback for the addresses."""

    def setUp(self):
        super().setUp()
        self.enterContext(patch.object(self.entry, 'CLIENTS', {4: LOOPBACK, 6: '::1'}))
        self.enterContext(patch.object(self.entry, 'EGRESS', EXIT))
        # The block is checked for the lab's own addresses, which the loopback does not have.
        self.enterContext(patch.object(self.entry, 'tunnel_of', lambda request: request.get('tunnel')))

    def observer(self, context=PLAIN, **kwargs):
        return Observer(self, tunnel=True, windows=True, context=context, **kwargs).start().wait_ready()

    def fetch(self, observer, request, source=LOOPBACK):
        """What the target says to one request, read until it closes the connection."""
        received = bytearray()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
            stream.settimeout(5)
            stream.bind((source, 0))
            stream.connect(observer.addresses[(4, 'https')])
            stream.sendall(request)
            try:
                while block := stream.recv(1024):
                    received.extend(block)
            except ConnectionError:
                pass
        return bytes(received)

    def document(self, observer):
        health = observer.finish()
        rows = observer.artifact('https.json')
        return health, rows[:-1], rows[-1]

    def test_get_and_head_of_both_versions_from_both_sources_are_answered_and_counted(self):
        observer = self.observer()
        for source in (LOOPBACK, EXIT):
            for version in ('1.0', '1.1'):
                for method in ('GET', 'HEAD'):
                    response = self.fetch(observer, get('/', version, method), source)
                    self.assertTrue(response.startswith(('HTTP/%s 200 OK' % version).encode()))
                    self.assertEqual(method == 'GET', response.endswith(self.entry.L3_BODY))
        health, rows, counts = self.document(observer)
        self.assertEqual((False, None), (health['error'], observer.error))
        self.assertEqual(8, len(rows))
        self.assertEqual(sorted((s, m, 'root', 2) for s in (LOOPBACK, EXIT) for m in ('GET', 'HEAD')),
                         sorted((c['source'], c['method'], c['path_class'], c['count']) for c in counts['counts']))

    def test_the_exchanges_of_stage_7b1_are_recorded_beside_the_requests_of_the_script(self):
        observer = self.observer()
        direct, via_node = observer.request['tunnel']['https']
        self.fetch(observer, get())
        answer = self.fetch(observer, b'GET ' + direct['path'].encode() + b' HTTP/1.0\r\n\r\n')
        self.fetch(observer, b'GET ' + via_node['path'].encode() + b' HTTP/1.0\r\n\r\n', EXIT)
        self.fetch(observer, get('/', '1.0', 'HEAD'), EXIT)
        health, rows, counts = self.document(observer)
        self.assertTrue(answer.endswith(wire.https_answer(direct)))
        self.assertEqual([None, direct['path'], via_node['path'], None], [row.get('path') for row in rows])
        self.assertEqual(['root', 'other', 'other', 'root'], [
            row.get('path_class') or 'other' for row in rows])
        self.assertEqual(4, sum(c['count'] for c in counts['counts']))
        self.assertFalse(health['error'])

    def test_a_tls_failure_in_the_middle_of_the_handshake_is_a_refusal_and_the_next_client_is_served(self):
        observer = self.observer(context=HalfOpened())
        with socket.create_connection(observer.addresses[(4, 'https')], 3) as stream:
            stream.sendall(b'\x16\x03\x01')
        response = self.fetch(observer, get('/', '1.0'))
        health, rows, counts = self.document(observer)
        self.assertEqual([dict(service='https', family=4, reason='ssl-error')], [r for r in rows if 'reason' in r])
        self.assertTrue(response.endswith(self.entry.L3_BODY))
        self.assertEqual(1, sum(c['count'] for c in counts['counts']))
        self.assertEqual((False, None), (health['error'], observer.error))
        self.assertNotIn('error_in', health)

    def test_a_request_cut_short_or_of_another_method_is_a_refusal_and_the_observer_goes_on(self):
        observer = self.observer()
        with socket.create_connection(observer.addresses[(4, 'https')], 3) as stream:
            stream.sendall(b'GET / HTTP/1.1\r\nHost: x\r\n')
        self.assertEqual(b'', self.fetch(observer, get(method='DELETE')))
        self.assertTrue(self.fetch(observer, get()).endswith(self.entry.L3_BODY))
        health, rows, counts = self.document(observer)
        self.assertEqual(['short-request', 'unsupported-method'], sorted(r['reason'] for r in rows if 'reason' in r))
        self.assertEqual((False, None), (health['error'], observer.error))

    def test_a_hundred_requests_in_a_row_are_counted_and_the_capture_is_never_stopped(self):
        observer = self.observer()
        frame = b'\x00' * 60
        for _ in range(3):
            observer.capture.feed(frame)
        for _ in range(100):
            self.assertTrue(self.fetch(observer, get()).endswith(self.entry.L3_BODY))
        for _ in range(3):
            observer.capture.feed(frame)
        time.sleep(.3)
        health, rows, counts = self.document(observer)
        self.assertEqual((False, 0, None), (health['error'], health['dropped'], observer.error))
        self.assertNotIn('error_in', health)
        self.assertEqual(16, len(rows))
        self.assertEqual((100, 84, 0), (counts['counts'][0]['count'], counts['rows_dropped'], counts['counts_dropped']))
        pcap = (observer.directory / 'capture.pcap').read_bytes()
        self.assertEqual(24 + 6 * (16 + len(frame)), len(pcap))
        self.assertEqual(6, sum(1 for offset in range(24, len(pcap), 16 + len(frame))
                                if struct.unpack_from('<I', pcap, offset + 8)[0] == len(frame)))

    def test_more_counters_than_the_limit_leave_the_observer_clean(self):
        observer = self.observer()
        with patch.object(self.entry, 'HTTPS_COUNT_KEYS', 2):
            for method, path in (('GET', '/'), ('GET', '/x'), ('HEAD', '/'), ('HEAD', '/x')):
                self.fetch(observer, get(path, method=method))
            health, rows, counts = self.document(observer)
        self.assertEqual((2, 2), (len(counts['counts']), counts['counts_dropped']))
        self.assertEqual((False, None), (health['error'], observer.error))

    def test_a_stalled_client_delays_neither_the_next_client_nor_the_capture(self):
        observer = self.observer(request_timeout=.6)
        frame = b'\x00' * 60
        stalled = socket.create_connection(observer.addresses[(4, 'https')], 3)
        self.addCleanup(stalled.close)
        began = time.monotonic()
        observer.capture.feed(frame)
        self.assertTrue(self.fetch(observer, get()).endswith(self.entry.L3_BODY))
        self.assertLess(time.monotonic() - began, .5)
        health, rows, counts = self.document(observer)
        self.assertEqual([dict(service='https', family=4, reason='timeout')], [r for r in rows if 'reason' in r])
        self.assertEqual((False, None), (health['error'], observer.error))
        self.assertEqual(24 + 16 + len(frame), len((observer.directory / 'capture.pcap').read_bytes()))

    def test_no_more_connections_than_the_limit_are_served_at_once(self):
        observer = self.observer(request_timeout=.6)
        with patch.object(self.entry, 'HTTPS_CONNECTIONS', 2):
            held = [socket.create_connection(observer.addresses[(4, 'https')], 3) for _ in range(2)]
            time.sleep(.2)
            self.assertEqual(b'', self.fetch(observer, get()))
            for stream in held:
                self.addCleanup(stream.close)
            health, rows, counts = self.document(observer)
        self.assertEqual(['connection-limit', 'timeout', 'timeout'], [r['reason'] for r in rows if 'reason' in r])
        self.assertEqual([], counts['counts'])
        self.assertEqual((False, None), (health['error'], observer.error))

    def test_a_run_that_is_not_an_l3_run_keeps_the_log_of_stage_7b1(self):
        observer = Observer(self, tunnel=True, context=PLAIN)
        observer.start().wait_ready()
        health = observer.finish()
        self.assertEqual([], observer.artifact('https.json'))
        self.assertFalse(health['error'])


class FixtureTests(unittest.TestCase):
    """What the controller makes of the target's log."""

    def counts(self, *entries):
        return dict(kind='counts', counts=[dict(source=s, method='GET', path_class='root', count=n) for s, n in entries],
                    rows_dropped=0, counts_dropped=0)

    def test_the_target_works_when_both_the_test_machine_and_the_exit_of_the_node_were_answered(self):
        log = [self.counts((wire.CLIENTS[4], 3), (wire.EGRESS, 40))]
        self.assertEqual(dict(answered=True, direct=True, via_node=True, requests=43), l3_lab.https_fixture(log))

    def test_an_answer_to_one_path_only_is_not_a_working_target(self):
        for sources, direct, via_node in (((wire.CLIENTS[4],), True, False), ((wire.EGRESS,), False, True), ((), False, False)):
            with self.subTest(sources=sources):
                log = [self.counts(*[(source, 5) for source in sources])]
                fixture = l3_lab.https_fixture(log)
                self.assertEqual((False, direct, via_node), (fixture['answered'], fixture['direct'], fixture['via_node']))

    def test_a_counter_of_zero_or_of_another_source_does_not_count(self):
        log = [self.counts((wire.CLIENTS[4], 4), (wire.EGRESS, 0), ('198.51.100.9', 7))]
        self.assertFalse(l3_lab.https_fixture(log)['answered'])

    def test_rows_and_refusals_alone_are_what_they_were_in_stage_7b1(self):
        direct = dict(source=wire.CLIENTS[4], port=1, path='/a', at=1.0)
        node = dict(source=wire.EGRESS, port=2, path='/b', at=2.0)
        refused = dict(service='https', family=4, reason='short-request')
        self.assertTrue(l3_lab.https_fixture([direct, refused, node])['answered'])
        self.assertFalse(l3_lab.https_fixture([direct, refused])['answered'])
        self.assertFalse(l3_lab.https_fixture([refused, refused])['answered'])
        self.assertEqual(dict(answered=False, direct=False, via_node=False, requests=0), l3_lab.https_fixture([]))

    def test_a_log_that_is_not_what_the_helper_writes_proves_nothing(self):
        for log in ([None, 3, 'x'], [dict(kind='counts', counts='many')], [dict(kind='counts', counts=[
                    dict(source=[1], count=3), dict(source=wire.EGRESS, count=True), 7])]):
            with self.subTest(log=log):
                self.assertFalse(l3_lab.https_fixture(log)['answered'])

    def test_the_block_of_a_run_reads_the_log_through_the_same_rule(self):
        health = dict(node=dict(alive_at_finish=True, exit_code=-15))
        logs = {'https.json': [self.counts((wire.CLIENTS[4], 1))], 'dns.json': []}
        block = l3_lab.fixtures_block(health, logs)
        self.assertEqual((False, True, False), (block['https']['answered'], block['https']['direct'],
                                               block['https']['via_node']))


if __name__ == '__main__':
    unittest.main()
