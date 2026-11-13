"""The lab's resolver and DoH target: wire logic and connection handling, with every system call replaced."""
import base64
import json
from pathlib import Path
import socket
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch

from tools.vm.matrix import lab_protocol as wire
from tools.vm.matrix.tests.test_lab_fixtures import Base


def query(name='example.com', qtype=1, qclass=1, flags=0x0100, identifier=0x1234, count=1, extra=b''):
    labels = b''.join(bytes([len(part)]) + part for part in name.encode().split(b'.')) + b'\0'
    return struct.pack('!HHHHHH', identifier, flags, count, 0, 0, 0) + labels + struct.pack('!HH', qtype, qclass) + extra


def fields(reply):
    return struct.unpack('!HHHHHH', reply[:12])


class ResolverTests(unittest.TestCase):
    def test_an_a_question_gets_the_one_fixed_address_and_a_log_entry(self):
        packet = query()
        reply, entry = wire.dns_reply(packet)
        self.assertEqual(('example.com', 'A'), entry)
        identifier, flags, questions, answers, authority, additional = fields(reply)
        self.assertEqual((0x1234, 0x8500, 1, 1, 0, 0), (identifier, flags, questions, answers, authority, additional))
        self.assertEqual(packet[12:], reply[12:len(packet)])
        self.assertEqual(b'\xc0\x0c\x00\x01\x00\x01' + struct.pack('!IH', wire.DNS_TTL, 4) + bytes([203, 0, 113, 2]),
                         reply[len(packet):])

    def test_recursion_is_neither_offered_nor_done(self):
        reply, _ = wire.dns_reply(query(flags=0x0100))
        self.assertEqual(0, fields(reply)[1] & 0x0080)
        reply, _ = wire.dns_reply(query(flags=0x0000))
        self.assertEqual(0x8400, fields(reply)[1])

    def test_aaaa_and_every_other_type_or_class_is_an_empty_noerror(self):
        for name, packet, kind in (('aaaa', query(qtype=28), 'AAAA'), ('txt', query(qtype=16), '16'),
                                   ('any', query(qtype=255), '255'), ('chaos', query(qclass=3), 'A'),
                                   ('a-in-any-class', query(qclass=255), 'A')):
            with self.subTest(name=name):
                reply, entry = wire.dns_reply(packet)
                self.assertEqual(('example.com', kind), entry)
                self.assertEqual((0x1234, 0x8500, 1, 0), fields(reply)[:4])
                self.assertEqual(len(packet), len(reply))

    def test_a_question_with_extra_records_is_answered_without_them(self):
        reply, entry = wire.dns_reply(query(extra=b'\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00'))
        self.assertIsNotNone(entry)
        self.assertEqual(1, fields(reply)[3])

    def test_a_cut_question_is_a_format_error_that_echoes_the_identifier(self):
        whole = query()
        for size in (13, 20, len(whole) - 3):
            with self.subTest(size=size):
                reply, entry = wire.dns_reply(whole[:size])
                self.assertIsNone(entry)
                self.assertEqual((0x1234, 0x8001, 0, 0, 0, 0), fields(reply))

    def test_garbage_is_a_format_error_or_silence_and_never_a_log_entry(self):
        for name, packet, rcode in (('short', b'\x12\x34\x01', None), ('empty', b'', None),
                                    ('response', query(flags=0x8180), None),
                                    ('two-questions', query(count=2), 1), ('no-question', query(count=0), 1),
                                    ('compressed', query()[:12] + b'\xc0\x0c\x00\x01\x00\x01', 1),
                                    ('opcode', query(flags=0x1000), 4),
                                    ('long-name', query(name='.'.join(['a' * 60] * 5)), 1)):
            with self.subTest(name=name):
                reply, entry = wire.dns_reply(packet)
                self.assertIsNone(entry)
                if rcode is None:
                    self.assertIsNone(reply)
                else:
                    self.assertEqual(0x8000 | rcode, fields(reply)[1])

    def test_a_long_name_is_logged_cut(self):
        _, entry = wire.dns_reply(query(name='.'.join(['a' * 30] * 6)))
        self.assertEqual(wire.DNS_NAME_LOG, len(entry[0]))


class HeadTests(unittest.TestCase):
    def test_a_request_head_is_method_target_and_lowercase_headers(self):
        head = b'POST /dns-query HTTP/1.1\r\nHost: 203.0.113.3\r\nContent-Type: application/dns-message\r\n'
        self.assertEqual(('POST', '/dns-query', {'host': '203.0.113.3', 'content-type': 'application/dns-message'}),
                         wire.parse_request_head(head.rstrip(b'\r\n')))

    def test_anything_but_a_plain_http_1_1_head_is_refused(self):
        for head in (b'GET / HTTP/1.0', b'GET /', b'GET x HTTP/1.1', b'G3T / HTTP/1.1', b'\xff / HTTP/1.1',
                     b'GET / HTTP/1.1\r\nno-colon', b'GET / HTTP/1.1\r\n : x',
                     b'GET / HTTP/1.1\r\nA: 1\r\na: 2', b'GET / HTTP/1.1 extra'):
            with self.subTest(head=head), self.assertRaises(ValueError):
                wire.parse_request_head(head)

    def test_a_response_has_an_exact_length_and_a_connection_state(self):
        raw = wire.http_response(200, {'content-type': 'x/y'}, b'abc', close=False)
        self.assertTrue(raw.startswith(b'HTTP/1.1 200 OK\r\n'))
        self.assertIn(b'content-length: 3\r\n', raw)
        self.assertIn(b'connection: keep-alive\r\n', raw)
        self.assertTrue(raw.endswith(b'\r\n\r\nabc'))
        self.assertIn(b'connection: close\r\n', wire.http_response(404, {}, b'', close=True))


class DohTests(unittest.TestCase):
    TYPE = {'content-type': 'application/dns-message'}

    def get_target(self, packet, padded=False):
        value = base64.urlsafe_b64encode(packet).decode()
        return wire.DOH_PATH + '?dns=' + (value if padded else value.rstrip('='))

    def test_a_post_with_the_dns_message_type_is_answered(self):
        packet = query()
        status, headers, body, entry = wire.doh_reply('POST', '/dns-query', self.TYPE, packet)
        self.assertEqual((200, ('example.com', 'A')), (status, entry))
        self.assertEqual('application/dns-message', headers['content-type'])
        self.assertEqual(wire.dns_reply(packet)[0], body)

    def test_a_content_type_parameter_and_case_are_accepted(self):
        status, *_ = wire.doh_reply('POST', '/dns-query', {'content-type': 'Application/DNS-Message; x=1'}, query())
        self.assertEqual(200, status)

    def test_a_get_with_the_message_in_base64url_is_answered_padded_or_not(self):
        packet = query(name='a.example.com', qtype=28)
        for padded in (False, True):
            with self.subTest(padded=padded):
                status, _, body, entry = wire.doh_reply('GET', self.get_target(packet, padded), {}, b'')
                self.assertEqual((200, ('a.example.com', 'AAAA')), (status, entry))
                self.assertEqual(wire.dns_reply(packet)[0], body)

    def test_the_wrong_path_gets_404_whatever_the_method(self):
        for method in ('GET', 'POST', 'PUT'):
            for target in ('/', '/dns-query/', '/dns-queryx', '/other?dns=AAAA'):
                with self.subTest(method=method, target=target):
                    self.assertEqual(404, wire.doh_reply(method, target, self.TYPE, query())[0])

    def test_any_other_method_gets_405_naming_the_allowed_ones(self):
        for method in ('PUT', 'DELETE', 'HEAD', 'OPTIONS'):
            with self.subTest(method=method):
                status, headers, _, entry = wire.doh_reply(method, '/dns-query', self.TYPE, b'')
                self.assertEqual((405, 'GET, POST', None), (status, headers['allow'], entry))

    def test_a_post_with_another_content_type_gets_415(self):
        for headers in ({}, {'content-type': 'application/json'}, {'content-type': 'text/plain'}):
            with self.subTest(headers=headers):
                self.assertEqual(415, wire.doh_reply('POST', '/dns-query', headers, query())[0])

    def test_a_body_over_the_limit_gets_413_and_one_at_the_limit_is_read(self):
        big = query(extra=bytes(wire.DOH_BODY_LIMIT))
        self.assertGreater(len(big), wire.DOH_BODY_LIMIT)
        self.assertEqual(413, wire.doh_reply('POST', '/dns-query', self.TYPE, big)[0])
        exact = query(extra=bytes(wire.DOH_BODY_LIMIT - len(query())))
        self.assertEqual(wire.DOH_BODY_LIMIT, len(exact))
        self.assertEqual(200, wire.doh_reply('POST', '/dns-query', self.TYPE, exact)[0])
        self.assertEqual(413, wire.doh_reply('GET', self.get_target(big), {}, b'')[0])

    def test_a_get_without_a_usable_message_gets_400(self):
        for target in ('/dns-query', '/dns-query?', '/dns-query?other=1', '/dns-query?dns=a&dns=b',
                       '/dns-query?dns=***', '/dns-query?dns=A', '/dns-query?dns='):
            with self.subTest(target=target):
                self.assertEqual(400, wire.doh_reply('GET', target, {}, b'')[0])

    def test_a_message_the_resolver_cannot_read_gets_400_not_an_error_packet(self):
        for body in (b'', b'\x00', query()[:15], query(count=2), query(flags=0x8100)):
            with self.subTest(body=body):
                status, _, payload, entry = wire.doh_reply('POST', '/dns-query', self.TYPE, body)
                self.assertEqual((400, b'', None), (status, payload, entry))


class Stream:
    """A TLS stream whose bytes are scripted: what the client sends and what the server wrote back."""

    def __init__(self, *chunks):
        self.chunks, self.sent = list(chunks), b''

    def recv(self, size):
        return self.chunks.pop(0) if self.chunks else b''

    def sendall(self, data):
        self.sent += data


def post(packet, extra=''):
    return (b'POST /dns-query HTTP/1.1\r\nHost: 203.0.113.3\r\nContent-Type: application/dns-message\r\n'
            + extra.encode() + b'Content-Length: ' + str(len(packet)).encode() + b'\r\n\r\n' + packet)


class ConnectionTests(Base):
    def log(self):
        return self.entry.DnsLog()

    def test_two_requests_in_one_connection_are_both_answered_and_logged(self):
        log = self.log()
        stream = Stream(post(query()) + post(query('b.example.com', 28))[:30], post(query('b.example.com', 28))[30:])
        self.entry.doh_connection(stream, (wire.CLIENTS[4], 40000), log)
        self.assertEqual(2, stream.sent.count(b'HTTP/1.1 200 OK'))
        self.assertEqual([dict(source=wire.CLIENTS[4], transport='doh', name='example.com', type='A'),
                          dict(source=wire.CLIENTS[4], transport='doh', name='b.example.com', type='AAAA')], log.rows)

    def test_a_request_asking_to_close_is_the_last_one(self):
        stream = Stream(post(query(), 'Connection: close\r\n') + post(query()))
        self.entry.doh_connection(stream, ('x', 1), self.log())
        self.assertEqual(1, stream.sent.count(b'HTTP/1.1 200 OK'))
        self.assertIn(b'connection: close', stream.sent)

    def test_the_connection_ends_after_the_request_limit(self):
        stream = Stream(post(query()) * (self.entry.DOH_REQUESTS + 4))
        self.entry.doh_connection(stream, ('x', 1), self.log())
        self.assertEqual(self.entry.DOH_REQUESTS, stream.sent.count(b'HTTP/1.1 200 OK'))

    def test_an_oversized_body_is_refused_with_413_before_it_is_read_and_closes(self):
        head = (b'POST /dns-query HTTP/1.1\r\nContent-Type: application/dns-message\r\nContent-Length: 100000\r\n\r\n')
        stream = Stream(head)
        self.entry.doh_connection(stream, ('x', 1), self.log())
        self.assertTrue(stream.sent.startswith(b'HTTP/1.1 413 '))
        self.assertIn(b'connection: close', stream.sent)

    def test_a_malformed_request_gets_400_and_closes(self):
        for name, raw in (('http-1-0', b'GET /dns-query HTTP/1.0\r\n\r\n'),
                          ('chunked', b'POST /dns-query HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n'),
                          ('bad-length', b'POST /dns-query HTTP/1.1\r\nContent-Length: x\r\n\r\n'),
                          ('cut-body', b'POST /dns-query HTTP/1.1\r\nContent-Length: 40\r\n\r\nabc'),
                          ('endless-head', b'GET /dns-query HTTP/1.1\r\nX: ' + b'a' * 9000)):
            with self.subTest(name=name):
                stream = Stream(raw)
                self.entry.doh_connection(stream, ('x', 1), self.log())
                self.assertTrue(stream.sent.startswith(b'HTTP/1.1 400 '))

    def test_a_refused_request_is_answered_and_not_logged(self):
        log = self.log()
        stream = Stream(b'GET /elsewhere HTTP/1.1\r\n\r\n')
        self.entry.doh_connection(stream, ('x', 1), log)
        self.assertTrue(stream.sent.startswith(b'HTTP/1.1 404 '))
        self.assertEqual([], log.rows)

    def test_the_log_keeps_256_rows_and_no_more_and_remembers_the_overflow(self):
        log = self.log()
        for number in range(256):
            log.record('192.0.2.2', 'udp', ('example.com', 'A'))
        self.assertEqual((256, False), (len(log.rows), log.overflow))
        log.record('192.0.2.2', 'udp', ('example.com', 'A'))
        self.assertEqual((256, True), (len(log.rows), log.overflow))
        big = self.log()
        for number in range(256):
            big.record('192.0.2.2', 'tcp', ('a' * wire.DNS_NAME_LOG, 'A'))
            if big.overflow:
                break
        self.assertTrue(big.overflow)
        self.assertLessEqual(len(json.dumps(big.rows)), wire.LOG_LIMIT)

    def test_the_tls_context_offers_http_1_1_only_and_the_doh_certificate(self):
        calls = []

        class Context:
            def __init__(self, protocol):
                calls.append(('protocol', protocol))

            def set_alpn_protocols(self, protocols):
                calls.append(('alpn', protocols))

            def load_cert_chain(self, cert, key):
                calls.append(('chain', cert, key))

            minimum_version = None
        with patch.object(self.entry.ssl, 'SSLContext', Context):
            context = self.entry.doh_context()
        self.assertEqual([('protocol', self.entry.ssl.PROTOCOL_TLS_SERVER), ('alpn', ['http/1.1']),
                          ('chain', str(self.entry.DOH_CERT), str(self.entry.DOH_KEY))], calls)
        self.assertEqual(self.entry.ssl.TLSVersion.TLSv1_2, context.minimum_version)
        self.assertEqual(('doh-cert.pem', 'doh-key.pem'), (self.entry.DOH_CERT.name, self.entry.DOH_KEY.name))


class ServerTests(Base):
    def test_udp_and_tcp_questions_are_answered_and_logged_until_told_to_stop(self):
        log, stop = self.entry.DnsLog(), threading.Event()
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        for sock in (udp, tcp):
            self.addCleanup(sock.close)
            sock.bind(('127.0.0.1', 0))
        tcp.listen(4)
        thread = threading.Thread(target=self.entry.dns_loop, args=(udp, tcp, log, stop))
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(stop.set)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(5)
            client.sendto(query('u.example.com'), udp.getsockname())
            self.assertEqual(wire.dns_reply(query('u.example.com'))[0], client.recvfrom(512)[0])
            # Garbage is dropped without an answer and does not end the loop.
            client.sendto(b'\x00', udp.getsockname())
        with socket.create_connection(tcp.getsockname(), timeout=5) as client:
            packet = query('t.example.com', 28)
            client.sendall(struct.pack('!H', len(packet)) + packet)
            size = int.from_bytes(client.recv(2), 'big')
            self.assertEqual(wire.dns_reply(packet)[0], client.recv(size))
        with socket.create_connection(tcp.getsockname(), timeout=5) as client:
            client.sendall(struct.pack('!H', 4000))
            client.settimeout(5)
            self.assertEqual(b'', client.recv(10))
        self.assertEqual([('127.0.0.1', 'udp', 'u.example.com', 'A'), ('127.0.0.1', 'tcp', 't.example.com', 'AAAA')],
                         [(r['source'], r['transport'], r['name'], r['type']) for r in log.rows])


class RequestTests(Base):
    def test_only_a_true_dns_flag_is_a_request_for_the_resolver(self):
        plain = {k: v for k, v in self.request.items() if k != 'tunnel'}
        self.assertEqual('enp7s0', self.identity(dict(plain, dns=True)))
        for value in (False, 1, 'yes', None, {}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.identity(dict(plain, dns=value))

    def test_a_run_cannot_turn_the_resolver_on_after_the_claim(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            saved = dict(self.request, operation='serve', interface='enp7s0', lab_id=directory.name)
            (directory / 'identity.json').write_text(json.dumps(saved))
            with patch.object(self.entry, 'identity', return_value='enp7s0'), \
                    patch.object(self.entry, 'ROOT', directory.parent), \
                    patch.object(self.entry, 'serve') as serve:
                with self.assertRaises(ValueError):
                    self.entry.main(dict(saved, dns=True))
                serve.assert_not_called()

    def test_setup_refuses_before_any_network_change_when_the_doh_files_are_missing(self):
        plain = {k: v for k, v in self.request.items() if k != 'tunnel'}
        with patch.object(self.entry, 'command', side_effect=AssertionError('network change')), \
                patch.object(self.entry, 'lstat', side_effect=FileNotFoundError):
            with self.assertRaisesRegex(self.entry.Refused, 'missing-doh-certificate'):
                self.entry.setup(dict(plain, dns=True), 'enp7s0', Path('unused'))

    def test_the_doh_files_are_checked_with_the_key_private(self):
        calls = []
        with patch.object(self.entry, 'fixture', lambda path, reason, **kw: calls.append((path, reason, kw))):
            self.entry.check_dns_fixtures()
        self.assertEqual([(self.entry.DOH_CERT, 'missing-doh-certificate', {}),
                          (self.entry.DOH_KEY, 'missing-doh-key', dict(private=True))], calls)

    def run_setup(self, request):
        commands = []
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory / 'ready.json').write_text('{}')
            child = type('Child', (), {'poll': lambda self: None})()
            with patch.object(self.entry, 'command', lambda *args: commands.append(args)), \
                    patch.object(self.entry, 'check_dns_fixtures'), \
                    patch.object(self.entry, 'check_lab_fixtures'), \
                    patch.object(self.entry.subprocess, 'Popen', return_value=child), \
                    patch.object(Path, 'write_text'):
                self.entry.setup(request, 'enp7s0', directory)
        return commands

    def test_the_resolver_and_the_doh_address_exist_in_the_namespace_only_on_request(self):
        plain = {k: v for k, v in self.request.items() if k != 'tunnel'}
        def added(commands):
            return [c[c.index('add') + 1] for c in commands if c[:4] == ('/usr/sbin/ip', 'netns', 'exec', 'rtlab')
                    and 'addr' in c and 'add' in c and 'rt-target' in c]
        self.assertEqual(['203.0.113.2/24', '2001:db8:6a:2::2/64'], added(self.run_setup(plain)))
        self.assertEqual(['203.0.113.2/24', '2001:db8:6a:2::2/64', '203.0.113.53/24', '203.0.113.3/24'],
                         added(self.run_setup(dict(plain, dns=True))))


if __name__ == '__main__':
    unittest.main()
