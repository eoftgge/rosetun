"""The VPN node and the HTTPS target of the lab helper, with every system call replaced."""
import importlib.util
import json
from pathlib import Path
import socket
import ssl
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.vm.matrix import lab, lab_protocol as wire

SING_BOX, CA = 'a' * 64, 'b' * 64


def load_entry():
    source = Path(lab.__file__).parents[1] / 'linux/guest/lab-entry.py'
    spec = importlib.util.spec_from_file_location('lab_entry_fixtures', source)
    entry = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {'lab_protocol': wire}):
        spec.loader.exec_module(entry)
    return entry


def tunnel_block(lab_id, nonces, **changes):
    block = dict(port=wire.NODE_PORT, method='aes-128-gcm', password='lab-only-fixed-password',
                 sing_box_sha256=SING_BOX, ca_sha256=CA, https=wire.https_exchanges(lab_id, nonces.__next__))
    block.update(changes)
    return block


class Base(unittest.TestCase):
    def setUp(self):
        self.entry = load_entry()
        nonces = iter(f'{i:024x}' for i in range(12))
        self.request = dict(role='lab', lab_id='a' * 32, vm_uuid='12345678-1234-4234-8234-123456789abc',
                            boot_id='22345678-1234-4234-8234-123456789abc', operation='setup', canary=False,
                            probes=wire.probes('a' * 32, nonces.__next__),
                            markers=wire.markers('a' * 32, nonces.__next__))
        self.request['tunnel'] = tunnel_block('a' * 32, nonces)
        self.tunnel = self.request['tunnel']

    def identity(self, request, role='lab'):
        values = {'/etc/rosetun-lab-role': role, '/proc/sys/kernel/random/boot_id': request['boot_id'],
                  '/sys/class/dmi/id/product_uuid': request['vm_uuid']}
        rows = json.dumps([dict(ifname='enp7s0', address=wire.MACS[role], link_type='ether')]).encode()
        with patch.object(self.entry.os, 'geteuid', return_value=0, create=True), \
                patch.object(Path, 'read_text', lambda p: values[p.as_posix()]), \
                patch.object(self.entry, 'command', return_value=rows):
            return self.entry.identity(dict(request, role=role))


class RequestTests(Base):
    def test_a_request_without_a_tunnel_block_is_what_stage_6b_sends(self):
        plain = {k: v for k, v in self.request.items() if k != 'tunnel'}
        self.assertEqual('enp7s0', self.identity(plain))
        self.assertIsNone(self.entry.tunnel_of(plain))

    def test_a_valid_tunnel_block_is_accepted_for_both_roles(self):
        self.assertEqual('enp7s0', self.identity(self.request))
        self.assertEqual('enp7s0', self.identity(self.request, role='test'))
        self.assertIs(self.tunnel, self.entry.tunnel_of(self.request))

    def test_every_malformed_tunnel_block_is_refused(self):
        first, second = self.tunnel['https']
        bad = {
            'null': None,
            'extra-key': dict(self.tunnel, extra=1),
            'missing-key': {k: v for k, v in self.tunnel.items() if k != 'ca_sha256'},
            'port-zero': dict(self.tunnel, port=0),
            'port-bool': dict(self.tunnel, port=True),
            'port-https': dict(self.tunnel, port=443),
            'port-http-fixture': dict(self.tunnel, port=8080),
            'port-socks': dict(self.tunnel, port=self.entry.SOCKS_PORT),
            'method': dict(self.tunnel, method='chacha20-ietf-poly1305'),
            'short-password': dict(self.tunnel, password='short'),
            'password-with-quote': dict(self.tunnel, password='lab"only-fixed-password'),
            'upper-case-hash': dict(self.tunnel, sing_box_sha256='A' * 64),
            'short-hash': dict(self.tunnel, ca_sha256='b' * 63),
            'one-exchange': dict(self.tunnel, https=[first]),
            'swapped-exchanges': dict(self.tunnel, https=[second, first]),
            'not-a-list': dict(self.tunnel, https='x'),
            'other-run': dict(self.tunnel, https=[dict(first, run_id='b' * 32), second]),
            'other-target': dict(self.tunnel, https=[first, dict(second, target='203.0.113.9')]),
            'other-source': dict(self.tunnel, https=[first, dict(second, source='192.0.2.9')]),
            'other-port': dict(self.tunnel, https=[first, dict(second, port=8443)]),
            'other-path': dict(self.tunnel, https=[first, dict(second, path='/x')]),
            'extra-field': dict(self.tunnel, https=[first, dict(second, extra=1)]),
            'repeated-nonce': dict(self.tunnel, https=[first, dict(second, nonce=first['nonce'],
                                                                   path=first['path'])]),
            'probe-nonce': dict(self.tunnel, https=[first, dict(
                second, nonce=self.request['probes'][0]['nonce'],
                path='/' + 'a' * 32 + '/' + self.request['probes'][0]['nonce'])]),
        }
        for name, block in bad.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.identity(dict(self.request, tunnel=block))

    def test_a_run_cannot_change_its_tunnel_block_after_the_claim(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            saved = dict(self.request)
            (directory / 'identity.json').write_text(json.dumps(saved))
            other = dict(self.request, tunnel=dict(self.tunnel, port=9001))
            with patch.object(self.entry, 'identity', return_value='enp7s0'), \
                    patch.object(self.entry, 'ROOT', directory.parent), \
                    patch.object(self.entry, 'serve') as serve:
                request = dict(saved, lab_id=directory.name, operation='serve', interface='enp7s0')
                (directory / 'identity.json').write_text(json.dumps(request))
                with self.assertRaises(ValueError):
                    self.entry.main(dict(request, tunnel=other['tunnel']))
                serve.assert_not_called()


class FixtureTests(Base):
    def stat_of(self, mode=0o100644, uid=0):
        return lambda path: SimpleNamespace(st_mode=mode, st_uid=uid)

    def test_a_missing_file_is_a_refusal_with_its_reason_not_a_skip(self):
        with tempfile.TemporaryDirectory() as temp, self.assertRaises(self.entry.Refused) as raised:
            self.entry.fixture(Path(temp) / 'absent', 'missing-sing-box')
        self.assertEqual('missing-sing-box', str(raised.exception))
        self.assertIsInstance(raised.exception, ValueError)

    def test_owner_mode_kind_and_hash_are_checked(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'file'
            path.write_bytes(b'inert')
            import hashlib
            digest = hashlib.sha256(b'inert').hexdigest()
            with patch.object(self.entry, 'lstat', self.stat_of()):
                self.entry.fixture(path, 'x', sha256=digest)
                with self.assertRaisesRegex(self.entry.Refused, 'x-hash'):
                    self.entry.fixture(path, 'x', sha256='0' * 64)
            for name, stat_of, private in (('foreign-owner', self.stat_of(uid=1000), False),
                                           ('group-writable', self.stat_of(mode=0o100664), False),
                                           ('directory', self.stat_of(mode=0o040755), False),
                                           ('readable-key', self.stat_of(mode=0o100644), True)):
                with self.subTest(name=name), patch.object(self.entry, 'lstat', stat_of), \
                        self.assertRaisesRegex(self.entry.Refused, 'x-unsafe'):
                    self.entry.fixture(path, 'x', private=private)
            with patch.object(self.entry, 'lstat', self.stat_of(mode=0o100600)):
                self.entry.fixture(path, 'x', private=True)

    def test_the_lab_checks_the_engine_the_certificate_and_the_key(self):
        calls = []
        with patch.object(self.entry, 'fixture', lambda path, reason, **kw: calls.append((path, reason, kw))):
            self.entry.check_lab_fixtures(self.tunnel)
        self.assertEqual([(self.entry.NODE_BINARY, 'missing-sing-box', dict(sha256=SING_BOX)),
                          (self.entry.HTTPS_CERT, 'missing-https-certificate', {}),
                          (self.entry.HTTPS_KEY, 'missing-https-key', dict(private=True))], calls)

    def test_setup_refuses_before_any_network_change_when_a_fixture_is_missing(self):
        with patch.object(self.entry, 'command', side_effect=AssertionError('network change')), \
                patch.object(self.entry, 'lstat', side_effect=FileNotFoundError):
            with self.assertRaisesRegex(self.entry.Refused, 'missing-sing-box'):
                self.entry.setup(self.request, 'enp7s0', Path('unused'))

    def test_the_test_machine_refuses_before_any_marker_when_its_engine_or_ca_is_missing(self):
        for missing in ('missing-sing-box', 'missing-ca-certificate'):
            def fixture(path, reason, **kw):
                if reason == missing:
                    raise self.entry.Refused(reason)
            with self.subTest(missing=missing), patch.object(self.entry, 'fixture', fixture), \
                    patch.object(self.entry, 'exchange_marker', side_effect=AssertionError('marker sent')):
                with self.assertRaisesRegex(self.entry.Refused, missing):
                    self.entry.probe_all(self.request)

    def test_the_helper_prints_the_reason_of_a_refusal_and_nothing_else(self):
        with patch.object(self.entry, 'main', side_effect=self.entry.Refused('missing-sing-box')), \
                patch.object(self.entry.sys, 'argv', ['entry', json.dumps(self.request)]), \
                patch('sys.stderr') as stderr, self.assertRaises(SystemExit) as raised:
            runpy_main(self.entry)
        self.assertEqual(2, raised.exception.code)
        self.assertIn('lab-helper-failed:missing-sing-box', ''.join(c.args[0] for c in stderr.write.call_args_list))


def runpy_main(entry):
    """Run the module's command-line block against the loaded module."""
    source = Path(entry.__file__).read_text()
    block = source[source.index("if __name__ == '__main__':"):]
    exec(compile(block.replace("if __name__ == '__main__':", 'if True:', 1), 'entry-main', 'exec'), vars(entry))


class ConfigTests(Base):
    def test_the_node_is_one_shadowsocks_inbound_on_the_lab_address_with_a_direct_exit(self):
        config = self.entry.node_config(self.tunnel)
        self.assertEqual({'log', 'inbounds', 'outbounds', 'route'}, set(config))
        self.assertEqual([dict(type='shadowsocks', tag='node-in', listen=wire.GATEWAYS[4],
                               listen_port=wire.NODE_PORT, method='aes-128-gcm',
                               password='lab-only-fixed-password')], config['inbounds'])
        self.assertEqual([dict(type='direct', tag='direct')], config['outbounds'])
        self.assertEqual({'final': 'direct'}, config['route'])
        self.assertNotIn('dns', config)

    def test_the_client_listens_on_loopback_only_and_leaves_through_the_node(self):
        config = self.entry.client_config(self.tunnel)
        self.assertEqual([dict(type='socks', tag='socks-in', listen='127.0.0.1',
                               listen_port=self.entry.SOCKS_PORT)], config['inbounds'])
        self.assertEqual([dict(type='shadowsocks', tag='node', server=wire.GATEWAYS[4],
                               server_port=wire.NODE_PORT, method='aes-128-gcm',
                               password='lab-only-fixed-password')], config['outbounds'])
        self.assertEqual({'final': 'node'}, config['route'])
        self.assertNotIn('dns', config)
        self.assertNotEqual('0.0.0.0', config['inbounds'][0]['listen'])


class LogTests(Base):
    def test_a_log_keeps_documentation_addresses_and_blanks_every_other(self):
        raw = (b'inbound/shadowsocks[node-in]: connection from 192.0.2.2:43000\n'
               b'outbound/direct[direct]: to 203.0.113.2:443 via 8.8.8.8 and 2001:db8::5 and 2606:4700::1111\n'
               b'listen [::1]:8388 10.1.2.3\n')
        text = self.entry.scrub_log(raw).decode()
        for kept in ('192.0.2.2', '203.0.113.2', '2001:db8::5'):
            self.assertIn(kept, text)
        for gone in ('8.8.8.8', '2606:4700::1111', '10.1.2.3', '::1'):
            self.assertNotIn(gone, text)
        self.assertIn('[address]', text)

    def test_a_log_is_cut_at_the_limit_and_may_hold_undecodable_bytes(self):
        text = self.entry.scrub_log(b'x' * (wire.LOG_LIMIT * 2))
        self.assertEqual(wire.LOG_LIMIT, len(text))
        self.assertTrue(self.entry.scrub_log(b'\xff\xfe broken'))


class ProcessTests(Base):
    TABLE = ('  sl  local_address rem_address   st\n'
             '   0: 010200C0:20C4 00000000:0000 0A 00000000:00000000\n'
             '   1: 0100007F:2A58 00000000:0000 0A 00000000:00000000\n'
             '   2: 010200C0:1F90 0100007F:0001 01 00000000:00000000\n')

    def test_listening_reads_the_kernel_table_for_a_listener_only(self):
        with tempfile.TemporaryDirectory() as temp:
            table = Path(temp) / 'tcp'
            table.write_text(self.TABLE)
            self.assertTrue(self.entry.listening('192.0.2.1', 8388, str(table)))
            self.assertTrue(self.entry.listening('127.0.0.1', 10840, str(table)))
            self.assertFalse(self.entry.listening('192.0.2.1', 8080, str(table)))
            self.assertFalse(self.entry.listening('192.0.2.1', 9999, str(table)))

    def process(self, polls):
        results = iter(polls)
        process = SimpleNamespace(returncode=None, terminated=0, killed=0)
        process.poll = lambda: next(results, None)
        process.terminate = lambda: setattr(process, 'terminated', process.terminated + 1)
        process.kill = lambda: setattr(process, 'killed', process.killed + 1)
        process.wait = lambda timeout: setattr(process, 'returncode', -15 if process.terminated else 0)
        return process

    def test_stop_reports_whether_the_process_was_alive_and_its_exit_code(self):
        running = self.process([None])
        self.assertEqual((True, -15), self.entry.stop_process(running))
        self.assertEqual(1, running.terminated)
        gone = self.process([3])
        gone.returncode = 3
        self.assertEqual((False, 3), self.entry.stop_process(gone))
        self.assertEqual(0, gone.terminated)

    def test_a_node_that_exits_or_never_listens_is_refused_and_not_left_running(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            dead = self.process([1])
            with patch.object(self.entry, 'spawn', return_value=dead), \
                    self.assertRaisesRegex(self.entry.Refused, 'node-exited'):
                self.entry.start_process(self.entry.node_config(self.tunnel), directory, 'node',
                                         wire.GATEWAYS[4], wire.NODE_PORT)
            silent = self.process([])
            with patch.object(self.entry, 'spawn', return_value=silent), \
                    patch.object(self.entry, 'listening', return_value=False), \
                    patch.object(self.entry.time, 'sleep'), \
                    self.assertRaisesRegex(self.entry.Refused, 'client-not-listening'):
                self.entry.start_process(self.entry.client_config(self.tunnel), directory, 'client',
                                         '127.0.0.1', self.entry.SOCKS_PORT)
            self.assertEqual(1, silent.terminated)

    def test_a_node_that_listens_is_returned_and_its_configuration_was_written_first(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            alive = self.process([])
            with patch.object(self.entry, 'spawn', return_value=alive) as spawn, \
                    patch.object(self.entry, 'listening', return_value=True) as listening:
                result = self.entry.start_process(self.entry.node_config(self.tunnel), directory, 'node',
                                                  wire.GATEWAYS[4], wire.NODE_PORT)
            self.assertIs(alive, result)
            self.assertEqual(self.entry.node_config(self.tunnel), json.loads((directory / 'node.json').read_text()))
            spawn.assert_called_once_with(directory / 'node.json', directory / 'node.stderr')
            listening.assert_called_with(wire.GATEWAYS[4], wire.NODE_PORT)


class Connection:
    """A server-side TLS connection whose handshake the test does not run."""

    def __init__(self, request):
        self.request, self.sent, self.timeout, self.unwrapped = request, b'', None, False

    def settimeout(self, value):
        self.timeout = value

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def recv(self, size):
        data, self.request = self.request[:size], self.request[size:]
        return data

    def sendall(self, data):
        self.sent += data

    def unwrap(self):
        self.unwrapped = True


class HttpsTargetTests(Base):
    def exchange(self, request, peer=(wire.CLIENTS[4], 40000), connection=None):
        connection = connection or Connection(request)
        context = SimpleNamespace(wrap_socket=lambda sock, server_side: sock)
        with patch.object(self.entry.time, 'monotonic', return_value=7.5):
            row = self.entry.https_exchange(connection, peer, context, self.request)
        return row, connection

    def get(self, exchange):
        return b'GET ' + exchange['path'].encode() + b' HTTP/1.0\r\n\r\n'

    def test_a_request_gets_the_nonce_answer_and_a_row_naming_source_port_and_path(self):
        direct, via_node = self.tunnel['https']
        row, connection = self.exchange(self.get(direct))
        self.assertEqual(dict(source=wire.CLIENTS[4], port=40000, path=direct['path'], at=7.5), row)
        self.assertTrue(connection.sent.startswith(b'HTTP/1.0 200 OK\r\nContent-Length: '))
        self.assertTrue(connection.sent.endswith(b'\r\n\r\n' + wire.https_answer(direct)))
        self.assertTrue(connection.unwrapped)
        row, _ = self.exchange(self.get(via_node), peer=(wire.EGRESS, 51000))
        self.assertEqual((wire.EGRESS, 51000, via_node['path']), (row['source'], row['port'], row['path']))

    def test_any_other_request_or_source_is_refused(self):
        direct = self.tunnel['https'][0]
        for name, request, peer in (('other-path', b'GET /x HTTP/1.0\r\n\r\n', wire.CLIENTS[4]),
                                    ('post', b'POST ' + direct['path'].encode() + b' HTTP/1.0\r\n\r\n', wire.CLIENTS[4]),
                                    ('http-1.1', b'GET ' + direct['path'].encode() + b' HTTP/1.1\r\n\r\n', wire.CLIENTS[4]),
                                    ('empty', b'', wire.CLIENTS[4]),
                                    ('foreign-source', self.get(direct), '198.51.100.9'),
                                    ('too-long', b'x' * 2000, wire.CLIENTS[4])):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.exchange(request, peer=(peer, 40000))

    def test_the_log_of_the_target_holds_sixteen_rows_and_no_more(self):
        log = []
        for number in range(16):
            self.entry.record_https(log, dict(source=wire.CLIENTS[4], port=40000 + number, path='/p', at=1.0))
        self.assertEqual(16, len(log))
        with self.assertRaisesRegex(ValueError, 'https-log-limit'):
            self.entry.record_https(log, dict(source=wire.CLIENTS[4], port=40016, path='/p', at=1.0))
        with self.assertRaisesRegex(ValueError, 'https-log-limit'):
            self.entry.record_https([], dict(source='x' * wire.LOG_LIMIT, port=1, path='/p', at=1.0))


class TunnelProbeTests(Base):
    def setUp(self):
        super().setUp()
        self.request['role'] = 'test'
        self.request['operation'] = 'probe'
        self.events = []

    def fakes(self, **failing):
        events = self.events

        class Sock:
            def __init__(self, *args):
                self.peer = None

            def __enter__(self):
                return self

            def __exit__(self, *args):
                events.append('close-socket')
                return False

            def settimeout(self, value):
                pass

            def bind(self, address):
                events.append(('bind', address))

            def connect(self, address):
                events.append(('connect', address))

            def getsockname(self):
                return (wire.CLIENTS[4], 40123)

        def get(sock, exchange, context):
            events.append(('get', exchange['kind']))
            if failing.get('get') == exchange['kind']:
                raise ValueError('unexpected-https-answer')
            return wire.https_answer(exchange)

        def start(config, directory, name, address, port):
            events.append(('start', name, address, port))
            return SimpleNamespace(name=name)

        def stop(process):
            events.append(('stop', process.name))
            return True, -15

        return (patch.object(self.entry.socket, 'socket', Sock),
                patch.object(self.entry.ssl, 'create_default_context', lambda: 'context'),
                patch.object(self.entry, 'https_get', get),
                patch.object(self.entry, 'start_process', start),
                patch.object(self.entry, 'stop_process', stop),
                patch.object(self.entry, 'socks_connect', lambda sock, address, port: events.append(('socks', address, port))),
                patch.object(self.entry, 'ROOT', Path(tempfile.mkdtemp())))

    def run_probe(self, **failing):
        patches = self.fakes(**failing)
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        return self.entry.probe_tunnel(self.request)

    def test_the_direct_request_comes_first_from_the_test_address_then_a_client_goes_through_the_node(self):
        result = self.run_probe()
        kinds = [e for e in self.events if isinstance(e, tuple)]
        self.assertEqual([('bind', (wire.CLIENTS[4], 0)), ('connect', (wire.TARGETS[4], 443)),
                          ('get', 'https-direct'), ('start', 'client', '127.0.0.1', self.entry.SOCKS_PORT),
                          ('connect', ('127.0.0.1', self.entry.SOCKS_PORT)),
                          ('socks', wire.TARGETS[4], 443), ('get', 'https-tunnel'), ('stop', 'client')], kinds)
        direct, via_node = self.tunnel['https']
        self.assertEqual(40123, result['direct']['client_port'])
        self.assertEqual(wire.https_answer(direct).hex(), result['direct']['response'])
        self.assertEqual(wire.https_answer(via_node).hex(), result['tunnel']['response'])
        self.assertEqual((direct['path'], via_node['path']), (result['direct']['path'], result['tunnel']['path']))
        self.assertEqual(-15, result['client_exit'])

    def test_the_client_is_stopped_even_when_the_request_through_the_node_fails(self):
        with self.assertRaises(ValueError):
            self.run_probe(get='https-tunnel')
        self.assertEqual(('stop', 'client'), [e for e in self.events if isinstance(e, tuple)][-1])

    def test_no_client_starts_when_the_direct_request_fails(self):
        with self.assertRaises(ValueError):
            self.run_probe(get='https-direct')
        self.assertFalse([e for e in self.events if isinstance(e, tuple) and e[0] == 'start'])

    def test_the_tunnel_steps_sit_between_the_exchanges_and_the_closing_marker(self):
        events = []

        def marker(m):
            events.append(m['word'])
            return dict(m, response=wire.marker_answer(m).hex())
        for canary, expected in ((False, ['open', 'exchanges', 'tunnel', 'close']),
                                 (True, ['open', 'exchanges', 'tunnel', 'canary', 'close'])):
            events.clear()
            with patch.object(self.entry, 'fixture'), patch.object(self.entry, 'exchange_marker', marker), \
                    patch.object(self.entry, 'probe_exchanges', lambda request: events.append('exchanges') or []), \
                    patch.object(self.entry, 'probe_tunnel',
                                 lambda request: events.append('tunnel') or dict(client_exit=0)), \
                    patch.object(self.entry, 'send_canary', lambda: events.append('canary')), \
                    patch.object(self.entry.time, 'sleep'):
                result = self.entry.probe_all(dict(self.request, canary=canary))
            self.assertEqual(expected, events)
            self.assertEqual(dict(client_exit=0), result['https'])

    def test_without_a_tunnel_block_the_result_keeps_its_three_keys(self):
        plain = {k: v for k, v in self.request.items() if k != 'tunnel'}
        with patch.object(self.entry, 'exchange_marker', lambda m: dict(m, response='')), \
                patch.object(self.entry, 'probe_exchanges', lambda request: []), \
                patch.object(self.entry, 'probe_tunnel', side_effect=AssertionError('tunnel step')), \
                patch.object(self.entry.time, 'sleep'):
            result = self.entry.probe_all(plain)
        self.assertEqual({'replies', 'marker_replies', 'marker_sent'}, set(result))


class WireTests(Base):
    def pair(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        return a, b

    def test_the_socks_handshake_is_method_then_connect_to_the_ipv4_target(self):
        client, server = self.pair()
        server.sendall(b'\x05\x00' + b'\x05\x00\x00\x01' + bytes(6))
        self.entry.socks_connect(client, wire.TARGETS[4], 443)
        self.assertEqual(b'\x05\x01\x00' + b'\x05\x01\x00\x01' + socket.inet_aton(wire.TARGETS[4]) + b'\x01\xbb',
                         server.recv(64))

    def test_a_refused_socks_method_or_connect_is_an_error(self):
        for reply in (b'\x05\xff', b'\x05\x00' + b'\x05\x05\x00\x01' + bytes(6),
                      b'\x05\x00' + b'\x05\x00\x00\x03' + bytes(6)):
            client, server = self.pair()
            server.sendall(reply)
            with self.subTest(reply=reply), self.assertRaises(ValueError):
                self.entry.socks_connect(client, wire.TARGETS[4], 443)

    def test_a_response_is_read_up_to_its_content_length_and_a_short_one_is_an_error(self):
        client, server = self.pair()
        server.sendall(b'HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nbody-and-more')
        self.assertEqual((b'HTTP/1.0 200 OK\r\nContent-Length: 4', b'body'), self.entry.read_response(client))
        client, server = self.pair()
        server.sendall(b'HTTP/1.0 200 OK\r\nContent-Length: 40\r\n\r\nshort')
        server.shutdown(socket.SHUT_WR)
        with self.assertRaises(ValueError):
            self.entry.read_response(client)
        client, server = self.pair()
        server.sendall(b'HTTP/1.0 200 OK\r\n\r\nno length')
        with self.assertRaises(ValueError):
            self.entry.read_response(client)

    def test_the_answer_must_be_the_nonce_answer_of_the_exchange(self):
        direct = self.tunnel['https'][0]

        class Wrapped:
            def __init__(self, response):
                self.response = response

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def sendall(self, data):
                self.request = data

            def recv(self, size):
                data, self.response = self.response[:size], self.response[size:]
                return data

        body = wire.https_answer(direct)
        good = b'HTTP/1.0 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
        wrapped = Wrapped(good)
        context = SimpleNamespace(wrap_socket=lambda sock, server_hostname: wrapped)
        self.assertEqual(body, self.entry.https_get(object(), direct, context))
        self.assertEqual(b'GET ' + direct['path'].encode() + b' HTTP/1.0\r\n\r\n', wrapped.request)
        for bad in (good.replace(b'200 OK', b'404 NF'), good[:-1] + b'x'):
            context = SimpleNamespace(wrap_socket=lambda sock, server_hostname, bad=bad: Wrapped(bad))
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.entry.https_get(object(), direct, context)

    def test_the_tls_error_for_a_missing_close_notify_after_the_full_response_is_not_an_error(self):
        direct = self.tunnel['https'][0]
        body = wire.https_answer(direct)
        full = b'HTTP/1.0 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body

        class Stream:
            def __init__(self):
                self.parts = [full]

            def recv(self, size):
                if self.parts:
                    return self.parts.pop()
                raise ssl.SSLEOFError()

        self.assertEqual(body, self.entry.read_response(Stream())[1])


if __name__ == '__main__':
    unittest.main()
