"""Offline unit tests for Stage 10f extended lab fixtures, observer endpoints, and DHCPv4 allowance."""

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import unittest

from tools.vm.matrix import lab as labmod, lab_protocol as lp, windows_list_guest as guest

_REPO = Path(__file__).resolve().parents[4]
_LAB_ENTRY_PATH = _REPO / 'tools' / 'vm' / 'linux' / 'guest' / 'lab-entry.py'


def _load_lab_entry():
    matrix_dir = str(_REPO / 'tools' / 'vm' / 'matrix')
    if matrix_dir not in sys.path:
        sys.path.insert(0, matrix_dir)
    spec = importlib.util.spec_from_file_location('rosetun_lab_entry_stage10f', _LAB_ENTRY_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _eth(src_mac, dst_mac, ethertype, payload):
    return (bytes.fromhex(dst_mac.replace(':', '')) + bytes.fromhex(src_mac.replace(':', ''))
            + struct.pack('!H', ethertype) + payload)


def _ipv4(proto, src, dst, payload):
    total = 20 + len(payload)
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, 1, 0, 64, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    return header + payload


def _udp(src_mac, dst_mac, src, dst, sport, dport, payload=b'x'):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return _eth(src_mac, dst_mac, 0x0800, _ipv4(17, src, dst, udp))


def _tcp(src_mac, dst_mac, src, dst, sport, dport, flags=0x02, payload=b''):
    tcp = struct.pack('!HHIIBBHHH', sport, dport, 1, 0, 0x50, flags, 65535, 0, 0) + payload
    return _eth(src_mac, dst_mac, 0x0800, _ipv4(6, src, dst, tcp))


def _pcap(frames):
    out = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 2048, 1))
    for index, frame in enumerate(frames, 1):
        out += struct.pack('<IIII', 1700000000 + index, 0, len(frame), len(frame)) + frame
    return bytes(out)


def _marker_frame(marker):
    payload = lp.marker_query(marker)
    return _udp(lp.MACS['test'], lp.MACS['lab'], lp.CLIENTS[4], lp.TARGETS[4], 40000, lp.PORTS['marker'], payload)


def _marker_ack_frame(marker):
    payload = lp.ACK_PREFIX.encode('ascii') + lp.marker_query(marker)
    return _udp(lp.MACS['lab'], lp.MACS['test'], lp.TARGETS[4], lp.CLIENTS[4], lp.PORTS['marker'], 40000, payload)


def _dhcp_packet(msg_type, *, mac=lp.MACS['test'], ciaddr='0.0.0.0', flags=0, requested_ip=None, server_id=None,
                 xid=b'\x11\x22\x33\x44'):
    chaddr = bytes.fromhex(mac.replace(':', '')) + bytes(10)
    header = (struct.pack('!BBBB4sHH', 1, 1, 6, 0, xid, 0, flags)
              + socket.inet_aton(ciaddr) + bytes(12) + chaddr + bytes(192) + b'\x63\x82\x53\x63')
    opts = bytearray([53, 1, msg_type])
    if requested_ip is not None:
        opts += bytes([50, 4]) + socket.inet_aton(requested_ip)
    if server_id is not None:
        opts += bytes([54, 4]) + socket.inet_aton(server_id)
    opts.append(255)
    return header + bytes(opts)


class LabProtocolStage10fTests(unittest.TestCase):

    def _window_pcap(self, lab_id, label, body_frames):
        opening = lp.window_marker(lab_id, 0, 'open', label)
        closing = lp.window_marker(lab_id, 0, 'close', label)
        frames = [_marker_frame(opening), _marker_ack_frame(opening), *body_frames,
                  _marker_frame(closing), _marker_ack_frame(closing)]
        health = dict(error=False, dropped=0, finished=True, capture_started=1.0, capture_ended=10.0,
                      markers=[dict(word='open', index=0, label=label, at=2.0),
                               dict(word='close', index=0, label=label, at=9.0)],
                      node=dict(alive_at_finish=True, exit_code=0))
        return _pcap(frames), health

    def test_dhcpv4_allowance_is_narrow(self):
        lab_id = 'a' * 32
        discover = _udp(lp.MACS['test'], 'ff:ff:ff:ff:ff:ff', '0.0.0.0', '255.255.255.255', 68, 67, b'disc')
        offer = _udp(lp.MACS['lab'], 'ff:ff:ff:ff:ff:ff', lp.GATEWAYS[4], '255.255.255.255', 67, 68, b'off')
        renew = _udp(lp.MACS['test'], lp.MACS['lab'], lp.CLIENTS[4], lp.GATEWAYS[4], 68, 67, b'req')
        ack = _udp(lp.MACS['lab'], lp.MACS['test'], lp.GATEWAYS[4], lp.CLIENTS[4], 67, 68, b'ack')
        pcap, health = self._window_pcap(lab_id, 'dhcp', [discover, offer, renew, ack])

        without = lp.classify_windows(pcap, lab_id, None, health=health, ready=True, tunnel_port=8388,
                                      required_labels=('dhcp',), flows=True)
        self.assertEqual(without['windows'][0]['leak'], 'DETECTED')

        allowed = lp.classify_windows(pcap, lab_id, None, health=health, ready=True, tunnel_port=8388,
                                      required_labels=('dhcp',), flows=True,
                                      window_allowances={'dhcp': ('dhcpv4',)})
        self.assertEqual(allowed['windows'][0]['leak'], 'NONE')
        self.assertEqual(allowed['windows'][0]['categories']['allowed']['dhcpv4'], 4)

        # Foreign destination on port 67 must still be a leak even with dhcpv4 allowance.
        foreign = _udp(lp.MACS['test'], lp.MACS['lab'], lp.CLIENTS[4], lp.TARGETS[4], 68, 67, b'leak')
        pcap_bad, health_bad = self._window_pcap(lab_id, 'dhcp', [foreign])
        bad = lp.classify_windows(pcap_bad, lab_id, None, health=health_bad, ready=True, tunnel_port=8388,
                                  required_labels=('dhcp',), flows=True,
                                  window_allowances={'dhcp': ('dhcpv4',)})
        self.assertEqual(bad['windows'][0]['leak'], 'DETECTED')

    def test_multi_protocol_and_per_window_tunnel_endpoints(self):
        lab_id = 'b' * 32
        hy2_out = _udp(lp.MACS['test'], lp.MACS['lab'], lp.CLIENTS[4], lp.GATEWAYS[4], 50001, lp.HYSTERIA2_PORT)
        hy2_in = _udp(lp.MACS['lab'], lp.MACS['test'], lp.GATEWAYS[4], lp.CLIENTS[4], lp.HYSTERIA2_PORT, 50001)
        reality_syn = _tcp(lp.MACS['test'], lp.MACS['lab'], lp.CLIENTS[4], lp.GATEWAYS[4], 50002, lp.REALITY_PORT)
        pcap, health = self._window_pcap(lab_id, 'hy2', [hy2_out, hy2_in])

        # Default TCP-only 8388 rejects Hysteria2 UDP 8443.
        default = lp.classify_windows(pcap, lab_id, None, health=health, ready=True, tunnel_port=8388,
                                      required_labels=('hy2',), flows=True)
        self.assertEqual(default['windows'][0]['leak'], 'DETECTED')

        # Window-scoped UDP 8443 accepts Hysteria2 UDP 8443.
        scoped = lp.classify_windows(
            pcap, lab_id, None, health=health, ready=True, tunnel_port=8388,
            required_labels=('hy2',), flows=True,
            window_tunnel_endpoints={'hy2': ((lp.GATEWAYS[4], 'udp', lp.HYSTERIA2_PORT),)})
        self.assertEqual(scoped['windows'][0]['leak'], 'NONE')

        # ICMPv4 Port Unreachable (type 3 code 3) citing an authorized UDP tunnel endpoint is tunnel traffic.
        inner_tuic = _ipv4(17, lp.CLIENTS[4], lp.GATEWAYS[4],
                           struct.pack('!HHHH', 50003, lp.TUIC_PORT, 16, 0) + b'01234567')
        icmp_tuic = _eth(lp.MACS['lab'], lp.MACS['test'], 0x0800,
                         _ipv4(1, lp.GATEWAYS[4], lp.CLIENTS[4], struct.pack('!BBHI', 3, 3, 0, 0) + inner_tuic))
        pcap_icmp, health_icmp = self._window_pcap(lab_id, 'tuic', [icmp_tuic])
        ok_icmp = lp.classify_windows(
            pcap_icmp, lab_id, None, health=health_icmp, ready=True, tunnel_port=8388,
            required_labels=('tuic',), flows=True,
            window_tunnel_endpoints={'tuic': ((lp.GATEWAYS[4], 'udp', lp.TUIC_PORT),)})
        self.assertEqual(ok_icmp['windows'][0]['leak'], 'NONE')

        # ICMPv4 Port Unreachable citing a non-tunnel UDP port must still be detected as a leak.
        inner_other = _ipv4(17, lp.CLIENTS[4], lp.GATEWAYS[4],
                            struct.pack('!HHHH', 50004, 9999, 16, 0) + b'01234567')
        icmp_other = _eth(lp.MACS['lab'], lp.MACS['test'], 0x0800,
                          _ipv4(1, lp.GATEWAYS[4], lp.CLIENTS[4], struct.pack('!BBHI', 3, 3, 0, 0) + inner_other))
        pcap_bad, health_bad = self._window_pcap(lab_id, 'tuic', [icmp_other])
        bad_icmp = lp.classify_windows(
            pcap_bad, lab_id, None, health=health_bad, ready=True, tunnel_port=8388,
            required_labels=('tuic',), flows=True,
            window_tunnel_endpoints={'tuic': ((lp.GATEWAYS[4], 'udp', lp.TUIC_PORT),)})
        self.assertEqual(bad_icmp['windows'][0]['leak'], 'DETECTED')
        self.assertEqual(scoped['windows'][0]['categories']['tunnel'], 2)

        # Window-scoped UDP 8443 still rejects TCP 8390 in that window.
        pcap_mix, health_mix = self._window_pcap(lab_id, 'hy2', [hy2_out, reality_syn])
        mixed = lp.classify_windows(
            pcap_mix, lab_id, None, health=health_mix, ready=True, tunnel_port=8388,
            required_labels=('hy2',), flows=True,
            window_tunnel_endpoints={'hy2': ((lp.GATEWAYS[4], 'udp', lp.HYSTERIA2_PORT),)})
        self.assertEqual(mixed['windows'][0]['leak'], 'DETECTED')

        # Global tunnel_endpoints accepts both UDP 8443 and TCP 8390.
        both = lp.classify_windows(
            pcap_mix, lab_id, None, health=health_mix, ready=True, tunnel_port=8388,
            required_labels=('hy2',), flows=True,
            tunnel_endpoints=((lp.GATEWAYS[4], 'udp', lp.HYSTERIA2_PORT),
                              (lp.GATEWAYS[4], 'tcp', lp.REALITY_PORT)))
        self.assertEqual(both['windows'][0]['leak'], 'NONE')
        self.assertEqual(both['windows'][0]['categories']['tunnel'], 2)


class LabEntryStage10fTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_lab_entry()

    def test_extended_fixtures_validation(self):
        base = dict(windows=True, tunnel={'port': 8388})
        self.assertIsNone(self.mod.extended_fixtures_of(base))
        good = {**base, 'extended_fixtures': {'protocols': True, 'xray': True, 'xray_sha256': 'a' * 64}}
        self.assertEqual(self.mod.extended_fixtures_of(good)['protocols'], True)

        for bad_block in (
            {},
            {'protocols': False},
            {'xray': True},
            {'protocols': True, 'unknown': True},
            {'protocols': 'yes'},
            {'protocols': True, 'proto_cert_sha256': 'not-hex'},
        ):
            with self.assertRaises(ValueError):
                self.mod.extended_fixtures_of({**base, 'extended_fixtures': bad_block})

        with self.assertRaises(ValueError):
            self.mod.extended_fixtures_of({'tunnel': {'port': 8388}, 'extended_fixtures': {'dhcp': True}})

    def test_configs_and_x25519_parser(self):
        tunnel = dict(port=8388, method='aes-128-gcm', password='rosetun-lab-test-password')
        cfg = self.mod.node_config(tunnel, protocols=True)
        tags = {ib['tag']: ib for ib in cfg['inbounds']}
        self.assertEqual(set(tags), {'node-in', 'hysteria2-in', 'tuic-in', 'anytls-in'})
        self.assertEqual(tags['hysteria2-in']['listen_port'], lp.HYSTERIA2_PORT)
        self.assertEqual(tags['tuic-in']['listen_port'], lp.TUIC_PORT)
        self.assertEqual(tags['anytls-in']['listen_port'], lp.ANYTLS_PORT)

        sec = self.mod.second_node_config(tunnel)
        self.assertEqual(sec['inbounds'][0]['listen_port'], lp.SECOND_NODE_PORT)
        self.assertEqual(sec['outbounds'][0]['inet4_bind_address'], lp.SECOND_NODE_EGRESS)
        self.assertEqual(sec['outbounds'][0]['inet6_bind_address'], lp.SECOND_NODE_EGRESS6)

        xcfg = self.mod.xray_config('priv-test-key')
        xtags = {ib['tag']: ib for ib in xcfg['inbounds']}
        self.assertEqual(xtags['reality-in']['port'], lp.REALITY_PORT)
        self.assertEqual(xtags['xhttp-in']['port'], lp.XHTTP_PORT)
        self.assertEqual(xtags['xhttp-in']['streamSettings']['xhttpSettings']['path'], lp.XHTTP_PATH)

        self.assertEqual(
            self.mod.parse_x25519_output('PrivateKey: abc123\nPassword (PublicKey): def456\nHash32: xyz\n'),
            ('abc123', 'def456'))
        self.assertEqual(
            self.mod.parse_x25519_output('Private key: k1\nPublic key: k2\n'),
            ('k1', 'k2'))
        with self.assertRaises(self.mod.Refused):
            self.mod.parse_x25519_output('unrelated output')

    def test_dhcp_reply_state_machine(self):
        reply, event, broadcast = self.mod.dhcp_reply(_dhcp_packet(1))
        self.assertIsNotNone(reply)
        self.assertGreaterEqual(len(reply), 300)
        self.assertEqual(event['kind'], 'discover')
        self.assertEqual(event['reply'], 'offer')
        self.assertTrue(broadcast)
        self.assertEqual(socket.inet_ntoa(reply[16:20]), lp.CLIENTS[4])

        # Unicast renew REQUEST
        reply, event, broadcast = self.mod.dhcp_reply(_dhcp_packet(3, ciaddr=lp.CLIENTS[4], requested_ip=lp.CLIENTS[4]))
        self.assertEqual(event['reply'], 'ack')
        self.assertFalse(broadcast)

        # Wrong IP REQUEST -> NAK
        reply, event, broadcast = self.mod.dhcp_reply(_dhcp_packet(3, requested_ip='192.0.2.99'))
        self.assertEqual(event['reply'], 'nak')
        self.assertTrue(broadcast)

        # Foreign MAC ignored
        self.assertEqual(self.mod.dhcp_reply(_dhcp_packet(1, mac='00:00:5e:00:53:99')), (None, None, False))

        # Wrong server ID ignored
        self.assertEqual(self.mod.dhcp_reply(_dhcp_packet(3, server_id='192.0.2.99')), (None, None, False))

        # RELEASE produces event without reply
        reply, event, _ = self.mod.dhcp_reply(_dhcp_packet(7, ciaddr=lp.CLIENTS[4]))
        self.assertIsNone(reply)
        self.assertEqual(event['kind'], 'release')

    def test_twohop_proxy_http_socks5_auth_and_toggle(self):
        # Local echo target on loopback
        echo_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        echo_sock.bind(('127.0.0.1', 0))
        echo_sock.listen(8)
        echo_port = echo_sock.getsockname()[1]
        echo_stop = threading.Event()

        def serve_echo():
            echo_sock.settimeout(0.2)
            while not echo_stop.is_set():
                try:
                    c, _ = echo_sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                with c:
                    data = c.recv(1024)
                    if data:
                        c.sendall(b'ECHO:' + data)

        echo_thread = threading.Thread(target=serve_echo, daemon=True)
        echo_thread.start()

        # Allocate 6 free loopback ports
        free_ports = {}
        holders = []
        for kind in lp.TWOHOP_PORTS:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('127.0.0.1', 0))
            free_ports[kind] = s.getsockname()[1]
            holders.append(s)
        for s in holders:
            s.close()

        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / 'twohop-state.json'
            # Generate self-signed cert via openssl? Avoid external tool dependency by stubbing _make_context!
            proxy = self.mod.TwoHopProxy(
                state_path, bind_v4='127.0.0.1', bind_v6=None, lan_bind=None,
                ports=free_ports, use_netns=False)
            proxy._make_context = lambda cert, key: None
            proxy.start_listeners()
            try:
                # 1. HTTP CONNECT
                with socket.create_connection(('127.0.0.1', free_ports['http']), timeout=3) as s:
                    s.sendall(f'CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n'.encode())
                    resp = s.recv(1024)
                    self.assertTrue(resp.startswith(b'HTTP/1.1 200'))
                    s.sendall(b'hello-http')
                    self.assertEqual(s.recv(1024), b'ECHO:hello-http')

                # 2. HTTP Auth failure (407) and success (200)
                with socket.create_connection(('127.0.0.1', free_ports['http-auth']), timeout=3) as s:
                    s.sendall(f'CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n\r\n'.encode())
                    self.assertTrue(s.recv(1024).startswith(b'HTTP/1.1 407'))
                token = base64.b64encode(f'{lp.TWOHOP_USER}:{lp.TWOHOP_PASSWORD}'.encode()).decode()
                with socket.create_connection(('127.0.0.1', free_ports['http-auth']), timeout=3) as s:
                    s.sendall((f'CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n'
                               f'Proxy-Authorization: Basic {token}\r\n\r\n').encode())
                    self.assertTrue(s.recv(1024).startswith(b'HTTP/1.1 200'))
                    s.sendall(b'hello-auth')
                    self.assertEqual(s.recv(1024), b'ECHO:hello-auth')

                # 3. SOCKS5 no-auth CONNECT
                with socket.create_connection(('127.0.0.1', free_ports['socks5']), timeout=3) as s:
                    s.sendall(b'\x05\x01\x00')
                    self.assertEqual(s.recv(2), b'\x05\x00')
                    s.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', echo_port))
                    reply = s.recv(10)
                    self.assertEqual(reply[:2], b'\x05\x00')
                    s.sendall(b'hello-socks')
                    self.assertEqual(s.recv(1024), b'ECHO:hello-socks')

                # 4. SOCKS5 auth fail & succeed
                with socket.create_connection(('127.0.0.1', free_ports['socks5-auth']), timeout=3) as s:
                    s.sendall(b'\x05\x01\x02')
                    self.assertEqual(s.recv(2), b'\x05\x02')
                    s.sendall(b'\x01\x03bad\x03bad')
                    self.assertEqual(s.recv(2), b'\x01\x01')
                with socket.create_connection(('127.0.0.1', free_ports['socks5-auth']), timeout=3) as s:
                    s.sendall(b'\x05\x01\x02')
                    self.assertEqual(s.recv(2), b'\x05\x02')
                    u, p = lp.TWOHOP_USER.encode(), lp.TWOHOP_PASSWORD.encode()
                    s.sendall(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
                    self.assertEqual(s.recv(2), b'\x01\x00')
                    s.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', echo_port))
                    self.assertEqual(s.recv(10)[:2], b'\x05\x00')
                    s.sendall(b'hello-sauth')
                    self.assertEqual(s.recv(1024), b'ECHO:hello-sauth')

                # 5. Stop listeners -> connection refused, then restart -> works again
                proxy.stop_listeners()
                with self.assertRaises(OSError):
                    socket.create_connection(('127.0.0.1', free_ports['http']), timeout=1)
                state = json.loads(state_path.read_bytes())
                self.assertFalse(state['running'])
                statuses = [(e['kind'], e['status']) for e in state['events']]
                self.assertIn(('http', 'ok'), statuses)
                self.assertIn(('http-auth', 'auth_failed'), statuses)
                self.assertIn(('http-auth', 'ok'), statuses)
                self.assertIn(('socks5', 'ok'), statuses)
                self.assertIn(('socks5-auth', 'auth_failed'), statuses)
                self.assertIn(('socks5-auth', 'ok'), statuses)
            finally:
                proxy.stop_listeners()
                echo_stop.set()
                echo_sock.close()
                echo_thread.join(2)

    def test_https_log_live_state_and_action_allowlists(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            log = self.mod.HttpsLog(state_path=t / 'https-state.json')
            log.served(dict(source=lp.TWOHOP_B[4], port=12345, method='GET', path_class='root', at=1.0), 'GET', 'root')
            self.mod.atomic_json(t / 'fixture-state.json', dict(services=dict(primary_node=True),
                                                                reality_public_key='pub123'))
            snapshot = self.mod.fixture_state(t)
            self.assertEqual(snapshot['reality_public_key'], 'pub123')
            self.assertEqual(snapshot['https']['by_source'][lp.TWOHOP_B[4]], 1)
            self.assertIn('fixture_state', guest.ACTION_OPERATIONS)
            self.assertIn('fixture_control', guest.ACTION_OPERATIONS)
            with self.assertRaises(ValueError):
                self.mod.fixture_control(t, {'service': 'bad', 'state': 'stop'})

    def test_dns_log_aggregate_collapses_repeated_queries_without_overflow(self):
        log = self.mod.DnsLog(aggregate=True)
        for _ in range(400):
            log.record(lp.EGRESS, 'doh', ('listed.lab.test', 'A'))
        log.record(lp.CLIENTS[4], 'udp', ('baseline.lab.test', 'A'))
        self.assertFalse(log.overflow)
        self.assertEqual(2, len(log.rows))
        self.assertEqual(400, log.rows[0]['count'])
        self.assertEqual('listed.lab.test', log.rows[0]['name'])
        self.assertEqual('baseline.lab.test', log.rows[1]['name'])


if __name__ == '__main__':
    unittest.main()
