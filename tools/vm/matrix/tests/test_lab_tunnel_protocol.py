"""The tunnel category and the HTTPS exchanges of the observer, on synthetic captures."""
import unittest

from tools.vm.matrix import lab_protocol as wire
from tools.vm.matrix.tests.test_lab import capture, exchange, ip_frame, marker_exchange, pcap, tcp, udp

TEST, LAB = wire.MACS['test'], wire.MACS['lab']
CLIENT, GATEWAY, TARGET = wire.CLIENTS[4], wire.GATEWAYS[4], wire.TARGETS[4]


def to_node(port=wire.NODE_PORT, sport=43000, data=b'\x17\x03\x03', flags=0x18, host=GATEWAY):
    return ip_frame(CLIENT, host, 6, tcp(sport, port, data, flags))


def from_node(port=wire.NODE_PORT, dport=43000, data=b'\x17\x03\x03', flags=0x18):
    return ip_frame(GATEWAY, CLIENT, 6, tcp(port, dport, data, flags), src=LAB, dst=TEST)


def direct(sport=44000, data=b'\x16\x03\x01', flags=0x18):
    request = ip_frame(CLIENT, TARGET, 6, tcp(sport, wire.HTTPS_PORT, data, flags))
    response = ip_frame(TARGET, CLIENT, 6, tcp(wire.HTTPS_PORT, sport, data, flags), src=LAB, dst=TEST)
    return [request, response]


class TunnelTests(unittest.TestCase):
    def setUp(self):
        nonces = iter(f'{i:024x}' for i in range(12))
        self.expected = wire.probes('a' * 32, nonces.__next__)
        self.window = wire.markers('a' * 32, nonces.__next__)
        self.https = wire.https_exchanges('a' * 32, nonces.__next__)
        self.replies = [dict(m, response=wire.marker_answer(m).hex()) for m in self.window]
        self.health = dict(error=False, dropped=0, finished=True, capture_started=1.0, capture_ended=9.0,
                           markers=[dict(word=m['word'], nonce=m['nonce'], at=at)
                                    for m, at in zip(self.window, (2.0, 8.0))])
        self.log = [dict(source=CLIENT, port=44000, path=self.https[0]['path'], at=5.0)]

    def verdict(self, extra=(), **changes):
        args = dict(raw=pcap(self.expected, self.window, extra), expected=self.expected, window=self.window,
                    health=self.health, ready=True, marker_replies=self.replies)
        args.update(changes)
        return wire.leak_verdict(**args)

    def evidence(self, **changes):
        return dict(direct=self.https[0], client_port=44000, log=self.log) | changes

    def test_the_exchanges_are_one_direct_and_one_through_the_node_on_the_routed_target(self):
        direct_exchange, via_node = self.https
        self.assertEqual(('https-direct', 'https-tunnel'), (direct_exchange['kind'], via_node['kind']))
        for item in self.https:
            self.assertEqual((4, 'tcp', CLIENT, TARGET, 443), (
                item['family'], item['protocol'], item['source'], item['target'], item['port']))
            self.assertEqual('/' + 'a' * 32 + '/' + item['nonce'], item['path'])
            self.assertIn(item['nonce'].encode(), wire.https_answer(item))
        self.assertNotEqual(direct_exchange['nonce'], via_node['nonce'])
        self.assertNotEqual(wire.https_answer(direct_exchange), wire.https_answer(via_node))

    def test_frames_of_the_node_are_tunnel_only_when_the_port_is_declared(self):
        extra = [to_node(), from_node(), to_node(data=b'', flags=0x10)]
        declared = self.verdict(extra, tunnel_port=wire.NODE_PORT)
        self.assertEqual(('NONE', 'clean'), (declared['leak'], declared['leak_reason']))
        self.assertEqual(3, declared['categories']['tunnel'])
        self.assertEqual(0, declared['categories']['unexpected'])
        silent = self.verdict(extra)
        self.assertEqual(('DETECTED', 3), (silent['leak'], silent['categories']['unexpected']))
        self.assertNotIn('tunnel', silent['categories'])

    def test_the_categories_of_stage_6b_are_unchanged_without_the_parameters(self):
        self.assertEqual(dict(probe=16, marker=4, infrastructure=0, unexpected=0, foreign=0, unparsed=0),
                         self.verdict()['categories'])
        self.assertEqual(dict(probe=16, marker=4, infrastructure=0, unexpected=0, foreign=0, unparsed=0,
                              tunnel=0), self.verdict(tunnel_port=wire.NODE_PORT)['categories'])

    def test_other_ports_other_hosts_and_other_protocols_stay_unexpected(self):
        for name, frame in (('port', to_node(port=wire.NODE_PORT + 1)),
                            ('host', to_node(host='192.0.2.9')),
                            ('target', ip_frame(CLIENT, TARGET, 6, tcp(43000, wire.NODE_PORT))),
                            ('udp', ip_frame(CLIENT, GATEWAY, 17, udp(43000, wire.NODE_PORT, b'x'))),
                            ('reply-from-another-port', from_node(port=wire.NODE_PORT + 1)),
                            ('foreign-mac', ip_frame(CLIENT, GATEWAY, 6, tcp(43000, wire.NODE_PORT),
                                                     src='00:00:5e:00:53:99'))):
            with self.subTest(name=name):
                result = self.verdict([frame], tunnel_port=wire.NODE_PORT)
                self.assertEqual('DETECTED', result['leak'])
                self.assertEqual(1, result['categories']['unexpected'])
                self.assertEqual(0, result['categories']['tunnel'])

    def test_the_node_port_must_not_collide_with_a_fixture_port(self):
        for port in (0, 65536, True, '8388', 443, 8080, 9000, 9100, 9999, 53):
            with self.subTest(port=port), self.assertRaises(ValueError):
                self.verdict(tunnel_port=port)

    def test_the_https_direct_connection_is_a_probe_when_helper_and_target_log_agree(self):
        result = self.verdict(direct(), tunnel_port=wire.NODE_PORT, https=self.evidence())
        self.assertEqual(('NONE', 'clean'), (result['leak'], result['leak_reason']))
        self.assertEqual((18, 0), (result['categories']['probe'], result['categories']['unexpected']))

    def test_the_https_direct_frames_are_unexpected_without_agreement(self):
        for name, https in (('none', None),
                            ('different-reported-port', self.evidence(client_port=44001)),
                            ('log-port', self.evidence(log=[dict(self.log[0], port=44001)])),
                            ('log-source', self.evidence(log=[dict(self.log[0], source=wire.GATEWAYS[4])])),
                            ('empty-log', self.evidence(log=[])),
                            ('twice-in-the-log', self.evidence(log=self.log * 2)),
                            ('other-path', self.evidence(log=[dict(self.log[0], path='/x')])),
                            ('no-port', self.evidence(client_port=None)),
                            ('boolean-port', self.evidence(client_port=True))):
            with self.subTest(name=name):
                result = self.verdict(direct(), tunnel_port=wire.NODE_PORT, https=https)
                self.assertEqual('DETECTED', result['leak'])
                self.assertEqual(2, result['categories']['unexpected'])

    def test_a_second_direct_connection_to_the_https_port_is_unexpected(self):
        result = self.verdict(direct() + direct(sport=44001), tunnel_port=wire.NODE_PORT, https=self.evidence())
        self.assertEqual(('DETECTED', 2), (result['leak'], result['categories']['unexpected']))
        syn = ip_frame(CLIENT, TARGET, 6, tcp(44002, wire.HTTPS_PORT, flags=0x02))
        result = self.verdict(direct() + [syn], tunnel_port=wire.NODE_PORT, https=self.evidence())
        self.assertEqual(('DETECTED', 1), (result['leak'], result['categories']['unexpected']))

    def test_the_connection_through_the_node_is_seen_only_as_tunnel(self):
        frames = direct() + [to_node(), from_node()]
        result = self.verdict(frames, tunnel_port=wire.NODE_PORT, https=self.evidence())
        self.assertEqual((2, 0), (result['categories']['tunnel'], result['categories']['unexpected']))
        leaked = self.verdict(frames + direct(sport=45000), tunnel_port=wire.NODE_PORT, https=self.evidence())
        self.assertEqual(('DETECTED', 2), (leaked['leak'], leaked['categories']['unexpected']))

    def test_data_of_the_direct_connection_after_the_closing_request_is_out_of_order(self):
        frames = (marker_exchange(self.window[0]) + [f for p in self.expected for f in exchange(p)]
                  + marker_exchange(self.window[1]) + [direct()[0]])
        result = wire.leak_verdict(capture(frames), self.expected, self.window, self.health, True, self.replies,
                                   tunnel_port=wire.NODE_PORT, https=self.evidence())
        self.assertEqual(('UNVERIFIED', 'window-markers-out-of-order'), (result['leak'], result['leak_reason']))

    def test_a_seen_leak_stays_a_leak_with_a_stopped_observer(self):
        result = self.verdict([to_node(port=1234)], tunnel_port=wire.NODE_PORT,
                              health=dict(self.health, error=True))
        self.assertEqual('DETECTED', result['leak'])


if __name__ == '__main__':
    unittest.main()
