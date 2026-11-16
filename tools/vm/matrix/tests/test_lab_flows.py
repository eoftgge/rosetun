"""The TCP connections of the test machine in each window, read from the headers of a synthetic capture."""
import struct
import unittest

from tools.vm.matrix import lab_protocol as wire
from tools.vm.matrix.tests.test_lab import ip_frame, tcp
from tools.vm.matrix.tests.test_lab_windows import RUN, health, marker_frames, served

SYN, SYN_ACK, PUSH, FIN, RST = 0x02, 0x12, 0x18, 0x11, 0x14
CLIENT, GATEWAY, TARGET = wire.CLIENTS[4], wire.GATEWAYS[4], wire.TARGETS[4]
STEP = 0.25
LABELS = ['reported', 'connect_ks']


def out(host, port, sport=43000, data=b'', flags=PUSH):
    return ip_frame(CLIENT, host, 6, tcp(sport, port, data, flags))


def back(host, port, dport=43000, data=b'', flags=PUSH):
    return ip_frame(host, CLIENT, 6, tcp(port, dport, data, flags), src=wire.MACS['lab'], dst=wire.MACS['test'])


def timed(frames, start=100.0):
    """A pcap whose record `n` was captured `n` quarter seconds after `start`."""
    raw = bytearray(wire.PCAP_HEADER)
    for n, frame in enumerate(frames):
        at = start + n * STEP
        raw.extend(struct.pack('<IIII', int(at), int(at % 1 * 1000000), len(frame), len(frame)) + frame)
    return bytes(raw)


def session(index, label, body=()):
    return marker_frames(index, 'open', label) + list(body) + marker_frames(index, 'close', label)


class FlowTests(unittest.TestCase):
    def classify(self, frames, flows=True, labels=LABELS, **changes):
        arguments = dict(health=health(served(list(enumerate(labels)))), ready=True, tunnel_port=wire.NODE_PORT,
                         required_labels=labels, flows=flows) | changes
        return wire.classify_windows(timed(frames) if type(frames) is list else frames, RUN, None, **arguments)

    def two(self, first=(), second=()):
        return session(0, LABELS[0], first) + session(1, LABELS[1], second)

    def flows(self, result, index):
        return result['windows'][index]['flows']

    def test_a_connection_to_the_node_with_data_both_ways_is_counted_by_frames_bytes_and_flags(self):
        body = [out(GATEWAY, wire.NODE_PORT, flags=SYN), back(GATEWAY, wire.NODE_PORT, flags=SYN_ACK),
                out(GATEWAY, wire.NODE_PORT, data=b'a' * 100), back(GATEWAY, wire.NODE_PORT, data=b'b' * 400),
                out(GATEWAY, wire.NODE_PORT, data=b'c' * 20), out(GATEWAY, wire.NODE_PORT, flags=FIN),
                back(GATEWAY, wire.NODE_PORT, flags=FIN)]
        result = self.classify(self.two((), body))
        self.assertEqual(dict(connections=[], omitted=0), self.flows(result, 0))
        (flow,) = self.flows(result, 1)['connections']
        self.assertEqual(dict(kind='node', client=CLIENT + ':43000', server=GATEWAY + ':8388',
                              frames_out=4, frames_back=3, bytes_out=120, bytes_back=400,
                              syn=True, syn_ack=True, fin=['out', 'back'], rst=[]),
                         {k: v for k, v in flow.items() if k not in ('first_ms', 'last_ms')})
        self.assertEqual(0, self.flows(result, 1)['omitted'])

    def test_every_window_has_the_lab_clock_at_the_request_that_opened_and_the_one_that_closed_it(self):
        result = self.classify(self.two((), [out(GATEWAY, wire.NODE_PORT, flags=SYN)]))
        self.assertEqual(dict(open_at=100.0, close_at=100.5), result['windows'][0]['clock'])
        self.assertEqual(dict(open_at=101.0, close_at=101.75), result['windows'][1]['clock'])

    def test_a_window_that_never_closed_has_no_closing_time_and_without_flows_there_is_no_clock(self):
        result = self.classify(session(0, LABELS[0]) + marker_frames(1, 'open', LABELS[1]))
        self.assertEqual(dict(open_at=100.0, close_at=100.5), result['windows'][0]['clock'])
        self.assertEqual(dict(open_at=101.0, close_at=None), result['windows'][1]['clock'])
        plain = self.classify(self.two(), flows=False)
        self.assertNotIn('clock', plain['windows'][0])

    def test_a_connection_with_only_a_syn_is_a_syn_and_nothing_came_back(self):
        result = self.classify(self.two((), [out(GATEWAY, wire.NODE_PORT, flags=SYN),
                                             out(GATEWAY, wire.NODE_PORT, flags=SYN)]))
        (flow,) = self.flows(result, 1)['connections']
        self.assertEqual(('node', 2, 0, True, False, [], []),
                         (flow['kind'], flow['frames_out'], flow['frames_back'], flow['syn'], flow['syn_ack'],
                          flow['fin'], flow['rst']))
        self.assertEqual((0, 0), (flow['bytes_out'], flow['bytes_back']))

    def test_a_reset_says_which_side_sent_it(self):
        body = [out(GATEWAY, wire.NODE_PORT, flags=SYN), back(GATEWAY, wire.NODE_PORT, flags=RST),
                out(GATEWAY, wire.NODE_PORT, sport=43001, flags=SYN), back(GATEWAY, wire.NODE_PORT, dport=43001,
                                                                         flags=SYN_ACK),
                out(GATEWAY, wire.NODE_PORT, sport=43001, flags=RST)]
        flows = self.flows(self.classify(self.two((), body)), 1)['connections']
        self.assertEqual([(CLIENT + ':43000', ['back']), (CLIENT + ':43001', ['out'])],
                         [(flow['client'], flow['rst']) for flow in flows])
        self.assertEqual([False, True], [flow['syn_ack'] for flow in flows])

    def test_the_target_the_node_and_everything_else_are_told_apart(self):
        body = [out(TARGET, wire.HTTPS_PORT, sport=44000, flags=SYN), back(TARGET, wire.HTTPS_PORT, dport=44000),
                out(GATEWAY, wire.NODE_PORT, sport=44001, flags=SYN),
                out(GATEWAY, 8080, sport=44002, flags=SYN),
                out('198.51.100.9', wire.HTTPS_PORT, sport=44003, flags=SYN)]
        flows = self.flows(self.classify(self.two((), body)), 1)['connections']
        self.assertEqual(['target', 'node', 'other', 'other'], [flow['kind'] for flow in flows])
        self.assertEqual(['203.0.113.2:443', '192.0.2.1:8388', '192.0.2.1:8080', '198.51.100.9:443'],
                         [flow['server'] for flow in flows])

    def test_without_a_tunnel_port_nothing_is_the_node(self):
        result = self.classify(self.two((), [out(GATEWAY, wire.NODE_PORT, flags=SYN)]), tunnel_port=None)
        self.assertEqual(['other'], [flow['kind'] for flow in self.flows(result, 1)['connections']])

    def test_times_are_milliseconds_after_the_opening_marker(self):
        # The second window opens at record 4 (the first window's four records come before it), so its
        # body starts two records later; offsets are counted from its own opening marker.
        body = [out(GATEWAY, wire.NODE_PORT, flags=SYN), back(GATEWAY, wire.NODE_PORT, flags=SYN_ACK),
                out(GATEWAY, wire.NODE_PORT, data=b'x')]
        result = self.classify(self.two((), body))
        (flow,) = self.flows(result, 1)['connections']
        self.assertEqual(2 * STEP * 1000, flow['first_ms'])
        self.assertEqual(4 * STEP * 1000, flow['last_ms'])

    def test_frames_outside_a_window_are_not_a_flow_of_any_window(self):
        before = [out(GATEWAY, wire.NODE_PORT, sport=45000, flags=SYN)]
        between = [out(GATEWAY, wire.NODE_PORT, sport=45001, flags=SYN)]
        inside = [out(GATEWAY, wire.NODE_PORT, sport=45002, flags=SYN)]
        frames = before + session(0, LABELS[0], inside) + between + session(1, LABELS[1])
        result = self.classify(frames)
        self.assertEqual([CLIENT + ':45002'], [f['client'] for f in self.flows(result, 0)['connections']])
        self.assertEqual([], self.flows(result, 1)['connections'])

    def test_a_window_keeps_at_most_64_connections_and_counts_the_rest(self):
        body = [out(GATEWAY, wire.NODE_PORT, sport=40000 + n, flags=SYN) for n in range(70)]
        body += [out(GATEWAY, wire.NODE_PORT, sport=40000 + n) for n in range(70)]
        flows = self.flows(self.classify(self.two((), body)), 1)
        self.assertEqual(64, len(flows['connections']))
        self.assertEqual(6, flows['omitted'])
        self.assertEqual({2}, {flow['frames_out'] for flow in flows['connections']})
        self.assertEqual(40000, int(flows['connections'][0]['client'].split(':')[1]))

    def test_flows_change_no_verdict_and_are_absent_unless_asked_for(self):
        body = [out(GATEWAY, wire.NODE_PORT, flags=SYN), out('198.51.100.9', 80, sport=46000, flags=SYN)]
        frames = timed(self.two((), body))
        plain = self.classify(frames, flows=False)
        asked = self.classify(frames, flows=True)
        self.assertTrue(all('flows' not in window for window in plain['windows']))
        added = ('flows', 'direct', 'clock')
        self.assertEqual(plain, {**asked, 'windows': [{k: v for k, v in w.items() if k not in added}
                                                      for w in asked['windows']]})
        # The leak is still the verdict of the window; its connection is what the flows say it was.
        self.assertEqual(['NONE', 'DETECTED'], [w['leak'] for w in asked['windows']])
        self.assertEqual(['other'], [f['kind'] for f in self.flows(asked, 1)['connections'] if f['client'].endswith(':46000')])

    def test_a_capture_without_the_windows_gives_empty_flows_for_a_window_that_is_not_there(self):
        result = self.classify(session(0, LABELS[0]), health=health(served([(0, LABELS[0])])))
        self.assertEqual([dict(connections=[], omitted=0)], [w['flows'] for w in result['windows']])

    def test_udp_and_other_protocols_are_not_flows(self):
        from tools.vm.matrix.tests.test_lab import udp
        body = [ip_frame(CLIENT, TARGET, 17, udp(42000, 9000, b'q')), ip_frame(CLIENT, TARGET, 1, bytes(8))]
        self.assertEqual([], self.flows(self.classify(self.two((), body)), 1)['connections'])

    def test_the_unexpected_frames_of_a_window_are_grouped_into_the_flows_the_test_machine_opened(self):
        from tools.vm.matrix.tests.test_lab import icmp, udp
        retried = ip_frame(CLIENT, wire.RESOLVER, 17, udp(42000, 53, b'q'))
        reply = ip_frame(wire.RESOLVER, CLIENT, 17, udp(53, 42000, b'r'), src=wire.MACS['lab'], dst=wire.MACS['test'])
        body = [out(GATEWAY, wire.NODE_PORT, flags=SYN), out(TARGET, 443, sport=44000, flags=SYN),
                back(TARGET, 443, dport=44000, flags=SYN_ACK), out(TARGET, 443, sport=44000, data=b'x'),
                retried, reply, retried, reply, back(TARGET, 443, dport=45000, data=b'late'),
                ip_frame(CLIENT, TARGET, 1, icmp(8))]
        result = self.classify(self.two((), body))
        window = result['windows'][1]
        self.assertEqual(9, window['categories']['unexpected'])
        self.assertEqual(dict(flows=[
            dict(protocol='tcp', kind='target', client=CLIENT + ':44000', server=TARGET + ':443', frames_out=2,
                 frames_back=1, opened=True),
            dict(protocol='udp', kind='resolver', client=CLIENT + ':42000', server=wire.RESOLVER + ':53',
                 frames_out=2, frames_back=2, opened=True),
            dict(protocol='tcp', kind='target', client=CLIENT + ':45000', server=TARGET + ':443', frames_out=0,
                 frames_back=1, opened=False)], other_frames=1, omitted_frames=0), window['direct'])
        # The node's connection is the tunnel, not a flow of unexpected frames.
        self.assertEqual(dict(flows=[], other_frames=0, omitted_frames=0), result['windows'][0]['direct'])

    def test_unexpected_frames_beyond_the_kept_flows_are_counted(self):
        from tools.vm.matrix.tests.test_lab import udp
        body = [ip_frame(CLIENT, TARGET, 17, udp(40000 + n, 9999, b'q')) for n in range(wire.FLOW_LIMIT + 3)]
        direct = self.classify(self.two((), body))['windows'][1]['direct']
        self.assertEqual((wire.FLOW_LIMIT, 3, 0), (len(direct['flows']), direct['omitted_frames'],
                                                   direct['other_frames']))
        self.assertEqual({'other'}, {flow['kind'] for flow in direct['flows']})

    def test_a_udp_exchange_the_other_side_began_and_a_resolver_on_another_port_are_no_expected_kind(self):
        from tools.vm.matrix.tests.test_lab import udp
        body = [ip_frame(wire.RESOLVER, CLIENT, 17, udp(53, 41000, b'r'), src=wire.MACS['lab'], dst=wire.MACS['test']),
                ip_frame(CLIENT, wire.RESOLVER, 17, udp(41001, 5353, b'q'))]
        flows = self.classify(self.two((), body))['windows'][1]['direct']['flows']
        self.assertEqual([('resolver', False), ('other', True)], [(f['kind'], f['opened']) for f in flows])

    def neighbor_request(self, target='192.0.2.250', **changes):
        from tools.vm.matrix.tests.test_lab import arp
        fields = dict(src=wire.MACS['test'], dst=wire.BROADCAST, sha=wire.MACS['test'], tha='00:00:00:00:00:00')
        sender = changes.pop('sender', CLIENT)
        return arp(changes.pop('op', 1), sender, target, **(fields | changes))

    def test_the_requests_of_the_test_machine_for_a_neighbor_are_one_flow_however_many_it_sends(self):
        for count in (1, 3, 6):
            with self.subTest(count=count):
                direct = self.classify(self.two((), [self.neighbor_request()] * count))['windows'][1]['direct']
                self.assertEqual(dict(flows=[dict(protocol='arp', kind='neighbor', client=CLIENT, server='192.0.2.250',
                                                  frames_out=count, frames_back=0, opened=True)],
                                      other_frames=0, omitted_frames=0), direct)
        # Two addresses asked for are two flows.
        direct = self.classify(self.two((), [self.neighbor_request(), self.neighbor_request('192.0.2.251')]))
        self.assertEqual(['192.0.2.250', '192.0.2.251'], [f['server'] for f in direct['windows'][1]['direct']['flows']])

    def test_an_arp_frame_that_only_looks_like_a_request_for_a_neighbor_is_no_flow(self):
        stranger, zero = '00:00:5e:00:53:70', '00:00:00:00:00:00'
        cases = {'an-answer-to-the-test-machine': self.neighbor_request(op=2, sender='192.0.2.250', target=CLIENT,
                                                                        src=stranger, dst=wire.MACS['test'],
                                                                        sha=stranger, tha=wire.MACS['test']),
                 'a-request-from-another-address': self.neighbor_request(sender='192.0.2.99'),
                 'a-request-to-one-machine': self.neighbor_request(dst=stranger),
                 'a-request-naming-another-hardware-address': self.neighbor_request(sha=stranger),
                 'a-request-with-a-target-hardware-address': self.neighbor_request(tha=stranger),
                 'an-announcement': self.neighbor_request(target=CLIENT),
                 'a-request-of-another-machine-for-the-test-machine': self.neighbor_request(
                     sender='192.0.2.250', target=CLIENT, src=stranger, sha=stranger)}
        for name, frame in cases.items():
            with self.subTest(name=name):
                window = self.classify(self.two((), [frame]))['windows'][1]
                self.assertEqual(('DETECTED', dict(flows=[], other_frames=1, omitted_frames=0)),
                                 (window['leak'], window['direct']))
        self.assertEqual(zero, wire.ZERO_MAC)

    def unreachable(self, datagram, source=GATEWAY, kind=3, **macs):
        from tools.vm.matrix.tests.test_lab import icmp
        macs = dict(src=wire.MACS['lab'], dst=wire.MACS['test']) | macs
        return ip_frame(source, CLIENT, 1, icmp(kind, bytes(4) + datagram[14:14 + 28]), **macs)

    def test_the_router_saying_a_datagram_of_a_flow_has_no_route_is_a_frame_back_of_that_flow(self):
        from tools.vm.matrix.tests.test_lab import udp
        datagram = ip_frame(CLIENT, '10.254.254.1', 17, udp(42000, 69, b'q'))
        body = [datagram, self.unreachable(datagram), datagram, self.unreachable(datagram)]
        direct = self.classify(self.two((), body))['windows'][1]['direct']
        self.assertEqual(dict(flows=[dict(protocol='udp', kind='other', client=CLIENT + ':42000',
                                          server='10.254.254.1:69', frames_out=2, frames_back=2, opened=True)],
                              other_frames=0, omitted_frames=0), direct)

    def test_an_error_that_belongs_to_no_flow_of_the_window_or_comes_from_elsewhere_is_no_frame_of_a_flow(self):
        from tools.vm.matrix.tests.test_lab import udp
        datagram = ip_frame(CLIENT, '10.254.254.1', 17, udp(42000, 69, b'q'))
        other = ip_frame(CLIENT, '10.254.254.1', 17, udp(42001, 69, b'q'))
        syn = out('10.254.254.1', 69, sport=42000, flags=SYN)
        cases = {'before-its-datagram': [self.unreachable(datagram), datagram],
                 'about-another-port': [datagram, self.unreachable(other)],
                 'about-a-tcp-segment': [datagram, self.unreachable(syn)],
                 'from-another-address': [datagram, self.unreachable(datagram, source=TARGET)],
                 'time-exceeded': [datagram, self.unreachable(datagram, kind=11)],
                 'from-another-machine': [datagram, self.unreachable(datagram, src='00:00:5e:00:53:70')]}
        for name, body in cases.items():
            with self.subTest(name=name):
                direct = self.classify(self.two((), body))['windows'][1]['direct']
                self.assertEqual(1, direct['other_frames'])
                self.assertEqual([0], [f['frames_back'] for f in direct['flows'] if f['client'] == CLIENT + ':42000'])

    def test_the_timestamps_of_a_capture_do_not_change_how_it_is_read(self):
        frames = self.two((), [out(GATEWAY, wire.NODE_PORT, flags=SYN)])
        self.assertEqual(list(wire.records(timed(frames))), frames)
        self.assertEqual(list(wire.records(timed(frames))), list(wire.records(timed(frames, start=5.5))))


if __name__ == '__main__':
    unittest.main()
