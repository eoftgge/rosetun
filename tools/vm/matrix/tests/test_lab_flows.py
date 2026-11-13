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
        self.assertEqual(plain, {**asked, 'windows': [{k: v for k, v in w.items() if k != 'flows'}
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

    def test_the_timestamps_of_a_capture_do_not_change_how_it_is_read(self):
        frames = self.two((), [out(GATEWAY, wire.NODE_PORT, flags=SYN)])
        self.assertEqual(list(wire.records(timed(frames))), frames)
        self.assertEqual(list(wire.records(timed(frames))), list(wire.records(timed(frames, start=5.5))))


if __name__ == '__main__':
    unittest.main()
