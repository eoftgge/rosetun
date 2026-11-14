"""The flows behind the lab node: the counting, the helper that writes them and the controller that reads them."""
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from tools.vm.matrix import l3_lab, lab_protocol as wire
from tools.vm.matrix.tests.test_lab import ip_frame, tcp, udp
from tools.vm.matrix.tests.test_lab_fixtures import load_entry
from tools.vm.matrix.tests.test_lab_observer import FakeCapture, Observer

SYN, SYN_ACK, PUSH, FIN, RST = 0x02, 0x12, 0x18, 0x11, 0x14
ROUTER, TARGET = '203.0.113.1', wire.TARGETS[4]
ROUTER6, TARGET6 = '2001:db8:6a:2::1', wire.TARGETS[6]


def out(data=b'', flags=PUSH, sport=51000, port=443):
    return ip_frame(ROUTER, TARGET, 6, tcp(sport, port, data, flags))


def back(data=b'', flags=PUSH, sport=51000, port=443):
    return ip_frame(TARGET, ROUTER, 6, tcp(port, sport, data, flags))


class HeaderTests(unittest.TestCase):
    def test_a_tcp_segment_gives_its_endpoints_flags_and_payload_size(self):
        self.assertEqual((6, (ROUTER, 51000), (TARGET, 443), SYN, 0), wire.route_header(out(flags=SYN)))
        self.assertEqual((6, (TARGET, 443), (ROUTER, 51000), PUSH, 7), wire.route_header(back(b'7 bytes')))

    def test_a_udp_datagram_gives_its_payload_size_and_no_flags(self):
        frame = ip_frame(ROUTER, TARGET, 17, udp(40000, 53, b'12345'))
        self.assertEqual((17, (ROUTER, 40000), (TARGET, 53), 0, 5), wire.route_header(frame))

    def test_the_payload_size_is_the_one_the_ip_header_says_and_not_the_bytes_captured(self):
        frame = bytearray(out(b'x' * 1000))
        self.assertEqual(1000, wire.route_header(bytes(frame[:80]))[4])

    def test_ethernet_padding_is_not_payload(self):
        self.assertEqual(0, wire.route_header(out(flags=SYN) + bytes(6))[4])

    def test_an_ipv6_segment_is_read_the_same_way(self):
        frame = ip_frame(ROUTER6, TARGET6, 6, tcp(51000, 443, b'abc'))
        self.assertEqual((6, (ROUTER6, 51000), (TARGET6, 443), PUSH, 3), wire.route_header(frame))

    def test_what_is_not_tcp_or_udp_or_is_a_fragment_or_is_too_short_is_none(self):
        icmp = ip_frame(ROUTER, TARGET, 1, bytes(8))
        fragment = ip_frame(ROUTER, TARGET, 6, tcp(51000, 443, b'abc'), fragment=0x2000)
        for packet in (icmp, fragment, b'', bytes(13), out()[:20], out()[:40], bytes(14) + bytes(40)):
            with self.subTest(size=len(packet)):
                self.assertIsNone(wire.route_header(packet))

    def test_a_tcp_header_longer_than_the_packet_is_none(self):
        frame = bytearray(out(b'abc'))
        frame[14 + 20 + 12] = 0xf0
        self.assertIsNone(wire.route_header(bytes(frame)))


class FlowTests(unittest.TestCase):
    def count(self, packets, limit=wire.ROUTE_FLOW_LIMIT, start=1000.0):
        flows = wire.RouteFlows(limit)
        for number, packet in enumerate(packets):
            flows.add(packet, start + number * .25)
        return flows

    def test_one_connection_is_one_row_with_both_directions_flags_and_times(self):
        flows = self.count([out(flags=SYN), back(flags=SYN_ACK), out(b'a' * 100), back(b'b' * 400),
                            out(flags=FIN), back(flags=FIN), out(flags=RST)])
        (row,) = flows.document()['flows']
        self.assertEqual(dict(proto='tcp', client=ROUTER + ':51000', server=TARGET + ':443', frames_out=4,
                              frames_back=3, bytes_out=100, bytes_back=400, first_at=1000.0, last_at=1001.5,
                              syn=True, syn_ack=True, fin=['out', 'back'], rst=['out']), row)

    def test_connections_with_other_ports_are_other_rows(self):
        flows = self.count([out(sport=51000), out(sport=51001), back(sport=51001), out(sport=51000, port=8443)])
        rows = flows.document()['flows']
        self.assertEqual([(ROUTER + ':51000', 443), (ROUTER + ':51001', 443), (ROUTER + ':51000', 8443)],
                         [(row['client'], int(row['server'].rsplit(':', 1)[1])) for row in rows])
        self.assertEqual([1, 1, 1], [row['frames_out'] for row in rows])
        self.assertEqual([0, 1, 0], [row['frames_back'] for row in rows])

    def test_a_syn_ack_seen_first_names_the_other_side_the_client(self):
        (row,) = self.count([back(flags=SYN_ACK), out()]).document()['flows']
        self.assertEqual((ROUTER + ':51000', TARGET + ':443', 1, 1), (row['client'], row['server'],
                                                                      row['frames_out'], row['frames_back']))
        self.assertEqual((False, True), (row['syn'], row['syn_ack']))

    def test_a_flow_without_a_syn_still_counts_from_its_first_packet(self):
        (row,) = self.count([back(b'late')]).document()['flows']
        self.assertEqual((TARGET + ':443', ROUTER + ':51000', 4), (row['client'], row['server'], row['bytes_out']))

    def test_udp_flows_have_no_flags(self):
        query = ip_frame(ROUTER, TARGET, 17, udp(40000, 53, b'q' * 20))
        answer = ip_frame(TARGET, ROUTER, 17, udp(53, 40000, b'a' * 60))
        (row,) = self.count([query, answer]).document()['flows']
        self.assertEqual(('udp', 20, 60, False, False, [], []),
                         (row['proto'], row['bytes_out'], row['bytes_back'], row['syn'], row['syn_ack'],
                          row['fin'], row['rst']))

    def test_ipv6_flows_are_named_with_brackets(self):
        frame = ip_frame(ROUTER6, TARGET6, 6, tcp(51000, 443, b'x', PUSH))
        (row,) = self.count([frame]).document()['flows']
        self.assertEqual(('[' + ROUTER6 + ']:51000', '[' + TARGET6 + ']:443'), (row['client'], row['server']))

    def test_the_flows_past_the_limit_are_counted_as_frames_and_the_known_ones_still_grow(self):
        flows = self.count([out(sport=50000 + n) for n in range(4)] + [out(sport=50001, data=b'more')], limit=3)
        document = flows.document()
        self.assertEqual(3, len(document['flows']))
        self.assertEqual(1, document['omitted_frames'])
        self.assertEqual(2, document['flows'][1]['frames_out'])

    def test_what_is_not_a_flow_is_counted_apart(self):
        arp = bytes(12) + b'\x08\x06' + bytes(28)
        document = self.count([arp, bytes(5), out(flags=SYN)]).document(error='route-count-failed', dropped=3)
        self.assertEqual((1, 2, 0, 'route-count-failed', 3),
                         (len(document['flows']), document['other_frames'], document['unparsed_frames'],
                          document['error'], document['dropped']))

    def test_a_packet_the_header_reader_refuses_is_counted_and_never_raised(self):
        flows = wire.RouteFlows()
        with patch.object(wire, 'route_header', side_effect=ValueError('invalid-ipv6')):
            flows.add(out(), 1000.0)
        self.assertEqual((0, 1), (len(flows.document()['flows']), flows.document()['unparsed_frames']))

    def test_the_largest_document_fits_the_file_limit(self):
        rows = [ip_frame('2001:db8:ffff:ffff:ffff:ffff:ffff:fff%d' % (n % 10), '2001:db8:ffff:ffff:ffff:ffff:ffff:fffe',
                         6, tcp(40000 + n, 65535, b'x', FIN | RST | SYN)) for n in range(wire.ROUTE_FLOW_LIMIT)]
        flows = self.count([frame for frame in rows for _ in range(2)])
        self.assertEqual(wire.ROUTE_FLOW_LIMIT, len(flows.document()['flows']))
        self.assertLess(len(json.dumps(flows.document())), wire.ROUTE_FLOWS_LIMIT)


class Stream:
    """A packet socket that hands out its packets and then has nothing."""

    def __init__(self, packets, error=None):
        self.packets, self.error, self.closed = list(packets), error, False

    def fileno(self):
        return 0

    def recv(self, size):
        if self.error is not None:
            raise self.error
        if not self.packets:
            raise BlockingIOError
        return self.packets.pop(0)


class FakeSelector:
    """A selector whose only descriptor is always ready."""

    def __init__(self, stop=None):
        self.stop, self.rounds = stop, 0

    def register(self, *args):
        pass

    def select(self, timeout):
        self.rounds += 1
        if self.rounds > 2 and self.stop is not None:
            self.stop.set()
        return [object()]

    def close(self):
        pass


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.entry = load_entry()
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.directory = Path(scratch.name)

    def run_count(self, route, flows, state):
        stop = threading.Event()
        selector = FakeSelector(stop)
        with patch.object(self.entry.selectors, 'DefaultSelector', lambda: selector):
            self.entry.route_count(route, flows, stop, state)

    def test_the_counting_thread_reads_every_waiting_packet_into_the_flows(self):
        flows, state = wire.RouteFlows(), {}
        self.run_count(Stream([out(flags=SYN), back(flags=SYN_ACK), out(b'abc')]), flows, state)
        self.assertEqual({}, state)
        (row,) = flows.document()['flows']
        self.assertEqual((2, 1, 3), (row['frames_out'], row['frames_back'], row['bytes_out']))

    def test_a_failure_of_the_count_is_noted_and_raised_nowhere(self):
        flows, state = wire.RouteFlows(), {}
        self.run_count(Stream([], error=OSError('network is down')), flows, state)
        self.assertEqual({'error': 'route-count-failed'}, state)
        self.assertEqual([], flows.document()['flows'])

    def test_the_file_is_the_document_with_addresses_outside_the_lab_blanked_and_it_is_created_once(self):
        outside = ip_frame(ROUTER, '10.0.0.1', 6, tcp(51000, 80, b'', SYN))
        flows, state = wire.RouteFlows(), dict(error=None, dropped=2)
        for packet in (out(flags=SYN), outside):
            flows.add(packet, 1000.0)
        path = self.directory / 'route-flows.json'
        self.entry.write_route_flows(path, flows, state)
        text = path.read_text()
        self.assertNotIn('10.0.0.1', text)
        document = json.loads(text)
        self.assertEqual([TARGET + ':443', '[address]:80'], [row['server'] for row in document['flows']])
        self.assertEqual(2, document['dropped'])
        with self.assertRaises(FileExistsError):
            self.entry.write_route_flows(path, flows, state)

    def test_a_document_over_the_bound_is_refused_and_not_written(self):
        flows = wire.RouteFlows()
        flows.document = lambda **kw: dict(flows=[], filler='x' * wire.ROUTE_FLOWS_LIMIT)
        path = self.directory / 'route-flows.json'
        with self.assertRaises(ValueError):
            self.entry.write_route_flows(path, flows, {})
        self.assertFalse(path.exists())


class ObserverTests(unittest.TestCase):
    """The real `serve` of the helper on loopback, with a second fake socket for the link behind the node."""

    def setUp(self):
        self.entry = load_entry()

    def observer(self, route, **request):
        observer = Observer(self, **request)
        sockets = {'lab0': observer.capture, 'rt-route': route}
        patcher = patch.object(self.entry, 'open_capture', lambda interface: sockets[interface])
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(route.close)
        return observer

    def document(self, observer):
        return json.loads((observer.directory / 'route-flows.json').read_text())

    def test_the_link_behind_the_node_is_counted_beside_a_capture_that_stays_clean(self):
        route = FakeCapture(drops=4)
        observer = self.observer(route, route_flows=True).start().wait_ready()
        route.feed(out(flags=SYN))
        route.feed(back(flags=SYN_ACK))
        route.feed(out(b'hello'))
        time.sleep(.5)
        health = observer.finish()
        self.assertEqual((False, 0), (health['error'], health['dropped']))
        document = self.document(observer)
        (row,) = document['flows']
        self.assertEqual((2, 1, 5, True, True), (row['frames_out'], row['frames_back'], row['bytes_out'],
                                                 row['syn'], row['syn_ack']))
        self.assertEqual((None, 4), (document['error'], document['dropped']))

    def test_a_run_that_does_not_ask_for_the_count_opens_no_second_socket_and_writes_no_file(self):
        route = FakeCapture()
        observer = self.observer(route)
        health = observer.run()
        self.assertFalse(health['error'])
        self.assertFalse((observer.directory / 'route-flows.json').exists())

    def test_a_link_that_cannot_be_opened_is_said_in_the_file_and_the_observer_goes_on(self):
        route = FakeCapture()
        observer = self.observer(route, route_flows=True)

        def open_capture(interface):
            if interface == 'rt-route':
                raise OSError('no such device')
            return observer.capture
        with patch.object(self.entry, 'open_capture', open_capture):
            health = observer.run()
        self.assertFalse(health['error'])
        self.assertEqual(dict(flows=[], omitted_frames=0, other_frames=0, unparsed_frames=0,
                              error='route-capture-unavailable', dropped=None), self.document(observer))

    def test_a_link_that_fails_while_counting_is_said_in_the_file_and_the_observer_stays_clean(self):
        route = FakeCapture(explode=OSError('network is down'))
        observer = self.observer(route, route_flows=True).start().wait_ready()
        route.feed(out())
        time.sleep(.4)
        health = observer.finish()
        self.assertEqual((False, 0), (health['error'], health['dropped']))
        self.assertEqual('route-count-failed', self.document(observer)['error'])

    def test_a_file_that_cannot_be_written_changes_nothing_else(self):
        observer = self.observer(FakeCapture(), route_flows=True)
        with patch.object(self.entry, 'write_route_flows', side_effect=OSError('disk full')):
            health = observer.run()
        self.assertFalse(health['error'])
        self.assertFalse((observer.directory / 'route-flows.json').exists())


class ControllerTests(unittest.TestCase):
    def row(self, **changes):
        return dict(proto='tcp', client=ROUTER + ':51000', server=TARGET + ':443', frames_out=4, frames_back=3,
                    bytes_out=120, bytes_back=400, first_at=1000.5, last_at=1015.5, syn=True, syn_ack=True,
                    fin=['out'], rst=[]) | changes

    def block(self, rows, **extra):
        return l3_lab.route_flows_block(dict(flows=rows, omitted_frames=0, other_frames=5, unparsed_frames=0,
                                             error=None, dropped=0, **extra))

    def test_a_well_formed_document_is_passed_on_field_by_field(self):
        block = self.block([self.row(secret='x')])
        self.assertEqual([self.row()], block['flows'])
        self.assertEqual((0, 0, 5, 0, None), (block['rejected_rows'], block['omitted_frames'], block['other_frames'],
                                              block['dropped'], block['error']))

    def test_a_row_of_another_shape_is_left_out_and_counted(self):
        bad = [self.row(proto='icmp'), self.row(client='a b'), self.row(frames_out=-1), self.row(bytes_back='1'),
               self.row(syn=1), self.row(fin=['sideways']), self.row(fin=['out', 'out']), self.row(first_at=None),
               {k: v for k, v in self.row().items() if k != 'rst'}, 'text']
        block = self.block([self.row()] + bad)
        self.assertEqual(([self.row()], len(bad)), (block['flows'], block['rejected_rows']))

    def test_more_rows_than_the_helper_keeps_are_rejected(self):
        block = self.block([self.row()] * (wire.ROUTE_FLOW_LIMIT + 3))
        self.assertEqual((wire.ROUTE_FLOW_LIMIT, 3), (len(block['flows']), block['rejected_rows']))

    def test_a_reason_and_the_counters_are_kept_only_in_their_shape(self):
        document = dict(flows=[], omitted_frames=-1, other_frames='3', unparsed_frames=True, error='Bad Reason!',
                        dropped=2 ** 50)
        block = l3_lab.route_flows_block(document)
        self.assertEqual((None, None, None, None, None), (block['omitted_frames'], block['other_frames'],
                                                          block['unparsed_frames'], block['error'],
                                                          block['dropped']))

    def test_a_document_that_is_no_document_is_none(self):
        for value in (None, [], 'text', dict(flows='x'), dict()):
            self.assertIsNone(l3_lab.route_flows_block(value))
