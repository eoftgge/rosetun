"""The scenarios of the group lined up with the flows of the wire and of the route link, on synthetic data."""
from datetime import datetime, timezone
import copy
import json
import unittest

from tools.vm.matrix import l3_align as align_module
from tools.vm.matrix.l3_summary import GROUP, WINDOW_OF

OPENED, CLOSED = 1000.0, 1060.0
FINISHED = datetime(2026, 11, 14, 0, 10, tzinfo=timezone.utc).timestamp()
CONNECT_KS = [identifier for identifier in GROUP if WINDOW_OF[identifier] == ('connect_ks', 0)]
DURATIONS = dict(zip(CONNECT_KS, (8000, 15000, 2000, 5000, 7000, 4000, 3000)))


def rows(durations=DURATIONS, others=1000):
    """The scenarios of the group in the order of the report, each with its duration."""
    return [dict(id=identifier, group='x', evidence='real-service', result='PASS', reason='ok',
                 duration_ms=durations.get(identifier, others)) for identifier in GROUP]


def wire(first_ms, last_ms, client='192.0.2.2:43000', kind='node', **changes):
    return dict(kind=kind, client=client, server='192.0.2.1:8388', frames_out=4, frames_back=3, bytes_out=120,
                bytes_back=400, first_ms=first_ms, last_ms=last_ms, syn=True, syn_ack=True, fin=[], rst=[]) | changes


def route(first_at, last_at, client='203.0.113.1:51000', **changes):
    return dict(proto='tcp', client=client, server='203.0.113.2:443', frames_out=4, frames_back=3, bytes_out=120,
                bytes_back=400, first_at=first_at, last_at=last_at, syn=True, syn_ack=True, fin=[],
                rst=['back']) | changes


def window(index=0, label='connect_ks', open_at=OPENED, close_at=CLOSED, connections=()):
    return dict(index=index, label=label, clock=dict(open_at=open_at, close_at=close_at),
                flows=dict(connections=list(connections), omitted=0))


def lab(windows, flows=None):
    block = dict(windows=windows)
    if flows is not None:
        block['route_flows'] = dict(flows=flows)
    return block


def of(table, identifier):
    return next(entry for entry in table['scenarios'] if entry['id'] == identifier)


class ReportTests(unittest.TestCase):
    def test_the_time_the_report_finished_and_its_cleanup_are_read_as_the_test_machine_wrote_them(self):
        raw = json.dumps(dict(finished='2026-11-14T00:10:00Z', cleanup=dict(duration_ms=2500))).encode()
        self.assertEqual(dict(finished=FINISHED, cleanup_ms=2500), align_module.report_clock(raw))

    def test_a_report_that_says_nothing_usable_gives_none_and_never_raises(self):
        for raw in (b'', b'[]', b'{}', b'{"finished": 5}', b'{"finished": "yesterday"}', b'\xff'):
            with self.subTest(raw=raw):
                self.assertEqual(dict(finished=None, cleanup_ms=None), align_module.report_clock(raw))
        raw = json.dumps(dict(finished='2026-11-14T00:10:00Z', cleanup=[])).encode()
        self.assertIsNone(align_module.report_clock(raw)['cleanup_ms'])
        raw = json.dumps(dict(finished='2026-11-14T00:10:00Z', cleanup=dict(duration_ms=-1))).encode()
        self.assertIsNone(align_module.report_clock(raw)['cleanup_ms'])

    def test_scenarios_are_placed_back_to_back_from_the_end_of_the_report(self):
        listing = [dict(id='a', duration_ms=1000), dict(id='b', duration_ms=2000), dict(id='c', duration_ms=500)]
        times = align_module.report_times(listing, dict(finished=100.0, cleanup_ms=500))
        self.assertEqual({'c': (99.0, 99.5), 'b': (97.0, 99.0), 'a': (96.0, 97.0)}, times)
        self.assertEqual({}, align_module.report_times(listing, dict(finished=None, cleanup_ms=None)))


class PlacementTests(unittest.TestCase):
    def table(self, windows=None, flows=None, report=None, listing=None):
        return align_module.align(listing or rows(), report, lab(windows if windows is not None else [window()], flows))

    def test_a_scenario_is_placed_after_those_of_its_window_that_ran_before_it_and_before_those_after_it(self):
        entry = of(self.table(), 'killswitch.tunnel-passes')
        self.assertEqual(dict(begin=8000, end=39000, slack=16000, window_span=60000), entry['interval_ms'])
        first = of(self.table(), 'killswitch.direct-blocked')['interval_ms']
        last = of(self.table(), 'killswitch.disconnect')['interval_ms']
        self.assertEqual((0, 24000), (first['begin'], first['end']))
        self.assertEqual((41000, 60000), (last['begin'], last['end']))

    def test_every_scenario_of_the_group_is_listed_in_order_and_marked_approximate(self):
        table = self.table()
        self.assertEqual(list(GROUP), [entry['id'] for entry in table['scenarios']])
        self.assertTrue(all(entry['approximate'] for entry in table['scenarios']))
        self.assertIn('approximate', table['note'])
        self.assertTrue(table['clock']['approximate'])

    def test_a_scenario_with_no_window_or_a_window_without_both_markers_is_listed_but_not_placed(self):
        table = self.table(windows=[window(open_at=None)])
        for identifier in ('preflight.identity', 'killswitch.tunnel-passes', 'engine.identity'):
            with self.subTest(identifier):
                entry = of(table, identifier)
                self.assertEqual((None, [], []), (entry['interval_ms'], entry['wire_flows'], entry['route_flows']))
        self.assertIsNone(of(table, 'preflight.identity')['window'])
        self.assertEqual(1, of(table, 'killswitch.tunnel-passes')['windows_with_label'])

    def test_a_scenario_the_report_lacks_is_missing_and_the_others_are_still_placed(self):
        listing = [row for row in rows() if row['id'] != 'lan.off']
        table = self.table(listing=listing)
        self.assertEqual(('MISSING', None), (of(table, 'lan.off')['result'], of(table, 'lan.off')['interval_ms']))
        self.assertEqual(dict(begin=8000, end=41000, slack=18000, window_span=60000),
                         of(table, 'killswitch.tunnel-passes')['interval_ms'])

    def test_durations_longer_than_the_window_are_shown_as_a_negative_slack_inside_it(self):
        table = self.table(windows=[window(close_at=OPENED + 30)])
        entry = of(table, 'killswitch.tunnel-passes')['interval_ms']
        self.assertEqual((-14000, 30000), (entry['slack'], entry['window_span']))
        self.assertTrue(0 <= entry['begin'] <= entry['end'] <= 30000)

    def test_the_first_window_of_a_label_that_has_both_markers_is_used_and_the_others_are_counted(self):
        windows = [window(0, open_at=None), window(1, open_at=2000.0, close_at=2060.0), window(2)]
        entry = of(self.table(windows=windows), 'killswitch.tunnel-passes')
        self.assertEqual((1, 3), (entry['window'], entry['windows_with_label']))


class FlowTests(unittest.TestCase):
    def table(self, connections=(), flows=None):
        return align_module.align(rows(), None, lab([window(connections=connections)], flows))

    def test_wire_flows_are_the_ones_of_the_window_that_overlap_the_interval_of_the_scenario(self):
        inside = wire(8500, 23500)
        connections = [wire(0, 3000, client='192.0.2.2:43001'), inside, wire(50000, 52000, client='192.0.2.2:43002'),
                       wire(38000, 41000, client='192.0.2.2:43003')]
        entry = of(self.table(connections), 'killswitch.tunnel-passes')
        self.assertEqual([inside, connections[3]], entry['wire_flows'])
        self.assertEqual(0, entry['wire_omitted'])
        first = of(self.table(connections), 'killswitch.direct-blocked')
        self.assertEqual([connections[0], inside], first['wire_flows'])

    def test_a_flow_with_no_time_is_kept_and_says_so(self):
        entry = of(self.table([wire(None, None)]), 'lan.off')
        (flow,) = entry['wire_flows']
        self.assertIs(True, flow['time_unknown'])

    def test_route_flows_are_set_in_milliseconds_after_the_opening_marker_and_overlap_the_same_way(self):
        flows = [route(OPENED + 9.0, OPENED + 24.0), route(OPENED - 20, OPENED - 5, client='203.0.113.1:51001'),
                 route(OPENED + 55, OPENED + 58, client='203.0.113.1:51002')]
        entry = of(self.table(flows=flows), 'killswitch.tunnel-passes')
        (flow,) = entry['route_flows']
        self.assertEqual((9000, 24000, '203.0.113.1:51000', ['back']),
                         (flow['first_ms'], flow['last_ms'], flow['client'], flow['rst']))
        self.assertNotIn('first_at', flow)
        late = of(self.table(flows=flows), 'killswitch.disconnect')
        self.assertEqual(['203.0.113.1:51002'], [f['client'] for f in late['route_flows']])

    def test_a_route_flow_that_began_before_the_window_and_is_still_open_in_it_is_listed(self):
        entry = of(self.table(flows=[route(OPENED - 30, OPENED + 12)]), 'killswitch.tunnel-passes')
        self.assertEqual([(-30000, 12000)], [(f['first_ms'], f['last_ms']) for f in entry['route_flows']])

    def test_a_run_without_route_flows_lists_none_and_still_lists_the_wire(self):
        entry = of(self.table([wire(9000, 12000)], flows=None), 'killswitch.tunnel-passes')
        self.assertEqual((1, []), (len(entry['wire_flows']), entry['route_flows']))

    def test_the_flows_of_a_scenario_are_capped_and_the_rest_counted(self):
        many = [wire(9000 + n, 9500 + n, client='192.0.2.2:%d' % (43000 + n)) for n in range(30)]
        routes = [route(OPENED + 9, OPENED + 10, client='203.0.113.1:%d' % (51000 + n)) for n in range(27)]
        entry = of(self.table(many, routes), 'killswitch.tunnel-passes')
        cap = align_module.FLOWS_PER_SCENARIO
        self.assertEqual((cap, 30 - cap, cap, 27 - cap),
                         (len(entry['wire_flows']), entry['wire_omitted'], len(entry['route_flows']),
                          entry['route_omitted']))

    def test_the_input_is_left_as_it_was(self):
        connections, flows = [wire(8500, 23500)], [route(OPENED + 9, OPENED + 24)]
        windows = [window(connections=connections)]
        before = copy.deepcopy((windows, flows, rows()))
        align_module.align(rows(), None, lab(windows, flows))
        self.assertEqual(before, (windows, flows, rows()))


class ClockTests(unittest.TestCase):
    def report(self, finished='2026-11-14T00:10:00Z'):
        return json.dumps(dict(finished=finished, cleanup=dict(duration_ms=0))).encode()

    def test_the_test_machine_times_are_counted_back_from_the_end_of_the_report_and_marked_approximate(self):
        listing = rows()
        table = align_module.align(listing, self.report(), lab([window()]))
        last = of(table, GROUP[-1])
        self.assertEqual('2026-11-14T00:10:00.000Z', last['report_end'])
        self.assertEqual('2026-11-14T00:09:59.000Z', last['report_begin'])
        first = of(table, 'preflight.identity')
        self.assertEqual(1.0, (datetime.fromisoformat(first['report_end'][:-1])
                               - datetime.fromisoformat(first['report_begin'][:-1])).total_seconds())

    def test_the_offset_is_the_lab_clock_at_the_opening_marker_less_the_test_clock_at_the_first_scenario(self):
        listing = rows()
        total_after_start = sum(row['duration_ms'] for row in listing[listing.index(
            next(r for r in listing if r['id'] == CONNECT_KS[0])):]) / 1000
        begin = FINISHED - total_after_start
        table = align_module.align(listing, self.report(), lab([window()]))
        (row,) = table['clock']['by_window']
        self.assertEqual(('connect_ks', 0, 1), (row['label'], row['window'], row['count']))
        self.assertAlmostEqual(OPENED - begin, row['offset_s'], places=3)
        self.assertEqual((row['offset_s'], 0.0), (table['clock']['offset_s'], table['clock']['spread_s']))

    def test_with_several_windows_the_estimate_is_the_median_and_the_spread_is_the_range(self):
        listing = rows()
        windows = [window(0, 'identity', open_at=500.0, close_at=520.0), window(1, 'connect_ks'),
                   window(2, 'reported', open_at=100.0, close_at=110.0)]
        table = align_module.align(listing, self.report(), lab(windows))
        offsets = sorted(row['offset_s'] for row in table['clock']['by_window'])
        self.assertEqual(3, len(offsets))
        self.assertEqual(offsets[1], table['clock']['offset_s'])
        self.assertAlmostEqual(offsets[2] - offsets[0], table['clock']['spread_s'], places=3)

    def test_without_a_time_in_the_report_there_is_no_offset_and_the_windows_still_place_the_scenarios(self):
        table = align_module.align(rows(), None, lab([window()]))
        self.assertEqual((None, None, []), (table['clock']['offset_s'], table['clock']['spread_s'],
                                             table['clock']['by_window']))
        self.assertIsNone(of(table, 'killswitch.tunnel-passes')['report_begin'])
        self.assertIsNotNone(of(table, 'killswitch.tunnel-passes')['interval_ms'])
