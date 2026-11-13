"""Phase windows: the marker, the helper's acceptance of it and the split of a capture, on synthetic pcaps."""
import unittest

from tools.vm.matrix import lab_protocol as wire
from tools.vm.matrix.tests.test_lab import capture, icmp, ip_frame, udp
from tools.vm.matrix.tests.test_lab_fixtures import Base
from tools.vm.matrix.tests.test_lab_tunnel_protocol import from_node, to_node

RUN = 'a' * 32
LEAK = ip_frame(wire.CLIENTS[4], wire.TARGETS[4], 1, icmp(8))


def marker_frames(index, word, label, run=RUN, answered=True):
    m = wire.window_marker(run, index, word, label)
    frames = [ip_frame(m['source'], m['target'], 17, udp(41000, m['port'], wire.marker_query(m)))]
    if answered:
        frames.append(ip_frame(m['target'], m['source'], 17, udp(m['port'], 41000, wire.marker_answer(m)),
                               src=wire.MACS['lab'], dst=wire.MACS['test']))
    return frames


def window(index, label, body=(), *, close=True):
    return marker_frames(index, 'open', label) + list(body) + (marker_frames(index, 'close', label) if close else [])


def health(rows, **changes):
    marks = [dict(word=word, index=index, label=label, at=2.0 + n) for n, (index, word, label) in enumerate(rows)]
    return dict(error=False, dropped=0, finished=True, capture_started=1.0, capture_ended=100.0,
                markers=marks) | changes


def served(frames_spec):
    return [(i, w, l) for i, l in frames_spec for w in ('open', 'close')]


class Cases(unittest.TestCase):
    LABELS = ['first', 'second', 'third']

    def verdict(self, frames, labels=None, rows=None, ready=True, **changes):
        labels = self.LABELS if labels is None else labels
        spec = [dict(label=label) for label in labels]
        raw = capture(frames) if isinstance(frames, list) else frames
        if rows is None:
            rows = served(list(enumerate(labels)))
        arguments = dict(health=health(rows), ready=ready) | changes
        return wire.classify_windows(raw, RUN, spec, **arguments)

    def three(self, bodies=((), (), ())):
        return [f for i, label in enumerate(self.LABELS) for f in window(i, label, bodies[i])]

    def leaks(self, result):
        return [w['leak'] for w in result['windows']]


class MarkerTests(unittest.TestCase):
    def test_the_marker_names_run_index_word_and_label(self):
        m = wire.window_marker(RUN, 3, 'open', 'killswitch.direct-blocked')
        self.assertEqual(b'rosetun-lab-marker:' + RUN.encode() + b'.3.open.killswitch.direct-blocked', wire.marker_query(m))
        self.assertEqual(b'rosetun-lab-ack:' + wire.marker_query(m), wire.marker_answer(m))
        self.assertEqual((3, 'open', 'killswitch.direct-blocked'), wire.parse_window_marker(wire.marker_query(m), RUN))

    def test_a_malformed_marker_is_refused_on_both_sides(self):
        for args in ((RUN, -1, 'open', 'x'), (RUN, 100, 'open', 'x'), (RUN, True, 'open', 'x'), (RUN, 0, 'middle', 'x'),
                     (RUN, 0, 'open', ''), (RUN, 0, 'open', 'A'), (RUN, 0, 'open', 'a' * 49), (RUN, 0, 'open', 'a b')):
            with self.subTest(args=args), self.assertRaises(ValueError):
                wire.window_marker(*args)
        prefix = b'rosetun-lab-marker:' + RUN.encode()
        for data in (prefix + b'.01.open.x', prefix + b'.0.open.', prefix + b'.0.open.x\n', prefix + b'.100.open.x',
                     prefix + b'.0.open.x.', b'rosetun-lab-marker:' + b'b' * 32 + b'.0.open.x', prefix + b'.0.open'):
            with self.subTest(data=data):
                found = wire.parse_window_marker(data, RUN)
                self.assertIsNone(found) if data != prefix + b'.0.open.x.' else self.assertEqual((0, 'open', 'x.'), found)

    def test_the_markers_of_stage_6b_keep_their_bytes(self):
        m = wire.markers(RUN, iter(['0' * 24, '1' * 24]).__next__)[0]
        self.assertEqual(b'rosetun-lab-marker:' + RUN.encode() + b'.' + b'0' * 24 + b'.open', wire.marker_query(m))
        self.assertIsNone(wire.parse_window_marker(wire.marker_query(m), RUN))


class HelperTests(Base):
    def windows_request(self, **changes):
        plain = {k: v for k, v in self.request.items() if k != 'tunnel'}
        return dict(plain, markers=[], windows=True) | changes

    def test_a_windows_request_carries_no_markers_of_its_own(self):
        self.assertEqual('enp7s0', self.identity(self.windows_request()))
        own = wire.markers(RUN, iter(f'{i:024x}' for i in range(20, 22)).__next__)
        for markers in (own, [{}], None):
            with self.subTest(markers=markers), self.assertRaises((ValueError, TypeError)):
                self.identity(self.windows_request(markers=markers))
        for value in (False, 1, 'yes'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.identity(self.windows_request(windows=value))

    def test_with_a_tunnel_the_nonces_of_probes_and_exchanges_still_must_differ(self):
        request = dict(self.request, markers=[], windows=True)
        self.assertEqual('enp7s0', self.identity(request))
        first, second = request['tunnel']['https']
        probe = request['probes'][0]['nonce']
        clash = dict(request['tunnel'], https=[first, dict(second, nonce=probe, path='/' + RUN + '/' + probe)])
        with self.assertRaises(ValueError):
            self.identity(dict(request, tunnel=clash))

    def test_any_index_is_accepted(self):
        request = self.windows_request(lab_id=RUN)
        for index in (0, 1, 7, 99):
            data = wire.marker_query(wire.window_marker(RUN, index, 'close', 'phase'))
            self.assertEqual((index, 'close', 'phase'),
                             self.entry.accept_window_marker(request, [], data, wire.CLIENTS[4]))

    def test_a_marker_of_another_run_source_or_shape_is_refused_and_the_log_is_bounded(self):
        request = self.windows_request(lab_id=RUN)
        good = wire.marker_query(wire.window_marker(RUN, 0, 'open', 'x'))
        for name, data, source, marks in (('run', wire.marker_query(wire.window_marker('b' * 32, 0, 'open', 'x')),
                                           wire.CLIENTS[4], []),
                                          ('source', good, '192.0.2.9', []), ('shape', good + b'!', wire.CLIENTS[4], []),
                                          ('full', good, wire.CLIENTS[4], [0] * (2 * wire.WINDOW_LIMIT))):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'unexpected-marker'):
                self.entry.accept_window_marker(request, marks, data, source)


class WindowTests(Cases):
    def test_three_clean_windows_are_none(self):
        result = self.verdict(self.three())
        self.assertEqual(['NONE'] * 3, self.leaks(result))
        self.assertEqual(['first', 'second', 'third'], [w['label'] for w in result['windows']])
        self.assertEqual({'NONE'}, {w['expected'] for w in result['windows']})
        self.assertEqual([4, 4, 4], [w['categories']['marker'] for w in result['windows']])
        self.assertEqual(0, result['outside_window']['categories']['outside-window'])

    def test_a_leak_in_the_second_window_is_detected_there_only(self):
        result = self.verdict(self.three(((), (LEAK,), ())))
        self.assertEqual(['NONE', 'DETECTED', 'NONE'], self.leaks(result))
        second = result['windows'][1]
        self.assertEqual((1, 1, 'unexpected-frames'), (second['categories']['unexpected'], len(second['unexpected']),
                                                      second['leak_reason']))
        self.assertEqual(0, result['outside_window']['categories']['outside-window'])

    def test_a_skipped_index_makes_the_missing_window_and_those_after_it_unverified(self):
        frames = window(0, 'first') + window(2, 'third')
        result = self.verdict(frames, rows=served([(0, 'first'), (2, 'third')]))
        self.assertEqual(['NONE', 'UNVERIFIED', 'UNVERIFIED'], self.leaks(result))
        self.assertEqual('window-missing', result['windows'][1]['leak_reason'])
        self.assertIn('window-index-out-of-sequence', result['windows'][2]['observer_reasons'])

    def test_a_window_without_its_closing_marker_is_unverified(self):
        frames = window(0, 'first') + window(1, 'second', close=False)
        result = self.verdict(frames, labels=['first', 'second'], rows=[(0, 'open', 'first'), (0, 'close', 'first'),
                                                                        (1, 'open', 'second')])
        self.assertEqual(['NONE', 'UNVERIFIED'], self.leaks(result))
        self.assertEqual('window-markers-missing-or-repeated', result['windows'][1]['leak_reason'])

    def test_an_unanswered_marker_is_unverified(self):
        frames = (marker_frames(0, 'open', 'first', answered=False) + marker_frames(0, 'close', 'first'))
        result = self.verdict(frames, labels=['first'], rows=served([(0, 'first')]))
        self.assertEqual('window-markers-missing-or-repeated', result['windows'][0]['leak_reason'])

    def test_a_leak_outside_the_windows_is_counted_apart_and_changes_no_verdict(self):
        frames = [LEAK] + self.three() + [LEAK, LEAK]
        result = self.verdict(frames)
        self.assertEqual(['NONE'] * 3, self.leaks(result))
        self.assertEqual(3, result['outside_window']['categories']['outside-window'])
        self.assertEqual(3, len(result['outside_window']['frames']))
        self.assertEqual([0, 0, 0], [w['categories']['unexpected'] for w in result['windows']])
        between = window(0, 'first') + [LEAK] + window(1, 'second')
        result = self.verdict(between, labels=['first', 'second'], rows=served([(0, 'first'), (1, 'second')]))
        self.assertEqual((['NONE', 'NONE'], 1), (self.leaks(result), result['outside_window']['categories']['outside-window']))

    def test_the_frames_of_the_tunnel_inside_a_window_are_not_a_leak_when_the_port_is_declared(self):
        bodies = ((to_node(), from_node()), (), ())
        result = self.verdict(self.three(bodies), tunnel_port=wire.NODE_PORT)
        self.assertEqual(['NONE'] * 3, self.leaks(result))
        self.assertEqual(2, result['windows'][0]['categories']['tunnel'])
        silent = self.verdict(self.three(bodies))
        self.assertEqual(['DETECTED', 'NONE', 'NONE'], self.leaks(silent))
        self.assertNotIn('tunnel', silent['windows'][0]['categories'])

    def test_a_marker_with_another_run_id_is_an_unexpected_frame(self):
        foreign = marker_frames(1, 'open', 'second', run='b' * 32, answered=False)
        result = self.verdict(self.three(((), foreign, ())))
        self.assertEqual(['NONE', 'DETECTED', 'NONE'], self.leaks(result))
        outside = self.verdict(foreign + self.three())
        self.assertEqual(['NONE'] * 3, self.leaks(outside))
        self.assertEqual(1, outside['outside_window']['categories']['outside-window'])

    def test_an_opening_inside_an_open_window_spoils_the_windows_from_there_and_keeps_a_seen_leak(self):
        frames = (marker_frames(0, 'open', 'first') + [LEAK] + marker_frames(1, 'open', 'second')
                  + marker_frames(1, 'close', 'second') + window(2, 'third'))
        rows = [(0, 'open', 'first'), (1, 'open', 'second'), (1, 'close', 'second'), (2, 'open', 'third'),
                (2, 'close', 'third')]
        result = self.verdict(frames, rows=rows)
        self.assertEqual(['DETECTED', 'UNVERIFIED', 'UNVERIFIED'], self.leaks(result))
        self.assertIn('open-inside-open-window', result['windows'][1]['observer_reasons'])

    def test_a_repeated_index_and_a_reverse_order_spoil_the_windows_after_the_fault(self):
        repeated = window(0, 'first') + window(1, 'second') + window(1, 'second') + window(2, 'third')
        rows = served([(0, 'first'), (1, 'second'), (1, 'second'), (2, 'third')])
        result = self.verdict(repeated, rows=rows)
        self.assertEqual(['NONE', 'UNVERIFIED', 'UNVERIFIED'], self.leaks(result))
        self.assertEqual('window-markers-missing-or-repeated', result['windows'][1]['leak_reason'])
        reverse = window(0, 'first') + window(2, 'third') + window(1, 'second')
        result = self.verdict(reverse, rows=served([(0, 'first'), (2, 'third'), (1, 'second')]))
        self.assertEqual(['NONE', 'UNVERIFIED', 'UNVERIFIED'], self.leaks(result))
        swapped = marker_frames(0, 'close', 'first') + marker_frames(0, 'open', 'first')
        result = self.verdict(swapped, labels=['first'], rows=[(0, 'close', 'first'), (0, 'open', 'first')])
        self.assertEqual('UNVERIFIED', self.leaks(result)[0])
        self.assertIn('close-without-open', result['windows'][0]['observer_reasons'])

    def test_a_label_other_than_the_expected_one_is_unverified(self):
        result = self.verdict(self.three(), labels=['first', 'other', 'third'],
                              rows=served([(0, 'first'), (1, 'second'), (2, 'third')]))
        self.assertEqual(['NONE', 'UNVERIFIED', 'NONE'], self.leaks(result))
        self.assertEqual('window-label-mismatch', result['windows'][1]['leak_reason'])

    def test_a_window_the_controller_did_not_expect_spoils_all(self):
        result = self.verdict(self.three(), labels=['first', 'second'], rows=served(list(enumerate(self.LABELS))))
        self.assertEqual(['UNVERIFIED', 'UNVERIFIED'], self.leaks(result))
        self.assertEqual([2], result['extra_windows'])
        self.assertIn('window-count-mismatch', result['observer_reasons'])

    def test_an_unclean_observer_makes_every_window_unverified_but_keeps_a_seen_leak(self):
        frames = self.three(((), (LEAK,), ()))
        for name, changes in (('not-ready', dict(ready=False)),
                              ('error', dict(health=health(served(list(enumerate(self.LABELS))), error=True))),
                              ('dropped', dict(health=health(served(list(enumerate(self.LABELS))), dropped=1))),
                              ('unfinished', dict(health=health(served(list(enumerate(self.LABELS))), finished=False)))):
            with self.subTest(name=name):
                result = self.verdict(frames, **changes)
                self.assertEqual(['UNVERIFIED', 'DETECTED', 'UNVERIFIED'], self.leaks(result))

    def test_what_the_lab_served_must_be_what_the_wire_shows(self):
        rows = served(list(enumerate(self.LABELS)))
        for name, changed in (('missing', rows[:-1]), ('extra', rows + [(3, 'open', 'x')]),
                              ('order', rows[1:2] + rows[:1] + rows[2:]), ('label', rows[:-1] + [(2, 'close', 'zzz')])):
            with self.subTest(name=name):
                self.assertEqual(['UNVERIFIED'] * 3, self.leaks(self.verdict(self.three(), rows=changed)))
        for bad in (None, 'x', [1]):
            with self.subTest(bad=bad):
                broken = dict(health(rows), markers=bad)
                self.assertEqual(['UNVERIFIED'] * 3, self.leaks(self.verdict(self.three(), health=broken)))
        late = health(rows, capture_ended=1.0)
        self.assertEqual(['UNVERIFIED'] * 3, self.leaks(self.verdict(self.three(), health=late)))

    def test_a_cut_or_overlong_or_unreadable_capture_never_says_none(self):
        raw = capture(self.three())
        for name, bad in (('cut', raw[:-5]), ('header', raw[1:]), ('empty', b'')):
            with self.subTest(name=name):
                self.assertNotIn('NONE', self.leaks(self.verdict(bad)))
        result = self.verdict(raw, limit=len(raw) + 100)
        self.assertEqual(['UNVERIFIED'] * 3, self.leaks(result))
        self.assertIn('capture-limit-reached', result['observer_reasons'])
        self.assertEqual(['NONE'] * 3, self.leaks(self.verdict(raw, limit=len(raw) + 16 + 2048)))

    def test_an_unreadable_frame_inside_a_window_spoils_that_window_only(self):
        broken = bytes(12) + b'\x08\x00\x45'
        result = self.verdict(self.three(((), (broken,), ())))
        self.assertEqual(['NONE', 'UNVERIFIED', 'NONE'], self.leaks(result))
        self.assertEqual(1, result['windows'][1]['categories']['unparsed'])
        outside = self.verdict([broken] + self.three())
        self.assertEqual((['NONE'] * 3, 1), (self.leaks(outside), outside['outside_window']['categories']['unparsed']))

    def test_only_none_is_an_expectation_for_now(self):
        for spec in ([dict(label='x', expected='DETECTED')], [dict(label='x', expected='')], [dict(label='X')],
                     [dict(label='x', extra=1)], [], 'x', [dict()], [dict(label=1)], [dict(label='x')] * 101):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                wire.classify_windows(capture([]), RUN, spec, health=health([]), ready=True)
        self.assertEqual(['NONE'], self.leaks(self.verdict(window(0, 'x'), labels=['x'], rows=served([(0, 'x')]))))

    def test_allowances_and_the_run_wide_options_apply_to_every_window(self):
        probe = ip_frame(wire.CLIENTS[4], wire.TARGETS[4], 17, udp(1, wire.CANARY_PORT, b'c'))
        result = self.verdict(self.three(((probe,), (), ())))
        self.assertEqual('DETECTED', result['windows'][0]['leak'])
        with self.assertRaises(ValueError):
            self.verdict(self.three(), allowances=('nonsense',))
        result = self.verdict(self.three(), allowances=('arp-probe',))
        self.assertEqual({'arp-probe': 0}, result['windows'][0]['categories']['allowed'])


class FoundWindowTests(Cases):
    """No list from the controller: the windows are the ones the markers name, by label."""
    GROUP = ['first', 'second']

    def found(self, frames, rows, required=GROUP, **changes):
        raw = capture(frames) if isinstance(frames, list) else frames
        return wire.classify_windows(raw, RUN, None, health=health(rows), ready=True,
                                     required_labels=required, **changes)

    def test_any_number_of_windows_with_any_labels_is_found_in_order(self):
        frames = window(0, 'first') + window(1, 'other') + window(2, 'second') + window(3, 'first')
        rows = served([(0, 'first'), (1, 'other'), (2, 'second'), (3, 'first')])
        result = self.found(frames, rows)
        self.assertEqual(['NONE'] * 4, self.leaks(result))
        self.assertEqual(['first', 'other', 'second', 'first'], [w['label'] for w in result['windows']])
        self.assertEqual([True, False, True, True], [w['in_group'] for w in result['windows']])
        self.assertEqual([], result['missing_labels'])
        self.assertEqual([], result['extra_windows'])
        self.assertNotIn('window-count-mismatch', result['observer_reasons'])

    def test_a_session_outside_the_group_spoils_nobody_and_a_leak_in_it_is_still_detected(self):
        frames = window(0, 'first') + window(1, 'other', (LEAK,)) + window(2, 'second')
        result = self.found(frames, served([(0, 'first'), (1, 'other'), (2, 'second')]))
        self.assertEqual(['NONE', 'DETECTED', 'NONE'], self.leaks(result))
        self.assertFalse(result['windows'][1]['in_group'])

    def test_two_windows_with_one_label_are_judged_each_by_itself(self):
        frames = window(0, 'first') + window(1, 'second') + window(2, 'first', (LEAK,))
        result = self.found(frames, served([(0, 'first'), (1, 'second'), (2, 'first')]))
        self.assertEqual(['NONE', 'NONE', 'DETECTED'], self.leaks(result))
        self.assertEqual([], result['missing_labels'])

    def test_a_label_of_the_group_without_a_window_is_listed_and_spoils_no_other_window(self):
        frames = window(0, 'first') + window(1, 'other')
        result = self.found(frames, served([(0, 'first'), (1, 'other')]))
        self.assertEqual(['NONE', 'NONE'], self.leaks(result))
        self.assertEqual(['second'], result['missing_labels'])
        nothing = self.found([], [])
        self.assertEqual([], nothing['windows'])
        self.assertEqual(self.GROUP, nothing['missing_labels'])

    def test_an_index_out_of_sequence_in_the_middle_spoils_the_windows_after_it(self):
        frames = window(0, 'first') + window(2, 'second') + window(3, 'first')
        result = self.found(frames, served([(0, 'first'), (2, 'second'), (3, 'first')]))
        self.assertEqual(['NONE', 'UNVERIFIED', 'UNVERIFIED', 'UNVERIFIED'], self.leaks(result))
        self.assertEqual('window-missing', result['windows'][1]['leak_reason'])
        self.assertIsNone(result['windows'][1]['label'])
        self.assertIn('window-index-out-of-sequence', result['windows'][2]['observer_reasons'])
        self.assertEqual([], result['missing_labels'])

    def test_a_repeated_index_and_a_missing_close_spoil_only_what_the_rules_say(self):
        frames = window(0, 'first') + window(1, 'second', close=False)
        rows = [(0, 'open', 'first'), (0, 'close', 'first'), (1, 'open', 'second')]
        result = self.found(frames, rows)
        self.assertEqual(['NONE', 'UNVERIFIED'], self.leaks(result))
        self.assertEqual('window-markers-missing-or-repeated', result['windows'][1]['leak_reason'])
        self.assertEqual([], result['missing_labels'])

    def test_a_label_that_changes_inside_a_window_is_unverified(self):
        frames = marker_frames(0, 'open', 'first') + marker_frames(0, 'close', 'second')
        result = self.found(frames, [(0, 'open', 'first'), (0, 'close', 'second')])
        self.assertEqual('window-label-mismatch', result['windows'][0]['leak_reason'])

    def test_the_observer_rules_still_apply_to_every_found_window(self):
        frames = window(0, 'first') + window(1, 'other')
        result = wire.classify_windows(capture(frames), RUN, None, ready=False, required_labels=self.GROUP,
                                       health=health(served([(0, 'first'), (1, 'other')])))
        self.assertEqual(['UNVERIFIED', 'UNVERIFIED'], self.leaks(result))
        self.assertIn('observer-not-ready', result['windows'][0]['observer_reasons'])

    def test_the_two_modes_do_not_mix_and_the_labels_are_checked(self):
        spec = [dict(label='first')]
        with self.assertRaises(ValueError):
            wire.classify_windows(capture([]), RUN, spec, health=health([]), ready=True, required_labels=['first'])
        for bad in (['First'], ['a', 'a'], [1], 'first', ['x' * 49]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                wire.classify_windows(capture([]), RUN, None, health=health([]), ready=True, required_labels=bad)

    def test_the_exact_mode_has_no_found_mode_fields(self):
        result = self.verdict(self.three())
        self.assertNotIn('missing_labels', result)
        self.assertNotIn('in_group', result['windows'][0])


if __name__ == '__main__':
    unittest.main()
