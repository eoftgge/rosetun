"""The lab's SSH poller of Linux L4 (stage 8d): its one-time key, what the observer lets through, and its loop."""

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from tools.vm.matrix import lab, lab_protocol as wire, linux_l2, poller_key
from tools.vm.matrix.tests.test_lab import ip_frame, tcp
from tools.vm.matrix.tests.test_lab_flows import SYN, SYN_ACK, PUSH, RST, timed
from tools.vm.matrix.tests.test_lab_fixtures import load_entry
from tools.vm.matrix.tests.test_lab_windows import RUN, health, marker_frames, served

# The two first test vectors of RFC 8032, section 7.1: public values, no secret anywhere.
VECTORS = (('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
            'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'),
           ('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
            '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'))
CLIENT, GATEWAY = wire.CLIENTS[4], wire.GATEWAYS[4]


class KeyTests(unittest.TestCase):
    def test_the_public_key_is_that_of_the_reference_vectors(self):
        for seed, public in VECTORS:
            self.assertEqual(bytes.fromhex(public), poller_key.public_key(bytes.fromhex(seed)))

    def test_a_seed_of_another_size_or_type_is_refused(self):
        for seed in (b'', bytes(31), bytes(33), 'a' * 32, None):
            with self.assertRaises(ValueError):
                poller_key.public_key(seed)

    def test_the_blob_is_what_delivery_and_the_importer_accept(self):
        private, blob = poller_key.new_pair(lambda size: bytes(range(size)))
        raw = base64.b64decode(blob)
        self.assertEqual(51, len(raw))
        self.assertTrue(raw.startswith(poller_key.BLOB_HEAD))
        self.assertTrue(raw.startswith(linux_l2.POLLER_KEY_HEAD))
        self.assertTrue(linux_l2.poller_key_shape(blob))
        self.assertEqual(poller_key.public_key(bytes(range(32))), raw[-32:])
        # What the lab's helper takes for a private key.
        entry = load_entry()
        self.assertIsNotNone(entry.POLLER_KEY_PATTERN.fullmatch(private))

    def test_the_private_key_file_has_the_layout_of_openssh_key_v1_and_a_new_pair_differs_each_time(self):
        private, blob = poller_key.new_pair(lambda size: bytes([7]) * size)
        lines = private.splitlines()
        self.assertEqual(['-----BEGIN OPENSSH PRIVATE KEY-----', '-----END OPENSSH PRIVATE KEY-----'],
                         [lines[0], lines[-1]])
        self.assertTrue(all(len(line) <= 70 for line in lines[1:-1]))
        raw = base64.b64decode(''.join(lines[1:-1]))
        self.assertTrue(raw.startswith(b'openssh-key-v1\0'))
        body = raw[len(b'openssh-key-v1\0'):]
        for expected in (b'none', b'none', b''):
            size = struct.unpack('>I', body[:4])[0]
            self.assertEqual(expected, body[4:4 + size])
            body = body[4 + size:]
        self.assertEqual(1, struct.unpack('>I', body[:4])[0])
        size = struct.unpack('>I', body[4:8])[0]
        self.assertEqual(base64.b64decode(blob), body[8:8 + size])
        rest = body[8 + size:]
        (length,) = struct.unpack('>I', rest[:4])
        self.assertEqual(0, length % 8)
        self.assertEqual(length, len(rest) - 4)
        self.assertNotEqual(poller_key.new_pair()[0], poller_key.new_pair()[0])

    @unittest.skipUnless(shutil.which('ssh-keygen') and os.name == 'posix', 'ssh-keygen needs a POSIX file mode here')
    def test_ssh_keygen_reads_the_private_key_and_derives_the_same_public_one(self):
        private, blob = poller_key.new_pair()
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'key'
            path.write_text(private, encoding='ascii', newline='\n')
            path.chmod(0o600)
            shown = subprocess.run(['ssh-keygen', '-y', '-f', str(path)], capture_output=True, text=True, check=True)
        self.assertEqual(['ssh-ed25519', blob], shown.stdout.split()[:2])


def out(port, flags=PUSH, host=GATEWAY):
    """A segment of the lab's poller to the test machine's sshd, from the poller's own source port."""
    return ip_frame(host, CLIENT, 6, tcp(port, 22, b'', flags), src=wire.MACS['lab'], dst=wire.MACS['test'])


def back(port, flags=PUSH, sport=22):
    return ip_frame(CLIENT, GATEWAY, 6, tcp(sport, port, b'', flags))


def session(label, body=()):
    return marker_frames(0, 'open', label) + list(body) + marker_frames(0, 'close', label)


class ObserverTests(unittest.TestCase):
    LABEL = 'lockdown'

    def classify(self, body, replies_from, poll=True, flows=True):
        frames = session(self.LABEL, body)
        extra = dict(inbound_poll=dict(replies_from=replies_from)) if poll else {}
        return wire.classify_windows(timed(frames), RUN, None, health=health(served([(0, self.LABEL)])), ready=True,
                                     tunnel_port=wire.NODE_PORT, required_labels=[self.LABEL], flows=flows, **extra)

    def window(self, result):
        (window,) = result['windows']
        return window

    def test_the_category_is_the_poller_and_only_the_poller(self):
        self.assertEqual('inbound-poll', wire.POLL_CATEGORY)
        window = self.window(self.classify([out(40001, SYN)], None))
        self.assertEqual((1, 0, 'NONE'), (window['categories']['inbound-poll'], window['categories']['unexpected'],
                                          window['leak']))

    def test_a_syn_nobody_answers_is_allowed_whenever_it_is_sent(self):
        body = [out(40001, SYN), out(40001, SYN), out(40002, SYN)]
        window = self.window(self.classify(body, None))
        self.assertEqual((3, 0, 'NONE'), (window['categories']['inbound-poll'], window['categories']['unexpected'],
                                          window['leak']))

    def test_an_answer_before_the_local_network_went_on_is_a_leak(self):
        body = [out(40001, SYN), back(40001, SYN_ACK)]
        # The two markers of the opening take records 0 and 1, so the body is at 100.5 and 100.75 seconds.
        early = self.window(self.classify(body, 105.0))
        self.assertEqual((1, 1, 'DETECTED'), (early['categories']['inbound-poll'], early['categories']['unexpected'],
                                              early['leak']))
        self.assertEqual(1, len(early['unexpected']))
        never = self.window(self.classify(body, None))
        self.assertEqual((1, 'DETECTED'), (never['categories']['unexpected'], never['leak']))

    def test_an_answer_after_it_is_the_poll_and_the_window_stays_clean(self):
        body = [out(40001, SYN), back(40001, SYN_ACK), out(40001, PUSH), back(40001, PUSH)]
        window = self.window(self.classify(body, 100.0))
        self.assertEqual((4, 0, 'NONE'), (window['categories']['inbound-poll'], window['categories']['unexpected'],
                                          window['leak']))
        # The answers are at 100.75 and 101.25: the moment itself is on the side of the poll, a later one is not.
        self.assertEqual(0, self.window(self.classify(body, 100.75))['categories']['unexpected'])
        edge = self.window(self.classify(body, 101.0))
        self.assertEqual((1, 3, 'DETECTED'), (edge['categories']['unexpected'], edge['categories']['inbound-poll'],
                                              edge['leak']))

    def test_an_answer_to_a_port_the_poller_never_used_is_unexpected_even_after_it(self):
        body = [out(40001, SYN), back(40009, SYN_ACK)]
        window = self.window(self.classify(body, 0.0))
        self.assertEqual((1, 1), (window['categories']['inbound-poll'], window['categories']['unexpected']))

    def test_only_the_poller_s_four_tuple_is_let_through(self):
        other_port = ip_frame(GATEWAY, CLIENT, 6, tcp(40001, 2222, b'', SYN), src=wire.MACS['lab'], dst=wire.MACS['test'])
        other_host = ip_frame('192.0.2.77', CLIENT, 6, tcp(40001, 22, b'', SYN), src=wire.MACS['lab'],
                              dst=wire.MACS['test'])
        wrong_mac = ip_frame(GATEWAY, CLIENT, 6, tcp(40001, 22, b'', SYN))
        udp_like = ip_frame(GATEWAY, CLIENT, 17, struct.pack('!HHHH', 40001, 22, 8, 0), src=wire.MACS['lab'],
                            dst=wire.MACS['test'])
        from_other_port = back(40001, SYN_ACK, sport=2222)
        for frame in (other_port, other_host, wrong_mac, udp_like, from_other_port):
            window = self.window(self.classify([out(40001, SYN), frame], 0.0))
            self.assertEqual((1, 1), (window['categories']['inbound-poll'], window['categories']['unexpected']),
                             frame.hex())

    def test_a_reset_after_the_local_network_is_an_answer_too(self):
        window = self.window(self.classify([out(40001, SYN), back(40001, RST)], 0.0))
        self.assertEqual((2, 0), (window['categories']['inbound-poll'], window['categories']['unexpected']))

    def test_the_poll_is_no_flow_of_the_window(self):
        body = [out(40001, SYN), back(40001, SYN_ACK), out(40002, SYN), back(40002, SYN_ACK)]
        window = self.window(self.classify(body, 0.0))
        self.assertEqual(dict(connections=[], omitted=0), window['flows'])
        self.assertEqual(0, window['direct']['other_frames'])

    def test_without_the_category_the_poller_is_an_unexpected_frame_as_for_every_other_suite(self):
        window = self.window(self.classify([out(40001, SYN)], None, poll=False))
        self.assertNotIn('inbound-poll', window['categories'])
        self.assertEqual((1, 'DETECTED'), (window['categories']['unexpected'], window['leak']))

    def test_the_boundary_is_a_time_or_none(self):
        for bad in ('100', True, float('nan'), float('inf'), [1]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.classify([], bad)
        with self.assertRaises(ValueError):
            wire.classify_windows(timed(session('x')), RUN, None, health=health(served([(0, 'x')])), ready=True,
                                  required_labels=['x'], inbound_poll=dict(replies_from=1.0, other=1))

    def test_a_poller_frame_outside_a_window_is_counted_apart_and_changes_no_verdict(self):
        frames = [out(40001, SYN), back(40001, SYN_ACK)] + session(self.LABEL)
        result = wire.classify_windows(timed(frames), RUN, None, health=health(served([(0, self.LABEL)])),
                                       ready=True, required_labels=[self.LABEL], inbound_poll=dict(replies_from=0.0))
        self.assertEqual('NONE', result['windows'][0]['leak'])
        self.assertEqual(2, result['outside_window']['categories']['inbound-poll'])


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.entry = load_entry()
        self.private, self.blob = poller_key.new_pair()
        self.request = dict(windows=True, poller=dict(private_key=self.private))

    def test_the_block_is_the_key_alone_and_needs_the_windows_of_a_stage_8_run(self):
        self.assertIs(self.request['poller'], self.entry.poller_of(self.request))
        self.assertIsNone(self.entry.poller_of(dict(windows=True)))
        for request in (dict(poller=dict(private_key=self.private)),
                        dict(windows=True, poller=dict(private_key=self.private, interval=1)),
                        dict(windows=True, poller=dict()), dict(windows=True, poller=self.private),
                        dict(windows=True, poller=dict(private_key=self.private.replace('OPENSSH', 'RSA'))),
                        dict(windows=True, poller=dict(private_key=self.private + 'x')),
                        dict(windows=True, poller=dict(private_key='-----BEGIN OPENSSH PRIVATE KEY-----\n'
                                                                  + 'A' * 2000 + '\n-----END OPENSSH PRIVATE KEY-----\n')),
                        dict(windows=True, control='observer-stopped', poller=dict(private_key=self.private))):
            with self.assertRaisesRegex(ValueError, 'invalid-poller'):
                self.entry.poller_of(request)

    def test_what_the_machine_keeps_names_the_key_by_its_hash_only(self):
        shown = self.entry.redacted(self.request)
        self.assertEqual(dict(private_key_sha256=hashlib.sha256(self.private.encode()).hexdigest()), shown['poller'])
        self.assertNotIn(self.private, json.dumps(shown))
        self.assertEqual(self.request['poller']['private_key'], self.private)
        plain = dict(windows=True)
        self.assertIs(plain, self.entry.redacted(plain))

    def test_the_lab_needs_ssh_to_be_a_root_owned_file_and_says_so_before_anything_is_changed(self):
        with patch.object(self.entry, 'lstat', side_effect=OSError):
            with self.assertRaisesRegex(self.entry.Refused, 'poller-ssh-missing'):
                self.entry.setup(self.request, 'enp7s0', Path('/nonexistent'))

    def test_one_attempt_is_one_login_with_the_key_of_the_run_from_the_labs_address(self):
        seen = []

        def run(arguments, **options):
            seen.append((arguments, options))
            return subprocess.CompletedProcess(arguments, 0)

        with patch.object(self.entry.subprocess, 'run', run):
            self.assertEqual(('accepted', 0), self.entry.poll_once(Path('/run/key')))
        arguments, options = seen[0]
        self.assertEqual('/usr/bin/ssh', Path(arguments[0]).as_posix())
        self.assertEqual(['-i', '/run/key'], [arguments[1], Path(arguments[2]).as_posix()])
        self.assertEqual(['-b', GATEWAY, '-F', '/dev/null'], arguments[3:7])
        self.assertEqual(['root@' + CLIENT, 'true'], arguments[-2:])
        for option in ('BatchMode=yes', 'IdentitiesOnly=yes', 'ConnectTimeout=5'):
            self.assertIn(option, arguments)
        self.assertEqual(self.entry.POLL_TIMEOUT, options['timeout'])
        self.assertEqual(subprocess.DEVNULL, options['stdin'])
        self.assertNotIn(self.private, ' '.join(arguments))

    def test_a_failed_login_a_timeout_and_a_missing_program_are_results_not_errors(self):
        for effect, expected in ((subprocess.CompletedProcess([], 255), ('failed', 255)),
                                 (subprocess.TimeoutExpired('ssh', 15), ('timeout', None)),
                                 (OSError('no ssh'), ('error', None))):
            def run(arguments, **options):
                if isinstance(effect, BaseException):
                    raise effect
                return effect
            with patch.object(self.entry.subprocess, 'run', run):
                self.assertEqual(expected, self.entry.poll_once(Path('/run/key')))

    def test_the_loop_logs_each_attempt_with_its_time_and_result_and_stops_when_told(self):
        log, stop, results = self.entry.PollerLog(), threading.Event(), iter([('failed', 255), ('accepted', 0)])

        class Stopping:
            def __init__(inner):
                inner.waits = []

            def is_set(inner):
                return stop.is_set()

            def wait(inner, seconds):
                inner.waits.append(seconds)
                if len(inner.waits) == 2:
                    stop.set()
                return stop.is_set()

        event = Stopping()
        with patch.object(self.entry, 'poll_once', lambda path: next(results)):
            self.entry.poller_loop(Path('/run/key'), log, event)
        self.assertEqual([self.entry.POLL_INTERVAL] * 2, event.waits)
        self.assertEqual([(1, 'failed', 255), (2, 'accepted', 0)], [(r['attempt'], r['result'], r['code']) for r in log.rows])
        self.assertTrue(all(type(r['at']) is float and r['elapsed_ms'] >= 0 for r in log.rows))
        self.assertEqual(10, self.entry.POLL_INTERVAL)

    def test_the_log_is_bounded_and_says_when_it_overflowed(self):
        log = self.entry.PollerLog()
        for number in range(self.entry.POLL_ROWS + 3):
            log.record(number, 1.0, 'accepted', 0, 1)
        self.assertEqual((self.entry.POLL_ROWS, True), (len(log.rows), log.overflow))
        self.assertLess(len(json.dumps(log.rows)), wire.LOG_LIMIT)

    def test_the_controller_reads_the_log_and_the_pair_registers_it_only_for_a_poller_run(self):
        self.assertEqual({'lab-poller': 'poller.json'}, lab.POLLER_ARTIFACTS)
        self.assertIn('poller', wire.OBSERVER_PLACES)


if __name__ == '__main__':
    unittest.main()
