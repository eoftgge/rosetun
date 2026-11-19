"""Stage 9d: a Windows guest on the lab's wire, offline.

The scripts the controller sends are checked as text and as what they would return; the noise report is read from
synthetic captures; and the run itself goes through fake machines, a fake lab guest and a fake Windows guest that answers
each script from its own data, so what is shown is the controller's order, its judgement and its refusals. What the
real guest does with the scripts is checked on the stand.
"""

import base64
from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.vm.matrix import (lab, lab_protocol as wire, lifecycle, windows_guest, windows_lab, windows_lab_guest as guest,
                             windows_noise, windows_run, windows_smoke)
from tools.vm.matrix.lifecycle import LifecycleError
from tools.vm.matrix.resources import _process_status, read_manifest
from tools.vm.matrix.tests import fake_controller, test_qemu
from tools.vm.matrix.tests.posix_only import controller_only
from tools.vm.matrix.tests.test_windows_run import Base as WindowsBase
from tools.vm.matrix.tests.test_lab import Endpoint, arp, exchange, ip_frame, marker_exchange, tcp, udp
from tools.vm.matrix.tests.test_lab_fixtures import load_entry
from tools.vm.matrix.tests.test_lab_windows import health

EXAMPLE = Path(__file__).resolve().parents[1] / 'execution-windows-lab-smoke.example.toml'
HEX = '1' * 64
MARKER = '(Send-RosetunMarker $d.marker)'
RUN = 'a' * 32
PEM = b'-----BEGIN CERTIFICATE-----\n' + base64.encodebytes(bytes(range(200))) + b'-----END CERTIFICATE-----\n'


def timed_capture(rows):
    """A pcap of (seconds, frame) rows."""
    raw = bytearray(wire.PCAP_HEADER)
    for seconds, frame in rows:
        whole = int(seconds)
        raw.extend(struct.pack('<IIII', whole, round((seconds - whole) * 1e6), len(frame), len(frame)) + frame)
    return bytes(raw)


def marker_rows(index, word, label, at, run=RUN):
    marker = wire.window_marker(run, index, word, label)
    request, response = marker_exchange(marker)
    return [(at, request), (at + 0.001, response)]


def request_arp():
    return arp(1, wire.CLIENTS[4], wire.GATEWAYS[4], src=wire.MACS['test'], dst=wire.BROADCAST,
               sha=wire.MACS['test'], tha='00:00:00:00:00:00')


def poll_arp():
    """The unicast request with which a stack checks that the gateway it knows still answers."""
    return arp(1, wire.CLIENTS[4], wire.GATEWAYS[4], src=wire.MACS['test'], dst=wire.MACS['lab'],
               sha=wire.MACS['test'], tha=wire.MACS['lab'])


def llmnr(port=50000):
    return ip_frame(wire.CLIENTS[4], '224.0.0.252', 17, udp(port, 5355, b'name'), dst='01:00:5e:00:00:fc')


class Scripts(unittest.TestCase):
    def test_the_network_script_names_the_lab_contract_and_nothing_else(self):
        script = guest.network_script()
        for text in ('00-00-5E-00-53-61', '192.0.2.2', '192.0.2.1', '2001:db8:6a:1::2', '2001:db8:6a:1::1', '203.0.113.53'):
            self.assertIn(text, script)
        self.assertLess(len(script), windows_guest.SCRIPT_LIMIT)
        self.assertNotIn("'", script.replace("'", '', script.count("'")))
        self.assertNotRegex(script, r'(?i)firewall|netsh|Set-NetFirewall')

    def test_the_probe_script_fits_the_limit_and_carries_the_nonces_not_the_answers(self):
        script, expected, direct, plain, opening, closing = self.probe()
        self.assertLessEqual(len(script), guest.SCRIPT_LIMIT)
        # The guest is told what to ask, never what the lab will answer.
        for p in expected:
            self.assertIn(p['nonce'], script)
            self.assertNotIn(wire.answer(p).hex(), script)
        data = json.loads(re.search(r"ConvertFrom-Json '([^']*)'", script)[1])
        self.assertEqual(8, len(data['probes']))
        self.assertEqual({'http': 8080, 'udp': 9000, 'dns-udp': 53, 'dns-tcp': 53}, data['ports'])
        self.assertEqual((wire.CLIENTS[4], wire.CLIENTS[6], wire.TARGETS[4], wire.TARGETS[6]),
                         (data['src4'], data['src6'], data['target4'], data['dst6']))
        self.assertEqual(wire.marker_query(opening).decode(), data['open'])
        self.assertEqual(wire.RESOLVER, data['resolver']['server'])
        windows_guest.arguments(script, guest.SCRIPT_LIMIT)

    def test_a_script_beyond_the_limit_is_refused_by_the_wrapper(self):
        with self.assertRaises(windows_guest.GuestAnswerError):
            windows_guest.arguments('x' * (windows_guest.SCRIPT_LIMIT + 1))
        with self.assertRaises(windows_guest.GuestAnswerError):
            windows_guest.arguments('x' * 100, windows_guest.SCRIPT_LIMIT_MAX + 1)
        windows_guest.arguments('x' * (windows_guest.SCRIPT_LIMIT + 1), guest.SCRIPT_LIMIT)

    def test_the_probe_script_refuses_probes_that_are_not_the_labs(self):
        _, expected, direct, plain, opening, closing = self.probe()
        for change in (lambda rows: rows.pop(), lambda rows: rows[0].update(source='192.0.2.9'),
                       lambda rows: rows[3].update(target='203.0.113.9')):
            rows = deepcopy(expected)
            change(rows)
            with self.assertRaises(ValueError):
                guest.probe_script(RUN, rows, direct, plain, opening, closing)

    def probe(self):
        nonces = iter(f'{n:024x}' for n in range(1, 40))
        expected = wire.probes(RUN, lambda: next(nonces))
        direct = wire.https_exchanges(RUN, lambda: next(nonces))[0]
        plain = wire.dns_checks(RUN, lambda: next(nonces))['plain']
        opening, closing = (wire.window_marker(RUN, 0, word, 'probes') for word in ('open', 'close'))
        return guest.probe_script(RUN, expected, direct, plain, opening, closing), expected, direct, plain, opening, closing

    def test_the_certificate_is_decoded_here_and_the_script_adds_it_to_the_machine_store(self):
        der = guest.certificate_der(PEM)
        script = guest.ca_script(der)
        self.assertIn("'LocalMachine'", script)
        self.assertIn('Root', script)
        self.assertNotIn('BEGIN CERTIFICATE', script)
        self.assertEqual(hashlib.sha1(der).hexdigest().upper(), guest.thumbprint(der))
        for bad in (b'', PEM + PEM, b'-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n',
                    PEM.replace(b'BEGIN', b'BEGIN X'), b'x' * 9000):
            with self.assertRaises(guest.CertificateRefused):
                guest.certificate_der(bad)

    def test_the_answer_for_the_certificate_must_carry_the_thumbprint_of_these_bytes(self):
        der = guest.certificate_der(PEM)
        good = json.dumps(dict(thumbprint=guest.thumbprint(der), subject='CN=lab', found=True))
        self.assertEqual('CN=lab', guest.certificate(good, der)['subject'])
        for change in (dict(thumbprint='0' * 40), dict(found=False), dict(subject=1)):
            with self.assertRaises(windows_guest.GuestAnswerError):
                guest.certificate(json.dumps(dict(json.loads(good), **change)), der)

    def test_an_error_text_becomes_a_code_of_the_fixed_alphabet(self):
        self.assertEqual('socketexception:timedout:-the-wait', guest.code('SocketException:TimedOut: The wait!'))
        self.assertIsNone(guest.code(None))
        self.assertEqual('guest-error', guest.code('!!!'))
        self.assertLessEqual(len(guest.code('x' * 500)), 64)


def network_answer(**changes):
    value = dict(alias='Ethernet', index=7, mac='00-00-5E-00-53-61', status='Up', dhcp4='Disabled',
                 addresses=[dict(address='fe80::1%7', family='IPv6', prefix=64, state='Preferred'),
                            dict(address='192.0.2.2', family='IPv4', prefix=24, state='Preferred'),
                            dict(address='2001:db8:6a:1::2', family='IPv6', prefix=64, state='Preferred')],
                 routes=[dict(prefix='0.0.0.0/0', next_hop='192.0.2.1'), dict(prefix='::/0', next_hop='2001:db8:6a:1::1')],
                 dns=['203.0.113.53'])
    value.update(changes)
    return value


class NetworkTests(unittest.TestCase):
    def test_a_network_as_the_lab_says_has_no_problem(self):
        value = guest.network(json.dumps(network_answer()))
        self.assertEqual([], guest.network_problems(value))

    def test_each_departure_from_the_contract_is_named(self):
        cases = {
            'address-v4-missing': dict(addresses=[a for a in network_answer()['addresses'] if a['address'] != '192.0.2.2']),
            'address-v6-not-preferred': dict(addresses=[dict(a, state='Tentative') if a['address'].startswith('2001')
                                                        else a for a in network_answer()['addresses']]),
            'address-v4-not-preferred': dict(addresses=[dict(a, prefix=16) if a['address'] == '192.0.2.2' else a
                                                        for a in network_answer()['addresses']]),
            'route-v4-missing': dict(routes=[dict(prefix='::/0', next_hop='2001:db8:6a:1::1')]),
            'route-v6-missing': dict(routes=[dict(prefix='0.0.0.0/0', next_hop='192.0.2.1')]),
            'dns-servers': dict(dns=['203.0.113.53', '198.51.100.1']),
            'adapter-mac': dict(mac='00-00-5E-00-53-62')}
        for problem, changes in cases.items():
            with self.subTest(problem=problem):
                self.assertIn(problem, guest.network_problems(guest.network(json.dumps(network_answer(**changes)))))

    def test_an_answer_that_is_not_of_the_shape_is_refused(self):
        for text in ('', 'x', '[]', json.dumps(dict(network_answer(), extra=1)),
                     json.dumps({k: v for k, v in network_answer().items() if k != 'dns'}),
                     json.dumps(network_answer(addresses=[dict(address='192.0.2.2')])),
                     json.dumps(network_answer(index='7')), json.dumps(network_answer(routes=[1])),
                     'x' * (guest.ANSWER_LIMIT + 1)):
            with self.subTest(text=text[:30]):
                with self.assertRaises(windows_guest.GuestAnswerError):
                    guest.network(text)


def answered(script_parts, **changes):
    """What a guest answers a probe script: each probe's lab answer, the HTTPS body, the lookup and the two markers."""
    script, expected, direct, plain, opening, closing = script_parts
    value = dict(
        markers=[dict(marker=wire.marker_query(m).decode(), ack=wire.ACK_PREFIX + wire.marker_query(m).decode(),
                      error=None) for m in (opening, closing)],
        probes=[dict(family=p['family'], service=p['service'], nonce=p['nonce'], response=wire.answer(p).hex(),
                     error=None) for p in expected],
        https=dict(path=direct['path'], client_port=51000, response=wire.https_answer(direct).hex(), error=None),
        resolver=dict(name=wire.token(plain).decode(), addresses=[wire.TARGETS[4]], error=None))
    value.update(changes)
    return json.dumps(value)


class ProbeAnswerTests(Scripts):
    def test_a_clean_answer_is_every_probe_answered_with_the_labs_own_bytes(self):
        parts = self.probe()
        _, expected, direct, plain, _, _ = parts
        doc = guest.probes_answer(answered(parts), expected, direct, plain)
        self.assertEqual([True] * 8, [row['answered'] for row in doc['probes']])
        self.assertTrue(doc['https']['answered'])
        self.assertEqual(51000, doc['https']['client_port'])
        self.assertTrue(doc['resolver']['answered'])
        self.assertEqual([True, True], [guest.marker(json.dumps(row), m)['acknowledged'] for row, m in
                                        zip(doc['markers'], parts[4:])])

    def test_a_probe_that_got_nothing_or_another_answer_is_not_answered_and_says_why(self):
        parts = self.probe()
        _, expected, direct, plain, _, _ = parts
        value = json.loads(answered(parts))
        value['probes'][1].update(response=None, error='SocketException:TimedOut:The wait')
        value['probes'][2].update(response='00' * 4)
        del value['probes'][5]
        doc = guest.probes_answer(json.dumps(value), expected, direct, plain)
        rows = {(r['family'], r['service']): r for r in doc['probes']}
        self.assertEqual([False, False, False], [rows[k]['answered'] for k in
                                                 ((4, 'udp'), (4, 'dns-udp'), (6, 'udp'))])
        self.assertEqual('socketexception:timedout:the-wait', rows[(4, 'udp')]['error'])
        self.assertEqual('probe-missing', rows[(6, 'udp')]['error'])

    def test_the_https_exchange_and_the_lookup_are_answered_only_with_what_the_lab_serves(self):
        parts = self.probe()
        _, expected, direct, plain, _, _ = parts
        value = json.loads(answered(parts))
        value['https'].update(response='00', error='AuthenticationException::certificate')
        value['resolver'].update(addresses=['198.51.100.7'])
        doc = guest.probes_answer(json.dumps(value), expected, direct, plain)
        self.assertEqual((False, False), (doc['https']['answered'], doc['resolver']['answered']))
        self.assertEqual('authenticationexception::certificate', doc['https']['error'])

    def test_an_answer_of_another_shape_or_for_another_exchange_is_refused(self):
        parts = self.probe()
        _, expected, direct, plain, _, _ = parts
        value = json.loads(answered(parts))
        bad = [dict(value, extra=1), dict(value, markers=value['markers'][:1]),
               dict(value, https=dict(value['https'], path='/other')),
               dict(value, resolver=dict(value['resolver'], name='other.lab.test')),
               dict(value, probes=[dict(value['probes'][0], extra=1)])]
        for item in bad:
            with self.subTest(item=str(item)[:40]):
                with self.assertRaises(windows_guest.GuestAnswerError):
                    guest.probes_answer(json.dumps(item), expected, direct, plain)

    def test_a_marker_is_acknowledged_only_with_its_own_text(self):
        marker = wire.window_marker(RUN, 1, 'open', 'rest')
        text = wire.marker_query(marker).decode()
        good = json.dumps(dict(marker=text, ack=wire.ACK_PREFIX + text, error=None))
        self.assertEqual(dict(sent=True, acknowledged=True, error=None), guest.marker(good, marker))
        other = wire.window_marker(RUN, 1, 'close', 'rest')
        self.assertFalse(guest.marker(good, other)['acknowledged'])
        refused = json.dumps(dict(marker=text, ack=None, error='SocketException:TimedOut:x'))
        self.assertEqual((True, False), tuple(guest.marker(refused, marker)[k] for k in ('sent', 'acknowledged')))


class WireTests(unittest.TestCase):
    def test_the_adapter_of_the_image_takes_the_lab_wire_and_no_second_adapter_is_added(self):
        argv = ['-device', f'virtio-net-pci,id=test-wire,mac={wire.MACS["test"]},bus=pcie.0,addr=0x4', '-nic', 'none']
        joined = windows_run.join_wire(argv, wire.MACS['test'])
        self.assertEqual(argv[0:1] + [argv[1] + ',netdev=labwire'] + argv[2:], joined)
        self.assertEqual(1, sum('virtio-net-pci' in item for item in joined))

    def test_another_mac_or_a_missing_adapter_is_refused(self):
        argv = ['-device', 'virtio-net-pci,id=test-wire,mac=00:00:5e:00:53:99,bus=pcie.0,addr=0x4']
        with self.assertRaises(ValueError):
            windows_run.join_wire(argv, '00:00:5e:00:53:99')
        with self.assertRaises(ValueError):
            windows_run.join_wire(['-nic', 'none'], wire.MACS['test'])
        twice = ['-device', f'virtio-net-pci,id=test-wire,mac={wire.MACS["test"]},x'] * 2
        with self.assertRaises(ValueError):
            windows_run.join_wire(twice, wire.MACS['test'])

    def test_the_lab_gives_an_image_that_has_its_adapter_only_the_backend(self):
        fixture = test_qemu.PreparationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        runs = {role: fixture.run for role in ()}
        pair = lab.LabPair.__new__(lab.LabPair)
        pair.lease = SimpleNamespace(_check_live=lambda: None)
        pair.closed, pair.used, pair.sockets = False, set(), dict(test=Endpoint(), lab=Endpoint())
        pair.evidence_disk = False
        pair.role = lambda run: 'test'
        argv, fd = pair.network(object(), adapter=True)
        self.assertEqual(['-netdev'], argv[:1])
        self.assertEqual(2, len(argv))
        self.assertIn('id=labwire', argv[1])
        self.assertEqual(pair.sockets['test'].fileno(), fd)
        self.assertEqual({}, runs)
        pair.used.clear()
        argv, _ = pair.network(object())
        self.assertEqual(4, len(argv))


class NoiseTests(unittest.TestCase):
    def window(self, body, *, opened=100.0, closed=700.0, label='rest', before=()):
        rows = list(before)
        rows += marker_rows(0, 'open', 'probes', 10.0) + marker_rows(0, 'close', 'probes', 20.0)
        rows += marker_rows(1, 'open', label, opened) + list(body) + marker_rows(1, 'close', label, closed)
        return timed_capture(sorted(rows, key=lambda row: row[0]))

    def test_a_guest_that_says_only_infrastructure_in_its_rest_has_no_noise(self):
        raw = self.window([(150.0, request_arp()), (151.0, request_arp())])
        document = windows_noise.report(raw, RUN)
        self.assertEqual('NONE', document['noise'])
        self.assertAlmostEqual(600.0, document['window']['seconds'], delta=0.01)
        self.assertEqual({'infrastructure': 2}, document['frames']['by_category'])
        self.assertEqual([], document['unexpected'])
        row, = document['groups']
        self.assertEqual(('test', 'arp', wire.GATEWAYS[4], 'request', 2, 'infrastructure'),
                         tuple(row[k] for k in ('sender', 'protocol', 'peer', 'port', 'frames', 'category')))
        self.assertEqual((50.0, 51.0), (row['first_seconds'], row['last_seconds']))

    def test_the_poll_of_the_gateway_by_hardware_address_is_infrastructure_and_a_poll_of_any_other_is_not(self):
        other = arp(1, wire.CLIENTS[4], wire.GATEWAYS[4], src=wire.MACS['test'], dst='00:00:5e:00:53:70',
                    sha=wire.MACS['test'], tha='00:00:5e:00:53:70')
        document = windows_noise.report(self.window([(150.0, poll_arp()), (151.0, poll_arp())]), RUN)
        self.assertEqual(('NONE', {'infrastructure': 2}), (document['noise'], document['frames']['by_category']))
        document = windows_noise.report(self.window([(150.0, poll_arp()), (151.0, other)]), RUN)
        self.assertEqual(('FOUND', {'infrastructure': 1, 'unexpected': 1}),
                         (document['noise'], document['frames']['by_category']))

    def test_every_frame_outside_infrastructure_is_listed_with_its_flow_and_times(self):
        body = [(120.0, llmnr(50000)), (121.0, llmnr(50000)), (130.0, llmnr(50001)), (140.0, request_arp()),
                (200.0, ip_frame(wire.CLIENTS[4], '203.0.113.9', 6, tcp(50100, 80, flags=0x02)))]
        document = windows_noise.report(self.window(body), RUN)
        self.assertEqual('FOUND', document['noise'])
        found = {(r['protocol'], r['peer'], r['port']): r for r in document['unexpected']}
        self.assertEqual({('udp', '224.0.0.252', 5355), ('tcp', '203.0.113.9', 80)}, set(found))
        group = found[('udp', '224.0.0.252', 5355)]
        self.assertEqual((3, 2, 20.0, 30.0, 'unexpected'), (group['frames'], group['flows'], group['first_seconds'],
                                                            group['last_seconds'], group['category']))
        self.assertEqual({'infrastructure': 1, 'unexpected': 4}, document['frames']['by_category'])
        self.assertTrue(document['groups'][0]['first_seconds'] <= document['groups'][-1]['first_seconds'])

    def test_a_frame_the_classifier_does_not_know_is_not_made_infrastructure_by_the_report(self):
        # The report adds no tolerance: DHCP and neighbor discovery of a stranger are findings.
        dhcp = ip_frame('0.0.0.0', '255.255.255.255', 17, udp(68, 67, b'discover'), dst=wire.BROADCAST)
        stranger = arp(1, '192.0.2.77', wire.GATEWAYS[4], src=wire.MACS['test'], dst=wire.BROADCAST,
                       sha=wire.MACS['test'], tha='00:00:00:00:00:00')
        document = windows_noise.report(self.window([(150.0, dhcp), (151.0, stranger)]), RUN)
        self.assertEqual('FOUND', document['noise'])
        self.assertEqual(2, sum(r['frames'] for r in document['unexpected']))

    def test_what_came_before_the_windows_is_context_and_never_decides_the_noise(self):
        before = [(1.0, llmnr()), (2.0, request_arp())]
        document = windows_noise.report(self.window([], before=before), RUN)
        self.assertEqual('NONE', document['noise'])
        self.assertEqual(2, document['outside']['frames'])
        self.assertEqual({'unexpected', 'infrastructure'}, {r['category'] for r in document['outside']['groups']})

    def test_the_frames_of_the_lab_in_the_window_are_grouped_apart_from_the_guests(self):
        reply = arp(2, wire.GATEWAYS[4], wire.CLIENTS[4], src=wire.MACS['lab'], dst=wire.MACS['test'],
                    sha=wire.MACS['lab'], tha=wire.MACS['test'])
        document = windows_noise.report(self.window([(150.0, request_arp()), (150.01, reply)]), RUN)
        self.assertEqual({'test', 'lab'}, {r['sender'] for r in document['groups']})
        self.assertEqual('NONE', document['noise'])

    def test_a_missing_or_repeated_window_is_unverified_not_none(self):
        raw = timed_capture(marker_rows(0, 'open', 'probes', 10.0) + marker_rows(0, 'close', 'probes', 20.0))
        self.assertEqual(('UNVERIFIED', 'window-missing'), tuple(windows_noise.report(raw, RUN)[k] for k in ('noise', 'reason')))
        twice = timed_capture(marker_rows(0, 'open', 'rest', 10.0) + marker_rows(0, 'close', 'rest', 20.0)
                              + marker_rows(1, 'open', 'rest', 30.0) + marker_rows(1, 'close', 'rest', 40.0))
        self.assertEqual('UNVERIFIED', windows_noise.report(twice, RUN)['noise'])
        self.assertEqual('UNVERIFIED', windows_noise.report(b'not a pcap', RUN)['noise'])

    def test_the_names_a_group_asked_for_are_read_from_its_frames_and_never_change_its_class(self):
        def question(name):
            labels = b''.join(bytes([len(part)]) + part.encode() for part in name.split('.'))
            return bytes.fromhex('6a0601000001000000000000') + labels + bytes.fromhex('0000010001')

        def hello(name):
            extension = bytes(2) + struct.pack('!HHBH', len(name) + 5, len(name) + 3, 0, len(name)) + name.encode()
            body = (bytes.fromhex('0303') + bytes(32) + bytes(1) + bytes.fromhex('00021301') + bytes.fromhex('0100')
                    + struct.pack('!H', len(extension)) + extension)
            handshake = b'\x01' + len(body).to_bytes(3, 'big') + body
            return bytes.fromhex('160301') + struct.pack('!H', len(handshake)) + handshake
        body = [(120.0, ip_frame(wire.CLIENTS[4], wire.RESOLVER, 17, udp(50000, 53, question('Example.test')))),
                (121.0, ip_frame(wire.CLIENTS[4], wire.RESOLVER, 17, udp(50001, 53, question('example.test')))),
                (130.0, ip_frame(wire.CLIENTS[4], wire.TARGETS[4], 6, tcp(50100, 443, hello('example.test')))),
                (131.0, ip_frame(wire.TARGETS[4], wire.CLIENTS[4], 6, tcp(443, 50100, b'x'), src=wire.MACS['lab'],
                                 dst=wire.MACS['test']))]
        document = windows_noise.report(self.window(body), RUN)
        by_kind = {(r['sender'], r['protocol']): r for r in document['unexpected']}
        self.assertEqual({'Example.test A': 1, 'example.test A': 1}, by_kind[('test', 'udp')]['dns_questions'])
        self.assertEqual({'example.test': 1}, by_kind[('test', 'tcp')]['tls_server_names'])
        # The answers of one server are one group, whichever port the guest used, and name nothing.
        answers = by_kind[('lab', 'tcp')]
        self.assertEqual((wire.TARGETS[4], 443, 'unexpected'), (answers['peer'], answers['port'], answers['category']))
        self.assertNotIn('tls_server_names', answers)
        self.assertEqual('FOUND', document['noise'])
        self.assertIn('example.test A x1', '\n'.join(windows_noise.table(document)))

    def test_the_table_has_a_line_for_each_group(self):
        document = windows_noise.report(self.window([(120.0, llmnr()), (140.0, request_arp())]), RUN)
        lines = windows_noise.table(document)
        self.assertEqual(1 + len(document['groups']), len(lines))  # no group of this capture names anything
        self.assertIn('224.0.0.252', '\n'.join(lines))
        self.assertIn('unexpected', '\n'.join(lines))

    def test_the_report_is_plain_json(self):
        json.dumps(windows_noise.report(self.window([(120.0, llmnr())]), RUN))


class ConfigTests(unittest.TestCase):
    def example(self):
        import tomllib
        with EXAMPLE.open('rb') as stream:
            config = tomllib.load(stream)
        config['state_directory'] = str(Path(__file__).resolve().parent / 'state')
        return config

    def test_the_example_is_a_valid_lab_configuration_and_the_windows_validator_takes_it(self):
        with patch.object(windows_smoke, '_state_path', create=True), patch.object(windows_lab, '_state_path'):
            config = windows_smoke.validate(self.example())
        self.assertEqual(('windows-lab-smoke', windows_lab.SCHEMA), (config['suite'], config['schema']))
        self.assertLessEqual(windows_lab.capture_seconds(config), wire.DURATION_MAX)

    def test_every_field_is_strict(self):
        changes = (lambda c: c.update(extra=1), lambda c: c['lab'].update(extra=1), lambda c: c['lab'].pop('ca_certificate'),
                   lambda c: c['smoke'].update(rest_seconds=59), lambda c: c['smoke'].update(rest_seconds=901),
                   lambda c: c['smoke'].update(script_seconds=29), lambda c: c['smoke'].update(agent_wait_seconds=301),
                   lambda c: c['smoke'].update(rest_seconds='600'),
                   lambda c: c['smoke'].update(settle_seconds=301), lambda c: c['smoke'].update(settle_seconds=-1),
                   lambda c: c['smoke'].update(settle_seconds='60'), lambda c: c['smoke'].update(settle_seconds=True),
                   lambda c: c['smoke'].update(extra_seconds=1), lambda c: c['smoke'].pop('rest_seconds'),
                   lambda c: c['lab']['qemu'].update(machine='q35'), lambda c: c['lab']['qemu'].update(qga=False),
                   lambda c: c['lab']['tunnel'].update(node_port=443), lambda c: c['lab'].update(doh_cert_sha256='A' * 64),
                   lambda c: c['lab'].update(ca_certificate=''), lambda c: c['deadlines'].update(boot=301),
                   lambda c: c['deadlines'].update(extra=1), lambda c: c.update(suite='windows-boot-smoke'),
                   lambda c: c.update(mode='release'), lambda c: c['qemu'].update(extra=1),
                   lambda c: c['lab']['image'].update(extra=1))
        for change in changes:
            with self.subTest(change=change):
                config = self.example()
                change(config)
                with self.assertRaises((ValueError, TypeError, KeyError)):
                    windows_smoke.validate(config)

    def test_a_capture_that_would_not_cover_the_run_is_refused(self):
        config = self.example()
        config['smoke'].update(rest_seconds=900, script_seconds=300, agent_wait_seconds=300, settle_seconds=0)
        self.assertEqual(wire.DURATION_MAX, windows_lab.capture_seconds(config))
        with patch.object(windows_lab, '_state_path'):
            windows_lab.validate(config)
            config['smoke']['settle_seconds'] = 1
            with self.assertRaisesRegex(ValueError, 'lab capture covers'):
                windows_lab.validate(config)
            config['smoke']['settle_seconds'] = 0
            with patch.object(windows_lab, 'CAPTURE_SLACK', windows_lab.CAPTURE_SLACK + 1):
                with self.assertRaisesRegex(ValueError, 'lab capture covers'):
                    windows_lab.validate(config)

    def test_the_settling_is_part_of_the_capture_and_is_sixty_seconds_when_left_out(self):
        config = self.example()
        self.assertEqual(60, config['smoke'].pop('settle_seconds'))
        left_out = windows_lab.capture_seconds(config)
        config['smoke']['settle_seconds'] = 60
        self.assertEqual((60, left_out), (windows_lab.SETTLE_DEFAULT, windows_lab.capture_seconds(config)))
        config['smoke']['settle_seconds'] = 90
        self.assertEqual(left_out + 30, windows_lab.capture_seconds(config))
        with patch.object(windows_lab, '_state_path'):
            del config['smoke']['settle_seconds']
            windows_lab.validate(config)

    def test_the_command_takes_the_suite_and_refuses_the_lab_flags(self):
        import contextlib
        import io
        from tools.vm.matrix import cli
        for flags in (['--lab'], ['--control', 'stop-helper'], ['--diagnostic']):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = cli.main(['run', 'windows-lab-smoke', '--config', str(EXAMPLE), *flags])
            self.assertEqual(2, code)


class Machines:
    """The two machines of the run, the lab guest and the Windows guest: each answers from the data it was given."""

    def __init__(self, test, *, network=None, rest_body=(), fault=None, probe_changes=None, probes_body=(),
                 between_body=(), after_body=()):
        self.test, self.fault, self.rest_body = test, fault, list(rest_body)
        self.probes_body, self.between_body, self.after_body = list(probes_body), list(between_body), list(after_body)
        self.network = network or network_answer()
        self.probe_changes = probe_changes or {}
        self.events, self.scripts, self.recorded, self.calls, self.vms, self.reads = [], [], [], [], {}, []
        self.expected = self.direct = self.plain = None
        self.lab_id = None
        self.slept = 0

    def note(self, name):
        self.events.append(name)
        if self.fault == name:
            raise ValueError('synthetic private stderr must never be published')

    def names(self):
        return [event for event in self.events if type(event) is str]

    # -- the Windows guest
    def powershell(self, script):
        self.scripts.append(script)
        if 'Get-NetAdapter' in script:
            self.note('guest-network')
            return json.dumps(self.network)
        if 'FromBase64String' in script:
            self.note('guest-ca')
            der = __import__('base64').b64decode(re.search(r"FromBase64String\('([^']*)'", script)[1])
            return json.dumps(dict(thumbprint=guest.thumbprint(der), subject='CN=lab', found=True))
        data = json.loads(re.search(r"ConvertFrom-Json '([^']*)'", script)[1])
        if '$d.probes' in script:
            self.note('guest-probes')
            self.plain = dict(name=data['resolver']['name'], server=data['resolver']['server'])
            if self.fault == 'guest-probes-failed':
                raise LifecycleError('qga-powershell-failed')
            by_nonce = {p['nonce']: p for p in self.expected}
            value = dict(
                markers=[dict(marker=data[w], ack=wire.ACK_PREFIX + data[w], error=None) for w in ('open', 'close')],
                probes=[dict(family=q['f'], service=q['s'], nonce=q['n'], response=wire.answer(by_nonce[q['n']]).hex(),
                             error=None) for q in data['probes']],
                https=dict(path=data['https']['path'], client_port=51000,
                           response=wire.https_answer(self.direct).hex(), error=None),
                resolver=dict(name=data['resolver']['name'], addresses=[wire.TARGETS[4]], error=None))
            value.update(self.probe_changes)
            return json.dumps(value)
        self.note('guest-marker')
        return json.dumps(dict(marker=data['marker'], ack=wire.ACK_PREFIX + data['marker'], error=None))

    def adapters(self):
        machines = self

        class Vm:
            vm_uuid = '12345678-1234-4234-8234-123456789abc'
            last_boot_id = 'win-4'
            boot_chain = ['win-4']
            evidence_failed = False

            def __init__(self, role, run):
                self.role, self.run, self.closed, self.completed = role, run, False, False
                self.qga = SimpleNamespace(valid=True, stderr_text='')
                self.process = SimpleNamespace(poll=lambda: None)

            def resume(self):
                machines.note('resume-' + self.role)

            def wait_initial_guest(self, **kwargs):
                machines.note('boot-' + self.role)
                return dict(result='observed')

            def recover_guest(self):
                machines.note('recovery-' + self.role)

            def watch_resets(self):
                machines.events.append(('watch', self.role))

            def guest_powershell(self, script, *, seconds=60, limit=6000):
                machines.test.assertLessEqual(len(script), limit)
                windows_guest.arguments(script, limit)
                return machines.powershell(script)

            def request_shutdown(self, *, wait=None):
                machines.note('shutdown-test')
                self.close()

            def close(self, **kwargs):
                if self.closed:
                    return
                machines.note('close-' + self.role)
                machines.events.append(('hard', self.role, kwargs.get('hard')))
                self.run._lease._active.discard(self)
                self.closed = self.completed = True

        def start(run, lab=None):
            role = lab.role(run)
            machines.note('start-' + role)
            vm = Vm(role, run)
            machines.vms[role] = vm
            run._lease._active.add(vm)
            return vm

        class LabGuest:
            def __init__(self, vm, role, lab_id, **kwargs):
                self.vm, self.role = vm, role
                machines.lab_id = lab_id

            def call(self, operation, expected, window=(), canary=False, tunnel=None, options=None):
                machines.note('lab-' + operation)
                machines.calls.append((operation, expected, list(window), tunnel, options))
                if operation == 'setup':
                    machines.expected, machines.direct = expected, tunnel['https'][0]
                    return dict(capture_ready=True)
                machines.write_disk(self.vm.run.directory / 'evidence.img')
                return dict(finished=True)

            def read(self, name, limit):
                machines.reads.append(name)
                return machines.artifact(name)

        def pair(*args, **kwargs):
            machines.note('evidence-disk')
            machines.pair_options = kwargs
            return lab.LabPair(*args, pair_factory=lambda *a: (Endpoint(), Endpoint()), **kwargs)

        def prepare(run, image, config, executor=None):
            machines.note('prepare-' + ('lab' if run.directory.name.endswith('-lab') else 'test'))
            return dict(kvm_qualified=False)

        return SimpleNamespace(
            execute=lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b'QEMU emulator version 10.0.13'),
            prepare=prepare, pair=pair, start=start, guest=LabGuest)

    # -- what the lab machine leaves
    def frames(self):
        """The wire of a clean run: the boot, the probes window, and the rest window with what the guest says in it."""
        lab_id, expected, direct = self.lab_id, self.expected, self.direct
        plain = wire.dns_checks(lab_id, lambda: '0' * 24)['plain']
        plain['nonce'] = re.search(r'\.([0-9a-f]{24})\.lab\.test', self.plain['name'])[1]
        rows = [(1.0, request_arp())]
        rows += marker_rows(0, 'open', 'probes', 10.0, lab_id)
        at = 11.0
        for p in expected:
            for frame in exchange(p, 40000 + int(p['nonce'], 16) % 1000):
                rows.append((at, frame))
                at += 0.01
        syn = ip_frame(wire.CLIENTS[4], wire.TARGETS[4], 6, tcp(51000, 443, flags=0x02))
        synack = ip_frame(wire.TARGETS[4], wire.CLIENTS[4], 6, tcp(443, 51000, flags=0x12),
                          src=wire.MACS['lab'], dst=wire.MACS['test'])
        rows += [(at, syn), (at + 0.01, synack)]
        request = ip_frame(wire.CLIENTS[4], wire.RESOLVER, 17, udp(52000, 53, wire.query(plain)))
        reply = ip_frame(wire.RESOLVER, wire.CLIENTS[4], 17, udp(53, 52000, wire.query(plain)),
                         src=wire.MACS['lab'], dst=wire.MACS['test'])
        rows += [(at + 0.02, request), (at + 0.03, reply)]
        rows += [(19.0 + n / 10, frame) for n, frame in enumerate(self.probes_body)]
        rows += marker_rows(0, 'close', 'probes', 20.0, lab_id)
        rows += [(30.0 + n, frame) for n, frame in enumerate(self.between_body)]
        rows += marker_rows(1, 'open', 'rest', 100.0, lab_id)
        rows += [(110.0 + n, frame) for n, frame in enumerate(self.rest_body)]
        rows += marker_rows(1, 'close', 'rest', 700.0, lab_id)
        rows += [(710.0 + n, frame) for n, frame in enumerate(self.after_body)]
        return rows, plain

    def served(self):
        return [(index, word, label) for index, label in enumerate(('probes', 'rest')) for word in ('open', 'close')]

    def write_disk(self, image):
        rows, _ = self.frames()
        entry = load_entry()
        image.write_bytes(bytes(wire.EVIDENCE_SIZE))
        with patch.object(entry.os, 'fsync'):
            writer = entry.EvidenceWriter(image, self.lab_id)
            writer.write(timed_capture(sorted(rows, key=lambda row: row[0])))
            writer.finish(complete=True)

    def artifact(self, name):
        _, plain = self.frames()
        if name == 'health.json':
            return json.dumps(health(self.served())).encode()
        if name == 'targets.json':
            return json.dumps([dict(p, response=wire.answer(p).hex()) for p in self.expected]).encode()
        if name == 'https.json':
            return json.dumps([dict(source=wire.CLIENTS[4], port=51000, path=self.direct['path'], at=6.0),
                               dict(kind='counts', counts=[], rows_dropped=0, counts_dropped=0)]).encode()
        if name == 'dns.json':
            return json.dumps([dict(source=wire.CLIENTS[4], transport='udp', name=wire.dns_name(plain), type='A')]).encode()
        return b'[]'


class Flow(unittest.TestCase):
    def setUp(self):
        self.fixture = test_qemu.PreparationTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        root = self.fixture.root
        self.pem = root / 'ca.crt'
        self.pem.write_bytes(PEM)
        record = asdict(self.fixture.image)
        self.config = dict(
            schema=windows_lab.SCHEMA, suite='windows-lab-smoke', mode='exploratory', platform='linux-x86_64-kvm',
            state_directory=str(root / 'lab-state'), stand_id='synthetic', image_descriptor='unused',
            qemu=asdict(self.windows_qemu()),
            smoke=dict(agent_wait_seconds=30, script_seconds=60, rest_seconds=60, shutdown_wait_seconds=30),
            deadlines=dict(preparation=600, boot=300),
            lab=dict(image=record, qemu=asdict(replace(self.fixture.config, machine='pc-i440fx-10.0', qga=True)),
                     tunnel=dict(sing_box_sha256=HEX, ca_sha256=hashlib.sha256(PEM).hexdigest(), node_port=8388),
                     https_cert_sha256='a' * 64, doh_cert_sha256='b' * 64, ca_certificate=str(self.pem)))
        self.clock = SimpleNamespace(now=0)
        self.sleeps = []

    def windows_qemu(self):
        from tools.vm.matrix.qemu import WindowsQemuConfig
        return WindowsQemuConfig('rosetun.matrix.qemu.v1', str(self.fixture.base), str(self.fixture.base),
                                 str(self.fixture.base), 'q35', memory_mib=4096, vcpus=4, qga=True,
                                 swtpm=str(self.fixture.base))

    def go(self, machines):
        def sleep(seconds):
            self.sleeps.append(seconds)
            self.clock.now += seconds

        def completion(directory, manifest):
            return any(v.run.directory == directory and v.closed for v in machines.vms.values())
        image = SimpleNamespace(identifier='windows-test', sha256=HEX, validate=lambda directory: None)
        with patch.object(socket, 'AF_UNIX', 1, create=True), \
                patch.object(windows_lab, 'preflight', return_value={}), \
                patch.object(windows_lab, 'load_windows_descriptor', return_value=image), \
                patch.object(windows_lab, 'completion_verified', side_effect=completion), \
                patch.object(windows_lab.windows_reboot, 'record',
                             side_effect=lambda vm, operation, **fields: machines.recorded.append((operation, fields))):
            return windows_lab.run_windows_lab_smoke(self.config, adapters=machines.adapters(),
                                                     clock=lambda: self.clock.now, sleep=sleep,
                                                     progress=lambda stage: None)


class RunTests(Flow):
    ORDER = ['prepare-lab', 'prepare-test', 'evidence-disk', 'start-lab', 'resume-lab', 'boot-lab', 'lab-setup',
             'start-test', 'resume-test', 'boot-test', 'guest-network', 'guest-ca', 'guest-probes', 'guest-marker',
             'guest-marker', 'lab-finish', 'shutdown-test', 'close-test', 'close-lab']

    def test_the_controller_follows_the_order_of_the_stage_and_a_quiet_guest_is_accepted(self):
        machines = Machines(self, rest_body=[request_arp()])
        result = self.go(machines)
        self.assertEqual([], result['errors'])
        self.assertEqual(self.ORDER, [name for name in machines.names() if name in set(self.ORDER)])
        self.assertEqual(0, result['exit_code'], result['execution'])
        execution = result['execution']
        self.assertTrue(execution['accepted'])
        self.assertEqual(('NONE', 'NONE', 'NONE'), (execution['noise'], execution['windows']['probes']['leak'],
                                                    execution['windows']['rest']['leak']))
        self.assertTrue(execution['probes']['passed'])
        self.assertEqual([], execution['network']['problems'])
        self.assertEqual({'qualified': True}, {'qualified': execution['probes']['lab_qualification']['qualified']})
        self.assertTrue(result['completed'])
        self.assertEqual((False, True), (result['qualified'], result['diagnostic']))

    def test_the_guest_is_left_alone_for_the_rest_and_only_looked_at(self):
        machines = Machines(self)
        result = self.go(machines)
        self.assertGreaterEqual(sum(self.sleeps), self.config['smoke']['rest_seconds'])
        self.assertGreaterEqual(result['execution']['rest']['waited_seconds'], self.config['smoke']['rest_seconds'])
        # Between the two marker scripts nothing was sent to the guest.
        scripts = [s for s in machines.scripts if MARKER in s]
        self.assertEqual(2, len(scripts))
        between = machines.events[machines.events.index('guest-marker'):]
        self.assertTrue(any(type(e) is tuple and e[0] == 'watch' for e in between))
        self.assertEqual(['guest-marker', 'guest-marker'], [e for e in between if e == 'guest-marker'])

    def test_the_lab_is_asked_for_windows_the_resolver_and_a_capture_that_covers_the_run(self):
        machines = Machines(self)
        self.go(machines)
        (_, expected, window, tunnel, options), finish = machines.calls
        self.assertEqual(8, len(expected))
        self.assertEqual([], window)
        self.assertEqual(dict(evidence_disk=True, dns=True, windows=True, duration_seconds=30 + 4 * 60 + 60 + 60 + 300,
                              certificates=dict(https_sha256='a' * 64, doh_sha256='b' * 64)), options)
        self.assertEqual(self.config['lab']['tunnel']['ca_sha256'], tunnel['ca_sha256'])
        self.assertEqual(dict(tunnel=True, evidence_disk=True, dns=True), machines.pair_options)
        self.assertEqual(options, finish[4])

    def test_the_guest_scripts_are_the_network_then_the_certificate_then_the_probes(self):
        machines = Machines(self)
        self.go(machines)
        kinds = ['network' if 'Get-NetAdapter' in s else 'ca' if 'FromBase64' in s else 'probes' if '$d.probes' in s
                 else 'marker' for s in machines.scripts]
        self.assertEqual(['network', 'ca', 'probes', 'marker', 'marker'], kinds)
        self.assertEqual(['guest-network', 'guest-ca', 'guest-probes'], [op for op, _ in machines.recorded][:3])

    def test_noise_in_the_rest_window_is_listed_and_the_run_is_judged_without_it(self):
        machines = Machines(self, rest_body=[request_arp(), poll_arp(), llmnr(50000), llmnr(50000)])
        result = self.go(machines)
        self.assertEqual([], result['errors'])
        self.assertEqual(0, result['exit_code'])
        execution = result['execution']
        self.assertEqual(('FOUND', 'DETECTED', 'NONE'), (execution['noise'], execution['windows']['rest']['leak'],
                                                         execution['windows']['probes']['leak']))
        row, = execution['noise_report']['unexpected']
        self.assertEqual((2, '224.0.0.252', 5355), (row['frames'], row['peer'], row['port']))
        self.assertIn('224.0.0.252', '\n'.join(execution['noise_table']))
        self.assertEqual({'infrastructure': 2, 'unexpected': 2}, execution['noise_report']['frames']['by_category'])
        self.assertTrue(execution['accepted'])
        self.assertTrue(result['completed'])

    def test_a_frame_in_the_window_of_the_probes_still_makes_the_run_negative(self):
        machines = Machines(self, probes_body=[llmnr(50000)])
        result = self.go(machines)
        self.assertEqual([], result['errors'])
        self.assertEqual(1, result['exit_code'])
        execution = result['execution']
        self.assertEqual(('DETECTED', 'NONE', 'NONE'), (execution['windows']['probes']['leak'],
                                                        execution['windows']['rest']['leak'], execution['noise']))
        self.assertFalse(execution['accepted'])

    def test_a_rest_that_was_not_observed_is_still_an_error_whatever_the_noise(self):
        machines = Machines(self, rest_body=[llmnr()])
        unobserved = dict(windows_noise.report(b'', 'a' * 32), noise='UNVERIFIED', reason='window-missing')
        with patch.object(windows_lab.windows_noise, 'report', return_value=unobserved):
            result = self.go(machines)
        self.assertEqual(1, result['exit_code'])
        self.assertEqual(('UNVERIFIED', False), (result['execution']['noise'], result['execution']['accepted']))

    def test_the_frames_around_the_windows_are_in_the_report_and_every_frame_is_in_one_section(self):
        machines = Machines(self, rest_body=[llmnr()], between_body=[llmnr(50001), request_arp()],
                            after_body=[llmnr(50002), llmnr(50003), poll_arp()])
        result = self.go(machines)
        self.assertEqual(0, result['exit_code'])
        report = result['execution']['noise_report']
        self.assertEqual((2, 3), (report['between']['frames'], report['after']['frames']))
        self.assertEqual((1, 1), (report['frames']['total'], len(report['groups'])))
        sections = report['accounting']
        self.assertTrue(sections['complete'])
        self.assertEqual(len(machines.frames()[0]), sections['sum'])
        self.assertEqual(sections['sum'], sections['capture_records'])
        self.assertEqual((8, 1, 1, 2, 3), tuple(sections[name] for name in ('markers', 'before', 'rest', 'between', 'after')))

    def test_the_guest_is_left_alone_after_its_set_up_and_before_the_probes(self):
        machines = Machines(self)
        result = self.go(machines)
        settle = self.config['smoke'].get('settle_seconds', windows_lab.SETTLE_DEFAULT)
        self.assertEqual(60, settle)
        self.assertGreaterEqual(result['execution']['settle']['waited_seconds'], settle)
        self.assertGreaterEqual(sum(self.sleeps), settle + self.config['smoke']['rest_seconds'])
        # No script goes to the guest between the certificate and the probes, and both machines are only looked at.
        events = machines.events
        waiting = events[events.index('guest-ca'):events.index('guest-probes')]
        self.assertTrue(any(type(e) is tuple and e[0] == 'watch' for e in waiting))
        self.assertEqual(['guest-ca'], [e for e in waiting if type(e) is str])

    def settled(self, seconds):
        self.config['smoke']['settle_seconds'] = seconds
        result = self.go(Machines(self))
        self.assertEqual(0, result['exit_code'])
        self.assertEqual(seconds, result['execution']['capture_seconds'] - 30 - 4 * 60 - 60 - 300)
        self.assertAlmostEqual(seconds, result['execution']['settle']['waited_seconds'], delta=5)
        self.assertGreaterEqual(sum(self.sleeps), seconds + self.config['smoke']['rest_seconds'])

    def test_a_settling_of_another_length_is_taken(self):
        self.settled(130)

    def test_a_settling_of_zero_seconds_waits_for_nothing(self):
        self.settled(0)

    def test_a_probe_that_failed_makes_the_run_negative_and_the_rest_is_still_observed(self):
        machines = Machines(self)
        original = machines.powershell

        def failing(script):
            text = original(script)
            if '$d.probes' not in script:
                return text
            value = json.loads(text)
            value['probes'][0].update(response=None, error='SocketException:TimedOut:x')
            return json.dumps(value)
        machines.powershell = failing
        result = self.go(machines)
        self.assertEqual(1, result['exit_code'])
        self.assertFalse(result['execution']['probes']['passed'])
        self.assertEqual('NONE', result['execution']['noise'])
        self.assertIsNotNone(result['execution']['rest'])

    def test_a_network_that_is_not_the_labs_stops_the_run_before_anything_is_sent(self):
        machines = Machines(self, network=network_answer(addresses=[]))
        result = self.go(machines)
        self.assertEqual(2, result['exit_code'])
        self.assertEqual([('network', 'windows-network-not-as-the-lab-says')],
                         [(e['stage'], e['reason']) for e in result['errors']])
        scripts = [s for s in machines.scripts if 'Get-NetAdapter' not in s]
        self.assertEqual([], scripts)
        self.assertNotIn('lab-finish', machines.names())
        self.assertIn(('hard', 'test', True), machines.events)
        self.assertEqual(['address-v4-missing', 'address-v6-missing'],
                         [p for p in result['execution']['network']['problems'] if p.startswith('address')])
        self.assertFalse(result['execution']['accepted'])

    def test_a_guest_that_cannot_run_the_network_script_stops_the_run(self):
        machines = Machines(self)
        machines.powershell = lambda script: (_ for _ in ()).throw(LifecycleError('qga-powershell-failed'))
        result = self.go(machines)
        self.assertEqual(2, result['exit_code'])
        self.assertEqual([('network', 'qga-powershell-failed')], [(e['stage'], e['reason']) for e in result['errors']])

    def test_a_ca_that_is_not_the_one_the_lab_pins_is_refused_before_the_guest_sees_it(self):
        self.pem.write_bytes(PEM + b'\n')
        machines = Machines(self)
        result = self.go(machines)
        self.assertEqual(2, result['exit_code'])
        self.assertEqual([('certificate', 'lab-ca-certificate-hash-mismatch')],
                         [(e['stage'], e['reason']) for e in result['errors']])
        self.assertFalse(any('FromBase64String' in s for s in machines.scripts))

    def test_a_failed_probe_script_is_an_error_but_the_rest_is_still_observed(self):
        machines = Machines(self, fault='guest-probes-failed')
        result = self.go(machines)
        self.assertEqual(2, result['exit_code'])
        self.assertEqual([('probes', 'qga-powershell-failed')], [(e['stage'], e['reason']) for e in result['errors']])
        self.assertIsNotNone(result['execution']['rest'])
        self.assertIsNone(result['execution']['probes'])

    def test_a_machine_that_leaves_during_the_rest_ends_the_run_without_a_verdict(self):
        machines = Machines(self)
        adapters = machines.adapters()
        start = adapters.start

        def leaving(run, lab=None):
            vm = start(run, lab=lab)
            if vm.role == 'lab':
                vm.process = SimpleNamespace(poll=lambda: 0 if machines.scripts and
                                             sum(MARKER in s for s in machines.scripts) >= 1 else None)
            return vm
        machines.adapters = lambda: SimpleNamespace(**{**vars(adapters), 'start': leaving})
        result = self.go(machines)
        self.assertEqual(2, result['exit_code'])
        self.assertEqual('vm-child-has-exited', result['errors'][0]['reason'])
        self.assertNotIn('lab-finish', machines.names())

    def test_the_summary_keeps_no_token_and_both_runs_hold_it(self):
        machines = Machines(self, rest_body=[llmnr()])
        result = self.go(machines)
        for role, directory in result['artifact_directories'].items():
            saved = json.loads((Path(directory) / 'execution-summary.json').read_text(encoding='utf-8'))
            self.assertEqual(result['exit_code'], saved['exit_code'])
            self.assertEqual('FOUND', saved['execution']['noise'])
        text = json.dumps(result)
        self.assertNotIn('BEGIN CERTIFICATE', text)


class WirePair(lab.LabPair):
    """What `lifecycle.start` asks of the lab's pair, for one machine, with a real descriptor to pass on."""

    def __init__(self, role, descriptor):
        self.wire_role, self.descriptor, self.adapter = role, descriptor, None

    def check_start(self, run):
        pass

    def resources(self, run):
        return {}

    def role(self, run):
        return self.wire_role

    def network(self, run, *, adapter=False):
        self.adapter = adapter
        return ['-netdev', f'stream,id=labwire,addr.type=fd,addr.str={self.descriptor},server=off'], self.descriptor


@controller_only
class JoinTests(WindowsBase):
    """A real `lifecycle.start` of the Windows run on the stand-in QEMU and swtpm, with the lab's wire."""

    def setUp(self):
        super().setUp()
        for item in fake_controller.patches():
            item.start()
            self.addCleanup(item.stop)
        self.addCleanup(self.stop_leftovers)
        self.fixture.prepare()
        self.fixture.calls = self.fixture.calls[:2]
        self.ends = socket.socketpair()
        for end in self.ends:
            self.addCleanup(end.close)

    def stop_leftovers(self):
        try:
            resources = read_manifest(self.run_directory)['resources']
        except (OSError, ValueError):
            return
        for resource in resources:
            if resource['kind'] == 'process' and _process_status(resource) == 'alive':
                os.kill(resource['pid'], signal.SIGKILL)

    def start(self, pair):
        def info(argv, *, timeout, output_limit):
            return self.fixture.fake(argv, timeout=30, output_limit=output_limit)
        return lifecycle.start(self.fixture.run, timeout=5, executor=info, lab=pair)

    def test_the_adapter_of_the_image_is_the_one_on_the_wire_and_there_is_no_second_one(self):
        pair = WirePair('test', self.ends[0].fileno())
        vm = self.start(pair)
        self.addCleanup(vm.hard_off)
        self.assertTrue(pair.adapter)
        qemu = next(r for r in read_manifest(self.run_directory)['resources'] if r['id'] == 'qemu')
        argv = Path('/proc/%d/cmdline' % qemu['pid']).read_bytes().decode().split('\0')
        adapters = [item for item in argv if item.startswith('virtio-net-pci')]
        self.assertEqual(1, len(adapters))
        self.assertIn('id=test-wire', adapters[0])
        self.assertIn('mac=' + wire.MACS['test'], adapters[0])
        self.assertTrue(adapters[0].endswith(',netdev=labwire'))
        self.assertEqual(1, sum(item.startswith('stream,id=labwire') for item in argv))
        self.assertEqual('test-wire', vm.wire)

    def test_the_lab_machine_is_never_a_windows_guest(self):
        with patch.object(lifecycle.subprocess, 'Popen', side_effect=AssertionError('no process')):
            with self.assertRaisesRegex(lifecycle.LifecycleError, 'prelaunch-validation-failed'):
                self.start(WirePair('lab', self.ends[0].fileno()))
        self.assertEqual('prepared', read_manifest(self.run_directory)['state'])


if __name__ == '__main__':
    unittest.main()
