"""Offline two-VM and evidence regressions. No host networking or real child."""
import base64
import contextlib
from dataclasses import asdict, replace
import json
import importlib.util
import io
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.vm.matrix import cli, lab, lifecycle, lab_protocol as wire
from tools.vm.matrix.resources import create_run, EXECUTION_FILES
from tools.vm.matrix.tests import test_qemu, test_lifecycle


class Endpoint:
    sequence = 70

    def __init__(self):
        Endpoint.sequence += 1
        self.fd = Endpoint.sequence

    def fileno(self):
        return self.fd

    def close(self):
        self.fd = -1

    def dup(self):
        return Endpoint()


ETHER_IPV4, ETHER_IPV6, ETHER_ARP = (n.to_bytes(2, 'big') for n in (0x0800, 0x86dd, 0x0806))


def mac(text):
    return bytes.fromhex(text.replace(':', ''))


def udp(sport, dport, data):
    return struct.pack('!HHHH', sport, dport, len(data) + 8, 0) + data


def tcp(sport, dport, data=b'', flags=0x18):
    return struct.pack('!HHIIHHHH', sport, dport, 0, 0, (5 << 12) | flags, 1024, 0, 0) + data


def icmp(kind, body=bytes(4)):
    return struct.pack('!BBH', kind, 0, 0) + body


def ethernet(src, dst, ether, body):
    return mac(dst) + mac(src) + ether + body


def ipv4(source, target, proto, transport, *, fragment=0):
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(transport), 0, fragment, 64, proto, 0,
                       socket.inet_pton(socket.AF_INET, source), socket.inet_pton(socket.AF_INET, target)) + transport


def ipv6(source, target, proto, transport, *, first=None, extension=b''):
    return struct.pack('!IHBB16s16s', 6 << 28, len(extension) + len(transport), proto if first is None else first, 64,
                       socket.inet_pton(socket.AF_INET6, source), socket.inet_pton(socket.AF_INET6, target)) + extension + transport


def ip_frame(source, target, proto, transport, *, src=wire.MACS['test'], dst=wire.MACS['lab'], **kwargs):
    if ':' in source:
        return ethernet(src, dst, ETHER_IPV6, ipv6(source, target, proto, transport, **kwargs))
    return ethernet(src, dst, ETHER_IPV4, ipv4(source, target, proto, transport, **kwargs))


def exchange(p, port=40000):
    """The request and the response frames of one probe, as the lab ingress sees them."""
    data = (wire.query(p), wire.answer(p))
    frames = []
    for reply in (False, True):
        source, target = (p['target'], p['source']) if reply else (p['source'], p['target'])
        sport, dport = (p['port'], port) if reply else (port, p['port'])
        transport = (tcp if p['protocol'] == 'tcp' else udp)(sport, dport, data[reply])
        frames.append(ip_frame(source, target, 6 if p['protocol'] == 'tcp' else 17, transport,
                               src=wire.MACS['lab' if reply else 'test'], dst=wire.MACS['test' if reply else 'lab']))
    return frames


def marker_exchange(m):
    request = ip_frame(m['source'], m['target'], 17, udp(41000, m['port'], wire.marker_query(m)))
    response = ip_frame(m['target'], m['source'], 17, udp(m['port'], 41000, wire.marker_answer(m)),
                        src=wire.MACS['lab'], dst=wire.MACS['test'])
    return [request, response]


def arp(op, sender, target, *, src, dst, sha, tha):
    body = struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, op, mac(sha), socket.inet_aton(sender), mac(tha), socket.inet_aton(target))
    return ethernet(src, dst, ETHER_ARP, body + bytes(18))


def neighbor(kind, source, target, neighbor_address, *, src, dst):
    return ip_frame(source, target, 58, icmp(kind, bytes(4) + socket.inet_pton(socket.AF_INET6, neighbor_address)),
                    src=src, dst=dst)


def capture(frames):
    raw = bytearray(wire.PCAP_HEADER)
    for frame in frames:
        raw.extend(struct.pack('<IIII', 0, 0, len(frame), len(frame)) + frame)
    return bytes(raw)


def pcap(expected, window=None, extra=()):
    frames = [f for p in expected for f in exchange(p)]
    if window is None:
        return capture(frames)
    return capture(marker_exchange(window[0]) + frames + list(extra) + marker_exchange(window[1]))


def canary_frames(*, udp_flow=True, tcp_flow=True):
    """The two deliberate flows and the errors the lab's router sends back for them."""
    def error(flow):
        return ip_frame(wire.TARGETS[4], wire.CLIENTS[4], 1, icmp(3, bytes(4) + flow[14:14 + 28]),
                        src=wire.MACS['lab'], dst=wire.MACS['test'])
    datagram = ip_frame(wire.CLIENTS[4], wire.TARGETS[4], 17, udp(42000, wire.CANARY_PORT, b'canary'))
    syn = ip_frame(wire.CLIENTS[4], wire.CANARY_TCP_TARGET, 6, tcp(42001, wire.CANARY_PORT, flags=0x02))
    return (([datagram, error(datagram)] if udp_flow else []) + ([syn, error(syn)] if tcp_flow else []))


def healthy(window, **changes):
    """A clean health record whose marker times follow the lab machine's own clock."""
    rows = [dict(word=m['word'], nonce=m['nonce'], at=at) for m, at in zip(window, (2.0, 8.0))]
    return dict(error=False, dropped=0, finished=True, capture_started=1.0, capture_ended=9.0,
                markers=rows) | changes


def wire_names():
    return tuple(row[0] for row in wire.ALLOWANCES)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.expected = wire.probes('a' * 32, iter(f'{i:024x}' for i in range(8)).__next__)
        self.replies = [{**p, 'response': wire.answer(p).hex()} for p in self.expected]
        self.raw = pcap(self.expected)
        self.health = dict(error=False, dropped=0, finished=True)

    def qualify(self, **changes):
        args = dict(expected=self.expected, replies=self.replies, logs=self.replies,
                    capture=self.raw, ready=True, health=self.health)
        args.update(changes)
        return wire.qualify(**args)

    def test_both_families_require_answers_logs_and_bidirectional_capture(self):
        self.assertTrue(self.qualify()['qualified'])
        self.assertEqual('PASS', self.qualify()['ipv6'])

    def test_stale_nonce_missing_target_stopped_observer_and_broken_channel_are_unverified(self):
        stale = wire.probes('b' * 32, iter(f'{i:024x}' for i in range(8)).__next__)
        for changes in (dict(capture=pcap(stale)), dict(replies=[]), dict(logs=[]),
                        dict(capture=self.raw[:24]), dict(ready=False),
                        dict(health=dict(error=True, dropped=0, finished=True)),
                        dict(health=dict(error=False, dropped=1, finished=True))):
            with self.subTest(changes=list(changes)):
                result = self.qualify(**changes)
                self.assertFalse(result['qualified'])
                self.assertEqual('UNVERIFIED', result['observer'])

    def test_routed_ipv6_cannot_be_replaced_by_link_local(self):
        foreign = [dict(p, target='fe80::1') if p['family'] == 6 else p for p in self.expected]
        self.assertFalse(self.qualify(capture=pcap(foreign))['qualified'])

    def test_incomplete_and_overlimit_capture_are_errors(self):
        for raw in (self.raw[:-1], b'x' * (wire.CAPTURE_LIMIT + 1), self.raw[:23]):
            with self.assertRaises(ValueError):
                self.qualify(capture=raw)

    def test_interfaces_are_selected_by_role_and_unique_mac(self):
        row = dict(ifname='enp7s0', address=wire.MACS['test'], link_type='ether')
        self.assertEqual('enp7s0', wire.interface([row], 'test'))
        for rows, role in (([row], 'lab'), ([row, row], 'test'), ([row], 'other'),
                           ([row, dict(ifname='other', address='00:00:5e:00:53:63', link_type='ether')], 'test')):
            with self.assertRaises(ValueError):
                wire.interface(rows, role)


class LeakTests(unittest.TestCase):
    def setUp(self):
        nonces = iter(f'{i:024x}' for i in range(10))
        self.expected = wire.probes('a' * 32, nonces.__next__)
        self.window = wire.markers('a' * 32, nonces.__next__)
        self.replies = [dict(m, response=wire.marker_answer(m).hex()) for m in self.window]
        self.health = dict(error=False, dropped=0, finished=True, capture_started=1.0, capture_ended=9.0,
                           markers=[dict(word=m['word'], nonce=m['nonce'], at=at)
                                    for m, at in zip(self.window, (2.0, 8.0))])
        self.test, self.lab = wire.MACS['test'], wire.MACS['lab']

    def verdict(self, extra=(), **changes):
        args = dict(raw=pcap(self.expected, self.window, extra), expected=self.expected, window=self.window,
                    health=self.health, ready=True, marker_replies=self.replies)
        args.update(changes)
        return wire.leak_verdict(**args)

    def ping(self, target=wire.TARGETS[4]):
        return ip_frame(wire.CLIENTS[4], target, 1, icmp(8, bytes(4) + b'ping'))

    def test_a_clean_run_has_no_leak_and_every_frame_in_a_category(self):
        result = self.verdict()
        self.assertEqual(('NONE', 'clean'), (result['leak'], result['leak_reason']))
        self.assertEqual(dict(probe=16, marker=4, infrastructure=0, unexpected=0, foreign=0, unparsed=0),
                         result['categories'])
        self.assertEqual(dict(markers_found=True, ordered=True), result['window'])
        self.assertEqual([], result['unexpected'])

    def test_arp_neighbor_discovery_and_multicast_listener_traffic_are_infrastructure(self):
        extra = [
            arp(1, wire.CLIENTS[4], wire.GATEWAYS[4], src=self.test, dst=wire.BROADCAST, sha=self.test,
                tha='00:00:00:00:00:00'),
            arp(2, wire.GATEWAYS[4], wire.CLIENTS[4], src=self.lab, dst=self.test, sha=self.lab, tha=self.test),
            neighbor(135, wire.CLIENTS[6], 'ff02::1:ff00:1', wire.GATEWAYS[6], src=self.test, dst='33:33:ff:00:00:01'),
            neighbor(136, wire.GATEWAYS[6], wire.CLIENTS[6], wire.GATEWAYS[6], src=self.lab, dst=self.test),
            neighbor(135, 'fe80::2', 'fe80::1', 'fe80::1', src=self.lab, dst=self.test),
            ip_frame('fe80::1', 'ff02::2', 58, icmp(133, bytes(4)), dst='33:33:00:00:00:02'),
            ip_frame('fe80::2', 'ff02::1', 58, icmp(134, bytes(12)), src=self.lab, dst='33:33:00:00:00:01'),
            ip_frame('fe80::1', 'ff02::16', 58, icmp(143, bytes(4)), first=0, dst='33:33:00:00:00:16',
                     extension=bytes([58, 0, 5, 2, 0, 0, 1, 0]))]
        result = self.verdict(extra)
        self.assertEqual(8, result['categories']['infrastructure'])
        self.assertEqual('NONE', result['leak'])

    def test_service_traffic_outside_the_listed_exchanges_is_a_leak(self):
        extra = [
            arp(1, wire.CLIENTS[4], '192.0.2.99', src=self.test, dst=wire.BROADCAST, sha=self.test,
                tha='00:00:00:00:00:00'),
            arp(2, wire.GATEWAYS[4], wire.CLIENTS[4], src=self.lab, dst=self.test, sha=self.test, tha=self.test),
            neighbor(135, wire.CLIENTS[6], 'ff02::1:ff00:1', '2001:db8:6a:3::9', src=self.test, dst='33:33:ff:00:00:01'),
            neighbor(136, wire.GATEWAYS[6], wire.CLIENTS[6], wire.GATEWAYS[6], src=self.lab, dst='00:00:5e:00:53:70'),
            ip_frame(wire.CLIENTS[6], wire.GATEWAYS[6], 58, icmp(128, bytes(4) + b'ping'))]
        result = self.verdict(extra)
        self.assertEqual((5, 'DETECTED'), (result['categories']['unexpected'], result['leak']))

    def test_repeated_tcp_segments_and_data_free_segments_of_the_connection_are_probe_frames(self):
        http = self.expected[0]
        request, response = exchange(http)
        client, server = http['source'], http['target']
        def segment(flags, reply=False):
            source, target = (server, client) if reply else (client, server)
            ports = (http['port'], 40000) if reply else (40000, http['port'])
            return ip_frame(source, target, 6, tcp(*ports, flags=flags), src=self.lab if reply else self.test,
                            dst=self.test if reply else self.lab)
        extra = [request, response, segment(0x02), segment(0x12, True), segment(0x10), segment(0x11),
                 segment(0x04, True)]
        result = self.verdict(extra)
        self.assertEqual((16 + 7, 'NONE'), (result['categories']['probe'], result['leak']))

    def test_a_connection_to_a_probe_service_that_carried_no_exchange_is_unexpected(self):
        syn = ip_frame(wire.CLIENTS[4], wire.TARGETS[4], 6, tcp(41234, wire.PORTS['http'], flags=0x02))
        self.assertEqual('DETECTED', self.verdict([syn])['leak'])

    def test_probe_shaped_frames_with_foreign_hardware_or_payload_are_unexpected(self):
        udp_probe = next(p for p in self.expected if p['service'] == 'udp' and p['family'] == 4)
        spoofed = ip_frame(udp_probe['source'], udp_probe['target'], 17,
                           udp(40001, udp_probe['port'], wire.query(udp_probe)), src='00:00:5e:00:53:70')
        other = ip_frame(udp_probe['source'], udp_probe['target'], 17, udp(40002, udp_probe['port'], b'other'))
        result = self.verdict([spoofed, other])
        self.assertEqual((2, 'DETECTED'), (result['categories']['unexpected'], result['leak']))

    def test_icmp_echo_from_the_test_machine_is_unexpected_and_described_without_payload(self):
        result = self.verdict([self.ping()])
        self.assertEqual('DETECTED', result['leak'])
        self.assertEqual([('0x0800', 4, 'icmp', ('192.0.2.2', '203.0.113.2'), None, 14 + 20 + 12)], result['unexpected'])

    def test_other_port_other_target_other_prefix_and_other_ethertype_are_unexpected(self):
        frames = {
            'port': ip_frame(wire.CLIENTS[4], wire.TARGETS[4], 17, udp(40003, 9001, b'x')),
            'target': ip_frame(wire.CLIENTS[4], '198.51.100.7', 6, tcp(40004, 8080, flags=0x02)),
            'prefix': ip_frame(wire.CLIENTS[6], '2001:db8:6a:3::2', 17, udp(40005, 9000, b'x')),
            'ethertype': ethernet(self.test, self.lab, (0x88b5).to_bytes(2, 'big'), bytes(46)),
            'broadcast': ethernet(self.test, wire.BROADCAST, (0x88b5).to_bytes(2, 'big'), bytes(46))}
        for name, frame in frames.items():
            with self.subTest(name=name):
                result = self.verdict([frame])
                self.assertEqual(('DETECTED', 1), (result['leak'], result['categories']['unexpected']))
        self.assertEqual(('0x88b5', None, None, (self.test, self.lab), None, 60),
                         self.verdict([frames['ethertype']])['unexpected'][0])

    def test_unparsable_frames_are_counted_and_never_become_no_leak(self):
        whole = ip_frame(wire.CLIENTS[4], wire.TARGETS[4], 17, udp(40006, 9000, b'payload'))
        fragment = ip_frame('198.51.100.1', '198.51.100.2', 17, udp(40006, 9000, b'payload'), fragment=0x2000,
                            src='00:00:5e:00:53:70', dst='00:00:5e:00:53:71')
        short_arp = ethernet(self.test, wire.BROADCAST, ETHER_ARP, bytes(20))
        for name, frame, reason in (('cut', whole[:-10], 'unparsed-frame:fragmented-or-invalid-ipv4'),
                                    ('fragment', fragment, 'unparsed-frame:fragmented-or-invalid-ipv4'),
                                    ('arp', short_arp, 'unparsed-frame:truncated-arp'),
                                    ('header', whole[:20], 'unparsed-frame:truncated-ipv4')):
            with self.subTest(name=name):
                result = self.verdict([frame])
                self.assertEqual(('UNVERIFIED', reason, 1), (result['leak'], result['leak_reason'],
                                                             result['categories']['unparsed']))

    def fragments(self, **kwargs):
        data = udp(40006, 9000, b'payload')
        header = bytes([17, 0, 0, 1, 0, 0, 0, 7])
        return {'ipv4-first': ip_frame(wire.CLIENTS[4], wire.TARGETS[4], 17, data, fragment=0x2000, **kwargs),
                'ipv4-later': ip_frame(wire.CLIENTS[4], wire.TARGETS[4], 17, data, fragment=0x0010, **kwargs),
                'ipv6': ip_frame(wire.CLIENTS[6], wire.TARGETS[6], 17, data, first=44, extension=header, **kwargs),
                'ipv6-behind-options': ip_frame(wire.CLIENTS[6], wire.TARGETS[6], 17, data, first=60,
                                                extension=bytes([44, 0, 1, 4, 0, 0]) + bytes(2) + header, **kwargs)}

    def test_a_fragment_to_or_from_the_test_machine_is_a_leak_described_without_payload(self):
        for name, frame in self.fragments().items():
            with self.subTest(name=name):
                result = self.verdict([frame])
                self.assertEqual(('DETECTED', 1, 0, 1), (result['leak'], result['categories']['unexpected'],
                                                          result['categories']['unparsed'], result['canary_other']))
                self.assertEqual('fragment', result['unexpected'][0][2])
                self.assertEqual(len(frame), result['unexpected'][0][5])
        addresses = ('0x0800', 4, 'fragment', (wire.CLIENTS[4], wire.TARGETS[4]), None, 14 + 20 + 15)
        self.assertEqual([addresses], self.verdict([self.fragments()['ipv4-first']])['unexpected'])

    def test_a_fragment_is_matched_by_hardware_address_or_by_ip_address(self):
        stranger, other = '00:00:5e:00:53:70', '00:00:5e:00:53:71'
        data = udp(40006, 9000, b'payload')
        to_test = ip_frame(wire.TARGETS[4], wire.CLIENTS[4], 17, data, fragment=0x2000, src=stranger, dst=other)
        by_mac = ip_frame('198.51.100.1', '198.51.100.2', 17, data, fragment=0x2000, src=stranger, dst=self.test)
        by_reply = ip_frame(wire.TARGETS[6], wire.CLIENTS[6], 17, data, first=44, src=self.lab, dst=self.test,
                            extension=bytes([17, 0, 0, 1, 0, 0, 0, 7]))
        for name, frame in (('to-address', to_test), ('by-mac', by_mac), ('reply', by_reply)):
            with self.subTest(name=name):
                result = self.verdict([frame])
                self.assertEqual(('DETECTED', 1), (result['leak'], result['categories']['unexpected']))

    def test_a_fragment_between_other_machines_or_with_unreadable_headers_is_unverified(self):
        stranger, other = '00:00:5e:00:53:70', '00:00:5e:00:53:71'
        data = udp(40006, 9000, b'payload')
        foreign4 = ip_frame('198.51.100.1', '198.51.100.2', 17, data, fragment=0x2000, src=stranger, dst=other)
        foreign6 = ip_frame('2001:db8:6a:3::1', '2001:db8:6a:3::2', 17, data, first=44, src=stranger, dst=other,
                            extension=bytes([17, 0, 0, 1, 0, 0, 0, 7]))
        mine = self.fragments()
        cases = (('foreign4', foreign4, 'unparsed-frame:fragmented-or-invalid-ipv4'),
                 ('foreign6', foreign6, 'unparsed-frame:fragmented-ipv6'),
                 ('cut-ipv4-header', mine['ipv4-first'][:14 + 12], 'unparsed-frame:truncated-ipv4'),
                 ('cut-ipv6-header', mine['ipv6'][:14 + 30], 'unparsed-frame:truncated-ipv6'),
                 ('cut-before-fragment-header', mine['ipv6-behind-options'][:14 + 40 + 4], 'unparsed-frame:invalid-ipv6'))
        for name, frame, reason in cases:
            with self.subTest(name=name):
                result = self.verdict([frame])
                self.assertEqual(('UNVERIFIED', reason, 1, 0), (result['leak'], result['leak_reason'],
                                                                result['categories']['unparsed'],
                                                                result['categories']['unexpected']))

    def test_a_fragment_cut_after_its_ip_header_is_still_a_leak(self):
        for name in ('ipv4-first', 'ipv6'):
            with self.subTest(name=name):
                frame = self.fragments()[name]
                self.assertEqual('DETECTED', self.verdict([frame[:14 + 48]])['leak'])

    def test_empty_and_header_only_captures_and_broken_records_are_unverified(self):
        for raw, reason in ((b'', 'invalid-pcap:invalid-or-overlimit-pcap'),
                            (wire.PCAP_HEADER, 'window-markers-missing-or-repeated'),
                            (pcap(self.expected, self.window)[:-1], 'invalid-pcap:truncated-pcap-frame'),
                            (pcap(self.expected, self.window) + bytes(5), 'invalid-pcap:incomplete-pcap')):
            with self.subTest(reason=reason):
                result = self.verdict(raw=raw)
                self.assertEqual(('UNVERIFIED', reason), (result['leak'], result['leak_reason']))

    def test_traffic_between_other_machines_is_counted_but_does_not_change_the_verdict(self):
        stranger = '00:00:5e:00:53:70'
        extra = [ip_frame('198.51.100.1', '198.51.100.2', 17, udp(5000, 5001, b'x'), src=stranger, dst=self.lab),
                 arp(1, '198.51.100.1', '198.51.100.2', src=self.lab, dst=wire.BROADCAST, sha=self.lab,
                     tha='00:00:00:00:00:00')]
        result = self.verdict(extra)
        self.assertEqual((2, 'NONE'), (result['categories']['foreign'], result['leak']))

    def test_a_seen_leak_stays_a_leak_when_the_observer_failed(self):
        broken = dict(error=True, dropped=3, finished=False)
        result = self.verdict([self.ping()], health=broken, ready=False, marker_replies=[])
        self.assertEqual('DETECTED', result['leak'])
        before_open = capture([self.ping()])
        self.assertEqual('DETECTED', self.verdict(raw=before_open, health=broken)['leak'])

    def test_traffic_before_open_and_after_close_is_still_judged(self):
        frames = marker_exchange(self.window[0]) + [f for p in self.expected for f in exchange(p)] \
            + marker_exchange(self.window[1])
        before = self.verdict(raw=capture([self.ping()] + frames))
        after = self.verdict(raw=capture(frames + [self.ping()]))
        self.assertEqual(('DETECTED', 'DETECTED'), (before['leak'], after['leak']))
        self.assertTrue(before['window']['ordered'] and after['window']['ordered'])

    def test_markers_must_be_single_complete_and_around_every_probe(self):
        open_pair, close_pair = (marker_exchange(m) for m in self.window)
        probes = [f for p in self.expected for f in exchange(p)]
        cases = {
            'no-close': open_pair + probes,
            'no-open': probes + close_pair,
            'open-twice': open_pair + open_pair + probes + close_pair,
            'close-twice': open_pair + probes + close_pair + close_pair,
            'request-only': open_pair[:1] + probes + close_pair,
            'probe-before-open': probes[:2] + open_pair + probes[2:] + close_pair,
            'probe-after-close': open_pair + probes[:-2] + close_pair + probes[-2:],
            'swapped': close_pair + probes + open_pair,
        }
        for name, frames in cases.items():
            with self.subTest(name=name):
                result = self.verdict(raw=capture(frames))
                self.assertEqual('UNVERIFIED', result['leak'])
                self.assertTrue(result['leak_reason'].startswith('window-markers-'), result['leak_reason'])
                self.assertFalse(result['window']['markers_found'] and result['window']['ordered'])

    def closing_case(self, *after):
        """Every exchange inside the window, then the frames that follow the closing marker."""
        open_pair, close_pair = (marker_exchange(m) for m in self.window)
        inside = [f for p in self.expected for f in exchange(p)]
        return self.verdict(raw=capture(open_pair + inside + close_pair + list(after)))

    def http_segment(self, flags, reply=False, port=40000):
        http = self.expected[0]
        source, target = (http['target'], http['source']) if reply else (http['source'], http['target'])
        ports = (http['port'], port) if reply else (port, http['port'])
        return ip_frame(source, target, 6, tcp(*ports, flags=flags), src=self.lab if reply else self.test,
                        dst=self.test if reply else self.lab)

    def test_the_last_segments_of_a_closing_connection_may_follow_the_closing_marker(self):
        for name, frame in (('ack-of-target', self.http_segment(0x10, True)),
                            ('fin-of-target', self.http_segment(0x11, True)),
                            ('ack-of-test', self.http_segment(0x10)),
                            ('reset', self.http_segment(0x04, True))):
            with self.subTest(name=name):
                result = self.closing_case(frame)
                self.assertEqual(('NONE', 17), (result['leak'], result['categories']['probe']))
                self.assertTrue(result['window']['ordered'])

    def test_a_syn_or_exchange_data_after_the_closing_marker_is_out_of_order(self):
        request = exchange(self.expected[0])[0]
        for name, frame in (('syn', self.http_segment(0x02)), ('syn-ack', self.http_segment(0x12, True)),
                            ('data', request)):
            with self.subTest(name=name):
                result = self.closing_case(frame)
                self.assertEqual(('UNVERIFIED', 'window-markers-out-of-order'),
                                 (result['leak'], result['leak_reason']))
                self.assertEqual(17, result['categories']['probe'])

    def test_an_empty_segment_on_a_port_no_exchange_used_after_the_closing_marker_is_a_leak(self):
        result = self.closing_case(self.http_segment(0x10, port=40999))
        self.assertEqual(('DETECTED', 1), (result['leak'], result['categories']['unexpected']))

    def link_events(self):
        zero = '00:00:00:00:00:00'
        return {
            'arp-announcement': arp(1, wire.CLIENTS[4], wire.CLIENTS[4], src=self.test, dst=wire.BROADCAST,
                                    sha=self.test, tha=zero),
            'arp-probe': arp(1, '0.0.0.0', wire.CLIENTS[4], src=self.test, dst=wire.BROADCAST, sha=self.test,
                             tha=zero),
            'ipv6-dad': neighbor(135, '::', 'ff02::1:ff00:2', wire.CLIENTS[6], src=self.test, dst='33:33:ff:00:00:02'),
            'ipv6-unspecified-rs': ip_frame('::', 'ff02::2', 58, icmp(133, bytes(4)), dst='33:33:00:00:00:02')}

    def test_a_link_event_is_a_leak_unless_its_allowance_is_declared(self):
        for name, frame in self.link_events().items():
            with self.subTest(name=name):
                plain = self.verdict([frame])
                self.assertEqual(('DETECTED', 1), (plain['leak'], plain['categories']['unexpected']))
                self.assertNotIn('allowed', plain['categories'])
                allowed = self.verdict([frame], allowances=[name])
                self.assertEqual(('NONE', 0), (allowed['leak'], allowed['categories']['unexpected']))
                self.assertEqual({name: 1}, allowed['categories']['allowed'])
                self.assertEqual('DETECTED', self.verdict([frame], allowances=set(wire_names()) - {name})['leak'])

    def test_every_allowance_together_counts_each_name_and_the_lab_machine_may_announce_too(self):
        lab_announcement = arp(1, wire.GATEWAYS[4], wire.GATEWAYS[4], src=self.lab, dst=wire.BROADCAST, sha=self.lab,
                               tha='00:00:00:00:00:00')
        extra = list(self.link_events().values()) + [lab_announcement]
        result = self.verdict(extra, allowances=wire_names())
        self.assertEqual(dict(zip(sorted(wire_names()), (2, 1, 1, 1))), result['categories']['allowed'])
        self.assertEqual(('NONE', 0), (result['leak'], result['categories']['unexpected']))

    def test_a_frame_that_only_looks_like_an_allowance_stays_unexpected(self):
        zero, stranger = '00:00:00:00:00:00', '00:00:5e:00:53:70'
        temporary = '2001:db8:6a:1::abcd'
        cases = {
            'announcement-of-another-address': arp(1, '192.0.2.99', '192.0.2.99', src=self.test, dst=wire.BROADCAST,
                                                   sha=self.test, tha=zero),
            'announcement-of-the-peer-address': arp(1, wire.GATEWAYS[4], wire.GATEWAYS[4], src=self.test,
                                                    dst=wire.BROADCAST, sha=self.test, tha=zero),
            'announcement-to-one-machine': arp(1, wire.CLIENTS[4], wire.CLIENTS[4], src=self.test, dst=self.lab,
                                               sha=self.test, tha=zero),
            'announcement-from-a-stranger': arp(1, wire.CLIENTS[4], wire.CLIENTS[4], src=stranger, dst=wire.BROADCAST,
                                                sha=stranger, tha=zero),
            'probe-for-another-address': arp(1, '0.0.0.0', '192.0.2.99', src=self.test, dst=wire.BROADCAST,
                                             sha=self.test, tha=zero),
            'dad-for-a-temporary-address': neighbor(135, '::', 'ff02::1:ff00:abcd', temporary, src=self.test,
                                                    dst='33:33:ff:00:ab:cd'),
            'dad-for-a-foreign-address': neighbor(135, '::', 'ff02::1:ff00:9', '2001:db8:6a:3::9', src=self.test,
                                                  dst='33:33:ff:00:00:09'),
            'dad-to-the-wrong-group': neighbor(135, '::', 'ff02::1:ff00:3', wire.CLIENTS[6], src=self.test,
                                               dst='33:33:ff:00:00:03'),
            'solicitation-from-a-temporary-address': neighbor(135, temporary, 'ff02::1:ff00:abcd', temporary,
                                                              src=self.test, dst='33:33:ff:00:ab:cd'),
            'router-solicitation-to-all-nodes': ip_frame('::', 'ff02::1', 58, icmp(133, bytes(4)),
                                                         dst='33:33:00:00:00:01'),
            'router-solicitation-from-a-temporary-address': ip_frame(temporary, 'ff02::2', 58, icmp(133, bytes(4)),
                                                                     dst='33:33:00:00:00:02'),
        }
        for name, frame in cases.items():
            with self.subTest(name=name):
                result = self.verdict([frame], allowances=wire_names())
                self.assertEqual(('DETECTED', 1), (result['leak'], result['categories']['unexpected']))
                self.assertEqual(0, sum(result['categories']['allowed'].values()))

    def test_an_unknown_allowance_is_an_error_before_anything_is_parsed(self):
        for names in (['arp-announcement', 'made-up'], ['ARP-PROBE'], [None]):
            with self.subTest(names=names):
                with self.assertRaises(ValueError):
                    self.verdict(raw=b'', allowances=names)
                with self.assertRaises(ValueError):
                    wire.classify(self.raw_capture(), self.expected, self.window, names)

    def test_a_marker_of_another_run_is_unexpected(self):
        stale = wire.markers('b' * 32, iter(f'{i:024x}' for i in range(2)).__next__)
        result = self.verdict(marker_exchange(stale[0]))
        self.assertEqual(('DETECTED', 2), (result['leak'], result['categories']['unexpected']))

    def test_every_observer_failure_makes_a_clean_capture_unverified(self):
        def health(**changes):
            return {**self.health, **changes}
        def times(started=1.0, opened=2.0, closed=8.0, ended=9.0):
            rows = [dict(word=m['word'], nonce=m['nonce'], at=at) for m, at in zip(self.window, (opened, closed))]
            return dict(capture_started=started, markers=rows, capture_ended=ended)
        cases = [
            ('observer-not-ready', dict(ready=False)),
            ('observer-health', dict(health=health(error=True))),
            ('observer-health', dict(health=health(dropped=1))),
            ('observer-health', dict(health=health(finished=False))),
            ('observer-health', dict(health=health(dropped=True))),
            ('marker-reply-mismatch', dict(marker_replies=self.replies[:1])),
            ('marker-reply-mismatch', dict(marker_replies=[dict(self.replies[0], response='00'), self.replies[1]])),
            ('capture-window-unrecorded', dict(health={k: v for k, v in self.health.items() if k != 'capture_ended'})),
            ('capture-window-unrecorded', dict(health=health(markers=[]))),
            ('capture-window-unrecorded', dict(health=health(capture_started='1'))),
            ('capture-window-unrecorded', dict(health=health(**times(started=float('nan'))))),
            ('capture-window-unrecorded', dict(health=health(markers=[dict(word='open', nonce='0' * 24, at=2.0),
                                                                      dict(word='close', nonce='1' * 24, at=8.0)]))),
            ('capture-ended-before-close', dict(health=health(**times(ended=7.0)))),
            ('capture-window-inconsistent', dict(health=health(**times(started=3.0)))),
            ('capture-window-inconsistent', dict(health=health(**times(opened=8.5)))),
        ]
        for index, (reason, changes) in enumerate(cases):
            with self.subTest(index=index, reason=reason):
                result = self.verdict(**changes)
                self.assertEqual(('UNVERIFIED', reason), (result['leak'], result['leak_reason']))

    def test_a_capture_that_reached_its_size_limit_is_unverified(self):
        padding = ethernet('00:00:5e:00:53:70', '00:00:5e:00:53:71', (0x88b5).to_bytes(2, 'big'), bytes(1400))
        frames = marker_exchange(self.window[0]) + [padding] * 90 + marker_exchange(self.window[1])
        result = self.verdict(raw=capture(frames))
        self.assertEqual(('UNVERIFIED', 'capture-limit-reached'), (result['leak'], result['leak_reason']))
        self.assertEqual(90, result['categories']['foreign'])

    def test_only_the_first_sixteen_unexpected_frames_are_described(self):
        result = self.verdict([self.ping()] * 20)
        self.assertEqual((20, 16), (result['categories']['unexpected'], len(result['unexpected'])))
        json.dumps(result)

    def test_canary_flows_include_the_errors_they_provoke_and_nothing_else(self):
        both = canary_frames()
        udp_flow = both[0]
        result = self.verdict(both)
        self.assertEqual((['tcp', 'udp'], 0, 'DETECTED', 4), (result['canary_flows'], result['canary_other'],
                                                              result['leak'], result['categories']['unexpected']))
        result = self.verdict(both[:2] + [self.ping()])
        self.assertEqual((['udp'], 1), (result['canary_flows'], result['canary_other']))
        stray = ip_frame(wire.TARGETS[4], wire.CLIENTS[4], 1, icmp(3, bytes(4) + udp_flow[14:14 + 20] + bytes(8)),
                         src=self.lab, dst=self.test)
        self.assertEqual(([], 1), tuple(self.verdict([stray])[k] for k in ('canary_flows', 'canary_other')))

    def test_the_window_needs_exactly_an_open_and_a_close_marker(self):
        for window in ([], self.window[::-1], self.window[:1], self.window + self.window):
            with self.assertRaises(ValueError):
                wire.classify(self.raw_capture(), self.expected, window)

    def raw_capture(self):
        return pcap(self.expected, self.window)

    def test_a_longer_health_record_still_qualifies_the_exchanges(self):
        replies = [{**p, 'response': wire.answer(p).hex()} for p in self.expected]
        result = wire.qualify(self.expected, replies, replies, self.raw_capture(), True, self.health)
        self.assertTrue(result['qualified'])


class PairTests(unittest.TestCase):
    def setUp(self):
        unix = patch.object(socket, 'AF_UNIX', 1, create=True)
        unix.start()
        self.addCleanup(unix.stop)
        self.fixture = test_qemu.PreparationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.config = replace(self.fixture.config, qga=True)
        self.runs = dict(test=self.fixture.run, lab=create_run(self.fixture.lease))
        self.plans = {}
        for role, run in self.runs.items():
            self.fixture.run, self.fixture.calls = run, []
            for identifier, name in EXECUTION_FILES.items():
                run.register(dict(id=identifier, kind='file', path=name))
                (run.directory / name).write_text('{}')
            (run.directory / 'execution-identity.json').write_text(json.dumps(dict(
                lab_id='lab-test', role=role, members={r: self.runs[r]._identity[0] for r in wire.MACS},
                controls=lab.controls(run),
                endpoint=dict(kind='inherited-unix-stream', role=role, mac=wire.MACS[role]))))
            self.plans[role] = self.fixture.prepare()
        self.endpoints = (Endpoint(), Endpoint())
        self.pair = lab.LabPair(self.fixture.lease, self.runs, 'lab-test', pair_factory=lambda *args: self.endpoints)
        self.addCleanup(self.pair.close)

    def launch(self, role):
        run, plan = self.runs[role], self.plans[role]
        child = test_lifecycle.Child()
        child.pid += 1 if role == 'lab' else 0
        control = test_lifecycle.Control(plan)
        identity = dict(id='qemu', kind='process', pid=child.pid, platform='posix',
                        boot_id='fake', start_id=str(child.pid), executable=self.fixture.config.executable)
        self.fixture.run, self.fixture.calls = run, [0, 0]
        class Agent:
            def __init__(self, stream, **kwargs):
                self.stream, self.closed = stream, False
            def close(self):
                self.stream.close()
                self.closed = True
        with patch.object(lifecycle, '_host'), patch.object(lifecycle, 'Qmp', return_value=control), \
             patch.object(lifecycle, 'Qga', side_effect=Agent), \
             patch.object(lifecycle.socket, 'socketpair', side_effect=lambda *args: (Endpoint(), Endpoint())), \
             patch.object(lifecycle, '_identity', return_value=identity), \
             patch.object(lifecycle.subprocess, 'Popen', return_value=child) as popen:
            vm = lifecycle.start(run, lab=self.pair, executor=self.fixture.fake, timeout=30)
        self.addCleanup(vm.close, hard=True)
        return vm, popen.call_args

    def test_two_owned_runs_have_separate_disks_ids_and_only_internal_network(self):
        first, a = self.launch('test')
        second, b = self.launch('lab')
        self.assertNotEqual(first.vm_uuid, second.vm_uuid)
        self.assertNotEqual(self.runs['test'].directory, self.runs['lab'].directory)
        for role, call in (('test', a), ('lab', b)):
            argv = call.args[0]
            disk = json.loads(argv[argv.index('-blockdev') + 1])
            self.assertEqual(str(self.runs[role].directory / 'root.qcow2'), disk['file']['filename'])
            self.assertIn('mac=' + wire.MACS[role], ' '.join(argv))
            self.assertIn('addr.type=fd', ' '.join(argv))
            self.assertFalse(any(x in ' '.join(argv) for x in ('hostfwd', 'tap,', 'user,', 'listen=')))
            self.assertEqual(3, len(call.kwargs['pass_fds']))
        self.assertFalse(set(a.kwargs['pass_fds']) & set(b.kwargs['pass_fds']))
        first.close(hard=True)
        self.assertTrue(first.completed)
        self.assertFalse(second.completed)
        self.assertEqual({second}, self.fixture.lease._active)

    def test_legacy_start_still_refuses_second_vm_and_foreign_role_is_rejected(self):
        self.launch('test')
        with self.assertRaises(lifecycle.LifecycleError):
            lifecycle.start(self.runs['lab'])
        with self.assertRaises(ValueError):
            self.pair.check_start(create_run(self.fixture.lease))
        with self.assertRaises(ValueError):
            self.pair.check_start(self.runs['test'])

    def test_channel_close_failure_is_explicit(self):
        with patch.object(self.endpoints[0], 'close', side_effect=OSError):
            with self.assertRaises(ValueError):
                self.pair.close()
            self.assertFalse(self.pair.closed)

    def test_opaque_capability_cannot_enable_multiple_vms(self):
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'invalid-lab-capability'):
            lifecycle.start(self.runs['test'], lab=SimpleNamespace(check_start=lambda _: None))


class OrchestrationTests(unittest.TestCase):
    def scenario(self, fault=None, canary=False):
        fixture = test_qemu.PreparationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        config = dict(schema='rosetun.matrix.lab.v1', state_directory=str(fixture.root / 'lab-state'),
                      stand_id='lab', qemu=asdict(replace(fixture.config, machine='pc-i440fx-10.0', qga=True)),
                      test_image=fixture.image.record(), lab_image=fixture.image.record())
        members, captured = {}, {}
        def start(run, lab):
            role = lab.role(run)
            class Vm:
                vm_uuid = '12345678-1234-4234-8234-123456789abc'
                last_boot_id = '22345678-1234-4234-8234-123456789abc'
                def resume(self): pass
                def wait_initial_guest(self, **kwargs): return dict(result='observed')
                def close(self, **kwargs):
                    run._lease._active.discard(self)
                    if fault == 'vm-close' and role == 'lab':
                        raise ValueError('close-failed')
                    self.closed = True
            vm = Vm()
            vm.run, vm.closed = run, False
            members[role] = vm
            run._lease._active.add(vm)
            return vm
        class Guest:
            def __init__(self, vm, role, lab_id, **kwargs): pass
            def call(self, operation, expected, window=(), canary=False):
                captured['probes'], captured['window'] = expected, list(window)
                captured.setdefault('canary', []).append((operation, canary))
                if operation == 'setup':
                    return dict(capture_ready=fault != 'observer-not-ready')
                if operation == 'probe':
                    if fault == 'target-unavailable':
                        raise ValueError('target-unavailable')
                    return dict(replies=[{**p, 'response': wire.answer(p).hex()} for p in expected],
                                marker_replies=[] if fault == 'marker-reply-lost' else
                                [{**m, 'response': wire.marker_answer(m).hex()} for m in window],
                                marker_sent=dict(open=1.0, close=2.0))
                return dict(finished=True)
            def read(self, name, limit):
                expected, window = captured['probes'], captured['window']
                if name == 'capture.pcap':
                    if fault == 'missing-observation':
                        return wire.PCAP_HEADER
                    if fault == 'leak':
                        return pcap(expected, window, [ip_frame(wire.CLIENTS[4], wire.TARGETS[4], 1, icmp(8))])
                    if canary and fault != 'no-markers':
                        stray = [ip_frame(wire.CLIENTS[4], wire.TARGETS[4], 1, icmp(8))]
                        extra = {'blind': [], 'udp-only': canary_frames(tcp_flow=False),
                                 'stray': canary_frames() + stray}.get(fault, canary_frames())
                        opened, closed = (marker_exchange(m) for m in window)
                        body = [f for p in expected for f in exchange(p)] + canary_frames()
                        if fault == 'lost-marker':
                            return capture(opened + body)
                        if fault == 'swapped-markers':
                            return capture(closed + body + opened)
                        return pcap(expected, window, extra)
                    return pcap(expected) if fault == 'no-markers' else pcap(expected, window)
                if name == 'targets.json':
                    return json.dumps([{**p, 'response': wire.answer(p).hex()} for p in expected]).encode()
                return json.dumps(healthy(window, finished=fault != 'incomplete-evidence',
                                          **(dict(markers=[]) if fault == 'unrecorded-window' else {}))).encode()
        def pair(*args):
            result = lab.LabPair(*args, pair_factory=lambda *args: (Endpoint(), Endpoint()))
            if fault == 'channel-close':
                result.close = lambda: (_ for _ in ()).throw(ValueError('close-failed'))
            return result
        adapters = SimpleNamespace(host=lambda: None, prepare=lambda *args: None, start=start, pair=pair, guest=Guest,
                     execute=lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b'QEMU version 10.0.13'))
        with patch.object(socket, 'AF_UNIX', 1, create=True), \
             patch.object(lab, 'completion_verified', side_effect=lambda directory, manifest:
                          any(v.run.directory == directory and v.closed for v in members.values())):
            result = lab.lab_smoke(config, canary=canary, adapters=adapters, clock=lambda: 0, sleep=lambda _: None)
        result['canary_calls'] = captured.get('canary', [])
        return result

    def test_complete_smoke_requires_both_completions_and_keeps_release_closed(self):
        result = self.scenario()
        self.assertEqual(0, result['exit_code'])
        self.assertTrue(result['completed'])
        self.assertEqual(dict(test=True, lab=True), result['completion'])
        self.assertTrue(result['qualification']['qualified'])
        self.assertEqual(('NONE', 'clean'), (result['leak'], result['leak_reason']))
        self.assertEqual(dict(markers_found=True, ordered=True, test_clock_sent=dict(open=1.0, close=2.0)),
                         result['window'])
        self.assertEqual('UNVERIFIED', result['security_invariants'])
        self.assertFalse(result['release_gate'])

    def test_close_errors_and_incomplete_observation_prevent_success(self):
        for fault in ('vm-close', 'channel-close', 'observer-not-ready', 'target-unavailable',
                      'missing-observation', 'incomplete-evidence'):
            with self.subTest(fault=fault):
                result = self.scenario(fault)
                self.assertEqual(2, result['exit_code'])
                if fault not in ('vm-close', 'channel-close'):
                    self.assertFalse(result['qualification']['qualified'])
                else:
                    self.assertFalse(result['completed'])

    def test_a_seen_leak_fails_the_run_and_a_missing_window_is_never_no_leak(self):
        leaked = self.scenario('leak')
        self.assertEqual((2, 'DETECTED', 1), (leaked['exit_code'], leaked['leak'], leaked['categories']['unexpected']))
        self.assertTrue(leaked['qualification']['qualified'])
        for fault in ('no-markers', 'missing-observation', 'incomplete-evidence', 'target-unavailable'):
            with self.subTest(fault=fault):
                result = self.scenario(fault)
                self.assertEqual((2, 'UNVERIFIED'), (result['exit_code'], result['leak']))
        self.assertEqual('window-markers-missing-or-repeated', self.scenario('no-markers')['leak_reason'])

    def test_a_canary_run_succeeds_only_when_exactly_its_own_two_flows_are_detected(self):
        result = self.scenario(canary=True)
        self.assertEqual((0, 'DETECTED', True, ['tcp', 'udp'], 0),
                         (result['exit_code'], result['leak'], result['canary'], result['canary_flows'],
                          result['canary_other']))
        self.assertTrue(result['qualification']['qualified'])
        self.assertIn(('probe', True), result['canary_calls'])
        self.assertEqual(4, result['categories']['unexpected'])
        for fault in ('blind', 'udp-only', 'stray', 'leak', 'target-unavailable', 'no-markers',
                      'incomplete-evidence'):
            with self.subTest(fault=fault):
                self.assertEqual(2, self.scenario(fault, canary=True)['exit_code'])
        self.assertEqual('NONE', self.scenario('blind', canary=True)['leak'])

    def test_a_canary_run_without_a_proven_window_fails_even_when_both_flows_are_seen(self):
        for fault, reason in (('lost-marker', 'window-markers-missing-or-repeated'),
                              ('swapped-markers', 'window-markers-out-of-order'),
                              ('marker-reply-lost', 'marker-reply-mismatch'),
                              ('unrecorded-window', 'capture-window-unrecorded')):
            with self.subTest(fault=fault):
                result = self.scenario(fault, canary=True)
                self.assertEqual(['tcp', 'udp'], result['canary_flows'])
                self.assertEqual('DETECTED', result['leak'])
                self.assertIn(reason, result['observer_reasons'])
                self.assertEqual(2, result['exit_code'])
        self.assertEqual([], self.scenario(canary=True)['observer_reasons'])

    def test_the_canary_condition_names_each_part_of_the_proven_window(self):
        clean = dict(canary=True, leak='DETECTED', canary_flows=['tcp', 'udp'], canary_other=0,
                     window=dict(markers_found=True, ordered=True), observer_reasons=[])
        self.assertTrue(lab.expected_leak(clean))
        for changes in (dict(window=dict(markers_found=False, ordered=False)),
                        dict(window=dict(markers_found=True, ordered=False)),
                        dict(observer_reasons=['observer-health'])):
            with self.subTest(changes=changes):
                self.assertFalse(lab.expected_leak({**clean, **changes}))

    def test_an_ordinary_run_never_asks_for_the_leak_and_a_leak_fails_it(self):
        result = self.scenario()
        self.assertEqual((False, 0), (result['canary'], result['exit_code']))
        self.assertNotIn(('probe', True), result['canary_calls'])
        self.assertEqual(2, self.scenario('leak')['exit_code'])

    def test_dry_run_has_no_mutations_or_network(self):
        fixture = test_qemu.PreparationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        config = dict(schema='rosetun.matrix.lab.v1', state_directory=str(fixture.root / 'absent'),
                      stand_id='lab', qemu=asdict(replace(fixture.config, machine='pc-i440fx-10.0', qga=True)),
                      test_image=fixture.image.record(), lab_image=fixture.image.record())
        with patch('subprocess.Popen', side_effect=AssertionError('real process')), \
             patch.object(socket, 'socketpair', side_effect=AssertionError('real socket')):
            self.assertTrue(lab.plan_lab(config)['dry_run'])
            self.assertFalse(Path(config['state_directory']).exists())

    def test_failed_second_vm_closes_owned_first_and_never_claims_lab_completion(self):
        unix = patch.object(socket, 'AF_UNIX', 1, create=True)
        unix.start()
        self.addCleanup(unix.stop)
        fixture = test_qemu.PreparationTests()
        fixture.setUp()
        try:
            # Use a separate ledger from the preparation fixture.
            config = dict(schema='rosetun.matrix.lab.v1', state_directory=str(fixture.root / 'lab-state'),
                          stand_id='lab', qemu=asdict(replace(fixture.config, machine='pc-i440fx-10.0', qga=True)),
                          test_image=fixture.image.record(), lab_image=fixture.image.record())
            active = []
            def prepare(run, image, qemu):
                pass
            def start(run, lab):
                if active:
                    raise ValueError('second-start-failed')
                class Vm:
                    vm_uuid = '12345678-1234-4234-8234-123456789abc'
                    last_boot_id = '22345678-1234-4234-8234-123456789abc'
                    def resume(self): pass
                    def wait_initial_guest(self, **kwargs): return dict(result='observed')
                    def close(self, **kwargs):
                        self.closed = True
                        run._lease._active.discard(self)
                vm = Vm()
                vm.run, vm.closed = run, False
                run._lease._active.add(vm)
                active.append(vm)
                return vm
            adapters = SimpleNamespace(host=lambda: None, prepare=prepare, start=start,
                         pair=lambda *args: lab.LabPair(*args, pair_factory=lambda *args: (Endpoint(), Endpoint())),
                         execute=lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b'QEMU version 10.0.13'))
            result = lab.lab_smoke(config, adapters=adapters, clock=lambda: 0, sleep=lambda _: None)
            self.assertTrue(active[0].closed)
            self.assertFalse(result['completed'])
            self.assertEqual(2, result['exit_code'])
            self.assertFalse(result['release_gate'])
        finally:
            fixture.doCleanups()


class CommandLineTests(unittest.TestCase):
    def run_cli(self, *flags, exit_code=0):
        calls = []
        def smoke(config, **kwargs):
            calls.append(kwargs)
            return dict(exit_code=exit_code)
        with patch.object(lab, 'load_lab', return_value={}), patch.object(lab, 'lab_smoke', smoke),              contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(['lab-smoke', '--config', 'unused.toml', *flags])
        return code, calls

    def test_the_leak_control_is_requested_only_by_the_canary_flag(self):
        self.assertEqual((0, [dict(canary=False)]), self.run_cli())
        self.assertEqual((0, [dict(canary=True)]), self.run_cli('--canary'))
        self.assertEqual((2, [dict(canary=True)]), self.run_cli('--canary', exit_code=2))


class QgaFacadeTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.clock = 0
        self.boot = '12345678-1234-4234-8234-123456789abc'
        def rpc(name, timeout, args):
            self.calls.append((name, args))
            return self.responses[name]
        self.responses = {
            'guest-exec': dict(pid=123),
            'guest-exec-status': dict(exited=True, exitcode=0, **{'out-data': base64.b64encode(
                json.dumps(dict(lab_id='a' * 32, boot_id=self.boot, replies=[])).encode()).decode()}),
            'guest-file-open': 7, 'guest-file-read': dict(count=3, eof=True, **{'buf-b64': 'YWJj'}),
            'guest-file-close': {}}
        self.vm = SimpleNamespace(_check=lambda: None, _guest_lock=threading.Lock(), reset_pending=False,
             vm_uuid=self.boot, last_boot_id=self.boot, qga=SimpleNamespace(
                 _rpc=rpc, read_boot_id=lambda _: self.boot, probe=lambda _: None, valid=True))
        self.guest = lab.Guest(self.vm, 'test', 'a' * 32, clock=lambda: self.clock, sleep=lambda _: None)

    def test_only_fixed_entry_and_operation_are_executable(self):
        self.guest.call('probe', [])
        self.assertEqual(lab.ENTRY, self.calls[0][1]['path'])
        with self.assertRaises(ValueError):
            self.guest.call('/bin/sh', [])

    def test_boot_change_prevents_exec(self):
        self.vm.qga.read_boot_id = lambda _: 'different'
        with self.assertRaises(ValueError):
            self.guest.call('probe', [])

        self.assertFalse(self.calls)

    def test_artifact_limit_and_file_close_are_enforced(self):
        self.assertEqual(b'abc', self.guest.read('health.json', 3))
        with self.assertRaises(ValueError):
            self.guest.read('health.json', 2)
        self.assertEqual('guest-file-close', self.calls[-1][0])

    def test_truncated_helper_output_and_deadline_are_errors(self):
        self.responses['guest-exec-status']['out-truncated'] = True
        with self.assertRaises(ValueError):
            self.guest.call('probe', [])
        self.clock = 91
        with self.assertRaises(ValueError):
            self.guest.call('probe', [])


class GuestIdentityTests(unittest.TestCase):
    def setUp(self):
        source = Path(lab.__file__).parents[1] / 'linux/guest/lab-entry.py'
        spec = importlib.util.spec_from_file_location('lab_entry_test', source)
        self.entry = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {'lab_protocol': wire}):
            spec.loader.exec_module(self.entry)
        nonces = iter(f'{i:024x}' for i in range(10))
        self.request = dict(role='lab', lab_id='a' * 32,
             vm_uuid='12345678-1234-4234-8234-123456789abc',
             boot_id='22345678-1234-4234-8234-123456789abc',
             probes=wire.probes('a' * 32, nonces.__next__), operation='setup')
        self.request['markers'] = wire.markers('a' * 32, nonces.__next__)
        self.request['canary'] = False

    def test_wrong_vm_boot_or_role_cannot_mutate_guest_network(self):
        values = {'/etc/rosetun-lab-role': 'lab',
                  '/proc/sys/kernel/random/boot_id': self.request['boot_id'],
                  '/sys/class/dmi/id/product_uuid': self.request['vm_uuid']}
        for key in ('role', 'vm_uuid', 'boot_id'):
            request = dict(self.request, **{key: 'wrong'})
            with patch.object(self.entry.os, 'geteuid', return_value=0, create=True), \
                 patch.object(Path, 'read_text', lambda p: values[p.as_posix()]), \
                 patch.object(self.entry, 'command', side_effect=AssertionError('network operation before identity')):
                with self.assertRaises(ValueError):
                    self.entry.main(request)

    def identity(self, request):
        values = {'/etc/rosetun-lab-role': 'lab',
                  '/proc/sys/kernel/random/boot_id': request['boot_id'],
                  '/sys/class/dmi/id/product_uuid': request['vm_uuid']}
        rows = json.dumps([dict(ifname='enp7s0', address=wire.MACS['lab'], link_type='ether')]).encode()
        with patch.object(self.entry.os, 'geteuid', return_value=0, create=True),              patch.object(Path, 'read_text', lambda p: values[p.as_posix()]),              patch.object(self.entry, 'command', return_value=rows):
            return self.entry.identity(request)

    def test_only_the_run_s_own_two_markers_are_accepted(self):
        self.assertEqual('enp7s0', self.identity(self.request))
        first, second = self.request['markers']
        bad = {
            'missing': self.request['markers'][:1],
            'swapped': [second, first],
            'repeated-nonce': [first, dict(second, nonce=first['nonce'])],
            'probe-nonce': [first, dict(second, nonce=self.request['probes'][0]['nonce'])],
            'other-run': [dict(first, run_id='b' * 32), second],
            'other-port': [first, dict(second, port=wire.PORTS['udp'])],
            'other-source': [first, dict(second, source='192.0.2.9')],
            'extra-field': [first, dict(second, extra=1)],
            'short-nonce': [first, dict(second, nonce='abc')],
        }
        with self.assertRaises(ValueError):
            self.identity(dict(self.request, canary='yes'))
        for name, window in bad.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.identity(dict(self.request, markers=window))

    def test_the_observer_accepts_each_marker_once_and_only_in_order(self):
        first, second = self.request['markers']
        request = self.request
        source = wire.CLIENTS[4]
        self.assertIs(first, self.entry.accept_marker(request, [], wire.marker_query(first), source))
        self.assertIs(second, self.entry.accept_marker(request, [{}], wire.marker_query(second), source))
        for marks, data, peer in (([], wire.marker_query(second), source), ([{}], wire.marker_query(first), source),
                                  ([{}, {}], wire.marker_query(second), source), ([], wire.marker_query(first), '192.0.2.9'),
                                  ([], wire.marker_query(first) + b'x', source), ([], b'', source)):
            with self.assertRaises(ValueError):
                self.entry.accept_marker(request, marks, data, peer)

    def test_the_test_machine_sends_the_opening_marker_first_and_the_closing_marker_last(self):
        events = []
        def marker(m):
            events.append(m['word'])
            return dict(m, response=wire.marker_answer(m).hex())
        def exchanges(request):
            events.append('exchanges')
            return []
        with patch.object(self.entry, 'exchange_marker', marker),              patch.object(self.entry, 'probe_exchanges', exchanges), patch.object(self.entry.time, 'sleep'):
            result = self.entry.probe_all(self.request)
        self.assertEqual(['open', 'exchanges', 'close'], events)
        self.assertEqual(['open', 'close'], [m['word'] for m in result['marker_replies']])
        self.assertEqual({'open', 'close'}, set(result['marker_sent']))

    def test_the_canary_goes_out_between_the_exchanges_and_the_closing_marker_only_when_asked(self):
        for canary, expected in ((False, ['open', 'exchanges', 'close']),
                                 (True, ['open', 'exchanges', 'canary', 'close'])):
            events = []
            def marker(m):
                events.append(m['word'])
                return dict(m, response=wire.marker_answer(m).hex())
            with patch.object(self.entry, 'exchange_marker', marker), \
                 patch.object(self.entry, 'probe_exchanges', lambda request: events.append('exchanges') or []), \
                 patch.object(self.entry, 'send_canary', lambda: events.append('canary')), \
                 patch.object(self.entry.time, 'sleep'):
                self.entry.probe_all(dict(self.request, canary=canary))
            self.assertEqual(expected, events)

    def test_the_canary_is_a_datagram_to_an_unserved_port_and_a_syn_to_an_unheld_address(self):
        sockets = []
        outcome = [self.entry.errno.EINPROGRESS]
        class Fake:
            def __init__(self, family, kind):
                self.sent, self.connected = [], None
                sockets.append(self)
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def bind(self, address): self.bound = address
            def setblocking(self, flag): self.blocking = flag
            def sendto(self, data, address): self.sent.append(address)
            def connect_ex(self, address):
                self.connected = address
                return outcome[0]
        with patch.object(self.entry.socket, 'socket', Fake):
            self.entry.send_canary()
        datagram, stream = sockets
        self.assertEqual([(wire.TARGETS[4], wire.CANARY_PORT)], datagram.sent)
        self.assertEqual((wire.CANARY_TCP_TARGET, wire.CANARY_PORT), stream.connected)
        self.assertEqual(wire.CLIENTS[4], stream.bound[0])
        self.assertNotIn(wire.CANARY_PORT, wire.PORTS.values())
        outcome[0] = self.entry.errno.ENETUNREACH
        with patch.object(self.entry.socket, 'socket', Fake), self.assertRaises(ValueError):
            self.entry.send_canary()

    def test_a_refused_opening_marker_sends_no_probe(self):
        with patch.object(self.entry, 'exchange_marker', side_effect=ValueError('unexpected-marker-answer')),              patch.object(self.entry, 'probe_exchanges', side_effect=AssertionError('probe after failed marker')):
            with self.assertRaises(ValueError):
                self.entry.probe_all(self.request)

    def test_guest_evidence_write_limit_and_one_shot_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'claim.json'
            self.entry.write(path, dict(run='a' * 32))
            with self.assertRaises(FileExistsError):
                self.entry.write(path, dict(run='b' * 32))
            with self.assertRaises(ValueError):
                self.entry.write(Path(directory) / 'large.json', 'x' * wire.LOG_LIMIT)


if __name__ == '__main__':
    unittest.main()
