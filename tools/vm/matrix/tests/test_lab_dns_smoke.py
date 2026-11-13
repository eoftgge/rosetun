"""`lab-smoke --dns`: the resolver and the DoH target qualified with a sing-box client, on fake adapters."""
import contextlib
from dataclasses import asdict, replace
import io
import json
from pathlib import Path
import socket
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.vm.matrix import cli, lab, lab_protocol as wire
from tools.vm.matrix.tests import test_qemu
from tools.vm.matrix.tests.test_lab import (Endpoint, capture, exchange, healthy, ip_frame, marker_exchange, tcp,
                                            udp)
from tools.vm.matrix.tests.test_lab_tunnel import tunnel_block
from tools.vm.matrix.tests.test_lab_tunnel_protocol import direct, from_node, to_node

CLIENT_UDP_PORT = 41500


def plain_frames(check, *, reply=True, source=wire.CLIENTS[4]):
    """dns-plain on the wire: the question to the resolver and the resolver's answer."""
    question = wire.query(check)
    frames = [ip_frame(source, wire.RESOLVER, 17, udp(CLIENT_UDP_PORT, 53, question))]
    if reply:
        frames.append(ip_frame(wire.RESOLVER, source, 17, udp(53, CLIENT_UDP_PORT, wire.dns_reply(question)[0]),
                               src=wire.MACS['lab'], dst=wire.MACS['test']))
    return frames


class DnsSmoke(unittest.TestCase):
    def scenario(self, fault=None, dns=True, tunnel=True):
        fixture = test_qemu.PreparationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        config = dict(schema=lab.SCHEMA_V2, state_directory=str(fixture.root / 'lab-state'), stand_id='lab',
                      qemu=asdict(replace(fixture.config, machine='pc-i440fx-10.0', qga=True)),
                      test_image=fixture.image.record(), lab_image=fixture.image.record(), tunnel=tunnel_block())
        members, captured, pairs = {}, {}, []

        def start(run, lab):
            role = lab.role(run)

            class Vm:
                vm_uuid = '12345678-1234-4234-8234-123456789abc'
                last_boot_id = '22345678-1234-4234-8234-123456789abc'

                def resume(self): pass

                def wait_initial_guest(self, **kwargs): return dict(result='observed')

                def close(self, **kwargs):
                    run._lease._active.discard(self)
                    self.closed = True
            vm = Vm()
            vm.run, vm.closed = run, False
            members[role] = vm
            run._lease._active.add(vm)
            return vm

        class Guest:
            def __init__(self, vm, role, lab_id, **kwargs):
                self.role = role

            def call(self, operation, expected, window=(), canary=False, tunnel=None, options=None):
                captured['probes'], captured['window'] = expected, list(window)
                captured.setdefault('calls', []).append((self.role, operation, tunnel, options))
                captured['exchanges'] = tunnel['https']
                captured['checks'] = (options or {}).get('dns_check')
                if operation == 'setup':
                    return dict(capture_ready=True)
                if operation == 'probe':
                    first, second = captured['exchanges']
                    reports = dict(direct=dict(first, response=wire.https_answer(first).hex(), client_port=44000),
                                   tunnel=dict(second, response=wire.https_answer(second).hex()), client_exit=0)
                    answer = {}
                    if captured['checks']:
                        plain, doh = captured['checks']['plain'], captured['checks']['doh']
                        if fault == 'doh-client-failed':
                            raise ValueError('lab-helper-failed')
                        if fault == 'helper-failed':
                            raise lab.HelperFailed('lab-helper-failed', 'typeerror:' + 'x' * 20)
                        answered = dict(plain=dict(plain, response=wire.dns_reply(wire.query(plain))[0].hex()),
                                        doh=dict(doh, response=wire.https_answer(doh).hex()))
                        failures = {
                            'doh-exchange-failed': (dict(exchange='dns-doh-singbox', reason='unexpected-https-answer',
                                                         elapsed_ms=312), 1, 'FATAL start service: boom'),
                            'plain-exchange-failed': (dict(exchange='dns-plain', reason='timeout', elapsed_ms=5003),
                                                      None, ''),
                            'failed-unreadable': ('boom', 0, 'WARN none'),
                            'failed-foreign': (dict(exchange='/etc/passwd', reason='Not Valid', elapsed_ms=-1), 0,
                                               'WARN none')}
                        if fault in failures:
                            failed, code, text = failures[fault]
                            kept = {} if fault == 'plain-exchange-failed' else dict(plain=answered['plain'])
                            answer = dict(dns=dict(kept, failed=failed, client_exit=code, client_log=text))
                        else:
                            answer = dict(dns=dict(answered, client_exit=0, client_log='WARN none'))
                    return dict(replies=[{**p, 'response': wire.answer(p).hex()} for p in expected],
                                marker_replies=[{**m, 'response': wire.marker_answer(m).hex()} for m in window],
                                marker_sent=dict(open=1.0, close=2.0), https=reports, **answer)
                return dict(finished=True)

            def read(self, name, limit):
                expected, window = captured['probes'], captured['window']
                first, second = captured['exchanges']
                checks = captured['checks']
                if name == 'capture.pcap':
                    extra = direct(sport=44000) + [to_node(), from_node()]
                    if checks:
                        extra += plain_frames(checks['plain'], reply=fault != 'no-plain-reply')
                        extra += [to_node(sport=43001), from_node(dport=43001)]
                    if fault == 'direct-doh':
                        extra += [ip_frame(wire.CLIENTS[4], wire.DOH_ADDRESS, 6, tcp(40000, 443, b'x', 0x18))]
                    if fault == 'stray-udp53':
                        extra += [ip_frame(wire.CLIENTS[4], wire.RESOLVER, 17, udp(40001, 53, b'not-the-question'))]
                    return capture([f for m in window[:1] for f in marker_exchange(m)]
                                   + [f for p in expected for f in exchange(p)] + extra
                                   + [f for m in window[1:] for f in marker_exchange(m)])
                if name == 'targets.json':
                    return json.dumps([{**p, 'response': wire.answer(p).hex()} for p in expected]).encode()
                if name == 'https.json':
                    rows = [dict(source=wire.CLIENTS[4], port=44000, path=first['path'], at=5.0),
                            dict(source=wire.EGRESS, port=51000, path=second['path'], at=6.0)]
                    if checks and fault != 'target-not-asked':
                        rows.append(dict(source=wire.CLIENTS[4] if fault == 'target-direct' else wire.EGRESS,
                                         port=51001, path=checks['doh']['path'], at=7.0))
                    return json.dumps(rows).encode()
                if name == 'dns.json':
                    rows = [dict(source=wire.CLIENTS[4], transport='udp', name=wire.dns_name(checks['plain']), type='A')]
                    if fault == 'no-plain-row':
                        rows = []
                    if fault != 'no-doh-row':
                        rows.append(dict(source=wire.CLIENTS[4] if fault == 'doh-bypassed-node' else wire.EGRESS,
                                         transport='doh', name=wire.dns_name(checks['doh']), type='A'))
                        rows.append(dict(source=wire.EGRESS, transport='doh', name=wire.dns_name(checks['doh']),
                                         type='AAAA'))
                    return json.dumps(rows).encode()
                if name == 'node.log':
                    return b'inbound/shadowsocks[node-in]: connection from 192.0.2.2:43000\n'
                return json.dumps(healthy(window, node=dict(alive_at_finish=True, exit_code=-15))).encode()

        def pair(*args, **kwargs):
            result = lab.LabPair(*args, pair_factory=lambda *a: (Endpoint(), Endpoint()), **kwargs)
            pairs.append(result)
            return result

        adapters = SimpleNamespace(host=lambda: None, prepare=lambda *args: None, start=start, pair=pair,
                                   guest=Guest, execute=lambda *args, **kwargs: SimpleNamespace(
                                       returncode=0, stdout=b'QEMU version 10.0.13'))
        with patch.object(socket, 'AF_UNIX', 1, create=True), \
                patch.object(lab, '_state_path', side_effect=lambda value: value), \
                patch.object(lab, 'completion_verified', side_effect=lambda directory, manifest:
                             any(v.run.directory == directory and v.closed for v in members.values())):
            result = lab.lab_smoke(config, tunnel=tunnel, dns=dns, adapters=adapters, clock=lambda: 0,
                                   sleep=lambda _: None)
        result['calls'], result['pairs'], result['members'] = captured.get('calls', []), pairs, members
        result['configuration_used'] = config
        return result

    def test_a_complete_dns_run_succeeds_and_reports_the_dns_block(self):
        result = self.scenario()
        self.assertEqual(0, result['exit_code'])
        self.assertEqual(('NONE', 'clean'), (result['leak'], result['leak_reason']))
        block = dict(result['dns'])
        path = Path(block.pop('client_log_path'))
        self.assertEqual(dict(plain=True, doh_via_node=True, doh_requests=2, client_exit=0, client_log='WARN none',
                              failed=None), block)
        self.assertEqual(('client.log', b'WARN none'), (path.name, path.read_bytes()))
        self.assertEqual(result['members']['test'].run.directory, path.parent)
        self.assertTrue(result['tunnel']['direct'] and result['tunnel']['via_node'])
        self.assertTrue(result['qualification']['qualified'])
        self.assertEqual(20, result['categories']['probe'])
        self.assertEqual(4, result['categories']['tunnel'])
        self.assertFalse(result['release_gate'])
        self.assertIn('dns.json', result['evidence_sha256'])

    def test_every_helper_call_carries_the_resolver_flag_and_the_two_checks(self):
        result = self.scenario()
        options = [call[3] for call in result['calls']]
        self.assertEqual(['setup', 'probe', 'finish'], [call[1] for call in result['calls']])
        self.assertTrue(all(o['dns'] is True for o in options))
        self.assertEqual(options[0], options[1])
        self.assertEqual(options[0], options[2])
        checks = options[0]['dns_check']
        self.assertEqual({'plain', 'doh'}, set(checks))
        self.assertEqual(('dns-plain', wire.RESOLVER, 53), (checks['plain']['service'], checks['plain']['target'],
                                                           checks['plain']['port']))
        self.assertEqual((wire.DNS_CHECK_DOH, wire.TARGETS[4], 443), (checks['doh']['kind'], checks['doh']['target'],
                                                                      checks['doh']['port']))
        nonces = [p['nonce'] for p in result['probes']] + [e['nonce'] for e in result['https']]
        self.assertFalse({checks['plain']['nonce'], checks['doh']['nonce']} & set(nonces))
        self.assertNotEqual(checks['plain']['nonce'], checks['doh']['nonce'])
        self.assertTrue(result['pairs'][0].dns)

    def test_the_dns_log_is_registered_and_read_only_with_the_flag(self):
        result = self.scenario()
        lab_run = result['members']['lab'].run
        self.assertTrue((lab_run.directory / 'dns.json').is_file())
        plain = self.scenario(dns=False)
        self.assertNotIn('dns', plain)
        self.assertNotIn('dns.json', plain['evidence_sha256'])
        self.assertTrue(all(call[3] is None for call in plain['calls']))

    def test_a_doh_question_that_did_not_come_through_the_node_fails_the_run(self):
        for fault in ('doh-bypassed-node', 'target-direct'):
            with self.subTest(fault=fault):
                result = self.scenario(fault)
                self.assertEqual(2, result['exit_code'])
                self.assertFalse(result['dns']['doh_via_node'])
                self.assertTrue(result['dns']['plain'])

    def test_a_missing_doh_record_or_target_request_fails_the_run(self):
        for fault in ('no-doh-row', 'target-not-asked'):
            with self.subTest(fault=fault):
                result = self.scenario(fault)
                self.assertEqual(2, result['exit_code'])
                self.assertFalse(result['dns']['doh_via_node'])

    def test_a_missing_plain_record_fails_the_run(self):
        result = self.scenario('no-plain-row')
        self.assertEqual((2, False, True), (result['exit_code'], result['dns']['plain'],
                                           result['dns']['doh_via_node']))

    def test_a_failed_doh_client_is_an_error_and_the_run_is_not_successful(self):
        result = self.scenario('doh-client-failed')
        self.assertEqual(2, result['exit_code'])
        self.assertEqual((False, False), (result['dns']['plain'], result['dns']['doh_via_node']))

    def test_a_failed_exchange_is_in_the_dns_block_with_the_exit_and_the_saved_log_of_the_client(self):
        for fault, failed, code, text in (
                ('doh-exchange-failed', dict(exchange='dns-doh-singbox', reason='unexpected-https-answer',
                                             elapsed_ms=312), 1, 'FATAL start service: boom'),
                ('plain-exchange-failed', dict(exchange='dns-plain', reason='timeout', elapsed_ms=5003), None, '')):
            with self.subTest(fault=fault):
                result = self.scenario(fault)
                block = result['dns']
                self.assertEqual(2, result['exit_code'])
                self.assertEqual((failed, code, text), (block['failed'], block['client_exit'], block['client_log']))
                self.assertFalse(block['doh_via_node'])
                self.assertEqual(text.encode(), Path(block['client_log_path']).read_bytes())
                self.assertEqual([], result['errors'])

    def test_a_failed_exchange_that_the_helper_reports_unreadably_is_not_believed_and_still_fails_the_run(self):
        for fault in ('failed-unreadable', 'failed-foreign'):
            with self.subTest(fault=fault):
                result = self.scenario(fault)
                self.assertEqual((2, None, False), (result['exit_code'], result['dns']['failed'],
                                                    result['dns']['doh_via_node']))

    def test_a_helper_that_failed_names_why_in_the_error_and_the_dns_block_stays_as_it_was(self):
        result = self.scenario('helper-failed')
        self.assertEqual(2, result['exit_code'])
        self.assertEqual([dict(stage='probe', kind='HelperFailed', reason='lab-helper-failed',
                               helper_reason='typeerror:' + 'x' * 20)], result['errors'])
        block = result['dns']
        self.assertEqual((False, False, None, None, None, None), (
            block['plain'], block['doh_via_node'], block['client_exit'], block['client_log'],
            block['client_log_path'], block['failed']))

    def test_the_client_log_is_saved_only_in_a_dns_run_and_never_with_the_owner_token(self):
        self.assertFalse((self.scenario(dns=False)['members']['test'].run.directory / 'client.log').exists())
        result = self.scenario()
        self.assertTrue((result['members']['test'].run.directory / 'client.log').is_file())
        run = result['members']['test'].run
        errors = []
        saved = lab.save_client_log(run, dict(client_log='leaked ' + run._identity[2]), dict(errors=errors))
        self.assertEqual((None, ['client-log']), (saved, [row['stage'] for row in errors]))
        self.assertEqual('WARN none', (run.directory / 'client.log').read_text())
        for reports in ({}, None, dict(client_log=b'bytes'), dict(client_log=None)):
            self.assertIsNone(lab.save_client_log(run, reports, dict(errors=[])))

    def test_a_frame_to_doh_or_udp_53_beside_dns_plain_is_a_leak(self):
        for fault in ('direct-doh', 'stray-udp53'):
            with self.subTest(fault=fault):
                result = self.scenario(fault)
                self.assertEqual(('DETECTED', 2), (result['leak'], result['exit_code']))
                self.assertEqual(1, result['categories']['unexpected'])

    def test_the_plain_question_is_a_probe_only_with_the_resolvers_own_question(self):
        result = self.scenario('no-plain-reply')
        # The question alone is still a probe; what is missing is the answer, which the log still shows.
        self.assertEqual(0, result['categories']['unexpected'])

    def test_dns_needs_the_tunnel_and_is_refused_before_anything_starts(self):
        sentinel = SimpleNamespace(host=lambda: self.fail('adapters used before the configuration was refused'))
        fixture = test_qemu.PreparationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        config = dict(schema=lab.SCHEMA_V2, state_directory=str(fixture.root / 'lab-state'), stand_id='lab',
                      qemu=asdict(replace(fixture.config, machine='pc-i440fx-10.0', qga=True)),
                      test_image=fixture.image.record(), lab_image=fixture.image.record(), tunnel=tunnel_block())
        with patch.object(lab, '_state_path', side_effect=lambda value: value):
            with self.assertRaisesRegex(ValueError, 'lab-dns-requires-tunnel'):
                lab.lab_smoke(config, dns=True, adapters=sentinel)
            with self.assertRaisesRegex(ValueError, 'lab-dns-requires-tunnel'):
                lab.plan_lab(config, dns=True)
            plan = lab.plan_lab(config, tunnel=True, dns=True)
        self.assertEqual(['dns-plain', 'dns-doh-singbox'], plan['dns']['exchanges'])
        self.assertNotIn('dns', lab.plan_lab(config, tunnel=True))

    def test_the_command_line_takes_dns_and_refuses_it_without_the_tunnel(self):
        with patch.object(lab, 'load_lab', return_value={}), \
                patch.object(lab, 'plan_lab', side_effect=ValueError('lab-dns-requires-tunnel')) as plan, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            code = cli.main(['lab-smoke', '--config', 'x', '--dry-run', '--dns'])
        self.assertEqual(2, code)
        self.assertEqual({'dns': True}, plan.call_args.kwargs)
        self.assertIn('"exit_code": 2', output.getvalue())


class ClientTests(unittest.TestCase):
    """The helper's side with every system call replaced: the client's configuration and the reply check."""

    def setUp(self):
        from tools.vm.matrix.tests.test_lab_fixtures import load_entry
        self.entry = load_entry()
        self.tunnel = dict(port=8388, method='aes-128-gcm', password='lab-only-password', sing_box_sha256='a' * 64,
                           ca_sha256='b' * 64, https=[])

    def test_the_configuration_is_the_one_of_rosetun_plus_the_resolving_rule(self):
        config = self.entry.dns_client_config(self.tunnel)
        self.assertEqual({'servers': [{'type': 'https', 'tag': 'dns-proxy', 'server': '203.0.113.3',
                                       'tls': {'server_name': 'doh.lab.test'}, 'detour': 'node'}]}, config['dns'])
        self.assertEqual({'rules': [{'action': 'resolve', 'server': 'dns-proxy'}], 'final': 'node'}, config['route'])
        self.assertEqual([{'type': 'socks', 'tag': 'socks-in', 'listen': '127.0.0.1', 'listen_port': 10808}],
                         config['inbounds'])
        self.assertEqual(['shadowsocks'], [o['type'] for o in config['outbounds']])
        self.assertEqual('node', config['outbounds'][0]['tag'])
        # The plain client of stage 7b1 is untouched.
        self.assertNotIn('dns', self.entry.client_config(self.tunnel))

    def test_the_socks_request_names_a_domain_and_nothing_resolves_it_in_the_helper(self):
        sent = []

        class Sock:
            def sendall(self, data): sent.append(data)
        replies = iter([b'\x05\x00', b'\x05\x00\x00\x01', b'\x00' * 6])
        with patch.object(self.entry, 'receive', lambda sock, size: next(replies)):
            self.entry.socks_connect_domain(Sock(), 'a.b.lab.test', 443)
        self.assertEqual([b'\x05\x01\x00', b'\x05\x01\x00\x03\x0ca.b.lab.test\x01\xbb'], sent)
        replies = iter([b'\x05\x00', b'\x05\x05\x00\x01'])
        with patch.object(self.entry, 'receive', lambda sock, size: next(replies)), \
                self.assertRaisesRegex(ValueError, 'socks-connect-refused'):
            self.entry.socks_connect_domain(Sock(), 'a.b.lab.test', 443)

    def test_the_reply_check_accepts_the_resolvers_answer_and_nothing_else(self):
        check = wire.dns_checks('a' * 32, lambda: 'b' * 24)['plain']
        reply = wire.dns_reply(wire.query(check))[0]
        self.assertTrue(wire.plain_reply_ok(check, reply))
        for bad in (reply[:-1], reply[:-4] + bytes([203, 0, 113, 9]), b'\x00\x00' + reply[2:],
                    reply[:2] + b'\x00\x00' + reply[4:], reply[:2] + b'\x81\x83' + reply[4:], b''):
            with self.subTest(bad=bad.hex()):
                self.assertFalse(wire.plain_reply_ok(check, bad))

    def test_the_request_block_is_checked_by_the_helper(self):
        from tools.vm.matrix.tests.test_lab_fixtures import Base
        case = Base()
        case.setUp()
        checks = wire.dns_checks(case.request['lab_id'], iter(f'{i:024x}' for i in range(100, 110)).__next__)
        plain = {k: v for k, v in case.request.items()}
        good = dict(plain, dns=True, dns_check=checks)
        self.assertEqual('enp7s0', case.identity(good))
        bad_blocks = (dict(checks, plain=dict(checks['plain'], target='203.0.113.2')),
                      dict(checks, plain=dict(checks['plain'], port=5353)),
                      dict(checks, doh=dict(checks['doh'], kind='https-tunnel')),
                      dict(checks, doh=dict(checks['doh'], path='/x')),
                      dict(checks, doh=dict(checks['doh'], source='192.0.2.9')),
                      dict(checks, extra={}), dict(plain=checks['plain']), [], None)
        for block in bad_blocks:
            with self.subTest(block=str(block)[:60]), self.assertRaises(ValueError):
                case.identity(dict(good, dns_check=block))
        with self.assertRaises(ValueError):
            case.identity(dict(plain, dns_check=checks))
        without_tunnel = {k: v for k, v in good.items() if k != 'tunnel'}
        with self.assertRaises(ValueError):
            case.identity(without_tunnel)
        clash = dict(checks, doh=dict(checks['doh'], nonce=case.request['tunnel']['https'][0]['nonce'],
                                      path='/' + case.request['lab_id'] + '/' + case.request['tunnel']['https'][0]['nonce']))
        with self.assertRaises(ValueError):
            case.identity(dict(good, dns_check=clash))


if __name__ == '__main__':
    unittest.main()
