"""lab.v2 and the tunnel qualification on fake adapters, like the other lab_smoke tests."""
import base64
from dataclasses import asdict, replace
import contextlib
import io
import json
from pathlib import Path
import socket
from types import SimpleNamespace
import tomllib
import unittest
from unittest.mock import patch

from tools.vm.matrix import cli, lab, l3_requests, lab_protocol as wire
from tools.vm.matrix.tests import test_qemu
from tools.vm.matrix.tests.test_lab import Endpoint, canary_frames, healthy, ip_frame, icmp, marker_exchange, exchange
from tools.vm.matrix.tests.test_lab import capture
from tools.vm.matrix.tests.test_lab_tunnel_protocol import direct, from_node, to_node

SING_BOX, CA = 'a' * 64, 'b' * 64
PACKAGE = Path(lab.__file__).resolve().parent


def tunnel_block(**changes):
    return dict(sing_box_sha256=SING_BOX, ca_sha256=CA, node_port=wire.NODE_PORT) | changes


class ConfigTests(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(lab, '_state_path', side_effect=lambda value: value)
        patcher.start()
        self.addCleanup(patcher.stop)
        fixture = test_qemu.PreparationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.v1 = dict(schema=lab.SCHEMA_V1, state_directory=str(fixture.root / 'state'), stand_id='lab',
                       qemu=asdict(replace(fixture.config, machine='pc-i440fx-10.0', qga=True)),
                       test_image=fixture.image.record(), lab_image=fixture.image.record())
        self.v2 = dict(self.v1, schema=lab.SCHEMA_V2, tunnel=tunnel_block())

    def test_version_1_reads_as_before_and_cannot_carry_a_tunnel_block(self):
        self.assertIs(self.v1, lab.validate(self.v1))
        with self.assertRaises(ValueError):
            lab.validate(dict(self.v1, tunnel=tunnel_block()))
        self.assertTrue(lab.plan_lab(self.v1)['dry_run'])

    def test_version_2_needs_the_tunnel_block_and_reads_it_strictly(self):
        self.assertIs(self.v2, lab.validate(self.v2))
        with self.assertRaises(ValueError):
            lab.validate({k: v for k, v in self.v2.items() if k != 'tunnel'})
        bad = ({'sing_box_sha256': 'A' * 64}, {'sing_box_sha256': 'a' * 63}, {'sing_box_sha256': 5},
               {'ca_sha256': None}, {'ca_sha256': 'b' * 65}, {'node_port': 0}, {'node_port': 65536},
               {'node_port': True}, {'node_port': '8388'}, {'node_port': 443}, {'node_port': 8080},
               {'node_port': 9100}, {'node_port': 9999}, {'node_port': wire.SOCKS_PORT}, {'extra': 1})
        for change in bad:
            with self.subTest(change=change), self.assertRaises(ValueError):
                lab.validate(dict(self.v2, tunnel=tunnel_block(**change)))
        with self.assertRaises(ValueError):
            lab.validate(dict(self.v2, tunnel={k: v for k, v in tunnel_block().items() if k != 'node_port'}))
        with self.assertRaises(ValueError):
            lab.validate(dict(self.v2, schema='rosetun.matrix.lab.v3'))

    def test_the_tunnel_flag_needs_version_2(self):
        with self.assertRaisesRegex(ValueError, 'lab-tunnel-requires-v2'):
            lab.plan_lab(self.v1, tunnel=True)
        self.assertTrue(lab.plan_lab(self.v2, tunnel=True)['dry_run'])
        sentinel = SimpleNamespace(host=lambda: self.fail('adapters used before the configuration was refused'))
        with self.assertRaisesRegex(ValueError, 'lab-tunnel-requires-v2'):
            lab.lab_smoke(self.v1, tunnel=True, adapters=sentinel)

    def test_the_example_files_are_the_two_versions(self):
        for name, schema in (('lab.example.toml', lab.SCHEMA_V1), ('lab-tunnel.example.toml', lab.SCHEMA_V2)):
            with self.subTest(name=name), (PACKAGE / name).open('rb') as stream:
                config = tomllib.load(stream)
                self.assertEqual(schema, config['schema'])
                lab.validate(config)
        with (PACKAGE / 'lab-tunnel.example.toml').open('rb') as stream:
            self.assertEqual(wire.NODE_PORT, tomllib.load(stream)['tunnel']['node_port'])

    def test_the_request_block_takes_method_and_password_from_the_one_public_template(self):
        shadowsocks = l3_requests.template()['node']['outbound']['shadowsocks']
        exchanges = wire.https_exchanges('a' * 32, iter(f'{i:024x}' for i in range(2)).__next__)
        block = lab.tunnel_request(self.v2, exchanges)
        self.assertEqual({'port', 'method', 'password', 'sing_box_sha256', 'ca_sha256', 'https'}, set(block))
        self.assertEqual((shadowsocks['method'], shadowsocks['password'], wire.NODE_PORT, SING_BOX, CA),
                         (block['method'], block['password'], block['port'], block['sing_box_sha256'],
                          block['ca_sha256']))
        self.assertEqual(exchanges, block['https'])


class OrchestrationTests(unittest.TestCase):
    def scenario(self, fault=None, canary=False):
        fixture = test_qemu.PreparationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        config = dict(schema=lab.SCHEMA_V2, state_directory=str(fixture.root / 'lab-state'),
                      stand_id='lab', qemu=asdict(replace(fixture.config, machine='pc-i440fx-10.0', qga=True)),
                      test_image=fixture.image.record(), lab_image=fixture.image.record(),
                      tunnel=tunnel_block())
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

            def call(self, operation, expected, window=(), canary=False, tunnel=None):
                captured['probes'], captured['window'] = expected, list(window)
                captured.setdefault('calls', []).append((self.role, operation, canary, tunnel))
                if tunnel is not None:
                    captured['exchanges'] = tunnel['https']
                if operation == 'setup':
                    return dict(capture_ready=True)
                if operation == 'probe':
                    direct_exchange, via_node = captured['exchanges']
                    port = 44001 if fault == 'port-mismatch' else 44000
                    reports = dict(
                        direct=dict(direct_exchange, response=wire.https_answer(direct_exchange).hex(),
                                    client_port=port),
                        tunnel=dict(via_node, response=wire.https_answer(via_node).hex()), client_exit=0)
                    if fault == 'no-answer':
                        raise ValueError('lab-helper-failed-missing-ca-certificate')
                    return dict(replies=[{**p, 'response': wire.answer(p).hex()} for p in expected],
                                marker_replies=[{**m, 'response': wire.marker_answer(m).hex()} for m in window],
                                marker_sent=dict(open=1.0, close=2.0), **({'https': reports} if tunnel else {}))
                return dict(finished=True)

            def read(self, name, limit):
                expected, window = captured['probes'], captured['window']
                direct_exchange, via_node = captured['exchanges']
                if name == 'capture.pcap':
                    extra = direct(sport=44000)
                    if fault != 'no-node-frames':
                        extra += [to_node(), from_node()]
                    if fault == 'leak':
                        extra += [ip_frame(wire.CLIENTS[4], wire.TARGETS[4], 1, icmp(8))]
                    if canary:
                        extra += canary_frames()
                    return capture(
                        [f for m in window[:1] for f in marker_exchange(m)]
                        + [f for p in expected for f in exchange(p)] + extra
                        + [f for m in window[1:] for f in marker_exchange(m)])
                if name == 'targets.json':
                    return json.dumps([{**p, 'response': wire.answer(p).hex()} for p in expected]).encode()
                if name == 'https.json':
                    rows = [dict(source=wire.CLIENTS[4], port=44000, path=direct_exchange['path'], at=5.0),
                            dict(source=wire.EGRESS, port=51000, path=via_node['path'], at=6.0)]
                    if fault == 'bypass':
                        rows[1]['source'] = wire.CLIENTS[4]
                    if fault == 'no-direct-row':
                        rows = rows[1:]
                    if fault == 'direct-twice':
                        rows.insert(0, rows[0])
                    return json.dumps(rows).encode()
                if name == 'node.log':
                    return b'inbound/shadowsocks[node-in]: connection from 192.0.2.2:43000\n'
                node = dict(alive_at_finish=fault != 'node-dead', exit_code=-15 if fault != 'node-dead' else 1)
                return json.dumps(healthy(window, node=node)).encode()

        def pair(*args, **kwargs):
            result = lab.LabPair(*args, pair_factory=lambda *a: (Endpoint(), Endpoint()), **kwargs)
            pairs.append(result)
            return result

        adapters = SimpleNamespace(host=lambda: None, prepare=lambda *args: None, start=start, pair=pair,
                                   guest=Guest,
                                   execute=lambda *args, **kwargs: SimpleNamespace(
                                       returncode=0, stdout=b'QEMU version 10.0.13'))
        with patch.object(socket, 'AF_UNIX', 1, create=True), \
                patch.object(lab, '_state_path', side_effect=lambda value: value), \
                patch.object(lab, 'completion_verified', side_effect=lambda directory, manifest:
                             any(v.run.directory == directory and v.closed for v in members.values())):
            result = lab.lab_smoke(config, canary=canary, tunnel=True, adapters=adapters,
                                   clock=lambda: 0, sleep=lambda _: None)
        result['calls'], result['pairs'], result['members'] = captured.get('calls', []), pairs, members
        return result

    def test_a_complete_tunnel_run_succeeds_and_reports_the_tunnel_block(self):
        result = self.scenario()
        self.assertEqual(0, result['exit_code'])
        self.assertEqual(('NONE', 'clean'), (result['leak'], result['leak_reason']))
        self.assertEqual(dict(direct=True, via_node=True, tunnel_frames=2,
                              node=dict(alive_at_finish=True, exit_code=-15), client_exit=0), result['tunnel'])
        self.assertEqual(2, result['categories']['tunnel'])
        self.assertEqual(18, result['categories']['probe'])
        self.assertTrue(result['qualification']['qualified'])
        self.assertEqual('UNVERIFIED', result['security_invariants'])
        self.assertFalse(result['release_gate'])
        self.assertEqual(2, len(result['https']))

    def test_every_call_to_both_helpers_carries_the_same_tunnel_block(self):
        result = self.scenario()
        blocks = [call[3] for call in result['calls']]
        self.assertEqual(['setup', 'probe', 'finish'], [call[1] for call in result['calls']])
        self.assertTrue(all(block is not None for block in blocks))
        self.assertEqual(blocks[0], blocks[1])
        self.assertEqual(blocks[0], blocks[2])
        self.assertEqual(wire.NODE_PORT, blocks[0]['port'])

    def test_the_two_extra_files_are_registered_with_the_lab_run_and_read_back(self):
        result = self.scenario()
        lab_run = result['members']['lab'].run
        paths = [r['path'] for r in json.loads((lab_run.directory / 'manifest.json').read_bytes())['resources']]
        for name in ('https.json', 'node.log', 'capture.pcap', 'health.json', 'targets.json'):
            self.assertIn(name, paths)
            self.assertTrue((lab_run.directory / name).is_file())
        self.assertEqual({'capture.pcap', 'targets.json', 'health.json', 'https.json', 'node.log'},
                         set(result['evidence_sha256']))

    def test_the_other_stages_keep_their_summary_and_their_registered_files(self):
        self.assertEqual({}, lab.LabPair.resources(SimpleNamespace(tunnel=False, role=lambda run: 'test'), None))
        plain = SimpleNamespace(tunnel=False, role=lambda run: 'lab')
        self.assertEqual(lab.ARTIFACTS, lab.LabPair.resources(plain, None))
        extended = SimpleNamespace(tunnel=True, role=lambda run: 'lab')
        self.assertEqual({**lab.ARTIFACTS, **lab.TUNNEL_ARTIFACTS}, lab.LabPair.resources(extended, None))
        self.assertEqual({}, lab.LabPair.resources(SimpleNamespace(tunnel=True, role=lambda run: 'test'), None))

    def test_a_request_through_the_node_that_reached_the_target_as_the_test_machine_fails(self):
        result = self.scenario('bypass')
        self.assertEqual((2, False, True), (result['exit_code'], result['tunnel']['via_node'],
                                             result['tunnel']['direct']))

    def test_a_dead_node_at_finish_fails(self):
        result = self.scenario('node-dead')
        self.assertEqual(2, result['exit_code'])
        self.assertFalse(result['tunnel']['node']['alive_at_finish'])
        self.assertEqual(1, result['tunnel']['node']['exit_code'])
        self.assertEqual(('NONE', True, True), (result['leak'], result['tunnel']['direct'], result['tunnel']['via_node']))

    def test_a_missing_or_doubled_row_in_the_target_log_fails(self):
        for fault in ('no-direct-row', 'direct-twice'):
            with self.subTest(fault=fault):
                result = self.scenario(fault)
                self.assertEqual((2, False), (result['exit_code'], result['tunnel']['direct']))

    def test_a_client_port_the_target_never_saw_fails_and_its_frames_are_a_leak(self):
        result = self.scenario('port-mismatch')
        self.assertEqual((2, 'DETECTED', False), (result['exit_code'], result['leak'], result['tunnel']['direct']))
        self.assertEqual(2, result['categories']['unexpected'])

    def test_a_run_without_a_single_frame_to_the_node_fails(self):
        result = self.scenario('no-node-frames')
        self.assertEqual((2, 0), (result['exit_code'], result['tunnel']['tunnel_frames']))

    def test_a_leak_fails_a_tunnel_run(self):
        result = self.scenario('leak')
        self.assertEqual((2, 'DETECTED', 1), (result['exit_code'], result['leak'],
                                               result['categories']['unexpected']))

    def test_a_refusal_of_the_test_helper_is_an_error_and_the_run_fails(self):
        result = self.scenario('no-answer')
        self.assertEqual(2, result['exit_code'])
        # The helper agreed on nothing, so the frames of the direct connection are a leak.
        self.assertEqual('DETECTED', result['leak'])
        self.assertFalse(result['tunnel']['direct'])
        self.assertTrue(result['errors'])

    def test_tunnel_and_canary_need_the_conditions_of_both(self):
        result = self.scenario(canary=True)
        self.assertEqual((0, 'DETECTED', ['tcp', 'udp'], 0), (
            result['exit_code'], result['leak'], result['canary_flows'], result['canary_other']))
        self.assertEqual(dict(direct=True, via_node=True), {k: result['tunnel'][k] for k in ('direct', 'via_node')})
        self.assertEqual(4, result['categories']['unexpected'])
        for fault in ('bypass', 'node-dead', 'no-node-frames', 'no-direct-row', 'port-mismatch', 'leak'):
            with self.subTest(fault=fault):
                self.assertEqual(2, self.scenario(fault, canary=True)['exit_code'])


class RefusalTests(unittest.TestCase):
    def encode(self, text):
        return base64.b64encode(text.encode()).decode()

    def test_the_reason_the_helper_printed_reaches_the_error(self):
        self.assertEqual('lab-helper-failed-missing-sing-box',
                         lab.refusal({'err-data': self.encode('lab-helper-failed:missing-sing-box\n')}))
        for status in ({}, {'err-data': self.encode('lab-helper-failed\n')},
                       {'err-data': self.encode('lab-helper-failed:/etc/passwd\n')},
                       {'err-data': self.encode('lab-helper-failed:' + 'a' * 65)},
                       {'err-data': '***'}, {'err-data': self.encode('Traceback')}):
            with self.subTest(status=status):
                self.assertEqual('lab-helper-failed', lab.refusal(status))


class CommandLineTests(unittest.TestCase):
    def run_cli(self, *flags, config=None, smoke=None):
        calls = []

        def default(config, **kwargs):
            calls.append(kwargs)
            return dict(exit_code=0)
        with patch.object(lab, 'load_lab', return_value=config or {}), \
                patch.object(lab, 'lab_smoke', smoke or default), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            code = cli.main(['lab-smoke', '--config', 'unused.toml', *flags])
        return code, calls, output.getvalue()

    def test_the_tunnel_flag_reaches_lab_smoke_alone_and_with_the_canary(self):
        self.assertEqual((0, [dict(canary=False, tunnel=True)]), self.run_cli('--tunnel')[:2])
        self.assertEqual((0, [dict(canary=True, tunnel=True)]), self.run_cli('--tunnel', '--canary')[:2])

    def test_without_the_flag_lab_smoke_gets_what_it_got_before(self):
        self.assertEqual((0, [dict(canary=False)]), self.run_cli()[:2])
        self.assertEqual((0, [dict(canary=True)]), self.run_cli('--canary')[:2])

    def test_a_version_1_configuration_with_the_flag_exits_2_before_any_work(self):
        fixture = test_qemu.PreparationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        v1 = dict(schema=lab.SCHEMA_V1, state_directory=str(fixture.root / 'state'), stand_id='lab',
                  qemu=asdict(replace(fixture.config, machine='pc-i440fx-10.0', qga=True)),
                  test_image=fixture.image.record(), lab_image=fixture.image.record())
        with patch.object(lab, '_state_path', side_effect=lambda value: value), \
                patch.object(lab, 'Adapters', side_effect=AssertionError('adapters created')):
            code, _, text = self.run_cli('--tunnel', config=v1, smoke=lab.lab_smoke)
        self.assertEqual(2, code)
        self.assertEqual(2, json.loads(text)['exit_code'])


if __name__ == '__main__':
    unittest.main()
