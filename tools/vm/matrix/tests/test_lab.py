"""Offline two-VM and evidence regressions. No host networking or real child."""
import base64
from dataclasses import asdict, replace
import json
import importlib.util
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.vm.matrix import lab, lifecycle, lab_protocol as wire
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


def pcap(expected):
    raw = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 2048, 1))
    for p in expected:
        for reply in (False, True):
            source, target = (p['target'], p['source']) if reply else (p['source'], p['target'])
            data = wire.answer(p) if reply else wire.query(p)
            sport, dport = (p['port'], 40000) if reply else (40000, p['port'])
            if p['protocol'] == 'tcp':
                transport = struct.pack('!HHIIHHHH', sport, dport, 0, 0, 0x5018, 1024, 0, 0) + data
                proto = 6
            else:
                transport = struct.pack('!HHHH', sport, dport, len(data) + 8, 0) + data
                proto = 17
            if p['family'] == 4:
                ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(transport), 0, 0, 64, proto, 0,
                                 socket.inet_pton(socket.AF_INET, source), socket.inet_pton(socket.AF_INET, target))
                ether = b'\x08\x00'
            else:
                ip = struct.pack('!IHBB16s16s', 6 << 28, len(transport), proto, 64,
                                 socket.inet_pton(socket.AF_INET6, source), socket.inet_pton(socket.AF_INET6, target))
                ether = b'\x86\xdd'
            frame = b'\x00' * 12 + ether + ip + transport
            raw.extend(struct.pack('<IIII', 0, 0, len(frame), len(frame)) + frame)
    return bytes(raw)


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
    def scenario(self, fault=None):
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
            def call(self, operation, expected):
                captured['probes'] = expected
                if operation == 'setup':
                    return dict(capture_ready=fault != 'observer-not-ready')
                if operation == 'probe':
                    if fault == 'target-unavailable':
                        raise ValueError('target-unavailable')
                    return dict(replies=[{**p, 'response': wire.answer(p).hex()} for p in expected])
                return dict(finished=True)
            def read(self, name, limit):
                expected = captured['probes']
                if name == 'capture.pcap':
                    return pcap(expected)[:24] if fault == 'missing-observation' else pcap(expected)
                if name == 'targets.json':
                    return json.dumps([{**p, 'response': wire.answer(p).hex()} for p in expected]).encode()
                return json.dumps(dict(error=False, dropped=0, finished=fault != 'incomplete-evidence')).encode()
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
            result = lab.lab_smoke(config, adapters=adapters, clock=lambda: 0, sleep=lambda _: None)
        return result

    def test_complete_smoke_requires_both_completions_and_keeps_release_closed(self):
        result = self.scenario()
        self.assertEqual(0, result['exit_code'])
        self.assertTrue(result['completed'])
        self.assertEqual(dict(test=True, lab=True), result['completion'])
        self.assertTrue(result['qualification']['qualified'])
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
        self.request = dict(role='lab', lab_id='a' * 32,
             vm_uuid='12345678-1234-4234-8234-123456789abc',
             boot_id='22345678-1234-4234-8234-123456789abc',
             probes=wire.probes('a' * 32, iter(f'{i:024x}' for i in range(8)).__next__), operation='setup')

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
