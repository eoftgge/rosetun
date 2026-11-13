"""The evidence disk: its header, the helper's writer, the controller's reader, the launch plan and the smoke."""
import contextlib
from dataclasses import asdict, replace
import hashlib
import io
import json
from pathlib import Path
import socket
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.vm.matrix import cli, lab, lab_protocol as wire
from tools.vm.matrix.tests import test_lab, test_qemu
from tools.vm.matrix.tests.test_lab import Endpoint, capture, exchange, healthy, marker_exchange
from tools.vm.matrix.tests.test_lab_fixtures import Base, load_entry
from tools.vm.matrix.tests.test_lab_tunnel import tunnel_block
from tools.vm.matrix.tests.test_lab_tunnel_protocol import direct, from_node, to_node

RUN = 'a' * 32
SMALL = 1024 * 1024


def make_image(path, pcap, *, run_id=RUN, complete=True, size=SMALL):
    """What the helper leaves on the disk, built by the helper's own writer."""
    path.write_bytes(bytes(size))
    entry = load_entry()
    with patch.object(entry.os, 'fsync'):
        writer = entry.EvidenceWriter(path, run_id)
        writer.write(pcap)
        writer.finish(complete=complete)
    return path


class HeaderTests(unittest.TestCase):
    DIGEST = hashlib.sha256(b'pcap').digest()

    def header(self, **changes):
        arguments = dict(run_id=RUN, length=4, digest=self.DIGEST, complete=True) | changes
        return wire.evidence_header(**arguments)

    def test_the_sizes_leave_room_for_the_header_and_the_limits_are_the_documented_ones(self):
        self.assertEqual((64 * 1024 * 1024, 60 * 1024 * 1024, 4096),
                         (wire.EVIDENCE_SIZE, wire.EVIDENCE_PCAP_LIMIT, wire.EVIDENCE_HEADER_SIZE))
        self.assertLessEqual(wire.EVIDENCE_HEADER_SIZE + wire.EVIDENCE_PCAP_LIMIT, wire.EVIDENCE_SIZE)
        self.assertEqual('rosetun-lab-evidence', wire.EVIDENCE_SERIAL)
        # A virtio-blk serial is at most twenty bytes.
        self.assertLessEqual(len(wire.EVIDENCE_SERIAL), 20)

    def test_a_header_names_the_run_the_length_and_the_hash_and_fills_its_block(self):
        block = self.header()
        self.assertEqual(wire.EVIDENCE_HEADER_SIZE, len(block))
        self.assertTrue(block.startswith(b'RTLABEV1'))
        self.assertEqual((4, self.DIGEST), wire.parse_evidence_header(block, RUN))

    def test_every_defect_of_a_header_has_its_own_reason(self):
        block = self.header()
        cases = {
            'evidence-truncated': block[:-1],
            'evidence-magic': b'XTLABEV1' + block[8:],
            'evidence-version': block[:8] + b'\x02\x00' + block[10:],
            'evidence-incomplete': self.header(complete=False),
            'evidence-run-id': self.header(run_id='b' * 32),
            'evidence-header-padding': block[:-1] + b'\x01',
            'evidence-length': self.header(length=wire.EVIDENCE_PCAP_LIMIT + 1),
        }
        for reason, bad in cases.items():
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                wire.parse_evidence_header(bad, RUN)
        self.assertEqual((wire.EVIDENCE_PCAP_LIMIT, self.DIGEST),
                         wire.parse_evidence_header(self.header(length=wire.EVIDENCE_PCAP_LIMIT), RUN))

    def test_a_block_of_zeros_is_a_disk_nobody_finished(self):
        with self.assertRaisesRegex(ValueError, 'evidence-magic'):
            wire.parse_evidence_header(bytes(wire.EVIDENCE_HEADER_SIZE), RUN)


class DeviceTests(Base):
    def test_the_disk_is_found_by_its_serial_and_by_nothing_else(self):
        self.assertEqual('/dev/disk/by-id/virtio-rosetun-lab-evidence', self.entry.EVIDENCE_DEVICE.as_posix())

    def test_a_missing_disk_is_a_refusal(self):
        with tempfile.TemporaryDirectory() as temp, self.assertRaisesRegex(self.entry.Refused, 'missing-evidence-disk'):
            self.entry.evidence_device(Path(temp) / 'absent')

    def test_a_file_that_is_not_a_block_device_is_a_refusal(self):
        with tempfile.TemporaryDirectory() as temp:
            plain = Path(temp) / 'plain'
            plain.write_bytes(b'')
            with self.assertRaisesRegex(self.entry.Refused, 'evidence-disk-not-a-block-device'):
                self.entry.evidence_device(plain)

    def test_a_block_device_is_accepted(self):
        with patch.object(self.entry.os, 'stat', return_value=SimpleNamespace(st_mode=stat.S_IFBLK | 0o600)):
            self.assertEqual(Path('x'), self.entry.evidence_device(Path('x')))

    def test_setup_refuses_before_any_network_change_when_the_disk_is_missing(self):
        plain = {k: v for k, v in self.request.items() if k != 'tunnel'}
        with patch.object(self.entry, 'command', side_effect=AssertionError('network change')), \
                patch.object(self.entry.os, 'stat', side_effect=FileNotFoundError):
            with self.assertRaisesRegex(self.entry.Refused, 'missing-evidence-disk'):
                self.entry.setup(dict(plain, evidence_disk=True), 'enp7s0', Path('unused'))


class WriterTests(Base):
    PCAP = wire.PCAP_HEADER + b'frames' * 100

    def test_the_helper_leaves_a_disk_the_controller_accepts(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(lab, 'EVIDENCE_SIZE', SMALL):
            image = make_image(Path(temp) / 'e.img', self.PCAP)
            self.assertEqual(self.PCAP, lab.read_evidence(image, RUN))

    def test_the_header_is_written_after_the_pcap_has_been_flushed_and_synced(self):
        events = []

        class Stream:
            def write(self, data):
                events.append(('write', len(data)))

            def flush(self):
                events.append('flush')

            def seek(self, offset):
                events.append(('seek', offset))

            def fileno(self):
                return 3

            def close(self):
                events.append('close')
        with patch('builtins.open', return_value=Stream()), \
                patch.object(self.entry.os, 'fsync', lambda fd: events.append('fsync')):
            writer = self.entry.EvidenceWriter(Path('device'), RUN)
            writer.write(b'abc')
            writer.finish(complete=True)
        self.assertEqual([('write', wire.EVIDENCE_HEADER_SIZE), ('write', 3), 'flush', 'fsync', ('seek', 0),
                          ('write', wire.EVIDENCE_HEADER_SIZE), 'flush', 'fsync', 'close'], events)

    def test_a_run_that_failed_leaves_a_header_that_says_so(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(lab, 'EVIDENCE_SIZE', SMALL):
            image = make_image(Path(temp) / 'e.img', self.PCAP, complete=False)
            with self.assertRaisesRegex(ValueError, 'evidence-incomplete'):
                lab.read_evidence(image, RUN)


class ReaderTests(unittest.TestCase):
    PCAP = wire.PCAP_HEADER + b'frames' * 100

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        size = patch.object(lab, 'EVIDENCE_SIZE', SMALL)
        size.start()
        self.addCleanup(size.stop)
        self.image = Path(self.temp.name) / 'e.img'

    def defect(self, reason, **changes):
        make_image(self.image, self.PCAP, **changes)
        return self.assertRaisesRegex(ValueError, reason)

    def test_a_complete_disk_gives_the_pcap(self):
        make_image(self.image, self.PCAP)
        self.assertEqual(self.PCAP, lab.read_evidence(self.image, RUN))

    def test_a_pcap_cut_short_on_the_disk_is_refused(self):
        make_image(self.image, self.PCAP)
        self.image.write_bytes(self.image.read_bytes()[:wire.EVIDENCE_HEADER_SIZE + len(self.PCAP) - 10])
        with self.assertRaisesRegex(ValueError, 'evidence-truncated'):
            lab.read_evidence(self.image, RUN)

    def test_an_image_of_another_size_is_refused(self):
        make_image(self.image, self.PCAP)
        self.image.write_bytes(self.image.read_bytes() + bytes(4096))
        with self.assertRaisesRegex(ValueError, 'evidence-size'):
            lab.read_evidence(self.image, RUN)

    def test_a_changed_byte_in_the_pcap_is_refused(self):
        make_image(self.image, self.PCAP)
        raw = bytearray(self.image.read_bytes())
        raw[wire.EVIDENCE_HEADER_SIZE + 30] ^= 1
        self.image.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, 'evidence-sha256'):
            lab.read_evidence(self.image, RUN)

    def test_a_disk_without_the_completion_flag_is_refused(self):
        with self.defect('evidence-incomplete', complete=False):
            lab.read_evidence(self.image, RUN)

    def test_a_disk_of_another_run_is_refused(self):
        with self.defect('evidence-run-id', run_id='b' * 32):
            lab.read_evidence(self.image, RUN)

    def test_a_disk_that_was_never_finished_is_refused(self):
        self.image.write_bytes(bytes(SMALL))
        with self.assertRaisesRegex(ValueError, 'evidence-magic'):
            lab.read_evidence(self.image, RUN)

    def test_any_byte_after_the_pcap_is_refused_wherever_it_sits(self):
        for position in (0, 1, 4096, SMALL - wire.EVIDENCE_HEADER_SIZE - len(self.PCAP) - 1):
            with self.subTest(position=position):
                make_image(self.image, self.PCAP)
                raw = bytearray(self.image.read_bytes())
                raw[wire.EVIDENCE_HEADER_SIZE + len(self.PCAP) + position] = 1
                self.image.write_bytes(raw)
                with self.assertRaisesRegex(ValueError, 'evidence-trailing-bytes'):
                    lab.read_evidence(self.image, RUN)

    def test_a_missing_image_is_an_os_error_the_smoke_turns_into_a_reason(self):
        with self.assertRaises(OSError):
            lab.read_evidence(Path(self.temp.name) / 'absent', RUN)


class RequestTests(Base):
    def test_only_a_true_evidence_flag_is_accepted(self):
        plain = {k: v for k, v in self.request.items() if k != 'tunnel'}
        self.assertEqual('enp7s0', self.identity(dict(plain, evidence_disk=True)))
        for value in (False, 1, 'yes', None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.identity(dict(plain, evidence_disk=value))

    def test_the_duration_is_a_whole_number_of_seconds_from_a_minute_to_the_job_and_five_minutes(self):
        plain = {k: v for k, v in self.request.items() if k != 'tunnel'}
        self.assertEqual((60, 2100), (wire.DURATION, wire.DURATION_MAX))
        for good in (60, 61, 1800, 2100):
            with self.subTest(good=good):
                self.assertEqual('enp7s0', self.identity(dict(plain, duration_seconds=good)))
        for bad in (59, 0, -60, 2101, True, 60.0, '60', None):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.identity(dict(plain, duration_seconds=bad))

    def test_a_run_cannot_change_either_after_the_claim(self):
        for change in (dict(evidence_disk=True), dict(duration_seconds=120)):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                saved = dict(self.request, operation='serve', interface='enp7s0', lab_id=directory.name)
                (directory / 'identity.json').write_text(json.dumps(saved))
                with patch.object(self.entry, 'identity', return_value='enp7s0'), \
                        patch.object(self.entry, 'ROOT', directory.parent), \
                        patch.object(self.entry, 'serve') as serve:
                    with self.assertRaises(ValueError):
                        self.entry.main(dict(saved, **change))
                    serve.assert_not_called()


class LaunchTests(unittest.TestCase):
    """The launch arguments with and without the disk, from the capability itself."""

    def pair(self, directory, **changes):
        run = SimpleNamespace(directory=Path(directory))
        pair = SimpleNamespace(lease=SimpleNamespace(_check_live=lambda: None), closed=False, used=set(),
                               role=lambda run: self.role, sockets=dict(test=Endpoint(), lab=Endpoint()),
                               evidence_disk=False)
        pair.__dict__.update(changes)
        return pair, run

    def network(self, role, directory, **changes):
        self.role = role
        pair, run = self.pair(directory, **changes)
        return lab.LabPair.network(pair, run), pair

    def test_without_the_disk_both_machines_get_exactly_the_arguments_of_stage_6a(self):
        with tempfile.TemporaryDirectory() as temp:
            for role in wire.MACS:
                with self.subTest(role=role):
                    (argv, fd), pair = self.network(role, temp)
                    self.assertEqual(['-netdev', f'stream,id=labwire,addr.type=fd,addr.str={fd},server=off',
                                      '-device', f'virtio-net-pci,netdev=labwire,id={role}-wire,mac={wire.MACS[role]}'],
                                     argv)

    def test_with_the_disk_only_the_lab_machine_gets_a_second_writable_raw_disk_with_the_serial(self):
        with tempfile.TemporaryDirectory() as temp:
            (plain, fd), pair = self.network('lab', temp)
            (extended, _), _ = self.network('lab', temp, evidence_disk=True, sockets=pair.sockets, used=set())
            (test_side, _), _ = self.network('test', temp, evidence_disk=True)
            self.assertEqual(plain, extended[:4])
            self.assertEqual(['-blockdev', '-device'], extended[4::2])
            blockdev = json.loads(extended[5])
            self.assertEqual({'driver': 'raw', 'node-name': 'evidence', 'read-only': False,
                              'file': {'driver': 'file', 'filename': str(Path(temp) / 'evidence.img')}}, blockdev)
            self.assertEqual('virtio-blk-pci,drive=evidence,id=evidence,serial=rosetun-lab-evidence', extended[7])
            self.assertEqual(8, len(extended))
            self.assertEqual(4, len(test_side))
            self.assertNotIn('evidence', ' '.join(test_side))

    def test_the_registered_files_gain_the_image_for_the_lab_machine_only_and_only_on_request(self):
        for tunnel in (False, True):
            base = {**lab.ARTIFACTS, **(lab.TUNNEL_ARTIFACTS if tunnel else {})}
            lab_side = SimpleNamespace(tunnel=tunnel, role=lambda run: 'lab', evidence_disk=True)
            self.assertEqual({**base, 'lab-evidence-disk': 'evidence.img'}, lab.LabPair.resources(lab_side, None))
            self.assertEqual(base, lab.LabPair.resources(SimpleNamespace(
                tunnel=tunnel, role=lambda run: 'lab', evidence_disk=False), None))
            self.assertEqual({}, lab.LabPair.resources(SimpleNamespace(
                tunnel=tunnel, role=lambda run: 'test', evidence_disk=True), None))


class DiskPairTests(test_lab.PairTests):
    """Every launch test of stage 6a again, with the disk on: nothing else may change."""

    def setUp(self):
        class DiskPair(lab.LabPair):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, evidence_disk=True, **kwargs)
        patcher = patch.object(lab, 'LabPair', DiskPair)
        patcher.start()
        self.addCleanup(patcher.stop)
        super().setUp()

    def test_the_image_is_a_zeroed_registered_file_of_the_fixed_size_in_the_lab_run_only(self):
        image = self.runs['lab'].directory / 'evidence.img'
        self.assertEqual(wire.EVIDENCE_SIZE, image.stat().st_size)
        self.assertFalse((self.runs['test'].directory / 'evidence.img').exists())
        paths = lambda run: [r.get('path') for r in run._read()['resources']]
        self.assertIn('evidence.img', paths(self.runs['lab']))
        self.assertNotIn('evidence.img', paths(self.runs['test']))

    def test_the_started_lab_machine_gets_the_disk_the_test_machine_does_not_and_no_descriptor_more(self):
        first, a = self.launch('test')
        second, b = self.launch('lab')
        test_argv, lab_argv = a.args[0], b.args[0]
        self.assertNotIn('evidence', ' '.join(test_argv))
        disk = json.loads(lab_argv[len(lab_argv) - 1 - lab_argv[::-1].index('-blockdev') + 1])
        self.assertEqual(('evidence', False), (disk['node-name'], disk['read-only']))
        self.assertIn('serial=rosetun-lab-evidence', ' '.join(lab_argv))
        self.assertEqual(3, len(b.kwargs['pass_fds']))


class Run:
    """The fake machines of a smoke with the evidence disk: the lab guest writes the disk on `finish`."""

    def __init__(self, test, fault=None, tunnel=False, canary=False):
        self.test, self.fault, self.tunnel, self.canary = test, fault, tunnel, canary
        self.events, self.members, self.calls, self.reads = [], {}, [], []
        self.exchanges = None

    def scenario(self):
        run = self
        fixture = test_qemu.PreparationTests()
        fixture.setUp()
        self.test.addCleanup(fixture.doCleanups)
        config = dict(schema=lab.SCHEMA_V2 if self.tunnel else lab.SCHEMA_V1,
                      state_directory=str(fixture.root / 'lab-state'), stand_id='lab',
                      qemu=asdict(replace(fixture.config, machine='pc-i440fx-10.0', qga=True)),
                      test_image=fixture.image.record(), lab_image=fixture.image.record(),
                      **({'tunnel': tunnel_block()} if self.tunnel else {}))
        captured = {}

        def start(machine, lab):
            role = lab.role(machine)

            class Vm:
                vm_uuid = '12345678-1234-4234-8234-123456789abc'
                last_boot_id = '22345678-1234-4234-8234-123456789abc'

                def resume(self): pass

                def wait_initial_guest(self, **kwargs): return dict(result='observed')

                def close(self, **kwargs):
                    run.events.append(('close', role))
                    machine._lease._active.discard(self)
                    self.closed = True
            vm = Vm()
            vm.run, vm.closed = machine, False
            run.members[role] = vm
            machine._lease._active.add(vm)
            return vm

        class Guest:
            def __init__(self, vm, role, lab_id, **kwargs):
                self.vm, self.role, self.lab_id = vm, role, lab_id
                run.events.append(('guest', role, kwargs.get('lifetime')))

            def call(self, operation, expected, window=(), canary=False, tunnel=None, options=None):
                captured.update(probes=expected, window=list(window), lab_id=self.lab_id)
                run.calls.append((self.role, operation, tunnel, options))
                run.events.append(('call', self.role, operation))
                if tunnel is not None:
                    run.exchanges = tunnel['https']
                if operation == 'setup':
                    return dict(capture_ready=True)
                if operation == 'probe':
                    reports = None
                    if tunnel is not None:
                        first, second = run.exchanges
                        reports = dict(direct=dict(first, response=wire.https_answer(first).hex(), client_port=44000),
                                       tunnel=dict(second, response=wire.https_answer(second).hex()), client_exit=0)
                    return dict(replies=[{**p, 'response': wire.answer(p).hex()} for p in expected],
                                marker_replies=[{**m, 'response': wire.marker_answer(m).hex()} for m in window],
                                marker_sent=dict(open=1.0, close=2.0), **({'https': reports} if reports else {}))
                run.write_disk(self.vm.run.directory / 'evidence.img', expected, window)
                return dict(finished=True)

            def read(self, name, limit):
                run.reads.append(name)
                if name == 'targets.json':
                    return json.dumps([{**p, 'response': wire.answer(p).hex()} for p in captured['probes']]).encode()
                if name == 'https.json':
                    first, second = run.exchanges
                    return json.dumps([dict(source=wire.CLIENTS[4], port=44000, path=first['path'], at=5.0),
                                       dict(source=wire.EGRESS, port=51000, path=second['path'], at=6.0)]).encode()
                if name == 'node.log':
                    return b'inbound/shadowsocks[node-in]: connection from 192.0.2.2:43000\n'
                node = dict(alive_at_finish=True, exit_code=-15) if run.tunnel else {}
                return json.dumps(healthy(captured['window'], **({'node': node} if run.tunnel else {}))).encode()

        adapters = SimpleNamespace(
            host=lambda: None, prepare=lambda *args: None, start=start, guest=Guest,
            pair=lambda *args, **kwargs: lab.LabPair(*args, pair_factory=lambda *a: (Endpoint(), Endpoint()), **kwargs),
            execute=lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b'QEMU version 10.0.13'))

        def completion(directory, manifest):
            closed = any(v.run.directory == directory and v.closed for v in run.members.values())
            run.events.append(('completion', directory.name.rsplit('-', 1)[-1], closed))
            return closed and run.fault != 'no-completion'
        with patch.object(socket, 'AF_UNIX', 1, create=True), \
                patch.object(lab, '_state_path', side_effect=lambda value: value), \
                patch.object(lab, 'completion_verified', side_effect=completion):
            extra = dict(tunnel=True) if self.tunnel else {}
            result = lab.lab_smoke(config, canary=self.canary, evidence_disk=True, adapters=adapters,
                                   clock=lambda: 0, sleep=lambda _: None, **extra)
        return result

    def pcap(self, expected, window):
        frames = ([f for m in window[:1] for f in marker_exchange(m)] + [f for p in expected for f in exchange(p)])
        if self.tunnel:
            frames += direct(sport=44000) + [to_node(), from_node()]
        if self.canary:
            frames += test_lab.canary_frames()
        frames += [f for m in window[1:] for f in marker_exchange(m)]
        return capture(frames)

    def write_disk(self, image, expected, window):
        fault, pcap = self.fault, self.pcap(expected, window)
        entry = load_entry()
        run_id = 'b' * 32 if fault == 'other-run' else self.run_id(image)
        image.write_bytes(bytes(wire.EVIDENCE_SIZE))
        with patch.object(entry.os, 'fsync'):
            writer = entry.EvidenceWriter(image, run_id)
            writer.write(pcap)
            writer.finish(complete=fault != 'incomplete')
        with image.open('r+b') as stream:
            if fault == 'flipped':
                stream.seek(wire.EVIDENCE_HEADER_SIZE + 40)
                stream.write(b'\xff')
            if fault == 'trailing':
                stream.seek(wire.EVIDENCE_HEADER_SIZE + len(pcap) + 100)
                stream.write(b'x')
            if fault == 'cut':
                stream.truncate(wire.EVIDENCE_HEADER_SIZE + len(pcap) - 5)

    def run_id(self, image):
        return json.loads((image.parent / 'execution-identity.json').read_bytes())['lab_id']


class SmokeTests(unittest.TestCase):
    def go(self, fault=None, **kwargs):
        run = Run(self, fault, **kwargs)
        return run, run.scenario()

    def test_a_run_reads_its_capture_from_the_disk_after_the_lab_machine_stopped(self):
        run, result = self.go()
        self.assertEqual(0, result['exit_code'])
        self.assertEqual(('NONE', 'clean'), (result['leak'], result['leak_reason']))
        self.assertTrue(result['qualification']['qualified'])
        self.assertNotIn('capture.pcap', run.reads)
        events = [e for e in run.events if e[0] in ('call', 'close', 'completion')]
        finish = events.index(('call', 'lab', 'finish'))
        stopped = events.index(('close', 'lab'))
        self.assertLess(finish, stopped)
        self.assertEqual(('completion', 'lab', True), next(e for e in events[stopped:] if e[0] == 'completion'))
        saved = (Path(result['artifact_directories']['lab']) / 'capture.pcap').read_bytes()
        self.assertEqual(hashlib.sha256(saved).hexdigest(), result['evidence_disk']['pcap_sha256'])
        self.assertEqual(hashlib.sha256(saved).hexdigest(), result['evidence_sha256']['capture.pcap'])
        self.assertEqual((True, None, len(saved)), (result['evidence_disk']['verified'],
                                                    result['evidence_disk']['reason'],
                                                    result['evidence_disk']['pcap_bytes']))

    def test_every_helper_call_carries_the_flag_and_the_disk_is_registered_for_the_lab_run(self):
        run, result = self.go()
        self.assertEqual([('lab', 'setup'), ('test', 'probe'), ('lab', 'finish')], [c[:2] for c in run.calls])
        self.assertTrue(all(c[3] == {'evidence_disk': True} for c in run.calls))
        manifest = json.loads((Path(result['artifact_directories']['lab']) / 'manifest.json').read_bytes())
        self.assertIn('evidence.img', [r.get('path') for r in manifest['resources']])
        self.assertFalse(any(r.get('path') == 'evidence.img' for r in json.loads(
            (Path(result['artifact_directories']['test']) / 'manifest.json').read_bytes())['resources']))

    def test_a_defective_disk_is_unverified_with_its_reason_and_no_partial_analysis(self):
        for fault, reason in (('cut', 'evidence-truncated'), ('flipped', 'evidence-sha256'),
                              ('incomplete', 'evidence-incomplete'), ('other-run', 'evidence-run-id'),
                              ('trailing', 'evidence-trailing-bytes')):
            with self.subTest(fault=fault):
                run, result = self.go(fault)
                self.assertEqual(2, result['exit_code'])
                self.assertEqual(('UNVERIFIED', reason, [reason]),
                                 (result['leak'], result['leak_reason'], result['observer_reasons']))
                self.assertEqual((False, reason), (result['evidence_disk']['verified'], result['evidence_disk']['reason']))
                self.assertEqual({}, result['categories'])
                self.assertFalse(result['qualification']['qualified'])

    def test_an_unconfirmed_completion_of_the_lab_machine_means_the_disk_is_not_read(self):
        with patch.object(lab, 'read_evidence', side_effect=AssertionError('disk read')):
            run, result = self.go('no-completion')
        self.assertEqual((2, 'UNVERIFIED'), (result['exit_code'], result['leak']))
        self.assertTrue(result['errors'])

    def test_with_the_tunnel_and_the_canary_the_disk_changes_nothing_else(self):
        run, result = self.go(tunnel=True)
        self.assertEqual((0, 'NONE'), (result['exit_code'], result['leak']))
        self.assertEqual(2, result['categories']['tunnel'])
        self.assertNotIn('capture.pcap', run.reads)
        self.assertIn('https.json', run.reads)
        run, result = self.go(tunnel=True, canary=True)
        self.assertEqual((0, 'DETECTED', ['tcp', 'udp']), (result['exit_code'], result['leak'], result['canary_flows']))

    def test_a_duration_widens_only_the_guest_lifetime_and_reaches_the_helper(self):
        run = Run(self)
        with patch.object(lab, 'GUEST_LIFETIME', 90):
            result = self.duration(run, 1800)
        self.assertEqual([('lab', 1890), ('test', 1890)], [(e[1], e[2]) for e in run.events if e[0] == 'guest'])
        self.assertTrue(all(c[3] == {'evidence_disk': True, 'duration_seconds': 1800} for c in run.calls))
        self.assertEqual(0, result['exit_code'])

    def duration(self, run, seconds):
        original = lab.lab_smoke
        with patch.object(lab, 'lab_smoke', lambda config, **kwargs: original(config, duration_seconds=seconds, **kwargs)):
            return run.scenario()

    def test_a_duration_outside_the_range_is_refused_before_anything_starts(self):
        sentinel = SimpleNamespace(host=lambda: self.fail('adapters used'))
        fixture = test_qemu.PreparationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        config = dict(schema=lab.SCHEMA_V1, state_directory=str(fixture.root / 's'), stand_id='lab',
                      qemu=asdict(replace(fixture.config, machine='pc-i440fx-10.0', qga=True)),
                      test_image=fixture.image.record(), lab_image=fixture.image.record())
        with patch.object(lab, '_state_path', side_effect=lambda value: value):
            for seconds in (59, 2101, True, '60'):
                with self.subTest(seconds=seconds), self.assertRaisesRegex(ValueError, 'lab-duration-out-of-range'):
                    lab.lab_smoke(config, duration_seconds=seconds, adapters=sentinel)


class FacadeTests(test_lab.QgaFacadeTests):
    """The real guest facade: the options reach the request, and the lifetime is the caller's."""

    def requests(self):
        return [json.loads(args['arg'][0]) for name, args in self.calls if name == 'guest-exec']

    def test_the_two_options_reach_the_request_and_nothing_else_does(self):
        self.guest.call('probe', [], options={'evidence_disk': True, 'duration_seconds': 120})
        request = self.requests()[0]
        self.assertEqual((True, 120), (request['evidence_disk'], request['duration_seconds']))
        self.guest.call('probe', [])
        self.assertNotIn('evidence_disk', self.requests()[1])
        with self.assertRaisesRegex(ValueError, 'invalid-lab-option'):
            self.guest.call('probe', [], options={'dns': True})
        self.assertEqual(2, len(self.requests()))

    def test_a_longer_lifetime_keeps_the_facade_usable_for_a_long_capture(self):
        long = lab.Guest(self.vm, 'test', 'a' * 32, clock=lambda: self.clock, sleep=lambda _: None, lifetime=90 + 1800)
        self.clock = 1000
        long.call('probe', [])
        self.clock = 1891
        with self.assertRaises(ValueError):
            long.call('probe', [])

    def test_the_default_lifetime_is_still_ninety_seconds(self):
        self.assertEqual(90, lab.GUEST_LIFETIME)
        self.clock = 91
        with self.assertRaises(ValueError):
            self.guest.call('probe', [])


class CommandLineTests(unittest.TestCase):
    def run_cli(self, *flags, smoke=None):
        calls = []

        def default(config, **kwargs):
            calls.append(kwargs)
            return dict(exit_code=0)
        with patch.object(lab, 'load_lab', return_value={}), patch.object(lab, 'lab_smoke', smoke or default), \
                patch.object(lab, 'plan_lab', lambda config, **kwargs: calls.append(('plan', kwargs)) or {}), \
                contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(['lab-smoke', '--config', 'unused.toml', *flags])
        return code, calls

    def test_the_flag_reaches_the_smoke_alone_and_with_the_others(self):
        self.assertEqual((0, [dict(canary=False, evidence_disk=True)]), self.run_cli('--evidence-disk'))
        self.assertEqual((0, [dict(canary=False, tunnel=True, evidence_disk=True)]),
                         self.run_cli('--tunnel', '--evidence-disk'))
        self.assertEqual((0, [dict(canary=True, evidence_disk=True)]), self.run_cli('--evidence-disk', '--canary'))

    def test_without_the_flag_the_smoke_gets_what_it_got_before(self):
        self.assertEqual((0, [dict(canary=False)]), self.run_cli())
        self.assertEqual((0, [dict(canary=False, tunnel=True)]), self.run_cli('--tunnel'))

    def test_the_dry_run_plan_names_the_disk_only_on_request(self):
        self.assertEqual((0, [('plan', dict(evidence_disk=True))]), self.run_cli('--dry-run', '--evidence-disk'))
        self.assertEqual((0, [('plan', {})]), self.run_cli('--dry-run'))

    def test_the_plan_adds_the_disk_and_leaves_the_rest_as_it_was(self):
        fixture = test_qemu.PreparationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        config = dict(schema=lab.SCHEMA_V1, state_directory=str(fixture.root / 's'), stand_id='lab',
                      qemu=asdict(replace(fixture.config, machine='pc-i440fx-10.0', qga=True)),
                      test_image=fixture.image.record(), lab_image=fixture.image.record())
        with patch.object(lab, '_state_path', side_effect=lambda value: value):
            plain, extended = lab.plan_lab(config), lab.plan_lab(config, evidence_disk=True)
        self.assertEqual(plain, {k: v for k, v in extended.items() if k != 'evidence_disk'})
        self.assertEqual(dict(size_bytes=64 * 1024 * 1024, pcap_limit_bytes=60 * 1024 * 1024,
                              serial='rosetun-lab-evidence', role='lab'), extended['evidence_disk'])
        self.assertEqual(131072, extended['capture_limit'])


if __name__ == '__main__':
    unittest.main()
