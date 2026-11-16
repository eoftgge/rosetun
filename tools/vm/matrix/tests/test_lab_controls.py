"""Stage 7c1: the negative controls of `lab-smoke --control`, on the real ledger and the real `lifecycle.start`."""
import base64
import contextlib
from dataclasses import asdict, replace
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.vm.matrix import cli, lab, lifecycle, qmp_adapter, lab_protocol as wire
from tools.vm.matrix.tests import test_lifecycle, test_qemu
from tools.vm.matrix.tests.test_lab import (Endpoint, canary_frames, capture, exchange, healthy, marker_exchange,
                                            pcap)

STOPPED = ('observer-stopped', 'observer-killed', 'link-down')


class Qmp(test_lifecycle.Control):
    """The scripted QMP of one fake QEMU; `links` keeps what `set_link` was given."""

    def __init__(self, plan):
        super().__init__(plan)
        self.links = []

    def command(self, name, timeout, *, event=None, arguments=None):
        if name == 'set_link':
            self.links.append(dict(arguments))
            return {}
        return super().command(name, timeout, event=event)


class Harness(unittest.TestCase):
    """One lab run: both machines start through `lifecycle.start` with a fake child, fake QMP and fake agent."""

    def config(self):
        fixture = test_qemu.PreparationTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        fixture.config = replace(fixture.config, qga=True)
        self.fixture = fixture
        return dict(schema='rosetun.matrix.lab.v1', state_directory=str(fixture.root / 'lab-state'),
                    stand_id='lab', qemu=asdict(replace(fixture.config, machine='pc-i440fx-10.0')),
                    test_image=fixture.image.record(), lab_image=fixture.image.record())

    def scenario(self, control=None, *, canary=False, fault=None):
        config = self.config()
        fixture = self.fixture
        plans, qmps, calls, vms, seen = {}, {}, [], {}, {}
        windows = [0]
        halts = control in STOPPED and fault not in ('never-seen', 'close-arrived')
        killed = control == 'observer-killed' and halts

        def prepare(run, image, qemu):
            fixture.run, fixture.calls = run, []
            plans[run] = fixture.prepare()

        class Agent:
            def __init__(self, stream, **kwargs):
                self.stream, self.closed = stream, False

            def close(self):
                self.stream.close()
                self.closed = True

        def start(run, lab):
            role = lab.role(run)
            child = test_lifecycle.Child()
            child.pid += 1 if role == 'lab' else 0
            qmps[role] = Qmp(plans[run])
            identity = dict(id='qemu', kind='process', pid=child.pid, platform='posix', boot_id='fake',
                            start_id=str(child.pid), executable=fixture.config.executable)
            fixture.run, fixture.calls = run, [0, 0]
            with patch.object(lifecycle, '_host'), patch.object(lifecycle, 'Qmp', return_value=qmps[role]), \
                 patch.object(lifecycle, 'Qga', side_effect=Agent), \
                 patch.object(lifecycle, '_open_control', side_effect=lambda *args, **kwargs: Endpoint()), \
                 patch.object(lifecycle, '_identity', return_value=identity), \
                 patch.object(lifecycle.subprocess, 'Popen', return_value=child):
                vm = lifecycle.start(run, lab=lab, executor=fixture.fake, timeout=30)
            vm.last_boot_id = '22345678-1234-4234-8234-123456789abc'
            vm.wait_initial_guest = lambda **kwargs: dict(result='observed')
            vms[role] = vm
            return vm

        class Guest:
            def __init__(self, vm, role, lab_id, **kwargs):
                self.role = role

            def call(self, operation, expected, window=(), canary=False, tunnel=None, options=None, poll=None,
                     attempts=40):
                seen.update(probes=expected, window=list(window))
                calls.append(dict(role=self.role, operation=operation, canary=canary, options=options,
                                  poll=poll is not None, attempts=attempts))
                if operation == 'setup':
                    return dict(capture_ready=True)
                if operation == 'window':
                    windows[0] += 1
                    # The lab answers its last exchange on the second poll, or on the fifth when it is slow.
                    return dict(exchanges_done=windows[0] >= (5 if fault == 'slow-exchanges' else 2)
                                and fault != 'never-seen')
                if operation == 'halt':
                    return dict(halted=True)
                if operation == 'finish':
                    if fault == 'finish-fails':
                        raise ValueError('finish-failed')
                    # A killed observer never wrote its health, and the lab machine says so instead of waiting.
                    return dict(finished=True, **({'observer_gone': True} if killed else {}))
                # The test machine's helper: it waits, the controller acts on its polls, then the closing marker fails.
                for _ in range(6 if poll is not None else 0):
                    poll()
                if halts:
                    raise lab.HelperFailed('lab-helper-failed', 'marker-close:4:timeout:5003ms')
                return dict(replies=[{**p, 'response': wire.answer(p).hex()} for p in expected],
                            marker_replies=[{**m, 'response': wire.marker_answer(m).hex()} for m in window],
                            marker_sent=dict(open=1.0, close=2.0))

            def read(self, name, limit):
                probes, window = seen['probes'], seen['window']
                if name == 'capture.pcap':
                    if (control == 'extra-packet' or canary) and fault != 'blind':
                        return pcap(probes, window, canary_frames())
                    if halts:
                        return capture(marker_exchange(window[0]) + [f for p in probes for f in exchange(p)])
                    return pcap(probes, window)
                if name == 'targets.json':
                    return json.dumps([{**p, 'response': wire.answer(p).hex()} for p in probes]).encode()
                changes = dict(markers=healthy(window)['markers'][:1]) if halts else {}
                # Only the lab's `halt` leaves the mark that the capture was ended on request.
                changes |= dict(halted=True) if control == 'observer-stopped' and halts else {}
                return json.dumps(healthy(window, **changes)).encode()

        adapters = SimpleNamespace(
            host=lambda: None, prepare=prepare, start=start, guest=Guest,
            pair=lambda *args, **kwargs: lab.LabPair(*args, pair_factory=lambda *a: (Endpoint(), Endpoint()), **kwargs),
            execute=lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b'QEMU version 10.0.13'))
        with patch.object(socket, 'AF_UNIX', 1, create=True):
            result = lab.lab_smoke(config, canary=canary, **({'control': control} if control else {}),
                                   adapters=adapters, clock=lambda: 0, sleep=lambda _: None)
        self.calls, self.qmps, self.vms = calls, qmps, vms
        return result

    def journal(self, result, role):
        path = Path(result['artifact_directories'][role]) / 'lifecycle.jsonl'
        return [(row['action'], row['result']) for row in map(json.loads, path.read_text().splitlines())]

    def lab_operations(self):
        return [c['operation'] for c in self.calls if c['role'] == 'lab']


class ControlRunTests(Harness):
    def test_an_extra_packet_run_is_judged_as_an_ordinary_one_and_passes_only_on_the_detected_leak(self):
        result = self.scenario('extra-packet')
        self.assertEqual((0, 'DETECTED', ['tcp', 'udp'], 0, False),
                         (result['exit_code'], result['leak'], result['canary_flows'], result['canary_other'],
                          result['canary']))
        self.assertEqual((True, True), (result['window']['markers_found'], result['window']['ordered']))
        self.assertEqual(dict(name='extra-packet', expected=lab.CONTROL_EXPECTATIONS['extra-packet'],
                              intervened=False, link_restored=False, met=True), result['control'])
        self.assertEqual([True], [c['canary'] for c in self.calls if c['operation'] == 'probe'])
        self.assertEqual(dict(test=True, lab=True), result['completion'])
        self.assertTrue(result['channel_closed'])
        self.assertEqual(2, self.scenario('extra-packet', fault='blind')['exit_code'])

    def test_stopping_the_observer_between_the_markers_ends_unverified_and_never_none(self):
        result = self.scenario('observer-stopped')
        self.assertEqual((0, 'UNVERIFIED'), (result['exit_code'], result['leak']))
        self.assertIn('window-markers-missing-or-repeated', result['observer_reasons'])
        self.assertIn('capture-halted-in-window', result['observer_reasons'])
        self.assertEqual((False, False), (result['window']['markers_found'], result['window']['ordered']))
        self.assertTrue(result['control']['met'] and result['control']['intervened'])
        self.assertEqual([], self.qmps['test'].links)
        self.assertEqual(dict(test=True, lab=True), result['completion'])

    def test_a_cut_link_is_told_from_a_stopped_observer_by_the_reason_only_the_stop_leaves(self):
        stopped = self.scenario('observer-stopped')
        cut = self.scenario('link-down')
        self.assertEqual((0, 0), (stopped['exit_code'], cut['exit_code']))
        self.assertIn('capture-halted-in-window', stopped['observer_reasons'])
        self.assertNotIn('capture-halted-in-window', cut['observer_reasons'])
        # The one reason tells them apart: a stop without it, or a cut with it, is not what the control shows.
        stopped['observer_reasons'].remove('capture-halted-in-window')
        cut['observer_reasons'].append('capture-halted-in-window')
        self.assertFalse(lab.control_met(stopped))
        self.assertFalse(lab.control_met(cut))

    def test_killing_the_observer_is_refused_without_a_verdict_and_never_says_none(self):
        result = self.scenario('observer-killed')
        self.assertEqual((0, 'UNVERIFIED', ['observer-gone']),
                         (result['exit_code'], result['leak'], result['observer_reasons']))
        self.assertTrue(result['control']['met'] and result['control']['intervened'])
        self.assertEqual((False, False), (result['window']['markers_found'], result['window']['ordered']))
        # The closing exchange of the test machine and the missing report of the observer are both on the record.
        self.assertEqual(['probe', 'lab-smoke'], [row['stage'] for row in result['errors']])
        self.assertEqual('observer-gone', result['errors'][1]['reason'])
        self.assertEqual(['setup', 'window', 'window', 'halt', 'finish'], self.lab_operations())
        self.assertEqual([], self.qmps['test'].links)
        self.assertEqual(dict(test=True, lab=True), result['completion'])
        self.assertTrue(result['channel_closed'])
        self.assertNotIn('evidence_sha256', result)

    def test_a_killed_observer_control_passes_only_on_its_own_refusal(self):
        changes = (lambda r: r['observer_reasons'].append('capture-halted-in-window'),
                   lambda r: r.update(leak='NONE'),
                   lambda r: r['errors'].pop(),
                   lambda r: r['errors'].pop(0),
                   lambda r: r['errors'].append(dict(stage='lab-smoke', kind='ValueError', reason='other')),
                   lambda r: r['control'].update(intervened=False))
        for index, change in enumerate(changes):
            with self.subTest(change=index):
                result = self.scenario('observer-killed')
                change(result)
                self.assertFalse(lab.control_met(result))
        # A kill does not pass as a stop or a cut, nor a stop as a kill.
        killed = self.scenario('observer-killed')
        for name in ('observer-stopped', 'link-down'):
            self.assertFalse(lab.control_met(dict(killed, control=dict(killed['control'], name=name))))
        stopped = self.scenario('observer-stopped')
        self.assertFalse(lab.control_met(dict(stopped, control=dict(stopped['control'], name='observer-killed'))))

    def test_a_kill_that_left_no_dead_observer_at_the_finish_is_judged_like_an_ordinary_run(self):
        # The lab machine did not report the observer gone: the run reads its evidence as usual and the control fails.
        result = self.scenario('observer-killed', fault='close-arrived')
        self.assertEqual((2, False), (result['exit_code'], result['control']['met']))

    def test_the_intervention_waits_for_the_lab_to_mark_the_opening_and_acts_once(self):
        result = self.scenario('observer-stopped')
        # The first poll found no marker and nothing was stopped; once it was stopped, nobody asked again.
        self.assertEqual(['setup', 'window', 'window', 'halt', 'finish'], self.lab_operations())
        self.assertTrue(result['control']['intervened'])
        # The opening can be marked long before the last exchange is answered: nothing is stopped until then.
        for control in STOPPED:
            with self.subTest(control=control, fault='slow-exchanges'):
                slow = self.scenario(control, fault='slow-exchanges')
                self.assertEqual((0, True), (slow['exit_code'], slow['control']['intervened']))
                self.assertEqual(['setup'] + ['window'] * 5 + (['halt'] if control != 'link-down' else [])
                                 + ['finish'], self.lab_operations())
                self.assertEqual(2 if control == 'link-down' else 0, len(self.qmps['test'].links))
        for control in STOPPED:
            with self.subTest(control=control):
                missed = self.scenario(control, fault='never-seen')
                self.assertEqual((2, False, False), (missed['exit_code'], missed['control']['intervened'],
                                                     missed['control']['met']))
                self.assertEqual([dict(stage='control', kind='ValueError', reason='exchanges-not-completed')],
                                 missed['errors'])
                self.assertEqual(['setup'] + ['window'] * 6 + ['finish'], self.lab_operations())
                self.assertEqual([], self.qmps['test'].links)

    def test_a_window_that_closed_after_all_is_a_failed_control(self):
        for control in STOPPED:
            with self.subTest(control=control):
                result = self.scenario(control, fault='close-arrived')
                self.assertEqual((2, 'NONE', False), (result['exit_code'], result['leak'], result['control']['met']))

    def test_cutting_the_link_goes_through_the_lifecycle_and_the_link_is_back_before_the_machines_close(self):
        result = self.scenario('link-down')
        self.assertEqual((0, 'UNVERIFIED', True), (result['exit_code'], result['leak'], result['control']['link_restored']))
        self.assertEqual([dict(name='test-wire', up=False), dict(name='test-wire', up=True)], self.qmps['test'].links)
        self.assertEqual([], self.qmps['lab'].links)
        self.assertNotIn('halt', self.lab_operations())
        rows = self.journal(result, 'test')
        order = [rows.index(row) for row in (('link-down', 'intent'), ('link-down', 'command-accepted'),
                                              ('link-up', 'intent'), ('link-up', 'command-accepted'))]
        self.assertEqual(sorted(order), order)
        self.assertLess(order[-1], min(i for i, row in enumerate(rows) if row[0] in ('close', 'hard-off')))
        self.assertEqual(dict(test=True, lab=True), result['completion'])
        self.assertEqual([], [row for row in self.journal(result, 'lab') if row[0].startswith('link')])

    def test_a_link_still_down_when_the_run_fails_is_brought_back_before_the_machines_close(self):
        result = self.scenario('link-down', fault='finish-fails')
        self.assertEqual((2, True), (result['exit_code'], result['control']['link_restored']))
        self.assertEqual([dict(name='test-wire', up=False), dict(name='test-wire', up=True)], self.qmps['test'].links)
        rows = self.journal(result, 'test')
        self.assertLess(rows.index(('link-up', 'command-accepted')),
                        min(i for i, row in enumerate(rows) if row[0] in ('close', 'hard-off')))
        self.assertEqual(dict(test=True, lab=True), result['completion'])

    def test_a_link_that_cannot_be_brought_back_is_an_error_and_never_a_pass(self):
        original = Qmp.command

        def refuse_up(self, name, timeout, *, event=None, arguments=None):
            if name == 'set_link' and arguments['up']:
                raise ValueError('qmp-exchange-failed')
            return original(self, name, timeout, event=event, arguments=arguments)
        with patch.object(Qmp, 'command', refuse_up):
            result = self.scenario('link-down')
        self.assertEqual((2, False), (result['exit_code'], result['control']['met']))
        self.assertIn('link-up', [row[0] for row in self.journal(result, 'test') if row[1] == 'error'])

    def test_each_control_names_what_was_expected(self):
        for control in lab.CONTROLS:
            with self.subTest(control=control):
                result = self.scenario(control)
                self.assertEqual((control, lab.CONTROL_EXPECTATIONS[control]),
                                 (result['control']['name'], result['control']['expected']))
                self.assertEqual(0, result['exit_code'])

    def test_the_guests_get_the_control_and_the_longer_wait_only_when_a_control_stops_something(self):
        self.scenario('link-down')
        probe = next(c for c in self.calls if c['operation'] == 'probe')
        self.assertEqual((dict(control='link-down'), True, lab.CONTROL_POLLS), (probe['options'], probe['poll'], probe['attempts']))
        self.assertEqual([dict(control='link-down')] * len(self.calls), [c['options'] for c in self.calls])
        self.scenario('extra-packet')
        self.assertEqual({None}, {c['options'] for c in self.calls})
        self.assertEqual({(False, 40)}, {(c['poll'], c['attempts']) for c in self.calls})

    def test_the_summary_of_an_ordinary_or_canary_run_has_no_control_block_and_the_same_exchanges(self):
        sequences = []
        for canary in (False, True):
            with self.subTest(canary=canary):
                result = self.scenario(canary=canary)
                self.assertNotIn('control', result)
                self.assertEqual((0, canary), (result['exit_code'], result['canary']))
                self.assertEqual({None}, {c['options'] for c in self.calls})
                self.assertEqual({(False, 40)}, {(c['poll'], c['attempts']) for c in self.calls})
                sequences.append([(c['role'], c['operation']) for c in self.calls])
        self.assertEqual(sequences[0], sequences[1])
        self.assertEqual([('lab', 'setup'), ('test', 'probe'), ('lab', 'finish')], sequences[0])
        # The extra packet asks of the machines exactly what the canary does.
        self.scenario('extra-packet')
        self.assertEqual(sequences[0], [(c['role'], c['operation']) for c in self.calls])
        self.assertEqual([True], [c['canary'] for c in self.calls if c['operation'] == 'probe'])


class PlanTests(Harness):
    def test_the_dry_run_names_the_control_and_the_library_refuses_a_bad_combination(self):
        config = self.config()
        self.assertNotIn('control', lab.plan_lab(config))
        self.assertEqual(dict(name='link-down', expected=lab.CONTROL_EXPECTATIONS['link-down']),
                         lab.plan_lab(config, control='link-down')['control'])
        for kwargs in (dict(control='nothing'), dict(control='link-down', tunnel=True)):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(ValueError, 'lab-control-invalid'):
                lab.plan_lab(config, **kwargs)
        with self.assertRaisesRegex(ValueError, 'lab-control-invalid'):
            lab.lab_smoke(config, canary=True, control='link-down')


class CommandLineControlTests(unittest.TestCase):
    def run_cli(self, *flags):
        calls = []

        def smoke(config, **kwargs):
            calls.append(kwargs)
            return dict(exit_code=0)
        with patch.object(lab, 'load_lab', return_value={}), patch.object(lab, 'lab_smoke', smoke), \
             contextlib.redirect_stdout(io.StringIO()):
            return cli.main(['lab-smoke', '--config', 'unused.toml', *flags]), calls

    def test_a_control_is_named_once_and_only_the_known_ones_are_taken(self):
        for control in wire.CONTROLS:
            self.assertEqual((0, [dict(canary=False, control=control)]), self.run_cli('--control', control))
        self.assertEqual((0, [dict(canary=False)]), self.run_cli())
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as refused:
            self.run_cli('--control', 'nothing')
        self.assertEqual(2, refused.exception.code)

    def test_a_control_cannot_go_with_the_canary_or_the_tunnel(self):
        for other in ('--canary', '--tunnel'):
            with self.subTest(other=other), contextlib.redirect_stderr(io.StringIO()), \
                 self.assertRaises(SystemExit) as refused:
                self.run_cli('--control', 'link-down', other)
            self.assertEqual(2, refused.exception.code)


class RequestTests(unittest.TestCase):
    """What goes to the guests: nothing differs from before unless a control asks for it."""

    def setUp(self):
        self.calls, self.boot, self.statuses = [], '12345678-1234-4234-8234-123456789abc', []

        def rpc(name, timeout, args):
            self.calls.append((name, args))
            if name == 'guest-exec-status':
                return self.statuses.pop(0) if self.statuses else dict(
                    exited=True, exitcode=0, **{'out-data': base64.b64encode(json.dumps(
                        dict(lab_id='a' * 32, boot_id=self.boot, exchanges_done=True)).encode()).decode()})
            return dict(pid=123)
        self.vm = SimpleNamespace(_check=lambda: None, _guest_lock=threading.Lock(), reset_pending=False,
                                  vm_uuid=self.boot, last_boot_id=self.boot, qga=SimpleNamespace(
                                      _rpc=rpc, read_boot_id=lambda _: self.boot, probe=lambda _: None, valid=True))
        nonces = iter(f'{i:024x}' for i in range(10))
        self.expected = wire.probes('a' * 32, nonces.__next__)
        self.window = wire.markers('a' * 32, nonces.__next__)

    def request(self, role, operation, **kwargs):
        guest = lab.Guest(self.vm, role, 'a' * 32, clock=lambda: 0, sleep=lambda _: None)
        self.calls.clear()
        guest.call(operation, self.expected, self.window, **kwargs)
        return json.loads(self.calls[0][1]['arg'][0])

    def test_an_ordinary_and_a_canary_request_have_no_control_and_a_control_request_differs_by_that_key_only(self):
        plain = self.request('test', 'probe')
        canary = self.request('test', 'probe', canary=True)
        self.assertNotIn('control', plain)
        self.assertNotIn('control', canary)
        self.assertEqual(plain, dict(canary, canary=False))
        for control in STOPPED:
            held = self.request('test', 'probe', options=dict(control=control))
            self.assertEqual(plain, {k: v for k, v in held.items() if k != 'control'})
            self.assertEqual(control, held['control'])
        # The extra packet is the canary's traffic byte for byte: only the summary is judged another way.
        self.assertEqual(canary, self.request('test', 'probe', canary=True))

    def test_the_lab_machine_has_two_more_operations_and_the_test_machine_has_none(self):
        for operation in ('window', 'halt'):
            sent = self.request('lab', operation, options=dict(control='observer-stopped'))
            self.assertEqual((operation, 'observer-stopped'), (sent['operation'], sent['control']))
            with self.assertRaises(ValueError):
                self.request('test', operation)
        with self.assertRaises(ValueError):
            self.request('lab', 'serve')
        with self.assertRaises(ValueError):
            self.request('test', 'probe', options=dict(control='link-down', other=1))

    def test_the_poll_runs_while_the_helper_is_busy_and_not_after_it_ends(self):
        self.statuses = [dict(exited=False), dict(exited=False)]
        polls = []
        guest = lab.Guest(self.vm, 'test', 'a' * 32, clock=lambda: 0, sleep=lambda _: None)
        guest.call('probe', self.expected, self.window, poll=lambda: polls.append(1), attempts=5)
        self.assertEqual(2, len(polls))

    def test_the_wait_for_a_helper_is_forty_checks_unless_a_control_asks_for_more(self):
        guest = lab.Guest(self.vm, 'test', 'a' * 32, clock=lambda: 0, sleep=lambda _: None)
        self.statuses = [dict(exited=False)] * 45
        with self.assertRaisesRegex(ValueError, 'lab-helper-timeout'):
            guest.call('probe', self.expected, self.window)
        self.assertEqual(40, sum(name == 'guest-exec-status' for name, _ in self.calls))
        self.statuses = [dict(exited=False)] * 3
        with self.assertRaisesRegex(ValueError, 'lab-helper-timeout'):
            guest.call('probe', self.expected, self.window, attempts=3)


class GuestControlTests(unittest.TestCase):
    def setUp(self):
        source = Path(lab.__file__).parents[1] / 'linux/guest/lab-entry.py'
        spec = importlib.util.spec_from_file_location('lab_entry_controls', source)
        self.entry = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {'lab_protocol': wire}):
            spec.loader.exec_module(self.entry)
        nonces = iter(f'{i:024x}' for i in range(10))
        self.request = dict(role='lab', lab_id='a' * 32, vm_uuid='12345678-1234-4234-8234-123456789abc',
                            boot_id='22345678-1234-4234-8234-123456789abc', operation='setup', canary=False,
                            probes=wire.probes('a' * 32, nonces.__next__))
        self.request['markers'] = wire.markers('a' * 32, nonces.__next__)

    def identity(self, request):
        values = {'/etc/rosetun-lab-role': 'lab', '/proc/sys/kernel/random/boot_id': request['boot_id'],
                  '/sys/class/dmi/id/product_uuid': request['vm_uuid']}
        rows = json.dumps([dict(ifname='enp7s0', address=wire.MACS['lab'], link_type='ether')]).encode()
        with patch.object(self.entry.os, 'geteuid', return_value=0, create=True), \
             patch.object(Path, 'read_text', lambda p: values[p.as_posix()]), \
             patch.object(self.entry, 'command', return_value=rows):
            return self.entry.identity(request)

    def test_only_a_stopping_control_without_a_canary_is_taken(self):
        for control in STOPPED:
            self.assertEqual('enp7s0', self.identity(dict(self.request, control=control)))
        for changes in (dict(control='extra-packet'), dict(control='nothing'), dict(control=None),
                        dict(control='link-down', canary=True)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.identity(dict(self.request, **changes))

    def test_the_test_machine_waits_between_its_exchanges_and_the_closing_marker_only_for_a_control(self):
        for control, expected in ((None, ['open', 'exchanges', 'close']),
                                  ('link-down', ['open', 'exchanges', 'hold', 'close'])):
            events = []

            def marker(m):
                events.append(m['word'])
                return dict(m, response=wire.marker_answer(m).hex())

            def sleep(seconds):
                if seconds == wire.CONTROL_HOLD_SECONDS:
                    events.append('hold')
            request = dict(self.request, role='test', operation='probe', **({'control': control} if control else {}))
            with patch.object(self.entry, 'exchange_marker', marker), \
                 patch.object(self.entry, 'probe_exchanges', lambda r: events.append('exchanges') or []), \
                 patch.object(self.entry.time, 'sleep', sleep):
                self.entry.probe_all(request)
            self.assertEqual(expected, events)

    def serve_dir(self, **changes):
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        run = directory / self.request['lab_id']
        run.mkdir()
        (run / 'identity.json').write_text(json.dumps(dict(self.request, **changes)))
        return directory, run, dict(self.request, **changes)

    def main(self, directory, request):
        with patch.object(self.entry, 'ROOT', directory), patch.object(self.entry, 'identity', return_value='enp7s0'), \
             patch.object(self.entry.time, 'sleep'):
            return self.entry.main(request)

    def test_the_window_operation_says_whether_every_exchange_was_answered_and_needs_a_control(self):
        directory, run, request = self.serve_dir(control='link-down')
        request['operation'] = 'window'
        self.assertEqual(dict(exchanges_done=False), self.main(directory, request))
        (run / 'exchanges-done').touch()
        self.assertEqual(dict(exchanges_done=True), self.main(directory, request))
        directory, run, request = self.serve_dir()
        with self.assertRaises(ValueError):
            self.main(directory, dict(request, operation='window'))

    def test_the_lab_is_done_only_after_the_opening_and_an_answer_to_every_expected_exchange(self):
        probes = self.request['probes']
        answered = [{**p, 'response': wire.answer(p).hex()} for p in probes]
        opening = [dict(word='open', nonce='0' * 24, at=1.0)]
        self.assertEqual(8, len(probes))
        self.assertFalse(self.entry.exchanges_done(self.request, [], answered))
        self.assertFalse(self.entry.exchanges_done(self.request, opening, []))
        for count in range(len(probes)):
            with self.subTest(answered=count):
                self.assertFalse(self.entry.exchanges_done(self.request, opening, answered[:count]))
        # A refused exchange is no answer, and neither is the same one twice.
        refused = answered[:7] + [dict(service='udp', family=4, reason='unexpected-request')]
        self.assertFalse(self.entry.exchanges_done(self.request, opening, refused))
        self.assertFalse(self.entry.exchanges_done(self.request, opening, answered[:7] + answered[:1]))
        self.assertTrue(self.entry.exchanges_done(self.request, opening, answered))
        self.assertTrue(self.entry.exchanges_done(self.request, opening, refused + answered[7:]))

    def test_the_halt_operation_stops_the_observer_once_and_only_for_that_control(self):
        directory, run, request = self.serve_dir(control='observer-stopped')
        (run / 'health.json').write_text('{}')
        self.assertEqual(dict(halted=True), self.main(directory, dict(request, operation='halt')))
        self.assertTrue((run / 'stop').exists())
        self.assertTrue((run / 'halted').exists())
        with self.assertRaises(FileExistsError):
            self.main(directory, dict(request, operation='halt'))
        for changes in (dict(control='link-down'), {}):
            directory, run, request = self.serve_dir(**changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.main(directory, dict(request, operation='halt'))
            self.assertFalse((run / 'stop').exists())

    def test_finish_finds_a_stopped_observer_only_when_the_control_stopped_it(self):
        directory, run, request = self.serve_dir(control='observer-stopped')
        (run / 'health.json').write_text('{}')
        (run / 'stop').touch()
        self.assertEqual(dict(finished=True), self.main(directory, dict(request, operation='finish')))
        for changes in (dict(control='link-down'), {}):
            directory, run, request = self.serve_dir(**changes)
            (run / 'stop').touch()
            with self.subTest(changes=changes), self.assertRaises(FileExistsError):
                self.main(directory, dict(request, operation='finish'))

    def observer_process(self, lab_id='a' * 32, operation='serve'):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)',
                                  json.dumps(dict(operation=operation, lab_id=lab_id))])
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        return child

    @unittest.skipUnless(Path('/proc/self/stat').exists(), 'the observer is found through /proc')
    def test_only_the_observer_of_this_run_counts_as_the_observer(self):
        lab_id = self.request['lab_id']
        mine = self.observer_process()
        self.assertTrue(self.entry.observer_alive(mine.pid, lab_id))
        self.assertFalse(self.entry.observer_alive(mine.pid, 'b' * 32))
        self.assertFalse(self.entry.observer_alive(self.observer_process(operation='setup').pid, lab_id))
        self.assertFalse(self.entry.observer_alive(os.getpid(), lab_id))
        mine.kill()
        # Dead and not yet reaped: a zombie is not an observer.
        for _ in range(50):
            if not self.entry.observer_alive(mine.pid, lab_id):
                break
            time.sleep(.1)
        self.assertFalse(self.entry.observer_alive(mine.pid, lab_id))
        self.assertFalse(self.entry.observer_alive(2 ** 22 + 1, lab_id))

    @unittest.skipUnless(Path('/proc/self/stat').exists(), 'the observer is found through /proc')
    def test_the_kill_goes_to_the_recorded_observer_with_sigkill_and_leaves_no_stop_or_health(self):
        directory, run, request = self.serve_dir(control='observer-killed')
        child = self.observer_process()
        (run / 'observer.pid').write_text(str(child.pid))
        with patch.object(self.entry, 'ROOT', directory), patch.object(self.entry, 'identity', return_value='enp7s0'):
            self.assertEqual(dict(halted=True), self.entry.main(dict(request, operation='halt')))
        self.assertEqual(-signal.SIGKILL, child.wait(10))
        self.assertEqual([], [p.name for p in run.iterdir() if p.name in ('stop', 'halted', 'health.json')])

    @unittest.skipUnless(Path('/proc/self/stat').exists(), 'the observer is found through /proc')
    def test_the_kill_refuses_a_process_that_is_not_the_observer_of_this_run(self):
        directory, run, request = self.serve_dir(control='observer-killed')
        for child in (self.observer_process('b' * 32), self.observer_process(operation='setup')):
            (run / 'observer.pid').write_text(str(child.pid))
            with self.assertRaisesRegex(ValueError, 'observer-not-running'):
                self.main(directory, dict(request, operation='halt'))
            self.assertIsNone(child.poll())
        (run / 'observer.pid').unlink()
        with self.assertRaises(OSError):
            self.main(directory, dict(request, operation='halt'))

    def test_the_kill_is_for_its_own_control_only(self):
        for changes in (dict(control='observer-stopped'), dict(control='link-down'), {}):
            directory, run, request = self.serve_dir(**changes)
            (run / 'observer.pid').write_text(str(os.getpid()))
            with self.subTest(changes=changes), patch.object(self.entry.os, 'kill') as kill:
                with self.assertRaises((ValueError, FileExistsError)):
                    self.main(directory, dict(request, operation='halt', **({} if changes else {'control': 'x'})))
                kill.assert_not_called()

    def test_the_finish_does_not_wait_for_a_killed_observer(self):
        directory, run, request = self.serve_dir(control='observer-killed')
        (run / 'observer.pid').write_text('2')
        with patch.object(self.entry, 'observer_alive', return_value=False):
            self.assertEqual(dict(finished=True, observer_gone=True),
                             self.main(directory, dict(request, operation='finish')))
        self.assertFalse((run / 'stop').exists())

    def test_the_finish_of_an_observer_that_is_not_gone_or_wrote_its_health_is_the_ordinary_one(self):
        directory, run, request = self.serve_dir(control='observer-killed')
        # No kill happened: the observer is alive and is stopped the ordinary way, but it says nothing, so it times out.
        (run / 'observer.pid').write_text('2')
        with patch.object(self.entry, 'observer_alive', return_value=True), self.assertRaisesRegex(
                ValueError, 'observer-stop-timeout'):
            self.main(directory, dict(request, operation='finish'))
        self.assertTrue((run / 'stop').exists())
        # It ended and wrote its health on its own: that is a finished observer, not a gone one.
        directory, run, request = self.serve_dir(control='observer-killed')
        (run / 'observer.pid').write_text('2')
        (run / 'health.json').write_text('{}')
        with patch.object(self.entry, 'observer_alive', return_value=False):
            self.assertEqual(dict(finished=True), self.main(directory, dict(request, operation='finish')))

    def test_the_setup_records_the_pid_of_the_observer_only_for_the_kill(self):
        for control, recorded in (('observer-killed', True), ('observer-stopped', False), ('link-down', False)):
            directory, run, request = self.serve_dir(control=control)
            (run / 'ready.json').write_text('{}')
            writes = []
            with self.subTest(control=control), patch.object(self.entry, 'command'), \
                 patch.object(self.entry.subprocess, 'Popen', return_value=SimpleNamespace(pid=4242, poll=lambda: None)), \
                 patch.object(Path, 'write_text', lambda path, text: writes.append((path.name, text))):
                self.entry.setup(dict(request, operation='setup'), 'enp7s0', run)
            self.assertEqual(recorded, ('observer.pid', '4242') in writes)

    def test_a_request_that_changed_its_control_since_the_setup_is_another_run(self):
        directory, run, request = self.serve_dir(control='link-down')
        with self.assertRaises(ValueError):
            self.main(directory, dict(request, operation='window', control='observer-stopped'))


class QmpArgumentTests(unittest.TestCase):
    def qmp(self):
        executed = []

        class Client:
            events = SimpleNamespace(accept=None)

            def __init__(self, **kwargs):
                pass

            async def execute(self, name, arguments=None):
                executed.append((name, arguments))
                return {}
        relay = SimpleNamespace(client=None, close=lambda: None)
        return qmp_adapter.Qmp(None, client_factory=Client, relay_factory=lambda stream: relay), executed

    def test_only_the_carrier_of_a_lab_wire_takes_arguments_and_only_those_two(self):
        qmp, executed = self.qmp()
        qmp.command('set_link', 5, arguments=dict(name='test-wire', up=False))
        self.assertEqual([('set_link', dict(name='test-wire', up=False))], executed)
        for name, arguments in (('set_link', None), ('set_link', dict(name='eth0', up=False)),
                                ('set_link', dict(name='test-wire', up='no')),
                                ('set_link', dict(name='test-wire', up=True, extra=1)),
                                ('stop', dict(name='test-wire', up=True))):
            with self.subTest(name=name, arguments=arguments), self.assertRaisesRegex(ValueError, 'invalid-qmp-arguments'):
                qmp.command(name, 5, arguments=arguments)
        self.assertEqual(1, len(executed))

    def test_the_other_commands_are_sent_as_before(self):
        qmp, executed = self.qmp()
        qmp.command('query-status', 5)
        self.assertEqual([('query-status', None)], executed)
        with self.assertRaisesRegex(ValueError, 'unsupported-qmp-command'):
            qmp.command('human-monitor-command', 5)


if __name__ == '__main__':
    unittest.main()
