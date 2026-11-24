"""Stage 10c: Windows Lockdown suite and controller power_cycle, offline.

Tests cover the Lockdown catalog and check-ID parity with `run-windows-lockdown.ps1`, QGA payload
size ceilings for 72 checks, configuration and CLI validation, `run_state` / `resources` / `diagnostics`
power-cut extensions, framing-aware `_WireRelay` survival across abrupt `test` disconnect,
`lifecycle.Vm.power_cycle()`, and full multi-boot synthetic two-machine execution (1 clean reboot +
6 abrupt power cuts -> 8 distinct `win-*` boot IDs).
"""

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import socket
import struct
import tempfile
import tomllib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.vm.matrix import (cli, config as matrix_config, diagnostics, lab, lab_protocol as wire,
                             lifecycle, qga, report as matrix_report, resources, run_state,
                             windows_list_guest as guest, windows_list_lab, windows_lockdown as lockdown,
                             windows_results, windows_smoke)
from tools.vm.matrix.catalog import digest, read_catalog
from tools.vm.matrix.tests.posix_only import controller_only
from tools.vm.matrix.tests.test_lab import ip_frame, tcp, udp
from tools.vm.matrix.tests.test_lab_windows import health
from tools.vm.matrix.tests.test_windows_failure import syn6
from tools.vm.matrix.tests.test_windows_lab import HEX, marker_rows, request_arp
from tools.vm.matrix.tests.test_windows_list_lab import BOOT, RUN, UUID, ListFlow, ListMachines, syn

EXAMPLE = Path(__file__).resolve().parents[1] / 'execution-windows-lockdown.example.toml'


def plan_files():
    rows = [dict(name=name, sha256=hashlib.sha256(name.encode()).hexdigest(), size=10 + n, pinned=True)
            for n, name in enumerate(guest.BINARIES)]
    rows += [dict(name=name, sha256=hashlib.sha256(name.encode()).hexdigest(), size=20, pinned=False)
             for name in (guest.PLAN_FILE, *lockdown.SCRIPTS)]
    return rows


def windows_for(case, run=RUN):
    return [(wire.window_marker(run, index, 'open', label), wire.window_marker(run, index, 'close', label))
            for index, label in enumerate(case.labels)]


class CatalogAndPlanTests(unittest.TestCase):
    def test_catalog_slices_match_runner_check_ids_and_counts(self):
        runner = (Path(matrix_config.LOCKDOWN_CATALOG).parent / 'guest' / lockdown.ENTRY).read_text(encoding='utf-8')
        full = lockdown.Case('full', power_cut_repeats=3)
        core = lockdown.Case('core', power_cut_repeats=0)
        reboot3 = lockdown.Case('reboot', power_cut_repeats=3)
        reboot1 = lockdown.Case('reboot', power_cut_repeats=1)
        self.assertEqual(72, len(full.checks))
        self.assertEqual(57, len(core.checks))
        self.assertEqual(24, len(reboot3.checks))
        self.assertEqual(18, len(reboot1.checks))
        self.assertEqual((1, 6, True), (full.planned_reboots, full.planned_power_cuts, full.multi_boot))
        self.assertEqual((0, 0, False), (core.planned_reboots, core.planned_power_cuts, core.multi_boot))
        self.assertEqual((1, 2, True), (reboot1.planned_reboots, reboot1.planned_power_cuts, reboot1.multi_boot))
        for check in full.checks:
            if check.startswith('cut.pass-'):
                suffix = check.split('.', 2)[2]
                self.assertIn(f'"cut.pass-$pass.{suffix}"', runner)
            else:
                self.assertIn(f"-Id '{check}'", runner)

    def test_job_plan_and_scripts_fit_qga_and_collect_limits(self):
        plain = wire.dns_checks(RUN, lambda: '1' * 24)['plain']
        case = lockdown.Case('full', power_cut_repeats=3, power_cut_delay_seconds=2)
        plan = case.plan_document(RUN, windows_for(case, RUN), plain, 8388, plan_files())
        self.assertEqual(lockdown.PREFIX + 'job.v1', plan['schema'])
        self.assertEqual(('full', 3, 2), (plan['case'], plan['power_cut_repeats'], plan['power_cut_delay_seconds']))
        self.assertEqual(case.catalog, plan['catalog'])
        self.assertNotIn('config', plan)
        self.assertEqual(('baseline', 'lockdown-core', 'reboot-lockdown', 'recovery'), case.labels)
        for index, label in enumerate(case.labels):
            for word in ('open', 'close'):
                self.assertEqual(f'rosetun-lab-marker:{RUN}.{index}.{word}.{label}', plan['markers'][label][word])
        script = case.start_script(plan_files())
        self.assertLess(len(script), 6000)
        self.assertIn(lockdown.ROOT, script)
        self.assertIn(lockdown.TASK, script)
        self.assertIn(lockdown.ENTRY, script)
        self.assertTrue(guest.script_limit_ok(case.collect_script()) and guest.script_limit_ok(case.after_script()))

        # Verify worst-case 72-check collected payload and status.json fit comfortably inside QGA limits.
        identity = dict(run_id='11111111-2222-4333-8444-555555555555', vm_id=UUID, boot_id='win-10')
        rec_plan = dict(schema=lockdown.PREFIX + 'plan.v1', suite='windows-lockdown', profile='exploratory',
                        policy=dict(mode='exploratory'), identity=identity, catalog=case.catalog,
                        catalog_digest=digest(case.catalog))
        events = [dict(schema=lockdown.PREFIX + 'event.v1', run_id=identity['run_id'], sequence=i + 1,
                       id=cid, result='PASS', reason='checked') for i, cid in enumerate(case.checks)]
        report = dict(schema=lockdown.PREFIX + 'report.v1', identity=identity, boot_id_at_end='win-17',
                      checks=events, summary=dict(total=len(events), pass_=0, **{'pass': len(events), 'fail': 0, 'skip': 0}),
                      cleanup=dict(status='PASS'), errors=[])
        report['summary'].pop('pass_')
        rec_status = dict(schema=lockdown.PREFIX + 'status.v1', identity=identity, state='finished', event_count=len(events))
        payload = json.dumps(dict(
            plan=json.dumps(rec_plan, separators=(',', ':')),
            events=''.join(json.dumps(e, separators=(',', ':')) + '\n' for e in events),
            report=json.dumps(report, separators=(',', ':')),
            status=json.dumps(rec_status, separators=(',', ':')),
            helper_tail='x' * 3000,
            identity=dict(uuid=UUID),
        ), separators=(',', ':'))
        self.assertLess(len(payload.encode('utf-8')), qga.EXEC_OUTPUT_LIMIT)
        self.assertLess(len(payload.encode('utf-8')), lockdown.COLLECT_ANSWER_LIMIT)
        parsed_collect = case.collected(payload)
        self.assertEqual(UUID, parsed_collect['identity']['uuid'])

        # Verify 72-check runner status.json fits well inside STATUS_ANSWER_LIMIT and validates.
        runner_status = dict(
            schema=guest.STATUS_SCHEMA, run=RUN, state='finished', step='done', sequence=200,
            started_utc='2026-11-23T00:00:00.000Z', updated_utc='2026-11-23T00:15:00.000Z',
            checks=[dict(id=cid, result='PASS', reason='checked', scenario='lockdown', note='ok') for cid in case.checks],
            markers=[dict(label=label, word=word, marker=f'rosetun-lab-marker:{RUN}.{idx}.{word}.{label}',
                          ack=f'rosetun-lab-ack:rosetun-lab-marker:{RUN}.{idx}.{word}.{label}',
                          error=None, utc='2026-11-23T00:01:00.000Z')
                     for idx, label in enumerate(case.labels) for word in ('open', 'close')],
            notes=[dict(name=f'boot-phase-{i}', value=10 + i) for i in range(8)],
            cleanup=dict(result='PASS', parts=dict(service='PASS', firewall='PASS', helper='PASS', tasks='PASS',
                                                   standard_user='PASS', adapter='PASS', work='PASS', binaries='PASS')),
            error=None,
        )
        raw_status = json.dumps(runner_status, separators=(',', ':'))
        self.assertLess(len(raw_status.encode('utf-8')), lockdown.STATUS_ANSWER_LIMIT)
        self.assertEqual('finished', case.runner_status(raw_status, RUN)['state'])

    def test_plan_and_report_cli_contract_for_windows_lockdown(self):
        out = io.StringIO()
        with patch.object(cli, 'load_profile', return_value={'mode': 'exploratory'}), contextlib.redirect_stdout(out):
            self.assertEqual(0, cli.main(['plan', 'windows-lockdown', '--config', 'profiles.toml', '--profile', 'exploratory']))
        planned = json.loads(out.getvalue())
        self.assertEqual(('rosetun.matrix.plan.v1', 'windows-lockdown'), (planned['schema'], planned['suite']))
        self.assertEqual(digest(read_catalog(matrix_config.LOCKDOWN_CATALOG)), planned['catalog_digest'])
        with self.assertRaisesRegex(ValueError, 'requires the guest journal and independent lab evidence'):
            matrix_report.assess({}, {}, planned)


class ConfigTests(unittest.TestCase):
    def example(self):
        with EXAMPLE.open('rb') as stream:
            config = tomllib.load(stream)
        config['state_directory'] = str(Path(__file__).resolve().parent / 'state')
        return config

    def test_example_validates_all_cases_and_rejects_invalid_power_cut_combinations(self):
        for case_name, repeats in (('full', 3), ('full', 1), ('core', 0), ('reboot', 2)):
            config = self.example()
            config['lockdown']['case'] = case_name
            config['lockdown']['power_cut_repeats'] = repeats
            with patch.object(windows_smoke, '_state_path', create=True), patch.object(windows_list_lab, '_state_path'):
                validated = windows_smoke.validate(config)
            self.assertEqual(('windows-lockdown', lockdown.SCHEMA, case_name, repeats),
                             (validated['suite'], validated['schema'], validated['lockdown']['case'],
                              validated['lockdown']['power_cut_repeats']))
        for bad in (
            lambda c: c['lockdown'].update(case='unknown'),
            lambda c: c['lockdown'].update(case='core', power_cut_repeats=1),
            lambda c: c['lockdown'].update(case='full', power_cut_repeats=0),
            lambda c: c['lockdown'].update(case='full', power_cut_repeats=4),
            lambda c: c['lockdown'].update(power_cut_delay_seconds=-1),
            lambda c: c['lockdown'].update(power_cut_delay_seconds=16),
            lambda c: c['lockdown'].update(power_cut_repeats=True),
            lambda c: c.update(list=dict(c['lockdown'])),
            lambda c: c.update(failure=dict(c['lockdown'])),
            lambda c: c.update(suite='windows-failure'),
        ):
            config = self.example()
            bad(config)
            with patch.object(windows_list_lab, '_state_path'), self.assertRaises(ValueError):
                lockdown.validate(config)

    def test_cli_dry_run_and_flag_refusals(self):
        out = io.StringIO()
        with patch.object(windows_smoke, '_state_path', create=True), patch.object(windows_list_lab, '_state_path'), \
                patch.object(windows_smoke, 'load', side_effect=lambda path: windows_smoke.validate(self.example())), \
                patch.object(lockdown, 'preflight', return_value={'suite': 'windows-lockdown', 'case': 'full'}) as plan, \
                contextlib.redirect_stdout(out):
            self.assertEqual(0, cli.main(['run', 'windows-lockdown', '--config', 'x', '--dry-run']))
            plan.assert_called_once()
            for flags in (['--lab'], ['--control', 'stop-helper'], ['--diagnostic']):
                self.assertEqual(2, cli.main(['run', 'windows-lockdown', '--config', str(EXAMPLE), *flags]))


class RunStateAndDiagnosticsTests(unittest.TestCase):
    def test_run_state_limits_and_boot_chain_scale_for_planned_power_cuts(self):
        # Zero power cuts must leave every existing budget completely unchanged.
        for name, base in run_state.BUDGETS.items():
            self.assertEqual(base, run_state.limit(name, 0, 0))
        self.assertEqual(run_state.BUDGETS['qga_recoveries'] + 7, run_state.limit('qga_recoveries', 1, 6))
        self.assertEqual(run_state.BUDGETS['qmp_calls'] + 96, run_state.limit('qmp_calls', 1, 6))
        self.assertEqual(run_state.BUDGETS['qmp_events'] + 48, run_state.limit('qmp_events', 1, 6))
        self.assertEqual(run_state.BUDGETS['qga_observations'] + 96, run_state.limit('qga_observations', 1, 6))
        with self.assertRaises(ValueError):
            run_state.limit('qga_recoveries', 0, run_state.MAX_PLANNED_POWER_CUTS + 1)

    @controller_only
    def test_run_state_boot_chain_allows_8_boots_with_planned_power_cuts(self):
        with tempfile.TemporaryDirectory() as tmp:
            lease = resources.StandLease(tmp, 'stand-rs')
            lease.acquire()
            try:
                run = resources.create_run(lease, 'run-rs')
                run.register(run_state.RESOURCE)
                st = run_state.RunState.create(run, boot_id='win-10')
                st.planned_reboots = 1
                st.planned_power_cuts = 6
                st.update('collected', planned_power_cuts=6)
                for i in range(1, 8):
                    st.extend_boot_chain(f'win-{10 + i}')
                reloaded = run_state.RunState.load(run)
                self.assertEqual(8, len(reloaded.document['boot_chain']))
                self.assertEqual(6, reloaded.document['collected']['planned_power_cuts'])
                bad = dict(reloaded.document, boot_chain=list(reloaded.document['boot_chain']) + ['win-99'])
                run_id, stand_id, token = run._identity
                with self.assertRaises(run_state.RunStateError):
                    run_state.validate(bad, run_id=run_id, stand_id=stand_id, token=token)
            finally:
                lease.release()

    def test_stderr_sink_append_mode_preserves_previous_boots_and_ceiling(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'qemu-stderr.log'
            s1 = diagnostics.StderrSink(log, 'secret-token', limit=20)
            s1.feed(b'boot-one\n', final=True)
            s1.close()
            s2 = diagnostics.StderrSink(log, 'secret-token', limit=20, append=True)
            s2.feed(b'boot-two\n')
            s2.feed(b'overflow-bytes', final=True)
            s2.close()
            self.assertTrue(s2.overflow)
            content = log.read_bytes()
            self.assertEqual(20, len(content))
            self.assertTrue(content.startswith(b'boot-one\nboot-two\n'))


class WireRelayTests(unittest.TestCase):
    @controller_only
    def test_relay_forwards_frames_drops_truncated_frame_on_sigkill_and_reconnects(self):
        lab_peer, lab_relay_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        test_peer1, test_relay_end1 = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        relay = lab._WireRelay(lab_relay_end, test_relay_end1)
        try:
            frame1 = b'hello-from-test-1'
            test_peer1.sendall(struct.pack('>I', len(frame1)) + frame1)
            hdr = lab_peer.recv(4)
            self.assertEqual(len(frame1), struct.unpack('>I', hdr)[0])
            self.assertEqual(frame1, lab_peer.recv(len(frame1)))

            frame2 = b'hello-from-lab-1'
            lab_peer.sendall(struct.pack('>I', len(frame2)) + frame2)
            hdr = test_peer1.recv(4)
            self.assertEqual(len(frame2), struct.unpack('>I', hdr)[0])
            self.assertEqual(frame2, test_peer1.recv(len(frame2)))

            # Simulate SIGKILL of test QEMU mid-frame: write length=50 and only 5 bytes, then close.
            test_peer1.sendall(struct.pack('>I', 50) + b'12345')
            test_peer1.close()

            # Attach replacement test socketpair (after power_cycle) and verify stream stays framed!
            test_peer2, test_relay_end2 = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                relay.attach_test(test_relay_end2)
                frame3 = b'hello-after-power-cycle'
                test_peer2.sendall(struct.pack('>I', len(frame3)) + frame3)
                lab_peer.settimeout(3.0)
                hdr = lab_peer.recv(4)
                self.assertEqual(len(frame3), struct.unpack('>I', hdr)[0])
                self.assertEqual(frame3, lab_peer.recv(len(frame3)))

                frame4 = b'reply-after-power-cycle'
                lab_peer.sendall(struct.pack('>I', len(frame4)) + frame4)
                test_peer2.settimeout(3.0)
                hdr = test_peer2.recv(4)
                self.assertEqual(len(frame4), struct.unpack('>I', hdr)[0])
                self.assertEqual(frame4, test_peer2.recv(len(frame4)))
            finally:
                test_peer2.close()
        finally:
            relay.close()
            lab_peer.close()


def _proc_record(identifier, pid, executable='qemu-system-x86_64'):
    return dict(id=identifier, kind='process', pid=pid, platform='posix',
                boot_id='host-boot-1', start_id=str(pid * 10), executable=executable)


class ResourcesAndPowerCycleTests(unittest.TestCase):
    @controller_only
    def test_prepared_run_registers_numbered_processes_while_running(self):
        with tempfile.TemporaryDirectory() as tmp:
            lease = resources.StandLease(tmp, 'stand-10c')
            lease.acquire()
            try:
                run = resources.create_run(lease, 'run-10c')
                for fid, name in (('lifecycle', 'lifecycle.jsonl'), ('completion', 'completion.json'),
                                  ('qemu-stderr', 'qemu-stderr.log'), ('launch-plan', 'launch-plan.json'),
                                  ('preparation', 'preparation.jsonl'), ('root', 'root.qcow2')):
                    run.register({'id': fid, 'kind': 'file', 'path': name})
                    if name != 'completion.json':
                        (run.directory / name).write_text('', encoding='utf-8')
                (run.directory / 'launch-plan.json').write_text(
                    json.dumps({'uuid': UUID, 'config': {'qga': False}}), encoding='utf-8')
                rows = [
                    dict(schema='rosetun.matrix.lifecycle.v2', sequence=1, action='exit', result='child-reaped',
                         utc='2026-11-23T00:00:00+00:00', run_id='run-10c', stand_id='stand-10c', vm_uuid=UUID),
                    dict(schema='rosetun.matrix.lifecycle.v2', sequence=2, action='completion',
                         result='controls-closed-child-reaped',
                         utc='2026-11-23T00:00:01+00:00', run_id='run-10c', stand_id='stand-10c', vm_uuid=UUID),
                ]
                (run.directory / 'lifecycle.jsonl').write_text(
                    ''.join(json.dumps(r) + '\n' for r in rows), encoding='utf-8')
                p_qemu = _proc_record('qemu', 100)
                p_swtpm = _proc_record('swtpm', 101, 'swtpm')
                p_swtpm1 = _proc_record('swtpm-1', 102, 'swtpm')
                p_qemu1 = _proc_record('qemu-1', 103)
                run.register(p_qemu)
                run.register(p_swtpm)
                run.mark('prepared')
                run.mark('starting')
                run.mark('running')
                run.register(p_swtpm1)
                run.register(p_qemu1)
                with self.assertRaises(ValueError):
                    run.register(_proc_record('other-1', 104, 'other'))
                run.mark('stopping')
                run.mark('exited')
                exits = [{'resource': r, 'returncode': code}
                         for r, code in ((p_qemu, -9), (p_swtpm, 0), (p_swtpm1, 0), (p_qemu1, 0))]
                run._complete(exits, UUID)
                self.assertTrue(resources.completion_verified(run.directory, run._read()))
            finally:
                lease.release()

    @controller_only
    def test_vm_power_cycle_replaces_qemu_and_swtpm_and_enforces_budget(self):
        class FakeProc:
            def __init__(self, pid):
                self.pid = pid
                self.returncode = None
                self.killed = False
                self.terminated = False
                self.stderr = io.BytesIO(b'')

            def poll(self):
                return self.returncode

            def kill(self):
                self.killed = True
                self.returncode = -9

            def terminate(self):
                self.terminated = True
                self.returncode = 0

            def wait(self, timeout=None):
                return self.returncode

        class FakeQmp:
            def __init__(self, *args, **kwargs):
                self.closed = False

            def handshake(self, timeout=None):
                return None

            def command(self, name, timeout=None, **kwargs):
                if name == 'query-uuid':
                    return {'UUID': UUID}
                if name == 'query-kvm':
                    return {'enabled': True, 'present': True}
                if name == 'query-status':
                    return {'status': 'prelaunch', 'running': False}
                return {}

            def close(self):
                self.closed = True

        class FakeQga:
            def __init__(self, *args, **kwargs):
                self.closed = False

            def close(self):
                self.closed = True

        class FakeLab:
            reconnectable = True

            def __init__(self):
                self.reconnects = 0
                self.releases = 0

            def reconnect_network(self, run, *, adapter=False):
                self.reconnects += 1
                return ['-netdev', 'stream,id=labwire,addr.type=fd,addr.str=99,server=off'], 99

            def release_child(self, run):
                self.releases += 1

        with tempfile.TemporaryDirectory() as tmp:
            lease = resources.StandLease(tmp, 'stand-pc')
            lease.acquire()
            try:
                run = resources.create_run(lease, 'run-pc')
                run.register(run_state.RESOURCE)
                run.register({'id': 'lifecycle', 'kind': 'file', 'path': 'lifecycle.jsonl'})
                run.register({'id': 'qemu-stderr', 'kind': 'file', 'path': 'qemu-stderr.log'})
                (run.directory / 'lifecycle.jsonl').write_text('', encoding='utf-8')
                (run.directory / 'qemu.qmp').write_text('', encoding='utf-8')
                (run.directory / 'qemu.qga').write_text('', encoding='utf-8')
                (run.directory / 'swtpm.sock').write_text('', encoding='utf-8')
                run.register(_proc_record('swtpm', 10, 'swtpm'))
                run.register(_proc_record('qemu', 11))
                run.mark('prepared')
                run.mark('starting')
                run.mark('running')
                st = run_state.RunState.create(run, boot_id='win-1')
                fake_lab = FakeLab()
                old_qemu = FakeProc(11)
                old_swtpm = FakeProc(10)
                new_qemu = FakeProc(21)
                new_swtpm = FakeProc(20)
                old_sink = diagnostics.StderrSink(run.directory / 'qemu-stderr.log', run._identity[2])
                old_sink.feed(b'boot-1\n', final=True)
                vm = lifecycle.Vm(run, 10)
                vm.process = old_qemu
                vm.swtpm = old_swtpm
                vm.windows = True
                vm.qmp = FakeQmp()
                vm.qga = FakeQga()
                vm.stderr = old_sink
                vm.vm_uuid = UUID
                vm.state = st
                vm.boot_chain = ['win-1']
                vm.last_boot_id = 'win-1'
                vm._processes = {'qemu': old_qemu, 'swtpm': old_swtpm}
                vm._launch = dict(
                    base_argv=['qemu'], qmp_socket=run.directory / 'qemu.qmp',
                    qga_socket=run.directory / 'qemu.qga', qga_argv=['-chardev', 'qga'],
                    config=SimpleNamespace(executable='qemu-system-x86_64', qga=True),
                    windows=True, swtpm_argv=['swtpm'], swtpm_executable='swtpm',
                    tpm_socket=run.directory / 'swtpm.sock', lab=fake_lab)
                lease._active.add(vm)
                vm.planned_power_cuts = 1

                def fake_start_swtpm(argv, executable, path, identifier='swtpm'):
                    vm.swtpm = new_swtpm
                    vm.swtpm_done = False
                    run.register(_proc_record(identifier, new_swtpm.pid, executable))
                    vm._processes[identifier] = new_swtpm

                with patch.object(vm, '_start_swtpm', side_effect=fake_start_swtpm), \
                        patch.object(lifecycle.subprocess, 'Popen', return_value=new_qemu), \
                        patch.object(lifecycle, '_open_control', return_value=SimpleNamespace(close=lambda: None)), \
                        patch.object(vm, '_new_qmp', return_value=FakeQmp()), \
                        patch.object(vm, '_new_qga', side_effect=lambda: setattr(vm, 'qga', FakeQga())), \
                        patch.object(lifecycle, '_identity',
                                     side_effect=lambda proc, exe, identifier='qemu': _proc_record(identifier, proc.pid, exe)):
                    vm.power_cycle()
                self.assertTrue(old_qemu.killed)
                self.assertEqual(1, vm.power_cycles)
                self.assertEqual(1, fake_lab.reconnects)
                self.assertEqual(1, fake_lab.releases)
                self.assertIs(new_qemu, vm.process)
                self.assertIs(new_swtpm, vm.swtpm)
                self.assertIn('qemu-1', vm._processes)
                self.assertIn('swtpm-1', vm._processes)
                self.assertEqual('power-cycle', vm.reset_kind)
                self.assertTrue(vm.reset_pending)
                # Clear reset_pending to simulate boot confirmation, then verify 2nd power_cycle exceeds budget.
                vm.reset_pending = False
                with self.assertRaises(lifecycle.LifecycleError):
                    vm.power_cycle()
                vm.stderr.close()
                lease._active.discard(vm)
            finally:
                lease.release()

    def test_attach_selects_latest_power_cycle_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            lease = resources.StandLease(directory, 'stand-pc-attach')
            lease.acquire()
            try:
                run = resources.create_run(lease, 'run-pc-attach')
                run.register(run_state.RESOURCE)
                run.register({'id': 'lifecycle', 'kind': 'file', 'path': 'lifecycle.jsonl'})
                run.register({'id': 'qmp-socket', 'kind': 'socket', 'path': 'qemu.qmp'})
                (run.directory / 'lifecycle.jsonl').write_text('', encoding='utf-8')
                (run.directory / 'launch-plan.json').write_text(
                    json.dumps({'uuid': UUID, 'windows_run': True}), encoding='utf-8')
                for gen_suffix, base_pid in (('', 10), ('-1', 20), ('-2', 30)):
                    run.register(_proc_record('swtpm' + gen_suffix, base_pid, 'swtpm'))
                    run.register(_proc_record('qemu' + gen_suffix, base_pid + 1, 'qemu-system-x86_64'))
                run.mark('prepared')
                run.mark('starting')
                run.mark('running')
                run_state.RunState.create(run, boot_id='win-1')

                selected = []

                class FakeForeign:
                    def __init__(self, record):
                        self.record = record
                        self.pid = record['pid']
                        selected.append((record['id'], record['pid']))

                    def poll(self):
                        return None

                class FakeAttachQmp:
                    def handshake(self, timeout):
                        return None

                    def command(self, name, args=None, *, timeout=5):
                        if name == 'query-uuid':
                            return {'UUID': UUID}
                        return {'status': 'running'}

                    def drain(self):
                        return []

                    def close(self):
                        return None

                with patch.object(lifecycle, 'ForeignProcess', FakeForeign), \
                        patch.object(lifecycle, '_open_control', return_value=SimpleNamespace(close=lambda: None)), \
                        patch.object(lifecycle.Vm, '_new_qmp', return_value=FakeAttachQmp()), \
                        patch.object(lifecycle, 'socket_path', side_effect=lambda root, name: root / name):
                    vm = lifecycle.attach(run, timeout=5)
                try:
                    self.assertEqual([('qemu-2', 31), ('swtpm-2', 30)], selected)
                    self.assertEqual(31, vm.process.pid)
                    self.assertEqual(30, vm.swtpm.pid)
                finally:
                    vm._release_control_lock()
                    lease._active.discard(vm)
            finally:
                lease.release()



class LockdownMachines(ListMachines):
    """Two-machine fake for single-boot and multi-boot Windows Lockdown runs."""

    def __init__(self, test, *, case='full', repeats=3, delay=2, core_direct=1, reboot_direct=0,
                 after_left=(), truncate_boot_chain=False, **kwargs):
        self.case = lockdown.Case(case, power_cut_repeats=repeats, power_cut_delay_seconds=delay)
        self.core_direct = core_direct
        self.reboot_direct = reboot_direct
        self.after_left = tuple(after_left)
        self.truncate_boot_chain = truncate_boot_chain
        super().__init__(test, session_direct=0, **kwargs)
        self.boot_counter = 10
        self.boot_chain = [f'win-{self.boot_counter}']
        self.poll_states = ['running']
        if self.case.planned_reboots:
            self.poll_states.append('reboot-requested')
        for _ in range(self.case.planned_power_cuts):
            self.poll_states.append('power-cut-requested')
        self.poll_states.append('finished')

    def results_of(self):
        return self.results or {check: 'PASS' for check in self.case.checks}

    def status(self, state, seq):
        error = self.runner_error if state in guest.ENDED else None
        results = self.results_of()
        rows = []
        for check in self.case.checks:
            result = results.get(check, 'SKIP')
            reason = 'checked' if result == 'PASS' else 'condition-false' if result == 'FAIL' else 'interrupted'
            rows.append(dict(id=check, result=result, reason=reason, scenario='lockdown', note='ok'))
        acks = []
        for label, (opening, closing) in zip(self.case.labels, windows_for(self.case, self.lab_id)):
            for word, marker in (('open', opening), ('close', closing)):
                text = wire.marker_query(marker).decode()
                acks.append(dict(label=label, word=word, marker=text,
                                 ack=wire.ACK_PREFIX + text if self.markers else None,
                                 error=None, utc='2026-11-23T00:10:00.000Z'))
        return dict(schema=guest.STATUS_SCHEMA, run=self.lab_id, state=state,
                    step='done' if state in guest.ENDED else state, sequence=seq,
                    started_utc='2026-11-23T00:00:00.000Z', updated_utc='2026-11-23T00:12:00.000Z',
                    checks=rows, markers=acks,
                    notes=[dict(name='sing-box-first-launch-seconds', value=2)],
                    cleanup=None if (self.cleanup is None or state not in guest.ENDED) else
                    dict(result=self.cleanup, parts=dict(service='PASS', firewall='PASS', helper='PASS', tasks='PASS',
                                                         standard_user='PASS', adapter='PASS', work='PASS', binaries='PASS')),
                    error=error)

    def program(self, path, arguments):
        self.programs.append((path, list(arguments)))
        self.test.assertEqual((guest.CMD, ['/c', 'type', lockdown.ROOT + r'\status.json']), (path, list(arguments)))
        self.polls += 1
        if self.polls == 1:
            return SimpleNamespace(exitcode=1, stdout=b'', stderr=b'')
        idx = min(self.polls - 2, len(self.poll_states) - 1)
        state = self.poll_states[idx]
        self.events.append(('poll', self.polls, state))
        return SimpleNamespace(exitcode=0, stdout=json.dumps(self.status(state, 10 + idx * 5)).encode(), stderr=b'')

    def recorded_files(self):
        initial_boot = self.boot_chain[0]
        end_boot = self.boot_chain[-1]
        identity = dict(run_id='11111111-2222-4333-8444-555555555555', vm_id=self.uuid or UUID, boot_id=initial_boot)
        plan = dict(schema=lockdown.PREFIX + 'plan.v1', suite='windows-lockdown', profile='exploratory',
                    policy=dict(mode='exploratory'), identity=identity, catalog=self.case.catalog,
                    catalog_digest=digest(self.case.catalog))
        events = []
        for check in self.case.checks:
            result = self.results_of().get(check, 'SKIP')
            reason = 'checked' if result == 'PASS' else 'condition-false' if result == 'FAIL' else 'interrupted'
            events.append(dict(schema=lockdown.PREFIX + 'event.v1', run_id=identity['run_id'],
                               sequence=len(events) + 1, id=check, result=result, reason=reason))
        counts = {name: sum(1 for e in events if e['result'] == name) for name in ('PASS', 'FAIL', 'SKIP')}
        report = dict(schema=lockdown.PREFIX + 'report.v1', identity=identity, boot_id_at_end=end_boot, checks=events,
                      summary={'total': len(events), 'pass': counts['PASS'], 'fail': counts['FAIL'], 'skip': counts['SKIP']},
                      cleanup=dict(status=self.cleanup), errors=[])
        status = dict(schema=lockdown.PREFIX + 'status.v1', identity=identity, state='finished', event_count=len(events))
        return dict(plan=json.dumps(plan), events=''.join(json.dumps(e) + '\n' for e in events),
                    report=json.dumps(report), status=json.dumps(status))

    def powershell(self, script):
        if 'medium-not-found' in script:
            self.note('guest-start')
            wanted = json.loads(re.search(r"ConvertFrom-Json '([^']*)'", script)[1])
            for name, digest_hex in wanted.items():
                if hashlib.sha256(self.disc[name]).hexdigest() != digest_hex:
                    raise AssertionError('disc digest mismatch')
            return json.dumps(dict(medium='E:\\', files=len(wanted), task=lockdown.TASK))
        if 'lockdown_wfp_provider' in script:
            self.note('guest-after')
            state = dict(wfp_provider=False, wfp_sublayer=False, runner_task=False, helper_task=False,
                         helper_process=False, engine_process=False, tunnel_adapter=False,
                         binaries=False, list_directory=False, root_removed=True,
                         lockdown_wfp_provider=False, lockdown_wfp_sublayer=False,
                         lockdown_service=False, resume_task=False, boot_check_task=False, matrix_user=False)
            for item in self.after_left:
                if item == 'root_directory':
                    state['root_removed'] = False
                else:
                    state[item] = True
            return json.dumps(state)
        return super().powershell(script)

    def served(self):
        return [(index, word, label) for index, label in enumerate(self.case.labels) for word in ('open', 'close')]

    def frames(self):
        lab_id, rows = self.lab_id, [(1.0, request_arp())]
        plain = wire.dns_checks(lab_id, lambda: '0' * 24)['plain']
        plain['nonce'] = re.search(r'\.([0-9a-f]{24})\.lab\.test', self.plain['name'])[1]
        t = 10.0
        for index, label in enumerate(self.case.labels):
            rows += marker_rows(index, 'open', label, t, lab_id)
            t += 1.0
            if label in ('baseline', 'recovery'):
                rows += syn(51000 + index, wire.TARGETS[4], 443, at=t)
                rows += syn6(51500 + index, wire.TARGETS[6], wire.PORTS['http'], at=t + 0.1)
                q = wire.query(plain)
                rows.append((t + 0.2, ip_frame(wire.CLIENTS[4], wire.RESOLVER, 17, udp(52000 + index, 53, q))))
                rows.append((t + 0.25, ip_frame(wire.RESOLVER, wire.CLIENTS[4], 17, udp(53, 52000 + index, q),
                                                src=wire.MACS['lab'], dst=wire.MACS['test'])))
            elif label == 'lockdown-core':
                rows += syn(53000, wire.GATEWAYS[4], 8388, at=t)
                for n in range(self.core_direct):
                    rows += syn(54000 + n, wire.TARGETS[4], 443, at=t + 0.1 + n * 0.05)
            elif label == 'reboot-lockdown':
                rows += syn(55000, wire.GATEWAYS[4], 8388, at=t)
                for n in range(self.reboot_direct):
                    rows += syn(56000 + n, wire.TARGETS[4], 443, at=t + 0.1 + n * 0.05)
            t += 5.0
            rows += marker_rows(index, 'close', label, t, lab_id)
            t += 5.0
        return rows, plain

    def artifact(self, name):
        _, plain = self.frames()
        if name == 'health.json':
            return json.dumps(health(self.served(), node=dict(alive_at_finish=True, exit_code=0))).encode()
        if name == 'https.json':
            counts = [dict(source=source, method='GET', path_class='root', count=2)
                      for source in (wire.CLIENTS[4], wire.EGRESS)]
            return json.dumps([dict(kind='counts', counts=counts, rows_dropped=0, counts_dropped=0)]).encode()
        if name == 'dns.json':
            rows = [dict(source=wire.EGRESS, transport='doh', name='listed.lab.test', type='A')]
            for phase in ('baseline', 'recovery'):
                qname = self.case.control_name(plain, phase)
                for transport in ('udp', 'tcp'):
                    rows.append(dict(source=wire.CLIENTS[4], transport=transport, name=qname, type='A'))
            return json.dumps(rows).encode()
        return b'[]'

    def adapters(self):
        adapters = super().adapters()
        original = adapters.start
        machines = self

        def start(run, lab=None):
            vm = original(run, lab=lab)
            if vm.role == 'test':
                vm.boot_chain = list(machines.boot_chain)
                vm.last_boot_id = machines.boot_chain[-1]
                vm.guest_resets = 0
                vm.power_cycles = 0

                def request_guest_reboot():
                    machines.events.append(('guest-reboot', vm.guest_resets + 1))

                def wait_guest_reset(timeout, clock, sleep):
                    vm.guest_resets += 1

                def power_cycle():
                    vm.power_cycles += 1
                    machines.events.append(('power-cycle', vm.power_cycles))

                def await_rebooted_guest(**kwargs):
                    if not machines.truncate_boot_chain:
                        machines.boot_counter += 1
                        boot_id = f'win-{machines.boot_counter}'
                        machines.boot_chain.append(boot_id)
                        vm.boot_chain.append(boot_id)
                        vm.last_boot_id = boot_id

                vm.request_guest_reboot = request_guest_reboot
                vm.wait_guest_reset = wait_guest_reset
                vm.power_cycle = power_cycle
                vm.await_rebooted_guest = await_rebooted_guest
            return vm

        adapters.start = start
        return adapters


@controller_only
class LockdownFlow(ListFlow):
    runs = 0

    def setUp(self):
        super().setUp()
        block = dict(self.config.pop('list'), case='full', power_cut_repeats=3, power_cut_delay_seconds=2,
                     agent_wait_seconds=180, script_seconds=120, runner_seconds=1500, poll_seconds=15)
        self.config.update(schema=lockdown.SCHEMA, suite='windows-lockdown', lockdown=block)

    def run_lockdown(self, *, case='full', repeats=3, delay=2, **changes):
        type(self).runs += 1
        cfg = dict(self.config, stand_id='lockdown-%d' % type(self).runs,
                   state_directory=self.config['state_directory'] + '-ld%d' % type(self).runs,
                   lockdown=dict(self.config['lockdown'], case=case, power_cut_repeats=repeats,
                                 power_cut_delay_seconds=delay))
        machines = LockdownMachines(self, case=case, repeats=repeats, delay=delay, **changes)

        def sleep(seconds):
            self.sleeps.append(seconds)
            self.clock.now += seconds

        def completion(directory, manifest):
            return any(v.run.directory == directory and v.closed for v in machines.vms.values())

        image = SimpleNamespace(identifier='windows-test', sha256=HEX, validate=lambda directory: None)
        with patch.object(__import__('socket'), 'AF_UNIX', 1, create=True), \
                patch.object(lockdown.Case, 'preflight', return_value={}), \
                patch.object(windows_list_lab, 'preflight', return_value={}), \
                patch.object(windows_list_lab, 'SING_BOX_SHA256', self.pins['sing-box.exe']), \
                patch.object(windows_list_lab, 'load_windows_descriptor', return_value=image), \
                patch.object(windows_list_lab, 'completion_verified', side_effect=completion), \
                patch.object(windows_list_lab.windows_lab, 'completion_verified', side_effect=completion), \
                patch.object(windows_list_lab.windows_reboot, 'record',
                             side_effect=lambda vm, operation, **fields: machines.recorded.append((operation, fields))):
            return lockdown.run(cfg, adapters=machines.adapters(), clock=lambda: self.clock.now,
                                sleep=sleep, progress=lambda stage: None), machines

    def test_full_multi_boot_lockdown_run_accepts_with_8_distinct_boots(self):
        result, _ = self.run_lockdown(case='full', repeats=3, delay=2)
        section = result['execution']
        self.assertEqual(0, result['exit_code'], (section['findings'], section['unverified'], result['errors']))
        self.assertTrue(section['accepted'])
        self.assertEqual([], section['findings'])
        self.assertEqual([], section['unverified'])
        self.assertEqual(8, len(section['boot_chain']))
        self.assertEqual(8, len(set(section['boot_chain'])))
        self.assertEqual((1, 6), (section['guest_resets'], section['power_cycles']))
        self.assertEqual('EXPECTED', section['windows']['lockdown-core']['verdict'])
        self.assertEqual('EXPECTED', section['windows']['reboot-lockdown']['verdict'])
        self.assertEqual('UNVERIFIED', section['full_matrix'])

    def test_core_single_boot_lockdown_run_accepts(self):
        result, _ = self.run_lockdown(case='core', repeats=0, delay=0)
        section = result['execution']
        self.assertEqual(0, result['exit_code'], (section['findings'], section['unverified'], result['errors']))
        self.assertTrue(section['accepted'])
        self.assertEqual(1, len(section['boot_chain']))
        self.assertEqual((0, 0), (section['guest_resets'], section['power_cycles']))

    def test_leak_in_reboot_lockdown_window_fails_with_exit_1(self):
        result, _ = self.run_lockdown(case='reboot', repeats=1, delay=1, reboot_direct=1)
        section = result['execution']
        self.assertEqual(1, result['exit_code'])
        self.assertIn('window-detected:reboot-lockdown', section['findings'])

    def test_lockdown_leftovers_fail_cleanup_check_with_exit_1(self):
        result, _ = self.run_lockdown(case='core', repeats=0, delay=0,
                                      after_left=('lockdown_wfp_provider', 'resume_task', 'matrix_user'))
        section = result['execution']
        self.assertEqual(1, result['exit_code'])
        self.assertTrue(any(f.startswith('cleanup-left:') and 'lockdown_wfp_provider' in f
                            and 'resume_task' in f and 'matrix_user' in f for f in section['findings']))

    def test_incomplete_boot_chain_is_unverified_with_exit_2(self):
        result, _ = self.run_lockdown(case='reboot', repeats=1, delay=1, truncate_boot_chain=True)
        section = result['execution']
        self.assertEqual(2, result['exit_code'])
        self.assertIn('boot-chain-incomplete', section['unverified'])
