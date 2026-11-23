"""Stage 10b: the Failure core suite of a Windows guest in the lab, offline.

Each selected case of the Failure core runs in its own disposable guest with three windows on the wire (`baseline`,
`session` and `recovery`), its own slice of `failure-core.tsv`, and the four physical calibration probes at both ends of
the run. What is tested here is the controller's selection, plan, start script, three-window judgement, control probe
checks, WFP provider/sublayer leftover detection, CLI refusal of `report` without wire evidence, and the full run flow
over the synthetic two-machine harness.
"""

import contextlib
import hashlib
import io
import json
from pathlib import Path
import re
from types import SimpleNamespace
import tomllib
import unittest
from unittest.mock import patch

from tools.vm.matrix import (cli, config as matrix_config, lab, lab_protocol as wire, report as matrix_report,
                             windows_failure as failure, windows_list_guest as guest, windows_list_lab, windows_smoke)
from tools.vm.matrix.catalog import digest, read_catalog
from tools.vm.matrix.tests.posix_only import controller_only
from tools.vm.matrix.tests.test_lab import ip_frame, tcp, udp
from tools.vm.matrix.tests.test_lab_windows import health
from tools.vm.matrix.tests.test_windows_lab import HEX, marker_rows, request_arp
from tools.vm.matrix.tests.test_windows_list_lab import BOOT, RUN, UUID, ListFlow, ListMachines, syn

EXAMPLE = Path(__file__).resolve().parents[1] / 'execution-windows-failure.example.toml'
EXPECTED_COUNTS = {
    'engine-killed': 17,
    'helper-killed': 12,
    'no-network': 15,
    'apply-rules': 14,
    'reconnect': 16,
    'temporary': 18,
    'dns-lock': 12,
}


def plan_files():
    rows = [dict(name=name, sha256=hashlib.sha256(name.encode()).hexdigest(), size=10 + n, pinned=True)
            for n, name in enumerate(guest.BINARIES)]
    rows += [dict(name=name, sha256=hashlib.sha256(name.encode()).hexdigest(), size=20, pinned=False)
             for name in (guest.PLAN_FILE, *failure.SCRIPTS)]
    return rows


def windows_for(run=RUN):
    return [(wire.window_marker(run, index, 'open', label), wire.window_marker(run, index, 'close', label))
            for index, label in enumerate(failure.Case.labels)]


def syn6(client_port, server, port, *, back=True, at=0.0):
    rows = [(at, ip_frame(wire.CLIENTS[6], server, 6, tcp(client_port, port, flags=0x02)))]
    if back:
        rows.append((at + 0.01, ip_frame(server, wire.CLIENTS[6], 6, tcp(port, client_port, flags=0x12),
                                         src=wire.MACS['lab'], dst=wire.MACS['test'])))
    return rows


class CatalogAndPlanTests(unittest.TestCase):
    def test_each_case_selects_its_exact_slice_of_the_failure_core_and_the_runner_names_every_check(self):
        runner = (Path(matrix_config.FAILURE_CATALOG).parent / 'guest' / failure.ENTRY).read_text(encoding='utf-8')
        for name, expected_count in EXPECTED_COUNTS.items():
            case = failure.Case(name)
            self.assertEqual(expected_count, len(case.checks), name)
            self.assertEqual(failure.BASE, case.checks[:4])
            for check in failure.CONNECT:
                self.assertIn(check, case.checks)
            for check in case.checks:
                self.assertIn(f"-Id '{check}'", runner)
        self.assertNotIn('reconnect.state-is-connected-after-engine-kill', failure.Case('reconnect').checks)
        self.assertNotIn('reconnect.no-leak-while-reconnecting', failure.Case('reconnect').checks)
        self.assertNotIn('engine-killed.server-check-works-under-protection', failure.Case('engine-killed').checks)
        self.assertNotIn('dns-lock.server-check-works-with-the-dns-lock', failure.Case('dns-lock').checks)

    def test_the_job_plan_carries_the_three_windows_the_ipv6_addresses_and_the_case_request(self):
        plain = wire.dns_checks(RUN, lambda: '1' * 24)['plain']
        for name in ('engine-killed', 'temporary', 'dns-lock'):
            case = failure.Case(name)
            plan = case.plan_document(RUN, windows_for(RUN), plain, 8388, plan_files())
            self.assertEqual(failure.PREFIX + 'job.v1', plan['schema'])
            self.assertEqual(name, plan['case'])
            self.assertEqual(case.catalog, plan['catalog'])
            self.assertNotIn('config', plan)
            self.assertEqual(dict(client4='192.0.2.2', target4='203.0.113.2', resolver='203.0.113.53',
                                  client6='2001:db8:6a:1::2', target6='2001:db8:6a:2::2', http_port=8080),
                             plan['addresses'])
            self.assertEqual(name != 'dns-lock', plan['request']['settings']['kill_switch'])
            self.assertEqual((False, False, False), (plan['request']['settings']['auto_reconnect'],
                                                     plan['request']['settings']['private_networks'],
                                                     plan['request']['settings']['allow_lan']))
            for index, label in enumerate(case.labels):
                for word in ('open', 'close'):
                    self.assertEqual(f'rosetun-lab-marker:{RUN}.{index}.{word}.{label}', plan['markers'][label][word])

    def test_the_start_script_and_collection_scripts_use_the_failure_root_and_fit_the_qga_limit(self):
        case = failure.Case('engine-killed')
        script = case.start_script(plan_files())
        self.assertLess(len(script), 6000)
        self.assertIn(failure.ROOT, script)
        self.assertIn(failure.TASK, script)
        self.assertIn(failure.ENTRY, script)
        wanted = json.loads(re.search(r"ConvertFrom-Json '([^']*)'", script)[1])
        self.assertEqual({guest.PLAN_FILE, *failure.SCRIPTS}, set(wanted))
        self.assertTrue(guest.script_limit_ok(case.collect_script()) and guest.script_limit_ok(case.after_script()))
        good = json.dumps(dict(medium='E:\\', files=5, task=failure.TASK))
        self.assertEqual('E:\\', case.started(good)['medium'])
        with self.assertRaises(guest.RunnerAnswerError):
            case.started(json.dumps(dict(medium='E:\\', files=5, task=guest.RUNNER_TASK)))

    def test_plan_and_report_cli_contract_for_windows_failure(self):
        out = io.StringIO()
        with patch.object(cli, 'load_profile', return_value={'mode': 'exploratory'}), contextlib.redirect_stdout(out):
            self.assertEqual(0, cli.main(['plan', 'windows-failure', '--config', 'profiles.toml', '--profile', 'exploratory']))
        planned = json.loads(out.getvalue())
        self.assertEqual(('rosetun.matrix.plan.v1', 'windows-failure'), (planned['schema'], planned['suite']))
        self.assertEqual(digest(read_catalog(matrix_config.FAILURE_CATALOG)), planned['catalog_digest'])
        with self.assertRaisesRegex(ValueError, 'requires the guest journal and independent lab evidence'):
            matrix_report.assess({}, {}, planned)


class ConfigTests(unittest.TestCase):
    def example(self):
        with EXAMPLE.open('rb') as stream:
            config = tomllib.load(stream)
        config['state_directory'] = str(Path(__file__).resolve().parent / 'state')
        return config

    def test_the_example_is_valid_for_every_case_and_refuses_unknown_cases_or_a_list_block(self):
        for name in failure.CASES:
            config = self.example()
            config['failure']['case'] = name
            with patch.object(windows_smoke, '_state_path', create=True), patch.object(windows_list_lab, '_state_path'):
                validated = windows_smoke.validate(config)
            self.assertEqual(('windows-failure', failure.SCHEMA, name),
                             (validated['suite'], validated['schema'], validated['failure']['case']))
        for bad in (
            lambda c: c['failure'].update(case='other'),
            lambda c: c['failure'].pop('case'),
            lambda c: c.update(list=dict(c['failure'])),
            lambda c: c.update(suite='windows-list'),
            lambda c: c.update(schema=windows_list_lab.SCHEMA),
        ):
            config = self.example()
            bad(config)
            with patch.object(windows_list_lab, '_state_path'), self.assertRaises(ValueError):
                failure.validate(config)

    def test_cli_dry_run_plans_the_selected_case_and_refuses_lab_flags(self):
        out = io.StringIO()
        with patch.object(windows_smoke, '_state_path', create=True), patch.object(windows_list_lab, '_state_path'), \
                patch.object(windows_smoke, 'load', side_effect=lambda path: windows_smoke.validate(self.example())), \
                patch.object(failure, 'preflight', return_value={'suite': 'windows-failure', 'case': 'engine-killed'}) as plan, \
                contextlib.redirect_stdout(out):
            self.assertEqual(0, cli.main(['run', 'windows-failure', '--config', 'x', '--dry-run']))
            plan.assert_called_once()
            for flags in (['--lab'], ['--control', 'stop-helper'], ['--diagnostic']):
                self.assertEqual(2, cli.main(['run', 'windows-failure', '--config', str(EXAMPLE), *flags]))


class FailureMachines(ListMachines):
    """Two-machine fake for a three-window Windows Failure case run."""

    def __init__(self, test, *, case='engine-killed', session_direct=None, baseline_v4=True, baseline_v6=True,
                 recovery_v4=True, recovery_v6=True, baseline_dns=('udp', 'tcp'), recovery_dns=('udp', 'tcp'),
                 **kwargs):
        self.case = failure.Case(case)
        if session_direct is None:
            session_direct = 1 if case == 'temporary' else 0
        super().__init__(test, session_direct=session_direct, **kwargs)
        self.baseline_v4, self.baseline_v6 = baseline_v4, baseline_v6
        self.recovery_v4, self.recovery_v6 = recovery_v4, recovery_v6
        self.baseline_dns, self.recovery_dns = tuple(baseline_dns), tuple(recovery_dns)

    def results_of(self):
        return self.results or {check: 'PASS' for check in self.case.checks}

    def status(self, state):
        error = self.runner_error if state in guest.ENDED else None
        results = self.results_of()
        rows = []
        for check in self.case.checks:
            result = results.get(check, 'SKIP')
            reason = 'checked' if result == 'PASS' else 'condition-false' if result == 'FAIL' else 'interrupted'
            rows.append(dict(id=check, result=result, reason=reason, scenario='failure', note='exit 0'))
        acks = []
        for label, (opening, closing) in zip(self.case.labels, windows_for(self.lab_id)):
            for word, marker in (('open', opening), ('close', closing)):
                text = wire.marker_query(marker).decode()
                acks.append(dict(label=label, word=word, marker=text,
                                 ack=wire.ACK_PREFIX + text if self.markers else None,
                                 error=None, utc='2026-11-20T00:10:00.000Z'))
        return dict(schema=guest.STATUS_SCHEMA, run=self.lab_id, state=state if state != 'running' else 'running',
                    step='done', sequence=40, started_utc='2026-11-20T00:09:00.000Z',
                    updated_utc='2026-11-20T00:11:00.000Z', checks=rows, markers=acks,
                    notes=[dict(name='sing-box-first-launch-seconds', value=2)],
                    cleanup=None if (self.cleanup is None or state not in guest.ENDED) else
                    dict(result=self.cleanup, parts=dict(list_directory='PASS', helper='PASS', firewall='PASS')),
                    error=error)

    def program(self, path, arguments):
        self.programs.append((path, list(arguments)))
        self.test.assertEqual((guest.CMD, ['/c', 'type', failure.ROOT + r'\status.json']), (path, list(arguments)))
        self.polls += 1
        if self.polls == 1:
            return SimpleNamespace(exitcode=1, stdout=b'', stderr=b'')
        index = min(self.polls - 2, len(self.states) - 1)
        self.events.append(('poll', self.polls))
        return SimpleNamespace(exitcode=0, stdout=json.dumps(self.status(self.states[index])).encode(), stderr=b'')

    def recorded_files(self):
        identity = dict(run_id='11111111-2222-4333-8444-555555555555', vm_id=self.uuid or UUID, boot_id=BOOT)
        plan = dict(schema=failure.PREFIX + 'plan.v1', suite='windows-failure', profile='exploratory',
                    policy=dict(mode='exploratory'), identity=identity, catalog=self.case.catalog,
                    catalog_digest=digest(self.case.catalog))
        events = []
        for check in self.case.checks:
            result = self.results_of().get(check, 'SKIP')
            reason = 'checked' if result == 'PASS' else 'condition-false' if result == 'FAIL' else 'interrupted'
            events.append(dict(schema=failure.PREFIX + 'event.v1', run_id=identity['run_id'],
                               sequence=len(events) + 1, id=check, result=result, reason=reason))
        if self.dropped_events:
            events = events[:-1]
        counts = {name: sum(1 for e in events if e['result'] == name) for name in ('PASS', 'FAIL', 'SKIP')}
        report = dict(schema=failure.PREFIX + 'report.v1', identity=identity, boot_id_at_end=BOOT, checks=events,
                      summary={'total': len(events), 'pass': counts['PASS'], 'fail': counts['FAIL'], 'skip': counts['SKIP']},
                      cleanup=dict(status=self.cleanup), errors=[])
        status = dict(schema=failure.PREFIX + 'status.v1', identity=identity, state='finished', event_count=len(events))
        return dict(plan=json.dumps(plan), events=''.join(json.dumps(e) + '\n' for e in events),
                    report=json.dumps(report), status=json.dumps(status))

    def powershell(self, script):
        if 'medium-not-found' in script:
            self.note('guest-start')
            wanted = json.loads(re.search(r"ConvertFrom-Json '([^']*)'", script)[1])
            for name, digest_hex in wanted.items():
                if hashlib.sha256(self.disc[name]).hexdigest() != digest_hex:
                    raise AssertionError('disc digest mismatch')
            return json.dumps(dict(medium='E:\\', files=len(wanted), task=failure.TASK))
        return super().powershell(script)

    def served(self):
        return [(index, word, label) for index, label in enumerate(self.case.labels) for word in ('open', 'close')]

    def frames(self):
        lab_id, rows = self.lab_id, [(1.0, request_arp())]
        plain = wire.dns_checks(lab_id, lambda: '0' * 24)['plain']
        plain['nonce'] = re.search(r'\.([0-9a-f]{24})\.lab\.test', self.plain['name'])[1]
        rows += marker_rows(0, 'open', 'baseline', 10.0, lab_id)
        if self.baseline_v4:
            rows += syn(51000, wire.TARGETS[4], 443, at=11.0)
        if self.baseline_v6:
            rows += syn6(51001, wire.TARGETS[6], wire.PORTS['http'], at=11.5)
        if 'udp' in self.baseline_dns:
            request = ip_frame(wire.CLIENTS[4], wire.RESOLVER, 17, udp(52000, 53, wire.query(plain)))
            reply = ip_frame(wire.RESOLVER, wire.CLIENTS[4], 17, udp(53, 52000, wire.query(plain)),
                             src=wire.MACS['lab'], dst=wire.MACS['test'])
            rows += [(12.0, request), (12.01, reply)]
        rows += marker_rows(0, 'close', 'baseline', 20.0, lab_id)
        rows += marker_rows(1, 'open', 'session', 30.0, lab_id)
        if self.node:
            rows += syn(54000, '192.0.2.1', 8388, at=31.0)
        for n in range(self.session_direct):
            rows += syn(55000 + n, wire.TARGETS[4], 443, at=40.0 + n)
        rows += [(50.0 + n / 10, frame) for n, frame in enumerate(self.session_body)]
        rows += marker_rows(1, 'close', 'session', 60.0, lab_id)
        rows += marker_rows(2, 'open', 'recovery', 70.0, lab_id)
        if self.recovery_v4:
            rows += syn(56000, wire.TARGETS[4], 443, at=71.0)
        if self.recovery_v6:
            rows += syn6(56001, wire.TARGETS[6], wire.PORTS['http'], at=71.5)
        rows += marker_rows(2, 'close', 'recovery', 80.0, lab_id)
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
            base_name = failure.Case.control_name(plain, 'baseline')
            after_name = failure.Case.control_name(plain, 'recovery')
            for transport in self.baseline_dns:
                rows.append(dict(source=wire.CLIENTS[4], transport=transport, name=base_name, type='A'))
            for transport in self.recovery_dns:
                rows.append(dict(source=wire.CLIENTS[4], transport=transport, name=after_name, type='A'))
            return json.dumps(rows).encode()
        return b'[]'


@controller_only
class RunFailureTests(ListFlow):
    runs = 0

    def setUp(self):
        super().setUp()
        block = dict(self.config.pop('list'), case='engine-killed')
        self.config.update(schema=failure.SCHEMA, suite='windows-failure', failure=block)

    def run_case(self, case='engine-killed', **changes):
        type(self).runs += 1
        config = dict(self.config, stand_id='failure-%d' % type(self).runs,
                      state_directory=self.config['state_directory'] + '-f%d' % type(self).runs,
                      failure=dict(self.config['failure'], case=case))
        machines = FailureMachines(self, case=case, **changes)

        def sleep(seconds):
            self.sleeps.append(seconds)
            self.clock.now += seconds

        def completion(directory, manifest):
            return any(v.run.directory == directory and v.closed for v in machines.vms.values())

        image = SimpleNamespace(identifier='windows-test', sha256=HEX, validate=lambda directory: None)
        with patch.object(__import__('socket'), 'AF_UNIX', 1, create=True), \
                patch.object(failure.Case, 'preflight', return_value={}), \
                patch.object(windows_list_lab, 'preflight', return_value={}), \
                patch.object(windows_list_lab, 'SING_BOX_SHA256', self.pins['sing-box.exe']), \
                patch.object(windows_list_lab, 'load_windows_descriptor', return_value=image), \
                patch.object(windows_list_lab, 'completion_verified', side_effect=completion), \
                patch.object(windows_list_lab.windows_lab, 'completion_verified', side_effect=completion), \
                patch.object(windows_list_lab.windows_reboot, 'record',
                             side_effect=lambda vm, operation, **fields: machines.recorded.append((operation, fields))):
            return failure.run(config, adapters=machines.adapters(), clock=lambda: self.clock.now,
                               sleep=sleep, progress=lambda stage: None), machines

    def test_clean_runs_pass_for_zero_direct_and_one_direct_session_cases(self):
        for case in ('engine-killed', 'temporary', 'dns-lock'):
            expected_checks = EXPECTED_COUNTS[case]
            result, _ = self.run_case(case)
            self.assertEqual(0, result['exit_code'], (case, result['execution']['findings'], result['execution']['unverified']))
            section = result['execution']
            self.assertEqual(failure.Case.SUMMARY_SCHEMA, result['schema'])
            self.assertTrue(section['accepted'])
            self.assertEqual((case, 'UNVERIFIED'), (section['case'], section['full_matrix']))
            self.assertEqual(['PASS'] * expected_checks, [row['result'] for row in section['checks']])
            self.assertEqual('EXPECTED', section['windows']['session']['verdict'])
            self.assertEqual({'baseline', 'session', 'recovery'}, set(section['windows']))

    def test_missing_control_flows_or_dns_in_baseline_or_recovery_make_the_run_unverified(self):
        cases = (
            (dict(baseline_v6=False), 'control-flow-missing:baseline'),
            (dict(recovery_v4=False), 'control-flow-missing:recovery'),
            (dict(baseline_dns=('udp',)), 'control-dns-missing:baseline:tcp'),
            (dict(recovery_dns=('tcp',)), 'control-dns-missing:recovery:udp'),
        )
        for kwargs, expected in cases:
            with self.subTest(expected=expected):
                result, _ = self.run_case(**kwargs)
                self.assertEqual(2, result['exit_code'])
                self.assertEqual([], result['execution']['findings'])
                self.assertIn(expected, result['execution']['unverified'])

    def test_an_unexpected_direct_flow_in_a_zero_direct_case_or_missing_direct_flow_in_temporary_is_a_finding(self):
        result, _ = self.run_case('engine-killed', session_direct=1)
        self.assertEqual(1, result['exit_code'])
        self.assertEqual(['window-detected:session'], result['execution']['findings'])
        result, _ = self.run_case('temporary', session_direct=0)
        self.assertEqual(1, result['exit_code'])
        self.assertIn('window-mismatch:session', result['execution']['findings'])

    def test_a_leftover_wfp_provider_or_sublayer_in_the_guest_after_cleanup_is_a_finding(self):
        for leftover in ('wfp_provider', 'wfp_sublayer'):
            result, _ = self.run_case(left=[leftover])
            self.assertEqual(1, result['exit_code'])
            self.assertEqual([f'cleanup-left:{leftover}'], result['execution']['findings'])
