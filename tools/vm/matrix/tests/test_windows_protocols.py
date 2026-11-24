"""Stage 10f: Windows Protocols and Extensions suite, offline controller and synthetic run tests.

Tests cover:
- 17-check `protocols-checks.tsv` parity with `run-windows-protocols.ps1`, runner byte budget, and `plan`/`report` CLI contracts;
- QGA payload/status ceilings for 17 checks and 9 windows;
- `windows_protocols` configuration (`windows.v9`) & CLI validation;
- Full synthetic two-machine `windows-protocols` execution across all 9 windows (positive + negative wire/DHCP/egress/cleanup cases).
"""

import base64
import contextlib
import hashlib
import io
import json
from pathlib import Path
import re
import tomllib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.vm.matrix import (cli, config as matrix_config, lab_protocol as wire, qga,
                             report as matrix_report, windows_list_guest as guest,
                             windows_list_lab, windows_protocols as protocols, windows_smoke)
from tools.vm.matrix.catalog import digest, read_catalog
from tools.vm.matrix.tests.posix_only import controller_only
from tools.vm.matrix.tests.test_lab import ip_frame, tcp, udp
from tools.vm.matrix.tests.test_lab_windows import health
from tools.vm.matrix.tests.test_windows_lab import HEX, marker_rows, request_arp
from tools.vm.matrix.tests.test_windows_list_lab import BOOT, RUN, UUID, ListFlow, ListMachines, syn

EXAMPLE = Path(__file__).resolve().parents[1] / 'execution-windows-protocols.example.toml'
WINDOWS_ROOT = Path(__file__).resolve().parents[2] / 'windows'
MAX_RUNNER_BYTES = 65536


def plan_files():
    rows = [dict(name=name, sha256=hashlib.sha256(name.encode()).hexdigest(), size=10 + n, pinned=True)
            for n, name in enumerate(protocols.BINARIES)]
    rows += [dict(name=name, sha256=hashlib.sha256(name.encode()).hexdigest(), size=20, pinned=False)
             for name in (guest.PLAN_FILE, *protocols.SCRIPTS)]
    return rows


def windows_for(profile, run=RUN):
    return [(wire.window_marker(run, index, 'open', label), wire.window_marker(run, index, 'close', label))
            for index, label in enumerate(profile.labels)]


class CatalogAndPlanTests(unittest.TestCase):
    def test_all_17_protocol_checks_are_referenced_by_runner_and_fit_size_budget(self):
        profile = protocols.ProtocolsProfile()
        self.assertEqual(17, len(profile.checks))
        runner_path = WINDOWS_ROOT / 'guest' / protocols.ENTRY
        self.assertLess(runner_path.stat().st_size, MAX_RUNNER_BYTES)
        runner = runner_path.read_text(encoding='utf-8')
        for check in profile.checks:
            with self.subTest(check=check):
                self.assertIn(f"'{check}'", runner)

    def test_plan_and_report_cli_contract_for_windows_protocols(self):
        out = io.StringIO()
        with patch.object(cli, 'load_profile', return_value={'mode': 'exploratory'}), contextlib.redirect_stdout(out):
            self.assertEqual(0, cli.main(['plan', 'windows-protocols', '--config', 'profiles.toml', '--profile', 'exploratory']))
        planned = json.loads(out.getvalue())
        self.assertEqual(('rosetun.matrix.plan.v1', 'windows-protocols'), (planned['schema'], planned['suite']))
        self.assertEqual(digest(read_catalog(matrix_config.PROTOCOLS_CATALOG)), planned['catalog_digest'])
        with self.assertRaisesRegex(ValueError, 'requires the guest journal and independent lab evidence'):
            matrix_report.assess({}, {}, planned)

    def test_plan_scripts_and_17_check_payloads_fit_qga_limits(self):
        plain = wire.dns_checks(RUN, lambda: '1' * 24)['plain']
        profile = protocols.ProtocolsProfile()
        plan = profile.plan_document(RUN, windows_for(profile, RUN), plain, 8388, plan_files())
        self.assertEqual(protocols.PREFIX + 'job.v1', plan['schema'])
        self.assertEqual(9, len(profile.labels))
        self.assertEqual(wire.HYSTERIA2_PORT, plan['protocols']['hysteria2_port'])
        self.assertEqual(wire.TUIC_PORT, plan['protocols']['tuic_port'])
        self.assertEqual(wire.ANYTLS_PORT, plan['protocols']['anytls_port'])
        self.assertEqual(wire.REALITY_PORT, plan['protocols']['reality_port'])
        self.assertEqual(wire.XHTTP_PORT, plan['protocols']['xhttp_port'])
        self.assertEqual(wire.SECOND_NODE_PORT, plan['protocols']['second_node_port'])
        self.assertEqual(wire.SECOND_NODE_EGRESS, plan['addresses']['second_node_egress'])
        self.assertIn('xray.exe', [row['name'] for row in plan['files']])
        self.assertTrue(guest.script_limit_ok(profile.start_script(plan_files())))
        self.assertTrue(guest.script_limit_ok(profile.collect_script()))
        self.assertTrue(guest.script_limit_ok(profile.after_script()))

        identity = dict(run_id='11111111-2222-4333-8444-555555555555', vm_id=UUID, boot_id=BOOT)
        rec_plan = dict(schema=protocols.PREFIX + 'plan.v1', suite='windows-protocols', profile='exploratory',
                        policy=dict(mode='exploratory'), identity=identity, catalog=profile.catalog,
                        catalog_digest=digest(profile.catalog))
        events = [dict(schema=protocols.PREFIX + 'event.v1', run_id=identity['run_id'], sequence=i + 1,
                       id=cid, result='PASS', reason='checked') for i, cid in enumerate(profile.checks)]
        report = dict(schema=protocols.PREFIX + 'report.v1', identity=identity, boot_id_at_end=BOOT,
                      checks=events, summary={'total': len(events), 'pass': len(events), 'fail': 0, 'skip': 0},
                      cleanup=dict(status='PASS'), errors=[])
        rec_status = dict(schema=protocols.PREFIX + 'status.v1', identity=identity,
                          state='finished', event_count=len(events))
        payload = json.dumps(dict(
            plan=json.dumps(rec_plan, separators=(',', ':')),
            events=''.join(json.dumps(e, separators=(',', ':')) + '\n' for e in events),
            report=json.dumps(report, separators=(',', ':')),
            status=json.dumps(rec_status, separators=(',', ':')),
            helper_tail='x' * 3000,
            identity=dict(uuid=UUID),
        ), separators=(',', ':'))
        self.assertLess(len(payload.encode('utf-8')), qga.EXEC_OUTPUT_LIMIT)
        self.assertLess(len(payload.encode('utf-8')), protocols.COLLECT_ANSWER_LIMIT)
        self.assertEqual(UUID, profile.collected(payload)['identity']['uuid'])

        for operation, params in (('fixture_state', {}), ('fixture_control', {'target': 'second_node', 'action': 'stop'})):
            status_doc = dict(
                schema=guest.STATUS_SCHEMA, run=RUN, state='lab-action-requested', step='second-node', sequence=40,
                started_utc='2026-11-24T00:00:00.000Z', updated_utc='2026-11-24T00:05:00.000Z',
                checks=[dict(id=cid, result='PASS', reason='checked', scenario='protocols', note='ok')
                        for cid in profile.checks],
                markers=[dict(label=label, word=word, marker=f'rosetun-lab-marker:{RUN}.{idx}.{word}.{label}',
                              ack=f'rosetun-lab-ack:rosetun-lab-marker:{RUN}.{idx}.{word}.{label}',
                              error=None, utc='2026-11-24T00:01:00.000Z')
                         for idx, label in enumerate(profile.labels) for word in ('open', 'close')],
                notes=[dict(name='window', value=1)],
                cleanup=None,
                error=None,
                action=dict(id='1111222233334444', operation=operation, params=params),
            )
            raw_status = json.dumps(status_doc, separators=(',', ':'))
            self.assertLess(len(raw_status.encode('utf-8')), protocols.STATUS_ANSWER_LIMIT)
            parsed = profile.runner_status(raw_status, RUN)
            self.assertEqual(('lab-action-requested', operation), (parsed['state'], parsed['action']['operation']))


class ConfigTests(unittest.TestCase):
    def example(self):
        with EXAMPLE.open('rb') as stream:
            config = tomllib.load(stream)
        config['state_directory'] = str(Path(__file__).resolve().parent / 'state')
        return config

    def test_example_validates_and_rejects_bad_protocols_configs(self):
        config = self.example()
        with patch.object(windows_smoke, '_state_path', create=True), patch.object(windows_list_lab, '_state_path'):
            validated = windows_smoke.validate(config)
        self.assertEqual(('windows-protocols', protocols.SCHEMA), (validated['suite'], validated['schema']))
        for bad in (
            lambda c: c['protocols'].pop('xray'),
            lambda c: c['protocols'].update(xray=''),
            lambda c: c['protocols'].update(xray_sha256='bad'),
            lambda c: c['lab'].pop('xray_sha256'),
            lambda c: c['lab'].update(xray_sha256='A' * 64),
            lambda c: c['lab'].pop('proto_cert_sha256'),
            lambda c: c['protocols'].update(runner_seconds=1801),
            lambda c: c.update(list=dict(c['protocols'])),
            lambda c: c.update(twohop=dict(c['protocols'])),
            lambda c: c.update(suite='windows-twohop'),
            lambda c: c.update(schema='rosetun.matrix.execution.windows.v8'),
        ):
            bad_cfg = self.example()
            bad(bad_cfg)
            with patch.object(windows_list_lab, '_state_path'), self.assertRaises(ValueError):
                protocols.validate(bad_cfg)

    def test_cli_dry_run_and_flag_refusals(self):
        out = io.StringIO()
        with patch.object(windows_smoke, '_state_path', create=True), patch.object(windows_list_lab, '_state_path'), \
                patch.object(windows_smoke, 'load', side_effect=lambda path: windows_smoke.validate(self.example())), \
                patch.object(protocols, 'preflight', return_value={'suite': 'windows-protocols'}) as pre, \
                contextlib.redirect_stdout(out):
            self.assertEqual(0, cli.main(['run', 'windows-protocols', '--config', 'x', '--dry-run']))
            pre.assert_called_once()
            for flags in (['--lab'], ['--control', 'stop-helper'], ['--diagnostic']):
                self.assertEqual(2, cli.main(['run', 'windows-protocols', '--config', str(EXAMPLE), *flags]))


class ProtocolsMachines(ListMachines):
    """Two-machine fake for Windows Protocols runs across all 9 windows."""

    def __init__(self, test, *, hysteria2_leak=False, wrong_anytls_port=False,
                 include_dhcp=True, include_second_node_egress=True, after_left=(), **kwargs):
        self.profile = protocols.ProtocolsProfile()
        self.hysteria2_leak = hysteria2_leak
        self.wrong_anytls_port = wrong_anytls_port
        self.include_dhcp = include_dhcp
        self.include_second_node_egress = include_second_node_egress
        self.after_left = tuple(after_left)
        self.action_replies = []
        super().__init__(test, session_direct=0, **kwargs)
        self.poll_states = ['running', 'lab-action-requested', 'lab-action-requested', 'finished']
        self.action_queue = [
            dict(id='a1a2a3a4a5a6a7a8', operation='fixture_state', params={}),
            dict(id='b1b2b3b4b5b6b7b8', operation='fixture_control', params=dict(service='second_node', state='stop')),
        ]

    def results_of(self):
        return self.results or {check: 'PASS' for check in self.profile.checks}

    def status(self, state, seq, action=None):
        error = self.runner_error if state in guest.ENDED else None
        results = self.results_of()
        rows = [dict(id=check, result=results.get(check, 'SKIP'),
                     reason='checked' if results.get(check, 'SKIP') == 'PASS' else 'condition-false',
                     scenario='protocols', note='ok') for check in self.profile.checks]
        acks = []
        for label, (opening, closing) in zip(self.profile.labels, windows_for(self.profile, self.lab_id)):
            for word, marker in (('open', opening), ('close', closing)):
                text = wire.marker_query(marker).decode()
                acks.append(dict(label=label, word=word, marker=text,
                                 ack=wire.ACK_PREFIX + text if self.markers else None,
                                 error=None, utc='2026-11-24T00:05:00.000Z'))
        return dict(schema=guest.STATUS_SCHEMA, run=self.lab_id, state=state,
                    step='done' if state in guest.ENDED else state, sequence=seq,
                    started_utc='2026-11-24T00:00:00.000Z', updated_utc='2026-11-24T00:06:00.000Z',
                    checks=rows, markers=acks, notes=[dict(name='protocols', value=17)],
                    cleanup=None if (self.cleanup is None or state not in guest.ENDED) else
                    dict(result=self.cleanup, parts=dict(connection='PASS', network='PASS', helper='PASS', files='PASS')),
                    error=error, action=action)

    def program(self, path, arguments):
        self.programs.append((path, list(arguments)))
        self.test.assertEqual((guest.CMD, ['/c', 'type', protocols.ROOT + r'\status.json']), (path, list(arguments)))
        self.polls += 1
        if self.polls == 1:
            return SimpleNamespace(exitcode=1, stdout=b'', stderr=b'')
        idx = min(self.polls - 2, len(self.poll_states) - 1)
        state = self.poll_states[idx]
        action = None
        if state == 'lab-action-requested':
            action_idx = sum(1 for item in self.poll_states[:idx] if item == 'lab-action-requested')
            action = self.action_queue[min(action_idx, len(self.action_queue) - 1)]
        self.events.append(('poll', self.polls, state))
        return SimpleNamespace(exitcode=0, stdout=json.dumps(self.status(state, 10 + idx * 5, action=action)).encode(), stderr=b'')

    def recorded_files(self):
        identity = dict(run_id='11111111-2222-4333-8444-555555555555', vm_id=self.uuid or UUID, boot_id=BOOT)
        plan = dict(schema=protocols.PREFIX + 'plan.v1', suite='windows-protocols', profile='exploratory',
                    policy=dict(mode='exploratory'), identity=identity, catalog=self.profile.catalog,
                    catalog_digest=digest(self.profile.catalog))
        events = []
        for check in self.profile.checks:
            result = self.results_of().get(check, 'SKIP')
            reason = 'checked' if result == 'PASS' else 'condition-false' if result == 'FAIL' else 'interrupted'
            events.append(dict(schema=protocols.PREFIX + 'event.v1', run_id=identity['run_id'],
                               sequence=len(events) + 1, id=check, result=result, reason=reason))
        counts = {name: sum(1 for e in events if e['result'] == name) for name in ('PASS', 'FAIL', 'SKIP')}
        report = dict(schema=protocols.PREFIX + 'report.v1', identity=identity, boot_id_at_end=BOOT, checks=events,
                      summary={'total': len(events), 'pass': counts['PASS'], 'fail': counts['FAIL'], 'skip': counts['SKIP']},
                      cleanup=dict(status=self.cleanup), errors=[])
        status = dict(schema=protocols.PREFIX + 'status.v1', identity=identity, state='finished', event_count=len(events))
        return dict(plan=json.dumps(plan), events=''.join(json.dumps(e) + '\n' for e in events),
                    report=json.dumps(report), status=json.dumps(status))

    def powershell(self, script):
        if 'medium-not-found' in script:
            self.note('guest-start')
            wanted = json.loads(re.search(r"ConvertFrom-Json '([^']*)'", script)[1])
            for name, digest_hex in wanted.items():
                if hashlib.sha256(self.disc[name]).hexdigest() != digest_hex:
                    raise AssertionError('disc digest mismatch')
            return json.dumps(dict(medium='E:\\', files=len(wanted), task=protocols.TASK))
        if 'action-reply-' in script:
            self.note('guest-action-reply')
            b64 = re.search(r"FromBase64String\('([^']*)'\)", script)[1]
            action_id = re.search(r"action-reply-([0-9a-f]{16})\.json", script)[1]
            reply = json.loads(base64.b64decode(b64).decode('utf-8'))
            self.action_replies.append(dict(id=action_id, payload=reply))
            return json.dumps(dict(wrote=True, id=action_id))
        if 'protocols_directory' in script:
            self.note('guest-after')
            state = dict(wfp_provider=False, wfp_sublayer=False, runner_task=False, helper_task=False,
                         helper_process=False, engine_process=False, tunnel_adapter=False,
                         binaries=False, list_directory=False, root_removed=True,
                         xray_process=False, protocols_directory=False)
            for item in self.after_left:
                if item == 'root_directory':
                    state['root_removed'] = False
                else:
                    state[item] = True
            return json.dumps(state)
        return super().powershell(script)

    def adapters(self):
        adapters = super().adapters()
        base_guest = adapters.guest
        machines = self

        class ProtocolsLabGuest(base_guest):
            def call(self, operation, expected, window=(), canary=False, tunnel=None, options=None):
                if operation == 'fixture_state':
                    machines.note('lab-fixture-state')
                    machines.calls.append((operation, expected, list(window), tunnel, options))
                    return dict(reality_public_key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                                dhcp=dict(discover=1, request=2, ack=2),
                                twohop=dict(connections={}),
                                services=dict(protocols=True, second_node=True, xray=True, twohop_b=False, dhcp=True))
                if operation == 'fixture_control':
                    machines.note('lab-fixture-control')
                    machines.calls.append((operation, expected, list(window), tunnel, options))
                    act = options['action']
                    return dict(service=act['service'], state=act['state'], running=act['state'] == 'start')
                return super().call(operation, expected, window=window, canary=canary, tunnel=tunnel, options=options)

        adapters.guest = ProtocolsLabGuest
        return adapters

    def served(self):
        return [(index, word, label) for index, label in enumerate(self.profile.labels) for word in ('open', 'close')]

    def frames(self):
        lab_id, rows = self.lab_id, [(1.0, request_arp())]
        plain = wire.dns_checks(lab_id, lambda: '0' * 24)['plain']
        plain['nonce'] = re.search(r'\.([0-9a-f]{24})\.lab\.test', self.plain['name'])[1]
        t = 10.0
        for index, label in enumerate(self.profile.labels):
            rows += marker_rows(index, 'open', label, t, lab_id)
            t += 1.0
            if label in ('baseline', 'recovery'):
                rows += syn(51000 + index, wire.TARGETS[4], 443, at=t)
                q = wire.query(plain)
                rows.append((t + 0.1, ip_frame(wire.CLIENTS[4], wire.RESOLVER, 17, udp(52000 + index, 53, q))))
                rows.append((t + 0.15, ip_frame(wire.RESOLVER, wire.CLIENTS[4], 17, udp(53, 52000 + index, q),
                                                src=wire.MACS['lab'], dst=wire.MACS['test'])))
            elif label == 'hysteria2':
                rows.append((t, ip_frame(wire.CLIENTS[4], wire.GATEWAYS[4], 17, udp(53000, wire.HYSTERIA2_PORT, b'h2'))))
                if self.hysteria2_leak:
                    rows += syn(53009, wire.TARGETS[4], 443, at=t + 0.2)
            elif label == 'tuic':
                rows.append((t, ip_frame(wire.CLIENTS[4], wire.GATEWAYS[4], 17, udp(53100, wire.TUIC_PORT, b'tuic'))))
            elif label == 'anytls':
                port = 8388 if self.wrong_anytls_port else wire.ANYTLS_PORT
                rows += syn(53200, wire.GATEWAYS[4], port, at=t)
            elif label == 'xray-reality':
                rows += syn(53300, wire.GATEWAYS[4], wire.REALITY_PORT, at=t)
                rows += syn(53301, wire.GATEWAYS[4], 8388, at=t + 0.1)
            elif label == 'xray-xhttp':
                rows += syn(53400, wire.GATEWAYS[4], wire.XHTTP_PORT, at=t)
                rows += syn(53401, wire.GATEWAYS[4], 8388, at=t + 0.1)
            elif label == 'second-node':
                rows += syn(53500, wire.GATEWAYS[4], 8388, at=t)
                rows += syn(53501, wire.GATEWAYS[4], wire.SECOND_NODE_PORT, at=t + 0.1)
            elif label == 'dhcp':
                rows += syn(53600, wire.GATEWAYS[4], 8388, at=t)
                if self.include_dhcp:
                    rows.append((t + 0.1, ip_frame('0.0.0.0', '255.255.255.255', 17,
                                                   udp(wire.DHCP_CLIENT_PORT, wire.DHCP_SERVER_PORT, b'dhcp'),
                                                   dst='ff:ff:ff:ff:ff:ff')))
                    rows.append((t + 0.2, ip_frame(wire.GATEWAYS[4], wire.CLIENTS[4], 17,
                                                   udp(wire.DHCP_SERVER_PORT, wire.DHCP_CLIENT_PORT, b'ack'),
                                                   src=wire.MACS['lab'], dst=wire.MACS['test'])))
            t += 5.0
            rows += marker_rows(index, 'close', label, t, lab_id)
            t += 5.0
        return rows, plain

    def artifact(self, name):
        _, plain = self.frames()
        if name == 'health.json':
            return json.dumps(health(self.served(), node=dict(alive_at_finish=True, exit_code=0))).encode()
        if name == 'https.json':
            sources = [wire.CLIENTS[4], wire.EGRESS]
            if self.include_second_node_egress:
                sources.append(wire.SECOND_NODE_EGRESS)
            counts = [dict(source=source, method='GET', path_class='root', count=2) for source in sources]
            return json.dumps([dict(kind='counts', counts=counts, rows_dropped=0, counts_dropped=0)]).encode()
        if name == 'dns.json':
            rows = [dict(source=wire.EGRESS, transport='doh', name='listed.lab.test', type='A')]
            for phase in ('baseline', 'recovery'):
                rows.append(dict(source=wire.CLIENTS[4], transport='udp',
                                 name=self.profile.control_name(plain, phase), type='A'))
            return json.dumps(rows).encode()
        return b'[]'


@controller_only
class ProtocolsFlow(ListFlow):
    runs = 0

    def setUp(self):
        super().setUp()
        root = self.fixture.root
        (root / 'xray.exe').write_bytes(b'xray')
        self.pins['xray.exe'] = hashlib.sha256(b'xray').hexdigest()
        block = dict(self.config.pop('list'),
                     agent_wait_seconds=180, script_seconds=120, runner_seconds=1200, poll_seconds=10,
                     xray=str(root / 'xray.exe'), xray_sha256=self.pins['xray.exe'])
        lab_block = dict(self.config['lab'], xray_sha256=HEX, proto_cert_sha256=HEX)
        self.config.update(schema=protocols.SCHEMA, suite='windows-protocols', protocols=block, lab=lab_block)

    def run_protocols(self, **changes):
        type(self).runs += 1
        cfg = dict(self.config, stand_id='proto-%d' % type(self).runs,
                   state_directory=self.config['state_directory'] + '-pr%d' % type(self).runs)
        machines = ProtocolsMachines(self, **changes)

        def sleep(seconds):
            self.sleeps.append(seconds)
            self.clock.now += seconds

        def completion(directory, manifest):
            return any(v.run.directory == directory and v.closed for v in machines.vms.values())

        image = SimpleNamespace(identifier='windows-test', sha256=HEX, validate=lambda directory: None)
        with patch.object(__import__('socket'), 'AF_UNIX', 1, create=True), \
                patch.object(protocols.ProtocolsProfile, 'preflight', return_value={}), \
                patch.object(windows_list_lab, 'preflight', return_value={}), \
                patch.object(windows_list_lab, 'SING_BOX_SHA256', self.pins['sing-box.exe']), \
                patch.object(windows_list_lab, 'load_windows_descriptor', return_value=image), \
                patch.object(windows_list_lab, 'completion_verified', side_effect=completion), \
                patch.object(windows_list_lab.windows_lab, 'completion_verified', side_effect=completion), \
                patch.object(windows_list_lab.windows_reboot, 'record',
                             side_effect=lambda vm, operation, **fields: machines.recorded.append((operation, fields))):
            return protocols.run(cfg, adapters=machines.adapters(), clock=lambda: self.clock.now,
                                 sleep=sleep, progress=lambda stage: None), machines

    def test_clean_windows_protocols_run_accepts_across_all_9_windows(self):
        result, machines = self.run_protocols()
        section = result['execution']
        self.assertEqual(0, result['exit_code'], (section['findings'], section['unverified'], result['errors']))
        self.assertTrue(section['accepted'])
        self.assertEqual([], section['findings'])
        self.assertEqual([], section['unverified'])
        self.assertEqual(2, section['lab_actions'])
        self.assertEqual(['a1a2a3a4a5a6a7a8', 'b1b2b3b4b5b6b7b8'], [row['id'] for row in machines.action_replies])
        setup_call = machines.calls[0]
        self.assertEqual('setup', setup_call[0])
        self.assertEqual(dict(protocols=True, second_node=True, xray=True, dhcp=True,
                              xray_sha256=HEX, proto_cert_sha256=HEX),
                         setup_call[4]['extended_fixtures'])
        for label in protocols.JUDGED_LABELS:
            self.assertEqual('EXPECTED', section['windows'][label]['verdict'])

    def test_direct_leak_in_hysteria2_window_is_refused(self):
        result, _ = self.run_protocols(hysteria2_leak=True)
        self.assertEqual(1, result['exit_code'])
        self.assertIn('window-detected:hysteria2', result['execution']['findings'])

    def test_wrong_tunnel_port_in_anytls_window_is_refused(self):
        result, _ = self.run_protocols(wrong_anytls_port=True)
        self.assertEqual(1, result['exit_code'])
        self.assertIn('window-detected:anytls', result['execution']['findings'])

    def test_missing_dhcpv4_allowance_in_dhcp_window_is_refused(self):
        result, _ = self.run_protocols(include_dhcp=False)
        self.assertEqual(1, result['exit_code'])
        self.assertIn('disagree:dhcp.renew-under-kill-switch', result['execution']['findings'])

    def test_missing_second_node_egress_is_refused(self):
        result, _ = self.run_protocols(include_second_node_egress=False)
        self.assertEqual(1, result['exit_code'])
        self.assertIn('disagree:second-node.egress', result['execution']['findings'])

    def test_leftover_xray_process_fails_cleanup(self):
        result, _ = self.run_protocols(after_left=('xray_process',))
        self.assertEqual(1, result['exit_code'])
        self.assertIn('cleanup-left:xray_process', result['execution']['findings'])


if __name__ == '__main__':
    unittest.main()
