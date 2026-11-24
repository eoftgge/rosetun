"""Stage 10f: Windows Two-Hop Proxy Chain suite, offline controller and synthetic run tests.

Tests cover:
- 40-scenario `two-hop-scenarios.tsv` parity with `run-windows-twohop.ps1`, runner byte budget, and `plan`/`report` CLI contracts;
- QGA payload/status ceilings for 40 scenarios and 4 windows;
- `windows_twohop` configuration (`windows.v10`) & CLI validation;
- Full synthetic two-machine `windows-twohop` execution across all 4 windows (positive + negative direct-B leak, domain-B DNS, target-B egress, and cleanup cases).
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
                             windows_list_lab, windows_smoke, windows_twohop as twohop)
from tools.vm.matrix.catalog import digest
from tools.vm.matrix.tests.posix_only import controller_only
from tools.vm.matrix.tests.test_lab import ip_frame, udp
from tools.vm.matrix.tests.test_lab_windows import health
from tools.vm.matrix.tests.test_windows_lab import HEX, marker_rows, request_arp
from tools.vm.matrix.tests.test_windows_list_lab import BOOT, RUN, UUID, ListFlow, ListMachines, syn

EXAMPLE = Path(__file__).resolve().parents[1] / 'execution-windows-twohop.example.toml'
WINDOWS_ROOT = Path(__file__).resolve().parents[2] / 'windows'
MAX_RUNNER_BYTES = 65536


def plan_files():
    rows = [dict(name=name, sha256=hashlib.sha256(name.encode()).hexdigest(), size=10 + n, pinned=True)
            for n, name in enumerate(twohop.BINARIES)]
    rows += [dict(name=name, sha256=hashlib.sha256(name.encode()).hexdigest(), size=20, pinned=False)
             for name in (guest.PLAN_FILE, *twohop.SCRIPTS)]
    return rows


def windows_for(profile, run=RUN):
    return [(wire.window_marker(run, index, 'open', label), wire.window_marker(run, index, 'close', label))
            for index, label in enumerate(profile.labels)]


class CatalogAndPlanTests(unittest.TestCase):
    def test_all_40_twohop_scenarios_are_covered_by_runner_and_fit_size_budget(self):
        profile = twohop.TwoHopProfile(proxy_port=10808)
        self.assertEqual(40, len(profile.checks))
        tun_checks = [cid for cid in profile.checks if cid.endswith(':tun')]
        proxy_checks = [cid for cid in profile.checks if cid.endswith(':system-proxy')]
        self.assertEqual(20, len(tun_checks))
        self.assertEqual(20, len(proxy_checks))

        runner_path = WINDOWS_ROOT / 'guest' / twohop.ENTRY
        self.assertLess(runner_path.stat().st_size, MAX_RUNNER_BYTES)
        runner = runner_path.read_text(encoding='utf-8')
        self.assertIn("-Mode 'tun'", runner)
        self.assertIn("-Mode 'system-proxy'", runner)
        base_ids = sorted({cid.split(':')[0] for cid in profile.checks})
        self.assertEqual(20, len(base_ids))
        for base_id in base_ids:
            with self.subTest(base_id=base_id):
                self.assertIn(f'"{base_id}:$Mode"', runner)

    def test_plan_and_report_cli_contract_for_windows_twohop(self):
        out = io.StringIO()
        with patch.object(cli, 'load_profile', return_value={'mode': 'exploratory'}), contextlib.redirect_stdout(out):
            self.assertEqual(0, cli.main(['plan', 'windows-twohop', '--config', 'profiles.toml', '--profile', 'exploratory']))
        planned = json.loads(out.getvalue())
        self.assertEqual(('rosetun.matrix.plan.v1', 'windows-twohop'), (planned['schema'], planned['suite']))
        self.assertEqual(digest(matrix_config.twohop_catalog(matrix_config.TWOHOP_CATALOG)), planned['catalog_digest'])
        with self.assertRaisesRegex(ValueError, 'requires the guest journal and independent lab evidence'):
            matrix_report.assess({}, {}, planned)

    def test_plan_scripts_and_40_check_payloads_fit_qga_limits(self):
        plain = wire.dns_checks(RUN, lambda: '1' * 24)['plain']
        profile = twohop.TwoHopProfile(proxy_port=10808)
        plan = profile.plan_document(RUN, windows_for(profile, RUN), plain, 8388, plan_files())
        self.assertEqual(twohop.PREFIX + 'job.v1', plan['schema'])
        self.assertEqual(4, len(profile.labels))
        self.assertEqual(10808, plan['proxy_port'])
        self.assertEqual(wire.TWOHOP_B[4], plan['twohop']['b4'])
        self.assertEqual(wire.TWOHOP_B[6], plan['twohop']['b6'])
        self.assertEqual(wire.LAN_PEER, plan['twohop']['lan_peer'])
        self.assertEqual(twohop.DOMAIN_B, plan['twohop']['domain_b'])
        self.assertIn('xray.exe', [row['name'] for row in plan['files']])
        self.assertTrue(guest.script_limit_ok(profile.start_script(plan_files())))
        self.assertTrue(guest.script_limit_ok(profile.collect_script()))
        self.assertTrue(guest.script_limit_ok(profile.after_script()))

        identity = dict(run_id='11111111-2222-4333-8444-555555555555', vm_id=UUID, boot_id=BOOT)
        rec_plan = dict(schema=twohop.PREFIX + 'plan.v1', suite='windows-twohop', profile='exploratory',
                        policy=dict(mode='exploratory'), identity=identity, catalog=profile.catalog,
                        catalog_digest=digest(profile.catalog))
        events = [dict(schema=twohop.PREFIX + 'event.v1', run_id=identity['run_id'], sequence=i + 1,
                       id=cid, result='PASS', reason='checked') for i, cid in enumerate(profile.checks)]
        report = dict(schema=twohop.PREFIX + 'report.v1', identity=identity, boot_id_at_end=BOOT,
                      checks=events, summary={'total': len(events), 'pass': len(events), 'fail': 0, 'skip': 0},
                      cleanup=dict(status='PASS'), errors=[])
        rec_status = dict(schema=twohop.PREFIX + 'status.v1', identity=identity,
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
        self.assertLess(len(payload.encode('utf-8')), twohop.COLLECT_ANSWER_LIMIT)
        self.assertEqual(UUID, profile.collected(payload)['identity']['uuid'])

        for operation, params in (('fixture_state', {}), ('fixture_control', {'target': 'twohop_b', 'action': 'stop'})):
            status_doc = dict(
                schema=guest.STATUS_SCHEMA, run=RUN, state='lab-action-requested', step='twohop-tun', sequence=50,
                started_utc='2026-11-24T00:00:00.000Z', updated_utc='2026-11-24T00:05:00.000Z',
                checks=[dict(id=cid, result='PASS', reason='checked', scenario='twohop', note='ok')
                        for cid in profile.checks],
                markers=[dict(label=label, word=word, marker=f'rosetun-lab-marker:{RUN}.{idx}.{word}.{label}',
                              ack=f'rosetun-lab-ack:rosetun-lab-marker:{RUN}.{idx}.{word}.{label}',
                              error=None, utc='2026-11-24T00:01:00.000Z')
                         for idx, label in enumerate(profile.labels) for word in ('open', 'close')],
                notes=[dict(name='scenarios', value=40)],
                cleanup=None,
                error=None,
                action=dict(id='1111222233334444', operation=operation, params=params),
            )
            raw_status = json.dumps(status_doc, separators=(',', ':'))
            self.assertLess(len(raw_status.encode('utf-8')), twohop.STATUS_ANSWER_LIMIT)
            parsed = profile.runner_status(raw_status, RUN)
            self.assertEqual(('lab-action-requested', operation), (parsed['state'], parsed['action']['operation']))


class ConfigTests(unittest.TestCase):
    def example(self):
        with EXAMPLE.open('rb') as stream:
            config = tomllib.load(stream)
        config['state_directory'] = str(Path(__file__).resolve().parent / 'state')
        return config

    def test_example_validates_and_rejects_bad_twohop_configs(self):
        config = self.example()
        with patch.object(windows_smoke, '_state_path', create=True), patch.object(windows_list_lab, '_state_path'):
            validated = windows_smoke.validate(config)
        self.assertEqual(('windows-twohop', twohop.SCHEMA, 10808),
                         (validated['suite'], validated['schema'], validated['twohop']['proxy_port']))
        for bad in (
            lambda c: c['twohop'].update(proxy_port=80),
            lambda c: c['twohop'].update(proxy_port=65536),
            lambda c: c['twohop'].update(proxy_port=True),
            lambda c: c['twohop'].update(proxy_port=8388),
            lambda c: c['twohop'].pop('xray'),
            lambda c: c['twohop'].update(xray_sha256='bad'),
            lambda c: c['lab'].pop('xray_sha256'),
            lambda c: c['lab'].pop('proto_cert_sha256'),
            lambda c: c['lab'].pop('twohop_cert_sha256'),
            lambda c: c['lab'].pop('twohop_untrusted_cert_sha256'),
            lambda c: c['twohop'].update(runner_seconds=1801),
            lambda c: c.update(list=dict(c['twohop'])),
            lambda c: c.update(protocols=dict(c['twohop'])),
            lambda c: c.update(suite='windows-protocols'),
            lambda c: c.update(schema='rosetun.matrix.execution.windows.v9'),
        ):
            bad_cfg = self.example()
            bad(bad_cfg)
            with patch.object(windows_list_lab, '_state_path'), self.assertRaises(ValueError):
                twohop.validate(bad_cfg)

    def test_cli_dry_run_and_flag_refusals(self):
        out = io.StringIO()
        with patch.object(windows_smoke, '_state_path', create=True), patch.object(windows_list_lab, '_state_path'), \
                patch.object(windows_smoke, 'load', side_effect=lambda path: windows_smoke.validate(self.example())), \
                patch.object(twohop, 'preflight', return_value={'suite': 'windows-twohop', 'proxy_port': 10808}) as pre, \
                contextlib.redirect_stdout(out):
            self.assertEqual(0, cli.main(['run', 'windows-twohop', '--config', 'x', '--dry-run']))
            pre.assert_called_once()
            for flags in (['--lab'], ['--control', 'stop-helper'], ['--diagnostic']):
                self.assertEqual(2, cli.main(['run', 'windows-twohop', '--config', str(EXAMPLE), *flags]))


class TwoHopMachines(ListMachines):
    """Two-machine fake for Windows Two-Hop runs across all 4 windows."""

    def __init__(self, test, *, direct_b_leak=False, domain_b_dns=False,
                 include_target_b=True, after_left=(), **kwargs):
        self.profile = twohop.TwoHopProfile(proxy_port=10808)
        self.direct_b_leak = direct_b_leak
        self.domain_b_dns = domain_b_dns
        self.include_target_b = include_target_b
        self.after_left = tuple(after_left)
        self.action_replies = []
        super().__init__(test, session_direct=0, **kwargs)
        self.poll_states = ['running', 'lab-action-requested', 'lab-action-requested', 'finished']
        self.action_queue = [
            dict(id='c1c2c3c4c5c6c7c8', operation='fixture_state', params={}),
            dict(id='d1d2d3d4d5d6d7d8', operation='fixture_control', params=dict(service='twohop_b', state='stop')),
        ]

    def results_of(self):
        return self.results or {check: 'PASS' for check in self.profile.checks}

    def status(self, state, seq, action=None):
        error = self.runner_error if state in guest.ENDED else None
        results = self.results_of()
        rows = [dict(id=check, result=results.get(check, 'SKIP'),
                     reason='checked' if results.get(check, 'SKIP') == 'PASS' else 'condition-false',
                     scenario='twohop', note='ok') for check in self.profile.checks]
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
                    checks=rows, markers=acks, notes=[dict(name='scenarios', value=40)],
                    cleanup=None if (self.cleanup is None or state not in guest.ENDED) else
                    dict(result=self.cleanup, parts=dict(connection='PASS', lockdown='PASS', helper='PASS', files='PASS')),
                    error=error, action=action)

    def program(self, path, arguments):
        self.programs.append((path, list(arguments)))
        self.test.assertEqual((guest.CMD, ['/c', 'type', twohop.ROOT + r'\status.json']), (path, list(arguments)))
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
        plan = dict(schema=twohop.PREFIX + 'plan.v1', suite='windows-twohop', profile='exploratory',
                    policy=dict(mode='exploratory'), identity=identity, catalog=self.profile.catalog,
                    catalog_digest=digest(self.profile.catalog))
        events = []
        for check in self.profile.checks:
            result = self.results_of().get(check, 'SKIP')
            reason = 'checked' if result == 'PASS' else 'condition-false' if result == 'FAIL' else 'interrupted'
            events.append(dict(schema=twohop.PREFIX + 'event.v1', run_id=identity['run_id'],
                               sequence=len(events) + 1, id=check, result=result, reason=reason))
        counts = {name: sum(1 for e in events if e['result'] == name) for name in ('PASS', 'FAIL', 'SKIP')}
        report = dict(schema=twohop.PREFIX + 'report.v1', identity=identity, boot_id_at_end=BOOT, checks=events,
                      summary={'total': len(events), 'pass': counts['PASS'], 'fail': counts['FAIL'], 'skip': counts['SKIP']},
                      cleanup=dict(status=self.cleanup), errors=[])
        status = dict(schema=twohop.PREFIX + 'status.v1', identity=identity, state='finished', event_count=len(events))
        return dict(plan=json.dumps(plan), events=''.join(json.dumps(e) + '\n' for e in events),
                    report=json.dumps(report), status=json.dumps(status))

    def powershell(self, script):
        if 'medium-not-found' in script:
            self.note('guest-start')
            wanted = json.loads(re.search(r"ConvertFrom-Json '([^']*)'", script)[1])
            for name, digest_hex in wanted.items():
                if hashlib.sha256(self.disc[name]).hexdigest() != digest_hex:
                    raise AssertionError('disc digest mismatch')
            return json.dumps(dict(medium='E:\\', files=len(wanted), task=twohop.TASK))
        if 'action-reply-' in script:
            self.note('guest-action-reply')
            b64 = re.search(r"FromBase64String\('([^']*)'\)", script)[1]
            action_id = re.search(r"action-reply-([0-9a-f]{16})\.json", script)[1]
            reply = json.loads(base64.b64decode(b64).decode('utf-8'))
            self.action_replies.append(dict(id=action_id, payload=reply))
            return json.dumps(dict(wrote=True, id=action_id))
        if 'twohop_directory' in script:
            self.note('guest-after')
            state = dict(wfp_provider=False, wfp_sublayer=False, runner_task=False, helper_task=False,
                         helper_process=False, engine_process=False, tunnel_adapter=False,
                         binaries=False, list_directory=False, root_removed=True,
                         lockdown_wfp_provider=False, lockdown_wfp_sublayer=False, lockdown_service=False,
                         xray_process=False, twohop_directory=False)
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

        class TwoHopLabGuest(base_guest):
            def call(self, operation, expected, window=(), canary=False, tunnel=None, options=None):
                if operation == 'fixture_state':
                    machines.note('lab-fixture-state')
                    machines.calls.append((operation, expected, list(window), tunnel, options))
                    return dict(reality_public_key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                                dhcp=dict(discover=0, request=0, ack=0),
                                twohop=dict(connections={'http_v4': {wire.SECOND_NODE_EGRESS: 2}}),
                                services=dict(protocols=False, second_node=True, xray=True, twohop_b=True, dhcp=False))
                if operation == 'fixture_control':
                    machines.note('lab-fixture-control')
                    machines.calls.append((operation, expected, list(window), tunnel, options))
                    act = options['action']
                    return dict(service=act['service'], state=act['state'], running=act['state'] == 'start')
                return super().call(operation, expected, window=window, canary=canary, tunnel=tunnel, options=options)

        adapters.guest = TwoHopLabGuest
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
            elif label in ('twohop-tun', 'twohop-proxy'):
                base = 53000 + index * 100
                rows += syn(base, wire.GATEWAYS[4], 8388, at=t)
                rows += syn(base + 1, wire.GATEWAYS[4], wire.SECOND_NODE_PORT, at=t + 0.1)
                rows += syn(base + 2, wire.GATEWAYS[4], wire.REALITY_PORT, at=t + 0.2)
                if label == 'twohop-tun' and self.direct_b_leak:
                    rows += syn(base + 9, wire.TWOHOP_B[4], wire.TWOHOP_PORTS['http'], at=t + 0.3)
            t += 5.0
            rows += marker_rows(index, 'close', label, t, lab_id)
            t += 5.0
        return rows, plain

    def artifact(self, name):
        _, plain = self.frames()
        if name == 'health.json':
            return json.dumps(health(self.served(), node=dict(alive_at_finish=True, exit_code=0))).encode()
        if name == 'https.json':
            sources = [wire.CLIENTS[4], wire.EGRESS, wire.SECOND_NODE_EGRESS]
            if self.include_target_b:
                sources.append(wire.TWOHOP_B[4])
            counts = [dict(source=source, method='GET', path_class='root', count=2) for source in sources]
            return json.dumps([dict(kind='counts', counts=counts, rows_dropped=0, counts_dropped=0)]).encode()
        if name == 'dns.json':
            rows = [dict(source=wire.EGRESS, transport='doh', name='listed.lab.test', type='A')]
            for phase in ('baseline', 'recovery'):
                rows.append(dict(source=wire.CLIENTS[4], transport='udp',
                                 name=self.profile.control_name(plain, phase), type='A'))
            if self.domain_b_dns:
                rows.append(dict(source=wire.CLIENTS[4], transport='udp', name=twohop.DOMAIN_B, type='A'))
            return json.dumps(rows).encode()
        return b'[]'


@controller_only
class TwoHopFlow(ListFlow):
    runs = 0

    def setUp(self):
        super().setUp()
        root = self.fixture.root
        (root / 'xray.exe').write_bytes(b'xray')
        self.pins['xray.exe'] = hashlib.sha256(b'xray').hexdigest()
        block = dict(self.config.pop('list'), proxy_port=10808,
                     agent_wait_seconds=180, script_seconds=120, runner_seconds=1600, poll_seconds=10,
                     xray=str(root / 'xray.exe'), xray_sha256=self.pins['xray.exe'])
        lab_block = dict(self.config['lab'], xray_sha256=HEX, proto_cert_sha256=HEX,
                         twohop_cert_sha256=HEX, twohop_untrusted_cert_sha256=HEX)
        self.config.update(schema=twohop.SCHEMA, suite='windows-twohop', twohop=block, lab=lab_block)

    def run_twohop(self, **changes):
        type(self).runs += 1
        cfg = dict(self.config, stand_id='twohop-%d' % type(self).runs,
                   state_directory=self.config['state_directory'] + '-th%d' % type(self).runs)
        machines = TwoHopMachines(self, **changes)

        def sleep(seconds):
            self.sleeps.append(seconds)
            self.clock.now += seconds

        def completion(directory, manifest):
            return any(v.run.directory == directory and v.closed for v in machines.vms.values())

        image = SimpleNamespace(identifier='windows-test', sha256=HEX, validate=lambda directory: None)
        with patch.object(__import__('socket'), 'AF_UNIX', 1, create=True), \
                patch.object(twohop.TwoHopProfile, 'preflight', return_value={}), \
                patch.object(windows_list_lab, 'preflight', return_value={}), \
                patch.object(windows_list_lab, 'SING_BOX_SHA256', self.pins['sing-box.exe']), \
                patch.object(windows_list_lab, 'load_windows_descriptor', return_value=image), \
                patch.object(windows_list_lab, 'completion_verified', side_effect=completion), \
                patch.object(windows_list_lab.windows_lab, 'completion_verified', side_effect=completion), \
                patch.object(windows_list_lab.windows_reboot, 'record',
                             side_effect=lambda vm, operation, **fields: machines.recorded.append((operation, fields))):
            return twohop.run(cfg, adapters=machines.adapters(), clock=lambda: self.clock.now,
                              sleep=sleep, progress=lambda stage: None), machines

    def test_clean_windows_twohop_run_accepts_across_all_4_windows(self):
        result, machines = self.run_twohop()
        section = result['execution']
        self.assertEqual(0, result['exit_code'], (section['findings'], section['unverified'], result['errors']))
        self.assertTrue(section['accepted'])
        self.assertEqual([], section['findings'])
        self.assertEqual([], section['unverified'])
        self.assertEqual(2, section['lab_actions'])
        self.assertEqual(10808, section['proxy_port'])
        self.assertEqual(['c1c2c3c4c5c6c7c8', 'd1d2d3d4d5d6d7d8'], [row['id'] for row in machines.action_replies])
        setup_call = machines.calls[0]
        self.assertEqual('setup', setup_call[0])
        self.assertEqual(dict(second_node=True, xray=True, two_hop=True,
                              xray_sha256=HEX, proto_cert_sha256=HEX,
                              twohop_cert_sha256=HEX, twohop_untrusted_cert_sha256=HEX),
                         setup_call[4]['extended_fixtures'])
        for label in twohop.JUDGED_LABELS:
            self.assertEqual('EXPECTED', section['windows'][label]['verdict'])

    def test_direct_b_connection_in_twohop_tun_window_is_refused(self):
        result, _ = self.run_twohop(direct_b_leak=True)
        self.assertEqual(1, result['exit_code'])
        self.assertIn('window-detected:twohop-tun', result['execution']['findings'])

    def test_dns_query_for_domain_b_is_refused(self):
        result, _ = self.run_twohop(domain_b_dns=True)
        self.assertEqual(1, result['exit_code'])
        self.assertIn('disagree:two-hop.domain-b-dns', result['execution']['findings'])

    def test_missing_target_b_in_https_evidence_is_refused(self):
        result, _ = self.run_twohop(include_target_b=False)
        self.assertEqual(1, result['exit_code'])
        self.assertIn('disagree:two-hop.target-b', result['execution']['findings'])

    def test_leftover_lockdown_provider_or_xray_fails_cleanup(self):
        result, _ = self.run_twohop(after_left=('lockdown_wfp_provider', 'xray_process'))
        self.assertEqual(1, result['exit_code'])
        self.assertIn('cleanup-left:lockdown_wfp_provider,xray_process', result['execution']['findings'])

    def test_large_lab_action_reply_chunks_under_script_limit(self):
        payload = dict(
            reality_public_key='A' * 43,
            twohop=dict(events=[
                dict(at=1700000000.0 + i, client=wire.SECOND_NODE_EGRESS, kind='http',
                     listen=wire.TWOHOP_B[4], out_source=wire.TWOHOP_B[4], port=3128,
                     status='ok', target='203.0.113.2:443')
                for i in range(90)
            ]),
        )
        action_id = 'a1b2c3d4e5f60718'
        scripts = guest.write_reply_scripts(twohop.ROOT, action_id, payload)
        self.assertGreater(len(scripts), 2)
        parts = []
        for script in scripts:
            self.assertTrue(guest.script_limit_ok(script), f'script too long: {len(script)}')
            self.assertTrue(guest.windows_guest.arguments(script))
            match = re.search(r"FromBase64String\('([^']*)'\)", script)
            if match:
                parts.append(base64.b64decode(match[1]))
        self.assertEqual(len(scripts) - 1, len(parts))
        self.assertEqual(payload, json.loads(b''.join(parts).decode('utf-8')))

    def test_planned_session_rotations_budget_bounds(self):
        from tools.vm.matrix import run_state
        rotations = twohop.TwoHopProfile.planned_session_rotations
        self.assertGreater(rotations, 0)
        self.assertEqual(run_state.BUDGETS['qga_recoveries'] + rotations,
                         run_state.limit('qga_recoveries', 0, 0, rotations))
        self.assertEqual(run_state.BUDGETS['qga_observations'] + rotations,
                         run_state.limit('qga_observations', 0, 0, rotations))
        with self.assertRaises(ValueError):
            run_state.limit('qga_recoveries', 0, 0, run_state.MAX_PLANNED_SESSION_ROTATIONS + 1)


if __name__ == '__main__':
    unittest.main()
