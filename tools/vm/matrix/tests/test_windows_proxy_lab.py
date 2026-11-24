"""Stage 10d: Windows Proxy suite on the isolated lab wire, offline.

Tests cover check-ID parity between `proxy-checks.json` and `run-windows-proxy.ps1`, QGA payload and
status ceilings for 46 checks, configuration and CLI validation, `lab-action-requested` (`probe_proxy`)
round-trip through `windows_list_lab.run_guest_suite`, wire allowances (`sharing-strict` and `lockdown`),
and full synthetic two-machine execution (positive + negative wire/cleanup cases).
"""

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

from tools.vm.matrix import (cli, lab_protocol as wire, qga, windows_list_guest as guest,
                             windows_list_lab, windows_proxy, windows_proxy_lab as proxy_lab,
                             windows_smoke)
from tools.vm.matrix.catalog import digest
from tools.vm.matrix.tests.posix_only import controller_only
from tools.vm.matrix.tests.test_lab import ip_frame, tcp, udp
from tools.vm.matrix.tests.test_lab_windows import health
from tools.vm.matrix.tests.test_windows_lab import HEX, marker_rows, request_arp
from tools.vm.matrix.tests.test_windows_list_lab import BOOT, RUN, UUID, ListFlow, ListMachines, syn

EXAMPLE = Path(__file__).resolve().parents[1] / 'execution-windows-proxy.example.toml'
PROXY_ROOT = Path(__file__).resolve().parents[2] / 'windows'


def plan_files():
    rows = [dict(name=name, sha256=hashlib.sha256(name.encode()).hexdigest(), size=10 + n, pinned=True)
            for n, name in enumerate(proxy_lab.BINARIES)]
    rows += [dict(name=name, sha256=hashlib.sha256(name.encode()).hexdigest(), size=20, pinned=False)
             for name in (guest.PLAN_FILE, *proxy_lab.SCRIPTS)]
    return rows


def windows_for(profile, run=RUN):
    return [(wire.window_marker(run, index, 'open', label), wire.window_marker(run, index, 'close', label))
            for index, label in enumerate(profile.labels)]


def inbound_proxy(source_ip, sport, proxy_port, *, syn_ack=True, at=10.0):
    """Peer (router/LAN) connecting inbound to the test VM's shared SOCKS5 proxy."""
    rows = [(at, ip_frame(source_ip, wire.CLIENTS[4], 6, tcp(sport, proxy_port, flags=0x02),
                          src=wire.MACS['lab'], dst=wire.MACS['test']))]
    if syn_ack:
        rows.append((at + 0.01, ip_frame(wire.CLIENTS[4], source_ip, 6, tcp(proxy_port, sport, flags=0x12))))
    return rows


class CatalogAndPlanTests(unittest.TestCase):
    def test_all_46_proxy_checks_are_referenced_by_runner(self):
        profile = proxy_lab.ProxyProfile(proxy_port=10808)
        self.assertEqual(46, len(profile.checks))
        runner = (PROXY_ROOT / 'guest' / proxy_lab.ENTRY).read_text(encoding='utf-8')
        for check in profile.checks:
            with self.subTest(check=check):
                self.assertIn(f"'{check}'", runner)

    def test_plan_scripts_and_46_check_payloads_fit_qga_limits(self):
        plain = wire.dns_checks(RUN, lambda: '1' * 24)['plain']
        profile = proxy_lab.ProxyProfile(proxy_port=10808)
        plan = profile.plan_document(RUN, windows_for(profile, RUN), plain, 8388, plan_files())
        self.assertEqual('rosetun.windows-proxy.job.v1', plan['schema'])
        self.assertEqual(10808, plan['proxy_port'])
        self.assertEqual(wire.LAN_PEER, plan['addresses']['lan_peer'])
        self.assertEqual(list(proxy_lab.BINARIES), [row['name'] for row in plan['files']])
        self.assertEqual(proxy_lab.LABELS, tuple(plan['markers'][label]['open'].split('.')[-1] for label in profile.labels))
        self.assertTrue(guest.script_limit_ok(profile.start_script(plan_files())))
        self.assertTrue(guest.script_limit_ok(profile.collect_script()))
        self.assertTrue(guest.script_limit_ok(profile.after_script()))
        reply_script = guest.write_reply_script(proxy_lab.ROOT, '0123456789abcdef', dict(ok=True, result=dict(connected=True)))
        self.assertTrue(guest.script_limit_ok(reply_script))

        identity = dict(run_id='11111111-2222-4333-8444-555555555555', vm_id=UUID, boot_id=BOOT)
        rec_plan = windows_proxy.make_plan('exploratory', dict(mode='exploratory'),
                                           use_host_node=True, keep_node=False, proxy_port=10808)
        rec_plan['identity'] = identity
        events = [dict(schema=windows_proxy.PREFIX + 'event.v1', run_id=identity['run_id'], sequence=i + 1,
                       id=cid, result='PASS', reason='checked') for i, cid in enumerate(profile.checks)]
        components = {name: ('NOT_CREATED' if name == 'node' else 'PASS') for name in windows_proxy.COMPONENTS}
        report = dict(schema=windows_proxy.PREFIX + 'report.v1', identity=identity, boot_id_at_end=BOOT,
                      checks=events, summary={'total': len(events), 'pass': len(events), 'fail': 0, 'skip': 0},
                      cleanup=dict(status='PASS', components=components), errors=[])
        rec_status = dict(schema=windows_proxy.PREFIX + 'status.v1', identity=identity,
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
        self.assertLess(len(payload.encode('utf-8')), proxy_lab.COLLECT_ANSWER_LIMIT)
        self.assertEqual(UUID, profile.collected(payload)['identity']['uuid'])

        status_doc = dict(
            schema=guest.STATUS_SCHEMA, run=RUN, state='lab-action-requested', step='sharing-strict', sequence=20,
            started_utc='2026-11-24T00:00:00.000Z', updated_utc='2026-11-24T00:02:00.000Z',
            checks=[dict(id=cid, result='PASS', reason='checked', scenario='proxy', note='ok') for cid in profile.checks],
            markers=[dict(label=label, word=word, marker=f'rosetun-lab-marker:{RUN}.{idx}.{word}.{label}',
                          ack=f'rosetun-lab-ack:rosetun-lab-marker:{RUN}.{idx}.{word}.{label}',
                          error=None, utc='2026-11-24T00:01:00.000Z')
                     for idx, label in enumerate(profile.labels) for word in ('open', 'close')],
            notes=[dict(name='proxy-port', value=10808)],
            cleanup=None,
            error=None,
            action=dict(id='0123456789abcdef', operation='probe_proxy', params=dict(source=wire.LAN_PEER, port=10808, mode='http_proxy')),
        )
        raw_status = json.dumps(status_doc, separators=(',', ':'))
        self.assertLess(len(raw_status.encode('utf-8')), proxy_lab.STATUS_ANSWER_LIMIT)
        parsed_status = profile.runner_status(raw_status, RUN)
        self.assertEqual(('lab-action-requested', 'probe_proxy'),
                         (parsed_status['state'], parsed_status['action']['operation']))


class ConfigTests(unittest.TestCase):
    def example(self):
        with EXAMPLE.open('rb') as stream:
            config = tomllib.load(stream)
        config['state_directory'] = str(Path(__file__).resolve().parent / 'state')
        return config

    def test_example_validates_and_rejects_bad_proxy_configs(self):
        config = self.example()
        with patch.object(windows_smoke, '_state_path', create=True), patch.object(windows_list_lab, '_state_path'):
            validated = windows_smoke.validate(config)
        self.assertEqual(('windows-proxy', proxy_lab.SCHEMA, 10808),
                         (validated['suite'], validated['schema'], validated['proxy']['proxy_port']))
        for bad in (
            lambda c: c['proxy'].update(proxy_port=80),
            lambda c: c['proxy'].update(proxy_port=70000),
            lambda c: c['proxy'].update(proxy_port=c['lab']['tunnel']['node_port']),
            lambda c: c['proxy'].update(desktop_proxy=''),
            lambda c: c['proxy'].update(desktop_proxy_sha256='A' * 64),
            lambda c: c.update(list=dict(c['proxy'])),
            lambda c: c.update(lan=dict(c['proxy'])),
            lambda c: c.update(suite='windows-list'),
        ):
            bad_cfg = self.example()
            bad(bad_cfg)
            with patch.object(windows_list_lab, '_state_path'), self.assertRaises(ValueError):
                proxy_lab.validate(bad_cfg)

    def test_cli_dry_run_and_flag_refusals(self):
        out = io.StringIO()
        with patch.object(windows_smoke, '_state_path', create=True), patch.object(windows_list_lab, '_state_path'), \
                patch.object(windows_smoke, 'load', side_effect=lambda path: windows_smoke.validate(self.example())), \
                patch.object(proxy_lab, 'preflight', return_value={'suite': 'windows-proxy', 'proxy_port': 10808}) as pre, \
                contextlib.redirect_stdout(out):
            self.assertEqual(0, cli.main(['run', 'windows-proxy', '--config', 'x', '--dry-run']))
            pre.assert_called_once()
            for flags in (['--lab'], ['--control', 'stop-helper'], ['--diagnostic']):
                self.assertEqual(2, cli.main(['run', 'windows-proxy', '--config', str(EXAMPLE), *flags]))


class ProxyMachines(ListMachines):
    """Two-machine fake for Windows Proxy lab runs, including lab-action probe_proxy round-trips."""

    def __init__(self, test, *, proxy_port=10808, strict_direct=0, peer_answered=True, server_answered=False,
                 lockdown_peer_answered=False, lockdown_peer_allowed=True, after_left=(), **kwargs):
        self.profile = proxy_lab.ProxyProfile(proxy_port=proxy_port)
        self.proxy_port = proxy_port
        self.strict_direct = strict_direct
        self.peer_answered = peer_answered
        self.server_answered = server_answered
        self.lockdown_peer_answered = lockdown_peer_answered
        self.lockdown_peer_allowed = lockdown_peer_allowed
        self.after_left = tuple(after_left)
        self.action_replies = []
        super().__init__(test, session_direct=0, **kwargs)
        self.poll_states = ['running', 'lab-action-requested', 'finished']

    def results_of(self):
        return self.results or {check: 'PASS' for check in self.profile.checks}

    def status(self, state, seq):
        error = self.runner_error if state in guest.ENDED else None
        results = self.results_of()
        rows = [dict(id=check, result=results.get(check, 'SKIP'),
                     reason='checked' if results.get(check, 'SKIP') == 'PASS' else 'condition-false',
                     scenario='proxy', note='ok') for check in self.profile.checks]
        acks = []
        for label, (opening, closing) in zip(self.profile.labels, windows_for(self.profile, self.lab_id)):
            for word, marker in (('open', opening), ('close', closing)):
                text = wire.marker_query(marker).decode()
                acks.append(dict(label=label, word=word, marker=text,
                                 ack=wire.ACK_PREFIX + text if self.markers else None,
                                 error=None, utc='2026-11-24T00:05:00.000Z'))
        doc = dict(schema=guest.STATUS_SCHEMA, run=self.lab_id, state=state,
                   step='done' if state in guest.ENDED else state, sequence=seq,
                   started_utc='2026-11-24T00:00:00.000Z', updated_utc='2026-11-24T00:06:00.000Z',
                   checks=rows, markers=acks, notes=[dict(name='proxy-port', value=self.proxy_port)],
                   cleanup=None if (self.cleanup is None or state not in guest.ENDED) else
                   dict(result=self.cleanup, parts=dict(lan='PASS', watch='PASS', listener='PASS',
                                                        connection='PASS', lockdown='PASS', desktop='PASS',
                                                        files='PASS')),
                   error=error, action=None)
        if state == 'lab-action-requested':
            doc['action'] = dict(id='a0a1a2a3a4a5a6a7', operation='probe_proxy',
                                 params=dict(source=wire.LAN_PEER, port=self.proxy_port, mode='http_proxy'))
        return doc

    def program(self, path, arguments):
        self.programs.append((path, list(arguments)))
        self.test.assertEqual((guest.CMD, ['/c', 'type', proxy_lab.ROOT + r'\status.json']), (path, list(arguments)))
        self.polls += 1
        if self.polls == 1:
            return SimpleNamespace(exitcode=1, stdout=b'', stderr=b'')
        idx = min(self.polls - 2, len(self.poll_states) - 1)
        state = self.poll_states[idx]
        self.events.append(('poll', self.polls, state))
        return SimpleNamespace(exitcode=0, stdout=json.dumps(self.status(state, 10 + idx * 5)).encode(), stderr=b'')

    def recorded_files(self):
        identity = dict(run_id='11111111-2222-4333-8444-555555555555', vm_id=self.uuid or UUID, boot_id=BOOT)
        plan = windows_proxy.make_plan('exploratory', dict(mode='exploratory'),
                                       use_host_node=True, keep_node=False, proxy_port=self.proxy_port)
        plan['identity'] = identity
        events = []
        for check in self.profile.checks:
            result = self.results_of().get(check, 'SKIP')
            reason = 'checked' if result == 'PASS' else 'condition-false' if result == 'FAIL' else 'interrupted'
            events.append(dict(schema=windows_proxy.PREFIX + 'event.v1', run_id=identity['run_id'],
                               sequence=len(events) + 1, id=check, result=result, reason=reason))
        counts = {name: sum(1 for e in events if e['result'] == name) for name in ('PASS', 'FAIL', 'SKIP')}
        components = {name: ('NOT_CREATED' if name == 'node' else self.cleanup) for name in windows_proxy.COMPONENTS}
        report = dict(schema=windows_proxy.PREFIX + 'report.v1', identity=identity, boot_id_at_end=BOOT,
                      checks=events,
                      summary={'total': len(events), 'pass': counts['PASS'], 'fail': counts['FAIL'], 'skip': counts['SKIP']},
                      cleanup=dict(status=self.cleanup, components=components), errors=[])
        status = dict(schema=windows_proxy.PREFIX + 'status.v1', identity=identity, state='finished',
                      event_count=len(events))
        return dict(plan=json.dumps(plan), events=''.join(json.dumps(e) + '\n' for e in events),
                    report=json.dumps(report), status=json.dumps(status))

    def powershell(self, script):
        if 'medium-not-found' in script:
            self.note('guest-start')
            wanted = json.loads(re.search(r"ConvertFrom-Json '([^']*)'", script)[1])
            for name, digest_hex in wanted.items():
                if hashlib.sha256(self.disc[name]).hexdigest() != digest_hex:
                    raise AssertionError('disc digest mismatch')
            return json.dumps(dict(medium='E:\\', files=len(wanted), task=proxy_lab.TASK))
        if 'action-reply-' in script:
            self.note('guest-action-reply')
            b64 = re.search(r"FromBase64String\('([^']*)'\)", script)[1]
            action_id = re.search(r"action-reply-([0-9a-f]{16})\.json", script)[1]
            reply = json.loads(__import__('base64').b64decode(b64).decode('utf-8'))
            self.action_replies.append(dict(id=action_id, payload=reply))
            return json.dumps(dict(wrote=True, id=action_id))
        if 'proxy_user' in script:
            self.note('guest-after')
            state = dict(wfp_provider=False, wfp_sublayer=False, runner_task=False, helper_task=False,
                         helper_process=False, engine_process=False, tunnel_adapter=False,
                         binaries=False, list_directory=False, root_removed=True,
                         lockdown_wfp_provider=False, lockdown_wfp_sublayer=False, lockdown_service=False,
                         egress_watch_task=False, proxy_user=False, desktop_task=False, desktop_process=False)
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

        class ProxyLabGuest(base_guest):
            def call(self, operation, expected, window=(), canary=False, tunnel=None, options=None):
                if operation == 'probe_proxy':
                    machines.note('lab-probe-proxy')
                    machines.calls.append((operation, expected, list(window), tunnel, options))
                    return dict(ok=True, reason='ok', status=200, body_ok=True, elapsed_ms=12)
                return super().call(operation, expected, window=window, canary=canary, tunnel=tunnel, options=options)

        adapters.guest = ProxyLabGuest
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
            elif label == 'strict':
                rows += syn(53000, wire.GATEWAYS[4], 8388, at=t)
                for n in range(self.strict_direct):
                    rows += syn(54000 + n, wire.TARGETS[4], 443, at=t + 0.2 + n * 0.05)
            elif label == 'sharing-strict':
                rows += syn(53100, wire.GATEWAYS[4], 8388, at=t)
                rows += inbound_proxy(wire.LAN_PEER, 45001, self.proxy_port,
                                      syn_ack=self.peer_answered, at=t + 0.2)
                rows += inbound_proxy(wire.GATEWAYS[4], 45002, self.proxy_port,
                                      syn_ack=self.server_answered, at=t + 0.4)
            elif label == 'lockdown':
                rows += syn(53200, wire.GATEWAYS[4], 8388, at=t)
                rows += inbound_proxy(wire.LAN_PEER, 45003, self.proxy_port,
                                      syn_ack=self.lockdown_peer_answered, at=t + 0.2)
                rows += inbound_proxy(wire.LAN_PEER, 45004, self.proxy_port,
                                      syn_ack=self.lockdown_peer_allowed, at=t + 0.4)
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
                rows.append(dict(source=wire.CLIENTS[4], transport='udp',
                                 name=self.profile.control_name(plain, phase), type='A'))
            return json.dumps(rows).encode()
        return b'[]'


@controller_only
class ProxyFlow(ListFlow):
    runs = 0

    def setUp(self):
        super().setUp()
        root = self.fixture.root
        dp = b'desktop-proxy-binary'
        (root / 'desktop_proxy.exe').write_bytes(dp)
        self.pins['desktop_proxy.exe'] = hashlib.sha256(dp).hexdigest()
        block = dict(self.config.pop('list'), proxy_port=10808,
                     desktop_proxy=str(root / 'desktop_proxy.exe'),
                     desktop_proxy_sha256=self.pins['desktop_proxy.exe'],
                     agent_wait_seconds=180, script_seconds=120, runner_seconds=1200, poll_seconds=15)
        self.config.update(schema=proxy_lab.SCHEMA, suite='windows-proxy', proxy=block)

    def run_proxy(self, **changes):
        type(self).runs += 1
        cfg = dict(self.config, stand_id='proxy-%d' % type(self).runs,
                   state_directory=self.config['state_directory'] + '-px%d' % type(self).runs)
        machines = ProxyMachines(self, **changes)

        def sleep(seconds):
            self.sleeps.append(seconds)
            self.clock.now += seconds

        def completion(directory, manifest):
            return any(v.run.directory == directory and v.closed for v in machines.vms.values())

        image = SimpleNamespace(identifier='windows-test', sha256=HEX, validate=lambda directory: None)
        with patch.object(__import__('socket'), 'AF_UNIX', 1, create=True), \
                patch.object(proxy_lab.ProxyProfile, 'preflight', return_value={}), \
                patch.object(windows_list_lab, 'preflight', return_value={}), \
                patch.object(windows_list_lab, 'SING_BOX_SHA256', self.pins['sing-box.exe']), \
                patch.object(windows_list_lab, 'load_windows_descriptor', return_value=image), \
                patch.object(windows_list_lab, 'completion_verified', side_effect=completion), \
                patch.object(windows_list_lab.windows_lab, 'completion_verified', side_effect=completion), \
                patch.object(windows_list_lab.windows_reboot, 'record',
                             side_effect=lambda vm, operation, **fields: machines.recorded.append((operation, fields))):
            return proxy_lab.run(cfg, adapters=machines.adapters(), clock=lambda: self.clock.now,
                                 sleep=sleep, progress=lambda stage: None), machines

    def test_clean_windows_proxy_run_accepts_with_lab_action_roundtrip(self):
        result, machines = self.run_proxy()
        section = result['execution']
        self.assertEqual(0, result['exit_code'], (section['findings'], section['unverified'], result['errors']))
        self.assertTrue(section['accepted'])
        self.assertEqual([], section['findings'])
        self.assertEqual([], section['unverified'])
        self.assertEqual(1, section['lab_actions'])
        self.assertEqual('a0a1a2a3a4a5a6a7', machines.action_replies[0]['id'])
        self.assertTrue(machines.action_replies[0]['payload']['ok'])
        self.assertTrue(machines.pair_options.get('proxy'))
        self.assertEqual('EXPECTED', section['windows']['strict']['verdict'])
        self.assertEqual('EXPECTED', section['windows']['sharing-strict']['verdict'])
        self.assertEqual('EXPECTED', section['windows']['lockdown']['verdict'])

    def test_direct_leak_in_strict_window_is_refused(self):
        result, _ = self.run_proxy(strict_direct=1)
        self.assertEqual(1, result['exit_code'])
        self.assertFalse(result['execution']['accepted'])
        self.assertIn('window-detected:strict', result['execution']['findings'])

    def test_sharing_strict_and_lockdown_cross_checks_catch_wire_disagreement(self):
        for name, kwargs, expected_finding in (
            ('peer-unanswered', dict(peer_answered=False), 'disagree:sharing.strict.host'),
            ('server-answered', dict(server_answered=True), 'disagree:sharing.strict.server'),
            ('lockdown-peer-answered', dict(lockdown_peer_answered=True), 'disagree:lockdown.host-blocked'),
            ('lockdown-peer-unanswered', dict(lockdown_peer_allowed=False), 'disagree:lockdown.host-allowed'),
        ):
            with self.subTest(name=name):
                result, _ = self.run_proxy(**kwargs)
                self.assertEqual(1, result['exit_code'])
                self.assertIn(expected_finding, result['execution']['findings'])

    def test_leftover_desktop_user_or_watch_task_fails_cleanup(self):
        result, _ = self.run_proxy(after_left=('proxy_user', 'egress_watch_task'))
        self.assertEqual(1, result['exit_code'])
        self.assertIn('cleanup-left:egress_watch_task,proxy_user', result['execution']['findings'])


if __name__ == '__main__':
    unittest.main()
