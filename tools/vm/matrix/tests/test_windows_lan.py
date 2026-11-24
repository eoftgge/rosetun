"""Stage 10d: Windows Local Network (LAN) suite, lab_protocol allowances, and lab-entry LAN fixtures, offline.

Tests cover:
- 72-check `lan-core.tsv` parity with `run-windows-lan.ps1` and `plan`/`report` CLI contracts;
- QGA payload/status ceilings for 72 checks and 11 windows;
- `windows_lan` configuration & CLI validation;
- Stage 10d `lab_protocol.py` allowances (`lan-peer-arp`, `shared-proxy-peer`, `shared-proxy-server`,
  `lan-mdns`, `lan-ssdp`, `lan-broadcast`, `extra-address-arp`) and multi-address `tunnel_addresses`;
- `lab-entry.py` Stage 10d helpers (`node_config(..., lan_fixtures=True)` and `validate_request` for
  `probe_proxy` / `lan_state` / `lan_fixtures`);
- Full synthetic two-machine `windows-lan` execution (positive + negative wire/cleanup cases).
"""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import struct
import tomllib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.vm.matrix import (cli, config as matrix_config, lab_protocol as wire, qga,
                             report as matrix_report, windows_lan as lan, windows_list_guest as guest,
                             windows_list_lab, windows_smoke)
from tools.vm.matrix.catalog import digest, read_catalog
from tools.vm.matrix.tests.posix_only import controller_only
from tools.vm.matrix.tests.test_lab import ip_frame, tcp, udp
from tools.vm.matrix.tests.test_lab_windows import health
from tools.vm.matrix.tests.test_windows_lab import HEX, marker_rows, request_arp
from tools.vm.matrix.tests.test_windows_list_lab import BOOT, RUN, UUID, ListFlow, ListMachines, syn

EXAMPLE = Path(__file__).resolve().parents[1] / 'execution-windows-lan.example.toml'
WINDOWS_ROOT = Path(__file__).resolve().parents[2] / 'windows'
LAB_ENTRY_PATH = Path(__file__).resolve().parents[2] / 'linux' / 'guest' / 'lab-entry.py'


def plan_files():
    rows = [dict(name=name, sha256=hashlib.sha256(name.encode()).hexdigest(), size=10 + n, pinned=True)
            for n, name in enumerate(guest.BINARIES)]
    rows += [dict(name=name, sha256=hashlib.sha256(name.encode()).hexdigest(), size=20, pinned=False)
             for name in (guest.PLAN_FILE, *lan.SCRIPTS)]
    return rows


def windows_for(profile, run=RUN):
    return [(wire.window_marker(run, index, 'open', label), wire.window_marker(run, index, 'close', label))
            for index, label in enumerate(profile.labels)]


def arp_for(src_ip, target_ip, *, src_mac=wire.MACS['test'], dst_mac='ff:ff:ff:ff:ff:ff'):
    def mac_bytes(text):
        return bytes.fromhex(text.replace(':', ''))

    def ip_bytes(text):
        return bytes(int(part) for part in text.split('.'))

    eth = mac_bytes(dst_mac) + mac_bytes(src_mac) + struct.pack('!H', 0x0806)
    payload = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + mac_bytes(src_mac) + ip_bytes(src_ip) + bytes(6) + ip_bytes(target_ip)
    return eth + payload


def load_lab_entry():
    spec = importlib.util.spec_from_file_location('rosetun_lab_entry_stage10d', LAB_ENTRY_PATH)
    module = importlib.util.module_from_spec(spec)
    with patch.dict('sys.modules', {'lab_protocol': wire}):
        spec.loader.exec_module(module)
    return module


class CatalogAndPlanTests(unittest.TestCase):
    def test_all_72_lan_checks_are_referenced_by_runner(self):
        profile = lan.LanProfile(long_session_seconds=30)
        self.assertEqual(72, len(profile.checks))
        runner = (WINDOWS_ROOT / 'guest' / lan.ENTRY).read_text(encoding='utf-8')
        for check in profile.checks:
            with self.subTest(check=check):
                self.assertIn(f"'{check}'", runner)

    def test_plan_and_report_cli_contract_for_windows_lan(self):
        out = io.StringIO()
        with patch.object(cli, 'load_profile', return_value={'mode': 'exploratory'}), contextlib.redirect_stdout(out):
            self.assertEqual(0, cli.main(['plan', 'windows-lan', '--config', 'profiles.toml', '--profile', 'exploratory']))
        planned = json.loads(out.getvalue())
        self.assertEqual(('rosetun.matrix.plan.v1', 'windows-lan'), (planned['schema'], planned['suite']))
        self.assertEqual(digest(read_catalog(matrix_config.LAN_CATALOG)), planned['catalog_digest'])
        with self.assertRaisesRegex(ValueError, 'requires the guest journal and independent lab evidence'):
            matrix_report.assess({}, {}, planned)

    def test_plan_scripts_and_72_check_payloads_fit_qga_limits(self):
        plain = wire.dns_checks(RUN, lambda: '1' * 24)['plain']
        profile = lan.LanProfile(long_session_seconds=600)
        plan = profile.plan_document(RUN, windows_for(profile, RUN), plain, 8388, plan_files())
        self.assertEqual(lan.PREFIX + 'job.v1', plan['schema'])
        self.assertEqual(600, plan['long_session_seconds'])
        self.assertEqual(wire.ROUTED_NODE, plan['request']['node']['server'])
        self.assertEqual(wire.PRIVATE_BEHIND_ROUTER, plan['addresses']['private_behind_router'])
        self.assertEqual(11, len(profile.labels))
        self.assertTrue(guest.script_limit_ok(profile.start_script(plan_files())))
        self.assertTrue(guest.script_limit_ok(profile.collect_script()))
        self.assertTrue(guest.script_limit_ok(profile.after_script()))

        identity = dict(run_id='11111111-2222-4333-8444-555555555555', vm_id=UUID, boot_id=BOOT)
        rec_plan = dict(schema=lan.PREFIX + 'plan.v1', suite='windows-lan', profile='exploratory',
                        policy=dict(mode='exploratory'), identity=identity, catalog=profile.catalog,
                        catalog_digest=digest(profile.catalog))
        events = [dict(schema=lan.PREFIX + 'event.v1', run_id=identity['run_id'], sequence=i + 1,
                       id=cid, result='PASS', reason='checked') for i, cid in enumerate(profile.checks)]
        report = dict(schema=lan.PREFIX + 'report.v1', identity=identity, boot_id_at_end=BOOT,
                      checks=events, summary={'total': len(events), 'pass': len(events), 'fail': 0, 'skip': 0},
                      cleanup=dict(status='PASS'), errors=[])
        rec_status = dict(schema=lan.PREFIX + 'status.v1', identity=identity,
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
        self.assertLess(len(payload.encode('utf-8')), lan.COLLECT_ANSWER_LIMIT)
        self.assertEqual(UUID, profile.collected(payload)['identity']['uuid'])

        status_doc = dict(
            schema=guest.STATUS_SCHEMA, run=RUN, state='lab-action-requested', step='lan-on', sequence=50,
            started_utc='2026-11-24T00:00:00.000Z', updated_utc='2026-11-24T00:05:00.000Z',
            checks=[dict(id=cid, result='PASS', reason='checked', scenario='lan', note='ok') for cid in profile.checks],
            markers=[dict(label=label, word=word, marker=f'rosetun-lab-marker:{RUN}.{idx}.{word}.{label}',
                          ack=f'rosetun-lab-ack:rosetun-lab-marker:{RUN}.{idx}.{word}.{label}',
                          error=None, utc='2026-11-24T00:01:00.000Z')
                     for idx, label in enumerate(profile.labels) for word in ('open', 'close')],
            notes=[dict(name='long-session-seconds', value=600)],
            cleanup=None,
            error=None,
            action=dict(id='1111222233334444', operation='lan_state', params={}),
        )
        raw_status = json.dumps(status_doc, separators=(',', ':'))
        self.assertLess(len(raw_status.encode('utf-8')), lan.STATUS_ANSWER_LIMIT)
        parsed = profile.runner_status(raw_status, RUN)
        self.assertEqual(('lab-action-requested', 'lan_state'), (parsed['state'], parsed['action']['operation']))


class ConfigTests(unittest.TestCase):
    def example(self):
        with EXAMPLE.open('rb') as stream:
            config = tomllib.load(stream)
        config['state_directory'] = str(Path(__file__).resolve().parent / 'state')
        return config

    def test_example_validates_and_rejects_bad_lan_configs(self):
        config = self.example()
        with patch.object(windows_smoke, '_state_path', create=True), patch.object(windows_list_lab, '_state_path'):
            validated = windows_smoke.validate(config)
        self.assertEqual(('windows-lan', lan.SCHEMA, 600),
                         (validated['suite'], validated['schema'], validated['lan']['long_session_seconds']))
        for bad in (
            lambda c: c['lan'].update(long_session_seconds=5),
            lambda c: c['lan'].update(long_session_seconds=901),
            lambda c: c['lan'].update(long_session_seconds=True),
            lambda c: c['lan'].update(long_session_seconds=600, runner_seconds=600),
            lambda c: c.update(list=dict(c['lan'])),
            lambda c: c.update(proxy=dict(c['lan'])),
            lambda c: c.update(suite='windows-list'),
        ):
            bad_cfg = self.example()
            bad(bad_cfg)
            with patch.object(windows_list_lab, '_state_path'), self.assertRaises(ValueError):
                lan.validate(bad_cfg)

    def test_cli_dry_run_and_flag_refusals(self):
        out = io.StringIO()
        with patch.object(windows_smoke, '_state_path', create=True), patch.object(windows_list_lab, '_state_path'), \
                patch.object(windows_smoke, 'load', side_effect=lambda path: windows_smoke.validate(self.example())), \
                patch.object(lan, 'preflight', return_value={'suite': 'windows-lan', 'long_session_seconds': 600}) as pre, \
                contextlib.redirect_stdout(out):
            self.assertEqual(0, cli.main(['run', 'windows-lan', '--config', 'x', '--dry-run']))
            pre.assert_called_once()
            for flags in (['--lab'], ['--control', 'stop-helper'], ['--diagnostic']):
                self.assertEqual(2, cli.main(['run', 'windows-lan', '--config', str(EXAMPLE), *flags]))


class WireAllowancesAndLabEntryTests(unittest.TestCase):
    def test_stage_10d_allowances_and_routed_tunnel_address(self):
        samples = [
            ('lan-peer-arp', arp_for(wire.CLIENTS[4], wire.LAN_PEER)),
            ('shared-proxy-peer', ip_frame(wire.LAN_PEER, wire.CLIENTS[4], 6, tcp(45000, 10808, flags=0x02),
                                           src=wire.MACS['lab'], dst=wire.MACS['test'])),
            ('shared-proxy-server', ip_frame(wire.GATEWAYS[4], wire.CLIENTS[4], 6, tcp(45001, 10808, flags=0x02),
                                             src=wire.MACS['lab'], dst=wire.MACS['test'])),
            ('lan-mdns', ip_frame(wire.CLIENTS[4], wire.MDNS_GROUP, 17, udp(5353, wire.MDNS_PORT, b'm'),
                                  dst='01:00:5e:00:00:fb')),
            ('lan-ssdp', ip_frame(wire.CLIENTS[4], wire.SSDP_GROUP, 17, udp(50000, wire.SSDP_PORT, b's'),
                                  dst='01:00:5e:7f:ff:fa')),
            ('lan-broadcast', ip_frame(wire.CLIENTS[4], '255.255.255.255', 17, udp(50001, wire.LAN_BROADCAST_PORT, b'b'),
                                       dst='ff:ff:ff:ff:ff:ff')),
            ('extra-address-arp', arp_for(wire.EXTRA_ADDRESS, wire.EXTRA_ADDRESS)),
        ]
        for name, raw in samples:
            with self.subTest(allowance=name):
                frame = wire.parse(raw)
                self.assertEqual(name, wire._allowance(frame, {name}, proxy_port=10808))
                # Must stay unexpected when the allowance is NOT opted in.
                self.assertIsNone(wire._allowance(frame, set(), proxy_port=10808))

        # Routed Shadowsocks node 203.0.113.10:8388 is classified as tunnel ONLY when listed in tunnel_addresses.
        routed = wire.parse(ip_frame(wire.CLIENTS[4], wire.ROUTED_NODE, 6, tcp(52000, 8388, flags=0x02)))
        self.assertFalse(wire._tunnel_frame(routed, 8388))
        self.assertTrue(wire._tunnel_frame(routed, 8388, lan.TUNNEL_ADDRESSES))
        self.assertEqual('node', wire._flow_kind((wire.ROUTED_NODE, 8388), 8388, lan.TUNNEL_ADDRESSES))
        self.assertEqual('other', wire._flow_kind((wire.ROUTED_NODE, 8388), 8388))

    def test_lab_entry_node_config_and_probe_proxy_validation_for_stage_10d(self):
        entry = load_lab_entry()
        tunnel = dict(port=8388, method='aes-128-gcm', password='password123')
        cfg_plain = entry.node_config(tunnel, lan_fixtures=False)
        self.assertEqual(1, len(cfg_plain['inbounds']))
        self.assertEqual(wire.GATEWAYS[4], cfg_plain['inbounds'][0]['listen'])
        self.assertNotIn('dns', cfg_plain)
        self.assertNotIn('default_domain_resolver', cfg_plain['route'])
        cfg_lan = entry.node_config(tunnel, lan_fixtures=True)
        self.assertEqual([wire.GATEWAYS[4], wire.ROUTED_NODE], [item['listen'] for item in cfg_lan['inbounds']])
        self.assertEqual([{'type': 'udp', 'tag': 'lab-dns', 'server': wire.RESOLVER}], cfg_lan['dns']['servers'])
        self.assertEqual('lab-dns', cfg_lan['route']['default_domain_resolver'])

        for bad in (
            dict(source='198.51.100.99', port=10808, mode='http_proxy'),
            dict(source=wire.LAN_PEER, port=0, mode='http_proxy'),
            dict(source=wire.LAN_PEER, port=10808, mode='ftp'),
            dict(source=wire.LAN_PEER, port=10808),
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                entry.probe_proxy(bad)


class LanMachines(ListMachines):
    """Two-machine fake for Windows LAN runs across all 11 windows."""

    def __init__(self, test, *, long_session_seconds=30, lan_off_leak=False, include_private_flow=True,
                 routed_node_present=True, after_left=(), **kwargs):
        self.profile = lan.LanProfile(long_session_seconds=long_session_seconds)
        self.lan_off_leak = lan_off_leak
        self.include_private_flow = include_private_flow
        self.routed_node_present = routed_node_present
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
                     scenario='lan', note='ok') for check in self.profile.checks]
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
                   checks=rows, markers=acks, notes=[dict(name='long-session-seconds', value=30)],
                   cleanup=None if (self.cleanup is None or state not in guest.ENDED) else
                   dict(result=self.cleanup, parts=dict(connection='PASS', address='PASS', helper='PASS', files='PASS')),
                   error=error, action=None)
        if state == 'lab-action-requested':
            doc['action'] = dict(id='b0b1b2b3b4b5b6b7', operation='lan_state', params={})
        return doc

    def program(self, path, arguments):
        self.programs.append((path, list(arguments)))
        self.test.assertEqual((guest.CMD, ['/c', 'type', lan.ROOT + r'\status.json']), (path, list(arguments)))
        self.polls += 1
        if self.polls == 1:
            return SimpleNamespace(exitcode=1, stdout=b'', stderr=b'')
        idx = min(self.polls - 2, len(self.poll_states) - 1)
        state = self.poll_states[idx]
        self.events.append(('poll', self.polls, state))
        return SimpleNamespace(exitcode=0, stdout=json.dumps(self.status(state, 10 + idx * 5)).encode(), stderr=b'')

    def recorded_files(self):
        identity = dict(run_id='11111111-2222-4333-8444-555555555555', vm_id=self.uuid or UUID, boot_id=BOOT)
        plan = dict(schema=lan.PREFIX + 'plan.v1', suite='windows-lan', profile='exploratory',
                    policy=dict(mode='exploratory'), identity=identity, catalog=self.profile.catalog,
                    catalog_digest=digest(self.profile.catalog))
        events = []
        for check in self.profile.checks:
            result = self.results_of().get(check, 'SKIP')
            reason = 'checked' if result == 'PASS' else 'condition-false' if result == 'FAIL' else 'interrupted'
            events.append(dict(schema=lan.PREFIX + 'event.v1', run_id=identity['run_id'],
                               sequence=len(events) + 1, id=check, result=result, reason=reason))
        counts = {name: sum(1 for e in events if e['result'] == name) for name in ('PASS', 'FAIL', 'SKIP')}
        report = dict(schema=lan.PREFIX + 'report.v1', identity=identity, boot_id_at_end=BOOT, checks=events,
                      summary={'total': len(events), 'pass': counts['PASS'], 'fail': counts['FAIL'], 'skip': counts['SKIP']},
                      cleanup=dict(status=self.cleanup), errors=[])
        status = dict(schema=lan.PREFIX + 'status.v1', identity=identity, state='finished', event_count=len(events))
        return dict(plan=json.dumps(plan), events=''.join(json.dumps(e) + '\n' for e in events),
                    report=json.dumps(report), status=json.dumps(status))

    def powershell(self, script):
        if 'medium-not-found' in script:
            self.note('guest-start')
            wanted = json.loads(re.search(r"ConvertFrom-Json '([^']*)'", script)[1])
            for name, digest_hex in wanted.items():
                if hashlib.sha256(self.disc[name]).hexdigest() != digest_hex:
                    raise AssertionError('disc digest mismatch')
            return json.dumps(dict(medium='E:\\', files=len(wanted), task=lan.TASK))
        if 'action-reply-' in script:
            self.note('guest-action-reply')
            b64 = re.search(r"FromBase64String\('([^']*)'\)", script)[1]
            action_id = re.search(r"action-reply-([0-9a-f]{16})\.json", script)[1]
            reply = json.loads(__import__('base64').b64decode(b64).decode('utf-8'))
            self.action_replies.append(dict(id=action_id, payload=reply))
            return json.dumps(dict(wrote=True, id=action_id))
        if 'extra_address' in script:
            self.note('guest-after')
            state = dict(wfp_provider=False, wfp_sublayer=False, runner_task=False, helper_task=False,
                         helper_process=False, engine_process=False, tunnel_adapter=False,
                         binaries=False, list_directory=False, root_removed=True,
                         extra_address=False, lan_directory=False)
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

        class LanLabGuest(base_guest):
            def call(self, operation, expected, window=(), canary=False, tunnel=None, options=None):
                if operation == 'lan_state':
                    machines.note('lab-lan-state')
                    machines.calls.append((operation, expected, list(window), tunnel, options))
                    return dict(mdns=['tok-mdns-1'], ssdp=['tok-ssdp-1'], broadcast=['tok-bcast-1'],
                                tcp=dict(peer=1, server=0, echo=1, hold=1))
                return super().call(operation, expected, window=window, canary=canary, tunnel=tunnel, options=options)

        adapters.guest = LanLabGuest
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
            elif label == 'lan-on':
                if self.routed_node_present:
                    rows += syn(53000, wire.ROUTED_NODE, 8388, at=t)
                rows.append((t + 0.1, arp_for(wire.CLIENTS[4], wire.LAN_PEER)))
                rows += syn(53001, wire.LAN_PEER, wire.LAN_LISTENER_PORT, at=t + 0.2)
                rows += syn(53002, wire.LAN_PEER, wire.LAN_ECHO_PORT, at=t + 0.3)
                rows.append((t + 0.4, ip_frame(wire.CLIENTS[4], wire.MDNS_GROUP, 17, udp(5353, wire.MDNS_PORT, b'm'),
                                               dst='01:00:5e:00:00:fb')))
                rows.append((t + 0.5, ip_frame(wire.CLIENTS[4], wire.SSDP_GROUP, 17, udp(50000, wire.SSDP_PORT, b's'),
                                               dst='01:00:5e:7f:ff:fa')))
                rows.append((t + 0.6, ip_frame(wire.CLIENTS[4], '255.255.255.255', 17,
                                               udp(50001, wire.LAN_BROADCAST_PORT, b'b'), dst='ff:ff:ff:ff:ff:ff')))
            elif label == 'address-change':
                rows += syn(53100, wire.ROUTED_NODE, 8388, at=t)
                rows.append((t + 0.1, arp_for(wire.EXTRA_ADDRESS, wire.EXTRA_ADDRESS)))
            elif label == 'lan-rule':
                rows += syn(53200, wire.ROUTED_NODE, 8388, at=t)
                rows.append((t + 0.1, arp_for(wire.CLIENTS[4], wire.LAN_PEER)))
                rows += syn(53201, wire.LAN_PEER, wire.LAN_LISTENER_PORT, at=t + 0.2)
            elif label == 'lan-private':
                rows += syn(53300, wire.ROUTED_NODE, 8388, at=t)
                if self.include_private_flow:
                    rows.append((t + 0.2, ip_frame(wire.CLIENTS[4], wire.PRIVATE_BEHIND_ROUTER, 6,
                                                   tcp(53301, 80, flags=0x02))))
            elif label == 'lan-off':
                rows += syn(53400, wire.ROUTED_NODE, 8388, at=t)
                if self.lan_off_leak:
                    rows += syn(53401, wire.LAN_PEER, wire.LAN_LISTENER_PORT, at=t + 0.2)
            elif label == 'switch':
                rows += syn(53500, wire.ROUTED_NODE, 8388, at=t)
                rows.append((t + 0.2, ip_frame(wire.CLIENTS[4], '255.255.255.255', 17,
                                               udp(50002, wire.LAN_BROADCAST_PORT, b'b'), dst='ff:ff:ff:ff:ff:ff')))
            elif label == 'lan-server':
                rows += syn(53600, wire.GATEWAYS[4], 8388, at=t)
                rows.append((t + 0.1, arp_for(wire.CLIENTS[4], wire.LAN_PEER)))
                rows += syn(53601, wire.LAN_PEER, wire.LAN_LISTENER_PORT, at=t + 0.2)
            elif label == 'lan-server-private':
                rows += syn(53700, wire.GATEWAYS[4], 8388, at=t)
                rows.append((t + 0.2, ip_frame(wire.CLIENTS[4], wire.PRIVATE_BEHIND_ROUTER, 6,
                                               tcp(53701, 80, flags=0x02))))
            elif label == 'lan-reopen':
                rows += syn(53800, wire.GATEWAYS[4], 8388, at=t)
                rows += syn(53801, wire.GATEWAYS[4], wire.LAN_LISTENER_PORT, at=t + 0.2)
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
class LanFlow(ListFlow):
    runs = 0

    def setUp(self):
        super().setUp()
        block = dict(self.config.pop('list'), long_session_seconds=30,
                     agent_wait_seconds=180, script_seconds=120, runner_seconds=1600, poll_seconds=15)
        self.config.update(schema=lan.SCHEMA, suite='windows-lan', lan=block)

    def run_lan(self, **changes):
        type(self).runs += 1
        cfg = dict(self.config, stand_id='lan-%d' % type(self).runs,
                   state_directory=self.config['state_directory'] + '-ln%d' % type(self).runs)
        machines = LanMachines(self, **changes)

        def sleep(seconds):
            self.sleeps.append(seconds)
            self.clock.now += seconds

        def completion(directory, manifest):
            return any(v.run.directory == directory and v.closed for v in machines.vms.values())

        image = SimpleNamespace(identifier='windows-test', sha256=HEX, validate=lambda directory: None)
        with patch.object(__import__('socket'), 'AF_UNIX', 1, create=True), \
                patch.object(lan.LanProfile, 'preflight', return_value={}), \
                patch.object(windows_list_lab, 'preflight', return_value={}), \
                patch.object(windows_list_lab, 'SING_BOX_SHA256', self.pins['sing-box.exe']), \
                patch.object(windows_list_lab, 'load_windows_descriptor', return_value=image), \
                patch.object(windows_list_lab, 'completion_verified', side_effect=completion), \
                patch.object(windows_list_lab.windows_lab, 'completion_verified', side_effect=completion), \
                patch.object(windows_list_lab.windows_reboot, 'record',
                             side_effect=lambda vm, operation, **fields: machines.recorded.append((operation, fields))):
            return lan.run(cfg, adapters=machines.adapters(), clock=lambda: self.clock.now,
                           sleep=sleep, progress=lambda stage: None), machines

    def test_clean_windows_lan_run_accepts_across_all_11_windows(self):
        result, machines = self.run_lan()
        section = result['execution']
        self.assertEqual(0, result['exit_code'], (section['findings'], section['unverified'], result['errors']))
        self.assertTrue(section['accepted'])
        self.assertEqual([], section['findings'])
        self.assertEqual([], section['unverified'])
        self.assertEqual(1, section['lab_actions'])
        self.assertEqual('b0b1b2b3b4b5b6b7', machines.action_replies[0]['id'])
        self.assertTrue(machines.pair_options.get('lan'))
        self.assertEqual('EXPECTED', section['windows']['lan-on']['verdict'])
        self.assertEqual('EXPECTED', section['windows']['address-change']['verdict'])
        self.assertEqual('EXPECTED', section['windows']['lan-private']['verdict'])
        self.assertEqual('EXPECTED', section['windows']['lan-off']['verdict'])
        self.assertEqual('EXPECTED', section['windows']['lan-server']['verdict'])
        self.assertEqual('EXPECTED', section['windows']['lan-server-private']['verdict'])
        self.assertEqual('EXPECTED', section['windows']['lan-reopen']['verdict'])

    def test_peer_leak_in_lan_off_window_is_refused(self):
        result, _ = self.run_lan(lan_off_leak=True)
        self.assertEqual(1, result['exit_code'])
        self.assertIn('window-detected:lan-off', result['execution']['findings'])

    def test_missing_private_behind_flow_is_refused(self):
        result, _ = self.run_lan(include_private_flow=False)
        self.assertEqual(1, result['exit_code'])
        self.assertIn('disagree:lan-private.behind-router-direct', result['execution']['findings'])

    def test_leftover_extra_address_fails_cleanup(self):
        result, _ = self.run_lan(after_left=('extra_address',))
        self.assertEqual(1, result['exit_code'])
        self.assertIn('cleanup-left:extra_address', result['execution']['findings'])


if __name__ == '__main__':
    unittest.main()
