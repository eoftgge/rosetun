"""Check the Windows Upgrade controller and its guest evidence contract offline."""

import contextlib
import hashlib
import io
import json
from pathlib import Path
import re
import socket
import tempfile
import tomllib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.vm.matrix import (cli, lab_protocol as wire, qga, report as matrix_report,
                             windows_list_guest as guest, windows_list_lab as lab, windows_media,
                             windows_smoke, windows_upgrade as upgrade)
from tools.vm.matrix.catalog import digest
from tools.vm.matrix.tests.posix_only import controller_only
from tools.vm.matrix.tests.test_lab import ip_frame, udp
from tools.vm.matrix.tests.test_lab_windows import health
from tools.vm.matrix.tests.test_windows_lab import HEX, marker_rows, request_arp
from tools.vm.matrix.tests.test_windows_list_lab import BOOT, RUN, UUID, ListFlow, ListMachines, status_document, syn

EXAMPLE = Path(__file__).resolve().parents[1] / 'execution-windows-upgrade.example.toml'
WINDOWS_ROOT = Path(__file__).resolve().parents[2] / 'windows'
SUITE = 'windows-upgrade'
INSTALLERS = ('old-setup.exe', 'new-setup.exe')
STRICT = ('lockdown', 'kill-switch', 'broken')


def markers_for(profile, run):
    return [(wire.window_marker(run, index, 'open', label), wire.window_marker(run, index, 'close', label))
            for index, label in enumerate(profile.labels)]


def recorded_files(profile, cleanup='PASS'):
    identity = dict(run_id=RUN, vm_id=UUID, boot_id=BOOT)
    plan = dict(schema=upgrade.PREFIX + 'plan.v1', suite=SUITE, profile='exploratory',
                policy={'mode': 'exploratory'}, identity=identity, catalog=profile.catalog,
                catalog_digest=digest(profile.catalog))
    events = [dict(schema=upgrade.PREFIX + 'event.v1', run_id=RUN, sequence=index,
                   id=check, result='PASS', reason='checked') for index, check in enumerate(profile.checks, 1)]
    report = dict(schema=upgrade.PREFIX + 'report.v1', identity=identity, boot_id_at_end=BOOT, checks=events,
                  summary={'total': len(events), 'pass': len(events), 'fail': 0, 'skip': 0},
                  cleanup={'status': cleanup}, errors=[])
    status = dict(schema=upgrade.PREFIX + 'status.v1', identity=identity, state='finished', event_count=len(events))
    return dict(plan=json.dumps(plan, separators=(',', ':')),
                events=''.join(json.dumps(event, separators=(',', ':')) + '\n' for event in events),
                report=json.dumps(report, separators=(',', ':')),
                status=json.dumps(status, separators=(',', ':')))


class ContractTests(unittest.TestCase):
    def test_catalog_matches_the_runner_check_order_and_fits_qga(self):
        profile = upgrade.UpgradeProfile()
        source = (WINDOWS_ROOT / 'guest' / upgrade.ENTRY).read_bytes()
        self.assertLess(len(source), 65536)
        ids = re.findall(rb"\bTest-Step -Id '([^']+)'", source)
        self.assertEqual(profile.checks, tuple(check.decode('ascii') for check in ids))
        self.assertTrue(all(row['required'] for row in profile.catalog))
        self.assertEqual({'baseline', 'lockdown', 'kill-switch', 'no-kill-switch', 'broken', 'recovery'},
                         {check.split('.')[0] for check in profile.checks})

        files = [dict(name=name, sha256=hashlib.sha256(name.encode()).hexdigest(), size=64,
                      pinned=name in upgrade.BINARIES)
                 for name in (*upgrade.BINARIES, guest.PLAN_FILE, *upgrade.SCRIPTS)]
        plain = wire.dns_checks(RUN, lambda: '1' * 24)['plain']
        plan = profile.plan_document(RUN, markers_for(profile, RUN), plain, 8388, files)
        self.assertEqual(upgrade.PREFIX + 'job.v1', plan['schema'])
        self.assertEqual(180, plan['setup_timeout_seconds'])
        self.assertEqual(set(upgrade.BINARIES), {row['name'] for row in plan['files']})
        self.assertTrue(set(INSTALLERS).issubset(upgrade.BINARIES))
        self.assertEqual(8388, plan['request']['node']['port'])
        self.assertEqual(set(profile.labels) | {'port'}, set(plan['markers']))
        for script in (profile.start_script(files), profile.collect_script(), profile.after_script()):
            self.assertTrue(guest.script_limit_ok(script))
        answer = json.dumps(dict(recorded_files(profile), helper_tail='x' * 3000,
                                 identity={'uuid': UUID}), separators=(',', ':'))
        self.assertLess(len(answer.encode('utf-8')), qga.EXEC_OUTPUT_LIMIT)
        self.assertEqual(UUID, profile.collected(answer)['identity']['uuid'])

    def test_cleanup_probe_requires_an_explicit_result_for_the_upgrade_hold(self):
        profile = upgrade.UpgradeProfile()
        state = dict.fromkeys(guest.UPGRADE_AFTER_FIELDS, False)
        state['root_removed'] = True
        self.assertIn('496d09fa-1d9a-451b-871f-35ba72197795', profile.after_script())
        self.assertEqual([], profile.after(json.dumps(state))['left'])
        state['upgrade_hold_wfp_provider'] = True
        self.assertEqual(['upgrade_hold_wfp_provider'], profile.after(json.dumps(state))['left'])
        del state['upgrade_hold_wfp_provider']
        with self.assertRaises(guest.RunnerAnswerError):
            profile.after(json.dumps(state))

    def test_cli_plan_matches_the_catalog_and_report_requires_independent_wire_evidence(self):
        profile = upgrade.UpgradeProfile()
        out = io.StringIO()
        with patch.object(cli, 'load_profile', return_value={'mode': 'exploratory'}), contextlib.redirect_stdout(out):
            code = cli.main(['plan', SUITE, '--config', 'profiles.toml', '--profile', 'exploratory'])
        self.assertEqual(0, code)
        planned = json.loads(out.getvalue())
        self.assertEqual(digest(profile.catalog), planned['catalog_digest'])
        with self.assertRaisesRegex(ValueError, 'requires the guest journal and independent lab evidence'):
            matrix_report.assess({}, {}, planned)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, body in recorded_files(profile).items():
                (root / (name + ('.jsonl' if name == 'events' else '.json'))).write_text(body, encoding='utf-8')
            report, plan = root / 'report.json', root / 'plan.json'
            self.assertTrue(profile.assess_files(report, plan)['acceptance']['accepted'])
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = cli.main(['report', str(report), '--plan', str(plan)])
            self.assertEqual(2, code)
            self.assertFalse(json.loads(out.getvalue())['acceptance']['accepted'])

    def test_setup_media_sources_are_pinned_and_both_files_are_staged(self):
        data = tomllib.loads(EXAMPLE.read_text(encoding='utf-8'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pins = {}
            for position, name in zip(('old_setup', 'new_setup'), INSTALLERS):
                path = root / name
                path.write_bytes(name.encode('ascii'))
                pins[name] = hashlib.sha256(path.read_bytes()).hexdigest()
                data['upgrade'].update({position: str(path), position + '_sha256': pins[name]})
            sources = [row for row in lab.media_sources(data) if row[0] in INSTALLERS]
            target = root / 'iso'
            target.mkdir()
            staged = windows_media.stage(target, sources, {})
            self.assertEqual(pins, {row['name']: row['sha256'] for row in staged if row['pinned']})
            for name in INSTALLERS:
                self.assertEqual((root / name).read_bytes(), (target / name).read_bytes())
            (root / 'new-setup.exe').write_bytes(b'changed')
            changed_target = root / 'changed-iso'
            changed_target.mkdir()
            with self.assertRaisesRegex(windows_media.MediaError, 'source-mismatch'):
                windows_media.stage(changed_target, sources, {})


class ConfigTests(unittest.TestCase):
    def example(self):
        data = tomllib.loads(EXAMPLE.read_text(encoding='utf-8'))
        data['state_directory'] = str(EXAMPLE.parent / 'state')
        return data

    def test_windows_v8_is_dispatched_and_rejects_malformed_installer_pins(self):
        data = self.example()
        self.assertEqual((SUITE, upgrade.SCHEMA), (data['suite'], data['schema']))
        self.assertIs(data, windows_smoke.validate(data))
        for invalid in ({'old_setup': ''}, {'new_setup': 1}, {'old_setup_sha256': 'A' * 64},
                        {'new_setup_sha256': '1' * 63}, {'setup_timeout_seconds': True},
                        {'setup_timeout_seconds': 0}, {'setup_timeout_seconds': 86400},
                        {'setup_timeout_seconds': 180, 'runner_seconds': 180},
                        {'new_setup_sha256': data['upgrade']['old_setup_sha256']},
                        {'new_setup': data['upgrade']['old_setup']}, {'unexpected': 'value'}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                upgrade.validate(dict(data, upgrade=dict(data['upgrade'], **invalid)))
        with self.assertRaises(ValueError):
            upgrade.validate(dict(data, list=data['upgrade']))

    def test_execution_cli_dispatches_dry_run_and_rejects_other_lab_modes(self):
        with patch.object(windows_smoke, 'load', return_value=self.example()), \
                patch.object(upgrade, 'preflight', return_value={'suite': SUITE}) as preflight, \
                contextlib.redirect_stdout(io.StringIO()):
            args = ['run', SUITE, '--config', str(EXAMPLE)]
            self.assertEqual(0, cli.main([*args, '--dry-run']))
            preflight.assert_called_once_with(self.example(), dry_run=True)
            for flags in (['--lab'], ['--control', 'stop-helper'], ['--diagnostic']):
                self.assertEqual(2, cli.main([*args, *flags]))


class UpgradeMachines(ListMachines):
    def __init__(self, test, *, leak=None, tunnel=True, open_flow=True, left=()):
        super().__init__(test, left=left)
        self.profile = upgrade.UpgradeProfile()
        self.leak, self.tunnel, self.open_flow = leak, tunnel, open_flow

    def status(self, state):
        markers = []
        for label, (opening, closing) in zip(self.profile.labels, markers_for(self.profile, self.lab_id)):
            for word, probe in (('open', opening), ('close', closing)):
                token = wire.marker_query(probe).decode('ascii')
                markers.append(dict(label=label, word=word, marker=token, ack=wire.ACK_PREFIX + token,
                                    error=None, utc='2026-11-24T00:01:00.000Z'))
        checks = [dict(id=check, result='PASS', reason='checked', scenario='upgrade', note='checked')
                  for check in self.profile.checks]
        status = status_document(self.lab_id, state=state, sequence=40 if state == 'finished' else 20,
                                 cleanup='PASS' if state == 'finished' else None, checks=checks, notes=[])
        status['markers'] = markers
        return status

    def program(self, path, arguments):
        self.test.assertEqual((guest.CMD, ['/c', 'type', upgrade.ROOT + r'\status.json']), (path, list(arguments)))
        self.polls += 1
        state = self.states[min(self.polls - 1, len(self.states) - 1)]
        return SimpleNamespace(exitcode=0, stdout=json.dumps(self.status(state)).encode(), stderr=b'')

    def recorded_files(self):
        return recorded_files(self.profile, self.cleanup)

    def powershell(self, script):
        if 'medium-not-found' in script:
            return json.dumps(dict(json.loads(super().powershell(script)), task=upgrade.TASK))
        if 'engine_process' in script:
            self.note('guest-after')
            state = dict.fromkeys(guest.UPGRADE_AFTER_FIELDS, False)
            state['root_removed'] = True
            state.update(dict.fromkeys(self.left, True))
            return json.dumps(state)
        return super().powershell(script)

    def served(self):
        return [(index, word, label) for index, label in enumerate(self.profile.labels) for word in ('open', 'close')]

    def frames(self):
        run = self.lab_id
        plain = wire.dns_checks(run, lambda: '0' * 24)['plain']
        plain['nonce'] = self.plan['baseline']['dns_name'].split('.')[1]
        rows = [(1.0, request_arp())]
        for index, label in enumerate(self.profile.labels):
            start = 10.0 + index * 10
            rows += marker_rows(index, 'open', label, start, run)
            if label in ('baseline', 'recovery') or (label == 'no-kill-switch' and self.open_flow):
                rows += syn(51000 + index, wire.TARGETS[4], 443, at=start + 1)
            if label == 'baseline':
                query = ip_frame(wire.CLIENTS[4], wire.RESOLVER, 17, udp(52000, 53, wire.query(plain)))
                answer = ip_frame(wire.RESOLVER, wire.CLIENTS[4], 17, udp(53, 52000, wire.answer(plain)),
                                  src=wire.MACS['lab'], dst=wire.MACS['test'])
                rows += [(start + 2, query), (start + 2.01, answer)]
            if label == 'kill-switch' and self.tunnel:
                rows += syn(53000, wire.GATEWAYS[4], 8388, at=start + 2)
            if label == self.leak:
                rows += syn(54000, wire.TARGETS[4], 443, at=start + 3)
            rows += marker_rows(index, 'close', label, start + 5, run)
        return rows, plain

    def artifact(self, name):
        if name == 'health.json':
            return json.dumps(health(self.served(), node=dict(alive_at_finish=True, exit_code=0))).encode()
        if name == 'dns.json':
            _, plain = self.frames()
            rows = [dict(source=wire.EGRESS, transport='doh', name='listed.lab.test', type='A')]
            rows.extend(dict(source=wire.CLIENTS[4], transport='udp',
                             name=self.profile.control_name(plain, label), type='A')
                        for label in ('baseline', 'recovery'))
            return json.dumps(rows).encode()
        return super().artifact(name)


@controller_only
class UpgradeFlow(ListFlow):
    def setUp(self):
        super().setUp()
        block = dict(self.config.pop('list'), setup_timeout_seconds=180, runner_seconds=1200)
        for role, name in zip(('old_setup', 'new_setup'), INSTALLERS):
            path = self.fixture.root / name
            path.write_bytes(name.encode('ascii'))
            block.update({role: str(path), role + '_sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        self.config.update(schema=upgrade.SCHEMA, suite=SUITE, upgrade=block)

    def run_upgrade(self, **changes):
        machines = UpgradeMachines(self, **changes)

        def sleep(seconds):
            self.clock.now += seconds

        def completion(directory, manifest):
            return any(vm.run.directory == directory and vm.closed for vm in machines.vms.values())

        image = SimpleNamespace(identifier='windows-test', sha256=HEX, validate=lambda directory: None)
        with patch.object(socket, 'AF_UNIX', 1, create=True), \
                patch.object(upgrade.UpgradeProfile, 'preflight', return_value={}), \
                patch.object(lab, 'SING_BOX_SHA256', self.pins['sing-box.exe']), \
                patch.object(lab, 'load_windows_descriptor', return_value=image), \
                patch.object(lab, 'completion_verified', side_effect=completion), \
                patch.object(lab.windows_lab, 'completion_verified', side_effect=completion), \
                patch.object(lab.windows_reboot, 'record',
                             side_effect=lambda vm, operation, **fields: machines.recorded.append((operation, fields))):
            result = upgrade.run(self.config, adapters=machines.adapters(), clock=lambda: self.clock.now,
                                 sleep=sleep, progress=lambda stage: None)
        return result, machines

    def test_clean_run_captures_every_window_and_records_the_setup_pins(self):
        result, machines = self.run_upgrade()
        section = result['execution']
        self.assertEqual(0, result['exit_code'], (section['findings'], section['unverified'], result['errors']))
        self.assertTrue(section['accepted'])
        self.assertTrue(section['image_unchanged'])
        self.assertEqual({'runner': 'PASS', 'left': []}, section['cleanup'])
        self.assertEqual({'lab': True, 'test': True}, result['completion'])
        self.assertFalse(result['qualified'])
        self.assertTrue(machines.pair_options['upgrade'])
        self.assertEqual(set(upgrade.LABELS), set(section['windows']))
        for label in (*STRICT, 'no-kill-switch'):
            self.assertEqual('EXPECTED', section['windows'][label]['verdict'])
        self.assertTrue(all(row['result'] == 'PASS' for row in section['checks']))
        for name in INSTALLERS:
            digest_hex = hashlib.sha256(machines.disc[name]).hexdigest()
            record = next(row for row in section['media']['files'] if row['name'] == name)
            self.assertEqual(digest_hex, record['sha256'])

    def test_direct_traffic_during_an_interrupted_upgrade_is_a_finding(self):
        result, _ = self.run_upgrade(leak='broken')
        self.assertEqual(1, result['exit_code'])
        self.assertIn('window-detected:broken', result['execution']['findings'])

    def test_a_missing_open_control_cannot_be_accepted(self):
        result, _ = self.run_upgrade(open_flow=False)
        self.assertEqual(1, result['exit_code'])
        self.assertIn('window-mismatch:no-kill-switch', result['execution']['findings'])

    def test_the_tunnel_claim_requires_independent_wire_traffic(self):
        result, _ = self.run_upgrade(tunnel=False)
        self.assertEqual(1, result['exit_code'])
        self.assertIn('disagree:kill-switch.tunnel', result['execution']['findings'])

    def test_persistent_upgrade_hold_fails_the_independent_cleanup_probe(self):
        result, _ = self.run_upgrade(left=('upgrade_hold_wfp_provider',))
        self.assertEqual(1, result['exit_code'])
        self.assertIn('cleanup-left:upgrade_hold_wfp_provider', result['execution']['findings'])

    def test_the_modified_installer_is_refused_before_either_vm_starts(self):
        Path(self.config['upgrade']['new_setup']).write_bytes(b'changed')
        result, machines = self.run_upgrade()
        self.assertEqual(2, result['exit_code'])
        self.assertEqual('windows-media-source-mismatch', result['errors'][0]['reason'])
        self.assertNotIn('start-lab', machines.names())


if __name__ == '__main__':
    unittest.main()
