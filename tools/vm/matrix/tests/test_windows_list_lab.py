"""Stage 10a: the List suite of a Windows guest in the lab, offline.

The runner (a PowerShell script of the checkout) is not run here: what is checked is everything the controller does
around it. The files of the disc and their hashes, the plan and the start script, the reading of the status file, the
artifacts of the Hyper-V matrix as the recorder writes them, the two windows the observer judges and every verdict and exit
code that follows from them. The two machines are the fakes of the stage 9d tests, and the guest answers each script from
its own data, so what is shown is the controller's order, its judgement and its refusals. What the real runner does
with the real Rosetun is checked on the stand.
"""

import hashlib
import json
from pathlib import Path
import re
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.vm.matrix import (lab, lab_protocol as wire, windows_list, windows_list_guest as guest, windows_list_lab,
                             windows_media, windows_noise, windows_smoke)
from tools.vm.matrix.lifecycle import LifecycleError
from tools.vm.matrix.tests.posix_only import controller_only
from tools.vm.matrix.tests.test_lab import Endpoint, ip_frame, tcp, udp
from tools.vm.matrix.tests.test_windows_lab import (Flow, HEX, Machines, marker_rows, request_arp, llmnr, network_answer,
                                                    timed_capture)
from tools.vm.matrix.tests.test_lab_windows import health

EXAMPLE = Path(__file__).resolve().parents[1] / 'execution-windows-list.example.toml'
BOOT = 'win-4'
UUID = '12345678-1234-4234-8234-123456789abc'
RUN = 'a' * 32


def plan_files():
    """The rows of a disc as `windows_media.stage` makes them, for plans made without a disc."""
    rows = [dict(name=name, sha256=hashlib.sha256(name.encode()).hexdigest(), size=10 + n, pinned=True)
            for n, name in enumerate(guest.BINARIES)]
    rows += [dict(name=name, sha256=hashlib.sha256(name.encode()).hexdigest(), size=20, pinned=False)
             for name in (guest.PLAN_FILE, *guest.SCRIPTS)]
    return rows


def windows_for(run=RUN):
    return [(wire.window_marker(run, index, 'open', label), wire.window_marker(run, index, 'close', label))
            for index, label in enumerate(guest.LABELS)]


def plan_for(run=RUN):
    plain = wire.dns_checks(run, lambda: '1' * 24)['plain']
    return guest.plan_document(run, windows_for(run), plain, 8388, plan_files())


class PlanTests(unittest.TestCase):
    def test_the_plan_names_the_lab_the_markers_the_files_and_nothing_the_guest_may_decide(self):
        plan = plan_for()
        self.assertEqual(guest.PLAN_SCHEMA, plan['schema'])
        self.assertEqual(dict(client4='192.0.2.2', target4='203.0.113.2', resolver='203.0.113.53'), plan['addresses'])
        self.assertEqual(9100, plan['markers']['port'])
        for label, index in (('baseline', 0), ('session', 1)):
            for word in ('open', 'close'):
                self.assertEqual('rosetun-lab-marker:%s.%d.%s.%s' % (RUN, index, word, label), plan['markers'][label][word])
        self.assertEqual(['rosetun.exe', 'rosetun-helper-privileged.exe', 'sing-box.exe'], [f['name'] for f in plan['files']])
        self.assertEqual({'listed': 'listed.lab.test', 'unlisted': 'unlisted.lab.test'}, plan['names'])
        self.assertRegex(plan['baseline']['dns_name'], r'^a{32}\.1{24}\.lab\.test$')

    def test_the_configuration_of_the_matrix_is_the_hyper_v_one_on_the_lab_node_with_documentation_addresses_only(self):
        config = plan_for()['config']
        self.assertEqual(3, config['version'])
        settings = config['settings']
        self.assertEqual((True, False, False, False), (settings['kill_switch'], settings['allow_lan'],
                                                       settings['private_networks'], settings['auto_reconnect']))
        node, = config['subscriptions'][0]['nodes']
        self.assertEqual(('192.0.2.1', 8388), (node['server'], node['port']))
        rule, = config['rule_sets'][0]['rules']
        self.assertEqual(('block', dict(list=dict(list='1', category=None))), (rule['target'], rule['matcher']))
        self.assertEqual('text', config['lists'][0]['format'])
        # The guest fills in the list's size and hash once it has written the file.
        self.assertEqual((0, ''), (config['lists'][0]['size'], config['lists'][0]['sha256']))

    def test_a_plan_needs_both_windows_and_the_three_binaries(self):
        plain = wire.dns_checks(RUN, lambda: '1' * 24)['plain']
        with self.assertRaises(ValueError):
            guest.plan_document(RUN, windows_for()[:1], plain, 8388, plan_files())
        with self.assertRaises(ValueError):
            guest.plan_document(RUN, windows_for(), plain, 8388, plan_files()[1:])

    def test_the_eleven_checks_of_the_hyper_v_matrix_are_the_ones_the_suite_runs(self):
        hyper_v = json.loads((Path(windows_list.ROOT) / 'list-checks.json').read_text(encoding='utf-8'))
        self.assertEqual([row['id'] for row in hyper_v], list(windows_list_lab.CHECKS))
        self.assertEqual(11, len(windows_list_lab.CHECKS))
        runner = (Path(windows_list.ROOT) / 'guest' / 'run-windows-list.ps1').read_text(encoding='utf-8')
        for check in windows_list_lab.CHECKS:
            self.assertIn("-Id '%s'" % check, runner)

    def test_the_start_script_carries_the_hashes_of_the_files_it_may_copy_and_fits_the_limit(self):
        rows = plan_files()
        script = guest.start_script(rows)
        self.assertLess(len(script), 6000)
        self.assertNotIn("'", script.split("ConvertFrom-Json '")[1].split("'")[0])
        wanted = json.loads(re.search(r"ConvertFrom-Json '([^']*)'", script)[1])
        self.assertEqual({guest.PLAN_FILE, *guest.SCRIPTS}, set(wanted))
        self.assertEqual(hashlib.sha256(b'lib.ps1').hexdigest(), wanted['lib.ps1'])
        self.assertIn(windows_media.LABEL, script)
        self.assertNotIn('rosetun.exe', script)
        from tools.vm.matrix import windows_guest
        windows_guest.arguments(script, windows_guest.SCRIPT_LIMIT_MAX)
        self.assertTrue(guest.script_limit_ok(guest.collect_script()) and guest.script_limit_ok(guest.after_script()))

    def test_a_start_answer_must_name_the_drive_the_file_count_and_the_task(self):
        good = json.dumps(dict(medium='E:\\', files=5, task='RosetunListRunner'))
        self.assertEqual('E:\\', guest.started(good)['medium'])
        for change in (dict(medium='E:'), dict(medium='\\\\x\\y\\'), dict(files=4), dict(task='Other'), dict(extra=1)):
            with self.subTest(change=change), self.assertRaises(guest.RunnerAnswerError):
                guest.started(json.dumps(dict(json.loads(good), **change)))


def status_document(run=RUN, state='finished', results=None, cleanup='PASS', markers=True, error=None, windows=None, **changes):
    results = results or {check: 'PASS' for check in windows_list_lab.CHECKS}
    rows = []
    for check in windows_list_lab.CHECKS:
        result = results.get(check, 'SKIP')
        reason = 'checked' if result == 'PASS' else 'condition-false' if result == 'FAIL' else 'interrupted'
        rows.append(dict(id=check, result=result, reason=reason, scenario='text block', note='exit 0'))
    acks = []
    for label, (opening, closing) in zip(guest.LABELS, windows or windows_for(run)):
        for word, marker in (('open', opening), ('close', closing)):
            text = wire.marker_query(marker).decode()
            acks.append(dict(label=label, word=word, marker=text, ack=wire.ACK_PREFIX + text if markers else None,
                             error=None, utc='2026-11-20T00:10:00.000Z'))
    value = dict(schema=guest.STATUS_SCHEMA, run=run, state=state, step='done', sequence=40,
                 started_utc='2026-11-20T00:09:00.000Z', updated_utc='2026-11-20T00:11:00.000Z', checks=rows,
                 markers=acks, notes=[dict(name='sing-box-first-launch-seconds', value=7)],
                 cleanup=None if cleanup is None else dict(result=cleanup, parts=dict(list_directory='PASS', helper='PASS')),
                 error=error)
    value.update(changes)
    return value


class StatusTests(unittest.TestCase):
    def test_a_status_of_the_shape_is_read(self):
        value = guest.runner_status(json.dumps(status_document()), RUN)
        self.assertEqual(('finished', 11), (value['state'], len(value['checks'])))

    def test_each_departure_from_the_shape_is_refused(self):
        good = status_document()
        bad = [dict(good, extra=1), dict(good, run='b' * 32), dict(good, state='done'), dict(good, sequence=0),
               dict(good, schema='x'), dict(good, updated_utc='yesterday'), dict(good, step='A step!'),
               dict(good, checks=[dict(good['checks'][0], result='MAYBE')]),
               dict(good, checks=[dict(good['checks'][0], note='x' * 200)]),
               dict(good, markers=[dict(good['markers'][0], label='other')]),
               dict(good, markers=[dict(good['markers'][0], ack=5)]),
               dict(good, notes=[dict(name='n', value='text')]),
               dict(good, cleanup=dict(result='MAYBE', parts={})),
               dict(good, cleanup=dict(result='PASS', parts=dict(a='MAYBE'))),
               dict(good, error=dict(place='x')), dict(good, checks=[good['checks'][0]] * 40)]
        for item in bad:
            with self.subTest(item=str(item)[:50]), self.assertRaises(guest.RunnerAnswerError):
                guest.runner_status(json.dumps(item), RUN)
        for text in ('', 'x', '[]', 'x' * (guest.ANSWER_LIMIT + 1)):
            with self.assertRaises(guest.RunnerAnswerError):
                guest.runner_status(text, RUN)

    def test_a_marker_counts_only_when_it_was_sent_once_with_its_own_text_and_acknowledged(self):
        windows = windows_for()
        good = guest.markers_of(guest.runner_status(json.dumps(status_document()), RUN), windows)
        self.assertTrue(all(good[label][word]['sent'] and good[label][word]['acknowledged']
                            for label in guest.LABELS for word in ('open', 'close')))
        silent = guest.markers_of(guest.runner_status(json.dumps(status_document(markers=False)), RUN), windows)
        self.assertEqual((True, False), (silent['session']['close']['sent'], silent['session']['close']['acknowledged']))
        twice = status_document()
        twice['markers'] = twice['markers'] + [twice['markers'][0]]
        repeated = guest.markers_of(guest.runner_status(json.dumps(twice), RUN), windows)
        self.assertEqual((False, False), (repeated['baseline']['open']['sent'], repeated['baseline']['open']['acknowledged']))
        wrong = status_document()
        wrong['markers'][1] = dict(wrong['markers'][1], marker='rosetun-lab-marker:' + RUN + '.0.close.other')
        self.assertFalse(guest.markers_of(guest.runner_status(json.dumps(wrong), RUN), windows)['baseline']['close']['sent'])
        missing = status_document()
        missing['markers'] = missing['markers'][:3]
        self.assertFalse(guest.markers_of(guest.runner_status(json.dumps(missing), RUN), windows)['session']['close']['sent'])

    def test_what_is_left_in_the_guest_is_named_and_a_clean_guest_has_nothing(self):
        clean = dict(runner_task=False, helper_task=False, helper_process=False, engine_process=False,
                     tunnel_adapter=False, binaries=False, list_directory=False, wfp_provider=False, wfp_sublayer=False,
                     root_removed=True)
        self.assertEqual(dict(left=[], clean=True), {k: guest.after(json.dumps(clean))[k] for k in ('left', 'clean')})
        dirty = dict(clean, helper_process=True, tunnel_adapter=True, root_removed=False)
        self.assertEqual(['helper_process', 'tunnel_adapter', 'root'], guest.after(json.dumps(dirty))['left'])
        for name in ('wfp_provider', 'wfp_sublayer'):
            self.assertEqual([name], guest.after(json.dumps(dict(clean, **{name: True})))['left'])
            with self.assertRaises(guest.RunnerAnswerError):
                guest.after(json.dumps({key: value for key, value in clean.items() if key != name}))
        for text in (json.dumps(dict(clean, extra=1)), json.dumps(dict(clean, root_removed='yes')), '', '[]'):
            with self.assertRaises(guest.RunnerAnswerError):
                guest.after(text)

    def test_the_files_the_runner_left_come_back_as_text_or_as_missing(self):
        text = json.dumps(dict(plan='{}', events='', report=None, status=None, helper_tail='x', identity=dict(uuid='U')))
        self.assertEqual('{}', guest.collected(text)['plan'])
        for bad in (json.dumps(dict(plan=1, events=None, report=None, status=None, helper_tail=None, identity=dict(uuid='U'))),
                    json.dumps(dict(plan=None, events=None, report=None, status=None, helper_tail=None, identity=5))):
            with self.assertRaises(guest.RunnerAnswerError):
                guest.collected(bad)


class MediaTests(unittest.TestCase):
    def setUp(self):
        from tools.vm.matrix.tests import test_qemu
        self.fixture = test_qemu.PreparationTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.root = self.fixture.root
        self.files = {}
        for name, body in (('one.exe', b'1' * 100), ('two.exe', b'2' * 50)):
            (self.root / name).write_bytes(body)
            self.files[name] = hashlib.sha256(body).hexdigest()
        self.scratch = self.root / 'scratch'
        self.scratch.mkdir()

    def stage(self, **changes):
        sources = [('one.exe', self.root / 'one.exe', self.files['one.exe']), ('two.exe', self.root / 'two.exe', None)]
        directory = self.root / ('stage-%d' % len(list(self.root.glob('stage-*'))))
        directory.mkdir()
        return directory, windows_media.stage(directory, sources, dict(changes.get('texts', {'plan.json': b'{}'})))

    def test_every_file_is_copied_hashed_and_listed_with_whether_it_was_pinned(self):
        directory, rows = self.stage()
        self.assertEqual(['one.exe', 'two.exe', 'plan.json'], [row['name'] for row in rows])
        self.assertEqual([True, False, False], [row['pinned'] for row in rows])
        self.assertEqual(self.files['one.exe'], rows[0]['sha256'])
        self.assertEqual(b'1' * 100, (directory / 'one.exe').read_bytes())
        self.assertEqual(hashlib.sha256(b'{}').hexdigest(), rows[2]['sha256'])

    def test_a_file_that_is_not_the_pinned_one_is_refused_before_it_is_copied(self):
        directory = self.root / 'refused'
        directory.mkdir()
        with self.assertRaisesRegex(windows_media.MediaError, 'source-mismatch'):
            windows_media.stage(directory, [('one.exe', self.root / 'one.exe', '0' * 64)], {})
        self.assertEqual([], list(directory.iterdir()))

    def test_a_name_that_could_leave_the_directory_or_repeat_is_refused(self):
        for name in ('../x', 'a/b', '', '.hidden', 'a b', 'x' * 49):
            with self.subTest(name=name), self.assertRaisesRegex(windows_media.MediaError, 'names-invalid'):
                windows_media.stage(self.root / 'x', [], {name: b''})
        with self.assertRaisesRegex(windows_media.MediaError, 'names-invalid'):
            windows_media.stage(self.root / 'x', [('one.exe', self.root / 'one.exe', None)], {'one.exe': b''})

    def test_a_file_that_changes_while_it_is_copied_is_refused(self):
        directory = self.root / 'moving'
        directory.mkdir()
        real = windows_media._digest

        def grow(path, limit=None):
            value = real(path, limit)
            (self.root / 'two.exe').write_bytes(b'2' * 51)
            return value
        with patch.object(windows_media, '_digest', grow), self.assertRaisesRegex(windows_media.MediaError, 'source-changed'):
            windows_media.stage(directory, [('two.exe', self.root / 'two.exe', None)], {})

    def test_a_file_over_the_limit_is_refused(self):
        with patch.object(windows_media, 'FILE_LIMIT', 60), self.assertRaisesRegex(windows_media.MediaError, 'too-large'):
            windows_media.stage(self.root / 'x', [('one.exe', self.root / 'one.exe', None)], {})

    def test_the_disc_is_made_into_the_runs_own_file_with_its_record_and_checked_before_the_guest_starts(self):
        run = self.fixture.run
        run.register(dict(id='windows-media', kind='file', path=windows_media.ISO_NAME))
        run.register(dict(id='windows-media-record', kind='file', path=windows_media.RECORD_NAME))
        for name in (windows_media.ISO_NAME, windows_media.RECORD_NAME):
            (run.directory / name).touch()
        calls = []

        def tool(argv, **kwargs):
            calls.append(argv)
            staged = Path(argv[-1])
            Path(argv[argv.index('-o') + 1]).write_bytes(b'ISO' + b''.join(sorted(p.read_bytes() for p in staged.iterdir())))
            return SimpleNamespace(returncode=0)
        sources = [('one.exe', self.root / 'one.exe', self.files['one.exe'])]
        record = windows_media.build(run, str(self.fixture.base), sources, {'plan.json': b'{}'}, runner=tool,
                                     scratch=str(self.scratch))
        self.assertEqual(['-as', 'mkisofs', '-quiet', '-iso-level', '3', '-J', '-joliet-long', '-V', 'ROSETUNLIST'],
                         calls[0][1:10])
        self.assertEqual(['one.exe', 'plan.json'], [row['name'] for row in record['files']])
        self.assertEqual(json.loads((run.directory / windows_media.RECORD_NAME).read_text()), record)
        self.assertEqual(hashlib.sha256((run.directory / windows_media.ISO_NAME).read_bytes()).hexdigest(),
                         record['iso']['sha256'])
        # The directory the files were staged in is gone, and the disc is the one the record names.
        self.assertEqual([], list(self.scratch.iterdir()))
        self.assertTrue(windows_media.verify(run, record))
        (run.directory / windows_media.ISO_NAME).write_bytes(b'ISO changed')
        with self.assertRaisesRegex(windows_media.MediaError, 'media-changed'):
            windows_media.verify(run, record)

    def test_a_disc_written_in_part_by_a_tool_that_then_fails_is_refused_and_never_matches_a_record(self):
        run = self.fixture.run
        run.register(dict(id='windows-media', kind='file', path=windows_media.ISO_NAME))
        (run.directory / windows_media.ISO_NAME).touch()
        sources = [('one.exe', self.root / 'one.exe', None)]

        def partial(argv, **kwargs):
            Path(argv[argv.index('-o') + 1]).write_bytes(b'ISO half')
            return SimpleNamespace(returncode=1)
        with self.assertRaisesRegex(windows_media.MediaError, 'tool-failed'):
            windows_media.build(run, str(self.fixture.base), sources, {}, runner=partial, scratch=str(self.scratch))
        record = dict(iso=dict(sha256=hashlib.sha256(b'ISO whole').hexdigest(), size=9))
        with self.assertRaisesRegex(windows_media.MediaError, 'media-changed'):
            windows_media.verify(run, record)
        self.assertEqual([], list(self.scratch.iterdir()))

    def test_a_tool_that_fails_or_cannot_run_is_a_refusal_with_nothing_left_behind(self):
        run = self.fixture.run
        run.register(dict(id='windows-media', kind='file', path=windows_media.ISO_NAME))
        (run.directory / windows_media.ISO_NAME).touch()
        sources = [('one.exe', self.root / 'one.exe', None)]
        for runner in (lambda argv, **kw: SimpleNamespace(returncode=1), lambda argv, **kw: (_ for _ in ()).throw(OSError())):
            with self.assertRaisesRegex(windows_media.MediaError, 'tool-failed'):
                windows_media.build(run, str(self.fixture.base), sources, {}, runner=runner, scratch=str(self.scratch))
            self.assertEqual([], list(self.scratch.iterdir()))


@controller_only
class WireTests(unittest.TestCase):
    def pair(self, media):
        pair = lab.LabPair.__new__(lab.LabPair)
        pair.lease = SimpleNamespace(_check_live=lambda: None)
        pair.closed, pair.used, pair.sockets = False, set(), dict(test=Endpoint(), lab=Endpoint())
        pair.evidence_disk, pair.media = False, media
        return pair

    def test_the_guest_gets_a_read_only_drive_on_the_machines_own_bus_and_the_lab_machine_gets_none(self):
        from tools.vm.matrix.tests import test_qemu
        fixture = test_qemu.PreparationTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        pair = self.pair(True)
        pair.role = lambda run: 'test'
        argv, _ = pair.network(fixture.run, adapter=True)
        joined = ' '.join(argv)
        self.assertIn('ide-cd,drive=winmedia,bus=ide.2,id=winmedia', joined)
        block = json.loads(argv[argv.index('-blockdev') + 1])
        self.assertEqual((True, True), (block['read-only'], block['file']['read-only']))
        self.assertTrue(block['file']['filename'].endswith('windows-media.iso'))
        lab_pair = self.pair(True)
        lab_pair.role = lambda run: 'lab'
        self.assertNotIn('ide-cd', ' '.join(lab_pair.network(fixture.run)[0]))
        without = self.pair(False)
        without.role = lambda run: 'test'
        self.assertNotIn('ide-cd', ' '.join(without.network(fixture.run, adapter=True)[0]))

    def test_the_resources_of_the_stage_are_the_guests_and_only_with_the_media(self):
        pair = self.pair(True)
        pair.role = lambda run: 'test'
        self.assertEqual(set(lab.MEDIA_RESOURCES), {k for k in pair.resources(None) if k in lab.MEDIA_RESOURCES})
        pair.media = False
        self.assertFalse(set(pair.resources(None)) & set(lab.MEDIA_RESOURCES))
        self.assertEqual(
            {'windows-list/plan.json', 'windows-list/events.jsonl', 'windows-list/report.json',
             'windows-list/status.json', 'windows-list/runner.json', 'windows-list/assessment.json'},
            {path for path in lab.MEDIA_RESOURCES.values() if path.startswith('windows-list/')})


class ConfigTests(unittest.TestCase):
    def example(self):
        import tomllib
        with EXAMPLE.open('rb') as stream:
            config = tomllib.load(stream)
        config['state_directory'] = str(Path(__file__).resolve().parent / 'state')
        return config

    def test_the_example_is_a_valid_configuration_and_the_windows_validator_takes_it(self):
        with patch.object(windows_smoke, '_state_path', create=True), patch.object(windows_list_lab, '_state_path'):
            config = windows_smoke.validate(self.example())
        self.assertEqual(('windows-list', windows_list_lab.SCHEMA), (config['suite'], config['schema']))
        self.assertLessEqual(windows_list_lab.capture_seconds(config), wire.DURATION_MAX)

    def test_every_field_is_strict(self):
        changes = (lambda c: c.update(extra=1), lambda c: c['list'].update(extra=1), lambda c: c['list'].pop('xorriso'),
                   lambda c: c['list'].update(runner_seconds=59), lambda c: c['list'].update(runner_seconds=1201),
                   lambda c: c['list'].update(poll_seconds=4), lambda c: c['list'].update(script_seconds=29),
                   lambda c: c['list'].update(settle_seconds=301), lambda c: c['list'].update(agent_wait_seconds='300'),
                   lambda c: c['list'].update(runner_seconds=True), lambda c: c['list'].update(rosetun=''),
                   lambda c: c['list'].update(helper_sha256='A' * 64), lambda c: c['list'].update(helper_sha256='0' * 63),
                   lambda c: c['list'].update(sing_box_sha256='1' * 64), lambda c: c.update(mode='release'),
                   lambda c: c.update(platform='windows'), lambda c: c['lab'].pop('ca_certificate'),
                   lambda c: c['lab']['qemu'].update(machine='pc-i440fx-9.2'), lambda c: c['deadlines'].update(boot=301),
                   lambda c: c.update(schema='rosetun.matrix.execution.windows.v2'),
                   lambda c: c['qemu'].update(extra=1))
        for index, change in enumerate(changes):
            config = self.example()
            change(config)
            with self.subTest(index=index), patch.object(windows_list_lab, '_state_path'):
                with self.assertRaises(ValueError):
                    windows_list_lab.validate(config)

    def test_a_capture_that_would_not_cover_the_run_is_refused(self):
        config = self.example()
        config['list'].update(agent_wait_seconds=300, script_seconds=300, settle_seconds=300, runner_seconds=1200)
        with patch.object(windows_list_lab, '_state_path'), self.assertRaisesRegex(ValueError, 'at most'):
            windows_list_lab.validate(config)

    def test_the_command_takes_the_suite_and_refuses_the_lab_flags_and_another_suites_configuration(self):
        import contextlib
        import io
        from tools.vm.matrix import cli
        with patch.object(windows_smoke, '_state_path', create=True), patch.object(windows_list_lab, '_state_path'), \
                patch.object(windows_smoke, 'load', side_effect=lambda path: windows_smoke.validate(self.example())), \
                patch.object(windows_list_lab, 'preflight', return_value={'suite': 'windows-list'}) as plan, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, cli.main(['run', 'windows-list', '--config', 'x', '--dry-run']))
            plan.assert_called_once()
            self.assertEqual(2, cli.main(['run', 'windows-lab-smoke', '--config', 'x', '--dry-run']))
            for flags in (['--lab'], ['--control', 'stop-helper'], ['--diagnostic']):
                self.assertEqual(2, cli.main(['run', 'windows-list', '--config', str(EXAMPLE), *flags]))


def syn(client_port, server, port, *, back=True, at=0.0):
    """The opening of a TCP connection of the test machine and, when `back`, the answer of the other end."""
    rows = [(at, ip_frame(wire.CLIENTS[4], server, 6, tcp(client_port, port, flags=0x02)))]
    if back:
        rows.append((at + 0.01, ip_frame(server, wire.CLIENTS[4], 6, tcp(port, client_port, flags=0x12),
                                         src=wire.MACS['lab'], dst=wire.MACS['test'])))
    return rows


class ListMachines(Machines):
    """The lab and the Windows guest of a List run: the runner answers from its own data, the wire shows what it says."""

    def __init__(self, test, *, results=None, cleanup='PASS', session_body=(), baseline_body=(), session_direct=1,
                 baseline_direct=True, node=True, markers=True, left=(), states=('running', 'finished'),
                 runner_error=None, dropped_events=False, uuid=None, poll_faults=0, calls=0, **kwargs):
        super().__init__(test, **kwargs)
        self.results, self.cleanup = results, cleanup
        self.session_body, self.baseline_body = list(session_body), list(baseline_body)
        self.session_direct, self.baseline_direct, self.node, self.markers = session_direct, baseline_direct, node, markers
        self.left, self.states, self.runner_error, self.dropped_events = list(left), list(states), runner_error, dropped_events
        self.uuid, self.poll_faults, self.session_calls = uuid, poll_faults, calls
        self.disc, self.plan, self.polls, self.programs = {}, None, 0, []

    # -- the disc the controller makes
    def xorriso(self, argv, **kwargs):
        staged = Path(argv[-1])
        self.disc = {item.name: item.read_bytes() for item in staged.iterdir()}
        self.plan = json.loads(self.disc['plan.json'])
        self.plain = dict(name=self.plan['baseline']['dns_name'])
        Path(argv[argv.index('-o') + 1]).write_bytes(b'ISO' + hashlib.sha256(json.dumps(sorted(self.disc)).encode()).digest())
        return SimpleNamespace(returncode=0)

    # -- the runner
    def results_of(self):
        return self.results or {check: 'PASS' for check in windows_list_lab.CHECKS}

    def status(self, state):
        error = self.runner_error if state in guest.ENDED else None
        return status_document(self.lab_id, state=state if state != 'running' else 'running', results=self.results_of(),
                               cleanup=self.cleanup if state in guest.ENDED else None, markers=self.markers,
                               error=error, windows=windows_for(self.lab_id))

    def program(self, path, arguments):
        self.programs.append((path, list(arguments)))
        self.test.assertEqual((guest.CMD, ['/c', 'type', guest.STATUS_PATH]), (path, list(arguments)))
        self.polls += 1
        if self.polls <= self.poll_faults:
            raise LifecycleError('qga-exec-timeout', cause='timeouterror')
        if self.polls == self.poll_faults + 1:
            return SimpleNamespace(exitcode=1, stdout=b'', stderr=b'')
        index = min(self.polls - self.poll_faults - 2, len(self.states) - 1)
        self.events.append(('poll', self.polls))
        return SimpleNamespace(exitcode=0, stdout=json.dumps(self.status(self.states[index])).encode(), stderr=b'')

    def recorded_files(self):
        identity = dict(run_id='11111111-2222-4333-8444-555555555555', vm_id=self.uuid or UUID, boot_id=BOOT)
        plan = windows_list.make_plan('exploratory', dict(mode='exploratory'))
        plan['identity'] = identity
        events = []
        for check, row in zip(windows_list_lab.CHECKS, [dict(id=c) for c in windows_list_lab.CHECKS]):
            result = self.results_of().get(check, 'SKIP')
            reason = 'checked' if result == 'PASS' else 'condition-false' if result == 'FAIL' else 'interrupted'
            events.append(dict(schema='rosetun.windows-list.event.v1', run_id=identity['run_id'],
                               sequence=len(events) + 1, id=check, result=result, reason=reason))
        if self.dropped_events:
            events = events[:-1]
        counts = {name: sum(1 for e in events if e['result'] == name) for name in ('PASS', 'FAIL', 'SKIP')}
        report = dict(schema='rosetun.windows-list.report.v1', identity=identity, boot_id_at_end=BOOT, checks=events,
                      summary={'total': len(events), 'pass': counts['PASS'], 'fail': counts['FAIL'], 'skip': counts['SKIP']},
                      cleanup=dict(status=self.cleanup), errors=[])
        status = dict(schema='rosetun.windows-list.status.v1', identity=identity, state='finished', event_count=len(events))
        return dict(plan=json.dumps(plan), events=''.join(json.dumps(e) + '\n' for e in events),
                    report=json.dumps(report), status=json.dumps(status))

    def powershell(self, script):
        if 'medium-not-found' in script:
            self.note('guest-start')
            wanted = json.loads(re.search(r"ConvertFrom-Json '([^']*)'", script)[1])
            for name, digest in wanted.items():
                if hashlib.sha256(self.disc[name]).hexdigest() != digest:
                    raise LifecycleError('qga-powershell-failed')
            return json.dumps(dict(medium='E:\\', files=len(wanted), task=guest.RUNNER_TASK))
        if 'Read-Text' in script:
            self.note('guest-collect')
            files = self.recorded_files()
            return json.dumps(dict(files, helper_tail='helper tail', identity=dict(uuid=(self.uuid or UUID).upper())))
        if 'engine_process' in script:
            self.note('guest-after')
            state = dict(runner_task=False, helper_task=False, helper_process=False, engine_process=False,
                         tunnel_adapter=False, binaries=False, list_directory=False, wfp_provider=False,
                         wfp_sublayer=False, root_removed=True)
            state.update({name: True for name in self.left})
            return json.dumps(state)
        return super().powershell(script)

    def adapters(self):
        adapters = super().adapters()
        original = adapters.start
        machines = self

        def start(run, lab=None):
            vm = original(run, lab=lab)
            vm.guest_program = lambda path, arguments, seconds=30: machines.program(path, arguments)
            vm.qga.calls = machines.session_calls
            return vm
        adapters.start = start
        adapters.xorriso = self.xorriso
        return adapters

    # -- the wire
    def served(self):
        return [(index, word, label) for index, label in enumerate(guest.LABELS) for word in ('open', 'close')]

    def frames(self):
        lab_id, rows = self.lab_id, [(1.0, request_arp())]
        plain = wire.dns_checks(lab_id, lambda: '0' * 24)['plain']
        plain['nonce'] = re.search(r'\.([0-9a-f]{24})\.lab\.test', self.plain['name'])[1]
        rows += marker_rows(0, 'open', 'baseline', 10.0, lab_id)
        if self.baseline_direct:
            rows += syn(51000, wire.TARGETS[4], 443, at=11.0)
            request = ip_frame(wire.CLIENTS[4], wire.RESOLVER, 17, udp(52000, 53, wire.query(plain)))
            reply = ip_frame(wire.RESOLVER, wire.CLIENTS[4], 17, udp(53, 52000, wire.query(plain)),
                             src=wire.MACS['lab'], dst=wire.MACS['test'])
            rows += [(12.0, request), (12.01, reply)]
        rows += [(15.0 + n / 10, frame) for n, frame in enumerate(self.baseline_body)]
        rows += marker_rows(0, 'close', 'baseline', 20.0, lab_id)
        rows += marker_rows(1, 'open', 'session', 30.0, lab_id)
        if self.node:
            rows += syn(54000, '192.0.2.1', 8388, at=31.0)
        for n in range(self.session_direct):
            rows += syn(55000 + n, wire.TARGETS[4], 443, at=40.0 + n)
        rows += [(50.0 + n / 10, frame) for n, frame in enumerate(self.session_body)]
        rows += marker_rows(1, 'close', 'session', 60.0, lab_id)
        return rows, plain

    def artifact(self, name):
        _, plain = self.frames()
        if name == 'health.json':
            return json.dumps(health(self.served(), node=dict(alive_at_finish=True, exit_code=0))).encode()
        if name == 'https.json':
            counts = [dict(source=source, method='GET', path_class='root', count=2) for source in (wire.CLIENTS[4], wire.EGRESS)]
            return json.dumps([dict(kind='counts', counts=counts, rows_dropped=0, counts_dropped=0)]).encode()
        if name == 'dns.json':
            rows = [dict(source=wire.EGRESS, transport='doh', name='listed.lab.test', type='A')]
            if self.baseline_direct:
                rows.append(dict(source=wire.CLIENTS[4], transport='udp', name=wire.dns_name(plain), type='A'))
            return json.dumps(rows).encode()
        return b'[]'


class ListFlow(Flow):
    def setUp(self):
        super().setUp()
        root = self.fixture.root
        self.pins = {}
        for name, body in (('rosetun.exe', b'cli'), ('helper.exe', b'helper'), ('sing-box.exe', b'engine')):
            (root / name).write_bytes(body)
            self.pins[name] = hashlib.sha256(body).hexdigest()
        smoke = dict(agent_wait_seconds=30, script_seconds=60, settle_seconds=10, runner_seconds=120, poll_seconds=10,
                     shutdown_wait_seconds=30, xorriso=str(self.fixture.base), rosetun=str(root / 'rosetun.exe'),
                     rosetun_sha256=self.pins['rosetun.exe'], helper=str(root / 'helper.exe'),
                     helper_sha256=self.pins['helper.exe'], sing_box=str(root / 'sing-box.exe'),
                     sing_box_sha256=self.pins['sing-box.exe'])
        self.config = dict(
            schema=windows_list_lab.SCHEMA, suite='windows-list', mode='exploratory', platform='linux-x86_64-kvm',
            state_directory=self.config['state_directory'], stand_id='synthetic', image_descriptor='unused',
            qemu=self.config['qemu'], list=smoke, deadlines=dict(preparation=600, boot=300), lab=self.config['lab'])

    def go(self, machines):
        def sleep(seconds):
            self.sleeps.append(seconds)
            self.clock.now += seconds

        def completion(directory, manifest):
            return any(v.run.directory == directory and v.closed for v in machines.vms.values())
        image = SimpleNamespace(identifier='windows-test', sha256=HEX, validate=lambda directory: None)
        with patch.object(__import__('socket'), 'AF_UNIX', 1, create=True), \
                patch.object(windows_list_lab, 'preflight', return_value={}), \
                patch.object(windows_list_lab, 'SING_BOX_SHA256', self.pins['sing-box.exe']), \
                patch.object(windows_list_lab, 'load_windows_descriptor', return_value=image), \
                patch.object(windows_list_lab, 'completion_verified', side_effect=completion), \
                patch.object(windows_list_lab.windows_lab, 'completion_verified', side_effect=completion), \
                patch.object(windows_list_lab.windows_reboot, 'record',
                             side_effect=lambda vm, operation, **fields: machines.recorded.append((operation, fields))):
            return windows_list_lab.run_windows_list(self.config, adapters=machines.adapters(),
                                                     clock=lambda: self.clock.now, sleep=sleep,
                                                     progress=lambda stage: None)


@controller_only
class RunTests(ListFlow):
    def test_a_clean_run_follows_the_order_of_the_stage_and_every_check_passes(self):
        machines = ListMachines(self)
        result = self.go(machines)
        self.assertEqual([], result['errors'])
        self.assertEqual(0, result['exit_code'], (result['execution']['findings'], result['execution']['unverified']))
        section = result['execution']
        self.assertTrue(section['accepted'])
        self.assertEqual(['PASS'] * 11, [row['result'] for row in section['checks']])
        self.assertEqual(list(windows_list_lab.CHECKS), [row['id'] for row in section['checks']])
        self.assertEqual('EXPECTED', section['windows']['session']['verdict'])
        self.assertEqual((True, False), (section['windows']['baseline']['listed'], section['windows']['session']['listed']))
        self.assertEqual('PASS', section['cleanup']['runner'])
        self.assertEqual([], section['cleanup']['left'])
        self.assertEqual(('PASS', True), (section['assessment']['cleanup']['status'], section['assessment']['acceptance']['accepted']))
        self.assertEqual((False, True), (result['qualified'], result['diagnostic']))
        names = [name for name in machines.names() if name in ('start-lab', 'lab-setup', 'start-test', 'guest-network',
                                                               'guest-ca', 'guest-start', 'guest-collect', 'guest-after',
                                                               'lab-finish', 'shutdown-test', 'close-test', 'close-lab')]
        self.assertEqual(['start-lab', 'lab-setup', 'start-test', 'guest-network', 'guest-ca', 'guest-start',
                          'guest-collect', 'guest-after', 'lab-finish', 'shutdown-test', 'close-test', 'close-lab'], names)

    def test_the_disc_holds_the_binaries_the_runner_and_the_plan_and_the_guest_is_told_their_hashes(self):
        machines = ListMachines(self)
        result = self.go(machines)
        self.assertEqual(set(guest.BINARIES) | set(guest.SCRIPTS) | {guest.PLAN_FILE}, set(machines.disc))
        for row in machines.plan['files']:
            self.assertEqual(hashlib.sha256(machines.disc[row['name']]).hexdigest(), row['sha256'])
        record = json.loads((Path(result['artifact_directories']['test']) / 'windows-media.json').read_text())
        self.assertEqual(sorted(machines.disc), sorted(row['name'] for row in record['files']))
        self.assertEqual(('rosetun-helper-privileged.exe', 'helper'), (machines.plan['files'][1]['name'],
                                                                      machines.disc['rosetun-helper-privileged.exe'].decode()))
        self.assertEqual(result['execution']['media']['iso']['sha256'], record['iso']['sha256'])
        self.assertNotIn('hunter2', json.dumps(result))

    def test_the_controller_only_reads_the_status_between_the_start_and_the_end_of_the_runner(self):
        machines = ListMachines(self, states=('running', 'running', 'cleaning', 'finished'))
        result = self.go(machines)
        self.assertEqual(0, result['exit_code'])
        events = machines.events
        start, collect = events.index('guest-start'), events.index('guest-collect')
        between = events[start:collect]
        self.assertEqual(4, sum(1 for e in between if type(e) is tuple and e[0] == 'poll'))
        # Nothing but the poll reached the guest: no PowerShell, only programs that read the status.
        self.assertEqual(['guest-start', 'guest-collect'], [e for e in events[start:collect + 1] if e in ('guest-start', 'guest-collect')])
        self.assertTrue(all(program == guest.CMD for program, _ in machines.programs))
        self.assertGreaterEqual(sum(self.sleeps), 5 * 10)
        # The first read finds no status file yet.
        self.assertEqual((5, 5), (result['execution']['runner']['polls'], len(machines.programs)))

    def test_the_guest_is_left_alone_before_the_runner_and_the_first_exchange_after_it_is_guarded(self):
        machines = ListMachines(self)
        result = self.go(machines)
        self.assertGreaterEqual(result['execution']['settle']['waited_seconds'], 10)
        self.assertIn(('ready', 'test'), machines.events)
        self.assertLess(machines.events.index(('ready', 'test')), machines.events.index('guest-start'))
        self.assertIn('guest-settle-session', [op for op, _ in machines.recorded])

    def test_the_lab_is_asked_for_the_node_the_resolver_and_a_capture_that_covers_the_run(self):
        machines = ListMachines(self)
        self.go(machines)
        (_, expected, window, tunnel, options), finish = machines.calls
        self.assertEqual(8, len(expected))
        self.assertEqual(windows_list_lab.capture_seconds(self.config), options['duration_seconds'])
        self.assertEqual(dict(tunnel=True, evidence_disk=True, dns=True, media=True), machines.pair_options)
        self.assertEqual(self.config['lab']['tunnel']['ca_sha256'], tunnel['ca_sha256'])

    # -- verdicts and exit codes
    runs = 0

    def run_with(self, **changes):
        # Each run of a test has a stand of its own: a lease is held until its machines are closed.
        type(self).runs += 1
        self.config = dict(self.config, stand_id='synthetic-%d' % type(self).runs,
                           state_directory=self.config['state_directory'] + '-%d' % type(self).runs)
        machines = ListMachines(self, **changes)
        return self.go(machines), machines

    def test_a_check_that_failed_is_a_finding_and_a_check_that_did_not_run_is_not_one(self):
        results = {check: 'PASS' for check in windows_list_lab.CHECKS}
        results['text.block'] = 'FAIL'
        result, _ = self.run_with(results=results)
        self.assertEqual(1, result['exit_code'])
        self.assertEqual(['check-failed:text.block'], result['execution']['findings'])
        skipped = {check: 'PASS' for check in windows_list_lab.CHECKS[:6]}
        result, _ = self.run_with(results=skipped, runner_error=dict(place='execution', text='boom'),
                                  states=('running', 'failed'))
        self.assertEqual(2, result['exit_code'])
        self.assertEqual([], result['execution']['findings'])
        self.assertIn('check-not-run:binary.apply', result['execution']['unverified'])
        self.assertIn('runner-error:execution', result['execution']['unverified'])

    def test_a_frame_in_the_session_outside_the_tunnel_and_the_one_direct_connection_is_a_leak(self):
        result, _ = self.run_with(session_body=[llmnr(50000)])
        self.assertEqual(1, result['exit_code'])
        self.assertEqual(['window-detected:session'], result['execution']['findings'])
        self.assertEqual('DETECTED', result['execution']['windows']['session']['verdict'])
        self.assertFalse(result['execution']['accepted'])

    def test_a_second_direct_connection_in_the_session_is_a_leak_and_none_is_a_contradiction_of_the_pass(self):
        result, _ = self.run_with(session_direct=2)
        self.assertEqual(1, result['exit_code'])
        self.assertEqual(['window-detected:session'], result['execution']['findings'])
        result, _ = self.run_with(session_direct=0)
        self.assertEqual(1, result['exit_code'])
        self.assertEqual(['window-mismatch:session', 'disagree:binary.direct'], result['execution']['findings'])
        self.assertEqual('MISMATCH', result['execution']['windows']['session']['verdict'])

    def test_the_noise_before_the_session_is_listed_and_never_a_finding(self):
        result, _ = self.run_with(baseline_body=[llmnr(50000), llmnr(50001)])
        self.assertEqual(0, result['exit_code'], result['execution']['unverified'])
        section = result['execution']
        self.assertEqual('DETECTED', section['windows']['baseline']['leak'])
        self.assertEqual('FOUND', section['baseline_noise']['noise'])
        self.assertTrue(any('224.0.0.252' in line for line in section['baseline_table']))
        self.assertTrue(section['accepted'])

    def test_a_pass_the_lab_did_not_see_on_the_wire_is_a_finding(self):
        result, _ = self.run_with(baseline_direct=False)
        self.assertEqual(1, result['exit_code'])
        self.assertEqual(['disagree:baseline.egress', 'disagree:baseline.dns'], result['execution']['findings'])
        # The lab's own resolver did not hear the question either, which is a fixture it did not see answer.
        self.assertEqual(['fixtures-not-seen:dns'], result['execution']['unverified'])
        result, _ = self.run_with(node=False)
        self.assertEqual(['disagree:text.tunnel'], result['execution']['findings'])

    def test_a_marker_that_was_not_acknowledged_leaves_the_run_unable_to_vouch(self):
        result, _ = self.run_with(markers=False)
        self.assertEqual(2, result['exit_code'])
        self.assertEqual([], result['execution']['findings'])
        self.assertIn('markers-not-acknowledged', result['execution']['unverified'])

    def test_the_cleanup_that_failed_or_left_something_is_a_finding_and_one_nobody_could_read_is_not(self):
        result, _ = self.run_with(cleanup='ERROR')
        self.assertEqual(1, result['exit_code'])
        self.assertIn('cleanup-error', result['execution']['findings'])
        result, _ = self.run_with(left=['helper_process', 'tunnel_adapter'])
        self.assertEqual(1, result['exit_code'])
        self.assertEqual(['cleanup-left:helper_process,tunnel_adapter'], result['execution']['findings'])
        result, _ = self.run_with(cleanup='UNVERIFIED')
        self.assertEqual(2, result['exit_code'])
        self.assertIn('cleanup-unverified', result['execution']['unverified'])

    def test_artifacts_that_disagree_or_miss_a_check_are_refused_by_the_assessment_and_the_run_is_unverified(self):
        result, _ = self.run_with(dropped_events=True)
        self.assertEqual(2, result['exit_code'])
        self.assertIn('checks-not-read', result['execution']['unverified'])
        self.assertTrue(any(item.startswith('assessment:') for item in result['execution']['unverified']))

    def test_a_guest_that_is_not_the_one_the_controller_started_is_unverified(self):
        result, _ = self.run_with(uuid='99999999-1234-4234-8234-123456789abc')
        self.assertEqual(2, result['exit_code'])
        self.assertIn('identity-differs', result['execution']['unverified'])

    def test_a_runner_that_never_ends_is_an_error_at_the_end_of_its_time(self):
        result, machines = self.run_with(states=('running',))
        self.assertEqual(2, result['exit_code'])
        self.assertEqual([('runner', 'windows-list-runner-timeout')], [(e['stage'], e['reason']) for e in result['errors']])
        self.assertNotIn('guest-collect', machines.names())
        self.assertIn(('hard', 'test', True), machines.events)
        self.assertGreaterEqual(sum(self.sleeps), 120)

    def test_a_poll_that_fails_is_tried_again_on_a_new_session_and_a_run_of_failures_ends_the_run(self):
        result, machines = self.run_with(poll_faults=2)
        self.assertEqual(0, result['exit_code'], result['execution']['unverified'])
        failed = [fields for op, fields in machines.recorded if op == 'guest-poll-failed']
        self.assertEqual([1, 2], [fields['failures'] for fields in failed])
        self.assertEqual('timeouterror', failed[0]['cause'])
        result, _ = self.run_with(poll_faults=windows_list_lab.POLL_FAILURES + 1)
        self.assertEqual(2, result['exit_code'])
        self.assertEqual('qga-exec-timeout', result['errors'][0]['reason'])
        self.assertEqual('timeouterror', result['errors'][0]['cause'])

    def test_a_session_close_to_its_calls_is_replaced_before_the_poll_and_not_before_the_start(self):
        result, machines = self.run_with(calls=windows_list_lab.CALLS_BEFORE_NEW_SESSION)
        self.assertEqual(0, result['exit_code'])
        self.assertGreaterEqual(machines.events.count(('ready', 'test')), 3)

    def test_a_network_that_is_not_the_labs_stops_the_run_before_the_disc_is_used(self):
        result, machines = self.run_with(network=network_answer(addresses=[]))
        self.assertEqual(2, result['exit_code'])
        self.assertEqual([('network', 'windows-network-not-as-the-lab-says')],
                         [(e['stage'], e['reason']) for e in result['errors']])
        self.assertNotIn('guest-start', machines.names())

    def test_the_disc_that_changed_before_the_guest_started_is_an_error_and_the_guest_never_starts(self):
        machines = ListMachines(self)
        adapters = machines.adapters()
        start = adapters.start

        def tampering(run, lab=None):
            if lab.role(run) == 'lab':
                (run.directory.with_name(run.directory.name[:-3] + 'test') / 'windows-media.iso').write_bytes(b'changed')
            return start(run, lab=lab)
        machines.adapters = lambda: SimpleNamespace(**{**vars(adapters), 'start': tampering})
        result = self.go(machines)
        self.assertEqual(2, result['exit_code'])
        self.assertEqual('windows-media-changed', result['errors'][0]['reason'])
        self.assertNotIn('start-test', machines.names())

    def test_a_binary_that_is_not_the_pinned_one_is_refused_before_anything_starts(self):
        (self.fixture.root / 'rosetun.exe').write_bytes(b'another build')
        machines = ListMachines(self)
        result = self.go(machines)
        self.assertEqual(2, result['exit_code'])
        self.assertEqual('windows-media-source-mismatch', result['errors'][0]['reason'])
        self.assertNotIn('start-lab', machines.names())

    def test_the_summary_keeps_no_token_and_both_runs_hold_it(self):
        result, _ = self.run_with()
        for role, directory in result['artifact_directories'].items():
            saved = json.loads((Path(directory) / 'execution-summary.json').read_text(encoding='utf-8'))
            self.assertEqual(result['exit_code'], saved['exit_code'])
            self.assertEqual('windows-list', saved['suite'])
        for name in ('plan.json', 'events.jsonl', 'report.json', 'status.json', 'runner.json', 'assessment.json'):
            self.assertTrue((Path(result['artifact_directories']['test']) / 'windows-list' / name).read_text())
