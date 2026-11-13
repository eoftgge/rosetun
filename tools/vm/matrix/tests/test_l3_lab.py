"""Linux L3 inside the two-machine lab: the configuration, the joint launch plans and the controller's order.

Everything here runs on fake machines and adapters; no VM, no QEMU and no network is started.
"""
from dataclasses import asdict, replace
import copy
import io
import json
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import tomllib
import unittest
from unittest.mock import patch

from tools.vm.matrix import (cli, execution, l2_media as media, l3_lab, l3_requests, l3_summary, lab, lab_protocol as wire,
                             lifecycle, linux_l2 as l2, qemu)
from tools.vm.matrix.resources import EXECUTION_FILES, create_run, read_manifest
from tools.vm.matrix.tests import (test_lifecycle, test_linux_l2, test_orchestrator_l3 as l3tests, test_qemu,
                                   test_stage_profiles)
from tools.vm.matrix.tests.test_lab import Endpoint, capture
from tools.vm.matrix.tests.test_lab_fixtures import load_entry
from tools.vm.matrix.tests.test_lab_windows import health, served
from tools.vm.matrix.tests.test_orchestrator_l3 import PACKAGE
from tools.vm.matrix.tests.test_qga import BOOT

SCENARIOS = Path(__file__).resolve().parents[2] / 'linux' / 'scenarios-l3.tsv'
HEX = '1' * 64


def example():
    with (PACKAGE / 'execution-l3-lab.example.toml').open('rb') as stream:
        config = tomllib.load(stream)
    for name in ('state_directory', 'content_directory', 'source_checkout'):
        config[name] = str(Path(tempfile.gettempdir()) / 'rosetun-l3-lab-test' / name)
    return config


def scenario_ids():
    rows = [line.split('\t') for line in SCENARIOS.read_text(encoding='utf-8').splitlines()]
    return [row[0] for row in rows[1:] if row and row[0]]


class ConfigTests(unittest.TestCase):
    def test_the_example_is_a_valid_version_3_configuration_for_the_lab(self):
        config = execution.validate(example())
        self.assertEqual(execution.SCHEMA_V3, config['schema'])
        self.assertIs(config['lab'], execution.lab_of(config))
        self.assertEqual(('linux-l3', 8388, 8388), (execution.suite_of(config), config['l3']['node_port'],
                                                    config['lab']['tunnel']['node_port']))
        self.assertEqual(900, config['timeouts']['job'])
        self.assertEqual(config['timeouts']['job'] + 180, config['deadlines']['execution'])

    def test_versions_1_and_2_never_carry_a_lab_block_and_have_none(self):
        v2 = execution.validate(self.v2())
        self.assertIsNone(execution.lab_of(v2))
        with self.assertRaises(ValueError):
            execution.validate(dict(self.v2(), lab=example()['lab']))
        v1 = {k: v for k, v in self.v2().items() if k not in ('suite', 'l3')}
        self.assertIsNone(execution.lab_of(dict(v1, schema=execution.SCHEMA)))
        with self.assertRaises(ValueError):
            execution.validate(dict(v1, schema=execution.SCHEMA, lab=example()['lab']))

    def v2(self):
        config = example()
        config.pop('lab')
        config['schema'] = execution.SCHEMA_V2
        config['timeouts']['job'], config['deadlines']['execution'] = 300, 480
        return config

    def test_version_3_is_for_the_l3_suite_and_needs_its_lab_block(self):
        config = example()
        del config['lab']
        with self.assertRaises(ValueError):
            execution.validate(config)
        config = example()
        config.update(suite='linux-l2')
        del config['l3']
        with self.assertRaises(ValueError):
            execution.validate(config)

    def test_the_lab_block_is_strict(self):
        changes = (lambda c: c['lab'].update(extra=1), lambda c: c['lab'].pop('doh_cert_sha256'),
                   lambda c: c['lab'].update(https_cert_sha256='A' * 64),
                   lambda c: c['lab'].update(doh_cert_sha256='1' * 63),
                   lambda c: c['lab']['image'].update(extra=1), lambda c: c['lab']['tunnel'].update(extra=1),
                   lambda c: c['lab']['tunnel'].update(sing_box_sha256='X' * 64),
                   lambda c: c['lab']['tunnel'].update(node_port=443),
                   lambda c: c['lab']['tunnel'].update(node_port=8389),
                   lambda c: c['l3'].update(node_port=8389),
                   lambda c: c['l3'].update(host_address='192.0.2.9'),
                   lambda c: c['l3'].update(probe_address='203.0.113.9'),
                   lambda c: c['lab'].update(image='not a table'))
        for change in changes:
            with self.subTest(change=change):
                config = example()
                change(config)
                with self.assertRaises((ValueError, TypeError, AttributeError)):
                    execution.validate(config)

    def test_the_capture_covers_a_job_of_at_most_the_job_limit_of_the_script(self):
        config = example()
        config['timeouts']['job'], config['deadlines']['execution'] = 1800, 1980
        execution.validate(config)
        config['timeouts']['job'], config['deadlines']['execution'] = 1801, 1981
        with self.assertRaises(ValueError):
            execution.validate(config)


class DryRunTests(unittest.TestCase):
    def setUp(self):
        self.base = l3tests.L3DryRunTests()
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.addCleanup(self.base.temp.cleanup)
        self.config = copy.deepcopy(self.base.config)
        self.config.update(schema=execution.SCHEMA_V3, lab=dict(
            image=self.base.fixture.image.record(), https_cert_sha256=HEX, doh_cert_sha256=HEX,
            tunnel=dict(sing_box_sha256=HEX, ca_sha256=HEX, node_port=8388)))

    def go(self, *arguments, config=None):
        with patch.object(execution, 'load_execution', return_value=self.config if config is None else config), \
                patch('subprocess.Popen', side_effect=AssertionError('external program forbidden')), \
                patch('sys.stdout', new_callable=io.StringIO) as output:
            code = cli.main(['run', 'linux-l3', '--config', 'synthetic', *arguments])
        return code, output.getvalue()

    def test_the_dry_run_describes_both_machines_and_starts_nothing(self):
        code, text = self.go('--dry-run', '--lab')
        self.assertEqual(0, code)
        plan = json.loads(text)
        self.assertTrue(plan['dry_run'])
        self.assertTrue(any('evidence disk' in action for action in plan['actions']))
        self.assertTrue(any('LAB_MARKER_ADDRESS' in action for action in plan['actions']))
        self.assertIn('only the kill switch group is judged;'.split(';')[0],
                      ' '.join(plan['limitations']))
        self.assertEqual(execution.SCHEMA_V3, plan['configuration']['schema'])
        self.assertFalse(Path(self.config['state_directory']).exists())

    def test_the_flag_and_the_configuration_must_agree(self):
        self.assertEqual(2, self.go('--dry-run')[0])
        v2 = {k: v for k, v in self.config.items() if k != 'lab'}
        v2['schema'] = execution.SCHEMA_V2
        self.assertEqual(2, self.go('--dry-run', '--lab', config=v2)[0])
        self.assertEqual(0, self.go('--dry-run', config=v2)[0])

    def test_the_lab_image_is_validated_like_the_test_image(self):
        self.config['lab']['image'] = dict(self.config['lab']['image'], sha256='f' * 64)
        code, _ = self.go('--dry-run', '--lab')
        self.assertEqual(2, code)


class JointStartTests(unittest.TestCase):
    """The real `lifecycle.start` for both machines of the run, on a fake process and fake endpoints."""

    def setUp(self):
        unix = patch.object(socket, 'AF_UNIX', 1, create=True)
        unix.start()
        self.addCleanup(unix.stop)
        self.media = test_stage_profiles.L3MediaTests()
        self.media.setUp()
        self.addCleanup(self.media.doCleanups)
        self.media.build()
        self.fixture = self.media.fixture.fixture
        self.runs = dict(test=self.media.run, lab=create_run(self.fixture.lease))
        self.fixture.config = replace(self.fixture.config, qga=True, machine='pc-i440fx-10.0')
        for role, run in self.runs.items():
            for identifier, name in EXECUTION_FILES.items():
                run.register(dict(id=identifier, kind='file', path=name))
                (run.directory / name).write_text('{}')
            (run.directory / 'execution-identity.json').write_text(json.dumps(dict(
                lab_id='lab-test', role=role, members={r: self.runs[r]._identity[0] for r in wire.MACS},
                controls=lab.controls(run),
                endpoint=dict(kind='inherited-unix-stream', role=role, mac=wire.MACS[role]))))
        self.fixture.run, self.fixture.calls = self.runs['lab'], []
        self.fixture.prepare()
        self.pair = lab.LabPair(self.fixture.lease, self.runs, 'lab-test', tunnel=True, evidence_disk=True, dns=True,
                                pair_factory=lambda *args: (Endpoint(), Endpoint()))
        self.addCleanup(self.pair.close)

    def launch(self, role):
        run = self.runs[role]
        plan = json.loads((run.directory / 'launch-plan.json').read_bytes())
        child = test_lifecycle.Child()
        child.pid += 1 if role == 'lab' else 0
        identity = dict(id='qemu', kind='process', pid=child.pid, platform='posix', boot_id='fake',
                        start_id=str(child.pid), executable=self.fixture.config.executable)
        self.fixture.run, self.fixture.calls = run, [0, 0]

        class Agent:
            def __init__(self, stream, **kwargs):
                self.stream, self.closed = stream, False

            def close(self):
                self.stream.close()
                self.closed = True
        with patch.object(lifecycle, '_host'), patch.object(lifecycle, 'Qmp', return_value=test_lifecycle.Control(plan)), \
                patch.object(lifecycle, 'Qga', side_effect=Agent), \
                patch.object(lifecycle.socket, 'socketpair', side_effect=lambda *args: (Endpoint(), Endpoint())), \
                patch.object(lifecycle, '_identity', return_value=identity), \
                patch.object(lifecycle.subprocess, 'Popen', return_value=child) as popen:
            vm = lifecycle.start(run, lab=self.pair, executor=self.fixture.fake, timeout=30)
        self.addCleanup(vm.close, hard=True)
        return vm, popen.call_args

    def test_the_test_machine_gets_the_lab_network_and_the_media_and_the_lab_machine_the_evidence_disk_only(self):
        first, a = self.launch('lab')
        second, b = self.launch('test')
        lab_line, test_line = ' '.join(a.args[0]), ' '.join(b.args[0])
        self.assertEqual({first, second}, self.fixture.lease._active)
        # The test machine: the wire to the lab, the ISO of the L3 package, no evidence disk.
        self.assertIn('mac=' + wire.MACS['test'], test_line)
        self.assertIn('addr.type=fd', test_line)
        self.assertIn('rosetun-l2-media', test_line)
        self.assertNotIn('rosetun-lab-evidence', test_line)
        self.assertNotIn('evidence', test_line)
        # The lab machine: the wire, the evidence disk, and nothing of the package or the L3 requests.
        self.assertIn('mac=' + wire.MACS['lab'], lab_line)
        self.assertIn('serial=rosetun-lab-evidence', lab_line)
        self.assertIn('evidence.img', lab_line)
        for forbidden in ('rosetun-l2-media', 'l2-media.iso', 'l3-requests', 'l2-snapshot', 'ROSETUN_L3'):
            self.assertNotIn(forbidden, lab_line)
        self.assertEqual(3, len(a.kwargs['pass_fds']))
        self.assertEqual(3, len(b.kwargs['pass_fds']))
        self.assertFalse(set(a.kwargs['pass_fds']) & set(b.kwargs['pass_fds']))

    def test_the_resources_and_plans_of_the_two_runs_do_not_mix(self):
        lab_plan = json.loads((self.runs['lab'].directory / 'launch-plan.json').read_bytes())
        test_plan = json.loads((self.runs['test'].directory / 'launch-plan.json').read_bytes())
        self.assertNotIn('l2_media', lab_plan)
        self.assertEqual('l3', test_plan['l2_media']['package']['profile'])
        lab_paths = {entry['path'] for entry in self.runs['lab']._read()['resources']}
        test_paths = {entry['path'] for entry in self.runs['test']._read()['resources']}
        self.assertIn('evidence.img', lab_paths)
        self.assertIn('dns.json', lab_paths)
        self.assertFalse({path for path in lab_paths if path.startswith(('l2-', 'l3-', 'linux-'))})
        self.assertFalse(test_paths & {'evidence.img', 'dns.json', 'capture.pcap', 'health.json'})
        self.assertTrue(any(path.startswith('l3-requests/') for path in test_paths))

    def test_either_machine_may_start_first(self):
        for order in (('test', 'lab'), ('lab', 'test')):
            with self.subTest(order=order):
                case = JointStartTests('test_the_resources_and_plans_of_the_two_runs_do_not_mix')
                case.setUp()
                try:
                    vms = [case.launch(role)[0] for role in order]
                    self.assertEqual(set(vms), case.fixture.lease._active)
                finally:
                    case.doCleanups()


class Machines:
    """Fake machines, a fake lab guest and the evidence the lab machine leaves on its disk."""
    # (label, frames inside the window, closed). A label of the group is one of the three below.
    CLEAN = (('reported', ()), ('identity', ()), ('connect_ks', ()), ('capabilities', ()), ('lan_on', ()))

    def __init__(self, test, windows=None, fault=None, rows=None, evidence=None, fixtures=None):
        self.test, self.fault = test, fault
        self.windows = list(self.CLEAN if windows is None else windows)
        self.rows, self.evidence, self.fixtures = rows, evidence, fixtures or {}
        self.events, self.calls, self.vms, self.guests, self.reads, self.imports = [], [], {}, [], [], []
        self.job_options = {}
        self.lab_id = None
        self.runs = {}

    # -- bookkeeping
    def note(self, name):
        self.events.append(name)
        if self.fault == name:
            raise ValueError('synthetic private stderr must never be published')

    def names(self):
        return list(self.events)

    # -- the fake adapters
    def adapters(self):
        machines = self

        class Vm:
            vm_uuid = '12345678-1234-4234-8234-123456789abc'
            last_boot_id = BOOT

            def __init__(self, role, run):
                self.role, self.run, self.closed, self.completed = role, run, False, False
                self.qga = SimpleNamespace(valid=True)

            def resume(self):
                machines.note('resume-' + self.role)

            def wait_initial_guest(self, **kwargs):
                machines.note('boot-' + self.role)
                return dict(result='observed')

            def recover_guest(self):
                machines.note('recovery')

            def close(self, **kwargs):
                machines.note('close-' + self.role)
                machines.events.append(('hard', self.role, kwargs.get('hard')))
                self.run._lease._active.discard(self)
                self.closed = self.completed = True

        def start(run, lab=None):
            role = lab.role(run)
            machines.note('start-' + role)
            vm = Vm(role, run)
            machines.vms[role] = vm
            machines.runs[role] = run
            run._lease._active.add(vm)
            return vm

        class Guest:
            def __init__(self, vm, role, lab_id, **kwargs):
                self.vm, self.role = vm, role
                machines.lab_id = lab_id
                machines.guests.append((role, lab_id, kwargs))

            def call(self, operation, expected, window=(), canary=False, tunnel=None, options=None):
                machines.note('lab-' + operation)
                machines.calls.append((operation, expected, list(window), tunnel, options))
                if operation == 'setup':
                    return dict(capture_ready=True)
                machines.write_disk(self.vm.run.directory / 'evidence.img')
                return dict(finished=True)

            def read(self, name, limit):
                machines.reads.append(name)
                machines.note('read-' + name)
                return machines.artifact(name)

        attempt = SimpleNamespace(state='built', receipt_verified=False, deadline=900)
        job = SimpleNamespace(submission='not-submitted', assessment=None, polls=0)

        def importer(vm, **kwargs):
            machines.note('import-create')
            machines.imports.append(kwargs)
            return attempt

        def stage():
            machines.note('import')
            attempt.state = 'ready'

        def receipt():
            machines.note('receipt')
            attempt.receipt_verified = True

        def create_job(**kwargs):
            machines.note('job-create')
            return job

        def submit():
            machines.note('submit')
            job.submission = 'launcher-spawned'

        def collect():
            machines.note('collect')
            job.polls += 1
            run = machines.runs['test']
            target = run.directory / 'linux-l3' / str(job.polls)
            target.mkdir(parents=True, exist_ok=True)
            (target / 'report.json').write_bytes(machines.report())
            job.assessment = dict(acceptance=dict(accepted=False, release=False),
                                  validation=dict(status='OK', problems=[]), execution=dict(status='PASS'))

        attempt.stage, attempt.check_receipt, attempt.linux_l2_job = stage, receipt, create_job
        job.submit, job.collect = submit, collect
        job.snapshot = lambda: dict(accepted=False, polls=job.polls)

        def pair(*args, **kwargs):
            machines.note('evidence-disk')
            machines.pair_options = kwargs
            machines.pair = lab.LabPair(*args, pair_factory=lambda *a: (Endpoint(), Endpoint()), **kwargs)
            return machines.pair

        def prepare(run, image, config, executor=None):
            machines.note('prepare-' + ('lab' if run.directory.name.endswith('-lab') else 'test'))

        def image(**record):
            machines.images = getattr(machines, 'images', []) + [record]
            return SimpleNamespace(**record)

        return SimpleNamespace(
            execute=lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b'QEMU emulator version 10.0.13'),
            image=image, config=lambda **record: SimpleNamespace(**record), prepare=prepare, pair=pair,
            requests=lambda run, server, port, **options: machines.requested(server, port, **options),
            attach=lambda run, **kwargs: machines.attached(kwargs), start=start, guest=Guest, importer=importer,
            host=lambda: None)

    def requested(self, server, port, **options):
        self.note('requests')
        self.request_node = (server, port)
        self.request_options = options

    def attached(self, kwargs):
        self.note('media')
        self.attach_options = kwargs

    # -- what the machines produce
    def frames(self, lab_id):
        """The wire and the lab machine's own log of it: a window is (label, frames[, closed])."""
        frames, rows = [], []
        for index, (label, body, *rest) in enumerate(self.windows):
            for word in ('open', 'close'):
                if word == 'close' and rest and rest[0] is False:
                    continue
                marker = wire.window_marker(lab_id, index, word, label)
                frames.append(wire_frame(marker['source'], marker['target'], 17,
                                         udp(41000, marker['port'], wire.marker_query(marker))))
                frames.append(wire_frame(marker['target'], marker['source'], 17,
                                         udp(marker['port'], 41000, wire.marker_answer(marker)), reply=True))
                rows.append((index, word, label))
                if word == 'open':
                    frames.extend(body)
        return frames, rows

    def pcap(self):
        frames, _ = self.frames(self.lab_id)
        return capture(frames)

    def write_disk(self, image):
        raw = self.evidence if self.evidence is not None else self.pcap()
        entry = load_entry()
        run_id = 'b' * 32 if self.fault == 'other-run' else self.lab_id
        image.write_bytes(bytes(wire.EVIDENCE_SIZE))
        with patch.object(entry.os, 'fsync'):
            writer = entry.EvidenceWriter(image, run_id)
            writer.write(raw)
            writer.finish(complete=self.fault != 'incomplete')

    def artifact(self, name):
        _, rows = self.frames(self.lab_id)
        node = dict(alive_at_finish=self.fixtures.get('node', True), exit_code=-15)
        if name == 'health.json':
            return json.dumps(health(rows, node=node)).encode()
        if name == 'https.json':
            # What the target of an L3 run leaves: its first rows and the counters by who was answered.
            sources = {False: [], 'direct-only': [wire.CLIENTS[4]], 'node-only': [wire.EGRESS]}.get(
                self.fixtures.get('https'), [wire.CLIENTS[4], wire.EGRESS])
            counts = [dict(source=source, method='GET', path_class='root', count=3) for source in sources]
            return json.dumps([dict(source=source, port=51000, method='GET', path_class='root', at=6.0)
                               for source in sources]
                              + list(self.fixtures.get('refusals', []))
                              + [dict(kind='counts', counts=counts, rows_dropped=0, counts_dropped=0)]).encode()
        if name == 'dns.json':
            kinds = [] if self.fixtures.get('dns') is False else ['udp']
            kinds += ['doh'] if self.fixtures.get('doh', True) else []
            return json.dumps([dict(source=wire.CLIENTS[4], transport=kind, name='example.com', type='A')
                               for kind in kinds]).encode()
        if name == 'node.log':
            return b'inbound/shadowsocks[node-in]: connection from 192.0.2.2:43000\n'
        return b'[]'

    def report(self):
        rows = self.rows or {identifier: ('PASS', 'ok') for identifier in scenario_ids()}
        scenarios = [dict(id=identifier, group='x', evidence='real-service', expectation='x', result=result,
                          reason=reason, duration_ms=1) for identifier, (result, reason) in rows.items()]
        counts = {name: sum(row['result'] == name for row in scenarios) for name in ('PASS', 'FAIL', 'ERROR', 'SKIP')}
        overall = 'ERROR' if counts['ERROR'] else 'FAIL' if counts['FAIL'] else 'PASS'
        return json.dumps(dict(schema=1, run_id='x', summary=dict(
            overall=overall, coverage='complete' if overall == 'PASS' and not counts['SKIP'] else 'none',
            pass_=counts['PASS'], total=len(scenarios), **{k.lower(): v for k, v in counts.items()
                                                            if k != 'PASS'}),
            cleanup=dict(status='PASS', actions='', problems=''), scenarios=scenarios)).encode()


def udp(sport, dport, payload):
    from tools.vm.matrix.tests.test_lab import udp as build
    return build(sport, dport, payload)


def wire_frame(src, dst, proto, body, reply=False):
    from tools.vm.matrix.tests.test_lab import ip_frame
    if reply:
        return ip_frame(src, dst, proto, body, src=wire.MACS['lab'], dst=wire.MACS['test'])
    return ip_frame(src, dst, proto, body)


class Flow(unittest.TestCase):
    JOB = 900

    def setUp(self):
        self.fixture = test_qemu.PreparationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.config = dict(
            schema=execution.SCHEMA_V3, suite='linux-l3', state_directory=str(self.fixture.root / 'lab-state'),
            stand_id='synthetic', image={'name': 'test'}, qemu=asdict(replace(
                self.fixture.config, machine='pc-i440fx-10.0', qga=True)),
            content_directory=str(self.fixture.root), source_checkout=str(self.fixture.root), xorriso='fake',
            accounts=dict(user_a='l2a', user_b='l2b'), timeouts=dict(scenario=30, unit=180, job=self.JOB),
            deadlines=dict(preparation=600, boot=300, **{'import': 900}, execution=self.JOB + 180),
            l3=dict(sing_box_sha256=HEX, host_address='192.0.2.1', node_port=8388, probe_address='203.0.113.2',
                    dns_probe_address='203.0.113.53'),
            lab=dict(image={'name': 'lab'}, https_cert_sha256='a' * 64, doh_cert_sha256='b' * 64,
                     tunnel=dict(sing_box_sha256=HEX, ca_sha256='c' * 64, node_port=8388)))
        self.clock = SimpleNamespace(now=0)
        self.sleeps = []

    def go(self, machines, **options):
        def sleep(seconds):
            self.sleeps.append(seconds)
            self.clock.now += seconds

        def completion(directory, manifest):
            return any(v.run.directory == directory and v.closed for v in machines.vms.values())
        with patch.object(socket, 'AF_UNIX', 1, create=True), \
                patch.object(l3_lab, 'preflight', return_value={}), \
                patch.object(l3_lab, 'completion_verified', side_effect=completion):
            return l3_lab.run_linux_l3_lab(self.config, adapters=machines.adapters(), clock=lambda: self.clock.now,
                                           sleep=sleep, progress=lambda stage: None, **options)


ORDER = ['prepare-lab', 'prepare-test', 'requests', 'media', 'evidence-disk', 'start-lab', 'resume-lab', 'boot-lab',
         'lab-setup', 'start-test', 'resume-test', 'boot-test', 'import-create', 'import', 'recovery', 'receipt',
         'job-create', 'submit', 'collect', 'lab-finish']


class OrderTests(Flow):
    def test_the_controller_follows_the_order_of_the_stage(self):
        machines = Machines(self)
        result = self.go(machines)
        names = [e for e in machines.events if type(e) is str]
        self.assertEqual(ORDER, names[:len(ORDER)])
        self.assertEqual(['read-targets.json', 'read-health.json', 'read-https.json', 'read-node.log',
                          'read-dns.json', 'close-test', 'close-lab'], names[len(ORDER):])
        self.assertEqual((True, dict(test=True, lab=True)), (result['completed'], result['completion']))
        self.assertEqual('l3-summary', result['schema'].split('.')[2])
        self.assertEqual(['lab', 'test'], sorted(result['artifact_directories']))
        self.assertFalse(result['release_gate'])
        self.assertEqual('UNVERIFIED', result['security_invariants'])

    def test_the_lab_machine_is_ready_before_the_test_machine_starts_and_stops_last(self):
        machines = Machines(self)
        self.go(machines)
        names = [e for e in machines.events if type(e) is str]
        self.assertLess(names.index('lab-setup'), names.index('start-test'))
        self.assertLess(names.index('lab-finish'), names.index('close-test'))
        self.assertLess(names.index('close-test'), names.index('close-lab'))
        self.assertLess(names.index('submit'), names.index('lab-finish'))
        self.assertIn(self.JOB + 125, self.sleeps)

    def test_both_helper_requests_are_the_same_and_ask_for_the_whole_lab(self):
        machines = Machines(self)
        self.go(machines)
        (setup, finish) = machines.calls
        self.assertEqual('setup', setup[0])
        self.assertEqual(('finish',), (finish[0],))
        # The helper compares the later request with the first: everything but the operation is equal.
        self.assertEqual(setup[1:], finish[1:])
        _, expected, window, tunnel, options = setup
        self.assertEqual(8, len(expected))
        self.assertEqual([], window)
        self.assertEqual(dict(evidence_disk=True, duration_seconds=self.JOB + 300, dns=True, windows=True,
                              certificates=dict(https_sha256='a' * 64, doh_sha256='b' * 64)), options)
        self.assertEqual((8388, 'aes-128-gcm', 'c' * 64, HEX),
                         (tunnel['port'], tunnel['method'], tunnel['ca_sha256'], tunnel['sing_box_sha256']))
        self.assertEqual(2, len(tunnel['https']))
        nonces = [p['nonce'] for p in expected] + [e['nonce'] for e in tunnel['https']]
        self.assertEqual(10, len(set(nonces)))
        self.assertTrue(all(p['run_id'] == machines.lab_id for p in expected))

    def test_the_pair_has_the_evidence_disk_the_tunnel_and_the_dns_logs(self):
        machines = Machines(self)
        result = self.go(machines)
        self.assertEqual(dict(tunnel=True, evidence_disk=True, dns=True), machines.pair_options)
        paths = {entry['path'] for entry in result['evidence'] if entry['role'] == 'lab'}
        self.assertTrue({'evidence.img', 'dns.json', 'https.json', 'node.log', 'capture.pcap'} <= paths)

    def test_the_importer_and_the_media_know_the_lab(self):
        machines = Machines(self)
        self.go(machines)
        self.assertEqual(('192.0.2.1', 8388), machines.request_node)
        self.assertEqual(dict(profile='l3', sing_box_sha256=HEX), {
            k: v for k, v in machines.attach_options.items() if k in ('profile', 'sing_box_sha256')})
        (options,) = machines.imports
        self.assertEqual(dict(sing_box_sha256=HEX, host_address='192.0.2.1', node_port=8388,
                              probe_address='203.0.113.2', dns_probe_address='203.0.113.53',
                              lab_marker_address='203.0.113.2:9100'), options['l3'])
        self.assertEqual(l3_lab.marker_address(), options['l3']['lab_marker_address'])
        self.assertEqual(wire.marker_run_id(options['guest_run_id']), machines.lab_id)

    def test_the_runs_carry_the_lab_identity_and_the_summary_is_saved_in_both(self):
        machines = Machines(self)
        result = self.go(machines)
        identities = result['identities']
        self.assertEqual(machines.lab_id, identities['lab_id'])
        for role, run in machines.runs.items():
            self.assertEqual(identities['lab_id'] + '-' + role, run.directory.name)
            saved = json.loads((run.directory / 'execution-summary.json').read_bytes())
            self.assertEqual(result, saved)
            linkage = json.loads((run.directory / 'execution-identity.json').read_bytes())
            self.assertEqual((identities['lab_id'], role), (linkage['lab_id'], linkage['role']))
        test_identity = json.loads((machines.runs['test'].directory / 'execution-identity.json').read_bytes())
        self.assertEqual(identities['guest_run_id'], test_identity['guest_run_id'])
        self.assertNotIn('guest_run_id', json.loads((machines.runs['lab'].directory / 'execution-identity.json').read_bytes()))
        for run in machines.runs.values():
            self.assertNotIn(run._identity[2], (run.directory / 'execution-summary.json').read_text())

    def test_the_facade_of_the_lab_guest_is_new_for_the_finish(self):
        machines = Machines(self)
        self.go(machines)
        self.assertEqual(['lab', 'lab'], [role for role, _, _ in machines.guests])

    def test_the_windows_and_the_legacy_report_are_in_the_summary(self):
        machines = Machines(self)
        result = self.go(machines)
        self.assertEqual(['reported', 'identity', 'connect_ks', 'capabilities', 'lan_on'],
                         [w['label'] for w in result['lab']['windows']])
        self.assertEqual(['NONE'] * 5, [w['leak'] for w in result['lab']['windows']])
        self.assertEqual(39, len(result['legacy']['scenarios']))
        self.assertEqual('PASS', result['legacy']['summary']['overall'])
        self.assertEqual(64, len(result['legacy']['report_sha256']))
        self.assertTrue(result['lab']['qualification']['evidence']['verified'])
        self.assertEqual(0, result['exit_code'])


class DiagnosticTests(Flow):
    def test_an_ordinary_run_asks_for_ordinary_requests_and_has_no_diagnostic_mark(self):
        machines = Machines(self)
        result = self.go(machines)
        self.assertEqual({}, machines.request_options)
        self.assertNotIn('diagnostic', result)
        self.assertNotIn('diagnostic-run', result['group']['unproven'])
        self.assertEqual((0, 'group-clean'), (result['exit_code'], result['outcome']))

    def test_a_diagnostic_run_asks_for_diagnostic_requests_marks_its_summary_and_is_never_below_2(self):
        machines = Machines(self)
        result = self.go(machines, diagnostic=True)
        self.assertEqual(dict(diagnostic=True), machines.request_options)
        self.assertIs(True, result['diagnostic'])
        self.assertIn('diagnostic-run', result['group']['unproven'])
        self.assertEqual(2, result['exit_code'])
        # Everything else is judged as in any run, and the mark is in both saved summaries.
        self.assertTrue(result['group']['passed'])
        self.assertEqual([], result['group']['findings'])
        for run in machines.runs.values():
            self.assertTrue(json.loads((run.directory / 'execution-summary.json').read_bytes())['diagnostic'])

    def test_an_interrupted_diagnostic_run_stays_130(self):
        result = dict(diagnostic=True, legacy=dict(scenarios=[]), errors=[], completed=True,
                      lab=dict(windows=[], missing_labels=[], qualification=dict(
                          evidence=dict(verified=True), fixtures={}, observer=dict(reasons=[]))))
        l3_summary.decide(result, True)
        self.assertEqual(130, result['exit_code'])

    def test_a_finding_of_a_diagnostic_run_stays_in_the_outcome_while_the_code_is_2(self):
        machines = Machines(self)
        result = self.go(machines, diagnostic=True)
        for row in result['legacy']['scenarios']:
            if row['id'] == 'killswitch.tunnel-passes':
                row['result'] = 'FAIL'
        result['errors'] = []
        l3_summary.decide(result, False)
        self.assertIn('group-scenario-failed', result['group']['findings'])
        self.assertEqual('findings', result['outcome'])
        self.assertEqual(2, result['exit_code'])
        result.pop('diagnostic')
        l3_summary.decide(result, False)
        self.assertEqual(1, result['exit_code'])

    def test_the_command_line_accepts_the_flag_only_with_the_lab(self):
        base = DryRunTests()
        base.setUp()
        try:
            self.assertEqual(2, base.go('--dry-run', '--diagnostic')[0])
            self.assertEqual(0, base.go('--dry-run', '--lab', '--diagnostic')[0])
        finally:
            base.doCleanups()

    def test_the_flag_reaches_the_lab_run(self):
        seen = []

        def lab_run(config, **options):
            seen.append(options)
            return dict(exit_code=2)
        base = DryRunTests()
        base.setUp()
        try:
            with patch.object(l3_lab, 'run_linux_l3_lab', side_effect=lab_run):
                base.go('--lab', '--diagnostic')
                base.go('--lab')
        finally:
            base.doCleanups()
        self.assertEqual([dict(diagnostic=True), {}], seen)


class FlowSummaryTests(Flow):
    def test_every_window_of_the_summary_has_its_flows_and_the_lab_has_the_refusals_of_the_target(self):
        machines = Machines(self)
        result = self.go(machines)
        windows = result['lab']['windows']
        self.assertTrue(windows)
        for window in windows:
            self.assertEqual({'connections', 'omitted'}, set(window['flows']))
        self.assertEqual([], result['lab']['https_refusals'])
        self.assertEqual(0, result['exit_code'])

    def test_a_connection_to_the_node_in_the_window_of_the_session_is_in_the_summary(self):
        from tools.vm.matrix.tests.test_lab import tcp
        syn = wire_frame(wire.CLIENTS[4], wire.GATEWAYS[4], 6, tcp(43000, 8388, flags=0x02))
        reply = wire_frame(wire.GATEWAYS[4], wire.CLIENTS[4], 6, tcp(8388, 43000, b'x' * 5, 0x18), reply=True)
        windows = [('reported', ()), ('identity', ()), ('connect_ks', (syn, reply)), ('capabilities', ()),
                   ('lan_on', ())]
        result = self.go(Machines(self, windows=windows))
        self.assertEqual(0, result['exit_code'])
        by_label = {w['label']: w['flows'] for w in result['lab']['windows']}
        (flow,) = by_label['connect_ks']['connections']
        self.assertEqual(('node', '192.0.2.2:43000', '192.0.2.1:8388', 1, 1, 0, 5, True, False),
                         (flow['kind'], flow['client'], flow['server'], flow['frames_out'], flow['frames_back'],
                          flow['bytes_out'], flow['bytes_back'], flow['syn'], flow['syn_ack']))
        self.assertEqual([], by_label['reported']['connections'])

    def test_the_refusals_of_the_target_reach_the_summary_without_changing_the_exit_code(self):
        refusal = dict(service='https', family=4, reason='ssl-unexpected_eof_while_reading')
        machines = Machines(self, fixtures=dict(refusals=[refusal]))
        result = self.go(machines)
        self.assertEqual([refusal], result['lab']['https_refusals'])
        self.assertEqual(0, result['exit_code'])

    def test_a_refusal_row_is_passed_on_as_service_family_and_reason_and_nothing_else(self):
        log = [dict(source='192.0.2.2', port=1, at=2.0, method='GET', path_class='root'),
               dict(service='https', family=4, reason='ssl-wrong_version_number', source='198.51.100.9'),
               dict(service='https', family=4, reason='timeout'),
               dict(service='X' * 40, family=7, reason='bad reason with spaces'),
               dict(kind='counts', counts=[], rows_dropped=0, counts_dropped=0), 'text', None]
        self.assertEqual([dict(service='https', family=4, reason='ssl-wrong_version_number'),
                          dict(service='https', family=4, reason='timeout'),
                          dict(service='invalid', family=None, reason='invalid')], l3_lab.https_refusals(log))
        self.assertEqual([], l3_lab.https_refusals(None))
        self.assertEqual([], l3_lab.https_refusals({'reason': 'x'}))
        many = [dict(service='https', family=4, reason='timeout')] * 20
        self.assertEqual(l3_lab.REFUSAL_ROWS, len(l3_lab.https_refusals(many)))


class FailureTests(Flow):
    POINTS = ORDER + ['read-health.json', 'close-test', 'close-lab']

    def test_a_failure_at_every_step_closes_what_was_started_and_is_an_error(self):
        for point in self.POINTS:
            with self.subTest(point=point):
                case = FailureTests()
                case.setUp()
                try:
                    machines = Machines(case, fault=point)
                    result = case.go(machines)
                    self.assertEqual(2, result['exit_code'])
                    self.assertTrue(result['errors'])
                    self.assertNotIn('private stderr', json.dumps(result))
                    if point.startswith('close-'):
                        # A close that fails leaves the run for the owner to inspect.
                        self.assertTrue(result['manual_recovery_required'])
                        self.assertFalse(result['completed'])
                    else:
                        self.assertTrue(all(vm.closed for vm in machines.vms.values()))
                    self.assertFalse(result['lab']['qualification']['evidence']['verified'])
                finally:
                    case.doCleanups()

    def test_a_failed_start_of_the_test_machine_still_closes_the_lab_machine(self):
        machines = Machines(self, fault='start-test')
        result = self.go(machines)
        self.assertEqual(2, result['exit_code'])
        self.assertEqual({'lab'}, set(machines.vms))
        self.assertTrue(machines.vms['lab'].closed)
        self.assertEqual(True, [e for e in machines.events if type(e) is tuple and e[1] == 'lab'][0][2])

    def test_a_machine_that_does_not_stop_is_not_a_complete_run(self):
        machines = Machines(self)
        result = self.go_without_completion(machines)
        self.assertEqual(2, result['exit_code'])
        self.assertFalse(result['completed'])
        self.assertTrue(result['manual_recovery_required'])

    def go_without_completion(self, machines):
        with patch.object(socket, 'AF_UNIX', 1, create=True), \
                patch.object(l3_lab, 'preflight', return_value={}), \
                patch.object(l3_lab, 'completion_verified', return_value=False):
            return l3_lab.run_linux_l3_lab(self.config, adapters=machines.adapters(), clock=lambda: self.clock.now,
                                           sleep=lambda s: None, progress=lambda stage: None)

    def test_a_wrong_qemu_is_refused_before_anything_is_created(self):
        machines = Machines(self)
        adapters = machines.adapters()
        adapters.execute = lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b'QEMU emulator version 10.0.130')
        with patch.object(socket, 'AF_UNIX', 1, create=True), patch.object(l3_lab, 'preflight', return_value={}):
            result = l3_lab.run_linux_l3_lab(self.config, adapters=adapters, clock=lambda: 0,
                                             sleep=lambda s: None, progress=lambda stage: None)
        self.assertEqual(2, result['exit_code'])
        self.assertEqual([], machines.events)

    def test_a_configuration_without_the_lab_is_refused(self):
        for change in (dict(suite='linux-l2'), dict(schema=execution.SCHEMA_V2)):
            with self.subTest(change=change), self.assertRaises(ValueError):
                l3_lab.run_linux_l3_lab(dict(self.config, **change), adapters=Machines(self).adapters())

    def test_an_interrupt_is_130_and_closes_both_machines(self):
        machines = Machines(self)
        adapters = machines.adapters()
        original = adapters.importer

        def importer(vm, **kwargs):
            attempt = original(vm, **kwargs)
            attempt.stage = lambda: (_ for _ in ()).throw(KeyboardInterrupt())
            return attempt
        adapters.importer = importer
        with patch.object(socket, 'AF_UNIX', 1, create=True), patch.object(l3_lab, 'preflight', return_value={}), \
                patch.object(l3_lab, 'completion_verified', side_effect=lambda d, m: all(
                    v.closed for v in machines.vms.values())):
            result = l3_lab.run_linux_l3_lab(self.config, adapters=adapters, clock=lambda: 0,
                                             sleep=lambda s: None, progress=lambda stage: None)
        self.assertEqual(130, result['exit_code'])
        self.assertTrue(all(vm.closed for vm in machines.vms.values()))
        self.assertEqual({'lab', 'test'}, set(machines.vms))


class EvidenceDiskTests(Flow):
    def untrusted(self, fault, reason):
        machines = Machines(self, fault=fault)
        result = self.go(machines)
        self.assertEqual(2, result['exit_code'])
        disk = result['lab']['qualification']['evidence']
        self.assertEqual((False, reason), (disk['verified'], disk['reason']))
        self.assertEqual([], result['lab']['windows'])
        self.assertEqual(39, len(result['legacy']['scenarios']))

    def test_a_disk_of_another_run_is_an_error_with_its_reason_and_no_analysis(self):
        self.untrusted('other-run', 'evidence-run-id')

    def test_a_disk_the_helper_did_not_complete_is_an_error_with_its_reason_and_no_analysis(self):
        self.untrusted('incomplete', 'evidence-incomplete')

    def test_the_hash_of_the_capture_is_the_hash_of_the_disk_content(self):
        machines = Machines(self)
        result = self.go(machines)
        raw = (machines.runs['lab'].directory / 'capture.pcap').read_bytes()
        disk = result['lab']['qualification']['evidence']
        import hashlib
        self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (disk['pcap_bytes'], disk['pcap_sha256']))
        self.assertEqual(disk['pcap_sha256'], result['lab']['artifacts_sha256']['capture.pcap'])


class LedgerSequenceTests(Flow):
    """The preparation of the run as the ledger sees it: nothing but the commands and the start is a fake.

    The lease, the runs, `qemu.prepare`, `write_requests`, `attach_media` and the `LabPair` are the real ones;
    `qemu-img` and `xorriso` are scripted, and `start` stops the controller where the machines would boot.
    """

    class Stopped(Exception):
        pass

    def setUp(self):
        super().setUp()
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        content = Path(temp.name)
        test_stage_profiles.package_l3(content, BOOT)
        for name in ('job.env', 'manifest.sha256', *('artifacts/' + n for n in l2.PROFILES['l3'].requests)):
            (content / name).unlink()
        record = self.fixture.image.record()
        self.config.update(content_directory=str(content), source_checkout=str(test_linux_l2.CHECKOUT),
                           xorriso=self.fixture.config.executable, image=record)
        self.config['lab']['image'] = record
        self.config['l3']['sing_box_sha256'] = test_stage_profiles.SING_BOX_SHA
        self.started = []
        self.commands = []

    def execute(self, argv, *, timeout, output_limit):
        self.commands.append(argv[1])
        if argv[1] == '--version':
            return qemu.CommandResult(0, b'QEMU emulator version 10.0.13\n')
        if argv[1] == '-no_rc':
            if argv[-1] == '-version':
                return qemu.CommandResult(0, b'xorriso 1.5.6\n')
            Path(argv[argv.index('-o') + 1]).write_bytes(b'inert ISO fixture')
            return qemu.CommandResult(0, b'')
        if argv[1] == 'create':
            Path(argv[-1]).write_bytes(b'fake overlay')
            return qemu.CommandResult(0, b'')
        base = Path(self.fixture.config.image_executable)
        chain = [self.fixture.info(argv[-1]), self.fixture.info(base)]
        if Path(argv[-1]) == base:
            chain = chain[:1]
        else:
            chain[0].update({'backing-filename': str(base), 'full-backing-filename': str(base),
                             'backing-filename-format': 'qcow2'})
        return qemu.CommandResult(0, json.dumps(chain).encode())

    def adapters(self):
        real = l3_lab.Adapters()

        def start(run, lab=None):
            self.started.append(run.directory.name)
            raise self.Stopped('stopped-before-start')

        def pair(*args, **kwargs):
            return lab.LabPair(*args, pair_factory=lambda *a: (Endpoint(), Endpoint()), **kwargs)
        real.execute, real.start, real.pair = self.execute, start, pair
        return real

    def go_to_the_start(self):
        with patch.object(l2, 'source_identity', return_value=test_stage_profiles.SOURCE), \
                patch.object(socket, 'AF_UNIX', 1, create=True), \
                patch.object(l3_lab, 'preflight', return_value={}):
            return l3_lab.run_linux_l3_lab(self.config, adapters=self.adapters(), clock=lambda: self.clock.now,
                                           sleep=self.sleeps.append, progress=lambda stage: None)

    def paths(self, result, role):
        directory = Path(result['artifact_directories'][role])
        return [entry['path'] for entry in read_manifest(directory)['resources']]

    def test_both_runs_are_prepared_and_the_pair_registers_its_files_last(self):
        result = self.go_to_the_start()
        self.assertEqual([dict(stage='start-lab', kind='Stopped', reason='stopped-before-start')], result['errors'])
        stages = [row['stage'] for row in result['stages']]
        self.assertEqual(['prepare-lab', 'prepare-test', 'requests', 'media', 'evidence-disk', 'start-lab'],
                         stages[stages.index('prepare-lab'):])
        self.assertTrue(all(row['state'] == 'completed' for row in result['stages'][:-1]))
        self.assertEqual(1, len(self.started))
        self.assertTrue(self.started[0].endswith('-lab'))

    def test_the_ledgers_hold_the_requests_and_the_media_before_the_files_of_the_pair(self):
        result = self.go_to_the_start()
        test, lab_paths = self.paths(result, 'test'), self.paths(result, 'lab')
        requests = list(media.request_resources('l3'))
        self.assertEqual(requests, test[test.index(requests[0]):][:len(requests)])
        self.assertLess(test.index('l2-package/manifest.sha256'), test.index('client.log'))
        self.assertEqual('client.log', test[-1])
        self.assertIn('evidence.img', lab_paths)
        self.assertNotIn('client.log', lab_paths)
        self.assertEqual(['l2-media.iso', 'l2-media.jsonl', 'l2-media.json'],
                         [name for name in test if name.startswith('l2-media.')])

    def test_the_commands_are_the_ones_of_the_preparation_and_the_media_only(self):
        self.go_to_the_start()
        self.assertEqual(['--version', '--version', 'info', 'create', 'info', 'info', 'create', 'info',
                          '-no_rc', '-no_rc'], self.commands)


if __name__ == '__main__':
    unittest.main()
